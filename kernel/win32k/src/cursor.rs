//! Les curseurs et les icônes (`cursoricon.c`, `defwnd.c` de ReactOS, comme
//! spécification) : des objets de la table des handles USER (`TYPE_CURSOR`)
//! que `user32` fait lui-même. LoadImage (LoadCursor, LoadIcon) demande
//! d'abord si le processus a déjà chargé la ressource (LR_SHARED :
//! [`find_existing`]), puis lit la ressource, en fait des bitmaps
//! (StretchDIBits : `crate::gdi::dibits`), crée un objet vide
//! (NtUserxCreateEmptyCurObject : [`create_empty`]) et lui donne ses données
//! (NtUserSetCursorIconData : [`set_data`]) : le point chaud, la taille, le
//! masque AND (et, pour un curseur monochrome, le masque XOR sous lui), les
//! couleurs, l'alpha. Les bitmaps deviennent publics : ils sont au curseur.
//!
//! Le noyau en tire la forme qu'il dessine ([`Shape`]) : chaque pixel est
//! transparent, opaque, inversé (XOR) ou mélangé (alpha), comme DrawIconEx
//! en DI_NORMAL.
//!
//! Les curseurs du système (SetSystemCursor, [`set_system_cursor`]) : la
//! première fois que win32k prend l'écran, il demande à `user32` de les
//! charger (le rappel LOADDEFAULTCURSORS, User32SetupDefaultCursors) ; un
//! curseur du système n'est plus à aucun processus (CURSORF_GLOBAL), et
//! LoadCursor(NULL, IDC_ARROW) d'une application le retrouve
//! ([`find_existing`] cherche les curseurs du processus, puis ceux du
//! système).
//!
//! Le curseur de l'écran : chaque thread a le sien (SetCursor :
//! [`set_cursor`]) ; l'écran montre celui du thread de la fenêtre sous le
//! pointeur (ou qui a la capture : [`pointer_over`]). WM_SETCURSOR va à
//! cette fenêtre à chaque message de la souris (`crate::mouse`), et
//! DefWindowProc ([`def_set_cursor`]) y met le curseur de sa classe dans la
//! zone cliente, une flèche double sur un bord, la flèche ailleurs.
//!
//! Pas encore : les curseurs animés (CURSORF_ACON : refusés), ShowCursor,
//! ClipCursor, GetIconInfo, DrawIconEx (l'icône du titre), CopyImage, le
//! remplacement d'un curseur du système déjà posé (FALSE, comme ReactOS),
//! GetClassLong(GCLP_HCURSOR) (le `CLS` n'a pas de pointeur vers l'objet).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    cursorf, CursorData32, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTCLIENT, HTLEFT, HTRIGHT, HTTOP, HTTOPLEFT,
    HTTOPRIGHT, OCR_CURSORS, OCR_NORMAL, OCR_SIZENESW, OCR_SIZENS, OCR_SIZENWSE, OCR_SIZEWE, RT_ICON, TYPE_CURSOR,
    WM_SETCURSOR, WS_CHILD, WS_MAXIMIZE,
};
use hal::sync::KSpinLock;

use crate::gdi::dib::{ColorRef, PixelLayout};
use crate::gui::ThreadInfo;
use crate::window::{LParam, Window};

/// Un curseur ou une icône a au plus 256 pixels de côté.
pub const MAX_SIDE: u32 = 256;

/// HTERROR (-2), le mot bas de `lParam` de WM_SETCURSOR : un clic hors
/// d'une fenêtre que bloque une fenêtre modale.
const HTERROR: u32 = 0xFFFE;

/// Le nom d'une ressource : un identifiant (MAKEINTRESOURCE) ou un nom,
/// gardé en majuscules (la comparaison ignore la casse).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    Id(u16),
    Name(Vec<u16>),
}

/// Un pixel d'une forme, sur ce que l'écran a dessous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pixel {
    /// L'écran reste (AND 1, XOR 0).
    Transparent,
    /// La couleur remplace l'écran (AND 0).
    Opaque(ColorRef),
    /// L'écran XOR la couleur (AND 1, XOR non nul) : le blanc l'inverse.
    Xor(ColorRef),
    /// L'écran mélangé à la couleur, par son alpha.
    Blend(ColorRef, u8),
}

impl Pixel {
    /// Ce que devient le pixel `screen` de l'écran sous lui.
    pub fn over(self, screen: ColorRef) -> ColorRef {
        match self {
            Pixel::Transparent => screen,
            Pixel::Opaque(color) => color,
            Pixel::Xor(color) => ColorRef((screen.0 ^ color.0) & 0x00FF_FFFF),
            Pixel::Blend(color, alpha) => {
                let mix = |a: u8, b: u8| {
                    ((u32::from(a) * u32::from(alpha) + u32::from(b) * (255 - u32::from(alpha))) / 255) as u8
                };
                let ((r, g, b), (sr, sg, sb)) = (color.components(), screen.components());
                ColorRef::rgb(mix(r, sr), mix(g, sg), mix(b, sb))
            }
        }
    }
}

/// La forme d'un curseur, telle que l'écran la dessine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    pub width: u32,
    pub height: u32,
    /// Le point chaud, depuis son coin en haut à gauche : il tombe sur la
    /// place du pointeur.
    pub hotspot: (i32, i32),
    /// Ses pixels, la ligne du haut d'abord.
    pub pixels: Vec<Pixel>,
}

impl Shape {
    /// La forme de `width` × `height` des masques d'un curseur (les pixels
    /// de 32 bits de ses bitmaps, la ligne du haut d'abord) : `mask`, le
    /// masque AND (blanc : 1), et sans `color` le masque XOR sous lui
    /// (`mask` a alors deux fois la hauteur) ; `alpha`, ses pixels avec leur
    /// alpha dans l'octet haut, l'emporte sur les masques. `None` si un
    /// bitmap est trop petit.
    pub fn from_bitmaps(
        (width, height): (u32, u32),
        hotspot: (i32, i32),
        mask: &[u32],
        color: Option<&[u32]>,
        alpha: Option<&[u32]>,
    ) -> Option<Self> {
        let count = width as usize * height as usize;
        let needed = if color.is_some() { count } else { 2 * count };
        if mask.len() < needed || color.is_some_and(|c| c.len() < count) || alpha.is_some_and(|a| a.len() < count) {
            return None;
        }
        let layout = PixelLayout::Bgrx;
        let is_one = |raw: u32| layout.color(raw).0 & 0x00FF_FFFF != 0;
        let pixels = (0..count)
            .map(|at| {
                if let Some(alpha) = alpha {
                    let raw = alpha[at];
                    return Pixel::Blend(layout.color(raw), (raw >> 24) as u8);
                }
                let and = is_one(mask[at]);
                let xor = match color {
                    Some(color) => layout.color(color[at]),
                    None if is_one(mask[count + at]) => ColorRef::rgb(255, 255, 255),
                    None => ColorRef::rgb(0, 0, 0),
                };
                match (and, xor.0 & 0x00FF_FFFF != 0) {
                    (false, _) => Pixel::Opaque(xor),
                    (true, false) => Pixel::Transparent,
                    (true, true) => Pixel::Xor(xor),
                }
            })
            .collect();
        Some(Self { width, height, hotspot, pixels })
    }

    /// La flèche dessinée avant que `user32` ait chargé les curseurs du
    /// système : `X` noir, `.` blanc, le reste transparent ; le point chaud
    /// en haut à gauche.
    pub fn arrow() -> Self {
        const ARROW: [&[u8; 12]; 19] = [
            b"X           ",
            b"XX          ",
            b"X.X         ",
            b"X..X        ",
            b"X...X       ",
            b"X....X      ",
            b"X.....X     ",
            b"X......X    ",
            b"X.......X   ",
            b"X........X  ",
            b"X.........X ",
            b"X......XXXXX",
            b"X...X..X    ",
            b"X..XX..X    ",
            b"X.X  X..X   ",
            b"XX   X..X   ",
            b"X     X..X  ",
            b"      X..X  ",
            b"       XX   ",
        ];
        let pixels = ARROW
            .iter()
            .flat_map(|row| row.iter())
            .map(|&cell| match cell {
                b'X' => Pixel::Opaque(ColorRef::rgb(0, 0, 0)),
                b'.' => Pixel::Opaque(ColorRef::rgb(255, 255, 255)),
                _ => Pixel::Transparent,
            })
            .collect();
        Self { width: 12, height: 19, hotspot: (0, 0), pixels }
    }
}

/// Ce que `user32` a donné à un curseur.
struct Data {
    /// `cursorf::*`.
    flags: u32,
    icon: bool,
    size: (u32, u32),
    /// Ses bitmaps : le masque, les couleurs, l'alpha (0 : aucun).
    bitmaps: [u32; 3],
    shape: Arc<Shape>,
    /// Le chemin du module de sa ressource, en majuscules.
    module: Option<Vec<u16>>,
    resource: Option<Resource>,
}

/// Un curseur ou une icône (CURICON_OBJECT).
pub struct CurIcon {
    /// Le PID de son processus ; 0 pour un curseur du système.
    pid: AtomicU32,
    /// Le curseur d'un thread (CURSORF_CURRENT : posé par SetCursor, retiré
    /// quand un autre le remplace, comme ReactOS).
    current: AtomicBool,
    data: KSpinLock<Option<Data>>,
}

impl CurIcon {
    /// Sa forme, s'il a ses données.
    pub fn shape(&self) -> Option<Arc<Shape>> {
        self.data.lock().as_ref().map(|data| data.shape.clone())
    }

    /// Sa taille, s'il a ses données (NtUserGetIconSize).
    pub fn size(&self) -> Option<(u32, u32)> {
        self.data.lock().as_ref().map(|data| data.size)
    }

    fn flags(&self) -> u32 {
        self.data.lock().as_ref().map_or(0, |data| data.flags)
    }
}

/// Les curseurs par handle.
static CURSORS: KSpinLock<Vec<(u32, Arc<CurIcon>)>> = KSpinLock::new(Vec::new());
/// Les curseurs du système, dans l'ordre de [`OCR_CURSORS`] ; 0 : pas posé.
static SYSTEM: KSpinLock<[u32; 16]> = KSpinLock::new([0; 16]);

/// Le PID du processus courant (0 hors d'un thread de Ps).
fn current_pid() -> u32 {
    ps::ethread::current_thread().map_or(0, |thread| thread.pid())
}

/// IntCreateCurIconHandle : un curseur vide dans la table des handles USER,
/// au processus courant ; rend son handle. Un curseur animé n'est pas
/// encore fait (`STATUS_NOT_IMPLEMENTED`, journalisé une fois).
///
/// # Errors
/// `STATUS_INSUFFICIENT_RESOURCES` sans place.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn create_empty(animated: bool) -> Result<u32, NtStatus> {
    if animated {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: an animated cursor: not yet");
        }
        return Err(abi::ntstatus::STATUS_NOT_IMPLEMENTED);
    }
    let owner = ps::ethread::current_thread()
        .and_then(|thread| crate::existing_process_info(thread.process()))
        .map_or(0, |info| info.server);
    let cursor = Arc::new(CurIcon {
        pid: AtomicU32::new(current_pid()),
        current: AtomicBool::new(false),
        data: KSpinLock::new(None),
    });
    // Comme pour un menu, l'entrée désigne l'objet du serveur, que `user32`
    // ne lit pas.
    let handle = crate::handles::alloc(Arc::as_ptr(&cursor) as u32, owner, TYPE_CURSOR)?;
    CURSORS.lock().push((handle, cursor));
    Ok(handle)
}

/// UserGetCurIconObject : le curseur `handle`, s'il existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get(handle: u32) -> Option<Arc<CurIcon>> {
    if handle == 0 {
        return None;
    }
    CURSORS.lock().iter().find(|(at, _)| *at == handle).map(|(_, cursor)| cursor.clone())
}

/// Les pixels de 32 bits du bitmap `handle` (public ou au processus
/// courant), s'il a `width` × `height` pixels au moins.
fn bitmap_pixels(handle: u32, width: u32, height: u32) -> Option<Vec<u32>> {
    let surface = crate::gdi::surface::lock(handle, crate::gdi::dc::current_pid())?;
    let (w, h) = surface.size();
    if w < width || h < height {
        return None;
    }
    let all = surface.raw_pixels()?;
    // Les `width` premières colonnes des `height` premières lignes.
    Some((0..height as usize).flat_map(|y| all[y * w as usize..y * w as usize + width as usize].to_vec()).collect())
}

/// IntSetCursorData : le curseur `handle` reçoit ce que `user32` a fait
/// (`data`), la ressource `resource` du module `module` dont il vient ; ses
/// bitmaps deviennent publics, et le noyau en tire sa forme. Faux pour un
/// curseur qui n'existe pas ou n'est pas au processus, une taille nulle ou
/// trop grande, un masque absent ou trop petit, un curseur animé.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn set_data(handle: u32, module: Option<Vec<u16>>, resource: Option<Resource>, data: &CursorData32) -> bool {
    let Some(cursor) = get(handle) else { return false };
    let pid = current_pid();
    if cursor.pid.load(Ordering::Acquire) != pid || data.flags & cursorf::ACON != 0 {
        return false;
    }
    let (cx, cy) = (data.cx, data.cy);
    if cx == 0 || cy == 0 || cx > MAX_SIDE || cy > MAX_SIDE || data.hbm_mask == 0 {
        return false;
    }
    let mask_height = if data.hbm_color == 0 { 2 * cy } else { cy };
    let Some(mask) = bitmap_pixels(data.hbm_mask, cx, mask_height) else { return false };
    let color = match data.hbm_color {
        0 => None,
        handle => match bitmap_pixels(handle, cx, cy) {
            Some(pixels) => Some(pixels),
            None => return false,
        },
    };
    let alpha = match data.hbm_alpha {
        0 => None,
        handle => bitmap_pixels(handle, cx, cy),
    };
    let hotspot = (i32::from(data.x_hotspot), i32::from(data.y_hotspot));
    let Some(shape) = Shape::from_bitmaps((cx, cy), hotspot, &mask, color.as_deref(), alpha.as_deref()) else {
        return false;
    };
    let bitmaps = [data.hbm_mask, data.hbm_color, data.hbm_alpha];
    for &bitmap in bitmaps.iter().filter(|&&bitmap| bitmap != 0) {
        let _ = crate::gdi::handles::set_owner(bitmap, crate::gdi::handles::OWNER_PUBLIC, 0);
    }
    let flags = data.flags & (cursorf::FROMRESOURCE | cursorf::LRSHARED);
    let previous = cursor.data.lock().replace(Data {
        flags,
        icon: data.rt == RT_ICON,
        size: (cx, cy),
        bitmaps,
        shape: Arc::new(shape),
        module,
        resource,
    });
    if let Some(previous) = previous {
        release_bitmaps(&previous);
    }
    true
}

/// Les bitmaps d'un curseur reviennent au processus courant, qui les
/// supprime.
fn release_bitmaps(data: &Data) {
    let pid = crate::gdi::dc::current_pid();
    for &bitmap in data.bitmaps.iter().filter(|&&bitmap| bitmap != 0) {
        if crate::gdi::handles::set_owner(bitmap, pid, 0).is_ok() {
            crate::gdi::delete_object(bitmap);
        }
    }
}

/// NtUserFindExistingCursorIcon : le curseur (ou l'icône, `icon`) de la
/// ressource `resource` du module `module` que le processus courant a déjà
/// chargé avec LR_SHARED, sinon un curseur du système de cette ressource.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn find_existing(module: &[u16], resource: &Resource, icon: bool) -> Option<u32> {
    let pid = current_pid();
    let cursors = CURSORS.lock();
    let matches = |cursor: &CurIcon| {
        cursor.data.lock().as_ref().is_some_and(|data| {
            data.icon == icon && data.module.as_deref() == Some(module) && data.resource.as_ref() == Some(resource)
        })
    };
    let process = cursors.iter().find(|(_, cursor)| {
        cursor.pid.load(Ordering::Acquire) == pid && cursor.flags() & cursorf::LRSHARED != 0 && matches(cursor)
    });
    let system = || cursors.iter().find(|(_, cursor)| cursor.pid.load(Ordering::Acquire) == 0 && matches(cursor));
    process.or_else(system).map(|(handle, _)| *handle)
}

/// IntDestroyCurIconObject : le curseur `handle` quitte la table, ses
/// bitmaps supprimés. Sans `force`, comme NtUserDestroyCursor : un curseur
/// du système reste (vrai), celui d'un autre processus ou le curseur d'un
/// thread aussi (faux), un curseur LR_SHARED reste (vrai).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy(handle: u32, force: bool) -> bool {
    let Some(cursor) = get(handle) else { return false };
    let owner = cursor.pid.load(Ordering::Acquire);
    if !force {
        if owner == 0 {
            return true;
        }
        if owner != current_pid() || cursor.current.load(Ordering::Acquire) {
            return false;
        }
        if cursor.flags() & cursorf::LRSHARED != 0 {
            return true;
        }
    }
    CURSORS.lock().retain(|(at, _)| *at != handle);
    let _ = crate::handles::free(handle);
    let data = cursor.data.lock().take();
    if let Some(data) = data {
        release_bitmaps(&data);
    }
    true
}

/// NtUserSetSystemCursor : le curseur `handle` devient le curseur du système
/// `id` (OCR_*) s'il n'y en a pas encore : il n'est plus à aucun processus.
/// Faux pour un identifiant inconnu, un curseur qui n'existe pas, une place
/// déjà prise (le curseur n'est pas copié, comme ReactOS).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_system_cursor(handle: u32, id: u32) -> bool {
    let Some(index) = OCR_CURSORS.iter().position(|&ocr| ocr == id) else { return false };
    let Some(cursor) = get(handle) else { return false };
    let mut system = SYSTEM.lock();
    if system[index] != 0 {
        return false;
    }
    system[index] = handle;
    cursor.pid.store(0, Ordering::Release);
    if let Some(data) = cursor.data.lock().as_mut() {
        data.flags |= cursorf::GLOBAL;
    }
    crate::handles::set_process(handle, 0);
    true
}

/// Le curseur du système `id` (OCR_*), s'il est posé.
pub fn system_cursor(id: u32) -> Option<u32> {
    let index = OCR_CURSORS.iter().position(|&ocr| ocr == id)?;
    Some(SYSTEM.lock()[index]).filter(|&handle| handle != 0)
}

/// `user32` a été prié de charger les curseurs du système.
static SYSTEM_LOADING: AtomicBool = AtomicBool::new(false);

/// co_IntLoadDefaultCursors, une fois : le thread courant, qui met un bureau
/// à l'écran pour la première fois, fait charger à `user32` les curseurs du
/// système (`crate::callback::load_default_cursors`) ; la flèche devient son
/// curseur. Journalisé une fois.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn load_system_cursors() {
    if SYSTEM_LOADING.swap(true, Ordering::AcqRel) {
        return;
    }
    match crate::callback::load_default_cursors() {
        Ok(arrow) => {
            let count = SYSTEM.lock().iter().filter(|&&handle| handle != 0).count();
            log::info!("win32k: user32 loaded {count} of 16 system cursors, the arrow {arrow:#x}");
        }
        Err(status) => log::warn!("win32k: the system cursors are not loaded: {status:?}"),
    }
}

/// Le thread (son adresse du serveur) dont l'écran montre le curseur : celui
/// de la fenêtre sous le pointeur, ou qui a la capture.
static POINTER_THREAD: AtomicU32 = AtomicU32::new(0);

/// L'écran montre le curseur `handle` (aucun : rien ; un curseur sans
/// données : la flèche).
fn show(handle: u32) {
    let image = match handle {
        0 => crate::display::CursorImage::Hidden,
        handle => match get(handle).and_then(|cursor| cursor.shape()) {
            Some(shape) => crate::display::CursorImage::Shape(shape),
            None => crate::display::CursorImage::Arrow,
        },
    };
    crate::display::set_cursor_image(image);
}

/// UserSetCursor : `handle` (0 : aucun) devient le curseur du thread
/// `thread`, et celui de l'écran si le pointeur est sur une de ses fenêtres.
/// Rend l'ancien.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_cursor(thread: &ThreadInfo, handle: u32) -> u32 {
    let old = thread.cursor.swap(handle, Ordering::AcqRel);
    if old != handle {
        if let Some(old) = get(old) {
            old.current.store(false, Ordering::Release);
        }
        if let Some(new) = get(handle) {
            new.current.store(true, Ordering::Release);
        }
    }
    if POINTER_THREAD.load(Ordering::Acquire) == thread.server {
        show(handle);
    }
    old
}

/// Le pointeur est passé sur une fenêtre du thread `server` (son adresse du
/// serveur) : l'écran montre son curseur, s'il en a un, ou la flèche du
/// système.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn pointer_over(server: u32) {
    if POINTER_THREAD.swap(server, Ordering::AcqRel) == server {
        return;
    }
    let handle = crate::gui::thread_info_of(server)
        .map(|thread| thread.cursor.load(Ordering::Acquire))
        .filter(|&handle| handle != 0)
        .or_else(|| system_cursor(OCR_NORMAL))
        .unwrap_or(0);
    show(handle);
}

/// IntSystemSetCursor : le curseur `handle` devient celui du thread courant.
fn system_set_cursor(handle: Option<u32>) {
    let Some(handle) = handle else { return };
    if let Some(thread) = ps::ethread::current_thread().and_then(|thread| thread.win32_thread()) {
        set_cursor(&crate::gui::thread_info(thread), handle);
    }
}

/// DefWindowProc de WM_SETCURSOR (`wParam` la fenêtre sous le pointeur,
/// `lParam` le code de l'endroit et le message de la souris) : une fenêtre
/// fille laisse d'abord son parent choisir, sauf sur un bord ; dans la zone
/// cliente, le curseur de la classe (FALSE : l'application peut faire
/// mieux) ; sur un bord ou un coin d'une fenêtre qui n'est pas agrandie, la
/// flèche double du système (TRUE) ; sur un code d'erreur, rien ; ailleurs,
/// la flèche (TRUE).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système. Envoie un message au parent.
pub fn def_set_cursor(window: &Arc<Window>, wparam: u32, lparam: u32) -> u32 {
    let hit = lparam & 0xFFFF;
    let style = window.state().style;
    if style & WS_CHILD != 0 && !(HTLEFT..=HTBOTTOMRIGHT).contains(&hit) {
        let parent = crate::window::get(window.state().parent).filter(|parent| !parent.is_desktop_window());
        if let Some(parent) = parent {
            if crate::window::send_message(&parent, WM_SETCURSOR, wparam, LParam::Value(lparam)).unwrap_or(0) != 0 {
                return 1;
            }
        }
    }
    if window.handle != wparam {
        return 0;
    }
    let maximized = style & WS_MAXIMIZE != 0;
    let size = |id| {
        if maximized {
            None
        } else {
            system_cursor(id)
        }
    };
    match hit {
        HTCLIENT => {
            let cursor = window.class.as_ref().map(|class| class.info.cursor).filter(|&cursor| get(cursor).is_some());
            system_set_cursor(cursor);
            0
        }
        HTERROR => 0,
        HTLEFT | HTRIGHT => set_size_cursor(size(OCR_SIZEWE)),
        HTTOP | HTBOTTOM => set_size_cursor(size(OCR_SIZENS)),
        HTTOPLEFT | HTBOTTOMRIGHT => set_size_cursor(size(OCR_SIZENWSE)),
        HTTOPRIGHT | HTBOTTOMLEFT => set_size_cursor(size(OCR_SIZENESW)),
        _ => {
            system_set_cursor(system_cursor(OCR_NORMAL));
            1
        }
    }
}

/// La flèche double `cursor` (aucune pour une fenêtre agrandie : la flèche)
/// devient le curseur du thread ; TRUE.
fn set_size_cursor(cursor: Option<u32>) -> u32 {
    system_set_cursor(cursor.or_else(|| system_cursor(OCR_NORMAL)));
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHITE: u32 = 0x00FF_FFFF;
    const BLACK: u32 = 0;

    #[test]
    fn a_monochrome_cursor_has_its_xor_mask_under_its_and_mask() {
        // 2 × 1: AND over XOR, the four combinations over two pixels each.
        let mask = [WHITE, BLACK, /* XOR */ BLACK, BLACK];
        let shape = Shape::from_bitmaps((2, 1), (1, 0), &mask, None, None).expect("enough rows");
        assert_eq!(shape.pixels, [Pixel::Transparent, Pixel::Opaque(ColorRef::rgb(0, 0, 0))]);
        let mask = [WHITE, BLACK, /* XOR */ WHITE, WHITE];
        let shape = Shape::from_bitmaps((2, 1), (0, 0), &mask, None, None).expect("enough rows");
        assert_eq!(
            shape.pixels,
            [Pixel::Xor(ColorRef::rgb(255, 255, 255)), Pixel::Opaque(ColorRef::rgb(255, 255, 255))]
        );
        assert_eq!(Shape::from_bitmaps((2, 1), (0, 0), &mask[..3], None, None), None, "the XOR mask is short");
    }

    #[test]
    fn a_color_cursor_takes_its_colors_where_the_mask_is_black() {
        let red = 0x00FF_0000; // BGRX: red in the third byte.
        let shape = Shape::from_bitmaps((2, 1), (0, 0), &[BLACK, WHITE], Some(&[red, BLACK]), None).expect("valid");
        assert_eq!(shape.pixels, [Pixel::Opaque(ColorRef::rgb(255, 0, 0)), Pixel::Transparent]);
        let alpha = [0x8000_00FF, 0x0000_0000];
        let shape =
            Shape::from_bitmaps((2, 1), (0, 0), &[BLACK, BLACK], Some(&[red, red]), Some(&alpha)).expect("valid");
        assert_eq!(
            shape.pixels,
            [Pixel::Blend(ColorRef::rgb(0, 0, 255), 0x80), Pixel::Blend(ColorRef::rgb(0, 0, 0), 0)]
        );
    }

    #[test]
    fn pixels_over_the_screen() {
        let screen = ColorRef::rgb(10, 20, 30);
        assert_eq!(Pixel::Transparent.over(screen), screen);
        assert_eq!(Pixel::Opaque(ColorRef::rgb(1, 2, 3)).over(screen), ColorRef::rgb(1, 2, 3));
        assert_eq!(Pixel::Xor(ColorRef::rgb(255, 255, 255)).over(screen), ColorRef::rgb(245, 235, 225), "inverted");
        assert_eq!(Pixel::Blend(ColorRef::rgb(255, 255, 255), 255).over(screen), ColorRef::rgb(255, 255, 255));
        assert_eq!(Pixel::Blend(ColorRef::rgb(255, 255, 255), 0).over(screen), screen);
        assert_eq!(
            Pixel::Blend(ColorRef::rgb(0, 0, 0), 128).over(ColorRef::rgb(255, 255, 255)),
            ColorRef::rgb(127, 127, 127)
        );
    }

    #[test]
    fn the_built_in_arrow_points_from_its_corner() {
        let arrow = Shape::arrow();
        assert_eq!((arrow.width, arrow.height, arrow.hotspot), (12, 19, (0, 0)));
        assert_eq!(arrow.pixels.len(), 12 * 19);
        assert_eq!(arrow.pixels[0], Pixel::Opaque(ColorRef::rgb(0, 0, 0)));
        assert_eq!(arrow.pixels[11], Pixel::Transparent);
    }
}
