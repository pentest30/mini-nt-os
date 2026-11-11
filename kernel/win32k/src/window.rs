//! Les fenêtres (02 §7.2) : la fenêtre de chaque bureau, que ReactOS crée
//! avec lui (IntCreateDesktop, par IntCreateWindow), et celles que crée
//! NtUserCreateWindowEx ([`create_window`]).
//!
//! Une fenêtre a son `WND` dans le tas de son bureau, où `user32` le lit par
//! son handle ([`crate::handles`], `TYPE_WINDOW`) ; win32k garde à côté ce
//! qui change (styles, rectangles, liens, région à mettre à jour) et réécrit
//! le `WND` à chaque changement. Les liens (parent, propriétaire, premier
//! enfant, voisines dans l'ordre Z) sont des handles, que [`get`] résout ;
//! le `WND` en porte les adresses du serveur. Le `CLS` de la classe est dans
//! le même tas (`Class::image_on`), comme le nom de la fenêtre.
//!
//! La fenêtre du bureau a sa procédure dans win32k
//! (`WNDS_SERVERSIDEWINDOWPROC`), comme DesktopWindowProc : WM_PAINT valide
//! la région à mettre à jour (BeginPaint, qui envoie d'abord
//! WM_ERASEBKGND), puis EndPaint ; WM_ERASEBKGND peint le fond du bureau
//! (IntPaintDesktop). Montrer la fenêtre l'invalide entière, puis la met à
//! jour aussitôt ([`show_desktop_window`]).
//!
//! Un message envoyé à une fenêtre du thread courant dont la procédure est
//! dans le client y va par un rappel ([`send_message`],
//! `callback::window_proc`), son `lParam` emballé comme PackParam : un
//! `CREATESTRUCT` suivi de ses chaînes pour WM_NCCREATE et WM_CREATE, un
//! `RECT` pour WM_NCCALCSIZE. Pendant le rappel, le `CLIENTINFO` du thread
//! désigne la fenêtre (`CallbackWnd`, IntSetTebWndCallback).
//!
//! Les fenêtres sœurs sont dans l'ordre Z ([`link`] : en haut, en bas, au
//! premier plan avec `WS_EX_TOPMOST`, après une sœur) ; SetWindowPos les
//! déplace ([`crate::winpos`]). Une fenêtre recouvrante placée par défaut
//! prend sa place et sa taille sur le moniteur ([`fix_coordinates`],
//! [`crate::monitor`]).
//!
//! Une fenêtre créée visible est montrée (`crate::winpos::show_window`) ; son
//! cadre se peint dans le noyau (`crate::paint`), pas encore sa zone cliente.
//!
//! Une fenêtre appartient à son thread de sa création à sa destruction
//! (DestroyWindow, ou la fin du thread : `crate::destroy`), qui rend son
//! handle ([`release`]) ; son `WND` reste dans le tas tant qu'une référence
//! du noyau la tient. Une création qui échoue la détruit.
//!
//! Pas encore : une fenêtre créée réduite ou agrandie (journalisé), la
//! fenêtre des messages (`HWND_MESSAGE`), les crochets, le fond d'écran, la
//! mise en page de droite à gauche.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::peb32::Peb32;
use abi::process_parameters::RtlUserProcessParameters32;
use abi::teb32::Teb32;
use abi::user::{
    CallbackWnd32, ClientInfo32, Cls32, CreateStructW32, DeskInfoHead32, LargeUnicodeString32, MinMaxInfo32, Msg32,
    Rect32, WindowProcArguments32, Wnd32, CSF_ANSIPROC, CSF_SERVERSIDEPROC, CSF_SYSTEMCLASS, CS_DBLCLKS, CW_USEDEFAULT,
    DLGWINDOWEXTRA, FNID_BUTTON, FNID_DESKTOP, FNID_DESTROY, FNID_DIALOG, FNID_GHOST, FNID_MENU, GWLP_HINSTANCE,
    GWLP_HWNDPARENT, GWLP_ID, GWLP_USERDATA, GWLP_WNDPROC, GWL_EXSTYLE, GWL_STYLE, HRGN_WINDOW, HWND_BOTTOM,
    HWND_MESSAGE, HWND_NOTOPMOST, HWND_TOP, HWND_TOPMOST, SIZE_MAXIMIZED, SIZE_MINIMIZED, SIZE_RESTORED,
    STARTF_USEPOSITION, STARTF_USESIZE, SW_SHOW, SW_SHOWMINIMIZED, TYPE_WINDOW, WC_DESKTOP, WINVER_WIN2K, WINVER_WIN31,
    WINVER_WINNT4, WM_CREATE, WM_ERASEBKGND, WM_GETMINMAXINFO, WM_MOVE, WM_NCCALCSIZE, WM_NCCREATE, WM_NCPAINT,
    WM_PAINT, WM_PARENTNOTIFY, WM_SIZE, WM_SYSTIMER, WM_TIMER, WNDS2_WIN31COMPAT, WNDS2_WIN40COMPAT, WNDS2_WIN50COMPAT,
    WNDS2_WMCREATEMSGPROCESSED, WNDS2_WMPAINTSENT, WNDS_ANSICREATOR, WNDS_ANSIWINDOWPROC, WNDS_DIALOGWINDOW,
    WNDS_ERASEBACKGROUND, WNDS_MAXIMIZESTOMONITOR, WNDS_PAINTNOTPROCESSED, WNDS_SENDERASEBACKGROUND,
    WNDS_SENDSIZEMOVEMSGS, WNDS_SERVERSIDEWINDOWPROC, WND_UNICODE, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN,
    WS_CLIPSIBLINGS, WS_DLGFRAME, WS_EX_DLGMODALFRAME, WS_EX_NOPARENTNOTIFY, WS_EX_SETANSICREATOR, WS_EX_STATICEDGE,
    WS_EX_TOPMOST, WS_EX_WINDOWEDGE, WS_MAXIMIZE, WS_MINIMIZE, WS_POPUP, WS_THICKFRAME, WS_VISIBLE,
};
use abi::winerror::{
    ERROR_CANNOT_FIND_WND_CLASS, ERROR_INVALID_MENU_HANDLE, ERROR_INVALID_WINDOW_HANDLE, ERROR_NOT_ENOUGH_MEMORY,
    ERROR_TLW_WITH_WSCHILD,
};
use hal::sync::KSpinLock;
use ke::usermem::UserPtr;
use ob::Object;

use crate::class::{Class, ClassName};
use crate::desktop::{Desktop, DesktopHeap};
use crate::gdi::dib::Rect;
use crate::gdi::region::Region;

/// COLOR_BACKGROUND : le pinceau de la classe du bureau, une couleur système
/// plus un.
const COLOR_BACKGROUND: u32 = 1;
/// Les octets de plus de la fenêtre du bureau : le PID et le TID que
/// DesktopWindowProc y range (DT_GWL_PROCESSID, DT_GWL_THREADID).
const DESKTOP_WND_EXTRA: u32 = 8;

/// Ce qui change d'une fenêtre.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowState {
    pub style: u32,
    pub ex_style: u32,
    /// WNDS_*.
    pub state: u32,
    /// WNDS2_*.
    pub state2: u32,
    pub fnid: u32,
    pub wnd_proc: u32,
    pub unicode: bool,
    pub module: u32,
    /// L'identifiant d'une fenêtre fille (`IDMenu`).
    pub id_menu: u32,
    /// Sa barre de menus (SetMenu) ; 0 sans barre.
    pub menu: u32,
    /// Ses liens, des handles (0 : aucun).
    pub parent: u32,
    pub owner: u32,
    pub child: u32,
    pub next: u32,
    pub prev: u32,
    /// Son nom dans le tas, s'il en a un.
    pub name: Option<Name>,
    pub window: Rect,
    pub client: Rect,
    /// La région à mettre à jour, dans la zone cliente, depuis son coin
    /// (vide : rien).
    pub update: Region,
    /// Le rectangle de la peinture en cours (BeginPaint, EndPaint).
    pub painting: Rect,
    /// La valeur de l'application (`dwUserData`, GWLP_USERDATA).
    pub user_data: u32,
    /// Le DIALOGINFO de `user32` d'un dialogue (`DialogPointer`,
    /// SetDialogPointer), une adresse du client.
    pub dialog_pointer: u32,
    /// La liste de ses propriétés dans le tas du bureau (`PropListHead` :
    /// la première, la dernière, adresses du serveur ; `PropListItems`) ;
    /// `None` sans propriété.
    pub prop_list: Option<(u32, u32, u32)>,
    /// Ses barres de défilement, dès qu'on lui en parle (`crate::scroll`),
    /// et la place de leur `SBINFO` dans le tas (`pSBInfo`).
    pub scroll: Option<crate::scroll::ScrollBars>,
}

impl WindowState {
    /// InvalidateRect(…, `rect`, `erase`) : la région à mettre à jour
    /// s'étend à `rect` (dans la zone cliente), et le fond sera effacé.
    pub fn invalidate(&mut self, rect: Rect, erase: bool) {
        let rect = rect.intersect(&self.client_area());
        if rect.is_empty() {
            return;
        }
        self.update.union_rect(rect);
        if erase {
            self.state |= WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND;
        }
    }

    /// Sa zone cliente, depuis son coin.
    pub fn client_area(&self) -> Rect {
        Rect::new(0, 0, self.client.right - self.client.left, self.client.bottom - self.client.top)
    }

    /// BeginPaint : la région à mettre à jour est validée et devient le
    /// rectangle de la peinture ; rend s'il faut d'abord effacer le fond.
    pub fn begin_paint(&mut self) -> bool {
        self.painting = core::mem::take(&mut self.update).bounds();
        let erase = self.state & WNDS_SENDERASEBACKGROUND != 0;
        self.state &= !(WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND);
        erase
    }
}

/// Le nom d'une fenêtre dans le tas de son bureau : la position de la
/// chaîne, sa longueur en octets (sans le NUL final) et la place qu'elle a
/// (NUL compris).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Name {
    pub at: u32,
    pub length: u32,
    pub capacity: u32,
}

/// Une fenêtre.
pub struct Window {
    pub handle: u32,
    /// Le tas de son bureau.
    pub heap: Arc<DesktopHeap>,
    /// La position de son `WND` dans le tas, et sa taille (octets de plus
    /// compris).
    pub wnd: u32,
    wnd_size: u32,
    /// La position du `CLS` de sa classe.
    pub cls: u32,
    /// Sa classe ; `None` pour la fenêtre du bureau, dont le `CLS` est à elle.
    pub class: Option<Arc<Class>>,
    /// L'adresse du serveur du `THREADINFO` de son thread ; 0 pour la
    /// fenêtre du bureau.
    pub pti: u32,
    /// Le nom du bureau, pour la fenêtre d'un bureau.
    pub desktop_name: Option<String>,
    state: KSpinLock<WindowState>,
    /// Sa destruction a commencé (co_UserDestroyWindow) : une seconde
    /// demande n'en refait rien.
    destroying: AtomicBool,
    /// Détruite : son handle est rendu, [`get`] ne la trouve plus.
    freed: AtomicBool,
}

impl Window {
    /// Ce qui change d'elle.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn state(&self) -> WindowState {
        self.state.lock().clone()
    }

    /// L'adresse du serveur de son `WND`.
    pub fn server_address(&self) -> u32 {
        self.heap.server_address(self.wnd)
    }

    /// C'est la fenêtre d'un bureau.
    pub fn is_desktop_window(&self) -> bool {
        self.desktop_name.is_some()
    }

    /// Elle n'est pas détruite.
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn is_alive(&self) -> bool {
        !self.freed.load(Ordering::Acquire)
    }

    /// Marque le début de sa destruction ; rend `false` si elle avait déjà
    /// commencé.
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn begin_destroy(&self) -> bool {
        !self.destroying.swap(true, Ordering::AcqRel)
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if self.is_alive() {
            WINDOWS.lock().remove(&self.handle);
            let _ = crate::handles::free(self.handle);
        }
        self.heap.free(self.wnd, self.wnd_size);
        let (name, scroll) = {
            let state = self.state.lock();
            (state.name, state.scroll)
        };
        if let Some(name) = name {
            self.heap.free(name.at, name.capacity);
        }
        if let Some(scroll) = scroll {
            self.heap.free(scroll.at, size_of::<abi::user::SbInfo32>() as u32);
        }
        if self.class.is_none() {
            self.heap.free(self.cls, size_of::<Cls32>() as u32);
        }
    }
}

/// Les fenêtres vivantes, par handle.
static WINDOWS: KSpinLock<BTreeMap<u32, Weak<Window>>> = KSpinLock::new(BTreeMap::new());

/// UserDeleteObject, la fin de co_UserFreeWindow : `window` est détruite ;
/// [`get`] ne la trouve plus, son handle est rendu à la table (que `user32`
/// lit). Son `WND`, son nom et le `CLS` d'un bureau restent dans le tas
/// jusqu'à sa dernière référence. Une seconde fois, rien.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub(crate) fn release(window: &Window) {
    if window.freed.swap(true, Ordering::AcqRel) {
        return;
    }
    WINDOWS.lock().remove(&window.handle);
    let _ = crate::handles::free(window.handle);
}

/// Les fenêtres vivantes de `pti` (l'adresse du serveur d'un `THREADINFO`),
/// d'après la table des fenêtres.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn windows_of(pti: u32) -> Vec<Arc<Window>> {
    let windows: Vec<Arc<Window>> = WINDOWS.lock().values().filter_map(Weak::upgrade).collect();
    windows.into_iter().filter(|window| window.pti == pti && window.is_alive()).collect()
}

/// UserGetWindowObject : la fenêtre de handle `handle`, si elle vit ; un
/// handle de génération 0 ou `0xFFFF` vaut pour celle de son entrée.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get(handle: u32) -> Option<Arc<Window>> {
    let windows = WINDOWS.lock();
    if let Some(window) = windows.get(&handle).and_then(Weak::upgrade) {
        return Some(window);
    }
    if !matches!(handle >> 16, 0 | 0xFFFF) {
        return None;
    }
    windows.iter().find(|(&other, _)| other & 0xFFFF == handle & 0xFFFF).and_then(|(_, window)| window.upgrade())
}

/// L'adresse du serveur du `WND` de la fenêtre `handle` ; 0 sans fenêtre.
fn server_address_of(handle: u32) -> u32 {
    if handle == 0 {
        return 0;
    }
    get(handle).map_or(0, |window| window.server_address())
}

fn rect32(rect: Rect) -> Rect32 {
    Rect32 { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }
}

/// Le `WND` de `window`, de l'état `state`.
fn wnd(window: &Window, state: &WindowState) -> Wnd32 {
    let heap = &window.heap;
    let self_address = window.server_address();
    let name = state.name.map_or(LargeUnicodeString32::default(), |name| LargeUnicodeString32 {
        length: name.length,
        maximum_length_ansi: name.capacity,
        buffer: heap.server_address(name.at),
    });
    Wnd32 {
        handle: window.handle,
        pti: window.pti,
        rpdesk: heap.server_base,
        self_address,
        state: state.state,
        state2: state.state2,
        ex_style: state.ex_style,
        style: state.style,
        module: state.module,
        fnid: state.fnid,
        spwnd_next: server_address_of(state.next),
        spwnd_prev: server_address_of(state.prev),
        spwnd_parent: server_address_of(state.parent),
        spwnd_child: server_address_of(state.child),
        spwnd_owner: server_address_of(state.owner),
        rc_window: rect32(state.window),
        rc_client: rect32(state.client),
        wnd_proc: state.wnd_proc,
        pcls: heap.server_address(window.cls),
        // A child's identifier, the bar of any other window (GetMenu).
        id_menu: if state.style & (WS_CHILD | WS_POPUP) == WS_CHILD { state.id_menu } else { state.menu },
        name,
        cb_wnd_extra: window.wnd_size - size_of::<Wnd32>() as u32,
        spwnd_last_active: self_address,
        icon_pos: [-1, -1],
        max_pos: [-1, -1],
        bits: if state.unicode { WND_UNICODE } else { 0 },
        // No GDI region objects yet: HRGN_WINDOW says there is an update
        // region, which is all user32 asks (GetUpdateRect, UpdateWindow).
        hrgn_update: if state.update.is_empty() { 0 } else { HRGN_WINDOW },
        user_data: state.user_data,
        dialog_pointer: state.dialog_pointer,
        prop_list_head: {
            // An empty list points at itself.
            let head = self_address + offset_of!(Wnd32, prop_list_head) as u32;
            let (flink, blink, _) = state.prop_list.unwrap_or((head, head, 0));
            abi::user::ListEntry32 { flink, blink }
        },
        prop_list_items: state.prop_list.map_or(0, |(_, _, count)| count),
        sb_info: state.scroll.map_or(0, |bars| heap.server_address(bars.at)),
        ..Wnd32::default()
    }
}

/// SetDialogPointer (HWNDPARAM_ROUTINE_SETDIALOGPOINTER) : le DIALOGINFO
/// `pointer` de `user32` pour `window`, que `user32` relit dans son `WND`
/// (GETDLGINFO) ; sans lui, CreateDialog détruit le dialogue qu'il vient de
/// créer. Non nul, la fenêtre devient un dialogue (`WNDS_DIALOGWINDOW`, et
/// FNID_DIALOG si elle n'a pas de FNID) ; nul, elle cesse de l'être et sa
/// FNID se marque détruite. Rien, comme ReactOS, pour une fenêtre d'un
/// autre processus que `process`, à procédure dans win32k, ou de moins de
/// DLGWINDOWEXTRA octets de plus ; rend si elle a changé.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_dialog_pointer(window: &Window, process: u32, pointer: u32) -> bool {
    let extra = window.wnd_size - size_of::<Wnd32>() as u32;
    if crate::gui::process_id_of(window.pti) != Some(process)
        || extra < DLGWINDOWEXTRA
        || window.state().state & WNDS_SERVERSIDEWINDOWPROC != 0
    {
        return false;
    }
    update(window, |state| {
        state.dialog_pointer = pointer;
        if pointer != 0 {
            if state.fnid == 0 {
                state.fnid = FNID_DIALOG;
            }
            state.state |= WNDS_DIALOGWINDOW;
        } else {
            state.fnid |= FNID_DESTROY;
            state.state &= !WNDS_DIALOGWINDOW;
        }
    });
    true
}

/// Réécrit le `WND` de `window`.
fn write(window: &Window) -> Result<(), NtStatus> {
    let state = window.state();
    window.heap.section.write_kernel(u64::from(window.wnd), wnd(window, &state).as_bytes())
}

/// La place, dans les octets de plus d'une fenêtre qui en a `extra`, de
/// l'index `index` de SetWindowLong (un LONG) ; `None` au-delà.
pub fn extra_offset(extra: u32, index: i32) -> Option<u32> {
    let index = u32::try_from(index).ok()?;
    (index.checked_add(4)? <= extra).then_some(index)
}

/// Le LONG `index` des octets de plus de `window` (GetWindowLong d'un
/// index positif), s'il y est.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn extra_long(window: &Window, index: i32) -> Option<u32> {
    let extra = window.wnd_size.checked_sub(size_of::<Wnd32>() as u32)?;
    let at = u64::from(window.wnd) + size_of::<Wnd32>() as u64 + u64::from(extra_offset(extra, index)?);
    let mut value = [0u8; 4];
    window.heap.section.read_kernel(at, &mut value).ok()?;
    Some(u32::from_le_bytes(value))
}

/// NtUserQueryWindow : ce que l'index `index` (`abi::user::query_window`)
/// demande de `window` :
/// - le PID et le TID de son thread ; pour une fenêtre console de `csrss`
///   (sa classe est celle que `consrv` a donnée,
///   `crate::console::console_window_class`), ceux du processus qui mène la
///   console, que `consrv` met dans ses octets de plus (0 et 4) ;
/// - la fenêtre active et celle qui a le clavier dans la file de son thread ;
/// - le PID de son thread (`REAL_ID`) ; si sa file est au premier plan ;
/// - 0 pour le reste : une fenêtre qui ne répond plus (MsqIsHung : l'âge du
///   dernier message lu n'est pas encore suivi), et les fenêtres et
///   contextes de l'IME (pas d'IME).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn query(window: &Window, index: u32) -> u32 {
    use abi::user::query_window;
    let thread = crate::gui::thread_info_of(window.pti);
    let console_leader = |at: i32| {
        let csrss = thread.as_ref().is_some_and(|thread| thread.ti_flags & abi::user::TIF_CSRSSTHREAD != 0);
        let console = window.class.as_ref().is_some_and(|class| {
            let atom = crate::console::console_window_class();
            atom != 0 && class.atom == atom
        });
        if csrss && console {
            extra_long(window, at)
        } else {
            None
        }
    };
    let process = || crate::gui::process_id_of(window.pti).unwrap_or(0);
    let queue = |pick: fn(&crate::queue::QueueState) -> u32| {
        thread.as_ref().map_or(0, |thread| thread.queue.with(|state| pick(state)).0)
    };
    match index {
        query_window::UNIQUE_PROCESS_ID => console_leader(0).unwrap_or_else(process),
        query_window::UNIQUE_THREAD_ID => {
            console_leader(4).unwrap_or_else(|| crate::gui::thread_of_server_address(window.pti).unwrap_or(0))
        }
        query_window::ACTIVE => queue(|state| state.active),
        query_window::FOCUS => queue(|state| state.focus),
        query_window::REAL_ID => process(),
        query_window::FOREGROUND => {
            let foreground = crate::input::foreground();
            u32::from(foreground.is_some_and(|foreground| foreground.server == window.pti && window.pti != 0))
        }
        _ => 0,
    }
}

/// co_IntSetWindowLongPtr, pour un index négatif que le noyau fait : la
/// valeur de l'application (GWLP_USERDATA), l'identifiant (GWLP_ID) ou
/// l'instance (GWLP_HINSTANCE) devient `value` ; rend l'ancienne. `None`
/// pour un autre index.
pub fn apply_long(state: &mut WindowState, index: i32, value: u32) -> Option<u32> {
    let field = match index {
        GWLP_USERDATA => &mut state.user_data,
        GWLP_ID => &mut state.id_menu,
        GWLP_HINSTANCE => &mut state.module,
        _ => return None,
    };
    Some(core::mem::replace(field, value))
}

/// co_IntSetWindowLongPtr (NtUserSetWindowLong) : le LONG `index` de
/// `window` devient `value` ; rend l'ancien. Un index positif est une place
/// dans ses octets de plus (`cbWndExtra`, après le `WND`, où `user32` les lit
/// lui-même) ; un index négatif, l'un de ceux de [`apply_long`].
///
/// # Errors
/// L'erreur de Win32 : `ERROR_INVALID_INDEX` pour une place au-delà des
/// octets de plus ou un index inconnu ; `ERROR_CALL_NOT_IMPLEMENTED` pour
/// GWL_STYLE, GWL_EXSTYLE, GWLP_WNDPROC et GWLP_HWNDPARENT (pas encore,
/// journalisé une fois).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_long(window: &Window, index: i32, value: u32) -> Result<u32, u32> {
    if index >= 0 {
        let extra = window.wnd_size - size_of::<Wnd32>() as u32;
        let at = extra_offset(extra, index).ok_or(abi::winerror::ERROR_INVALID_INDEX)?;
        let at = u64::from(window.wnd) + size_of::<Wnd32>() as u64 + u64::from(at);
        let mut old = [0u8; 4];
        let section = &window.heap.section;
        section
            .read_kernel(at, &mut old)
            .and_then(|()| section.write_kernel(at, &value.to_le_bytes()))
            .map_err(abi::winerror::dos_error)?;
        return Ok(u32::from_le_bytes(old));
    }
    if matches!(index, GWL_STYLE | GWL_EXSTYLE | GWLP_WNDPROC | GWLP_HWNDPARENT) {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: SetWindowLong of the style, the procedure or the parent ({index}): not yet");
        }
        return Err(abi::winerror::ERROR_CALL_NOT_IMPLEMENTED);
    }
    let mut old = None;
    change(window, |state| old = apply_long(state, index, value));
    old.ok_or(abi::winerror::ERROR_INVALID_INDEX)
}

/// Change ce qui change de `window` par `change`, puis réécrit son `WND`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn change(window: &Window, change: impl FnOnce(&mut WindowState)) -> WindowState {
    update(window, change)
}

/// Change ce qui change de `window` par `change`, puis réécrit son `WND`.
/// Une fenêtre qui se met à avoir quelque chose à peindre, ou cesse de
/// l'avoir, compte pour son thread (`cPaintsReady`, [`crate::paint::is_dirty`]).
/// Une propriété d'une fenêtre (SetProp ; une propriété du système : les
/// icônes de WM_SETICON).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Property {
    hwnd: u32,
    atom: u16,
    data: u32,
    system: bool,
}

/// Les propriétés des fenêtres, l'atome remplacé à la seconde pose. Leur
/// copie dans le tas partagé (`crate::shared::alloc`, UserHeapAlloc : des
/// `PROPERTY` chaînées depuis le `WND`), que `user32` lit lui-même par
/// `ulSharedDelta` (GetProp, WM_GETICON) : ses blocs, par fenêtre
/// ([`publish_properties`]).
static PROPERTIES: hal::sync::KSpinLock<alloc::vec::Vec<Property>> = hal::sync::KSpinLock::new(alloc::vec::Vec::new());
static PROPERTY_BLOCKS: hal::sync::KSpinLock<alloc::vec::Vec<(u32, alloc::vec::Vec<u32>)>> =
    hal::sync::KSpinLock::new(alloc::vec::Vec::new());

/// Les blocs de `PROPERTY` de la fenêtre `hwnd` retournent au tas partagé.
fn free_property_blocks(hwnd: u32) {
    let blocks = {
        let mut all = PROPERTY_BLOCKS.lock();
        all.iter().position(|(window, _)| *window == hwnd).map(|at| all.swap_remove(at))
    };
    if let Some((_, offsets)) = blocks {
        for offset in offsets {
            crate::shared::free(offset, size_of::<abi::user::Property32>() as u32);
        }
    }
}

/// La chaîne des `PROPERTY` de `properties` dans des blocs du tas d'adresses
/// du serveur `blocks`, depuis la tête de liste `head` (l'adresse du
/// serveur de `PropListHead`) : chaque entrée, avec ses voisines ; la
/// dernière revient à la tête, comme la première.
pub fn property_chain(head: u32, blocks: &[u32], properties: &[(u16, u32, bool)]) -> Vec<abi::user::Property32> {
    let count = blocks.len().min(properties.len());
    (0..count)
        .map(|i| {
            let (atom, data, system) = properties[i];
            abi::user::Property32 {
                entry: abi::user::ListEntry32 {
                    flink: if i + 1 < count { blocks[i + 1] } else { head },
                    blink: if i > 0 { blocks[i - 1] } else { head },
                },
                data,
                atom,
                fs: if system { abi::user::PROPERTY_FLAG_SYSTEM } else { 0 },
            }
        })
        .collect()
}

/// Les propriétés de `window` réécrites dans le tas partagé, où `user32` les
/// lit : de nouveaux blocs, chaînés depuis son `WND`. Sans place, la liste
/// reste vide (journalisé une fois).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
fn publish_properties(window: &Window) {
    free_property_blocks(window.handle);
    let properties: Vec<(u16, u32, bool)> = PROPERTIES
        .lock()
        .iter()
        .filter(|property| property.hwnd == window.handle)
        .map(|property| (property.atom, property.data, property.system))
        .collect();
    let size = size_of::<abi::user::Property32>() as u32;
    let mut offsets = Vec::with_capacity(properties.len());
    for _ in &properties {
        match crate::shared::alloc(size) {
            Some(offset) => offsets.push(offset),
            None => {
                static REPORTED: AtomicBool = AtomicBool::new(false);
                if !REPORTED.swap(true, Ordering::Relaxed) {
                    log::warn!("win32k: the windows' properties do not fit in the shared heap: user32 sees none");
                }
                for offset in offsets.drain(..) {
                    crate::shared::free(offset, size);
                }
                break;
            }
        }
    }
    let head = window.server_address() + offset_of!(Wnd32, prop_list_head) as u32;
    let blocks: Vec<u32> = offsets.iter().map(|&offset| crate::shared::server_address(offset)).collect();
    if let Some(section) = crate::shared::section() {
        for (offset, property) in offsets.iter().zip(property_chain(head, &blocks, &properties)) {
            let _ = section.write_kernel(u64::from(*offset), property.as_bytes());
        }
    }
    let list = (!blocks.is_empty()).then(|| (blocks[0], blocks[blocks.len() - 1], blocks.len() as u32));
    update(window, |state| state.prop_list = list);
    if !offsets.is_empty() {
        PROPERTY_BLOCKS.lock().push((window.handle, offsets));
    }
}

/// UserRemoveWindowProps : les propriétés de la fenêtre `hwnd` partent (à
/// sa destruction), et leurs blocs du tas partagé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn remove_properties(hwnd: u32) {
    PROPERTIES.lock().retain(|property| property.hwnd != hwnd);
    free_property_blocks(hwnd);
}

/// SetProp : la propriété `atom` de la fenêtre devient `data` (remplacée si
/// l'atome y était déjà) ; `system` pour une propriété du système
/// (PROPERTY_FLAG_SYSTEM : les icônes de WM_SETICON, que GetProp d'une
/// application ne voit pas). `user32` la voit dans le tas du bureau.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_property(window: &Window, atom: u16, data: u32, system: bool) {
    {
        let mut properties = PROPERTIES.lock();
        let found = properties
            .iter_mut()
            .find(|property| property.hwnd == window.handle && property.atom == atom && property.system == system);
        match found {
            Some(property) => property.data = data,
            None => properties.push(Property { hwnd: window.handle, atom, data, system }),
        }
    }
    publish_properties(window);
}

/// GetProp du noyau : la propriété `atom` (du système ou non) de la
/// fenêtre, si elle l'a.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn property(window: &Window, atom: u16, system: bool) -> Option<u32> {
    PROPERTIES
        .lock()
        .iter()
        .find(|property| property.hwnd == window.handle && property.atom == atom && property.system == system)
        .map(|property| property.data)
}

/// NtUserSetMenu (IntSetMenu) : la barre de menus de la fenêtre devient
/// `hmenu` (0 la retire ; le menu sait de quelle fenêtre il est la barre,
/// `crate::menu::attach`) ; si elle change, ou avec `repaint`, et que la
/// fenêtre n'est pas réduite, la zone cliente se recalcule (WM_NCCALCSIZE :
/// la barre prend sa place sous le titre) et le cadre se repeint.
///
/// # Errors
/// `ERROR_INVALID_WINDOW_HANDLE` pour une fenêtre fille ;
/// `ERROR_INVALID_MENU_HANDLE` pour un menu qui n'existe pas ou qui est la
/// barre d'une autre fenêtre.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le service système.
pub fn set_menu(window: &alloc::sync::Arc<Window>, hmenu: u32, repaint: bool) -> Result<(), u32> {
    let state = window.state();
    if state.style & (WS_CHILD | WS_POPUP) == WS_CHILD {
        return Err(ERROR_INVALID_WINDOW_HANDLE);
    }
    let changed = state.menu != hmenu;
    if changed {
        crate::menu::attach(hmenu, state.menu, window.handle)?;
        update(window, |state| state.menu = hmenu);
    }
    if state.style & WS_MINIMIZE != 0 || !(changed || repaint) {
        return Ok(());
    }
    let rect = window.state().window;
    let mut calc = rect_bytes(rect);
    let _ = send_message(window, WM_NCCALCSIZE, 0, LParam::Buffer { bytes: &mut calc, write_back: true });
    let client = fix_client_rect(rect_of(&calc), rect);
    update(window, |state| state.client = client);
    let _ = send_message(window, WM_NCPAINT, 0, LParam::Value(0));
    Ok(())
}

/// IntSetMenu à la création : la barre de menus d'une fenêtre qui n'est pas
/// fille (`kind`, ses styles WS_CHILD et WS_POPUP) est `hmenu`, un menu qui
/// existe (`exists`), dès WM_NCCALCSIZE ; une fille n'en a pas, `hmenu` est
/// son identifiant.
///
/// # Errors
/// `ERROR_INVALID_MENU_HANDLE` pour un menu qui n'existe pas.
fn creation_menu(kind: u32, hmenu: u32, exists: impl FnOnce(u32) -> bool) -> Result<u32, u32> {
    if kind == WS_CHILD || hmenu == 0 {
        Ok(0)
    } else if exists(hmenu) {
        Ok(hmenu)
    } else {
        Err(ERROR_INVALID_MENU_HANDLE)
    }
}

/// co_IntCallLoadMenu : le menu de la classe `class`, que `user32` charge de
/// son module ; aucun sans nom de menu, si le rappel échoue ou si le menu
/// rendu n'existe pas (comme ReactOS, la fenêtre se crée sans barre).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
fn class_menu(class: &Class) -> Option<u32> {
    let resource = class.menu.resource()?;
    let loaded = crate::callback::load_menu(class.info.instance, resource).ok()?;
    crate::menu::exists(loaded).then_some(loaded)
}

/// SetWindowFNID : l'identifiant interne de la fenêtre.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_fnid(window: &Window, fnid: u32) {
    update(window, |state| state.fnid = fnid);
}

fn update(window: &Window, change: impl FnOnce(&mut WindowState)) -> WindowState {
    let (dirty, state) = {
        let mut state = window.state.lock();
        let dirty = crate::paint::is_dirty(&state);
        change(&mut state);
        (dirty, state.clone())
    };
    if crate::paint::is_dirty(&state) != dirty {
        crate::paint::count_paint(window, !dirty);
    }
    let _ = write(window);
    state
}

/// IntCreateWindow pour un bureau neuf : sa fenêtre (la classe du bureau,
/// `WS_POPUP | WS_CLIPCHILDREN`, cachée, de `width` × `height`), son `WND`
/// et sa classe dans `heap`, son handle ; le `DESKTOPINFO` en `desk_info`
/// la désigne (`spwnd`). `name` est celui du bureau.
///
/// # Errors
/// Celles du tas et de la table des handles.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create_desktop_window(
    heap: &Arc<DesktopHeap>,
    name: &str,
    desk_info: u32,
    width: u32,
    height: u32,
) -> Result<Arc<Window>, NtStatus> {
    let cls = heap.alloc(size_of::<Cls32>() as u32)?;
    let class = Cls32 {
        atom_class_name: WC_DESKTOP,
        atom_nv_class_name: WC_DESKTOP,
        fnid: FNID_DESKTOP,
        rpdesk_parent: heap.server_base,
        csf_flags: CSF_SERVERSIDEPROC | CSF_SYSTEMCLASS,
        style: CS_DBLCLKS,
        cb_wnd_extra: DESKTOP_WND_EXTRA as i32,
        background: COLOR_BACKGROUND + 1,
        ..Cls32::default()
    };
    let wnd_size = size_of::<Wnd32>() as u32 + DESKTOP_WND_EXTRA;
    let allocated =
        heap.section.write_kernel(u64::from(cls), class.as_bytes()).and_then(|()| heap.alloc(wnd_size)).and_then(
            |wnd| match crate::handles::alloc(heap.server_address(wnd), 0, TYPE_WINDOW) {
                Ok(handle) => Ok((wnd, handle)),
                Err(status) => {
                    heap.free(wnd, wnd_size);
                    Err(status)
                }
            },
        );
    let (wnd, handle) = match allocated {
        Ok(allocated) => allocated,
        Err(status) => {
            heap.free(cls, size_of::<Cls32>() as u32);
            return Err(status);
        }
    };
    let rect = Rect::new(0, 0, width as i32, height as i32);
    let state = WindowState {
        style: WS_POPUP | WS_CLIPCHILDREN,
        state: WNDS_SERVERSIDEWINDOWPROC,
        fnid: FNID_DESKTOP,
        unicode: true,
        window: rect,
        client: rect,
        ..WindowState::default()
    };
    let window = Arc::new(Window {
        handle,
        heap: heap.clone(),
        wnd,
        wnd_size,
        cls,
        class: None,
        pti: 0,
        desktop_name: Some(String::from(name)),
        state: KSpinLock::new(state),
        destroying: AtomicBool::new(false),
        freed: AtomicBool::new(false),
    });
    WINDOWS.lock().insert(handle, Arc::downgrade(&window));
    write(&window)?;
    let spwnd = u64::from(desk_info) + offset_of!(DeskInfoHead32, spwnd) as u64;
    heap.section.write_kernel(spwnd, &window.server_address().to_le_bytes())?;
    Ok(window)
}

/// co_IntShowDesktop : la fenêtre du bureau `desktop`, à la taille de
/// l'écran (`width` × `height`), devient visible ; elle est invalidée entière
/// (fond compris), puis mise à jour aussitôt (UpdateWindow : WM_PAINT).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn show_desktop_window(desktop: &Desktop, width: u32, height: u32) {
    let window = &desktop.window;
    let rect = Rect::new(0, 0, width as i32, height as i32);
    update(window, |state| {
        state.style |= WS_VISIBLE;
        state.window = rect;
        state.client = rect;
        state.invalidate(rect, true);
    });
    update_window(window);
}

/// IntHideDesktop : la fenêtre du bureau n'est plus visible.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn hide_desktop_window(desktop: &Desktop) {
    update(&desktop.window, |state| state.style &= !WS_VISIBLE);
}

/// UpdateWindow : une fenêtre visible qui a une région à mettre à jour
/// reçoit WM_PAINT.
fn update_window(window: &Window) {
    let state = window.state();
    if state.style & WS_VISIBLE != 0 && !state.update.is_empty() {
        server_window_proc(window, WM_PAINT, 0, &mut LParam::Value(0));
    }
}

/// La procédure dans win32k d'une fenêtre qui en a une ; `None` pour une
/// autre (sa procédure est alors celle du client). Celle d'un menu
/// déroulant se reconnaît à sa classe : sa FNID n'est posée qu'à
/// WM_NCCREATE.
fn server_window_proc(window: &Window, message: u32, wparam: u32, lparam: &mut LParam<'_>) -> Option<u32> {
    let state = window.state();
    if state.state & WNDS_SERVERSIDEWINDOWPROC == 0 {
        return None;
    }
    let fnid = state.fnid;
    drop(state);
    let value = match lparam {
        LParam::Value(value) => *value,
        LParam::Buffer { .. } => 0,
    };
    match fnid {
        FNID_DESKTOP => Some(desktop_window_proc(window, message, wparam, value)),
        _ if window.class.as_ref().is_some_and(|class| class.fnid == FNID_MENU) => {
            Some(crate::menupopup::window_proc(window, message, wparam, lparam))
        }
        _ => None,
    }
}

/// DesktopWindowProc : WM_PAINT valide la région à mettre à jour (avec
/// WM_ERASEBKGND d'abord s'il faut effacer le fond), WM_ERASEBKGND peint le
/// fond du bureau dans le rectangle de la peinture.
fn desktop_window_proc(window: &Window, message: u32, _wparam: u32, _lparam: u32) -> u32 {
    match message {
        WM_PAINT => {
            let mut erase = false;
            update(window, |state| erase = state.begin_paint());
            if erase {
                desktop_window_proc(window, WM_ERASEBKGND, 0, 0);
            }
            // EndPaint.
            update(window, |state| state.painting = Rect::default());
            0
        }
        WM_ERASEBKGND => {
            paint_desktop(window, window.state().painting);
            1
        }
        _ => 0,
    }
}

/// IntPaintDesktop : le fond du bureau, de la couleur système
/// `COLOR_BACKGROUND`, dans `rect` (journalisé : c'est rare).
fn paint_desktop(window: &Window, rect: Rect) {
    let painted = crate::display::draw(|screen| screen.fill_rect(rect, crate::gdi::syscolor::BACKGROUND));
    if painted {
        log::info!(
            "win32k: the desktop window of {} erased (WM_ERASEBKGND), {}x{}",
            window.desktop_name.as_deref().unwrap_or("?"),
            rect.right - rect.left,
            rect.bottom - rect.top
        );
    }
}

/// Le `lParam` d'un message envoyé : une valeur, ou des octets que le
/// message désigne (emballés comme PackParam), repris après la procédure
/// pour un message qui y écrit.
pub enum LParam<'a> {
    Value(u32),
    Buffer { bytes: &'a mut [u8], write_back: bool },
}

/// IntDispatchMessage : `message`, sorti de la file, à la procédure de sa
/// fenêtre (`user32` n'en passe ici que WM_PAINT et ceux d'une procédure
/// dans win32k) ; rend ce qu'elle rend, 0 sans fenêtre. Une fenêtre qui n'a
/// pas appelé BeginPaint pour WM_PAINT repeint son cadre et son fond
/// (IntPaintWindow). Le WM_SYSTIMER d'une minuterie à procédure du noyau
/// l'appelle (`crate::timer::kernel_procedure` : le clignotement du caret).
///
/// # Errors
/// Ceux de [`send_message`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn dispatch_message(message: &Msg32) -> Result<u32, NtStatus> {
    if message.message == WM_SYSTIMER && message.l_param != 0 {
        // FindSystemTimer: a system timer's procedure in the kernel (the
        // caret's blink).
        let thread = crate::gui::convert_current_thread().ok();
        let procedure =
            thread.and_then(|thread| crate::timer::kernel_procedure(&thread, message.hwnd, message.w_param));
        if let Some(procedure) = procedure {
            procedure(message.hwnd, message.w_param);
        }
        return Ok(0);
    }
    if message.message == WM_TIMER && message.l_param != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: DispatchMessage of a timer's procedure: not yet");
        }
        return Ok(0);
    }
    let Some(window) = get(message.hwnd) else { return Ok(0) };
    let paint = message.message == WM_PAINT;
    if paint {
        update(&window, |state| state.state |= WNDS_PAINTNOTPROCESSED);
    }
    let result = send_message(&window, message.message, message.w_param, LParam::Value(message.l_param))?;
    if paint && get(window.handle).is_some() && window.state().state & WNDS_PAINTNOTPROCESSED != 0 {
        update(&window, |state| state.state2 &= !WNDS2_WMPAINTSENT);
        crate::paint::paint_window(&window);
    }
    Ok(result)
}

/// co_IntSendMessage : `message` à la procédure de `window` ; rend ce
/// qu'elle rend. Une procédure dans win32k (DesktopWindowProc) est appelée
/// directement ; une procédure du client l'est par un rappel, le
/// `CLIENTINFO` du thread désignant la fenêtre. La fenêtre d'un autre thread
/// reçoit le message par sa file ([`crate::sent::send`]), le thread courant
/// attendant la réponse.
///
/// Un tampon du noyau voyage vers un autre thread par sa copie
/// ([`crate::sent::send_buffer`]).
///
/// # Errors
/// Celles du rappel ; un envoi à un autre thread sans réponse
/// ([`crate::sent::SendError::status`]).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn send_message(window: &Arc<Window>, message: u32, wparam: u32, lparam: LParam<'_>) -> Result<u32, NtStatus> {
    let mut lparam = lparam;
    let value = match &lparam {
        LParam::Value(value) => *value,
        LParam::Buffer { .. } => 0,
    };
    if let Some(result) = server_window_proc(window, message, wparam, &mut lparam) {
        return Ok(result);
    }
    let thread = crate::convert_current_thread()?;
    if thread.server != window.pti {
        let target = crate::gui::thread_info_of(window.pti).ok_or(crate::sent::SendError::Gone.status())?;
        let sent = match lparam {
            LParam::Value(value) => crate::sent::send(&thread, &target, window.handle, message, wparam, value, None),
            LParam::Buffer { bytes, write_back } => {
                crate::sent::send_buffer(&thread, &target, window.handle, message, wparam, bytes, write_back)
            }
        };
        return sent.map_err(crate::sent::SendError::status);
    }
    drop(thread);
    let state = window.state();
    let arguments = WindowProcArguments32 {
        proc: state.wnd_proc,
        is_ansi_proc: u32::from(!state.unicode),
        wnd: window.handle,
        msg: message,
        w_param: wparam,
        l_param: value,
        ..WindowProcArguments32::default()
    };
    let previous = set_callback_window(window);
    let result = match lparam {
        LParam::Value(_) => crate::callback::window_proc(arguments, None, false),
        LParam::Buffer { bytes, write_back } => crate::callback::window_proc(arguments, Some(bytes), write_back),
    };
    if let Some(previous) = previous {
        restore_callback_window(previous);
    }
    result
}

/// Le thread courant et l'adresse du `CallbackWnd` de son `CLIENTINFO`.
fn callback_window_address() -> Option<(Arc<Object<ps::EThread>>, u64)> {
    let thread = ps::ethread::current_thread()?;
    let at = u64::from(thread.teb())
        + offset_of!(Teb32, win32_client_info) as u64
        + offset_of!(ClientInfo32, callback_wnd) as u64;
    Some((thread, at))
}

/// IntSetTebWndCallback : le `CLIENTINFO` du thread courant désigne
/// `window` (son handle, son `WND` dans la vue du processus) ; rend ce
/// qu'il désignait.
fn set_callback_window(window: &Window) -> Option<CallbackWnd32> {
    let (thread, at) = callback_window_address()?;
    let process = thread.process();
    let mut bytes = [0u8; size_of::<CallbackWnd32>()];
    process.read_memory(at, &mut bytes).ok()?;
    let word = |i: usize| u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    let previous = CallbackWnd32 { hwnd: word(0), pwnd: word(1), act_ctx: word(2) };
    let view = crate::process_info(process).ok().and_then(|info| info.heap_view(&window.heap));
    let current = CallbackWnd32 { hwnd: window.handle, pwnd: view.map_or(0, |view| view + window.wnd), act_ctx: 0 };
    process.write_memory(at, current.as_bytes()).ok()?;
    Some(previous)
}

/// IntRestoreTebWndCallback : le `CLIENTINFO` du thread courant désigne de
/// nouveau `previous`.
fn restore_callback_window(previous: CallbackWnd32) {
    if let Some((thread, at)) = callback_window_address() {
        let _ = thread.process().write_memory(at, previous.as_bytes());
    }
}

/// NtUserDefSetText : le nom de `window` devient `text` (vide : un nom vide),
/// à sa place s'il y tient, sinon dans un bloc neuf du tas.
///
/// # Errors
/// Celles du tas.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_text(window: &Window, text: &[u16]) -> Result<(), NtStatus> {
    let length = 2 * text.len() as u32;
    let bytes: Vec<u8> = text.iter().chain([&0]).flat_map(|unit| unit.to_le_bytes()).collect();
    let current = window.state().name;
    let name = match current {
        Some(name) if length + 2 <= name.capacity => Name { length, ..name },
        _ if text.is_empty() => {
            update(window, |state| {
                if let Some(name) = state.name.as_mut() {
                    name.length = 0;
                }
            });
            return match current {
                Some(name) => window.heap.section.write_kernel(u64::from(name.at), &[0, 0]),
                None => Ok(()),
            };
        }
        _ => {
            let at = window.heap.alloc(length + 2)?;
            if let Some(old) = current {
                window.heap.free(old.at, old.capacity);
            }
            Name { at, length, capacity: length + 2 }
        }
    };
    window.heap.section.write_kernel(u64::from(name.at), &bytes)?;
    update(window, |state| state.name = Some(name));
    Ok(())
}

/// Le nom de `window`, s'il en a un.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text(window: &Window) -> Option<Vec<u16>> {
    let name = window.state().name?;
    let mut bytes = alloc::vec![0u8; name.length as usize];
    window.heap.section.read_kernel(u64::from(name.at), &mut bytes).ok()?;
    Some(bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect())
}

/// Ce que NtUserCreateWindowEx donne (CREATESTRUCTW, et le reste).
#[derive(Clone, Debug, Default)]
pub struct CreateParams {
    pub ex_style: u32,
    /// Le nom de la classe (de sa version).
    pub class: Option<ClassName>,
    pub name: Vec<u16>,
    pub style: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub parent: u32,
    pub menu: u32,
    pub instance: u32,
    pub param: u32,
    /// La version de Windows qu'attend le module (`dwFlags`).
    pub expected_version: u32,
}

/// Ce que les paramètres du processus (STARTUPINFO) disent de la place, de
/// la taille et de la commande de ShowWindow d'une fenêtre recouvrante :
/// `WindowFlags` (`STARTF_*`), `StartingX`, `StartingY`, `CountX`,
/// `CountY`, `ShowWindowFlags`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartupPlace {
    pub flags: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub show: u32,
}

/// IntFixWindowCoordinates ; rend la commande de ShowWindow d'une fenêtre
/// créée visible (`SW_SHOW`, ou le `y` d'une fenêtre recouvrante placée par
/// défaut sur un moniteur). Une fenêtre recouvrante sans moniteur (`work`
/// nul) prend la place et la taille de ReactOS sans moniteur (0, 0,
/// 800 × 600). Avec la zone de travail `work` de son moniteur,
/// `CW_USEDEFAULT` en `x` lui donne la place de `startup`
/// (`STARTF_USEPOSITION`) ou la suivante de la cascade (`cascade`) ; en
/// `cx`, la taille de `startup` (`STARTF_USESIZE`) ou les trois quarts de la
/// zone ; en `cy` seul, les trois quarts de sa hauteur. Une autre fenêtre a
/// 0 et 0 pour `CW_USEDEFAULT` en `x` (ou en `cx`). `CW_USEDEFAULT` sur 16
/// bits (-32768) vaut aussi.
///
/// ReactOS prend `CountX` et `CountY` sous `STARTF_USEPOSITION` : c'est
/// `STARTF_USESIZE` qui les annonce.
pub fn fix_coordinates(
    params: &mut CreateParams,
    work: Option<Rect>,
    startup: &StartupPlace,
    cascade: impl FnOnce() -> (i32, i32),
) -> u32 {
    let default = |value: i32| value as u32 == CW_USEDEFAULT || value == i32::from(i16::MIN);
    let mut show = SW_SHOW;
    if params.style & (WS_POPUP | WS_CHILD) == 0 {
        let Some(work) = work else {
            (params.x, params.y, params.cx, params.cy) = (0, 0, 800, 600);
            return show;
        };
        let (width, height) = (work.right - work.left, work.bottom - work.top);
        if default(params.x) {
            if !default(params.y) {
                show = params.y as u32;
            }
            (params.x, params.y) =
                if startup.flags & STARTF_USEPOSITION != 0 { (startup.x, startup.y) } else { cascade() };
        }
        if default(params.cx) {
            (params.cx, params.cy) = if startup.flags & STARTF_USESIZE != 0 {
                (startup.cx, startup.cy)
            } else {
                (width * 3 / 4, height * 3 / 4)
            };
        } else if default(params.cy) {
            params.cy = height * 3 / 4;
        }
        return show;
    }
    if default(params.x) {
        (params.x, params.y) = (0, 0);
    }
    if default(params.cx) {
        (params.cx, params.cy) = (0, 0);
    }
    show
}

/// Le `STARTUPINFO` du processus courant, dans ses paramètres
/// (`Peb->ProcessParameters`) ; rien s'ils sont illisibles.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système (lit la mémoire utilisateur).
pub fn startup_place() -> StartupPlace {
    let Some(process) = ps::ethread::current_thread().map(|thread| thread.process().clone()) else {
        return StartupPlace::default();
    };
    let parameters = UserPtr::<u32>::new(process.peb() + offset_of!(Peb32, process_parameters) as u32).read();
    let Ok(parameters) = parameters else { return StartupPlace::default() };
    let field = |offset: usize| UserPtr::<u32>::new(parameters + offset as u32).read().unwrap_or(0);
    StartupPlace {
        flags: field(offset_of!(RtlUserProcessParameters32, window_flags)),
        x: field(offset_of!(RtlUserProcessParameters32, starting_x)) as i32,
        y: field(offset_of!(RtlUserProcessParameters32, starting_y)) as i32,
        cx: field(offset_of!(RtlUserProcessParameters32, count_x)) as i32,
        cy: field(offset_of!(RtlUserProcessParameters32, count_y)) as i32,
        show: field(offset_of!(RtlUserProcessParameters32, show_window_flags)),
    }
}

/// Les styles d'une fenêtre neuve (IntCreateWindow) : `WS_VISIBLE` ôté (la
/// montrer viendra après), `WS_CLIPSIBLINGS` pour une fenêtre qui n'est pas
/// fille, `WS_CAPTION` en plus pour une recouvrante ; `WS_EX_WINDOWEDGE`
/// d'après le cadre ; les `WNDS_*` qui en découlent
/// (`WNDS_SENDSIZEMOVEMSGS` pour une recouvrante).
pub fn new_window_styles(style: u32, ex_style: u32) -> (u32, u32, u32) {
    let mut style = style & !WS_VISIBLE;
    let mut ex_style = ex_style & !WS_EX_SETANSICREATOR;
    if style & (WS_CHILD | WS_POPUP) != WS_CHILD {
        style |= WS_CLIPSIBLINGS;
        if style & WS_POPUP == 0 {
            style |= WS_CAPTION;
        }
    }
    if ex_style & WS_EX_DLGMODALFRAME != 0 {
        ex_style |= WS_EX_WINDOWEDGE;
    } else if style & (WS_DLGFRAME | WS_THICKFRAME) != 0 {
        if !(ex_style & WS_EX_STATICEDGE != 0 && style & (WS_CHILD | WS_POPUP) != 0) {
            ex_style |= WS_EX_WINDOWEDGE;
        }
    } else {
        ex_style &= !WS_EX_WINDOWEDGE;
    }
    let state = if style & (WS_CHILD | WS_POPUP) == 0 { WNDS_SENDSIZEMOVEMSGS } else { 0 };
    (style, ex_style, state)
}

/// Les `WNDS2_*` de compatibilité d'un module qui attend `version`.
pub fn compatibility(version: u32) -> u32 {
    let mut state2 = 0;
    if version >= WINVER_WIN31 {
        state2 |= WNDS2_WIN31COMPAT;
        if version >= WINVER_WINNT4 {
            state2 |= WNDS2_WIN40COMPAT;
            if version >= WINVER_WIN2K {
                state2 |= WNDS2_WIN50COMPAT;
            }
        }
    }
    state2
}

/// PackParam de WM_NCCREATE et WM_CREATE : le `CREATESTRUCT` `create`,
/// puis le nom de la fenêtre (et son NUL), puis la classe : `A` et son
/// atome, ou `S`, son nom et son NUL ; `name` et `class` sont leurs
/// positions depuis le début.
pub fn pack_create_struct(create: &CreateStructW32, name: &[u16], class: &ClassName) -> Vec<u8> {
    let mut packed = create.as_bytes().to_vec();
    let units = |packed: &mut Vec<u8>, units: &[u16]| {
        packed.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
    };
    let name_at = packed.len() as u32;
    units(&mut packed, name);
    units(&mut packed, &[0]);
    let class_at = packed.len() as u32;
    match class {
        ClassName::Atom(atom) => units(&mut packed, &[u16::from(b'A'), *atom]),
        ClassName::String(string) => {
            units(&mut packed, &[u16::from(b'S')]);
            units(&mut packed, string);
            units(&mut packed, &[0]);
        }
    }
    let at = offset_of!(CreateStructW32, name);
    packed[at..at + 4].copy_from_slice(&name_at.to_le_bytes());
    let at = offset_of!(CreateStructW32, class);
    packed[at..at + 4].copy_from_slice(&class_at.to_le_bytes());
    packed
}

/// FixClientRect : la zone cliente, ramenée dans le rectangle de la fenêtre.
pub fn fix_client_rect(client: Rect, window: Rect) -> Rect {
    let clamp = |value: i32, low: i32, high: i32| value.max(low).min(high.max(low));
    Rect {
        left: clamp(client.left, window.left, window.right),
        top: clamp(client.top, window.top, window.bottom),
        right: clamp(client.right, window.left, window.right),
        bottom: clamp(client.bottom, window.top, window.bottom),
    }
}

/// Un `RECT` en octets.
fn rect_bytes(rect: Rect) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (slot, value) in bytes.chunks_exact_mut(4).zip([rect.left, rect.top, rect.right, rect.bottom]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Le `RECT` de ces octets.
fn rect_of(bytes: &[u8]) -> Rect {
    let word = |i: usize| i32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    Rect { left: word(0), top: word(1), right: word(2), bottom: word(3) }
}

/// Une fois, journalise ce qui manque encore à une création de fenêtre.
fn report_missing(what: &str, reported: &AtomicBool) {
    if !reported.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: CreateWindowEx: {what}: not yet");
    }
}

/// IntLinkWindow : `window` entre parmi les enfants de `parent`, juste
/// après `after` dans l'ordre Z, ou en tête.
fn link_window(window: &Arc<Window>, parent: &Arc<Window>, after: Option<&Arc<Window>>) {
    let next = match after {
        Some(after) => {
            let next = after.state().next;
            update(after, |state| state.next = window.handle);
            next
        }
        None => {
            let first = parent.state().child;
            update(parent, |state| state.child = window.handle);
            first
        }
    };
    update(window, |state| (state.prev, state.next) = (after.map_or(0, |after| after.handle), next));
    if let Some(next) = get(next) {
        update(&next, |state| state.prev = window.handle);
    }
}

/// Elle est au premier plan (`WS_EX_TOPMOST`).
fn is_topmost(window: &Window) -> bool {
    window.state().ex_style & WS_EX_TOPMOST != 0
}

/// IntLinkHwnd : `window` prend sa place parmi les enfants de son parent :
/// en bas (`HWND_BOTTOM`), tout en haut et au premier plan
/// (`HWND_TOPMOST`), en haut sous les fenêtres au premier plan
/// (`HWND_TOP` ; au-dessus de son propriétaire, elle y passe), au même
/// rang hors du premier plan (`HWND_NOTOPMOST`), ou juste sous la sœur
/// `after` (inconnue : `HWND_TOP`), dont elle prend le premier plan.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn link(window: &Arc<Window>, after: u32) {
    let mut after = after;
    if after == HWND_NOTOPMOST {
        if !is_topmost(window) {
            return;
        }
        update(window, |state| state.ex_style &= !WS_EX_TOPMOST);
        after = HWND_TOP;
    }
    unlink(window);
    let Some(parent) = get(window.state().parent) else { return };
    match after {
        HWND_BOTTOM => {
            let mut last = get(parent.state().child);
            while let Some(next) = last.as_ref().and_then(|sibling| get(sibling.state().next)) {
                last = Some(next);
            }
            link_window(window, &parent, last.as_ref());
            update(window, |state| state.ex_style &= !WS_EX_TOPMOST);
        }
        HWND_TOPMOST => {
            link_window(window, &parent, None);
            update(window, |state| state.ex_style |= WS_EX_TOPMOST);
        }
        HWND_TOP => {
            let mut before = get(parent.state().child);
            if !is_topmost(window) {
                let owner = window.state().owner;
                while let Some(sibling) = before.clone() {
                    let next = sibling.state().next;
                    if next == 0 || !is_topmost(&sibling) {
                        break;
                    }
                    if sibling.handle == owner {
                        update(window, |state| state.ex_style |= WS_EX_TOPMOST);
                        break;
                    }
                    before = get(next);
                }
            }
            let previous = before.and_then(|before| get(before.state().prev));
            link_window(window, &parent, previous.as_ref());
        }
        _ => {
            let Some(sibling) = get(after) else { return link(window, HWND_TOP) };
            if sibling.handle == window.handle {
                return;
            }
            link_window(window, &parent, Some(&sibling));
            if !is_topmost(&sibling) {
                update(window, |state| state.ex_style &= !WS_EX_TOPMOST);
            } else if get(sibling.state().next).is_some_and(|next| is_topmost(&next)) {
                update(window, |state| state.ex_style |= WS_EX_TOPMOST);
            }
        }
    }
}

/// IntIsWindowVisible : elle et ses parents jusqu'au bureau sont visibles,
/// aucun parent réduit.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn is_visible(window: &Window) -> bool {
    let mut state = window.state();
    let mut current = window.handle;
    loop {
        if state.style & WS_VISIBLE == 0 || (state.style & WS_MINIMIZE != 0 && current != window.handle) {
            return false;
        }
        if state.fnid == FNID_DESKTOP {
            return true;
        }
        let Some(parent) = get(state.parent) else { return true };
        (current, state) = (parent.handle, parent.state());
    }
}

/// Elle possède une autre fenêtre (une fenêtre contextuelle, par exemple).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn owns_windows(window: &Window) -> bool {
    let windows: Vec<Arc<Window>> = WINDOWS.lock().values().filter_map(Weak::upgrade).collect();
    windows.iter().any(|other| other.state().owner == window.handle)
}

/// IntWinListOwnedPopups : les fenêtres que possède la fenêtre `hwnd`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn owned_by(hwnd: u32) -> Vec<Arc<Window>> {
    let windows: Vec<Arc<Window>> = WINDOWS.lock().values().filter_map(Weak::upgrade).collect();
    windows.into_iter().filter(|other| other.state().owner == hwnd && other.handle != hwnd).collect()
}

/// WinPosInternalMoveWindow : `window` et ses enfants, à toute profondeur,
/// se déplacent de `dx`, `dy` (rectangles de la fenêtre et de la zone
/// cliente).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn move_tree(window: &Window, dx: i32, dy: i32) {
    let moved = |rect: Rect| Rect::new(rect.left + dx, rect.top + dy, rect.right + dx, rect.bottom + dy);
    let state = update(window, |state| (state.window, state.client) = (moved(state.window), moved(state.client)));
    let mut child = get(state.child);
    while let Some(current) = child {
        move_tree(&current, dx, dy);
        child = get(current.state().next);
    }
}

/// IntWinListChildren et le parcours de NtUserBuildHwndList : les handles
/// des enfants de `parent`, dans leur ordre Z ; avec `deep`, chacun suivi de
/// ses propres enfants, à toute profondeur.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn children(parent: &Window, deep: bool) -> Vec<u32> {
    let mut list = Vec::new();
    let mut child = get(parent.state().child);
    while let Some(window) = child {
        list.push(window.handle);
        if deep {
            list.extend(children(&window, true));
        }
        child = get(window.state().next);
    }
    list
}

/// IntUnlinkWindow : `window` quitte les enfants de son parent.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub(crate) fn unlink(window: &Arc<Window>) {
    let state = window.state();
    if let Some(prev) = get(state.prev) {
        update(&prev, |prev| prev.next = state.next);
    } else if let Some(parent) = get(state.parent).filter(|parent| parent.state().child == window.handle) {
        update(&parent, |parent| parent.child = state.next);
    }
    if let Some(next) = get(state.next) {
        update(&next, |next| next.prev = state.prev);
    }
    update(window, |state| (state.prev, state.next) = (0, 0));
}

/// co_UserCreateWindowEx : une fenêtre de la classe `params.class` sur le
/// bureau du thread courant, sa procédure prévenue par WM_NCCREATE,
/// WM_NCCALCSIZE et WM_CREATE, puis, si elle n'attend pas d'être montrée,
/// WM_SIZE et WM_MOVE ; une fenêtre fille prévient son parent
/// (WM_PARENTNOTIFY). Elle appartient au thread dès qu'elle a un handle. Une
/// fenêtre qui n'est pas fille a pour barre de menus `params.menu` dès sa
/// création ([`creation_menu`]), sinon le menu de sa classe
/// ([`class_menu`]). Une création qui échoue après la prise du handle
/// détruit la fenêtre (`crate::destroy::destroy_window` : WM_DESTROY et
/// WM_NCDESTROY, comme ReactOS).
///
/// # Errors
/// L'erreur Win32, s'il y en a une : sans classe,
/// `ERROR_CANNOT_FIND_WND_CLASS` ; une fenêtre fille sans parent,
/// `ERROR_TLW_WITH_WSCHILD` ; un parent ou un propriétaire qui n'existe pas,
/// `ERROR_INVALID_WINDOW_HANDLE` ; un menu qui n'existe pas,
/// `ERROR_INVALID_MENU_HANDLE` ; le tas plein,
/// `ERROR_NOT_ENOUGH_MEMORY`. Aucune quand la procédure refuse WM_NCCREATE
/// ou WM_CREATE, ou que le thread n'a pas de bureau.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système. Rappelle le mode utilisateur.
pub fn create_window(mut params: CreateParams) -> Result<Arc<Window>, Option<u32>> {
    let thread = crate::convert_current_thread().map_err(|_| None)?;
    // Une fenêtre sans bureau : le shell de session en reçoit un du noyau
    // (WinSta0\Default, créés s'il le faut) — le moment exact du besoin,
    // après qu'un vrai winlogon ait eu le sien.
    let desktop = match thread.desktop() {
        Some(desktop) => desktop.desktop,
        None => {
            let process = ps::ethread::current_thread().map(|thread| thread.process().clone());
            let Some(process) = process else { return Err(None) };
            crate::startup::session_desktop(&process).map_err(|_| None)?
        }
    };
    let process = ps::ethread::current_thread().ok_or(None)?.process().clone();
    let process_info = crate::process_info(&process).map_err(|_| None)?;
    drop(process);
    let class_name = params.class.clone().ok_or(Some(ERROR_CANNOT_FIND_WND_CLASS))?;
    let class = {
        let client_module = crate::client::client_module();
        let mut classes = process_info.classes.lock();
        classes.register_system_classes(client_module);
        classes.find(&class_name, params.instance, client_module)
    };
    let class = class.ok_or(Some(ERROR_CANNOT_FIND_WND_CLASS))?;

    // The parent and the owner.
    let mut parent = desktop.window.clone();
    let mut owner = None;
    let kind = params.style & (WS_CHILD | WS_POPUP);
    if params.parent == HWND_MESSAGE {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("message-only windows (HWND_MESSAGE)", &REPORTED);
        return Err(Some(ERROR_INVALID_WINDOW_HANDLE));
    } else if params.parent != 0 {
        let window = get(params.parent).ok_or(Some(ERROR_INVALID_WINDOW_HANDLE))?;
        if kind == WS_CHILD {
            parent = window;
        } else if !window.is_desktop_window() {
            // An owner is a top-level window.
            let mut top = window;
            while top.state().style & (WS_POPUP | WS_CHILD) == WS_CHILD {
                match get(top.state().parent).filter(|up| !up.is_desktop_window()) {
                    Some(up) => top = up,
                    None => break,
                }
            }
            owner = Some(top);
        }
    } else if kind == WS_CHILD {
        return Err(Some(ERROR_TLW_WITH_WSCHILD));
    }
    let menu = creation_menu(kind, params.menu, crate::menu::exists).map_err(Some)?;
    let startup = if params.style & (WS_POPUP | WS_CHILD) == 0 { startup_place() } else { StartupPlace::default() };
    let work = crate::monitor::primary().map(|monitor| monitor.work);
    let mut show =
        fix_coordinates(&mut params, work, &startup, || crate::monitor::next_cascade_place().unwrap_or((0, 0)));
    if kind == WS_CHILD && !parent.is_desktop_window() {
        let client = parent.state().client;
        params.x += client.left;
        params.y += client.top;
    }

    // IntCreateWindow.
    let unicode_window = params.ex_style & WS_EX_SETANSICREATOR == 0;
    let (style, ex_style, mut state) = new_window_styles(params.style, params.ex_style);
    if class.flags & CSF_SERVERSIDEPROC != 0 {
        state |= WNDS_SERVERSIDEWINDOWPROC;
    }
    let mut wnd_proc = class.info.wnd_proc;
    if (FNID_BUTTON..=FNID_GHOST).contains(&class.fnid)
        && crate::client::client_procedure(class.fnid, unicode_window) == Some(wnd_proc)
    {
        // A control's procedure of the other character set: the window's.
        wnd_proc = crate::client::client_procedure(class.fnid, !unicode_window).unwrap_or(wnd_proc);
    }
    if !unicode_window {
        state |= WNDS_ANSICREATOR;
    }
    let unicode = class.flags & CSF_ANSIPROC == 0;
    if !unicode {
        state |= WNDS_ANSIWINDOWPROC;
    }
    let heap = desktop.heap.clone();
    let cls = class.image_on(&heap).map_err(|_| Some(ERROR_NOT_ENOUGH_MEMORY))?;
    let wnd_size = size_of::<Wnd32>() as u32 + class.info.wnd_extra.max(0) as u32;
    let wnd = heap.alloc(wnd_size).map_err(|_| Some(ERROR_NOT_ENOUGH_MEMORY))?;
    let handle = match crate::handles::alloc(heap.server_address(wnd), thread.server, TYPE_WINDOW) {
        Ok(handle) => handle,
        Err(_) => {
            heap.free(wnd, wnd_size);
            return Err(Some(ERROR_NOT_ENOUGH_MEMORY));
        }
    };
    let window_state = WindowState {
        style,
        ex_style,
        state,
        state2: compatibility(params.expected_version),
        wnd_proc,
        unicode,
        module: params.instance,
        id_menu: if kind == WS_CHILD { params.menu } else { 0 },
        // IntSetMenu: a menu that is another window's bar is none of hers.
        menu: if crate::menu::attach(menu, 0, handle).is_ok() { menu } else { 0 },
        parent: parent.handle,
        owner: owner.as_ref().map_or(0, |owner| owner.handle),
        ..WindowState::default()
    };
    let window = Arc::new(Window {
        handle,
        heap: heap.clone(),
        wnd,
        wnd_size,
        cls,
        class: Some(class.clone()),
        pti: thread.server,
        desktop_name: None,
        state: KSpinLock::new(window_state),
        destroying: AtomicBool::new(false),
        freed: AtomicBool::new(false),
    });
    WINDOWS.lock().insert(handle, Arc::downgrade(&window));
    thread.windows.lock().push(window.clone());
    if !params.name.is_empty() && set_text(&window, &params.name).is_err() {
        drop((thread, desktop, process_info));
        return Err(failed_creation(&window, Some(ERROR_NOT_ENOUGH_MEMORY)));
    }

    drop((thread, desktop, process_info));

    // Without a menu, a window that is not a child takes its class's
    // (co_IntCallLoadMenu); user32 loads it itself for an overlapped or
    // popup style.
    if kind != WS_CHILD && menu == 0 {
        if let Some(loaded) = class_menu(&class).filter(|&loaded| crate::menu::attach(loaded, 0, window.handle).is_ok())
        {
            update(&window, |state| state.menu = loaded);
        }
    }

    // The window's rectangle, its size within what WM_GETMINMAXINFO allows
    // a sizing or overlapped window; the minimum wins over the maximum.
    let (mut cx, mut cy) = (params.cx, params.cy);
    if params.style & WS_THICKFRAME != 0 || kind == 0 {
        let info = min_max_info(&window);
        cx = cx.min(info.max_track_size[0]).max(info.min_track_size[0]);
        cy = cy.min(info.max_track_size[1]).max(info.min_track_size[1]);
    }
    let rect = Rect::new(params.x, params.y, params.x.wrapping_add(cx), params.y.wrapping_add(cy));
    update(&window, |state| (state.window, state.client) = (rect, rect));

    // WM_NCCREATE, with the window's and the class's names.
    let create = CreateStructW32 {
        create_params: params.param,
        instance: params.instance,
        menu: params.menu,
        parent: params.parent,
        cy: params.cy,
        cx: params.cx,
        y: params.y,
        x: params.x,
        style: params.style,
        ex_style: params.ex_style,
        ..CreateStructW32::default()
    };
    let mut packed = pack_create_struct(&create, &params.name, &class_name);
    let accepted = send_message(&window, WM_NCCREATE, 0, LParam::Buffer { bytes: &mut packed, write_back: true });
    if !accepted.is_ok_and(|accepted| accepted != 0) || !window.is_alive() {
        return Err(failed_creation(&window, None));
    }
    link(&window, if style & (WS_CHILD | WS_MAXIMIZE) == WS_CHILD { HWND_BOTTOM } else { HWND_TOP });

    // WM_NCCALCSIZE: the client area.
    let mut calc = rect_bytes(rect);
    let _ = send_message(&window, WM_NCCALCSIZE, 0, LParam::Buffer { bytes: &mut calc, write_back: true });
    let client = fix_client_rect(rect_of(&calc), rect);
    update(&window, |state| state.client = client);

    // WM_CREATE.
    let mut packed = pack_create_struct(&create, &params.name, &class_name);
    let created = send_message(&window, WM_CREATE, 0, LParam::Buffer { bytes: &mut packed, write_back: true });
    if !created.is_ok_and(|result| result != u32::MAX) || !window.is_alive() {
        return Err(failed_creation(&window, None));
    }
    update(&window, |state| state.state2 |= WNDS2_WMCREATEMSGPROCESSED);
    if window.state().state & WNDS_SENDSIZEMOVEMSGS == 0 {
        send_size_move(&window);
    }
    if params.style & (WS_MINIMIZE | WS_MAXIMIZE) != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("a window created minimized or maximized", &REPORTED);
    }
    if kind == WS_CHILD && ex_style & WS_EX_NOPARENTNOTIFY == 0 && !parent.is_desktop_window() {
        let id = window.state().id_menu;
        let _ = send_message(&parent, WM_PARENTNOTIFY, (id << 16) | WM_CREATE, LParam::Value(handle));
    }
    if params.style & WS_VISIBLE != 0 {
        let style = window.state().style;
        if style & WS_MAXIMIZE != 0 {
            show = SW_SHOW;
        } else if style & WS_MINIMIZE != 0 {
            show = SW_SHOWMINIMIZED;
        }
        crate::winpos::show_window(&window, show);
    }
    if !window.is_alive() {
        // Destroyed by its own procedure while being created.
        return Err(None);
    }
    Ok(window)
}

/// La fin d'une création qui échoue : la fenêtre est détruite
/// (co_UserDestroyWindow) ; rend l'erreur Win32 `error`.
fn failed_creation(window: &Arc<Window>, error: Option<u32>) -> Option<u32> {
    let _ = crate::destroy::destroy_window(window);
    error
}

/// IntGetClientRect : la zone cliente de `window`, à l'origine (celle de la
/// fenêtre du bureau commence en 0, 0).
pub fn client_rect(window: &Window) -> Rect {
    let client = window.state().client;
    if window.is_desktop_window() {
        return Rect::new(0, 0, client.right, client.bottom);
    }
    Rect::new(0, 0, client.right - client.left, client.bottom - client.top)
}

/// co_WinPosGetMinMaxInfo : les limites de `window`. Les valeurs par défaut
/// (`defwnd::min_max_info`, dans la zone cliente de son parent, en
/// `ptReserved` le coin de la fenêtre), ce qu'en fait sa procédure
/// (WM_GETMINMAXINFO), puis, sur un moniteur, ce qu'elle a laissé s'adapte à
/// sa zone de travail (`WNDS_MAXIMIZESTOMONITOR` si la fenêtre agrandie le
/// couvre).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn min_max_info(window: &Arc<Window>) -> MinMaxInfo32 {
    let state = window.state();
    let parent = get(state.parent).map_or(Rect::default(), |parent| client_rect(&parent));
    let corner = (state.window.left, state.window.top);
    let defaults = crate::defwnd::min_max_info(state.style, state.ex_style, corner, parent, &crate::metrics::get);
    let mut bytes = defaults.as_bytes().to_vec();
    let _ = send_message(window, WM_GETMINMAXINFO, 0, LParam::Buffer { bytes: &mut bytes, write_back: true });
    let word = |i: usize| i32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    let mut info = MinMaxInfo32 {
        reserved: [word(0), word(1)],
        max_size: [word(2), word(3)],
        max_position: [word(4), word(5)],
        min_track_size: [word(6), word(7)],
        max_track_size: [word(8), word(9)],
    };
    if let Some(monitor) = crate::monitor::primary() {
        let covers = crate::defwnd::adapt_to_monitor(&mut info, &defaults, state.style, monitor.rect, monitor.work);
        update(window, |state| {
            state.state =
                if covers { state.state | WNDS_MAXIMIZESTOMONITOR } else { state.state & !WNDS_MAXIMIZESTOMONITOR }
        });
    }
    info
}

/// co_WinPosSendSizeMove : WM_SIZE (la taille de la zone cliente ;
/// `SIZE_MAXIMIZED`, ou `SIZE_MINIMIZED` sans taille), puis WM_MOVE (sa
/// place, dans la zone cliente du parent) ; ils n'attendent plus
/// (`WNDS_SENDSIZEMOVEMSGS`).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn send_size_move(window: &Arc<Window>) {
    let state = update(window, |state| state.state &= !WNDS_SENDSIZEMOVEMSGS);
    let client = state.client;
    let (kind, size) = if state.style & WS_MAXIMIZE != 0 {
        (SIZE_MAXIMIZED, make_long(client.right - client.left, client.bottom - client.top))
    } else if state.style & WS_MINIMIZE != 0 {
        (SIZE_MINIMIZED, 0)
    } else {
        (SIZE_RESTORED, make_long(client.right - client.left, client.bottom - client.top))
    };
    let _ = send_message(window, WM_SIZE, kind, LParam::Value(size));
    let origin = match get(state.parent) {
        Some(parent) if !parent.is_desktop_window() => parent.state().client,
        _ => Rect::default(),
    };
    let _ =
        send_message(window, WM_MOVE, 0, LParam::Value(make_long(client.left - origin.left, client.top - origin.top)));
}

/// MAKELONG(`low`, `high`) de deux valeurs sur 16 bits.
pub fn make_long(low: i32, high: i32) -> u32 {
    (low as u32 & 0xFFFF) | ((high as u32 & 0xFFFF) << 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(width: i32, height: i32) -> WindowState {
        let rect = Rect::new(0, 0, width, height);
        WindowState { window: rect, client: rect, ..WindowState::default() }
    }

    #[test]
    fn a_top_level_window_takes_its_menu_bar_at_its_creation() {
        let exists = |handle: u32| handle == 0x0003_002A;
        assert_eq!(creation_menu(0, 0x0003_002A, exists), Ok(0x0003_002A), "overlapped: its bar");
        assert_eq!(creation_menu(WS_POPUP, 0x0003_002A, exists), Ok(0x0003_002A), "a popup too");
        assert_eq!(creation_menu(0, 0, exists), Ok(0), "no menu");
        assert_eq!(creation_menu(0, 0xDEAD_BEEF, exists), Err(ERROR_INVALID_MENU_HANDLE));
        assert_eq!(creation_menu(WS_CHILD, 7, exists), Ok(0), "a child's hMenu is its identifier");
        assert_eq!(creation_menu(WS_CHILD | WS_POPUP, 0x0003_002A, exists), Ok(0x0003_002A), "not a child");
    }

    #[test]
    fn properties_chain_from_the_wnd_and_back() {
        // What user32's IntGetProp walks: PropListHead.Flink, then each
        // entry's Flink, PropListItems times.
        let head = 0xBC00_0100;
        let blocks = [0xBC00_2000, 0xBC00_2010, 0xBC00_2020];
        let chain = property_chain(head, &blocks, &[(0xC001, 7, false), (0xC002, 8, true), (0xC003, 9, false)]);
        assert_eq!(chain.len(), 3);
        assert_eq!((chain[0].entry.flink, chain[0].entry.blink), (blocks[1], head));
        assert_eq!((chain[1].entry.flink, chain[1].entry.blink), (blocks[2], blocks[0]));
        assert_eq!((chain[2].entry.flink, chain[2].entry.blink), (head, blocks[1]), "the last one back to the head");
        assert_eq!((chain[1].atom, chain[1].data, chain[1].fs), (0xC002, 8, abi::user::PROPERTY_FLAG_SYSTEM));
        assert_eq!(chain[0].fs, 0, "an application's property");
        assert!(property_chain(head, &[], &[(1, 2, false)]).is_empty(), "no block, no entry");
    }

    #[test]
    fn a_long_of_the_extra_bytes_fits_in_them() {
        assert_eq!(extra_offset(8, 0), Some(0));
        assert_eq!(extra_offset(8, 4), Some(4));
        assert_eq!(extra_offset(8, 5), None, "one byte past the end");
        assert_eq!(extra_offset(0, 0), None, "no extra bytes");
        assert_eq!(extra_offset(8, -1), None, "a negative index is not a place");
        assert_eq!(extra_offset(u32::MAX, i32::MAX), Some(i32::MAX as u32));
        assert_eq!(extra_offset(16, i32::MAX), None);
    }

    #[test]
    fn the_kernel_sets_the_user_data_the_id_and_the_instance() {
        let mut state = WindowState { id_menu: 3, module: 0x0040_0000, ..WindowState::default() };
        assert_eq!(apply_long(&mut state, GWLP_USERDATA, 0x1234), Some(0));
        assert_eq!(apply_long(&mut state, GWLP_USERDATA, 0x5678), Some(0x1234));
        assert_eq!(state.user_data, 0x5678);
        assert_eq!(apply_long(&mut state, GWLP_ID, 9), Some(3));
        assert_eq!(apply_long(&mut state, GWLP_HINSTANCE, 0x0100_0000), Some(0x0040_0000));
        assert_eq!((state.id_menu, state.module), (9, 0x0100_0000));
        let before = state.clone();
        assert_eq!(apply_long(&mut state, GWL_STYLE, 0), None);
        assert_eq!(apply_long(&mut state, -100, 0), None);
        assert_eq!(state, before, "unchanged");
    }

    #[test]
    fn invalid_rectangles_add_up_in_the_client_area() {
        let mut state = window(100, 50);
        state.invalidate(Rect::new(10, 10, 20, 20), false);
        state.invalidate(Rect::new(80, 40, 200, 90), false);
        assert_eq!(state.update.bounds(), Rect::new(10, 10, 100, 50), "their union, cut to the client area");
        assert_eq!(state.update.area(), 10 * 10 + 20 * 10, "two pieces, not their bounds");
        assert_eq!(state.state & WNDS_SENDERASEBACKGROUND, 0, "no erase asked");
        state.invalidate(Rect::new(200, 200, 300, 300), true);
        assert_eq!(state.update.bounds(), Rect::new(10, 10, 100, 50), "outside: nothing");
        assert_eq!(state.state & WNDS_SENDERASEBACKGROUND, 0, "nor an erase");
    }

    #[test]
    fn begin_paint_validates_and_tells_whether_to_erase() {
        let mut state = window(100, 50);
        state.invalidate(Rect::new(0, 0, 100, 50), true);
        assert_ne!(state.state & WNDS_ERASEBACKGROUND, 0);
        assert!(state.begin_paint(), "erase first");
        assert_eq!((state.update.clone(), state.painting), (Region::default(), Rect::new(0, 0, 100, 50)));
        assert_eq!(state.state & (WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND), 0);
        assert!(!state.begin_paint(), "nothing more to erase");
        assert!(state.painting.is_empty(), "nor to paint");
    }

    #[test]
    fn rectangles_unite() {
        assert_eq!(Rect::new(0, 0, 10, 10).union(&Rect::new(5, -5, 20, 8)), Rect::new(0, -5, 20, 10));
    }

    #[test]
    fn a_create_struct_is_packed_with_its_strings() {
        let create = CreateStructW32 { x: 100, y: 50, cx: 400, cy: 300, style: WS_POPUP, ..CreateStructW32::default() };
        let name: Vec<u16> = "Mino".encode_utf16().collect();
        let class = ClassName::String("Cls".encode_utf16().collect());
        let packed = pack_create_struct(&create, &name, &class);
        let word = |at: usize| u32::from_le_bytes([packed[at], packed[at + 1], packed[at + 2], packed[at + 3]]);
        assert_eq!(word(0x24), 0x30, "the name right after the CREATESTRUCT");
        assert_eq!(word(0x28), 0x30 + 10, "then the class, after the name and its NUL");
        assert_eq!((word(0x1C), word(0x20)), (100, WS_POPUP), "x, style");
        let units: Vec<u16> = packed[0x30..].chunks_exact(2).map(|u| u16::from_le_bytes([u[0], u[1]])).collect();
        let expected: Vec<u16> = "Mino\0SCls\0".encode_utf16().collect();
        assert_eq!(units, expected);
        let by_atom = pack_create_struct(&create, &[], &ClassName::Atom(0xC00A));
        assert_eq!(by_atom.len(), 0x30 + 2 + 4, "an empty name's NUL, then A and the atom");
        assert_eq!(&by_atom[0x32..], &[b'A', 0, 0x0A, 0xC0]);
    }

    #[test]
    fn styles_of_a_new_window() {
        assert_eq!(new_window_styles(WS_POPUP | WS_VISIBLE, 0), (WS_POPUP | WS_CLIPSIBLINGS, 0, 0));
        assert_eq!(new_window_styles(WS_CHILD, WS_EX_WINDOWEDGE), (WS_CHILD, 0, 0), "no frame, no edge");
        let (style, ex_style, state) = new_window_styles(WS_THICKFRAME, WS_EX_SETANSICREATOR);
        assert_eq!(style, WS_THICKFRAME | WS_CLIPSIBLINGS | WS_CAPTION, "an overlapped window has a caption");
        assert_eq!((ex_style, state), (WS_EX_WINDOWEDGE, WNDS_SENDSIZEMOVEMSGS));
        assert_eq!(new_window_styles(WS_POPUP | WS_DLGFRAME, WS_EX_STATICEDGE).1, WS_EX_STATICEDGE, "a static edge");
        assert_eq!(new_window_styles(WS_POPUP, WS_EX_DLGMODALFRAME).1, WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE);
    }

    #[test]
    fn default_coordinates_without_a_monitor() {
        let none = StartupPlace::default();
        let mut overlapped = CreateParams { x: 10, cx: CW_USEDEFAULT as i32, ..CreateParams::default() };
        fix_coordinates(&mut overlapped, None, &none, || (1, 1));
        assert_eq!((overlapped.x, overlapped.y, overlapped.cx, overlapped.cy), (0, 0, 800, 600), "no monitor");
        let mut popup =
            CreateParams { style: WS_POPUP, x: CW_USEDEFAULT as i32, y: 7, cx: 30, cy: 40, ..CreateParams::default() };
        fix_coordinates(&mut popup, None, &none, || (1, 1));
        assert_eq!((popup.x, popup.y, popup.cx, popup.cy), (0, 0, 30, 40));
        let mut child = CreateParams { style: WS_CHILD, x: 5, y: 6, cx: -32768, cy: 9, ..CreateParams::default() };
        fix_coordinates(&mut child, None, &none, || (1, 1));
        assert_eq!((child.x, child.y, child.cx, child.cy), (5, 6, 0, 0), "a 16-bit CW_USEDEFAULT too");
        let mut wide = CreateParams { style: WS_CHILD, cx: 0x8000, cy: 9, ..CreateParams::default() };
        fix_coordinates(&mut wide, None, &none, || (1, 1));
        assert_eq!((wide.cx, wide.cy), (0x8000, 9), "32768 is a width");
    }

    #[test]
    fn default_coordinates_on_a_monitor() {
        let work = Some(Rect::new(0, 0, 1280, 800));
        let none = StartupPlace::default();
        let default = CW_USEDEFAULT as i32;
        let mut overlapped = CreateParams { x: default, y: 4, cx: default, cy: 7, ..CreateParams::default() };
        let show = fix_coordinates(&mut overlapped, work, &none, || (23, 23));
        assert_eq!((overlapped.x, overlapped.y, overlapped.cx, overlapped.cy), (23, 23, 960, 600), "cascade, 3/4");
        assert_eq!(show, 4, "its y: the command of ShowWindow (SW_SHOWNOACTIVATE)");
        let mut given = CreateParams { x: 10, y: 20, cx: 300, cy: default, ..CreateParams::default() };
        let show = fix_coordinates(&mut given, work, &none, || unreachable!("no cascade for a given place"));
        assert_eq!(show, SW_SHOW);
        assert_eq!((given.x, given.y, given.cx, given.cy), (10, 20, 300, 600), "3/4 of the height alone");
        let startup =
            StartupPlace { flags: STARTF_USEPOSITION | STARTF_USESIZE, x: 40, y: 50, cx: 640, cy: 480, show: 0 };
        let mut started = CreateParams { x: default, y: default, cx: default, ..CreateParams::default() };
        let show = fix_coordinates(&mut started, work, &startup, || unreachable!("STARTF_USEPOSITION"));
        assert_eq!(show, SW_SHOW, "y is CW_USEDEFAULT too");
        assert_eq!((started.x, started.y, started.cx, started.cy), (40, 50, 640, 480));
        let place_only = StartupPlace { flags: STARTF_USEPOSITION, ..startup };
        let mut placed = CreateParams { x: default, cx: default, ..CreateParams::default() };
        fix_coordinates(&mut placed, work, &place_only, || unreachable!("STARTF_USEPOSITION"));
        assert_eq!((placed.x, placed.y, placed.cx, placed.cy), (40, 50, 960, 600), "no STARTF_USESIZE");
    }

    #[test]
    fn compatibility_follows_the_expected_version() {
        assert_eq!(compatibility(0x0300), 0);
        assert_eq!(compatibility(0x030A), WNDS2_WIN31COMPAT);
        assert_eq!(compatibility(0x0400), WNDS2_WIN31COMPAT | WNDS2_WIN40COMPAT);
        assert_eq!(compatibility(0x0501), WNDS2_WIN31COMPAT | WNDS2_WIN40COMPAT | WNDS2_WIN50COMPAT);
    }

    #[test]
    fn the_client_area_stays_in_the_window() {
        let window = Rect::new(10, 10, 110, 60);
        assert_eq!(fix_client_rect(Rect::new(12, 30, 108, 58), window), Rect::new(12, 30, 108, 58));
        assert_eq!(fix_client_rect(Rect::new(0, 0, 200, 100), window), window);
        assert_eq!(fix_client_rect(Rect::new(120, 70, 130, 80), window), Rect::new(110, 60, 110, 60));
    }
}
