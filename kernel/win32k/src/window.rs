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
//! Une fenêtre recouvrante placée par défaut prend sa place et sa taille sur
//! le moniteur ([`fix_coordinates`], [`crate::monitor`]).
//!
//! Pas encore : DestroyWindow (les fenêtres d'un thread vivent autant que
//! lui), ShowWindow et SetWindowPos (une fenêtre créée visible reste
//! cachée, journalisé), les menus, les messages envoyés à un autre thread, la fenêtre des
//! messages (`HWND_MESSAGE`), les crochets, les régions (la région à mettre
//! à jour est un rectangle), les contextes de périphérique (WM_ERASEBKGND
//! reçoit 0), le fond d'écran, les fenêtres au premier plan
//! (`WS_EX_TOPMOST`), la mise en page de droite à gauche.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{NtStatus, STATUS_NOT_IMPLEMENTED};
use abi::peb32::Peb32;
use abi::process_parameters::RtlUserProcessParameters32;
use abi::teb32::Teb32;
use abi::user::{
    CallbackWnd32, ClientInfo32, Cls32, CreateStructW32, DeskInfoHead32, LargeUnicodeString32, MinMaxInfo32, Rect32,
    WindowProcArguments32, Wnd32, CSF_ANSIPROC, CSF_SERVERSIDEPROC, CSF_SYSTEMCLASS, CS_DBLCLKS, CW_USEDEFAULT,
    FNID_BUTTON, FNID_DESKTOP, FNID_GHOST, HWND_BOTTOM, HWND_MESSAGE, HWND_TOP, SIZE_RESTORED, STARTF_USEPOSITION,
    STARTF_USESIZE, TYPE_WINDOW, WC_DESKTOP, WINVER_WIN2K, WINVER_WIN31, WINVER_WINNT4, WM_CREATE, WM_ERASEBKGND,
    WM_GETMINMAXINFO, WM_MOVE, WM_NCCALCSIZE, WM_NCCREATE, WM_PAINT, WM_PARENTNOTIFY, WM_SIZE, WNDS2_WIN31COMPAT,
    WNDS2_WIN40COMPAT, WNDS2_WIN50COMPAT, WNDS2_WMCREATEMSGPROCESSED, WNDS_ANSICREATOR, WNDS_ANSIWINDOWPROC,
    WNDS_ERASEBACKGROUND, WNDS_MAXIMIZESTOMONITOR, WNDS_SENDERASEBACKGROUND, WNDS_SENDSIZEMOVEMSGS,
    WNDS_SERVERSIDEWINDOWPROC, WND_UNICODE, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS, WS_DLGFRAME,
    WS_EX_DLGMODALFRAME, WS_EX_NOPARENTNOTIFY, WS_EX_SETANSICREATOR, WS_EX_STATICEDGE, WS_EX_WINDOWEDGE, WS_MAXIMIZE,
    WS_MINIMIZE, WS_POPUP, WS_THICKFRAME, WS_VISIBLE,
};
use abi::winerror::{
    ERROR_CANNOT_FIND_WND_CLASS, ERROR_INVALID_WINDOW_HANDLE, ERROR_NOT_ENOUGH_MEMORY, ERROR_TLW_WITH_WSCHILD,
};
use hal::sync::KSpinLock;
use ke::usermem::UserPtr;
use ob::Object;

use crate::class::{Class, ClassName};
use crate::desktop::{Desktop, DesktopHeap};
use crate::gdi::dib::Rect;

/// COLOR_BACKGROUND : le pinceau de la classe du bureau, une couleur système
/// plus un.
const COLOR_BACKGROUND: u32 = 1;
/// Les octets de plus de la fenêtre du bureau : le PID et le TID que
/// DesktopWindowProc y range (DT_GWL_PROCESSID, DT_GWL_THREADID).
const DESKTOP_WND_EXTRA: u32 = 8;

/// Ce qui change d'une fenêtre.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    /// La région à mettre à jour, un rectangle (vide : rien).
    pub update: Rect,
    /// Le rectangle de la peinture en cours (BeginPaint, EndPaint).
    pub painting: Rect,
}

impl WindowState {
    /// InvalidateRect(…, `rect`, `erase`) : la région à mettre à jour
    /// s'étend à `rect` (dans la zone cliente), et le fond sera effacé.
    pub fn invalidate(&mut self, rect: Rect, erase: bool) {
        let rect = rect.intersect(&Rect::new(
            0,
            0,
            self.client.right - self.client.left,
            self.client.bottom - self.client.top,
        ));
        if rect.is_empty() {
            return;
        }
        self.update = if self.update.is_empty() { rect } else { self.update.union(&rect) };
        if erase {
            self.state |= WNDS_SENDERASEBACKGROUND | WNDS_ERASEBACKGROUND;
        }
    }

    /// BeginPaint : la région à mettre à jour est validée et devient le
    /// rectangle de la peinture ; rend s'il faut d'abord effacer le fond.
    pub fn begin_paint(&mut self) -> bool {
        self.painting = core::mem::take(&mut self.update);
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
}

impl Window {
    /// Ce qui change d'elle.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn state(&self) -> WindowState {
        *self.state.lock()
    }

    /// L'adresse du serveur de son `WND`.
    pub fn server_address(&self) -> u32 {
        self.heap.server_address(self.wnd)
    }

    /// C'est la fenêtre d'un bureau.
    pub fn is_desktop_window(&self) -> bool {
        self.desktop_name.is_some()
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        WINDOWS.lock().remove(&self.handle);
        let _ = crate::handles::free(self.handle);
        self.heap.free(self.wnd, self.wnd_size);
        if let Some(name) = self.state.lock().name {
            self.heap.free(name.at, name.capacity);
        }
        if self.class.is_none() {
            self.heap.free(self.cls, size_of::<Cls32>() as u32);
        }
    }
}

/// Les fenêtres vivantes, par handle.
static WINDOWS: KSpinLock<BTreeMap<u32, Weak<Window>>> = KSpinLock::new(BTreeMap::new());

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
        id_menu: state.id_menu,
        name,
        cb_wnd_extra: window.wnd_size - size_of::<Wnd32>() as u32,
        spwnd_last_active: self_address,
        icon_pos: [-1, -1],
        max_pos: [-1, -1],
        bits: if state.unicode { WND_UNICODE } else { 0 },
        ..Wnd32::default()
    }
}

/// Réécrit le `WND` de `window`.
fn write(window: &Window) -> Result<(), NtStatus> {
    let state = window.state();
    window.heap.section.write_kernel(u64::from(window.wnd), wnd(window, &state).as_bytes())
}

/// Change ce qui change de `window` par `change`, puis réécrit son `WND`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn change(window: &Window, change: impl FnOnce(&mut WindowState)) -> WindowState {
    update(window, change)
}

/// Change ce qui change de `window` par `change`, puis réécrit son `WND`.
fn update(window: &Window, change: impl FnOnce(&mut WindowState)) -> WindowState {
    let state = {
        let mut state = window.state.lock();
        change(&mut state);
        *state
    };
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
        server_window_proc(window, WM_PAINT, 0, 0);
    }
}

/// La procédure dans win32k d'une fenêtre qui en a une ; `None` pour une
/// autre (sa procédure est alors celle du client).
fn server_window_proc(window: &Window, message: u32, wparam: u32, lparam: u32) -> Option<u32> {
    let state = window.state();
    match state.fnid {
        FNID_DESKTOP if state.state & WNDS_SERVERSIDEWINDOWPROC != 0 => {
            Some(desktop_window_proc(window, message, wparam, lparam))
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

/// co_IntSendMessage : `message` à la procédure de `window`, une fenêtre du
/// thread courant ; rend ce qu'elle rend. Une procédure dans win32k
/// (DesktopWindowProc) est appelée directement ; une procédure du client
/// l'est par un rappel, le `CLIENTINFO` du thread désignant la fenêtre.
///
/// # Errors
/// `STATUS_NOT_IMPLEMENTED` pour une fenêtre d'un autre thread (journalisé
/// une fois) ; celles du rappel.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn send_message(window: &Arc<Window>, message: u32, wparam: u32, lparam: LParam<'_>) -> Result<u32, NtStatus> {
    let value = match &lparam {
        LParam::Value(value) => *value,
        LParam::Buffer { .. } => 0,
    };
    if let Some(result) = server_window_proc(window, message, wparam, value) {
        return Ok(result);
    }
    let thread = crate::convert_current_thread()?;
    if thread.server != window.pti {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: message {message:#x} sent to a window of another thread: not yet");
        }
        return Err(STATUS_NOT_IMPLEMENTED);
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

/// Ce que les paramètres du processus (STARTUPINFO) disent de la place et
/// de la taille d'une fenêtre recouvrante : `WindowFlags` (`STARTF_*`),
/// `StartingX`, `StartingY`, `CountX`, `CountY`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartupPlace {
    pub flags: u32,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
}

/// IntFixWindowCoordinates. Une fenêtre recouvrante sans moniteur (`work`
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
) {
    let default = |value: i32| value as u32 == CW_USEDEFAULT || value == i32::from(i16::MIN);
    if params.style & (WS_POPUP | WS_CHILD) == 0 {
        let Some(work) = work else {
            (params.x, params.y, params.cx, params.cy) = (0, 0, 800, 600);
            return;
        };
        let (width, height) = (work.right - work.left, work.bottom - work.top);
        if default(params.x) {
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
        return;
    }
    if default(params.x) {
        (params.x, params.y) = (0, 0);
    }
    if default(params.cx) {
        (params.cx, params.cy) = (0, 0);
    }
}

/// Le `STARTUPINFO` du processus courant, dans ses paramètres
/// (`Peb->ProcessParameters`) ; rien s'ils sont illisibles.
fn startup_place() -> StartupPlace {
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

/// IntLinkHwnd : `window` entre parmi les enfants de `parent`, en haut de
/// l'ordre Z (`HWND_TOP`) ou en bas (`HWND_BOTTOM`).
fn link(window: &Arc<Window>, parent: &Arc<Window>, after: u32) {
    let first = parent.state().child;
    if after == HWND_BOTTOM && first != 0 {
        let mut last = first;
        while let Some(next) = get(last).map(|sibling| sibling.state().next).filter(|&next| next != 0) {
            last = next;
        }
        update(window, |state| (state.prev, state.next) = (last, 0));
        if let Some(last) = get(last) {
            update(&last, |state| state.next = window.handle);
        }
        return;
    }
    update(window, |state| (state.prev, state.next) = (0, first));
    if let Some(first) = get(first) {
        update(&first, |state| state.prev = window.handle);
    }
    update(parent, |state| state.child = window.handle);
}

/// IntUnlinkWindow : `window` quitte les enfants de son parent.
fn unlink(window: &Arc<Window>) {
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
/// (WM_PARENTNOTIFY). Elle appartient au thread.
///
/// # Errors
/// L'erreur Win32, s'il y en a une : sans classe,
/// `ERROR_CANNOT_FIND_WND_CLASS` ; une fenêtre fille sans parent,
/// `ERROR_TLW_WITH_WSCHILD` ; un parent ou un propriétaire qui n'existe pas,
/// `ERROR_INVALID_WINDOW_HANDLE` ; le tas plein,
/// `ERROR_NOT_ENOUGH_MEMORY`. Aucune quand la procédure refuse WM_NCCREATE
/// ou WM_CREATE, ou que le thread n'a pas de bureau.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système. Rappelle le mode utilisateur.
pub fn create_window(mut params: CreateParams) -> Result<Arc<Window>, Option<u32>> {
    let thread = crate::convert_current_thread().map_err(|_| None)?;
    let Some(desktop) = thread.desktop() else { return Err(None) };
    let desktop = desktop.desktop;
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
    let startup = if params.style & (WS_POPUP | WS_CHILD) == 0 { startup_place() } else { StartupPlace::default() };
    let work = crate::monitor::primary().map(|monitor| monitor.work);
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
    });
    WINDOWS.lock().insert(handle, Arc::downgrade(&window));
    if !params.name.is_empty() && set_text(&window, &params.name).is_err() {
        return Err(Some(ERROR_NOT_ENOUGH_MEMORY));
    }
    if kind != WS_CHILD && params.menu == 0 && class.menu.unicode != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("the menu of a class (co_IntCallLoadMenu)", &REPORTED);
    }

    drop((thread, desktop, process_info));

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
    if !accepted.is_ok_and(|accepted| accepted != 0) {
        return Err(None);
    }
    link(&window, &parent, if style & (WS_CHILD | WS_MAXIMIZE) == WS_CHILD { HWND_BOTTOM } else { HWND_TOP });

    // WM_NCCALCSIZE: the client area.
    let mut calc = rect_bytes(rect);
    let _ = send_message(&window, WM_NCCALCSIZE, 0, LParam::Buffer { bytes: &mut calc, write_back: true });
    let client = fix_client_rect(rect_of(&calc), rect);
    update(&window, |state| state.client = client);

    // WM_CREATE.
    let mut packed = pack_create_struct(&create, &params.name, &class_name);
    let created = send_message(&window, WM_CREATE, 0, LParam::Buffer { bytes: &mut packed, write_back: true });
    if !created.is_ok_and(|result| result != u32::MAX) {
        unlink(&window);
        return Err(None);
    }
    update(&window, |state| state.state2 |= WNDS2_WMCREATEMSGPROCESSED);
    if window.state().state & WNDS_SENDSIZEMOVEMSGS == 0 {
        send_size_move(&window, &parent);
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
        static REPORTED: AtomicBool = AtomicBool::new(false);
        report_missing("showing a window created visible (co_WinPosShowWindow)", &REPORTED);
    }
    let thread = crate::convert_current_thread().map_err(|_| None)?;
    thread.windows.lock().push(window.clone());
    Ok(window)
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

/// co_WinPosSendSizeMove : WM_SIZE (la taille de la zone cliente), puis
/// WM_MOVE (sa position, dans la zone cliente du parent).
fn send_size_move(window: &Arc<Window>, parent: &Arc<Window>) {
    let state = update(window, |state| state.state &= !WNDS_SENDSIZEMOVEMSGS);
    let client = state.client;
    let size = (((client.bottom - client.top) as u32 & 0xFFFF) << 16) | ((client.right - client.left) as u32 & 0xFFFF);
    let _ = send_message(window, WM_SIZE, SIZE_RESTORED, LParam::Value(size));
    let origin = if parent.is_desktop_window() { Rect::default() } else { parent.state().client };
    let (x, y) = (client.left - origin.left, client.top - origin.top);
    let _ = send_message(window, WM_MOVE, 0, LParam::Value(((y as u32 & 0xFFFF) << 16) | (x as u32 & 0xFFFF)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(width: i32, height: i32) -> WindowState {
        let rect = Rect::new(0, 0, width, height);
        WindowState { window: rect, client: rect, ..WindowState::default() }
    }

    #[test]
    fn invalid_rectangles_add_up_in_the_client_area() {
        let mut state = window(100, 50);
        state.invalidate(Rect::new(10, 10, 20, 20), false);
        state.invalidate(Rect::new(80, 40, 200, 90), false);
        assert_eq!(state.update, Rect::new(10, 10, 100, 50), "their union, cut to the client area");
        assert_eq!(state.state & WNDS_SENDERASEBACKGROUND, 0, "no erase asked");
        state.invalidate(Rect::new(200, 200, 300, 300), true);
        assert_eq!(state.update, Rect::new(10, 10, 100, 50), "outside: nothing");
        assert_eq!(state.state & WNDS_SENDERASEBACKGROUND, 0, "nor an erase");
    }

    #[test]
    fn begin_paint_validates_and_tells_whether_to_erase() {
        let mut state = window(100, 50);
        state.invalidate(Rect::new(0, 0, 100, 50), true);
        assert_ne!(state.state & WNDS_ERASEBACKGROUND, 0);
        assert!(state.begin_paint(), "erase first");
        assert_eq!((state.update, state.painting), (Rect::default(), Rect::new(0, 0, 100, 50)));
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
        let mut overlapped = CreateParams { x: default, y: 5, cx: default, cy: 7, ..CreateParams::default() };
        fix_coordinates(&mut overlapped, work, &none, || (23, 23));
        assert_eq!((overlapped.x, overlapped.y, overlapped.cx, overlapped.cy), (23, 23, 960, 600), "cascade, 3/4");
        let mut given = CreateParams { x: 10, y: 20, cx: 300, cy: default, ..CreateParams::default() };
        fix_coordinates(&mut given, work, &none, || unreachable!("no cascade for a given place"));
        assert_eq!((given.x, given.y, given.cx, given.cy), (10, 20, 300, 600), "3/4 of the height alone");
        let startup = StartupPlace { flags: STARTF_USEPOSITION | STARTF_USESIZE, x: 40, y: 50, cx: 640, cy: 480 };
        let mut started = CreateParams { x: default, cx: default, ..CreateParams::default() };
        fix_coordinates(&mut started, work, &startup, || unreachable!("STARTF_USEPOSITION"));
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
