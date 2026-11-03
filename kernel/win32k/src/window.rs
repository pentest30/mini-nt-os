//! Les fenêtres (02 §7.2) : pour l'instant la fenêtre du bureau, que
//! ReactOS crée avec chaque bureau (IntCreateDesktop, par IntCreateWindow).
//!
//! Une fenêtre a son `WND` dans le tas de son bureau, où `user32` le lit par
//! son handle ([`crate::handles`], `TYPE_WINDOW`) ; win32k garde à côté ce
//! qui change (style, rectangles, région à mettre à jour) et réécrit le
//! `WND` à chaque changement. Sa classe (`CLS`) est dans le même tas.
//!
//! Sa procédure tourne dans win32k (`WNDS_SERVERSIDEWINDOWPROC`), comme
//! DesktopWindowProc : WM_PAINT valide la région à mettre à jour
//! (BeginPaint, qui envoie d'abord WM_ERASEBKGND), puis EndPaint ;
//! WM_ERASEBKGND peint le fond du bureau (IntPaintDesktop). Montrer la
//! fenêtre l'invalide entière, puis la met à jour aussitôt
//! ([`show_desktop_window`]) : en attendant le thread du bureau et les
//! files de messages, WM_PAINT est envoyé directement.
//!
//! Pas encore : les autres fenêtres (NtUserCreateWindowEx), les classes de
//! `user32` et la table des atomes, les files de messages, les régions (la
//! région à mettre à jour est un rectangle), les contextes de périphérique
//! (WM_ERASEBKGND reçoit 0 : le fond est peint dans le rectangle de
//! BeginPaint), la fenêtre des messages du bureau, le fond d'écran.

use alloc::sync::Arc;
use core::mem::{offset_of, size_of};

use abi::ntstatus::NtStatus;
use abi::user::{
    Cls32, DeskInfoHead32, Rect32, Wnd32, CSF_SERVERSIDEPROC, CSF_SYSTEMCLASS, CS_DBLCLKS, FNID_DESKTOP, TYPE_WINDOW,
    WC_DESKTOP, WM_ERASEBKGND, WM_PAINT, WNDS_ERASEBACKGROUND, WNDS_SENDERASEBACKGROUND, WNDS_SERVERSIDEWINDOWPROC,
    WS_CLIPCHILDREN, WS_POPUP, WS_VISIBLE,
};
use hal::sync::KSpinLock;

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
    /// WNDS_*.
    pub state: u32,
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

/// Une fenêtre.
pub struct Window {
    pub handle: u32,
    /// La position de son `WND` dans le tas de son bureau.
    pub wnd: u32,
    /// Celle de sa classe.
    pub cls: u32,
    pub fnid: u32,
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
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = crate::handles::free(self.handle);
    }
}

fn rect32(rect: Rect) -> Rect32 {
    Rect32 { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }
}

/// Le `WND` de `window`, dans le tas `heap` de son bureau.
fn wnd(heap: &DesktopHeap, window: &Window, state: &WindowState) -> Wnd32 {
    Wnd32 {
        handle: window.handle,
        rpdesk: heap.server_base,
        self_address: heap.server_address(window.wnd),
        state: state.state,
        style: state.style,
        fnid: window.fnid,
        rc_window: rect32(state.window),
        rc_client: rect32(state.client),
        pcls: heap.server_address(window.cls),
        cb_wnd_extra: DESKTOP_WND_EXTRA,
        ..Wnd32::default()
    }
}

/// Réécrit le `WND` de `window` dans `heap`.
fn write(heap: &DesktopHeap, window: &Window, state: &WindowState) -> Result<(), NtStatus> {
    heap.section.write_kernel(u64::from(window.wnd), wnd(heap, window, state).as_bytes())
}

/// IntCreateWindow pour un bureau neuf : sa fenêtre (la classe du bureau,
/// `WS_POPUP | WS_CLIPCHILDREN`, cachée, de `width` × `height`), son `WND`
/// et sa classe dans `heap`, son handle ; le `DESKTOPINFO` en `desk_info`
/// la désigne (`spwnd`).
///
/// # Errors
/// Celles du tas et de la table des handles.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create_desktop_window(
    heap: &DesktopHeap,
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
    heap.section.write_kernel(u64::from(cls), class.as_bytes())?;
    let wnd = heap.alloc(size_of::<Wnd32>() as u32 + DESKTOP_WND_EXTRA)?;
    let handle = crate::handles::alloc(heap.server_address(wnd), 0, TYPE_WINDOW)?;
    let rect = Rect::new(0, 0, width as i32, height as i32);
    let state = WindowState {
        style: WS_POPUP | WS_CLIPCHILDREN,
        state: WNDS_SERVERSIDEWINDOWPROC,
        window: rect,
        client: rect,
        ..WindowState::default()
    };
    let window = Arc::new(Window { handle, wnd, cls, fnid: FNID_DESKTOP, state: KSpinLock::new(state) });
    write(heap, &window, &state)?;
    let spwnd = u64::from(desk_info) + offset_of!(DeskInfoHead32, spwnd) as u64;
    heap.section.write_kernel(spwnd, &heap.server_address(wnd).to_le_bytes())?;
    Ok(window)
}

/// Change ce qui change de `window` par `change`, puis réécrit son `WND`.
fn update(desktop: &Desktop, window: &Window, change: impl FnOnce(&mut WindowState)) -> WindowState {
    let state = {
        let mut state = window.state.lock();
        change(&mut state);
        *state
    };
    let _ = write(&desktop.heap, window, &state);
    state
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
    update(desktop, window, |state| {
        state.style |= WS_VISIBLE;
        state.window = rect;
        state.client = rect;
        state.invalidate(rect, true);
    });
    update_window(desktop, window);
}

/// IntHideDesktop : la fenêtre du bureau n'est plus visible.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn hide_desktop_window(desktop: &Desktop) {
    update(desktop, &desktop.window, |state| state.style &= !WS_VISIBLE);
}

/// UpdateWindow : une fenêtre visible qui a une région à mettre à jour
/// reçoit WM_PAINT.
fn update_window(desktop: &Desktop, window: &Window) {
    let state = window.state();
    if state.style & WS_VISIBLE != 0 && !state.update.is_empty() {
        send_message(desktop, window, WM_PAINT, 0, 0);
    }
}

/// Envoie un message à la procédure de `window`, qui tourne dans win32k ;
/// rend son résultat.
pub fn send_message(desktop: &Desktop, window: &Window, message: u32, wparam: u32, lparam: u32) -> u32 {
    match window.fnid {
        FNID_DESKTOP => desktop_window_proc(desktop, window, message, wparam, lparam),
        _ => 0,
    }
}

/// DesktopWindowProc : WM_PAINT valide la région à mettre à jour (avec
/// WM_ERASEBKGND d'abord s'il faut effacer le fond), WM_ERASEBKGND peint le
/// fond du bureau dans le rectangle de la peinture.
fn desktop_window_proc(desktop: &Desktop, window: &Window, message: u32, _wparam: u32, _lparam: u32) -> u32 {
    match message {
        WM_PAINT => {
            let mut erase = false;
            update(desktop, window, |state| erase = state.begin_paint());
            if erase {
                send_message(desktop, window, WM_ERASEBKGND, 0, 0);
            }
            // EndPaint.
            update(desktop, window, |state| state.painting = Rect::default());
            0
        }
        WM_ERASEBKGND => {
            paint_desktop(desktop, window.state().painting);
            1
        }
        _ => 0,
    }
}

/// IntPaintDesktop : le fond du bureau, de la couleur système
/// `COLOR_BACKGROUND`, dans `rect` (journalisé : c'est rare).
fn paint_desktop(desktop: &Desktop, rect: Rect) {
    let painted = crate::display::draw(|screen| screen.fill_rect(rect, crate::gdi::syscolor::BACKGROUND));
    if painted {
        log::info!(
            "win32k: the desktop window of {} erased (WM_ERASEBKGND), {}x{}",
            desktop.name,
            rect.right - rect.left,
            rect.bottom - rect.top
        );
    }
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
}
