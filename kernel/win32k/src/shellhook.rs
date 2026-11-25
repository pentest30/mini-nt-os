//! Les crochets du shell (ReactOS `desktop.c` : IntRegisterShellHookWindow,
//! IntDeRegisterShellHookWindow, co_IntShellHookNotify ; `focus.c` :
//! UpdateShellHook, IntCheckFullscreen ; `winpos.c`, `window.c`, comme
//! spécification) : la liste des tâches de la barre d'`explorer` s'inscrit
//! (RegisterShellHookWindow, pour son bureau) et reçoit le message enregistré
//! « SHELLHOOK » (`gpsi->uiShellMsg`), posté, avec un code HSHELL_* en
//! `wParam` et la fenêtre en `lParam`, quand une fenêtre de premier niveau
//! est montrée ([`window_shown`]), cachée ([`window_hidden`]), détruite
//! ([`window_destroyed`]), renommée ([`title_changed`]) ou activée
//! ([`activated`]) : elle y ajoute, retire ou met en avant ses boutons. Les
//! fenêtres inscrites sont celles du bureau d'entrée qui reçoivent ces
//! messages ([`notify`]).
//!
//! Pas encore : les crochets WH_SHELL, HSHELL_TASKMAN, HSHELL_LANGUAGE,
//! HSHELL_APPCOMMAND, HSHELL_GETMINRECT.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::user::{
    Msg32, HSHELL_APPCOMMAND, HSHELL_LANGUAGE, HSHELL_REDRAW, HSHELL_RUDEAPPACTIVATED, HSHELL_WINDOWACTIVATED,
    HSHELL_WINDOWCREATED, HSHELL_WINDOWDESTROYED, SWP_NOACTIVATE, WS_CHILD, WS_EX_APPWINDOW, WS_EX_TOOLWINDOW,
    WS_POPUP, WS_VISIBLE,
};
use hal::sync::KSpinLock;

use crate::atom::AtomName;
use crate::gdi::dib::Rect;
use crate::window::{self, Window};

/// Le message « SHELLHOOK » (un atome de USER, comme RegisterWindowMessage
/// le donne), une fois ajouté.
static SHELL_MESSAGE: AtomicU32 = AtomicU32::new(0);

/// La dernière fenêtre en plein écran annoncée (ghwndOldFullscreen).
static OLD_FULLSCREEN: KSpinLock<u32> = KSpinLock::new(0);

/// Les fenêtres inscrites d'un bureau (`ShellHookWindows`).
pub struct ShellHookWindows {
    windows: KSpinLock<Vec<u32>>,
}

impl Default for ShellHookWindows {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellHookWindows {
    pub const fn new() -> Self {
        Self { windows: KSpinLock::new(Vec::new()) }
    }

    /// IntRegisterShellHookWindow : `hwnd` s'inscrit, une fois au plus,
    /// en dernier ; `false` si la mémoire manque.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn register(&self, hwnd: u32) -> bool {
        let mut windows = self.windows.lock();
        windows.retain(|&window| window != hwnd);
        if windows.try_reserve(1).is_err() {
            return false;
        }
        windows.push(hwnd);
        true
    }

    /// IntDeRegisterShellHookWindow : `hwnd` n'est plus inscrite ; `false`
    /// si elle ne l'était pas.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn deregister(&self, hwnd: u32) -> bool {
        let mut windows = self.windows.lock();
        let before = windows.len();
        windows.retain(|&window| window != hwnd);
        windows.len() != before
    }

    /// Les fenêtres inscrites, dans l'ordre de leur inscription.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn list(&self) -> Vec<u32> {
        self.windows.lock().clone()
    }
}

/// Le message « SHELLHOOK », ajouté à la table des atomes de USER au premier
/// appel ; `None` si elle est pleine.
fn shell_message() -> Option<u32> {
    let message = SHELL_MESSAGE.load(Ordering::Relaxed);
    if message != 0 {
        return Some(message);
    }
    let name: Vec<u16> = "SHELLHOOK".encode_utf16().collect();
    let atom = u32::from(crate::atom::add(AtomName::String(&name)).ok()?);
    SHELL_MESSAGE.store(atom, Ordering::Relaxed);
    Some(atom)
}

/// HWND_ROUTINE_REGISTERSHELLHOOKWINDOW : `window` s'inscrit sur le bureau
/// du thread courant ; `false` sans bureau.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn register(window: &Window) -> bool {
    current_desktop().is_some_and(|desktop| desktop.shell_hooks.register(window.handle))
}

/// HWND_ROUTINE_DEREGISTERSHELLHOOKWINDOW : `hwnd` n'est plus inscrite sur le
/// bureau du thread courant, ou, sans lui, sur le bureau d'entrée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn deregister(hwnd: u32) -> bool {
    current_desktop().or_else(crate::desktop::input_desktop).is_some_and(|desktop| desktop.shell_hooks.deregister(hwnd))
}

/// Le bureau du thread courant, s'il en a un.
fn current_desktop() -> Option<Arc<ob::Object<crate::desktop::Desktop>>> {
    let thread = ps::ethread::current_thread()?;
    let info = crate::gui::thread_info(thread.win32_thread()?);
    info.desktop().map(|desktop| desktop.desktop)
}

/// co_IntShellHookNotify : le message « SHELLHOOK » posté à chaque fenêtre
/// inscrite du bureau d'entrée, `code` en `wParam` ; en `lParam`, `lparam`
/// pour HSHELL_LANGUAGE et HSHELL_APPCOMMAND, `wparam` sinon (la fenêtre).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn notify(code: u32, wparam: u32, lparam: u32) {
    let Some(message) = shell_message() else { return };
    let Some(desktop) = crate::desktop::input_desktop() else { return };
    let param = if code == HSHELL_LANGUAGE || code == HSHELL_APPCOMMAND { lparam } else { wparam };
    let time = hal::timer::get_tick_count() as u32;
    for hwnd in desktop.shell_hooks.list() {
        let Some(window) = window::get(hwnd) else { continue };
        let Some(thread) = crate::gui::thread_info_of(window.pti) else { continue };
        let posted = Msg32 { hwnd, message, w_param: code, l_param: param, time, ..Msg32::default() };
        crate::queue::post(&thread, posted);
    }
}

/// Le parent de `window` est la fenêtre du bureau (une fenêtre de premier
/// niveau).
fn is_top_level(window: &Window) -> bool {
    window::get(window.state().parent).is_some_and(|parent| parent.is_desktop_window())
}

/// Une fenêtre de premier niveau sans propriétaire (`!spwndOwner &&
/// !IntGetParent`).
fn is_unowned_top_level(window: &Window) -> bool {
    let state = window.state();
    state.owner == 0 && state.style & WS_CHILD == 0
}

/// co_WinPosSetWindowPos, SWP_SHOWWINDOW : une fenêtre qu'une barre des
/// tâches montre (une fille `WS_POPUP` avec `WS_EX_APPWINDOW` ; sinon
/// `WS_EX_APPWINDOW`, ou ni `WS_EX_TOOLWINDOW`, ni propriétaire, ni parent
/// que la fenêtre du bureau) : HSHELL_WINDOWCREATED, puis, sans
/// `SWP_NOACTIVATE`, [`activated`]. Appelée avant que `WS_VISIBLE` lui soit
/// mis.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn window_shown(window: &Window, flags: u32) {
    if window.is_desktop_window() {
        return;
    }
    let state = window.state();
    let shown = if state.style & WS_CHILD != 0 {
        state.style & WS_POPUP != 0 && state.ex_style & WS_EX_APPWINDOW != 0
    } else {
        state.ex_style & WS_EX_APPWINDOW != 0
            || (state.ex_style & WS_EX_TOOLWINDOW == 0
                && state.owner == 0
                && (state.parent == 0 || is_top_level(window)))
    };
    if shown {
        notify(HSHELL_WINDOWCREATED, window.handle, 0);
        if flags & SWP_NOACTIVATE == 0 {
            activated(window);
        }
    }
}

/// co_WinPosSetWindowPos, SWP_HIDEWINDOW : une fenêtre de premier niveau
/// cachée, HSHELL_WINDOWDESTROYED.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn window_hidden(window: &Window) {
    if is_top_level(window) {
        notify(HSHELL_WINDOWDESTROYED, window.handle, 0);
    }
}

/// co_UserDestroyWindow : une fenêtre de premier niveau sans propriétaire
/// détruite, HSHELL_WINDOWDESTROYED.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn window_destroyed(window: &Window) {
    if is_unowned_top_level(window) {
        notify(HSHELL_WINDOWDESTROYED, window.handle, 0);
    }
}

/// NtUserDefSetText : une fenêtre de premier niveau sans propriétaire
/// renommée, HSHELL_REDRAW.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn title_changed(window: &Window) {
    if is_unowned_top_level(window) {
        notify(HSHELL_REDRAW, window.handle, 0);
    }
}

/// UpdateShellHook : `window` activée. En plein écran
/// ([`is_fullscreen`]), HSHELL_RUDEAPPACTIVATED, une fois tant qu'elle le
/// reste ; sinon HSHELL_WINDOWACTIVATED, pour elle si c'est une fenêtre de
/// premier niveau qu'une barre des tâches montre, pour aucune (0) sinon.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn activated(window: &Window) {
    if check_fullscreen(window) {
        return;
    }
    let ex_style = window.state().ex_style;
    let shown = is_top_level(window) && (ex_style & WS_EX_TOOLWINDOW == 0 || ex_style & WS_EX_APPWINDOW != 0);
    notify(HSHELL_WINDOWACTIVATED, if shown { window.handle } else { 0 }, 0);
}

/// IntCheckFullscreen : `window` est en plein écran ; annoncée
/// (HSHELL_RUDEAPPACTIVATED) si elle ne l'était pas déjà.
fn check_fullscreen(window: &Window) -> bool {
    let monitor = crate::monitor::primary().map(|monitor| monitor.rect);
    {
        let mut old = OLD_FULLSCREEN.lock();
        if *old != 0 && !window::get(*old).is_some_and(|old| is_fullscreen(&old, monitor)) {
            *old = 0;
        }
    }
    if !is_fullscreen(window, monitor) {
        return false;
    }
    let announce = core::mem::replace(&mut *OLD_FULLSCREEN.lock(), window.handle) != window.handle;
    if announce {
        notify(HSHELL_RUDEAPPACTIVATED, window.handle, 1);
    }
    true
}

/// IntIsWindowFullscreen : `window`, visible et pas une fille, couvre tout le
/// moniteur principal (`monitor`, l'écran sans lui).
fn is_fullscreen(window: &Window, monitor: Option<Rect>) -> bool {
    let state = window.state();
    if state.style & WS_VISIBLE == 0 || state.style & WS_CHILD != 0 {
        return false;
    }
    let screen = || {
        let metric = |index| crate::metrics::get(index);
        Rect::new(0, 0, metric(abi::user::sm::CXSCREEN), metric(abi::user::sm::CYSCREEN))
    };
    covers(state.window, monitor.unwrap_or_else(screen))
}

/// `window` couvre `monitor` entier.
pub fn covers(window: Rect, monitor: Rect) -> bool {
    window.intersect(&monitor) == monitor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_registers_once_and_in_order() {
        let windows = ShellHookWindows::new();
        assert!(windows.register(0x10));
        assert!(windows.register(0x20));
        assert!(windows.register(0x10), "again: it goes last");
        assert_eq!(windows.list(), [0x20, 0x10]);
        assert!(windows.deregister(0x20));
        assert!(!windows.deregister(0x20), "already gone");
        assert_eq!(windows.list(), [0x10]);
    }

    #[test]
    fn a_window_is_fullscreen_when_it_covers_the_whole_monitor() {
        let monitor = Rect::new(0, 0, 1280, 800);
        assert!(covers(Rect::new(0, 0, 1280, 800), monitor));
        assert!(covers(Rect::new(-4, -4, 1284, 804), monitor), "a maximized frame beyond the edges");
        assert!(!covers(Rect::new(0, 0, 1280, 770), monitor), "above a taskbar");
        assert!(!covers(Rect::new(100, 100, 400, 300), monitor));
    }
}
