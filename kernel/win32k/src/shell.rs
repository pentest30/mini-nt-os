//! La fenêtre du shell (NtUserSetShellWindowEx, ReactOS `window.c`) : le
//! bureau d'`explorer` (« Progman ») et la fenêtre de son fond (la liste de
//! ses icônes) se déclarent une fois par station (ShellWindow,
//! ShellListView) et dans le `DESKTOPINFO` du bureau du thread
//! (`hShellWindow`, `spwndShell`, `spwndBkGnd`, `ppiShellProcess`, que
//! `user32` lit pour GetShellWindow). La fenêtre du shell passe au bas de
//! l'ordre Z (`WNDS2_BOTTOMMOST`) et SetWindowPos ne l'en fait plus bouger
//! ([`is_shell_window`]) : les autres fenêtres, la barre des tâches
//! comprise, restent au-dessus. Détruite, elle quitte la station et le
//! `DESKTOPINFO` ([`forget`]).
//!
//! Pas encore : le raccourci Ctrl+Échap vers le shell (SC_TASKLIST,
//! UserRegisterHotKey), faute de RegisterHotKey.

use alloc::sync::Arc;

use abi::user::{HWND_BOTTOM, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, WNDS2_BOTTOMMOST, WS_EX_TOPMOST};
use abi::winerror::{ERROR_INVALID_HANDLE, ERROR_INVALID_WINDOW_HANDLE};
use ob::Object;

use crate::gui::{ProcessWindowStation, ThreadInfo};
use crate::window::{self, Window};

/// La station du processus courant, s'il en a une.
fn current_station() -> Option<ProcessWindowStation> {
    let thread = ps::ethread::current_thread()?;
    crate::gui::existing_process_info(thread.process())?.window_station()
}

/// Le `THREADINFO` du thread courant, s'il est un thread GUI.
fn current_thread_info() -> Option<Arc<ThreadInfo>> {
    ps::ethread::current_thread()?.win32_thread().map(crate::gui::thread_info)
}

/// Au premier plan (`WS_EX_TOPMOST`).
fn is_topmost(window: &Window) -> bool {
    window.state().ex_style & WS_EX_TOPMOST != 0
}

/// NtUserSetShellWindowEx : `shell` devient la fenêtre du shell de la
/// station du processus courant, et `list_view` celle de son fond. Refusé
/// s'il y a déjà un shell, ou si l'une est au premier plan (`Err(None)`,
/// sans erreur, comme ReactOS). La fenêtre du shell passe au bas de l'ordre
/// Z sans être activée ; le `DESKTOPINFO` du bureau du thread courant les
/// reçoit, avec le `PROCESSINFO` du processus.
///
/// # Errors
/// `ERROR_INVALID_WINDOW_HANDLE` pour une fenêtre qui n'existe pas,
/// `ERROR_INVALID_HANDLE` pour un processus sans station.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système. Rappelle le mode utilisateur
/// (WM_WINDOWPOSCHANGING, WM_WINDOWPOSCHANGED).
pub fn set_shell_window(shell: u32, list_view: u32) -> Result<(), Option<u32>> {
    let shell_window = window::get(shell).ok_or(Some(ERROR_INVALID_WINDOW_HANDLE))?;
    let background = window::get(list_view).ok_or(Some(ERROR_INVALID_WINDOW_HANDLE))?;
    let station = current_station().ok_or(Some(ERROR_INVALID_HANDLE))?;
    if station.station.with_shell(|windows| windows.shell != 0) {
        return Err(None);
    }
    if (list_view != shell && is_topmost(&background)) || is_topmost(&shell_window) {
        return Err(None);
    }
    window::change(&shell_window, |state| state.state2 |= WNDS2_BOTTOMMOST);
    crate::winpos::set_window_pos(&shell_window, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    if !station.station.with_shell(|windows| windows.claim(shell, list_view)) {
        return Err(None);
    }
    let process = ps::ethread::current_thread().and_then(|thread| crate::gui::existing_process_info(thread.process()));
    if let (Some(thread), Some(process)) = (current_thread_info(), process) {
        if let Some(desktop) = thread.desktop() {
            let _ = desktop.desktop.set_shell(&shell_window, &background, process.server);
        }
    }
    drop(station);
    Ok(())
}

/// UserGetShellWindow : `hwnd` est la fenêtre du shell de la station du
/// processus courant ; SetWindowPos ne change pas son rang dans l'ordre Z.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn is_shell_window(hwnd: u32) -> bool {
    current_station().is_some_and(|station| station.station.with_shell(|windows| windows.shell == hwnd))
}

/// IntDestroyWindow et co_UserDestroyWindow : `hwnd`, détruite, n'est plus
/// ni la fenêtre du shell ni celle de son fond de la station du bureau du
/// thread courant, ni le `hShellWindow` de ce bureau.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn forget(hwnd: u32) {
    let Some(desktop) = current_thread_info().and_then(|thread| thread.desktop()) else { return };
    let desktop: &Arc<Object<crate::desktop::Desktop>> = &desktop.desktop;
    desktop.station.with_shell(|windows| windows.forget(hwnd));
    desktop.forget_shell_window(hwnd);
}
