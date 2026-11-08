//! Les services des minuteries de USER (`win32k::timer`) : NtUserSetTimer,
//! NtUserSetSystemTimer, NtUserKillTimer, NtUserCallHwndParam
//! (KillSystemTimer, et SetDialogPointer), NtUserValidateTimerCallback.
//!
//! Ils rendent une valeur (un identifiant, un BOOL) : un échec rend 0, avec
//! l'erreur Win32 comme dernière erreur.

use abi::ntstatus::NtStatus;
use abi::user::{HWNDPARAM_ROUTINE_KILLSYSTEMTIMER, HWNDPARAM_ROUTINE_SETDIALOGPOINTER};
use abi::winerror::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_WINDOW_HANDLE};
use alloc::sync::Arc;
use win32k::gui::ThreadInfo;
use win32k::timer::TimerKey;
use win32k::window::Window;

/// Les routines de NtUserCallHwndParam demandées sans être implémentées.
static UNSUPPORTED_HWND_PARAM_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallHwndParam");

/// 0 avec `error` comme dernière erreur.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// Le `THREADINFO` du thread courant (déjà un thread GUI : `super::dispatch`).
fn current() -> Arc<ThreadInfo> {
    win32k::convert_current_thread().expect("a GUI thread at a win32k service")
}

/// La fenêtre `hwnd`, `None` pour 0 ; `Err` pour une fenêtre inconnue.
fn window_of(hwnd: u32) -> Result<Option<Arc<Window>>, ()> {
    match hwnd {
        0 => Ok(None),
        _ => win32k::window::get(hwnd).map(Some).ok_or(()),
    }
}

/// SetTimer ou SetSystemTimer : rend l'identifiant de la minuterie ; pour
/// une fenêtre, `nIDEvent`, ou 1 s'il est nul (son message porte 0).
fn set(arguments: &[u32], system: bool) -> NtStatus {
    let [hwnd, id, elapse, procedure] = arguments[..4] else { unreachable!("4 arguments") };
    let Ok(window) = window_of(hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE) };
    let key = TimerKey { hwnd: window.as_ref().map_or(0, |window| window.handle), id, system };
    // SetSystemTimer: the procedure is ignored (ReactOS too).
    let procedure = if system { 0 } else { procedure };
    match win32k::timer::set_timer(&current(), window.as_deref(), key, elapse, procedure) {
        Ok(0) if window.is_some() => NtStatus(1),
        Ok(id) => NtStatus(id),
        Err(error) => fail(error),
    }
}

/// NtUserSetTimer(hWnd, nIDEvent, uElapse, lpTimerFunc) : la minuterie de
/// la fenêtre `hWnd` (du processus courant), ou du thread courant sans
/// fenêtre (un identifiant libre, sauf si le thread en a une de
/// `nIDEvent`) ; WM_TIMER toutes les `uElapse` ms. 0 pour une fenêtre
/// inconnue (`ERROR_INVALID_WINDOW_HANDLE`), d'un autre processus
/// (`ERROR_ACCESS_DENIED`).
pub(super) fn nt_user_set_timer(arguments: &[u32]) -> NtStatus {
    set(arguments, false)
}

/// NtUserSetSystemTimer(hWnd, nIDEvent, uElapse, lpTimerFunc) : de même,
/// une minuterie du système (WM_SYSTIMER), sans procédure.
pub(super) fn nt_user_set_system_timer(arguments: &[u32]) -> NtStatus {
    set(arguments, true)
}

/// KillTimer ou KillSystemTimer : TRUE si la minuterie existait.
fn kill(hwnd: u32, id: u32, system: bool) -> NtStatus {
    let Ok(window) = window_of(hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE) };
    let key = TimerKey { hwnd: window.as_ref().map_or(0, |window| window.handle), id, system };
    NtStatus(u32::from(win32k::timer::kill_timer(&current(), key)))
}

/// NtUserKillTimer(hWnd, uIDEvent) : retire la minuterie ; FALSE si elle
/// n'existait pas.
pub(super) fn nt_user_kill_timer(arguments: &[u32]) -> NtStatus {
    let [hwnd, id] = arguments[..2] else { unreachable!("2 arguments") };
    kill(hwnd, id, false)
}

/// NtUserCallHwndParam(hWnd, Param, Routine) : KillSystemTimer
/// (`HWNDPARAM_ROUTINE_KILLSYSTEMTIMER`) ; les autres routines sont
/// journalisées une fois et échouent (`ERROR_CALL_NOT_IMPLEMENTED`).
pub(super) fn nt_user_call_hwnd_param(arguments: &[u32]) -> NtStatus {
    let [hwnd, param, routine] = arguments[..3] else { unreachable!("3 arguments") };
    match routine {
        HWNDPARAM_ROUTINE_KILLSYSTEMTIMER => kill(hwnd, param, true),
        HWNDPARAM_ROUTINE_SETDIALOGPOINTER => {
            let Ok(Some(window)) = window_of(hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE) };
            if let Some(process) = ps::ethread::current_thread().map(|thread| thread.process().pid()) {
                win32k::window::set_dialog_pointer(&window, process, param);
            }
            // ReactOS rend 0 : user32 relit le WND.
            NtStatus(0)
        }
        _ => {
            UNSUPPORTED_HWND_PARAM_ROUTINES.report(routine);
            fail(ERROR_CALL_NOT_IMPLEMENTED)
        }
    }
}

/// NtUserValidateTimerCallback(lParam) : TRUE si le processus courant a une
/// minuterie de procédure `lParam` (DispatchMessage de `user32` ne l'appelle
/// qu'à cette condition).
pub(super) fn nt_user_validate_timer_callback(arguments: &[u32]) -> NtStatus {
    NtStatus(u32::from(win32k::timer::validate_callback(arguments[0])))
}
