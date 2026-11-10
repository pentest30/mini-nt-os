//! Les services de la souris et de l'état du thread (`win32k::mouse`,
//! `win32k::queue`) : NtUserSetCapture, NtUserCallNoParam
//! (ReleaseCapture), NtUserGetThreadState (GetFocus, GetActiveWindow,
//! GetCapture) ; GetCursorPos est une routine de NtUserCallOneParam
//! (`super::message`).
//!
//! Ils rendent une valeur : un échec rend 0, avec l'erreur Win32 comme
//! dernière erreur.

use abi::ntstatus::NtStatus;
use abi::user::{
    NOPARAM_ROUTINE_RELEASECAPTURE, THREADSTATE_ACTIVEWINDOW, THREADSTATE_CAPTUREWINDOW, THREADSTATE_FOCUSWINDOW,
    THREADSTATE_GETCURSOR,
};
use abi::winerror::{dos_error, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_WINDOW_HANDLE};
use alloc::sync::Arc;
use win32k::gui::ThreadInfo;

/// Les routines de NtUserCallNoParam demandées sans être implémentées.
static UNSUPPORTED_NO_PARAM_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallNoParam");
/// Les routines de NtUserGetThreadState demandées sans être implémentées.
static UNSUPPORTED_THREAD_STATES: super::ClassReport = super::ClassReport::new("NtUserGetThreadState");

/// 0 avec `error` comme dernière erreur.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// Le `THREADINFO` du thread courant (déjà un thread GUI : `super::dispatch`).
fn current() -> Arc<ThreadInfo> {
    win32k::convert_current_thread().expect("a GUI thread at a win32k service")
}

/// NtUserSetCapture(hWnd) : HWND, la fenêtre qui avait la capture pour le
/// thread (`win32k::mouse::set_capture`) ; 0 sans rien changer pour une
/// fenêtre d'un autre thread ; 0 et `ERROR_INVALID_WINDOW_HANDLE` pour une
/// fenêtre inconnue.
pub(super) fn nt_user_set_capture(arguments: &[u32]) -> NtStatus {
    let window = match arguments[0] {
        0 => None,
        hwnd => match win32k::window::get(hwnd) {
            Some(window) => Some(window),
            None => return fail(ERROR_INVALID_WINDOW_HANDLE),
        },
    };
    NtStatus(win32k::mouse::set_capture(&current(), window.as_ref()))
}

/// NtUserCallNoParam(Routine) : `NOPARAM_ROUTINE_RELEASECAPTURE`, la
/// capture rendue (TRUE) ; `NOPARAM_ROUTINE_CREATEMENU` et
/// `NOPARAM_ROUTINE_CREATEMENUPOPUP` (`0` et `1`, les premières de l'enum
/// de XP SP2), un menu neuf — son handle (`win32k::menu`). Une autre rend
/// 0 et `ERROR_CALL_NOT_IMPLEMENTED`, journalisée une fois.
pub(super) fn nt_user_call_no_param(arguments: &[u32]) -> NtStatus {
    match arguments[0] {
        NOPARAM_ROUTINE_RELEASECAPTURE => {
            win32k::mouse::set_capture(&current(), None);
            NtStatus(1)
        }
        0 | 1 => match win32k::menu::create() {
            Ok(handle) => NtStatus(handle),
            Err(status) => fail(abi::winerror::dos_error(status)),
        },
        routine => {
            UNSUPPORTED_NO_PARAM_ROUTINES.report(routine);
            fail(ERROR_CALL_NOT_IMPLEMENTED)
        }
    }
}

/// NtUserGetThreadState(Routine) : la fenêtre qui a le clavier
/// (`THREADSTATE_FOCUSWINDOW`), la fenêtre active
/// (`THREADSTATE_ACTIVEWINDOW`) ou celle qui a la capture
/// (`THREADSTATE_CAPTUREWINDOW`) dans la file du thread ; son curseur
/// (`THREADSTATE_GETCURSOR` : GetCursor, `win32k::cursor`). Une autre rend
/// 0, journalisée une fois.
pub(super) fn nt_user_get_thread_state(arguments: &[u32]) -> NtStatus {
    let routine = arguments[0];
    if routine == THREADSTATE_GETCURSOR {
        return NtStatus(current().cursor.load(core::sync::atomic::Ordering::Acquire));
    }
    let field = match routine {
        THREADSTATE_FOCUSWINDOW => |queue: &mut win32k::queue::QueueState| queue.focus,
        THREADSTATE_ACTIVEWINDOW => |queue: &mut win32k::queue::QueueState| queue.active,
        THREADSTATE_CAPTUREWINDOW => |queue: &mut win32k::queue::QueueState| queue.capture,
        _ => {
            UNSUPPORTED_THREAD_STATES.report(routine);
            return NtStatus(0);
        }
    };
    NtStatus(current().queue.with(field).0)
}

/// ONEPARAM_ROUTINE_GETCURSORPOS : la place du curseur dans le POINT en
/// `point` (TRUE) ; 0 et l'erreur de la faute si l'écriture faute.
pub(super) fn get_cursor_pos(point: u32) -> NtStatus {
    let (x, y) = win32k::mouse::cursor_or_center();
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&x.to_le_bytes());
    bytes[4..].copy_from_slice(&y.to_le_bytes());
    match ke::usermem::copy_to_user(u64::from(point), &bytes) {
        Ok(()) => NtStatus(1),
        Err(status) => fail(dos_error(status)),
    }
}
