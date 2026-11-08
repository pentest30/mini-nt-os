//! Les services des files de messages (`win32k::queue`) :
//! NtUserPostThreadMessage, NtUserPostMessage, NtUserPeekMessage,
//! NtUserGetMessage, NtUserWaitMessage, NtUserCallOneParam
//! (PostQuitMessage, GetQueueStatus), et NtUserMessageCall
//! (DefWindowProc du noyau, `win32k::defwnd`).
//!
//! Ils rendent une valeur (un BOOL, un état) : un échec rend 0, avec
//! l'erreur Win32 comme dernière erreur.

use abi::ntstatus::NtStatus;
use abi::user::{
    Msg32, FNID_DEFWINDOWPROC, FNID_FIRST, ONEPARAM_ROUTINE_GETQUEUESTATUS, ONEPARAM_ROUTINE_POSTQUITMESSAGE,
    PM_REMOVE, PM_VALID_FLAGS, QS_ALLINPUT, QS_ALLPOSTMESSAGE, QS_SMRESULT, WM_MAXIMUM, WM_QUIT,
};
use abi::winerror::{
    dos_error, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_INVALID_WINDOW_HANDLE,
    ERROR_MESSAGE_SYNC_ONLY,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use ke::usermem::copy_to_user;
use win32k::gui::ThreadInfo;
use win32k::queue::{self, Filter};

/// HWND_BROADCAST : un message pour toutes les fenêtres de premier niveau.
const HWND_BROADCAST: u32 = 0xFFFF;

/// Les routines de NtUserCallOneParam demandées sans être implémentées.
static UNSUPPORTED_ONE_PARAM_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallOneParam");
/// Les types de NtUserMessageCall demandés sans être implémentés : un bit
/// par FNID depuis `FNID_FIRST` (le dernier vaut pour tous les autres).
static UNSUPPORTED_MESSAGE_CALLS: AtomicU32 = AtomicU32::new(0);
/// Un message posté à une fenêtre a déjà été demandé.
static WINDOW_POST_REPORTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// 0 avec `error` comme dernière erreur.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// Le `THREADINFO` du thread courant (déjà un thread GUI : `super::dispatch`).
fn current() -> Arc<ThreadInfo> {
    win32k::convert_current_thread().expect("a GUI thread at a win32k service")
}

/// Le message `message` (`wparam`, `lparam`) pour `hwnd`, daté de maintenant.
fn message(hwnd: u32, message: u32, wparam: u32, lparam: u32) -> Msg32 {
    let time = hal::timer::get_tick_count() as u32;
    Msg32 { hwnd, message, w_param: wparam, l_param: lparam, time, ..Msg32::default() }
}

/// NtUserPostThreadMessage(idThread, Msg, wParam, lParam) : le message, posté
/// à la file du thread `idThread` (un thread GUI) ; FALSE pour un message qui
/// porte un pointeur (`ERROR_MESSAGE_SYNC_ONLY`), un thread inconnu
/// (`ERROR_INVALID_PARAMETER`) ou qui n'est pas un thread GUI.
pub(super) fn nt_user_post_thread_message(arguments: &[u32]) -> NtStatus {
    let [tid, msg, wparam, lparam] = arguments[..4] else { unreachable!("4 arguments") };
    let thread = match ps::ethread::lookup_thread(tid) {
        Ok(thread) => thread,
        Err(status) => return fail(dos_error(status)),
    };
    let Some(info) = thread.win32_thread() else { return NtStatus(0) };
    if queue::is_pointer_message(msg, wparam) {
        return fail(ERROR_MESSAGE_SYNC_ONLY);
    }
    queue::post(&win32k::gui::thread_info(info), message(0, msg, wparam, lparam));
    NtStatus(1)
}

/// NtUserPostMessage(hWnd, Msg, wParam, lParam) (UserPostMessage) : sans
/// fenêtre, le message est posté au thread courant ; à une fenêtre, à la
/// file du thread qui l'a créée ; à toutes les fenêtres (`HWND_BROADCAST`),
/// à aucune encore. FALSE pour un message qui porte un pointeur
/// (`ERROR_MESSAGE_SYNC_ONLY`) ou une fenêtre inconnue
/// (`ERROR_INVALID_WINDOW_HANDLE`). La fenêtre du bureau n'a pas de thread
/// (pas encore de thread du bureau) : le message est perdu, journalisé une
/// fois.
pub(super) fn nt_user_post_message(arguments: &[u32]) -> NtStatus {
    let [hwnd, msg, wparam, lparam] = arguments[..4] else { unreachable!("4 arguments") };
    if queue::is_pointer_message(msg, wparam) {
        return fail(ERROR_MESSAGE_SYNC_ONLY);
    }
    match hwnd {
        0 => {
            queue::post(&current(), message(0, msg, wparam, lparam));
            NtStatus(1)
        }
        HWND_BROADCAST => NtStatus(1),
        _ => {
            let Some(window) = win32k::window::get(hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE) };
            match win32k::gui::thread_info_of(window.pti) {
                Some(thread) => queue::post(&thread, message(window.handle, msg, wparam, lparam)),
                None => {
                    if !WINDOW_POST_REPORTED.swap(true, core::sync::atomic::Ordering::Relaxed) {
                        log::warn!("sys: NtUserPostMessage to a window without a thread ({hwnd:#x}): dropped");
                    }
                }
            }
            NtStatus(1)
        }
    }
}

/// Écrit `message` en `address`.
fn give(address: u32, message: &Msg32) -> Result<(), NtStatus> {
    ke::usermem::copy_to_user(u64::from(address), message.as_bytes())
}

/// NtUserPeekMessage(pMsg, hWnd, MsgFilterMin, MsgFilterMax, RemoveMsg) :
/// le premier message de la file du thread que demandent la fenêtre et
/// l'intervalle, sorti avec `PM_REMOVE` ; FALSE sans message, ou pour un
/// drapeau inconnu (`ERROR_INVALID_FLAGS`).
pub(super) fn nt_user_peek_message(arguments: &[u32]) -> NtStatus {
    let [msg, hwnd, min, max, remove] = arguments[..5] else { unreachable!("5 arguments") };
    if remove & !PM_VALID_FLAGS != 0 {
        return fail(ERROR_INVALID_FLAGS);
    }
    let filter = Filter { hwnd, min, max };
    match queue::peek(&current(), &filter, remove & PM_REMOVE != 0) {
        None => NtStatus(0),
        Some(found) => match give(msg, &found) {
            Ok(()) => NtStatus(1),
            Err(status) => fail(dos_error(status)),
        },
    }
}

/// NtUserGetMessage(pMsg, hWnd, MsgFilterMin, MsgFilterMax) : le premier
/// message demandé de la file du thread, sorti ; attend qu'il en arrive un.
/// TRUE, ou FALSE pour WM_QUIT ; FALSE pour un intervalle au-delà de
/// `WM_MAXIMUM` (`ERROR_INVALID_PARAMETER`).
pub(super) fn nt_user_get_message(arguments: &[u32]) -> NtStatus {
    let [msg, hwnd, min, max] = arguments[..4] else { unreachable!("4 arguments") };
    if (min | max) & !WM_MAXIMUM != 0 {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let found = match queue::get(&current(), &Filter { hwnd, min, max }) {
        Ok(found) => found,
        Err(status) => return fail(dos_error(status)),
    };
    match give(msg, &found) {
        Ok(()) => NtStatus(u32::from(found.message != WM_QUIT)),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserDispatchMessage(pMsg) : le message à la procédure de sa fenêtre
/// (IntDispatchMessage) ; rend ce qu'elle rend, 0 sans fenêtre ou pour un
/// `pMsg` illisible (l'erreur de Win32 de la faute).
pub(super) fn nt_user_dispatch_message(arguments: &[u32]) -> NtStatus {
    let message = match read_message(arguments[0]) {
        Ok(message) => message,
        Err(status) => return fail(dos_error(status)),
    };
    match win32k::window::dispatch_message(&message) {
        Ok(result) => NtStatus(result),
        Err(status) => fail(dos_error(status)),
    }
}

/// Le MSG en `address`, chez le processus courant (sans `time` ni `pt`).
pub(super) fn read_message(address: u32) -> Result<Msg32, NtStatus> {
    let mut bytes = [0u8; core::mem::size_of::<Msg32>()];
    ke::usermem::copy_from_user(&mut bytes, u64::from(address))?;
    let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    Ok(Msg32 { hwnd: word(0), message: word(4), w_param: word(8), l_param: word(12), ..Msg32::default() })
}

/// NtUserWaitMessage() : attend qu'un message arrive dans la file du thread,
/// s'il n'y en a pas ; TRUE.
pub(super) fn nt_user_wait_message(_arguments: &[u32]) -> NtStatus {
    match queue::wait_message(&current()) {
        Ok(()) => NtStatus(1),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserCallOneParam(Param, Routine) : la routine, qui rend une valeur.
/// `ONEPARAM_ROUTINE_POSTQUITMESSAGE` : WM_QUIT de code `Param` pour le
/// thread (TRUE) ; `ONEPARAM_ROUTINE_GETQUEUESTATUS` : l'état de sa file
/// pour les bits `Param` (dans `QS_ALLINPUT | QS_ALLPOSTMESSAGE |
/// QS_SMRESULT`) ; `ONEPARAM_ROUTINE_RELEASEDC` : le DC `Param` retourne au
/// cache (UserReleaseDC : 1, ou 0 pour un DC qui n'en est pas un pris par
/// le processus) ; `ONEPARAM_ROUTINE_GETCURSORPOS` : la place du curseur
/// dans le POINT `Param` (`super::mouse::get_cursor_pos`). Une autre rend 0
/// et `ERROR_CALL_NOT_IMPLEMENTED`, journalisée une fois.
pub(super) fn nt_user_call_one_param(arguments: &[u32]) -> NtStatus {
    let (param, routine) = (arguments[0], arguments[1]);
    match routine {
        abi::user::ONEPARAM_ROUTINE_RELEASEDC => NtStatus(u32::from(win32k::dce::release_dc(param))),
        abi::user::ONEPARAM_ROUTINE_GETCURSORPOS => super::mouse::get_cursor_pos(param),
        ONEPARAM_ROUTINE_POSTQUITMESSAGE => {
            queue::post_quit(&current(), param);
            NtStatus(1)
        }
        ONEPARAM_ROUTINE_GETQUEUESTATUS => {
            let flags = param as u16 & (QS_ALLINPUT | QS_ALLPOSTMESSAGE | QS_SMRESULT);
            NtStatus(queue::status(&current(), flags))
        }
        _ => {
            UNSUPPORTED_ONE_PARAM_ROUTINES.report(routine);
            fail(ERROR_CALL_NOT_IMPLEMENTED)
        }
    }
}

/// NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi).
/// `FNID_DEFWINDOWPROC` : le traitement par défaut du message
/// (`win32k::defwnd::def_window_proc`), dont le résultat va en `ResultInfo`
/// s'il n'est pas nul ; TRUE. FALSE pour une fenêtre qui n'existe pas
/// (`ERROR_INVALID_WINDOW_HANDLE`, sans fenêtre : `hWnd` nul est permis),
/// une structure du message illisible ou un `ResultInfo` où l'on ne peut
/// pas écrire (ReactOS n'a pas de garde autour du traitement : une faute y
/// arrêterait le système). Les autres types (la barre de défilement, le
/// bureau, les menus, SendMessage et ses variantes…) rendent FALSE et
/// `ERROR_CALL_NOT_IMPLEMENTED`, journalisés une fois chacun. `Ansi` ne
/// sert pas encore : aucun des messages traités n'a de texte.
pub(super) fn nt_user_message_call(arguments: &[u32]) -> NtStatus {
    let (handle, message, wparam, lparam, result_info, kind) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    if kind != FNID_DEFWINDOWPROC {
        let bit = 1 << kind.wrapping_sub(FNID_FIRST).min(31);
        if UNSUPPORTED_MESSAGE_CALLS.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            log::warn!("sys: NtUserMessageCall type {kind:#x} is not implemented");
        }
        return fail(ERROR_CALL_NOT_IMPLEMENTED);
    }
    let window = match handle {
        0 => None,
        _ => match win32k::window::get(handle) {
            Some(window) => Some(window),
            None => return fail(ERROR_INVALID_WINDOW_HANDLE),
        },
    };
    let Ok(result) = win32k::defwnd::def_window_proc(window.as_ref(), message, wparam, lparam) else {
        return NtStatus(0);
    };
    if result_info != 0 && copy_to_user(u64::from(result_info), &result.to_le_bytes()).is_err() {
        return NtStatus(0);
    }
    NtStatus(1)
}
