//! Le caret (`win32k::caret`) : NtUserCreateCaret, NtUserShowCaret,
//! NtUserHideCaret, NtUserGetCaretPos, NtUserGetCaretBlinkTime ; DestroyCaret,
//! SetCaretPos et SetCaretBlinkTime passent par NtUserCallNoParam,
//! NtUserCallTwoParam et NtUserCallOneParam. Comme dans win32k, un échec rend
//! FALSE et met l'erreur Win32 dans le TEB du thread.

use abi::ntstatus::NtStatus;
use abi::winerror::dos_error;
use ke::usermem::copy_to_user;

/// BOOL d'un résultat, l'erreur de Win32 posée.
fn boolean(result: Result<(), u32>) -> NtStatus {
    match result {
        Ok(()) => NtStatus(1),
        Err(error) => {
            let _ = win32k::set_last_error(error);
            NtStatus(0)
        }
    }
}

/// NtUserCreateCaret(hWnd, hBitmap, nWidth, nHeight) : BOOL
/// (`win32k::caret::create`).
pub(super) fn nt_user_create_caret(arguments: &[u32]) -> NtStatus {
    let [hwnd, bitmap, width, height] = arguments[..4] else { unreachable!("4 arguments") };
    boolean(win32k::caret::create(hwnd, bitmap, width as i32, height as i32))
}

/// NtUserShowCaret(hWnd) : BOOL (`win32k::caret::show`).
pub(super) fn nt_user_show_caret(arguments: &[u32]) -> NtStatus {
    boolean(win32k::caret::show(arguments[0]))
}

/// NtUserHideCaret(hWnd) : BOOL (`win32k::caret::hide`).
pub(super) fn nt_user_hide_caret(arguments: &[u32]) -> NtStatus {
    boolean(win32k::caret::hide(arguments[0]))
}

/// NtUserGetCaretPos(lpPoint) : BOOL ; le POINT du client reçoit le coin
/// du caret du thread.
pub(super) fn nt_user_get_caret_pos(arguments: &[u32]) -> NtStatus {
    let (x, y) = win32k::caret::pos();
    let bytes: alloc::vec::Vec<u8> = [x, y].iter().flat_map(|word| word.to_le_bytes()).collect();
    boolean(copy_to_user(u64::from(arguments[0]), &bytes).map_err(dos_error))
}

/// NtUserGetCaretBlinkTime() : le temps de clignotement, en millisecondes.
pub(super) fn nt_user_get_caret_blink_time(_arguments: &[u32]) -> NtStatus {
    NtStatus(win32k::caret::blink_time())
}
