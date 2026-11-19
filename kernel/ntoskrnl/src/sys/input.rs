//! Les services du clavier (`win32k::input`) : NtUserGetKeyState,
//! NtUserGetAsyncKeyState, NtUserGetKeyboardState, NtUserToUnicodeEx,
//! NtUserTranslateMessage et NtUserSetFocus ; les raccourcis
//! (`win32k::hotkey`) : NtUserRegisterHotKey, NtUserUnregisterHotKey.
//!
//! Ils rendent une valeur : un échec rend 0, avec l'erreur Win32 comme
//! dernière erreur.

use abi::ntstatus::NtStatus;
use abi::user::{MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN};
use abi::winerror::{
    dos_error, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_INVALID_WINDOW_HANDLE, ERROR_WINDOW_OF_OTHER_THREAD,
};
use ke::usermem::{copy_from_user, copy_to_user};
use win32k::hotkey::HotKey;
use win32k::kbdtables::{KeyState, DOWN, LOCKED};

/// SC_KEY_UP : le bit d'un scan code relâché (ToUnicodeEx ne traduit pas).
const SC_KEY_UP: u32 = 0x8000;
/// Les caractères au plus que ToUnicodeEx écrit.
const MAX_CHARS: u32 = 0x1000;

/// 0 avec `error` comme dernière erreur.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// NtUserGetKeyState(nVirtKey) : SHORT, l'état de la touche vu du thread
/// (0xFF80 enfoncée, 1 basculée) ; 0 et `ERROR_INVALID_PARAMETER` au-delà de
/// 0xFF.
pub(super) fn nt_user_get_key_state(arguments: &[u32]) -> NtStatus {
    let Ok(vk) = u8::try_from(arguments[0]) else { return fail(ERROR_INVALID_PARAMETER) };
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    NtStatus(u32::from(win32k::input::key_state(&thread, vk)))
}

/// NtUserGetAsyncKeyState(Key) : SHORT, 0x8000 si la touche est enfoncée, 1
/// si elle l'a été depuis l'appel précédent ; 0 et `ERROR_INVALID_PARAMETER`
/// au-delà de 0xFF.
pub(super) fn nt_user_get_async_key_state(arguments: &[u32]) -> NtStatus {
    let Ok(vk) = u8::try_from(arguments[0]) else { return fail(ERROR_INVALID_PARAMETER) };
    NtStatus(u32::from(win32k::input::async_key_state(vk)))
}

/// NtUserGetKeyboardState(lpKeyState) : BOOL ; les 256 octets de l'état du
/// clavier vu du thread (0x80 enfoncée, 1 basculée).
pub(super) fn nt_user_get_keyboard_state(arguments: &[u32]) -> NtStatus {
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    match copy_to_user(u64::from(arguments[0]), &win32k::input::keyboard_state(&thread)) {
        Ok(()) => NtStatus(1),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserToUnicodeEx(wVirtKey, wScanCode, lpKeyState, pwszBuff, cchBuff,
/// wFlags, dwhkl) : INT, les caractères de la touche dans l'état donné
/// (négatif : une touche morte), écrits dans les `cchBuff` caractères de
/// `pwszBuff` (le reste à zéro), dans la disposition `dwhkl` ou celle du
/// thread. 0 pour une touche relâchée (`SC_KEY_UP`), au-delà de 0xFF, un
/// état illisible, un tampon trop grand ou qu'on ne peut écrire.
pub(super) fn nt_user_to_unicode_ex(arguments: &[u32]) -> NtStatus {
    let [vk, scan, state, buffer, count, _flags, hkl] = arguments[..7] else { unreachable!("7 arguments") };
    let Ok(vk) = u8::try_from(vk) else { return NtStatus(0) };
    if scan & SC_KEY_UP != 0 || count as i32 <= 0 || count > MAX_CHARS {
        return NtStatus(0);
    }
    let mut keys: KeyState = [0; 256];
    if let Err(status) = copy_from_user(&mut keys, u64::from(state)) {
        return fail(dos_error(status));
    }
    keys.iter_mut().for_each(|key| *key &= DOWN | LOCKED);
    let thread = win32k::convert_current_thread().ok();
    let mut chars = alloc::vec![0u16; count as usize];
    let written = win32k::input::to_unicode_ex(hkl, thread.as_deref(), vk, &keys, &mut chars);
    if written == 0 {
        return NtStatus(0);
    }
    let bytes: alloc::vec::Vec<u8> = chars.iter().flat_map(|ch| ch.to_le_bytes()).collect();
    match copy_to_user(u64::from(buffer), &bytes) {
        Ok(()) => NtStatus(written as u32),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserTranslateMessage(lpMsg, flags) : BOOL ; le caractère d'un
/// WM_KEYDOWN ou WM_SYSKEYDOWN posté à la file du thread
/// (`win32k::input::translate_message`).
pub(super) fn nt_user_translate_message(arguments: &[u32]) -> NtStatus {
    let message = match super::message::read_message(arguments[0]) {
        Ok(message) => message,
        Err(status) => return fail(dos_error(status)),
    };
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    NtStatus(u32::from(win32k::input::translate_message(&thread, &message)))
}

/// NtUserSetFocus(hWnd) : HWND, la fenêtre qui avait le clavier dans la
/// file du thread (`win32k::input::set_focus`) ; 0 et
/// `ERROR_INVALID_WINDOW_HANDLE` pour une fenêtre inconnue.
pub(super) fn nt_user_set_focus(arguments: &[u32]) -> NtStatus {
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    let window = match arguments[0] {
        0 => None,
        hwnd => match win32k::window::get(hwnd) {
            Some(window) => Some(window),
            None => return fail(ERROR_INVALID_WINDOW_HANDLE),
        },
    };
    NtStatus(win32k::input::set_focus(&thread, window.as_ref()))
}

/// NtUserSetActiveWindow(hWnd) : HWND, la fenêtre active d'avant dans la
/// file du thread si elle vit encore (`win32k::input::set_active`) ; 0 et
/// `ERROR_INVALID_WINDOW_HANDLE` pour une fenêtre inconnue, 0 sans rien
/// changer pour la fenêtre d'un autre thread.
pub(super) fn nt_user_set_active_window(arguments: &[u32]) -> NtStatus {
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    let window = match arguments[0] {
        0 => None,
        hwnd => match win32k::window::get(hwnd) {
            Some(window) => Some(window),
            None => return fail(ERROR_INVALID_WINDOW_HANDLE),
        },
    };
    NtStatus(win32k::input::set_active(&thread, window.as_ref()))
}

/// NtUserRegisterHotKey(hWnd, id, fsModifiers, vk) : BOOL, le raccourci
/// `fsModifiers` et `vk` posé pour la fenêtre `hWnd` du thread, ou pour le
/// thread sans fenêtre (`win32k::hotkey::register`). FALSE et
/// `ERROR_INVALID_FLAGS` pour un autre modificateur que MOD_ALT,
/// MOD_CONTROL, MOD_SHIFT et MOD_WIN ; `ERROR_INVALID_WINDOW_HANDLE` pour une
/// fenêtre inconnue, `ERROR_WINDOW_OF_OTHER_THREAD` pour celle d'un autre
/// thread ; `ERROR_HOTKEY_ALREADY_REGISTERED` pour une combinaison qui en a
/// un ; FALSE sans erreur pour VK_PACKET.
pub(super) fn nt_user_register_hot_key(arguments: &[u32]) -> NtStatus {
    let [hwnd, id, modifiers, vk] = arguments[..4] else { unreachable!("4 arguments") };
    if modifiers & !(MOD_ALT | MOD_CONTROL | MOD_SHIFT | MOD_WIN) != 0 {
        return fail(ERROR_INVALID_FLAGS);
    }
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    if hwnd != 0 {
        let Some(window) = win32k::window::get(hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE) };
        if window.pti != thread.server {
            return fail(ERROR_WINDOW_OF_OTHER_THREAD);
        }
    }
    let key = HotKey { pti: thread.server, hwnd, modifiers, vk, id: id as i32, shell: false };
    match win32k::hotkey::register(key) {
        Ok(()) => NtStatus(1),
        Err(Some(error)) => fail(error),
        Err(None) => NtStatus(0),
    }
}

/// NtUserUnregisterHotKey(hWnd, id) : BOOL, les raccourcis `id` de la
/// fenêtre `hWnd`, ou du thread sans fenêtre, retirés ; FALSE s'il n'y en
/// avait pas, avec `ERROR_INVALID_WINDOW_HANDLE` pour une fenêtre inconnue.
pub(super) fn nt_user_unregister_hot_key(arguments: &[u32]) -> NtStatus {
    let [hwnd, id] = arguments[..2] else { unreachable!("2 arguments") };
    if hwnd != 0 && win32k::window::get(hwnd).is_none() {
        return fail(ERROR_INVALID_WINDOW_HANDLE);
    }
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    NtStatus(u32::from(win32k::hotkey::unregister(thread.server, hwnd, id as i32)))
}
