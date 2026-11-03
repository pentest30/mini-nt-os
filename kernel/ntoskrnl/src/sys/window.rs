//! Les fenêtres (`win32k::window`) : NtUserCreateWindowEx, NtUserDefSetText.
//! Comme dans win32k, un échec rend 0 et met l'erreur Win32 dans le TEB du
//! thread.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{LargeUnicodeString32, WS_CHILD, WS_POPUP};
use abi::winerror::{dos_error, ERROR_INVALID_MENU_HANDLE, ERROR_SUCCESS};
use ke::usermem::{copy_from_user, probe_for_read, UserPtr};
use win32k::class::ClassName;
use win32k::window::CreateParams;

/// IS_ATOM : une adresse sous 64 Kio est un atome entier.
fn is_atom(address: u32) -> bool {
    address >> 16 == 0
}

/// Le bit `bAnsi` d'un `LARGE_STRING` : sa chaîne est en ANSI.
const LARGE_STRING_ANSI: u32 = 0x8000_0000;

/// ProbeAndCaptureLargeString : la chaîne Unicode d'un `LARGE_STRING`,
/// sans regarder son bit `bAnsi`, comme ReactOS : user32 ne pose que
/// `MaximumLength` dans celui d'un nom de classe (le bit est ce qui restait
/// sur sa pile), et CreateWindowExA lui laisse le nom de la fenêtre déjà
/// converti en Unicode.
fn capture_large_string(address: u32) -> Result<Vec<u16>, NtStatus> {
    capture(address, false)
}

/// Le texte d'un `LARGE_STRING` de NtUserDefSetText, en Unicode : là,
/// `bAnsi` dit s'il est en ANSI (DefWindowProcA, RtlLargeStringToUnicodeString).
/// Un texte ANSI garde ses caractères ASCII ; un autre devient `?` (pas
/// encore de page de code ici, journalisé une fois).
fn capture_text(address: u32) -> Result<Vec<u16>, NtStatus> {
    capture(address, true)
}

/// La chaîne d'un `LARGE_STRING`, en ANSI si `honor_ansi` et son `bAnsi`
/// le disent.
fn capture(address: u32, honor_ansi: bool) -> Result<Vec<u16>, NtStatus> {
    let string = UserPtr::<LargeUnicodeString32>::new(address).read()?;
    let ansi = honor_ansi && string.maximum_length_ansi & LARGE_STRING_ANSI != 0;
    let length = if ansi { string.length } else { string.length & !1 };
    let mut bytes = alloc::vec![0u8; length as usize];
    if !bytes.is_empty() {
        probe_for_read(u64::from(string.buffer), bytes.len(), if ansi { 1 } else { 2 })?;
        copy_from_user(&mut bytes, u64::from(string.buffer))?;
    }
    if ansi {
        if bytes.iter().any(|&byte| byte >= 0x80) {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!("sys: an ANSI window text beyond ASCII: no code page conversion yet");
            }
        }
        return Ok(bytes.iter().map(|&byte| if byte < 0x80 { u16::from(byte) } else { u16::from(b'?') }).collect());
    }
    Ok(bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect())
}

/// Un nom de classe : un atome entier dans le pointeur, ou un
/// `LARGE_STRING` (tronqué à 65535 octets, comme ReactOS).
fn class_name(address: u32) -> Result<ClassName, NtStatus> {
    if is_atom(address) {
        return Ok(ClassName::Atom(address as u16));
    }
    let mut name = capture_large_string(address)?;
    name.truncate(usize::from(u16::MAX) / 2);
    Ok(ClassName::String(name))
}

/// Met l'erreur Win32 `error` et rend 0.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// NtUserCreateWindowEx(dwExStyle, plstrClassName, plstrClsVersion,
/// plstrWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu,
/// hInstance, lpParam, dwFlags, acbiBuffer) : crée la fenêtre
/// (`win32k::window::create_window`) et rend son handle, l'erreur Win32
/// remise à 0. La classe est celle de `plstrClsVersion` (le nom de la
/// version, comme ReactOS). Pas encore de menus : une fenêtre qui n'est pas
/// fille ne peut pas en recevoir (`ERROR_INVALID_MENU_HANDLE`, comme un
/// handle de menu invalide ; journalisé une fois).
pub(super) fn nt_user_create_window_ex(arguments: &[u32]) -> NtStatus {
    let (ex_style, version, name, style) = (arguments[0], arguments[2], arguments[3], arguments[4]);
    let (x, y, cx, cy) = (arguments[5] as i32, arguments[6] as i32, arguments[7] as i32, arguments[8] as i32);
    let (parent, menu, instance, param, expected_version) =
        (arguments[9], arguments[10], arguments[11], arguments[12], arguments[13]);
    if style & (WS_POPUP | WS_CHILD) != WS_CHILD && menu != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtUserCreateWindowEx with a menu: no menus yet");
        }
        return fail(ERROR_INVALID_MENU_HANDLE);
    }
    let captured = capture_large_string(name).and_then(|name| Ok((name, class_name(version)?)));
    let (name, class) = match captured {
        Ok(captured) => captured,
        Err(status) => return fail(dos_error(status)),
    };
    let params = CreateParams {
        ex_style,
        class: Some(class),
        name,
        style,
        x,
        y,
        cx,
        cy,
        parent,
        menu,
        instance,
        param,
        expected_version,
    };
    match win32k::window::create_window(params) {
        Ok(window) => {
            let _ = win32k::set_last_error(ERROR_SUCCESS);
            NtStatus(window.handle)
        }
        Err(Some(error)) => fail(error),
        Err(None) => NtStatus(0),
    }
}

/// NtUserDefSetText(hWnd, WindowText) : le nom de la fenêtre devient le
/// texte (DefWindowProc, WM_SETTEXT et WM_NCCREATE) ; rend TRUE. Sans
/// texte : TRUE, rien ne change. FALSE pour une fenêtre qui n'existe pas
/// (`ERROR_INVALID_WINDOW_HANDLE`) ou un texte illisible.
pub(super) fn nt_user_def_set_text(arguments: &[u32]) -> NtStatus {
    let (handle, text) = (arguments[0], arguments[1]);
    if text == 0 {
        return NtStatus(1);
    }
    let text = match capture_text(text) {
        Ok(text) => text,
        Err(status) => return fail(dos_error(status)),
    };
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    match win32k::window::set_text(&window, &text) {
        Ok(()) => NtStatus(1),
        Err(status) => fail(dos_error(status)),
    }
}
