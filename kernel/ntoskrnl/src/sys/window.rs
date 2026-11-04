//! Les fenêtres (`win32k::window`, `win32k::winpos`) : NtUserCreateWindowEx,
//! NtUserDefSetText, NtUserSetWindowPos, NtUserMoveWindow, NtUserShowWindow.
//! Comme dans win32k, un échec rend 0 et met l'erreur Win32 dans le TEB du
//! thread.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    LargeUnicodeString32, HWND_BOTTOM, HWND_NOTOPMOST, HWND_TOP, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOREDRAW, SWP_NOSIZE, SWP_NOZORDER, SW_MAX, WS_CHILD, WS_POPUP,
};
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

/// NtUserSetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags) : place
/// la fenêtre (`win32k::winpos::set_window_pos`), ses coordonnées ramenées
/// sur 16 bits, sa taille entre 0 et 32767. FALSE pour une fenêtre ou une
/// sœur `hWndInsertAfter` qui n'existe pas (`ERROR_INVALID_WINDOW_HANDLE`),
/// ou qui est la fenêtre du bureau.
pub(super) fn nt_user_set_window_pos(arguments: &[u32]) -> NtStatus {
    let (handle, after, flags) = (arguments[0], arguments[1], arguments[6]);
    let (mut x, mut y, mut cx, mut cy) =
        (arguments[2] as i32, arguments[3] as i32, arguments[4] as i32, arguments[5] as i32);
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    if window.is_desktop_window() {
        return NtStatus(0);
    }
    if !matches!(after, HWND_TOP | HWND_BOTTOM | HWND_TOPMOST | HWND_NOTOPMOST) {
        match win32k::window::get(after) {
            None => return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE),
            Some(sibling) if sibling.is_desktop_window() => return NtStatus(0),
            Some(_) => {}
        }
    }
    if flags & SWP_NOMOVE == 0 {
        (x, y) = (x.clamp(-32768, 32767), y.clamp(-32768, 32767));
    }
    if flags & SWP_NOSIZE == 0 {
        (cx, cy) = (cx.clamp(0, 32767), cy.clamp(0, 32767));
    }
    NtStatus(u32::from(win32k::winpos::set_window_pos(&window, after, x, y, cx, cy, flags)))
}

/// NtUserMoveWindow(hWnd, X, Y, nWidth, nHeight, bRepaint) :
/// NtUserSetWindowPos sans ordre Z ni activation (`SWP_NOREDRAW` sans
/// `bRepaint`).
pub(super) fn nt_user_move_window(arguments: &[u32]) -> NtStatus {
    let mut flags = SWP_NOZORDER | SWP_NOACTIVATE;
    if arguments[5] == 0 {
        flags |= SWP_NOREDRAW;
    }
    let forwarded = [arguments[0], 0, arguments[1], arguments[2], arguments[3], arguments[4], flags];
    nt_user_set_window_pos(&forwarded)
}

/// NtUserShowWindow(hWnd, nCmdShow) : montre ou cache la fenêtre
/// (`win32k::winpos::show_window`) ; rend si elle était visible. FALSE pour
/// une fenêtre qui n'existe pas (`ERROR_INVALID_WINDOW_HANDLE`) ou celle du
/// bureau ; une commande au-delà de `SW_MAX` : `ERROR_INVALID_PARAMETER`
/// (une commande négative ne fait rien, comme ReactOS, qui compare avec
/// signe).
pub(super) fn nt_user_show_window(arguments: &[u32]) -> NtStatus {
    let (handle, command) = (arguments[0], arguments[1]);
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    if window.is_desktop_window() {
        return NtStatus(0);
    }
    if command as i32 > SW_MAX as i32 {
        return fail(abi::winerror::ERROR_INVALID_PARAMETER);
    }
    NtStatus(u32::from(win32k::winpos::show_window(&window, command)))
}

/// NtUserBeginPaint(hWnd, lpPaint) : `hWnd` se peint (IntBeginPaint) ; le
/// `PAINTSTRUCT` écrit, rend son DC, NULL sans DC. NULL pour une fenêtre
/// inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou un `lpPaint` qu'on ne peut
/// écrire (le DC reste pris, comme dans ReactOS).
pub(super) fn nt_user_begin_paint(arguments: &[u32]) -> NtStatus {
    let (handle, paint) = (arguments[0], arguments[1]);
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let ps = win32k::paint::begin_paint(&window);
    match ke::usermem::copy_to_user(u64::from(paint), ps.as_bytes()) {
        Ok(()) => NtStatus(ps.hdc),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserEndPaint(hWnd, lpPaint) : le DC de BeginPaint (`lpPaint->hdc`) est
/// rendu ; TRUE. FALSE pour une fenêtre inconnue
/// (`ERROR_INVALID_WINDOW_HANDLE`) ou un `lpPaint` illisible.
pub(super) fn nt_user_end_paint(arguments: &[u32]) -> NtStatus {
    let (handle, paint) = (arguments[0], arguments[1]);
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let mut bytes = [0u8; core::mem::size_of::<abi::user::PaintStruct32>()];
    if copy_from_user(&mut bytes, u64::from(paint)).is_err() {
        return NtStatus(0);
    }
    let ps = abi::user::PaintStruct32::from_bytes(&bytes).expect("the size of a PAINTSTRUCT");
    win32k::paint::end_paint(&window, ps.hdc);
    NtStatus(1)
}
