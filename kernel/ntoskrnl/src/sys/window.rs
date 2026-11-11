//! Les fenêtres (`win32k::window`, `win32k::winpos`, `win32k::destroy`) :
//! NtUserCreateWindowEx, NtUserDestroyWindow, NtUserDefSetText,
//! NtUserSetWindowPos, NtUserMoveWindow, NtUserShowWindow.
//! Comme dans win32k, un échec rend 0 et met l'erreur Win32 dans le TEB du
//! thread.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    LargeUnicodeString32, HWND_BOTTOM, HWND_NOTOPMOST, HWND_TOP, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOREDRAW, SWP_NOSIZE, SWP_NOZORDER, SW_MAX,
};
use abi::winerror::{dos_error, ERROR_SUCCESS};
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
/// version, comme ReactOS). `hMenu` est la barre de menus d'une fenêtre qui
/// n'est pas fille, l'identifiant d'une fille (`create_window`).
pub(super) fn nt_user_create_window_ex(arguments: &[u32]) -> NtStatus {
    let (ex_style, version, name, style) = (arguments[0], arguments[2], arguments[3], arguments[4]);
    let (x, y, cx, cy) = (arguments[5] as i32, arguments[6] as i32, arguments[7] as i32, arguments[8] as i32);
    let (parent, menu, instance, param, expected_version) =
        (arguments[9], arguments[10], arguments[11], arguments[12], arguments[13]);
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

/// NtUserDestroyWindow(hWnd) : BOOL. La fenêtre du thread courant est
/// détruite avec ses enfants et ses fenêtres possédées
/// (`win32k::destroy::destroy_window`) ; FALSE pour une fenêtre qui n'existe
/// pas (`ERROR_INVALID_WINDOW_HANDLE`), d'un autre thread ou d'un bureau
/// (`ERROR_ACCESS_DENIED`).
pub(super) fn nt_user_destroy_window(arguments: &[u32]) -> NtStatus {
    let Some(window) = win32k::window::get(arguments[0]) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    match win32k::destroy::destroy_window(&window) {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
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

/// NtUserShowWindowAsync(hWnd, nCmdShow) : comme NtUserShowWindow pour une
/// fenêtre du thread courant (WM_ASYNC_SHOWWINDOW envoyé sans attendre, que
/// traite aussitôt co_WinPosShowWindow) ; rend si elle était visible. Pour
/// la fenêtre d'un autre thread : pas encore (les messages envoyés entre
/// threads), FALSE et `ERROR_CALL_NOT_IMPLEMENTED`, journalisé une fois.
pub(super) fn nt_user_show_window_async(arguments: &[u32]) -> NtStatus {
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
    let own = win32k::convert_current_thread().is_ok_and(|thread| thread.server == window.pti);
    if !own {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: ShowWindowAsync of another thread's window (sent messages): not yet");
        }
        return fail(abi::winerror::ERROR_CALL_NOT_IMPLEMENTED);
    }
    NtStatus(u32::from(win32k::winpos::show_window(&window, command)))
}

/// NtUserSetWindowLong(hWnd, Index, NewValue, Ansi) : le LONG `Index` de la
/// fenêtre devient `NewValue` (`win32k::window::set_long`) ; rend l'ancien.
/// 0 et l'erreur de Win32 pour une fenêtre inconnue
/// (`ERROR_INVALID_WINDOW_HANDLE`), la fenêtre du bureau
/// (`ERROR_ACCESS_DENIED` ; ReactOS met à tort le statut NT
/// `STATUS_ACCESS_DENIED` comme erreur) ou un index refusé.
pub(super) fn nt_user_set_window_long(arguments: &[u32]) -> NtStatus {
    let [handle, index, value] = arguments[..3] else { unreachable!("4 arguments, the last unused") };
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    if window.is_desktop_window() {
        return fail(abi::winerror::ERROR_ACCESS_DENIED);
    }
    match win32k::window::set_long(&window, index as i32, value) {
        Ok(old) => NtStatus(old),
        Err(error) => fail(error),
    }
}

/// NtUserBeginPaint(hWnd, lpPaint) : `hWnd` se peint (IntBeginPaint) ; le
/// `PAINTSTRUCT` écrit, rend son DC, NULL sans DC. NULL pour une fenêtre
/// inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou un `lpPaint` qu'on ne peut
/// écrire (le DC reste pris, comme dans ReactOS ; le caret que BeginPaint a
/// caché se remontre, l'appelant n'ayant pas d'EndPaint à faire).
pub(super) fn nt_user_begin_paint(arguments: &[u32]) -> NtStatus {
    let (handle, paint) = (arguments[0], arguments[1]);
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let ps = win32k::paint::begin_paint(&window);
    match ke::usermem::copy_to_user(u64::from(paint), ps.as_bytes()) {
        Ok(()) => NtStatus(ps.hdc),
        Err(status) => {
            win32k::caret::show_in(&window);
            fail(dos_error(status))
        }
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

/// Les routines de NtUserCallHwndLock demandées sans être implémentées.
static UNSUPPORTED_HWND_LOCK_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallHwndLock");

/// Le RECT en `address` ; `None` pour une adresse nulle.
pub(super) fn read_rect(address: u32) -> Result<Option<win32k::gdi::dib::Rect>, NtStatus> {
    if address == 0 {
        return Ok(None);
    }
    let mut bytes = [0u8; 16];
    copy_from_user(&mut bytes, u64::from(address))?;
    let word = |i: usize| i32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    Ok(Some(win32k::gdi::dib::Rect::new(word(0), word(1), word(2), word(3))))
}

/// La fenêtre `handle`, ou celle du bureau du thread pour 0.
fn window_or_desktop(handle: u32) -> Option<alloc::sync::Arc<win32k::window::Window>> {
    if handle != 0 {
        return win32k::window::get(handle);
    }
    let thread = win32k::convert_current_thread().ok()?;
    Some(thread.desktop()?.desktop.window.clone())
}

/// NtUserRedrawWindow(hWnd, lprcUpdate, hrgnUpdate, flags) : TRUE, après
/// co_UserRedrawWindow (hWnd nul : la fenêtre du bureau ; la région, dans
/// la zone cliente, l'emporte sur le rectangle). FALSE pour une fenêtre
/// inconnue (`ERROR_INVALID_WINDOW_HANDLE`), un rectangle illisible
/// (l'erreur de la faute), un drapeau inconnu (`ERROR_INVALID_FLAGS`) ou
/// une région qui n'est pas au processus (`ERROR_NOT_ENOUGH_MEMORY`, comme
/// ReactOS). `HRGN_WINDOW` compte comme aucune région.
pub(super) fn nt_user_redraw_window(arguments: &[u32]) -> NtStatus {
    let [handle, rect, region, flags] = arguments[..4] else { unreachable!("4 arguments") };
    let Some(window) = window_or_desktop(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let rect = match read_rect(rect) {
        Ok(rect) => rect,
        Err(status) => return fail(dos_error(status)),
    };
    if flags & !abi::user::RDW_VALID_FLAGS != 0 {
        return fail(abi::winerror::ERROR_INVALID_FLAGS);
    }
    let region = if region > abi::user::HRGN_WINDOW {
        match win32k::gdi::rgnobj::lock(region) {
            Some(object) => Some(object.get()),
            None => return fail(abi::winerror::ERROR_NOT_ENOUGH_MEMORY),
        }
    } else {
        None
    };
    win32k::paint::redraw_window(&window, rect, region.as_ref(), flags);
    NtStatus(1)
}

/// NtUserInvalidateRgn(hWnd, hRgn, bErase) : RedrawWindow de la région
/// (aucune : la zone cliente) avec `RDW_INVALIDATE` (et `RDW_ERASE`). hWnd
/// nul : FALSE et `ERROR_INVALID_WINDOW_HANDLE`.
pub(super) fn nt_user_invalidate_rgn(arguments: &[u32]) -> NtStatus {
    let [handle, region, erase] = arguments[..3] else { unreachable!("3 arguments") };
    use abi::user::{RDW_ERASE, RDW_INVALIDATE};
    if handle == 0 {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    }
    nt_user_redraw_window(&[handle, 0, region, RDW_INVALIDATE | if erase != 0 { RDW_ERASE } else { 0 }])
}

/// NtUserGetUpdateRgn(hWnd, hRgn, bErase) : la région à mettre à jour de la
/// fenêtre (dans sa zone cliente) va dans `hRgn` ; rend sa complexité
/// (NULLREGION sans région), ou ERROR pour une fenêtre inconnue
/// (`ERROR_INVALID_WINDOW_HANDLE`) ou une région `hRgn` qui n'est pas au
/// processus quand il y a quelque chose à y mettre.
pub(super) fn nt_user_get_update_rgn(arguments: &[u32]) -> NtStatus {
    let [handle, hrgn, erase] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(window) = win32k::window::get(handle) else {
        let _ = win32k::set_last_error(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
        return NtStatus(abi::gdi::ERROR as u32);
    };
    let update = win32k::paint::get_update_region(&window, erase != 0);
    let object = win32k::gdi::rgnobj::lock(hrgn);
    let region = match update {
        Some(region) if !region.is_empty() => region,
        _ => {
            if let Some(object) = object {
                object.set(win32k::gdi::region::Region::default());
            }
            return NtStatus(abi::gdi::NULLREGION as u32);
        }
    };
    let Some(object) = object else { return NtStatus(abi::gdi::ERROR as u32) };
    let complexity = region.complexity();
    object.set(region);
    NtStatus(complexity as u32)
}

/// La fenêtre de GetDC (hWnd nul : aucune, tout l'écran) ; `Err` : hWnd
/// inconnu (`ERROR_INVALID_WINDOW_HANDLE`).
fn dc_window(handle: u32) -> Result<Option<alloc::sync::Arc<win32k::window::Window>>, NtStatus> {
    if handle == 0 {
        return Ok(None);
    }
    match win32k::window::get(handle) {
        Some(window) => Ok(Some(window)),
        None => Err(fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE)),
    }
}

/// NtUserGetDCEx(hWnd, hrgnClip, flags) : HDC, un DC du cache pour la
/// fenêtre (`win32k::dce::get_dc` ; hWnd nul : tout l'écran), coupé selon
/// `flags` par `hrgnClip` (à l'écran ; au DC jusqu'à sa remise ;
/// `HRGN_WINDOW` : la fenêtre ou sa zone cliente). NULL pour une fenêtre
/// inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou sans DC.
pub(super) fn nt_user_get_dc_ex(arguments: &[u32]) -> NtStatus {
    let [handle, region, flags] = arguments[..3] else { unreachable!("3 arguments") };
    let window = match dc_window(handle) {
        Ok(window) => window,
        Err(status) => return status,
    };
    let clip = match region {
        0 => win32k::dce::Clip::None,
        abi::user::HRGN_WINDOW => win32k::dce::Clip::Window,
        region => win32k::dce::Clip::Handle(region),
    };
    NtStatus(win32k::dce::get_dc(window.as_deref(), clip, flags).unwrap_or(0))
}

/// NtUserGetDC(hWnd) : GetDCEx sans région, avec `DCX_USESTYLE` (hWnd nul :
/// `DCX_CACHE | DCX_WINDOW`, tout l'écran).
pub(super) fn nt_user_get_dc(arguments: &[u32]) -> NtStatus {
    use abi::user::{DCX_CACHE, DCX_USESTYLE, DCX_WINDOW};
    let handle = arguments[0];
    let flags = if handle == 0 { DCX_CACHE | DCX_WINDOW } else { DCX_USESTYLE };
    nt_user_get_dc_ex(&[handle, 0, flags])
}

/// NtUserGetWindowDC(hWnd) : GetDCEx de toute la fenêtre, cadre compris
/// (`DCX_USESTYLE | DCX_WINDOW`).
pub(super) fn nt_user_get_window_dc(arguments: &[u32]) -> NtStatus {
    use abi::user::{DCX_USESTYLE, DCX_WINDOW};
    nt_user_get_dc_ex(&[arguments[0], 0, DCX_USESTYLE | DCX_WINDOW])
}

/// Les routines de NtUserCallHwndParamLock demandées sans être
/// implémentées.
static UNSUPPORTED_HWND_PARAM_LOCK_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallHwndParamLock");

/// NtUserCallHwndParamLock(hWnd, Param, Routine) :
/// `TWOPARAM_ROUTINE_VALIDATERGN` (ValidateRgn : la région `Param`, aucune
/// ou pas au processus : toute la zone cliente, est validée) ; TRUE. FALSE
/// pour une fenêtre inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou une autre
/// routine (journalisée à son premier appel).
pub(super) fn nt_user_call_hwnd_param_lock(arguments: &[u32]) -> NtStatus {
    let [handle, param, routine] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    match routine {
        abi::user::TWOPARAM_ROUTINE_VALIDATERGN => {
            let region = win32k::gdi::rgnobj::lock(param).map(|object| object.get());
            win32k::paint::redraw_window(&window, None, region.as_ref(), abi::user::RDW_VALIDATE);
            NtStatus(1)
        }
        _ => {
            let _ = UNSUPPORTED_HWND_PARAM_LOCK_ROUTINES.report(routine);
            NtStatus(0)
        }
    }
}

/// NtUserInvalidateRect(hWnd, lpRect, bErase) : RedrawWindow avec
/// `RDW_INVALIDATE` (et `RDW_ERASE`) ; hWnd nul : tout le bureau, ses
/// fenêtres et leur cadre, effacés aussitôt.
pub(super) fn nt_user_invalidate_rect(arguments: &[u32]) -> NtStatus {
    let [handle, rect, erase] = arguments[..3] else { unreachable!("3 arguments") };
    use abi::user::{RDW_ALLCHILDREN, RDW_ERASE, RDW_ERASENOW, RDW_FRAME, RDW_INVALIDATE};
    let (rect, flags) = match handle {
        0 => (0, RDW_ALLCHILDREN | RDW_INVALIDATE | RDW_FRAME | RDW_ERASE | RDW_ERASENOW),
        _ => (rect, RDW_INVALIDATE | if erase != 0 { RDW_ERASE } else { 0 }),
    };
    nt_user_redraw_window(&[handle, rect, 0, flags])
}

/// NtUserValidateRect(hWnd, lpRect) : RedrawWindow avec `RDW_VALIDATE` ;
/// hWnd nul : comme InvalidateRect de tout le bureau.
pub(super) fn nt_user_validate_rect(arguments: &[u32]) -> NtStatus {
    let [handle, rect] = arguments[..2] else { unreachable!("2 arguments") };
    use abi::user::{RDW_ALLCHILDREN, RDW_ERASE, RDW_ERASENOW, RDW_FRAME, RDW_INVALIDATE, RDW_VALIDATE};
    let (rect, flags) = match handle {
        0 => (0, RDW_ALLCHILDREN | RDW_INVALIDATE | RDW_FRAME | RDW_ERASE | RDW_ERASENOW),
        _ => (rect, RDW_VALIDATE),
    };
    nt_user_redraw_window(&[handle, rect, 0, flags])
}

/// NtUserGetUpdateRect(hWnd, lpRect, bErase) : TRUE si la fenêtre a une
/// région à mettre à jour, dont le rectangle (dans sa zone cliente) va en
/// `lpRect` s'il n'est pas nul (sinon 0, 0, 0, 0). FALSE pour une fenêtre
/// inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou un `lpRect` qu'on ne peut
/// écrire (`ERROR_INVALID_PARAMETER`).
pub(super) fn nt_user_get_update_rect(arguments: &[u32]) -> NtStatus {
    let [handle, rect, erase] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let update = win32k::paint::get_update_rect(&window, erase != 0);
    if rect != 0 {
        let r = update.unwrap_or_default();
        let mut bytes = [0u8; 16];
        for (slot, value) in bytes.chunks_exact_mut(4).zip([r.left, r.top, r.right, r.bottom]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        if ke::usermem::copy_to_user(u64::from(rect), &bytes).is_err() {
            return fail(abi::winerror::ERROR_INVALID_PARAMETER);
        }
    }
    NtStatus(u32::from(update.is_some()))
}

/// NtUserCallHwndLock(hWnd, Routine) : `HWNDLOCK_ROUTINE_UPDATEWINDOW`
/// (UpdateWindow : la fenêtre et ses enfants se peignent aussitôt) ;
/// `HWNDLOCK_ROUTINE_DRAWMENUBAR` (DrawMenuBar : le cadre d'une fenêtre qui
/// n'est pas fille se recalcule, sa barre se remet en page et se repeint,
/// SetWindowPos(SWP_FRAMECHANGED)) ; TRUE.
/// FALSE pour une fenêtre inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou une
/// autre routine (journalisée à son premier appel).
pub(super) fn nt_user_call_hwnd_lock(arguments: &[u32]) -> NtStatus {
    let [handle, routine] = arguments[..2] else { unreachable!("2 arguments") };
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    match routine {
        abi::user::HWNDLOCK_ROUTINE_UPDATEWINDOW => {
            win32k::paint::update_window(&window, abi::user::RDW_ALLCHILDREN);
            NtStatus(1)
        }
        abi::user::HWNDLOCK_ROUTINE_DRAWMENUBAR => {
            use abi::user::{SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER};
            if window.state().style & (abi::user::WS_CHILD | abi::user::WS_POPUP) != abi::user::WS_CHILD {
                let flags = SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED;
                win32k::winpos::set_window_pos(&window, 0, 0, 0, 0, 0, flags);
            }
            NtStatus(1)
        }
        _ => {
            let _ = UNSUPPORTED_HWND_LOCK_ROUTINES.report(routine);
            NtStatus(0)
        }
    }
}

/// NtUserSetLogonNotifyWindow(hWnd) : la fenêtre devient la fenêtre SAS du
/// processus de logon (`win32k::logon`), où USER postera WM_LOGONNOTIFY ;
/// TRUE. FALSE pour une fenêtre inconnue, ou pour un autre processus que
/// celui de logon (`ERROR_ACCESS_DENIED`), comme dans ReactOS
/// (`ntuser/winsta.c`).
pub(super) fn nt_user_set_logon_notify_window(arguments: &[u32]) -> NtStatus {
    let handle = arguments[0];
    if win32k::window::get(handle).is_none() {
        return NtStatus(0);
    }
    match win32k::logon::set_logon_notify_window(handle, super::current_process().pid()) {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
    }
}

/// Le type CTLCOLOR_* de `message`, s'il est l'un des WM_CTLCOLOR*.
fn ctl_type(message: u32) -> Option<u32> {
    message.checked_sub(abi::user::WM_CTLCOLORMSGBOX).filter(|&ctl_type| ctl_type < abi::user::CTLCOLOR_MAX)
}

/// NtUserGetControlColor(hwndParent, hwnd, hdc, CtlMsg) : HBRUSH, le pinceau
/// du fond du contrôle `hwnd` que donne `hwndParent` (lui-même sans parent)
/// en réponse à `CtlMsg` (WM_CTLCOLOR*), ou celui par défaut, ses couleurs
/// posées dans le DC (`win32k::defwnd::get_control_color`). NULL pour une
/// fenêtre inconnue, un autre message ou sans DC.
pub(super) fn nt_user_get_control_color(arguments: &[u32]) -> NtStatus {
    let [parent, hwnd, hdc, message] = arguments[..4] else { unreachable!("4 arguments") };
    let Some(window) = win32k::window::get(hwnd) else { return NtStatus(0) };
    if ctl_type(message).is_none() || hdc == 0 {
        return NtStatus(0);
    }
    let parent = win32k::window::get(parent);
    NtStatus(win32k::defwnd::get_control_color(parent.as_ref(), &window, hdc, message))
}

/// NtUserGetControlBrush(hwnd, hdc, ctlType) : HBRUSH, de même avec le parent
/// de `hwnd` (son propriétaire pour une fenêtre surgissante,
/// `win32k::defwnd::get_control_brush`) ; `ctlType` est le message
/// WM_CTLCOLOR*.
pub(super) fn nt_user_get_control_brush(arguments: &[u32]) -> NtStatus {
    let [hwnd, hdc, message] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(window) = win32k::window::get(hwnd) else { return NtStatus(0) };
    if ctl_type(message).is_none() || hdc == 0 {
        return NtStatus(0);
    }
    NtStatus(win32k::defwnd::get_control_brush(&window, hdc, message))
}

/// NtUserInternalGetWindowText(hWnd, lpString, nMaxCount) : INT, le texte de
/// la fenêtre (ses unités UTF-16). Avec un tampon, au plus `nMaxCount - 1`
/// unités puis un NUL y vont, et le nombre copié est rendu ; sans tampon, la
/// longueur du texte. 0 pour une fenêtre inconnue
/// (`ERROR_INVALID_WINDOW_HANDLE`), un tampon de moins de 2 unités
/// (`ERROR_INVALID_PARAMETER`) ou qu'on ne peut écrire.
pub(super) fn nt_user_internal_get_window_text(arguments: &[u32]) -> NtStatus {
    let [hwnd, buffer, count] = arguments[..3] else { unreachable!("3 arguments") };
    if buffer != 0 && (count as i32) <= 1 {
        return fail(abi::winerror::ERROR_INVALID_PARAMETER);
    }
    let Some(window) = win32k::window::get(hwnd) else { return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE) };
    let text = win32k::window::text(&window).unwrap_or_default();
    if buffer == 0 {
        return NtStatus(text.len() as u32);
    }
    let copied = text.len().min(count as usize - 1);
    let bytes: Vec<u8> =
        text[..copied].iter().chain(core::iter::once(&0)).flat_map(|unit| unit.to_le_bytes()).collect();
    match ke::usermem::copy_to_user(u64::from(buffer), &bytes) {
        Ok(()) => NtStatus(copied as u32),
        Err(status) => fail(dos_error(status)),
    }
}
