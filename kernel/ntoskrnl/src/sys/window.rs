//! Les fenêtres (`win32k::window`, `win32k::winpos`, `win32k::destroy`) :
//! NtUserCreateWindowEx, NtUserDestroyWindow, NtUserDefSetText,
//! NtUserSetWindowPos, NtUserMoveWindow, NtUserShowWindow,
//! NtUserSetShellWindowEx (`win32k::shell`).
//! Comme dans win32k, un échec rend 0 et met l'erreur Win32 dans le TEB du
//! thread.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::NtStatus;
use abi::user::{
    LargeUnicodeString32, WindowPlacement32, HWND_BOTTOM, HWND_NOTOPMOST, HWND_TOP, HWND_TOPMOST, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOREDRAW, SWP_NOSIZE, SWP_NOZORDER, SW_MAX,
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
    // The pointers a WH_CBT hook sees as the names: the caller's own.
    let buffer_of = |address: u32| {
        if address == 0 {
            return 0;
        }
        UserPtr::<LargeUnicodeString32>::new(address).read().map_or(0, |string| string.buffer)
    };
    let class_address = if is_atom(arguments[1]) { arguments[1] } else { buffer_of(arguments[1]) };
    let params = CreateParams {
        ex_style,
        class: Some(class),
        name_address: buffer_of(arguments[3]),
        class_address,
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
        Ok(()) => {
            win32k::shellhook::title_changed(&window);
            NtStatus(1)
        }
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

/// Les `SWP_*` que NtUserDeferWindowPos accepte (les autres :
/// `ERROR_INVALID_FLAGS`) ; `win32k::deferpos` en refuse encore quelques-uns
/// (`ERROR_INVALID_PARAMETER`), comme ReactOS.
const DEFER_WINDOW_POS_FLAGS: u32 = abi::user::SWP_ASYNCWINDOWPOS
    | abi::user::SWP_DEFERERASE
    | abi::user::SWP_NOSENDCHANGING
    | abi::user::SWP_NOOWNERZORDER
    | abi::user::SWP_NOCOPYBITS
    | abi::user::SWP_HIDEWINDOW
    | abi::user::SWP_SHOWWINDOW
    | abi::user::SWP_FRAMECHANGED
    | SWP_NOACTIVATE
    | SWP_NOREDRAW
    | SWP_NOZORDER
    | SWP_NOMOVE
    | SWP_NOSIZE;

/// Une fenêtre qu'un déplacement peut nommer : elle existe, ce n'est ni la
/// fenêtre d'un bureau ni sa fenêtre des messages ; `ERROR_INVALID_WINDOW_HANDLE`
/// si elle n'existe pas, 0 (sans erreur) sinon.
fn movable_window(handle: u32) -> Result<(), Option<u32>> {
    let window = win32k::window::get(handle).ok_or(Some(abi::winerror::ERROR_INVALID_WINDOW_HANDLE))?;
    if window.is_desktop_window() || window.is_message_window() {
        return Err(None);
    }
    Ok(())
}

/// NtUserDeferWindowPos(hWinPosInfo, hWnd, hWndInsertAfter, x, y, cx, cy,
/// Flags) : le déplacement de `hWnd` entre dans le lot (DeferWindowPos,
/// `win32k::deferpos::defer`) ; rend le lot. 0 et `ERROR_INVALID_FLAGS` pour
/// un drapeau inconnu ; 0 pour une fenêtre qui n'existe pas
/// (`ERROR_INVALID_WINDOW_HANDLE`), un bureau ou sa fenêtre des messages,
/// pour l'une ou pour celle d'avant elle (un `HWND_*` excepté) ; 0 et
/// l'erreur du lot sinon.
pub(super) fn nt_user_defer_window_pos(arguments: &[u32]) -> NtStatus {
    let [batch, handle, after, x, y, cx, cy, flags] = arguments[..8] else { unreachable!("8 arguments") };
    if flags & !DEFER_WINDOW_POS_FLAGS != 0 {
        return fail(abi::winerror::ERROR_INVALID_FLAGS);
    }
    let named = movable_window(handle).and_then(|()| {
        if matches!(after, HWND_TOP | HWND_BOTTOM | HWND_TOPMOST | HWND_NOTOPMOST) {
            Ok(())
        } else {
            movable_window(after)
        }
    });
    match named {
        Err(Some(error)) => return fail(error),
        Err(None) => return NtStatus(0),
        Ok(()) => {}
    }
    let next =
        win32k::deferpos::Move { hwnd: handle, after, x: x as i32, y: y as i32, cx: cx as i32, cy: cy as i32, flags };
    match win32k::deferpos::defer(batch, next) {
        Ok(batch) => NtStatus(batch),
        Err(error) => fail(error),
    }
}

/// NtUserEndDeferWindowPosEx(hWinPosInfo, bAsync) : les déplacements du lot,
/// faits l'un après l'autre (EndDeferWindowPos, `win32k::deferpos::end`) ;
/// TRUE s'ils ont tous réussi. FALSE et l'erreur pour un lot qui n'existe
/// pas, ou avec `bAsync` (pas encore).
pub(super) fn nt_user_end_defer_window_pos_ex(arguments: &[u32]) -> NtStatus {
    match win32k::deferpos::end(arguments[0], arguments[1] != 0) {
        Ok(done) => NtStatus(u32::from(done)),
        Err(error) => fail(error),
    }
}

/// NtUserSetWindowRgn(hWnd, hRgn, bRedraw) : la région de la fenêtre. Sans
/// région (`hRgn` NULL), la fenêtre n'en a pas : comme ReactOS, son cadre se
/// recalcule et elle passe en tête de ses sœurs (SetWindowPos HWND_TOP,
/// SWP_FRAMECHANGED, sans la déplacer ni l'activer ; SWP_NOREDRAW sans
/// `bRedraw`) ; rend ce que SetWindowPos rend. 0 pour une fenêtre qui
/// n'existe pas (`ERROR_INVALID_WINDOW_HANDLE`), un bureau ou sa fenêtre des
/// messages. Pas encore : une vraie région (régions visibles et test de
/// position la suivant), refusée (0, `ERROR_CALL_NOT_IMPLEMENTED`,
/// journalisée une fois) ; la barre des tâches n'en pose une que sur
/// plusieurs moniteurs.
pub(super) fn nt_user_set_window_rgn(arguments: &[u32]) -> NtStatus {
    let (handle, region, redraw) = (arguments[0], arguments[1], arguments[2] != 0);
    match movable_window(handle) {
        Err(Some(error)) => return fail(error),
        Err(None) => return NtStatus(0),
        Ok(()) => {}
    }
    if region != 0 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtUserSetWindowRgn with a region: not yet");
        }
        return fail(abi::winerror::ERROR_CALL_NOT_IMPLEMENTED);
    }
    let Some(window) = win32k::window::get(handle) else { return NtStatus(0) };
    let mut flags = abi::user::SWP_NOCLIENTSIZE
        | abi::user::SWP_NOCLIENTMOVE
        | SWP_NOACTIVATE
        | abi::user::SWP_FRAMECHANGED
        | SWP_NOSIZE
        | SWP_NOMOVE;
    if !redraw {
        flags |= SWP_NOREDRAW;
    }
    NtStatus(u32::from(win32k::winpos::set_window_pos(&window, HWND_TOP, 0, 0, 0, 0, flags)))
}

/// NtUserSetShellWindowEx(hwndShell, hwndShellListView) : la fenêtre du
/// shell et celle de son fond pour la station du processus
/// (`win32k::shell::set_shell_window`) ; la première passe au bas de
/// l'ordre Z. FALSE s'il y a déjà un shell ou si l'une est au premier plan
/// ; FALSE et l'erreur pour une fenêtre qui n'existe pas, ou sans station.
pub(super) fn nt_user_set_shell_window_ex(arguments: &[u32]) -> NtStatus {
    match win32k::shell::set_shell_window(arguments[0], arguments[1]) {
        Ok(()) => NtStatus(1),
        Err(Some(error)) => fail(error),
        Err(None) => NtStatus(0),
    }
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
    let Ok(current) = win32k::convert_current_thread() else {
        return NtStatus(0);
    };
    if current.server != window.pti {
        // co_IntSendMessageNoWait of WM_ASYNC_SHOWWINDOW: its thread shows
        // it (`win32k::window::send_message`), the caller does not wait.
        let sent = win32k::sent::notify_window(&current, &window, abi::user::WM_ASYNC_SHOWWINDOW, command, 0);
        return NtStatus(u32::from(sent.is_ok()));
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
    let [handle, index, value, ansi] = arguments[..4] else { unreachable!("4 arguments") };
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    if window.is_desktop_window() {
        return fail(abi::winerror::ERROR_ACCESS_DENIED);
    }
    match win32k::window::set_long(&window, index as i32, value, ansi != 0) {
        Ok(old) => NtStatus(old),
        Err(error) => fail(error),
    }
}

/// NtUserGetCPD(hWnd, Flags, ProcIn) : la procédure d'appel de la classe de
/// `hWnd` pour `ProcIn` (`win32k::window::call_procedure`, UserGetCPD), que
/// `user32` demande quand GetWindowLong(GWLP_WNDPROC) ou
/// GetClassLong(GCLP_WNDPROC) voit une procédure de l'autre jeu de caractères
/// (IntGetWndProc, IntGetClsWndProc) ; 0 sans elle, et `user32` rend alors la
/// procédure même, comme ReactOS.
pub(super) fn nt_user_get_cpd(arguments: &[u32]) -> NtStatus {
    let [handle, flags, procedure] = arguments[..3] else { unreachable!("3 arguments") };
    NtStatus(win32k::window::call_procedure(handle, flags, procedure).unwrap_or(0))
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

/// Les routines de NtUserCallHwnd demandées sans être implémentées.
static UNSUPPORTED_HWND_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallHwnd");

/// NtUserCallHwnd(hWnd, Routine) : `HWND_ROUTINE_REGISTERSHELLHOOKWINDOW`
/// et `HWND_ROUTINE_DEREGISTERSHELLHOOKWINDOW` (RegisterShellHookWindow,
/// DeregisterShellHookWindow : `win32k::shellhook`), TRUE si c'est fait,
/// FALSE pour une fenêtre qui n'existe pas. Une autre routine rend 0, avec
/// `ERROR_CALL_NOT_IMPLEMENTED`, journalisée une fois.
pub(super) fn nt_user_call_hwnd(arguments: &[u32]) -> NtStatus {
    let [hwnd, routine] = arguments[..2] else { unreachable!("2 arguments") };
    match routine {
        abi::user::HWND_ROUTINE_REGISTERSHELLHOOKWINDOW => {
            NtStatus(u32::from(win32k::window::get(hwnd).is_some_and(|window| win32k::shellhook::register(&window))))
        }
        abi::user::HWND_ROUTINE_DEREGISTERSHELLHOOKWINDOW => {
            NtStatus(u32::from(win32k::window::get(hwnd).is_some() && win32k::shellhook::deregister(hwnd)))
        }
        _ => {
            UNSUPPORTED_HWND_ROUTINES.report(routine);
            let _ = win32k::set_last_error(abi::winerror::ERROR_CALL_NOT_IMPLEMENTED);
            NtStatus(0)
        }
    }
}

/// Les routines de NtUserCallHwndOpt demandées sans être implémentées.
static UNSUPPORTED_HWND_OPT_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallHwndOpt");

/// NtUserCallHwndOpt(hWnd, Routine) : `HWNDOPT_ROUTINE_SETTASKMANWINDOW` et
/// `HWNDOPT_ROUTINE_SETPROGMANWINDOW` (SetTaskmanWindow, SetProgmanWindow) :
/// `hWnd` va dans le `DESKTOPINFO` du bureau du thread courant
/// (`win32k::desktop::Desktop::set_shell_helper_window`). Rend `hWnd`,
/// comme ReactOS ; une autre routine est journalisée une fois.
pub(super) fn nt_user_call_hwnd_opt(arguments: &[u32]) -> NtStatus {
    let [hwnd, routine] = arguments[..2] else { unreachable!("2 arguments") };
    let task_man = match routine {
        abi::user::HWNDOPT_ROUTINE_SETTASKMANWINDOW => true,
        abi::user::HWNDOPT_ROUTINE_SETPROGMANWINDOW => false,
        _ => {
            UNSUPPORTED_HWND_OPT_ROUTINES.report(routine);
            return NtStatus(hwnd);
        }
    };
    if let Some(desktop) = win32k::convert_current_thread().ok().and_then(|thread| thread.desktop()) {
        let _ = desktop.desktop.set_shell_helper_window(task_man, hwnd);
    }
    NtStatus(hwnd)
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

/// La fenêtre `handle`, aucune pour 0 ; `Err` pour une fenêtre inconnue.
fn optional_window(handle: u32) -> Result<Option<alloc::sync::Arc<win32k::window::Window>>, ()> {
    match handle {
        0 => Ok(None),
        handle => win32k::window::get(handle).map(Some).ok_or(()),
    }
}

/// NtUserLockWindowUpdate(hWndLock) : LockWindowUpdate
/// (`win32k::dce::lock_window_update`) ; hWndLock nul déverrouille. Une
/// fenêtre inconnue : FALSE et `ERROR_INVALID_WINDOW_HANDLE`. ReactOS n'a
/// qu'un stub, qui rend FALSE : `browseui` ne déverrouille que s'il a pu
/// verrouiller.
pub(super) fn nt_user_lock_window_update(arguments: &[u32]) -> NtStatus {
    let [handle] = arguments[..1] else { unreachable!("1 argument") };
    let Ok(window) = optional_window(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    NtStatus(u32::from(win32k::dce::lock_window_update(window.as_ref())))
}

/// NtUserDrawCaption(hWnd, hDC, lpRc, uFlags) : DrawCaption
/// (`win32k::paint::draw_caption`), le rectangle lu chez l'appelant (nul :
/// `ERROR_NOACCESS`, comme la sonde de ReactOS) ; hWnd peut être nul, une
/// fenêtre inconnue rend FALSE et `ERROR_INVALID_WINDOW_HANDLE`.
pub(super) fn nt_user_draw_caption(arguments: &[u32]) -> NtStatus {
    let [handle, hdc, rect, flags] = arguments[..4] else { unreachable!("4 arguments") };
    let Ok(window) = optional_window(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let rect = match read_rect(rect) {
        Ok(Some(rect)) => rect,
        Ok(None) => return fail(dos_error(abi::ntstatus::STATUS_ACCESS_VIOLATION)),
        Err(status) => return fail(dos_error(status)),
    };
    match win32k::paint::draw_caption(window.as_deref(), hdc, rect, flags) {
        Ok(drawn) => NtStatus(u32::from(drawn)),
        Err(error) => fail(error),
    }
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

/// NtUserQueryWindow(hWnd, Index) : ce que l'index demande de la fenêtre
/// (`win32k::window::query` : PID, TID, fenêtre active, fenêtre qui a le
/// clavier, premier plan…) ; 0 pour une fenêtre inconnue
/// (`ERROR_INVALID_WINDOW_HANDLE`).
pub(super) fn nt_user_query_window(arguments: &[u32]) -> NtStatus {
    let (handle, index) = (arguments[0], arguments[1]);
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    NtStatus(win32k::window::query(&window, index))
}

/// NtUserGetWindowPlacement(hWnd, lpwndpl) : le `WINDOWPLACEMENT` de la
/// fenêtre (`win32k::winpos::placement`) écrit en `lpwndpl`, sa longueur
/// mise à 44 quelle qu'elle soit (comme ReactOS) ; TRUE. FALSE pour une
/// fenêtre inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou une structure qu'on
/// ne peut lire ou écrire (l'erreur de la copie).
pub(super) fn nt_user_get_window_placement(arguments: &[u32]) -> NtStatus {
    let (handle, address) = (arguments[0], arguments[1]);
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let mut bytes = [0u8; size_of::<WindowPlacement32>()];
    if let Err(status) = copy_from_user(&mut bytes, u64::from(address)) {
        return fail(dos_error(status));
    }
    let placement = win32k::winpos::placement(&window);
    match ke::usermem::copy_to_user(u64::from(address), &placement.as_bytes()) {
        Ok(()) => NtStatus(1),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserSetWindowPlacement(hWnd, lpwndpl) : la fenêtre placée et montrée
/// selon le `WINDOWPLACEMENT` (`win32k::winpos::set_placement`). FALSE pour
/// une structure qu'on ne peut lire (l'erreur de la copie), d'une autre
/// longueur que 44 (`ERROR_INVALID_PARAMETER` ; la tolérance de ReactOS
/// pour un module qui attend Windows 3.x : pas encore), une fenêtre
/// inconnue (`ERROR_INVALID_WINDOW_HANDLE`) ou celle du bureau.
pub(super) fn nt_user_set_window_placement(arguments: &[u32]) -> NtStatus {
    let (handle, address) = (arguments[0], arguments[1]);
    let mut bytes = [0u8; size_of::<WindowPlacement32>()];
    if let Err(status) = copy_from_user(&mut bytes, u64::from(address)) {
        return fail(dos_error(status));
    }
    let placement = WindowPlacement32::from_bytes(&bytes);
    if placement.length as usize != size_of::<WindowPlacement32>() {
        return fail(abi::winerror::ERROR_INVALID_PARAMETER);
    }
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    NtStatus(u32::from(win32k::winpos::set_placement(&window, &placement)))
}

/// NtUserCallHwndLock(hWnd, Routine) : `HWNDLOCK_ROUTINE_UPDATEWINDOW`
/// (UpdateWindow : la fenêtre et ses enfants se peignent aussitôt) ;
/// `HWNDLOCK_ROUTINE_DRAWMENUBAR` (DrawMenuBar : le cadre d'une fenêtre qui
/// n'est pas fille se recalcule, sa barre se remet en page et se repeint,
/// SetWindowPos(SWP_FRAMECHANGED)) ; TRUE.
/// `HWNDLOCK_ROUTINE_SETFOREGROUNDWINDOW` (SetForegroundWindow,
/// `win32k::input::set_foreground_window`) : si sa fenêtre de premier niveau
/// a pu être activée.
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
        abi::user::HWNDLOCK_ROUTINE_SETFOREGROUNDWINDOW => {
            NtStatus(u32::from(win32k::input::set_foreground_window(&window)))
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

/// NtUserGetAncestor(hWnd, uType) : HWND, l'ancêtre `uType` (`GA_*`) de la
/// fenêtre (`win32k::window::ancestor`) ; 0 sans lui, 0 et
/// `ERROR_INVALID_WINDOW_HANDLE` pour une fenêtre inconnue, 0 et
/// `ERROR_INVALID_PARAMETER` pour un autre type.
pub(super) fn nt_user_get_ancestor(arguments: &[u32]) -> NtStatus {
    let [handle, kind] = arguments[..2] else { unreachable!("2 arguments") };
    let Some(window) = win32k::window::get(handle) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    if !(abi::user::GA_PARENT..=abi::user::GA_ROOTOWNER).contains(&kind) {
        return fail(abi::winerror::ERROR_INVALID_PARAMETER);
    }
    NtStatus(win32k::window::ancestor(&window, kind).map_or(0, |ancestor| ancestor.handle))
}

/// NtUserWindowFromPoint(X, Y) : HWND, la fenêtre sous le point
/// (`win32k::mouse::window_from_point`) ; 0 sans bureau d'entrée.
pub(super) fn nt_user_window_from_point(arguments: &[u32]) -> NtStatus {
    let [x, y] = arguments[..2] else { unreachable!("2 arguments") };
    let thread = win32k::convert_current_thread().expect("a GUI thread at a win32k service");
    NtStatus(win32k::mouse::window_from_point(&thread, x as i32, y as i32).map_or(0, |window| window.handle))
}

/// NtUserGetForegroundWindow() : HWND, la fenêtre active du thread du premier
/// plan (`win32k::input::foreground_window`) ; 0 sans elle.
pub(super) fn nt_user_get_foreground_window(_arguments: &[u32]) -> NtStatus {
    NtStatus(win32k::input::foreground_window())
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

/// NtUserSetParent(hWndChild, hWndNewParent) : `hWndChild` devient
/// l'enfant de `hWndNewParent` (`win32k::winpos::set_parent`), celui du
/// bureau du thread s'il est nul, sa fenêtre des messages pour
/// `HWND_MESSAGE` ; rend l'ancien parent. Comme co_UserSetParent : 0 et
/// `ERROR_INVALID_PARAMETER` pour `HWND_BROADCAST`, `ERROR_ACCESS_DENIED`
/// pour la fenêtre du bureau, `ERROR_INVALID_WINDOW_HANDLE` pour une
/// fenêtre qui n'existe pas.
pub(super) fn nt_user_set_parent(arguments: &[u32]) -> NtStatus {
    let (child, new_parent) = (arguments[0], arguments[1]);
    if child == HWND_BROADCAST || new_parent == HWND_BROADCAST {
        return fail(abi::winerror::ERROR_INVALID_PARAMETER);
    }
    let Some(desktop) = win32k::convert_current_thread().ok().and_then(|thread| thread.desktop()) else {
        return fail(abi::winerror::ERROR_ACCESS_DENIED);
    };
    let parent = match new_parent {
        0 => Some(desktop.desktop.window.clone()),
        abi::user::HWND_MESSAGE => Some(desktop.desktop.message_window.clone()),
        handle => win32k::window::get(handle),
    };
    let Some(window) = win32k::window::get(child) else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    if window.is_desktop_window() {
        return fail(abi::winerror::ERROR_ACCESS_DENIED);
    }
    let Some(parent) = parent else {
        return fail(abi::winerror::ERROR_INVALID_WINDOW_HANDLE);
    };
    let pid = super::current_process().pid();
    match win32k::winpos::set_parent(&window, &parent, pid) {
        Ok(old) => NtStatus(old.map_or(0, |old| old.handle)),
        Err(win32k::winpos::SetParentError(Some(error))) => fail(error),
        Err(win32k::winpos::SetParentError(None)) => NtStatus(0),
    }
}

/// HWND_BROADCAST.
const HWND_BROADCAST: u32 = 0xFFFF;
