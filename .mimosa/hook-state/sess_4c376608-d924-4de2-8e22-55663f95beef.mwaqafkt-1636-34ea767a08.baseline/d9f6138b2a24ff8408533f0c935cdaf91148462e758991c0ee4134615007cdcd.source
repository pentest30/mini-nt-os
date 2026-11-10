//! Les moniteurs (`win32k::monitor`) : NtUserMonitorFromWindow,
//! NtUserMonitorFromRect, NtUserMonitorFromPoint, NtUserGetMonitorInfo.
//! Comme dans win32k, un échec rend 0 (aucun moniteur, ou FALSE) et met
//! l'erreur Win32 dans le TEB du thread.

use abi::ntstatus::NtStatus;
use abi::user::{
    MonitorInfo32, CCHDEVICENAME, MONITORINFOEXW_SIZE, MONITORINFOF_PRIMARY, MONITOR_DEFAULTTONEAREST,
    MONITOR_DEFAULTTONULL, MONITOR_DEFAULTTOPRIMARY,
};
use abi::winerror::{
    dos_error, ERROR_INVALID_FLAGS, ERROR_INVALID_MONITOR_HANDLE, ERROR_INVALID_PARAMETER, ERROR_INVALID_WINDOW_HANDLE,
};
use alloc::vec::Vec;
use core::mem::size_of;
use ke::usermem::{copy_from_user, copy_to_user};
use win32k::gdi::dib::Rect;

/// Le nom du périphérique d'affichage du moniteur (`szDevice`), le premier.
const DEVICE_NAME: &str = "\\\\.\\DISPLAY1";

/// Met l'erreur Win32 `error` et rend 0.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// Un `MONITOR_DEFAULTTO*` connu.
fn valid_flags(flags: u32) -> bool {
    matches!(flags, MONITOR_DEFAULTTONULL | MONITOR_DEFAULTTOPRIMARY | MONITOR_DEFAULTTONEAREST)
}

/// Un rectangle vide compte pour son coin (un pixel).
fn at_least_a_pixel(rect: Rect) -> Rect {
    if rect.is_empty() {
        return Rect::new(rect.left, rect.top, rect.left + 1, rect.top + 1);
    }
    rect
}

/// Le handle du moniteur de `rect`, ou 0.
fn monitor_of(rect: Rect, flags: u32) -> NtStatus {
    NtStatus(win32k::monitor::from_rect(rect, flags).map_or(0, |monitor| monitor.handle))
}

/// NtUserMonitorFromWindow(hWnd, dwFlags) : le moniteur de la fenêtre (son
/// rectangle ; vide, son coin). `dwFlags` inconnu : `ERROR_INVALID_FLAGS`.
/// Une fenêtre qui n'existe pas (`ERROR_INVALID_WINDOW_HANDLE`), ou nulle,
/// compte pour un rectangle vide en 0, 0, qui ne coupe aucun moniteur.
pub(super) fn nt_user_monitor_from_window(arguments: &[u32]) -> NtStatus {
    let (handle, flags) = (arguments[0], arguments[1]);
    if !valid_flags(flags) {
        return fail(ERROR_INVALID_FLAGS);
    }
    let mut rect = Rect::default();
    if handle != 0 {
        match win32k::window::get(handle) {
            Some(window) => rect = at_least_a_pixel(window.state().window),
            None => {
                let _ = win32k::set_last_error(ERROR_INVALID_WINDOW_HANDLE);
            }
        }
    }
    monitor_of(rect, flags)
}

/// NtUserMonitorFromRect(lprc, dwFlags) : le moniteur du rectangle (vide :
/// son coin).
pub(super) fn nt_user_monitor_from_rect(arguments: &[u32]) -> NtStatus {
    let (address, flags) = (arguments[0], arguments[1]);
    if !valid_flags(flags) {
        return fail(ERROR_INVALID_FLAGS);
    }
    let mut bytes = [0u8; 16];
    if let Err(status) = copy_from_user(&mut bytes, u64::from(address)) {
        return fail(dos_error(status));
    }
    let word = |i: usize| i32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    monitor_of(at_least_a_pixel(Rect::new(word(0), word(1), word(2), word(3))), flags)
}

/// NtUserMonitorFromPoint(pt, dwFlags) : le moniteur du point (`pt` passé
/// par valeur : x puis y).
pub(super) fn nt_user_monitor_from_point(arguments: &[u32]) -> NtStatus {
    let (x, y, flags) = (arguments[0] as i32, arguments[1] as i32, arguments[2]);
    if !valid_flags(flags) {
        return fail(ERROR_INVALID_FLAGS);
    }
    monitor_of(Rect::new(x, y, x.wrapping_add(1), y.wrapping_add(1)), flags)
}

/// NtUserGetMonitorInfo(hMonitor, lpmi) : le rectangle du moniteur, sa zone
/// de travail, `MONITORINFOF_PRIMARY` et, dans un `MONITORINFOEXW`, le nom
/// de son périphérique ; TRUE. Un moniteur inconnu :
/// `ERROR_INVALID_MONITOR_HANDLE` ; sans structure, ou d'une autre taille :
/// `ERROR_INVALID_PARAMETER`.
pub(super) fn nt_user_get_monitor_info(arguments: &[u32]) -> NtStatus {
    let (handle, address) = (arguments[0], arguments[1]);
    let Some(monitor) = win32k::monitor::get(handle) else {
        return fail(ERROR_INVALID_MONITOR_HANDLE);
    };
    if address == 0 {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let mut size = [0u8; 4];
    if let Err(status) = copy_from_user(&mut size, u64::from(address)) {
        return fail(dos_error(status));
    }
    let size = u32::from_le_bytes(size);
    if size != size_of::<MonitorInfo32>() as u32 && size != MONITORINFOEXW_SIZE {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let rect = |r: Rect| [r.left, r.top, r.right, r.bottom];
    let info =
        MonitorInfo32 { size, monitor: rect(monitor.rect), work: rect(monitor.work), flags: MONITORINFOF_PRIMARY };
    let mut bytes: Vec<u8> = info.as_bytes().to_vec();
    if size == MONITORINFOEXW_SIZE {
        let mut name = [0u16; CCHDEVICENAME];
        for (unit, char) in name.iter_mut().zip(DEVICE_NAME.encode_utf16()) {
            *unit = char;
        }
        bytes.extend(name.iter().flat_map(|unit| unit.to_le_bytes()));
    }
    match copy_to_user(u64::from(address), &bytes) {
        Ok(()) => NtStatus(1),
        Err(status) => fail(dos_error(status)),
    }
}
