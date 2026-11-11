//! Les barres de défilement des fenêtres (`win32k::scroll`) :
//! NtUserSetScrollInfo, NtUserSBGetParms, NtUserGetScrollBarInfo,
//! NtUserSetScrollBarInfo, NtUserShowScrollBar, NtUserEnableScrollBar ; le
//! défilement d'une fenêtre ou d'un DC (`win32k::scrollex`) :
//! NtUserScrollWindowEx, NtUserScrollDC.
//! Comme dans win32k, un échec rend 0 et met l'erreur Win32 dans le TEB du
//! thread ; une fenêtre qui n'existe pas, `ERROR_INVALID_WINDOW_HANDLE`.

use core::mem::size_of;

use abi::ntstatus::NtStatus;
use abi::user::{ScrollBarInfo32, ScrollInfo32, SetScrollBarInfo32};
use abi::winerror::{dos_error, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_INVALID_WINDOW_HANDLE};
use ke::usermem::{copy_from_user, copy_to_user};
use win32k::gdi::region::Region;
use win32k::window::Window;

/// Met l'erreur Win32 `error` et rend 0.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// UserGetWindowObject : la fenêtre `hwnd`, ou l'erreur de Win32.
fn window(hwnd: u32) -> Result<alloc::sync::Arc<Window>, u32> {
    win32k::window::get(hwnd).ok_or(ERROR_INVALID_WINDOW_HANDLE)
}

/// Les `N` octets du client en `address`, ou l'erreur de Win32.
fn capture<const N: usize>(address: u32) -> Result<[u8; N], u32> {
    let mut bytes = [0u8; N];
    copy_from_user(&mut bytes, u64::from(address)).map_err(dos_error)?;
    Ok(bytes)
}

/// NtUserSetScrollInfo(hWnd, fnBar, lpsi, bRedraw) : la position de la
/// barre (ou celle d'avant, SIF_PREVIOUSPOS), après
/// `win32k::scroll::set_scroll_info`. Le SCROLLINFO est lu sans son
/// `nTrackPos` (comme ReactOS). 0 pour la fenêtre d'un bureau.
pub(super) fn nt_user_set_scroll_info(arguments: &[u32]) -> NtStatus {
    let [hwnd, bar, info, redraw] = arguments[..4] else { unreachable!("4 arguments") };
    let set = || {
        let window = window(hwnd)?;
        if window.is_desktop_window() {
            return Ok(0);
        }
        let bytes = capture::<{ size_of::<ScrollInfo32>() - 4 }>(info)?;
        let info = ScrollInfo32::from_bytes(&bytes).ok_or(ERROR_INVALID_PARAMETER)?;
        win32k::scroll::set_scroll_info(&window, bar, &info, redraw != 0)
    };
    match set() {
        Ok(pos) => NtStatus(pos as u32),
        Err(error) => fail(error),
    }
}

/// NtUserSBGetParms(hWnd, fnBar, pSBData, lpsi) : BOOL ; le SCROLLINFO du
/// client reçoit ce que son `fMask` demande (`win32k::scroll::scroll_info`).
/// `pSBData` (la copie de `user32`) n'est pas lue : le noyau a la sienne.
pub(super) fn nt_user_sb_get_parms(arguments: &[u32]) -> NtStatus {
    let [hwnd, bar, _data, info] = arguments[..4] else { unreachable!("4 arguments") };
    let get = || {
        let window = window(hwnd)?;
        let bytes = capture::<{ size_of::<ScrollInfo32>() }>(info)?;
        let asked = ScrollInfo32::from_bytes(&bytes).ok_or(ERROR_INVALID_PARAMETER)?;
        let answer = win32k::scroll::scroll_info(&window, bar, asked)?;
        copy_to_user(u64::from(info), answer.as_bytes()).map_err(dos_error)
    };
    match get() {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
    }
}

/// NtUserGetScrollBarInfo(hWnd, idObject, psbi) : BOOL ; le SCROLLBARINFO
/// du client (dont le `cbSize` doit être le sien) reçoit celui de la barre,
/// son rectangle dans la fenêtre (`win32k::scroll::scroll_bar_info`).
pub(super) fn nt_user_get_scroll_bar_info(arguments: &[u32]) -> NtStatus {
    let [hwnd, object, info] = arguments[..3] else { unreachable!("3 arguments") };
    let get = || {
        let bytes = capture::<{ size_of::<ScrollBarInfo32>() }>(info)?;
        let size = ScrollBarInfo32::from_bytes(&bytes).map_or(0, |info| info.cb_size);
        if size as usize != size_of::<ScrollBarInfo32>() {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let window = window(hwnd)?;
        let answer = win32k::scroll::scroll_bar_info(&window, object as i32)?;
        copy_to_user(u64::from(info), answer.as_bytes()).map_err(dos_error)
    };
    match get() {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
    }
}

/// NtUserSetScrollBarInfo(hWnd, idObject, info) : BOOL ; la position suivie
/// et l'état des parties de la barre (`win32k::scroll::set_scroll_bar_info`).
pub(super) fn nt_user_set_scroll_bar_info(arguments: &[u32]) -> NtStatus {
    let [hwnd, object, info] = arguments[..3] else { unreachable!("3 arguments") };
    let set = || {
        let window = window(hwnd)?;
        let bytes = capture::<{ size_of::<SetScrollBarInfo32>() }>(info)?;
        let info = SetScrollBarInfo32::from_bytes(&bytes).ok_or(ERROR_INVALID_PARAMETER)?;
        win32k::scroll::set_scroll_bar_info(&window, object as i32, &info)
    };
    match set() {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
    }
}

/// NtUserShowScrollBar(hWnd, nBar, bShow) : si le cadre a changé
/// (`win32k::scroll::show_scroll_bar` : SB_HORZ, SB_VERT ou les deux).
pub(super) fn nt_user_show_scroll_bar(arguments: &[u32]) -> NtStatus {
    let [hwnd, bar, show] = arguments[..3] else { unreachable!("3 arguments") };
    let show = show != 0;
    let shown = window(hwnd).and_then(|window| {
        let show_h = bar != abi::user::sb::VERT && show;
        let show_v = bar != abi::user::sb::HORZ && show;
        win32k::scroll::show_scroll_bar(&window, bar, show_h, show_v)
    });
    match shown {
        Ok(changed) => NtStatus(u32::from(changed)),
        Err(error) => fail(error),
    }
}

/// NtUserEnableScrollBar(hWnd, wSBflags, wArrows) : BOOL, si les flèches ont
/// changé (`win32k::scroll::enable_scroll_bar`) ; `user32` repeint alors la
/// barre.
pub(super) fn nt_user_enable_scroll_bar(arguments: &[u32]) -> NtStatus {
    let [hwnd, bar, arrows] = arguments[..3] else { unreachable!("3 arguments") };
    match window(hwnd).and_then(|window| win32k::scroll::enable_scroll_bar(&window, bar, arrows)) {
        Ok(changed) => NtStatus(u32::from(changed)),
        Err(error) => fail(error),
    }
}

/// Le RECT `rect` en `address` chez le client, s'il y en a un.
fn give_rect(address: u32, rect: win32k::gdi::dib::Rect) -> Result<(), u32> {
    if address == 0 {
        return Ok(());
    }
    let words = [rect.left, rect.top, rect.right, rect.bottom];
    let bytes: alloc::vec::Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    copy_to_user(u64::from(address), &bytes).map_err(dos_error)
}

/// La région GDI `hrgn` du processus, si elle est donnée ;
/// `ERROR_INVALID_HANDLE` pour un handle qui n'en est pas une.
fn region_object(hrgn: u32) -> Result<Option<alloc::sync::Arc<win32k::gdi::rgnobj::RegionObject>>, u32> {
    if hrgn == 0 {
        return Ok(None);
    }
    win32k::gdi::rgnobj::lock(hrgn).map(Some).ok_or(ERROR_INVALID_HANDLE)
}

/// NtUserScrollWindowEx(hWnd, dx, dy, prcScroll, prcClip, hrgnUpdate,
/// prcUpdate, flags) : la complexité de ce que le défilement découvre
/// (NULLREGION, SIMPLEREGION, COMPLEXREGION ; `win32k::scrollex::scroll_window`),
/// que `hrgnUpdate` reçoit, avec la région déjà à repeindre de la fenêtre,
/// et `prcUpdate` son rectangle ; ERROR (0) pour une fenêtre qu'on ne voit
/// pas, un RECT illisible ou une région qui n'en est pas une.
pub(super) fn nt_user_scroll_window_ex(arguments: &[u32]) -> NtStatus {
    let [hwnd, dx, dy, scroll, clip, hrgn, update_rect, flags] = arguments[..8] else { unreachable!("8 arguments") };
    let run = || {
        let window = window(hwnd)?;
        let scroll = super::window::read_rect(scroll).map_err(dos_error)?;
        let clip = super::window::read_rect(clip).map_err(dos_error)?;
        let object = region_object(hrgn)?;
        let delta = (dx as i32, dy as i32);
        let Some(scrolled) = win32k::scrollex::scroll_window(&window, delta, scroll, clip, flags, object.is_some())
        else {
            return Ok(abi::gdi::ERROR);
        };
        give_rect(update_rect, scrolled.update.bounds())?;
        if let Some(object) = object {
            let mut region = scrolled.update.clone();
            region.union(&scrolled.window_update);
            object.set(region);
        }
        Ok(scrolled.update.complexity())
    };
    match run() {
        Ok(complexity) => NtStatus(complexity as u32),
        Err(error) => fail(error),
    }
}

/// NtUserScrollDC(hDC, dx, dy, prcScroll, prcClip, hrgnUpdate, prcUpdate) :
/// BOOL ; le contenu du DC défile (`win32k::scrollex::scroll_dc`), ce qu'il
/// découvre (en coordonnées logiques) dans `hrgnUpdate` et `prcUpdate`.
/// FALSE pour un DC qui n'est pas au processus, un RECT illisible ou une
/// région qui n'en est pas une.
pub(super) fn nt_user_scroll_dc(arguments: &[u32]) -> NtStatus {
    let [hdc, dx, dy, scroll, clip, hrgn, update_rect] = arguments[..7] else { unreachable!("7 arguments") };
    let run = || {
        let scroll = super::window::read_rect(scroll).map_err(dos_error)?;
        let clip = super::window::read_rect(clip).map_err(dos_error)?;
        let object = region_object(hrgn)?;
        let Some(update): Option<Region> = win32k::scrollex::scroll_dc(hdc, (dx as i32, dy as i32), scroll, clip)
        else {
            return Err(ERROR_INVALID_HANDLE);
        };
        give_rect(update_rect, update.bounds())?;
        if let Some(object) = object {
            object.set(update);
        }
        Ok(())
    };
    match run() {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
    }
}
