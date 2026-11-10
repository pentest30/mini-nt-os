//! Les services des menus (`win32k::menu`) : la barre de menus d'une
//! fenêtre et ses items — la création passe par NtUserCallNoParam
//! (CREATEMENU, CREATEMENUPOPUP), les items par NtUserThunkedMenuItemInfo,
//! l'état par NtUserEnableMenuItem, la barre par NtUserSetMenu, la
//! destruction par NtUserDestroyMenu.

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use ke::usermem::UserPtr;

/// La taille d'un MENUITEMINFOW de XP.
const MENU_ITEM_INFO_SIZE: usize = 48;
/// MIIM_* : les champs qu'un appel demande.
const MIIM_STATE: u32 = 0x0001;
const MIIM_ID: u32 = 0x0002;
const MIIM_SUBMENU: u32 = 0x0004;
const MIIM_STRING: u32 = 0x0040;
const MIIM_FTYPE: u32 = 0x0100;
/// MFT_SEPARATOR.
const MFT_SEPARATOR: u32 = 0x0001;
/// MF_BYPOSITION.
const MF_BYPOSITION: u32 = 0x0400;

/// Le mot 32 bits à `at` de `bytes`.
fn word(bytes: &[u8; MENU_ITEM_INFO_SIZE], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Le titre de l'item : l'UNICODE_STRING à `caption` chez l'appelant (sa
/// longueur, son tampon), comme `user32` le thunk.
fn capture_caption(caption: u32) -> Result<alloc::vec::Vec<u16>, NtStatus> {
    let mut string = [0u8; 8];
    ke::usermem::copy_from_user(&mut string, u64::from(caption))?;
    let length = u16::from_le_bytes([string[0], string[1]]) as usize & !1;
    let buffer = u32::from_le_bytes([string[4], string[5], string[6], string[7]]);
    let mut units = alloc::vec![0u8; length];
    ke::usermem::copy_from_user(&mut units, u64::from(buffer))?;
    Ok(units.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}

/// NtUserThunkedMenuItemInfo(hMenu, uItem, fByPosition, bInsert, lpmii,
/// lpszCaption) : l'item inséré (`bInsert`) au bout ou à sa position, ou
/// mis à jour — son identifiant, son sous-menu, son état, son séparateur,
/// son titre. TRUE, FALSE sans menu ou champs illisibles.
pub(super) fn nt_user_thunked_menu_item_info(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, by_position, insert, info, caption] = arguments[..6] else { unreachable!("6 arguments") };
    let change = || -> Result<(), NtStatus> {
        let menu = win32k::menu::get(hmenu).ok_or(STATUS_INVALID_PARAMETER)?;
        let size = UserPtr::<u32>::new(info).read()? as usize;
        if size != 44 && size != 48 {
            // XP SP2 accepte les deux tailles (avec ou sans hbmpItem).
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut bytes = [0u8; MENU_ITEM_INFO_SIZE];
        ke::usermem::copy_from_user(&mut bytes[..size], u64::from(info))?;
        let mask = word(&bytes, 4);
        let mut flags = 0;
        if mask & MIIM_FTYPE != 0 && word(&bytes, 8) & MFT_SEPARATOR != 0 {
            flags |= win32k::menu::mf::SEPARATOR;
        }
        if mask & MIIM_STATE != 0 && word(&bytes, 12) & 0x0003 != 0 {
            flags |= win32k::menu::mf::DISABLED | win32k::menu::mf::GRAYED;
        }
        let title =
            if mask & MIIM_STRING != 0 && caption != 0 { capture_caption(caption)? } else { alloc::vec::Vec::new() };
        let new = win32k::menu::Item {
            id: if mask & MIIM_ID != 0 { word(&bytes, 16) } else { 0 },
            caption: title,
            flags,
            popup: if mask & MIIM_SUBMENU != 0 { word(&bytes, 20) } else { 0 },
        };
        if insert != 0 {
            let at = (by_position != 0).then_some(item);
            menu.insert(at, new);
            return Ok(());
        }
        menu.set(item, by_position != 0, |held| {
            if mask & MIIM_ID != 0 {
                held.id = new.id;
            }
            if mask & MIIM_SUBMENU != 0 {
                held.popup = new.popup;
            }
            if mask & (MIIM_FTYPE | MIIM_STATE) != 0 {
                held.flags = (held.flags & !win32k::menu::mf::SEPARATOR) | (new.flags & win32k::menu::mf::SEPARATOR);
                held.flags = (held.flags & !(win32k::menu::mf::DISABLED | win32k::menu::mf::GRAYED))
                    | (new.flags & (win32k::menu::mf::DISABLED | win32k::menu::mf::GRAYED));
            }
            if mask & MIIM_STRING != 0 && !new.caption.is_empty() {
                held.caption = new.caption;
            }
        })
        .ok_or(STATUS_INVALID_PARAMETER)
    };
    let failed = |status: NtStatus| {
        let _ = win32k::set_last_error(abi::winerror::dos_error(status));
        NtStatus(0)
    };
    change().map_or_else(failed, |()| NtStatus(1))
}

/// NtUserEnableMenuItem(hMenu, uItem, uEnable) : l'état de l'item —
/// MF_ENABLED (0) le remet, MF_GRAYED/MF_DISABLED le retire — par
/// identifiant ou position (`MF_BYPOSITION`) ; rend son état d'avant
/// (MF_ENABLED, MF_GRAYED…), -1 sans item.
pub(super) fn nt_user_enable_menu_item(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, enable] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(menu) = win32k::menu::get(hmenu) else { return NtStatus(u32::MAX) };
    let by_position = enable & MF_BYPOSITION != 0;
    let Some(before) = menu.find(item, by_position) else { return NtStatus(u32::MAX) };
    let previous = u32::from(before.flags & (win32k::menu::mf::GRAYED | win32k::menu::mf::DISABLED) != 0);
    let disable = enable & (win32k::menu::mf::GRAYED | win32k::menu::mf::DISABLED) != 0;
    let _ = menu.set(item, by_position, |held| {
        held.flags = (held.flags & !(win32k::menu::mf::GRAYED | win32k::menu::mf::DISABLED))
            | if disable { win32k::menu::mf::GRAYED | win32k::menu::mf::DISABLED } else { 0 };
    });
    NtStatus(previous)
}

/// NtUserDestroyMenu(hMenu) : BOOL. Le menu et ses sous-menus sont détruits
/// (IntDestroyMenuObject, `win32k::menu::destroy`) ; FALSE pour un menu qui
/// n'existe pas (`ERROR_INVALID_MENU_HANDLE`).
pub(super) fn nt_user_destroy_menu(arguments: &[u32]) -> NtStatus {
    if win32k::menu::destroy(arguments[0]) {
        NtStatus(1)
    } else {
        let _ = win32k::set_last_error(abi::winerror::ERROR_INVALID_MENU_HANDLE);
        NtStatus(0)
    }
}

/// NtUserRemoveMenu(hMenu, uPosition, uFlags) : l'item retiré (son
/// sous-menu vit) ; TRUE, FALSE sans lui.
pub(super) fn nt_user_remove_menu(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, flags] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(menu) = win32k::menu::get(hmenu) else { return NtStatus(0) };
    NtStatus(u32::from(menu.remove(item, flags & MF_BYPOSITION != 0).is_some()))
}

/// NtUserSetMenu(hWnd, hMenu, bRepaint) : la barre de menus de la fenêtre
/// (0 la retire) ; la zone cliente se recalcule et le cadre se repeint.
/// TRUE, FALSE sans fenêtre.
pub(super) fn nt_user_set_menu(arguments: &[u32]) -> NtStatus {
    let [hwnd, hmenu, _repaint] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(window) = win32k::window::get(hwnd) else { return NtStatus(0) };
    win32k::window::set_menu(&window, hmenu);
    NtStatus(1)
}
