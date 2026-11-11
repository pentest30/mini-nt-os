//! Les services des menus (`win32k::menu`) : la création passe par
//! NtUserCallNoParam (CREATEMENU, CREATEMENUPOPUP, `super::mouse`), les items
//! par NtUserThunkedMenuItemInfo, leur état par NtUserEnableMenuItem,
//! NtUserCheckMenuItem et NtUserSetMenuDefaultItem, le menu par
//! NtUserThunkedMenuInfo, NtUserSetMenuContextHelpId et
//! NtUserSetMenuFlagRtoL, la barre d'une fenêtre par NtUserSetMenu ; la
//! destruction par NtUserRemoveMenu, NtUserDeleteMenu, NtUserDestroyMenu.
//! `user32` lit le reste lui-même dans le tas du bureau.
//!
//! Comme dans win32k, un échec rend FALSE (ou -1) et met l'erreur Win32
//! dans le TEB ; un menu qui n'existe pas, `ERROR_INVALID_MENU_HANDLE`.

use alloc::vec::Vec;

use abi::menu::{miim, MenuInfo32, MenuItemInfoW32, MENUITEMINFOW_OLD_SIZE, ROSMENUINFO_SIZE};
use abi::ntstatus::NtStatus;
use abi::winerror::{dos_error, ERROR_INVALID_MENU_HANDLE, ERROR_INVALID_PARAMETER, ERROR_INVALID_WINDOW_HANDLE};
use ke::usermem::{copy_from_user, UserPtr};

/// La taille d'un MENUITEMINFOW.
const MENU_ITEM_INFO_SIZE: u32 = core::mem::size_of::<MenuItemInfoW32>() as u32;
/// La taille de ROSMENUITEMINFO, que seul le `user32` de ReactOS donnait à
/// SetMenuItemInfo : ses champs après MENUITEMINFOW ne sont pas lus.
const ROSMENUITEMINFO_SIZE: u32 = 80;

/// Met l'erreur Win32 `error` et rend `value`.
fn fail(error: u32, value: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(value)
}

/// TRUE, ou FALSE avec l'erreur.
fn boolean(result: Result<(), u32>) -> NtStatus {
    match result {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error, 0),
    }
}

/// Le menu `hmenu` existe, sinon `ERROR_INVALID_MENU_HANDLE`
/// (UserGetMenuObject).
fn menu(hmenu: u32) -> Result<u32, u32> {
    if win32k::menu::exists(hmenu) {
        Ok(hmenu)
    } else {
        Err(ERROR_INVALID_MENU_HANDLE)
    }
}

/// ProbeAndCaptureUnicodeString : la légende d'un item, l'UNICODE_STRING
/// en `caption` chez l'appelant ; `None` sans elle ou sans tampon.
fn capture_caption(caption: u32) -> Result<Option<Vec<u16>>, u32> {
    if caption == 0 {
        return Ok(None);
    }
    let mut string = [0u8; 8];
    copy_from_user(&mut string, u64::from(caption)).map_err(dos_error)?;
    let length = u16::from_le_bytes([string[0], string[1]]) as usize & !1;
    let buffer = u32::from_le_bytes([string[4], string[5], string[6], string[7]]);
    if buffer == 0 {
        return Ok(None);
    }
    let mut units = alloc::vec![0u8; length];
    copy_from_user(&mut units, u64::from(buffer)).map_err(dos_error)?;
    Ok(Some(units.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()))
}

/// UserInsertMenuItem et UserMenuItemInfo : le MENUITEMINFOW en `info` chez
/// l'appelant, de 48 octets ou de 44 sans `hbmpItem` (0 alors) ; une autre
/// taille, ou MIIM_BITMAP sans `hbmpItem`, `ERROR_INVALID_PARAMETER`. SetMenuItemInfo
/// prend aussi la taille du ROSMENUITEMINFO de ReactOS.
fn capture_item_info(info: u32, insert: bool) -> Result<MenuItemInfoW32, u32> {
    let size = UserPtr::<u32>::new(info).read().map_err(dos_error)?;
    let known =
        size == MENU_ITEM_INFO_SIZE || size == MENUITEMINFOW_OLD_SIZE || (!insert && size == ROSMENUITEMINFO_SIZE);
    if !known {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut bytes = [0u8; MENU_ITEM_INFO_SIZE as usize];
    let read = size.min(MENU_ITEM_INFO_SIZE) as usize;
    copy_from_user(&mut bytes[..read], u64::from(info)).map_err(dos_error)?;
    let item = MenuItemInfoW32::from_bytes(&bytes[..read]).ok_or(ERROR_INVALID_PARAMETER)?;
    if !insert && size == MENUITEMINFOW_OLD_SIZE && item.f_mask & miim::BITMAP != 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    Ok(item)
}

/// NtUserThunkedMenuItemInfo(hMenu, uItem, fByPosition, bInsert, lpmii,
/// lpszCaption) : avec `bInsert`, un item neuf au bout, à sa position ou
/// avant l'item d'identifiant `uItem` (`win32k::menu::insert_item`) ; sans,
/// l'item `uItem` mis à jour (`win32k::menu::set_item_info`). Le texte vient
/// de la légende capturée. TRUE ; FALSE et l'erreur sinon.
pub(super) fn nt_user_thunked_menu_item_info(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, by_position, insert, info, caption] = arguments[..6] else { unreachable!("6 arguments") };
    let run = || {
        let hmenu = menu(hmenu)?;
        let text = capture_caption(caption)?;
        let info = capture_item_info(info, insert != 0)?;
        if insert != 0 {
            win32k::menu::insert_item(hmenu, item, by_position != 0, &info, text.as_deref())
        } else {
            win32k::menu::set_item_info(hmenu, item, by_position != 0, &info, text.as_deref())
        }
    };
    boolean(run())
}

/// NtUserThunkedMenuInfo(hMenu, lpcmi) : le MENUINFO (de 28 octets jusqu'à
/// la taille d'un ROSMENUINFO, dont seuls les champs de MENUINFO sont lus)
/// change le menu (`win32k::menu::set_info`). TRUE ; FALSE et l'erreur
/// sinon.
pub(super) fn nt_user_thunked_menu_info(arguments: &[u32]) -> NtStatus {
    let [hmenu, info] = arguments[..2] else { unreachable!("2 arguments") };
    let run = || {
        let hmenu = menu(hmenu)?;
        let size = UserPtr::<u32>::new(info).read().map_err(dos_error)?;
        let least = core::mem::size_of::<MenuInfo32>() as u32;
        if !(least..=ROSMENUINFO_SIZE).contains(&size) {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut bytes = [0u8; core::mem::size_of::<MenuInfo32>()];
        copy_from_user(&mut bytes, u64::from(info)).map_err(dos_error)?;
        let info = MenuInfo32::from_bytes(&bytes).ok_or(ERROR_INVALID_PARAMETER)?;
        win32k::menu::set_info(hmenu, &info).then_some(()).ok_or(ERROR_INVALID_MENU_HANDLE)
    };
    boolean(run())
}

/// NtUserEnableMenuItem(hMenu, uIDEnableItem, uEnable) : l'état grisé et
/// désactivé de l'item, par identifiant ou position (MF_BYPOSITION) ; rend
/// celui d'avant (MF_GRAYED, MF_DISABLED), -1 sans menu ou item.
pub(super) fn nt_user_enable_menu_item(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, enable] = arguments[..3] else { unreachable!("3 arguments") };
    match menu(hmenu) {
        Ok(hmenu) => NtStatus(win32k::menu::enable(hmenu, item, enable)),
        Err(error) => fail(error, u32::MAX),
    }
}

/// NtUserCheckMenuItem(hMenu, uIDCheckItem, uCheck) : l'item coché ou non
/// (MF_CHECKED) ; rend son état d'avant, -1 sans menu ou item.
pub(super) fn nt_user_check_menu_item(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, check] = arguments[..3] else { unreachable!("3 arguments") };
    match menu(hmenu) {
        Ok(hmenu) => NtStatus(win32k::menu::check(hmenu, item, check)),
        Err(error) => fail(error, u32::MAX),
    }
}

/// NtUserSetMenuDefaultItem(hMenu, uItem, fByPos) : l'item par défaut du
/// menu (-1 : aucun). BOOL.
pub(super) fn nt_user_set_menu_default_item(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, by_position] = arguments[..3] else { unreachable!("3 arguments") };
    match menu(hmenu) {
        Ok(hmenu) => NtStatus(u32::from(win32k::menu::set_default(hmenu, item, by_position != 0))),
        Err(error) => fail(error, 0),
    }
}

/// NtUserSetMenuContextHelpId(hMenu, dwContextHelpId). BOOL.
pub(super) fn nt_user_set_menu_context_help_id(arguments: &[u32]) -> NtStatus {
    let [hmenu, help_id] = arguments[..2] else { unreachable!("2 arguments") };
    boolean(menu(hmenu).map(|hmenu| {
        win32k::menu::set_help_id(hmenu, help_id);
    }))
}

/// NtUserSetMenuFlagRtoL(hMenu) : le menu se lit de droite à gauche. BOOL.
pub(super) fn nt_user_set_menu_flag_rtol(arguments: &[u32]) -> NtStatus {
    boolean(menu(arguments[0]).map(|hmenu| {
        win32k::menu::set_rtol(hmenu);
    }))
}

/// NtUserDestroyMenu(hMenu) : BOOL. Le menu et ses sous-menus sont détruits
/// (IntDestroyMenuObject, `win32k::menu::destroy`) ; FALSE pour un menu qui
/// n'existe pas (`ERROR_INVALID_MENU_HANDLE`).
pub(super) fn nt_user_destroy_menu(arguments: &[u32]) -> NtStatus {
    if win32k::menu::destroy(arguments[0]) {
        NtStatus(1)
    } else {
        fail(ERROR_INVALID_MENU_HANDLE, 0)
    }
}

/// NtUserRemoveMenu(hMenu, uPosition, uFlags) : l'item retiré (son
/// sous-menu vit) ; TRUE, FALSE sans lui.
pub(super) fn nt_user_remove_menu(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, flags] = arguments[..3] else { unreachable!("3 arguments") };
    match menu(hmenu) {
        Ok(hmenu) => NtStatus(u32::from(win32k::menu::remove(hmenu, item, flags, false))),
        Err(error) => fail(error, 0),
    }
}

/// NtUserDeleteMenu(hMenu, uPosition, uFlags) : l'item retiré, son
/// sous-menu détruit ; TRUE, FALSE sans lui.
pub(super) fn nt_user_delete_menu(arguments: &[u32]) -> NtStatus {
    let [hmenu, item, flags] = arguments[..3] else { unreachable!("3 arguments") };
    match menu(hmenu) {
        Ok(hmenu) => NtStatus(u32::from(win32k::menu::remove(hmenu, item, flags, true))),
        Err(error) => fail(error, 0),
    }
}

/// NtUserSetMenu(hWnd, hMenu, bRepaint) : la barre de menus de la fenêtre
/// (0 la retire ; `win32k::window::set_menu`). TRUE ; FALSE pour une
/// fenêtre qui n'existe pas ou qui est fille, un menu qui n'existe pas ou
/// qui est la barre d'une autre fenêtre.
pub(super) fn nt_user_set_menu(arguments: &[u32]) -> NtStatus {
    let [hwnd, hmenu, repaint] = arguments[..3] else { unreachable!("3 arguments") };
    let Some(window) = win32k::window::get(hwnd) else { return fail(ERROR_INVALID_WINDOW_HANDLE, 0) };
    boolean(win32k::window::set_menu(&window, hmenu, repaint != 0))
}
