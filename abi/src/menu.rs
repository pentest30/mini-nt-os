//! Menus: the records `user32` reads in a desktop's heap (`MENU`, `ITEM`, as
//! ReactOS's `ntuser.h` lays them out on i386) and those it gives to win32k
//! (`MENUITEMINFOW`, `MENUINFO`), with the SDK's flags.
//!
//! A menu is a desktop object: its handle entry points to its `MENU` in the
//! heap (a server address), which `user32` turns into its own address
//! (DesktopPtrToUser) to read `cItems`, `rgItems` and the items themselves:
//! GetMenuItemCount, GetSubMenu, GetMenuItemID, GetMenuState,
//! GetMenuString, GetMenuItemInfo, IsMenu.

use core::mem::{offset_of, size_of};

/// MF_* (and the MFT_*, MFS_* that share their bits): an item's type and
/// state, as InsertMenu and ModifyMenu give them.
pub mod mf {
    pub const STRING: u32 = 0x0000;
    pub const GRAYED: u32 = 0x0001;
    pub const DISABLED: u32 = 0x0002;
    pub const BITMAP: u32 = 0x0004;
    pub const CHECKED: u32 = 0x0008;
    pub const POPUP: u32 = 0x0010;
    pub const MENUBARBREAK: u32 = 0x0020;
    pub const MENUBREAK: u32 = 0x0040;
    pub const HILITE: u32 = 0x0080;
    pub const OWNERDRAW: u32 = 0x0100;
    pub const BYPOSITION: u32 = 0x0400;
    pub const SEPARATOR: u32 = 0x0800;
    pub const DEFAULT: u32 = 0x1000;
    pub const SYSMENU: u32 = 0x2000;
    pub const HELP: u32 = 0x4000;
    pub const MOUSESELECT: u32 = 0x8000;
}

/// MFT_*: an item's type (`ITEM.fType`).
pub mod mft {
    pub const STRING: u32 = 0x0000;
    pub const BITMAP: u32 = 0x0004;
    pub const MENUBARBREAK: u32 = 0x0020;
    pub const MENUBREAK: u32 = 0x0040;
    pub const OWNERDRAW: u32 = 0x0100;
    pub const RADIOCHECK: u32 = 0x0200;
    pub const SEPARATOR: u32 = 0x0800;
    pub const RIGHTORDER: u32 = 0x2000;
    /// The same bit as MF_HELP: the item goes to the right of the bar.
    pub const RIGHTJUSTIFY: u32 = 0x4000;
}

/// MFS_*: an item's state (`ITEM.fState`).
pub mod mfs {
    /// MFS_GRAYED and MFS_DISABLED are both MF_GRAYED | MF_DISABLED.
    pub const GRAYED: u32 = 0x0003;
    pub const DISABLED: u32 = 0x0003;
    pub const CHECKED: u32 = 0x0008;
    pub const HILITE: u32 = 0x0080;
    pub const DEFAULT: u32 = 0x1000;
    /// ReactOS's: the item's bitmap is one of the magic HBMMENU_* values.
    pub const HBMMENUBMP: u32 = 0x2000_0000;
}

/// The bits of `fType` a MENUITEMINFO carries (MENUITEMINFO_TYPE_MASK).
pub const MENUITEMINFO_TYPE_MASK: u32 = mft::STRING
    | mft::BITMAP
    | mft::OWNERDRAW
    | mft::SEPARATOR
    | mft::MENUBARBREAK
    | mft::MENUBREAK
    | mft::RADIOCHECK
    | mft::RIGHTORDER
    | mft::RIGHTJUSTIFY;
/// TYPE_MASK: the type bits with MF_POPUP and MF_SYSMENU.
pub const TYPE_MASK: u32 = MENUITEMINFO_TYPE_MASK | mf::POPUP | mf::SYSMENU;
/// The bits of `fState` a MENUITEMINFO carries (MENUITEMINFO_STATE_MASK).
pub const MENUITEMINFO_STATE_MASK: u32 = !TYPE_MASK & !(mf::BYPOSITION | mf::MOUSESELECT);

/// MIIM_*: the fields of a MENUITEMINFO that a call gives or asks.
pub mod miim {
    pub const STATE: u32 = 0x0001;
    pub const ID: u32 = 0x0002;
    pub const SUBMENU: u32 = 0x0004;
    pub const CHECKMARKS: u32 = 0x0008;
    pub const TYPE: u32 = 0x0010;
    pub const DATA: u32 = 0x0020;
    pub const STRING: u32 = 0x0040;
    pub const BITMAP: u32 = 0x0080;
    pub const FTYPE: u32 = 0x0100;
}

/// MIM_*: the fields of a MENUINFO that SetMenuInfo gives.
pub mod mim {
    pub const MAXHEIGHT: u32 = 0x0001;
    pub const BACKGROUND: u32 = 0x0002;
    pub const HELPID: u32 = 0x0004;
    pub const MENUDATA: u32 = 0x0008;
    pub const STYLE: u32 = 0x0010;
    pub const APPLYTOSUBMENUS: u32 = 0x8000_0000;
}

/// MNS_*: a menu's style, the upper bits of `MENU.fFlags`.
pub mod mns {
    pub const NOCHECK: u32 = 0x8000_0000;
    pub const MODELESS: u32 = 0x4000_0000;
    pub const DRAGDROP: u32 = 0x2000_0000;
    pub const AUTODISMISS: u32 = 0x1000_0000;
    pub const NOTIFYBYPOS: u32 = 0x0800_0000;
    pub const CHECKORBMP: u32 = 0x0400_0000;
    /// MNS_STYLE_MASK.
    pub const STYLE_MASK: u32 = NOCHECK | MODELESS | DRAGDROP | AUTODISMISS | NOTIFYBYPOS | CHECKORBMP;
}

/// MNF_*: a menu's own flags, the lower bits of `MENU.fFlags` (ReactOS's).
pub mod mnf {
    /// A popup menu (CreatePopupMenu, or attached as a submenu).
    pub const POPUP: u32 = 0x0001;
    pub const UNDERLINE: u32 = 0x0004;
    pub const INACTIVE: u32 = 0x0010;
    pub const RTOL: u32 = 0x0020;
    pub const SYSSUBMENU: u32 = 0x0100;
    pub const SYSMENU: u32 = 0x0200;
}

/// NO_SELECTED_ITEM: `MENU.iItem` when no item is selected.
pub const NO_SELECTED_ITEM: u32 = 0xFFFF;

/// The magic bitmaps of an item (HBMMENU_*), `hbmp` from -1 to 11.
pub mod hbmmenu {
    pub const CALLBACK: u32 = 0xFFFF_FFFF;
    pub const SYSTEM: u32 = 1;
    pub const MBAR_RESTORE: u32 = 2;
    pub const MBAR_MINIMIZE: u32 = 3;
    pub const MBAR_CLOSE: u32 = 5;
    pub const MBAR_CLOSE_D: u32 = 6;
    pub const MBAR_MINIMIZE_D: u32 = 7;
    pub const POPUP_CLOSE: u32 = 8;
    pub const POPUP_RESTORE: u32 = 9;
    pub const POPUP_MAXIMIZE: u32 = 10;
    pub const POPUP_MINIMIZE: u32 = 11;
}

/// IS_MAGIC_BITMAP: `hbmp` is one of the HBMMENU_* values, not a bitmap.
pub const fn is_magic_bitmap(hbmp: u32) -> bool {
    let value = hbmp as i32;
    value != 0 && value < 12 && value >= -1
}

/// MENU_ITEM_TYPE: the bits that say what an item shows.
pub const fn item_kind(f_type: u32) -> u32 {
    f_type & (mf::STRING | mf::BITMAP | mf::OWNERDRAW | mf::SEPARATOR)
}

/// PROCDESKHEAD, 32-bit: the head of a desktop object a process owns.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcDeskHead32 {
    /// Its handle (`h`).
    pub h: u32,
    pub c_lock_obj: u32,
    /// `hTaskWow`: ReactOS keeps the owner's `PROCESSINFO` there.
    pub h_task_wow: u32,
    /// Its desktop (`rpdesk`).
    pub rpdesk: u32,
    /// Its own server address (`pSelf`).
    pub p_self: u32,
}

/// MENU, 32-bit, ReactOS's (`ntuser.h`), in the heap of its desktop.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Menu32 {
    pub head: ProcDeskHead32,
    /// MNS_* | MNF_*.
    pub f_flags: u32,
    /// The selected item's position, NO_SELECTED_ITEM without.
    pub i_item: u32,
    /// The items `rgItems` has room for.
    pub c_alloced: u32,
    pub c_items: u32,
    pub cx_menu: u32,
    pub cy_menu: u32,
    pub cx_text_align: u32,
    pub spwnd_notify: u32,
    /// Its items (server address of an `ITEM` array), 0 without.
    pub rg_items: u32,
    pub p_parent_menus: u32,
    pub dw_context_help_id: u32,
    pub cy_max: u32,
    pub dw_menu_data: u32,
    pub hbr_back: u32,
    pub i_top: i32,
    pub i_max_top: i32,
    pub dw_arrows_on: u32,
    /// ReactOS's own fields: `ListEntry`, `hWnd` (the window whose bar it
    /// is), `TimeToHide`.
    pub list_entry: [u32; 2],
    pub hwnd: u32,
    pub time_to_hide: u32,
}

/// UNICODE_STRING, 32-bit, in an `ITEM` (ReactOS's `lpstr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnicodeString32 {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u32,
}

/// ITEM, 32-bit, ReactOS's (`ntuser.h`): one item of `MENU.rgItems`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Item32 {
    pub f_type: u32,
    pub f_state: u32,
    pub w_id: u32,
    /// The submenu it opens (server address of its `MENU`), 0 without.
    pub sp_sub_menu: u32,
    pub hbmp_checked: u32,
    pub hbmp_unchecked: u32,
    /// Its text (server address of NUL-terminated UTF-16), 0 without.
    pub xlpstr: u32,
    /// The length of its text, in characters.
    pub cch: u32,
    pub dw_item_data: u32,
    /// Its place in the menu (`xItem`, `yItem`) and size.
    pub x_item: u32,
    pub y_item: u32,
    pub cx_item: u32,
    pub cy_item: u32,
    pub dx_tab: u32,
    pub ul_x: u32,
    pub ul_width: u32,
    pub hbmp: u32,
    pub cx_bmp: i32,
    pub cy_bmp: i32,
    /// ReactOS's: the same text as a UNICODE_STRING.
    pub lpstr: UnicodeString32,
}

/// MENUITEMINFOW, 32-bit; an application may give it without `hbmpItem`
/// (44 bytes, before Windows 2000).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MenuItemInfoW32 {
    pub cb_size: u32,
    pub f_mask: u32,
    pub f_type: u32,
    pub f_state: u32,
    pub w_id: u32,
    pub h_sub_menu: u32,
    pub hbmp_checked: u32,
    pub hbmp_unchecked: u32,
    pub dw_item_data: u32,
    pub dw_type_data: u32,
    pub cch: u32,
    pub hbmp_item: u32,
}

/// The size of a MENUITEMINFOW without `hbmpItem`.
pub const MENUITEMINFOW_OLD_SIZE: u32 = offset_of!(MenuItemInfoW32, hbmp_item) as u32;

/// MENUINFO, 32-bit (SetMenuInfo).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MenuInfo32 {
    pub cb_size: u32,
    pub f_mask: u32,
    pub dw_style: u32,
    pub cy_max: u32,
    pub hbr_back: u32,
    pub dw_context_help_id: u32,
    pub dw_menu_data: u32,
}

/// The size of ReactOS's ROSMENUINFO (MENUINFO and the fields only its
/// own `user32` gave): NtUserThunkedMenuInfo takes a MENUINFO up to it.
pub const ROSMENUINFO_SIZE: u32 = 76;

const _: () = {
    assert!(size_of::<ProcDeskHead32>() == 20);
    assert!(size_of::<Menu32>() == 104);
    assert!(offset_of!(Menu32, f_flags) == 20);
    assert!(offset_of!(Menu32, c_items) == 32);
    assert!(offset_of!(Menu32, rg_items) == 52);
    assert!(offset_of!(Menu32, dw_context_help_id) == 60);
    assert!(offset_of!(Menu32, hbr_back) == 72);
    assert!(offset_of!(Menu32, dw_arrows_on) == 84);
    assert!(offset_of!(Menu32, hwnd) == 96);
    assert!(size_of::<UnicodeString32>() == 8);
    assert!(size_of::<Item32>() == 84);
    assert!(offset_of!(Item32, sp_sub_menu) == 12);
    assert!(offset_of!(Item32, xlpstr) == 24);
    assert!(offset_of!(Item32, dw_item_data) == 32);
    assert!(offset_of!(Item32, x_item) == 36);
    assert!(offset_of!(Item32, hbmp) == 64);
    assert!(offset_of!(Item32, lpstr) == 76);
    assert!(size_of::<MenuItemInfoW32>() == 48);
    assert!(MENUITEMINFOW_OLD_SIZE == 44);
    assert!(size_of::<MenuInfo32>() == 28);
};

/// The little-endian words of `bytes`, `N` of them, or `None` if it is
/// shorter.
fn words<const N: usize>(bytes: &[u8]) -> Option<[u32; N]> {
    let mut words = [0u32; N];
    for (index, word) in words.iter_mut().enumerate() {
        let at = index * 4;
        *word = u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?);
    }
    Some(words)
}

impl MenuItemInfoW32 {
    /// The record in `bytes`: 48 bytes, or 44 without `hbmpItem` (0).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let [cb_size, f_mask, f_type, f_state, w_id, h_sub_menu, hbmp_checked, hbmp_unchecked, dw_item_data, dw_type_data, cch] =
            words::<11>(bytes)?;
        let hbmp_item = words::<12>(bytes).map_or(0, |all| all[11]);
        Some(Self {
            cb_size,
            f_mask,
            f_type,
            f_state,
            w_id,
            h_sub_menu,
            hbmp_checked,
            hbmp_unchecked,
            dw_item_data,
            dw_type_data,
            cch,
            hbmp_item,
        })
    }
}

impl MenuInfo32 {
    /// The record in `bytes`, if they are at least 28.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let [cb_size, f_mask, dw_style, cy_max, hbr_back, dw_context_help_id, dw_menu_data] = words::<7>(bytes)?;
        Some(Self { cb_size, f_mask, dw_style, cy_max, hbr_back, dw_context_help_id, dw_menu_data })
    }
}

/// `as_bytes` for records of integers whose sizes, checked above, leave no
/// padding.
macro_rules! as_bytes {
    ($($record:ty),*) => {$(
        impl $record {
            /// Its bytes, as they go to the desktop's heap or to user mode.
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: a `#[repr(C)]` record of integers without padding
                // (its size is checked above): every byte is initialised.
                unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
            }
        }
    )*};
}

as_bytes!(Menu32, Item32, MenuItemInfoW32, MenuInfo32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_masks_of_a_menu_item_info() {
        assert_eq!(MENUITEMINFO_TYPE_MASK, 0x6B64);
        assert_eq!(TYPE_MASK, 0x6B74);
        assert_eq!(MENUITEMINFO_STATE_MASK & 0xFFFF, 0x108B, "grayed, disabled, checked, hilite, default");
        assert_eq!(mns::STYLE_MASK, 0xFC00_0000);
    }

    #[test]
    fn magic_bitmaps_go_from_minus_one_to_eleven() {
        assert!(is_magic_bitmap(hbmmenu::CALLBACK));
        assert!(is_magic_bitmap(hbmmenu::POPUP_MINIMIZE));
        assert!(!is_magic_bitmap(0));
        assert!(!is_magic_bitmap(12));
        assert!(!is_magic_bitmap(0x0405_0020), "a bitmap's handle");
    }

    #[test]
    fn a_menu_item_info_reads_back_with_or_without_its_bitmap() {
        let info = MenuItemInfoW32 { cb_size: 48, f_mask: 0x42, w_id: 100, cch: 4, hbmp_item: 7, ..Default::default() };
        assert_eq!(MenuItemInfoW32::from_bytes(info.as_bytes()), Some(info));
        let old = MenuItemInfoW32::from_bytes(&info.as_bytes()[..44]).unwrap();
        assert_eq!((old.cch, old.hbmp_item), (4, 0), "44 bytes: no hbmpItem");
        assert_eq!(MenuItemInfoW32::from_bytes(&info.as_bytes()[..40]), None);
        let menu_info = MenuInfo32 { cb_size: 28, f_mask: mim::HELPID, dw_context_help_id: 9, ..Default::default() };
        assert_eq!(MenuInfo32::from_bytes(menu_info.as_bytes()), Some(menu_info));
    }
}
