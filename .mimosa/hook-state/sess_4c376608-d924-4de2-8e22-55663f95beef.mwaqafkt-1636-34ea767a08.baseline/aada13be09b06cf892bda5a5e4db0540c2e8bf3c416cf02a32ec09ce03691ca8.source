//! The keyboard: what a keyboard driver gives win32k (KEYBOARD_INPUT_DATA,
//! `ntddkbd.h`) and the tables of a keyboard layout DLL (KBDTABLES and
//! what it points to, `kbd.h`), as a 32-bit image holds them: pointers are
//! addresses in the image at its preferred base.

use core::mem::{offset_of, size_of};

/// KEYBOARD_INPUT_DATA `Flags`: a key released (`KEY_MAKE` is 0).
pub const KEY_BREAK: u16 = 1;
/// After an `E0` prefix byte.
pub const KEY_E0: u16 = 2;
/// After an `E1` prefix byte (Pause).
pub const KEY_E1: u16 = 4;
/// KEYBOARD_OVERRUN_MAKE_CODE: the controller lost bytes.
pub const KEYBOARD_OVERRUN_MAKE_CODE: u16 = 0xFF;

/// KEYBOARD_INPUT_DATA: one key going down or up.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyboardInputData {
    pub unit_id: u16,
    /// The scan code, without the break bit.
    pub make_code: u16,
    /// KEY_BREAK, KEY_E0, KEY_E1.
    pub flags: u16,
    pub reserved: u16,
    pub extra_information: u32,
}

/// The flags of a virtual key in `pusVSCtoVK` (its low byte is the key).
pub const KBDEXT: u16 = 0x100;
pub const KBDMULTIVK: u16 = 0x200;
pub const KBDSPECIAL: u16 = 0x400;
pub const KBDNUMPAD: u16 = 0x800;

/// The modifier bits of a layout (MODIFIERS: `pVkToBit`).
pub const KBDSHIFT: u8 = 1;
pub const KBDCTRL: u8 = 2;
pub const KBDALT: u8 = 4;
/// A combination of modifiers without characters (`ModNumber`).
pub const SHFT_INVALID: u8 = 0x0F;

/// Special characters of a VK_TO_WCHARS row.
pub const WCH_NONE: u16 = 0xF000;
pub const WCH_DEAD: u16 = 0xF001;
pub const WCH_LGTR: u16 = 0xF002;

/// VK_TO_WCHARS `Attributes`: Caps Lock shifts the key.
pub const CAPLOK: u8 = 0x01;
pub const SGCAPS: u8 = 0x02;
/// Caps Lock shifts the key with AltGr.
pub const CAPLOKALTGR: u8 = 0x04;

/// KBDTABLES `fLocaleFlags`: the right Alt is AltGr (Ctrl + Alt).
pub const KLLF_ALTGR: u32 = 0x0001;

/// KBDTABLES: a layout's tables.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KbdTables32 {
    /// MODIFIERS.
    pub char_modifiers: u32,
    /// VK_TO_WCHAR_TABLE[], up to one without rows.
    pub vk_to_wchar_table: u32,
    /// DEADKEY[], up to `dwBoth` 0.
    pub dead_key: u32,
    pub key_names: u32,
    pub key_names_ext: u32,
    pub key_names_dead: u32,
    /// USHORT[bMaxVSCtoVK]: the virtual key of each scan code.
    pub vsc_to_vk: u32,
    pub max_vsc_to_vk: u8,
    pub _pad: [u8; 3],
    /// VSC_VK[], up to `Vsc` 0: the keys after `E0`.
    pub vsc_to_vk_e0: u32,
    /// The keys after `E1`.
    pub vsc_to_vk_e1: u32,
    pub locale_flags: u32,
    pub lg_max: u8,
    pub cb_lg_entry: u8,
    pub _pad2: [u8; 2],
    pub ligature: u32,
}

/// MODIFIERS, before its `ModNumber[]` (from byte 6).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modifiers32 {
    /// VK_TO_BIT[], up to `Vk` 0.
    pub vk_to_bit: u32,
    pub max_mod_bits: u16,
}

/// The offset of `ModNumber[]` in MODIFIERS.
pub const MODIFIERS_MOD_NUMBER: u32 = 6;

/// VK_TO_WCHAR_TABLE: rows of `nModifications` characters, `cbSize` bytes
/// each (VK_TO_WCHARS: `VirtualKey`, `Attributes`, `wch[]`), up to a row of
/// `VirtualKey` 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VkToWcharTable32 {
    pub vk_to_wchars: u32,
    pub modifications: u8,
    pub size: u8,
    pub _pad: [u8; 2],
}

/// DEADKEY: `dwBoth` (the dead character in its high word, the next one
/// in its low word) gives `wchComposed`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeadKey32 {
    pub both: u32,
    pub composed: u16,
    pub flags: u16,
}

/// VSC_VK: a prefixed scan code's virtual key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VscVk32 {
    pub vsc: u8,
    pub _pad: u8,
    pub vk: u16,
}

const _: () = {
    assert!(size_of::<KeyboardInputData>() == 12);
    assert!(offset_of!(KeyboardInputData, flags) == 4);
    assert!(offset_of!(KeyboardInputData, extra_information) == 8);
    assert!(size_of::<KbdTables32>() == 52);
    assert!(offset_of!(KbdTables32, vsc_to_vk) == 24);
    assert!(offset_of!(KbdTables32, max_vsc_to_vk) == 28);
    assert!(offset_of!(KbdTables32, vsc_to_vk_e0) == 32);
    assert!(offset_of!(KbdTables32, locale_flags) == 40);
    assert!(offset_of!(KbdTables32, ligature) == 48);
    assert!(size_of::<Modifiers32>() == 8);
    assert!(offset_of!(Modifiers32, max_mod_bits) == 4);
    assert!(size_of::<VkToWcharTable32>() == 8);
    assert!(offset_of!(VkToWcharTable32, size) == 5);
    assert!(size_of::<DeadKey32>() == 8);
    assert!(size_of::<VscVk32>() == 4);
    assert!(offset_of!(VscVk32, vk) == 2);
};

/// A little-endian `u32` at `at` in `bytes`.
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// A little-endian `u16` at `at` in `bytes`.
fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

impl KbdTables32 {
    /// The tables in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        Some(Self {
            char_modifiers: word(bytes, 0),
            vk_to_wchar_table: word(bytes, 4),
            dead_key: word(bytes, 8),
            key_names: word(bytes, 12),
            key_names_ext: word(bytes, 16),
            key_names_dead: word(bytes, 20),
            vsc_to_vk: word(bytes, 24),
            max_vsc_to_vk: bytes[28],
            _pad: [0; 3],
            vsc_to_vk_e0: word(bytes, 32),
            vsc_to_vk_e1: word(bytes, 36),
            locale_flags: word(bytes, 40),
            lg_max: bytes[44],
            cb_lg_entry: bytes[45],
            _pad2: [0; 2],
            ligature: word(bytes, 48),
        })
    }
}

impl Modifiers32 {
    /// The head of MODIFIERS in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() >= MODIFIERS_MOD_NUMBER as usize)
            .then(|| Self { vk_to_bit: word(bytes, 0), max_mod_bits: half(bytes, 4) })
    }
}

impl VkToWcharTable32 {
    /// The table in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() >= size_of::<Self>()).then(|| Self {
            vk_to_wchars: word(bytes, 0),
            modifications: bytes[4],
            size: bytes[5],
            _pad: [0; 2],
        })
    }
}

impl DeadKey32 {
    /// The entry in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() >= size_of::<Self>()).then(|| Self {
            both: word(bytes, 0),
            composed: half(bytes, 4),
            flags: half(bytes, 6),
        })
    }
}

impl VscVk32 {
    /// The entry in `bytes`; `None` if they are too few.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() >= size_of::<Self>()).then(|| Self { vsc: bytes[0], _pad: 0, vk: half(bytes, 2) })
    }
}
