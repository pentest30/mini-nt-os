//! What the registry services return to an i386 process (CLAUDE.md,
//! rule 5), laid out as on XP SP2: the fixed parts of `KEY_*_INFORMATION`
//! and `KEY_VALUE_*_INFORMATION`, which a name, a class or data follows.
//! ReactOS's NDK headers (`cmtypes.h`) serve as the specification of the
//! formats; offsets are checked at compile time.
//!
//! The structures that start with a LARGE_INTEGER are packed to 4 bytes: in
//! an i386 process, what follows the fixed part starts at the offset of the
//! next field, before any padding to 8 bytes.

use core::mem::{offset_of, size_of};

/// `KEY_INFORMATION_CLASS`.
pub const KEY_BASIC_INFORMATION: u32 = 0;
pub const KEY_NODE_INFORMATION: u32 = 1;
pub const KEY_FULL_INFORMATION: u32 = 2;

/// `KEY_VALUE_INFORMATION_CLASS`.
pub const KEY_VALUE_BASIC_INFORMATION: u32 = 0;
pub const KEY_VALUE_FULL_INFORMATION: u32 = 1;
pub const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;

/// Key access rights.
pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_NOTIFY: u32 = 0x0010;
pub const KEY_CREATE_LINK: u32 = 0x0020;
/// KEY_ALL_ACCESS.
pub const KEY_ALL_ACCESS: u32 = 0x000F_003F;

/// Value types.
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;

macro_rules! as_bytes {
    ($($t:ty),*) => {
        $(impl $t {
            /// Its bytes, as they go to the caller.
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: integer fields, packed or naturally aligned without
                // padding (sizes checked below): every byte is initialised.
                unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
            }
        })*
    };
}

/// KEY_BASIC_INFORMATION, before its name.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyBasicInformation32 {
    pub last_write_time: u64,
    pub title_index: u32,
    /// In bytes.
    pub name_length: u32,
}

/// KEY_NODE_INFORMATION, before its name, which its class follows.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyNodeInformation32 {
    pub last_write_time: u64,
    pub title_index: u32,
    /// From the start of the structure; `0xFFFFFFFF` without a class.
    pub class_offset: u32,
    pub class_length: u32,
    pub name_length: u32,
}

/// KEY_FULL_INFORMATION, before its class.
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyFullInformation32 {
    pub last_write_time: u64,
    pub title_index: u32,
    pub class_offset: u32,
    pub class_length: u32,
    pub sub_keys: u32,
    /// The longest subkey name, in bytes.
    pub max_name_len: u32,
    pub max_class_len: u32,
    pub values: u32,
    pub max_value_name_len: u32,
    pub max_value_data_len: u32,
}

/// KEY_VALUE_BASIC_INFORMATION, before its name.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyValueBasicInformation32 {
    pub title_index: u32,
    pub data_type: u32,
    pub name_length: u32,
}

/// KEY_VALUE_FULL_INFORMATION, before its name; its data starts at
/// `data_offset`, from the start of the structure.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyValueFullInformation32 {
    pub title_index: u32,
    pub data_type: u32,
    pub data_offset: u32,
    pub data_length: u32,
    pub name_length: u32,
}

/// KEY_VALUE_PARTIAL_INFORMATION, before its data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyValuePartialInformation32 {
    pub title_index: u32,
    pub data_type: u32,
    pub data_length: u32,
}

as_bytes!(
    KeyBasicInformation32,
    KeyNodeInformation32,
    KeyFullInformation32,
    KeyValueBasicInformation32,
    KeyValueFullInformation32,
    KeyValuePartialInformation32
);

const _: () = {
    assert!(size_of::<KeyBasicInformation32>() == 16);
    assert!(offset_of!(KeyBasicInformation32, name_length) == 12);
    assert!(size_of::<KeyNodeInformation32>() == 24);
    assert!(offset_of!(KeyNodeInformation32, class_offset) == 12);
    assert!(offset_of!(KeyNodeInformation32, name_length) == 20);
    assert!(size_of::<KeyFullInformation32>() == 44);
    assert!(offset_of!(KeyFullInformation32, sub_keys) == 20);
    assert!(offset_of!(KeyFullInformation32, values) == 32);
    assert!(offset_of!(KeyFullInformation32, max_value_data_len) == 40);
    assert!(size_of::<KeyValueBasicInformation32>() == 12);
    assert!(size_of::<KeyValueFullInformation32>() == 20);
    assert!(offset_of!(KeyValueFullInformation32, data_offset) == 8);
    assert!(offset_of!(KeyValueFullInformation32, name_length) == 16);
    assert!(size_of::<KeyValuePartialInformation32>() == 12);
    assert!(offset_of!(KeyValuePartialInformation32, data_length) == 8);
};
