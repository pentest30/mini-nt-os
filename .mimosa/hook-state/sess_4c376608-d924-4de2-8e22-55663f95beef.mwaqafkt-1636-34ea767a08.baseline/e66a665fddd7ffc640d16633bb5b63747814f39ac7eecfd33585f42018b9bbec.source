//! RTL_USER_PROCESS_PARAMETERS (CLAUDE.md, rule 5): what an i386 process
//! finds at `Peb->ProcessParameters`, laid out as on XP SP2 (0x290 bytes,
//! without the `EnvironmentSize` that later versions add). ReactOS's NDK
//! headers (`rtltypes.h`) serve as the specification of the format; offsets
//! are checked at compile time.
//!
//! The block is *normalized* when its string buffers are addresses, and
//! *denormalized* when they are offsets from the block's start, as the
//! creator writes it; ntdll normalizes it at process start if needed
//! (`RtlNormalizeProcessParams`). The environment is a separate block of
//! UTF-16 `NAME=value` strings, each terminated, ending with an empty one.

use core::mem::{offset_of, size_of};

use crate::peb32::UnicodeString32;

/// RTL_USER_PROCESS_PARAMETERS_NORMALIZED: the string buffers are
/// addresses.
pub const RTL_USER_PROCESS_PARAMETERS_NORMALIZED: u32 = 0x01;

/// RTL_MAX_DRIVE_LETTERS.
pub const RTL_MAX_DRIVE_LETTERS: usize = 32;

/// CURDIR: the current directory, as a DOS path ending with `\`, and its
/// handle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CurDir32 {
    pub dos_path: UnicodeString32,
    pub handle: u32,
}

/// RTL_DRIVE_LETTER_CURDIR: the current directory of a drive, kept for
/// child processes (the `=C:` variables).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtlDriveLetterCurDir32 {
    pub flags: u16,
    pub length: u16,
    pub time_stamp: u32,
    /// A STRING (ANSI), laid out as a UNICODE_STRING.
    pub dos_path: UnicodeString32,
}

/// The XP x86 RTL_USER_PROCESS_PARAMETERS.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtlUserProcessParameters32 {
    /// The size of the block, strings included.
    pub maximum_length: u32,
    pub length: u32,
    /// `RTL_USER_PROCESS_PARAMETERS_*`.
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: u32,
    pub console_flags: u32,
    pub standard_input: u32,
    pub standard_output: u32,
    pub standard_error: u32,
    pub current_directory: CurDir32,
    /// The directories searched for DLLs, separated by `;`.
    pub dll_path: UnicodeString32,
    pub image_path_name: UnicodeString32,
    pub command_line: UnicodeString32,
    /// The environment block's address.
    pub environment: u32,
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,
    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: UnicodeString32,
    pub desktop_info: UnicodeString32,
    pub shell_info: UnicodeString32,
    pub runtime_data: UnicodeString32,
    pub current_directories: [RtlDriveLetterCurDir32; RTL_MAX_DRIVE_LETTERS],
}

const _: () = {
    assert!(size_of::<CurDir32>() == 0x0C);
    assert!(size_of::<RtlDriveLetterCurDir32>() == 0x10);
    assert!(size_of::<RtlUserProcessParameters32>() == 0x290);
    assert!(offset_of!(RtlUserProcessParameters32, flags) == 0x08);
    assert!(offset_of!(RtlUserProcessParameters32, console_handle) == 0x10);
    assert!(offset_of!(RtlUserProcessParameters32, standard_input) == 0x18);
    assert!(offset_of!(RtlUserProcessParameters32, current_directory) == 0x24);
    assert!(offset_of!(RtlUserProcessParameters32, dll_path) == 0x30);
    assert!(offset_of!(RtlUserProcessParameters32, image_path_name) == 0x38);
    assert!(offset_of!(RtlUserProcessParameters32, command_line) == 0x40);
    assert!(offset_of!(RtlUserProcessParameters32, environment) == 0x48);
    assert!(offset_of!(RtlUserProcessParameters32, starting_x) == 0x4C);
    assert!(offset_of!(RtlUserProcessParameters32, show_window_flags) == 0x6C);
    assert!(offset_of!(RtlUserProcessParameters32, window_title) == 0x70);
    assert!(offset_of!(RtlUserProcessParameters32, desktop_info) == 0x78);
    assert!(offset_of!(RtlUserProcessParameters32, shell_info) == 0x80);
    assert!(offset_of!(RtlUserProcessParameters32, runtime_data) == 0x88);
    assert!(offset_of!(RtlUserProcessParameters32, current_directories) == 0x90);
};

impl RtlUserProcessParameters32 {
    /// A block with every field zero.
    pub fn zeroed() -> Self {
        // SAFETY: every field is an integer or a struct or array of
        // integers, for which all-zero bytes are a valid value.
        unsafe { core::mem::zeroed() }
    }

    /// Its bytes, as they go into the process.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: the struct has no implicit padding (every field is 4-byte
        // aligned and sized, or a pair of u16 before a u32; size checked
        // above) and only integer fields: every byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn its_bytes_are_its_fields_in_place() {
        let mut params = RtlUserProcessParameters32::zeroed();
        params.flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
        params.image_path_name = UnicodeString32 { length: 4, maximum_length: 6, buffer: 0x1234_5678 };
        let bytes = params.as_bytes();
        assert_eq!(bytes.len(), 0x290);
        assert_eq!(&bytes[0x08..0x0C], &[1, 0, 0, 0]);
        assert_eq!(&bytes[0x38..0x40], &[4, 0, 6, 0, 0x78, 0x56, 0x34, 0x12]);
    }
}
