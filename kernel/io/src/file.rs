//! File object — NT FILE_OBJECT.
//!
//! Created by NtCreateFile / NtOpenFile, referenced by a handle.
//! The file object is the per-open-instance state; the device below it
//! holds the actual data.

use alloc::string::String;
use ob::{AccessMask, ObjectType};

/// FILE_ALL_ACCESS.
pub const FILE_ALL_ACCESS: AccessMask = AccessMask(0x001F_01FF);

/// The `File` type: the generic rights of the XP SDK (FILE_GENERIC_*).
pub static FILE_TYPE: ObjectType = ObjectType::new(
    "File",
    FILE_ALL_ACCESS,
    ob::GenericMapping {
        read: AccessMask(0x0012_0089),
        write: AccessMask(0x0012_0116),
        execute: AccessMask(0x0012_00A0),
        all: FILE_ALL_ACCESS,
    },
);

pub struct FileObject {
    pub path: String,
    pub current_offset: u64,
    pub flags: u32,
}

impl FileObject {
    pub fn new(path: &str, flags: u32) -> Self {
        Self { path: path.into(), current_offset: 0, flags }
    }
}
