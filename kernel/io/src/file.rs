//! File object — NT FILE_OBJECT.
//!
//! Created by NtCreateFile / NtOpenFile, referenced by a handle.
//! The file object is the per-open-instance state; the device below it
//! holds the actual data.

use alloc::string::String;
use ob::{ObjectHeader, ObjectType, KernelObject};

pub struct FileObject {
    pub header:        ObjectHeader,
    pub path:          String,
    pub current_offset: u64,
    pub flags:         u32,
}

impl KernelObject for FileObject {
    fn header(&self) -> &ObjectHeader { &self.header }
}

impl FileObject {
    pub fn new(path: &str, flags: u32) -> Self {
        Self {
            header: ObjectHeader { name: None, obj_type: ObjectType::File },
            path: path.into(),
            current_offset: 0,
            flags,
        }
    }
}
