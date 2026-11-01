//! What the file services take and return to an i386 process (CLAUDE.md,
//! rule 5), laid out as on XP SP2: `IO_STATUS_BLOCK`, the values of
//! NtCreateFile and NtOpenFile, and the `FILE_*_INFORMATION` structures
//! that NtQueryInformationFile and NtQueryAttributesFile return. Values are
//! those of the XP SDK and DDK headers; offsets are checked at compile time.
//!
//! A `LARGE_INTEGER` is aligned to 8 bytes in these structures, in an i386
//! process as here: each one ends padded to a multiple of 8.

use core::mem::{offset_of, size_of};

/// IO_STATUS_BLOCK of an i386 process.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoStatusBlock32 {
    pub status: u32,
    pub information: u32,
}

/// The `Information` of an open (NtCreateFile, NtOpenFile).
pub const FILE_SUPERSEDED: u32 = 0;
pub const FILE_OPENED: u32 = 1;
pub const FILE_CREATED: u32 = 2;
pub const FILE_OVERWRITTEN: u32 = 3;
pub const FILE_EXISTS: u32 = 4;
pub const FILE_DOES_NOT_EXIST: u32 = 5;

/// Create dispositions (NtCreateFile).
pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;
pub const FILE_MAXIMUM_DISPOSITION: u32 = 5;

/// Create and open options.
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
pub const FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
pub const FILE_OPEN_BY_FILE_ID: u32 = 0x0000_2000;
/// The options a caller may give.
pub const FILE_VALID_OPTION_FLAGS: u32 = 0x00FF_FFFF;

/// The special byte offsets of NtReadFile and NtWriteFile, as LARGE_INTEGER.
/// FILE_WRITE_TO_END_OF_FILE: append.
pub const FILE_WRITE_TO_END_OF_FILE: i64 = -1;
/// FILE_USE_FILE_POINTER_POSITION: the current position.
pub const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

/// Share access.
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;
pub const FILE_SHARE_VALID_FLAGS: u32 = 0x0000_0007;

/// Specific access rights of files and directories.
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_LIST_DIRECTORY: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_ADD_FILE: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
pub const FILE_READ_EA: u32 = 0x0008;
pub const FILE_WRITE_EA: u32 = 0x0010;
pub const FILE_EXECUTE: u32 = 0x0020;
pub const FILE_TRAVERSE: u32 = 0x0020;
pub const FILE_DELETE_CHILD: u32 = 0x0040;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
/// FILE_ALL_ACCESS: the standard rights required, SYNCHRONIZE, 0x1FF.
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE.
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;

/// File attributes (`FILE_ATTRIBUTE_*`); the low six are those of FAT.
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0080;

/// `FILE_INFORMATION_CLASS`.
pub const FILE_BASIC_INFORMATION: u32 = 4;
pub const FILE_STANDARD_INFORMATION: u32 = 5;
pub const FILE_DISPOSITION_INFORMATION: u32 = 13;
pub const FILE_POSITION_INFORMATION: u32 = 14;
pub const FILE_END_OF_FILE_INFORMATION: u32 = 20;
pub const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;

/// `FS_INFORMATION_CLASS`, and FileFsMaximumInformation of XP.
pub const FILE_FS_DEVICE_INFORMATION: u32 = 4;
pub const FILE_FS_MAXIMUM_INFORMATION: u32 = 10;

/// Device types and characteristics (FILE_FS_DEVICE_INFORMATION).
pub const FILE_DEVICE_DISK: u32 = 0x0000_0007;
pub const FILE_REMOVABLE_MEDIA: u32 = 0x0000_0001;
pub const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;

/// FILE_FS_DEVICE_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsDeviceInformation {
    pub device_type: u32,
    pub characteristics: u32,
}

/// FILE_BASIC_INFORMATION. Times in 100 ns since 1601, 0 when unknown.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileBasicInformation {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub file_attributes: u32,
}

/// FILE_STANDARD_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStandardInformation {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
}

/// FILE_POSITION_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilePositionInformation {
    pub current_byte_offset: u64,
}

/// FILE_NETWORK_OPEN_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNetworkOpenInformation {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
}

/// Little-endian fields put at their offsets, the rest (padding) zero.
struct Encoder<const N: usize>([u8; N]);

impl<const N: usize> Encoder<N> {
    fn u64(mut self, at: usize, value: u64) -> Self {
        self.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
        self
    }
    fn u32(mut self, at: usize, value: u32) -> Self {
        self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
        self
    }
    fn u8(mut self, at: usize, value: u8) -> Self {
        self.0[at] = value;
        self
    }
}

impl IoStatusBlock32 {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()]).u32(0, self.status).u32(4, self.information).0
    }
}

impl FileFsDeviceInformation {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()]).u32(0, self.device_type).u32(4, self.characteristics).0
    }
}

impl FileBasicInformation {
    /// Its bytes, as they go to the caller, padding zeroed.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()])
            .u64(offset_of!(Self, creation_time), self.creation_time)
            .u64(offset_of!(Self, last_access_time), self.last_access_time)
            .u64(offset_of!(Self, last_write_time), self.last_write_time)
            .u64(offset_of!(Self, change_time), self.change_time)
            .u32(offset_of!(Self, file_attributes), self.file_attributes)
            .0
    }
}

impl FileStandardInformation {
    /// Its bytes, as they go to the caller, padding zeroed.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()])
            .u64(offset_of!(Self, allocation_size), self.allocation_size)
            .u64(offset_of!(Self, end_of_file), self.end_of_file)
            .u32(offset_of!(Self, number_of_links), self.number_of_links)
            .u8(offset_of!(Self, delete_pending), self.delete_pending)
            .u8(offset_of!(Self, directory), self.directory)
            .0
    }
}

impl FilePositionInformation {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()]).u64(0, self.current_byte_offset).0
    }
}

impl FileNetworkOpenInformation {
    /// Its bytes, as they go to the caller, padding zeroed.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()])
            .u64(offset_of!(Self, creation_time), self.creation_time)
            .u64(offset_of!(Self, last_access_time), self.last_access_time)
            .u64(offset_of!(Self, last_write_time), self.last_write_time)
            .u64(offset_of!(Self, change_time), self.change_time)
            .u64(offset_of!(Self, allocation_size), self.allocation_size)
            .u64(offset_of!(Self, end_of_file), self.end_of_file)
            .u32(offset_of!(Self, file_attributes), self.file_attributes)
            .0
    }
}

const _: () = {
    assert!(size_of::<IoStatusBlock32>() == 8);
    assert!(size_of::<FileFsDeviceInformation>() == 8);
    assert!(size_of::<FileBasicInformation>() == 40);
    assert!(offset_of!(FileBasicInformation, file_attributes) == 32);
    assert!(size_of::<FileStandardInformation>() == 24);
    assert!(offset_of!(FileStandardInformation, number_of_links) == 16);
    assert!(offset_of!(FileStandardInformation, directory) == 21);
    assert!(size_of::<FilePositionInformation>() == 8);
    assert!(size_of::<FileNetworkOpenInformation>() == 56);
    assert!(offset_of!(FileNetworkOpenInformation, allocation_size) == 32);
    assert!(offset_of!(FileNetworkOpenInformation, file_attributes) == 48);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_land_at_their_offsets_and_padding_is_zero() {
        let basic =
            FileBasicInformation { creation_time: 1, last_write_time: 3, file_attributes: 0x20, ..Default::default() };
        let bytes = basic.to_bytes();
        assert_eq!((bytes[0], bytes[16], bytes[32]), (1, 3, 0x20));
        assert!(bytes[36..].iter().all(|&b| b == 0));
        let standard =
            FileStandardInformation { end_of_file: 0x1234, number_of_links: 1, directory: 1, ..Default::default() };
        let bytes = standard.to_bytes();
        assert_eq!((&bytes[8..10], bytes[16], bytes[20], bytes[21]), (&[0x34, 0x12][..], 1, 0, 1));
        assert_eq!(&bytes[22..], &[0, 0]);
        let iosb = IoStatusBlock32 { status: 0xC000_0034, information: 1 }.to_bytes();
        assert_eq!(iosb, [0x34, 0, 0, 0xC0, 1, 0, 0, 0]);
    }
}
