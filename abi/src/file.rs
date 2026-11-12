//! What the file services take and return to an i386 process (CLAUDE.md,
//! rule 5), laid out as on XP SP2: `IO_STATUS_BLOCK`, the values of
//! NtCreateFile and NtOpenFile, the `FILE_*_INFORMATION` structures that
//! NtQueryInformationFile and NtQueryAttributesFile return, the entries of
//! NtQueryDirectoryFile ([`DirectoryEntry::encode`]) and the
//! `FILE_FS_*_INFORMATION` structures of NtQueryVolumeInformationFile.
//! Values are those of the XP SDK and DDK headers; offsets are checked at
//! compile time.
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
pub const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0100;

/// `FILE_INFORMATION_CLASS`.
pub const FILE_BASIC_INFORMATION: u32 = 4;
pub const FILE_STANDARD_INFORMATION: u32 = 5;
/// FileEaInformation: the size of the file's extended attributes.
pub const FILE_EA_INFORMATION: u32 = 7;
pub const FILE_DISPOSITION_INFORMATION: u32 = 13;
pub const FILE_POSITION_INFORMATION: u32 = 14;
pub const FILE_END_OF_FILE_INFORMATION: u32 = 20;
pub const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;
/// FileNameInformation: the path of the file from the root of its volume.
pub const FILE_NAME_INFORMATION: u32 = 9;

/// The classes of NtQueryDirectoryFile (`FILE_INFORMATION_CLASS`).
pub const FILE_DIRECTORY_INFORMATION: u32 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
pub const FILE_NAMES_INFORMATION: u32 = 12;
pub const FILE_OBJECT_ID_INFORMATION: u32 = 29;
pub const FILE_REPARSE_POINT_INFORMATION: u32 = 33;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u32 = 37;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u32 = 38;

/// The entries NtQueryDirectoryFile returns each begin at a multiple of
/// this, from the start of the buffer (their `NextEntryOffset`).
pub const DIRECTORY_ENTRY_ALIGNMENT: usize = 8;

/// `FS_INFORMATION_CLASS`, and FileFsMaximumInformation of XP.
pub const FILE_FS_VOLUME_INFORMATION: u32 = 1;
pub const FILE_FS_SIZE_INFORMATION: u32 = 3;
pub const FILE_FS_DEVICE_INFORMATION: u32 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;
pub const FILE_FS_MAXIMUM_INFORMATION: u32 = 10;

/// `FileSystemAttributes` (FILE_FS_ATTRIBUTE_INFORMATION).
pub const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
pub const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
pub const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
/// The mounted filesystem refuses all mutations.
pub const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;

/// Device types and characteristics (FILE_FS_DEVICE_INFORMATION).
pub const FILE_DEVICE_DISK: u32 = 0x0000_0007;
pub const FILE_REMOVABLE_MEDIA: u32 = 0x0000_0001;
pub const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;
/// The filesystem device is read-only.
pub const FILE_READ_ONLY_DEVICE: u32 = 0x0000_0002;

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

/// FILE_EA_INFORMATION: the size of the extended attributes, as a
/// FILE_FULL_EA_INFORMATION list would hold them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileEaInformation {
    pub ea_size: u32,
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

/// FILE_DIRECTORY_INFORMATION (NtQueryDirectoryFile), as in C: its name
/// begins at `file_name`, `file_name_length` bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileDirectoryInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub file_name: [u16; 1],
}

/// FILE_FULL_DIR_INFORMATION: the same, with the size of the extended
/// attributes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFullDirInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub ea_size: u32,
    pub file_name: [u16; 1],
}

/// FILE_BOTH_DIR_INFORMATION: the same, with the 8.3 name (`ShortName`,
/// 12 characters at most, `short_name_length` bytes; none for a name that
/// already is one).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileBothDirInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name_length: u32,
    pub ea_size: u32,
    pub short_name_length: u8,
    pub short_name: [u16; 12],
    pub file_name: [u16; 1],
}

/// FILE_NAMES_INFORMATION: the name alone.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNamesInformation {
    pub next_entry_offset: u32,
    pub file_index: u32,
    pub file_name_length: u32,
    pub file_name: [u16; 1],
}

/// What an entry of NtQueryDirectoryFile says of a file, whatever its
/// class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectoryEntry<'a> {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub name: &'a [u16],
    /// Its 8.3 name, if it has one apart from `name` (12 units at most).
    pub short_name: &'a [u16],
}

/// For the class `class` of NtQueryDirectoryFile: where the name of an
/// entry begins, and the size of its structure in C (the least buffer the
/// I/O manager takes); `None` for another class, or one of the ID classes
/// (no file IDs here).
pub const fn directory_entry_layout(class: u32) -> Option<(usize, usize)> {
    match class {
        FILE_DIRECTORY_INFORMATION => {
            Some((offset_of!(FileDirectoryInformation, file_name), size_of::<FileDirectoryInformation>()))
        }
        FILE_FULL_DIRECTORY_INFORMATION => {
            Some((offset_of!(FileFullDirInformation, file_name), size_of::<FileFullDirInformation>()))
        }
        FILE_BOTH_DIRECTORY_INFORMATION => {
            Some((offset_of!(FileBothDirInformation, file_name), size_of::<FileBothDirInformation>()))
        }
        FILE_NAMES_INFORMATION => {
            Some((offset_of!(FileNamesInformation, file_name), size_of::<FileNamesInformation>()))
        }
        _ => None,
    }
}

impl DirectoryEntry<'_> {
    /// Writes the entry of the class `class` at the start of `out`,
    /// `NextEntryOffset` 0, its name cut to what `out` holds after the
    /// fixed part (`FileNameLength` says what was written); returns the
    /// bytes written. `None` for a class [`directory_entry_layout`] does not
    /// know, or an `out` shorter than the fixed part.
    pub fn encode(&self, class: u32, out: &mut [u8]) -> Option<usize> {
        let (name_at, _) = directory_entry_layout(class)?;
        if out.len() < name_at {
            return None;
        }
        let name_bytes = (self.name.len() * 2).min((out.len() - name_at) & !1);
        out[..name_at].fill(0);
        let put32 = |out: &mut [u8], at: usize, value: u32| out[at..at + 4].copy_from_slice(&value.to_le_bytes());
        let put64 = |out: &mut [u8], at: usize, value: u64| out[at..at + 8].copy_from_slice(&value.to_le_bytes());
        // The fields every class has, at the same offsets.
        put32(out, offset_of!(FileDirectoryInformation, file_index), self.file_index);
        if class == FILE_NAMES_INFORMATION {
            put32(out, offset_of!(FileNamesInformation, file_name_length), name_bytes as u32);
        } else {
            put64(out, offset_of!(FileDirectoryInformation, creation_time), self.creation_time);
            put64(out, offset_of!(FileDirectoryInformation, last_access_time), self.last_access_time);
            put64(out, offset_of!(FileDirectoryInformation, last_write_time), self.last_write_time);
            put64(out, offset_of!(FileDirectoryInformation, change_time), self.change_time);
            put64(out, offset_of!(FileDirectoryInformation, end_of_file), self.end_of_file);
            put64(out, offset_of!(FileDirectoryInformation, allocation_size), self.allocation_size);
            put32(out, offset_of!(FileDirectoryInformation, file_attributes), self.file_attributes);
            put32(out, offset_of!(FileDirectoryInformation, file_name_length), name_bytes as u32);
        }
        if class == FILE_BOTH_DIRECTORY_INFORMATION {
            let short = &self.short_name[..self.short_name.len().min(12)];
            out[offset_of!(FileBothDirInformation, short_name_length)] = (short.len() * 2) as u8;
            let at = offset_of!(FileBothDirInformation, short_name);
            for (i, unit) in short.iter().enumerate() {
                out[at + 2 * i..at + 2 * i + 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        for (i, unit) in self.name.iter().take(name_bytes / 2).enumerate() {
            out[name_at + 2 * i..name_at + 2 * i + 2].copy_from_slice(&unit.to_le_bytes());
        }
        Some(name_at + name_bytes)
    }
}

/// FILE_NAME_INFORMATION, as in C: the name begins at `file_name`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNameInformation {
    pub file_name_length: u32,
    pub file_name: [u16; 1],
}

/// FILE_FS_VOLUME_INFORMATION, as in C: the label begins at `volume_label`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsVolumeInformation {
    pub volume_creation_time: u64,
    pub volume_serial_number: u32,
    pub volume_label_length: u32,
    pub supports_objects: u8,
    pub volume_label: [u16; 1],
}

/// FILE_FS_SIZE_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsSizeInformation {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// FILE_FS_FULL_SIZE_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsFullSizeInformation {
    pub total_allocation_units: u64,
    pub caller_available_allocation_units: u64,
    pub actual_available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// FILE_FS_ATTRIBUTE_INFORMATION, as in C: the name of the file system
/// begins at `file_system_name`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFsAttributeInformation {
    pub file_system_attributes: u32,
    pub maximum_component_name_length: u32,
    pub file_system_name_length: u32,
    pub file_system_name: [u16; 1],
}

/// Writes `name` at `name_at` in `out`, as much of it as `out` holds
/// (whole units); returns the bytes written up to its end, and whether it
/// was cut (`STATUS_BUFFER_OVERFLOW`). `None` if `out` ends before
/// `name_at`.
fn put_name(out: &mut [u8], name_at: usize, name: &[u16]) -> Option<(usize, bool)> {
    let room = out.len().checked_sub(name_at)? / 2;
    let kept = name.len().min(room);
    for (i, unit) in name[..kept].iter().enumerate() {
        out[name_at + 2 * i..name_at + 2 * i + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Some((name_at + 2 * kept, kept < name.len()))
}

impl FileNameInformation {
    /// The structure for the name `name` in `out` (`FileNameLength`: the
    /// whole name, in bytes), the name cut to what `out` holds: the bytes
    /// written and whether the name was cut. `None` for an `out` shorter
    /// than the length field.
    pub fn encode(name: &[u16], out: &mut [u8]) -> Option<(usize, bool)> {
        let at = offset_of!(Self, file_name);
        out.get_mut(..at)?.copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        put_name(out, at, name)
    }
}

impl FileFsVolumeInformation {
    /// This structure with the label `label` in `out` (`VolumeLabelLength`:
    /// the whole label), cut to what `out` holds: the bytes written and
    /// whether the label was cut. `None` for an `out` shorter than the
    /// fixed part.
    pub fn encode(&self, label: &[u16], out: &mut [u8]) -> Option<(usize, bool)> {
        let at = offset_of!(Self, volume_label);
        let fixed = out.get_mut(..at)?;
        fixed.fill(0);
        fixed[0..8].copy_from_slice(&self.volume_creation_time.to_le_bytes());
        fixed[8..12].copy_from_slice(&self.volume_serial_number.to_le_bytes());
        fixed[12..16].copy_from_slice(&((label.len() * 2) as u32).to_le_bytes());
        fixed[16] = self.supports_objects;
        put_name(out, at, label)
    }
}

impl FileFsAttributeInformation {
    /// This structure with the name `name` in `out` (`FileSystemNameLength`:
    /// the whole name), cut to what `out` holds: the bytes written and
    /// whether the name was cut. `None` for an `out` shorter than the fixed
    /// part.
    pub fn encode(&self, name: &[u16], out: &mut [u8]) -> Option<(usize, bool)> {
        let at = offset_of!(Self, file_system_name);
        let fixed = out.get_mut(..at)?;
        fixed[0..4].copy_from_slice(&self.file_system_attributes.to_le_bytes());
        fixed[4..8].copy_from_slice(&self.maximum_component_name_length.to_le_bytes());
        fixed[8..12].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
        put_name(out, at, name)
    }
}

impl FileFsSizeInformation {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()])
            .u64(offset_of!(Self, total_allocation_units), self.total_allocation_units)
            .u64(offset_of!(Self, available_allocation_units), self.available_allocation_units)
            .u32(offset_of!(Self, sectors_per_allocation_unit), self.sectors_per_allocation_unit)
            .u32(offset_of!(Self, bytes_per_sector), self.bytes_per_sector)
            .0
    }
}

impl FileFsFullSizeInformation {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()])
            .u64(offset_of!(Self, total_allocation_units), self.total_allocation_units)
            .u64(offset_of!(Self, caller_available_allocation_units), self.caller_available_allocation_units)
            .u64(offset_of!(Self, actual_available_allocation_units), self.actual_available_allocation_units)
            .u32(offset_of!(Self, sectors_per_allocation_unit), self.sectors_per_allocation_unit)
            .u32(offset_of!(Self, bytes_per_sector), self.bytes_per_sector)
            .0
    }
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
    /// The structure in `bytes`, as a caller gives it (NtSetInformationFile).
    pub fn from_bytes(bytes: &[u8; size_of::<Self>()]) -> Self {
        let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        Self {
            creation_time: long(offset_of!(Self, creation_time)),
            last_access_time: long(offset_of!(Self, last_access_time)),
            last_write_time: long(offset_of!(Self, last_write_time)),
            change_time: long(offset_of!(Self, change_time)),
            file_attributes: u32::from_le_bytes(
                bytes[offset_of!(Self, file_attributes)..offset_of!(Self, file_attributes) + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            ),
        }
    }

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

impl FileEaInformation {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        Encoder([0; size_of::<Self>()]).u32(0, self.ea_size).0
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
    assert!(size_of::<FileEaInformation>() == 4);
    assert!(size_of::<FileNetworkOpenInformation>() == 56);
    assert!(offset_of!(FileNetworkOpenInformation, allocation_size) == 32);
    assert!(offset_of!(FileNetworkOpenInformation, file_attributes) == 48);
    assert!(size_of::<FileDirectoryInformation>() == 72);
    assert!(offset_of!(FileDirectoryInformation, creation_time) == 8);
    assert!(offset_of!(FileDirectoryInformation, end_of_file) == 40);
    assert!(offset_of!(FileDirectoryInformation, file_attributes) == 56);
    assert!(offset_of!(FileDirectoryInformation, file_name) == 64);
    assert!(size_of::<FileFullDirInformation>() == 72);
    assert!(offset_of!(FileFullDirInformation, ea_size) == 64);
    assert!(offset_of!(FileFullDirInformation, file_name) == 68);
    assert!(size_of::<FileBothDirInformation>() == 96);
    assert!(offset_of!(FileBothDirInformation, short_name_length) == 68);
    assert!(offset_of!(FileBothDirInformation, short_name) == 70);
    assert!(offset_of!(FileBothDirInformation, file_name) == 94);
    assert!(size_of::<FileNamesInformation>() == 16);
    assert!(offset_of!(FileNamesInformation, file_name_length) == 8);
    assert!(offset_of!(FileNamesInformation, file_name) == 12);
    // The fields common to the classes, at the same offsets.
    assert!(offset_of!(FileFullDirInformation, file_name_length) == 60);
    assert!(offset_of!(FileBothDirInformation, file_name_length) == 60);
    assert!(offset_of!(FileBothDirInformation, allocation_size) == 48);
    assert!(size_of::<FileNameInformation>() == 8);
    assert!(offset_of!(FileNameInformation, file_name) == 4);
    assert!(size_of::<FileFsVolumeInformation>() == 24);
    assert!(offset_of!(FileFsVolumeInformation, volume_serial_number) == 8);
    assert!(offset_of!(FileFsVolumeInformation, supports_objects) == 16);
    assert!(offset_of!(FileFsVolumeInformation, volume_label) == 18);
    assert!(size_of::<FileFsSizeInformation>() == 24);
    assert!(offset_of!(FileFsSizeInformation, sectors_per_allocation_unit) == 16);
    assert!(size_of::<FileFsFullSizeInformation>() == 32);
    assert!(offset_of!(FileFsFullSizeInformation, sectors_per_allocation_unit) == 24);
    assert!(size_of::<FileFsAttributeInformation>() == 16);
    assert!(offset_of!(FileFsAttributeInformation, file_system_name) == 12);
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
        let back = FileBasicInformation::from_bytes(&basic.to_bytes());
        assert_eq!(back, basic, "read back as a caller gives it");
    }

    /// `text` (ASCII) in UTF-16, in `out`.
    fn units<const N: usize>(text: &str) -> [u16; N] {
        let mut out = [0u16; N];
        for (unit, byte) in out.iter_mut().zip(text.bytes()) {
            *unit = u16::from(byte);
        }
        out
    }

    #[test]
    fn a_directory_entry_lands_where_its_class_puts_it() {
        let (name, short) = (units::<18>("advapi32_vista.dll"), units::<12>("ADVAPI~1.DLL"));
        let entry = DirectoryEntry {
            file_index: 0x40,
            creation_time: 1,
            last_write_time: 3,
            end_of_file: 0x1234,
            allocation_size: 0x1000,
            file_attributes: FILE_ATTRIBUTE_ARCHIVE,
            name: &name,
            short_name: &short,
            ..Default::default()
        };
        let mut out = [0xAAu8; 160];
        assert_eq!(entry.encode(FILE_BOTH_DIRECTORY_INFORMATION, &mut out), Some(94 + 36));
        assert_eq!(&out[0..8], &[0, 0, 0, 0, 0x40, 0, 0, 0], "NextEntryOffset 0, FileIndex");
        assert_eq!((out[8], out[24], &out[40..42], out[49], out[56]), (1, 3, &[0x34, 0x12][..], 0x10, 0x20));
        assert_eq!((out[60], out[64], out[68]), (36, 0, 24), "FileNameLength, EaSize, ShortNameLength");
        assert_eq!((out[70], out[71], out[92]), (b'A', 0, b'L'), "ShortName");
        assert_eq!((out[94], out[95], out[128]), (b'a', 0, b'l'), "FileName");
        assert_eq!(out[130], 0xAA, "nothing past the entry");

        // The name alone; then cut to what the buffer holds.
        let mut names = [0u8; 40];
        assert_eq!(entry.encode(FILE_NAMES_INFORMATION, &mut names), Some(12 + 36 - 8));
        assert_eq!((names[4], names[8], names[12]), (0x40, 28, b'a'), "the name cut to 14 units");
        assert_eq!(entry.encode(FILE_DIRECTORY_INFORMATION, &mut [0u8; 63]), None, "shorter than the fixed part");
        assert_eq!(entry.encode(FILE_ID_BOTH_DIRECTORY_INFORMATION, &mut out), None);
        let mut odd = [0u8; 64 + 5];
        assert_eq!(entry.encode(FILE_DIRECTORY_INFORMATION, &mut odd), Some(64 + 4), "whole units only");
        assert_eq!(odd[60], 4);
    }

    #[test]
    fn names_follow_their_structure_and_say_their_whole_length() {
        let name = units::<9>("\\WINDOWS\\");
        let mut out = [0xAAu8; 32];
        assert_eq!(FileNameInformation::encode(&name, &mut out), Some((4 + 18, false)));
        assert_eq!((out[0], out[4], out[6], out[22]), (18, b'\\', b'W', 0xAA));
        // Cut: the length still says the whole name.
        assert_eq!(FileNameInformation::encode(&name, &mut out[..9]), Some((8, true)));
        assert_eq!(out[0], 18);
        assert_eq!(FileNameInformation::encode(&name, &mut out[..3]), None);

        let volume = FileFsVolumeInformation { volume_serial_number: 0x4D49_4E4F, ..Default::default() };
        let label = units::<4>("MINO");
        let mut out = [0xAAu8; 40];
        assert_eq!(volume.encode(&label, &mut out), Some((18 + 8, false)));
        assert_eq!(
            (&out[8..12], out[12], out[16], out[18], out[24]),
            (&[0x4F, 0x4E, 0x49, 0x4D][..], 8, 0, b'M', b'O')
        );
        assert_eq!(volume.encode(&[], &mut out[..24]), Some((18, false)), "no label");
        assert_eq!(volume.encode(&label, &mut out[..17]), None);

        let attributes = FileFsAttributeInformation {
            file_system_attributes: FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK,
            maximum_component_name_length: 255,
            ..Default::default()
        };
        let fat32 = units::<5>("FAT32");
        assert_eq!(attributes.encode(&fat32, &mut out), Some((12 + 10, false)));
        assert_eq!((out[0], out[4], out[8], out[12], out[20]), (6, 255, 10, b'F', b'2'));
        assert_eq!(attributes.encode(&fat32, &mut out[..16]), Some((16, true)));

        let size = FileFsFullSizeInformation {
            total_allocation_units: 0x1_0000_0002,
            caller_available_allocation_units: 7,
            actual_available_allocation_units: 7,
            sectors_per_allocation_unit: 8,
            bytes_per_sector: 512,
        }
        .to_bytes();
        assert_eq!((size[0], size[4], size[8], size[16], size[24], &size[28..30]), (2, 1, 7, 7, 8, &[0, 2][..]));
        let small =
            FileFsSizeInformation { available_allocation_units: 3, bytes_per_sector: 512, ..Default::default() };
        assert_eq!((small.to_bytes()[8], small.to_bytes()[21]), (3, 2));
    }
}
