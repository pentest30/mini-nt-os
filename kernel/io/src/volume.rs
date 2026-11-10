//! Mounted filesystem dispatch: writable FAT32 and read-only NTFS data volumes.
//! NTFS performs allocation and I/O at PASSIVE_LEVEL, without a volume spinlock.
pub use crate::fat_volume::{Listed, Node, SharedBlockDevice, Space, VolumeLabel};
use crate::{fat_volume::FatMount, ntfs_volume::NtfsMount};
use abi::{
    file::{FileBasicInformation, FileFsDeviceInformation},
    ntstatus::*,
};
use alloc::{string::String, vec::Vec};

/// A mounted FAT32 or read-only NTFS filesystem.
pub struct Volume(Backend);
enum Backend {
    Fat(FatMount),
    Ntfs(NtfsMount),
}

impl Volume {
    /// Mount a FAT32 device (legacy callers with no capacity information).
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn mount(device: SharedBlockDevice) -> Result<Self, NtStatus> {
        FatMount::mount(device).map(|v| Self(Backend::Fat(v)))
    }
    /// Identify and mount a capacity-bounded partition. An NTFS signature
    /// never falls back to FAT if its metadata is invalid or unsupported.
    /// # IRQL
    /// PASSIVE_LEVEL; allocates and performs I/O.
    pub fn mount_partition(device: SharedBlockDevice, sectors: u64) -> Result<Self, NtStatus> {
        if device.sector_size() != 512 || sectors == 0 {
            return Err(STATUS_UNRECOGNIZED_VOLUME);
        }
        let mut boot = [0; 512];
        device.read_sector(0, &mut boot).map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        if &boot[3..11] == b"NTFS    " {
            NtfsMount::mount(device, sectors).map(|v| Self(Backend::Ntfs(v)))
        } else {
            Self::mount(device)
        }
    }
    /// Replace the FAT clock for deterministic tests.
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        match self.0 {
            Backend::Fat(v) => Self(Backend::Fat(v.with_clock(clock))),
            other => Self(other),
        }
    }
    /// Whether all mutations are refused by this filesystem driver.
    pub fn is_read_only(&self) -> bool {
        matches!(self.0, Backend::Ntfs(_))
    }
    /// Filesystem name reported by FileFsAttributeInformation.
    pub fn filesystem_name(&self) -> &'static str {
        if self.is_read_only() {
            "NTFS"
        } else {
            "FAT32"
        }
    }
    /// Filesystem capability bits: preserved names, Unicode, and read-only volume.
    pub fn filesystem_attributes(&self) -> u32 {
        abi::file::FILE_CASE_PRESERVED_NAMES
            | abi::file::FILE_UNICODE_ON_DISK
            | if self.is_read_only() { abi::file::FILE_READ_ONLY_VOLUME } else { 0 }
        // FILE_READ_ONLY_VOLUME
    }
    /// The validated root directory.
    pub fn root(&self) -> Node {
        match &self.0 {
            Backend::Fat(v) => v.root(),
            Backend::Ntfs(v) => v.root(),
        }
    }
    /// Cluster size in bytes.
    pub fn cluster_bytes(&self) -> u32 {
        match &self.0 {
            Backend::Fat(v) => v.cluster_bytes(),
            Backend::Ntfs(v) => v.cluster_bytes(),
        }
    }
    /// Mounted disk characteristics, including FILE_READ_ONLY_DEVICE for NTFS.
    pub fn device_information(&self) -> FileFsDeviceInformation {
        match &self.0 {
            Backend::Fat(v) => v.device_information(),
            Backend::Ntfs(_) => FileFsDeviceInformation {
                device_type: abi::file::FILE_DEVICE_DISK,
                characteristics: abi::file::FILE_DEVICE_IS_MOUNTED | abi::file::FILE_READ_ONLY_DEVICE,
            },
        }
    }
    /// Volume serial number and label.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn label(&self) -> Result<VolumeLabel, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.label(),
            Backend::Ntfs(v) => v.label(),
        }
    }
    /// Total and free allocation units.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn space(&self) -> Result<Space, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.space(),
            Backend::Ntfs(v) => v.space(),
        }
    }
    /// Resolve a backslash-separated path relative to a directory.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn lookup(&self, from: &Node, path: &str) -> Result<Node, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.lookup(from, path),
            Backend::Ntfs(v) => v.lookup(from, path),
        }
    }
    /// Directory names (excluding dot entries).
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn list(&self, node: &Node) -> Result<Vec<String>, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.list(node),
            Backend::Ntfs(v) => Ok(v.entries(node)?.into_iter().map(|e| e.name).collect()),
        }
    }
    /// Entries for NtQueryDirectoryFile.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn entries(&self, node: &Node) -> Result<Vec<Listed>, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.entries(node),
            Backend::Ntfs(v) => v.entries(node),
        }
    }
    /// Revalidate a node's identity and metadata.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn current(&self, node: &Node) -> Result<Node, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.current(node),
            Backend::Ntfs(v) => v.current(node),
        }
    }
    /// Read file bytes, returning zero at EOF.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn read(&self, node: &Node, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.read(node, offset, out),
            Backend::Ntfs(v) => v.read(node, offset, out),
        }
    }
    /// Write FAT file bytes; NTFS always returns STATUS_MEDIA_WRITE_PROTECTED.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn write(&self, node: &Node, offset: u64, data: &[u8]) -> Result<Node, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.write(node, offset, data),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        }
    }
    /// Change FAT file length; NTFS is write protected.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_size(&self, node: &Node, size: u32) -> Result<Node, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.set_size(node, size),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        }
    }
    /// Change FAT metadata; NTFS is write protected.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_basic(&self, node: &Node, basic: &FileBasicInformation) -> Result<Node, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.set_basic(node, basic),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        }
    }
    /// Flush writable volumes. NTFS has no dirty data and performs no device operation.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn flush(&self) -> Result<(), NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.flush(),
            Backend::Ntfs(_) => Ok(()),
        }
    }
    /// Create a FAT entry; NTFS is write protected.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn create(&self, directory: &Node, name: &str, as_directory: bool, attributes: u32) -> Result<Node, NtStatus> {
        match &self.0 {
            Backend::Fat(v) => v.create(directory, name, as_directory, attributes),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        }
    }
}
