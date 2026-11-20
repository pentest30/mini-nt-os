//! Mounted filesystem dispatch: writable FAT32 and read-only NTFS data volumes.
//! NTFS performs allocation and I/O at PASSIVE_LEVEL, without a volume spinlock.
//!
//! A volume also keeps what the FCB of an open file keeps of its opens
//! ([`Volume::begin_open`], [`Volume::cleanup`]): how many file objects on it
//! still have a handle (OpenHandleCount), and whether its deletion is
//! pending (FileDispositionInformation, FILE_DELETE_ON_CLOSE). The file is
//! deleted when the last of them closes its last handle, as vfatfs does at
//! IRP_MJ_CLEANUP; an open of a file whose deletion is pending fails with
//! `STATUS_DELETE_PENDING`. File objects the kernel opens for itself, without
//! a handle, do not count.
//!
//! A lock that can wait (`fcb`, a KGUARDED_MUTEX, as the FCB resource of a
//! file system driver) puts in order the opens, each checked and counted at
//! once, and the last cleanups, each with its deletion: an open looked up
//! before a deletion finds its entry gone, and fails. The deletion writes
//! the volume under it, never under the spinlock of the table (`opened`),
//! which only keeps the counts.
//!
//! The FCB also keeps the byte-range locks of each file (its FILE_LOCK,
//! [`crate::file_lock`]): [`Volume::lock`], [`Volume::unlock`],
//! [`Volume::unlock_all`] at the last close of a file object, and the checks
//! of reads and writes ([`Volume::check_read`], [`Volume::check_write`]).
pub use crate::fat_volume::{Listed, Node, SharedBlockDevice, Space, VolumeLabel};
use crate::file_lock::{FileLocks, LockOwner};
use crate::{fat_volume::FatMount, ntfs_volume::NtfsMount};
use abi::{
    file::{FileBasicInformation, FileFsDeviceInformation},
    ntstatus::*,
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use hal::sync::KSpinLock;
use ke::KGuardedMutex;

/// A mounted FAT32 or read-only NTFS filesystem.
pub struct Volume {
    backend: Backend,
    /// Puts in order the opens and the last cleanups (see the module).
    fcb: KGuardedMutex<()>,
    /// What the FCB of each open file keeps, by its identity on the volume.
    opened: KSpinLock<BTreeMap<u64, Opened>>,
    /// The byte-range locks of each file that has some, by its identity.
    locks: KSpinLock<BTreeMap<u64, FileLocks>>,
}

/// The opens of a file (its FCB).
#[derive(Clone, Copy, Debug, Default)]
struct Opened {
    /// The file objects on it that still have a handle (OpenHandleCount).
    handles: u32,
    /// FCB_DELETE_PENDING: the file goes with the last of them.
    delete_pending: bool,
}

impl Volume {
    fn new(backend: Backend) -> Self {
        Self {
            backend,
            fcb: KGuardedMutex::new(()),
            opened: KSpinLock::new(BTreeMap::new()),
            locks: KSpinLock::new(BTreeMap::new()),
        }
    }

    /// The content of `node` changes: before the change, and after it (even
    /// a write that failed halfway), the sections no longer share what was
    /// read of it (`crate::section_cache`); what a section read while it
    /// changed is not kept.
    fn changed(&self, node: &Node) {
        crate::section_cache::CACHE.invalidate(self.cache_id(), node.identity());
    }

    /// What designates this volume in `crate::section_cache`: its address.
    pub(crate) fn cache_id(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }
}
enum Backend {
    Fat(FatMount),
    Ntfs(NtfsMount),
}

impl Volume {
    /// Mount a FAT32 device (legacy callers with no capacity information).
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn mount(device: SharedBlockDevice) -> Result<Self, NtStatus> {
        FatMount::mount(device).map(|v| Self::new(Backend::Fat(v)))
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
            NtfsMount::mount(device, sectors).map(|v| Self::new(Backend::Ntfs(v)))
        } else {
            Self::mount(device)
        }
    }
    /// Replace the FAT clock for deterministic tests.
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        let backend = match self.backend {
            Backend::Fat(v) => Backend::Fat(v.with_clock(clock)),
            other => other,
        };
        Self { backend, fcb: self.fcb, opened: self.opened, locks: self.locks }
    }
    /// Whether all mutations are refused by this filesystem driver.
    pub fn is_read_only(&self) -> bool {
        matches!(self.backend, Backend::Ntfs(_))
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
        match &self.backend {
            Backend::Fat(v) => v.root(),
            Backend::Ntfs(v) => v.root(),
        }
    }
    /// Cluster size in bytes.
    pub fn cluster_bytes(&self) -> u32 {
        match &self.backend {
            Backend::Fat(v) => v.cluster_bytes(),
            Backend::Ntfs(v) => v.cluster_bytes(),
        }
    }
    /// Mounted disk characteristics, including FILE_READ_ONLY_DEVICE for NTFS.
    pub fn device_information(&self) -> FileFsDeviceInformation {
        match &self.backend {
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
        match &self.backend {
            Backend::Fat(v) => v.label(),
            Backend::Ntfs(v) => v.label(),
        }
    }
    /// Total and free allocation units.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn space(&self) -> Result<Space, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.space(),
            Backend::Ntfs(v) => v.space(),
        }
    }
    /// Resolve a backslash-separated path relative to a directory.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn lookup(&self, from: &Node, path: &str) -> Result<Node, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.lookup(from, path),
            Backend::Ntfs(v) => v.lookup(from, path),
        }
    }
    /// UTF-8 convenience listing (excluding dot entries). For arbitrary UTF-16
    /// names use `entries`; unrepresentable names are never converted lossily.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn list(&self, node: &Node) -> Result<Vec<String>, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.list(node),
            Backend::Ntfs(v) => v
                .entries(node)?
                .into_iter()
                .map(|e| String::from_utf16(&e.name).map_err(|_| STATUS_OBJECT_NAME_INVALID))
                .collect(),
        }
    }
    /// Entries for NtQueryDirectoryFile.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn entries(&self, node: &Node) -> Result<Vec<Listed>, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.entries(node),
            Backend::Ntfs(v) => v.entries(node),
        }
    }
    /// Revalidate a node's identity and metadata.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn current(&self, node: &Node) -> Result<Node, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.current(node),
            Backend::Ntfs(v) => v.current(node),
        }
    }
    /// Read file bytes, returning zero at EOF.
    /// # IRQL
    /// PASSIVE_LEVEL; may allocate and read the device.
    pub fn read(&self, node: &Node, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.read(node, offset, out),
            Backend::Ntfs(v) => v.read(node, offset, out),
        }
    }
    /// Write FAT file bytes; NTFS always returns STATUS_MEDIA_WRITE_PROTECTED.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn write(&self, node: &Node, offset: u64, data: &[u8]) -> Result<Node, NtStatus> {
        self.changed(node);
        let written = match &self.backend {
            Backend::Fat(v) => v.write(node, offset, data),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        };
        self.changed(node);
        written
    }
    /// Change FAT file length; NTFS is write protected.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_size(&self, node: &Node, size: u32) -> Result<Node, NtStatus> {
        self.changed(node);
        let resized = match &self.backend {
            Backend::Fat(v) => v.set_size(node, size),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        };
        self.changed(node);
        resized
    }
    /// Change FAT metadata; NTFS is write protected.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_basic(&self, node: &Node, basic: &FileBasicInformation) -> Result<Node, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.set_basic(node, basic),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        }
    }
    /// Flush writable volumes. NTFS has no dirty data and performs no device operation.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn flush(&self) -> Result<(), NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.flush(),
            Backend::Ntfs(_) => Ok(()),
        }
    }
    /// The lazy writer's pass (`crate::lazy_writer`): flushes what a flush
    /// would write, if anything waits; returns whether something did. NTFS
    /// has nothing waiting.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn write_behind(&self) -> Result<bool, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.write_behind(),
            Backend::Ntfs(_) => Ok(false),
        }
    }
    /// What was written has not all reached the medium (see
    /// [`write_behind`](Self::write_behind)).
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_dirty(&self) -> bool {
        match &self.backend {
            Backend::Fat(v) => v.is_dirty(),
            Backend::Ntfs(_) => false,
        }
    }
    /// Create a FAT entry; NTFS is write protected.
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn create(&self, directory: &Node, name: &str, as_directory: bool, attributes: u32) -> Result<Node, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.create(directory, name, as_directory, attributes),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        }
    }
}

impl Volume {
    /// An open of `node` (NtCreateFile, NtOpenFile), before its file object
    /// gets a handle: under the FCB lock, the entry found by the lookup must
    /// still name the file (`STATUS_OBJECT_NAME_NOT_FOUND` if the last close
    /// of an earlier open deleted it since), its deletion must not be
    /// pending (`STATUS_DELETE_PENDING`), and the open then counts until
    /// [`Volume::cleanup`].
    ///
    /// # IRQL
    /// PASSIVE_LEVEL; may read the device.
    pub fn begin_open(&self, node: &Node) -> Result<(), NtStatus> {
        let _fcb = self.fcb.lock();
        if !self.still_exists(node)? {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let Some(identity) = node.identity() else { return Ok(()) };
        let mut opened = self.opened.lock();
        let opens = opened.entry(identity).or_default();
        if opens.delete_pending {
            if opens.handles == 0 {
                opened.remove(&identity);
            }
            return Err(STATUS_DELETE_PENDING);
        }
        opens.handles += 1;
        Ok(())
    }

    /// The entry of `node` still names it (FAT: neither deleted nor taken
    /// by another name; NTFS, read-only: always).
    /// # IRQL
    /// PASSIVE_LEVEL; may read the device.
    pub fn still_exists(&self, node: &Node) -> Result<bool, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.still_names(node),
            Backend::Ntfs(_) => Ok(true),
        }
    }

    /// The deletion of `node` is pending.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn delete_pending(&self, node: &Node) -> bool {
        node.identity().is_some_and(|identity| self.opened.lock().get(&identity).is_some_and(|o| o.delete_pending))
    }

    /// NtSetInformationFile(FileDispositionInformation): with `delete`, the
    /// deletion of `node` becomes pending, else it is called off. As
    /// VfatSetDispositionInformation: `STATUS_ACCESS_DENIED` for the root,
    /// `STATUS_CANNOT_DELETE` for a read-only file,
    /// `STATUS_DIRECTORY_NOT_EMPTY` for a directory that holds something,
    /// `STATUS_MEDIA_WRITE_PROTECTED` on NTFS; a deletion already pending
    /// is not checked again.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL; may read the device.
    pub fn set_delete_pending(&self, node: &Node, delete: bool) -> Result<(), NtStatus> {
        let Some(identity) = node.identity() else {
            return if delete { Err(STATUS_ACCESS_DENIED) } else { Ok(()) };
        };
        let _fcb = self.fcb.lock();
        if delete && !self.delete_pending(node) {
            if self.is_read_only() {
                return Err(STATUS_MEDIA_WRITE_PROTECTED);
            }
            let current = self.current(node)?;
            if current.attributes & abi::file::FILE_ATTRIBUTE_READONLY != 0 {
                return Err(STATUS_CANNOT_DELETE);
            }
            if current.directory && !self.is_empty_directory(&current)? {
                return Err(STATUS_DIRECTORY_NOT_EMPTY);
            }
        }
        let mut opened = self.opened.lock();
        match opened.get_mut(&identity) {
            Some(opens) => opens.delete_pending = delete,
            None if delete => {
                opened.insert(identity, Opened { handles: 0, delete_pending: true });
            }
            None => {}
        }
        Ok(())
    }

    /// The last handle of a file object on `node` is closed
    /// (IRP_MJ_CLEANUP), or an open counted by [`Volume::begin_open`] fails
    /// before its handle: with `delete_on_close` (FILE_DELETE_ON_CLOSE), the
    /// deletion of the file becomes pending; with the last of its file
    /// objects, a pending deletion is done. A directory that holds something
    /// then stays, as with vfatfs (`STATUS_DIRECTORY_NOT_EMPTY`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL; may write the device.
    pub fn cleanup(&self, node: &Node, delete_on_close: bool) -> Result<(), NtStatus> {
        let Some(identity) = node.identity() else { return Ok(()) };
        // Under the FCB lock, so that no open counts itself between the last
        // close and the deletion; the spinlock only while the counts change.
        let _fcb = self.fcb.lock();
        let delete = {
            let mut opened = self.opened.lock();
            let Some(opens) = opened.get_mut(&identity) else { return Ok(()) };
            opens.handles = opens.handles.saturating_sub(1);
            opens.delete_pending |= delete_on_close;
            if opens.handles > 0 {
                return Ok(());
            }
            let delete = opens.delete_pending;
            opened.remove(&identity);
            delete
        };
        if !delete {
            return Ok(());
        }
        self.changed(node);
        match &self.backend {
            Backend::Fat(v) => v.delete(node),
            Backend::Ntfs(_) => Err(STATUS_MEDIA_WRITE_PROTECTED),
        }
    }

    /// The directory `node` holds nothing (`.` and `..` alone).
    /// # IRQL
    /// PASSIVE_LEVEL; may read the device.
    pub fn is_empty_directory(&self, node: &Node) -> Result<bool, NtStatus> {
        match &self.backend {
            Backend::Fat(v) => v.is_empty_directory(node),
            Backend::Ntfs(_) => Ok(false),
        }
    }
}

impl Volume {
    /// NtLockFile on `node`: see [`FileLocks::lock`]. The root has no
    /// identity and no locks (`STATUS_INVALID_DEVICE_REQUEST`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL; allocates from the non-paged pool.
    pub fn lock(
        &self,
        node: &Node,
        offset: u64,
        length: u64,
        exclusive: bool,
        owner: LockOwner,
    ) -> Result<(), NtStatus> {
        let identity = node.identity().ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        self.locks.lock().entry(identity).or_default().lock(offset, length, exclusive, owner)
    }

    /// NtUnlockFile on `node`: see [`FileLocks::unlock`].
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn unlock(&self, node: &Node, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        let identity = node.identity().ok_or(STATUS_RANGE_NOT_LOCKED)?;
        let mut locks = self.locks.lock();
        let file = locks.get_mut(&identity).ok_or(STATUS_RANGE_NOT_LOCKED)?;
        let result = file.unlock(offset, length, owner);
        if file.is_empty() {
            locks.remove(&identity);
        }
        result
    }

    /// The last handle of the file object `file_object` on `node` is closed
    /// (FsRtlFastUnlockAll): its locks go.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn unlock_all(&self, node: &Node, file_object: usize) {
        let Some(identity) = node.identity() else { return };
        let mut locks = self.locks.lock();
        if let Some(file) = locks.get_mut(&identity) {
            file.unlock_all(file_object);
            if file.is_empty() {
                locks.remove(&identity);
            }
        }
    }

    /// A read of `node` by `owner`: see [`FileLocks::check_read`].
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn check_read(&self, node: &Node, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        let Some(identity) = node.identity() else { return Ok(()) };
        self.locks.lock().get(&identity).map_or(Ok(()), |file| file.check_read(offset, length, owner))
    }

    /// A write of `node` by `owner`: see [`FileLocks::check_write`].
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn check_write(&self, node: &Node, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        let Some(identity) = node.identity() else { return Ok(()) };
        self.locks.lock().get(&identity).map_or(Ok(()), |file| file.check_write(offset, length, owner))
    }
}
