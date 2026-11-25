//! Tests of writing to a FAT32 volume, on a disk in memory formatted as
//! `tools/mkfat` does (32 reserved sectors, two FATs, 512-byte clusters).
//! A volume of at least 65 525 clusters is checked by `fsck.vfat -n` when
//! dosfstools is installed.

extern crate std;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hal::sync::KSpinLock;

use crate::fat::{make_entry, short_name, BlockDevice, FatError, FatFile, FatVolume, CASE_LOWER_BASE, CASE_LOWER_EXT};

pub(crate) struct RwDisk(pub(crate) KSpinLock<Vec<u8>>);

impl BlockDevice for RwDisk {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        let at = lba as usize * 512;
        out.copy_from_slice(self.0.lock().get(at..at + 512).ok_or(FatError::Io)?);
        Ok(())
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        let at = lba as usize * 512;
        self.0.lock().get_mut(at..at + 512).ok_or(FatError::Io)?.copy_from_slice(data);
        Ok(())
    }
}

/// An empty FAT32 volume of `clusters` clusters.
pub(crate) fn fat32(clusters: u32) -> RwDisk {
    let fat_sectors = ((clusters as usize + 2) * 4).div_ceil(512);
    let data_start = 32 + 2 * fat_sectors;
    let total = data_start + clusters as usize;
    let mut d = vec![0u8; total * 512];
    let b = &mut d[..512];
    b[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    b[3..11].copy_from_slice(b"MINO    ");
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = 1;
    b[14..16].copy_from_slice(&32u16.to_le_bytes());
    b[16] = 2;
    b[21] = 0xF8;
    b[24..26].copy_from_slice(&63u16.to_le_bytes());
    b[26..28].copy_from_slice(&255u16.to_le_bytes());
    b[32..36].copy_from_slice(&(total as u32).to_le_bytes());
    b[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
    b[44..48].copy_from_slice(&2u32.to_le_bytes());
    b[48..50].copy_from_slice(&1u16.to_le_bytes());
    b[50..52].copy_from_slice(&6u16.to_le_bytes());
    b[64] = 0x80;
    b[66] = 0x29;
    b[71..82].copy_from_slice(b"NO NAME    ");
    b[82..90].copy_from_slice(b"FAT32   ");
    b[510..512].copy_from_slice(&[0x55, 0xAA]);
    let boot: Vec<u8> = d[..512].to_vec();
    d[6 * 512..7 * 512].copy_from_slice(&boot);
    for sector in [1, 7] {
        let s = &mut d[sector * 512..(sector + 1) * 512];
        s[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        s[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        s[488..496].copy_from_slice(&[0xFF; 8]);
        s[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    }
    for fat in [32 * 512, (32 + fat_sectors) * 512] {
        for (i, value) in [0x0FFF_FFF8u32, 0x0FFF_FFFF, 0x0FFF_FFFF].iter().enumerate() {
            d[fat + 4 * i..fat + 4 * i + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    RwDisk(KSpinLock::new(d))
}

/// `fsck.vfat -n` on `bytes`: `None` without it.
pub(crate) fn fsck(bytes: &[u8]) -> Option<Result<(), String>> {
    use std::process::Command;
    let program = ["/usr/sbin/fsck.vfat", "/sbin/fsck.vfat", "fsck.vfat"]
        .into_iter()
        .find(|p| Command::new(p).arg("--help").output().is_ok())?;
    let path = std::env::temp_dir().join(std::format!("io-fat-{}-{:p}.img", std::process::id(), bytes.as_ptr()));
    std::fs::write(&path, bytes).expect("write the image");
    let output = Command::new(program).args(["-n"]).arg(&path).output().expect("run fsck.vfat");
    let _ = std::fs::remove_file(&path);
    Some(if output.status.success() {
        Ok(())
    } else {
        Err(std::format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
    })
}

/// The volume on `disk` passes `fsck.vfat`, when it is there.
pub(crate) fn assert_clean(volume: FatVolume<RwDisk>) {
    volume.flush().expect("flush the cached FAT before fsck");
    let bytes = core::mem::take(&mut *volume_disk(&volume).0.lock());
    if let Some(result) = fsck(&bytes) {
        result.unwrap_or_else(|report| panic!("fsck.vfat: {report}"));
    } else {
        std::eprintln!("fsck.vfat not found: the volume is not checked (dosfstools)");
    }
}

fn volume_disk(volume: &FatVolume<RwDisk>) -> &RwDisk {
    volume.device()
}

/// The big volume `fsck.vfat` wants.
const FSCK_CLUSTERS: u32 = 65_600;

fn read_all<D: BlockDevice>(volume: &FatVolume<D>, first_cluster: u32, size: u32) -> Vec<u8> {
    let mut file = FatFile { first_cluster, file_size: size, position: 0 };
    let mut bytes = vec![0u8; size as usize];
    assert_eq!(volume.read(&mut file, &mut bytes), Ok(size as usize));
    bytes
}

#[test]
fn a_file_is_created_written_and_read_back() {
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    let at = volume.add_entry(root, &make_entry(&short_name("hello.txt").unwrap(), 0x20, 0, 0), 3).unwrap();
    let (mut first, mut size) = (0, 0);
    let text: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    volume.write_file(&mut first, &mut size, 0, &text, 3).unwrap();
    volume.update_entry(at, first, size).unwrap();
    assert_eq!((size, volume.chain(first).unwrap().len()), (1500, 3));
    let (entry, found) = volume.find_entry(root, "HELLO.TXT").unwrap();
    assert_eq!((found, entry.first_cluster, entry.file_size), (at, first, 1500));
    assert_eq!(read_all(&volume, first, size), text);
    // Overwrite the middle, then write past the end, leaving a gap.
    volume.write_file(&mut first, &mut size, 500, b"MIDDLE", 3).unwrap();
    volume.write_file(&mut first, &mut size, 3000, b"END", 3).unwrap();
    volume.update_entry(at, first, size).unwrap();
    let back = read_all(&volume, first, size);
    assert_eq!((back.len(), &back[500..506], &back[3000..]), (3003, &b"MIDDLE"[..], &b"END"[..]));
    assert!(back[1500..3000].iter().all(|&b| b == 0), "the gap reads as zeros");
    assert_eq!(&back[..500], &text[..500]);
    assert_clean(volume);
}

#[test]
fn directories_grow_and_hold_their_dot_entries() {
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    let (dir, _) = volume.create_directory(root, "SUB", 3).unwrap();
    let (inner, _) = volume.create_directory(dir, "INNER", 3).unwrap();
    for i in 0..40 {
        let name = short_name(&std::format!("F{i}.DAT")).unwrap();
        let at = volume.add_entry(dir, &make_entry(&name, 0x20, 0, 0), 3).unwrap();
        let (mut first, mut size) = (0, 0);
        volume.write_file(&mut first, &mut size, 0, std::format!("file {i}").as_bytes(), 3).unwrap();
        volume.update_entry(at, first, size).unwrap();
    }
    assert_eq!(volume.chain(dir).unwrap().len(), 3, "43 entries need three clusters of 16");
    let listed = volume.list_dir("/SUB").unwrap();
    assert_eq!((listed.len(), listed[0].name.as_str(), listed[1].first_cluster), (43, ".", 0));
    assert_eq!(volume.list_dir("/SUB/INNER").unwrap()[1].first_cluster, dir, "`..` names its parent");
    let (entry, _) = volume.find_entry(dir, "f39.dat").unwrap();
    assert_eq!(read_all(&volume, entry.first_cluster, entry.file_size), b"file 39");
    assert!(volume.find_entry(inner, "x").is_err());
    assert_clean(volume);
}

#[test]
fn truncation_gives_clusters_back() {
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    let at = volume.add_entry(root, &make_entry(&short_name("BIG.BIN").unwrap(), 0x20, 0, 0), 3).unwrap();
    let (mut first, mut size) = (0, 0);
    volume.write_file(&mut first, &mut size, 0, &[7u8; 5000], 3).unwrap();
    volume.set_file_size(&mut first, &mut size, 100, 3).unwrap();
    volume.update_entry(at, first, size).unwrap();
    assert_eq!((size, volume.chain(first).unwrap().len()), (100, 1));
    // Bytes 100 to 511 of the kept cluster still hold 7s: a write past the
    // end must not let them through.
    volume.write_file(&mut first, &mut size, 1000, b"X", 3).unwrap();
    let back = read_all(&volume, first, size);
    assert_eq!((back.len(), back[1000]), (1001, b'X'));
    assert!(back[100..1000].iter().all(|&b| b == 0), "the gap reads as zeros");
    volume.set_file_size(&mut first, &mut size, 100, 3).unwrap();
    let kept = first;
    volume.set_file_size(&mut first, &mut size, 0, 3).unwrap();
    assert_eq!((first, size, volume.fat_entry(kept)), (0, 0, Ok(0)), "no cluster left, the last one free");
    volume.update_entry(at, first, size).unwrap();
    volume.set_file_size(&mut first, &mut size, 700, 3).unwrap();
    volume.update_entry(at, first, size).unwrap();
    assert_eq!(read_all(&volume, first, size), vec![0u8; 700], "extended with zeros, not what was there");
    assert_clean(volume);
}

#[test]
fn a_full_volume_refuses_and_keeps_what_was_there() {
    let volume = FatVolume::mount(fat32(8)).unwrap();
    let (mut first, mut size) = (0, 0);
    volume.write_file(&mut first, &mut size, 0, &[1u8; 1024], 3).unwrap();
    let before = volume.chain(first).unwrap();
    assert_eq!(volume.write_file(&mut first, &mut size, 1024, &[2u8; 512 * 8], 3), Err(FatError::Full));
    assert_eq!((volume.chain(first).unwrap(), size), (before, 1024), "the chain as it was");
    assert_eq!(volume.write_file(&mut first, &mut size, u64::from(u32::MAX), b"x", 3), Err(FatError::Full), "4 GiB");
    let free: Vec<u32> = (2..10).filter(|&c| volume.fat_entry(c) == Ok(0)).collect();
    assert_eq!(free.len(), 8 - 1 - 2, "the root and the file's two clusters");
}

#[test]
fn a_long_name_that_cannot_be_written_leaves_no_entry() {
    let volume = FatVolume::mount(fat32(8)).unwrap();
    let root = volume.root_cluster();
    // More than VFAT's 255 units: refused before anything is written (the
    // 64th part's order would read as the last-part flag).
    assert_eq!(volume.add_entry_long(root, &"n".repeat(256), 0x20, 3), Err(FatError::PathFormat));
    assert_eq!(volume.add_entry_long(root, &"n".repeat(900), 0x20, 3), Err(FatError::PathFormat));
    assert!(volume.dir_entries(root).unwrap().is_empty());
    // The root keeps two free slots of its 16, and no cluster is left: the
    // three entries of the name (two parts, its 8.3 entry) need a run of three
    // free slots, so the directory to grow — refused before anything is
    // written.
    for i in 0..14 {
        volume.add_entry(root, &make_entry(&short_name(&std::format!("F{i}.DAT")).unwrap(), 0x20, 0, 0), 3).unwrap();
    }
    let (mut first, mut size) = (0, 0);
    volume.write_file(&mut first, &mut size, 0, &[1u8; 512 * 7], 3).unwrap();
    assert_eq!(volume.add_entry_long(root, "A long file name.txt", 0x20, 3), Err(FatError::Full));
    for index in 14..16 {
        let entry = volume.read_entry(crate::fat::EntryRef { cluster: root, index }).unwrap();
        assert_eq!(entry[0], 0x00, "slot {index}: still free, nothing written");
    }
    assert_eq!(volume.dir_entries(root).unwrap().len(), 14);
    assert!(volume.find_entry(root, "A long file name.txt").is_err());
}

/// A disk that counts the sectors written to it, and fails every write from
/// the `fail_at`-th on.
struct Counting {
    disk: RwDisk,
    writes: core::sync::atomic::AtomicU32,
    fail_at: u32,
}

impl BlockDevice for Counting {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        self.disk.read_sector(lba, out)
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        if self.writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1 >= self.fail_at {
            return Err(FatError::Io);
        }
        self.disk.write_sector(lba, data)
    }
}

/// A volume of `clusters` clusters whose free clusters hold what an old file
/// left there (0xA5), on a [`Counting`] disk.
fn stale(clusters: u32, fail_at: u32) -> FatVolume<Counting> {
    let disk = fat32(clusters);
    let data_start = 32 + 2 * ((clusters as usize + 2) * 4).div_ceil(512);
    // Cluster 2 is the root; the others are free.
    disk.0.lock()[(data_start + 1) * 512..].fill(0xA5);
    FatVolume::mount(Counting { disk, writes: core::sync::atomic::AtomicU32::new(0), fail_at }).unwrap()
}

#[test]
fn a_new_file_goes_to_the_device_once() {
    let volume = stale(64, u32::MAX);
    let data: Vec<u8> = (0..2048u32).map(|i| (i % 253) as u8).collect();
    let (mut first, mut size) = (0, 0);
    volume.write_file(&mut first, &mut size, 0, &data, 3).unwrap();
    // Zeroing the clusters before writing them wrote each sector twice: the
    // installer's copy of the system took twice as long.
    let writes = volume.device().writes.load(core::sync::atomic::Ordering::Relaxed);
    assert_eq!(writes, 4, "four clusters, each written once");
    assert_eq!(read_all(&volume, first, size), data);
    // A size that leaves part of the last cluster: that part, which held
    // 0xA5, reads as zeros, as when the clusters were zeroed first.
    let (mut first, mut size) = (0, 0);
    volume.write_file(&mut first, &mut size, 0, &data[..1500], 3).unwrap();
    let raw = read_all(&volume, first, 1536);
    assert_eq!(&raw[..1500], &data[..1500]);
    assert!(raw[1500..].iter().all(|&b| b == 0), "the rest of the last cluster is zeroed");
    // Growing a file: the clusters it adds are covered the same way.
    volume.write_file(&mut first, &mut size, 1500, &data[..1000], 3).unwrap();
    let raw = read_all(&volume, first, 2560);
    assert_eq!((&raw[..1500], &raw[1500..2500]), (&data[..1500], &data[..1000]));
    assert!(raw[2500..].iter().all(|&b| b == 0), "the rest of the new last cluster is zeroed");
}

#[test]
fn a_failed_write_gives_back_the_clusters_it_took() {
    // The third sector written fails: the file's clusters are taken, not
    // all written.
    let volume = stale(64, 3);
    let free = |volume: &FatVolume<Counting>| (2..66).filter(|&c| volume.fat_entry(c) == Ok(0)).count();
    let before = free(&volume);
    let (mut first, mut size) = (0, 0);
    assert_eq!(volume.write_file(&mut first, &mut size, 0, &[1u8; 2048], 3), Err(FatError::Io));
    assert_eq!((first, size, free(&volume)), (0, 0, before), "no cluster kept, no size recorded");
}

#[test]
fn a_read_only_device_writes_nothing() {
    struct ReadOnly(RwDisk);
    impl BlockDevice for ReadOnly {
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
            self.0.read_sector(lba, out)
        }
    }
    let volume = FatVolume::mount(ReadOnly(fat32(64))).unwrap();
    let entry = make_entry(&short_name("A").unwrap(), 0x20, 0, 0);
    assert_eq!(volume.add_entry(volume.root_cluster(), &entry, 3).err(), Some(FatError::ReadOnly));
}

/// A disk the test keeps, to read its bytes after the volume wrote them.
struct Shared(alloc::sync::Arc<RwDisk>);

impl BlockDevice for Shared {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        self.0.read_sector(lba, out)
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        self.0.write_sector(lba, data)
    }
}

fn mounted(clusters: u32) -> (alloc::sync::Arc<crate::Volume>, alloc::sync::Arc<RwDisk>) {
    let disk = alloc::sync::Arc::new(fat32(clusters));
    let volume = crate::Volume::mount(alloc::boxed::Box::new(Shared(disk.clone()))).unwrap();
    (alloc::sync::Arc::new(volume), disk)
}

#[test]
fn files_are_created_written_and_seen_by_every_open() {
    use crate::{check_open, File};
    use abi::file::*;
    use abi::ntstatus::*;

    let (volume, disk) = mounted(FSCK_CLUSTERS);
    let root = File::open(&volume, "\\").unwrap();
    let logs = root.create_child("Logs", true, 0).unwrap();
    assert!(logs.is_directory());
    assert_eq!(logs.path(), "\\Logs");
    let file = logs.create_child("today.txt", false, 0).unwrap();
    assert_eq!((file.path(), file.node().unwrap().size), ("\\Logs\\today.txt", 0));
    assert_eq!(file.node().unwrap().attributes, FILE_ATTRIBUTE_ARCHIVE);
    file.write(0, b"hello").unwrap();
    let other = File::open(&volume, "\\LOGS\\TODAY.TXT").unwrap();
    assert_eq!(other.read_all().unwrap(), b"hello");
    file.write(5, b", world").unwrap();
    assert_eq!(other.node().unwrap().size, 12, "another open sees the new size");
    assert_eq!(other.read_all().unwrap(), b"hello, world");
    assert_eq!(check_open(&other, FILE_OVERWRITE_IF, 0, ob::AccessMask::NONE), Ok(FILE_OVERWRITTEN));
    assert_eq!(file.node().unwrap().size, 0, "emptied for every open");

    assert_eq!(logs.create_child("TODAY.TXT", false, 0).err(), Some(STATUS_OBJECT_NAME_COLLISION));
    // A long name is kept: VFAT entries and an 8.3 alias (see
    // long_names_are_written_and_reread).
    let long = logs.create_child("A long name.txt", false, 0).unwrap();
    long.write(0, b"long").unwrap();
    assert_eq!(File::open(&volume, "\\Logs\\A long name.txt").unwrap().read_all().unwrap(), b"long");
    // A long-named directory too, and what it holds.
    let profiles = root.create_child("Documents and Settings", true, 0).unwrap();
    assert!(profiles.is_directory());
    let user = profiles.create_child("Default User", true, 0).unwrap();
    user.create_child("NTUSER.DAT", false, 0).unwrap().write(0, b"regf").unwrap();
    let path = "\\documents and settings\\DEFAULT USER\\ntuser.dat";
    assert_eq!(File::open(&volume, path).unwrap().read_all().unwrap(), b"regf");
    assert_eq!(logs.create_child("bad*name", false, 0).err(), Some(STATUS_OBJECT_NAME_INVALID));
    // VFAT holds 255 UTF-16 units at most: a longer name, file or
    // directory, is refused before anything is written.
    let longest = "n".repeat(255);
    logs.create_child(&longest, false, 0).unwrap().write(0, b"255").unwrap();
    assert_eq!(File::open(&volume, &std::format!("\\Logs\\{longest}")).unwrap().read_all().unwrap(), b"255");
    let too_long = "n".repeat(256);
    assert_eq!(logs.create_child(&too_long, false, 0).err(), Some(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(logs.create_child(&"d".repeat(900), true, 0).err(), Some(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(File::open(&volume, &std::format!("\\Logs\\{too_long}")).err(), Some(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(file.create_child("x", false, 0).err(), Some(STATUS_OBJECT_PATH_NOT_FOUND), "under a file");
    assert_eq!(logs.write(0, b"x").err(), Some(STATUS_INVALID_DEVICE_REQUEST), "writing a directory");
    let locked = root.create_child("RO.TXT", false, FILE_ATTRIBUTE_READONLY).unwrap();
    let write = ob::AccessMask(FILE_WRITE_DATA);
    assert_eq!(check_open(&locked, FILE_OPEN, 0, write), Err(STATUS_ACCESS_DENIED));
    let many: Vec<_> = (0..30).map(|i| logs.create_child(&std::format!("N{i}.LOG"), false, 0).unwrap()).collect();
    many[29].write(0, &[9u8; 2000]).unwrap();
    assert_eq!(File::open(&volume, "\\Logs\\n29.log").unwrap().read_all().unwrap(), vec![9u8; 2000]);
    drop((root, logs, file, other, locked, many));

    volume.flush().expect("flush the cached FAT before fsck");
    let bytes = core::mem::take(&mut *disk.0.lock());
    match fsck(&bytes) {
        Some(result) => result.unwrap_or_else(|report| panic!("fsck.vfat: {report}")),
        None => std::eprintln!("fsck.vfat not found: the volume is not checked (dosfstools)"),
    }
}

#[test]
fn a_full_volume_says_so() {
    use crate::File;
    use abi::ntstatus::STATUS_DISK_FULL;

    let (volume, _disk) = mounted(8);
    let file = File::open(&volume, "\\").unwrap().create_child("FULL.BIN", false, 0).unwrap();
    file.write(0, &[1u8; 1024]).unwrap();
    assert_eq!(file.write(1024, &[2u8; 512 * 8]).err(), Some(STATUS_DISK_FULL));
    assert_eq!(file.node().unwrap().size, 1024, "the size as it was");
    assert_eq!(file.read_all().unwrap(), vec![1u8; 1024]);
}

#[test]
fn a_volume_describes_itself_and_dates_what_it_writes() {
    use crate::fat::{nt_time, FatTime};
    use crate::{File, Space, Volume, VolumeLabel};
    use abi::file::*;
    use abi::ntstatus::*;

    // 2026-11-06 09:54:31.25 UTC, as KeQuerySystemTime gives it; then, for
    // a write, 10:00:00.
    const DATE: u16 = ((2026 - 1980) << 9) | (11 << 5) | 6;
    const TIME: u16 = (9 << 11) | (54 << 5) | (30 / 2);
    const LATER: u16 = 10 << 11;
    static CLOCK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    fn now() -> u64 {
        CLOCK.load(core::sync::atomic::Ordering::Relaxed)
    }
    CLOCK.store(nt_time(DATE, TIME, 125), core::sync::atomic::Ordering::Relaxed);
    let clusters = 100;
    let disk = alloc::sync::Arc::new(fat32(clusters));
    {
        let mut bytes = disk.0.lock();
        bytes[67..71].copy_from_slice(&0x4D49_4E4Fu32.to_le_bytes());
        // The volume label, the first entry of the root (cluster 2, after the
        // reserved sectors and the two FATs of one sector each).
        let root = (32 + 2) * 512;
        bytes[root..root + 32].copy_from_slice(&make_entry(b"MINO DISK  ", 0x08, 0, 0));
    }
    let volume = Volume::mount(alloc::boxed::Box::new(Shared(disk.clone()))).unwrap().with_clock(now);
    let volume = alloc::sync::Arc::new(volume);

    assert_eq!(volume.label(), Ok(VolumeLabel { serial: 0x4D49_4E4F, label: "MINO DISK".encode_utf16().collect() }));
    let empty = Space {
        total_clusters: u64::from(clusters),
        free_clusters: u64::from(clusters - 1),
        sectors_per_cluster: 1,
        bytes_per_sector: 512,
    };
    assert_eq!(volume.space(), Ok(empty), "the root takes a cluster");

    // Created now: creation (to the hundredth), last write and access (to
    // 2 s, and the day).
    let root = File::open(&volume, "\\").unwrap();
    let file = root.create_child("A.TXT", false, 0).unwrap();
    let created = file.node().unwrap();
    assert_eq!(created.creation_time, nt_time(DATE, TIME, 125));
    assert_eq!((created.last_write_time, created.last_access_time), (nt_time(DATE, TIME, 0), nt_time(DATE, 0, 0)));
    assert!(volume.list(&volume.root()).unwrap().contains(&String::from("A.TXT")), "beside the label");
    CLOCK.store(nt_time(DATE, LATER, 0), core::sync::atomic::Ordering::Relaxed);
    file.write(0, &[7u8; 1500]).unwrap();
    assert_eq!(volume.space().unwrap().free_clusters, u64::from(clusters - 1 - 3), "three clusters written");
    let written = file.node().unwrap();
    assert_eq!((written.creation_time, written.last_write_time), (created.creation_time, nt_time(DATE, LATER, 0)));

    // FileBasicInformation: 0 leaves a field; FILE_ATTRIBUTE_NORMAL clears.
    let image = nt_time(12548, 12 << 11, 0);
    let basic = FileBasicInformation {
        creation_time: image,
        last_write_time: image,
        file_attributes: FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_TEMPORARY,
        ..Default::default()
    };
    file.set_basic_information(&basic).unwrap();
    let changed = file.node().unwrap();
    assert_eq!((changed.creation_time, changed.last_write_time), (image, image));
    assert_eq!(changed.last_access_time, nt_time(DATE, 0, 0), "left as it was");
    assert_eq!(changed.attributes, FILE_ATTRIBUTE_READONLY, "what FAT keeps of them");
    let normal = FileBasicInformation { file_attributes: FILE_ATTRIBUTE_NORMAL, ..Default::default() };
    file.set_basic_information(&normal).unwrap();
    assert_eq!(file.node().unwrap().attributes, FILE_ATTRIBUTE_NORMAL);
    assert_eq!(file.node().unwrap().creation_time, image, "the dates left");
    let accessed = FileBasicInformation { last_access_time: nt_time(12549, 0, 0), ..Default::default() };
    file.set_basic_information(&accessed).unwrap();
    assert_eq!(file.node().unwrap().last_access_time, nt_time(12549, 0, 0), "the day after");
    let before_fat = FileBasicInformation { creation_time: nt_time(0, 0, 0) + 1, ..Default::default() };
    assert_eq!(file.set_basic_information(&before_fat).err(), Some(STATUS_INVALID_PARAMETER), "before 1980");
    assert_eq!(root.set_basic_information(&basic).err(), Some(STATUS_INVALID_PARAMETER), "the root has no entry");
    // A directory keeps its bit.
    let directory = root.create_child("D", true, 0).unwrap();
    directory.set_basic_information(&FileBasicInformation { file_attributes: FILE_ATTRIBUTE_HIDDEN, ..basic }).unwrap();
    assert_eq!(directory.node().unwrap().attributes, FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN);
    let _ = FatTime::default();
}

#[test]
fn a_directory_takes_a_long_name() {
    // The profiles of an installed system (ADR-023): userenv's
    // InitializeProfiles creates `Documents and Settings`, then `Default User`
    // in it. A directory was refused a name 8.3 could not hold.
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    let (profiles, _) = volume.create_directory(root, "Documents and Settings", 3).unwrap();
    let (user, _) = volume.create_directory(profiles, "Default User", 3).unwrap();
    let at = volume.add_entry_long(user, "NTUSER.DAT", 0x20, 3).unwrap();
    let (mut first, mut size) = (0, 0);
    volume.write_file(&mut first, &mut size, 0, b"regf", 3).unwrap();
    volume.update_entry(at, first, size).unwrap();
    let (found, _) = volume.find_entry(root, "DOCUMENTS AND SETTINGS").expect("by its long name, any case");
    assert_eq!(found.first_cluster, profiles);
    let listed = volume.dir_entries(root).unwrap().into_iter().find(|e| e.name == "Documents and Settings").unwrap();
    assert_eq!(&listed.raw_name, b"DOCUME~1   ", "its alias");
    assert_ne!(listed.attr & 0x10, 0, "a directory");
    let inside = volume.list_dir("/Documents and Settings/Default User").unwrap();
    assert_eq!((inside[0].name.as_str(), inside[0].first_cluster), (".", user));
    assert_eq!((inside[1].name.as_str(), inside[1].first_cluster), ("..", profiles), "`..` names its parent");
    assert_eq!(inside[2].name, "NTUSER.DAT");
    let (ntuser, _) = volume.find_entry(user, "ntuser.dat").unwrap();
    assert_eq!(read_all(&volume, ntuser.first_cluster, ntuser.file_size), b"regf");
    assert_clean(volume);
}

#[test]
fn long_names_are_written_and_reread() {
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    // KERNEL32_VISTA.DLL : the name that stopped the first installed copy.
    let at = volume.add_entry_long(root, "KERNEL32_VISTA.DLL", 0x20, 3).unwrap();
    let (mut first, mut size) = (0, 0);
    let text: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    volume.write_file(&mut first, &mut size, 0, &text, 3).unwrap();
    volume.update_entry(at, first, size).unwrap();
    // Found by its long name, any case; its 8.3 entry holds the alias.
    let (entry, _) = volume.find_entry(root, "kernel32_vista.dll").unwrap();
    assert_eq!((entry.first_cluster, entry.file_size), (first, 1000));
    assert_eq!(read_all(&volume, first, size), text);
    let kernel32 = volume.dir_entries(root).unwrap().into_iter().find(|e| e.name == "KERNEL32_VISTA.DLL").unwrap();
    assert_eq!(kernel32.short_name.as_deref(), Some("KERNEL~1.DLL"));
    assert_eq!(&kernel32.raw_name, b"KERNEL~1DLL");
    // A second long name with the same base and extension gets the next
    // alias; one with another extension keeps ~1 (the 8.3 name as a whole is
    // unique, as XP makes it). All stay readable.
    volume.add_entry_long(root, "KERNEL32_OTHER.DLL", 0x20, 3).unwrap();
    volume.add_entry_long(root, "KERNEL32_VISTA.TXT", 0x20, 3).unwrap();
    let aliases: Vec<[u8; 11]> = volume
        .dir_entries(root)
        .unwrap()
        .iter()
        .filter(|e| e.name.starts_with("KERNEL32_"))
        .map(|e| e.raw_name)
        .collect();
    assert_eq!(aliases, [*b"KERNEL~1DLL", *b"KERNEL~2DLL", *b"KERNEL~1TXT"]);
    for name in ["kernel32_vista.dll", "KERNEL32_OTHER.DLL", "KERNEL32_VISTA.TXT"] {
        assert!(volume.find_entry(root, name).is_ok(), "{name} is found");
    }
    assert_clean(volume);
}

#[test]
fn a_volume_creates_and_opens_long_names() {
    use abi::ntstatus::STATUS_OBJECT_NAME_COLLISION;

    let (volume, _disk) = mounted(FSCK_CLUSTERS);
    let root = volume.root();
    let node = volume.create(&root, "KERNEL32_VISTA.DLL", false, 0).unwrap();
    volume.write(&node, 0, b"MZ").unwrap();
    // Seen again by its long name, any case, and in the listing with its
    // alias; the alias alone is not a second entry.
    assert_eq!(volume.lookup(&root, "kernel32_vista.dll").unwrap().size, 2);
    let listed = volume.entries(&root).unwrap();
    let kernel32 = listed.iter().find(|e| e.name == "KERNEL32_VISTA.DLL".encode_utf16().collect::<Vec<_>>()).unwrap();
    assert_eq!(kernel32.short_name.as_deref(), Some("KERNEL~1.DLL".encode_utf16().collect::<Vec<_>>().as_slice()));
    assert_eq!(listed.iter().filter(|e| e.name == "KERNEL~1.DLL".encode_utf16().collect::<Vec<_>>()).count(), 0);
    // The same long name twice is refused; a different one is not.
    assert_eq!(volume.create(&root, "KERNEL32_VISTA.DLL", false, 0).err(), Some(STATUS_OBJECT_NAME_COLLISION));
    assert!(volume.create(&root, "KERNEL32_VISTA.TXT", false, 0).is_ok());
}

/// A name's long-name entries go just before its 8.3 entry, in a run of free
/// slots that holds them all (vfatFindDirSpace of ReactOS's vfatfs): a hole
/// that a deleted entry left and that is too short is skipped, one that fits
/// is taken again. Inno Setup moves each file it installs (MoveFile, which
/// kernel32 makes a copy and a delete without FileRenameInformation): in
/// PeaZip's `res\themes`, `nographic-embedded` was written with its two
/// long-name entries in such a hole and its alias `NOGRAP~1` at the end,
/// found by neither name ("The system cannot find the path specified").
#[test]
fn a_long_name_takes_a_run_of_free_slots_past_a_short_hole() {
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    let (dir, _) = volume.create_directory(root, "themes", 3).unwrap();
    // Slots 2 and 3: a name that takes two (one long-name entry, its alias).
    let temp = volume.add_entry_long(dir, "Temp File.tmp", 0x20, 3).unwrap();
    assert_eq!(temp.index, 3);
    volume.add_entry_long(dir, "firecrystal.theme.7z", 0x20, 3).unwrap();
    volume.delete_entry(temp, 0).unwrap();
    // Three entries: not in the hole of two.
    let (theme, at) = volume.create_directory(dir, "nographic-embedded", 3).unwrap();
    assert_eq!(at.index, 9, "its alias after its two long-name entries, past the hole");
    let (found, _) = volume.find_entry(dir, "nographic-embedded").expect("found by its long name");
    assert_eq!(found.first_cluster, theme);
    let names: Vec<String> = volume.dir_entries(dir).unwrap().into_iter().map(|entry| entry.name).collect();
    assert!(names.iter().any(|name| name == "nographic-embedded"), "listed by its long name: {names:?}");
    assert!(!names.iter().any(|name| name == "NOGRAP~1"), "not by its alias alone: {names:?}");
    // Two entries (13 characters: one long-name entry): the hole again.
    let again = volume.add_entry_long(dir, "Short One.txt", 0x20, 3).unwrap();
    assert_eq!(again.index, 3, "the hole holds it");
    assert!(volume.find_entry(dir, "short one.txt").is_ok());
    assert_clean(volume);
}

/// What a [`ReadCounting`] disk counts: the calls that read it, and the
/// sectors they read.
#[derive(Default)]
struct Reads {
    calls: core::sync::atomic::AtomicU32,
    sectors: core::sync::atomic::AtomicU32,
}

impl Reads {
    fn take(&self) -> (u32, u32) {
        use core::sync::atomic::Ordering::Relaxed;
        (self.calls.swap(0, Relaxed), self.sectors.swap(0, Relaxed))
    }
}

/// A disk that reads runs of sectors in one call, as an ATA disk does, and
/// counts them.
struct ReadCounting(alloc::sync::Arc<RwDisk>, alloc::sync::Arc<Reads>);

impl BlockDevice for ReadCounting {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        self.read_sectors(lba, out)
    }
    fn read_sectors(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        use core::sync::atomic::Ordering::Relaxed;
        self.1.calls.fetch_add(1, Relaxed);
        self.1.sectors.fetch_add((out.len() / 512) as u32, Relaxed);
        for (i, sector) in out.chunks_exact_mut(512).enumerate() {
            self.0.read_sector(lba + i as u64, sector)?;
        }
        Ok(())
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        self.0.write_sector(lba, data)
    }
}

/// A byte pattern no two nearby sectors share.
fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length).map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[3] ^ seed).collect()
}

#[test]
fn file_reads_take_runs_of_contiguous_clusters() {
    use crate::File;

    let reads = alloc::sync::Arc::new(Reads::default());
    let disk = alloc::sync::Arc::new(fat32(4096));
    let device = alloc::boxed::Box::new(ReadCounting(disk, reads.clone()));
    let volume = alloc::sync::Arc::new(crate::Volume::mount(device).unwrap());
    let root = File::open(&volume, "\\").unwrap();
    // 300 Kio in one write: 600 clusters of 512 bytes, one after the other.
    let long = pattern(300 * 1024, 0x11);
    let whole = root.create_child("WHOLE.BIN", false, 0).unwrap();
    whole.write(0, &long).unwrap();
    // Two files written in turns: their clusters alternate.
    let (one, two) = (root.create_child("ONE.BIN", false, 0).unwrap(), root.create_child("TWO.BIN", false, 0).unwrap());
    let (first, second) = (pattern(8 * 512, 0x22), pattern(8 * 512, 0x33));
    for at in (0..8 * 512).step_by(512) {
        one.write(at as u64, &first[at..at + 512]).unwrap();
        two.write(at as u64, &second[at..at + 512]).unwrap();
    }

    let read = |file: &File, offset: u64, length: usize| {
        let node = file.node().unwrap();
        reads.take();
        let mut out = vec![0u8; length];
        assert_eq!(volume.read(&node, offset, &mut out).unwrap(), length);
        // The read checks the file's entry first: a sector of its own.
        let (calls, sectors) = reads.take();
        (out, (calls - 1, sectors - 1))
    };
    let (out, counted) = read(&whole, 0, long.len());
    assert!(out == long, "the whole file");
    assert_eq!(counted, (3, 600), "three runs of 128 Kio at most: 256 + 256 + 88 sectors");
    let (out, counted) = read(&whole, 1000, 3000);
    assert!(out[..] == long[1000..4000], "from the middle of a cluster");
    assert_eq!(counted, (1, 7), "clusters 1 to 7, one run");
    let (out, counted) = read(&whole, 0, 128 * 1024 + 512);
    assert!(out[..] == long[..128 * 1024 + 512], "a cluster more than a run");
    assert_eq!(counted, (2, 257), "256 sectors a call at most");
    let (out, counted) = read(&one, 0, first.len());
    assert!(out == first, "a fragmented file");
    assert_eq!(counted, (8, 8), "a run per cluster: its clusters are not contiguous");
    let (out, _) = read(&two, 512 + 17, 1024);
    assert!(out[..] == second[512 + 17..512 + 17 + 1024]);
}

#[test]
fn an_image_section_reads_the_head_of_its_file_only() {
    use crate::File;

    let (volume, _disk) = mounted(256);
    let root = File::open(&volume, "\\").unwrap();
    let file = root.create_child("SETUP.EXE", false, 0).unwrap();
    let bytes: alloc::vec::Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    file.write(0, &bytes).unwrap();
    let (head, hold) = file.image_head().unwrap();
    assert!(head[..] == bytes[..64 * 1024], "its first 64 KiB: the rest is read at a fault");
    assert!(hold.is_some());
    let small = root.create_child("SMALL.EXE", false, 0).unwrap();
    small.write(0, &bytes[..3000]).unwrap();
    assert!(small.image_head().unwrap().0[..] == bytes[..3000], "a file shorter than that");
}

#[test]
fn the_file_of_an_image_section_is_neither_written_nor_deleted() {
    use crate::{check_open, File};
    use abi::file::{FILE_DELETE_ON_CLOSE, FILE_OPEN, FILE_OPENED, FILE_OVERWRITE, FILE_READ_DATA, FILE_WRITE_DATA};
    use abi::ntstatus::STATUS_CANNOT_DELETE;
    use ob::AccessMask;

    let (volume, _disk) = mounted(256);
    let root = File::open(&volume, "\\").unwrap();
    let file = root.create_child("LOADED.DLL", false, 0).unwrap();
    file.write(0, b"MZ").unwrap();
    let other = root.create_child("OTHER.DLL", false, 0).unwrap();
    let (_, hold) = file.image_head().unwrap();
    let opened = File::open(&volume, "\\loaded.dll").unwrap();
    let read = AccessMask(FILE_READ_DATA);
    assert_eq!(check_open(&opened, FILE_OPEN, 0, read), Ok(FILE_OPENED), "read, as a loader does");
    let write = AccessMask(FILE_WRITE_DATA);
    assert_eq!(check_open(&opened, FILE_OPEN, 0, write), Err(abi::ntstatus::STATUS_SHARING_VIOLATION));
    assert_eq!(check_open(&opened, FILE_OVERWRITE, 0, read), Err(abi::ntstatus::STATUS_SHARING_VIOLATION));
    let delete = AccessMask::DELETE;
    assert_eq!(check_open(&opened, FILE_OPEN, FILE_DELETE_ON_CLOSE, delete), Err(STATUS_CANNOT_DELETE));
    assert_eq!(opened.set_delete_pending(true), Err(STATUS_CANNOT_DELETE));
    assert_eq!(check_open(&other, FILE_OPEN, 0, write), Ok(FILE_OPENED), "another file");
    drop(hold);
    assert_eq!(check_open(&opened, FILE_OPEN, 0, write), Ok(FILE_OPENED), "the section gone");
    assert_eq!(opened.set_delete_pending(true), Ok(()));
}

#[test]
fn data_sections_share_the_segment_of_an_unchanged_file_and_read_nothing() {
    use crate::File;
    use alloc::sync::Arc;

    /// What `mm::section::FileSegment` is to Io: a `dyn Any`, made for the
    /// size of the file.
    struct Segment(u64);

    let (volume, _disk) = mounted(256);
    let root = File::open(&volume, "\\").unwrap();
    let file = root.create_child("BIG.BIN", false, 0).unwrap();
    file.write(0, &[7u8; 10_000]).unwrap();
    let made = core::cell::Cell::new(0);
    let make = |size: u64| {
        made.set(made.get() + 1);
        Ok(Arc::new(Segment(size)))
    };
    let first = file.data_segment(make).unwrap();
    assert_eq!((first.0, made.get()), (10_000, 1), "made for the size of the file");
    let again = File::open(&volume, "\\big.bin").unwrap().data_segment(make).unwrap();
    assert!(Arc::ptr_eq(&first, &again) && made.get() == 1, "another open, the same segment");
    file.write(0, b"x").unwrap();
    let written = file.data_segment(make).unwrap();
    assert!(!Arc::ptr_eq(&first, &written) && made.get() == 2, "a write: a new segment");
    drop((first, again, written));
    let _ = file.data_segment(make).unwrap();
    assert_eq!(made.get(), 3, "gone with its last section");
}

/// The 8.3 entry of `name` in the directory at `dir`, and how many long-name
/// entries come right before it.
fn entry_and_long_parts(volume: &FatVolume<RwDisk>, dir: u32, name: &str) -> ([u8; 32], usize) {
    let (_, at) = volume.find_entry(dir, name).unwrap();
    let entry = volume.read_entry(at).unwrap();
    let parts = (0..at.index)
        .rev()
        .map(|index| volume.read_entry(crate::fat::EntryRef { index, ..at }).unwrap())
        .take_while(|before| before[11] == 0x0F && before[0] != 0xE5)
        .count();
    (entry, parts)
}

#[test]
fn a_name_8_3_holds_keeps_its_case() {
    // shell32 creates `Recent` in a profile; it came back `RECENT` (a single
    // 8.3 entry), and the places bar of the Save As box showed it so. As
    // vfatfs: all upper case, the 8.3 entry alone; a base or an extension
    // all in lower case, the NT case flags; mixed case, a long name.
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    let (recent, _) = volume.create_directory(root, "Recent", 3).unwrap();
    for name in ["UPPER.DAT", "readme.txt", "lower.TXT", "UPCASE.txt", "123.dat", "Mixed.txt", "MIXEXT.Txt"] {
        volume.add_entry_long(recent, name, 0x20, 3).unwrap();
    }
    let (entry, parts) = entry_and_long_parts(&volume, root, "RECENT");
    assert_eq!((&entry[..11], entry[12], parts), (&b"RECENT     "[..], 0, 1), "a long name before RECENT");
    let listed = volume.dir_entries(root).unwrap().into_iter().find(|e| e.raw_name == *b"RECENT     ").unwrap();
    assert_eq!((listed.name.as_str(), listed.short_name.as_deref()), ("Recent", Some("RECENT")));
    assert_eq!(volume.find_entry(root, "recent").unwrap().0.first_cluster, recent, "found in any case");
    let expected: [(&str, &[u8; 11], u8, usize); 7] = [
        ("UPPER.DAT", b"UPPER   DAT", 0, 0),
        ("readme.txt", b"README  TXT", CASE_LOWER_BASE | CASE_LOWER_EXT, 0),
        ("lower.TXT", b"LOWER   TXT", CASE_LOWER_BASE, 0),
        ("UPCASE.txt", b"UPCASE  TXT", CASE_LOWER_EXT, 0),
        ("123.dat", b"123     DAT", CASE_LOWER_EXT, 0),
        ("Mixed.txt", b"MIXED   TXT", 0, 1),
        ("MIXEXT.Txt", b"MIXEXT  TXT", 0, 1),
    ];
    for (name, short, case, long_parts) in expected {
        let (entry, parts) = entry_and_long_parts(&volume, recent, name);
        assert_eq!((&entry[..11], entry[12], parts), (&short[..], case, long_parts), "{name}");
    }
    // Read back in its case, by the long name or by the flags; an entry
    // without a long name has no separate 8.3 name.
    let names: Vec<(String, Option<String>)> =
        volume.dir_entries(recent).unwrap().into_iter().skip(2).map(|e| (e.name, e.short_name)).collect();
    let short = |name: &str| Some(String::from(name));
    assert_eq!(
        names,
        [
            ("UPPER.DAT".into(), None),
            ("readme.txt".into(), None),
            ("lower.TXT".into(), None),
            ("UPCASE.txt".into(), None),
            ("123.dat".into(), None),
            ("Mixed.txt".into(), short("MIXED.TXT")),
            ("MIXEXT.Txt".into(), short("MIXEXT.TXT")),
        ]
    );
    assert_clean(volume);
}

#[test]
fn a_volume_creates_a_mixed_case_name_in_its_case() {
    use abi::ntstatus::STATUS_OBJECT_NAME_COLLISION;

    let (volume, disk) = mounted(FSCK_CLUSTERS);
    let root = volume.root();
    let recent = volume.create(&root, "Recent", true, 0).unwrap();
    volume.create(&recent, "notes.txt", false, 0).unwrap();
    let utf16 = |name: &str| name.encode_utf16().collect::<Vec<u16>>();
    let listed = volume.entries(&root).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].name.clone(), listed[0].short_name.clone()), (utf16("Recent"), Some(utf16("RECENT"))));
    assert!(listed[0].directory);
    assert_eq!(volume.list(&root).unwrap(), ["Recent"]);
    assert_eq!(volume.list(&recent).unwrap(), ["notes.txt"]);
    // Its 8.3 name too, in the case its flags give (vfatfs).
    let notes = volume.entries(&recent).unwrap().into_iter().find(|e| e.name == utf16("notes.txt")).unwrap();
    assert_eq!(notes.short_name, Some(utf16("notes.txt")));
    // Found in any case, and taken in any case.
    assert_eq!(volume.lookup(&root, "RECENT\\NOTES.TXT").unwrap().size, 0);
    assert_eq!(volume.create(&root, "RECENT", true, 0).err(), Some(STATUS_OBJECT_NAME_COLLISION));
    assert_eq!(volume.create(&recent, "Notes.Txt", false, 0).err(), Some(STATUS_OBJECT_NAME_COLLISION));
    // A fresh mount reads the same names.
    volume.flush().unwrap();
    drop(volume);
    let again = crate::Volume::mount(alloc::boxed::Box::new(Shared(disk.clone()))).unwrap();
    assert_eq!(again.list(&again.root()).unwrap(), ["Recent"]);
    let bytes = core::mem::take(&mut *disk.0.lock());
    match fsck(&bytes) {
        Some(result) => result.unwrap_or_else(|report| panic!("fsck.vfat: {report}")),
        None => std::eprintln!("fsck.vfat not found: the volume is not checked (dosfstools)"),
    }
}

#[test]
fn set_end_of_file_sets_the_allocation_too() {
    // SetEndOfFile of kernel32 sends FileEndOfFileInformation, then
    // FileAllocationInformation at the same value: Inno Setup gives its
    // extracted setup.tmp its size so, and stopped on "Unable to create a
    // temporary file" while the second was not implemented.
    use crate::File;
    use abi::file::{FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY};
    use abi::ntstatus::{STATUS_DISK_FULL, STATUS_INVALID_PARAMETER};

    let (volume, _disk) = mounted(64);
    let root = File::open(&volume, "\\").unwrap();
    let file = root.create_child("SETUP.TMP", false, 0).unwrap();
    file.write(0, &[7u8; 1000]).unwrap();
    file.set_size(3000).unwrap();
    file.set_allocation_size(3000).unwrap();
    let standard = file.standard_information().unwrap();
    assert_eq!((standard.end_of_file, standard.allocation_size), (3000, 3072), "the end of file kept");
    let free = volume.space().unwrap().free_clusters;

    // Above the end of file: the size stays, the volume must hold it.
    file.set_allocation_size(3000 + 512 * free).unwrap();
    assert_eq!(file.node().unwrap().size, 3000, "a reservation does not move the end of file");
    assert_eq!(file.set_allocation_size(3072 + 512 * free + 1).err(), Some(STATUS_DISK_FULL), "a cluster too many");
    assert_eq!(file.set_allocation_size(u64::from(u32::MAX) + 1).err(), Some(STATUS_DISK_FULL), "past FAT's 4 GiB");
    assert_eq!(file.node().unwrap().size, 3000, "a refused reservation changes nothing");
    assert_eq!(volume.space().unwrap().free_clusters, free, "no cluster taken");

    // Below it: the file is cut there, and gives its clusters back.
    file.set_allocation_size(600).unwrap();
    let standard = file.standard_information().unwrap();
    assert_eq!((standard.end_of_file, standard.allocation_size), (600, 1024));
    assert_eq!(file.read_all().unwrap(), vec![7u8; 600]);
    assert_eq!(volume.space().unwrap().free_clusters, free + 4);
    file.set_allocation_size(0).unwrap();
    assert_eq!(file.node().unwrap().size, 0);
    assert_eq!(root.set_allocation_size(0).err(), Some(STATUS_INVALID_PARAMETER), "a directory");

    // FileAttributeTagInformation (DeleteFileW asks it): the attributes,
    // without a reparse point.
    let tag = file.attribute_tag_information().unwrap();
    assert_eq!((tag.file_attributes, tag.reparse_tag), (FILE_ATTRIBUTE_ARCHIVE, 0));
    let locked = root.create_child("LOCKED.TXT", false, FILE_ATTRIBUTE_READONLY).unwrap();
    assert_eq!(
        locked.attribute_tag_information().unwrap().file_attributes & FILE_ATTRIBUTE_READONLY,
        FILE_ATTRIBUTE_READONLY
    );
    let dir = root.create_child("is-1234.tmp", true, 0).unwrap();
    assert_eq!(dir.attribute_tag_information().unwrap().file_attributes, FILE_ATTRIBUTE_DIRECTORY);
}

#[test]
fn a_deleted_entry_takes_its_long_name_across_clusters() {
    // A directory of one cluster (16 entries of 512 bytes): `.`, `..`, 12
    // short names, then a long name of 2 parts whose 8.3 entry is the
    // first of the next cluster.
    let volume = FatVolume::mount(fat32(FSCK_CLUSTERS)).unwrap();
    let root = volume.root_cluster();
    let (dir, _) = volume.create_directory(root, "Spill", 3).unwrap();
    for i in 0..12 {
        volume.add_entry_long(dir, &std::format!("F{i}.TXT"), 0x20, 3).unwrap();
    }
    let long = "A long name across two.txt";
    let at = volume.add_entry_long(dir, long, 0x20, 3).unwrap();
    assert_eq!(at.index, 0, "its 8.3 entry begins the second cluster");
    assert_ne!(at.cluster, dir);
    let first = volume.allocate_cluster(3).unwrap();
    let free = volume.free_clusters().unwrap();
    volume.delete_entry(at, first).unwrap();
    assert_eq!(volume.free_clusters().unwrap(), free + 1, "its chain freed");
    let names: Vec<String> = volume.dir_entries(dir).unwrap().into_iter().map(|entry| entry.name).collect();
    assert!(!names.iter().any(|name| name == long), "gone, long name and all");
    assert_eq!(names.len(), 14, "`.`, `..` and the 12 others stay");
    for index in [14, 15] {
        let part = volume.read_entry(crate::fat::EntryRef { cluster: dir, index }).unwrap();
        assert_eq!((part[0], part[11]), (0xE5, 0x0F), "a long-name part, deleted");
    }
    let neighbour = volume.read_entry(crate::fat::EntryRef { cluster: dir, index: 13 }).unwrap();
    assert_eq!(&neighbour[..8], b"F11     ", "the entry before the name stays");
    assert!(!volume.is_empty_directory(dir).unwrap());
    let (empty, _) = volume.create_directory(root, "Empty", 3).unwrap();
    assert!(volume.is_empty_directory(empty).unwrap(), "`.` and `..` alone");
}

#[test]
fn a_file_goes_with_the_last_handle_once_its_deletion_is_pending() {
    // DeleteFileW: open with DELETE, FileDispositionInformation, close.
    // Inno Setup's loader deletes its setup.tmp so, NSIS the temporary file
    // whose name becomes its plug-ins directory; neither could.
    use crate::{check_open, File};
    use abi::file::*;
    use abi::ntstatus::*;
    use ob::{AccessMask, HandleAttributes, HandleTable};

    let (volume, disk) = mounted(FSCK_CLUSTERS);
    let table = HandleTable::new();
    let open = |path: &str, options: u32| {
        let file = File::open(&volume, path).unwrap();
        file.begin_open(options).unwrap();
        let handle = table.insert(file.clone(), AccessMask(0x001F_01FF), HandleAttributes::default()).unwrap();
        (file, handle)
    };
    let root = File::open(&volume, "\\").unwrap();
    let free = volume.space().unwrap().free_clusters;
    root.create_child("A temporary file.tmp", false, 0).unwrap().write(0, &[5u8; 3000]).unwrap();

    // Two opens: the file waits for the second.
    let (first, first_handle) = open("\\A temporary file.tmp", 0);
    let (second, second_handle) = open("\\a temporary file.tmp", 0);
    first.set_delete_pending(true).unwrap();
    assert_eq!(second.standard_information().unwrap().delete_pending, 1, "seen by every open");
    let again = File::open(&volume, "\\A temporary file.tmp").unwrap();
    assert_eq!(check_open(&again, FILE_OPEN, 0, AccessMask::NONE), Err(STATUS_DELETE_PENDING));
    table.close(first_handle).unwrap();
    assert!(File::open(&volume, "\\A temporary file.tmp").is_ok(), "the second open still holds it");
    assert_eq!(second.read_all().unwrap(), vec![5u8; 3000]);
    table.close(second_handle).unwrap();
    assert_eq!(File::open(&volume, "\\A temporary file.tmp").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
    assert_eq!(volume.space().unwrap().free_clusters, free, "its clusters given back");
    assert!(volume.list(&volume.root()).unwrap().is_empty());

    // Called off, the file stays; FILE_DELETE_ON_CLOSE deletes it.
    root.create_child("KEEP.TXT", false, 0).unwrap();
    let (kept, kept_handle) = open("\\KEEP.TXT", 0);
    kept.set_delete_pending(true).unwrap();
    kept.set_delete_pending(false).unwrap();
    table.close(kept_handle).unwrap();
    let (_, on_close) = open("\\KEEP.TXT", FILE_DELETE_ON_CLOSE);
    assert!(File::open(&volume, "\\KEEP.TXT").is_ok());
    table.close(on_close).unwrap();
    assert_eq!(File::open(&volume, "\\KEEP.TXT").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));

    // What cannot be deleted: a read-only file, a directory that holds
    // something, the root.
    root.create_child("RO.TXT", false, FILE_ATTRIBUTE_READONLY).unwrap();
    let (locked, locked_handle) = open("\\RO.TXT", 0);
    assert_eq!(locked.set_delete_pending(true), Err(STATUS_CANNOT_DELETE));
    assert_eq!(check_open(&locked, FILE_OPEN, FILE_DELETE_ON_CLOSE, AccessMask::NONE), Err(STATUS_CANNOT_DELETE));
    table.close(locked_handle).unwrap();
    let plugins = root.create_child("nsa1.tmp", true, 0).unwrap();
    plugins.create_child("System.dll", false, 0).unwrap();
    let (full, full_handle) = open("\\nsa1.tmp", 0);
    assert_eq!(full.set_delete_pending(true), Err(STATUS_DIRECTORY_NOT_EMPTY));
    let (dll, dll_handle) = open("\\nsa1.tmp\\System.dll", 0);
    dll.set_delete_pending(true).unwrap();
    table.close(dll_handle).unwrap();
    full.set_delete_pending(true).unwrap();
    table.close(full_handle).unwrap();
    assert_eq!(File::open(&volume, "\\nsa1.tmp").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND), "empty, then gone");
    assert_eq!(root.set_delete_pending(true), Err(STATUS_ACCESS_DENIED));
    let (root_open, root_handle) = open("\\", 0);
    assert_eq!(check_open(&root_open, FILE_OPEN, FILE_DELETE_ON_CLOSE, AccessMask::NONE), Err(STATUS_CANNOT_DELETE));
    table.close(root_handle).unwrap();
    assert_eq!(volume.list(&volume.root()).unwrap(), ["RO.TXT"]);
    drop((root, again, first, second, kept, locked, plugins, full, dll, root_open));

    volume.flush().expect("flush the cached FAT before fsck");
    let bytes = core::mem::take(&mut *disk.0.lock());
    match fsck(&bytes) {
        Some(result) => result.unwrap_or_else(|report| panic!("fsck.vfat: {report}")),
        None => std::eprintln!("fsck.vfat not found: the volume is not checked (dosfstools)"),
    }
}

#[test]
fn an_open_looked_up_before_the_deletion_finds_the_file_gone() {
    // NtCreateFile looks the name up, then counts the open: between the
    // two, another thread could close the last handle of the file whose
    // deletion was pending, and the open counted itself on a deleted entry.
    use crate::File;
    use abi::ntstatus::*;
    use ob::{AccessMask, HandleAttributes, HandleTable};

    let (volume, _disk) = mounted(FSCK_CLUSTERS);
    let table = HandleTable::new();
    let root = File::open(&volume, "\\").unwrap();
    root.create_child("GONE.TMP", false, 0).unwrap().write(0, b"bytes").unwrap();
    let looked_up = File::open(&volume, "\\GONE.TMP").unwrap();
    let holder = File::open(&volume, "\\GONE.TMP").unwrap();
    holder.begin_open(0).unwrap();
    let handle = table.insert(holder.clone(), AccessMask(0x001F_01FF), HandleAttributes::default()).unwrap();
    holder.set_delete_pending(true).unwrap();
    table.close(handle).unwrap();
    assert_eq!(File::open(&volume, "\\GONE.TMP").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND), "deleted");
    assert_eq!(looked_up.begin_open(0), Err(STATUS_OBJECT_NAME_NOT_FOUND), "its entry is gone");
    // Its slot taken by another name: still not the file looked up.
    root.create_child("OTHER.TMP", false, 0).unwrap();
    assert_eq!(looked_up.begin_open(0), Err(STATUS_OBJECT_NAME_NOT_FOUND), "another file's entry");

    // While the deletion is pending, an open fails; one counted before it
    // holds the file, and its failure before the handle lets it go.
    root.create_child("HELD.TMP", false, 0).unwrap();
    let early = File::open(&volume, "\\HELD.TMP").unwrap();
    early.begin_open(0).unwrap();
    let marker = File::open(&volume, "\\HELD.TMP").unwrap();
    marker.begin_open(0).unwrap();
    let marker_handle = table.insert(marker.clone(), AccessMask(0x001F_01FF), HandleAttributes::default()).unwrap();
    marker.set_delete_pending(true).unwrap();
    table.close(marker_handle).unwrap();
    let late = File::open(&volume, "\\HELD.TMP").unwrap();
    assert_eq!(late.begin_open(0), Err(STATUS_DELETE_PENDING));
    assert!(File::open(&volume, "\\HELD.TMP").is_ok(), "the early open holds it");
    early.abandon_open();
    assert_eq!(File::open(&volume, "\\HELD.TMP").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND), "then it goes");
}

#[test]
fn delete_on_close_is_refused_where_nothing_can_be_deleted() {
    use abi::file::{FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_READONLY};
    use abi::ntstatus::{STATUS_CANNOT_DELETE, STATUS_MEDIA_WRITE_PROTECTED};

    let allowed = crate::delete_on_close_allowed;
    assert_eq!(allowed(true, false, FILE_ATTRIBUTE_ARCHIVE), Err(STATUS_MEDIA_WRITE_PROTECTED), "NTFS, read-only");
    assert_eq!(allowed(false, true, 0), Err(STATUS_CANNOT_DELETE), "the root");
    assert_eq!(allowed(false, false, FILE_ATTRIBUTE_READONLY), Err(STATUS_CANNOT_DELETE), "a read-only file");
    assert_eq!(allowed(false, false, FILE_ATTRIBUTE_ARCHIVE), Ok(()));
}

#[test]
fn a_flush_writes_each_dirty_fat_sector_once() {
    let volume = stale(64, u32::MAX);
    let writes = |volume: &FatVolume<Counting>| volume.device().writes.load(core::sync::atomic::Ordering::Relaxed);
    assert!(!volume.is_dirty(), "as mounted");
    let (mut first, mut size) = (0, 0);
    volume.write_file(&mut first, &mut size, 0, &[7u8; 2048], 3).unwrap();
    assert!(volume.is_dirty(), "a chain in the cached FAT");
    let before = writes(&volume);
    volume.flush().unwrap();
    // The four clusters' entries lie in the first FAT sector: once to each
    // of the two copies.
    assert_eq!(writes(&volume) - before, 2);
    assert!(!volume.is_dirty());
    // The marks were never cleared: every flush wrote again each sector
    // ever changed, and the lazy writer would have, every second.
    volume.flush().unwrap();
    assert_eq!(writes(&volume) - before, 2, "nothing left to write");
    // A write in place, without a new cluster: the device has it, its
    // cache may too.
    volume.write_file(&mut first, &mut size, 0, &[8u8; 512], 3).unwrap();
    assert!(volume.is_dirty(), "the device not flushed since");
}

/// A disk the test keeps, to take its bytes as a power cut leaves them; it
/// counts its flushes, and with `fail_flush` refuses them.
struct Watched {
    disk: alloc::sync::Arc<RwDisk>,
    flushes: alloc::sync::Arc<core::sync::atomic::AtomicU32>,
    fail_flush: bool,
}

impl BlockDevice for Watched {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        self.disk.read_sector(lba, out)
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        self.disk.write_sector(lba, data)
    }
    fn flush(&self) -> Result<(), FatError> {
        if self.fail_flush {
            return Err(FatError::Io);
        }
        self.flushes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// A volume of `clusters` clusters on a [`Watched`] disk: the volume, its
/// disk, its count of flushes.
fn watched(
    clusters: u32,
    fail_flush: bool,
) -> (alloc::sync::Arc<crate::Volume>, alloc::sync::Arc<RwDisk>, alloc::sync::Arc<core::sync::atomic::AtomicU32>) {
    let disk = alloc::sync::Arc::new(fat32(clusters));
    let flushes = alloc::sync::Arc::new(core::sync::atomic::AtomicU32::new(0));
    let device = Watched { disk: disk.clone(), flushes: flushes.clone(), fail_flush };
    let volume = crate::Volume::mount(alloc::boxed::Box::new(device)).unwrap();
    (alloc::sync::Arc::new(volume), disk, flushes)
}

/// `fsck.vfat -n` finds `bytes` clean, when it is there.
fn assert_fsck_clean(bytes: &[u8], after: &str) {
    match fsck(bytes) {
        Some(result) => result.unwrap_or_else(|report| panic!("fsck.vfat after {after}: {report}")),
        None => std::eprintln!("fsck.vfat not found: the volume is not checked (dosfstools)"),
    }
}

#[test]
fn a_power_cut_between_two_passes_of_the_lazy_writer_leaves_a_clean_volume() {
    // The `logon` scenario ends by killing QEMU. When explorer had just
    // written its recycle bin, the entries of C:\RECYCLED were on the disk
    // and their chains still in the cached FAT, until the lazy writer's
    // next pass: fsck found an incomplete chain there. The FAT now goes to
    // the disk before the entry that names it, and after a freed chain.
    use crate::File;
    use ob::{AccessMask, HandleAttributes, HandleTable};

    let (volume, disk) = mounted(FSCK_CLUSTERS);
    let cut = || {
        let bytes = disk.0.lock().clone();
        (FatVolume::mount(RwDisk(KSpinLock::new(bytes.clone()))).unwrap(), bytes)
    };
    let root = File::open(&volume, "\\").unwrap();

    // A new directory, and a file in it grown by two writes.
    let bin = root.create_child("RECYCLED", true, 0).unwrap();
    let info = bin.create_child("INFO2", false, 0).unwrap();
    let data = pattern(5000, 7);
    info.write(0, &data[..20]).unwrap();
    info.write(20, &data[20..]).unwrap();
    let (after, bytes) = cut();
    let (dir, _) = after.find_entry(after.root_cluster(), "RECYCLED").unwrap();
    let (entry, _) = after.find_entry(dir.first_cluster, "INFO2").unwrap();
    assert_eq!(read_all(&after, entry.first_cluster, entry.file_size), data, "a file grown");
    drop(after);
    assert_fsck_clean(&bytes, "a file grown");

    // The directory grows by clusters (16 entries in each).
    let names: Vec<String> = (0..40).map(|i| std::format!("F{i}.TXT")).collect();
    for name in &names {
        bin.create_child(name, false, 0).unwrap().write(0, name.as_bytes()).unwrap();
    }
    let (after, bytes) = cut();
    let (dir, _) = after.find_entry(after.root_cluster(), "RECYCLED").unwrap();
    for name in &names {
        let (entry, _) = after.find_entry(dir.first_cluster, name).unwrap();
        assert_eq!(read_all(&after, entry.first_cluster, entry.file_size), name.as_bytes(), "{name}");
    }
    drop(after);
    assert_fsck_clean(&bytes, "a directory grown");

    // A file truncated: its entry, then its freed clusters.
    info.set_size(100).unwrap();
    let (after, bytes) = cut();
    let (dir, _) = after.find_entry(after.root_cluster(), "RECYCLED").unwrap();
    let (entry, _) = after.find_entry(dir.first_cluster, "INFO2").unwrap();
    assert_eq!(read_all(&after, entry.first_cluster, entry.file_size), &data[..100], "a file truncated");
    drop(after);
    assert_fsck_clean(&bytes, "a file truncated");

    // A file deleted with its last handle (DeleteFileW).
    let free = volume.space().unwrap().free_clusters;
    let table = HandleTable::new();
    let doomed = File::open(&volume, "\\RECYCLED\\F0.TXT").unwrap();
    doomed.begin_open(0).unwrap();
    let handle = table.insert(doomed.clone(), AccessMask(0x001F_01FF), HandleAttributes::default()).unwrap();
    doomed.set_delete_pending(true).unwrap();
    table.close(handle).unwrap();
    assert_eq!(volume.space().unwrap().free_clusters, free + 1, "its cluster given back");
    let (after, bytes) = cut();
    let (dir, _) = after.find_entry(after.root_cluster(), "RECYCLED").unwrap();
    assert!(after.find_entry(dir.first_cluster, "F0.TXT").is_err(), "a file deleted");
    assert_eq!(after.free_clusters().map(u64::from), Ok(free + 1), "and its cluster free on the disk");
    drop(after);
    assert_fsck_clean(&bytes, "a file deleted");
}

#[test]
fn after_a_pass_of_the_lazy_writer_a_power_cut_loses_nothing() {
    use crate::lazy_writer::{MountedVolumes, WrittenBehind};
    use crate::File;
    use core::sync::atomic::Ordering;

    let (volume, disk, flushes) = watched(FSCK_CLUSTERS, false);
    let mounted = MountedVolumes::new();
    mounted.register(&volume);
    mounted.register(&volume);
    assert_eq!(mounted.write_behind(), WrittenBehind::default(), "nothing waits after the mount");
    let data = pattern(5000, 3);
    let file = File::open(&volume, "\\").unwrap().create_child("Session.log", false, 0).unwrap();
    file.write(0, &data).unwrap();

    // A power cut now, before the pass: the chain went to the disk before
    // the entry that names it. (It used to stay in the cached FAT: the
    // entry's chain ended on a free cluster.) Only the device's own cache
    // waits for the lazy writer.
    let bytes = disk.0.lock().clone();
    let cut = FatVolume::mount(RwDisk(KSpinLock::new(bytes.clone()))).unwrap();
    let (entry, _) = cut.find_entry(cut.root_cluster(), "Session.log").unwrap();
    assert_eq!(read_all(&cut, entry.first_cluster, entry.file_size), data, "the chain is on the disk");
    drop(cut);
    assert_fsck_clean(&bytes, "a write, before the pass");

    assert!(mounted.is_dirty());
    assert_eq!(mounted.write_behind(), WrittenBehind { volumes: 1, error: None });
    assert_eq!(flushes.load(Ordering::Relaxed), 1, "the device's cache flushed too");
    assert!(!mounted.is_dirty());
    assert_eq!(mounted.write_behind(), WrittenBehind::default(), "nothing left, no device flush");
    assert_eq!(flushes.load(Ordering::Relaxed), 1);

    // A power cut now: the file is whole.
    let bytes = disk.0.lock().clone();
    let cut = FatVolume::mount(RwDisk(KSpinLock::new(bytes.clone()))).unwrap();
    let (entry, _) = cut.find_entry(cut.root_cluster(), "SESSION.LOG").unwrap();
    assert_eq!(read_all(&cut, entry.first_cluster, entry.file_size), data);
    drop(cut);
    assert_fsck_clean(&bytes, "the pass");
}

#[test]
fn the_shutdown_flushes_every_volume_past_an_error() {
    use crate::lazy_writer::MountedVolumes;
    use crate::File;
    use abi::ntstatus::STATUS_IO_DEVICE_ERROR;
    use core::sync::atomic::Ordering;

    let (broken, _, _) = watched(64, true);
    let (sound, disk, flushes) = watched(64, false);
    let mounted = MountedVolumes::new();
    for volume in [&broken, &sound] {
        mounted.register(volume);
        File::open(volume, "\\").unwrap().create_child("A.TXT", false, 0).unwrap().write(0, &[1u8; 1024]).unwrap();
    }
    assert_eq!(mounted.flush(), Err(STATUS_IO_DEVICE_ERROR), "the first error");
    assert_eq!(flushes.load(Ordering::Relaxed), 1, "the volume after it flushed all the same");
    assert!(!sound.is_dirty() && broken.is_dirty(), "a device that refused keeps what waits");
    let cut = FatVolume::mount(RwDisk(KSpinLock::new(disk.0.lock().clone()))).unwrap();
    let (entry, _) = cut.find_entry(cut.root_cluster(), "A.TXT").unwrap();
    assert_eq!(read_all(&cut, entry.first_cluster, entry.file_size), vec![1u8; 1024]);
    let pass = mounted.write_behind();
    assert_eq!((pass.volumes, pass.error), (0, Some(STATUS_IO_DEVICE_ERROR)), "tried again, refused again");
}

#[test]
fn the_locks_of_a_file_are_seen_by_each_of_its_opens_and_go_with_the_last_handle() {
    // msiexec (7-Zip, OpenOffice) opens its package by the structured
    // storage of ole32, which locks byte ranges far past the end of the file
    // (LockFileEx, LOCKFILE_FAIL_IMMEDIATELY) and loops while they conflict.
    use crate::File;
    use abi::ntstatus::*;
    use ob::{AccessMask, HandleAttributes, HandleTable};

    let (volume, _disk) = mounted(FSCK_CLUSTERS);
    let table = HandleTable::new();
    let root = File::open(&volume, "\\").unwrap();
    root.create_child("PACKAGE.MSI", false, 0).unwrap().write(0, &[7u8; 4096]).unwrap();
    let open = |path: &str| {
        let file = File::open(&volume, path).unwrap();
        file.begin_open(0).unwrap();
        let handle = table.insert(file.clone(), AccessMask(0x001F_01FF), HandleAttributes::default()).unwrap();
        (file, handle)
    };
    let (first, first_handle) = open("\\PACKAGE.MSI");
    let (second, second_handle) = open("\\package.msi");
    let a = first.lock_owner(8, 0);
    let b = second.lock_owner(12, 0);

    // A range of the storage's locks, and one in the data.
    first.lock(0x7FFF_FF92, 1, true, a).unwrap();
    first.lock(0, 512, true, a).unwrap();
    assert_eq!(second.lock(0x7FFF_FF92, 1, false, b), Err(STATUS_FILE_LOCK_CONFLICT), "seen by every open");
    assert_eq!(second.check_read(100, 10, b), Err(STATUS_FILE_LOCK_CONFLICT));
    assert_eq!(second.check_write(511, 2, b), Err(STATUS_FILE_LOCK_CONFLICT));
    first.check_write(0, 512, a).unwrap();
    second.check_read(512, 100, b).unwrap();
    assert_eq!(second.unlock(0, 512, b), Err(STATUS_RANGE_NOT_LOCKED));
    first.unlock(0, 512, a).unwrap();
    second.check_write(0, 512, b).unwrap();

    // A directory has no locks.
    assert_eq!(root.lock(0, 1, true, root.lock_owner(8, 0)), Err(STATUS_INVALID_PARAMETER));

    // Its last handle closed, the first open's locks go.
    table.close(first_handle).unwrap();
    second.lock(0x7FFF_FF92, 1, true, b).unwrap();
    table.close(second_handle).unwrap();
    let (third, third_handle) = open("\\PACKAGE.MSI");
    third.lock(0x7FFF_FF92, 1, true, third.lock_owner(16, 0)).unwrap();
    table.close(third_handle).unwrap();
}
