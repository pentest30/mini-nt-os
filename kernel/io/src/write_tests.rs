//! Tests of writing to a FAT32 volume, on a disk in memory formatted as
//! `tools/mkfat` does (32 reserved sectors, two FATs, 512-byte clusters).
//! A volume of at least 65 525 clusters is checked by `fsck.vfat -n` when
//! dosfstools is installed.

extern crate std;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hal::sync::KSpinLock;

use crate::fat::{make_entry, short_name, BlockDevice, FatError, FatFile, FatVolume};

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

fn read_all(volume: &FatVolume<RwDisk>, first_cluster: u32, size: u32) -> Vec<u8> {
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
    let (dir, _) = volume.create_directory(root, &short_name("SUB").unwrap(), 3).unwrap();
    let (inner, _) = volume.create_directory(dir, &short_name("INNER").unwrap(), 3).unwrap();
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
    assert_eq!(logs.create_child("A long name.txt", false, 0).err(), Some(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(logs.create_child("bad*name", false, 0).err(), Some(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(file.create_child("x", false, 0).err(), Some(STATUS_OBJECT_PATH_NOT_FOUND), "under a file");
    assert_eq!(logs.write(0, b"x").err(), Some(STATUS_INVALID_DEVICE_REQUEST), "writing a directory");
    let locked = root.create_child("RO.TXT", false, FILE_ATTRIBUTE_READONLY).unwrap();
    let write = ob::AccessMask(FILE_WRITE_DATA);
    assert_eq!(check_open(&locked, FILE_OPEN, 0, write), Err(STATUS_ACCESS_DENIED));
    let many: Vec<_> = (0..30).map(|i| logs.create_child(&std::format!("N{i}.LOG"), false, 0).unwrap()).collect();
    many[29].write(0, &[9u8; 2000]).unwrap();
    assert_eq!(File::open(&volume, "\\Logs\\n29.log").unwrap().read_all().unwrap(), vec![9u8; 2000]);
    drop((root, logs, file, other, locked, many));

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
