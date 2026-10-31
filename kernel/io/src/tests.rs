//! Tests of the volume, the files and the devices, on a small FAT32 disk in
//! memory:
//!
//! ```text
//! \BOOT.INI                      "hello"
//! \WINDOWS\SYSTEM32\NTDLL.DLL    600 bytes, two clusters, written 2004-08-04 12:34:56
//! \WINDOWS\SYSTEM32\CONFIG\      empty
//! ```

extern crate std;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::file::*;
use abi::ntstatus::*;
use ob::{downcast, Namespace, ObjectRef, SymbolicLink};

use crate::fat::{BlockDevice, FatError};
use crate::{check_open, Device, File, Volume, DEVICE_TYPE, FILE_TYPE};

struct Disk(Vec<u8>);

impl BlockDevice for Disk {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        let at = lba as usize * 512;
        out.copy_from_slice(self.0.get(at..at + 512).ok_or(FatError::Io)?);
        Ok(())
    }
}

const NTDLL_SIZE: usize = 600;
const WRITE_DATE: u16 = 12548; // 2004-08-04
const WRITE_TIME: u16 = 25692; // 12:34:56

fn ntdll_byte(i: usize) -> u8 {
    (i * 7) as u8
}

/// A directory entry.
fn entry(name: &[u8; 11], attr: u8, cluster: u16, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    e[26..28].copy_from_slice(&cluster.to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

fn disk() -> Disk {
    let sectors = 2 + 7; // BPB, FAT, clusters 2 to 8
    let mut d = alloc::vec![0u8; sectors * 512];
    d[11..13].copy_from_slice(&512u16.to_le_bytes());
    d[13] = 1;
    d[14..16].copy_from_slice(&1u16.to_le_bytes());
    d[16] = 1;
    d[32..36].copy_from_slice(&(sectors as u32).to_le_bytes());
    d[36..40].copy_from_slice(&1u32.to_le_bytes());
    d[44..48].copy_from_slice(&2u32.to_le_bytes());
    let eoc = 0x0FFF_FFFFu32;
    let fat = [0x0FFF_FFF8, 0xFFFF_FFFF, eoc, eoc, eoc, 6, eoc, eoc, eoc];
    for (i, next) in fat.iter().enumerate() {
        d[512 + 4 * i..512 + 4 * i + 4].copy_from_slice(&next.to_le_bytes());
    }
    let mut cluster = |c: usize, entries: &[[u8; 32]]| {
        let at = 1024 + (c - 2) * 512;
        for (i, e) in entries.iter().enumerate() {
            d[at + 32 * i..at + 32 * (i + 1)].copy_from_slice(e);
        }
    };
    cluster(2, &[entry(b"WINDOWS    ", 0x10, 3, 0), entry(b"BOOT    INI", 0x20, 7, 5)]);
    cluster(
        3,
        &[entry(b".          ", 0x10, 3, 0), entry(b"..         ", 0x10, 0, 0), entry(b"SYSTEM32   ", 0x10, 4, 0)],
    );
    let mut ntdll = entry(b"NTDLL   DLL", 0x21, 5, NTDLL_SIZE as u32);
    ntdll[22..24].copy_from_slice(&WRITE_TIME.to_le_bytes());
    ntdll[24..26].copy_from_slice(&WRITE_DATE.to_le_bytes());
    cluster(
        4,
        &[
            entry(b".          ", 0x10, 4, 0),
            entry(b"..         ", 0x10, 3, 0),
            ntdll,
            entry(b"CONFIG     ", 0x10, 8, 0),
        ],
    );
    cluster(8, &[entry(b".          ", 0x10, 8, 0), entry(b"..         ", 0x10, 4, 0)]);
    for i in 0..NTDLL_SIZE {
        d[1024 + 3 * 512 + i] = ntdll_byte(i);
    }
    d[1024 + 5 * 512..1024 + 5 * 512 + 5].copy_from_slice(b"hello");
    Disk(d)
}

fn volume() -> Arc<Volume> {
    Arc::new(Volume::mount(Box::new(disk())).expect("a FAT32 volume"))
}

#[test]
fn names_resolve_without_case() {
    let volume = volume();
    let root = volume.root();
    let ntdll = volume.lookup(&root, "windows\\System32\\NTDLL.dll").unwrap();
    assert!(!ntdll.directory);
    assert_eq!((ntdll.size, ntdll.attributes), (600, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE));
    assert_eq!(ntdll.last_write_time, crate::fat::nt_time(WRITE_DATE, WRITE_TIME, 0));
    assert_ne!(ntdll.last_write_time, 0);
    let system32 = volume.lookup(&root, "WINDOWS\\SYSTEM32").unwrap();
    assert!(system32.directory);
    assert_eq!(system32.attributes, FILE_ATTRIBUTE_DIRECTORY);
    assert_eq!(volume.lookup(&system32, "config\\").map(|n| n.directory), Ok(true), "a trailing \\ on a directory");
    assert_eq!(volume.lookup(&root, "BOOT.INI").map(|n| n.size), Ok(5));
}

#[test]
fn bad_names_say_why() {
    let volume = volume();
    let root = volume.root();
    let status = |path| volume.lookup(&root, path).err();
    assert_eq!(status("WINDOWS\\MISSING.DLL"), Some(STATUS_OBJECT_NAME_NOT_FOUND));
    assert_eq!(status("WINDOWS\\NOWHERE\\X"), Some(STATUS_OBJECT_PATH_NOT_FOUND));
    assert_eq!(status("BOOT.INI\\X"), Some(STATUS_OBJECT_PATH_NOT_FOUND), "a file has no children");
    assert_eq!(status("BOOT.INI\\"), Some(STATUS_OBJECT_NAME_INVALID), "a trailing \\ on a file");
    assert_eq!(status("WINDOWS\\\\SYSTEM32"), Some(STATUS_OBJECT_NAME_INVALID), "an empty component");
    assert_eq!(status("WINDOWS\\..\\BOOT.INI"), Some(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(status("WIN*"), Some(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(status("A long name.txt"), Some(STATUS_OBJECT_NAME_NOT_FOUND), "no long names yet");
}

#[test]
fn a_file_reads_across_clusters() {
    let volume = volume();
    let file = File::open(&volume, "\\WINDOWS\\SYSTEM32\\NTDLL.DLL").unwrap();
    let all = file.read_all().unwrap();
    assert_eq!(all.len(), NTDLL_SIZE);
    assert!(all.iter().enumerate().all(|(i, &b)| b == ntdll_byte(i)));
    let mut tail = [0u8; 100];
    assert_eq!(file.read(550, &mut tail), Ok(50), "up to the end");
    assert_eq!(tail[0], ntdll_byte(550));
    assert_eq!(file.read(600, &mut tail), Ok(0), "at the end");
    let directory = File::open(&volume, "\\WINDOWS").unwrap();
    assert_eq!(directory.read(0, &mut tail), Err(STATUS_INVALID_DEVICE_REQUEST));
}

#[test]
fn a_file_describes_itself() {
    let volume = volume();
    let file = File::open(&volume, "\\WINDOWS\\SYSTEM32\\NTDLL.DLL").unwrap();
    assert_eq!(file.path(), "\\WINDOWS\\SYSTEM32\\NTDLL.DLL");
    let standard = file.standard_information();
    assert_eq!((standard.allocation_size, standard.end_of_file, standard.directory), (1024, 600, 0));
    assert_eq!(standard.number_of_links, 1);
    let basic = file.basic_information();
    assert_eq!(basic.file_attributes, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE);
    assert_eq!((basic.last_write_time, basic.change_time), (file.node().last_write_time, file.node().last_write_time));
    let open = file.network_open_information();
    assert_eq!((open.allocation_size, open.end_of_file, open.file_attributes), (1024, 600, basic.file_attributes));
    let root = File::open(&volume, "\\").unwrap();
    assert_eq!((root.path(), root.is_directory()), ("\\", true));
    assert_eq!(root.standard_information().directory, 1);
}

#[test]
fn a_name_relative_to_a_directory() {
    let volume = volume();
    let system32 = File::open(&volume, "\\WINDOWS\\SYSTEM32\\").unwrap();
    assert_eq!(system32.path(), "\\WINDOWS\\SYSTEM32");
    let ntdll = system32.open_relative("ntdll.dll").unwrap();
    assert_eq!((ntdll.path(), ntdll.node().size), ("\\WINDOWS\\SYSTEM32\\ntdll.dll", 600));
    assert_eq!(ntdll.open_relative("x").err(), Some(STATUS_OBJECT_PATH_NOT_FOUND), "relative to a file");
    let root = File::open(&volume, "\\").unwrap();
    assert_eq!(root.open_relative("BOOT.INI").map(|f| String::from(f.path())), Ok(String::from("\\BOOT.INI")));
}

#[test]
fn check_open_follows_the_disposition_and_the_options() {
    let volume = volume();
    let file = File::open(&volume, "\\BOOT.INI").unwrap();
    let directory = File::open(&volume, "\\WINDOWS").unwrap();
    assert_eq!(check_open(&file, FILE_OPEN, 0), Ok(FILE_OPENED));
    assert_eq!(check_open(&file, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE), Ok(FILE_OPENED));
    assert_eq!(check_open(&directory, FILE_OPEN, FILE_DIRECTORY_FILE), Ok(FILE_OPENED));
    assert_eq!(check_open(&file, FILE_OPEN, FILE_DIRECTORY_FILE), Err(STATUS_NOT_A_DIRECTORY));
    assert_eq!(check_open(&directory, FILE_OPEN, FILE_NON_DIRECTORY_FILE), Err(STATUS_FILE_IS_A_DIRECTORY));
    assert_eq!(check_open(&file, FILE_CREATE, 0), Err(STATUS_OBJECT_NAME_COLLISION));
    assert_eq!(check_open(&file, FILE_OVERWRITE_IF, 0), Err(STATUS_MEDIA_WRITE_PROTECTED));
    assert_eq!(check_open(&file, FILE_SUPERSEDE, 0), Err(STATUS_MEDIA_WRITE_PROTECTED));
    let both = FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE;
    assert_eq!(check_open(&directory, FILE_OPEN, both), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(check_open(&directory, FILE_OVERWRITE, FILE_DIRECTORY_FILE), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(check_open(&file, 6, 0), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn the_namespace_reaches_files_through_the_drive_letter() {
    let ns = Namespace::new();
    let device: ObjectRef = Device::with_volume(Volume::mount(Box::new(disk())).unwrap());
    ns.insert(&device, "\\Device\\Ramdisk0", None, 0).unwrap();
    let c: ObjectRef = SymbolicLink::create("\\Device\\Ramdisk0");
    ns.insert(&c, "\\GLOBAL??\\C:", None, 0).unwrap();
    let system_root: ObjectRef = SymbolicLink::create("\\Device\\Ramdisk0\\WINDOWS");
    ns.insert(&system_root, "\\SystemRoot", None, 0).unwrap();

    let file = |object: ObjectRef| downcast::<File>(&object).expect("a file");
    let system32 = ns.open("\\??\\C:\\WINDOWS\\system32", None, Some(&FILE_TYPE), 0).unwrap();
    assert_eq!(file(system32.clone()).path(), "\\WINDOWS\\system32");
    let ntdll = ns.open("ntdll.dll", Some(&system32), Some(&FILE_TYPE), 0).unwrap();
    assert_eq!(file(ntdll).node().size, 600);
    let through_root = ns.open("\\SystemRoot\\System32\\NTDLL.DLL", None, Some(&FILE_TYPE), 0).unwrap();
    assert_eq!(file(through_root).path(), "\\WINDOWS\\System32\\NTDLL.DLL");
    let root = ns.open("\\??\\C:\\", None, Some(&FILE_TYPE), 0).unwrap();
    assert!(file(root).is_directory());
    assert!(ns.open("\\??\\C:", None, None, 0).unwrap().is_type(&DEVICE_TYPE), "the device itself");
    assert_eq!(ns.open("\\??\\C:", None, Some(&FILE_TYPE), 0).err(), Some(STATUS_OBJECT_TYPE_MISMATCH));
    assert_eq!(
        ns.open("\\??\\C:\\WINDOWS\\NOPE.DLL", None, Some(&FILE_TYPE), 0).err(),
        Some(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(ns.open("\\??\\D:\\X", None, None, 0).err(), Some(STATUS_OBJECT_PATH_NOT_FOUND), "no D:");
}
