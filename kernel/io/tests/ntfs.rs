//! Real-image adapter test. Explicitly run with ntfs-3g tools on PATH.
use abi::{file::*, ntstatus::*, object::AccessMask};
use io_manager::{
    fat::{BlockDevice, FatError},
    partition::PartitionDevice,
    volume::Volume,
    File,
};
use std::{
    fs,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct Disk {
    data: Arc<Vec<u8>>,
    writes: Arc<AtomicUsize>,
}
impl BlockDevice for Disk {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        let offset = usize::try_from(lba.checked_mul(512).ok_or(FatError::Io)?).map_err(|_| FatError::Io)?;
        out.copy_from_slice(self.data.get(offset..offset + 512).ok_or(FatError::Io)?);
        Ok(())
    }
    fn write_sector(&self, _: u64, _: &[u8]) -> Result<(), FatError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        Err(FatError::Io)
    }
    fn flush(&self) -> Result<(), FatError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        Err(FatError::Io)
    }
}
fn run(name: &str, args: &[&str]) {
    let out = Command::new(name).args(args).output().expect("ntfs-3g tool on PATH");
    assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
}
struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
#[ignore = "requires mkntfs and ntfscp on PATH"]
fn real_ntfs_partition_uses_file_api_and_never_writes() {
    let dir = Scratch(std::env::temp_dir().join(format!("mino-ntfs-io-{}", std::process::id())));
    fs::create_dir_all(&dir.0).unwrap();
    let image = dir.0.join("volume.img");
    let image_path = image.to_str().unwrap();
    fs::File::create(&image).unwrap().set_len(32 * 1024 * 1024).unwrap();
    run("mkntfs", &["-F", "-Q", "-s", "512", "-c", "4096", "-L", "MinoData", image_path]);
    let expected: Vec<u8> = (0..131195).map(|n| (n % 251) as u8).collect();
    let source = dir.0.join("source");
    fs::write(&source, &expected).unwrap();
    run("ntfscp", &[image_path, source.to_str().unwrap(), "/Été.bin"]);
    // ntfscp accepts Unicode text; replace the private-use leading unit in
    // both FILE_NAME and $I30. Ordering stays after the other fixture names.
    run("ntfscp", &[image_path, source.to_str().unwrap(), "/\u{e000}-surrogate.txt"]);
    let mut raw = fs::read(&image).unwrap();
    let placeholder: Vec<u8> = "\u{e000}-surrogate.txt".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let offsets: Vec<_> = raw
        .windows(placeholder.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == placeholder).then_some(i))
        .collect();
    assert_eq!(offsets.len(), 2, "FILE_NAME and root index name");
    for at in offsets {
        raw[at..at + 2].copy_from_slice(&0xd800u16.to_le_bytes());
    }
    let mut unusual: Vec<u16> = "\u{e000}-surrogate.txt".encode_utf16().collect();
    unusual[0] = 0xd800;
    let sectors = raw.len() as u64 / 512;
    let mut data = vec![0xa5; raw.len() + 4 * 512];
    data[3 * 512..3 * 512 + raw.len()].copy_from_slice(&raw);
    let data = Arc::new(data);
    let writes = Arc::new(AtomicUsize::new(0));
    let partition =
        PartitionDevice::new(Disk { data: data.clone(), writes: writes.clone() }, sectors + 4, 3, sectors).unwrap();
    let volume = Arc::new(Volume::mount_partition(Box::new(partition), sectors).unwrap());
    assert_eq!(volume.filesystem_name(), "NTFS");
    assert!(volume.is_read_only());
    assert_eq!(volume.label().unwrap().label, "MinoData".encode_utf16().collect::<Vec<_>>());
    assert!(volume.space().unwrap().free_clusters > 0);
    let file = File::open(&volume, "\\ÉTÉ.BIN").unwrap();
    assert_eq!(file.node().unwrap().size, expected.len() as u64);
    assert_ne!(file.node().unwrap().creation_time, 0);
    assert_eq!(file.read_all().unwrap(), expected);
    let mut bytes = [0xff; 16];
    assert_eq!(file.read(expected.len() as u64 - 5, &mut bytes).unwrap(), 5);
    assert_eq!(&bytes[..5], &expected[expected.len() - 5..]);
    assert_eq!(&bytes[5..], &[0xff; 11]);
    assert_eq!(file.read(u64::MAX, &mut bytes).unwrap(), 0);
    let root = File::open(&volume, "\\").unwrap();
    let entries = volume.entries(&volume.root()).unwrap();
    assert!(entries.iter().any(|e| e.name == unusual));
    assert!(entries.iter().any(|e| e.name == "Été.bin".encode_utf16().collect::<Vec<_>>()));
    let (names, status) = root.query_directory(FILE_NAMES_INFORMATION, 4096, false, Some(&unusual), true).unwrap();
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(u32::from_le_bytes(names[8..12].try_into().unwrap()) as usize, unusual.len() * 2);
    assert_eq!(&names[12..12 + unusual.len() * 2], unusual.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>());
    assert_eq!(root.open_relative("été.bin").unwrap().node().unwrap().size, expected.len() as u64);
    assert!(matches!(root.open_relative("missing\\child"), Err(STATUS_OBJECT_PATH_NOT_FOUND)));
    assert!(matches!(root.open_relative("missing"), Err(STATUS_OBJECT_NAME_NOT_FOUND)));
    assert_eq!(file.write(0, b"changed"), Err(STATUS_MEDIA_WRITE_PROTECTED));
    assert_eq!(file.set_size(0), Err(STATUS_MEDIA_WRITE_PROTECTED));
    assert_eq!(file.set_basic_information(&FileBasicInformation::default()), Err(STATUS_MEDIA_WRITE_PROTECTED));
    assert!(matches!(root.create_child("new.txt", false, 0), Err(STATUS_MEDIA_WRITE_PROTECTED)));
    for access in [FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, AccessMask::DELETE.0] {
        assert_eq!(io_manager::check_open(&file, FILE_OPEN, 0, AccessMask(access)), Err(STATUS_MEDIA_WRITE_PROTECTED));
    }
    assert_eq!(
        io_manager::check_open(&file, FILE_OVERWRITE, 0, AccessMask(FILE_READ_DATA)),
        Err(STATUS_MEDIA_WRITE_PROTECTED)
    );
    assert!(io_manager::check_open(&file, FILE_OPEN, 0, AccessMask(FILE_READ_DATA)).is_ok());
    for desired in
        [AccessMask::GENERIC_READ, AccessMask::MAXIMUM_ALLOWED, AccessMask::MAXIMUM_ALLOWED | AccessMask::GENERIC_READ]
    {
        let granted = file.granted_access(desired).unwrap();
        assert!(granted.contains(AccessMask(FILE_READ_DATA)));
        io_manager::check_open(&file, FILE_OPEN, 0, granted).unwrap();
        let table = ob::HandleTable::new();
        let handle = table.insert(file.clone(), granted, Default::default()).unwrap();
        assert_eq!(table.query(handle).unwrap().0, granted);
        assert!(table.reference_as::<File>(handle, &io_manager::FILE_TYPE, AccessMask(FILE_READ_DATA)).is_ok());
        for denied in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_EA,
            FILE_DELETE_CHILD,
            AccessMask::DELETE.0,
            AccessMask::WRITE_DAC.0,
            AccessMask::WRITE_OWNER.0,
        ] {
            assert!(matches!(
                table.reference_as::<File>(handle, &io_manager::FILE_TYPE, AccessMask(denied)),
                Err(STATUS_ACCESS_DENIED)
            ));
        }
    }
    for desired in
        [AccessMask::GENERIC_WRITE, AccessMask::GENERIC_ALL, AccessMask::MAXIMUM_ALLOWED | AccessMask(FILE_WRITE_DATA)]
    {
        assert_eq!(file.granted_access(desired), Err(STATUS_MEDIA_WRITE_PROTECTED));
    }
    file.flush().unwrap();
    drop(file);
    drop(root);
    drop(volume);
    assert_eq!(writes.load(Ordering::Relaxed), 0, "including flush and drop");
    assert_eq!(&data[3 * 512..3 * 512 + raw.len()], raw.as_slice());
}
