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
    let raw = fs::read(&image).unwrap();
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
    assert_eq!(volume.label().unwrap().label, "MinoData");
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
    assert!(root.list().unwrap().contains(&"Été.bin".to_string()));
    assert!(root.query_directory(FILE_NAMES_INFORMATION, 4096, false, None, true).is_ok());
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
    file.flush().unwrap();
    drop(file);
    drop(root);
    drop(volume);
    assert_eq!(writes.load(Ordering::Relaxed), 0, "including flush and drop");
    assert_eq!(&data[3 * 512..3 * 512 + raw.len()], raw.as_slice());
}
