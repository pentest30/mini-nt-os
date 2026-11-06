//! Cross-component checks: GPT + the FAT formatter + the kernel's reader.
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use io_manager::{
    partition::{system_volume, PartitionDevice},
    BlockDevice, FatError, FatVolume,
};

#[derive(Clone)]
struct Disk(Rc<RefCell<Vec<u8>>>);
impl BlockDevice for Disk {
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        let at = lba as usize * 512;
        out.copy_from_slice(self.0.borrow().get(at..at + 512).ok_or(FatError::Io)?);
        Ok(())
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        let at = lba as usize * 512;
        self.0.borrow_mut().get_mut(at..at + 512).ok_or(FatError::Io)?.copy_from_slice(data);
        Ok(())
    }
}
impl gpt::ReadSectors for Disk {
    type Error = FatError;
    fn read_sector(&self, lba: u64, out: &mut [u8; 512]) -> Result<(), FatError> {
        BlockDevice::read_sector(self, lba, out)
    }
}
impl gpt::WriteSectors for Disk {
    fn write_sector(&mut self, lba: u64, data: &[u8; 512]) -> Result<(), FatError> {
        BlockDevice::write_sector(self, lba, data)
    }
    fn flush(&mut self) -> Result<(), FatError> {
        Ok(())
    }
}
struct Format(PartitionDevice<Disk>);
impl crate::format::WriteSectors for Format {
    type Error = FatError;
    fn write_sector(&mut self, lba: u32, data: &[u8; 512]) -> Result<(), FatError> {
        self.0.write_sector(u64::from(lba), data)
    }
    fn flush(&mut self) -> Result<(), FatError> {
        self.0.flush()
    }
}
fn disk() -> (Disk, u64, u32) {
    let image = crate::build(&[(crate::path("HELLO.TXT").unwrap(), b"GPT payload".to_vec())]).unwrap();
    let size = (image.len() / 512) as u32;
    let sectors = u64::from(size) + 2048 + 33;
    let mut bytes = vec![0x5a; sectors as usize * 512];
    bytes[2048 * 512..2048 * 512 + image.len()].copy_from_slice(&image);
    let mut disk = Disk(Rc::new(RefCell::new(bytes)));
    let part = |index, kind, first_lba, last_lba| gpt::Partition {
        index,
        kind,
        id: [index as u8; 16],
        first_lba,
        last_lba,
        attributes: 0,
        name: [0; 36],
    };
    let layout = gpt::Layout::new(
        sectors,
        [0x41; 16],
        vec![part(1, gpt::EFI_SYSTEM, 128, 1023), part(2, gpt::BASIC_DATA, 2048, 2048 + u64::from(size) - 1)],
    )
    .unwrap();
    gpt::write(&mut disk, &layout).unwrap();
    (disk, sectors, size)
}
#[test]
fn kernel_skips_efi_and_reads_fat_inside_basic_data_partition() {
    let (disk, sectors, _) = disk();
    assert!(io_manager::partition::has_gpt(&disk).unwrap());
    let raw = Disk(Rc::new(RefCell::new(crate::build(&[]).unwrap())));
    assert!(!io_manager::partition::has_gpt(&raw).unwrap());
    let volume = FatVolume::mount(system_volume(disk, sectors).unwrap()).unwrap();
    let mut file = volume.open("/HELLO.TXT").unwrap();
    let mut out = [0; 11];
    assert_eq!(volume.read(&mut file, &mut out), Ok(11));
    assert_eq!(&out, b"GPT payload");
}
#[test]
fn formatting_a_partition_preserves_both_gpt_copies_and_its_neighbour() {
    let (disk, sectors, size) = disk();
    let before = gpt::read(&disk, sectors).unwrap();
    let mut target = Format(system_volume(disk.clone(), sectors).unwrap());
    crate::format::format(&mut target, size).unwrap();
    assert_eq!(gpt::read(&disk, sectors).unwrap(), before);
    assert!(disk.0.borrow()[128 * 512..1024 * 512].iter().all(|&b| b == 0x5a));
    let volume = FatVolume::mount(target.0).unwrap();
    assert!(volume.list_dir("/").unwrap().is_empty());
}
#[test]
fn corrupt_primary_uses_backup_but_two_bad_copies_never_mount_as_raw_fat() {
    let (disk, sectors, _) = disk();
    disk.0.borrow_mut()[512] ^= 1;
    assert!(FatVolume::mount(system_volume(disk.clone(), sectors).unwrap()).is_ok());
    disk.0.borrow_mut()[(sectors as usize - 1) * 512] ^= 1;
    assert!(matches!(system_volume(disk, sectors), Err(FatError::Corrupt)));
}
