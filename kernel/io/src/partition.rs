//! GPT discovery and bounded partition devices. Raw FAT32 system disks
//! remain supported; a protective MBR or GPT signature forbids raw fallback.

use crate::fat::{BlockDevice, FatError};

/// A partition view which cannot address metadata or a neighbouring volume.
pub struct PartitionDevice<D> {
    disk: D,
    first: u64,
    sectors: u64,
}

impl<D: BlockDevice> PartitionDevice<D> {
    /// Checks a nonempty partition against its device's capacity.
    ///
    /// # IRQL
    /// Any level; no I/O or allocation.
    pub fn new(disk: D, capacity: u64, first: u64, sectors: u64) -> Result<Self, FatError> {
        if sectors == 0 || first.checked_add(sectors).is_none_or(|end| end > capacity) {
            return Err(FatError::Corrupt);
        }
        Ok(Self { disk, first, sectors })
    }

    fn translate(&self, lba: u64, len: usize) -> Result<u64, FatError> {
        if lba >= self.sectors || len != self.disk.sector_size() as usize {
            return Err(FatError::Io);
        }
        self.first.checked_add(lba).ok_or(FatError::Io)
    }
}

impl<D: BlockDevice> BlockDevice for PartitionDevice<D> {
    fn sector_size(&self) -> u32 {
        self.disk.sector_size()
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        self.disk.read_sector(self.translate(lba, out.len())?, out)
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        self.disk.write_sector(self.translate(lba, data.len())?, data)
    }
    fn flush(&self) -> Result<(), FatError> {
        self.disk.flush()
    }
}

struct Reader<'a, D>(&'a D);
impl<D: BlockDevice> gpt::ReadSectors for Reader<'_, D> {
    type Error = FatError;
    fn read_sector(&self, lba: u64, out: &mut [u8; 512]) -> Result<(), FatError> {
        self.0.read_sector(lba, out)
    }
}

/// Whether a disk advertises GPT, including a damaged protective table.
/// Used to distinguish an installed primary disk from the virtual FAT ESP.
///
/// # IRQL
/// <= DISPATCH_LEVEL (device I/O may wait actively).
pub fn has_gpt<D: BlockDevice>(disk: &D) -> Result<bool, FatError> {
    if disk.sector_size() != 512 {
        return Ok(false);
    }
    let mut sector = [0; 512];
    disk.read_sector(0, &mut sector)?;
    if gpt::has_protective_partition(&sector) {
        return Ok(true);
    }
    disk.read_sector(1, &mut sector)?;
    Ok(&sector[..8] == b"EFI PART")
}

/// Returns a Basic Data partition of a GPT disk, or the whole raw disk.
/// GPT metadata is fully checked before a partition is exposed. The first
/// Basic Data slot is the system partition; EFI partitions are skipped.
///
/// # IRQL
/// <= DISPATCH_LEVEL (device I/O may wait actively, allocates nonpaged memory).
pub fn system_volume<D: BlockDevice>(disk: D, capacity: u64) -> Result<PartitionDevice<D>, FatError> {
    if disk.sector_size() != 512 || capacity == 0 {
        return Err(FatError::Unsupported);
    }
    let mut mbr = [0; 512];
    disk.read_sector(0, &mut mbr)?;
    let mut header = [0; 512];
    if capacity > 1 {
        disk.read_sector(1, &mut header)?;
    }
    if gpt::has_protective_partition(&mbr) || &header[..8] == b"EFI PART" {
        let (layout, source) = gpt::read(&Reader(&disk), capacity).map_err(|e| match e {
            gpt::Error::Io(e) => e,
            gpt::Error::Invalid(_) => FatError::Corrupt,
        })?;
        let p = layout.partitions().iter().find(|p| p.kind == gpt::BASIC_DATA).ok_or(FatError::Unsupported)?;
        let (first, sectors) = (p.first_lba, p.last_lba - p.first_lba + 1);
        log::info!("Io: GPT system partition {}: LBA {} + {} sectors ({:?})", p.index, first, sectors, source);
        PartitionDevice::new(disk, capacity, first, sectors)
    } else {
        PartitionDevice::new(disk, capacity, 0, capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    struct Disk(Arc<AtomicU64>);
    impl BlockDevice for Disk {
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_sector(&self, lba: u64, _out: &mut [u8]) -> Result<(), FatError> {
            self.0.store(lba, Ordering::SeqCst);
            Ok(())
        }
        fn write_sector(&self, lba: u64, _out: &[u8]) -> Result<(), FatError> {
            self.0.store(lba, Ordering::SeqCst);
            Ok(())
        }
        fn flush(&self) -> Result<(), FatError> {
            Err(FatError::ReadOnly)
        }
    }
    #[test]
    fn partition_translates_and_bounds_reads_and_writes() {
        let last = Arc::new(AtomicU64::new(0));
        let p = PartitionDevice::new(Disk(last.clone()), 100, 10, 20).unwrap();
        p.read_sector(0, &mut [0; 512]).unwrap();
        assert_eq!(last.load(Ordering::SeqCst), 10);
        p.write_sector(19, &[0; 512]).unwrap();
        assert_eq!(last.load(Ordering::SeqCst), 29);
        assert_eq!(p.read_sector(20, &mut [0; 512]), Err(FatError::Io));
        assert_eq!(p.write_sector(u64::MAX, &[0; 512]), Err(FatError::Io));
        assert_eq!(p.read_sector(0, &mut [0; 511]), Err(FatError::Io));
        assert_eq!(last.load(Ordering::SeqCst), 29);
        assert_eq!(p.flush(), Err(FatError::ReadOnly));
        for (first, size) in [(u64::MAX, 2), (99, 2), (0, 0)] {
            assert!(PartitionDevice::new(Disk(last.clone()), 100, first, size).is_err());
        }
    }
}
