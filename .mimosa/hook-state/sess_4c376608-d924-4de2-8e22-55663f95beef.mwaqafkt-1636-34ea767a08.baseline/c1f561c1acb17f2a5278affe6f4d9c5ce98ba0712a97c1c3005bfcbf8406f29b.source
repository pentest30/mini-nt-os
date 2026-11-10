//! Incremental FAT32 quick format, using constant working memory.
//!
//! Addresses are relative to the volume, not the enclosing disk. The caller
//! must provide exclusive access to an unmounted volume. Free data clusters
//! are left untouched: this is not a secure erase. An I/O error can leave a
//! partially formatted volume; it must not be mounted as a successful format.

use crate::image::{boot_sector, fs_info_sector, END_OF_CHAIN, FAT_COUNT, MIN_CLUSTERS, RESERVED_SECTORS, SECTOR};

/// A writable volume of 512-byte sectors. Implementations enforce bounds and
/// translate volume-relative LBAs to their device's addresses.
pub trait WriteSectors {
    /// The device's write or flush error, preserved by the formatter.
    type Error;

    /// Writes exactly one sector at the volume-relative `lba`.
    fn write_sector(&mut self, lba: u32, sector: &[u8; SECTOR]) -> Result<(), Self::Error>;

    /// Makes all successful writes reach the backing medium.
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// Why a format could not complete.
#[derive(Debug, PartialEq, Eq)]
pub enum FormatError<E> {
    /// The volume cannot hold FAT32 with one 512-byte sector per cluster.
    InvalidSize,
    /// The backing device rejected a write or flush.
    Io(E),
}

/// The geometry of a FAT32 volume, including both FAT copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Total number of 512-byte sectors, including metadata.
    pub total_sectors: u32,
    /// Number of sectors in each FAT.
    pub fat_sectors: u32,
    /// First data sector; cluster 2 (the root directory) starts here.
    pub data_start: u32,
    /// Number of data clusters, including the root directory.
    pub clusters: u32,
}

impl Geometry {
    /// Calculates geometry without writing. Returns `None` for a FAT16-sized
    /// volume or cluster numbers that would overlap FAT32's reserved values.
    pub fn for_sectors(total_sectors: u32) -> Option<Self> {
        let available = total_sectors.checked_sub(RESERVED_SECTORS as u32)?;
        // f * (512 / 4) >= (available - 2*f) + 2, including the two
        // reserved FAT entries. u64 also covers the largest u32 volume.
        let fat_sectors = (u64::from(available) + 2).div_ceil((SECTOR / 4 + FAT_COUNT) as u64) as u32;
        let data_start = RESERVED_SECTORS as u32 + FAT_COUNT as u32 * fat_sectors;
        let clusters = total_sectors.checked_sub(data_start)?;
        // The last cluster is clusters + 1; 0x0FFF_FFF0 is reserved.
        if !(MIN_CLUSTERS as u32..=0x0FFF_FFEE).contains(&clusters) {
            return None;
        }
        Some(Self { total_sectors, fat_sectors, data_start, clusters })
    }
}

/// Quick-formats `total_sectors` sectors as an empty FAT32 volume.
///
/// Clears the reserved area, both FATs, and the root directory, then writes
/// the boot/FSInfo sectors and their backups and flushes the device. Size is
/// validated before any write. Uses the same headers as [`crate::image::build`].
pub fn format<D: WriteSectors>(device: &mut D, total_sectors: u32) -> Result<Geometry, FormatError<D::Error>> {
    let geometry = Geometry::for_sectors(total_sectors).ok_or(FormatError::InvalidSize)?;
    let zero = [0u8; SECTOR];
    for lba in 0..=geometry.data_start {
        device.write_sector(lba, &zero).map_err(FormatError::Io)?;
    }
    let mut fat = [0u8; SECTOR];
    fat[..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    fat[4..8].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
    fat[8..12].copy_from_slice(&END_OF_CHAIN.to_le_bytes()); // root directory
    for copy in 0..FAT_COUNT as u32 {
        device.write_sector(RESERVED_SECTORS as u32 + copy * geometry.fat_sectors, &fat).map_err(FormatError::Io)?;
    }
    let boot = boot_sector(total_sectors, geometry.fat_sectors);
    let info = fs_info_sector();
    for (lba, sector) in [(1, &info), (7, &info), (6, &boot), (0, &boot)] {
        device.write_sector(lba, sector).map_err(FormatError::Io)?;
    }
    device.flush().map_err(FormatError::Io)?;
    Ok(geometry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use io_manager::{BlockDevice, FatError, FatVolume};

    struct Disk {
        bytes: Vec<u8>,
        remaining: usize,
        flushed: bool,
        fail_flush: bool,
    }

    impl Disk {
        fn new(sectors: u32, fill: u8) -> Self {
            Self {
                bytes: vec![fill; sectors as usize * SECTOR],
                remaining: usize::MAX,
                flushed: false,
                fail_flush: false,
            }
        }
    }

    impl WriteSectors for Disk {
        type Error = &'static str;

        fn write_sector(&mut self, lba: u32, sector: &[u8; SECTOR]) -> Result<(), Self::Error> {
            if self.remaining == 0 {
                return Err("write failed");
            }
            self.remaining -= 1;
            let at = lba as usize * SECTOR;
            self.bytes[at..at + SECTOR].copy_from_slice(sector);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            if self.fail_flush {
                return Err("flush failed");
            }
            self.flushed = true;
            Ok(())
        }
    }

    impl BlockDevice for Disk {
        fn sector_size(&self) -> u32 {
            SECTOR as u32
        }

        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
            let at = lba as usize * SECTOR;
            out.copy_from_slice(self.bytes.get(at..at + SECTOR).ok_or(FatError::Io)?);
            Ok(())
        }
    }

    const SECTORS: u32 = 70_000;

    #[test]
    fn empty_image_and_incremental_format_are_identical() {
        let image = crate::build(&[]).unwrap();
        let mut disk = Disk::new((image.len() / SECTOR) as u32, 0);
        let sectors = (disk.bytes.len() / SECTOR) as u32;
        format(&mut disk, sectors).unwrap();
        assert_eq!(disk.bytes, image);
        assert!(disk.flushed);
    }

    #[test]
    fn dirty_metadata_is_cleared_but_free_data_is_untouched() {
        let mut disk = Disk::new(SECTORS, 0xA5);
        let geometry = format(&mut disk, SECTORS).unwrap();
        let root = geometry.data_start as usize * SECTOR;
        assert!(disk.bytes[root..root + SECTOR].iter().all(|&b| b == 0));
        assert!(disk.bytes[root + SECTOR..].iter().all(|&b| b == 0xA5));
        let fat = RESERVED_SECTORS * SECTOR;
        let fat_len = geometry.fat_sectors as usize * SECTOR;
        assert_eq!(&disk.bytes[fat..fat + fat_len], &disk.bytes[fat + fat_len..fat + 2 * fat_len]);
        assert!(disk.bytes[fat + 12..fat + fat_len].iter().all(|&b| b == 0));
        assert_eq!(&disk.bytes[..SECTOR], &disk.bytes[6 * SECTOR..7 * SECTOR]);
        assert_eq!(&disk.bytes[SECTOR..2 * SECTOR], &disk.bytes[7 * SECTOR..8 * SECTOR]);
        assert!(disk.bytes[2 * SECTOR..6 * SECTOR].iter().all(|&b| b == 0));
        if let Some(result) = crate::image::fsck(&disk.bytes) {
            result.unwrap();
        }
        let volume = FatVolume::mount(disk).unwrap();
        assert!(volume.list_dir("/").unwrap().is_empty());
    }

    #[test]
    fn geometry_covers_fat_sector_boundaries_and_size_limits() {
        for sectors in 66_600..67_000 {
            let g = Geometry::for_sectors(sectors).unwrap();
            assert!(u64::from(g.fat_sectors) * 128 >= u64::from(g.clusters) + 2);
            assert_eq!(g.data_start + g.clusters, sectors);
        }
        let first = (65_525..67_000).find(|&n| Geometry::for_sectors(n).is_some()).unwrap();
        assert_eq!(Geometry::for_sectors(first).unwrap().clusters, MIN_CLUSTERS as u32);
        assert!(Geometry::for_sectors(first - 1).is_none());
        for sectors in [0, 31, 32, 33, 65_525, u32::MAX] {
            assert!(Geometry::for_sectors(sectors).is_none());
        }
    }

    #[test]
    fn invalid_size_does_not_touch_the_device() {
        let mut disk = Disk::new(1, 0xA5);
        assert_eq!(format(&mut disk, 1), Err(FormatError::InvalidSize));
        assert_eq!(disk.remaining, usize::MAX);
        assert!(!disk.flushed);
        assert!(disk.bytes.iter().all(|&b| b == 0xA5));
    }

    #[test]
    fn write_and_flush_errors_are_preserved() {
        let writes = Geometry::for_sectors(SECTORS).unwrap().data_start as usize + 7;
        for remaining in [0, 50, writes - 6, writes - 5, writes - 4, writes - 3, writes - 2, writes - 1] {
            let mut disk = Disk::new(SECTORS, 0xA5);
            disk.remaining = remaining;
            assert_eq!(format(&mut disk, SECTORS), Err(FormatError::Io("write failed")));
            assert_eq!(disk.remaining, 0);
            assert!(!disk.flushed);
        }
        let mut disk = Disk::new(SECTORS, 0);
        disk.fail_flush = true;
        assert_eq!(format(&mut disk, SECTORS), Err(FormatError::Io("flush failed")));
        assert!(!disk.flushed);
    }
}
