//! Les disques (02 §8) : un disque ATA en PIO (`hal::ata`), vu comme
//! périphérique de blocs de secteurs de 512 octets.
//!
//! Pas encore : piles de périphériques et IRP, partitions (le disque porte
//! un seul volume, sans table de partitions), virtio-blk.

use hal::ata::AtaDrive;

use crate::fat::{BlockDevice, FatError};

/// Un disque ATA et son nombre de secteurs.
pub struct AtaDisk {
    drive: AtaDrive,
    sectors: u64,
}

impl AtaDisk {
    /// Le disque `drive`, s'il y en a un (IDENTIFY DEVICE).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (attente active).
    pub fn probe(drive: AtaDrive) -> Option<Self> {
        drive.identify().ok().filter(|&sectors| sectors > 0).map(|sectors| Self { drive, sectors })
    }

    /// Son nombre de secteurs.
    pub fn sectors(&self) -> u64 {
        self.sectors
    }

    fn check(&self, lba: u64, length: usize) -> Result<(), FatError> {
        if length != 512 || lba >= self.sectors {
            return Err(FatError::Io);
        }
        Ok(())
    }
}

impl BlockDevice for AtaDisk {
    fn sector_size(&self) -> u32 {
        512
    }

    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        self.check(lba, out.len())?;
        self.drive.read_sectors(lba, out).map_err(|_| FatError::Io)
    }

    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        self.check(lba, data.len())?;
        self.drive.write_sectors(lba, data).map_err(|_| FatError::Io)
    }

    fn flush(&self) -> Result<(), FatError> {
        self.drive.flush().map_err(|_| FatError::Io)
    }
}
