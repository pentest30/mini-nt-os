//! Les disques (02 §8) : un disque ATA en PIO (`hal::ata`), vu comme
//! périphérique de blocs de secteurs de 512 octets.
//! `hal::ata` sérialise chaque commande complète par canal, même entre copies
//! d’AtaDisk, partitions, volumes et disques maître/esclave.
//!
//! Pas encore : piles de périphériques et IRP, virtio-blk. Les partitions GPT sont découvertes par
//! `partition`, qui expose une vue bornée du volume système.

use hal::ata::AtaDrive;

use crate::fat::{BlockDevice, FatError};

/// Le plus de secteurs qu'une commande READ SECTORS lit.
const COMMAND_SECTORS: usize = 256;

/// Un disque ATA et son nombre de secteurs.
#[derive(Clone)]
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

    /// The sectors in commands of 256 sectors at most (READ SECTORS takes
    /// up to 256): one command for a run of contiguous clusters, where a
    /// sector each cost a command apiece.
    fn read_sectors(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        let count = (out.len() / 512) as u64;
        if out.is_empty()
            || !out.len().is_multiple_of(512)
            || lba.checked_add(count).is_none_or(|end| end > self.sectors)
        {
            return Err(FatError::Io);
        }
        for (i, chunk) in out.chunks_mut(COMMAND_SECTORS * 512).enumerate() {
            let at = lba + (i * COMMAND_SECTORS) as u64;
            self.drive.read_sectors(at, chunk).map_err(|_| FatError::Io)?;
        }
        Ok(())
    }

    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        self.check(lba, data.len())?;
        self.drive.write_sectors(lba, data).map_err(|_| FatError::Io)
    }

    fn flush(&self) -> Result<(), FatError> {
        self.drive.flush().map_err(|_| FatError::Io)
    }
}
