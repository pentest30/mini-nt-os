//! GPT system disks for boot tests. Fixed GUIDs identify disposable test
//! images only; an installer must generate new disk and partition GUIDs.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::Result;

pub(crate) struct Disk(pub(crate) File);
impl gpt::ReadSectors for Disk {
    type Error = std::io::Error;
    fn read_sector(&self, lba: u64, out: &mut [u8; 512]) -> std::io::Result<()> {
        let mut file = &self.0;
        file.seek(SeekFrom::Start(lba.checked_mul(512).ok_or(std::io::ErrorKind::InvalidInput)?))?;
        file.read_exact(out)
    }
}
impl gpt::WriteSectors for Disk {
    fn write_sector(&mut self, lba: u64, data: &[u8; 512]) -> std::io::Result<()> {
        self.0.seek(SeekFrom::Start(lba.checked_mul(512).ok_or(std::io::ErrorKind::InvalidInput)?))?;
        self.0.write_all(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.sync_all()
    }
}

/// Wraps the FAT image in a Basic Data partition aligned to 1 MiB. Leaves
/// 1 MiB before it and enough trailing space for the backup table/header.
pub fn create(volume: &Path, image: &Path) -> Result<()> {
    let create = || -> std::io::Result<()> {
        let mut source = File::open(volume)?;
        let bytes = source.metadata()?.len();
        if bytes == 0 || bytes % 512 != 0 {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let sectors = bytes / 512;
        let total =
            2048u64.checked_add(sectors).and_then(|n| n.checked_add(33)).ok_or(std::io::ErrorKind::InvalidInput)?;
        let mut disk = Disk(OpenOptions::new().read(true).write(true).create(true).truncate(true).open(image)?);
        disk.0.set_len(total.checked_mul(512).ok_or(std::io::ErrorKind::InvalidInput)?)?;
        let layout = gpt::Layout::new(
            total,
            [0x41; 16],
            vec![gpt::Partition {
                index: 1,
                kind: gpt::BASIC_DATA,
                id: [0x42; 16],
                first_lba: 2048,
                last_lba: 2048 + sectors - 1,
                attributes: 0,
                name: [0; 36],
            }],
        )
        .map_err(|e| std::io::Error::other(format!("GPT layout: {e:?}")))?;
        gpt::write(&mut disk, &layout).map_err(|e| std::io::Error::other(format!("GPT write: {e:?}")))?;
        disk.0.seek(SeekFrom::Start(2048 * 512))?;
        std::io::copy(&mut source, &mut disk.0)?;
        disk.0.sync_all()
    };
    create().map_err(|e| format!("{}: {e}", image.display()))
}

/// Verifies both GPT copies after the boots and extracts only the volume
/// for fsck.vfat. The on-disk partition is not modified by the checker.
pub fn extract(image: &Path) -> Result<PathBuf> {
    let extract = || -> std::io::Result<PathBuf> {
        let mut disk = Disk(File::open(image)?);
        let bytes = disk.0.metadata()?.len();
        if bytes % 512 != 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let (layout, source) =
            gpt::read(&disk, bytes / 512).map_err(|e| std::io::Error::other(format!("GPT read: {e:?}")))?;
        if source != gpt::Source::Both {
            return Err(std::io::Error::other("both GPT copies must survive the boots"));
        }
        let p = layout.partitions().iter().find(|p| p.kind == gpt::BASIC_DATA).ok_or(std::io::ErrorKind::NotFound)?;
        let start = p.first_lba * 512;
        let bytes = (p.last_lba - p.first_lba + 1) * 512;
        disk.0.seek(SeekFrom::Start(start))?;
        let out = image.with_extension("volume.img");
        let mut file = File::create(&out)?;
        if std::io::copy(&mut disk.0.take(bytes), &mut file)? != bytes {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        Ok(out)
    };
    extract().map_err(|e| format!("{}: {e}", image.display()))
}

/// Checks the first writable installer milestone: a canonical two-partition
/// GPT on the 96 MiB disposable target, with both copies valid, each volume
/// carrying Mino's FAT32 boot sector over its written metadata prefix, and
/// every free cluster still zero.
pub fn verify_setup_target(image: &Path) -> Result<()> {
    let verify = || -> std::io::Result<()> {
        const EXPECTED_BYTES: u64 = 96 * 1024 * 1024;
        const ESP_FIRST: u64 = 2048;
        const ESP_SECTORS: u64 = 40 * 2048;

        let mut disk = Disk(File::open(image)?);
        let bytes = disk.0.metadata()?.len();
        if bytes != EXPECTED_BYTES {
            return Err(std::io::Error::other(format!("expected a 96 MiB target, got {bytes} bytes")));
        }
        let sectors = bytes / 512;
        let (layout, source) =
            gpt::read(&disk, sectors).map_err(|e| std::io::Error::other(format!("GPT read: {e:?}")))?;
        if source != gpt::Source::Both {
            return Err(std::io::Error::other("primary and backup GPT copies are not both valid"));
        }
        let partitions = layout.partitions();
        let system_first = ESP_FIRST + ESP_SECTORS;
        if layout.id() == [0; 16]
            || partitions.len() != 2
            || partitions[0].index != 1
            || partitions[0].kind != gpt::EFI_SYSTEM
            || partitions[0].id == [0; 16]
            || partitions[0].first_lba != ESP_FIRST
            || partitions[0].last_lba + 1 != system_first
            || partitions[1].index != 2
            || partitions[1].kind != gpt::BASIC_DATA
            || partitions[1].id == [0; 16]
            || partitions[1].id == partitions[0].id
            || partitions[1].first_lba != system_first
            || partitions[1].last_lba != sectors - 34
        {
            return Err(std::io::Error::other("installer GPT does not match its immutable two-partition plan"));
        }

        disk.0.seek(SeekFrom::Start(34 * 512))?;
        let mut remaining = (sectors - 67) * 512;
        let mut buffer = [0u8; 64 * 1024];
        // Le formatage rapide écrit la zone réservée, les deux FATs et le
        // répertoire racine de chaque volume (leur secteur de boot porte la
        // signature de Mino) ; les clusters libres d'un disque vierge
        // restent à zéro.
        let system_first = ESP_FIRST + ESP_SECTORS;
        let system_sectors = sectors - 34 - system_first;
        let esp_geometry = fatfs::format::Geometry::for_sectors(u32::try_from(ESP_SECTORS).unwrap())
            .ok_or_else(|| std::io::Error::other("the ESP geometry"))?;
        let system_geometry = fatfs::format::Geometry::for_sectors(u32::try_from(system_sectors).unwrap())
            .ok_or_else(|| std::io::Error::other("the system geometry"))?;
        let written_prefix = |lba: u64| -> bool {
            (lba >= ESP_FIRST && lba < ESP_FIRST + u64::from(esp_geometry.data_start) + 1)
                || (lba >= system_first && lba < system_first + u64::from(system_geometry.data_start) + 1)
        };
        let mut lba = 34u64;
        while remaining != 0 {
            let take = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
            disk.0.read_exact(&mut buffer[..take])?;
            for at in 0..take / 512 {
                let sector = &buffer[at * 512..(at + 1) * 512];
                if lba == ESP_FIRST || lba == system_first {
                    if sector[510..512] != [0x55, 0xAA] || &sector[3..11] != b"MINO    " {
                        return Err(std::io::Error::other(format!("the FAT32 boot sector at LBA {lba} is not Mino's")));
                    }
                } else if !written_prefix(lba) && sector.iter().any(|&byte| byte != 0) {
                    return Err(std::io::Error::other("a partition-content sector was modified"));
                }
                lba += 1;
            }
            remaining -= take as u64;
        }
        Ok(())
    };
    verify().map_err(|e| format!("{}: {e}", image.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrapping_and_extracting_preserves_the_volume() {
        let root = std::env::temp_dir().join(format!("mino-gpt-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let volume = root.join("fat.img");
        let image = root.join("c.img");
        let bytes = vec![0xa5; 4096];
        std::fs::write(&volume, &bytes).unwrap();
        create(&volume, &image).unwrap();
        let extracted = extract(&image).unwrap();
        assert_eq!(std::fs::read(extracted).unwrap(), bytes);
        std::fs::remove_dir_all(root).unwrap();
    }
}
