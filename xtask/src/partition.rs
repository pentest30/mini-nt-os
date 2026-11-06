//! GPT system disks for boot tests. Fixed GUIDs identify disposable test
//! images only; an installer must generate new disk and partition GUIDs.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::Result;

struct Disk(File);
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
