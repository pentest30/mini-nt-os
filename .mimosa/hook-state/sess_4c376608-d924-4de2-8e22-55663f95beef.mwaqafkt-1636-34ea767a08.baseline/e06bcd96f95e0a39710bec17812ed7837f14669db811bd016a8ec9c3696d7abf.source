//! Development installation images: plan first, then write a new file.
//! The layout planner has no I/O and can later drive a console or GUI review.
//! This is image construction, not an in-guest installer or a raw-disk tool.

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::partition::Disk;
use crate::Result;

const ALIGNMENT: u64 = 2048;

/// Sizes and positions shown before any destination is created.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub esp_first: u64,
    pub esp_sectors: u64,
    pub system_first: u64,
    pub system_sectors: u64,
    pub total_sectors: u64,
}

impl Plan {
    /// Both FAT images must be nonempty whole sectors. All arithmetic is checked.
    pub fn new(esp_bytes: u64, system_bytes: u64) -> Result<Self> {
        if esp_bytes == 0 || system_bytes == 0 || !esp_bytes.is_multiple_of(512) || !system_bytes.is_multiple_of(512) {
            return Err("partition images must contain nonempty whole 512-byte sectors".into());
        }
        let esp_sectors = esp_bytes / 512;
        let system_sectors = system_bytes / 512;
        let system_first = ALIGNMENT
            .checked_add(esp_sectors)
            .and_then(|n| n.checked_add(ALIGNMENT - 1))
            .map(|n| n / ALIGNMENT * ALIGNMENT)
            .ok_or("image size overflow")?;
        let total_sectors =
            system_first.checked_add(system_sectors).and_then(|n| n.checked_add(33)).ok_or("image size overflow")?;
        total_sectors.checked_mul(512).ok_or("image size overflow")?;
        Ok(Self { esp_first: ALIGNMENT, esp_sectors, system_first, system_sectors, total_sectors })
    }

    fn layout(&self) -> Result<gpt::Layout> {
        let part = |index, kind, first, sectors, label: &str| {
            let mut name = [0; 36];
            for (dst, src) in name.iter_mut().zip(label.encode_utf16()) {
                *dst = src;
            }
            gpt::Partition {
                index,
                kind,
                id: [index as u8 + 0x50; 16],
                first_lba: first,
                last_lba: first + sectors - 1,
                attributes: 0,
                name,
            }
        };
        // Stable GUIDs for development images, not identifiers for a deployed
        // installer. Clones need fresh identifiers before independent use.
        gpt::Layout::new(
            self.total_sectors,
            [0x50; 16],
            vec![
                part(1, gpt::EFI_SYSTEM, self.esp_first, self.esp_sectors, "Mino Boot"),
                part(2, gpt::BASIC_DATA, self.system_first, self.system_sectors, "Mino System"),
            ],
        )
        .map_err(|e| format!("installation layout: {e:?}"))
    }
}

/// Builds the ESP using the existing FAT writer and places it alongside the
/// system FAT image in a GPT disk. Refuses existing destinations, including
/// device paths. All source files and the plan are checked before creation.
pub fn create(esp_dir: &Path, output: &Path) -> Result<Plan> {
    let read = |path: &Path| fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
    let system = read(&esp_dir.join("fat.img"))?;
    let esp = fatfs::build(&[
        (fatfs::path("EFI/BOOT/BOOTX64.EFI")?, read(&esp_dir.join("EFI/BOOT/BOOTX64.EFI"))?),
        (fatfs::path("kernel.elf")?, read(&esp_dir.join("kernel.elf"))?),
        (fatfs::path("fat.img")?, system.clone()),
    ])?;
    let plan = Plan::new(esp.len() as u64, system.len() as u64)?;
    let layout = plan.layout()?;
    println!(
        "Install plan: EFI {} MiB at LBA {}; system {} MiB at LBA {}; disk {} MiB",
        plan.esp_sectors / 2048,
        plan.esp_first,
        plan.system_sectors / 2048,
        plan.system_first,
        plan.total_sectors / 2048
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| format!("{}: {e} (destination must not exist)", output.display()))?;
    let write = || -> Result<()> {
        let mut disk = Disk(file);
        disk.0.set_len(plan.total_sectors * 512).map_err(|e| e.to_string())?;
        gpt::write(&mut disk, &layout).map_err(|e| format!("GPT: {e:?}"))?;
        for (first, bytes) in [(plan.esp_first, &esp), (plan.system_first, &system)] {
            disk.0.seek(SeekFrom::Start(first * 512)).map_err(|e| e.to_string())?;
            disk.0.write_all(bytes).map_err(|e| e.to_string())?;
        }
        disk.0.sync_all().map_err(|e| e.to_string())?;
        let (actual, source) = gpt::read(&disk, plan.total_sectors).map_err(|e| format!("GPT verification: {e:?}"))?;
        if actual != layout || source != gpt::Source::Both {
            return Err("written layout differs from plan".into());
        }
        Ok(())
    };
    if let Err(e) = write() {
        // Only a file just created by this operation can be removed here.
        let _ = fs::remove_file(output);
        return Err(e);
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_is_aligned_nonoverlapping_and_checked() {
        let plan = Plan::new(34_123_264, 34_123_264).unwrap();
        assert_eq!(plan.esp_first % 2048, 0);
        assert_eq!(plan.system_first % 2048, 0);
        assert!(plan.system_first >= plan.esp_first + plan.esp_sectors);
        assert_eq!(plan.total_sectors, plan.system_first + plan.system_sectors + 33);
        let layout = plan.layout().unwrap();
        assert_eq!(layout.partitions()[0].kind, gpt::EFI_SYSTEM);
        assert_eq!(layout.partitions()[1].kind, gpt::BASIC_DATA);
        for (esp, system) in [(0, 512), (512, 0), (513, 512), (512, 513), (u64::MAX - 511, 512)] {
            assert!(Plan::new(esp, system).is_err());
        }
    }
    #[test]
    fn missing_sources_do_not_create_destination() {
        let path = std::env::temp_dir().join(format!("mino-missing-source-{}.img", std::process::id()));
        assert!(!path.exists());
        assert!(create(Path::new("missing-installer-source"), &path).is_err());
        assert!(!path.exists());
    }
}
