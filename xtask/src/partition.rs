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

/// Checks the installer's result on the 96 MiB disposable target: a
/// canonical two-partition GPT with both copies valid, and — read back by
/// the host's own FAT32 reader, independent of the kernel's — each volume
/// walking whole, every file's chain intact (the DLLs with their MZ, the
/// hives of CONFIG with their regf, the long names with their checksums),
/// free clusters left, and the system volume holding exactly the tree of
/// `ramdisk`, the image the copy read: every file, by its long name, with
/// its size and its bytes. When the ESP holds files (the installer booted
/// from a real GPT disk), they are the three boot files of the run's ESP,
/// `ramdisk`'s directory, byte for byte, plus `MINO.TAG`, which makes the
/// loader prefer the installed ESP while the installation medium is attached.
pub fn verify_setup_target(image: &Path, ramdisk: &Path) -> Result<()> {
    let verify = || -> std::io::Result<()> {
        const EXPECTED_BYTES: u64 = 96 * 1024 * 1024;
        const ESP_FIRST: u64 = 2048;
        // The plan of the kernel (io_manager::install): 48 MiB of ESP.
        const ESP_SECTORS: u64 = 48 * 2048;

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

        // L'ESP : un volume FAT32 qui se lit et se marche. Son contenu dépend
        // du média de démarrage : sous QEMU, l'ESP virtuelle FAT16 ne se
        // monte pas et les fichiers de boot ne se copient pas ; depuis une
        // image GPT, l'ESP cible tient le chargeur, le noyau et le ramdisk
        // du run, à l'octet près.
        let esp_sectors = partitions[0].last_lba - partitions[0].first_lba + 1;
        let esp = crate::fat32::Fat32::read(&mut disk.0, partitions[0].first_lba, esp_sectors)
            .map_err(std::io::Error::other)?;
        let esp_tree = esp.walk().map_err(std::io::Error::other)?;
        if esp_tree.files != 0 {
            let run_esp = ramdisk.parent().ok_or_else(|| std::io::Error::other("the ramdisk has no directory"))?;
            let boot_files = [
                ("EFI/BOOT/BOOTX64.EFI", "EFI/BOOT/BOOTX64.EFI"),
                ("kernel.elf", "KERNEL.ELF"),
                ("fat.img", "FAT.IMG"),
            ];
            if esp_tree.files != boot_files.len() as u32 + 1 {
                return Err(std::io::Error::other(format!(
                    "the ESP holds {} files, not the 3 boot files and installation marker",
                    esp_tree.files
                )));
            }
            for (host, on_esp) in boot_files {
                let bytes = std::fs::read(run_esp.join(host))?;
                match esp_tree.contents.get(on_esp) {
                    Some(&(size, hash)) if size as usize == bytes.len() && hash == crate::fat32::fnv1a(&bytes) => {}
                    Some(_) => return Err(std::io::Error::other(format!("ESP {on_esp}: not the run's {host}"))),
                    None => return Err(std::io::Error::other(format!("ESP {on_esp} is missing"))),
                }
            }
            let marker = b"Mino installed\r\n";
            match esp_tree.contents.get("MINO.TAG") {
                Some(&(size, hash)) if size as usize == marker.len() && hash == crate::fat32::fnv1a(marker) => {}
                Some(_) => return Err(std::io::Error::other("ESP MINO.TAG: invalid installation marker")),
                None => return Err(std::io::Error::other("ESP MINO.TAG is missing")),
            }
        }

        // Le volume système : l'arbre copié, relu et vérifié en entier.
        let system_sectors = partitions[1].last_lba - partitions[1].first_lba + 1;
        let system = crate::fat32::Fat32::read(&mut disk.0, partitions[1].first_lba, system_sectors)
            .map_err(std::io::Error::other)?;
        let stats = system.walk().map_err(std::io::Error::other)?;
        if stats.free_clusters == 0 {
            return Err(std::io::Error::other("the system volume has no free cluster left"));
        }

        // La source de la copie : le ramdisk du démarrage (`fat.img`), relu
        // par le même lecteur. La cible doit en tenir chaque fichier, sous
        // son nom long, avec sa taille et ses octets. Elle peut en tenir
        // plus : les self-tests du démarrage écrivent sur le ramdisk avant la
        // copie (`minotest.txt`, `MinoDir`, un nom long…), que le noyau copie
        // aussi ; leurs chaînes sont vérifiées par la marche. (Sans espace
        // utilisateur, le ramdisk n'a que quelques fichiers : la comparaison
        // vaut pour tous les scénarios.)
        let mut source_file = File::open(ramdisk)?;
        let source_sectors = source_file.metadata()?.len() / 512;
        let source_tree = crate::fat32::Fat32::read(&mut source_file, 0, source_sectors)
            .and_then(|volume| volume.walk())
            .map_err(|e| std::io::Error::other(format!("{}: {e}", ramdisk.display())))?;
        if source_tree.files == 0 {
            return Err(std::io::Error::other(format!("{}: an empty source tree", ramdisk.display())));
        }
        const BOOTSTRAP_WINLOGON: &str = "WINDOWS/SYSTEM32/WINLOGON.EXE";
        const REAL_WINLOGON: &str = "WINDOWS/SYSTEM32/WINLOGON.ORG";
        let restores_winlogon = source_tree.contents.contains_key(REAL_WINLOGON);
        for (path, &(size, hash)) in &source_tree.contents {
            if restores_winlogon && path == BOOTSTRAP_WINLOGON {
                // SETUP1.EXE booted the installation medium under this name;
                // it must not become the installed Winlogon.
                continue;
            }
            let installed_path = if restores_winlogon && path == REAL_WINLOGON { BOOTSTRAP_WINLOGON } else { path };
            match stats.contents.get(installed_path) {
                None => return Err(std::io::Error::other(format!("{installed_path} did not persist"))),
                Some(&(copied, _)) if copied != size => {
                    return Err(std::io::Error::other(format!(
                        "{installed_path}: {copied} bytes copied, {size} in the source"
                    )));
                }
                Some(&(_, copied)) if copied != hash => {
                    return Err(std::io::Error::other(format!("{installed_path}: the bytes differ from the source")));
                }
                Some(_) => {}
            }
        }
        if restores_winlogon && stats.contents.contains_key(REAL_WINLOGON) {
            return Err(std::io::Error::other("the temporary WINLOGON.ORG reached the installed system"));
        }
        if stats.directories < source_tree.directories {
            return Err(std::io::Error::other(format!(
                "{} directories copied, {} in the source",
                stats.directories, source_tree.directories
            )));
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
