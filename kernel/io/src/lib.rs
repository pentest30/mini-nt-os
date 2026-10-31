//! Io — gestionnaire d'E/S (02 §5.6).
//!
//! - [`volume`] : un système de fichiers monté (FAT32, ADR-017), en lecture.
//! - [`device`] : le type `Device` ; un périphérique qui porte un volume
//!   résout la suite d'un nom en fichier (IopParseDevice).
//! - [`file`] : le type `File`, les fichiers ouverts, et ce que NtCreateFile
//!   vérifie une fois le fichier trouvé.
//!
//! Au démarrage, [`mount_boot_volume`] fait du disque RAM le volume système :
//! `\Device\Ramdisk0`, avec `\??\C:` et `\SystemRoot` qui y mènent.
//!
//! Pas encore : IRP et piles de périphériques, pilotes de disque, écriture,
//! E/S asynchrones, ports de complétion.
//!
//! Le reste de ce module (`open_fat_file`, `open_game_file`, le volume
//! « demo », [`DeviceObject`], [`Irp`]) sert l'ancienne architecture : ne pas
//! l'étendre (audit §5).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::mem::ManuallyDrop;
use hal::sync::KSpinLock;

pub mod device;
pub mod driver;
pub mod fat;
pub mod file;
pub mod irp;
pub mod volume;

pub use device::{Device, DEVICE_TYPE};
pub use driver::{DeviceObject, DriverObject};
pub use fat::{BlockDevice, DirEntry, DirEntryInfo, Fat32Bpb, FatError, FatFile, FatVolume};
pub use file::{check_open, File, FileObject, FILE_TYPE};
pub use irp::{Irp, IrpMajor};
pub use volume::{Node, Volume};

/// Le volume de démarrage.
pub const BOOT_VOLUME: &str = "\\Device\\Ramdisk0";
/// Les liens qui y mènent : la lettre `C:`, et `\SystemRoot`, le
/// répertoire du système.
pub const BOOT_LINKS: [(&str, &str); 2] =
    [("\\GLOBAL??\\C:", BOOT_VOLUME), ("\\SystemRoot", "\\Device\\Ramdisk0\\WINDOWS")];

/// Fait du disque RAM de démarrage le volume système, en attendant les
/// pilotes de disque (ADR-017) : son système de fichiers monté sur le
/// périphérique [`BOOT_VOLUME`], et les liens [`BOOT_LINKS`], permanents.
/// Rend sa taille, ou `None` sans disque RAM.
///
/// # IRQL
/// PASSIVE_LEVEL, une fois, après [`init`] et `ob::init`.
pub fn mount_boot_volume() -> Result<Option<u64>, abi::ntstatus::NtStatus> {
    let Some(disk) = ramdisk_device() else { return Ok(None) };
    let size = disk.total_size as u64;
    let volume = Volume::mount(alloc::boxed::Box::new(disk))?;
    let namespace = ob::namespace();
    let device: ob::ObjectRef = Device::with_volume(volume);
    namespace.insert(&device, BOOT_VOLUME, None, abi::object::OBJ_PERMANENT)?;
    for (name, target) in BOOT_LINKS {
        let link: ob::ObjectRef = ob::SymbolicLink::create(target);
        namespace.insert(&link, name, None, abi::object::OBJ_PERMANENT)?;
    }
    Ok(Some(size))
}

struct RamBlockDevice {
    sector_size: u32,
    data_addr: usize,
    data_len: usize,
}

struct PhysRamBlockDevice {
    sector_size: u32,
    phys_base: u64,
    total_size: usize,
    hhdm_offset: u64,
}

impl BlockDevice for RamBlockDevice {
    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        let s = self.sector_size as usize;
        if out.len() != s {
            return Err(FatError::Io);
        }
        let off = lba as usize * s;
        let end = off + s;
        if end > self.data_len {
            return Err(FatError::Io);
        }
        // SAFETY: data_addr..data_addr+data_len is valid for reads; out is valid for writes.
        unsafe {
            core::ptr::copy_nonoverlapping((self.data_addr as *const u8).add(off), out.as_mut_ptr(), s);
        }
        Ok(())
    }
}

impl BlockDevice for PhysRamBlockDevice {
    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        let s = self.sector_size as usize;
        if out.len() != s {
            return Err(FatError::Io);
        }
        let off = lba as usize * s;
        let end = off + s;
        if end > self.total_size {
            return Err(FatError::Io);
        }
        // SAFETY: HHDM maps all physical RAM; phys_base..+total_size is the ramdisk.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.hhdm_offset + self.phys_base + off as u64) as *const u8,
                out.as_mut_ptr(),
                s,
            );
        }
        Ok(())
    }
}

/// Bulk-read a file directly from the physical ramdisk, bypassing sector-by-sector I/O.
/// Walks the FAT chain once using direct memory reads, detects contiguous cluster runs,
/// and copies each run with a single memcpy.  O(clusters) with zero heap allocations
/// for the chain walk.
pub fn read_fat_file_bulk(file: &mut FatFile, out: &mut [u8]) -> Result<usize, FatError> {
    prep_rep_ops();
    let (phys, size, hhdm) = *RAMDISK_SOURCE.lock();
    if phys == 0 || size < 512 {
        // Fall back to normal read
        return read_fat_file(file, out);
    }
    let base_ptr = (hhdm + phys) as *const u8;
    let total_size = size as usize;

    // Parse BPB from sector 0
    if total_size < 48 {
        return Err(FatError::InvalidBpb);
    }
    // SAFETY: base_ptr..+total_size is mapped via HHDM.
    let bps = unsafe { u16::from_le_bytes([*base_ptr.add(11), *base_ptr.add(12)]) } as usize;
    let spc = unsafe { *base_ptr.add(13) } as usize;
    let rsvd = unsafe { u16::from_le_bytes([*base_ptr.add(14), *base_ptr.add(15)]) } as usize;
    let fats = unsafe { *base_ptr.add(16) } as usize;
    let spf =
        unsafe { u32::from_le_bytes([*base_ptr.add(36), *base_ptr.add(37), *base_ptr.add(38), *base_ptr.add(39)]) }
            as usize;
    if bps == 0 || spc == 0 || rsvd == 0 || fats == 0 {
        return Err(FatError::InvalidBpb);
    }
    let bpc = bps * spc; // bytes per cluster
    let fat_start = rsvd * bps; // FAT byte offset in ramdisk
    let data_start = (rsvd + fats * spf) * bps; // data area byte offset

    let remaining = (file.file_size.saturating_sub(file.position)) as usize;
    let target = remaining.min(out.len());
    if target == 0 {
        return Ok(0);
    }

    // Walk to the starting cluster (skip past file.position)
    let mut cluster = file.first_cluster;
    let mut skip_clusters = file.position as usize / bpc;
    while skip_clusters > 0 {
        cluster = fat_next(base_ptr, fat_start, cluster)?;
        skip_clusters -= 1;
    }
    let mut cluster_offset = file.position as usize % bpc;
    let mut written = 0usize;

    while written < target {
        // Detect contiguous run starting at `cluster`
        let run_start = cluster;
        let mut run_len = 1u32;
        loop {
            let next = fat_next(base_ptr, fat_start, run_start + run_len - 1);
            match next {
                Ok(n) if n == run_start + run_len => {
                    run_len += 1;
                }
                _ => break,
            }
        }

        // Copy from the contiguous run
        let run_data_off = data_start + (run_start as usize - 2) * bpc;
        let run_bytes = run_len as usize * bpc;
        let src_start = run_data_off + cluster_offset;
        let can_take = (run_bytes - cluster_offset).min(target - written);

        if src_start + can_take > total_size {
            return Err(FatError::Io);
        }

        // SAFETY: src is within ramdisk HHDM mapping; out is caller-provided.
        unsafe {
            core::ptr::copy_nonoverlapping(base_ptr.add(src_start), out.as_mut_ptr().add(written), can_take);
        }
        written += can_take;
        cluster_offset = 0;

        if written < target {
            // Advance past this run
            cluster = fat_next(base_ptr, fat_start, run_start + run_len - 1)?;
        }
    }

    file.position = file.position.saturating_add(written as u32);
    Ok(written)
}

/// Read a FAT32 chain entry directly from ramdisk memory. Zero allocations.
fn fat_next(base_ptr: *const u8, fat_byte_offset: usize, cluster: u32) -> Result<u32, FatError> {
    let off = fat_byte_offset + cluster as usize * 4;
    // SAFETY: FAT table is within the ramdisk mapping.
    let raw = unsafe {
        u32::from_le_bytes([*base_ptr.add(off), *base_ptr.add(off + 1), *base_ptr.add(off + 2), *base_ptr.add(off + 3)])
    } & 0x0FFF_FFFF;
    if !(2..0x0FFF_FFF8).contains(&raw) {
        Err(FatError::NotFound) // EOF or invalid
    } else {
        Ok(raw)
    }
}

// ── ATA disk block device (channel 1, game data) ────────────────────────────

struct AtaBlockDevice;

impl BlockDevice for AtaBlockDevice {
    fn sector_size(&self) -> u32 {
        512
    }

    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        if out.len() != 512 {
            return Err(FatError::Io);
        }
        hal::ata::read_sector(lba as u32, out).map_err(|_| FatError::Io)
    }
}

static ATA_PRESENT: KSpinLock<Option<bool>> = KSpinLock::new(None);

fn ata_device() -> Option<AtaBlockDevice> {
    let mut guard = ATA_PRESENT.lock();
    let present = *guard.get_or_insert_with(|| {
        let p = hal::ata::probe();
        if p {
            log::info!("Io: ATA channel 1 disk detected");
        }
        p
    });
    if present {
        Some(AtaBlockDevice)
    } else {
        None
    }
}

/// Open a file on the game data disk (ATA channel 1, FAT32).
pub fn open_game_file(path: &str) -> Result<FatFile, FatError> {
    prep_rep_ops();
    let dev = ata_device().ok_or(FatError::Io)?;
    FatVolume::mount_and_open(dev, path)
}

/// Read from a game data file.
pub fn read_game_file(file: &mut FatFile, out: &mut [u8]) -> Result<usize, FatError> {
    prep_rep_ops();
    let dev = ata_device().ok_or(FatError::Io)?;
    FatVolume::mount_and_read(dev, file, out)
}

/// List a directory on the game data disk.
pub fn list_game_dir(path: &str) -> Result<Vec<DirEntryInfo>, FatError> {
    prep_rep_ops();
    let dev = ata_device().ok_or(FatError::Io)?;
    FatVolume::mount(dev)?.list_dir(path)
}

fn leak_vec(data: Vec<u8>) -> (usize, usize) {
    let mut data = ManuallyDrop::new(data);
    (data.as_mut_ptr() as usize, data.len())
}

static DEMO_SOURCE: KSpinLock<Option<(u32, usize, usize)>> = KSpinLock::new(None);
static RAMDISK_SOURCE: KSpinLock<(u64, u64, u64)> = KSpinLock::new((0, 0, 0));

fn prep_rep_ops() {
    unsafe {
        asm!("cld", options(nostack));
    }
}

pub fn open_fat_file(path: &str) -> Result<FatFile, FatError> {
    prep_rep_ops();
    if let Some(dev) = ramdisk_device() {
        return FatVolume::mount_and_open(dev, path);
    }
    ensure_demo_source()?;
    let (sector_size, data_addr, data_len) = *DEMO_SOURCE.lock().as_ref().ok_or(FatError::NotFound)?;
    let dev = RamBlockDevice { sector_size, data_addr, data_len };
    FatVolume::mount_and_open(dev, path)
}

pub fn read_fat_file(file: &mut FatFile, out: &mut [u8]) -> Result<usize, FatError> {
    prep_rep_ops();
    if let Some(dev) = ramdisk_device() {
        return FatVolume::mount_and_read(dev, file, out);
    }
    ensure_demo_source()?;
    let (sector_size, data_addr, data_len) = *DEMO_SOURCE.lock().as_ref().ok_or(FatError::NotFound)?;
    let dev = RamBlockDevice { sector_size, data_addr, data_len };
    FatVolume::mount_and_read(dev, file, out)
}

pub fn list_fat_dir(path: &str) -> Result<Vec<DirEntryInfo>, FatError> {
    prep_rep_ops();
    if let Some(dev) = ramdisk_device() {
        return FatVolume::mount(dev)?.list_dir(path);
    }
    ensure_demo_source()?;
    let (sector_size, data_addr, data_len) = *DEMO_SOURCE.lock().as_ref().ok_or(FatError::NotFound)?;
    let dev = RamBlockDevice { sector_size, data_addr, data_len };
    FatVolume::mount(dev)?.list_dir(path)
}

pub fn smoke_probe_mz() -> Result<[u8; 2], FatError> {
    let mut file = open_fat_file("/CMD.EXE")?;
    let mut sig = [0u8; 2];
    let n = read_fat_file(&mut file, &mut sig)?;
    if n != 2 {
        return Err(FatError::Io);
    }
    Ok(sig)
}

pub fn init(ramdisk_phys_base: u64, ramdisk_size: u64, hhdm_offset: u64) {
    {
        let mut src = RAMDISK_SOURCE.lock();
        *src = (ramdisk_phys_base, ramdisk_size, hhdm_offset);
    }
    log::info!("Io: initialised");
}

fn ramdisk_device() -> Option<PhysRamBlockDevice> {
    let (phys, size, hhdm) = *RAMDISK_SOURCE.lock();
    if phys == 0 || size < 512 {
        return None;
    }
    Some(PhysRamBlockDevice { sector_size: 512, phys_base: phys, total_size: size as usize, hhdm_offset: hhdm })
}

fn ensure_demo_source() -> Result<(), FatError> {
    prep_rep_ops();
    {
        let guard = DEMO_SOURCE.lock();
        if guard.is_some() {
            return Ok(());
        }
    }
    let disk = build_demo_fat32_disk();
    let (data_addr, data_len) = leak_vec(disk);
    let mut guard = DEMO_SOURCE.lock();
    *guard = Some((512, data_addr, data_len));
    log::info!("Io: FAT32 read-only volume mounted (demo)");
    Ok(())
}

fn build_demo_fat32_disk() -> Vec<u8> {
    let sectors = 64usize;
    let mut disk = vec![0u8; sectors * 512];
    let mut boot = [0u8; 512];
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&1u16.to_le_bytes());
    boot[16] = 1;
    boot[17..19].copy_from_slice(&0u16.to_le_bytes());
    boot[19..21].copy_from_slice(&0u16.to_le_bytes());
    boot[32..36].copy_from_slice(&(sectors as u32).to_le_bytes());
    boot[36..40].copy_from_slice(&1u32.to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes());
    disk[0..512].copy_from_slice(&boot);

    let mut fat = [0u8; 512];
    fat[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    fat[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    fat[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    fat[12..16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    disk[512..1024].copy_from_slice(&fat);

    let mut root = [0u8; 512];
    root[0..11].copy_from_slice(b"KERNEL  BIN");
    root[11] = 0x20;
    root[20..22].copy_from_slice(&0u16.to_le_bytes());
    root[26..28].copy_from_slice(&3u16.to_le_bytes());
    root[28..32].copy_from_slice(&4u32.to_le_bytes());
    root[32] = 0x00;
    disk[1024..1536].copy_from_slice(&root);

    let mut file = [0u8; 512];
    file[0..4].copy_from_slice(b"ABCD");
    disk[1536..2048].copy_from_slice(&file);
    disk
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_tests;
