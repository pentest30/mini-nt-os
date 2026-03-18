//! B3 — Kernel binary loader.
//!
//! Reads `\kernel.bin` from the EFI System Partition into the physical
//! load address (1 MiB mark, 0x0010_0000). The kernel is a flat binary
//! with `kernel_main` at its very first byte (enforced by the linker script).
//!
//! # Phase 1 constraints
//! - No ELF parsing — flat binary only.
//! - Maximum kernel size: `KERNEL_MAX_SIZE` bytes.
//! - Load address: physical `KERNEL_PHYS_BASE`.

use uefi::{
    prelude::BootServices,
    proto::media::{
        file::{File, FileAttribute, FileInfo, FileMode, RegularFile},
        fs::SimpleFileSystem,
    },
    table::boot::AllocateType,
    CStr16,
};

/// Physical address where the kernel binary is loaded.
pub const KERNEL_PHYS_BASE: u64 = 0x0010_0000; // 1 MiB

/// Maximum file size for kernel or ramdisk: 16 MiB (Phase 3: DXVK DLLs in ramdisk).
const KERNEL_MAX_SIZE: usize = 16 * 1024 * 1024;

/// Filename on the ESP (in the root directory).
const KERNEL_FILENAME: &CStr16 = uefi::cstr16!("kernel.bin");
const RAMDISK_FILENAME: &CStr16 = uefi::cstr16!("fat.img");

/// Load the kernel binary from the ESP into physical memory.
///
/// Returns `(kernel_phys_base, kernel_size_bytes)`.
///
/// # Panics
/// Panics if the kernel file cannot be found or is too large.
///
/// # Safety
/// Must be called with UEFI boot services still active.
pub fn load(bt: &BootServices) -> (u64, u64) {
    match load_file(bt, KERNEL_FILENAME, KERNEL_PHYS_BASE, true) {
        Some((base, size)) => (base, size),
        None => panic!("loader: kernel.bin not found on any SimpleFileSystem volume"),
    }
}

pub fn load_optional_ramdisk(bt: &BootServices) -> Option<(u64, u64)> {
    load_file(bt, RAMDISK_FILENAME, 0, false)
}

fn load_file(
    bt: &BootServices,
    filename: &CStr16,
    fixed_phys_base: u64,
    require_present: bool,
) -> Option<(u64, u64)> {
    // ── Find a SimpleFileSystem protocol handle ───────────────────────────────
    // Look for handles that support SimpleFileSystem (ESP and other volumes).
    let handles = bt
        .find_handles::<SimpleFileSystem>()
        .expect("loader: no SimpleFileSystem handles found");

    // Try each volume until we find kernel.bin.
    for handle in handles.iter() {
        let mut fs = match bt.open_protocol_exclusive::<SimpleFileSystem>(*handle) {
            Ok(fs) => fs,
            Err(_) => continue,
        };

        let mut root = match fs.open_volume() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let file_handle = match root.open(filename, FileMode::Read, FileAttribute::empty()) {
            Ok(fh) => fh,
            Err(_) => continue, // not on this volume
        };

        // SAFETY: we opened it in read mode; it's a regular file.
        let mut file = unsafe { RegularFile::new(file_handle) };

        // Query file size via FileInfo.
        let mut info_buf = [0u8; 256];
        let info: &FileInfo = file
            .get_info(&mut info_buf)
            .expect("loader: failed to get kernel file info");
        let file_size = info.file_size() as usize;

        assert!(file_size <= KERNEL_MAX_SIZE, "loader: file too large ({} > {} bytes)", file_size, KERNEL_MAX_SIZE);
        assert!(file_size > 0, "loader: kernel.bin is empty");

        // ── Allocate physical pages ───────────────────────────────────────────
        let page_count = (file_size + 4095) / 4096;
        let phys_base = if fixed_phys_base != 0 {
            bt.allocate_pages(
                AllocateType::Address(fixed_phys_base),
                uefi::table::boot::MemoryType::LOADER_DATA,
                page_count,
            )
            .expect("loader: failed to allocate fixed pages") as u64
        } else {
            bt.allocate_pages(
                AllocateType::AnyPages,
                uefi::table::boot::MemoryType::LOADER_DATA,
                page_count,
            )
            .expect("loader: failed to allocate pages") as u64
        };

        // ── Read kernel binary directly into physical memory ──────────────────
        // UEFI identity-maps all physical RAM, so phys == virt here.
        // SAFETY: KERNEL_PHYS_BASE is page-aligned; we just allocated it;
        //         file_size bytes will be written.
        let dst = unsafe { core::slice::from_raw_parts_mut(phys_base as *mut u8, file_size) };

        let bytes_read = file.read(dst).expect("loader: kernel read failed");
        assert_eq!(bytes_read, file_size, "loader: short read");

        log::info!("loader: file loaded at {:#x}, {} bytes ({} pages)", phys_base, file_size, page_count);
        return Some((phys_base, file_size as u64));
    }

    if require_present {
        None
    } else {
        log::info!("loader: optional file not found");
        None
    }
}
