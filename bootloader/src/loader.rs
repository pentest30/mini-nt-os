//! B3 — Kernel and ramdisk loader.
//!
//! The kernel is an ELF64 executable linked at 0xFFFF_FFFF_8000_0000 (ADR-014).
//! Its PT_LOAD segments are copied into one physically contiguous block,
//! laid out exactly as their virtual addresses (BSS zeroed), and described by a
//! [`KernelImage`] that `paging::map_kernel` maps with each segment's rights.
//!
//! The optional ramdisk (`fat.img`) is loaded verbatim.

use uefi::{
    prelude::BootServices,
    proto::media::{
        file::{File, FileAttribute, FileInfo, FileMode, RegularFile},
        fs::SimpleFileSystem,
    },
    table::boot::{AllocateType, MemoryType},
    CStr16,
};

/// Maximum file size for kernel or ramdisk: 16 MiB (Phase 3: DXVK DLLs in ramdisk).
const KERNEL_MAX_SIZE: usize = 16 * 1024 * 1024;

/// Filenames on the ESP (in the root directory).
const KERNEL_FILENAME: &CStr16 = uefi::cstr16!("kernel.elf");
const RAMDISK_FILENAME: &CStr16 = uefi::cstr16!("fat.img");

/// Lowest address the kernel may be linked at: the top 2 GiB (`code-model=kernel`).
const KERNEL_LINK_MIN: u64 = 0xFFFF_FFFF_8000_0000;

/// Most PT_LOAD segments accepted (the linker script emits three).
pub const MAX_SEGMENTS: usize = 8;

/// One PT_LOAD segment of the kernel, with its rights.
#[derive(Clone, Copy, Debug, Default)]
pub struct Segment {
    pub vaddr:      u64,
    pub memsz:      u64,
    pub writable:   bool,
    pub executable: bool,
}

/// The kernel image in physical memory: `[virt_base, virt_base + size)` is
/// backed by `[phys_base, phys_base + size)`, page for page.
pub struct KernelImage {
    pub phys_base:     u64,
    pub virt_base:     u64,
    /// Whole span in bytes, page-aligned, BSS included.
    pub size:          u64,
    pub entry:         u64,
    pub segments:      [Segment; MAX_SEGMENTS],
    pub segment_count: usize,
}

/// Load `kernel.elf` from the ESP and lay its segments out in physical memory.
///
/// # Panics
/// Panics if the kernel file is missing, too large or not a valid x86-64 ELF
/// executable linked in the top 2 GiB.
pub fn load_kernel(bt: &BootServices) -> KernelImage {
    let (file_phys, file_size) = load_file(bt, KERNEL_FILENAME, true)
        .unwrap_or_else(|| panic!("loader: kernel.elf not found on any SimpleFileSystem volume"));
    // SAFETY: load_file just read file_size bytes at file_phys (identity-mapped).
    let file = unsafe { core::slice::from_raw_parts(file_phys as *const u8, file_size as usize) };
    let image = place_segments(bt, file);
    // SAFETY: the file buffer was allocated by load_file and is no longer used.
    let _ = unsafe { bt.free_pages(file_phys, pages(file_size)) };
    log::info!(
        "loader: kernel ELF at {:#x}..{:#x} (phys {:#x}), entry {:#x}, {} segments",
        image.virt_base, image.virt_base + image.size, image.phys_base, image.entry, image.segment_count,
    );
    image
}

/// Validates the ELF headers, then copies every PT_LOAD segment into a fresh
/// contiguous block at its offset from the lowest segment.
fn place_segments(bt: &BootServices, file: &[u8]) -> KernelImage {
    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;

    assert!(file.len() >= 64 && file[..4] == *b"\x7fELF", "loader: kernel.elf is not ELF");
    assert!(file[4] == 2 && file[5] == 1, "loader: kernel.elf must be ELF64 little-endian");
    assert!(rd16(file, 16) == 2, "loader: kernel.elf must be an executable (ET_EXEC)");
    assert!(rd16(file, 18) == 0x3E, "loader: kernel.elf must target x86-64");
    let entry = rd64(file, 24);
    let phoff = rd64(file, 32) as usize;
    let phentsize = rd16(file, 54) as usize;
    let phnum = rd16(file, 56) as usize;
    assert!(phentsize >= 56, "loader: bad program header size");

    let mut segments = [Segment::default(); MAX_SEGMENTS];
    let mut count = 0usize;
    let mut offsets = [(0u64, 0u64); MAX_SEGMENTS]; // (p_offset, p_filesz)
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if rd32(file, ph) != PT_LOAD {
            continue;
        }
        assert!(count < MAX_SEGMENTS, "loader: too many PT_LOAD segments");
        let flags = rd32(file, ph + 4);
        let (offset, vaddr, filesz, memsz) =
            (rd64(file, ph + 8), rd64(file, ph + 16), rd64(file, ph + 32), rd64(file, ph + 40));
        assert!(filesz <= memsz, "loader: segment file size exceeds memory size");
        assert!(offset.checked_add(filesz).is_some_and(|end| end <= file.len() as u64),
                "loader: segment outside the file");
        assert!(vaddr >= KERNEL_LINK_MIN, "loader: kernel must be linked in the top 2 GiB");
        segments[count] = Segment { vaddr, memsz, writable: flags & PF_W != 0, executable: flags & PF_X != 0 };
        offsets[count] = (offset, filesz);
        count += 1;
    }
    assert!(count > 0, "loader: kernel.elf has no PT_LOAD segment");

    let virt_base = segments[..count].iter().map(|s| s.vaddr & !0xFFF).min().unwrap_or(0);
    let virt_end = segments[..count]
        .iter()
        .map(|s| (s.vaddr + s.memsz + 0xFFF) & !0xFFF)
        .max()
        .unwrap_or(0);
    assert!(entry >= virt_base && entry < virt_end, "loader: entry point outside the image");
    let size = virt_end - virt_base;

    let phys_base = bt
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages(size))
        .expect("loader: failed to allocate pages for the kernel image");
    // SAFETY: [phys_base, phys_base + size) was just allocated (identity-mapped);
    // every copy below stays inside it and inside `file` (checked above).
    unsafe {
        core::ptr::write_bytes(phys_base as *mut u8, 0, size as usize);
        for (seg, &(offset, filesz)) in segments[..count].iter().zip(&offsets[..count]) {
            let dst = phys_base + (seg.vaddr - virt_base);
            core::ptr::copy_nonoverlapping(file.as_ptr().add(offset as usize), dst as *mut u8, filesz as usize);
        }
    }

    KernelImage { phys_base, virt_base, size, entry, segments, segment_count: count }
}

fn pages(bytes: u64) -> usize {
    bytes.div_ceil(4096) as usize
}

fn rd16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().expect("loader: truncated ELF"))
}

fn rd32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("loader: truncated ELF"))
}

fn rd64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("loader: truncated ELF"))
}

pub fn load_optional_ramdisk(bt: &BootServices) -> Option<(u64, u64)> {
    load_file(bt, RAMDISK_FILENAME, false)
}

fn load_file(
    bt: &BootServices,
    filename: &CStr16,
    require_present: bool,
) -> Option<(u64, u64)> {
    // ── Find a SimpleFileSystem protocol handle ───────────────────────────────
    // Look for handles that support SimpleFileSystem (ESP and other volumes).
    let handles = bt
        .find_handles::<SimpleFileSystem>()
        .expect("loader: no SimpleFileSystem handles found");

    // Try each volume until we find the file.
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
            .expect("loader: failed to get file info");
        let file_size = info.file_size() as usize;

        assert!(file_size <= KERNEL_MAX_SIZE, "loader: file too large ({} > {} bytes)", file_size, KERNEL_MAX_SIZE);
        assert!(file_size > 0, "loader: file is empty");

        // ── Allocate physical pages ───────────────────────────────────────────
        let page_count = (file_size + 4095) / 4096;
        let phys_base = bt
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, page_count)
            .expect("loader: failed to allocate pages");

        // ── Read the file directly into physical memory ───────────────────────
        // UEFI identity-maps all physical RAM, so phys == virt here.
        // SAFETY: phys_base is page-aligned and was just allocated for
        //         file_size bytes.
        let dst = unsafe { core::slice::from_raw_parts_mut(phys_base as *mut u8, file_size) };

        let bytes_read = file.read(dst).expect("loader: file read failed");
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
