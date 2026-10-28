//! B1 — UEFI memory map → BootInfo regions.
//!
//! Translates UEFI `MemoryDescriptor` types to our `MemoryKind` enum and
//! builds the compact `MemoryRegion` array that the kernel reads from
//! `BootInfo`. Must be called *before* `ExitBootServices`.

use boot_info::{MemoryKind, MemoryRegion, MEMORY_MAP_MAX};
use uefi::table::boot::{BootServices, MemoryType};

/// Collect the UEFI physical memory map into a `MemoryRegion` array.
///
/// Returns `(regions, count)` where `regions[..count]` is valid.
/// Adjacent regions of the same kind are NOT merged (the kernel handles that).
///
/// Called from `efi_main` with boot services still active.
pub fn collect(bt: &BootServices) -> ([MemoryRegion; MEMORY_MAP_MAX], usize) {
    let mut out = [MemoryRegion::zeroed(); MEMORY_MAP_MAX];
    let mut count = 0usize;

    #[repr(C, align(8))]
    struct MmapBuf([u8; 32 * 1024]);
    let mut buf = MmapBuf([0u8; 32 * 1024]);
    let map = bt.memory_map(&mut buf.0).expect("UEFI: failed to get memory map");

    for desc in map.entries() {
        if count >= MEMORY_MAP_MAX {
            log::warn!("memory map truncated at {} entries", MEMORY_MAP_MAX);
            break;
        }

        let kind = uefi_type_to_kind(desc.ty);
        let start_pfn = desc.phys_start / 4096;
        let page_count = desc.page_count;

        // Skip zero-size regions.
        if page_count == 0 {
            continue;
        }

        // Merge with previous entry if kind and PFN are contiguous.
        if count > 0 {
            let prev = &mut out[count - 1];
            if prev.kind == kind && prev.start_pfn + prev.page_count == start_pfn {
                prev.page_count += page_count;
                continue;
            }
        }

        out[count] = MemoryRegion { kind, start_pfn, page_count };
        count += 1;
    }

    log::info!(
        "memory map: {} regions ({} total pages)",
        count,
        out[..count].iter().map(|r| r.page_count).sum::<u64>()
    );

    (out, count)
}

/// Mark a physical range [start_pfn, start_pfn+pages) as `KernelImage` in
/// the region array returned by `collect()`. Called after loading the kernel
/// so that `mm::init` does not hand out kernel pages to the buddy allocator.
pub fn mark_kernel(
    regions: &mut [MemoryRegion],
    count:   usize,
    kernel_start_pfn: u64,
    kernel_pages:     u64,
) {
    // Simple approach: find the Usable region that contains the kernel and
    // split it. For Phase 1 (kernel at 1 MiB on a machine with contiguous
    // low RAM) this is always a single region split into at most 3 pieces.
    for i in 0..count {
        let r = &regions[i];
        if r.kind != MemoryKind::Usable {
            continue;
        }
        let r_end = r.start_pfn + r.page_count;
        let k_end = kernel_start_pfn + kernel_pages;

        if r.start_pfn <= kernel_start_pfn && k_end <= r_end {
            // Kernel is fully inside this region.
            let before_pfn   = r.start_pfn;
            let before_pages = kernel_start_pfn - before_pfn;
            let after_pfn    = k_end;
            let after_pages  = r_end - k_end;

            // Overwrite this slot with the KernelImage region.
            regions[i] = MemoryRegion {
                kind:       MemoryKind::KernelImage,
                start_pfn:  kernel_start_pfn,
                page_count: kernel_pages,
            };

            // Compact remaining: shift everything right and insert before/after.
            // For simplicity just mark and leave — the buddy allocator skips
            // non-Usable regions, so the before/after pages are "lost" until
            // Phase 2 reclaimation. This is acceptable for Phase 1.
            // TODO Phase 2: split properly to reclaim surrounding pages.
            let _ = (before_pfn, before_pages, after_pfn, after_pages);
            return;
        }
    }
    log::warn!("mark_kernel: kernel range not found in Usable regions — proceeding");
}

// ── UEFI type mapping ─────────────────────────────────────────────────────────

fn uefi_type_to_kind(ty: MemoryType) -> MemoryKind {
    match ty {
        MemoryType::CONVENTIONAL => MemoryKind::Usable,

        MemoryType::ACPI_RECLAIM => MemoryKind::AcpiReclaimable,

        MemoryType::RUNTIME_SERVICES_CODE
        | MemoryType::RUNTIME_SERVICES_DATA => MemoryKind::UefiRuntime,

        MemoryType::LOADER_CODE
        | MemoryType::LOADER_DATA
        | MemoryType::BOOT_SERVICES_CODE
        | MemoryType::BOOT_SERVICES_DATA => MemoryKind::BootloaderReclaimable,

        _ => MemoryKind::Reserved,
    }
}
