//! Mm — Memory Manager executive.
//!
//! Mirrors NT's Mm subsystem:
//!   - Physical page database (PFN database) — Phase 1: buddy allocator
//!   - Virtual Address Descriptor tree (VAD) per process — Phase 2
//!   - NtAllocateVirtualMemory / NtFreeVirtualMemory — Phase 2
//!   - Section objects (file mapping — needed for PE loader) — Phase 2
//!   - Page fault handler (demand paging) — Phase 3
//!
//! Address space layout (XP-compatible 2GB/2GB split):
//!   User mode:   0x0000_0000_0000_1000 – 0x0000_0000_7FFF_FFFF
//!   Kernel mode: 0xFFFF_8000_0000_0000 – 0xFFFF_FFFF_FFFF_FFFF
//!
//! WI7e Ch.5 "Memory Management"

#![no_std]
extern crate alloc;

pub mod buddy;
pub mod paging;
pub mod vad;
pub mod virtual_alloc;

pub use buddy::{BuddyAllocator, Pfn};
pub use paging::MmPageTables;
pub use virtual_alloc::PageMapper;

use boot_info::BootInfo;

#[inline]
fn add_usable_excluding_kernel(
    allocator: &mut BuddyAllocator,
    start_pfn: u64,
    page_count: u64,
    kernel_start_pfn: u64,
    kernel_end_pfn: u64,
) -> u64 {
    let end_pfn = start_pfn + page_count;

    // No overlap with kernel image: add whole segment.
    if end_pfn <= kernel_start_pfn || start_pfn >= kernel_end_pfn {
        allocator.add_region(Pfn(start_pfn), page_count);
        return page_count;
    }

    let mut added = 0u64;

    // Segment before kernel image.
    if start_pfn < kernel_start_pfn {
        let before = kernel_start_pfn - start_pfn;
        allocator.add_region(Pfn(start_pfn), before);
        added += before;
    }

    // Segment after kernel image.
    if end_pfn > kernel_end_pfn {
        let after = end_pfn - kernel_end_pfn;
        allocator.add_region(Pfn(kernel_end_pfn), after);
        added += after;
    }

    added
}

/// Initialise the physical memory manager from the bootloader memory map.
///
/// Iterates the `BootInfo` memory regions and adds every `Usable` region
/// to the global buddy allocator. Regions that overlap the kernel image
/// (including BSS) are excluded.
///
/// `kernel_phys_end` must be the physical address of the byte AFTER the last
/// kernel static (i.e. `__bss_end` from the linker script). `boot_info.kernel_size`
/// only covers the loaded flat binary and does NOT include BSS; passing the
/// wrong end would leave BSS frames in the usable pool, allowing the buddy to
/// hand them out as page-table frames and silently corrupt kernel statics.
///
/// # IRQL: PASSIVE_LEVEL — called once during kernel init, interrupts off.
pub fn init(boot_info: &BootInfo, kernel_phys_end: u64) {
    let mut total: u64 = 0;
    let kernel_start_pfn = boot_info.kernel_phys_base / 4096;
    let kernel_end_pfn = (kernel_phys_end + 4095) / 4096;

    {
        let mut buddy = buddy::BUDDY.lock();
        let allocator = buddy.get_or_insert_with(BuddyAllocator::new);

        for region in boot_info.regions() {
            if region.kind.is_usable() {
                total += add_usable_excluding_kernel(
                    allocator,
                    region.start_pfn,
                    region.page_count,
                    kernel_start_pfn,
                    kernel_end_pfn,
                );
            }
        }
    }

    log::info!(
        "Mm: buddy initialised — {} MiB usable ({} pages)",
        total * buddy::PAGE_SIZE as u64 / (1024 * 1024),
        total
    );
}
