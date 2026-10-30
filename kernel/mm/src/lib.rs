//! Mm — Memory Manager executive.
//!
//! Mirrors NT's Mm subsystem:
//!   - Physical page database (PFN database, `pfn`) over the buddy allocator
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
pub mod kstack;
pub mod paging;
pub mod pfn;
pub mod pool;
pub mod vad;
pub mod virtual_alloc;

pub use buddy::{BuddyAllocator, Pfn};
pub use paging::MmPageTables;
pub use virtual_alloc::PageMapper;

use core::sync::atomic::{AtomicU64, Ordering};

use abi::BootInfo;

/// Bootloader HHDM offset, recorded by [`init`] for code that edits page tables later.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Initialise the physical memory manager from the bootloader memory map:
/// the PFN database (`pfn`) covers every page below the HHDM limit, its own
/// table is carved from the first usable run that holds it, and every usable
/// page outside the kernel image and that table goes to the free lists.
///
/// `kernel_phys_end` must be the physical address of the byte AFTER the last
/// kernel static (`__bss_end`), so that BSS frames never reach the free lists.
///
/// # IRQL: PASSIVE_LEVEL — called once during kernel init, interrupts off.
pub fn init(boot_info: &BootInfo, kernel_phys_end: u64) {
    HHDM_OFFSET.store(boot_info.hhdm_offset, Ordering::Release);
    let page = buddy::PAGE_SIZE as u64;
    // Pages the HHDM reaches: the only ones Mm can zero or edit.
    let limit = hal::HHDM_SIZE / page;
    let kernel = (boot_info.kernel_phys_base / page, kernel_phys_end.div_ceil(page));
    let usable = || boot_info.regions().iter().filter(|r| r.kind.is_usable());
    let clipped = |r: &abi::MemoryRegion| (r.start_pfn.min(limit), (r.start_pfn + r.page_count).min(limit));

    let count = usable().map(|r| clipped(r).1).max().unwrap_or(0);
    let table_pages = (count * core::mem::size_of::<pfn::MmPfn>() as u64).div_ceil(page);
    // The first usable run that holds the table, outside the kernel image, and
    // above 1 MiB if possible: the memory below stays for what needs it (the
    // startup trampoline of the other processors).
    let first_fit = |excluded: &[(u64, u64)]| {
        let mut table = None;
        for r in usable() {
            let (start, end) = clipped(r);
            pfn::for_each_outside(start, end, excluded, |a, b| {
                if table.is_none() && b - a >= table_pages {
                    table = Some(a);
                }
            });
        }
        table
    };
    const LOW_MEMORY_PAGES: u64 = 0x10_0000 / 4096;
    let mut low_and_kernel = [(0, LOW_MEMORY_PAGES), kernel];
    low_and_kernel.sort_unstable();
    let table = first_fit(&low_and_kernel)
        .or_else(|| first_fit(&[kernel]))
        .expect("no room for the PFN database in the memory map");

    let mut frames = pfn::PAGE_FRAMES.lock();
    // SAFETY: [table, table + table_pages) is usable RAM below the HHDM limit,
    // outside the kernel image, and kept out of the free lists below: it
    // belongs to the database for good.
    unsafe { frames.init((boot_info.hhdm_offset + table * page) as *mut pfn::MmPfn, count) };
    frames.mark_active(Pfn(table), table_pages, pfn::PageUsage::PfnDatabase);
    let mut excluded = [kernel, (table, table + table_pages)];
    excluded.sort_unstable();
    for r in usable() {
        let (start, end) = clipped(r);
        pfn::for_each_outside(start, end, &excluded, |a, b| frames.add_free(Pfn(a), b - a));
    }
    let stats = frames.stats();
    drop(frames);

    log::info!(
        "Mm: PFN database: {} pages tracked, table at {:#x} ({} KiB), {} MiB free",
        stats.tracked,
        table * page,
        table_pages * page / 1024,
        stats.free * page / (1024 * 1024),
    );
    let ignored: u64 = usable().map(|r| r.page_count - (clipped(r).1 - clipped(r).0)).sum();
    if ignored > 0 {
        log::warn!("Mm: {} MiB of RAM above the 4 GiB HHDM left unused", ignored * page / (1024 * 1024));
    }
}
