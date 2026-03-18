//! B2 — 4-level page tables.
//!
//! Builds the minimal page tables needed to hand off to the kernel:
//!
//!   1. Identity map [0, 4 GiB) — 2 MiB huge pages.
//!      Covers UEFI runtime, MMIO, APIC (0xFEE0_0000), bootloader code.
//!
//!   2. HHDM [HHDM_OFFSET, HHDM_OFFSET + HHDM_SIZE) → [0, HHDM_SIZE).
//!      2 MiB huge pages. The kernel image at physical 0x0010_0000 is
//!      accessible at HHDM_OFFSET + 0x0010_0000 = 0xFFFF_8000_0010_0000.
//!
//! All page table frames are allocated from UEFI (LOADER_DATA).
//! After ExitBootServices we write CR3 to activate these tables.
//!
//! # Safety invariants
//! - UEFI firmware identity-maps all physical RAM, so phys == virt during
//!   bootloader execution. We can cast physical frame addresses directly to
//!   `*mut PageTable` pointers.
//! - All allocated frames are zeroed before use.

use uefi::table::boot::{AllocateType, BootServices, MemoryType};
use x86_64::{
    PhysAddr,
    structures::paging::{PageTable, PageTableFlags},
};

/// Base virtual address of the Higher-Half Direct Map.
/// Physical address `p` is accessible at `HHDM_OFFSET + p` in the kernel.
pub const HHDM_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// How much physical memory to map in the HHDM (4 GiB covers all QEMU defaults).
const HHDM_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Size of one huge page (2 MiB).
const HUGE_2M: u64 = 2 * 1024 * 1024;

/// Flags for a 2 MiB huge-page data leaf (present, writable, huge).
const HUGE_DATA: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits()
        | PageTableFlags::WRITABLE.bits()
        | PageTableFlags::HUGE_PAGE.bits(),
);

/// Flags for an intermediate page-directory entry (present, writable).
const DIR_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits(),
);

// ── Public entry point ────────────────────────────────────────────────────────

/// Build the 4-level page tables and return the physical address of the PML4.
///
/// Call this while UEFI boot services are still active (we need `allocate_pages`).
///
/// After `ExitBootServices`, write the returned address to CR3 to activate the
/// new mapping before jumping to the kernel.
///
/// # Safety
/// Must be called from UEFI boot services context (single-threaded, identity map).
pub unsafe fn build(bt: &BootServices) -> PhysAddr {
    // ── Allocate PML4 (Level 4 page table) ──────────────────────────────────
    let l4_phys = alloc_zeroed_frame(bt);

    // ── Identity map [0, 4 GiB) ─────────────────────────────────────────────
    // PML4[0] covers virtual [0, 512 GiB).
    // PDPT[0..3] each cover one GiB; each GiB uses one PD of 2 MiB entries.
    build_range(bt, l4_phys, 0 /* virt start */, 0 /* phys start */, 4 * 1024 * 1024 * 1024);

    // ── HHDM ─────────────────────────────────────────────────────────────────
    // PML4[256] covers virtual [HHDM_OFFSET, HHDM_OFFSET + 512 GiB).
    build_range(bt, l4_phys, HHDM_OFFSET, 0 /* phys start */, HHDM_SIZE);

    log::info!(
        "paging: PML4 at {:#x}, HHDM [{:#x}, {:#x}) → [0, {:#x})",
        l4_phys.as_u64(),
        HHDM_OFFSET,
        HHDM_OFFSET + HHDM_SIZE,
        HHDM_SIZE
    );

    l4_phys
}

// ── Internals ─────────────────────────────────────────────────────────────────

/// Map `[virt_start, virt_start + size)` → `[phys_start, phys_start + size)`
/// using 2 MiB huge pages. Both `virt_start` and `phys_start` must be 2 MiB
/// aligned; `size` must be a multiple of 2 MiB.
unsafe fn build_range(
    bt:         &BootServices,
    l4_phys:    PhysAddr,
    virt_start: u64,
    phys_start: u64,
    size:       u64,
) {
    debug_assert!(virt_start % HUGE_2M == 0);
    debug_assert!(phys_start % HUGE_2M == 0);
    debug_assert!(size % HUGE_2M == 0);

    let n_pages = size / HUGE_2M;

    for i in 0..n_pages {
        let virt = virt_start + i * HUGE_2M;
        let phys = phys_start + i * HUGE_2M;
        map_huge_2m(bt, l4_phys, virt, phys);
    }
}

/// Map a single 2 MiB page: virtual `virt` → physical `phys`.
/// Intermediate tables are allocated on demand.
///
/// # Safety
/// `l4_phys` must point to a valid, accessible PML4 frame.
unsafe fn map_huge_2m(bt: &BootServices, l4_phys: PhysAddr, virt: u64, phys: u64) {
    let l4_idx = ((virt >> 39) & 0x1FF) as usize;
    let l3_idx = ((virt >> 30) & 0x1FF) as usize;
    let l2_idx = ((virt >> 21) & 0x1FF) as usize;

    // SAFETY: l4_phys is a valid 4 KiB frame we just allocated and zeroed.
    // In UEFI identity-map context phys == virt, so casting to *mut PageTable is valid.
    let l4 = unsafe { &mut *(l4_phys.as_u64() as *mut PageTable) };

    // ── Level 4 → Level 3 ────────────────────────────────────────────────────
    let l3_phys = if l4[l4_idx].is_unused() {
        let frame = alloc_zeroed_frame(bt);
        // SAFETY: frame is freshly allocated; DIR_FLAGS marks it present+writable.
        unsafe { l4[l4_idx].set_addr(frame, DIR_FLAGS) };
        frame
    } else {
        PhysAddr::new(l4[l4_idx].addr().as_u64())
    };

    // SAFETY: same reasoning — phys == virt in UEFI context.
    let l3 = unsafe { &mut *(l3_phys.as_u64() as *mut PageTable) };

    // ── Level 3 → Level 2 ────────────────────────────────────────────────────
    let l2_phys = if l3[l3_idx].is_unused() {
        let frame = alloc_zeroed_frame(bt);
        // SAFETY: as above.
        unsafe { l3[l3_idx].set_addr(frame, DIR_FLAGS) };
        frame
    } else {
        PhysAddr::new(l3[l3_idx].addr().as_u64())
    };

    // SAFETY: l2_phys is valid.
    let l2 = unsafe { &mut *(l2_phys.as_u64() as *mut PageTable) };

    // ── Level 2 leaf (2 MiB huge page) ───────────────────────────────────────
    if l2[l2_idx].is_unused() {
        // SAFETY: PhysAddr is 2 MiB aligned; HUGE_DATA sets HUGE_PAGE bit.
        unsafe { l2[l2_idx].set_addr(PhysAddr::new(phys), HUGE_DATA) };
    }
    // Already mapped — skip (can happen if ranges overlap, which they don't here).
}

// ── UEFI frame allocator ──────────────────────────────────────────────────────

/// Allocate one 4 KiB page-table frame from UEFI and zero it.
///
/// Returns the physical address of the frame.
///
/// # Safety
/// Must be called with UEFI boot services active.
fn alloc_zeroed_frame(bt: &BootServices) -> PhysAddr {
    let phys = bt
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
        .expect("paging: failed to allocate page-table frame");

    // Zero the frame. In UEFI context phys == virt (identity mapped).
    // SAFETY: UEFI just allocated this page; we own it exclusively.
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, 4096);
    }

    PhysAddr::new(phys)
}
