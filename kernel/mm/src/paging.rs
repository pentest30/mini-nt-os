//! D3 — Kernel page-table manager.
//!
//! Wraps `x86_64::structures::paging::OffsetPageTable` and exposes:
//!   - [`PageTableFrameAllocator`]: implements `FrameAllocator<Size4KiB>`
//!     with pages of the PFN database (`mm::pfn`, usage `PageTable`).
//!   - [`MmPageTables`]: safe `map_page` / `unmap_page` / `translate` API.
//!
//! # Usage
//! ```ignore
//! let mut pt = unsafe { MmPageTables::new(boot_info.hhdm_offset) };
//! unsafe { pt.map_page(virt, phys, PageTableFlags::PRESENT | PageTableFlags::WRITABLE) };
//! ```
//!
//! WI7e Ch.5 §Virtual Address Translation
//! Phil-Opp "Writing an OS in Rust" §Paging Implementation

use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        page_table::PageTableEntry, FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageTable,
        PageTableFlags, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::buddy::Pfn;
use crate::pfn::PageUsage;

// ── Frame allocator ───────────────────────────────────────────────────────────

/// Frame allocator for the page tables that `map_page` creates: one page of
/// the PFN database (`mm::pfn`) each, usage `PageTable`, zeroed.
///
/// Takes the PFN database's lock on every call: never while holding it.
pub struct PageTableFrameAllocator;

// SAFETY: Every frame returned is a freshly allocated, page-aligned physical
// frame; it cannot alias any existing mapping.
unsafe impl FrameAllocator<Size4KiB> for PageTableFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let pfn = crate::pfn::allocate_page(PageUsage::PageTable)?;
        let phys = pfn.to_phys();
        zero_frame(phys);
        let addr = PhysAddr::new(phys);
        // SAFETY: to_phys() returns a page-aligned address.
        Some(PhysFrame::containing_address(addr))
    }
}

// SAFETY: The frame being freed was previously obtained from `allocate_frame`.
impl FrameDeallocator<Size4KiB> for PageTableFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        crate::pfn::free_page(Pfn(frame.start_address().as_u64() / 4096));
    }
}

fn alloc_zeroed_pt_phys() -> u64 {
    let pfn = crate::pfn::allocate_page(PageUsage::PageTable).expect("alloc_zeroed_pt_phys: out of physical memory");
    let phys = pfn.to_phys();
    zero_frame(phys);
    phys
}

/// Zeroes a fresh frame through the HHDM (the identity map is gone after
/// phase 0). The bootloader's HHDM covers the first 4 GiB only.
fn zero_frame(phys: u64) {
    assert!(phys < 0x1_0000_0000, "frame {:#x} above the 4 GiB HHDM", phys);
    let virt = crate::HHDM_OFFSET.load(core::sync::atomic::Ordering::Acquire) + phys;
    // SAFETY: the frame was just allocated, so nothing else uses it,
    // and the HHDM maps it writable.
    unsafe { core::ptr::write_bytes(virt as *mut u8, 0, 4096) };
}

/// Software bit of a non-present leaf entry that still holds its physical
/// page: a `PAGE_NOACCESS` page or a guard page that was touched before
/// (`mm::address_space`). The processor ignores every other bit of a
/// non-present entry.
pub const PTE_RETAINED: PageTableFlags = PageTableFlags::BIT_9;

// ── Page table manager ────────────────────────────────────────────────────────

/// Page-table manager for one PML4: the active one ([`MmPageTables::new`]),
/// or that of another address space ([`MmPageTables::for_directory`]).
///
/// All physical addresses in the page tables are accessible at
/// `hhdm_offset + phys`, which `OffsetPageTable` uses to walk the hierarchy.
///
/// # IRQL: <= DISPATCH_LEVEL — the PFN database's lock is a `KSpinLock`.
pub struct MmPageTables {
    inner: OffsetPageTable<'static>,
    /// Raw HHDM offset — stored so `patch_user_path` can walk intermediate
    /// entries directly without a second borrow of `self.inner`.
    phys_offset: u64,
    /// Physical address of the PML4.
    pml4: u64,
}

impl MmPageTables {
    /// The active page tables (CR3), with the bootloader's HHDM offset.
    ///
    /// # Safety
    /// - The bootloader's page tables must be active (called after ExitBootServices).
    /// - `hhdm_offset` must match the value stored in `BootInfo::hhdm_offset`.
    /// - The PML4 at the current CR3 must stay live while this value is used.
    pub unsafe fn new(hhdm_offset: u64) -> Self {
        let (l4_frame, _) = Cr3::read();
        // SAFETY: forwarded; CR3 holds a valid PML4.
        unsafe { Self::for_directory(hhdm_offset, l4_frame.start_address().as_u64()) }
    }

    /// The page tables under the PML4 at physical address `pml4`, active or
    /// not: an address space's directory table base (`mm::address_space`).
    ///
    /// # Safety
    /// `pml4` is a valid PML4 that stays live while this value is used;
    /// `hhdm_offset` is the bootloader's.
    pub unsafe fn for_directory(hhdm_offset: u64, pml4: u64) -> Self {
        let phys_offset = VirtAddr::new(hhdm_offset);
        // SAFETY: the HHDM maps every physical address; `pml4` is a valid PML4.
        let l4: &'static mut PageTable = unsafe { &mut *(phys_offset + pml4).as_mut_ptr() };
        // SAFETY: l4 is a valid PML4; phys_offset is the correct HHDM offset so
        // all physical addresses in the hierarchy are reachable.
        let inner = unsafe { OffsetPageTable::new(l4, phys_offset) };
        Self { inner, phys_offset: hhdm_offset, pml4 }
    }

    /// The PML4 of these tables, through the HHDM.
    fn l4(&self) -> &'static mut PageTable {
        // SAFETY: `pml4` is a live PML4 (contract of the constructors); the
        // HHDM maps it.
        unsafe { &mut *((self.phys_offset + self.pml4) as *mut PageTable) }
    }

    /// Removes the bootloader's identity map of [0, 4 GiB) by clearing PML4[0]
    /// (ADR-014): the user half then starts empty, and a bad user pointer
    /// faults instead of reading physical memory. The tables under PML4[0]
    /// are bootloader memory, not reclaimed for now.
    ///
    /// # Safety
    /// - Nothing uses an identity address any more: code, stacks, `BootInfo`
    ///   and MMIO are reached through the kernel image or the HHDM.
    /// - No user mapping exists yet: PML4[0] holds the identity map only.
    ///
    /// # IRQL
    /// Any level. Edits the active PML4 and flushes the TLB.
    pub unsafe fn remove_identity_map(&mut self) {
        let l4 = self.l4();
        l4[0].set_unused();
        // PML4[0] spans whole TLB entries: drop them all, global ones aside
        // (the identity map never sets GLOBAL).
        x86_64::instructions::tlb::flush_all();
    }

    /// Patch `USER_ACCESSIBLE` into the PML4 → PDPT → PD intermediate entries
    /// for `virt`, without touching the leaf PT entry.
    ///
    /// The bootloader builds [0, 4 GiB) with `PRESENT | WRITABLE` on all
    /// intermediate entries but **no** `USER_ACCESSIBLE`.  The x86_64 CPU checks
    /// the U/S bit at *every* level; a supervisor-only intermediate causes a
    /// PROTECTION_VIOLATION for any ring-3 access, regardless of the leaf flags.
    ///
    /// `OffsetPageTable::map_to` sets `USER_ACCESSIBLE` on any **new** intermediate
    /// frame it allocates (because we pass it in `flags`), but it never retrofits
    /// the bit into pre-existing entries created by the bootloader.
    ///
    /// # Safety
    /// - The PML4, PDPT, and PD entries for `virt` must already be PRESENT
    ///   (at least through the PD level) and accessible via the HHDM.
    /// - The patched page tables must be the active CR3.
    /// - IRQL: PASSIVE_LEVEL.
    #[expect(
        dead_code,
        reason = "no caller since the bootloader maps user ranges itself; revisit with per-process PML4 (M2)"
    )]
    unsafe fn patch_user_intermediate_entries(&mut self, virt: VirtAddr) {
        let hhdm = self.phys_offset;

        // ── Level 4 — PML4 ───────────────────────────────────────────────────
        let l4 = self.l4();
        let l4e = &mut l4[virt.p4_index()];
        if !l4e.flags().contains(PageTableFlags::PRESENT) {
            return;
        }
        {
            let (a, f) = (l4e.addr(), l4e.flags() | PageTableFlags::USER_ACCESSIBLE);
            l4e.set_addr(a, f);
        }
        let l3_phys = l4e.addr();

        // ── Level 3 — PDPT ───────────────────────────────────────────────────
        // SAFETY: l3_phys is valid (came from a PRESENT PML4 entry).
        let l3 = unsafe { &mut *((hhdm + l3_phys.as_u64()) as *mut PageTable) };
        let l3e = &mut l3[virt.p3_index()];
        if !l3e.flags().contains(PageTableFlags::PRESENT) {
            return;
        }
        {
            let (a, f) = (l3e.addr(), l3e.flags() | PageTableFlags::USER_ACCESSIBLE);
            l3e.set_addr(a, f);
        }
        // Stop at a 1 GiB huge page — there is no PD below.
        if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
            x86_64::instructions::tlb::flush_all();
            return;
        }
        let l2_phys = l3e.addr();

        // ── Level 2 — PD ─────────────────────────────────────────────────────
        // SAFETY: l2_phys is valid (came from a PRESENT, non-huge PDPT entry).
        let l2 = unsafe { &mut *((hhdm + l2_phys.as_u64()) as *mut PageTable) };
        let l2e = &mut l2[virt.p2_index()];
        if l2e.flags().contains(PageTableFlags::PRESENT) {
            let (a, f) = (l2e.addr(), l2e.flags() | PageTableFlags::USER_ACCESSIBLE);
            l2e.set_addr(a, f);
        }

        // Flush TLB — the CPU caches intermediate entries independently of leaf entries.
        x86_64::instructions::tlb::flush_all();
    }

    /// Map a single 4 KiB page at virtual address `virt` to physical address `phys`.
    ///
    /// Intermediate page-table frames are allocated from the PFN database;
    /// never a PML4 entry of the kernel half, which `mm::address_space` fills
    /// at boot for every address space to share. The TLB entry for `virt` is
    /// flushed after the mapping is installed.
    ///
    /// # Safety
    /// - `virt` must not already be mapped as a 4 KiB page.
    /// - `phys` must be page-aligned and valid.
    /// - Must not be called at IRQL >= DISPATCH, nor with the PFN database's
    ///   lock held (it allocates page tables).
    pub unsafe fn map_page(&mut self, virt: VirtAddr, phys: PhysAddr, flags: PageTableFlags) {
        let h = self.phys_offset;
        let user = flags.contains(PageTableFlags::USER_ACCESSIBLE);
        let mut parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        if user {
            parent |= PageTableFlags::USER_ACCESSIBLE;
        }
        let l4 = self.l4();
        let l4e = &mut l4[virt.p4_index()];
        if !l4e.flags().contains(PageTableFlags::PRESENT) {
            assert!(
                usize::from(virt.p4_index()) < 256 || !crate::address_space::kernel_half_filled(),
                "map_page: kernel PML4 entry {} missing after boot",
                usize::from(virt.p4_index())
            );
            let p = alloc_zeroed_pt_phys();
            l4e.set_addr(PhysAddr::new(p), parent);
        } else {
            l4e.set_addr(l4e.addr(), l4e.flags() | parent);
        }
        let l3 = unsafe { &mut *((h + l4e.addr().as_u64()) as *mut PageTable) };
        let l3e = &mut l3[virt.p3_index()];
        if !l3e.flags().contains(PageTableFlags::PRESENT) {
            let p = alloc_zeroed_pt_phys();
            l3e.set_addr(PhysAddr::new(p), parent);
        } else {
            if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
                panic!("map_page: unexpected 1GiB huge page parent");
            }
            l3e.set_addr(l3e.addr(), l3e.flags() | parent);
        }
        let l2 = unsafe { &mut *((h + l3e.addr().as_u64()) as *mut PageTable) };
        let l2e = &mut l2[virt.p2_index()];
        if l2e.flags().contains(PageTableFlags::PRESENT) && l2e.flags().contains(PageTableFlags::HUGE_PAGE) {
            let base = l2e.addr().as_u64();
            let old = l2e.flags();
            let pt_phys = alloc_zeroed_pt_phys();
            let pt = unsafe { &mut *((h + pt_phys) as *mut PageTable) };
            for i in 0..512usize {
                let mut f = PageTableFlags::PRESENT;
                if old.contains(PageTableFlags::WRITABLE) {
                    f |= PageTableFlags::WRITABLE;
                }
                if old.contains(PageTableFlags::USER_ACCESSIBLE) {
                    f |= PageTableFlags::USER_ACCESSIBLE;
                }
                if old.contains(PageTableFlags::NO_EXECUTE) {
                    f |= PageTableFlags::NO_EXECUTE;
                }
                pt[i].set_addr(PhysAddr::new(base + (i as u64) * 4096), f);
            }
            l2e.set_addr(PhysAddr::new(pt_phys), parent);
            x86_64::instructions::tlb::flush_all();
        }
        if !l2e.flags().contains(PageTableFlags::PRESENT) {
            let p = alloc_zeroed_pt_phys();
            l2e.set_addr(PhysAddr::new(p), parent);
        } else {
            l2e.set_addr(l2e.addr(), l2e.flags() | parent);
        }
        let l1 = unsafe { &mut *((h + l2e.addr().as_u64()) as *mut PageTable) };
        let pte = &mut l1[virt.p1_index()];
        pte.set_addr(phys, flags | PageTableFlags::PRESENT);
        x86_64::instructions::tlb::flush_all();
    }

    /// Unmap the 4 KiB page at `virt` and return its physical frame.
    ///
    /// The returned frame is NOT freed (`mm::pfn`) — the caller is responsible
    /// for releasing it (or tracking it for later reclamation).
    ///
    /// # Safety
    /// `virt` must currently be mapped as a 4 KiB page (not a huge page).
    pub unsafe fn unmap_page(&mut self, virt: VirtAddr) -> PhysFrame<Size4KiB> {
        let page = Page::<Size4KiB>::containing_address(virt);
        // SAFETY: caller guarantees the page is mapped.
        let (frame, flush) = self.inner.unmap(page).expect("MmPageTables::unmap_page: page not mapped");
        flush.flush();
        frame
    }

    /// Replace the flags of the 4 KiB page mapped at `virt` and flush its
    /// TLB entry.
    ///
    /// # Safety
    /// `virt` must currently be mapped as a 4 KiB page, and nothing may rely on
    /// its former access rights.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (allocates nothing).
    pub unsafe fn update_flags(&mut self, virt: VirtAddr, flags: PageTableFlags) {
        let page = Page::<Size4KiB>::containing_address(virt);
        // SAFETY: caller guarantees the page is mapped and its rights may change.
        let flush = unsafe { self.inner.update_flags(page, flags | PageTableFlags::PRESENT) }
            .expect("MmPageTables::update_flags: page not mapped");
        flush.flush();
    }

    /// The level-1 entry of `virt`, if the tables down to it exist and no
    /// huge page covers it. Whoever changes it flushes the TLB.
    ///
    /// # IRQL
    /// Any level.
    pub fn leaf_entry(&mut self, virt: VirtAddr) -> Option<&mut PageTableEntry> {
        let h = self.phys_offset;
        let mut table = self.l4();
        for index in [virt.p4_index(), virt.p3_index(), virt.p2_index()] {
            let entry = &table[index];
            if !entry.flags().contains(PageTableFlags::PRESENT) || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return None;
            }
            // SAFETY: a present, non-huge entry above level 1 holds a page
            // table, which the HHDM maps; `&mut self` keeps it ours.
            table = unsafe { &mut *((h + entry.addr().as_u64()) as *mut PageTable) };
        }
        Some(&mut table[virt.p1_index()])
    }

    /// The leaf flags of a page with these rights.
    ///
    /// # IRQL
    /// Any level.
    pub fn leaf_flags(writable: bool, executable: bool, user: bool) -> PageTableFlags {
        let mut flags = PageTableFlags::PRESENT;
        flags.set(PageTableFlags::WRITABLE, writable);
        flags.set(PageTableFlags::NO_EXECUTE, !executable);
        flags.set(PageTableFlags::USER_ACCESSIBLE, user);
        flags
    }

    /// Translate a virtual address to its physical address and leaf PTE flags.
    ///
    /// Returns `None` if any level of the page-table hierarchy is not present.
    /// For 1 GiB and 2 MiB huge pages the flags are those of the huge-page entry.
    pub fn translate_flags(&self, virt: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> {
        let h = self.phys_offset;
        let l4 = self.l4();
        let e4 = &l4[virt.p4_index()];
        if !e4.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        let l3 = unsafe { &*((h + e4.addr().as_u64()) as *const PageTable) };
        let e3 = &l3[virt.p3_index()];
        if !e3.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if e3.flags().contains(PageTableFlags::HUGE_PAGE) {
            let off = virt.as_u64() & ((1u64 << 30) - 1);
            return Some((PhysAddr::new(e3.addr().as_u64() + off), e3.flags()));
        }
        let l2 = unsafe { &*((h + e3.addr().as_u64()) as *const PageTable) };
        let e2 = &l2[virt.p2_index()];
        if !e2.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if e2.flags().contains(PageTableFlags::HUGE_PAGE) {
            let off = virt.as_u64() & ((1u64 << 21) - 1);
            return Some((PhysAddr::new(e2.addr().as_u64() + off), e2.flags()));
        }
        let l1 = unsafe { &*((h + e2.addr().as_u64()) as *const PageTable) };
        let e1 = &l1[virt.p1_index()];
        if !e1.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        Some((PhysAddr::new(e1.addr().as_u64() + (virt.as_u64() & 0xFFF)), e1.flags()))
    }

    /// Translate a virtual address to its physical address, if mapped.
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let h = self.phys_offset;
        let l4 = self.l4();
        let e4 = &l4[virt.p4_index()];
        if !e4.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        let l3 = unsafe { &*((h + e4.addr().as_u64()) as *const PageTable) };
        let e3 = &l3[virt.p3_index()];
        if !e3.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if e3.flags().contains(PageTableFlags::HUGE_PAGE) {
            let base = e3.addr().as_u64();
            let off = virt.as_u64() & ((1u64 << 30) - 1);
            return Some(PhysAddr::new(base + off));
        }
        let l2 = unsafe { &*((h + e3.addr().as_u64()) as *const PageTable) };
        let e2 = &l2[virt.p2_index()];
        if !e2.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        if e2.flags().contains(PageTableFlags::HUGE_PAGE) {
            let base = e2.addr().as_u64();
            let off = virt.as_u64() & ((1u64 << 21) - 1);
            return Some(PhysAddr::new(base + off));
        }
        let l1 = unsafe { &*((h + e2.addr().as_u64()) as *const PageTable) };
        let e1 = &l1[virt.p1_index()];
        if !e1.flags().contains(PageTableFlags::PRESENT) {
            return None;
        }
        let base = e1.addr().as_u64();
        Some(PhysAddr::new(base + (virt.as_u64() & 0xFFF)))
    }
}
