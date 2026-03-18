//! D3 — Kernel page-table manager.
//!
//! Wraps `x86_64::structures::paging::OffsetPageTable` and exposes:
//!   - [`BuddyFrameAllocator`]: implements `FrameAllocator<Size4KiB>` using
//!     the global buddy allocator.
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
    PhysAddr, VirtAddr,
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable,
        Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    },
};

use crate::buddy::{Pfn, BUDDY};

// ── Frame allocator ───────────────────────────────────────────────────────────

/// Frame allocator that delegates to the global buddy allocator (order 0).
///
/// Acquires the buddy lock on every call, so it must be used only at
/// `IRQL PASSIVE_LEVEL`. Suitable for intermediate page-table frame
/// allocation during `map_page`.
pub struct BuddyFrameAllocator;

// SAFETY: Every frame returned is a freshly allocated, page-aligned physical
// frame from the buddy free list; it cannot alias any existing mapping.
unsafe impl FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let pfn = BUDDY.lock().as_mut()?.alloc(0)?; // order 0 = single 4 KiB page
        let phys = pfn.to_phys();
        if phys >= 0x1_0000_0000 {
            panic!("BuddyFrameAllocator: frame above 4GiB not identity-mapped ({:#x})", phys);
        }
        unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096) };
        let addr = PhysAddr::new(phys);
        // SAFETY: to_phys() returns a page-aligned address from the buddy.
        Some(PhysFrame::containing_address(addr))
    }
}

// SAFETY: The frame being freed was previously obtained from the buddy.
impl FrameDeallocator<Size4KiB> for BuddyFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let pfn = Pfn(frame.start_address().as_u64() / 4096);
        if let Some(b) = BUDDY.lock().as_mut() {
            b.free(pfn, 0);
        }
    }
}

fn alloc_zeroed_pt_phys() -> u64 {
    let pfn = BUDDY
        .lock()
        .as_mut()
        .expect("alloc_zeroed_pt_phys: buddy not initialised")
        .alloc(0)
        .expect("alloc_zeroed_pt_phys: out of physical memory");
    let phys = pfn.to_phys();
    if phys >= 0x1_0000_0000 {
        panic!("alloc_zeroed_pt_phys: frame above 4GiB not identity-mapped ({:#x})", phys);
    }
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096) };
    phys
}

// ── Page table manager ────────────────────────────────────────────────────────

/// Kernel page-table manager.
///
/// Constructed once from the active CR3 and the HHDM offset provided by the
/// bootloader. All physical addresses in the existing page tables are
/// accessible at `hhdm_offset + phys`, which `OffsetPageTable` uses to walk
/// the hierarchy.
///
/// # IRQL: PASSIVE_LEVEL — the buddy lock is a `spin::Mutex` (spins at DISPATCH).
pub struct MmPageTables {
    inner:       OffsetPageTable<'static>,
    /// Raw HHDM offset — stored so `patch_user_path` can walk intermediate
    /// entries directly without a second borrow of `self.inner`.
    phys_offset: u64,
}

impl MmPageTables {
    /// Construct from the current CR3 and the bootloader's HHDM offset.
    ///
    /// # Safety
    /// - The bootloader's page tables must be active (called after ExitBootServices).
    /// - `hhdm_offset` must match the value stored in `BootInfo::hhdm_offset`.
    /// - The PML4 frame at the current CR3 must remain live for `'static`
    ///   (it is in bootloader memory, never freed in Phase 1).
    pub unsafe fn new(hhdm_offset: u64) -> Self {
        let phys_offset = VirtAddr::new(hhdm_offset);
        let (l4_frame, _) = Cr3::read();
        let phys = l4_frame.start_address();

        // Translate the PML4 physical address to its HHDM virtual address so we
        // can obtain a Rust reference to the live PageTable.
        //
        // SAFETY: the HHDM maps every physical address; phys is a valid PML4 frame.
        let virt = phys_offset + phys.as_u64();
        let l4: &'static mut PageTable = unsafe { &mut *virt.as_mut_ptr() };

        // SAFETY: l4 is the current, valid PML4; phys_offset is the correct HHDM
        // offset so all physical addresses in the hierarchy are reachable.
        let inner = unsafe { OffsetPageTable::new(l4, phys_offset) };

        Self { inner, phys_offset: hhdm_offset }
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
    unsafe fn patch_user_intermediate_entries(&mut self, virt: VirtAddr) {
        let hhdm = self.phys_offset;

        // ── Level 4 — PML4 ───────────────────────────────────────────────────
        let (l4_frame, _) = Cr3::read();
        // SAFETY: HHDM maps every physical address; l4_frame is a live PML4.
        let l4 = unsafe {
            &mut *((hhdm + l4_frame.start_address().as_u64()) as *mut PageTable)
        };
        let l4e = &mut l4[virt.p4_index()];
        if !l4e.flags().contains(PageTableFlags::PRESENT) { return; }
        {
            let (a, f) = (l4e.addr(), l4e.flags() | PageTableFlags::USER_ACCESSIBLE);
            l4e.set_addr(a, f);
        }
        let l3_phys = l4e.addr();

        // ── Level 3 — PDPT ───────────────────────────────────────────────────
        // SAFETY: l3_phys is valid (came from a PRESENT PML4 entry).
        let l3 = unsafe {
            &mut *((hhdm + l3_phys.as_u64()) as *mut PageTable)
        };
        let l3e = &mut l3[virt.p3_index()];
        if !l3e.flags().contains(PageTableFlags::PRESENT) { return; }
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
        let l2 = unsafe {
            &mut *((hhdm + l2_phys.as_u64()) as *mut PageTable)
        };
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
    /// Intermediate page-table frames are allocated from the buddy allocator.
    /// The TLB entry for `virt` is flushed after the mapping is installed.
    ///
    /// # Safety
    /// - `virt` must not already be mapped as a 4 KiB page.
    /// - `phys` must be page-aligned and valid.
    /// - Must not be called at IRQL >= DISPATCH (buddy lock is a spin mutex).
    pub unsafe fn map_page(
        &mut self,
        virt:  VirtAddr,
        phys:  PhysAddr,
        flags: PageTableFlags,
    ) {
        let h = self.phys_offset;
        let user = flags.contains(PageTableFlags::USER_ACCESSIBLE);
        let mut parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        if user {
            parent |= PageTableFlags::USER_ACCESSIBLE;
        }
        let (l4f, _) = Cr3::read();
        let l4 = unsafe { &mut *((h + l4f.start_address().as_u64()) as *mut PageTable) };
        let l4e = &mut l4[virt.p4_index()];
        if !l4e.flags().contains(PageTableFlags::PRESENT) {
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
    /// The returned frame is NOT freed to the buddy — the caller is responsible
    /// for releasing it (or tracking it for later reclamation).
    ///
    /// # Safety
    /// `virt` must currently be mapped as a 4 KiB page (not a huge page).
    pub unsafe fn unmap_page(&mut self, virt: VirtAddr) -> PhysFrame<Size4KiB> {
        let page = Page::<Size4KiB>::containing_address(virt);
        // SAFETY: caller guarantees the page is mapped.
        let (frame, flush) = self.inner
            .unmap(page)
            .expect("MmPageTables::unmap_page: page not mapped");
        flush.flush();
        frame
    }

    /// Translate a virtual address to its physical address and leaf PTE flags.
    ///
    /// Returns `None` if any level of the page-table hierarchy is not present.
    /// For 1 GiB and 2 MiB huge pages the flags are those of the huge-page entry.
    pub fn translate_flags(&self, virt: VirtAddr) -> Option<(PhysAddr, PageTableFlags)> {
        let h = self.phys_offset;
        let (l4f, _) = Cr3::read();
        let l4 = unsafe { &*((h + l4f.start_address().as_u64()) as *const PageTable) };
        let e4 = &l4[virt.p4_index()];
        if !e4.flags().contains(PageTableFlags::PRESENT) { return None; }
        let l3 = unsafe { &*((h + e4.addr().as_u64()) as *const PageTable) };
        let e3 = &l3[virt.p3_index()];
        if !e3.flags().contains(PageTableFlags::PRESENT) { return None; }
        if e3.flags().contains(PageTableFlags::HUGE_PAGE) {
            let off = virt.as_u64() & ((1u64 << 30) - 1);
            return Some((PhysAddr::new(e3.addr().as_u64() + off), e3.flags()));
        }
        let l2 = unsafe { &*((h + e3.addr().as_u64()) as *const PageTable) };
        let e2 = &l2[virt.p2_index()];
        if !e2.flags().contains(PageTableFlags::PRESENT) { return None; }
        if e2.flags().contains(PageTableFlags::HUGE_PAGE) {
            let off = virt.as_u64() & ((1u64 << 21) - 1);
            return Some((PhysAddr::new(e2.addr().as_u64() + off), e2.flags()));
        }
        let l1 = unsafe { &*((h + e2.addr().as_u64()) as *const PageTable) };
        let e1 = &l1[virt.p1_index()];
        if !e1.flags().contains(PageTableFlags::PRESENT) { return None; }
        Some((PhysAddr::new(e1.addr().as_u64() + (virt.as_u64() & 0xFFF)), e1.flags()))
    }

    /// Translate a virtual address to its physical address, if mapped.
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let h = self.phys_offset;
        let (l4f, _) = Cr3::read();
        let l4 = unsafe { &*((h + l4f.start_address().as_u64()) as *const PageTable) };
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
