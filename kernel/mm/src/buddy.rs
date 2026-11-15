//! Buddy allocator — physical page allocator.
//!
//! Manages physical memory in power-of-two page blocks (orders 0–12).
//! Order 0 = 4 KiB (one page), order 12 = 16 MiB.
//!
//! The PFN database (`mm::pfn`) sits on top of it: every allocation and free
//! goes through `mm::pfn`, which owns the one instance (`PAGE_FRAMES`) and
//! checks each page's state.
//!
//! # Free lists without a limit
//! Each order's free list is doubly linked through a table of [`FreeLink`]s,
//! one per page, that the owner hands over before adding memory
//! ([`BuddyAllocator::set_links`]: `mm::init` takes it from the memory map
//! with the PFN database, before any allocation). The first page of a free
//! block holds its order and its neighbours in the list of that order: taking
//! a block, putting one back, and finding whether a block's buddy is free (to
//! merge them) are O(1), and a list holds as many blocks as memory can make.
//! The lists were once fixed arrays of 512 entries per order: a process that
//! left more than 512 free pages whose buddies were still in use (its page
//! tables, freed one by one) stopped the system.

/// Page size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;
/// Maximum order (2^12 pages = 16 MiB block). Increased for Phase 3 DLL loading.
pub const MAX_ORDER: usize = 13;
/// No page: the end of a list.
const NONE: u32 = u32::MAX;
/// The order of a page that heads no free block.
const NOT_FREE: u8 = u8::MAX;

/// A physical page frame number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pfn(pub u64);

impl Pfn {
    pub fn to_phys(self) -> u64 {
        self.0 * PAGE_SIZE as u64
    }
}

/// The free-list links of a page: for the first page of a free block, the
/// block's order and its neighbours in the list of that order.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeLink {
    next: u32,
    prev: u32,
    order: u8,
}

impl FreeLink {
    /// A page that heads no free block.
    pub const UNUSED: Self = Self { next: NONE, prev: NONE, order: NOT_FREE };
}

// ── BuddyAllocator ────────────────────────────────────────────────────────────

/// Buddy allocator state: the head of each order's list; the links live in
/// the table given by [`set_links`](Self::set_links).
pub struct BuddyAllocator {
    heads: [u32; MAX_ORDER],
    links: *mut FreeLink,
    link_count: u64,
    total_pages: u64,
    free_pages: u64,
}

// SAFETY: `links` designates a table reserved for the allocator for the life
// of the system, that only its owner touches (under `mm::pfn::PAGE_FRAMES`).
unsafe impl Send for BuddyAllocator {}

impl Default for BuddyAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl BuddyAllocator {
    /// An allocator without memory nor links, for a static (no heap
    /// allocation).
    pub const fn new() -> Self {
        Self { heads: [NONE; MAX_ORDER], links: core::ptr::null_mut(), link_count: 0, total_pages: 0, free_pages: 0 }
    }

    /// The free lists are linked through `links`, one entry for each of the
    /// pages 0 to `count - 1`: memory can then be added below `count`.
    ///
    /// # Safety
    /// Once; `links` designates `count` entries writable, reserved for the
    /// allocator for its life.
    ///
    /// # Panics
    /// If called twice, or for more pages than a link can name.
    pub unsafe fn set_links(&mut self, links: *mut FreeLink, count: u64) {
        assert!(self.links.is_null(), "free-list links given twice");
        assert!(count < u64::from(NONE), "{count} pages: more than the links can name");
        for i in 0..count as usize {
            // SAFETY: guaranteed by the caller.
            unsafe { links.add(i).write(FreeLink::UNUSED) };
        }
        self.links = links;
        self.link_count = count;
    }

    /// The links of `pfn`.
    ///
    /// # Panics
    /// If `pfn` is beyond the links.
    fn link(&mut self, pfn: u64) -> &mut FreeLink {
        assert!(pfn < self.link_count, "page {pfn:#x} beyond the free-list links");
        // SAFETY: `link_count` entries reserved for the allocator (contract
        // of `set_links`), `pfn` below.
        unsafe { &mut *self.links.add(pfn as usize) }
    }

    /// `pfn` heads a free block of order `order`.
    fn heads_free_block(&self, pfn: u64, order: usize) -> bool {
        // SAFETY: as `link`, `pfn` below `link_count`.
        pfn < self.link_count && unsafe { (*self.links.add(pfn as usize)).order } == order as u8
    }

    /// Puts the block of order `order` at `pfn` at the head of its list.
    fn push(&mut self, order: usize, pfn: u64) {
        let head = self.heads[order];
        *self.link(pfn) = FreeLink { next: head, prev: NONE, order: order as u8 };
        if head != NONE {
            self.link(u64::from(head)).prev = pfn as u32;
        }
        self.heads[order] = pfn as u32;
    }

    /// Takes the block of order `order` at `pfn` out of its list.
    fn unlink(&mut self, order: usize, pfn: u64) {
        let FreeLink { next, prev, .. } = *self.link(pfn);
        if prev == NONE {
            self.heads[order] = next;
        } else {
            self.link(u64::from(prev)).next = next;
        }
        if next != NONE {
            self.link(u64::from(next)).prev = prev;
        }
        *self.link(pfn) = FreeLink::UNUSED;
    }

    /// Takes the first block of the list of order `order`.
    fn pop(&mut self, order: usize) -> Option<u64> {
        let head = self.heads[order];
        if head == NONE {
            return None;
        }
        self.unlink(order, u64::from(head));
        Some(u64::from(head))
    }

    /// Mark a physical region [start_pfn, start_pfn + page_count) as free.
    ///
    /// # Panics
    /// If the region goes beyond the links (`set_links`).
    pub fn add_region(&mut self, start_pfn: Pfn, page_count: u64) {
        let mut pfn = start_pfn.0;
        let end = pfn + page_count;
        assert!(end <= self.link_count, "pages {pfn:#x}..{end:#x} beyond the free-list links");
        self.total_pages += page_count;
        self.free_pages += page_count;

        while pfn < end {
            // Find the largest aligned order that fits within [pfn, end).
            let mut order = MAX_ORDER - 1;
            while order > 0 {
                let block_size = 1u64 << order;
                if pfn.is_multiple_of(block_size) && pfn + block_size <= end {
                    break;
                }
                order -= 1;
            }
            self.push(order, pfn);
            pfn += 1u64 << order;
        }
    }

    /// Allocate 2^order contiguous physical pages. Returns the base PFN.
    ///
    /// # IRQL: any (under the lock of `mm::pfn::PAGE_FRAMES`)
    pub fn alloc(&mut self, order: usize) -> Option<Pfn> {
        assert!(order < MAX_ORDER);

        // Find the smallest free block that satisfies the request.
        for o in order..MAX_ORDER {
            if let Some(pfn) = self.pop(o) {
                // Split excess blocks and put them back.
                for split in (order..o).rev() {
                    let buddy_pfn = pfn + (1u64 << split);
                    self.push(split, buddy_pfn);
                }
                self.free_pages -= 1u64 << order;
                return Some(Pfn(pfn));
            }
        }
        None // Out of memory
    }

    /// Free 2^order pages starting at `pfn`, coalescing with buddies.
    ///
    /// # IRQL: any (under the lock of `mm::pfn::PAGE_FRAMES`)
    pub fn free(&mut self, pfn: Pfn, order: usize) {
        assert!(order < MAX_ORDER);
        self.free_pages += 1u64 << order;

        let mut current_order = order;
        let mut current_pfn = pfn.0;

        while current_order < MAX_ORDER - 1 {
            let buddy_pfn = current_pfn ^ (1u64 << current_order);
            if !self.heads_free_block(buddy_pfn, current_order) {
                break;
            }
            self.unlink(current_order, buddy_pfn);
            current_pfn = current_pfn.min(buddy_pfn);
            current_order += 1;
        }

        self.push(current_order, current_pfn);
    }

    pub fn total_pages(&self) -> u64 {
        self.total_pages
    }
    pub fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Calls `f(pfn, order)` for every free block.
    pub fn for_each_free_block(&self, mut f: impl FnMut(Pfn, usize)) {
        for (order, &head) in self.heads.iter().enumerate() {
            let mut pfn = head;
            while pfn != NONE {
                f(Pfn(u64::from(pfn)), order);
                // SAFETY: a page of a list is below `link_count` (`push`).
                pfn = unsafe { (*self.links.add(pfn as usize)).next };
            }
        }
    }
}

// ── Unit tests (task F3) ─────────────────────────────────────────────────────
//
// Run with: cargo test -p mm
// These tests run on the host (std), so we use a local BuddyAllocator
// instance rather than the global one (`mm::pfn::PAGE_FRAMES`).

#[cfg(test)]
mod tests {
    use super::*;

    /// An allocator with links for `link_count` pages, none free.
    fn with_links(link_count: u64) -> BuddyAllocator {
        let links = alloc::boxed::Box::leak(alloc::vec![FreeLink::UNUSED; link_count as usize].into_boxed_slice());
        let mut a = BuddyAllocator::new();
        // SAFETY: the test's table, never freed.
        unsafe { a.set_links(links.as_mut_ptr(), link_count) };
        a
    }

    fn make_alloc(page_count: u64) -> BuddyAllocator {
        let mut a = with_links(page_count);
        a.add_region(Pfn(0), page_count);
        a
    }

    /// The free blocks, by order.
    fn blocks(a: &BuddyAllocator) -> alloc::vec::Vec<(u64, usize)> {
        let mut blocks = alloc::vec::Vec::new();
        a.for_each_free_block(|pfn, order| blocks.push((pfn.0, order)));
        blocks.sort_unstable();
        blocks
    }

    #[test]
    fn thousands_of_lone_free_pages_fit_in_the_lists() {
        // Every other page freed: none can merge with its buddy, still in use
        // (what a process leaves when its page tables go one by one). The old
        // fixed lists held 512 blocks per order and stopped the system.
        let pages = 8192u64;
        let mut a = make_alloc(pages);
        let taken: alloc::vec::Vec<Pfn> = (0..pages).map(|_| a.alloc(0).expect("a page")).collect();
        assert!(a.alloc(0).is_none());
        for pfn in taken.iter().filter(|pfn| pfn.0 % 2 == 0) {
            a.free(*pfn, 0);
        }
        assert_eq!(a.free_pages(), pages / 2);
        assert_eq!(blocks(&a).len(), (pages / 2) as usize, "4096 lone pages, order 0");
        for pfn in taken.iter().filter(|pfn| pfn.0 % 2 == 1) {
            a.free(*pfn, 0);
        }
        assert_eq!(a.free_pages(), pages);
        assert_eq!(blocks(&a), [(0, 12), (4096, 12)], "all merged back into two blocks of 16 MiB");
    }

    #[test]
    fn a_block_comes_out_of_the_middle_of_its_list() {
        let mut a = make_alloc(16);
        let pages: alloc::vec::Vec<Pfn> = (0..16).map(|_| a.alloc(0).unwrap()).collect();
        for pfn in [0u64, 4, 8, 12, 2] {
            a.free(Pfn(pfn), 0);
        }
        // 3's buddy, 2, is in the middle of the order-0 list: it comes out
        // and the two make an order-1 block.
        a.free(pages[3], 0);
        assert_eq!(blocks(&a), [(0, 0), (2, 1), (4, 0), (8, 0), (12, 0)]);
        assert_eq!(a.alloc(1), Some(Pfn(2)));
    }

    #[test]
    #[should_panic(expected = "beyond the free-list links")]
    fn memory_beyond_the_links_is_refused() {
        let mut a = with_links(8);
        a.add_region(Pfn(4), 8);
    }

    #[test]
    fn test_add_region_counts() {
        let a = make_alloc(1024);
        assert_eq!(a.total_pages(), 1024);
        assert_eq!(a.free_pages(), 1024);
    }

    #[test]
    fn test_alloc_order0_and_free() {
        let mut a = make_alloc(4);
        let pfn = a.alloc(0).expect("alloc order-0 failed");
        assert_eq!(a.free_pages(), 3);
        a.free(pfn, 0);
        assert_eq!(a.free_pages(), 4);
        assert_eq!(a.total_pages(), a.free_pages());
    }

    #[test]
    fn test_alloc_exact_order_alignment() {
        let mut a = make_alloc(64);
        let pfn = a.alloc(3).expect("alloc order-3 failed");
        assert_eq!(pfn.0 % 8, 0, "order-3 block must be 8-page aligned");
        assert_eq!(a.free_pages(), 56);
    }

    #[test]
    fn test_oom_returns_none() {
        let mut a = make_alloc(1);
        let _pfn = a.alloc(0).expect("first alloc should succeed");
        assert!(a.alloc(0).is_none(), "second alloc must return None (OOM)");
    }

    #[test]
    fn test_buddy_merge_on_free() {
        let mut a = make_alloc(2);
        let p0 = a.alloc(0).expect("alloc p0");
        let p1 = a.alloc(0).expect("alloc p1");
        assert_eq!(a.free_pages(), 0);
        a.free(p1, 0);
        a.free(p0, 0);
        assert_eq!(a.free_pages(), 2);
        let merged = a.alloc(1).expect("merged order-1 alloc failed");
        assert_eq!(merged.0 % 2, 0, "merged order-1 block must be 2-page aligned");
    }

    #[test]
    fn test_exhaust_and_recover() {
        let pages = 8u64;
        let mut a = make_alloc(pages);
        let mut allocated = alloc::vec::Vec::new();
        for _ in 0..pages {
            allocated.push(a.alloc(0).expect("should have pages left"));
        }
        assert!(a.alloc(0).is_none(), "must be OOM now");
        for pfn in allocated {
            a.free(pfn, 0);
        }
        assert_eq!(a.free_pages(), pages);
    }
}
