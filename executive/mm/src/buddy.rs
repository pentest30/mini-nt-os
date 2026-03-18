//! Buddy allocator — physical page allocator.
//!
//! Manages physical memory in power-of-two page blocks (orders 0–10).
//! Order 0 = 4 KiB (one page), Order 10 = 4 MiB.
//!
//! NT's real PFN database is more complex (coloured, NUMA-aware),
//! but this covers Phase 1 and Phase 2 needs.
//!
//! # No-alloc design
//! Free lists use fixed-size arrays instead of Vec so the buddy allocator
//! can be initialised BEFORE the kernel heap exists (mm::init() is called
//! before the LockedHeap is set up).
//!
//! MAX_FREE_ENTRIES per order is 512.  Worst-case with 128 MiB RAM and 31
//! BootInfo regions the total entries across all levels is ~350, so 512 per
//! level is a large safety margin.

use spin::Mutex;

/// Page size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;
/// Maximum order (2^10 pages = 4 MiB block).
pub const MAX_ORDER: usize = 11;
/// Maximum free-list entries per order level.
const MAX_FREE_ENTRIES: usize = 512;

/// A physical page frame number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pfn(pub u64);

impl Pfn {
    pub fn to_phys(self) -> u64 { self.0 * PAGE_SIZE as u64 }
}

// ── Fixed-size free list ──────────────────────────────────────────────────────

/// A fixed-capacity stack of PFNs — no heap allocation required.
struct FreeList {
    data:  [u64; MAX_FREE_ENTRIES],
    count: usize,
}

impl FreeList {
    const fn new() -> Self {
        Self { data: [0u64; MAX_FREE_ENTRIES], count: 0 }
    }

    fn push(&mut self, pfn: u64) {
        assert!(self.count < MAX_FREE_ENTRIES, "buddy free list overflow");
        self.data[self.count] = pfn;
        self.count += 1;
    }

    fn pop(&mut self) -> Option<u64> {
        if self.count == 0 { return None; }
        self.count -= 1;
        Some(self.data[self.count])
    }

    /// Remove the entry at `pos` (swap with last for O(1) removal).
    fn remove(&mut self, pos: usize) {
        self.data[pos] = self.data[self.count - 1];
        self.count -= 1;
    }

    fn position(&self, pfn: u64) -> Option<usize> {
        self.data[..self.count].iter().position(|&x| x == pfn)
    }
}

// ── BuddyAllocator ────────────────────────────────────────────────────────────

/// Buddy allocator state — ~44 KiB in kernel BSS (no heap required).
pub struct BuddyAllocator {
    /// free_lists[order] = set of free block PFNs of size 2^order pages.
    free_lists:  [FreeList; MAX_ORDER],
    total_pages: u64,
    free_pages:  u64,
}

pub static BUDDY: Mutex<Option<BuddyAllocator>> = Mutex::new(None);

impl BuddyAllocator {
    /// Create a new empty allocator (no heap allocation).
    pub fn new() -> Self {
        // core::array::from_fn works for any N without heap.
        Self {
            free_lists:  core::array::from_fn(|_| FreeList::new()),
            total_pages: 0,
            free_pages:  0,
        }
    }

    /// Mark a physical region [start_pfn, start_pfn + page_count) as free.
    pub fn add_region(&mut self, start_pfn: Pfn, page_count: u64) {
        let mut pfn = start_pfn.0;
        let end = pfn + page_count;
        self.total_pages += page_count;
        self.free_pages  += page_count;

        while pfn < end {
            // Find the largest aligned order that fits within [pfn, end).
            let mut order = MAX_ORDER - 1;
            while order > 0 {
                let block_size = 1u64 << order;
                if pfn % block_size == 0 && pfn + block_size <= end {
                    break;
                }
                order -= 1;
            }
            self.free_lists[order].push(pfn);
            pfn += 1u64 << order;
        }
    }

    /// Allocate 2^order contiguous physical pages. Returns the base PFN.
    ///
    /// # IRQL: any (spin lock held by caller via BUDDY.lock())
    pub fn alloc(&mut self, order: usize) -> Option<Pfn> {
        assert!(order < MAX_ORDER);

        // Find the smallest free block that satisfies the request.
        for o in order..MAX_ORDER {
            if let Some(pfn) = self.free_lists[o].pop() {
                // Split excess blocks and put them back.
                for split in (order..o).rev() {
                    let buddy_pfn = pfn + (1u64 << split);
                    self.free_lists[split].push(buddy_pfn);
                }
                self.free_pages -= 1u64 << order;
                return Some(Pfn(pfn));
            }
        }
        None // Out of memory
    }

    /// Free 2^order pages starting at `pfn`, coalescing with buddies.
    ///
    /// # IRQL: any (spin lock held by caller via BUDDY.lock())
    pub fn free(&mut self, pfn: Pfn, order: usize) {
        assert!(order < MAX_ORDER);
        self.free_pages += 1u64 << order;

        let mut current_order = order;
        let mut current_pfn   = pfn.0;

        while current_order < MAX_ORDER - 1 {
            let buddy_pfn = current_pfn ^ (1u64 << current_order);
            if let Some(pos) = self.free_lists[current_order].position(buddy_pfn) {
                self.free_lists[current_order].remove(pos);
                current_pfn   = current_pfn.min(buddy_pfn);
                current_order += 1;
            } else {
                break;
            }
        }

        self.free_lists[current_order].push(current_pfn);
    }

    pub fn total_pages(&self) -> u64 { self.total_pages }
    pub fn free_pages(&self)  -> u64 { self.free_pages  }
}

/// Global accessor — initialised by `mm::init()`.
pub fn with<F, R>(f: F) -> R
where F: FnOnce(&mut BuddyAllocator) -> R
{
    f(BUDDY.lock().as_mut().expect("Mm buddy allocator not initialised"))
}

// ── Unit tests (task F3) ─────────────────────────────────────────────────────
//
// Run with: cargo test -p mm
// These tests run on the host (std), so we use a local BuddyAllocator
// instance rather than the global BUDDY mutex.

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alloc(page_count: u64) -> BuddyAllocator {
        let mut a = BuddyAllocator::new();
        a.add_region(Pfn(0), page_count);
        a
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
