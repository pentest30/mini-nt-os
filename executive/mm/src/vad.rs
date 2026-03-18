//! VAD — Virtual Address Descriptor tree.
//!
//! NT tracks every VirtualAlloc region in an AVL tree of VAD nodes
//! per process. Each node describes:
//!   - Virtual address range [start, end)
//!   - Protection flags (PAGE_READWRITE, PAGE_EXECUTE_READ, …)
//!   - Type (private, mapped section, image)
//!
//! The PE loader inserts VAD nodes when mapping an .exe or .dll.
//! Games call VirtualAlloc which also inserts nodes.
//!
//! Implementation note (Phase 2.5):
//!   We use a fixed-size sorted array instead of BTreeMap. The BTreeMap
//!   requires the global allocator for its internal B-tree nodes, and we
//!   observed corruption when the bump allocator's heap region is not yet
//!   fully mapped at the time of the first BTreeMap insert. A flat sorted
//!   array has no internal allocation overhead and is sufficient for the
//!   ~32 VAD entries a process accumulates during Phase 2–3.
//!
//! WI7e Ch.5 §Virtual Address Descriptors
//! ReactOS ntoskrnl/mm/vadnode.c

use bitflags::bitflags;

bitflags! {
    /// Page protection flags — matches NT PAGE_* constants.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageProtect: u32 {
        const NOACCESS           = 0x01;
        const READONLY           = 0x02;
        const READWRITE          = 0x04;
        const WRITECOPY          = 0x08;
        const EXECUTE            = 0x10;
        const EXECUTE_READ       = 0x20;
        const EXECUTE_READWRITE  = 0x40;
        const EXECUTE_WRITECOPY  = 0x80;
        const GUARD              = 0x100;
        const NOCACHE            = 0x200;
    }
}

/// VAD node — describes one virtual memory region.
#[derive(Clone, Debug)]
pub struct VadNode {
    pub start:   u64,
    pub end:     u64,   // exclusive
    pub protect: PageProtect,
    pub kind:    VadKind,
}

impl VadNode {
    pub fn private(start: u64, end: u64, protect: PageProtect) -> Self {
        Self { start, end, protect, kind: VadKind::Private }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VadKind {
    /// Private committed pages (VirtualAlloc MEM_COMMIT).
    Private,
    /// Image mapping (PE loader).
    Image { path: alloc::string::String },
    /// Data file mapping (CreateFileMapping).
    Mapped,
}

// ── Fixed-size sorted-array VAD store ────────────────────────────────────────

/// Maximum number of VAD entries per process.
/// 64 is plenty for Phase 2–3 (image + stubs + PEB/TEB + heap regions).
const MAX_VAD: usize = 64;

/// Per-process VAD tree.
///
/// Internally a sorted array of up to `MAX_VAD` nodes, ordered by `start`.
/// Gives O(log n) find via binary search; O(n) insert/remove via array shift.
/// No heap allocation for internal bookkeeping — avoids bump-allocator races
/// during early boot before the heap mapping is stable.
pub struct VadTree {
    // Invariant: entries[0..len] are valid, sorted by .start, non-overlapping.
    entries: [Option<VadNode>; MAX_VAD],
    len:     usize,
}

impl VadTree {
    pub fn new() -> Self {
        // SAFETY: Option<VadNode> with None is valid zero-bits on all
        // platforms Rust targets; const-init is safe here.
        Self {
            entries: [const { None }; MAX_VAD],
            len: 0,
        }
    }

    /// Number of entries currently in the tree.
    pub fn len(&self) -> usize { self.len }

    /// Returns `true` if the tree has no entries.
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Insert a new VAD node. Returns `Err("VAD overlap")` if the range
    /// overlaps any existing node, or `Err("VAD table full")` if the
    /// fixed-size table is exhausted.
    ///
    /// Overlap condition: two ranges [a, b) and [c, d) overlap iff a < d && c < b.
    pub fn insert(&mut self, node: VadNode) -> Result<(), &'static str> {
        if self.len >= MAX_VAD {
            return Err("VAD table full");
        }

        // Binary search for the insertion point (first entry with start >= node.start).
        let idx = self.lower_bound(node.start);

        // Check the entry immediately before (it might extend into our range).
        if idx > 0 {
            let prev = self.entries[idx - 1].as_ref().unwrap();
            if prev.end > node.start {
                return Err("VAD overlap");
            }
        }
        // Check the entry at idx (it might start inside our range).
        if idx < self.len {
            let next = self.entries[idx].as_ref().unwrap();
            if next.start < node.end {
                return Err("VAD overlap");
            }
        }

        // Shift entries[idx..] right by one to make room.
        let mut i = self.len;
        while i > idx {
            self.entries[i] = self.entries[i - 1].take();
            i -= 1;
        }
        self.entries[idx] = Some(node);
        self.len += 1;
        Ok(())
    }

    /// Find the VAD node containing `addr`, if any.
    pub fn find(&self, addr: u64) -> Option<&VadNode> {
        if self.len == 0 {
            return None;
        }
        // Find the last entry with start <= addr.
        // lower_bound returns first index with start >= addr+1, i.e. start > addr.
        // So the candidate is one before that.
        let idx = self.upper_bound(addr); // first entry with start > addr
        if idx == 0 {
            return None;
        }
        let node = self.entries[idx - 1].as_ref().unwrap();
        if addr < node.end {
            Some(node)
        } else {
            None
        }
    }

    /// Remove the VAD node starting at `start_addr` (VirtualFree MEM_RELEASE).
    /// Returns the removed node, or `None` if not found.
    pub fn remove(&mut self, start_addr: u64) -> Option<VadNode> {
        let idx = self.lower_bound(start_addr);
        if idx >= self.len {
            return None;
        }
        let entry = self.entries[idx].as_ref()?;
        if entry.start != start_addr {
            return None;
        }
        let removed = self.entries[idx].take().unwrap();
        // Shift entries[idx+1..] left by one.
        let mut i = idx;
        while i + 1 < self.len {
            self.entries[i] = self.entries[i + 1].take();
            i += 1;
        }
        self.len -= 1;
        Some(removed)
    }

    /// Return an iterator over (start, end) pairs — for diagnostics only.
    pub fn debug_ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.entries[..self.len]
            .iter()
            .map(|e| { let n = e.as_ref().unwrap(); (n.start, n.end) })
    }

    /// Find the lowest free virtual range of at least `size` bytes,
    /// starting the search at `search_start` (aligned to `align`).
    ///
    /// Returns the base address of the gap, or `None` if the address
    /// space is exhausted.
    ///
    /// Used by `NtAllocateVirtualMemory` when `base_addr == NULL`.
    pub fn find_free_gap(&self, search_start: u64, size: u64, align: u64) -> Option<u64> {
        debug_assert!(align.is_power_of_two());
        let mut cursor = align_up(search_start, align);

        for entry in &self.entries[..self.len] {
            let node = entry.as_ref().unwrap();
            if node.start < search_start {
                // Behind our search start; skip but update cursor if needed.
                if node.end > cursor {
                    cursor = align_up(node.end, align);
                }
                continue;
            }
            // Is there a gap between cursor and this node?
            if node.start >= cursor + size {
                return Some(cursor);
            }
            // Move cursor past this node, realign.
            cursor = align_up(node.end, align);
        }

        // Gap after the last node (or the tree is empty).
        Some(cursor)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Index of the first entry whose `start >= key` (classic lower_bound).
    fn lower_bound(&self, key: u64) -> usize {
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].as_ref().unwrap().start < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Index of the first entry whose `start > key` (classic upper_bound).
    fn upper_bound(&self, key: u64) -> usize {
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].as_ref().unwrap().start <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

#[inline]
fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test -p mm
//
// T2-1a: basic insert, find, remove
// T2-1b: overlap detection (all six overlap cases)
// T2-1c: find_free_gap — empty tree, with gaps, with adjacent allocations

#[cfg(test)]
mod tests {
    use super::*;

    fn rw() -> PageProtect { PageProtect::READWRITE }
    fn rx() -> PageProtect { PageProtect::EXECUTE_READ }

    // ── T2-1a: insert / find / remove ────────────────────────────────────────

    #[test]
    fn insert_single_node_and_find_by_start() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        let n = t.find(0x1000).expect("find at start");
        assert_eq!(n.start, 0x1000);
        assert_eq!(n.end,   0x2000);
    }

    #[test]
    fn find_address_inside_node() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x5000, rw())).unwrap();
        assert!(t.find(0x3000).is_some());
        assert!(t.find(0x4FFF).is_some());
    }

    #[test]
    fn find_address_at_exclusive_end_returns_none() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        assert!(t.find(0x2000).is_none(), "end is exclusive");
    }

    #[test]
    fn find_address_before_any_node_returns_none() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x2000, 0x3000, rw())).unwrap();
        assert!(t.find(0x1000).is_none());
    }

    #[test]
    fn insert_two_adjacent_nodes_both_findable() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        t.insert(VadNode::private(0x2000, 0x3000, rx())).unwrap();
        assert_eq!(t.find(0x1800).map(|n| n.protect), Some(rw()));
        assert_eq!(t.find(0x2000).map(|n| n.protect), Some(rx()));
    }

    #[test]
    fn remove_existing_node_decreases_len() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        assert_eq!(t.len(), 1);
        let removed = t.remove(0x1000).expect("remove must succeed");
        assert_eq!(removed.start, 0x1000);
        assert_eq!(t.len(), 0);
        assert!(t.find(0x1000).is_none(), "gone after remove");
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut t = VadTree::new();
        assert!(t.remove(0xDEAD_0000).is_none());
    }

    #[test]
    fn len_and_is_empty() {
        let mut t = VadTree::new();
        assert!(t.is_empty());
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
    }

    // ── T2-1b: overlap detection ──────────────────────────────────────────────

    #[test]
    fn overlap_exact_same_range_rejected() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x3000, rw())).unwrap();
        assert!(t.insert(VadNode::private(0x1000, 0x3000, rw())).is_err());
    }

    #[test]
    fn overlap_new_starts_inside_existing_rejected() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x3000, rw())).unwrap();
        // New starts inside [0x1000, 0x3000)
        assert!(t.insert(VadNode::private(0x2000, 0x4000, rw())).is_err());
    }

    #[test]
    fn overlap_new_ends_inside_existing_rejected() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x2000, 0x4000, rw())).unwrap();
        // New ends inside [0x2000, 0x4000)
        assert!(t.insert(VadNode::private(0x1000, 0x3000, rw())).is_err());
    }

    #[test]
    fn overlap_new_contains_existing_rejected() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x2000, 0x3000, rw())).unwrap();
        // New fully encloses existing
        assert!(t.insert(VadNode::private(0x1000, 0x4000, rw())).is_err());
    }

    #[test]
    fn overlap_existing_contains_new_rejected() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x4000, rw())).unwrap();
        // New is fully inside existing
        assert!(t.insert(VadNode::private(0x2000, 0x3000, rw())).is_err());
    }

    #[test]
    fn adjacent_ranges_not_considered_overlap() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        // [0x2000, 0x3000) is adjacent — NOT an overlap (end is exclusive)
        assert!(t.insert(VadNode::private(0x2000, 0x3000, rw())).is_ok());
    }

    // ── T2-1c: find_free_gap ──────────────────────────────────────────────────

    const PAGE: u64 = 0x1000;

    #[test]
    fn find_free_gap_empty_tree_returns_search_start() {
        let t = VadTree::new();
        let addr = t.find_free_gap(PAGE, PAGE, PAGE).expect("gap");
        assert_eq!(addr, PAGE);
    }

    #[test]
    fn find_free_gap_before_first_allocation() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(4 * PAGE, 8 * PAGE, rw())).unwrap();
        // Search from PAGE — should find [PAGE, 4*PAGE) which is large enough for 2 pages
        let addr = t.find_free_gap(PAGE, 2 * PAGE, PAGE).expect("gap");
        assert_eq!(addr, PAGE);
    }

    #[test]
    fn find_free_gap_between_two_allocations() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(1 * PAGE, 3 * PAGE, rw())).unwrap(); // gap before: [0,1), after: [3,5)
        t.insert(VadNode::private(5 * PAGE, 8 * PAGE, rw())).unwrap(); // gap [3,5) = 2 pages
        // Ask for exactly 2 pages starting search from PAGE
        let addr = t.find_free_gap(PAGE, 2 * PAGE, PAGE).expect("gap");
        assert_eq!(addr, 3 * PAGE);
    }

    #[test]
    fn find_free_gap_after_all_allocations() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(1 * PAGE, 3 * PAGE, rw())).unwrap();
        t.insert(VadNode::private(3 * PAGE, 5 * PAGE, rw())).unwrap();
        // Gaps: only before [1*PAGE, 3*PAGE) or after [5*PAGE, ...)
        let addr = t.find_free_gap(1 * PAGE, 4 * PAGE, PAGE).expect("gap");
        assert_eq!(addr, 5 * PAGE, "must find gap after all nodes");
    }

    #[test]
    fn find_free_gap_alignment_respected() {
        let t = VadTree::new();
        // Request 64 KiB aligned to 64 KiB, starting from 0x1000
        let align = 0x10000u64;
        let addr = t.find_free_gap(0x1000, align, align).expect("gap");
        assert_eq!(addr % align, 0, "must be aligned to {:#x}", align);
        assert!(addr >= 0x10000, "must be at or above alignment boundary");
    }

    #[test]
    fn find_free_gap_skips_too_small_holes() {
        let mut t = VadTree::new();
        // Hole of 1 page between allocations, but we want 3 pages
        t.insert(VadNode::private(1 * PAGE, 2 * PAGE, rw())).unwrap();
        t.insert(VadNode::private(3 * PAGE, 6 * PAGE, rw())).unwrap();
        // 1-page hole at [2*PAGE, 3*PAGE) is too small; must get gap at [6*PAGE, ...)
        let addr = t.find_free_gap(PAGE, 3 * PAGE, PAGE).expect("gap");
        assert_eq!(addr, 6 * PAGE);
    }

    // ── Additional edge cases ─────────────────────────────────────────────────

    #[test]
    fn insert_out_of_order_sorted_correctly() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x5000, 0x6000, rw())).unwrap();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        t.insert(VadNode::private(0x3000, 0x4000, rw())).unwrap();
        // All three must be findable
        assert!(t.find(0x1000).is_some());
        assert!(t.find(0x3000).is_some());
        assert!(t.find(0x5000).is_some());
        // Gaps must not be findable
        assert!(t.find(0x2000).is_none());
        assert!(t.find(0x4000).is_none());
    }

    #[test]
    fn remove_middle_entry_others_intact() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        t.insert(VadNode::private(0x3000, 0x4000, rw())).unwrap();
        t.insert(VadNode::private(0x5000, 0x6000, rw())).unwrap();
        t.remove(0x3000).expect("remove middle");
        assert_eq!(t.len(), 2);
        assert!(t.find(0x1000).is_some());
        assert!(t.find(0x3000).is_none());
        assert!(t.find(0x5000).is_some());
    }
}
