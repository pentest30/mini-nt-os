//! BumpAllocator — a simple, always-correct kernel heap.
// no_std when targeting bare metal; std when running host tests.
#![cfg_attr(not(test), no_std)]
//!
//! # Design
//! A bump allocator advances a pointer on every allocation and never frees
//! individual blocks. `dealloc` is a no-op (Phase 2 kernel structures are
//! permanent: BTreeMap namespace, Arc<EProcess>, String image names, etc.).
//!
//! # Why not `linked_list_allocator`?
//! `linked_list_allocator 0.10` corrupts its free-list when mixed-size
//! allocs (BTreeMap node sizes ~128–256 bytes) are followed by large allocs
//! (~12 KiB). The bump allocator has zero fragmentation and is trivially
//! correct at the cost of "no real dealloc".
//!
//! # Phase 3 upgrade path
//! When we need real per-process heap (for dynamic process creation), swap
//! this for a slab allocator. The `GlobalAlloc` interface is unchanged so
//! the rest of the kernel sees no difference.

use core::{
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};

/// Simple bump allocator.
///
/// # Safety contract for callers
/// - Call `init()` exactly once before any allocation.
/// - Single-CPU, Phase 2: no concurrent alloc calls.
/// - Callers must disable interrupts when using the global instance to
///   prevent timer-ISR re-entrance (the ISR currently never allocates,
///   but this is cheap insurance).
pub struct BumpAllocator {
    heap_start: AtomicUsize,
    heap_end:   AtomicUsize, // exclusive upper bound
    next:       AtomicUsize, // next free byte
    allocated:  AtomicUsize, // live byte count (dealloc decrements for stats)
}

impl BumpAllocator {
    /// Create an uninitialised allocator. Must call `init` before use.
    pub const fn new() -> Self {
        Self {
            heap_start: AtomicUsize::new(0),
            heap_end:   AtomicUsize::new(0),
            next:       AtomicUsize::new(0),
            allocated:  AtomicUsize::new(0),
        }
    }

    /// Initialise the allocator with a contiguous backing region.
    ///
    /// # Safety
    /// - `start` must point to at least `size` bytes of valid R/W memory.
    /// - The region must remain valid for the lifetime of the allocator.
    /// - Must be called exactly once and before any allocation.
    pub unsafe fn init(&self, start: *mut u8, size: usize) {
        let base = start as usize;
        self.heap_start.store(base, Ordering::Relaxed);
        self.heap_end  .store(base + size, Ordering::Relaxed);
        self.next      .store(base, Ordering::Relaxed);
        self.allocated .store(0, Ordering::Relaxed);
    }

    /// Bytes used so far (includes padding for alignment).
    pub fn used(&self) -> usize {
        self.next.load(Ordering::Relaxed)
            .saturating_sub(self.heap_start.load(Ordering::Relaxed))
    }

    /// Bytes still available.
    pub fn free(&self) -> usize {
        self.heap_end.load(Ordering::Relaxed)
            .saturating_sub(self.next.load(Ordering::Relaxed))
    }

    /// Total heap capacity.
    pub fn capacity(&self) -> usize {
        self.heap_end.load(Ordering::Relaxed)
            .saturating_sub(self.heap_start.load(Ordering::Relaxed))
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    /// Allocate `layout.size()` bytes aligned to `layout.align()`.
    ///
    /// Returns null on OOM.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size  = layout.size();

        // Align `next` up to the required alignment.
        let current = self.next.load(Ordering::Relaxed);
        let aligned = (current + align - 1) & !(align - 1);
        let end_addr = aligned.checked_add(size).unwrap_or(usize::MAX);

        if end_addr > self.heap_end.load(Ordering::Relaxed) {
            // OOM
            return core::ptr::null_mut();
        }

        self.next.store(end_addr, Ordering::Relaxed);
        self.allocated.fetch_add(size, Ordering::Relaxed);
        aligned as *mut u8
    }

    /// No-op — bump allocator does not free individual blocks.
    ///
    /// For Phase 2 this is correct: all kernel structures allocated during
    /// init (namespace BTreeMap, EPROCESS Arc, etc.) are permanent.
    unsafe fn dealloc(&self, _ptr: *mut u8, layout: Layout) {
        // Best-effort stats tracking only.
        self.allocated.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test -p kernel --lib
//
// These tests run on the host (std env supplies memory for the backing array).

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;

    /// Build a `BumpAllocator` backed by a heap-allocated Vec for testing.
    fn make_allocator(size: usize) -> (BumpAllocator, Vec<u8>) {
        let mut backing = vec![0u8; size];
        let alloc = BumpAllocator::new();
        // SAFETY: backing is valid R/W for its lifetime; test owns both.
        unsafe { alloc.init(backing.as_mut_ptr(), backing.len()); }
        (alloc, backing)
    }

    // ── Allocation basics ─────────────────────────────────────────────────────

    #[test]
    fn alloc_single_byte_returns_non_null() {
        let (a, _b) = make_allocator(64);
        let ptr = unsafe { a.alloc(Layout::from_size_align(1, 1).unwrap()) };
        assert!(!ptr.is_null());
    }

    #[test]
    fn alloc_returns_different_pointers() {
        let (a, _b) = make_allocator(64);
        let layout = Layout::from_size_align(8, 8).unwrap();
        let p1 = unsafe { a.alloc(layout) };
        let p2 = unsafe { a.alloc(layout) };
        assert_ne!(p1, p2, "successive allocs must return distinct pointers");
    }

    #[test]
    fn alloc_non_overlapping_ranges() {
        let (a, _b) = make_allocator(256);
        let layout = Layout::from_size_align(32, 8).unwrap();
        let p1 = unsafe { a.alloc(layout) } as usize;
        let p2 = unsafe { a.alloc(layout) } as usize;
        // [p1, p1+32) and [p2, p2+32) must not overlap
        assert!(p1 + 32 <= p2 || p2 + 32 <= p1,
            "allocations overlap: p1={:#x} p2={:#x}", p1, p2);
    }

    // ── Alignment ─────────────────────────────────────────────────────────────

    #[test]
    fn alloc_respects_alignment_1() {
        let (a, _b) = make_allocator(256);
        for align in [1usize, 2, 4, 8, 16, 32, 64] {
            let layout = Layout::from_size_align(1, align).unwrap();
            let ptr = unsafe { a.alloc(layout) } as usize;
            assert_eq!(ptr % align, 0, "ptr {:#x} not aligned to {}", ptr, align);
        }
    }

    #[test]
    fn alloc_64_byte_aligned_from_unaligned_cursor() {
        let (a, _b) = make_allocator(1024);
        // First alloc: 1 byte — cursor will be at start+1 (misaligned for 64)
        unsafe { a.alloc(Layout::from_size_align(1, 1).unwrap()); }
        let ptr = unsafe { a.alloc(Layout::from_size_align(8, 64).unwrap()) } as usize;
        assert_eq!(ptr % 64, 0, "must align to 64 bytes");
    }

    // ── OOM ───────────────────────────────────────────────────────────────────

    #[test]
    fn alloc_returns_null_on_oom() {
        let (a, _b) = make_allocator(16);
        // Consume all 16 bytes
        unsafe { a.alloc(Layout::from_size_align(16, 1).unwrap()); }
        // Next alloc should fail
        let ptr = unsafe { a.alloc(Layout::from_size_align(1, 1).unwrap()) };
        assert!(ptr.is_null(), "must return null when heap is full");
    }

    #[test]
    fn alloc_exactly_fills_heap() {
        let (a, _b) = make_allocator(64);
        let ptr = unsafe { a.alloc(Layout::from_size_align(64, 1).unwrap()) };
        assert!(!ptr.is_null(), "exact-size alloc must succeed");
        let ptr2 = unsafe { a.alloc(Layout::from_size_align(1, 1).unwrap()) };
        assert!(ptr2.is_null(), "any alloc after full heap must fail");
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    #[test]
    fn capacity_reflects_init_size() {
        let (a, _b) = make_allocator(1024);
        assert_eq!(a.capacity(), 1024);
    }

    #[test]
    fn used_increases_after_alloc() {
        let (a, _b) = make_allocator(512);
        let before = a.used();
        unsafe { a.alloc(Layout::from_size_align(64, 1).unwrap()); }
        assert!(a.used() >= before + 64);
    }

    #[test]
    fn free_decreases_after_alloc() {
        let (a, _b) = make_allocator(512);
        let before = a.free();
        unsafe { a.alloc(Layout::from_size_align(64, 1).unwrap()); }
        assert!(a.free() <= before - 64);
    }

    #[test]
    fn dealloc_is_safe_noop() {
        let (a, _b) = make_allocator(128);
        let layout = Layout::from_size_align(32, 8).unwrap();
        let ptr = unsafe { a.alloc(layout) };
        assert!(!ptr.is_null());
        // dealloc must not crash and the allocator must still function
        unsafe { a.dealloc(ptr, layout); }
        let ptr2 = unsafe { a.alloc(layout) };
        assert!(!ptr2.is_null(), "allocator must still work after dealloc");
    }

    // ── Stress: mixed sizes (simulates BTreeMap + large alloc pattern) ────────

    #[test]
    fn mixed_small_then_large_alloc_succeeds() {
        // This is the exact pattern that broke linked_list_allocator.
        // Many small allocs (simulating BTreeMap nodes) then a large alloc.
        let (a, _b) = make_allocator(64 * 1024);
        // Simulate ob/ps init: ~20 allocs of 32–256 bytes
        for _ in 0..20 {
            let l = Layout::from_size_align(128, 8).unwrap();
            let p = unsafe { a.alloc(l) };
            assert!(!p.is_null(), "small alloc during init must succeed");
        }
        // Simulate loader_demo: alloc 12 KiB
        let large = Layout::from_size_align(12 * 1024, 8).unwrap();
        let p = unsafe { a.alloc(large) };
        assert!(!p.is_null(),
            "12 KiB alloc after small allocs must succeed (was broken with linked_list_allocator)");
    }

    #[test]
    fn hundred_varied_allocs_then_large() {
        let (a, _b) = make_allocator(4 * 1024 * 1024); // 4 MiB
        // Simulate realistic kernel init allocation pattern
        for i in 0..100 {
            let size  = 24 + (i % 8) * 32;    // 24..248 bytes
            let align = 1 << (i % 4);          // 1, 2, 4, or 8
            let l = Layout::from_size_align(size, align).unwrap();
            let p = unsafe { a.alloc(l) };
            assert!(!p.is_null(), "alloc {} failed", i);
        }
        // 12 KiB allocation like build_test_pe32
        let big = Layout::from_size_align(12 * 1024, 8).unwrap();
        let p = unsafe { a.alloc(big) };
        assert!(!p.is_null(), "12 KiB alloc after 100 mixed allocs must succeed");
        // 4 KiB for VAD/page-table work  
        let med = Layout::from_size_align(4096, 4096).unwrap();
        let p2 = unsafe { a.alloc(med) };
        assert!(!p2.is_null(), "4 KiB aligned alloc must succeed");
    }
}
