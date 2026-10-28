//! Kernel pool: the global allocator for kernel memory.
//!
//! Replaces the bump allocator, which never freed anything (audit §3.2).
//!
//! - Blocks up to 2 KiB come from per-size-class free lists (powers of two,
//!   16 B to 2 KiB), refilled one page at a time.
//! - Larger blocks take whole pages from an address-ordered list of free page
//!   runs, which merges neighbours on free.
//!
//! Every block is aligned to its class size (or to the page for page runs), so
//! the layout passed to `dealloc` is enough to find its class: no headers.
//!
//! Nothing is paged (ADR-010), so this is the nonpaged pool, usable up to
//! DISPATCH_LEVEL. The backing region is fixed at `init` and pre-mapped by the
//! caller; slab pages are not returned to the page runs. Growth and per-tag
//! pools come with Mm's pools in M2.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

const PAGE: usize = 4096;
/// Smallest block: room for the free-list link, and 16-byte alignment.
const MIN_BLOCK: usize = 16;
/// Largest size served by a size class; larger requests take whole pages.
const MAX_BLOCK: usize = 2048;
const NUM_CLASSES: usize = 8; // 16, 32, 64, 128, 256, 512, 1024, 2048

/// Free block of a size class; the link lives in the free memory itself.
struct FreeBlock {
    next: *mut FreeBlock,
}

/// Free run of whole pages; the header lives in its first page.
struct FreeRun {
    pages: usize,
    next: *mut FreeRun,
}

struct Inner {
    classes: [*mut FreeBlock; NUM_CLASSES],
    /// Free page runs, sorted by address, never adjacent (merged on free).
    runs: *mut FreeRun,
    start: usize,
    end: usize,
    used: usize,
}

/// The kernel pool. Create with [`Pool::new`], hand it its region with
/// [`Pool::init`], then use it as the `#[global_allocator]`.
pub struct Pool {
    locked: AtomicBool,
    inner: UnsafeCell<Inner>,
}

// SAFETY: `inner` is only reached through `with_lock`, which serialises access.
unsafe impl Sync for Pool {}

impl Pool {
    /// An empty pool: every allocation fails until [`Pool::init`].
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            inner: UnsafeCell::new(Inner {
                classes: [ptr::null_mut(); NUM_CLASSES],
                runs: ptr::null_mut(),
                start: 0,
                end: 0,
                used: 0,
            }),
        }
    }

    /// Gives the pool its backing region. The region is trimmed to whole pages.
    ///
    /// # Safety
    /// `[start, start + size)` must be mapped, writable, used by nothing else
    /// and valid for the life of the pool. Call once, before any allocation.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub unsafe fn init(&self, start: *mut u8, size: usize) {
        let begin = align_up(start as usize, PAGE);
        let end = (start as usize + size) & !(PAGE - 1);
        self.with_lock(|inner| {
            inner.start = begin;
            inner.end = end;
            inner.used = 0;
            inner.classes = [ptr::null_mut(); NUM_CLASSES];
            inner.runs = ptr::null_mut();
            if end > begin {
                // SAFETY: the caller hands over [begin, end), page-aligned and writable.
                unsafe { inner.give_pages(begin, (end - begin) / PAGE) };
            }
        });
    }

    /// Bytes currently handed out (rounded up to the block or page size).
    pub fn used(&self) -> usize {
        self.with_lock(|inner| inner.used)
    }

    /// Bytes not handed out, including blocks cached in the size classes.
    pub fn free(&self) -> usize {
        self.with_lock(|inner| (inner.end - inner.start) - inner.used)
    }

    /// Size of the backing region.
    pub fn capacity(&self) -> usize {
        self.with_lock(|inner| inner.end - inner.start)
    }

    /// Runs `f` with the pool locked. On the bare-metal target, interrupts are
    /// off while the lock is held, so an interrupt can never spin on it.
    fn with_lock<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let irq = irq_save();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held, so this is the only live reference to inner.
        let result = f(unsafe { &mut *self.inner.get() });
        self.locked.store(false, Ordering::Release);
        irq_restore(irq);
        result
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: blocks come from the region given to `init`, never overlap while
// live (each is on no free list until freed), and honour the layout's
// alignment (class blocks are aligned to their power-of-two size, page runs
// to the page or more).
unsafe impl GlobalAlloc for Pool {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with_lock(|inner| match class_of(layout) {
            // SAFETY: the pool's invariants hold under the lock.
            Some(class) => unsafe { inner.alloc_block(class) },
            // SAFETY: as above.
            None => unsafe { inner.alloc_pages(pages_for(layout.size()), layout.align()) },
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.with_lock(|inner| match class_of(layout) {
            // SAFETY: the caller returns a block this pool handed out for `layout`.
            Some(class) => unsafe { inner.free_block(ptr as usize, class) },
            None => {
                let pages = pages_for(layout.size());
                inner.used -= pages * PAGE;
                // SAFETY: as above; these pages were taken by alloc_pages.
                unsafe { inner.give_pages(ptr as usize, pages) };
            }
        })
    }
}

impl Inner {
    /// # Safety
    /// Pool invariants: the free lists and runs describe free memory in the region.
    unsafe fn alloc_block(&mut self, class: usize) -> *mut u8 {
        if self.classes[class].is_null() {
            // SAFETY: forwarded.
            let page = unsafe { self.take_pages(1, PAGE) };
            if page == 0 {
                return ptr::null_mut();
            }
            let size = class_size(class);
            // Thread the new page's blocks onto the class list, lowest first.
            for offset in (0..PAGE).step_by(size).rev() {
                let block = (page + offset) as *mut FreeBlock;
                // SAFETY: the page was just taken from the runs; block is inside it.
                unsafe { block.write(FreeBlock { next: self.classes[class] }) };
                self.classes[class] = block;
            }
        }
        let block = self.classes[class];
        // SAFETY: block heads the class list, so it is a free block of this class.
        self.classes[class] = unsafe { (*block).next };
        self.used += class_size(class);
        block as *mut u8
    }

    /// # Safety
    /// `addr` must be a live block of `class` handed out by `alloc_block`.
    unsafe fn free_block(&mut self, addr: usize, class: usize) {
        let block = addr as *mut FreeBlock;
        // SAFETY: the block is ours again and at least MIN_BLOCK bytes.
        unsafe { block.write(FreeBlock { next: self.classes[class] }) };
        self.classes[class] = block;
        self.used -= class_size(class);
    }

    /// # Safety
    /// Pool invariants hold.
    unsafe fn alloc_pages(&mut self, pages: usize, align: usize) -> *mut u8 {
        // SAFETY: forwarded.
        let addr = unsafe { self.take_pages(pages, align) };
        if addr == 0 {
            return ptr::null_mut();
        }
        self.used += pages * PAGE;
        addr as *mut u8
    }

    /// Takes `pages` pages aligned to `align` (at least a page) from the first
    /// run that fits, splitting it. Returns 0 when nothing fits.
    ///
    /// # Safety
    /// Pool invariants hold.
    unsafe fn take_pages(&mut self, pages: usize, align: usize) -> usize {
        let align = align.max(PAGE);
        let mut link: *mut *mut FreeRun = &mut self.runs;
        // SAFETY: every run reached from self.runs is a free run in the region.
        unsafe {
            while !(*link).is_null() {
                let run = *link;
                let run_start = run as usize;
                let run_end = run_start + (*run).pages * PAGE;
                let start = align_up(run_start, align);
                let end = start + pages * PAGE;
                if end <= run_end {
                    let next = (*run).next;
                    // Unlink the run, then give back what is left on both sides.
                    *link = next;
                    if start > run_start {
                        self.give_pages(run_start, (start - run_start) / PAGE);
                    }
                    if run_end > end {
                        self.give_pages(end, (run_end - end) / PAGE);
                    }
                    return start;
                }
                link = &mut (*run).next;
            }
        }
        0
    }

    /// Inserts `[addr, addr + pages * PAGE)` into the runs, merging neighbours.
    ///
    /// # Safety
    /// The pages must be free, page-aligned, inside the region and not already
    /// in a run.
    unsafe fn give_pages(&mut self, addr: usize, pages: usize) {
        if pages == 0 {
            return;
        }
        let mut prev: *mut FreeRun = ptr::null_mut();
        let mut next = self.runs;
        // SAFETY: runs reached from self.runs are free runs in the region; the
        // new pages are free and ours to write.
        unsafe {
            while !next.is_null() && (next as usize) < addr {
                prev = next;
                next = (*next).next;
            }
            let run = addr as *mut FreeRun;
            run.write(FreeRun { pages, next });
            if !next.is_null() && addr + pages * PAGE == next as usize {
                (*run).pages += (*next).pages;
                (*run).next = (*next).next;
            }
            if prev.is_null() {
                self.runs = run;
            } else if prev as usize + (*prev).pages * PAGE == addr {
                (*prev).pages += (*run).pages;
                (*prev).next = (*run).next;
            } else {
                (*prev).next = run;
            }
        }
    }
}

/// Size class for `layout`, or `None` when it needs whole pages.
fn class_of(layout: Layout) -> Option<usize> {
    let size = layout.size().max(layout.align()).max(MIN_BLOCK).next_power_of_two();
    if size > MAX_BLOCK {
        return None;
    }
    Some((size.trailing_zeros() - MIN_BLOCK.trailing_zeros()) as usize)
}

const fn class_size(class: usize) -> usize {
    MIN_BLOCK << class
}

fn pages_for(size: usize) -> usize {
    size.max(1).div_ceil(PAGE)
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(target_os = "none")]
fn irq_save() -> bool {
    let enabled = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();
    enabled
}

#[cfg(target_os = "none")]
fn irq_restore(enabled: bool) {
    if enabled {
        x86_64::instructions::interrupts::enable();
    }
}

// Host tests run in user mode, where cli/sti fault: the lock alone serialises.
#[cfg(not(target_os = "none"))]
fn irq_save() -> bool {
    false
}

#[cfg(not(target_os = "none"))]
fn irq_restore(_enabled: bool) {}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    /// A pool over a fresh page-aligned host buffer, freed on drop.
    struct TestPool {
        pool: Pool,
        base: *mut u8,
        layout: Layout,
    }

    impl TestPool {
        fn new(size: usize) -> Self {
            let layout = Layout::from_size_align(size, PAGE).unwrap();
            // SAFETY: non-zero size.
            let base = unsafe { std::alloc::alloc(layout) };
            assert!(!base.is_null());
            let pool = Pool::new();
            // SAFETY: the buffer is ours, writable, and outlives the pool.
            unsafe { pool.init(base, size) };
            Self { pool, base, layout }
        }

        fn alloc(&self, size: usize, align: usize) -> *mut u8 {
            // SAFETY: valid layout with non-zero size.
            unsafe { self.pool.alloc(Layout::from_size_align(size, align).unwrap()) }
        }

        fn dealloc(&self, ptr: *mut u8, size: usize, align: usize) {
            // SAFETY: ptr came from alloc with the same layout.
            unsafe { self.pool.dealloc(ptr, Layout::from_size_align(size, align).unwrap()) }
        }

        fn contains(&self, ptr: *mut u8, size: usize) -> bool {
            let (p, b) = (ptr as usize, self.base as usize);
            p >= b && p + size <= b + self.layout.size()
        }
    }

    impl Drop for TestPool {
        fn drop(&mut self) {
            // SAFETY: allocated in new() with this layout.
            unsafe { std::alloc::dealloc(self.base, self.layout) };
        }
    }

    // ── Ported from bump-alloc ────────────────────────────────────────────────

    #[test]
    fn alloc_single_byte_returns_non_null() {
        let t = TestPool::new(64 * 1024);
        assert!(!t.alloc(1, 1).is_null());
    }

    #[test]
    fn alloc_returns_different_pointers() {
        let t = TestPool::new(64 * 1024);
        assert_ne!(t.alloc(8, 8), t.alloc(8, 8));
    }

    #[test]
    fn alloc_non_overlapping_ranges() {
        let t = TestPool::new(64 * 1024);
        let a = t.alloc(100, 8) as usize;
        let b = t.alloc(100, 8) as usize;
        assert!(a + 100 <= b || b + 100 <= a);
    }

    #[test]
    fn alloc_respects_alignment() {
        let t = TestPool::new(256 * 1024);
        for align in [1, 2, 8, 16, 64, 256, 4096, 8192] {
            let p = t.alloc(24, align);
            assert!(!p.is_null());
            assert_eq!(p as usize % align, 0, "align {align}");
        }
    }

    #[test]
    fn alloc_returns_null_on_oom() {
        let t = TestPool::new(16 * 1024);
        assert!(t.alloc(64 * 1024, 8).is_null());
    }

    #[test]
    fn alloc_exactly_fills_heap() {
        let t = TestPool::new(16 * 1024);
        let p = t.alloc(16 * 1024, 8);
        assert!(!p.is_null() && t.contains(p, 16 * 1024));
        assert!(t.alloc(1, 1).is_null(), "heap is full");
    }

    #[test]
    fn capacity_reflects_init_size() {
        let t = TestPool::new(64 * 1024);
        assert_eq!(t.pool.capacity(), 64 * 1024);
    }

    #[test]
    fn used_and_free_track_allocations() {
        let t = TestPool::new(64 * 1024);
        assert_eq!(t.pool.used(), 0);
        let p = t.alloc(100, 8); // 128-byte class
        assert_eq!(t.pool.used(), 128);
        assert_eq!(t.pool.free(), 64 * 1024 - 128);
        t.dealloc(p, 100, 8);
        assert_eq!(t.pool.used(), 0);
    }

    #[test]
    fn mixed_small_then_large_alloc_succeeds() {
        let t = TestPool::new(256 * 1024);
        for _ in 0..50 {
            assert!(!t.alloc(48, 8).is_null());
        }
        let big = t.alloc(12 * 1024, 16);
        assert!(!big.is_null() && t.contains(big, 12 * 1024));
    }

    #[test]
    fn hundred_varied_allocs_then_large() {
        let t = TestPool::new(1024 * 1024);
        for i in 1..=100 {
            assert!(!t.alloc(i * 7, 8).is_null());
        }
        assert!(!t.alloc(64 * 1024, 4096).is_null());
    }

    // ── Real freeing ──────────────────────────────────────────────────────────

    #[test]
    fn freed_block_is_reused() {
        let t = TestPool::new(64 * 1024);
        let a = t.alloc(200, 8);
        t.dealloc(a, 200, 8);
        assert_eq!(t.alloc(200, 8), a);
    }

    #[test]
    fn freed_pages_merge_back_into_one_run() {
        let t = TestPool::new(24 * 1024);
        let a = t.alloc(8 * 1024, 8);
        let b = t.alloc(8 * 1024, 8);
        let c = t.alloc(8 * 1024, 8);
        assert!(t.alloc(4096, 8).is_null(), "full");
        // Free in an order that needs both forward and backward merges.
        t.dealloc(a, 8 * 1024, 8);
        t.dealloc(c, 8 * 1024, 8);
        t.dealloc(b, 8 * 1024, 8);
        let all = t.alloc(24 * 1024, 8);
        assert_eq!(all, t.base, "the three runs merged into the whole region");
    }

    #[test]
    fn oom_recovers_after_free() {
        let t = TestPool::new(16 * 1024);
        let p = t.alloc(16 * 1024, 8);
        assert!(t.alloc(4096, 8).is_null());
        t.dealloc(p, 16 * 1024, 8);
        assert!(!t.alloc(4096, 8).is_null());
    }

    /// The pattern that made `linked_list_allocator` "corrupt" (bump-alloc
    /// notes): B-tree-node-sized blocks mixed with ~12 KiB blocks, here with
    /// frees and content checks.
    #[test]
    fn btree_nodes_mixed_with_12k_blocks_keep_their_contents() {
        let t = TestPool::new(2 * 1024 * 1024);
        let mut live: Vec<(*mut u8, usize, u8)> = Vec::new();
        for round in 0..400usize {
            let size = if round % 5 == 4 { 12 * 1024 } else { 128 + (round * 37) % 160 };
            let p = t.alloc(size, 8);
            assert!(!p.is_null() && t.contains(p, size), "round {round}");
            let tag = round as u8;
            // SAFETY: p is a live block of `size` bytes.
            unsafe { ptr::write_bytes(p, tag, size) };
            live.push((p, size, tag));
            if round % 3 == 2 {
                let (q, qs, qt) = live.remove(round % live.len());
                // SAFETY: q is live with qs bytes.
                assert!(unsafe { core::slice::from_raw_parts(q, qs) }.iter().all(|&b| b == qt));
                t.dealloc(q, qs, 8);
            }
        }
        for (p, size, tag) in live {
            // SAFETY: p is live with size bytes.
            assert!(unsafe { core::slice::from_raw_parts(p, size) }.iter().all(|&b| b == tag));
        }
    }

    /// Random sizes and alignments, random frees, content checked on every free.
    #[test]
    fn random_workload_never_overlaps() {
        let t = TestPool::new(4 * 1024 * 1024);
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut live: BTreeMap<usize, (usize, usize, u8)> = BTreeMap::new();
        for i in 0..5000u32 {
            if live.is_empty() || rand() % 3 != 0 {
                let size = match rand() % 10 {
                    0 => 4096 + (rand() % 20_000) as usize,
                    _ => 1 + (rand() % 2500) as usize,
                };
                let align = 1usize << (rand() % 7);
                let p = t.alloc(size, align);
                if p.is_null() {
                    continue;
                }
                let addr = p as usize;
                assert_eq!(addr % align, 0);
                assert!(t.contains(p, size));
                if let Some((&a, &(s, _, _))) = live.range(..=addr).next_back() {
                    assert!(a + s <= addr, "overlaps the block below");
                }
                if let Some((&a, _)) = live.range(addr..).next() {
                    assert!(addr + size <= a, "overlaps the block above");
                }
                let tag = i as u8;
                // SAFETY: p is a live block of `size` bytes.
                unsafe { ptr::write_bytes(p, tag, size) };
                live.insert(addr, (size, align, tag));
            } else {
                let key = *live.keys().nth((rand() as usize) % live.len()).unwrap();
                let (size, align, tag) = live.remove(&key).unwrap();
                // SAFETY: key is a live block of `size` bytes.
                let bytes = unsafe { core::slice::from_raw_parts(key as *const u8, size) };
                assert!(bytes.iter().all(|&b| b == tag), "block at {key:#x} was overwritten");
                t.dealloc(key as *mut u8, size, align);
            }
        }
        for (addr, (size, align, _)) in core::mem::take(&mut live) {
            t.dealloc(addr as *mut u8, size, align);
        }
        assert_eq!(t.pool.used(), 0);
    }

    #[test]
    fn class_of_maps_layouts_to_classes() {
        let l = |s, a| Layout::from_size_align(s, a).unwrap();
        assert_eq!(class_of(l(1, 1)), Some(0));
        assert_eq!(class_of(l(16, 8)), Some(0));
        assert_eq!(class_of(l(17, 8)), Some(1));
        assert_eq!(class_of(l(8, 64)), Some(2), "alignment raises the class");
        assert_eq!(class_of(l(2048, 8)), Some(7));
        assert_eq!(class_of(l(2049, 8)), None);
        assert_eq!(class_of(l(8, 4096)), None, "page alignment needs whole pages");
    }
}
