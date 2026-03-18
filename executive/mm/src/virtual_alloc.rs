//! NtAllocateVirtualMemory / NtFreeVirtualMemory — Phase 2 implementation.
//!
//! Games call VirtualAlloc (→ kernel32) which maps to NtAllocateVirtualMemory.
//! Common call patterns in XP-era games:
//!
//!   VirtualAlloc(NULL,  size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
//!   VirtualAlloc(NULL,  size, MEM_RESERVE,              PAGE_NOACCESS)
//!   VirtualAlloc(base,  size, MEM_COMMIT,               PAGE_READWRITE)
//!
//! Design
//! ──────
//! Physical page allocation and page-table mapping are delegated to the
//! `PageMapper` trait. This decouples policy (VAD bookkeeping) from
//! mechanism (buddy allocator + OffsetPageTable), which also makes the
//! code testable with a mock.
//!
//! In production the kernel passes a `KernelPageMapper` that calls
//! `mm::buddy::BUDDY` and `mm::MmPageTables`. In tests we use `MockMapper`.
//!
//! WI7e Ch.5 §NtAllocateVirtualMemory, §NtFreeVirtualMemory

use super::vad::{PageProtect, VadKind, VadNode, VadTree};

// ── Public types ──────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AllocType: u32 {
        const MEM_COMMIT      = 0x1000;
        const MEM_RESERVE     = 0x2000;
        const MEM_RESET       = 0x80000;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FreeType: u32 {
        const MEM_DECOMMIT = 0x4000;
        const MEM_RELEASE  = 0x8000;
    }
}

/// Allocation granularity: 64 KiB (matches NT; base addresses must be
/// aligned to this boundary).
pub const ALLOC_GRANULARITY: u64 = 0x1_0000;

/// First usable user-mode address (skip the null page and below).
pub const USER_VA_START: u64 = 0x0001_0000;

/// 4 KiB page size.
pub const PAGE_SIZE: u64 = 0x1000;

// ── PageMapper trait ──────────────────────────────────────────────────────────

/// Physical-page commit/decommit interface.
///
/// Implemented by the kernel's page-table manager for production use;
/// replaced by `MockMapper` in tests.
///
/// # IRQL
/// Callers must be at PASSIVE_LEVEL. The buddy allocator and
/// `MmPageTables` both hold spin locks that imply DISPATCH_LEVEL
/// semantics.
pub trait PageMapper {
    /// Physically back one 4 KiB virtual page.
    ///
    /// The implementation must:
    ///   1. Allocate one physical frame from the buddy.
    ///   2. Map `virt_addr` → frame in the current page tables.
    ///   3. Zero-fill the frame (required by NT for security).
    fn commit_page(
        &mut self,
        virt_addr:  u64,
        writable:   bool,
        executable: bool,
        user:       bool,
    ) -> Result<(), &'static str>;

    /// Remove physical backing from one 4 KiB virtual page.
    ///
    /// The implementation must unmap the page and return the frame to
    /// the buddy allocator.
    fn decommit_page(&mut self, virt_addr: u64) -> Result<(), &'static str>;
}

// ── Helper: derive protection flags ──────────────────────────────────────────

#[inline]
fn protect_writable(p: PageProtect) -> bool {
    p.intersects(
        PageProtect::READWRITE
        | PageProtect::WRITECOPY
        | PageProtect::EXECUTE_READWRITE
        | PageProtect::EXECUTE_WRITECOPY,
    )
}

#[inline]
fn protect_executable(p: PageProtect) -> bool {
    p.intersects(
        PageProtect::EXECUTE
        | PageProtect::EXECUTE_READ
        | PageProtect::EXECUTE_READWRITE
        | PageProtect::EXECUTE_WRITECOPY,
    )
}

// ── NtAllocateVirtualMemory ───────────────────────────────────────────────────

/// Allocate virtual memory in `vad`, optionally physically committing pages.
///
/// - `base_addr == 0` → bottom-up allocation from `USER_VA_START`.
/// - `base_addr != 0` → hint; aligned down to `ALLOC_GRANULARITY`.
/// - `MEM_RESERVE`    → insert VAD node only; no physical pages.
/// - `MEM_COMMIT`     → also call `mapper.commit_page()` for every page.
/// - On partial commit failure the VAD entry is rolled back (atomic from
///   the VAD perspective; partially committed pages may be leaked — Phase 3
///   adds proper rollback of physical pages).
///
/// Returns the base address of the reserved/committed region.
pub fn allocate(
    vad:        &mut VadTree,
    mapper:     Option<&mut dyn PageMapper>,
    base_addr:  u64,
    size:       u64,
    alloc_type: AllocType,
    protect:    PageProtect,
) -> Result<u64, &'static str> {
    if size == 0 {
        return Err("NtAllocateVirtualMemory: size == 0");
    }
    if !alloc_type.intersects(AllocType::MEM_RESERVE | AllocType::MEM_COMMIT) {
        return Err("NtAllocateVirtualMemory: must specify MEM_RESERVE or MEM_COMMIT");
    }

    let size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let addr = if base_addr == 0 {
        vad.find_free_gap(USER_VA_START, size, ALLOC_GRANULARITY)
            .ok_or("NtAllocateVirtualMemory: address space exhausted")?
    } else {
        // For explicit base addresses snap to page boundary, not 64 KiB.
        // The 64 KiB granularity applies only to bottom-up (base=0) allocations.
        // Kernel-internal callers (setup_process for PEB/TEB) require exact
        // page-level placement; PEB and TEB fall in the same 64 KiB granule
        // and would alias if we rounded down that far.
        base_addr & !(PAGE_SIZE - 1)
    };

    vad.insert(VadNode {
        start:   addr,
        end:     addr + size,
        protect,
        kind:    VadKind::Private,
    })?;

    // Physically commit pages if requested.
    if alloc_type.contains(AllocType::MEM_COMMIT) {
        if let Some(m) = mapper {
            let writable   = protect_writable(protect);
            let executable = protect_executable(protect);

            let mut va = addr;
            while va < addr + size {
                if let Err(e) = m.commit_page(va, writable, executable, /*user=*/true) {
                    // Roll back the VAD entry so the address range appears free.
                    // Physical pages already committed are leaked in Phase 2.
                    // TODO Phase 3: free partially committed frames here.
                    vad.remove(addr);
                    return Err(e);
                }
                va += PAGE_SIZE;
            }
        }
    }

    Ok(addr)
}

// ── NtFreeVirtualMemory ───────────────────────────────────────────────────────

/// Free virtual memory.
///
/// - `MEM_RELEASE`   → remove VAD entry and decommit all pages.
/// - `MEM_DECOMMIT`  → Phase 2: accepted but no per-page tracking yet,
///                     so pages are not individually decommitted (no-op).
pub fn free(
    vad:       &mut VadTree,
    mapper:    Option<&mut dyn PageMapper>,
    base_addr: u64,
    _size:     u64,
    free_type: FreeType,
) -> Result<(), &'static str> {
    if free_type.contains(FreeType::MEM_RELEASE) {
        let node = vad.remove(base_addr)
            .ok_or("NtFreeVirtualMemory: address not found")?;

        // Decommit every page that was backed with physical frames.
        if let Some(m) = mapper {
            let mut va = node.start;
            while va < node.end {
                // Best-effort: ignore individual decommit errors.
                let _ = m.decommit_page(va);
                va += PAGE_SIZE;
            }
        }
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test -p mm
//
// T4-1a: PageMapper::commit_page called correct number of times
// T4-1b: MEM_RESERVE does NOT trigger commit_page
// T4-1c: Commit failure rolls back VAD (atomicity)
// T4-1d: decommit_page called for every page on MEM_RELEASE
// T4-1e: Protection flags propagated correctly to mapper
//
// Legacy T2-2 tests retained below with updated signatures.

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::vad::PageProtect;

    // ── MockMapper ─────────────────────────────────────────────────────────────

    struct MockMapper {
        committed:    alloc::vec::Vec<(u64, bool, bool, bool)>, // (virt, writable, exec, user)
        decommitted:  alloc::vec::Vec<u64>,
        fail_on:      Option<u64>,  // return Err on this virtual address
    }

    impl MockMapper {
        fn new() -> Self {
            Self { committed: alloc::vec::Vec::new(), decommitted: alloc::vec::Vec::new(), fail_on: None }
        }
        fn with_fail(virt: u64) -> Self {
            Self { committed: alloc::vec::Vec::new(), decommitted: alloc::vec::Vec::new(), fail_on: Some(virt) }
        }
    }

    impl PageMapper for MockMapper {
        fn commit_page(&mut self, virt: u64, w: bool, x: bool, u: bool) -> Result<(), &'static str> {
            if self.fail_on == Some(virt) { return Err("mock commit fail"); }
            self.committed.push((virt, w, x, u));
            Ok(())
        }
        fn decommit_page(&mut self, virt: u64) -> Result<(), &'static str> {
            self.decommitted.push(virt);
            Ok(())
        }
    }

    fn rw()  -> PageProtect { PageProtect::READWRITE }
    fn rx()  -> PageProtect { PageProtect::EXECUTE_READ }
    fn na()  -> PageProtect { PageProtect::NOACCESS }

    fn commit(vad: &mut VadTree, mapper: &mut MockMapper, size: u64) -> u64 {
        allocate(vad, Some(mapper), 0, size,
                 AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw())
            .expect("alloc failed")
    }

    fn reserve(vad: &mut VadTree, size: u64) -> u64 {
        allocate(vad, None, 0, size, AllocType::MEM_RESERVE, na())
            .expect("reserve failed")
    }

    // ── T4-1a: commit call count ──────────────────────────────────────────────

    #[test]
    fn one_page_commit_calls_commit_once() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        commit(&mut vad, &mut m, PAGE_SIZE);
        assert_eq!(m.committed.len(), 1);
    }

    #[test]
    fn four_page_commit_calls_commit_four_times() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        commit(&mut vad, &mut m, 4 * PAGE_SIZE);
        assert_eq!(m.committed.len(), 4);
    }

    #[test]
    fn commit_addresses_are_page_aligned_and_sequential() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        let base = commit(&mut vad, &mut m, 3 * PAGE_SIZE);
        let addrs: alloc::vec::Vec<u64> = m.committed.iter().map(|&(a, _, _, _)| a).collect();
        assert_eq!(addrs, [base, base + PAGE_SIZE, base + 2 * PAGE_SIZE]);
    }

    // ── T4-1b: MEM_RESERVE does not commit ───────────────────────────────────

    #[test]
    fn mem_reserve_does_not_call_commit() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        allocate(&mut vad, Some(&mut m), 0, 0x8000,
                 AllocType::MEM_RESERVE, na()).unwrap();
        assert_eq!(m.committed.len(), 0, "MEM_RESERVE must not commit pages");
    }

    #[test]
    fn no_mapper_mem_commit_still_succeeds() {
        // If mapper == None, MEM_COMMIT is a no-op physically (useful for
        // Phase 2 lazy-commit paths and the existing T2-2 tests).
        let mut vad = VadTree::new();
        let addr = allocate(&mut vad, None, 0, PAGE_SIZE,
                            AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw())
            .expect("alloc without mapper must succeed");
        assert!(vad.find(addr).is_some());
    }

    // ── T4-1c: rollback on commit failure ────────────────────────────────────

    #[test]
    fn commit_failure_on_first_page_rolls_back_vad() {
        let mut vad = VadTree::new();
        // Bottom-up first address will be USER_VA_START aligned to 64 KiB.
        let expected_base = (USER_VA_START + ALLOC_GRANULARITY - 1) & !(ALLOC_GRANULARITY - 1);
        let mut m = MockMapper::with_fail(expected_base);
        let result = allocate(&mut vad, Some(&mut m), 0, PAGE_SIZE,
                              AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw());
        assert!(result.is_err(), "must propagate commit error");
        assert!(vad.is_empty(), "VAD must be rolled back on commit failure");
    }

    #[test]
    fn commit_failure_on_mid_page_rolls_back_vad() {
        let mut vad = VadTree::new();
        // Fail on the 3rd page of a 4-page allocation.
        let expected_base = (USER_VA_START + ALLOC_GRANULARITY - 1) & !(ALLOC_GRANULARITY - 1);
        let fail_addr = expected_base + 2 * PAGE_SIZE;
        let mut m = MockMapper::with_fail(fail_addr);
        let result = allocate(&mut vad, Some(&mut m), 0, 4 * PAGE_SIZE,
                              AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw());
        assert!(result.is_err());
        assert!(vad.is_empty(), "partial commit must roll back VAD");
    }

    #[test]
    fn commit_failure_at_explicit_base_rolls_back_vad() {
        let mut vad = VadTree::new();
        let base = 0x0040_0000u64;
        let mut m = MockMapper::with_fail(base);
        let result = allocate(&mut vad, Some(&mut m), base, PAGE_SIZE,
                              AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw());
        assert!(result.is_err());
        assert!(vad.is_empty(), "VAD must be rolled back at explicit base");
    }

    // ── T4-1d: decommit on MEM_RELEASE ───────────────────────────────────────

    #[test]
    fn free_release_calls_decommit_for_all_pages() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        let addr = commit(&mut vad, &mut m, 4 * PAGE_SIZE);
        free(&mut vad, Some(&mut m), addr, 0, FreeType::MEM_RELEASE).unwrap();
        assert_eq!(m.decommitted.len(), 4, "must decommit all 4 pages on release");
    }

    #[test]
    fn free_release_decommit_addresses_are_correct() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        let addr = commit(&mut vad, &mut m, 2 * PAGE_SIZE);
        free(&mut vad, Some(&mut m), addr, 0, FreeType::MEM_RELEASE).unwrap();
        assert_eq!(m.decommitted, [addr, addr + PAGE_SIZE]);
    }

    #[test]
    fn free_decommit_only_does_not_call_decommit_page() {
        // MEM_DECOMMIT without MEM_RELEASE — Phase 2 no-op.
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        let addr = commit(&mut vad, &mut m, PAGE_SIZE);
        m.decommitted.clear(); // reset after initial commit
        free(&mut vad, Some(&mut m), addr, PAGE_SIZE, FreeType::MEM_DECOMMIT).unwrap();
        assert_eq!(m.decommitted.len(), 0, "MEM_DECOMMIT without RELEASE must be no-op");
        assert!(vad.find(addr).is_some(), "VAD entry must remain after decommit-only");
    }

    // ── T4-1e: protection flags ───────────────────────────────────────────────

    #[test]
    fn readwrite_protect_gives_writable_not_executable() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        allocate(&mut vad, Some(&mut m), 0x0040_0000, PAGE_SIZE,
                 AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, PageProtect::READWRITE).unwrap();
        let (_, w, x, _) = m.committed[0];
        assert!(w,  "READWRITE must be writable");
        assert!(!x, "READWRITE must not be executable");
    }

    #[test]
    fn execute_read_protect_gives_executable_not_writable() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        allocate(&mut vad, Some(&mut m), 0x0040_0000, PAGE_SIZE,
                 AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, PageProtect::EXECUTE_READ).unwrap();
        let (_, w, x, _) = m.committed[0];
        assert!(!w, "EXECUTE_READ must not be writable");
        assert!(x,  "EXECUTE_READ must be executable");
    }

    #[test]
    fn noaccess_protect_gives_neither_writable_nor_executable() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        allocate(&mut vad, Some(&mut m), 0x0040_0000, PAGE_SIZE,
                 AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, PageProtect::NOACCESS).unwrap();
        let (_, w, x, _) = m.committed[0];
        assert!(!w, "NOACCESS must not be writable");
        assert!(!x, "NOACCESS must not be executable");
    }

    #[test]
    fn all_pages_marked_user_accessible() {
        let mut vad = VadTree::new();
        let mut m   = MockMapper::new();
        commit(&mut vad, &mut m, 3 * PAGE_SIZE);
        for &(_, _, _, u) in &m.committed {
            assert!(u, "all user allocations must have USER_ACCESSIBLE flag");
        }
    }

    // ── Legacy T2-2 tests (updated for new API) ───────────────────────────────

    fn alloc_no_mapper(vad: &mut VadTree, size: u64) -> u64 {
        allocate(vad, None, 0, size, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw())
            .expect("alloc failed")
    }

    #[test]
    fn null_base_returns_nonzero_address() {
        let mut vad = VadTree::new();
        let addr = alloc_no_mapper(&mut vad, PAGE_SIZE);
        assert_ne!(addr, 0);
        assert_eq!(addr % ALLOC_GRANULARITY, 0);
    }

    #[test]
    fn explicit_base_uses_hint() {
        let mut vad = VadTree::new();
        let addr = allocate(&mut vad, None, 0x0040_0000, PAGE_SIZE,
                            AllocType::MEM_RESERVE, rw()).unwrap();
        assert_eq!(addr, 0x0040_0000);
    }

    #[test]
    fn size_rounded_up_to_page() {
        let mut vad = VadTree::new();
        let addr = alloc_no_mapper(&mut vad, 1);
        let node = vad.find(addr).unwrap();
        assert_eq!(node.end - node.start, PAGE_SIZE);
    }

    #[test]
    fn zero_size_returns_error() {
        let mut vad = VadTree::new();
        assert!(allocate(&mut vad, None, 0, 0, AllocType::MEM_RESERVE, rw()).is_err());
    }

    #[test]
    fn successive_allocs_non_overlapping() {
        let mut vad = VadTree::new();
        let a1 = alloc_no_mapper(&mut vad, PAGE_SIZE);
        let a2 = alloc_no_mapper(&mut vad, PAGE_SIZE);
        let n1 = vad.find(a1).unwrap();
        let n2 = vad.find(a2).unwrap();
        assert!(n1.end <= n2.start || n2.end <= n1.start);
    }

    #[test]
    fn free_release_removes_vad() {
        let mut vad = VadTree::new();
        let addr = alloc_no_mapper(&mut vad, PAGE_SIZE);
        free(&mut vad, None, addr, PAGE_SIZE, FreeType::MEM_RELEASE).unwrap();
        assert!(vad.find(addr).is_none());
    }
}
