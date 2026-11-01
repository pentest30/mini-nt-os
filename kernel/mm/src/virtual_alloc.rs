//! NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory et
//! NtQueryVirtualMemory : la mémoire privée d'un processus (02 §5.3).
//!
//! Games call VirtualAlloc (→ kernel32) which maps to NtAllocateVirtualMemory.
//! Common call patterns in XP-era games:
//!
//!   VirtualAlloc(NULL,  size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
//!   VirtualAlloc(NULL,  size, MEM_RESERVE,              PAGE_NOACCESS)
//!   VirtualAlloc(base,  size, MEM_COMMIT,               PAGE_READWRITE)
//!
//! La VAD (`mm::vad`) tient l'état de chaque page : réservée, ou commitée avec
//! sa protection. Un commit se fait dans une réservation existante, un
//! décommit rend les pages réservées, une libération rend toute la
//! réservation.
//!
//! Design
//! ──────
//! Physical page allocation and page-table mapping are delegated to the
//! `PageMapper` trait. This decouples policy (VAD bookkeeping) from
//! mechanism (PFN database + page tables), which also makes the
//! code testable with a mock.
//!
//! In production the kernel passes a `KernelPageMapper` that calls
//! `mm::pfn` and `mm::MmPageTables`. In tests we use `MockMapper`.
//!
//! Le mapper d'un espace d'adresses (`mm::address_space`) ne projette rien au
//! commit : la faute de page le fera (`mm::fault`). Ceux de l'ancien code
//! projettent tout de suite, et y rendent lisibles `PAGE_NOACCESS` et
//! `PAGE_GUARD`.
//!
//! Pas encore : libération d'une partie d'une réservation, `MEM_RESET`.
//!
//! WI7e Ch.5 §NtAllocateVirtualMemory, §NtFreeVirtualMemory

use abi::ntstatus::{
    NtStatus, STATUS_CONFLICTING_ADDRESSES, STATUS_FREE_VM_NOT_AT_BASE, STATUS_INVALID_PAGE_PROTECTION,
    STATUS_INVALID_PARAMETER, STATUS_MEMORY_NOT_ALLOCATED, STATUS_NOT_COMMITTED, STATUS_NO_MEMORY,
    STATUS_UNABLE_TO_DELETE_SECTION, STATUS_UNABLE_TO_FREE_VM,
};

use super::section::{self, SectionKind};
use super::vad::{PageChange, PageProtect, PageState, VadKind, VadNode, VadTree, USER_VA_END};

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

/// L'état d'une plage (`MEMORY_BASIC_INFORMATION.State`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MemState {
    Commit = 0x1000,
    Reserve = 0x2000,
    Free = 0x1_0000,
}

/// Le type d'une plage (`MEMORY_BASIC_INFORMATION.Type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MemType {
    Private = 0x2_0000,
    Mapped = 0x4_0000,
    Image = 0x100_0000,
}

/// Ce que NtQueryVirtualMemory (`MemoryBasicInformation`) dit d'une adresse :
/// la plus longue suite de pages de même état et de même protection qui
/// commence à sa page, et la réservation qui la contient. Le layout de l'ABI
/// viendra avec l'appel système (M3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionInfo {
    pub base_address: u64,
    /// Début de la réservation ; 0 pour une plage libre.
    pub allocation_base: u64,
    /// Protection donnée à la réservation ; vide pour une plage libre.
    pub allocation_protect: PageProtect,
    pub region_size: u64,
    pub state: MemState,
    /// Protection des pages commitées ; vide si réservées, `NOACCESS` si libres.
    pub protect: PageProtect,
    /// `None` pour une plage libre.
    pub kind: Option<MemType>,
}

// ── PageMapper trait ──────────────────────────────────────────────────────────

/// Physical-page commit/decommit interface.
///
/// Implemented by the kernel's page-table manager for production use;
/// replaced by `MockMapper` in tests.
///
/// # IRQL
/// Callers must be at PASSIVE_LEVEL: committing a page allocates a physical
/// page and maybe page tables.
pub trait PageMapper {
    /// Physically back one 4 KiB virtual page.
    ///
    /// The implementation must:
    ///   1. Allocate one physical frame from the PFN database.
    ///   2. Map `virt_addr` → frame in the current page tables.
    ///   3. Zero-fill the frame (required by NT for security).
    ///
    /// Fails, with nothing mapped, when memory runs out (`STATUS_NO_MEMORY`).
    fn commit_page(&mut self, virt_addr: u64, writable: bool, executable: bool, user: bool) -> Result<(), NtStatus>;

    /// Remove physical backing from one 4 KiB virtual page that
    /// [`commit_page`](Self::commit_page) backed: unmap it and return its
    /// frame to the PFN database.
    fn decommit_page(&mut self, virt_addr: u64);

    /// Give `protect` to one committed 4 KiB virtual page; with
    /// [`commit_page`](Self::commit_page), the page it backed.
    fn protect_page(&mut self, virt_addr: u64, protect: PageProtect);
}

/// Les adresses des pages de `[start, end)`.
fn pages(start: u64, end: u64) -> impl Iterator<Item = u64> {
    (start..end).step_by(PAGE_SIZE as usize)
}

fn page_align_up(addr: u64) -> Option<u64> {
    Some(addr.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1))
}

/// Les pages qui couvrent `[base, base + size)`, non vide et dans l'espace
/// utilisateur. Une plage désignée peut commencer sous [`USER_VA_START`],
/// jusqu'à la page 0, comme sous XP : `RtlpInitEnvironment` réserve ainsi le
/// premier Mio d'un sous-système (à partir de l'adresse 4). Une plage sans
/// base n'y est jamais placée.
fn user_range(base: u64, size: u64) -> Result<(u64, u64), NtStatus> {
    let start = base & !(PAGE_SIZE - 1);
    let end = base.checked_add(size).and_then(page_align_up).ok_or(STATUS_INVALID_PARAMETER)?;
    if size == 0 || end > USER_VA_END {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok((start, end))
}

// ── NtAllocateVirtualMemory ───────────────────────────────────────────────────

/// Réserve ou commite de la mémoire privée dans `vad` ; rend la base de la
/// plage.
///
/// - `base_addr == 0` : une nouvelle réservation, la plus basse qui tienne au-dessus
///   de `USER_VA_START`, alignée sur `ALLOC_GRANULARITY`, même avec `MEM_COMMIT`
///   seul (comme NT).
/// - `base_addr != 0` avec `MEM_RESERVE` : une nouvelle réservation des pages qui
///   couvrent `[base_addr, base_addr + size)` ; `STATUS_CONFLICTING_ADDRESSES` si
///   elle recoupe une réservation. Elle s'aligne sur la page et non sur 64 Kio :
///   l'ancien chargeur (`setup_process`) place le PEB et le TEB dans le même
///   granule de 64 Kio.
/// - `base_addr != 0` avec `MEM_COMMIT` seul : la plage doit tenir dans une
///   réservation (`STATUS_CONFLICTING_ADDRESSES` sinon).
///
/// `MEM_COMMIT` commite les pages réservées de la plage et donne `protect` à ses
/// pages déjà commitées. Avec `mapper`, les premières sont projetées et les
/// secondes reprotégées ; en cas d'échec, tout est défait : pages rendues,
/// protections et VAD comme avant.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn allocate(
    vad: &mut VadTree,
    mapper: Option<&mut dyn PageMapper>,
    base_addr: u64,
    size: u64,
    alloc_type: AllocType,
    protect: PageProtect,
) -> Result<u64, NtStatus> {
    if size == 0 || !alloc_type.intersects(AllocType::MEM_RESERVE | AllocType::MEM_COMMIT) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Copy-on-write needs a section to copy from.
    if !protect.is_valid() || protect.copy_on_write() {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }

    let (start, end, reserve) = if base_addr == 0 {
        let size = page_align_up(size).ok_or(STATUS_INVALID_PARAMETER)?;
        let start = vad.find_free_gap(USER_VA_START, size, ALLOC_GRANULARITY).ok_or(STATUS_NO_MEMORY)?;
        (start, start + size, true)
    } else {
        let (start, end) = user_range(base_addr, size)?;
        (start, end, alloc_type.contains(AllocType::MEM_RESERVE))
    };

    if reserve {
        vad.insert(VadNode::reserved(start, end, protect, VadKind::Private))
            .map_err(|_| STATUS_CONFLICTING_ADDRESSES)?;
    } else if vad.find(start).is_none_or(|node| end > node.end || node.kind != VadKind::Private) {
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }
    if !alloc_type.contains(AllocType::MEM_COMMIT) {
        return Ok(start);
    }

    let node = vad.find_mut(start).expect("the reservation found or inserted above");
    let changes = node.commit(start, end, protect);
    if let Some(m) = mapper {
        if let Err(status) = map_commit(m, &changes, protect) {
            if reserve {
                vad.remove(start);
            } else {
                for c in &changes {
                    match c.old_state {
                        PageState::Reserved => node.decommit(c.start, c.end),
                        PageState::Committed => node.commit(c.start, c.end, c.old_protect),
                    };
                }
            }
            return Err(status);
        }
    }
    Ok(start)
}

/// Projette les pages que [`VadNode::commit`] a changées : une page qui était
/// réservée reçoit une page physique, une page déjà commitée sa nouvelle
/// protection. En cas d'échec, défait ce qui a été fait.
fn map_commit(m: &mut dyn PageMapper, changes: &[PageChange], protect: PageProtect) -> Result<(), NtStatus> {
    for (i, c) in changes.iter().enumerate() {
        for va in pages(c.start, c.end) {
            let done = match c.old_state {
                PageState::Reserved => m.commit_page(va, protect.writable(), protect.executable(), /*user=*/ true),
                PageState::Committed => {
                    m.protect_page(va, protect);
                    Ok(())
                }
            };
            if let Err(status) = done {
                // The changes come in address order: undo every page below `va`.
                for undo in &changes[..=i] {
                    for back in pages(undo.start, undo.end.min(va)) {
                        match undo.old_state {
                            PageState::Reserved => m.decommit_page(back),
                            PageState::Committed => m.protect_page(back, undo.old_protect),
                        }
                    }
                }
                return Err(status);
            }
        }
    }
    Ok(())
}

// ── NtFreeVirtualMemory ───────────────────────────────────────────────────────

/// Rend de la mémoire privée ; rend la plage traitée (base, taille).
///
/// - `MEM_DECOMMIT` : les pages commitées de `[base_addr, base_addr + size)`
///   redeviennent réservées, et `mapper` rend leurs pages physiques. La plage
///   tient dans une réservation (`STATUS_UNABLE_TO_FREE_VM` sinon) ;
///   `size == 0` désigne toute la réservation qui commence en `base_addr`.
/// - `MEM_RELEASE` : la réservation qui commence en `base_addr` disparaît, ses
///   pages commitées d'abord décommitées. `size` vaut 0 ou couvre toute la
///   réservation (`STATUS_UNABLE_TO_FREE_VM` sinon).
///
/// Une adresse hors de toute réservation donne `STATUS_MEMORY_NOT_ALLOCATED`,
/// une adresse qui n'en est pas le début là où il le faut
/// `STATUS_FREE_VM_NOT_AT_BASE`. Une vue de section (image, fichier) se rend
/// par NtUnmapViewOfSection : `STATUS_UNABLE_TO_DELETE_SECTION`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn free(
    vad: &mut VadTree,
    mapper: Option<&mut dyn PageMapper>,
    base_addr: u64,
    size: u64,
    free_type: FreeType,
) -> Result<(u64, u64), NtStatus> {
    let release = free_type == FreeType::MEM_RELEASE;
    if !release && free_type != FreeType::MEM_DECOMMIT {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let node = vad.find_mut(base_addr).ok_or(STATUS_MEMORY_NOT_ALLOCATED)?;
    if node.kind != VadKind::Private {
        return Err(STATUS_UNABLE_TO_DELETE_SECTION);
    }
    let (start, end) = if size == 0 { (base_addr, node.end) } else { user_range(base_addr, size)? };
    if (size == 0 || release) && start != node.start {
        return Err(STATUS_FREE_VM_NOT_AT_BASE);
    }
    if end > node.end || (release && end != node.end) {
        return Err(STATUS_UNABLE_TO_FREE_VM);
    }

    let changes = node.decommit(start, end);
    if let Some(m) = mapper {
        for va in changes.iter().flat_map(|c| pages(c.start, c.end)) {
            m.decommit_page(va);
        }
    }
    if release {
        vad.remove(start);
    }
    Ok((start, end - start))
}

// ── NtProtectVirtualMemory ────────────────────────────────────────────────────

/// Donne la protection `protect` aux pages de `[base_addr, base_addr + size)`,
/// qui sont toutes commitées et d'une même réservation ; rend l'ancienne
/// protection de la première.
///
/// `STATUS_CONFLICTING_ADDRESSES` si la plage ne tient pas dans une
/// réservation, `STATUS_NOT_COMMITTED` si une de ses pages n'est pas commitée ;
/// rien ne change alors.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn protect(
    vad: &mut VadTree,
    mapper: Option<&mut dyn PageMapper>,
    base_addr: u64,
    size: u64,
    protect: PageProtect,
) -> Result<PageProtect, NtStatus> {
    if !protect.is_valid() {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    let (start, end) = user_range(base_addr, size)?;
    let node = vad.find_mut(start).filter(|node| end <= node.end).ok_or(STATUS_CONFLICTING_ADDRESSES)?;
    let protect = match &node.kind {
        VadKind::Private if protect.copy_on_write() => return Err(STATUS_INVALID_PAGE_PROTECTION),
        VadKind::Private => protect,
        VadKind::View { section, .. } => section::view_protection(section, protect)?,
    };
    let old = node.protect(start, end, protect).ok_or(STATUS_NOT_COMMITTED)?;
    if let Some(m) = mapper {
        for va in pages(start, end) {
            m.protect_page(va, protect);
        }
    }
    Ok(old)
}

// ── NtQueryVirtualMemory ──────────────────────────────────────────────────────

/// Décrit la plage qui commence à la page de `addr` : libre jusqu'à la
/// réservation suivante, ou la suite de pages de même état de sa réservation.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn query(vad: &VadTree, addr: u64) -> Result<RegionInfo, NtStatus> {
    if addr >= USER_VA_END {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let page = addr & !(PAGE_SIZE - 1);
    let Some(node) = vad.find(page) else {
        let end = vad.next_after(page).map_or(USER_VA_END, |next| next.start);
        return Ok(RegionInfo {
            base_address: page,
            allocation_base: 0,
            allocation_protect: PageProtect::empty(),
            region_size: end - page,
            state: MemState::Free,
            protect: PageProtect::NOACCESS,
            kind: None,
        });
    };
    let (run_start, run) = node.run_at(page).expect("a page of the reservation");
    let committed = run.state == PageState::Committed;
    Ok(RegionInfo {
        base_address: page,
        allocation_base: node.start,
        allocation_protect: node.protect,
        region_size: run_start + run.pages * PAGE_SIZE - page,
        state: if committed { MemState::Commit } else { MemState::Reserve },
        protect: if committed { run.protect } else { PageProtect::empty() },
        kind: Some(match &node.kind {
            VadKind::Private => MemType::Private,
            VadKind::View { section, .. } if section.kind() == SectionKind::Image => MemType::Image,
            VadKind::View { .. } => MemType::Mapped,
        }),
    })
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
// Legacy T2-2 tests retained below with updated signatures, then reserve and
// commit, decommit, release, protect and query.

#[cfg(test)]
mod tests {
    use super::super::section::Section;
    use super::super::vad::{PageProtect, PageRun};
    use super::*;
    use abi::ntstatus::STATUS_SECTION_PROTECTION;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    // ── MockMapper ─────────────────────────────────────────────────────────────

    #[derive(Default)]
    struct MockMapper {
        committed: Vec<(u64, bool, bool, bool)>, // (virt, writable, exec, user)
        decommitted: Vec<u64>,
        protected: Vec<(u64, bool, bool)>, // (virt, writable, exec)
        fail_on: Option<u64>,              // return Err on this virtual address
    }

    impl MockMapper {
        fn new() -> Self {
            Self::default()
        }
        fn with_fail(virt: u64) -> Self {
            Self { fail_on: Some(virt), ..Self::default() }
        }
        fn committed_pages(&self) -> Vec<u64> {
            self.committed.iter().map(|&(va, ..)| va).collect()
        }
    }

    impl PageMapper for MockMapper {
        fn commit_page(&mut self, virt: u64, w: bool, x: bool, u: bool) -> Result<(), NtStatus> {
            if self.fail_on == Some(virt) {
                return Err(STATUS_NO_MEMORY);
            }
            self.committed.push((virt, w, x, u));
            Ok(())
        }
        fn decommit_page(&mut self, virt: u64) {
            self.decommitted.push(virt);
        }
        fn protect_page(&mut self, virt: u64, p: PageProtect) {
            self.protected.push((virt, p.writable(), p.executable()));
        }
    }

    fn rw() -> PageProtect {
        PageProtect::READWRITE
    }
    fn na() -> PageProtect {
        PageProtect::NOACCESS
    }

    fn commit(vad: &mut VadTree, mapper: &mut MockMapper, size: u64) -> u64 {
        allocate(vad, Some(mapper), 0, size, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw())
            .expect("alloc failed")
    }

    // ── T4-1a: commit call count ──────────────────────────────────────────────

    #[test]
    fn one_page_commit_calls_commit_once() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        commit(&mut vad, &mut m, PAGE_SIZE);
        assert_eq!(m.committed.len(), 1);
    }

    #[test]
    fn four_page_commit_calls_commit_four_times() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        commit(&mut vad, &mut m, 4 * PAGE_SIZE);
        assert_eq!(m.committed.len(), 4);
    }

    #[test]
    fn commit_addresses_are_page_aligned_and_sequential() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        let base = commit(&mut vad, &mut m, 3 * PAGE_SIZE);
        let addrs: alloc::vec::Vec<u64> = m.committed.iter().map(|&(a, _, _, _)| a).collect();
        assert_eq!(addrs, [base, base + PAGE_SIZE, base + 2 * PAGE_SIZE]);
    }

    // ── T4-1b: MEM_RESERVE does not commit ───────────────────────────────────

    #[test]
    fn mem_reserve_does_not_call_commit() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        allocate(&mut vad, Some(&mut m), 0, 0x8000, AllocType::MEM_RESERVE, na()).unwrap();
        assert_eq!(m.committed.len(), 0, "MEM_RESERVE must not commit pages");
    }

    #[test]
    fn no_mapper_mem_commit_still_succeeds() {
        // If mapper == None, MEM_COMMIT is a no-op physically (useful for
        // Phase 2 lazy-commit paths and the existing T2-2 tests).
        let mut vad = VadTree::new();
        let addr = allocate(&mut vad, None, 0, PAGE_SIZE, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw())
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
        let result =
            allocate(&mut vad, Some(&mut m), 0, PAGE_SIZE, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw());
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
        let result =
            allocate(&mut vad, Some(&mut m), 0, 4 * PAGE_SIZE, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw());
        assert_eq!(result, Err(STATUS_NO_MEMORY), "must propagate the mapper's status");
        assert!(vad.is_empty(), "partial commit must roll back VAD");
        assert_eq!(m.decommitted, [expected_base, expected_base + PAGE_SIZE], "the pages backed so far go back");
    }

    #[test]
    fn commit_failure_at_explicit_base_rolls_back_vad() {
        let mut vad = VadTree::new();
        let base = 0x0040_0000u64;
        let mut m = MockMapper::with_fail(base);
        let result =
            allocate(&mut vad, Some(&mut m), base, PAGE_SIZE, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw());
        assert!(result.is_err());
        assert!(vad.is_empty(), "VAD must be rolled back at explicit base");
    }

    // ── T4-1d: decommit on MEM_RELEASE ───────────────────────────────────────

    #[test]
    fn free_release_calls_decommit_for_all_pages() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        let addr = commit(&mut vad, &mut m, 4 * PAGE_SIZE);
        free(&mut vad, Some(&mut m), addr, 0, FreeType::MEM_RELEASE).unwrap();
        assert_eq!(m.decommitted.len(), 4, "must decommit all 4 pages on release");
    }

    #[test]
    fn free_release_decommit_addresses_are_correct() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        let addr = commit(&mut vad, &mut m, 2 * PAGE_SIZE);
        free(&mut vad, Some(&mut m), addr, 0, FreeType::MEM_RELEASE).unwrap();
        assert_eq!(m.decommitted, [addr, addr + PAGE_SIZE]);
    }

    #[test]
    fn free_decommit_returns_the_page_and_keeps_the_reservation() {
        // MEM_DECOMMIT without MEM_RELEASE: was a no-op (audit §4.5).
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        let addr = commit(&mut vad, &mut m, PAGE_SIZE);
        assert_eq!(free(&mut vad, Some(&mut m), addr, PAGE_SIZE, FreeType::MEM_DECOMMIT), Ok((addr, PAGE_SIZE)));
        assert_eq!(m.decommitted, [addr], "MEM_DECOMMIT must return the page");
        assert!(vad.find(addr).is_some(), "VAD entry must remain after decommit-only");
        assert_eq!(query(&vad, addr).unwrap().state, MemState::Reserve);
    }

    // ── T4-1e: protection flags ───────────────────────────────────────────────

    #[test]
    fn readwrite_protect_gives_writable_not_executable() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        allocate(
            &mut vad,
            Some(&mut m),
            0x0040_0000,
            PAGE_SIZE,
            AllocType::MEM_RESERVE | AllocType::MEM_COMMIT,
            PageProtect::READWRITE,
        )
        .unwrap();
        let (_, w, x, _) = m.committed[0];
        assert!(w, "READWRITE must be writable");
        assert!(!x, "READWRITE must not be executable");
    }

    #[test]
    fn execute_read_protect_gives_executable_not_writable() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        allocate(
            &mut vad,
            Some(&mut m),
            0x0040_0000,
            PAGE_SIZE,
            AllocType::MEM_RESERVE | AllocType::MEM_COMMIT,
            PageProtect::EXECUTE_READ,
        )
        .unwrap();
        let (_, w, x, _) = m.committed[0];
        assert!(!w, "EXECUTE_READ must not be writable");
        assert!(x, "EXECUTE_READ must be executable");
    }

    #[test]
    fn noaccess_protect_gives_neither_writable_nor_executable() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        allocate(
            &mut vad,
            Some(&mut m),
            0x0040_0000,
            PAGE_SIZE,
            AllocType::MEM_RESERVE | AllocType::MEM_COMMIT,
            PageProtect::NOACCESS,
        )
        .unwrap();
        let (_, w, x, _) = m.committed[0];
        assert!(!w, "NOACCESS must not be writable");
        assert!(!x, "NOACCESS must not be executable");
    }

    #[test]
    fn all_pages_marked_user_accessible() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        commit(&mut vad, &mut m, 3 * PAGE_SIZE);
        for &(_, _, _, u) in &m.committed {
            assert!(u, "all user allocations must have USER_ACCESSIBLE flag");
        }
    }

    // ── Legacy T2-2 tests (updated for new API) ───────────────────────────────

    fn alloc_no_mapper(vad: &mut VadTree, size: u64) -> u64 {
        allocate(vad, None, 0, size, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw()).expect("alloc failed")
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
        let addr = allocate(&mut vad, None, 0x0040_0000, PAGE_SIZE, AllocType::MEM_RESERVE, rw()).unwrap();
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

    // ── Réservation puis commit ───────────────────────────────────────────────

    const BASE: u64 = 0x0040_0000;
    const P: u64 = PAGE_SIZE;
    const COMMIT: AllocType = AllocType::MEM_COMMIT;
    const RESERVE: AllocType = AllocType::MEM_RESERVE;

    fn rx() -> PageProtect {
        PageProtect::EXECUTE_READ
    }

    /// Une réservation de `pages` pages en `BASE`, rien de commité.
    fn reserve(vad: &mut VadTree, pages: u64) {
        assert_eq!(allocate(vad, None, BASE, pages * P, RESERVE, rw()), Ok(BASE));
    }

    fn runs(vad: &VadTree) -> Vec<(u64, PageState, PageProtect)> {
        vad.find(BASE)
            .unwrap()
            .runs()
            .iter()
            .map(|&PageRun { pages, state, protect }| (pages, state, protect))
            .collect()
    }

    const R: PageState = PageState::Reserved;
    const C: PageState = PageState::Committed;

    #[test]
    fn commit_inside_a_reservation_backs_only_those_pages() {
        // Reserve-then-commit used to fail: the commit was a second, overlapping VAD.
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        reserve(&mut vad, 16);
        assert_eq!(allocate(&mut vad, Some(&mut m), BASE + 4 * P, 2 * P, COMMIT, rx()), Ok(BASE + 4 * P));
        assert_eq!(m.committed, [(BASE + 4 * P, false, true, true), (BASE + 5 * P, false, true, true)]);
        assert_eq!(vad.len(), 1, "no second VAD");
        assert_eq!(runs(&vad), [(4, R, rw()), (2, C, rx()), (10, R, rw())]);
    }

    #[test]
    fn commit_outside_or_across_a_reservation_fails_and_changes_nothing() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        assert_eq!(allocate(&mut vad, Some(&mut m), BASE, P, COMMIT, rw()), Err(STATUS_CONFLICTING_ADDRESSES));
        assert!(vad.is_empty());
        reserve(&mut vad, 4);
        let across = allocate(&mut vad, Some(&mut m), BASE + 2 * P, 4 * P, COMMIT, rw());
        assert_eq!(across, Err(STATUS_CONFLICTING_ADDRESSES));
        let below = allocate(&mut vad, Some(&mut m), BASE - P, 2 * P, COMMIT, rw());
        assert_eq!(below, Err(STATUS_CONFLICTING_ADDRESSES));
        assert_eq!(runs(&vad), [(4, R, rw())]);
        assert!(m.committed.is_empty());
    }

    #[test]
    fn reserving_over_a_reservation_fails() {
        let mut vad = VadTree::new();
        reserve(&mut vad, 4);
        let overlap = allocate(&mut vad, None, BASE + 3 * P, 2 * P, RESERVE | COMMIT, rw());
        assert_eq!(overlap, Err(STATUS_CONFLICTING_ADDRESSES));
        assert_eq!(vad.len(), 1);
    }

    #[test]
    fn recommitting_reprotects_the_committed_pages() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        reserve(&mut vad, 4);
        allocate(&mut vad, Some(&mut m), BASE, 2 * P, COMMIT, rw()).unwrap();
        allocate(&mut vad, Some(&mut m), BASE, 4 * P, COMMIT, rx()).unwrap();
        assert_eq!(m.committed_pages(), [BASE, BASE + P, BASE + 2 * P, BASE + 3 * P], "each page backed once");
        assert_eq!(m.protected, [(BASE, false, true), (BASE + P, false, true)]);
        assert_eq!(runs(&vad), [(4, C, rx())]);
    }

    #[test]
    fn a_failed_commit_inside_a_reservation_restores_pages_and_protections() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::with_fail(BASE + 3 * P);
        reserve(&mut vad, 4);
        allocate(&mut vad, Some(&mut m), BASE, 2 * P, COMMIT, rw()).unwrap();
        m.committed.clear();
        let failed = allocate(&mut vad, Some(&mut m), BASE, 4 * P, COMMIT, rx());
        assert_eq!(failed, Err(STATUS_NO_MEMORY));
        assert_eq!(m.committed_pages(), [BASE + 2 * P]);
        assert_eq!(m.decommitted, [BASE + 2 * P], "the page backed by this call goes back");
        assert_eq!(
            m.protected,
            [(BASE, false, true), (BASE + P, false, true), (BASE, true, false), (BASE + P, true, false)],
            "reprotected, then restored"
        );
        assert_eq!(runs(&vad), [(2, C, rw()), (2, R, rw())]);
    }

    #[test]
    fn decommitted_pages_can_be_committed_again() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        allocate(&mut vad, Some(&mut m), BASE, 4 * P, RESERVE | COMMIT, rw()).unwrap();
        assert_eq!(free(&mut vad, Some(&mut m), BASE + P, 2 * P, FreeType::MEM_DECOMMIT), Ok((BASE + P, 2 * P)));
        assert_eq!(m.decommitted, [BASE + P, BASE + 2 * P]);
        assert_eq!(runs(&vad), [(1, C, rw()), (2, R, rw()), (1, C, rw())]);
        m.committed.clear();
        allocate(&mut vad, Some(&mut m), BASE, 4 * P, COMMIT, rw()).unwrap();
        assert_eq!(m.committed_pages(), [BASE + P, BASE + 2 * P], "only the decommitted pages are backed again");
        assert_eq!(runs(&vad), [(4, C, rw())]);
    }

    #[test]
    fn decommitting_reserved_pages_returns_nothing() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        reserve(&mut vad, 4);
        assert_eq!(free(&mut vad, Some(&mut m), BASE, 0, FreeType::MEM_DECOMMIT), Ok((BASE, 4 * P)));
        assert!(m.decommitted.is_empty());
        assert_eq!(vad.len(), 1);
    }

    #[test]
    fn release_returns_only_the_committed_pages() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        reserve(&mut vad, 8);
        allocate(&mut vad, Some(&mut m), BASE + 2 * P, P, COMMIT, rw()).unwrap();
        allocate(&mut vad, Some(&mut m), BASE + 5 * P, P, COMMIT, rw()).unwrap();
        assert_eq!(free(&mut vad, Some(&mut m), BASE, 0, FreeType::MEM_RELEASE), Ok((BASE, 8 * P)));
        assert_eq!(m.decommitted, [BASE + 2 * P, BASE + 5 * P]);
        assert!(vad.is_empty());
    }

    #[test]
    fn free_checks_the_address_the_size_and_the_type() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        allocate(&mut vad, Some(&mut m), BASE, 4 * P, RESERVE | COMMIT, rw()).unwrap();
        let mut free = |base, size, ty| free(&mut vad, Some(&mut m), base, size, ty);
        assert_eq!(free(BASE + 8 * P, 0, FreeType::MEM_RELEASE), Err(STATUS_MEMORY_NOT_ALLOCATED));
        assert_eq!(free(BASE + P, 0, FreeType::MEM_RELEASE), Err(STATUS_FREE_VM_NOT_AT_BASE));
        assert_eq!(free(BASE + P, P, FreeType::MEM_RELEASE), Err(STATUS_FREE_VM_NOT_AT_BASE));
        assert_eq!(free(BASE + P, 0, FreeType::MEM_DECOMMIT), Err(STATUS_FREE_VM_NOT_AT_BASE));
        assert_eq!(free(BASE, 2 * P, FreeType::MEM_RELEASE), Err(STATUS_UNABLE_TO_FREE_VM), "partial release");
        assert_eq!(free(BASE + P, 4 * P, FreeType::MEM_DECOMMIT), Err(STATUS_UNABLE_TO_FREE_VM));
        let both = FreeType::MEM_RELEASE | FreeType::MEM_DECOMMIT;
        assert_eq!(free(BASE, 0, both), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(free(BASE, 0, FreeType::empty()), Err(STATUS_INVALID_PARAMETER));
        assert!(m.decommitted.is_empty());
        assert_eq!(runs(&vad), [(4, C, rw())]);
    }

    #[test]
    fn a_section_view_is_not_freed_here() {
        let mut vad = VadTree::new();
        let section = crate::section::Section::create_pagefile(P, rw()).unwrap();
        vad.insert(VadNode::view(BASE, BASE + P, rw(), VadKind::View { section, offset: 0 }, &[(1, rw())])).unwrap();
        assert_eq!(free(&mut vad, None, BASE, 0, FreeType::MEM_RELEASE), Err(STATUS_UNABLE_TO_DELETE_SECTION));
        assert_eq!(vad.len(), 1);
    }

    #[test]
    fn protect_changes_committed_pages_and_returns_the_old_protection() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        allocate(&mut vad, Some(&mut m), BASE, 4 * P, RESERVE | COMMIT, rw()).unwrap();
        assert_eq!(protect(&mut vad, Some(&mut m), BASE + P, 2 * P, rx()), Ok(rw()));
        assert_eq!(m.protected, [(BASE + P, false, true), (BASE + 2 * P, false, true)]);
        assert_eq!(runs(&vad), [(1, C, rw()), (2, C, rx()), (1, C, rw())]);
        assert_eq!(protect(&mut vad, Some(&mut m), BASE + 2 * P, P, rw()), Ok(rx()));
    }

    #[test]
    fn protect_refuses_reserved_free_and_invalid() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        reserve(&mut vad, 4);
        allocate(&mut vad, Some(&mut m), BASE, 2 * P, COMMIT, rw()).unwrap();
        let mut protect = |base, size, p| protect(&mut vad, Some(&mut m), base, size, p);
        assert_eq!(protect(BASE + P, 2 * P, rx()), Err(STATUS_NOT_COMMITTED));
        assert_eq!(protect(BASE + 3 * P, 2 * P, rx()), Err(STATUS_CONFLICTING_ADDRESSES));
        assert_eq!(protect(BASE + 8 * P, P, rx()), Err(STATUS_CONFLICTING_ADDRESSES));
        assert_eq!(protect(BASE, P, rx() | rw()), Err(STATUS_INVALID_PAGE_PROTECTION));
        assert_eq!(protect(BASE, 0, rx()), Err(STATUS_INVALID_PARAMETER));
        assert!(m.protected.is_empty());
        assert_eq!(runs(&vad), [(2, C, rw()), (2, R, rw())]);
    }

    #[test]
    fn query_describes_free_reserved_and_committed_regions() {
        let mut vad = VadTree::new();
        let free_all = query(&vad, BASE + 0x123).unwrap();
        assert_eq!((free_all.base_address, free_all.region_size), (BASE, USER_VA_END - BASE));
        assert_eq!((free_all.state, free_all.protect, free_all.kind), (MemState::Free, na(), None));

        reserve(&mut vad, 16);
        allocate(&mut vad, None, BASE + 4 * P, 2 * P, COMMIT, rx()).unwrap();
        let below = query(&vad, BASE - 0x10_0000).unwrap();
        assert_eq!((below.base_address, below.region_size), (BASE - 0x10_0000, 0x10_0000), "free up to the VAD");
        assert_eq!((below.allocation_base, below.allocation_protect), (0, PageProtect::empty()));

        let reserved = query(&vad, BASE + P + 0x234).unwrap();
        let expected = RegionInfo {
            base_address: BASE + P,
            allocation_base: BASE,
            allocation_protect: rw(),
            region_size: 3 * P,
            state: MemState::Reserve,
            protect: PageProtect::empty(),
            kind: Some(MemType::Private),
        };
        assert_eq!(reserved, expected);
        let committed = query(&vad, BASE + 4 * P).unwrap();
        assert_eq!((committed.region_size, committed.state, committed.protect), (2 * P, MemState::Commit, rx()));
        let tail = query(&vad, BASE + 6 * P).unwrap();
        assert_eq!((tail.region_size, tail.state), (10 * P, MemState::Reserve));
        let above = query(&vad, BASE + 16 * P).unwrap();
        assert_eq!((above.region_size, above.state), (USER_VA_END - BASE - 16 * P, MemState::Free));
        assert_eq!(query(&vad, USER_VA_END), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn allocate_checks_protection_and_range() {
        let mut vad = VadTree::new();
        let bad = PageProtect::READWRITE | PageProtect::EXECUTE_READ;
        assert_eq!(allocate(&mut vad, None, 0, P, RESERVE, bad), Err(STATUS_INVALID_PAGE_PROTECTION));
        let over_the_top = allocate(&mut vad, None, USER_VA_END - P, 2 * P, RESERVE, rw());
        assert_eq!(over_the_top, Err(STATUS_INVALID_PARAMETER));
        assert_eq!(allocate(&mut vad, None, u64::MAX - P, 2 * P, RESERVE, rw()), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(allocate(&mut vad, None, 0, P, AllocType::MEM_RESET, rw()), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(allocate(&mut vad, None, 0, USER_VA_END, RESERVE, rw()), Err(STATUS_NO_MEMORY), "too big");
        assert!(vad.is_empty());
    }

    #[test]
    fn a_given_base_may_be_below_64_kib_but_a_free_range_never_is() {
        // RtlpInitEnvironment: the first MiB of a subsystem, from address 4.
        const MIB: u64 = 0x10_0000;
        let mut vad = VadTree::new();
        assert_eq!(allocate(&mut vad, None, 4, MIB - 256, RESERVE, rw()), Ok(0));
        let node = vad.find(0).unwrap();
        assert_eq!((node.start, node.end), (0, MIB), "pages 0 to 255");
        assert_eq!(allocate(&mut vad, None, 0, P, RESERVE, rw()), Ok(MIB), "a free range above it");
        assert_eq!(allocate(&mut vad, None, P, P, RESERVE, rw()), Err(STATUS_CONFLICTING_ADDRESSES));
        assert_eq!(free(&mut vad, None, 0, 0, FreeType::MEM_RELEASE), Ok((0, MIB)));
        let mut empty = VadTree::new();
        assert_eq!(allocate(&mut empty, None, 0, P, RESERVE, rw()), Ok(USER_VA_START), "never below 64 KiB");
    }

    #[test]
    fn an_unaligned_base_reserves_every_page_it_touches() {
        let mut vad = VadTree::new();
        assert_eq!(allocate(&mut vad, None, BASE + 0x800, P, RESERVE, rw()), Ok(BASE));
        let node = vad.find(BASE).unwrap();
        assert_eq!((node.start, node.end), (BASE, BASE + 2 * P));
    }

    #[test]
    fn commit_alone_at_no_base_reserves_too() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        let addr = allocate(&mut vad, Some(&mut m), 0, 2 * P, COMMIT, rw()).unwrap();
        assert_eq!(m.committed_pages(), [addr, addr + P]);
        assert_eq!(query(&vad, addr).unwrap().region_size, 2 * P);
    }

    // ── Vues de section ───────────────────────────────────────────────────────

    /// Une vue de `pages` pages de `section` en `BASE`, avec `protect`.
    fn view(vad: &mut VadTree, section: Arc<Section>, pages: u64, protect: PageProtect) {
        let node =
            VadNode::view(BASE, BASE + pages * P, protect, VadKind::View { section, offset: 0 }, &[(pages, protect)]);
        vad.insert(node).unwrap();
    }

    fn image_section() -> Arc<Section> {
        let file = pe::builder::Pe32Builder::new(0x40_0000)
            .section(".text", 0x1000, 0x1000, &[0xC3], pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
            .build();
        Section::create_image(Arc::from(file)).unwrap()
    }

    #[test]
    fn private_memory_is_never_copy_on_write() {
        let mut vad = VadTree::new();
        for wc in [PageProtect::WRITECOPY, PageProtect::EXECUTE_WRITECOPY] {
            assert_eq!(allocate(&mut vad, None, 0, P, RESERVE | COMMIT, wc), Err(STATUS_INVALID_PAGE_PROTECTION));
        }
        allocate(&mut vad, None, BASE, P, RESERVE | COMMIT, rw()).unwrap();
        assert_eq!(protect(&mut vad, None, BASE, P, PageProtect::WRITECOPY), Err(STATUS_INVALID_PAGE_PROTECTION));
    }

    #[test]
    fn a_view_is_neither_committed_nor_freed_through_virtual_memory() {
        let mut vad = VadTree::new();
        view(&mut vad, Section::create_pagefile(4 * P, rw()).unwrap(), 4, rw());
        assert_eq!(allocate(&mut vad, None, BASE, P, COMMIT, rw()), Err(STATUS_CONFLICTING_ADDRESSES));
        assert_eq!(free(&mut vad, None, BASE, P, FreeType::MEM_DECOMMIT), Err(STATUS_UNABLE_TO_DELETE_SECTION));
        assert_eq!(vad.len(), 1);
    }

    #[test]
    fn protecting_a_view_asks_its_section() {
        let mut vad = VadTree::new();
        let mut m = MockMapper::new();
        view(&mut vad, Section::create_pagefile(2 * P, PageProtect::READONLY).unwrap(), 2, PageProtect::READONLY);
        assert_eq!(protect(&mut vad, Some(&mut m), BASE, P, rw()), Err(STATUS_SECTION_PROTECTION));
        assert_eq!(protect(&mut vad, Some(&mut m), BASE, P, PageProtect::WRITECOPY), Ok(PageProtect::READONLY));
        assert_eq!(runs(&vad), [(1, C, PageProtect::WRITECOPY), (1, C, PageProtect::READONLY)]);
    }

    #[test]
    fn writing_to_an_image_view_is_copy_on_write() {
        let mut vad = VadTree::new();
        view(&mut vad, image_section(), 2, PageProtect::EXECUTE_READ);
        assert_eq!(protect(&mut vad, None, BASE + P, P, rw()), Ok(PageProtect::EXECUTE_READ));
        assert_eq!(query(&vad, BASE + P).unwrap().protect, PageProtect::WRITECOPY, "as XP shows a relocated page");
        assert_eq!(query(&vad, BASE).unwrap().kind, Some(MemType::Image));
    }

    #[test]
    fn query_tells_a_data_view_from_an_image() {
        let mut vad = VadTree::new();
        view(&mut vad, Section::create_pagefile(P, rw()).unwrap(), 1, rw());
        let info = query(&vad, BASE).unwrap();
        assert_eq!((info.kind, info.state, info.protect), (Some(MemType::Mapped), MemState::Commit, rw()));
    }
}
