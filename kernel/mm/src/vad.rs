//! VAD (02 §5.3) : les plages d'adresses d'un processus.
//!
//! Chaque nœud ([`VadNode`]) décrit une réservation `[start, end)` : son type
//! (privé, image, fichier), la protection donnée à la réservation, et l'état
//! de chacune de ses pages, réservée ou commitée avec sa protection, en suites
//! de pages de même état ([`PageRun`]). [`VadNode::commit`],
//! [`VadNode::decommit`] et [`VadNode::protect`] changent ces états et disent
//! quelles pages ont changé, pour que l'appelant les projette ou les rende
//! (`mm::virtual_alloc`).
//!
//! L'arbre est un `BTreeMap` (B-arbre équilibré) clé sur le début des nœuds,
//! plutôt que l'arbre AVL intrusif de NT : mêmes complexités, aucune limite de
//! nombre, et ses nœuds viennent du pool comme le reste. Il a remplacé un
//! tableau de 64 entrées qui refusait la 65e allocation (audit §4.5) et
//! contournait une « corruption du BTreeMap » imputée au premier tas
//! (audit §4.2) ; avec les piles noyau gardées et `mm::pool`, l'autotest du
//! tas et le smoke test passent.
//!
//! WI7e Ch.5 §Virtual Address Descriptors

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::bitflags;

use crate::section::Section;

/// Taille d'une page.
const PAGE: u64 = 0x1000;

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

impl PageProtect {
    /// Une protection acceptée par NtAllocateVirtualMemory et
    /// NtProtectVirtualMemory : une seule protection de base, avec au plus
    /// `GUARD` ou `NOCACHE`, qui ne vont pas avec `NOACCESS`.
    pub fn is_valid(self) -> bool {
        let base = self.bits() & 0xFF;
        let modifiers = self & (Self::GUARD | Self::NOCACHE);
        base.count_ones() == 1
            && self.bits() & !0x3FF == 0
            && modifiers != Self::GUARD | Self::NOCACHE
            && (base != Self::NOACCESS.bits() || modifiers.is_empty())
    }

    /// Les pages s'écrivent (la copie sur écriture comptée).
    pub fn writable(self) -> bool {
        self.intersects(Self::READWRITE | Self::WRITECOPY | Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY)
    }

    /// Les pages s'exécutent.
    pub fn executable(self) -> bool {
        self.intersects(Self::EXECUTE | Self::EXECUTE_READ | Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY)
    }

    /// Un accès est possible : ni `NOACCESS`, ni une garde pas encore levée.
    pub fn accessible(self) -> bool {
        !self.intersects(Self::NOACCESS | Self::GUARD)
    }

    /// Une écriture copie d'abord la page partagée (`WRITECOPY`).
    pub fn copy_on_write(self) -> bool {
        self.intersects(Self::WRITECOPY | Self::EXECUTE_WRITECOPY)
    }

    /// La protection d'une page une fois copiée : `WRITECOPY` devient
    /// `READWRITE`, `EXECUTE_WRITECOPY` `EXECUTE_READWRITE`.
    pub fn without_copy(self) -> Self {
        let modifiers = self & (Self::GUARD | Self::NOCACHE);
        if self.contains(Self::WRITECOPY) {
            Self::READWRITE | modifiers
        } else if self.contains(Self::EXECUTE_WRITECOPY) {
            Self::EXECUTE_READWRITE | modifiers
        } else {
            self
        }
    }

    /// Une écriture qui ne se partage pas devient copie sur écriture :
    /// `READWRITE` devient `WRITECOPY`, `EXECUTE_READWRITE`
    /// `EXECUTE_WRITECOPY`.
    pub fn with_copy(self) -> Self {
        let modifiers = self & (Self::GUARD | Self::NOCACHE);
        if self.contains(Self::READWRITE) {
            Self::WRITECOPY | modifiers
        } else if self.contains(Self::EXECUTE_READWRITE) {
            Self::EXECUTE_WRITECOPY | modifiers
        } else {
            self
        }
    }
}

/// État d'une page d'une réservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageState {
    /// Réservée : aucune mémoire derrière, tout accès fait une faute.
    Reserved,
    /// Commitée : utilisable avec sa protection.
    Committed,
}

/// Une suite de pages consécutives de même état et de même protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRun {
    pub pages: u64,
    pub state: PageState,
    /// Protection des pages commitées ; celle de la réservation sinon.
    pub protect: PageProtect,
}

/// Une plage de pages changée par une opération, avec ce qu'elle était.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageChange {
    pub start: u64,
    pub end: u64, // exclusive
    pub old_state: PageState,
    pub old_protect: PageProtect,
}

/// VAD node — describes one reservation and the state of its pages.
#[derive(Clone, Debug)]
pub struct VadNode {
    pub start: u64,
    pub end: u64, // exclusive
    /// Protection donnée à la réservation (AllocationProtect).
    pub protect: PageProtect,
    pub kind: VadKind,
    /// Les pages de `start` à `end`, dans l'ordre ; deux suites voisines
    /// diffèrent toujours.
    runs: Vec<PageRun>,
}

impl VadNode {
    /// Une réservation privée des pages qui couvrent `[start, end)`,
    /// entièrement commitée avec `protect`.
    pub fn private(start: u64, end: u64, protect: PageProtect) -> Self {
        let mut node = Self::reserved(start & !(PAGE - 1), align_up(end, PAGE), protect, VadKind::Private);
        node.runs[0].state = PageState::Committed;
        node
    }

    /// Une vue de section `[start, end)` (`kind`), commitée en entier : ses
    /// pages ont les protections de `protects`, des suites (nombre de pages,
    /// protection) qui la couvrent dans l'ordre.
    ///
    /// # Panics
    /// Si `protects` ne couvre pas exactement la vue.
    pub fn view(start: u64, end: u64, protect: PageProtect, kind: VadKind, protects: &[(u64, PageProtect)]) -> Self {
        let mut node = Self::reserved(start, end, protect, kind);
        node.runs =
            protects.iter().map(|&(pages, protect)| PageRun { pages, state: PageState::Committed, protect }).collect();
        assert_eq!(node.runs.iter().map(|r| r.pages).sum::<u64>(), (end - start) / PAGE, "protections of a view");
        node.merge();
        node
    }

    /// La section et la page de la section que projette la page `addr` d'une
    /// vue ; `None` hors d'une vue.
    pub fn section_page(&self, addr: u64) -> Option<(&Arc<Section>, u64)> {
        match &self.kind {
            VadKind::View { section, offset } => Some((section, (offset + addr - self.start) / PAGE)),
            VadKind::Private => None,
        }
    }

    /// Une réservation dont aucune page n'est commitée.
    ///
    /// # Panics
    /// Si `[start, end)` n'est pas une plage de pages non vide.
    pub fn reserved(start: u64, end: u64, protect: PageProtect, kind: VadKind) -> Self {
        assert!(start.is_multiple_of(PAGE) && end.is_multiple_of(PAGE) && start < end, "VAD [{start:#x}, {end:#x})");
        let runs = alloc::vec![PageRun { pages: (end - start) / PAGE, state: PageState::Reserved, protect }];
        Self { start, end, protect, kind, runs }
    }

    /// Les suites de pages de la réservation, dans l'ordre.
    pub fn runs(&self) -> &[PageRun] {
        &self.runs
    }

    /// La suite qui contient `addr`, et l'adresse de son début.
    pub fn run_at(&self, addr: u64) -> Option<(u64, PageRun)> {
        let mut at = self.start;
        for &run in &self.runs {
            let end = at + run.pages * PAGE;
            if (at..end).contains(&addr) {
                return Some((at, run));
            }
            at = end;
        }
        None
    }

    /// Commite les pages de `[start, end)` avec `protect` : les pages
    /// réservées deviennent commitées, les pages déjà commitées prennent cette
    /// protection (comme ReactOS et Wine). Rend les plages changées.
    pub fn commit(&mut self, start: u64, end: u64, protect: PageProtect) -> Vec<PageChange> {
        self.update(start, end, |run| {
            let changes = run.state == PageState::Reserved || run.protect != protect;
            if changes {
                *run = PageRun { state: PageState::Committed, protect, ..*run };
            }
            changes
        })
    }

    /// Décommite les pages commitées de `[start, end)` : elles redeviennent
    /// réservées. Rend les plages qui étaient commitées.
    pub fn decommit(&mut self, start: u64, end: u64) -> Vec<PageChange> {
        let reservation = self.protect;
        self.update(start, end, |run| {
            let committed = run.state == PageState::Committed;
            if committed {
                *run = PageRun { state: PageState::Reserved, protect: reservation, ..*run };
            }
            committed
        })
    }

    /// Donne la protection `protect` aux pages de `[start, end)`, toutes
    /// commitées ; rend l'ancienne protection de la première, ou `None`
    /// (rien de changé) si l'une n'est pas commitée.
    pub fn protect(&mut self, start: u64, end: u64, protect: PageProtect) -> Option<PageProtect> {
        self.check_range(start, end)?;
        let (_, first) = self.run_at(start)?;
        if !self.runs_in(start, end).all(|r| r.state == PageState::Committed) {
            return None;
        }
        self.update(start, end, |run| {
            run.protect = protect;
            true
        });
        Some(first.protect)
    }

    /// Les suites qui recoupent `[start, end)`.
    fn runs_in(&self, start: u64, end: u64) -> impl Iterator<Item = &PageRun> + '_ {
        let mut at = self.start;
        self.runs.iter().filter(move |run| {
            let run_end = at + run.pages * PAGE;
            let overlaps = at < end && start < run_end;
            at = run_end;
            overlaps
        })
    }

    /// `Some` si `[start, end)` est une plage de pages non vide de la réservation.
    fn check_range(&self, start: u64, end: u64) -> Option<()> {
        (start.is_multiple_of(PAGE)
            && end.is_multiple_of(PAGE)
            && self.start <= start
            && start < end
            && end <= self.end)
            .then_some(())
    }

    /// Applique `change` à chaque suite de `[start, end)`, coupées à ses bords,
    /// puis refusionne les suites voisines égales. Rend, dans l'ordre, les
    /// plages des suites que `change` dit avoir changées, avec leur état
    /// d'avant.
    ///
    /// # Panics
    /// Si `[start, end)` n'est pas une plage de pages non vide de la réservation.
    fn update(&mut self, start: u64, end: u64, mut change: impl FnMut(&mut PageRun) -> bool) -> Vec<PageChange> {
        assert!(self.check_range(start, end).is_some(), "[{start:#x}, {end:#x}) outside the VAD");
        self.split_at(start);
        self.split_at(end);
        let mut changed = Vec::new();
        let mut at = self.start;
        for run in &mut self.runs {
            let run_end = at + run.pages * PAGE;
            let old = *run;
            if at >= start && run_end <= end && change(run) {
                changed.push(PageChange { start: at, end: run_end, old_state: old.state, old_protect: old.protect });
            }
            at = run_end;
        }
        self.merge();
        changed
    }

    /// Coupe la suite qui contient `addr` pour qu'une suite commence en `addr`.
    fn split_at(&mut self, addr: u64) {
        let mut at = self.start;
        for i in 0..self.runs.len() {
            let run = self.runs[i];
            let end = at + run.pages * PAGE;
            if at < addr && addr < end {
                let before = (addr - at) / PAGE;
                self.runs[i].pages = before;
                self.runs.insert(i + 1, PageRun { pages: run.pages - before, ..run });
                return;
            }
            at = end;
        }
    }

    /// Fusionne les suites voisines de même état et de même protection.
    fn merge(&mut self) {
        let mut merged: Vec<PageRun> = Vec::with_capacity(self.runs.len());
        for run in self.runs.drain(..) {
            match merged.last_mut() {
                Some(last) if last.state == run.state && last.protect == run.protect => last.pages += run.pages,
                _ => merged.push(run),
            }
        }
        self.runs = merged;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VadKind {
    /// Private memory (VirtualAlloc).
    Private,
    /// Une vue de section (NtMapViewOfSection), à `offset` octets de son
    /// début : image, fichier de données ou mémoire partagée.
    View { section: Arc<Section>, offset: u64 },
}

/// Fin (exclue) de l'espace utilisateur d'un processus 32 bits (2 Gio, moins
/// la zone interdite du haut, comme XP).
pub const USER_VA_END: u64 = 0x7FFF_0000;

/// Per-process VAD tree: non-overlapping nodes keyed by start address.
pub struct VadTree {
    nodes: BTreeMap<u64, VadNode>,
}

impl VadTree {
    pub fn new() -> Self {
        Self { nodes: BTreeMap::new() }
    }

    /// Number of entries currently in the tree.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if the tree has no entries.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Insert a new VAD node. Returns `Err("VAD overlap")` if the range
    /// overlaps any existing node.
    ///
    /// Overlap condition: two ranges [a, b) and [c, d) overlap iff a < d && c < b.
    pub fn insert(&mut self, node: VadNode) -> Result<(), &'static str> {
        if self.overlaps(node.start, node.end) {
            return Err("VAD overlap");
        }
        self.nodes.insert(node.start, node);
        Ok(())
    }

    /// Un nœud recoupe `[start, end)`.
    pub(crate) fn overlaps(&self, start: u64, end: u64) -> bool {
        // The node starting at or below start might extend into the range;
        // the first node starting after it might begin inside it.
        self.nodes.range(..=start).next_back().is_some_and(|(_, prev)| prev.end > start)
            || self.nodes.range(start..).next().is_some_and(|(_, next)| next.start < end)
    }

    /// Find the VAD node containing `addr`, if any.
    pub fn find(&self, addr: u64) -> Option<&VadNode> {
        self.nodes.range(..=addr).next_back().map(|(_, node)| node).filter(|node| addr < node.end)
    }

    /// Le nœud qui contient `addr`, modifiable.
    pub fn find_mut(&mut self, addr: u64) -> Option<&mut VadNode> {
        self.nodes.range_mut(..=addr).next_back().map(|(_, node)| node).filter(|node| addr < node.end)
    }

    /// Le premier nœud qui commence après `addr`.
    pub fn next_after(&self, addr: u64) -> Option<&VadNode> {
        self.nodes.range(addr + 1..).next().map(|(_, node)| node)
    }

    /// Remove the VAD node starting at `start_addr` (VirtualFree MEM_RELEASE).
    /// Returns the removed node, or `None` if not found.
    pub fn remove(&mut self, start_addr: u64) -> Option<VadNode> {
        self.nodes.remove(&start_addr)
    }

    /// Return an iterator over (start, end) pairs — for diagnostics only.
    pub fn debug_ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.nodes.values().map(|n| (n.start, n.end))
    }

    /// Find the lowest free virtual range of at least `size` bytes,
    /// starting the search at `search_start` (aligned to `align`), below
    /// [`USER_VA_END`].
    ///
    /// Returns the base address of the gap, or `None` if the address
    /// space is exhausted.
    ///
    /// Used by `NtAllocateVirtualMemory` when `base_addr == NULL`.
    pub fn find_free_gap(&self, search_start: u64, size: u64, align: u64) -> Option<u64> {
        debug_assert!(align.is_power_of_two());
        let mut cursor = align_up(search_start, align);

        for node in self.nodes.values() {
            if node.start < search_start {
                // Behind our search start; skip but update cursor if needed.
                if node.end > cursor {
                    cursor = align_up(node.end, align);
                }
                continue;
            }
            // Is there a gap between cursor and this node?
            if node.start >= cursor + size {
                break;
            }
            // Move cursor past this node, realign.
            cursor = align_up(node.end, align);
        }

        // The gap found, or the one after the last node.
        (cursor.checked_add(size)? <= USER_VA_END).then_some(cursor)
    }
}

impl Default for VadTree {
    fn default() -> Self {
        Self::new()
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
#[expect(clippy::identity_op, reason = "page counts are written uniformly: 1 * PAGE, 3 * PAGE")]
mod tests {
    use super::*;

    fn rw() -> PageProtect {
        PageProtect::READWRITE
    }
    fn rx() -> PageProtect {
        PageProtect::EXECUTE_READ
    }
    fn ro() -> PageProtect {
        PageProtect::READONLY
    }
    fn na() -> PageProtect {
        PageProtect::NOACCESS
    }

    // ── T2-1a: insert / find / remove ────────────────────────────────────────

    #[test]
    fn insert_single_node_and_find_by_start() {
        let mut t = VadTree::new();
        t.insert(VadNode::private(0x1000, 0x2000, rw())).unwrap();
        let n = t.find(0x1000).expect("find at start");
        assert_eq!(n.start, 0x1000);
        assert_eq!(n.end, 0x2000);
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
    fn more_than_64_regions_fit() {
        // The array version refused the 65th node (audit §4.5).
        let mut t = VadTree::new();
        for i in 0..1000u64 {
            t.insert(VadNode::private(i * 2 * PAGE, i * 2 * PAGE + PAGE, rw())).unwrap();
        }
        assert_eq!(t.len(), 1000);
        assert_eq!(t.find(999 * 2 * PAGE).map(|n| n.start), Some(999 * 2 * PAGE));
        assert!(t.find(999 * 2 * PAGE + PAGE).is_none(), "gap between nodes");
        assert_eq!(t.find_free_gap(0, PAGE, PAGE), Some(PAGE));
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

    // ── États des pages ──────────────────────────────────────────────────────

    fn reserved(pages: u64) -> VadNode {
        VadNode::reserved(0x10_0000, 0x10_0000 + pages * PAGE, rw(), VadKind::Private)
    }

    fn run(pages: u64, state: PageState, protect: PageProtect) -> PageRun {
        PageRun { pages, state, protect }
    }

    const R: PageState = PageState::Reserved;
    const C: PageState = PageState::Committed;

    fn change(start: u64, end: u64, old_state: PageState, old_protect: PageProtect) -> PageChange {
        PageChange { start, end, old_state, old_protect }
    }

    #[test]
    fn a_reservation_starts_with_no_page_committed() {
        let n = reserved(16);
        assert_eq!(n.runs(), [run(16, R, rw())]);
        assert_eq!(VadNode::private(0x1000, 0x3000, rw()).runs(), [run(2, C, rw())]);
        let unaligned = VadNode::private(0x1800, 0x2800, rw());
        assert_eq!((unaligned.start, unaligned.end), (0x1000, 0x3000), "the pages the range touches");
        assert_eq!(unaligned.runs(), [run(2, C, rw())]);
    }

    #[test]
    fn committing_the_middle_splits_the_reservation_in_three() {
        let mut n = reserved(16);
        let base = n.start;
        let changed = n.commit(base + 4 * PAGE, base + 6 * PAGE, rx());
        assert_eq!(changed, [change(base + 4 * PAGE, base + 6 * PAGE, R, rw())]);
        assert_eq!(n.runs(), [run(4, R, rw()), run(2, C, rx()), run(10, R, rw())]);
        assert_eq!(n.run_at(base + 5 * PAGE), Some((base + 4 * PAGE, run(2, C, rx()))));
    }

    #[test]
    fn committing_already_committed_pages_gives_them_the_new_protection() {
        let mut n = reserved(8);
        let base = n.start;
        n.commit(base + 2 * PAGE, base + 4 * PAGE, rx());
        n.commit(base + 6 * PAGE, base + 8 * PAGE, rw());
        let changed = n.commit(base, base + 8 * PAGE, rw());
        assert_eq!(
            changed,
            [
                change(base, base + 2 * PAGE, R, rw()),
                change(base + 2 * PAGE, base + 4 * PAGE, C, rx()),
                change(base + 4 * PAGE, base + 6 * PAGE, R, rw()),
            ],
            "pages 6 and 7 were already committed with this protection"
        );
        assert_eq!(n.runs(), [run(8, C, rw())]);
    }

    #[test]
    fn pages_committed_one_by_one_merge_into_one_run() {
        let mut n = reserved(8);
        let base = n.start;
        for i in [3, 0, 7, 1, 2, 6, 4, 5] {
            n.commit(base + i * PAGE, base + (i + 1) * PAGE, rw());
        }
        assert_eq!(n.runs(), [run(8, C, rw())]);
    }

    #[test]
    fn decommitting_returns_what_was_committed_and_restores_the_reservation() {
        let mut n = reserved(8);
        let base = n.start;
        n.commit(base, base + 3 * PAGE, rx());
        n.commit(base + 5 * PAGE, base + 8 * PAGE, rx());
        let changed = n.decommit(base + 2 * PAGE, base + 6 * PAGE);
        assert_eq!(
            changed,
            [change(base + 2 * PAGE, base + 3 * PAGE, C, rx()), change(base + 5 * PAGE, base + 6 * PAGE, C, rx())]
        );
        assert_eq!(n.runs(), [run(2, C, rx()), run(4, R, rw()), run(2, C, rx())]);
    }

    #[test]
    fn protect_needs_every_page_committed_and_returns_the_old_protection() {
        let mut n = reserved(8);
        let base = n.start;
        n.commit(base, base + 4 * PAGE, rw());
        assert_eq!(n.protect(base + 2 * PAGE, base + 6 * PAGE, rx()), None, "pages 4 and 5 are reserved");
        assert_eq!(n.runs(), [run(4, C, rw()), run(4, R, rw())], "nothing changed");
        assert_eq!(n.protect(base + PAGE, base + 3 * PAGE, rx()), Some(rw()));
        assert_eq!(n.runs(), [run(1, C, rw()), run(2, C, rx()), run(1, C, rw()), run(4, R, rw())]);
        assert_eq!(n.protect(base, base + 4 * PAGE, rw()), Some(rw()));
        assert_eq!(n.runs(), [run(4, C, rw()), run(4, R, rw())], "merged back");
    }

    #[test]
    fn valid_protections() {
        for p in [na(), ro(), rw(), rx(), PageProtect::EXECUTE_READWRITE, rw() | PageProtect::GUARD] {
            assert!(p.is_valid(), "{p:?}");
        }
        let invalid = [
            PageProtect::empty(),
            rw() | rx(),
            PageProtect::GUARD,
            na() | PageProtect::GUARD,
            rw() | PageProtect::GUARD | PageProtect::NOCACHE,
            PageProtect::from_bits_retain(0x404),
        ];
        for p in invalid {
            assert!(!p.is_valid(), "{p:?}");
        }
    }

    #[test]
    fn rights_of_a_protection() {
        let rights = |p: PageProtect| (p.writable(), p.executable(), p.accessible());
        assert_eq!(rights(ro()), (false, false, true));
        assert_eq!(rights(rw()), (true, false, true));
        assert_eq!(rights(PageProtect::WRITECOPY), (true, false, true));
        assert_eq!(rights(PageProtect::EXECUTE), (false, true, true));
        assert_eq!(rights(rx()), (false, true, true));
        assert_eq!(rights(PageProtect::EXECUTE_READWRITE), (true, true, true));
        assert_eq!(rights(PageProtect::EXECUTE_WRITECOPY), (true, true, true));
        assert_eq!(rights(na()), (false, false, false));
        assert_eq!(rights(rw() | PageProtect::GUARD), (true, false, false));
        assert_eq!(rights(rw() | PageProtect::NOCACHE), (true, false, true));
    }

    #[test]
    fn copy_on_write_protections() {
        let wc = PageProtect::WRITECOPY;
        let ewc = PageProtect::EXECUTE_WRITECOPY;
        let erw = PageProtect::EXECUTE_READWRITE;
        assert!(wc.copy_on_write() && ewc.copy_on_write() && !rw().copy_on_write() && !erw.copy_on_write());
        assert_eq!((wc.without_copy(), ewc.without_copy(), rx().without_copy()), (rw(), erw, rx()));
        assert_eq!((rw().with_copy(), erw.with_copy(), ro().with_copy()), (wc, ewc, ro()));
        assert_eq!((wc | PageProtect::GUARD).without_copy(), rw() | PageProtect::GUARD);
    }

    #[test]
    fn a_view_starts_committed_with_its_protections() {
        let wc = PageProtect::WRITECOPY;
        let section = Section::create_pagefile(4 * PAGE, rw()).unwrap();
        let kind = VadKind::View { section: section.clone(), offset: 0x1_0000 };
        let n = VadNode::view(0x10_0000, 0x10_4000, wc, kind, &[(1, ro()), (1, rx()), (2, wc)]);
        assert_eq!(n.runs(), [run(1, C, ro()), run(1, C, rx()), run(2, C, wc)]);
        let (s, index) = n.section_page(0x10_2fff).unwrap();
        assert!(Arc::ptr_eq(s, &section));
        assert_eq!(index, 0x10 + 2, "offset 64 KiB, third page");
        assert!(reserved(1).section_page(0x10_0000).is_none(), "private memory");
    }

    #[test]
    #[should_panic(expected = "protections of a view")]
    fn a_view_needs_a_protection_for_each_page() {
        VadNode::view(0x10_0000, 0x10_4000, rw(), VadKind::Private, &[(3, rw())]);
    }

    #[test]
    #[should_panic(expected = "outside the VAD")]
    fn a_range_beyond_the_reservation_stops() {
        let mut n = reserved(4);
        let base = n.start;
        n.commit(base + 2 * PAGE, base + 6 * PAGE, rw());
    }

    #[test]
    fn the_free_gap_search_stops_at_the_end_of_the_user_space() {
        let t = VadTree::new();
        assert_eq!(t.find_free_gap(USER_VA_END - PAGE, PAGE, PAGE), Some(USER_VA_END - PAGE));
        assert_eq!(t.find_free_gap(USER_VA_END - PAGE, 2 * PAGE, PAGE), None);
    }
}
