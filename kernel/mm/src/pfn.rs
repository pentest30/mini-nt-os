//! Base PFN (02 §5.3) : une entrée par page physique, au-dessus de l'allocateur
//! buddy qui garde les listes libres.
//!
//! Chaque entrée dit l'état de sa page ([`PageState`]) : réservée (firmware,
//! image du noyau, données du chargeur, hors mémoire), libre (dans les listes du
//! buddy) ou active, avec alors son usage ([`PageUsage`]), l'ordre du bloc
//! alloué sur sa première page et un compteur de références. Toute page passe
//! par [`allocate_pages`] et [`free_pages`], qui vérifient ces états : une
//! page libérée deux fois, une page réservée ou un bloc rendu avec un autre
//! ordre arrêtent le système au lieu de corrompre les listes libres. Des
//! compteurs par usage ([`stats`]) disent où est la mémoire, et permettront de
//! vérifier qu'un processus terminé a tout rendu (critère de sortie de M2).
//!
//! La base couvre les pages sous 4 Gio, que le HHDM projette ; le reste de la
//! mémoire est ignoré tant que le HHDM s'y arrête. Le tableau est pris dans la
//! carte mémoire au démarrage, avant toute allocation ([`crate::init`]).
//!
//! Pas encore : compteur de partage et pointeur vers la PTE (sections, copie
//! sur écriture), listes de pages à zéro, en attente et modifiées.

use core::fmt;

use hal::sync::KSpinLock;

use crate::buddy::{BuddyAllocator, Pfn, MAX_ORDER};

/// État d'une page physique.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageState {
    /// Hors de la mémoire gérée : firmware, image du noyau, données du
    /// chargeur, trou de la carte mémoire.
    Reserved = 0,
    /// Dans les listes libres du buddy.
    Free = 1,
    /// Allouée, pour l'usage de son entrée.
    Active = 2,
}

/// À quoi sert une page active.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageUsage {
    /// Le tableau de la base PFN elle-même.
    PfnDatabase = 0,
    /// Une table de pages (PML4, PDPT, PD, PT).
    PageTable = 1,
    /// Une pile noyau (`mm::kstack`).
    KernelStack = 2,
    /// Le pool non paginé (le tas du noyau).
    NonPagedPool = 3,
    /// La mémoire privée d'un processus (pages commitées).
    UserPrivate = 4,
    /// Un tampon contigu du noyau, rendu après usage (lecture d'un fichier).
    Buffer = 5,
    /// Le pool paginé (jamais paginé encore, ADR-010).
    PagedPool = 6,
}

/// Nombre d'usages de [`PageUsage`].
pub const USAGE_COUNT: usize = 7;

impl PageUsage {
    const ALL: [PageUsage; USAGE_COUNT] = [
        PageUsage::PfnDatabase,
        PageUsage::PageTable,
        PageUsage::KernelStack,
        PageUsage::NonPagedPool,
        PageUsage::UserPrivate,
        PageUsage::Buffer,
        PageUsage::PagedPool,
    ];
}

/// Ordre d'une page qui n'est pas la première de son bloc.
const NOT_HEAD: u8 = u8::MAX;

/// Entrée de la base PFN (MMPFN) : 8 octets par page.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmPfn {
    pub state: PageState,
    /// Pour une page active.
    pub usage: PageUsage,
    /// Ordre du bloc pour sa première page active, `NOT_HEAD` sinon.
    order: u8,
    _reserved: u8,
    /// Références à la page active ; elle se libère à 1.
    pub ref_count: u32,
}

const _: () = assert!(core::mem::size_of::<MmPfn>() == 8);

impl MmPfn {
    const RESERVED: Self =
        Self { state: PageState::Reserved, usage: PageUsage::PfnDatabase, order: NOT_HEAD, _reserved: 0, ref_count: 0 };
    const FREE: Self = Self { state: PageState::Free, ..Self::RESERVED };

    /// L'ordre de son bloc, pour la première page d'un bloc actif.
    pub fn block_order(&self) -> Option<u8> {
        (self.state == PageState::Active && self.order != NOT_HEAD).then_some(self.order)
    }
}

/// Comptes de pages de la base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PfnStats {
    /// Pages couvertes par la base.
    pub tracked: u64,
    /// Pages libres.
    pub free: u64,
    /// Pages actives, par usage (indice : `PageUsage as usize`).
    pub active: [u64; USAGE_COUNT],
}

impl PfnStats {
    /// Pages actives, tous usages confondus.
    pub fn active_total(&self) -> u64 {
        self.active.iter().sum()
    }

    /// Pages actives pour `usage`.
    pub fn active(&self, usage: PageUsage) -> u64 {
        self.active[usage as usize]
    }
}

impl fmt::Display for PfnStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} pages: {} free", self.tracked, self.free)?;
        for usage in PageUsage::ALL {
            write!(f, ", {:?} {}", usage, self.active(usage))?;
        }
        Ok(())
    }
}

/// Les pages physiques : les listes libres du buddy et la base PFN, sous un
/// même verrou.
pub struct PageFrames {
    buddy: BuddyAllocator,
    /// `count` entrées, pour les pages 0 à `count - 1`.
    pfns: *mut MmPfn,
    count: u64,
    active: [u64; USAGE_COUNT],
}

// SAFETY: `pfns` désigne un tableau réservé à la base pour toute la vie du
// système, que seul le propriétaire de `PageFrames` touche (sous `PAGE_FRAMES`).
unsafe impl Send for PageFrames {}

impl PageFrames {
    /// Une base sans page, avant [`init`](Self::init) : constante, pour un
    /// static (le buddy pèse plus de 50 Kio, trop pour la pile de démarrage).
    pub const fn empty() -> Self {
        Self { buddy: BuddyAllocator::new(), pfns: core::ptr::null_mut(), count: 0, active: [0; USAGE_COUNT] }
    }

    /// La base couvre `count` pages, toutes réservées : [`add_free`](Self::add_free)
    /// et [`mark_active`](Self::mark_active) disent ensuite ce qui est libre et
    /// déjà pris.
    ///
    /// # Safety
    /// Une fois ; `pfns` désigne `count` entrées accessibles en écriture,
    /// réservées à la base pour toute sa vie.
    pub unsafe fn init(&mut self, pfns: *mut MmPfn, count: u64) {
        assert!(self.pfns.is_null(), "PFN database initialised twice");
        for i in 0..count as usize {
            // SAFETY: garanti par l'appelant.
            unsafe { pfns.add(i).write(MmPfn::RESERVED) };
        }
        self.pfns = pfns;
        self.count = count;
    }

    fn entries(&mut self) -> &mut [MmPfn] {
        // SAFETY: `count` entrées réservées à la base (contrat de `init`) ; aucune
        // avant.
        unsafe { core::slice::from_raw_parts_mut(self.pfns, self.count as usize) }
    }

    /// L'entrée de `pfn`, si la base la couvre.
    pub fn entry(&self, pfn: Pfn) -> Option<MmPfn> {
        // SAFETY: `count` entrées réservées à la base (contrat de `init`).
        (pfn.0 < self.count).then(|| unsafe { self.pfns.add(pfn.0 as usize).read() })
    }

    /// Les entrées des pages `[start, start + pages)`.
    ///
    /// # Panics
    /// Si la base ne les couvre pas toutes.
    fn range(&mut self, start: u64, pages: u64) -> &mut [MmPfn] {
        let end = start.checked_add(pages).filter(|&end| end <= self.count);
        let end = end.unwrap_or_else(|| panic!("pages {start:#x}+{pages} outside the PFN database"));
        &mut self.entries()[start as usize..end as usize]
    }

    /// Les pages `[start, start + pages)`, réservées, deviennent libres.
    ///
    /// # Panics
    /// Si l'une n'est pas réservée, ou hors de la base.
    pub fn add_free(&mut self, start: Pfn, pages: u64) {
        for (i, e) in self.range(start.0, pages).iter_mut().enumerate() {
            assert_eq!(e.state, PageState::Reserved, "page {:#x} added twice", start.0 + i as u64);
            *e = MmPfn::FREE;
        }
        self.buddy.add_region(start, pages);
    }

    /// Les pages `[start, start + pages)`, réservées, sont déjà prises pour
    /// `usage`, hors des listes libres (le tableau de la base lui-même).
    ///
    /// # Panics
    /// Si l'une n'est pas réservée, ou hors de la base.
    pub fn mark_active(&mut self, start: Pfn, pages: u64, usage: PageUsage) {
        for (i, e) in self.range(start.0, pages).iter_mut().enumerate() {
            assert_eq!(e.state, PageState::Reserved, "page {:#x} already managed", start.0 + i as u64);
            *e = MmPfn { state: PageState::Active, usage, ref_count: 1, ..MmPfn::RESERVED };
        }
        self.active[usage as usize] += pages;
    }

    /// Alloue 2^`order` pages contiguës pour `usage` ; `None` s'il n'y a plus
    /// de bloc assez grand.
    ///
    /// # Panics
    /// Si le buddy rend une page que la base ne dit pas libre : ses listes
    /// sont corrompues.
    pub fn allocate(&mut self, order: usize, usage: PageUsage) -> Option<Pfn> {
        assert!(order < MAX_ORDER, "order {order}");
        let pfn = self.buddy.alloc(order)?;
        let pages = 1u64 << order;
        for (i, e) in self.range(pfn.0, pages).iter_mut().enumerate() {
            assert_eq!(e.state, PageState::Free, "the free lists handed out page {:#x}", pfn.0 + i as u64);
            *e = MmPfn { state: PageState::Active, usage, ref_count: 1, ..MmPfn::RESERVED };
        }
        self.entries()[pfn.0 as usize].order = order as u8;
        self.active[usage as usize] += pages;
        Some(pfn)
    }

    /// Libère le bloc de 2^`order` pages alloué en `pfn`.
    ///
    /// # Panics
    /// Si `pfn` n'est pas le début d'un bloc actif de cet ordre, ou si l'une
    /// de ses pages a encore d'autres références.
    pub fn free(&mut self, pfn: Pfn, order: usize) {
        let head = self.entry(pfn).unwrap_or_else(|| panic!("freeing page {:#x}, outside the PFN database", pfn.0));
        assert_eq!(
            head.block_order(),
            Some(order as u8),
            "freeing page {:#x} as a block of order {order}: it is {head:?}",
            pfn.0
        );
        let usage = head.usage;
        let pages = 1u64 << order;
        for (i, e) in self.range(pfn.0, pages).iter_mut().enumerate() {
            assert!(
                e.state == PageState::Active && e.usage == usage && e.ref_count == 1,
                "freeing page {:#x} of a block: it is {e:?}",
                pfn.0 + i as u64
            );
            *e = MmPfn::FREE;
        }
        self.active[usage as usize] -= pages;
        self.buddy.free(pfn, order);
    }

    /// Les comptes de pages.
    pub fn stats(&self) -> PfnStats {
        PfnStats { tracked: self.count, free: self.buddy.free_pages(), active: self.active }
    }

    /// Vérifie que la base et les listes libres disent la même chose : chaque
    /// page des listes est libre, il n'y a pas de page libre hors des listes,
    /// et les pages actives correspondent aux compteurs par usage.
    pub fn check(&self) -> Result<(), &'static str> {
        let mut in_lists = 0u64;
        let mut consistent = true;
        self.buddy.for_each_free_block(|pfn, order| {
            for page in pfn.0..pfn.0 + (1 << order) {
                in_lists += 1;
                consistent &= self.entry(Pfn(page)).is_some_and(|e| e.state == PageState::Free);
            }
        });
        if !consistent {
            return Err("a page of the free lists is not free in the PFN database");
        }
        if in_lists != self.buddy.free_pages() {
            return Err("the free lists do not hold as many pages as they count");
        }
        if self.count == 0 {
            return Ok(());
        }
        // SAFETY: `count` entrées réservées à la base (contrat de `init`).
        let entries = unsafe { core::slice::from_raw_parts(self.pfns, self.count as usize) };
        let mut active = [0u64; USAGE_COUNT];
        let mut free = 0u64;
        for e in entries {
            match e.state {
                PageState::Free => free += 1,
                PageState::Active => active[e.usage as usize] += 1,
                PageState::Reserved => {}
            }
        }
        if free != in_lists {
            return Err("a free page of the PFN database is not in the free lists");
        }
        if active != self.active {
            return Err("the active pages do not match the counts per usage");
        }
        Ok(())
    }
}

/// Les pages physiques du système, posées par [`crate::init`].
pub static PAGE_FRAMES: KSpinLock<PageFrames> = KSpinLock::new(PageFrames::empty());

fn with<R>(f: impl FnOnce(&mut PageFrames) -> R) -> R {
    let mut frames = PAGE_FRAMES.lock();
    assert!(frames.count != 0, "Mm used before mm::init");
    f(&mut frames)
}

/// Alloue 2^`order` pages physiques contiguës pour `usage` ; `None` s'il n'y a
/// plus de bloc assez grand.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn allocate_pages(order: usize, usage: PageUsage) -> Option<Pfn> {
    with(|frames| frames.allocate(order, usage))
}

/// Alloue une page physique pour `usage`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn allocate_page(usage: PageUsage) -> Option<Pfn> {
    allocate_pages(0, usage)
}

/// Libère le bloc de 2^`order` pages alloué en `pfn` par [`allocate_pages`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn free_pages(pfn: Pfn, order: usize) {
    with(|frames| frames.free(pfn, order));
}

/// Libère une page allouée par [`allocate_page`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn free_page(pfn: Pfn) {
    free_pages(pfn, 0);
}

/// Les comptes de pages du système.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn stats() -> PfnStats {
    with(|frames| frames.stats())
}

/// Vérifie la base et les listes libres du système ([`PageFrames::check`]).
///
/// # IRQL
/// <= DISPATCH_LEVEL ; parcourt toute la base, verrou tenu.
pub fn check() -> Result<(), &'static str> {
    with(|frames| frames.check())
}

/// Appelle `f` pour chaque morceau de `[start, end)` hors des intervalles
/// `excluded` (triés, disjoints, semi-ouverts).
pub fn for_each_outside(start: u64, end: u64, excluded: &[(u64, u64)], mut f: impl FnMut(u64, u64)) {
    let mut at = start;
    for &(lo, hi) in excluded {
        if hi <= at || lo >= end {
            continue;
        }
        if lo > at {
            f(at, lo);
        }
        at = at.max(hi);
    }
    if at < end {
        f(at, end);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    /// Une base de `count` pages, toutes réservées.
    fn reserved(count: u64) -> Box<PageFrames> {
        let pfns = Box::leak(std::vec![MmPfn::FREE; count as usize].into_boxed_slice());
        let mut frames = Box::new(PageFrames::empty());
        // SAFETY: tableau du test, jamais libéré.
        unsafe { frames.init(pfns.as_mut_ptr(), count) };
        frames
    }

    /// Une base de `count` pages, dont `[start, end)` libres.
    fn frames(count: u64, start: u64, end: u64) -> Box<PageFrames> {
        let mut frames = reserved(count);
        frames.add_free(Pfn(start), end - start);
        frames
    }

    #[test]
    fn pages_start_reserved_until_added() {
        let f = frames(64, 16, 48);
        assert_eq!(f.entry(Pfn(15)).map(|e| e.state), Some(PageState::Reserved));
        assert_eq!(f.entry(Pfn(16)).map(|e| e.state), Some(PageState::Free));
        assert_eq!(f.entry(Pfn(48)).map(|e| e.state), Some(PageState::Reserved));
        assert_eq!(f.entry(Pfn(64)), None);
        assert_eq!(f.stats(), PfnStats { tracked: 64, free: 32, active: [0; USAGE_COUNT] });
        assert_eq!(f.check(), Ok(()));
    }

    #[test]
    fn an_allocation_marks_its_block_active_for_its_usage_and_a_free_undoes_it() {
        let mut f = frames(64, 0, 64);
        let pfn = f.allocate(2, PageUsage::KernelStack).unwrap();
        for page in pfn.0..pfn.0 + 4 {
            let e = f.entry(Pfn(page)).unwrap();
            assert_eq!((e.state, e.usage, e.ref_count), (PageState::Active, PageUsage::KernelStack, 1));
        }
        assert_eq!(f.entry(pfn).unwrap().block_order(), Some(2));
        assert_eq!(f.entry(Pfn(pfn.0 + 1)).unwrap().block_order(), None, "only the head carries the order");
        assert_eq!((f.stats().free, f.stats().active(PageUsage::KernelStack)), (60, 4));
        assert_eq!(f.check(), Ok(()));
        f.free(pfn, 2);
        assert_eq!(f.stats(), PfnStats { tracked: 64, free: 64, active: [0; USAGE_COUNT] });
        assert!((pfn.0..pfn.0 + 4).all(|p| f.entry(Pfn(p)).unwrap().state == PageState::Free));
        assert_eq!(f.check(), Ok(()));
    }

    #[test]
    fn counts_follow_each_usage() {
        let mut f = frames(64, 0, 64);
        let a = f.allocate(0, PageUsage::PageTable).unwrap();
        let _b = f.allocate(1, PageUsage::UserPrivate).unwrap();
        let _c = f.allocate(0, PageUsage::PageTable).unwrap();
        let s = f.stats();
        assert_eq!((s.active(PageUsage::PageTable), s.active(PageUsage::UserPrivate), s.active_total()), (2, 2, 4));
        f.free(a, 0);
        assert_eq!(f.stats().active(PageUsage::PageTable), 1);
        assert_eq!(f.check(), Ok(()));
    }

    #[test]
    fn pages_taken_before_the_free_lists_count_as_active() {
        let mut f = reserved(32);
        f.mark_active(Pfn(0), 2, PageUsage::PfnDatabase);
        f.add_free(Pfn(2), 30);
        assert_eq!(f.stats().active(PageUsage::PfnDatabase), 2);
        assert_eq!(f.check(), Ok(()));
        let all: Vec<_> = core::iter::from_fn(|| f.allocate(0, PageUsage::Buffer)).collect();
        assert_eq!(all.len(), 30, "the database's own pages are never handed out");
        assert!(all.iter().all(|p| p.0 >= 2));
    }

    #[test]
    #[should_panic(expected = "freeing page")]
    fn a_double_free_stops() {
        let mut f = frames(16, 0, 16);
        let pfn = f.allocate(0, PageUsage::Buffer).unwrap();
        f.free(pfn, 0);
        f.free(pfn, 0);
    }

    #[test]
    #[should_panic(expected = "as a block of order 0")]
    fn a_block_freed_with_another_order_stops() {
        let mut f = frames(16, 0, 16);
        let pfn = f.allocate(1, PageUsage::Buffer).unwrap();
        f.free(pfn, 0);
    }

    #[test]
    #[should_panic(expected = "freeing page")]
    fn freeing_the_middle_of_a_block_stops() {
        let mut f = frames(16, 0, 16);
        let pfn = f.allocate(2, PageUsage::Buffer).unwrap();
        f.free(Pfn(pfn.0 + 1), 0);
    }

    #[test]
    #[should_panic(expected = "freeing page")]
    fn freeing_a_reserved_page_stops() {
        let mut f = frames(16, 8, 16);
        f.free(Pfn(2), 0);
    }

    #[test]
    #[should_panic(expected = "added twice")]
    fn adding_a_page_twice_stops() {
        let mut f = frames(16, 0, 8);
        f.add_free(Pfn(4), 8);
    }

    #[test]
    #[should_panic(expected = "handed out page")]
    fn a_page_the_free_lists_hand_out_while_active_stops() {
        let mut f = frames(1, 0, 1);
        let pfn = f.allocate(0, PageUsage::Buffer).unwrap();
        f.buddy.free(pfn, 0);
        f.allocate(0, PageUsage::Buffer);
    }

    #[test]
    fn check_reports_a_page_freed_behind_the_database() {
        let mut f = frames(16, 0, 16);
        let pfn = f.allocate(0, PageUsage::Buffer).unwrap();
        f.buddy.free(pfn, 0);
        assert!(f.check().is_err(), "a page in the free lists, active in the database");
    }

    #[test]
    fn check_reports_counts_or_entries_out_of_step() {
        let mut f = frames(16, 0, 16);
        f.allocate(0, PageUsage::Buffer).unwrap();
        f.active[PageUsage::Buffer as usize] += 1;
        assert!(f.check().is_err(), "the counts say one page too many");
        f.active[PageUsage::Buffer as usize] -= 1;
        assert_eq!(f.check(), Ok(()));
        let mut f = frames(16, 0, 8);
        f.entries()[12] = MmPfn::FREE;
        assert!(f.check().is_err(), "a free entry outside the free lists");
    }

    #[test]
    fn ranges_are_split_around_exclusions() {
        let mut parts = Vec::new();
        for_each_outside(0, 100, &[(10, 20), (30, 40)], |a, b| parts.push((a, b)));
        assert_eq!(parts, [(0, 10), (20, 30), (40, 100)]);
        parts.clear();
        for_each_outside(15, 35, &[(10, 20), (30, 40)], |a, b| parts.push((a, b)));
        assert_eq!(parts, [(20, 30)]);
        parts.clear();
        for_each_outside(10, 20, &[(0, 50)], |a, b| parts.push((a, b)));
        assert!(parts.is_empty());
        for_each_outside(0, 8, &[], |a, b| parts.push((a, b)));
        assert_eq!(parts, [(0, 8)]);
    }
}
