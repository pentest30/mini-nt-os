//! Les vues système (MmMapViewInSystemSpace, 02 §4.2) : une section
//! projetée dans la moitié haute, que le noyau atteint quel que soit
//! l'espace d'adresses courant, pendant que des processus la voient par
//! leurs propres vues. win32k y range ce qu'il partage avec un client et
//! dessine lui-même (les pixels d'une DIB section).
//!
//! Les vues prennent des pages de la région [`REGION_BASE`], sous une entrée
//! de la PML4 complétée au démarrage et partagée par tous les espaces
//! (`mm::address_space`) : une projection faite dans les tables courantes
//! vaut pour tous. Chaque vue est suivie d'une page jamais projetée, qui
//! arrête un débordement. Les pages viennent de la section, créées à la
//! projection : la vue ne fait jamais de faute, elle s'atteint à
//! DISPATCH_LEVEL. La vue garde la section ; la défaire ([`SystemView`] qui
//! disparaît) ne rend que les adresses, les pages restent à la section.
//!
//! Pas encore : les sections réservées (`SEC_RESERVE`), de fichier et
//! d'image ; plusieurs processeurs (la TLB des autres processeurs n'est pas
//! vidée) ; l'hyperspace, que 02 §4.2 met dans la même région.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY};
use hal::sync::KSpinLock;
use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};

use crate::paging::MmPageTables;
use crate::section::{Section, SectionKind};

/// La taille d'une page.
const PAGE: u64 = 4096;
/// Le début de la région des vues système (02 §4.2).
pub const REGION_BASE: u64 = 0xFFFF_C000_0000_0000;
/// Les pages de la région : 64 Gio.
pub const REGION_PAGES: u64 = (64 << 30) / PAGE;

/// Une page d'une vue : du noyau seul, en lecture et écriture, jamais
/// exécutée.
const VIEW_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits() | PageTableFlags::NO_EXECUTE.bits(),
);

/// Les pages libres d'une région, en plages triées et disjointes (premier
/// ajustement), sous la plus haute jamais prise.
#[derive(Debug, Default)]
struct Ranges {
    /// (première page, nombre), triées par première page, jamais contiguës.
    free: Vec<(u64, u64)>,
    /// La première page jamais prise.
    top: u64,
}

impl Ranges {
    /// `pages` pages contiguës : la première plage libre qui les tient,
    /// sinon au-dessus de toutes, sous `limit`. Rend la première ; `None` si
    /// la région est pleine.
    fn take(&mut self, pages: u64, limit: u64) -> Option<u64> {
        if pages == 0 {
            return None;
        }
        if let Some(at) = self.free.iter().position(|&(_, count)| count >= pages) {
            let (first, count) = self.free[at];
            if count == pages {
                self.free.remove(at);
            } else {
                self.free[at] = (first + pages, count - pages);
            }
            return Some(first);
        }
        let first = self.top;
        self.top = first.checked_add(pages).filter(|&end| end <= limit)?;
        Some(first)
    }

    /// Rend les `pages` pages de `first`, fondues avec leurs voisines ; une
    /// plage qui finit à la plus haute la fait redescendre.
    fn give_back(&mut self, first: u64, pages: u64) {
        let at = self.free.partition_point(|&(start, _)| start < first);
        let (mut start, mut end) = (first, first + pages);
        if let Some(&(next, count)) = self.free.get(at).filter(|&&(next, _)| next == end) {
            end = next + count;
            self.free.remove(at);
        }
        if let Some(&(previous, count)) = at.checked_sub(1).and_then(|before| self.free.get(before)) {
            if previous + count == start {
                start = previous;
                self.free.remove(at - 1);
            }
        }
        if end == self.top {
            self.top = start;
        } else {
            let at = self.free.partition_point(|&(other, _)| other < start);
            self.free.insert(at, (start, end - start));
        }
    }
}

/// Les pages libres de la région des vues système.
static RANGES: KSpinLock<Ranges> = KSpinLock::new(Ranges { free: Vec::new(), top: 0 });

/// Une section projetée dans le noyau : `size` octets en `base`, défaits
/// quand elle disparaît.
pub struct SystemView {
    base: u64,
    size: u64,
    section: Arc<Section>,
}

impl SystemView {
    /// Son adresse, dans la moitié haute.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Ses octets (des pages entières).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// La section qu'elle projette.
    pub fn section(&self) -> &Arc<Section> {
        &self.section
    }
}

/// MmMapViewInSystemSpace : les `size` octets de `section` à partir de
/// `offset` (arrondis aux pages) projetés dans le noyau, ses pages créées
/// s'il le faut.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` pour une section qui n'est pas du fichier
/// d'échange ou qui est réservée (`SEC_RESERVE`), un `offset` qui n'est pas
/// au début d'une page, une taille nulle ou qui dépasse la section ;
/// `STATUS_NO_MEMORY` sans adresses dans la région ou sans pages (rien ne
/// reste alors projeté).
///
/// # IRQL
/// PASSIVE_LEVEL. Alloue des pages et change les tables de pages du noyau.
pub fn map(section: &Arc<Section>, offset: u64, size: u64) -> Result<SystemView, NtStatus> {
    let end = offset.checked_add(size).ok_or(STATUS_INVALID_PARAMETER)?;
    if section.kind() != SectionKind::Pagefile
        || section.is_reserve()
        || !offset.is_multiple_of(PAGE)
        || size == 0
        || end > section.size()
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let pages = size.div_ceil(PAGE);
    // One more, never mapped: an overrun faults instead of reaching the next view.
    let first = RANGES.lock().take(pages + 1, REGION_PAGES).ok_or(STATUS_NO_MEMORY)?;
    let base = REGION_BASE + first * PAGE;
    // SAFETY: HHDM_OFFSET is the bootloader's offset, recorded by mm::init,
    // and the active CR3 holds the kernel half, shared by every space.
    let mut tables = unsafe { MmPageTables::new(crate::HHDM_OFFSET.load(Ordering::Acquire)) };
    for index in 0..pages {
        let page = match section.page(offset / PAGE + index) {
            Ok(page) => page,
            Err(status) => {
                for mapped in 0..index {
                    // SAFETY: mapped just below, by this call; nothing uses it yet.
                    unsafe { tables.unmap_page(VirtAddr::new(base + mapped * PAGE)) };
                }
                RANGES.lock().give_back(first, pages + 1);
                return Err(status);
            }
        };
        // SAFETY: these addresses were just taken from the region, so nothing
        // maps them; the page is the section's, alive as long as the view
        // holds it.
        unsafe { tables.map_page(VirtAddr::new(base + index * PAGE), PhysAddr::new(page.to_phys()), VIEW_FLAGS) };
    }
    Ok(SystemView { base, size: pages * PAGE, section: section.clone() })
}

impl Drop for SystemView {
    /// MmUnmapViewInSystemSpace : les adresses de la vue retournent à la
    /// région ; ses pages restent à la section.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    fn drop(&mut self) {
        // SAFETY: as in `map`.
        let mut tables = unsafe { MmPageTables::new(crate::HHDM_OFFSET.load(Ordering::Acquire)) };
        for page in (self.base..self.base + self.size).step_by(PAGE as usize) {
            // SAFETY: `map` mapped every page of the view, and the view is
            // going: whoever reached its pages did so through it.
            unsafe { tables.unmap_page(VirtAddr::new(page)) };
        }
        let first = (self.base - REGION_BASE) / PAGE;
        RANGES.lock().give_back(first, self.size / PAGE + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_follow_each_other_then_reuse_what_comes_back() {
        let mut ranges = Ranges::default();
        assert_eq!(ranges.take(3, 100), Some(0));
        assert_eq!(ranges.take(2, 100), Some(3));
        assert_eq!(ranges.take(4, 100), Some(5));
        ranges.give_back(3, 2);
        assert_eq!(ranges.take(3, 100), Some(9), "a hole too small is skipped");
        assert_eq!(ranges.take(1, 100), Some(3), "the first hole that fits");
        assert_eq!(ranges.take(1, 100), Some(4));
        assert!(ranges.free.is_empty());
        assert_eq!(ranges.take(0, 100), None, "no view without pages");
    }

    #[test]
    fn neighbours_merge_and_the_top_comes_down() {
        let mut ranges = Ranges::default();
        for _ in 0..4 {
            ranges.take(2, 100);
        }
        ranges.give_back(0, 2);
        ranges.give_back(4, 2);
        assert_eq!(ranges.free, [(0, 2), (4, 2)]);
        ranges.give_back(2, 2);
        assert_eq!(ranges.free, [(0, 6)], "both neighbours");
        ranges.give_back(6, 2);
        assert_eq!((ranges.free.len(), ranges.top), (0, 0), "all back below the top");
    }

    #[test]
    fn the_region_has_an_end() {
        let mut ranges = Ranges::default();
        assert_eq!(ranges.take(8, 10), Some(0));
        assert_eq!(ranges.take(3, 10), None);
        assert_eq!(ranges.top, 8, "a refusal takes nothing");
        assert_eq!(ranges.take(2, 10), Some(8));
    }

    // 02 §4.2: system views, after the kernel stacks and under the kernel image.
    const _: () = {
        assert!(crate::kstack::REGION_BASE < REGION_BASE);
        assert!(REGION_BASE + REGION_PAGES * PAGE <= 0xFFFF_FFFF_8000_0000);
    };
}
