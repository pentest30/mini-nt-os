//! Fautes de page (02 §5.3) : MmAccessFault.
//!
//! Une faute dans la moitié basse d'un espace d'adresses (`mm::address_space`)
//! se résout d'après sa VAD ([`resolve`]) :
//!
//! - page commitée jamais touchée : une page à zéro, projetée avec la
//!   protection de la VAD (demande à zéro) ; dans une vue de section, la page
//!   de la section, partagée (`mm::section`) ;
//! - écriture sur une page de section en copie sur écriture : une copie
//!   privée, qui prend la protection inscriptible correspondante ;
//! - page de garde : la garde est levée et l'accès échoue avec
//!   `STATUS_GUARD_PAGE_VIOLATION`, une seule fois ; l'accès suivant est
//!   normal. Dans la pile du thread fautif, la garde descend plutôt d'une page
//!   et l'accès reprend (`AddressSpace::extend_user_stack`) ;
//! - page `PAGE_NOACCESS`, réservée ou libre, accès que la protection refuse :
//!   `STATUS_ACCESS_VIOLATION`.
//!
//! Une page `PAGE_NOACCESS` ou de garde qui a déjà une page physique la garde
//! dans une entrée non présente (`paging::PTE_RETAINED`) : ses données
//! survivent aux changements de protection.
//!
//! `hal::idt` appelle [`page_fault_hook`] sous DISPATCH_LEVEL, interruptions
//! masquées ; une faute dans la moitié basse à DISPATCH_LEVEL ou plus arrête
//! le système avant (IRQL_NOT_LESS_OR_EQUAL), car la VAD se prend sous un
//! verrou tournant.
//!
//! Les droits d'une page suivent la protection de la VAD ; dans un espace sans
//! DEP (ADR-020), toute page lisible s'exécute aussi
//! (`AddressSpace::set_execute_enabled`).
//!
//! Pas encore : extension de la pile par une faute du noyau (sa copie du
//! contexte d'une exception sur la pile utilisateur, M3) ; pagination sur
//! disque.
//!
//! WI7e Ch.5 §Page Fault Handling

use core::sync::atomic::{AtomicU64, Ordering};

use abi::ntstatus::{NtStatus, STATUS_GUARD_PAGE_VIOLATION, STATUS_STACK_OVERFLOW};
use x86_64::structures::idt::PageFaultErrorCode;

use crate::address_space::{AddressSpace, USER_HALF_END};
use crate::vad::{PageProtect, PageState};
use crate::virtual_alloc::PAGE_SIZE;

/// Les fautes résolues par une page à zéro, depuis le démarrage.
static DEMAND_ZERO_FAULTS: AtomicU64 = AtomicU64::new(0);

/// L'accès qui a fait la faute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

impl Access {
    /// L'accès que décrit le code d'erreur d'une faute de page.
    pub fn from_error_code(error: PageFaultErrorCode) -> Self {
        if error.contains(PageFaultErrorCode::INSTRUCTION_FETCH) {
            Self::Execute
        } else if error.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            Self::Write
        } else {
            Self::Read
        }
    }
}

/// D'où vient une page de la VAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backing {
    /// Mémoire privée : une page à zéro.
    Private,
    /// Vue de section : la page de la section.
    Section,
}

/// Ce que la table des pages tient pour une page ; `shared` : la page
/// physique est celle d'une section (`paging::PTE_SHARED`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PteState {
    /// Aucune page physique.
    Absent,
    /// Une page physique, non présente : `PAGE_NOACCESS` ou garde.
    Retained,
    /// Présente, avec ces droits.
    Present { writable: bool, executable: bool, shared: bool },
}

/// Ce qu'il faut faire d'une faute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Projeter une page à zéro avec cette protection.
    DemandZero(PageProtect),
    /// Projeter la page de la section avec cette protection.
    MapShared(PageProtect),
    /// Copier la page de la section dans une page privée, projetée avec
    /// cette protection sans la copie ([`PageProtect::without_copy`]).
    CopyOnWrite(PageProtect),
    /// Rendre à la page physique tenue les droits de cette protection.
    Remap(PageProtect),
    /// Lever la garde de la page : `STATUS_GUARD_PAGE_VIOLATION`.
    Guard,
    /// `STATUS_ACCESS_VIOLATION`.
    AccessViolation,
}

/// Les droits (écriture, exécution) de la page présente d'une page de
/// protection `protect` : inscriptible, sauf la page d'une section qui se
/// copie à l'écriture ; une page privée ne se copie pas.
pub fn page_rights(protect: PageProtect, shared: bool) -> (bool, bool) {
    (protect.writable() && !(shared && protect.copy_on_write()), protect.executable())
}

/// Décide d'une faute d'après l'état de la page dans la VAD (`None` : hors de
/// toute réservation) et d'où elle vient, dans la table des pages, et
/// l'accès.
pub fn resolve(page: Option<(PageState, PageProtect)>, backing: Backing, pte: PteState, access: Access) -> Resolution {
    let Some((PageState::Committed, protect)) = page else {
        return Resolution::AccessViolation;
    };
    if protect.contains(PageProtect::GUARD) {
        return Resolution::Guard;
    }
    let allowed = protect.accessible()
        && match access {
            Access::Read => true,
            Access::Write => protect.writable(),
            Access::Execute => protect.executable(),
        };
    if !allowed {
        return Resolution::AccessViolation;
    }
    let copy = access == Access::Write && protect.copy_on_write();
    match (backing, pte) {
        (_, PteState::Retained) => Resolution::Remap(protect),
        (Backing::Private, PteState::Absent) => Resolution::DemandZero(protect),
        (Backing::Section, PteState::Absent) if copy => Resolution::CopyOnWrite(protect),
        (Backing::Section, PteState::Absent) => Resolution::MapShared(protect),
        (_, PteState::Present { shared: true, .. }) if copy => Resolution::CopyOnWrite(protect),
        (_, PteState::Present { writable, executable, shared })
            if (writable, executable) != page_rights(protect, shared) =>
        {
            Resolution::Remap(protect)
        }
        // The page tables already allow this access: nothing explains the
        // fault, and retrying it would loop.
        (_, PteState::Present { .. }) => Resolution::AccessViolation,
    }
}

/// MiCheckForUserStackOverflow, sans la mémoire : une faute en `addr` a levé
/// une page de garde, dans une pile réservée de `bottom` (DeallocationStack)
/// à `base` (StackBase). Dans la pile, la nouvelle garde est la page sous la
/// page touchée, et la nouvelle limite (StackLimit) le bas de celle-ci ; la
/// garde ne descend pas sur les deux pages du bas de la réservation
/// (`STATUS_STACK_OVERFLOW`, la page touchée restant utilisable). Hors de la
/// pile : `STATUS_GUARD_PAGE_VIOLATION`.
pub fn stack_extension(addr: u64, bottom: u64, base: u64) -> Result<(u64, u64), NtStatus> {
    if !(bottom..base).contains(&addr) {
        return Err(STATUS_GUARD_PAGE_VIOLATION);
    }
    let page = addr & !(PAGE_SIZE - 1);
    let guard = page - PAGE_SIZE;
    if guard <= bottom + PAGE_SIZE {
        return Err(STATUS_STACK_OVERFLOW);
    }
    Ok((guard, page))
}

/// La faute de page de Mm, pour `hal::idt` : `None` hors de la moitié basse
/// d'un espace d'adresses, sinon `STATUS_SUCCESS` si l'accès peut reprendre
/// ou l'exception qu'il lève. Une garde levée par le mode utilisateur étend
/// la pile du thread courant, si elle en est (son TEB vient du KPCR).
///
/// # IRQL
/// < DISPATCH_LEVEL (hal le vérifie avant l'appel).
pub fn page_fault_hook(addr: u64, error: PageFaultErrorCode) -> Option<NtStatus> {
    if addr >= USER_HALF_END {
        return None;
    }
    let space = AddressSpace::current()?;
    let status = space.access_fault(addr, Access::from_error_code(error));
    let teb = hal::pcr::current().teb();
    if status == STATUS_GUARD_PAGE_VIOLATION && error.contains(PageFaultErrorCode::USER_MODE) && teb != 0 {
        return Some(space.extend_user_stack(addr, teb));
    }
    Some(status)
}

/// Compte une faute résolue par une page à zéro.
pub(crate) fn count_demand_zero() {
    DEMAND_ZERO_FAULTS.fetch_add(1, Ordering::Relaxed);
}

/// Les fautes résolues par une page à zéro depuis le démarrage.
///
/// # IRQL
/// Tout niveau.
pub fn demand_zero_faults() -> u64 {
    DEMAND_ZERO_FAULTS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stack_guard_moves_down_one_page() {
        const P: u64 = PAGE_SIZE;
        let (bottom, base) = (0x1_0000, 0x11_0000);
        assert_eq!(stack_extension(base - 2 * P + 0x10, bottom, base), Ok((base - 3 * P, base - 2 * P)));
        assert_eq!(stack_extension(bottom + 3 * P, bottom, base), Ok((bottom + 2 * P, bottom + 3 * P)));
        assert_eq!(stack_extension(bottom + 2 * P + 4, bottom, base), Err(STATUS_STACK_OVERFLOW), "last page kept");
        assert_eq!(stack_extension(base, bottom, base), Err(STATUS_GUARD_PAGE_VIOLATION), "above the stack");
        assert_eq!(stack_extension(bottom - 1, bottom, base), Err(STATUS_GUARD_PAGE_VIOLATION), "below it");
    }
    use Access::{Execute, Read, Write};
    use PteState::{Absent, Present, Retained};
    use Resolution::{AccessViolation, CopyOnWrite, DemandZero, Guard, MapShared, Remap};

    const C: PageState = PageState::Committed;
    const RW: PageProtect = PageProtect::READWRITE;
    const RO: PageProtect = PageProtect::READONLY;
    const RX: PageProtect = PageProtect::EXECUTE_READ;
    const NA: PageProtect = PageProtect::NOACCESS;

    const P: Backing = Backing::Private;
    const S: Backing = Backing::Section;
    const WC: PageProtect = PageProtect::WRITECOPY;

    fn present(writable: bool, executable: bool) -> PteState {
        Present { writable, executable, shared: false }
    }

    fn shared(writable: bool, executable: bool) -> PteState {
        Present { writable, executable, shared: true }
    }

    #[test]
    fn a_first_touch_of_a_committed_page_gets_a_zeroed_page() {
        for access in [Read, Write] {
            assert_eq!(resolve(Some((C, RW)), P, Absent, access), DemandZero(RW));
        }
        assert_eq!(resolve(Some((C, RX)), P, Absent, Execute), DemandZero(RX));
    }

    #[test]
    fn free_and_reserved_pages_are_access_violations() {
        for access in [Read, Write, Execute] {
            assert_eq!(resolve(None, P, Absent, access), AccessViolation);
            assert_eq!(resolve(Some((PageState::Reserved, RW)), P, Absent, access), AccessViolation);
        }
    }

    #[test]
    fn the_protection_decides_the_access() {
        assert_eq!(resolve(Some((C, RO)), P, Absent, Write), AccessViolation);
        assert_eq!(resolve(Some((C, RW)), P, Absent, Execute), AccessViolation, "NX");
        assert_eq!(resolve(Some((C, RX)), P, Absent, Write), AccessViolation);
        assert_eq!(resolve(Some((C, RO)), P, Absent, Read), DemandZero(RO));
        for access in [Read, Write, Execute] {
            assert_eq!(resolve(Some((C, NA)), P, Absent, access), AccessViolation);
            assert_eq!(resolve(Some((C, NA)), P, Retained, access), AccessViolation, "data kept, still no access");
        }
    }

    #[test]
    fn a_guard_page_fires_whatever_the_access_and_the_page_tables() {
        let guard = RW | PageProtect::GUARD;
        for pte in [Absent, Retained] {
            for access in [Read, Write, Execute] {
                assert_eq!(resolve(Some((C, guard)), P, pte, access), Guard);
            }
        }
    }

    #[test]
    fn a_retained_page_gets_its_rights_back() {
        assert_eq!(resolve(Some((C, RW)), P, Retained, Write), Remap(RW));
    }

    #[test]
    fn a_present_page_is_remapped_only_when_its_rights_lag_behind_the_vad() {
        assert_eq!(resolve(Some((C, RW)), P, present(false, false), Write), Remap(RW), "made writable");
        assert_eq!(resolve(Some((C, RW)), P, present(true, false), Write), AccessViolation, "nothing to fix");
        assert_eq!(resolve(Some((C, RO)), P, present(false, false), Write), AccessViolation);
    }

    #[test]
    fn a_section_page_maps_the_shared_page_until_a_copy_on_write() {
        assert_eq!(resolve(Some((C, RO)), S, Absent, Read), MapShared(RO));
        assert_eq!(resolve(Some((C, RW)), S, Absent, Write), MapShared(RW), "shared write");
        assert_eq!(resolve(Some((C, WC)), S, Absent, Read), MapShared(WC));
        assert_eq!(resolve(Some((C, WC)), S, Absent, Write), CopyOnWrite(WC), "written before ever read");
        assert_eq!(resolve(Some((C, WC)), S, shared(false, false), Write), CopyOnWrite(WC));
        assert_eq!(resolve(Some((C, WC)), S, shared(false, false), Read), AccessViolation, "nothing to fix");
        assert_eq!(resolve(Some((C, RO)), S, shared(false, false), Write), AccessViolation);
        assert_eq!(resolve(Some((C, WC)), S, Retained, Write), Remap(WC), "rights first, then the copy");
    }

    #[test]
    fn a_copied_page_is_private_and_writable() {
        // Its VAD protection became READWRITE; protected back to WRITECOPY,
        // it is still the view's own page.
        assert_eq!(resolve(Some((C, WC)), S, present(false, false), Write), Remap(WC));
        assert_eq!(resolve(Some((C, WC)), S, present(true, false), Write), AccessViolation);
    }

    #[test]
    fn page_rights_copy_only_shared_pages() {
        assert_eq!(page_rights(WC, true), (false, false));
        assert_eq!(page_rights(WC, false), (true, false));
        assert_eq!(page_rights(PageProtect::EXECUTE_WRITECOPY, true), (false, true));
        assert_eq!(page_rights(RW, true), (true, false), "shared write");
    }

    #[test]
    fn the_error_code_gives_the_access() {
        assert_eq!(Access::from_error_code(PageFaultErrorCode::empty()), Read);
        assert_eq!(Access::from_error_code(PageFaultErrorCode::CAUSED_BY_WRITE), Write);
        let fetch = PageFaultErrorCode::INSTRUCTION_FETCH | PageFaultErrorCode::USER_MODE;
        assert_eq!(Access::from_error_code(fetch), Execute);
    }
}
