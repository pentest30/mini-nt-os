//! Fautes de page (02 §5.3) : MmAccessFault.
//!
//! Une faute dans la moitié basse d'un espace d'adresses (`mm::address_space`)
//! se résout d'après sa VAD ([`resolve`]) :
//!
//! - page commitée jamais touchée : une page à zéro, projetée avec la
//!   protection de la VAD (demande à zéro) ;
//! - page de garde : la garde est levée et l'accès échoue avec
//!   `STATUS_GUARD_PAGE_VIOLATION`, une seule fois ; l'accès suivant est normal ;
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
//! Pas encore : extension de la pile utilisateur par sa page de garde (avec le
//! TEB, Ps) ; politique DEP par processus (NX s'applique toujours, la règle
//! OptIn d'XP SP2 viendra avec Ps) ; copie sur écriture et pages de section ;
//! pagination sur disque.
//!
//! WI7e Ch.5 §Page Fault Handling

use core::sync::atomic::{AtomicU64, Ordering};

use abi::ntstatus::NtStatus;
use x86_64::structures::idt::PageFaultErrorCode;

use crate::address_space::{AddressSpace, USER_HALF_END};
use crate::vad::{PageProtect, PageState};

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

/// Ce que la table des pages tient pour une page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PteState {
    /// Aucune page physique.
    Absent,
    /// Une page physique, non présente : `PAGE_NOACCESS` ou garde.
    Retained,
    /// Présente, avec ces droits.
    Present { writable: bool, executable: bool },
}

/// Ce qu'il faut faire d'une faute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Projeter une page à zéro avec cette protection.
    DemandZero(PageProtect),
    /// Rendre à la page physique tenue les droits de cette protection.
    Remap(PageProtect),
    /// Lever la garde de la page : `STATUS_GUARD_PAGE_VIOLATION`.
    Guard,
    /// `STATUS_ACCESS_VIOLATION`.
    AccessViolation,
}

/// Décide d'une faute d'après l'état de la page dans la VAD (`None` : hors de
/// toute réservation), dans la table des pages, et l'accès.
pub fn resolve(page: Option<(PageState, PageProtect)>, pte: PteState, access: Access) -> Resolution {
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
    match pte {
        PteState::Absent => Resolution::DemandZero(protect),
        PteState::Retained => Resolution::Remap(protect),
        PteState::Present { writable, executable }
            if (writable, executable) != (protect.writable(), protect.executable()) =>
        {
            Resolution::Remap(protect)
        }
        // The page tables already allow this access: nothing explains the
        // fault, and retrying it would loop.
        PteState::Present { .. } => Resolution::AccessViolation,
    }
}

/// La faute de page de Mm, pour `hal::idt` : `None` hors de la moitié basse
/// d'un espace d'adresses, sinon `STATUS_SUCCESS` si l'accès peut reprendre
/// ou l'exception qu'il lève.
///
/// # IRQL
/// < DISPATCH_LEVEL (hal le vérifie avant l'appel).
pub fn page_fault_hook(addr: u64, error: PageFaultErrorCode) -> Option<NtStatus> {
    if addr >= USER_HALF_END {
        return None;
    }
    let space = AddressSpace::current()?;
    Some(space.access_fault(addr, Access::from_error_code(error)))
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
    use Access::{Execute, Read, Write};
    use PteState::{Absent, Present, Retained};
    use Resolution::{AccessViolation, DemandZero, Guard, Remap};

    const C: PageState = PageState::Committed;
    const RW: PageProtect = PageProtect::READWRITE;
    const RO: PageProtect = PageProtect::READONLY;
    const RX: PageProtect = PageProtect::EXECUTE_READ;
    const NA: PageProtect = PageProtect::NOACCESS;

    fn present(writable: bool, executable: bool) -> PteState {
        Present { writable, executable }
    }

    #[test]
    fn a_first_touch_of_a_committed_page_gets_a_zeroed_page() {
        for access in [Read, Write] {
            assert_eq!(resolve(Some((C, RW)), Absent, access), DemandZero(RW));
        }
        assert_eq!(resolve(Some((C, RX)), Absent, Execute), DemandZero(RX));
    }

    #[test]
    fn free_and_reserved_pages_are_access_violations() {
        for access in [Read, Write, Execute] {
            assert_eq!(resolve(None, Absent, access), AccessViolation);
            assert_eq!(resolve(Some((PageState::Reserved, RW)), Absent, access), AccessViolation);
        }
    }

    #[test]
    fn the_protection_decides_the_access() {
        assert_eq!(resolve(Some((C, RO)), Absent, Write), AccessViolation);
        assert_eq!(resolve(Some((C, RW)), Absent, Execute), AccessViolation, "NX");
        assert_eq!(resolve(Some((C, RX)), Absent, Write), AccessViolation);
        assert_eq!(resolve(Some((C, RO)), Absent, Read), DemandZero(RO));
        for access in [Read, Write, Execute] {
            assert_eq!(resolve(Some((C, NA)), Absent, access), AccessViolation);
            assert_eq!(resolve(Some((C, NA)), Retained, access), AccessViolation, "data kept, still no access");
        }
    }

    #[test]
    fn a_guard_page_fires_whatever_the_access_and_the_page_tables() {
        let guard = RW | PageProtect::GUARD;
        for pte in [Absent, Retained] {
            for access in [Read, Write, Execute] {
                assert_eq!(resolve(Some((C, guard)), pte, access), Guard);
            }
        }
    }

    #[test]
    fn a_retained_page_gets_its_rights_back() {
        assert_eq!(resolve(Some((C, RW)), Retained, Write), Remap(RW));
    }

    #[test]
    fn a_present_page_is_remapped_only_when_its_rights_lag_behind_the_vad() {
        assert_eq!(resolve(Some((C, RW)), present(false, false), Write), Remap(RW), "made writable");
        assert_eq!(resolve(Some((C, RW)), present(true, false), Write), AccessViolation, "nothing to fix");
        assert_eq!(resolve(Some((C, RO)), present(false, false), Write), AccessViolation);
    }

    #[test]
    fn the_error_code_gives_the_access() {
        assert_eq!(Access::from_error_code(PageFaultErrorCode::empty()), Read);
        assert_eq!(Access::from_error_code(PageFaultErrorCode::CAUSED_BY_WRITE), Write);
        let fetch = PageFaultErrorCode::INSTRUCTION_FETCH | PageFaultErrorCode::USER_MODE;
        assert_eq!(Access::from_error_code(fetch), Execute);
    }
}
