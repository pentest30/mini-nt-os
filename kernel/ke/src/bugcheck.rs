//! `KeBugCheckEx` : arrêter le système sur l'écran d'erreur fatale.
//!
//! Ke y ajoute ce qu'il sait du processeur, le thread courant, puis passe la
//! main à l'écran de la HAL (`hal::bugcheck`), qui affiche la pile noyau
//! symbolisée depuis l'appelant. Un seul processeur pour l'instant : il n'y en
//! a pas d'autre à arrêter.

use core::fmt;

pub use hal::bugcheck::BugCheckCode;
use hal::bugcheck::StackStart;

/// Arrête le système : code d'arrêt et ses quatre paramètres.
///
/// # IRQL
/// Tout niveau ; masque les interruptions. Ne revient pas.
pub fn ke_bug_check_ex(code: BugCheckCode, p1: u64, p2: u64, p3: u64, p4: u64) -> ! {
    bug_check(code, [p1, p2, p3, p4], None)
}

/// [`ke_bug_check_ex`] avec une raison lisible, affichée sous le code : le
/// message d'un `panic!` (06 §5).
///
/// # IRQL
/// Tout niveau ; masque les interruptions. Ne revient pas.
pub fn ke_bug_check_with_reason(code: BugCheckCode, params: [u64; 4], reason: &dyn fmt::Display) -> ! {
    bug_check(code, params, Some(reason))
}

#[inline(never)]
fn bug_check(code: BugCheckCode, params: [u64; 4], reason: Option<&dyn fmt::Display>) -> ! {
    // Sans thread courant (avant `ke::init`), la ligne manque.
    let thread = crate::sched::try_current_tid().map(|tid| ("thread       ", tid as u64));
    hal::bugcheck::stop(code, params, reason, thread.as_slice(), StackStart::Caller)
}
