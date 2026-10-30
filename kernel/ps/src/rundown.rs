//! Protection contre le rundown (EX_RUNDOWN_REF, en attendant Ex) : des
//! accès qui retardent la destruction d'une ressource.
//!
//! Tant qu'il n'est pas lancé, chaque accès [`acquire`](RundownRef::acquire)
//! sa protection, puis la rend ([`release`](RundownRef::release)). Qui lance
//! le rundown ([`begin`](RundownRef::begin)) refuse les accès suivants et
//! attend la fin de ceux en cours : le dernier à rendre sa protection le
//! réveille. Sert à l'espace d'adresses d'un processus
//! (`EPROCESS.RundownProtect`), lu et écrit sous DISPATCH_LEVEL pendant que
//! son dernier thread peut se terminer.

use core::sync::atomic::{AtomicU32, Ordering};

/// Bit 0 : le rundown est lancé ; au-dessus, le nombre d'accès en cours.
const ACTIVE: u32 = 1;
const ONE: u32 = 2;

/// L'état d'une protection contre le rundown, sans l'attente.
pub struct RundownRef {
    state: AtomicU32,
}

impl Default for RundownRef {
    fn default() -> Self {
        Self::new()
    }
}

impl RundownRef {
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(0) }
    }

    /// ExAcquireRundownProtection : `false` si le rundown est lancé.
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn acquire(&self) -> bool {
        self.state
            .fetch_update(Ordering::Acquire, Ordering::Relaxed, |state| {
                (state & ACTIVE == 0).then(|| state.checked_add(ONE).expect("rundown reference overflow"))
            })
            .is_ok()
    }

    /// ExReleaseRundownProtection : `true` si c'était le dernier accès d'un
    /// rundown lancé, dont il faut réveiller l'auteur.
    ///
    /// # IRQL
    /// Tout niveau.
    #[must_use = "the last release must wake the rundown"]
    pub fn release(&self) -> bool {
        let old = self.state.fetch_sub(ONE, Ordering::Release);
        assert!(old >= ONE, "rundown protection released without being acquired");
        old == ONE | ACTIVE
    }

    /// Lance le rundown : plus aucun accès n'est accordé. `true` s'il en
    /// reste en cours, dont le dernier réveillera l'appelant.
    ///
    /// # Panics
    /// S'il est déjà lancé.
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn begin(&self) -> bool {
        let old = self.state.fetch_or(ACTIVE, Ordering::AcqRel);
        assert_eq!(old & ACTIVE, 0, "rundown begun twice");
        old >= ONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accesses_are_refused_once_the_rundown_begins() {
        let r = RundownRef::new();
        assert!(r.acquire());
        assert!(!r.release(), "no rundown to wake");
        assert!(!r.begin(), "nothing in progress: no wait");
        assert!(!r.acquire());
    }

    #[test]
    fn the_last_access_wakes_the_rundown() {
        let r = RundownRef::new();
        assert!(r.acquire() && r.acquire());
        assert!(r.begin(), "two accesses in progress");
        assert!(!r.acquire(), "refused while it waits");
        assert!(!r.release());
        assert!(r.release(), "the last one wakes it");
    }

    #[test]
    #[should_panic(expected = "without being acquired")]
    fn a_release_needs_an_acquire() {
        let _ = RundownRef::new().release();
    }
}
