//! KPCR : la zone de contrôle de chaque processeur (02 §HAL, ADR-015). En mode
//! noyau, la base de GS pointe sur celle du CPU courant ; elle porte l'état par
//! CPU de la HAL (IRQL, interruption DISPATCH en attente) et le KPRCB de Ke.
//!
//! Un seul CPU pour l'instant : celui du démarrage (BSP), dont le KPCR est
//! statique.
//!
//! Pas encore SWAPGS : le noyau ne change jamais GS, et le code utilisateur XP
//! ne s'en sert pas (son TEB est en FS). Un programme qui chargerait GS
//! fausserait la base jusqu'à la refonte des entrées depuis le mode
//! utilisateur (`KTRAP_FRAME`, M3), qui passeront par SWAPGS.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8};

use crate::irql::Irql;

/// Zone de contrôle d'un processeur.
#[repr(C)]
pub struct Kpcr {
    /// Adresse de ce KPCR : `gs:[0]`.
    self_ptr: *const Kpcr,
    /// Le KPRCB de Ke, enregistré à son initialisation.
    prcb: AtomicPtr<c_void>,
    /// Numéro du processeur.
    number: u32,
    /// IRQL courant (`hal::irql`).
    pub(crate) irql: AtomicU8,
    /// L'interruption DISPATCH est demandée et ne s'est pas encore exécutée.
    pub(crate) dispatch_pending: AtomicBool,
}

/// Décalage de l'IRQL dans le KPCR, pour l'assembleur (`gs:[IRQL_OFFSET]`).
pub(crate) const IRQL_OFFSET: usize = core::mem::offset_of!(Kpcr, irql);

const _: () = assert!(core::mem::offset_of!(Kpcr, self_ptr) == 0, "gs:[0] is the KPCR's own address");

// SAFETY: `self_ptr` et `number` ne changent pas après l'initialisation ; le
// reste est atomique.
unsafe impl Sync for Kpcr {}

/// Le KPCR du processeur de démarrage.
static BSP_PCR: Kpcr = Kpcr {
    self_ptr: ptr::addr_of!(BSP_PCR),
    prcb: AtomicPtr::new(ptr::null_mut()),
    number: 0,
    irql: AtomicU8::new(Irql::Passive.as_u8()),
    dispatch_pending: AtomicBool::new(false),
};

impl Kpcr {
    /// Numéro du processeur.
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Le KPRCB que Ke a enregistré, ou nul.
    pub fn prcb(&self) -> *mut c_void {
        self.prcb.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Enregistre le KPRCB de Ke pour ce processeur.
    ///
    /// # IRQL
    /// Tout niveau ; une fois, à l'initialisation de Ke.
    pub fn set_prcb(&self, prcb: *mut c_void) {
        self.prcb.store(prcb, core::sync::atomic::Ordering::Release);
    }
}

/// Fait pointer GS sur le KPCR du processeur de démarrage. IA32_KERNEL_GS_BASE
/// reçoit la même adresse, pour qu'un SWAPGS ne la perde pas.
///
/// # Safety
/// Une fois, au début de `hal::init` (après le port série, qui n'utilise pas
/// l'IRQL, pour qu'un échec s'affiche), avant le premier accès au KPCR.
///
/// # IRQL
/// HIGH_LEVEL (démarrage, interruptions masquées).
pub unsafe fn init_bsp() {
    let base = ptr::addr_of!(BSP_PCR) as u64;
    // SAFETY: les deux MSR existent en mode long ; `base` est une adresse
    // canonique du noyau, valide pour toujours.
    unsafe {
        crate::msr::wrmsr(crate::msr::IA32_GS_BASE, base);
        crate::msr::wrmsr(crate::msr::IA32_KERNEL_GS_BASE, base);
    }
    assert!(ptr::eq(current(), &BSP_PCR), "GS does not reach the boot processor's KPCR");
}

/// Le KPCR du processeur courant, par `gs:[0]`. Sur l'hôte (tests), celui du
/// processeur de démarrage.
///
/// # IRQL
/// Tout niveau.
#[inline]
pub fn current() -> &'static Kpcr {
    #[cfg(target_os = "none")]
    {
        let pcr: *const Kpcr;
        // SAFETY: en mode noyau, la base de GS est le KPCR de ce CPU
        // (`init_bsp`), dont le premier champ est sa propre adresse. Pas
        // `pure` : un thread pourra changer de CPU entre deux lectures (SMP).
        unsafe {
            core::arch::asm!("mov {}, gs:[0]", out(reg) pcr, options(nostack, preserves_flags, readonly));
            &*pcr
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        &BSP_PCR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_boot_processor_kpcr_points_to_itself() {
        let pcr = current();
        assert!(ptr::eq(pcr.self_ptr, pcr));
        assert_eq!(pcr.number(), 0);
    }
}
