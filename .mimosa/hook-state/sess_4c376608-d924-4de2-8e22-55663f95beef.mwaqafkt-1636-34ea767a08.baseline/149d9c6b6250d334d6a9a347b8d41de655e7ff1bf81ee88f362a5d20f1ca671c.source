//! KPRCB (ADR-015) : l'état de Ke propre à chaque processeur. Le KPCR de la HAL
//! (`hal::pcr`, atteint par GS) pointe dessus.
//!
//! Il porte le thread courant, l'ordonnancement du processeur (files prêtes et
//! thread idle, [`Scheduler`]), sa file de DPC, et ce que l'horloge transmet à
//! l'interruption DISPATCH. La table des threads et la roue de timers restent
//! communes aux processeurs.
//!
//! Un seul CPU pour l'instant : celui du démarrage, dont le KPRCB est statique.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32};

use hal::sync::IrqLock;

use crate::dpc::DpcQueue;
use crate::sched::{Scheduler, Thread};

/// État de Ke propre à un processeur.
pub struct KPrcb {
    /// Le thread courant. Seule une commutation le change ; lu sans verrou.
    pub(crate) current_thread: AtomicPtr<Thread>,
    /// Files prêtes et thread idle de ce processeur, sous le verrou dispatcher.
    scheduler: UnsafeCell<Scheduler>,
    /// File de DPC de ce processeur. Les ISR y insèrent : elle se prend
    /// interruptions masquées.
    pub(crate) dpc_queue: IrqLock<DpcQueue>,
    /// Ticks d'horloge pas encore imputés au quantum du thread courant.
    pub(crate) clock_ticks: AtomicU32,
    /// Une commutation est à examiner à la prochaine interruption DISPATCH (fin
    /// de quantum, ou préemption).
    pub(crate) reschedule: AtomicBool,
}

// SAFETY: `scheduler` n'est touché que verrou dispatcher tenu (voir
// `scheduler`) ; le reste est atomique ou protégé par son propre verrou.
unsafe impl Sync for KPrcb {}

impl KPrcb {
    const fn new() -> Self {
        Self {
            current_thread: AtomicPtr::new(ptr::null_mut()),
            scheduler: UnsafeCell::new(Scheduler::new()),
            dpc_queue: IrqLock::new(DpcQueue::new()),
            clock_ticks: AtomicU32::new(0),
            reschedule: AtomicBool::new(false),
        }
    }

    /// L'ordonnancement de ce processeur. Chaque accès crée une référence qui ne
    /// vit que le temps d'un appel de méthode : jamais à travers un appel au
    /// dispatcher, qui peut revenir ici (`KePlatform::ready_thread`).
    ///
    /// # Safety
    /// Verrou dispatcher tenu.
    pub(crate) unsafe fn scheduler(&self) -> *mut Scheduler {
        self.scheduler.get()
    }
}

/// Le KPRCB du processeur de démarrage.
static BSP_PRCB: KPrcb = KPrcb::new();

/// Enregistre le KPRCB du processeur de démarrage dans son KPCR.
///
/// # IRQL
/// Une fois, au début de `ke::init`.
pub(crate) fn init_bsp() {
    hal::pcr::current().set_prcb(ptr::addr_of!(BSP_PRCB).cast_mut().cast::<c_void>());
    assert!(ptr::eq(current(), &BSP_PRCB), "the KPCR does not reach the boot processor's KPRCB");
}

/// Le KPRCB du processeur courant, ou `None` avant `ke::init` : pour l'écran
/// d'erreur fatale, qui ne doit pas échouer à son tour.
///
/// # IRQL
/// Tout niveau.
pub(crate) fn try_current() -> Option<&'static KPrcb> {
    #[cfg(target_os = "none")]
    {
        let prcb = hal::pcr::current().prcb().cast::<KPrcb>();
        // SAFETY: non nul, c'est un KPRCB statique enregistré par `init_bsp`.
        (!prcb.is_null()).then(|| unsafe { &*prcb })
    }
    #[cfg(not(target_os = "none"))]
    {
        Some(&BSP_PRCB)
    }
}

/// Le KPRCB du processeur courant, par son KPCR. Sur l'hôte (tests), celui du
/// processeur de démarrage.
///
/// # IRQL
/// Tout niveau, après `ke::init`.
#[inline]
pub(crate) fn current() -> &'static KPrcb {
    #[cfg(target_os = "none")]
    {
        let prcb = hal::pcr::current().prcb().cast::<KPrcb>();
        assert!(!prcb.is_null(), "Ke used before ke::init");
        // SAFETY: non nul, c'est un KPRCB statique enregistré par `init_bsp`.
        unsafe { &*prcb }
    }
    #[cfg(not(target_os = "none"))]
    {
        &BSP_PRCB
    }
}
