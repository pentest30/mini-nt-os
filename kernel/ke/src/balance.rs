//! Balance set manager : un thread système, à la première priorité temps réel,
//! qui se réveille chaque seconde. Il relève pour l'instant les threads
//! affamés (`sched::ki_scan_ready_queues`) ; Mm y ajoutera la gestion des
//! working sets.
//!
//! Ke n'alloue pas de pile : l'exécutif le crée sur une pile de Mm, une fois
//! l'ordonnanceur prêt.

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;

use crate::dispatcher::{ke_wait_for_single_object, KTimer, ObjectType, ProcessorMode};
use crate::sched::{ki_scan_ready_queues, KePlatform, LOW_REALTIME_PRIORITY};
use crate::timer::{ke_initialize_timer, ke_set_timer};

/// Priorité du balance set manager : au-dessus de tout thread de priorité
/// variable, y compris un thread relevé contre la famine.
pub const BALANCE_SET_MANAGER_PRIORITY: u8 = LOW_REALTIME_PRIORITY;

/// Période du balance set manager.
const PERIOD_MS: i32 = 1000;

/// Routine du thread du balance set manager ; ne revient pas.
///
/// # IRQL
/// PASSIVE_LEVEL, sur son propre thread, à [`BALANCE_SET_MANAGER_PRIORITY`].
pub fn ke_balance_set_manager(_context: *mut c_void) {
    let mut timer = MaybeUninit::<KTimer>::uninit();
    let timer = timer.as_mut_ptr();
    // SAFETY: le timer vit sur la pile de ce thread, qui ne se termine jamais :
    // il reste valide tant qu'il est armé.
    unsafe {
        ke_initialize_timer(timer, ObjectType::SynchronizationTimer);
        ke_set_timer::<KePlatform>(timer, -i64::from(PERIOD_MS) * 10_000, PERIOD_MS, ptr::null());
    }
    loop {
        // SAFETY: timer initialisé, valide pour toujours (voir plus haut).
        unsafe {
            ke_wait_for_single_object::<KePlatform>(
                ptr::addr_of_mut!((*timer).header),
                ProcessorMode::Kernel,
                false,
                None,
            );
        }
        ki_scan_ready_queues();
    }
}
