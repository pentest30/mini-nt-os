//! Interruption d'horloge, côté Ke : ce que fait chaque tick une fois l'heure
//! avancée par `hal::timer` (02 §Ke, « Horloges »).

/// Crochet d'horloge (`hal::timer::set_clock_hook`), à chaque tick : DPC
/// d'expiration si l'heure atteint un timer armé, et fin de quantum (d'un tick
/// tant que l'ordonnanceur est le tourniquet de la phase 2).
///
/// # IRQL
/// Dans l'ISR d'horloge, interruptions masquées : ni attente, ni `KSpinLock`.
pub fn ki_clock_interrupt() {
    crate::timer::ki_check_timers();
    crate::scheduler::request_reschedule();
}
