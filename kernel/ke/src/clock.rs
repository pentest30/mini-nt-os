//! Interruption d'horloge, côté Ke : ce que fait chaque tick une fois l'heure
//! avancée par `hal::timer` (02 §Ke, « Horloges »).

/// Crochet d'horloge (`hal::timer::set_clock_hook`), à chaque tick : fin de
/// quantum, d'un tick tant que l'ordonnanceur est le tourniquet de la phase 2.
///
/// # IRQL
/// Dans l'ISR d'horloge, interruptions masquées : ni attente, ni `KSpinLock`.
pub fn ki_clock_interrupt() {
    crate::scheduler::request_reschedule();
}
