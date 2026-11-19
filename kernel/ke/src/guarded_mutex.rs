//! KGUARDED_MUTEX : un verrou qui peut attendre, pour du code à
//! PASSIVE_LEVEL ou APC_LEVEL qui fait des E/S ou alloue en le tenant
//! (06 §4 : jamais sous un verrou tournant, qui tient DISPATCH_LEVEL).
//!
//! Comme KeAcquireGuardedMutex : le thread entre en région gardée (aucun APC
//! noyau ne le prend, ni ne le termine, tant qu'il tient le verrou), puis
//! prend le verrou, ou attend qu'il se libère sur un événement de
//! synchronisation du dispatcher, qui réveille un attendant à chaque
//! libération. Le propriétaire n'est pas noté : une prise récursive bloque
//! le thread.
//!
//! Sans thread de Ke qui s'exécute (avant `ke::init`, ou dans les tests
//! hôte des crates qui s'en servent), il n'y a ni région gardée ni attente :
//! le verrou tourne sur place, ce qui suffit hors de l'ordonnanceur.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::apc::{ke_enter_guarded_region, ke_leave_guarded_region};
use crate::dispatcher::{
    ke_initialize_event, ke_set_event, ke_wait_for_single_object, KEvent, ObjectType, ProcessorMode,
};
use crate::sched::KePlatform;

/// Un verrou qui peut attendre, sur une donnée `T`.
pub struct KGuardedMutex<T> {
    locked: AtomicBool,
    /// Les threads qui vont attendre `gate` ou l'attendent.
    waiters: AtomicU32,
    /// Un événement de synchronisation, à adresse fixe : le dispatcher garde
    /// son adresse dans les blocs d'attente.
    gate: *mut KEvent,
    data: UnsafeCell<T>,
}

// SAFETY: la donnée ne s'atteint que sous le verrou ; l'événement n'est
// touché que par le dispatcher, sous son propre verrou.
unsafe impl<T: Send> Send for KGuardedMutex<T> {}
// SAFETY: voir `Send`.
unsafe impl<T: Send> Sync for KGuardedMutex<T> {}

/// Un thread de Ke s'exécute : il peut entrer en région gardée et attendre.
fn in_ke_thread() -> bool {
    crate::sched::try_current_tid().is_some()
}

impl<T> KGuardedMutex<T> {
    /// KeInitializeGuardedMutex, libre.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new(data: T) -> Self {
        let gate = Box::into_raw(Box::<KEvent>::new_uninit()).cast::<KEvent>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_event(gate, ObjectType::SynchronizationEvent, false) };
        Self { locked: AtomicBool::new(false), waiters: AtomicU32::new(0), gate, data: UnsafeCell::new(data) }
    }

    fn try_take(&self) -> bool {
        self.locked.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_ok()
    }

    /// KeAcquireGuardedMutex : prend le verrou, en attendant qu'il se libère.
    ///
    /// # IRQL
    /// <= APC_LEVEL. Peut attendre.
    pub fn lock(&self) -> KGuardedMutexGuard<'_, T> {
        let waits = in_ke_thread();
        if waits {
            ke_enter_guarded_region::<KePlatform>();
        }
        while !self.try_take() {
            if !waits {
                core::hint::spin_loop();
                continue;
            }
            // Counted before the second try: a release that comes after it
            // sees the waiter and sets the gate.
            self.waiters.fetch_add(1, Ordering::SeqCst);
            if !self.try_take() {
                // SAFETY: l'événement vit autant que `self`, que l'appelant
                // tient pendant l'attente.
                unsafe {
                    ke_wait_for_single_object::<KePlatform>(
                        ptr::addr_of_mut!((*self.gate).header),
                        ProcessorMode::Kernel,
                        false,
                        None,
                    )
                };
                self.waiters.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            self.waiters.fetch_sub(1, Ordering::SeqCst);
            break;
        }
        KGuardedMutexGuard { mutex: self, guarded: waits }
    }

    /// KeTryToAcquireGuardedMutex : prend le verrou s'il est libre.
    ///
    /// # IRQL
    /// <= APC_LEVEL.
    pub fn try_lock(&self) -> Option<KGuardedMutexGuard<'_, T>> {
        let guarded = in_ke_thread();
        if guarded {
            ke_enter_guarded_region::<KePlatform>();
        }
        if self.try_take() {
            return Some(KGuardedMutexGuard { mutex: self, guarded });
        }
        if guarded {
            ke_leave_guarded_region::<KePlatform>();
        }
        None
    }

    fn release(&self) {
        self.locked.store(false, Ordering::SeqCst);
        if self.waiters.load(Ordering::SeqCst) > 0 {
            // SAFETY: initialisé par `new`, vivant autant que `self`.
            unsafe { ke_set_event::<KePlatform>(self.gate, 0) };
        }
    }
}

impl<T> Drop for KGuardedMutex<T> {
    fn drop(&mut self) {
        // SAFETY: alloué par `new` ; personne ne l'attend plus (on tient
        // `&mut self`).
        drop(unsafe { Box::from_raw(self.gate) });
    }
}

/// Le verrou tenu : sa donnée, jusqu'à la sortie de la portée.
pub struct KGuardedMutexGuard<'a, T> {
    mutex: &'a KGuardedMutex<T>,
    /// Le thread est entré en région gardée en le prenant.
    guarded: bool,
}

impl<T> Deref for KGuardedMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: le verrou est tenu.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for KGuardedMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: le verrou est tenu, par ce seul gardien.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for KGuardedMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.release();
        if self.guarded {
            ke_leave_guarded_region::<KePlatform>();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn it_holds_its_data_and_lets_go() {
        let mutex = KGuardedMutex::new(1u32);
        {
            let mut held = mutex.lock();
            *held += 1;
            assert!(mutex.try_lock().is_none(), "held");
        }
        assert_eq!(*mutex.try_lock().expect("free again"), 2);
    }

    #[test]
    fn threads_take_it_in_turn() {
        // Outside the scheduler (no Ke thread on the host), it spins.
        let mutex = Arc::new(KGuardedMutex::new(0u64));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let mutex = mutex.clone();
                std::thread::spawn(move || {
                    for _ in 0..2_000 {
                        let mut held = mutex.lock();
                        let before = *held;
                        std::thread::yield_now();
                        *held = before + 1;
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(*mutex.lock(), 8_000, "no increment lost: one holder at a time");
    }
}
