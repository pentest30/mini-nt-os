//! Les événements à clé (ExKeyedEventObjectType) : des rendez-vous entre un
//! thread qui attend une clé (NtWaitForKeyedEvent) et un thread qui la
//! libère (NtReleaseKeyedEvent), dans le même processus.
//!
//! Le premier arrivé se met dans la file de l'événement, avec un KEVENT à
//! lui, et l'attend ; le second l'en retire et le signale, et repart aussitôt.
//! Une attente qui finit autrement (échéance, alerte) se retire de la file,
//! sauf si un partenaire l'en a déjà retirée : le rendez-vous a eu lieu, et
//! elle rend `STATUS_SUCCESS`. Une clé est paire (`ntdll` y met des adresses).
//!
//! Les sections critiques de `ntdll` s'en servent quand elles ne peuvent pas
//! créer leur événement, et ses variables de condition toujours ; un handle
//! nul désigne l'événement de `\KernelObjects\CritSecOutOfMemoryEvent`
//! ([`global`]).
//!
//! WI7e Ch.8 §Keyed Events

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER_1, STATUS_SUCCESS};
use hal::sync::{KSpinLock, Once};
use ke::dispatcher::{
    ke_initialize_event, ke_set_event, ke_wait_for_single_object, KEvent, ObjectType as KObjectType, ProcessorMode,
    EVENT_INCREMENT,
};
use ke::sched::KePlatform;
use ob::{create_object, AccessMask, GenericMapping, Object, ObjectType};

/// Attendre une clé (NtWaitForKeyedEvent).
pub const KEYEDEVENT_WAIT: AccessMask = AccessMask(0x0001);
/// Libérer une clé (NtReleaseKeyedEvent).
pub const KEYEDEVENT_WAKE: AccessMask = AccessMask(0x0002);
/// KEYEDEVENT_ALL_ACCESS d'XP.
pub const KEYEDEVENT_ALL_ACCESS: AccessMask = AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | 0x0003);

/// Le type `KeyedEvent`, avec la correspondance générique d'XP.
pub static KEYED_EVENT_TYPE: ObjectType = ObjectType::new(
    "KeyedEvent",
    KEYEDEVENT_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | KEYEDEVENT_WAIT.0),
        write: AccessMask(AccessMask::STANDARD_RIGHTS_WRITE.0 | KEYEDEVENT_WAKE.0),
        execute: AccessMask::STANDARD_RIGHTS_EXECUTE,
        all: KEYEDEVENT_ALL_ACCESS,
    },
);

/// Le nom de l'événement à clé qu'un handle nul désigne.
pub const GLOBAL_NAME: &str = "\\KernelObjects\\CritSecOutOfMemoryEvent";

/// Un thread qui attend son partenaire.
struct Waiter {
    id: u64,
    process: u32,
    key: u32,
    /// Il libère la clé (sinon il l'attend).
    releasing: bool,
    /// Le KEVENT qu'il attend, à lui ; il le rend après sa sortie de la file.
    event: *mut KEvent,
}

/// La file des threads qui attendent leur partenaire.
#[derive(Default)]
struct Queue {
    waiters: Vec<Waiter>,
}

impl Queue {
    /// Retire et rend le partenaire d'un thread du processus `process` qui
    /// libère (`releasing`) ou attend la clé `key`, s'il y en a un.
    fn take_partner(&mut self, process: u32, key: u32, releasing: bool) -> Option<Waiter> {
        let at = self.waiters.iter().position(|w| w.process == process && w.key == key && w.releasing != releasing)?;
        Some(self.waiters.remove(at))
    }

    /// Retire le thread `id` ; il n'y était plus si un partenaire l'en a
    /// retiré.
    fn remove(&mut self, id: u64) -> bool {
        match self.waiters.iter().position(|w| w.id == id) {
            Some(at) => {
                self.waiters.remove(at);
                true
            }
            None => false,
        }
    }
}

/// Le corps d'un objet événement à clé.
pub struct KeyedEvent {
    queue: KSpinLock<Queue>,
    next_id: AtomicU64,
}

// SAFETY: the KEVENTs of the queue are each its waiter's, reached only under
// the queue's lock until their waiter frees them.
unsafe impl Send for KeyedEvent {}
// SAFETY: see `Send`.
unsafe impl Sync for KeyedEvent {}

impl KeyedEvent {
    /// ExCreateKeyedEvent : un événement à clé sans attente.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create() -> Arc<Object<Self>> {
        create_object(&KEYED_EVENT_TYPE, Self { queue: KSpinLock::new(Queue::default()), next_id: AtomicU64::new(1) })
    }

    /// NtWaitForKeyedEvent (`releasing` faux) et NtReleaseKeyedEvent
    /// (`releasing` vrai) : le rendez-vous du thread courant, du processus
    /// `process`, avec un thread qui fait l'inverse sur la clé `key`. Le
    /// partenaire déjà là est réveillé et l'appel rend `STATUS_SUCCESS` ;
    /// sinon le thread attend le sien (alertable, jusqu'à `timeout`, format
    /// NT) : `STATUS_SUCCESS`, `STATUS_TIMEOUT`, `STATUS_USER_APC` ou
    /// `STATUS_ALERTED`. `STATUS_INVALID_PARAMETER_1` pour une clé impaire.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, dans un thread de Ps. Peut bloquer.
    pub fn meet(&self, process: u32, key: u32, releasing: bool, alertable: bool, timeout: Option<i64>) -> NtStatus {
        if key & 1 != 0 {
            return STATUS_INVALID_PARAMETER_1;
        }
        let mut queue = self.queue.lock();
        if let Some(partner) = queue.take_partner(process, key, releasing) {
            // SAFETY: the partner's event lives until it leaves its wait and
            // takes this lock; it is out of the queue, set under the lock.
            unsafe { ke_set_event::<KePlatform>(partner.event, EVENT_INCREMENT) };
            return STATUS_SUCCESS;
        }
        let event = Box::into_raw(Box::<KEvent>::new_uninit()).cast::<KEvent>();
        // SAFETY: new memory, at a fixed address, nobody waits on it yet.
        unsafe { ke_initialize_event(event, KObjectType::SynchronizationEvent, false) };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        queue.waiters.push(Waiter { id, process, key, releasing, event });
        drop(queue);
        // SAFETY: a Ps thread at PASSIVE_LEVEL; the event stays allocated
        // until it is freed below, once out of the queue.
        let status = unsafe {
            ke_wait_for_single_object::<KePlatform>(
                ptr::addr_of_mut!((*event).header),
                ProcessorMode::User,
                alertable,
                timeout,
            )
        };
        // Out of the queue now, by itself or by its partner (who set the
        // event under the lock): nobody reaches the event any more.
        let met = !self.queue.lock().remove(id);
        // SAFETY: allocated above, out of the queue and its wait.
        drop(unsafe { Box::from_raw(event) });
        if met {
            STATUS_SUCCESS
        } else {
            status
        }
    }

    /// Le nombre de threads qui attendent leur partenaire.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn waiting(&self) -> usize {
        self.queue.lock().waiters.len()
    }
}

/// L'événement à clé de `\KernelObjects\CritSecOutOfMemoryEvent`, que
/// désigne un handle nul.
static GLOBAL: Once<Arc<Object<KeyedEvent>>> = Once::new();

/// L'événement à clé que désigne un handle nul ; créé à la première demande.
/// Le noyau le nomme dans l'espace de noms au démarrage ([`GLOBAL_NAME`]).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn global() -> Arc<Object<KeyedEvent>> {
    GLOBAL.call_once(KeyedEvent::create).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiter(id: u64, process: u32, key: u32, releasing: bool) -> Waiter {
        Waiter { id, process, key, releasing, event: ptr::null_mut() }
    }

    #[test]
    fn a_partner_is_the_other_side_of_the_same_key_in_the_same_process() {
        let mut queue = Queue::default();
        queue.waiters.push(waiter(1, 20, 0x10, false));
        queue.waiters.push(waiter(2, 24, 0x20, false));
        queue.waiters.push(waiter(3, 20, 0x20, true));
        assert!(queue.take_partner(20, 0x10, false).is_none(), "two waiters do not meet");
        assert!(queue.take_partner(24, 0x10, true).is_none(), "another process");
        assert_eq!(queue.take_partner(20, 0x10, true).map(|w| w.id), Some(1));
        assert!(queue.take_partner(20, 0x10, true).is_none(), "taken once");
        assert_eq!(queue.take_partner(20, 0x20, false).map(|w| w.id), Some(3), "a releaser waits for its waiter");
        assert_eq!(queue.waiters.len(), 1);
    }

    #[test]
    fn a_waiter_knows_whether_it_was_met() {
        let mut queue = Queue::default();
        queue.waiters.push(waiter(1, 20, 0x10, false));
        queue.waiters.push(waiter(2, 20, 0x10, false));
        assert!(queue.remove(2), "still there: it timed out");
        let _ = queue.take_partner(20, 0x10, true);
        assert!(!queue.remove(1), "taken by its partner: it was met");
    }

    #[test]
    fn an_odd_key_is_refused_and_the_global_event_is_one() {
        let event = KeyedEvent::create();
        assert_eq!(event.meet(20, 0x11, false, false, Some(0)), STATUS_INVALID_PARAMETER_1);
        assert_eq!(event.waiting(), 0);
        assert!(Arc::ptr_eq(&global(), &global()));
    }
}
