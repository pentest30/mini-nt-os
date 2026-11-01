//! Les événements (ExEventObjectType) : un KEVENT de Ke dans un objet d'Ob.
//!
//! Un événement de notification reste signalé jusqu'à ce qu'on le remette à
//! zéro, et libère tous ceux qui l'attendent ; un événement de
//! synchronisation libère un seul thread, et l'attente satisfaite le remet à
//! zéro. Le KEVENT est à adresse fixe (Ke y chaîne ses blocs d'attente) et
//! vit autant que l'objet : qui l'attend tient une référence sur l'objet.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;

use ke::dispatcher::{
    ke_initialize_event, ke_pulse_event, ke_reset_event, ke_set_event, DispatcherHeader, KEvent,
    ObjectType as KObjectType, EVENT_INCREMENT,
};
use ke::sched::KePlatform;
use ob::{create_object, AccessMask, GenericMapping, Object, ObjectType};

/// Lire l'état (NtQueryEvent).
pub const EVENT_QUERY_STATE: AccessMask = AccessMask(0x0001);
/// Changer l'état (NtSetEvent, NtResetEvent, NtClearEvent, NtPulseEvent).
pub const EVENT_MODIFY_STATE: AccessMask = AccessMask(0x0002);
/// EVENT_ALL_ACCESS d'XP.
pub const EVENT_ALL_ACCESS: AccessMask =
    AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | AccessMask::SYNCHRONIZE.0 | 0x0003);

/// Le type `Event` (ExEventObjectType), avec la correspondance générique
/// d'XP.
pub static EVENT_TYPE: ObjectType = ObjectType::new(
    "Event",
    EVENT_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | EVENT_QUERY_STATE.0),
        write: AccessMask(AccessMask::STANDARD_RIGHTS_WRITE.0 | EVENT_MODIFY_STATE.0),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | AccessMask::SYNCHRONIZE.0),
        all: EVENT_ALL_ACCESS,
    },
);

/// EVENT_TYPE : les deux sortes d'événements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EventType {
    NotificationEvent = 0,
    SynchronizationEvent = 1,
}

impl EventType {
    /// La sorte que désigne `value` (EVENT_TYPE) ; `None` pour une autre.
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::NotificationEvent),
            1 => Some(Self::SynchronizationEvent),
            _ => None,
        }
    }

    const fn dispatcher_type(self) -> KObjectType {
        match self {
            Self::NotificationEvent => KObjectType::NotificationEvent,
            Self::SynchronizationEvent => KObjectType::SynchronizationEvent,
        }
    }
}

/// Le corps d'un objet événement.
pub struct Event {
    kind: EventType,
    event: *mut KEvent,
}

// SAFETY: Ke ne touche au KEVENT que sous le verrou dispatcher ; le pointeur
// ne change pas.
unsafe impl Send for Event {}
// SAFETY: voir `Send`.
unsafe impl Sync for Event {}

impl Event {
    /// ExCreateEvent : un objet événement de sorte `kind`, signalé ou non.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(kind: EventType, signaled: bool) -> Arc<Object<Self>> {
        let event = Box::into_raw(Box::<KEvent>::new_uninit()).cast::<KEvent>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_event(event, kind.dispatcher_type(), signaled) };
        create_object(&EVENT_TYPE, Self { kind, event })
    }

    /// Sa sorte.
    pub fn kind(&self) -> EventType {
        self.kind
    }

    /// Son état : non nul s'il est signalé (KeReadStateEvent).
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn state(&self) -> i32 {
        // SAFETY: initialisé par `create`, vivant autant que `self` ; un mot
        // lu d'un bloc, sans le verrou, comme le fait XP.
        unsafe { ptr::addr_of!((*self.event).header.signal_state).read_volatile() }
    }

    /// KeSetEvent : le signale ; rend l'état d'avant.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set(&self) -> i32 {
        // SAFETY: initialisé par `create`.
        unsafe { ke_set_event::<KePlatform>(self.event, EVENT_INCREMENT) }
    }

    /// KeResetEvent : le remet à zéro ; rend l'état d'avant.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn reset(&self) -> i32 {
        // SAFETY: initialisé par `create`.
        unsafe { ke_reset_event::<KePlatform>(self.event) }
    }

    /// KePulseEvent : libère ceux qui l'attendent, puis le remet à zéro ;
    /// rend l'état d'avant.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn pulse(&self) -> i32 {
        // SAFETY: initialisé par `create`.
        unsafe { ke_pulse_event::<KePlatform>(self.event, EVENT_INCREMENT) }
    }

    /// Son en-tête, à attendre tant qu'on tient l'objet.
    pub fn dispatcher_object(&self) -> *mut DispatcherHeader {
        // SAFETY: le KEVENT vit autant que `self`.
        unsafe { ptr::addr_of_mut!((*self.event).header) }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: alloué par `create` ; l'objet meurt, et qui l'attendait le
        // tenait.
        drop(unsafe { Box::from_raw(self.event) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_says_its_state_before_each_change() {
        let event = Event::create(EventType::NotificationEvent, false);
        assert_eq!((event.kind(), event.state()), (EventType::NotificationEvent, 0));
        assert_eq!(event.set(), 0, "set: it was not signaled");
        assert_eq!((event.set(), event.state()), (1, 1), "set again: it was");
        assert_eq!((event.reset(), event.state()), (1, 0));
        assert_eq!((event.pulse(), event.state()), (0, 0), "a pulse leaves it reset");
        let signaled = Event::create(EventType::SynchronizationEvent, true);
        assert_eq!((signaled.state(), signaled.pulse(), signaled.state()), (1, 1, 0));
    }

    #[test]
    fn only_two_kinds_of_event() {
        assert_eq!(EventType::from_u32(0), Some(EventType::NotificationEvent));
        assert_eq!(EventType::from_u32(1), Some(EventType::SynchronizationEvent));
        assert_eq!(EventType::from_u32(2), None);
    }
}
