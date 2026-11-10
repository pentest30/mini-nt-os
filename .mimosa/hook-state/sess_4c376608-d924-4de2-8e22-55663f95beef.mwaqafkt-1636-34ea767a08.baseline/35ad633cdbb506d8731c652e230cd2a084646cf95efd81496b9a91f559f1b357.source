//! Ex — les objets de l'exécutif (02 §5.10).
//!
//! - [`event`] : les événements (type `Event`), sur le KEVENT de Ke.
//! - [`keyed_event`] : les événements à clé (type `KeyedEvent`), des
//!   rendez-vous par clé entre deux threads d'un processus.
//! - [`semaphore`] : les sémaphores (type `Semaphore`), sur le KSEMAPHORE de
//!   Ke.
//!
//! Les mutants et les timers viendront quand le mode utilisateur les
//! demandera (M5).
//!
//! WI7e Ch.8 §Synchronization

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod event;
pub mod keyed_event;
pub mod locale;
pub mod mutant;
pub mod semaphore;

pub use event::{Event, EventType, EVENT_ALL_ACCESS, EVENT_MODIFY_STATE, EVENT_QUERY_STATE, EVENT_TYPE};
pub use keyed_event::{KeyedEvent, KEYEDEVENT_ALL_ACCESS, KEYEDEVENT_WAIT, KEYEDEVENT_WAKE, KEYED_EVENT_TYPE};
pub use semaphore::{Semaphore, SEMAPHORE_ALL_ACCESS, SEMAPHORE_MODIFY_STATE, SEMAPHORE_QUERY_STATE, SEMAPHORE_TYPE};
