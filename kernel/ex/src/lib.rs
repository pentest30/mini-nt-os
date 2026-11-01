//! Ex — les objets de l'exécutif (02 §5.10).
//!
//! - [`event`] : les événements (type `Event`), sur le KEVENT de Ke.
//!
//! Les mutants, sémaphores, timers et événements à clé viendront quand le
//! mode utilisateur les demandera (M5).
//!
//! WI7e Ch.8 §Synchronization

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod event;

pub use event::{Event, EventType, EVENT_ALL_ACCESS, EVENT_MODIFY_STATE, EVENT_QUERY_STATE, EVENT_TYPE};
