//! Ke — Kernel executive layer.
//!
//! Provides:
//!   - Thread scheduler (round-robin → priority in Phase 2)
//!   - Synchronisation primitives: KEVENT, KSEMAPHORE, KMUTEX
//!   - APC (Asynchronous Procedure Call) queues
//!   - DPC (Deferred Procedure Call) lists
//!
//! NT reference: ntoskrnl/ke/

#![no_std]
extern crate alloc;

pub mod apc;
pub mod dpc;
pub mod event;
pub mod scheduler;
pub mod thread;

pub use event::{KEvent, EventType};
pub use scheduler::Scheduler;

/// Initialise the Ke layer. Called from kernel_main after HAL.
pub fn init() {
    scheduler::init();
    log::info!("Ke: initialised");
}
