//! Ke — Kernel executive layer.
//!
//! Provides:
//!   - Thread scheduler (round-robin → priority in Phase 2)
//!   - Dispatcher (ADR-005): waitable objects, KWAIT_BLOCK, wait and signal
//!   - Synchronisation primitives: KEVENT, KSEMAPHORE, KMUTEX
//!   - APC (Asynchronous Procedure Call) queues
//!   - DPC (Deferred Procedure Call) queue, without allocation, and the
//!     DISPATCH interrupt that drains it
//!
//! NT reference: ntoskrnl/ke/

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod apc;
pub mod clock;
pub mod dispatcher;
pub mod dpc;
pub mod event;
pub mod scheduler;
pub mod thread;

pub use event::{EventType, KEvent};
pub use scheduler::Scheduler;

/// Initialise the Ke layer. Called from kernel_main after HAL and Mm.
///
/// # Safety
/// See [`scheduler::init`]: `idle_stack_top` tops a mapped, writable kernel
/// stack reserved for the idle thread.
pub unsafe fn init(idle_stack_top: u64) {
    // SAFETY: forwarded from the caller's guarantee.
    unsafe { scheduler::init(idle_stack_top) };
    log::info!("Ke: initialised");
}
