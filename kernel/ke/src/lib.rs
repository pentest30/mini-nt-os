//! Ke — Kernel executive layer.
//!
//! Provides:
//!   - Scheduler: 32 priorities, quantum, preemption, waits, boosts (`sched`)
//!   - Balance set manager: raises starved threads every second (`balance`)
//!   - Per-processor state, reached through the HAL's KPCR (`prcb`, ADR-015)
//!   - Dispatcher (ADR-005): waitable objects, KWAIT_BLOCK, wait and signal
//!   - Timer wheel and KTIMER objects (periodic, with a DPC)
//!   - FPU state per thread (ADR-009) and kernel FPU brackets (`fpu`)
//!   - Synchronisation primitives: KEVENT, KSEMAPHORE, KMUTEX
//!   - Kernel APCs: `KApc` objects, delivered at APC_LEVEL (`apc`)
//!   - DPC (Deferred Procedure Call) queue, without allocation, and the
//!     DISPATCH interrupt that drains it
//!   - `KeBugCheckEx`, the fatal error screen (`bugcheck`)
//!
//! NT reference: ntoskrnl/ke/

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod apc;
pub mod balance;
pub mod bugcheck;
pub mod clock;
pub mod context;
pub mod dispatcher;
pub mod dpc;
pub mod event;
pub mod fpu;
pub mod prcb;
pub mod sched;
pub mod thread;
pub mod timer;
pub mod usermem;

pub use event::{EventType, KEvent};

/// Initialise the Ke layer. Called from kernel_main after HAL and Mm.
///
/// # Safety
/// See [`sched::init`]: `idle_stack_top` tops a mapped, writable kernel
/// stack reserved for the idle thread.
pub unsafe fn init(idle_stack_top: u64) {
    // The boot processor's KPRCB first: the scheduler lives in it.
    prcb::init_bsp();
    // SAFETY: forwarded from the caller's guarantee.
    unsafe { sched::init(idle_stack_top) };
    log::info!("Ke: initialised");
}
