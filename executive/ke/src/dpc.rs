//! DPC — Deferred Procedure Call list.
//!
//! DPCs run at IRQL DISPATCH_LEVEL (2).
//! Device drivers (and the timer ISR) queue DPCs for work that is
//! too slow for the ISR itself but must happen before returning to
//! thread context (e.g. completing an I/O IRP, updating the clock).
//!
//! CRITICAL: No page faults allowed at DISPATCH_LEVEL.

use alloc::collections::VecDeque;
use spin::Mutex;

pub type DpcRoutine = fn(arg: *mut u8);

pub struct Kdpc {
    pub routine:  DpcRoutine,
    pub argument: *mut u8,
}

// SAFETY: DPC arguments are caller-managed; treated as opaque.
unsafe impl Send for Kdpc {}

static DPC_QUEUE: Mutex<VecDeque<Kdpc>> = Mutex::new(VecDeque::new());

/// Enqueue a DPC. Safe to call from any IRQL.
pub fn queue(dpc: Kdpc) {
    DPC_QUEUE.lock().push_back(dpc);
}

/// Drain and execute all pending DPCs.
/// Called at IRQL DISPATCH_LEVEL by the timer ISR before returning.
pub fn drain() {
    loop {
        let dpc = DPC_QUEUE.lock().pop_front();
        match dpc {
            Some(d) => (d.routine)(d.argument),
            None    => break,
        }
    }
}
