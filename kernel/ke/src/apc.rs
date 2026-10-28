//! APC — Asynchronous Procedure Call queues.
//!
//! NT uses APCs to deliver work to a specific thread context:
//!   - Kernel-mode APCs: run at IRQL APC_LEVEL (1), always deliverable
//!   - User-mode APCs:   run when thread is in an alertable wait
//!
//! Used heavily by the I/O manager (completion), and by Win32
//! for QueueUserAPC / ReadFileEx / WriteFileEx.
//!
//! Phase 1: queue structure only, no delivery yet.

use alloc::collections::VecDeque;

pub type ApcRoutine = fn(arg: *mut u8);

#[derive(Debug)]
pub struct Kapc {
    pub routine:   ApcRoutine,
    pub argument:  *mut u8,
    pub kernel_mode: bool,
}

// SAFETY: APC arguments are caller-managed; we treat the pointer as opaque.
unsafe impl Send for Kapc {}

pub struct ApcQueue {
    kernel: VecDeque<Kapc>,
    user:   VecDeque<Kapc>,
}

impl ApcQueue {
    pub const fn new() -> Self {
        Self {
            kernel: VecDeque::new(),
            user:   VecDeque::new(),
        }
    }

    pub fn enqueue(&mut self, apc: Kapc) {
        if apc.kernel_mode {
            self.kernel.push_back(apc);
        } else {
            self.user.push_back(apc);
        }
    }

    /// Drain one kernel-mode APC. Called at IRQL APC_LEVEL.
    pub fn drain_kernel(&mut self) -> Option<Kapc> {
        self.kernel.pop_front()
    }

    /// Drain one user-mode APC. Called on return to user mode.
    pub fn drain_user(&mut self) -> Option<Kapc> {
        self.user.pop_front()
    }
}
