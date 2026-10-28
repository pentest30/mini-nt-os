//! KEVENT — NT kernel event object.
//!
//! Two variants (mirrors NT exactly):
//!   - `NotificationEvent`  — stays signalled until manually reset;
//!                            all waiters released at once.
//!   - `SynchronizationEvent` — auto-resets after releasing ONE waiter.
//!
//! Used pervasively: I/O completion, process exit, timer expiry, etc.

use spin::Mutex;

/// Corresponds to NT's `EVENT_TYPE` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    /// Manual-reset (NotificationEvent).
    Notification,
    /// Auto-reset (SynchronizationEvent).
    Synchronization,
}

/// Kernel event — safe to embed in other kernel objects.
pub struct KEvent {
    inner: Mutex<EventInner>,
}

struct EventInner {
    kind:      EventType,
    signalled: bool,
    // TODO Phase 2: wait queue (list of blocked KTHREADs).
}

impl KEvent {
    /// Create a new event.
    pub const fn new(kind: EventType, initial_state: bool) -> Self {
        Self {
            inner: Mutex::new(EventInner { kind, signalled: initial_state }),
        }
    }

    /// Signal the event. Returns the previous signalled state.
    pub fn set(&self) -> bool {
        let mut g = self.inner.lock();
        let prev = g.signalled;
        g.signalled = true;
        // TODO: wake waiters from the wait queue.
        prev
    }

    /// Clear the event (KeResetEvent).
    pub fn reset(&self) -> bool {
        let mut g = self.inner.lock();
        let prev = g.signalled;
        g.signalled = false;
        prev
    }

    /// Non-blocking poll — returns `true` if currently signalled.
    /// For Synchronization events, clears the signal atomically.
    pub fn poll(&self) -> bool {
        let mut g = self.inner.lock();
        if g.signalled {
            if g.kind == EventType::Synchronization {
                g.signalled = false;
            }
            true
        } else {
            false
        }
    }
}
