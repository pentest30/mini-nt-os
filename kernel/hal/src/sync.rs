//! `IrqLock`: the kernel's interim spin lock (06 §4).
//!
//! The kernel is preemptible: whenever interrupts are enabled, the timer ISR
//! may switch to another thread. A plain spin lock held by a preempted thread
//! deadlocks the CPU as soon as the next thread takes it with interrupts
//! disabled (system call handlers, ISRs): that thread spins forever and the
//! holder never runs again. `IrqLock` keeps interrupts disabled while it is
//! held, so its holder cannot be preempted.
//!
//! It stands in for `KSpinLock`, which will raise the IRQL to DISPATCH_LEVEL
//! once preemption waits for the IRQL to drop (M1). Until then, the kernel's
//! other spin locks (buddy, pool, Ob, Io) keep the problem.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// A spin lock held with interrupts disabled, reachable only through
/// [`with`](Self::with) and [`try_with`](Self::try_with).
pub struct IrqLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is only reached by the holder of the lock.
unsafe impl<T: Send> Sync for IrqLock<T> {}

impl<T> IrqLock<T> {
    pub const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// Runs `f` with the lock held and interrupts disabled; their previous
    /// state is restored afterwards.
    ///
    /// # IRQL
    /// Any level. `f` must not block, and must not take this lock again.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        without_interrupts(|| {
            while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                core::hint::spin_loop();
            }
            // SAFETY: the lock is held, so this is the only reference.
            let result = f(unsafe { &mut *self.value.get() });
            self.locked.store(false, Ordering::Release);
            result
        })
    }

    /// Like [`with`](Self::with), but returns `None` instead of waiting when
    /// the lock is held: for fatal paths, whose interrupted code may own it.
    ///
    /// # IRQL
    /// Any level.
    pub fn try_with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        without_interrupts(|| {
            self.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).ok()?;
            // SAFETY: the lock is held, so this is the only reference.
            let result = f(unsafe { &mut *self.value.get() });
            self.locked.store(false, Ordering::Release);
            Some(result)
        })
    }
}

/// Interrupts are only the kernel's to disable: host builds (tests) run `f`
/// as is.
fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    if cfg!(target_os = "none") {
        x86_64::instructions::interrupts::without_interrupts(f)
    } else {
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_gives_exclusive_access_and_releases() {
        let lock = IrqLock::new(1);
        assert_eq!(lock.with(|v| core::mem::replace(v, 2)), 1);
        assert_eq!(lock.with(|v| *v), 2, "released after the first call");
    }

    #[test]
    fn try_with_fails_while_held() {
        let lock = IrqLock::new(0);
        lock.with(|_| assert_eq!(lock.try_with(|_| ()), None));
        assert_eq!(lock.try_with(|v| *v), Some(0));
    }
}
