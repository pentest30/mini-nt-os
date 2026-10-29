//! The kernel's spin locks (06 §4).
//!
//! The kernel is preemptible: the timer ISR may switch to another thread. A
//! plain spin lock held by a preempted thread deadlocks the CPU as soon as the
//! next thread takes it with interrupts disabled (system call handlers): that
//! thread spins forever and the holder never runs again. Hence:
//!
//! - [`KSpinLock`]: NT's spin lock. Taking it raises the IRQL to
//!   DISPATCH_LEVEL, where preemption is deferred (`hal::irql`): its holder is
//!   never switched out. For data shared by threads and system call handlers.
//! - [`IrqLock`]: held with interrupts disabled. For data an ISR touches too
//!   (serial port, console, scheduler state).
//!
//! `spin::Mutex` is not allowed in the kernel.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::irql::{self, Irql};

/// NT spin lock: [`lock`](Self::lock) raises the IRQL to DISPATCH_LEVEL until
/// the guard drops. Guards must drop in reverse order of acquisition (each
/// restores the IRQL its lock was taken at).
pub struct KSpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is only reached through a guard, held by one owner.
unsafe impl<T: Send> Sync for KSpinLock<T> {}

impl<T> KSpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// KeAcquireSpinLock.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL; DISPATCH_LEVEL until the guard drops: no blocking,
    /// no page fault. Not from an ISR (use `IrqLock`).
    pub fn lock(&self) -> KSpinLockGuard<'_, T> {
        let old_irql = raise_to_dispatch();
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        KSpinLockGuard { lock: self, old_irql }
    }

    /// Like [`lock`](Self::lock), but `None` instead of waiting when held.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn try_lock(&self) -> Option<KSpinLockGuard<'_, T>> {
        let old_irql = raise_to_dispatch();
        if self.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            Some(KSpinLockGuard { lock: self, old_irql })
        } else {
            lower_to(old_irql);
            None
        }
    }
}

/// Holds a [`KSpinLock`]; dropping it releases the lock and restores the IRQL.
pub struct KSpinLockGuard<'a, T> {
    lock: &'a KSpinLock<T>,
    old_irql: Irql,
}

impl<T> Deref for KSpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for KSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock, and is borrowed mutably.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for KSpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        lower_to(self.old_irql);
    }
}

/// The IRQL is the kernel's: host builds (tests, several threads) leave it.
fn raise_to_dispatch() -> Irql {
    if cfg!(target_os = "none") {
        irql::raise(Irql::Dispatch)
    } else {
        Irql::Passive
    }
}

fn lower_to(old: Irql) {
    if cfg!(target_os = "none") {
        irql::lower(old);
    }
}

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
    fn kspinlock_guard_derefs_and_releases_on_drop() {
        let lock = KSpinLock::new(1);
        *lock.lock() += 1;
        assert_eq!(*lock.lock(), 2, "released when the first guard dropped");
    }

    #[test]
    fn kspinlock_try_lock_fails_while_held() {
        let lock = KSpinLock::new(0);
        let guard = lock.lock();
        assert!(lock.try_lock().is_none());
        drop(guard);
        assert!(lock.try_lock().is_some());
    }

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
