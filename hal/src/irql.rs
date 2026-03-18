//! IRQL — Interrupt Request Level
//!
//! NT defines IRQLs as a priority scheme layered on top of the CPU's
//! hardware interrupt priority. We model them as a typed enum rather
//! than a raw `u8` so the compiler catches level-ordering mistakes.
//!
//! XP-era IRQL hierarchy (x86):
//!
//!   PASSIVE  (0) — normal thread execution, page faults allowed
//!   APC      (1) — APC delivery; page faults still allowed
//!   DISPATCH (2) — scheduler / DPC; NO page faults, NO heap
//!   DIRQL    (3..26) — device interrupts
//!   CLOCK2   (28)
//!   IPI      (29)
//!   HIGH     (31) — NMI / machine check; nothing is maskable
//!
//! In debug builds, `assert_alloc_safe()` fires if heap allocation is
//! attempted at IRQL >= DISPATCH_LEVEL, matching NT kernel behaviour.
//!
//! WI7e Ch.3 "Interrupt Request Levels and Deferred Procedure Calls"

use core::sync::atomic::{AtomicU8, Ordering};

// ── IRQL type ────────────────────────────────────────────────────────────────

/// Interrupt Request Level.
///
/// Stored as `u8` in [`CURRENT_IRQL`] and in APIC TPR writes.
/// Device IRQLs 3–30 are collapsed to [`Irql::Device`] for simplicity;
/// the raw byte is preserved in [`CURRENT_IRQL`] for TPR programming.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Irql {
    /// Normal thread execution — page faults and heap allocations safe.
    Passive  = 0,
    /// APC delivery level — page faults still allowed.
    Apc      = 1,
    /// Scheduler / DPC level — NO page faults, NO heap allocations.
    Dispatch = 2,
    /// Device interrupt level (raw values 3–30).
    Device   = 3,
    /// High level — NMI / machine check, nothing is safe.
    High     = 31,
}

impl Irql {
    /// Convert to raw `u8` for APIC TPR writes.
    ///
    /// This is `const fn` so it can be used in static initialisers.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Reconstruct an `Irql` from a raw byte.
    #[inline]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0      => Irql::Passive,
            1      => Irql::Apc,
            2      => Irql::Dispatch,
            3..=30 => Irql::Device,
            _      => Irql::High,
        }
    }
}

// ── Per-CPU IRQL storage ─────────────────────────────────────────────────────

/// Current IRQL for this CPU.
///
/// Phase 1: single CPU — one global suffices.
/// Phase 2 SMP: replace with a per-CPU cell indexed by LAPIC ID.
///
/// Starts at PASSIVE_LEVEL (0) — before any HAL init.
static CURRENT_IRQL: AtomicU8 = AtomicU8::new(Irql::Passive.as_u8());

// ── Public API ───────────────────────────────────────────────────────────────

/// Initialise the IRQL subsystem.
///
/// Sets the APIC Task Priority Register to 0 (PASSIVE) so all interrupt
/// vectors are unmasked. Called from `hal::init()` after the APIC is mapped.
///
/// # IRQL: Called at PASSIVE_LEVEL during boot, with interrupts disabled.
///
/// # Safety
/// Must be called exactly once, before any interrupt is enabled.
pub unsafe fn init() {
    CURRENT_IRQL.store(Irql::Passive.as_u8(), Ordering::Release);
    // TODO Phase 1: write 0 to APIC TPR once APIC MMIO is mapped.
    // SAFETY: APIC MMIO mapped by hal::timer::init() before this point.
    // unsafe { core::ptr::write_volatile((APIC_BASE + APIC_TPR) as *mut u32, 0); }
    log::trace!("IRQL: initialised at PASSIVE_LEVEL");
}

/// Read the current IRQL.
///
/// # IRQL: Any level (read-only, safe from ISR context).
#[inline]
pub fn current() -> Irql {
    Irql::from_u8(CURRENT_IRQL.load(Ordering::Relaxed))
}

/// Raise the IRQL to `new_irql`. Returns the previous IRQL.
///
/// Programs the APIC Task Priority Register to mask lower-priority
/// interrupts — equivalent to NT's `KeRaiseIrql`.
///
/// # Panics (debug)
/// Panics if `new_irql < current()`.
///
/// # IRQL: Any level. After return, current IRQL == `new_irql`.
#[inline]
pub fn raise(new_irql: Irql) -> Irql {
    let prev_raw = CURRENT_IRQL.swap(new_irql.as_u8(), Ordering::AcqRel);
    let prev = Irql::from_u8(prev_raw);
    debug_assert!(
        new_irql >= prev,
        "IRQL raise: attempted to lower from {:?} to {:?}",
        prev, new_irql
    );
    // TODO Phase 1: mask via APIC TPR.
    // SAFETY: APIC MMIO is mapped and stable at this point.
    // unsafe { apic_write(APIC_TPR, (new_irql.as_u8() as u32) << 4); }
    prev
}

/// Lower the IRQL back to `old_irql` (as returned by a previous [`raise`]).
///
/// Unmasks interrupts that were suppressed at the higher level.
/// Equivalent to NT's `KeLowerIrql`.
///
/// # Panics (debug)
/// Panics if `old_irql > current()`.
///
/// # IRQL: Any level. After return, current IRQL == `old_irql`.
#[inline]
pub fn lower(old_irql: Irql) {
    let cur = Irql::from_u8(CURRENT_IRQL.load(Ordering::Relaxed));
    debug_assert!(
        old_irql <= cur,
        "IRQL lower: target {:?} is above current {:?}",
        old_irql, cur
    );
    CURRENT_IRQL.store(old_irql.as_u8(), Ordering::Release);
    // TODO Phase 1: unmask via APIC TPR.
    // SAFETY: APIC MMIO is mapped and stable at this point.
    // unsafe { apic_write(APIC_TPR, (old_irql.as_u8() as u32) << 4); }

    // Re-enable hardware interrupts when returning to PASSIVE or APC.
    if old_irql < Irql::Dispatch {
        // SAFETY: lowering to PASSIVE/APC — all required data structures
        // are consistent, so interrupts are safe to re-enable here.
        unsafe { x86_64::instructions::interrupts::enable() };
    }
}

// ── Alloc guard ──────────────────────────────────────────────────────────────

/// Assert that the current IRQL permits heap allocation.
///
/// Call this at every heap allocation site in debug builds.
/// Matches NT rule: no pool allocation at or above DISPATCH_LEVEL.
///
/// # IRQL: Any level (the assertion itself is lockless and safe).
#[inline]
pub fn assert_alloc_safe() {
    debug_assert!(
        current() < Irql::Dispatch,
        "Heap allocation attempted at IRQL {:?} — must be < DISPATCH_LEVEL",
        current()
    );
}

// ── RAII guard ───────────────────────────────────────────────────────────────

/// RAII guard: raises IRQL on construction, restores on drop.
///
/// Equivalent to NT's `KeRaiseIrql` / `KeLowerIrql` pair, preventing
/// the common bug of forgetting to lower after early returns.
///
/// ```rust,ignore
/// let _guard = IrqlGuard::raise(Irql::Dispatch);
/// // spinlock critical section
/// // guard drops → IRQL automatically restored
/// ```
///
/// # IRQL: `level` must be >= current().
pub struct IrqlGuard {
    prev: Irql,
}

impl IrqlGuard {
    /// Raise IRQL to `level` and return a guard that restores it on drop.
    #[inline]
    pub fn raise(level: Irql) -> Self {
        Self { prev: raise(level) }
    }
}

impl Drop for IrqlGuard {
    fn drop(&mut self) {
        lower(self.prev);
    }
}
