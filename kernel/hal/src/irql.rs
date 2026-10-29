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
//! The IRQL is a per-CPU software value (one CPU for now; the KPRCB will hold
//! it, ADR-015). The APIC TPR will mirror it once the clock vector sits above
//! DISPATCH_LEVEL (M1).
//!
//! The dispatch is NT's DISPATCH software interrupt: Ke's hook drains the DPC
//! queue, then switches threads if a quantum end asked for it. Requested by
//! [`request_dispatch`] (DPC queued, quantum end), it runs below
//! DISPATCH_LEVEL only: at once if the requester is there with interrupts
//! enabled, at the epilogue of the ISR that requested it if the interrupted
//! code was there ([`dispatch_from_interrupt`]), otherwise as soon as [`lower`]
//! brings the IRQL below DISPATCH_LEVEL with interrupts enabled. A thread
//! holding a `KSpinLock` (at DISPATCH_LEVEL) is therefore never preempted.
//!
//! WI7e Ch.3 "Interrupt Request Levels and Deferred Procedure Calls"

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

// ── IRQL type ────────────────────────────────────────────────────────────────

/// Interrupt Request Level.
///
/// Stored as `u8` in [`HAL_CURRENT_IRQL`] and in APIC TPR writes.
/// Device IRQLs 3–30 are collapsed to [`Irql::Device`] for simplicity;
/// the raw byte is preserved in [`HAL_CURRENT_IRQL`] for TPR programming.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Irql {
    /// Normal thread execution — page faults and heap allocations safe.
    Passive = 0,
    /// APC delivery level — page faults still allowed.
    Apc = 1,
    /// Scheduler / DPC level — NO page faults, NO heap allocations.
    Dispatch = 2,
    /// Device interrupt level (raw values 3–30).
    Device = 3,
    /// High level — NMI / machine check, nothing is safe.
    High = 31,
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
            0 => Irql::Passive,
            1 => Irql::Apc,
            2 => Irql::Dispatch,
            3..=30 => Irql::Device,
            _ => Irql::High,
        }
    }
}

// ── Per-CPU IRQL storage ─────────────────────────────────────────────────────

/// Current IRQL for this CPU. Starts at PASSIVE_LEVEL, before any HAL init.
///
/// Unmangled: the ring-3 trampoline (`ring3.rs`) stores PASSIVE_LEVEL into it
/// before entering user mode, which runs at PASSIVE_LEVEL.
#[unsafe(no_mangle)]
static HAL_CURRENT_IRQL: AtomicU8 = AtomicU8::new(Irql::Passive.as_u8());

/// The DISPATCH software interrupt is requested and has not run yet.
static DISPATCH_PENDING: AtomicBool = AtomicBool::new(false);

/// The DISPATCH interrupt handler: `fn()` stored as `usize`, 0 until Ke
/// registers it.
static DISPATCH_HOOK: AtomicUsize = AtomicUsize::new(0);

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
    HAL_CURRENT_IRQL.store(Irql::Passive.as_u8(), Ordering::Release);
    log::trace!("IRQL: initialised at PASSIVE_LEVEL");
}

/// Read the current IRQL.
///
/// # IRQL: Any level (read-only, safe from ISR context).
#[inline]
pub fn current() -> Irql {
    Irql::from_u8(HAL_CURRENT_IRQL.load(Ordering::Relaxed))
}

/// Raise the IRQL to `new_irql`. Returns the previous IRQL — NT's
/// `KeRaiseIrql`.
///
/// # Panics
/// If `new_irql < current()` (NT: IRQL_NOT_GREATER_OR_EQUAL).
///
/// # IRQL: Any level. After return, current IRQL == `new_irql`.
#[inline]
pub fn raise(new_irql: Irql) -> Irql {
    let prev = Irql::from_u8(HAL_CURRENT_IRQL.swap(new_irql.as_u8(), Ordering::AcqRel));
    assert!(new_irql >= prev, "IRQL raise: attempted to lower from {:?} to {:?}", prev, new_irql);
    prev
}

/// Lower the IRQL back to `old_irql` (as returned by a previous [`raise`]) —
/// NT's `KeLowerIrql`. Below DISPATCH_LEVEL with interrupts enabled, runs the
/// dispatch requested meanwhile, if any: this thread may be switched out here.
///
/// # Panics
/// If `old_irql > current()`.
///
/// # IRQL: Any level. After return, current IRQL == `old_irql`.
#[inline]
pub fn lower(old_irql: Irql) {
    let cur = Irql::from_u8(HAL_CURRENT_IRQL.load(Ordering::Relaxed));
    assert!(old_irql <= cur, "IRQL lower: target {:?} is above current {:?}", old_irql, cur);
    HAL_CURRENT_IRQL.store(old_irql.as_u8(), Ordering::Release);
    if old_irql < Irql::Dispatch && DISPATCH_PENDING.load(Ordering::Acquire) && interrupts_enabled() {
        x86_64::instructions::interrupts::without_interrupts(run_dispatch);
    }
}

/// Registers the DISPATCH interrupt handler (Ke: DPC queue, then thread
/// switch), run at DISPATCH_LEVEL with interrupts disabled on entry and exit.
/// `None` until Ke is ready.
///
/// # IRQL: Any level.
pub fn set_dispatch_hook(hook: Option<fn()>) {
    DISPATCH_HOOK.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Requests the DISPATCH interrupt (HalRequestSoftwareInterrupt). Below
/// DISPATCH_LEVEL with interrupts enabled it runs before this returns: the
/// caller may be switched out here. Otherwise it runs at the epilogue of the
/// current ISR, or when the IRQL drops below DISPATCH_LEVEL.
///
/// # IRQL: Any level, ISR included.
pub fn request_dispatch() {
    DISPATCH_PENDING.store(true, Ordering::Release);
    if current() < Irql::Dispatch && interrupts_enabled() {
        x86_64::instructions::interrupts::without_interrupts(run_dispatch);
    }
}

/// From an ISR epilogue (EOI sent, interrupts disabled): runs the DISPATCH
/// interrupt the ISR requested, if the interrupted code ran below
/// DISPATCH_LEVEL; otherwise it stays pending until the IRQL drops.
///
/// # IRQL: DIRQL, in an ISR.
pub fn dispatch_from_interrupt() {
    if current() < Irql::Dispatch {
        run_dispatch();
    }
}

/// Runs the DISPATCH interrupt at DISPATCH_LEVEL, interrupts disabled, until
/// no request is left (an ISR may request it again while the handler runs
/// DPCs with interrupts enabled). The thread switched to resumes at its own
/// switch point, which restores its own IRQL; this one restores `old` when it
/// runs again.
fn run_dispatch() {
    let old = raise(Irql::Dispatch);
    while DISPATCH_PENDING.swap(false, Ordering::AcqRel) {
        let hook = DISPATCH_HOOK.load(Ordering::Acquire);
        if hook != 0 {
            // SAFETY: `hook` was stored by `set_dispatch_hook` from a valid `fn()`.
            let dispatch: fn() = unsafe { core::mem::transmute(hook) };
            dispatch();
        }
    }
    // Not `lower`: interrupts are off, and the dispatch has just run.
    HAL_CURRENT_IRQL.store(old.as_u8(), Ordering::Release);
}

fn interrupts_enabled() -> bool {
    cfg!(target_os = "none") && x86_64::instructions::interrupts::are_enabled()
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
