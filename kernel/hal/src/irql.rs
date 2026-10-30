//! IRQL — Interrupt Request Level
//!
//! NT defines IRQLs as a priority scheme layered on top of the CPU's
//! hardware interrupt priority. We model them as a typed enum rather
//! than a raw `u8` so the compiler catches level-ordering mistakes.
//!
//! The scale is the x64 one: an IRQL is an APIC priority class, so the IRQL
//! *is* the APIC task priority, CR8 (02 §Ke: IRQLs "implémentés via le TPR").
//! An interrupt vector's class (vector >> 4) is the IRQL its ISR runs at, and
//! the APIC delivers it only above the current IRQL:
//!
//!   PASSIVE  (0)     — normal thread execution, page faults allowed
//!   APC      (1)     — APC delivery; page faults still allowed
//!   DISPATCH (2)     — scheduler / DPC; NO page faults, NO heap
//!   DEVICE   (3..12) — device interrupts (DIRQL): the 8259's vectors 0x30–0x3F
//!   CLOCK    (13)    — APIC timer, vector 0xD0: it still ticks at DISPATCH_LEVEL
//!   IPI      (14)
//!   HIGH     (15)    — every maskable interrupt masked
//!
//! CR8 is the only copy of the IRQL (an atomic stands in for it on the host,
//! in tests): an ISR that interrupts a raise or a lower restores exactly the
//! CR8 it found ([`enter_interrupt`], [`exit_interrupt`]).
//!
//! Exception: the PS/2 keyboard comes through the 8259 as ExtINT, which the
//! TPR does not mask. Until it is routed through the IOAPIC, its ISR can
//! interrupt code above DEVICE_LEVEL; it then leaves that IRQL as it is.
//!
//! In debug builds, `assert_alloc_safe()` fires if heap allocation is
//! attempted at IRQL >= DISPATCH_LEVEL, matching NT kernel behaviour.
//!
//! The dispatch is NT's DISPATCH software interrupt: Ke's hook drains the DPC
//! queue, then switches threads if a quantum end asked for it. Requested by
//! [`request_dispatch`] (DPC queued, quantum end), it runs below
//! DISPATCH_LEVEL only: at once if the requester is there with interrupts
//! enabled, at the epilogue of the ISR that requested it if the interrupted
//! code was there ([`exit_interrupt`]), otherwise as soon as [`lower`]
//! brings the IRQL below DISPATCH_LEVEL with interrupts enabled. A thread
//! holding a `KSpinLock` (at DISPATCH_LEVEL) is therefore never preempted.
//!
//! The APC software interrupt works the same way one level down: Ke's hook
//! delivers the current thread's kernel APCs at APC_LEVEL, interrupts
//! enabled. Requested by [`request_apc`] (an APC queued to the running
//! thread, or a thread resumed with APCs pending), it runs once the IRQL is
//! below APC_LEVEL, after any pending DISPATCH interrupt.
//!
//! WI7e Ch.3 "Interrupt Request Levels and Deferred Procedure Calls"

use core::sync::atomic::{AtomicUsize, Ordering};

// ── IRQL type ────────────────────────────────────────────────────────────────

/// Interrupt Request Level: an APIC priority class, the value of CR8.
///
/// Device IRQLs 3–12 are collapsed to [`Irql::Device`] until interrupt
/// objects give each device its own level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Irql {
    /// Normal thread execution — page faults and heap allocations safe.
    Passive = 0,
    /// APC delivery level — page faults still allowed.
    Apc = 1,
    /// Scheduler / DPC level — NO page faults, NO heap allocations.
    Dispatch = 2,
    /// Device interrupt level (DIRQL, 3–12).
    Device = 3,
    /// Clock interrupt level (APIC timer).
    Clock = 13,
    /// Inter-processor interrupt level.
    Ipi = 14,
    /// High level — every maskable interrupt masked.
    High = 15,
}

impl Irql {
    /// The APIC priority class, as written to CR8.
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
            3..=12 => Irql::Device,
            13 => Irql::Clock,
            14 => Irql::Ipi,
            _ => Irql::High,
        }
    }
}

// ── Per-CPU IRQL storage ─────────────────────────────────────────────────────

/// This CPU's IRQL: CR8, the APIC task priority. The ring-3 trampoline
/// (`ring3.rs`) clears it before entering user mode.
#[inline]
fn read_raw() -> u8 {
    #[cfg(target_os = "none")]
    {
        let cr8: u64;
        // SAFETY: reading CR8 has no side effect.
        unsafe { core::arch::asm!("mov {}, cr8", out(reg) cr8, options(nomem, nostack, preserves_flags)) };
        cr8 as u8
    }
    #[cfg(not(target_os = "none"))]
    {
        HOST_IRQL.load(Ordering::Relaxed)
    }
}

/// Sets this CPU's IRQL. Not `nomem`: memory accesses must not move across a
/// change of IRQL.
#[inline]
fn write_raw(irql: u8) {
    #[cfg(target_os = "none")]
    {
        // SAFETY: `irql` is an `Irql` (0..=15): CR8's reserved bits stay clear.
        // Raising masks interrupts, lowering lets the pending ones in.
        unsafe { core::arch::asm!("mov cr8, {}", in(reg) u64::from(irql), options(nostack, preserves_flags)) };
    }
    #[cfg(not(target_os = "none"))]
    {
        HOST_IRQL.store(irql, Ordering::Relaxed);
    }
}

/// CR8 of the host tests.
#[cfg(not(target_os = "none"))]
static HOST_IRQL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The DISPATCH interrupt handler: `fn()` stored as `usize`, 0 until Ke
/// registers it.
static DISPATCH_HOOK: AtomicUsize = AtomicUsize::new(0);
/// `fn()` run by the APC software interrupt, or 0.
static APC_HOOK: AtomicUsize = AtomicUsize::new(0);

// ── Public API ───────────────────────────────────────────────────────────────

/// Initialise the IRQL subsystem.
///
/// Sets CR8, the APIC task priority, to PASSIVE_LEVEL so all interrupt
/// vectors are unmasked. Called from `hal::init()`.
///
/// # IRQL: Called at PASSIVE_LEVEL during boot, with interrupts disabled.
///
/// # Safety
/// Must be called exactly once, before any interrupt is enabled.
pub unsafe fn init() {
    write_raw(Irql::Passive.as_u8());
    log::trace!("IRQL: initialised at PASSIVE_LEVEL");
}

/// Read the current IRQL.
///
/// # IRQL: Any level (read-only, safe from ISR context).
#[inline]
pub fn current() -> Irql {
    Irql::from_u8(read_raw())
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
    let prev = current();
    assert!(new_irql >= prev, "IRQL raise: attempted to lower from {:?} to {:?}", prev, new_irql);
    write_raw(new_irql.as_u8());
    prev
}

/// Lower the IRQL back to `old_irql` (as returned by a previous [`raise`]) —
/// NT's `KeLowerIrql`. With interrupts enabled, runs the DISPATCH interrupt
/// requested meanwhile below DISPATCH_LEVEL (this thread may be switched out
/// here), then the APC interrupt below APC_LEVEL.
///
/// # Panics
/// If `old_irql > current()`.
///
/// # IRQL: Any level. After return, current IRQL == `old_irql`.
#[inline]
pub fn lower(old_irql: Irql) {
    let cur = current();
    assert!(old_irql <= cur, "IRQL lower: target {:?} is above current {:?}", old_irql, cur);
    write_raw(old_irql.as_u8());
    if old_irql < Irql::Dispatch && dispatch_pending().load(Ordering::Acquire) && interrupts_enabled() {
        x86_64::instructions::interrupts::without_interrupts(run_dispatch);
    }
    if old_irql < Irql::Apc && apc_pending().load(Ordering::Acquire) && interrupts_enabled() {
        run_apc();
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

/// Registers the APC interrupt handler (Ke: kernel APC delivery to the
/// current thread), run at APC_LEVEL with interrupts enabled. `None` until Ke
/// is ready.
///
/// # IRQL: Any level.
pub fn set_apc_hook(hook: Option<fn()>) {
    APC_HOOK.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Requests the DISPATCH interrupt (HalRequestSoftwareInterrupt). Below
/// DISPATCH_LEVEL with interrupts enabled it runs before this returns: the
/// caller may be switched out here. Otherwise it runs at the epilogue of the
/// current ISR, or when the IRQL drops below DISPATCH_LEVEL. An APC
/// interrupt requested meanwhile follows it.
///
/// # IRQL: Any level, ISR included.
pub fn request_dispatch() {
    dispatch_pending().store(true, Ordering::Release);
    if current() < Irql::Dispatch && interrupts_enabled() {
        x86_64::instructions::interrupts::without_interrupts(run_dispatch);
        if current() < Irql::Apc && apc_pending().load(Ordering::Acquire) {
            run_apc();
        }
    }
}

/// Requests the APC interrupt for the current thread. Below APC_LEVEL with
/// interrupts enabled it runs before this returns; otherwise at the epilogue
/// of the current ISR, or when the IRQL drops below APC_LEVEL.
///
/// # IRQL: Any level, ISR included.
pub fn request_apc() {
    apc_pending().store(true, Ordering::Release);
    if current() < Irql::Apc && interrupts_enabled() {
        run_apc();
    }
}

/// From an ISR prologue: raises the IRQL to the ISR's `level` and returns the
/// interrupted IRQL, for [`exit_interrupt`]. The APIC only delivers an
/// interrupt above the current IRQL, so `level` is above it, except for the
/// 8259's ExtINT interrupts (PS/2 keyboard), which the TPR does not mask:
/// those leave a higher IRQL as it is.
///
/// # IRQL: In an ISR, interrupts disabled.
pub fn enter_interrupt(level: Irql) -> Irql {
    let interrupted = current();
    if level > interrupted {
        write_raw(level.as_u8());
    }
    interrupted
}

/// From an ISR epilogue (EOI sent, interrupts disabled): back to the
/// `interrupted` IRQL, then the DISPATCH interrupt the ISR requested, if the
/// interrupted code ran below DISPATCH_LEVEL, and a pending APC interrupt
/// below APC_LEVEL (with interrupts enabled meanwhile); otherwise they stay
/// pending until the IRQL drops.
///
/// # IRQL: In an ISR, interrupts disabled.
pub fn exit_interrupt(interrupted: Irql) {
    write_raw(interrupted.as_u8());
    if interrupted < Irql::Dispatch {
        run_dispatch();
    }
    if interrupted < Irql::Apc && apc_pending().load(Ordering::Acquire) {
        // Kernel APCs run interrupts enabled, nested in this ISR's frame on
        // the interrupted thread's stack; the IRQL masks nothing but them.
        if cfg!(target_os = "none") {
            x86_64::instructions::interrupts::enable();
            run_apc();
            x86_64::instructions::interrupts::disable();
        }
    }
}

/// Runs the DISPATCH interrupt at DISPATCH_LEVEL, interrupts disabled, until
/// no request is left (an ISR may request it again while the handler runs
/// DPCs with interrupts enabled). The thread switched to resumes at its own
/// switch point, which restores its own IRQL; this one restores `old` when it
/// runs again.
fn run_dispatch() {
    let old = raise(Irql::Dispatch);
    while dispatch_pending().swap(false, Ordering::AcqRel) {
        let hook = DISPATCH_HOOK.load(Ordering::Acquire);
        if hook != 0 {
            // SAFETY: `hook` was stored by `set_dispatch_hook` from a valid `fn()`.
            let dispatch: fn() = unsafe { core::mem::transmute(hook) };
            dispatch();
        }
    }
    // Not `lower`: interrupts are off, and the dispatch has just run.
    write_raw(old.as_u8());
}

/// Runs the APC interrupt at APC_LEVEL, interrupts enabled, until no request
/// is left, then lowers back (which runs a DISPATCH or APC interrupt
/// requested meanwhile).
fn run_apc() {
    let old = raise(Irql::Apc);
    while apc_pending().swap(false, Ordering::AcqRel) {
        let hook = APC_HOOK.load(Ordering::Acquire);
        if hook != 0 {
            // SAFETY: `hook` was stored by `set_apc_hook` from a valid `fn()`.
            let deliver: fn() = unsafe { core::mem::transmute(hook) };
            deliver();
        }
    }
    lower(old);
}

/// The APC software interrupt of this CPU is requested and has not run yet
/// (KPCR).
#[inline]
fn apc_pending() -> &'static core::sync::atomic::AtomicBool {
    &crate::pcr::current().apc_pending
}

/// The DISPATCH software interrupt of this CPU is requested and has not run
/// yet (KPCR).
#[inline]
fn dispatch_pending() -> &'static core::sync::atomic::AtomicBool {
    &crate::pcr::current().dispatch_pending
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_apic_priority_classes() {
        for irql in [Irql::Passive, Irql::Apc, Irql::Dispatch, Irql::Device, Irql::Clock, Irql::Ipi, Irql::High] {
            assert_eq!(Irql::from_u8(irql.as_u8()), irql);
            assert!(irql.as_u8() <= 15, "CR8 holds 4 bits");
        }
        assert_eq!(Irql::from_u8(12), Irql::Device, "DIRQLs 3 to 12");
        assert!(Irql::Clock > Irql::Dispatch, "the clock ticks at DISPATCH_LEVEL");
        assert_eq!(crate::timer::CLOCK_VECTOR >> 4, Irql::Clock.as_u8());
    }

    /// The only test that changes the IRQL: the host's stand-in CR8 is global.
    #[test]
    fn an_isr_runs_at_its_level_and_restores_the_one_it_interrupted() {
        assert_eq!(current(), Irql::Passive);
        let before = raise(Irql::Dispatch);
        let interrupted = enter_interrupt(Irql::Clock);
        assert_eq!((interrupted, current()), (Irql::Dispatch, Irql::Clock));
        exit_interrupt(interrupted);
        assert_eq!(current(), Irql::Dispatch, "no DISPATCH interrupt above PASSIVE");
        let high = raise(Irql::High);
        let interrupted = enter_interrupt(Irql::Device);
        assert_eq!(current(), Irql::High, "an ExtINT ISR leaves a higher IRQL as it is");
        exit_interrupt(interrupted);
        lower(high);
        lower(before);
        assert_eq!(current(), Irql::Passive);
    }
}
