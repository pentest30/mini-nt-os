//! C3 — APIC timer: detect, calibrate via PIT, start at 100 Hz.
//!
//! Calibration procedure:
//!   1. Software-enable local APIC (SVR bit 8 + spurious vector 0xFF).
//!   2. Set APIC timer divisor = 16.
//!   3. Program PIT channel 2 for a 10 ms one-shot delay.
//!   4. Read remaining APIC count → derive `ticks_per_ms`.
//!   5. Set APIC timer to periodic mode, initial count = ticks_per_ms × 10.
//!   6. Enable interrupts — ISR at vector 0x20 calls `tick()` + EOI.
//!
//! After calibration `get_tick_count()` returns real milliseconds since boot,
//! feeding `kernel32!GetTickCount` and `winmm!timeGetTime`.
//!
//! WI7e Ch.3 "Clock Intervals and Timer Resolution"

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use x86_64::instructions::port::Port;

// ── Tick interval ─────────────────────────────────────────────────────────────

/// Default tick interval in milliseconds (100 Hz = 10 ms, matching XP default).
pub const TICK_INTERVAL_MS: u64 = 10;

// ── APIC MMIO ─────────────────────────────────────────────────────────────────

/// xAPIC MMIO base — architectural default, identity-mapped by the bootloader.
const APIC_BASE: u64 = 0xFEE0_0000;

const APIC_SVR:           u64 = 0x0F0; // Spurious Interrupt Vector Register
const APIC_TIMER_LVT:     u64 = 0x320; // Timer Local Vector Table entry
const APIC_TIMER_INIT:    u64 = 0x380; // Initial count register
const APIC_TIMER_CURRENT: u64 = 0x390; // Current count register (read-only)
const APIC_TIMER_DIVIDE:  u64 = 0x3E0; // Divide configuration register

/// Timer LVT: periodic mode (bit 17) | vector 0x20.
const TIMER_VECTOR:       u32 = 0x20;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const LVT_MASKED:         u32 = 1 << 16;

// ── PIT I/O ports and constants ───────────────────────────────────────────────

const PIT_CMD:  u16 = 0x43; // PIT mode/command register
const PIT_CH2:  u16 = 0x42; // PIT channel 2 data port
const PCSPKR:   u16 = 0x61; // PC speaker / system control port

/// PIT ticks that represent 10 ms at 1.193182 MHz: ⌊1_193_182 × 10 / 1000⌋.
const PIT_10MS: u16 = 11_931;

// ── Counters ──────────────────────────────────────────────────────────────────

/// Monotonically-increasing tick counter; one unit = TICK_INTERVAL_MS ms.
/// Incremented by the APIC timer ISR (vector 0x20).
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// APIC timer ticks per millisecond, stored after calibration.
/// Zero means the timer has not been calibrated yet.
static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);

/// Optional timer tick callback registered by higher layers (Ke).
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);
static SHARED_USER_DATA_VA: AtomicU64 = AtomicU64::new(0);

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the APIC timer and enable hardware interrupts.
///
/// Calibrates the APIC timer frequency using PIT channel 2 as a reference.
/// After this call the timer fires at 100 Hz (10 ms intervals) and increments
/// `TICK_COUNT` via the ISR registered in `idt.rs`.
///
/// # Safety
/// - Must run after `idt::init()` (IDT loaded; timer ISR at vector 0x20 reachable).
/// - The APIC MMIO region at `0xFEE0_0000` must be identity-mapped (done by
///   the bootloader).
/// - Interrupts must be disabled on entry; this function enables them.
pub unsafe fn init() {
    // Ensure no upper-layer callback runs before Ke is initialised.
    TICK_HOOK.store(0, Ordering::Release);

    // ── 0. Disable legacy 8259 PIC ───────────────────────────────────────────
    // Mask all IRQs on both master and slave PIC so that PS/2 keyboard IRQ1
    // (and any other legacy IRQ) never fires as an unhandled PIC interrupt.
    // Without this, pressing a key causes IRQ1 → un-present IDT vector →
    // #GP/#NP exception → kernel panic / freeze.  We use the LAPIC for all
    // interrupt routing; PS/2 data is read by polling ports 0x60/0x64.
    // SAFETY: I/O ports 0x21 and 0xA1 are always accessible at CPL 0.
    unsafe {
        let mut master_imr = Port::<u8>::new(0x21);
        let mut slave_imr  = Port::<u8>::new(0xA1);
        master_imr.write(0xFF); // mask all master PIC IRQs (IRQ0–7)
        slave_imr.write(0xFF);  // mask all slave PIC IRQs  (IRQ8–15)
    }
    log::info!("HAL timer: legacy 8259 PIC masked");

    // ── 1. Software-enable local APIC ────────────────────────────────────────
    // Spurious Interrupt Vector Register (SVR):
    //   bit 8  = APIC software enable
    //   bits 7:0 = spurious vector (must be >= 0xF0 on some firmwares; 0xFF safe)
    // SAFETY: APIC MMIO identity-mapped by bootloader.
    unsafe {
        let svr = apic_read(APIC_SVR);
        apic_write(APIC_SVR, svr | 0x100 | 0xFF);
    }

    // ── 2. Set timer divisor = 16 ────────────────────────────────────────────
    // APIC divide config: 0x3 = divide by 16.
    unsafe { apic_write(APIC_TIMER_DIVIDE, 0x3); }

    // ── 3. Mask the timer LVT and start APIC timer at max count ──────────────
    unsafe {
        apic_write(APIC_TIMER_LVT, LVT_MASKED | TIMER_VECTOR);
        apic_write(APIC_TIMER_INIT, 0xFFFF_FFFF);
    }

    // ── 4. PIT channel 2 calibration: 10 ms one-shot ─────────────────────────
    // SAFETY: I/O ports 0x42, 0x43, 0x61 are always accessible at CPL 0.
    let ticks_per_ms = unsafe {
        let mut pit_cmd = Port::<u8>::new(PIT_CMD);
        let mut pit_ch2 = Port::<u8>::new(PIT_CH2);
        let mut pcspkr  = Port::<u8>::new(PCSPKR);

        // Enable channel 2 gate (bit 0), disable speaker (clear bit 1).
        let ctrl = pcspkr.read();
        pcspkr.write((ctrl & !0x02) | 0x01);

        // Channel 2: lobyte/hibyte access, mode 0 (interrupt on terminal count).
        // Command byte 0xB0 = 1011_0000b:
        //   [7:6] = 10 → channel 2
        //   [5:4] = 11 → lobyte then hibyte
        //   [3:1] = 000 → mode 0
        //   [0]   = 0  → binary
        pit_cmd.write(0xB0);
        pit_ch2.write((PIT_10MS & 0xFF) as u8);  // lobyte
        pit_ch2.write((PIT_10MS >> 8)   as u8);  // hibyte

        // Poll until PIT channel 2 output goes high (port 0x61 bit 5).
        // Output in mode 0 transitions LOW→HIGH when the counter reaches 0.
        // Timeout after ~10M reads to survive broken firmware.
        let mut i = 0u32;
        while pcspkr.read() & 0x20 == 0 && i < 10_000_000 {
            i += 1;
        }

        // Read remaining APIC count; compute elapsed ticks.
        let apic_after = apic_read(APIC_TIMER_CURRENT);
        let ticks_10ms = 0xFFFF_FFFFu32.wrapping_sub(apic_after);

        // Restore PC speaker control register.
        pcspkr.write(ctrl);

        // Round to nearest millisecond.
        (ticks_10ms as u64 + 5) / 10
    };

    // Guard against degenerate calibration (APIC not present or misconfigured).
    let ticks_per_ms = ticks_per_ms.max(100); // absolute floor: 100 ticks/ms
    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::Relaxed);

    log::info!(
        "HAL timer: calibrated — {} ticks/ms  initial_count={}  ({} Hz)",
        ticks_per_ms,
        ticks_per_ms * TICK_INTERVAL_MS,
        1000 / TICK_INTERVAL_MS,
    );

    // ── 5. Program APIC timer: periodic mode ─────────────────────────────────
    // Stop first (prevent spurious fire between LVT write and INIT write).
    unsafe { apic_write(APIC_TIMER_INIT, 0); }
    unsafe {
        apic_write(APIC_TIMER_LVT,  LVT_TIMER_PERIODIC | TIMER_VECTOR);
        apic_write(APIC_TIMER_INIT, (ticks_per_ms * TICK_INTERVAL_MS) as u32);
    }

    // ── 6. Enable hardware interrupts ────────────────────────────────────────
    x86_64::instructions::interrupts::enable();
    log::info!("HAL timer: interrupts enabled — APIC timer running");
}

/// Called by the timer ISR on every APIC tick. Async-signal-safe.
///
/// # IRQL: CLOCK_LEVEL (hardware interrupt context)
#[inline]
pub fn tick() {
    let ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let sud = SHARED_USER_DATA_VA.load(Ordering::Relaxed);
    if sud != 0 {
        let tick_ms              = ticks.wrapping_mul(TICK_INTERVAL_MS);
        let interrupt_time_100ns = tick_ms.wrapping_mul(10_000);

        // KSYSTEM_TIME split: LowPart (u32), High1Time (u32), High2Time (u32).
        // High2Time == High1Time is the XP torn-read safety contract.
        let it_lo = interrupt_time_100ns as u32;
        let it_hi = (interrupt_time_100ns >> 32) as u32;
        let tc_lo = tick_ms as u32;
        let tc_hi = (tick_ms >> 32) as u32;

        // SAFETY: SHARED_USER_DATA_VA points to a mapped, writable page; single-CPU ISR.
        unsafe {
            // TickCountLowDeprecated at 0x000 — legacy; kept for very old code.
            core::ptr::write_volatile((sud + 0x000) as *mut u32, tc_lo);

            // InterruptTime at 0x008 (KSYSTEM_TIME: LowPart / High1Time / High2Time).
            core::ptr::write_volatile((sud + 0x008) as *mut u32, it_lo);
            core::ptr::write_volatile((sud + 0x00C) as *mut u32, it_hi);
            core::ptr::write_volatile((sud + 0x010) as *mut u32, it_hi); // High2Time

            // SystemTime at 0x014 — use InterruptTime value (no absolute epoch for now).
            core::ptr::write_volatile((sud + 0x014) as *mut u32, it_lo);
            core::ptr::write_volatile((sud + 0x018) as *mut u32, it_hi);
            core::ptr::write_volatile((sud + 0x01C) as *mut u32, it_hi); // High2Time

            // TickCount at 0x320 (union: KSYSTEM_TIME / ULONGLONG TickCountQuad).
            // GetTickCount() = (TickCountQuad * TickCountMultiplier[0x004]) >> 24.
            // With multiplier=0x0100_0000 that simplifies to TickCountQuad directly.
            core::ptr::write_volatile((sud + 0x320) as *mut u32, tc_lo); // LowPart
            core::ptr::write_volatile((sud + 0x324) as *mut u32, tc_hi); // High1Time
            core::ptr::write_volatile((sud + 0x328) as *mut u32, tc_hi); // High2Time
        }
    }
    // TODO Phase 2: invoke Ke scheduler tick callback once ISR hook path
    // is fully validated on hardware/QEMU.
}

/// Return elapsed milliseconds since `init()` was called.
///
/// Feeds `kernel32!GetTickCount` and `winmm!timeGetTime`.
///
/// # IRQL: Any level (single atomic read)
#[inline]
pub fn get_tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed) * TICK_INTERVAL_MS
}

/// Reprogram the APIC timer to the requested resolution.
///
/// Called by `NtSetTimerResolution(hundred_ns, TRUE)` (via `timeBeginPeriod`).
/// `hundred_ns = 10_000` → 1 ms; clamped to [1, 15] ms.
///
/// # IRQL: PASSIVE_LEVEL only
pub fn set_resolution(hundred_ns: u32) {
    let ticks_per_ms = APIC_TICKS_PER_MS.load(Ordering::Relaxed);
    if ticks_per_ms == 0 {
        log::warn!("timer::set_resolution called before calibration — ignored");
        return;
    }

    // hundred_ns units: 10_000 = 1ms; clamp interval to [1ms, 15ms].
    let ms = ((hundred_ns / 10_000) as u64).clamp(1, 15);
    let new_count = (ticks_per_ms * ms) as u32;

    // SAFETY: APIC MMIO identity-mapped; caller guarantees PASSIVE_LEVEL.
    unsafe { apic_write(APIC_TIMER_INIT, new_count); }

    log::info!(
        "timer::set_resolution: {}ms interval ({}×100ns request)",
        ms, hundred_ns
    );
}

/// Register or clear the timer tick callback.
///
/// Pass `Some(ke::scheduler::schedule)` to enable preemptive round-robin.
/// Call this after both HAL and Ke have been initialised, with interrupts
/// disabled to avoid a race with the timer ISR.
///
/// # IRQL: PASSIVE_LEVEL only (during init).
pub fn set_tick_hook(hook: Option<fn()>) {
    let addr = hook.map_or(0usize, |f| f as usize);
    TICK_HOOK.store(addr, Ordering::Release);
}

pub fn set_shared_user_data_addr(addr: Option<u64>) {
    SHARED_USER_DATA_VA.store(addr.unwrap_or(0), Ordering::Release);
}

/// Invoke the scheduler hook registered via `set_tick_hook`, if any.
///
/// Called by the timer ISR **after** sending APIC EOI so the APIC can
/// accept the next periodic tick before we switch stacks.  Must be
/// async-signal-safe: no heap allocation, no page faults.
///
/// # IRQL: DIRQL (timer ISR) — no alloc, no page faults.
#[inline]
pub fn call_schedule_hook() {
    let addr = TICK_HOOK.load(Ordering::Acquire);
    if addr == 0 { return; }
    // SAFETY: `addr` was written by `set_tick_hook` with a valid `fn()`.
    let f: fn() = unsafe { core::mem::transmute(addr) };
    f();
}

// ── APIC MMIO helpers ─────────────────────────────────────────────────────────

/// Read a 32-bit APIC register at `offset` from `APIC_BASE`.
///
/// # Safety
/// APIC MMIO must be mapped at `APIC_BASE` and `offset` must be a valid
/// APIC register offset aligned to 16 bytes.
#[inline]
unsafe fn apic_read(offset: u64) -> u32 {
    // SAFETY: caller guarantees mapping and valid offset.
    unsafe { core::ptr::read_volatile((APIC_BASE + offset) as *const u32) }
}

/// Write a 32-bit APIC register at `offset`.
///
/// # Safety
/// Same as `apic_read`.
#[inline]
unsafe fn apic_write(offset: u64, value: u32) {
    // SAFETY: caller guarantees mapping and valid offset.
    unsafe { core::ptr::write_volatile((APIC_BASE + offset) as *mut u32, value) }
}
