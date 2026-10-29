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
//! Each tick advances the interrupt time ([`interrupt_time`], in 100 ns) by
//! the interval currently programmed, which `set_resolution` can change: the
//! clock stays right at any resolution. `get_tick_count()` returns real
//! milliseconds since boot, feeding `kernel32!GetTickCount` and
//! `winmm!timeGetTime`.
//!
//! WI7e Ch.3 "Clock Intervals and Timer Resolution"

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::instructions::port::Port;

// ── Tick interval ─────────────────────────────────────────────────────────────

/// Default tick interval in milliseconds (100 Hz = 10 ms, matching XP default).
pub const TICK_INTERVAL_MS: u64 = 10;

// ── APIC MMIO ─────────────────────────────────────────────────────────────────

/// xAPIC MMIO physical base — architectural default.
const APIC_PHYS: u64 = 0xFEE0_0000;

/// Virtual address of APIC register `offset`: through the HHDM once the
/// kernel has set it, through the identity map before (early `init`).
#[inline]
pub(crate) fn apic_reg(offset: u64) -> u64 {
    crate::HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed) + APIC_PHYS + offset
}

const APIC_SVR: u64 = 0x0F0; // Spurious Interrupt Vector Register
const APIC_TIMER_LVT: u64 = 0x320; // Timer Local Vector Table entry
const APIC_TIMER_INIT: u64 = 0x380; // Initial count register
const APIC_TIMER_CURRENT: u64 = 0x390; // Current count register (read-only)
const APIC_TIMER_DIVIDE: u64 = 0x3E0; // Divide configuration register

/// Timer LVT: periodic mode (bit 17) | vector 0x20.
const TIMER_VECTOR: u32 = 0x20;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const LVT_MASKED: u32 = 1 << 16;

// ── PIT I/O ports and constants ───────────────────────────────────────────────

const PIT_CMD: u16 = 0x43; // PIT mode/command register
const PIT_CH2: u16 = 0x42; // PIT channel 2 data port
const PCSPKR: u16 = 0x61; // PC speaker / system control port

/// PIT ticks that represent 10 ms at 1.193182 MHz: ⌊1_193_182 × 10 / 1000⌋.
const PIT_10MS: u16 = 11_931;

// ── Counters ──────────────────────────────────────────────────────────────────

/// Interrupt time: 100 ns units since the timer started (NT's InterruptTime,
/// KUSER_SHARED_DATA). Advanced by the APIC timer ISR (vector 0x20).
static INTERRUPT_TIME: AtomicU64 = AtomicU64::new(0);

/// Interval between two ticks, in 100 ns units: the period the APIC timer is
/// programmed with ([`TICK_INTERVAL_MS`], then `set_resolution`).
static TICK_INTERVAL_100NS: AtomicU64 = AtomicU64::new(TICK_INTERVAL_MS * 10_000);

/// APIC timer ticks per millisecond, stored after calibration.
/// Zero means the timer has not been calibrated yet.
static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);

static SHARED_USER_DATA_VA: AtomicU64 = AtomicU64::new(0);

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the APIC timer and enable hardware interrupts.
///
/// Calibrates the APIC timer frequency using PIT channel 2 as a reference.
/// After this call the timer fires at 100 Hz (10 ms intervals) and advances
/// the interrupt time via the ISR registered in `idt.rs`.
///
/// # Safety
/// - Must run after `idt::init()` (IDT loaded; timer ISR at vector 0x20 reachable).
/// - The APIC MMIO region at `0xFEE0_0000` must be mapped: identity map at
///   boot, HHDM once `set_hhdm_offset` has run (see `apic_reg`).
/// - Interrupts must be disabled on entry; this function enables them.
pub unsafe fn init() {
    // ── 0. Remap legacy 8259 PIC (IRQ0→0x20, IRQ8→0x28) ─────────────────────
    // Remap master PIC to vectors 0x20–0x27 and slave to 0x28–0x2F so they
    // don't overlap CPU exceptions (0x00–0x1F).  Then unmask only IRQ1
    // (PS/2 keyboard) on the master; all other legacy IRQs stay masked.
    // SAFETY: I/O ports 0x20/0x21/0xA0/0xA1 are always accessible at CPL 0.
    unsafe {
        let mut master_cmd = Port::<u8>::new(0x20);
        let mut master_dat = Port::<u8>::new(0x21);
        let mut slave_cmd = Port::<u8>::new(0xA0);
        let mut slave_dat = Port::<u8>::new(0xA1);
        // ICW1: begin init sequence (IC4 needed)
        master_cmd.write(0x11);
        slave_cmd.write(0x11);
        // ICW2: vector offset
        master_dat.write(0x20); // master: IRQ0 → vector 0x20
        slave_dat.write(0x28); // slave:  IRQ8 → vector 0x28
                               // ICW3: master/slave wiring
        master_dat.write(0x04); // slave on IRQ2
        slave_dat.write(0x02); // slave cascade identity
                               // ICW4: 8086 mode
        master_dat.write(0x01);
        slave_dat.write(0x01);
        // OCW1: mask all except IRQ1 (keyboard) on master; mask all on slave
        master_dat.write(0xFD); // 1111_1101 = unmask IRQ1 only
        slave_dat.write(0xFF); // mask all slave IRQs
    }
    log::info!("HAL timer: 8259 PIC remapped (IRQ1 unmasked for PS/2 keyboard)");

    // ── 1. Software-enable local APIC ────────────────────────────────────────
    // Spurious Interrupt Vector Register (SVR):
    //   bit 8  = APIC software enable
    //   bits 7:0 = spurious vector (must be >= 0xF0 on some firmwares; 0xFF safe)
    // SAFETY: APIC MMIO is mapped at apic_reg(0) (identity map at this point).
    unsafe {
        let svr = apic_read(APIC_SVR);
        apic_write(APIC_SVR, svr | 0x100 | 0xFF);
    }

    // ── 2. Set timer divisor = 16 ────────────────────────────────────────────
    // APIC divide config: 0x3 = divide by 16.
    unsafe {
        apic_write(APIC_TIMER_DIVIDE, 0x3);
    }

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
        let mut pcspkr = Port::<u8>::new(PCSPKR);

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
        pit_ch2.write((PIT_10MS & 0xFF) as u8); // lobyte
        pit_ch2.write((PIT_10MS >> 8) as u8); // hibyte

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
    unsafe {
        apic_write(APIC_TIMER_INIT, 0);
    }
    unsafe {
        apic_write(APIC_TIMER_LVT, LVT_TIMER_PERIODIC | TIMER_VECTOR);
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
#[expect(clippy::identity_op, reason = "KUSER_SHARED_DATA fields are written at their offsets, 0x000 included")]
pub fn tick() {
    let interval = TICK_INTERVAL_100NS.load(Ordering::Relaxed);
    let interrupt_time_100ns = INTERRUPT_TIME.fetch_add(interval, Ordering::Relaxed).wrapping_add(interval);
    let sud = SHARED_USER_DATA_VA.load(Ordering::Relaxed);
    if sud != 0 {
        let tick_ms = interrupt_time_100ns / 10_000;

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
    interrupt_time() / 10_000
}

/// Interrupt time: 100 ns units since the timer started, at the resolution of
/// the last tick.
///
/// # IRQL
/// Any level (single atomic read).
#[inline]
pub fn interrupt_time() -> u64 {
    INTERRUPT_TIME.load(Ordering::Relaxed)
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

    // The interrupt time follows the new period. Writing the initial count
    // restarts the countdown: at most one tick is counted with the old one.
    set_tick_interval_ms(ms);
    // SAFETY: APIC MMIO is mapped at apic_reg(0) (HHDM); caller guarantees
    // PASSIVE_LEVEL.
    unsafe {
        apic_write(APIC_TIMER_INIT, new_count);
    }

    log::info!("timer::set_resolution: {}ms interval ({}×100ns request)", ms, hundred_ns);
}

/// The interval each tick adds to the interrupt time.
fn set_tick_interval_ms(ms: u64) {
    TICK_INTERVAL_100NS.store(ms * 10_000, Ordering::Relaxed);
}

pub fn set_shared_user_data_addr(addr: Option<u64>) {
    SHARED_USER_DATA_VA.store(addr.unwrap_or(0), Ordering::Release);
}

// ── APIC MMIO helpers ─────────────────────────────────────────────────────────

/// Read a 32-bit APIC register at `offset`.
///
/// # Safety
/// APIC MMIO must be mapped at `apic_reg(0)` and `offset` must be a valid
/// APIC register offset aligned to 16 bytes.
#[inline]
unsafe fn apic_read(offset: u64) -> u32 {
    // SAFETY: caller guarantees mapping and valid offset.
    unsafe { core::ptr::read_volatile(apic_reg(offset) as *const u32) }
}

/// Write a 32-bit APIC register at `offset`.
///
/// # Safety
/// Same as `apic_read`.
#[inline]
unsafe fn apic_write(offset: u64, value: u32) {
    // SAFETY: caller guarantees mapping and valid offset.
    unsafe { core::ptr::write_volatile(apic_reg(offset) as *mut u32, value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After `set_resolution`, a tick adds the new interval, not 10 ms
    /// (GetTickCount ran up to 10 times too fast after `timeBeginPeriod(1)`).
    #[test]
    fn interrupt_time_advances_by_the_programmed_interval() {
        let start = interrupt_time();
        tick();
        assert_eq!(interrupt_time() - start, TICK_INTERVAL_MS * 10_000);
        set_tick_interval_ms(1);
        tick();
        tick();
        set_tick_interval_ms(TICK_INTERVAL_MS);
        assert_eq!(interrupt_time() - start, (TICK_INTERVAL_MS + 2) * 10_000);
        assert_eq!(get_tick_count(), interrupt_time() / 10_000);
    }
}
