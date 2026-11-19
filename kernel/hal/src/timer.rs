//! C3 — APIC timer: detect, calibrate via PIT, start at 100 Hz.
//!
//! Calibration procedure:
//!   1. Software-enable local APIC (SVR bit 8 + spurious vector 0xFF).
//!   2. Set APIC timer divisor = 16.
//!   3. Program PIT channel 2 for a 10 ms one-shot delay.
//!   4. Read remaining APIC count → derive `ticks_per_ms`.
//!   5. Set APIC timer to periodic mode, initial count = ticks_per_ms × 10.
//!   6. Enable interrupts — ISR at vector [`CLOCK_VECTOR`] calls `tick()` + EOI.
//!
//! Each tick advances the interrupt time ([`interrupt_time`], in 100 ns) by
//! the interval currently programmed, which `set_resolution` can change: the
//! clock stays right at any resolution. `get_tick_count()` returns real
//! milliseconds since boot, feeding `kernel32!GetTickCount` and
//! `winmm!timeGetTime`.
//!
//! The same 10 ms of PIT also calibrate the time-stamp counter, which gives
//! the performance counter ([`performance_counter`],
//! KeQueryPerformanceCounter).
//!
//! Real machines differ from QEMU in two ways handled here. Recent chipsets
//! may clock-gate the PIT, which then never counts: the rates then come from
//! the core crystal clock that CPUID leaf 0x15 gives ([`crystal_rates`]).
//! And the firmware may leave the local APIC in x2APIC mode, where its
//! registers are MSRs ([`x2apic_msr`]) and the MMIO page answers nothing.
//!
//! WI7e Ch.3 "Clock Intervals and Timer Resolution"

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use x86_64::instructions::port::Port;

// ── Tick interval ─────────────────────────────────────────────────────────────

/// Default tick interval in milliseconds (100 Hz = 10 ms, matching XP default).
pub const TICK_INTERVAL_MS: u64 = 10;

/// The longest interval [`set_resolution`] programs, in milliseconds.
const MAXIMUM_INTERVAL_MS: u64 = 15;
/// The longest clock interval, in 100 ns units (NT's KeMaximumIncrement,
/// which `NtQuerySystemInformation` gives as the timer resolution).
pub const MAXIMUM_INCREMENT: u32 = MAXIMUM_INTERVAL_MS as u32 * 10_000;

// ── APIC MMIO ─────────────────────────────────────────────────────────────────

/// xAPIC MMIO physical base — architectural default.
const APIC_PHYS: u64 = 0xFEE0_0000;

/// Virtual address of APIC register `offset`: through the HHDM once the
/// kernel has set it, through the identity map before (early `init`).
#[inline]
pub(crate) fn apic_reg(offset: u64) -> u64 {
    crate::HHDM_OFFSET.load(core::sync::atomic::Ordering::Relaxed) + APIC_PHYS + offset
}

/// IA32_APIC_BASE: the local APIC's base and mode.
const IA32_APIC_BASE: u32 = 0x1B;
/// IA32_APIC_BASE bit 10 (EXTD): the local APIC is in x2APIC mode.
const APIC_BASE_X2APIC: u64 = 1 << 10;

/// Whether the firmware left the local APIC in x2APIC mode: its registers are
/// then MSRs. Set once by [`init`], before the first access.
static X2APIC: AtomicBool = AtomicBool::new(false);

/// The MSR of x2APIC register `offset`: 0x800 plus the xAPIC MMIO offset
/// divided by 16 (Intel SDM vol. 3A, 11.12.1.2).
const fn x2apic_msr(offset: u64) -> u32 {
    0x800 + (offset >> 4) as u32
}

pub(crate) const APIC_EOI: u64 = 0x0B0; // End Of Interrupt
const APIC_SVR: u64 = 0x0F0; // Spurious Interrupt Vector Register
const APIC_LVT_LINT0: u64 = 0x350; // LINT0 Local Vector Table entry
const APIC_LVT_LINT1: u64 = 0x360; // LINT1 Local Vector Table entry
const APIC_TIMER_LVT: u64 = 0x320; // Timer Local Vector Table entry
const APIC_TIMER_INIT: u64 = 0x380; // Initial count register
const APIC_TIMER_CURRENT: u64 = 0x390; // Current count register (read-only)
const APIC_TIMER_DIVIDE: u64 = 0x3E0; // Divide configuration register

/// Vector of the clock interrupt (APIC timer). Its priority class, 13, is
/// CLOCK_LEVEL (`hal::irql`): the clock still ticks at DISPATCH_LEVEL.
pub const CLOCK_VECTOR: u8 = 0xD0;
const _: () = assert!(CLOCK_VECTOR >> 4 == crate::irql::Irql::Clock.as_u8());

/// First vector of the legacy 8259 PIC (IRQ0); IRQ n arrives at `PIC_VECTOR_BASE
/// + n`. Class 3: DEVICE_LEVEL.
pub const PIC_VECTOR_BASE: u8 = 0x30;
const _: () = assert!(PIC_VECTOR_BASE >> 4 == crate::irql::Irql::Device.as_u8());

/// Timer LVT vector.
const TIMER_VECTOR: u32 = CLOCK_VECTOR as u32;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const LVT_MASKED: u32 = 1 << 16;
/// LVT delivery mode ExtINT: the 8259's interrupts arrive through this pin.
const LVT_EXTINT: u32 = 0b111 << 8;
/// LVT delivery mode NMI.
const LVT_NMI: u32 = 0b100 << 8;

/// Port 0x61 reads before giving up on the PIT (about 10 s on real hardware,
/// where a port read takes about a microsecond).
const PIT_POLL_LIMIT: u32 = 10_000_000;

/// The rates of the core crystal clock, from CPUID leaf 0x15
/// (`denominator` EAX, `numerator` EBX, `crystal_hz` ECX): APIC timer ticks
/// per millisecond at divide-by-16, then the TSC frequency in Hz. When the
/// leaf enumerates the crystal, the APIC timer counts at its frequency (Intel
/// SDM vol. 3A, 11.5.4) and the TSC at `crystal × numerator / denominator`.
/// `None` when the leaf leaves one of them out.
pub fn crystal_rates(denominator: u32, numerator: u32, crystal_hz: u32) -> Option<(u64, u64)> {
    if denominator == 0 || numerator == 0 || crystal_hz == 0 {
        return None;
    }
    let ticks_per_ms = crystal_hz as u64 / 16 / 1000;
    let tsc_hz = crystal_hz as u64 * numerator as u64 / denominator as u64;
    Some((ticks_per_ms, tsc_hz))
}

/// [`crystal_rates`] of this CPU, `None` without leaf 0x15.
fn cpu_crystal_rates() -> Option<(u64, u64)> {
    // Leaf 0x15 is read only when the maximum basic leaf reaches it.
    if core::arch::x86_64::__cpuid(0).eax < 0x15 {
        return None;
    }
    let leaf = core::arch::x86_64::__cpuid(0x15);
    crystal_rates(leaf.eax, leaf.ebx, leaf.ecx)
}

// ── PIT I/O ports and constants ───────────────────────────────────────────────

const PIT_CMD: u16 = 0x43; // PIT mode/command register
const PIT_CH2: u16 = 0x42; // PIT channel 2 data port
const PCSPKR: u16 = 0x61; // PC speaker / system control port

/// PIT ticks that represent 10 ms at 1.193182 MHz: ⌊1_193_182 × 10 / 1000⌋.
const PIT_10MS: u16 = 11_931;

// ── Counters ──────────────────────────────────────────────────────────────────

/// Interrupt time: 100 ns units since the timer started (NT's InterruptTime,
/// KUSER_SHARED_DATA). Advanced by the APIC timer ISR ([`CLOCK_VECTOR`]).
static INTERRUPT_TIME: AtomicU64 = AtomicU64::new(0);

/// Interval between two ticks, in 100 ns units: the period the APIC timer is
/// programmed with ([`TICK_INTERVAL_MS`], then `set_resolution`). Public :
/// NtQuery/NtSetTimerResolution le rend à l'appelant.
pub static TICK_INTERVAL_100NS: AtomicU64 = AtomicU64::new(TICK_INTERVAL_MS * 10_000);

/// APIC timer ticks per millisecond, stored after calibration.
/// Zero means the timer has not been calibrated yet.
static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);

/// Time-stamp counter ticks per second, stored after calibration; zero
/// before.
static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);
/// The time-stamp counter at the end of the calibration: the performance
/// counter's 0.
static TSC_BASE: AtomicU64 = AtomicU64::new(0);

/// The legacy loader's KUSER_SHARED_DATA, by a kernel address valid in every
/// address space (its HHDM alias); 0 without it.
static SHARED_USER_DATA_VA: AtomicU64 = AtomicU64::new(0);
/// The kernel alias of KUSER_SHARED_DATA (`mm::shared_data`), which every Ps
/// process maps; 0 until set.
static SHARED_DATA_ALIAS: AtomicU64 = AtomicU64::new(0);

/// Ke's clock interrupt handler: `fn()` stored as `usize`, 0 until registered.
static CLOCK_HOOK: AtomicUsize = AtomicUsize::new(0);

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the APIC timer and enable hardware interrupts.
///
/// Calibrates the APIC timer frequency using PIT channel 2 as a reference.
/// After this call the timer fires at 100 Hz (10 ms intervals) and advances
/// the interrupt time via the ISR registered in `idt.rs`.
///
/// # Safety
/// - Must run after `idt::init()` (IDT loaded; timer ISR at [`CLOCK_VECTOR`] reachable).
/// - The APIC MMIO region at `0xFEE0_0000` must be mapped: identity map at
///   boot, HHDM once `set_hhdm_offset` has run (see `apic_reg`).
/// - Interrupts must be disabled on entry; this function enables them.
pub unsafe fn init() {
    // The APIC's mode, before its first register access.
    // SAFETY: IA32_APIC_BASE exists on every x86-64 CPU; reading it changes nothing.
    let x2apic = unsafe { crate::msr::rdmsr(IA32_APIC_BASE) } & APIC_BASE_X2APIC != 0;
    X2APIC.store(x2apic, Ordering::Relaxed);
    log::info!("HAL APIC: {}", if x2apic { "x2APIC mode, registers as MSRs" } else { "xAPIC mode, MMIO registers" });

    // ── 0. Remap legacy 8259 PIC (IRQ0→0x30, IRQ8→0x38) ─────────────────────
    // Remap master PIC to vectors 0x30–0x37 and slave to 0x38–0x3F (class 3,
    // DEVICE_LEVEL) so they
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
        // Master: IRQ0 → vector 0x30; slave: IRQ8 → vector 0x38.
        master_dat.write(PIC_VECTOR_BASE);
        slave_dat.write(PIC_VECTOR_BASE + 8);
        // ICW3: master/slave wiring
        master_dat.write(0x04);
        slave_dat.write(0x02);
        // ICW4: 8086 mode
        master_dat.write(0x01);
        slave_dat.write(0x01);
        // OCW1: on the master, IRQ1 (keyboard) and IRQ2 (the slave's
        // cascade); on the slave, IRQ12 (the mouse). All others masked.
        master_dat.write(0xF9); // 1111_1001
        slave_dat.write(0xEF); // 1110_1111
                               // Le contrôleur 8042 doit avoir son clavier activé avant que IRQ1
                               // ne produise quoi que ce soit (les émulateurs stricts — VirtualBox
                               // — et le matériel réel l'exigent ; QEMU tolère l'oubli) ; de même
                               // la souris de son port auxiliaire pour IRQ12.
        crate::ps2::controller_enable_keyboard();
    }
    // SAFETY: interrupts are still disabled (init), after the keyboard.
    match unsafe { crate::ps2::controller_enable_mouse() } {
        Some(size) => log::info!("HAL PS/2: keyboard IRQ1 and mouse IRQ12 enabled ({size}-byte packets)"),
        None => log::info!("HAL PS/2: keyboard IRQ1 enabled; no mouse on the 8042's auxiliary port"),
    }

    // ── 1. Software-enable local APIC ────────────────────────────────────────
    // Spurious Interrupt Vector Register (SVR):
    //   bit 8  = APIC software enable
    //   bits 7:0 = spurious vector (must be >= 0xF0 on some firmwares; 0xFF safe)
    // SAFETY: APIC MMIO is mapped at apic_reg(0) (identity map at this point).
    unsafe {
        let svr = apic_read(APIC_SVR);
        apic_write(APIC_SVR, svr | 0x100 | 0xFF);
    }

    // ── 1b. Virtual wire: the 8259 reaches the CPU through LINT0 ─────────────
    // The keyboard and mouse IRQs come from the 8259, as ExtINT on LINT0;
    // LINT1 carries NMIs. QEMU's firmware leaves them so; a real machine's
    // firmware may mask LINT0 once it routes through the I/O APIC.
    // SAFETY: the APIC registers are reachable (mode chosen above).
    unsafe {
        apic_write(APIC_LVT_LINT0, LVT_EXTINT);
        apic_write(APIC_LVT_LINT1, LVT_NMI);
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
        // A clock-gated PIT never gets there: give up after PIT_POLL_LIMIT
        // reads, or after a second when CPUID gives the TSC's frequency.
        let tsc_limit = cpu_crystal_rates().map_or(u64::MAX, |(_, tsc_hz)| tsc_hz);
        let tsc_before = core::arch::x86_64::_rdtsc();
        let mut i = 0u32;
        while pcspkr.read() & 0x20 == 0
            && i < PIT_POLL_LIMIT
            && core::arch::x86_64::_rdtsc().wrapping_sub(tsc_before) < tsc_limit
        {
            i += 1;
        }
        let pit_counted = pcspkr.read() & 0x20 != 0;

        // Read remaining APIC count; compute elapsed ticks.
        let apic_after = apic_read(APIC_TIMER_CURRENT);
        let tsc_after = core::arch::x86_64::_rdtsc();
        let ticks_10ms = 0xFFFF_FFFFu32.wrapping_sub(apic_after);
        // The same 10 ms in time-stamp counter ticks: × 100 per second.
        TSC_FREQUENCY.store(tsc_after.wrapping_sub(tsc_before).saturating_mul(100), Ordering::Relaxed);
        TSC_BASE.store(tsc_after, Ordering::Relaxed);

        // Restore PC speaker control register.
        pcspkr.write(ctrl);

        if pit_counted {
            // Round to nearest millisecond.
            (ticks_10ms as u64 + 5) / 10
        } else if let Some((ticks_per_ms, tsc_hz)) = cpu_crystal_rates() {
            log::warn!("HAL timer: the PIT does not count (clock-gated?): rates of the CPUID 0x15 crystal");
            TSC_FREQUENCY.store(tsc_hz, Ordering::Relaxed);
            ticks_per_ms
        } else {
            log::warn!("HAL timer: the PIT does not count and CPUID gives no crystal: the clock rate is wrong");
            (ticks_10ms as u64 + 5) / 10
        }
    };

    // Guard against degenerate calibration (APIC not present or misconfigured).
    let ticks_per_ms = ticks_per_ms.max(100); // absolute floor: 100 ticks/ms
    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::Relaxed);

    log::info!(
        "HAL timer: calibrated — {} ticks/ms  initial_count={}  ({} Hz); TSC at {} Hz",
        ticks_per_ms,
        ticks_per_ms * TICK_INTERVAL_MS,
        1000 / TICK_INTERVAL_MS,
        TSC_FREQUENCY.load(Ordering::Relaxed),
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
pub fn tick() {
    let interval = TICK_INTERVAL_100NS.load(Ordering::Relaxed);
    let interrupt_time_100ns = INTERRUPT_TIME.fetch_add(interval, Ordering::Relaxed).wrapping_add(interval);
    for target in [&SHARED_USER_DATA_VA, &SHARED_DATA_ALIAS] {
        let sud = target.load(Ordering::Relaxed);
        if sud != 0 {
            // SAFETY: each target is a mapped, writable KUSER_SHARED_DATA
            // page (its setter's contract).
            unsafe { write_times(sud, interrupt_time_100ns) };
        }
    }
    crate::splash::tick();
}

/// Writes the times of the KUSER_SHARED_DATA page at `sud`: InterruptTime
/// (0x008), SystemTime (0x014, the boot time of the real-time clock plus the
/// interrupt time, `rtc::system_time`), TickCount in milliseconds (0x320, `TickCountMultiplier`
/// 1 << 24) and its deprecated low part (0x000). Each KSYSTEM_TIME is
/// written High2Time, LowPart, then High1Time: a lock-free reader retries
/// until High1Time equals High2Time.
///
/// # Safety
/// `sud` is a mapped, writable KUSER_SHARED_DATA page.
unsafe fn write_times(sud: u64, interrupt_time_100ns: u64) {
    let tick_ms = interrupt_time_100ns / 10_000;
    let write_time = |offset: u64, value: u64| {
        // SAFETY: `offset` + 12 lies in the page (guaranteed by the caller).
        unsafe {
            core::ptr::write_volatile((sud + offset + 8) as *mut u32, (value >> 32) as u32);
            core::ptr::write_volatile((sud + offset) as *mut u32, value as u32);
            core::ptr::write_volatile((sud + offset + 4) as *mut u32, (value >> 32) as u32);
        }
    };
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(sud as *mut u32, tick_ms as u32) };
    write_time(0x008, interrupt_time_100ns);
    write_time(0x014, crate::rtc::boot_time() + interrupt_time_100ns);
    write_time(0x320, tick_ms);
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

/// KeQueryPerformanceCounter: the performance counter and its frequency
/// (ticks per second): the time-stamp counter since the calibration; before
/// it (or without it, on the host), the interrupt time at 10 MHz.
///
/// # IRQL
/// Any level.
pub fn performance_counter() -> (u64, u64) {
    match TSC_FREQUENCY.load(Ordering::Relaxed) {
        0 => (interrupt_time(), 10_000_000),
        frequency => {
            // SAFETY: RDTSC has no effect beyond reading the counter.
            let now = unsafe { core::arch::x86_64::_rdtsc() };
            (now.wrapping_sub(TSC_BASE.load(Ordering::Relaxed)), frequency)
        }
    }
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
    let ms = ((hundred_ns / 10_000) as u64).clamp(1, MAXIMUM_INTERVAL_MS);
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

/// Waits for `periods` periods of the APIC timer by watching its count reload,
/// without its interrupt: the self-tests check with it what the IRQL masks.
///
/// # IRQL
/// Any level, once the timer is running (`init`).
pub fn spin_periods(periods: u32) {
    // SAFETY: the APIC is mapped at apic_reg(0) once `init` has run; the
    // current-count register is read-only.
    let count = || unsafe { apic_read(APIC_TIMER_CURRENT) };
    let mut last = count();
    let mut seen = 0;
    while seen < periods {
        let now = count();
        if now > last {
            seen += 1; // counted down to 0, then reloaded
        }
        last = now;
        core::hint::spin_loop();
    }
}

/// The interval each tick adds to the interrupt time.
fn set_tick_interval_ms(ms: u64) {
    TICK_INTERVAL_100NS.store(ms * 10_000, Ordering::Relaxed);
}

/// Registers Ke's clock interrupt handler, run by the timer ISR at each tick
/// once the interrupt time has advanced, interrupts disabled.
///
/// # IRQL
/// Any level.
pub fn set_clock_hook(hook: Option<fn()>) {
    CLOCK_HOOK.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Runs Ke's clock interrupt handler, if registered.
///
/// # IRQL
/// In the timer ISR.
pub(crate) fn call_clock_hook() {
    let hook = CLOCK_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: `hook` was stored by `set_clock_hook` from a valid `fn()`.
        let clock: fn() = unsafe { core::mem::transmute(hook) };
        clock();
    }
}

pub fn set_shared_user_data_addr(addr: Option<u64>) {
    SHARED_USER_DATA_VA.store(addr.unwrap_or(0), Ordering::Release);
}

/// Sets the kernel alias of KUSER_SHARED_DATA, whose times every tick
/// updates.
///
/// # Safety
/// `alias` is a mapped, writable KUSER_SHARED_DATA page, for good.
///
/// # IRQL
/// Any level.
pub unsafe fn set_shared_data_alias(alias: u64) {
    SHARED_DATA_ALIAS.store(alias, Ordering::Release);
}

// ── APIC MMIO helpers ─────────────────────────────────────────────────────────

/// Read a 32-bit APIC register at `offset`: its MSR in x2APIC mode, its
/// MMIO word otherwise.
///
/// # Safety
/// In xAPIC mode, APIC MMIO must be mapped at `apic_reg(0)`; `offset` must
/// be a valid APIC register offset aligned to 16 bytes, readable in the
/// current mode.
#[inline]
unsafe fn apic_read(offset: u64) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: x2APIC mode: every APIC register is an MSR (caller's offset).
        return unsafe { crate::msr::rdmsr(x2apic_msr(offset)) } as u32;
    }
    // SAFETY: caller guarantees mapping and valid offset.
    unsafe { core::ptr::read_volatile(apic_reg(offset) as *const u32) }
}

/// Write a 32-bit APIC register at `offset` (see [`apic_read`]).
///
/// # Safety
/// Same as `apic_read`.
#[inline]
pub(crate) unsafe fn apic_write(offset: u64, value: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: x2APIC mode: every APIC register is an MSR (caller's offset).
        unsafe { crate::msr::wrmsr(x2apic_msr(offset), value as u64) };
        return;
    }
    // SAFETY: caller guarantees mapping and valid offset.
    unsafe { core::ptr::write_volatile(apic_reg(offset) as *mut u32, value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The x2APIC MSRs of the registers this module drives (Intel SDM vol. 3A,
    /// table 11-6): a real machine's firmware may leave the APIC in x2APIC
    /// mode, where the MMIO page answers nothing.
    #[test]
    fn each_apic_register_has_its_x2apic_msr() {
        assert_eq!(x2apic_msr(APIC_EOI), 0x80B);
        assert_eq!(x2apic_msr(APIC_SVR), 0x80F);
        assert_eq!(x2apic_msr(APIC_TIMER_LVT), 0x832);
        assert_eq!(x2apic_msr(APIC_LVT_LINT0), 0x835);
        assert_eq!(x2apic_msr(APIC_LVT_LINT1), 0x836);
        assert_eq!(x2apic_msr(APIC_TIMER_INIT), 0x838);
        assert_eq!(x2apic_msr(APIC_TIMER_CURRENT), 0x839);
        assert_eq!(x2apic_msr(APIC_TIMER_DIVIDE), 0x83E);
    }

    /// A Raptor Lake laptop (i7-1355U: 38.4 MHz crystal, TSC ratio 136/2),
    /// whose chipset may gate the PIT: 2400 APIC ticks per millisecond at
    /// divide-by-16, a 2.6112 GHz TSC. A leaf without the crystal gives none.
    #[test]
    fn the_crystal_gives_the_apic_and_tsc_rates() {
        assert_eq!(crystal_rates(2, 136, 38_400_000), Some((2400, 2_611_200_000)));
        assert_eq!(crystal_rates(2, 136, 0), None);
        assert_eq!(crystal_rates(0, 0, 0), None);
    }

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
