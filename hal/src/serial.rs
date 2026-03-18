//! Serial port output (COM1, 0x3F8) — earliest possible debug channel.
//!
//! Also provides `SerialLogger` — a `log::Log` implementation that writes
//! formatted records to COM1. Call `logger_init()` once after `serial::init()`
//! to redirect all `log::info!` / `log::warn!` / etc. calls to the UART.

use spin::Mutex;
use uart_16550::SerialPort;
use x86_64::instructions::port::Port;

static COM1: Mutex<Option<SerialPort>> = Mutex::new(None);
const COM1_BASE: u16 = 0x3F8;

/// Initialise COM1 at 115200 baud.
///
/// # Safety
/// Must be called once, with interrupts disabled.
pub unsafe fn init() {
    // SAFETY: 0x3F8 is the standard COM1 I/O port address.
    let mut port = unsafe { SerialPort::new(0x3F8) };
    port.init();
    *COM1.lock() = Some(port);
}

/// Write a byte to COM1. No-ops if the port is not yet initialised.
pub fn write_byte(b: u8) {
    if let Some(ref mut port) = *COM1.lock() {
        port.send(b);
    }
}

pub fn try_read_byte() -> Option<u8> {
    unsafe {
        let mut line_status = Port::<u8>::new(COM1_BASE + 5);
        if line_status.read() & 0x01 == 0 {
            return None;
        }
        let mut data = Port::<u8>::new(COM1_BASE);
        Some(data.read())
    }
}

pub fn read_byte_blocking() -> u8 {
    loop {
        if let Some(b) = try_read_byte() {
            return b;
        }
        // Also drain the PS/2 keyboard buffer so QEMU keyboard input reaches
        // the shell when serial input is unavailable.
        if let Some(b) = super::ps2::try_read_byte() {
            return b;
        }
        core::hint::spin_loop();
    }
}

/// Write formatted output to COM1 (for use in the panic handler).
///
/// Uses the same `SerialWriter` approach as `SerialLogger::log` but acquires
/// the COM1 lock directly. Safe to call from the panic handler.
pub fn write_fmt(args: core::fmt::Arguments) {
    use core::fmt::Write;
    struct SerialWriterDirect;
    impl core::fmt::Write for SerialWriterDirect {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            // Use write_byte directly to avoid recursive lock acquisition.
            if let Some(ref mut port) = *COM1.lock() {
                for b in s.bytes() { port.send(b); }
            }
            Ok(())
        }
    }
    let _ = core::fmt::write(&mut SerialWriterDirect, args);
}

/// Write a string to COM1.
pub fn write_str(s: &str) {
    for b in s.bytes() {
        write_byte(b);
    }
}

/// Write a string to COM1 from an ISR context using `try_lock`.
///
/// Unlike `write_str`, this never spins — if the PASSIVE-level code already
/// holds the COM1 lock, this call is silently skipped (bytes may be lost).
/// Acceptable for debug output; heap allocation is never performed.
///
/// # IRQL: DISPATCH_LEVEL or above (ISR-safe)
pub fn write_str_isr(s: &str) {
    if let Some(ref mut guard) = COM1.try_lock() {
        if let Some(ref mut port) = **guard {
            for b in s.bytes() {
                port.send(b);
            }
        }
    }
}

// ── Serial logger ─────────────────────────────────────────────────────────────

/// A `log::Log` implementation that writes to COM1.
///
/// Registered as the global logger by `logger_init()`. Formats records as:
///   `[LEVEL] message\n`
///
/// # IRQL: PASSIVE_LEVEL (takes the COM1 spin lock)
pub struct SerialLogger;

static SERIAL_LOGGER: SerialLogger = SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        // Write "[LEVEL] message\n" without heap allocation.
        write_str("[");
        write_str(record.level().as_str());
        write_str("] ");
        use core::fmt::Write;
        let mut w = SerialWriter;
        let _ = core::fmt::write(&mut w, *record.args());
        write_str("\n");

        // Mirror the same record to the framebuffer console (no-op if not init).
        super::fb::write_log_record(record.level().as_str(), record.args());
    }

    fn flush(&self) {}
}

/// Adapter implementing `core::fmt::Write` over `write_byte`.
struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        super::serial::write_str(s);
        Ok(())
    }
}

/// Register `SerialLogger` as the global `log` logger.
///
/// Must be called after `serial::init()` (COM1 must be open).
/// Idempotent — safe to call multiple times (subsequent calls are no-ops).
///
/// # IRQL: PASSIVE_LEVEL
pub fn logger_init() {
    let _ = log::set_logger(&SERIAL_LOGGER);
    log::set_max_level(log::LevelFilter::Info);
}
