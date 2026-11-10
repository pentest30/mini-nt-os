//! Serial port output (COM1, 0x3F8) — earliest possible debug channel.
//!
//! Also provides `SerialLogger` — a `log::Log` implementation that writes
//! formatted records to COM1. Call `logger_init()` once after `serial::init()`
//! to redirect all `log::info!` / `log::warn!` / etc. calls to the UART.
//!
//! A record is formatted first, into a buffer of [`LINE_CAPACITY`] bytes on
//! the stack, then sent in one hold of the COM1 lock ([`Chunks`]): two
//! writers no longer mix their lines (a thread switched out in the middle of
//! a line, another processor, an ISR), which cut the markers the boot
//! scenarios look for. A longer record goes in chunks of that size, each
//! whole. The lock disables interrupts while a line goes: QEMU's and
//! VirtualBox's UART take a byte at once; a real 16550 at 115200 baud takes
//! about 87 µs a byte.

use crate::sync::IrqLock;
use uart_16550::SerialPort;
use x86_64::instructions::port::Port;

/// Held with interrupts disabled: system call handlers log too (see `IrqLock`).
static COM1: IrqLock<Option<SerialPort>> = IrqLock::new(None);
const COM1_BASE: u16 = 0x3F8;

/// Initialise COM1 at 115200 baud.
///
/// # Safety
/// Must be called once, with interrupts disabled.
pub unsafe fn init() {
    // SAFETY: 0x3F8 is the standard COM1 I/O port address.
    let mut port = unsafe { SerialPort::new(0x3F8) };
    port.init();
    COM1.with(|com1| *com1 = Some(port));
}

/// Write a string to COM1 by direct port I/O, without taking the COM1 lock.
///
/// For fatal paths only (STOP screen): a fault may arrive while the lock is
/// held, and waiting for it would hang. Output may interleave with a writer
/// that was interrupted mid-line.
///
/// # IRQL
/// Any level.
pub fn write_str_unlocked(s: &str) {
    let mut line_status = Port::<u8>::new(COM1_BASE + 5);
    let mut data = Port::<u8>::new(COM1_BASE);
    for &b in s.as_bytes() {
        // SAFETY: COM1 is a standard UART initialised by `init`; reading LSR
        // and writing THR have no effect beyond sending the byte.
        unsafe {
            while line_status.read() & 0x20 == 0 {
                core::hint::spin_loop();
            }
            data.write(b);
        }
    }
}

/// Write a byte to COM1. No-ops if the port is not yet initialised.
pub fn write_byte(b: u8) {
    COM1.with(|com1| {
        if let Some(port) = com1 {
            port.send(b);
        }
    });
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
/// Takes the COM1 lock for each piece of `args` (not for the whole line, as
/// `SerialLogger::log` does). Safe to call from the panic handler.
pub fn write_fmt(args: core::fmt::Arguments) {
    struct SerialWriterDirect;
    impl core::fmt::Write for SerialWriterDirect {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            COM1.with(|com1| {
                if let Some(port) = com1 {
                    s.bytes().for_each(|b| port.send(b));
                }
            });
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

/// Write a string to COM1 from an ISR context, without waiting for the lock.
///
/// Unlike `write_str`, this never spins — if the PASSIVE-level code already
/// holds the COM1 lock, this call is silently skipped (bytes may be lost).
/// Acceptable for debug output; heap allocation is never performed.
///
/// # IRQL: DISPATCH_LEVEL or above (ISR-safe)
pub fn write_str_isr(s: &str) {
    COM1.try_with(|com1| {
        if let Some(port) = com1 {
            s.bytes().for_each(|b| port.send(b));
        }
    });
}

// ── Serial logger ─────────────────────────────────────────────────────────────

/// The bytes of a record that go out in one hold of the COM1 lock: more than
/// a `DbgPrint` (512 bytes) and its prefix.
pub const LINE_CAPACITY: usize = 640;

/// A formatted record, cut into chunks of at most `N` bytes, each handed
/// whole to `flush`: a record of `N` bytes or fewer is flushed once.
pub struct Chunks<F: FnMut(&[u8]), const N: usize> {
    buffer: [u8; N],
    len: usize,
    flush: F,
}

impl<F: FnMut(&[u8]), const N: usize> Chunks<F, N> {
    pub fn new(flush: F) -> Self {
        Self { buffer: [0; N], len: 0, flush }
    }

    /// Hands what is left to `flush`.
    pub fn finish(mut self) {
        if self.len != 0 {
            (self.flush)(&self.buffer[..self.len]);
        }
    }
}

impl<F: FnMut(&[u8]), const N: usize> core::fmt::Write for Chunks<F, N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let mut bytes = s.as_bytes();
        while !bytes.is_empty() {
            let take = bytes.len().min(N - self.len);
            self.buffer[self.len..self.len + take].copy_from_slice(&bytes[..take]);
            self.len += take;
            bytes = &bytes[take..];
            if self.len == N {
                (self.flush)(&self.buffer);
                self.len = 0;
            }
        }
        Ok(())
    }
}

/// Sends `bytes` to COM1 in one hold of its lock.
fn send_line(bytes: &[u8]) {
    COM1.with(|com1| {
        if let Some(port) = com1 {
            bytes.iter().for_each(|&b| port.send(b));
        }
    });
}

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
        // "[LEVEL] message\n", formatted without heap allocation and without
        // the lock (a Display that logs does not deadlock), then sent whole.
        let mut line = Chunks::<_, LINE_CAPACITY>::new(send_line);
        let _ = core::fmt::write(&mut line, format_args!("[{}] {}\n", record.level().as_str(), record.args()));
        line.finish();

        // Mirror the same record to the framebuffer console (no-op if not init).
        super::fb::write_log_record(record.level().as_str(), record.args());
    }

    fn flush(&self) {}
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

#[cfg(test)]
mod tests {
    extern crate std;
    use core::fmt::Write;
    use std::format;
    use std::vec::Vec;

    use super::Chunks;

    /// The chunks a record of `text` is flushed in, with `N` bytes a chunk.
    fn chunks<const N: usize>(text: &str) -> Vec<Vec<u8>> {
        let mut flushed = Vec::new();
        let mut line = Chunks::<_, N>::new(|bytes: &[u8]| flushed.push(bytes.to_vec()));
        writeln!(line, "[INFO] {text}").unwrap();
        line.finish();
        flushed
    }

    #[test]
    fn a_line_goes_out_in_one_piece() {
        // Each flush is one hold of the COM1 lock: a line that fits goes in
        // one, and no other writer can cut it (send-messages lost a marker).
        let flushed = chunks::<128>("DbgPrint 28.48: [send] sent messages out of GetMessage: 0");
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0], b"[INFO] DbgPrint 28.48: [send] sent messages out of GetMessage: 0\n");
    }

    #[test]
    fn a_longer_line_goes_in_whole_chunks_and_nothing_is_lost() {
        let text = "x".repeat(150);
        let flushed = chunks::<64>(&text);
        assert_eq!(flushed.iter().map(Vec::len).collect::<Vec<_>>(), [64, 64, 30]);
        assert_eq!(flushed.concat(), format!("[INFO] {text}\n").into_bytes());
        assert_eq!(chunks::<8>("1").concat(), b"[INFO] 1\n", "exactly full, then the newline");
    }
}
