//! Fatal error ("STOP") screen, printed without taking any lock.
//!
//! Minimal M0 version for the fault handlers: code, four parameters, a reason
//! and a few labelled values. The full `KeBugCheckEx` (symbolised stack, Ke)
//! comes with M1. Output goes to COM1 by direct port I/O and, when its lock
//! is free, to the framebuffer console.

/// A CPU trap the kernel cannot handle. Parameter 1 is the trap number.
pub const UNEXPECTED_KERNEL_MODE_TRAP: u32 = 0x7F;

/// Prints the STOP screen and halts this CPU for good.
///
/// `details` are printed one per line as `  <label> 0x<value>`.
///
/// # IRQL
/// Any level; raises to HIGH (interrupts off). Takes no lock and does not allocate.
pub fn stop(code: u32, name: &str, params: [u64; 4], reason: &str, details: &[(&str, u64)]) -> ! {
    x86_64::instructions::interrupts::disable();

    out("\n*** STOP: 0x");
    hex(code as u64, 8);
    out(" (");
    for (i, &p) in params.iter().enumerate() {
        if i > 0 {
            out(", ");
        }
        out("0x");
        hex(p, 16);
    }
    out(")\n");
    out(name);
    out("\n");
    out(reason);
    out("\n");
    for &(label, value) in details {
        out("  ");
        out(label);
        out(" 0x");
        hex(value, 16);
        out("\n");
    }
    out("System halted.\n");

    loop {
        x86_64::instructions::hlt();
    }
}

fn out(s: &str) {
    super::serial::write_str_unlocked(s);
    super::fb::write_str_fatal(s);
}

/// Writes `value` as `digits` lowercase hex digits, zero-padded.
fn hex(value: u64, digits: u32) {
    let mut buf = [0u8; 16];
    for i in 0..digits as usize {
        let nibble = (value >> ((digits as usize - 1 - i) * 4)) & 0xF;
        buf[i] = b"0123456789abcdef"[nibble as usize];
    }
    // The buffer holds only ASCII hex digits.
    out(core::str::from_utf8(&buf[..digits as usize]).unwrap_or("?"));
}
