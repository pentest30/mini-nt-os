//! PS/2 keyboard driver — polled, scancode set 1.
//!
//! Uses the 8042 controller output-buffer-full flag (port 0x64 bit 0) to
//! detect available scancodes, translating them to ASCII.  No IRQ / IOAPIC
//! configuration required — polled from the `read_byte_blocking` spin loop.
//!
//! Scancode set 1 (IBM XT/AT) — QEMU's default for `-device ps2-kbd`.
//! Key-release codes (bit 7 set) and unmapped codes return `None`.
//!
//! # Mouse interference
//! Bit 5 of the status byte (MOBF) distinguishes keyboard vs mouse data.
//! We skip mouse bytes so accidental mouse movement doesn't corrupt input.
//!
//! WI7e Ch.3 "Trap Dispatching" §I/O Interrupt Handling
//! ReactOS drivers/keyboard/i8042prt/

use x86_64::instructions::port::Port;

const PS2_DATA:   u16 = 0x60;
const PS2_STATUS: u16 = 0x64;

/// Flush any stale byte from the PS/2 output buffer.
///
/// Call once during HAL init to clear leftovers from UEFI/firmware.
///
/// # Safety
/// Must be called with interrupts disabled (avoids racing with IOAPIC if
/// a platform routes IRQ1 to a vector before we handle it).
pub unsafe fn init() {
    // SAFETY: caller guarantees interrupts disabled; I/O port access is safe
    // on bare-metal x86 when we own the hardware.
    unsafe {
        let mut status = Port::<u8>::new(PS2_STATUS);
        let mut data   = Port::<u8>::new(PS2_DATA);
        // Drain up to 16 stale bytes left by UEFI firmware.
        for _ in 0..16 {
            if status.read() & 0x01 == 0 { break; }
            let _ = data.read();
        }
    }
    log::trace!("HAL PS/2: controller flushed (polled, scancode set 1)");
}

/// Try to read one ASCII byte from the PS/2 keyboard output buffer.
///
/// Returns `None` if:
///   - The output buffer is empty (port 0x64 bit 0 = 0).
///   - The byte is from the mouse (port 0x64 bit 5 = 1).
///   - The scancode is a key-release (bit 7 set) or has no ASCII mapping.
///
/// # IRQL: any — pure I/O port reads, no locks.
pub fn try_read_byte() -> Option<u8> {
    // SAFETY: reading I/O ports 0x60/0x64 is always safe on x86 bare-metal.
    unsafe {
        let mut status_port = Port::<u8>::new(PS2_STATUS);
        let status = status_port.read();

        // Bit 0: output buffer full.
        if status & 0x01 == 0 {
            return None;
        }
        // Bit 5: output is from the auxiliary (mouse) port — skip it.
        let mut data_port = Port::<u8>::new(PS2_DATA);
        let sc = data_port.read();
        if status & 0x20 != 0 {
            return None; // discard mouse byte
        }
        // Bit 7: key release — drop.
        if sc & 0x80 != 0 {
            return None;
        }
        scancode_to_ascii(sc)
    }
}

// ── Scancode set 1 → ASCII (unshifted US QWERTY) ─────────────────────────────
//
// 0x00 means "no mapping" (modifier keys, F-keys, numpad, etc.).
// We only need the subset CMD.EXE uses: letters, digits, punctuation, Enter,
// Backspace, Space, ESC, Tab.

static SC1_TO_ASCII: [u8; 89] = {
    let mut t = [0u8; 89];

    // ESC
    t[0x01] = 0x1B;

    // Digit row
    t[0x02] = b'1'; t[0x03] = b'2'; t[0x04] = b'3'; t[0x05] = b'4';
    t[0x06] = b'5'; t[0x07] = b'6'; t[0x08] = b'7'; t[0x09] = b'8';
    t[0x0A] = b'9'; t[0x0B] = b'0'; t[0x0C] = b'-'; t[0x0D] = b'=';
    t[0x0E] = 0x08; // Backspace
    t[0x0F] = b'\t';

    // QWERTY row
    t[0x10] = b'q'; t[0x11] = b'w'; t[0x12] = b'e'; t[0x13] = b'r';
    t[0x14] = b't'; t[0x15] = b'y'; t[0x16] = b'u'; t[0x17] = b'i';
    t[0x18] = b'o'; t[0x19] = b'p'; t[0x1A] = b'['; t[0x1B] = b']';
    t[0x1C] = b'\n'; // Enter

    // ASDF row (0x1D = left Ctrl — skip)
    t[0x1E] = b'a'; t[0x1F] = b's'; t[0x20] = b'd'; t[0x21] = b'f';
    t[0x22] = b'g'; t[0x23] = b'h'; t[0x24] = b'j'; t[0x25] = b'k';
    t[0x26] = b'l'; t[0x27] = b';'; t[0x28] = b'\''; t[0x29] = b'`';

    // ZXCV row (0x2A = left Shift — skip, 0x2B = \)
    t[0x2B] = b'\\';
    t[0x2C] = b'z'; t[0x2D] = b'x'; t[0x2E] = b'c'; t[0x2F] = b'v';
    t[0x30] = b'b'; t[0x31] = b'n'; t[0x32] = b'm';
    t[0x33] = b','; t[0x34] = b'.'; t[0x35] = b'/';

    // Space
    t[0x39] = b' ';

    // Keypad (numlock on): map digits and operators
    t[0x47] = b'7'; t[0x48] = b'8'; t[0x49] = b'9'; t[0x4A] = b'-';
    t[0x4B] = b'4'; t[0x4C] = b'5'; t[0x4D] = b'6'; t[0x4E] = b'+';
    t[0x4F] = b'1'; t[0x50] = b'2'; t[0x51] = b'3'; t[0x52] = b'0';
    t[0x53] = b'.';
    // Keypad Enter (0x1C extended — handled in main table) and / are extended.

    t
};

fn scancode_to_ascii(sc: u8) -> Option<u8> {
    let idx = sc as usize;
    if idx >= SC1_TO_ASCII.len() {
        return None;
    }
    let c = SC1_TO_ASCII[idx];
    if c == 0 { None } else { Some(c) }
}
