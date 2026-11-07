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

use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::instructions::port::Port;

const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_COMMAND: u16 = 0x64;

// ── ISR-safe key ring buffer ─────────────────────────────────────────────────
// Lock-free SPSC ring: ISR writes (producer), message queue reads (consumer).
const KEY_BUF_SIZE: usize = 64;
static KEY_BUF: [core::sync::atomic::AtomicU8; KEY_BUF_SIZE] =
    [const { core::sync::atomic::AtomicU8::new(0) }; KEY_BUF_SIZE];
static KEY_HEAD: AtomicUsize = AtomicUsize::new(0); // ISR writes here
static KEY_TAIL: AtomicUsize = AtomicUsize::new(0); // consumer reads here
/// The bytes the ISR could not keep, the ring being full.
static DROPPED: AtomicUsize = AtomicUsize::new(0);

/// How many bytes the ISR could not keep since the boot, the ring being
/// full (its reader too slow): each one is a key lost, or a release, which
/// leaves a key down.
///
/// # IRQL
/// Any level.
pub fn dropped() -> usize {
    DROPPED.load(Ordering::Relaxed)
}

/// What the IRQ1 ISR calls once a byte is in the ring (0: nothing).
static NOTIFY: AtomicUsize = AtomicUsize::new(0);

/// Sets what the IRQ1 ISR calls once a byte is in the ring: the keyboard
/// driver's reader queues a DPC (`drivers/input/i8042`). `None`: nothing.
///
/// # IRQL
/// Any level. `hook` runs in the ISR, at DEVICE_LEVEL: it must neither
/// block nor allocate.
pub fn set_notify(hook: Option<fn()>) {
    NOTIFY.store(hook.map_or(0, |hook| hook as usize), Ordering::Release);
}

/// Called from the IRQ1 ISR — push a scancode into the ring buffer, then
/// call the hook of [`set_notify`].
/// No heap, no locks, ISR-safe.
pub fn isr_push_scancode(scancode: u8) {
    let head = KEY_HEAD.load(Ordering::Relaxed);
    let next = (head + 1) % KEY_BUF_SIZE;
    let tail = KEY_TAIL.load(Ordering::Acquire);
    if next == tail {
        // Full: counted (`dropped`), not logged from the ISR.
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    KEY_BUF[head].store(scancode, Ordering::Relaxed);
    KEY_HEAD.store(next, Ordering::Release);
    let hook = NOTIFY.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `set_notify` stores here, the address of a `fn()`.
        let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(hook) };
        hook();
    }
}

// ── The mouse: its own ring, filled by IRQ12 ─────────────────────────────────

const MOUSE_BUF_SIZE: usize = 128;
static MOUSE_BUF: [core::sync::atomic::AtomicU8; MOUSE_BUF_SIZE] =
    [const { core::sync::atomic::AtomicU8::new(0) }; MOUSE_BUF_SIZE];
static MOUSE_HEAD: AtomicUsize = AtomicUsize::new(0);
static MOUSE_TAIL: AtomicUsize = AtomicUsize::new(0);
static MOUSE_DROPPED: AtomicUsize = AtomicUsize::new(0);
/// The size of the mouse's packets: 3, 4 with a wheel (IntelliMouse), 0
/// without a mouse.
static MOUSE_PACKET: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The size of the mouse's packets: 3 bytes, 4 with a wheel; `None` without
/// a mouse on the 8042's auxiliary port.
///
/// # IRQL
/// Any level.
pub fn mouse_packet_size() -> Option<usize> {
    match MOUSE_PACKET.load(Ordering::Acquire) {
        0 => None,
        size => Some(usize::from(size)),
    }
}

/// How many mouse bytes the IRQ12 ISR could not keep (the ring full): the
/// decoder resynchronises on the next packet.
///
/// # IRQL
/// Any level.
pub fn mouse_dropped() -> usize {
    MOUSE_DROPPED.load(Ordering::Relaxed)
}

/// Called from the IRQ12 ISR: a byte of the mouse into its ring, then the
/// hook of [`set_notify`] (the raw input thread reads both rings).
/// No heap, no locks, ISR-safe.
pub fn isr_push_mouse(byte: u8) {
    let head = MOUSE_HEAD.load(Ordering::Relaxed);
    let next = (head + 1) % MOUSE_BUF_SIZE;
    if next == MOUSE_TAIL.load(Ordering::Acquire) {
        MOUSE_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    MOUSE_BUF[head].store(byte, Ordering::Relaxed);
    MOUSE_HEAD.store(next, Ordering::Release);
    let hook = NOTIFY.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `set_notify` stores here, the address of a `fn()`.
        let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(hook) };
        hook();
    }
}

/// The next byte of the mouse, if its ring holds one.
///
/// # IRQL
/// Any level (one reader: the raw input thread).
pub fn pop_mouse() -> Option<u8> {
    let tail = MOUSE_TAIL.load(Ordering::Relaxed);
    if tail == MOUSE_HEAD.load(Ordering::Acquire) {
        return None;
    }
    let byte = MOUSE_BUF[tail].load(Ordering::Relaxed);
    MOUSE_TAIL.store((tail + 1) % MOUSE_BUF_SIZE, Ordering::Release);
    Some(byte)
}

/// Pop the next scancode from the ring buffer. Returns None if empty.
/// Called from the message queue at PASSIVE_LEVEL.
pub fn pop_scancode() -> Option<u8> {
    let tail = KEY_TAIL.load(Ordering::Relaxed);
    let head = KEY_HEAD.load(Ordering::Acquire);
    if tail == head {
        return None;
    }
    let sc = KEY_BUF[tail].load(Ordering::Relaxed);
    KEY_TAIL.store((tail + 1) % KEY_BUF_SIZE, Ordering::Release);
    Some(sc)
}

/// Convert a scancode set 1 make code to (virtual_key, ascii).
/// Returns None for key-release (bit 7 set) or unmapped keys.
pub fn scancode_to_key(sc: u8) -> Option<(u32, u8)> {
    if sc & 0x80 != 0 {
        return None;
    } // key release
    let ascii = scancode_to_ascii(sc)?;
    // Map to VK_* codes used by Win32 WM_KEYDOWN
    let vk = match ascii {
        b'\n' => 0x0D,                               // VK_RETURN
        0x08 => 0x08,                                // VK_BACK
        0x1B => 0x1B,                                // VK_ESCAPE
        b'\t' => 0x09,                               // VK_TAB
        b' ' => 0x20,                                // VK_SPACE
        b'a'..=b'z' => 0x41 + (ascii - b'a') as u32, // VK_A..VK_Z
        b'0'..=b'9' => 0x30 + (ascii - b'0') as u32, // VK_0..VK_9
        _ => ascii as u32,
    };
    Some((vk, ascii))
}

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
        let mut data = Port::<u8>::new(PS2_DATA);
        // Drain up to 16 stale bytes left by UEFI firmware.
        for _ in 0..16 {
            if status.read() & 0x01 == 0 {
                break;
            }
            let _ = data.read();
        }
    }
    log::trace!("HAL PS/2: controller flushed (polled, scancode set 1)");
}

/// Attend que l'entrée du contrôleur (port 0x64 bit 1) soit vide avant une
/// écriture de commande ou de donnée. Borné : le contrôleur est émulé ou
/// présent, il répond.
fn wait_input_clear() {
    // SAFETY: port 0x64 status reads are always safe at CPL 0.
    for _ in 0..100_000 {
        if unsafe { Port::<u8>::new(PS2_STATUS).read() } & 2 == 0 {
            return;
        }
    }
}

/// Initialisation du contrôleur 8042 pour le clavier et la souris : vide la
/// sortie, active le port auxiliaire (0xA8), écrit l'octet de configuration
/// (horloges du clavier et de la souris rétablies, interruptions sur tampon
/// de sortie plein des deux ports — IRQ1, IRQ12 —, la traduction vers le jeu
/// 1 préservée), réactive le port du clavier et lui demande d'émettre ses
/// codes (scan enable). La souris elle-même se règle ensuite
/// ([`controller_enable_mouse`]).
///
/// L'octet de configuration se lit ici seulement, la sortie vidée juste
/// avant : relu plus tard, l'accusé du clavier (0xFA) pourrait passer pour
/// lui, et l'écrire couperait le clavier.
///
/// Sans cette séquence, les émulateurs stricts (VirtualBox) et le matériel
/// réel n'émettent ni codes ni IRQ1 — QEMU tolère l'oubli.
///
/// # Safety
/// Must be called with interrupts disabled (the IRQ1 handler would race the
/// controller setup), at CPL 0.
pub unsafe fn controller_enable_keyboard() {
    // SAFETY: interrupts disabled (the caller's contract); every access is
    // a port read/write of the i8042 controller, always safe at CPL 0.
    unsafe {
        let mut status = Port::<u8>::new(PS2_STATUS);
        let mut data = Port::<u8>::new(PS2_DATA);
        let mut command = Port::<u8>::new(PS2_COMMAND);
        // Vide la sortie (les codes en attente partent).
        for _ in 0..16 {
            if status.read() & 1 == 0 {
                break;
            }
            let _ = data.read();
        }
        // Active le port de la souris (0xA8), puis lit l'octet de
        // configuration (0x20 → sortie) et le réécrit (0x60) : horloges du
        // clavier et de la souris rétablies (bits 4 et 5 à 0), interruptions
        // sur le tampon de sortie du clavier et de la souris (bits 0 et 1 à
        // 1). Le bit 6 (traduction vers le jeu 1) est préservé.
        command.write(0xA8);
        wait_input_clear();
        command.write(0x20);
        let mut config = data.read();
        config &= !((1 << 4) | (1 << 5));
        config |= 1 | (1 << 1);
        wait_input_clear();
        command.write(0x60);
        wait_input_clear();
        data.write(config);
        // Réactive le port du clavier (0xAE), puis lui demande d'émettre ses
        // codes (0xF4). L'accusé 0xFA du clavier arrive par IRQ1 : le ring du
        // pilote le jette.
        wait_input_clear();
        command.write(0xAE);
        wait_input_clear();
        data.write(0xF4);
    }
}

/// The next byte of the controller's output, when it comes within a bound:
/// the byte and whether it is the mouse's (status bit 5). A keyboard byte
/// met while the mouse is set up goes to the keyboard's ring.
fn read_output() -> Option<(u8, bool)> {
    for _ in 0..200_000 {
        // SAFETY: reading the 8042's status and data ports, at CPL 0.
        let status = unsafe { Port::<u8>::new(PS2_STATUS).read() };
        if status & 1 != 0 {
            // SAFETY: as above; the output buffer is full.
            let byte = unsafe { Port::<u8>::new(PS2_DATA).read() };
            return Some((byte, status & 0x20 != 0));
        }
    }
    None
}

/// The mouse's next byte: a keyboard byte on the way goes to its ring.
fn read_mouse_byte() -> Option<u8> {
    for _ in 0..8 {
        let (byte, from_mouse) = read_output()?;
        if from_mouse {
            return Some(byte);
        }
        isr_push_scancode(byte);
    }
    None
}

/// Sends `byte` to the mouse (through the 8042's 0xD4) and reads its
/// acknowledgement: `true` for 0xFA.
fn mouse_command(byte: u8) -> bool {
    wait_input_clear();
    // SAFETY: an 8042 command, then its data byte, at CPL 0.
    unsafe { Port::<u8>::new(PS2_COMMAND).write(0xD4) };
    wait_input_clear();
    // SAFETY: as above.
    unsafe { Port::<u8>::new(PS2_DATA).write(byte) };
    read_mouse_byte() == Some(0xFA)
}

/// Initialisation de la souris du port auxiliaire du 8042 (i8042prt,
/// `mouse.c`, comme spécification), le port déjà activé et son interruption
/// (IRQ12) ouverte par [`controller_enable_keyboard`] : la souris remise à
/// ses réglages (0xF6) ; la molette demandée par la séquence d'IntelliMouse
/// (cadences 200, 100, 80, puis l'identifiant : 3 avec une molette, les
/// paquets ont alors 4 octets) ; enfin l'émission des mouvements (0xF4).
/// Rend la taille des paquets, `None` sans souris.
///
/// # Safety
/// Interrupts disabled (IRQ1 and IRQ12 would race the setup), at CPL 0,
/// after [`controller_enable_keyboard`].
pub unsafe fn controller_enable_mouse() -> Option<usize> {
    if !mouse_command(0xF6) {
        return None;
    }
    let wheel = [200, 100, 80].iter().all(|&rate| mouse_command(0xF3) && mouse_command(rate))
        && mouse_command(0xF2)
        && read_mouse_byte() == Some(3);
    // The default rate again, then the mouse reports.
    let _ = mouse_command(0xF3) && mouse_command(100);
    if !mouse_command(0xF4) {
        return None;
    }
    let size = if wheel { 4 } else { 3 };
    MOUSE_PACKET.store(size, Ordering::Release);
    Some(usize::from(size))
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
    t[0x02] = b'1';
    t[0x03] = b'2';
    t[0x04] = b'3';
    t[0x05] = b'4';
    t[0x06] = b'5';
    t[0x07] = b'6';
    t[0x08] = b'7';
    t[0x09] = b'8';
    t[0x0A] = b'9';
    t[0x0B] = b'0';
    t[0x0C] = b'-';
    t[0x0D] = b'=';
    t[0x0E] = 0x08; // Backspace
    t[0x0F] = b'\t';

    // QWERTY row
    t[0x10] = b'q';
    t[0x11] = b'w';
    t[0x12] = b'e';
    t[0x13] = b'r';
    t[0x14] = b't';
    t[0x15] = b'y';
    t[0x16] = b'u';
    t[0x17] = b'i';
    t[0x18] = b'o';
    t[0x19] = b'p';
    t[0x1A] = b'[';
    t[0x1B] = b']';
    t[0x1C] = b'\n'; // Enter

    // ASDF row (0x1D = left Ctrl — skip)
    t[0x1E] = b'a';
    t[0x1F] = b's';
    t[0x20] = b'd';
    t[0x21] = b'f';
    t[0x22] = b'g';
    t[0x23] = b'h';
    t[0x24] = b'j';
    t[0x25] = b'k';
    t[0x26] = b'l';
    t[0x27] = b';';
    t[0x28] = b'\'';
    t[0x29] = b'`';

    // ZXCV row (0x2A = left Shift — skip, 0x2B = \)
    t[0x2B] = b'\\';
    t[0x2C] = b'z';
    t[0x2D] = b'x';
    t[0x2E] = b'c';
    t[0x2F] = b'v';
    t[0x30] = b'b';
    t[0x31] = b'n';
    t[0x32] = b'm';
    t[0x33] = b',';
    t[0x34] = b'.';
    t[0x35] = b'/';

    // Space
    t[0x39] = b' ';

    // Keypad (numlock on): map digits and operators
    t[0x47] = b'7';
    t[0x48] = b'8';
    t[0x49] = b'9';
    t[0x4A] = b'-';
    t[0x4B] = b'4';
    t[0x4C] = b'5';
    t[0x4D] = b'6';
    t[0x4E] = b'+';
    t[0x4F] = b'1';
    t[0x50] = b'2';
    t[0x51] = b'3';
    t[0x52] = b'0';
    t[0x53] = b'.';
    // Keypad Enter (0x1C extended — handled in main table) and / are extended.

    t
};

/// Public wrapper for the launcher's `read_key()`.
pub fn scancode_to_ascii_pub(sc: u8) -> Option<u8> {
    if sc & 0x80 != 0 {
        return None;
    } // key release
    scancode_to_ascii(sc)
}

fn scancode_to_ascii(sc: u8) -> Option<u8> {
    let idx = sc as usize;
    if idx >= SC1_TO_ASCII.len() {
        return None;
    }
    let c = SC1_TO_ASCII[idx];
    if c == 0 {
        None
    } else {
        Some(c)
    }
}
