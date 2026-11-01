//! L'alimentation : redémarrer la machine.

use x86_64::instructions::port::Port;

/// Les lectures de l'état du contrôleur qu'on attend au plus.
const SPINS: u32 = 10_000_000;

/// Redémarre la machine par le contrôleur du clavier (impulsion sur la ligne
/// RESET) ; sous QEMU avec `-no-reboot`, QEMU s'arrête.
///
/// # IRQL
/// Tout niveau ; ne revient pas.
pub fn reset() -> ! {
    // SAFETY: the keyboard controller's command port; pulsing the reset line
    // is the intent, nothing runs after it.
    unsafe {
        let mut status = Port::<u8>::new(0x64);
        for _ in 0..SPINS {
            if status.read() & 0x02 == 0 {
                break;
            }
        }
        Port::<u8>::new(0x64).write(0xFE);
    }
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}
