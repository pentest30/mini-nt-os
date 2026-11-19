//! L'alimentation : redémarrer la machine, l'arrêter, l'éteindre (ACPI,
//! [`crate::acpi`]).

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
    halt()
}

/// SLP_EN, le bit de PM1x_CNT qui fait entrer la machine dans l'état de
/// veille de SLP_TYP (bits 10 à 12).
const SLEEP_ENABLE: u16 = 1 << 13;
/// SLP_TYP dans PM1x_CNT.
const SLEEP_TYPE_SHIFT: u16 = 10;
const SLEEP_TYPE_MASK: u16 = 0b111 << SLEEP_TYPE_SHIFT;
/// SCI_EN : la machine est en mode ACPI.
const SCI_ENABLE: u16 = 1;

/// Éteint la machine (S5, HalPowerDownRoutine) par ce qu'a trouvé
/// [`crate::acpi::init`] : en mode ACPI (ACPI_ENABLE écrit dans SMI_CMD, si
/// SCI_EN n'y est pas), SLP_TYP de `\_S5_` et SLP_EN dans PM1a_CNT et
/// PM1b_CNT ; sous QEMU, QEMU s'arrête. Sans ACPI, ou si la machine reste
/// allumée, le processeur s'arrête ([`halt`]).
///
/// # IRQL
/// Tout niveau ; ne revient pas.
pub fn power_off() -> ! {
    x86_64::instructions::interrupts::disable();
    if let Some(off) = crate::acpi::soft_off() {
        // SAFETY: the ports of the FADT, whose checksum was verified; going
        // to S5 is the intent, nothing runs after it.
        unsafe {
            let mut pm1a = Port::<u16>::new(off.pm1a_control);
            if pm1a.read() & SCI_ENABLE == 0 && off.smi_command != 0 && off.acpi_enable != 0 {
                Port::<u8>::new(off.smi_command).write(off.acpi_enable);
                for _ in 0..SPINS {
                    if pm1a.read() & SCI_ENABLE != 0 {
                        break;
                    }
                }
            }
            let sleep = |control: u16, sleep_type: u16| {
                let mut port = Port::<u16>::new(control);
                let kept = port.read() & !(SLEEP_TYPE_MASK | SLEEP_ENABLE);
                port.write(kept | ((sleep_type << SLEEP_TYPE_SHIFT) & SLEEP_TYPE_MASK) | SLEEP_ENABLE);
            };
            sleep(off.pm1a_control, off.sleep_type_a);
            if off.pm1b_control != 0 {
                sleep(off.pm1b_control, off.sleep_type_b);
            }
        }
        for _ in 0..SPINS {
            core::hint::spin_loop();
        }
    }
    halt()
}

/// Arrête le processeur pour de bon (HalHaltSystem) : interruptions
/// masquées, `hlt` ; la machine reste sous tension, ce qu'on écrit est déjà
/// sur le disque.
///
/// # IRQL
/// Tout niveau ; ne revient pas.
pub fn halt() -> ! {
    loop {
        x86_64::instructions::interrupts::disable();
        x86_64::instructions::hlt();
    }
}
