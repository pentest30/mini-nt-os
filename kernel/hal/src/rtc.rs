//! L'horloge temps réel (RTC du CMOS) : l'heure du démarrage
//! (HalQueryRealTimeClock, KeBootTime).
//!
//! Lue une fois, au démarrage : secondes, minutes, heures, jour, mois,
//! année et siècle (le registre 0x32, celui que l'ACPI désigne d'habitude),
//! en BCD ou en binaire, sur 12 ou 24 heures selon le registre d'état B, et
//! relue tant qu'une mise à jour de l'horloge la traverse. Le temps système
//! est alors cette heure plus le temps d'interruption ([`system_time`]), en
//! unités de 100 ns depuis le 1er janvier 1601, comme NT.
//!
//! Le RTC est lu comme UTC (QEMU le règle ainsi par défaut) : le biais du
//! fuseau horaire, qu'XP tire du registre, est encore nul.
//!
//! Pas encore : NtSetSystemTime (écrire le RTC), le fuseau horaire.

use core::sync::atomic::{AtomicU64, Ordering};

/// Le temps système au démarrage du timer (temps d'interruption 0).
static BOOT_TIME: AtomicU64 = AtomicU64::new(0);

/// Une date et une heure du calendrier grégorien.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// Registre d'état B : les valeurs sont en binaire (sinon en BCD).
const STATUS_B_BINARY: u8 = 0x04;
/// Registre d'état B : les heures vont de 0 à 23 (sinon de 1 à 12, le bit 7
/// de l'heure marquant l'après-midi).
const STATUS_B_24_HOUR: u8 = 0x02;

/// La date que donnent les registres du RTC `[secondes, minutes, heures,
/// jour, mois, année, siècle]`, selon le registre d'état B ; `None` pour une
/// date impossible. Un siècle hors de 19 à 21 (un RTC sans ce registre)
/// vaut 20.
pub fn decode(registers: [u8; 7], status_b: u8) -> Option<DateTime> {
    let value = |byte: u8| {
        if status_b & STATUS_B_BINARY != 0 {
            byte
        } else {
            (byte >> 4) * 10 + (byte & 0x0F)
        }
    };
    let [second, minute, hour, day, month, year, century] = registers;
    let hour = if status_b & STATUS_B_24_HOUR != 0 {
        value(hour)
    } else {
        // 12 AM is 0, 12 PM is 12.
        let pm = hour & 0x80 != 0;
        value(hour & 0x7F) % 12 + if pm { 12 } else { 0 }
    };
    let century = match value(century) {
        century @ 19..=21 => u16::from(century),
        _ => 20,
    };
    let date = DateTime {
        year: century * 100 + u16::from(value(year)),
        month: value(month),
        day: value(day),
        hour,
        minute: value(minute),
        second: value(second),
    };
    nt_time(date).map(|_| date)
}

/// `date` en temps NT : unités de 100 ns depuis le 1er janvier 1601 ;
/// `None` pour une date impossible ou avant 1601.
pub fn nt_time(date: DateTime) -> Option<u64> {
    let DateTime { year, month, day, hour, minute, second } = date;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if year < 1601 || day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days from 1601-01-01, the start of a 400-year cycle: whole years, then
    // the days of the months before, then the day.
    let years = u64::from(year - 1601);
    let mut days = years * 365 + years / 4 - years / 100 + years / 400;
    const BEFORE: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += BEFORE[usize::from(month - 1)] + u64::from(day - 1);
    if leap && month > 2 {
        days += 1;
    }
    let seconds = days * 86_400 + u64::from(hour) * 3600 + u64::from(minute) * 60 + u64::from(second);
    Some(seconds * 10_000_000)
}

/// Lit le registre `register` du CMOS, l'NMI laissée active.
///
/// # Safety
/// Rien d'autre n'accède au CMOS en même temps (démarrage, interruptions
/// masquées).
unsafe fn cmos(register: u8) -> u8 {
    use x86_64::instructions::port::Port;
    // SAFETY: ports 0x70 and 0x71 select and read a CMOS register; nothing
    // else uses them now (the caller's contract).
    unsafe {
        Port::<u8>::new(0x70).write(register & 0x7F);
        Port::<u8>::new(0x71).read()
    }
}

/// Lit le RTC et retient l'heure du démarrage ; `None` si sa date est
/// impossible (le temps système part alors de 1601).
///
/// # Safety
/// Une fois, au démarrage, interruptions masquées, avant que le timer ne
/// compte le temps d'interruption.
pub unsafe fn init() -> Option<DateTime> {
    // SAFETY: the caller's contract: nothing else touches the CMOS.
    let read = || unsafe {
        // Wait for no update in progress (status A, bit 7), boundedly.
        for _ in 0..100_000 {
            if cmos(0x0A) & 0x80 == 0 {
                break;
            }
        }
        [cmos(0x00), cmos(0x02), cmos(0x04), cmos(0x07), cmos(0x08), cmos(0x09), cmos(0x32)]
    };
    // An update between two reads changes them: read until two agree.
    let mut registers = read();
    for _ in 0..8 {
        let again = read();
        if again == registers {
            break;
        }
        registers = again;
    }
    // SAFETY: as above.
    let status_b = unsafe { cmos(0x0B) };
    let date = decode(registers, status_b)?;
    BOOT_TIME.store(nt_time(date)?, Ordering::Release);
    Some(date)
}

/// KeBootTime : le temps système au démarrage du timer, en 100 ns depuis
/// 1601.
///
/// # IRQL
/// Tout niveau.
pub fn boot_time() -> u64 {
    BOOT_TIME.load(Ordering::Acquire)
}

/// KeQuerySystemTime : le temps système, en 100 ns depuis 1601 (UTC), à la
/// résolution du dernier tick.
///
/// # IRQL
/// Tout niveau.
pub fn system_time() -> u64 {
    boot_time() + crate::timer::interrupt_time()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> DateTime {
        DateTime { year, month, day, hour, minute, second }
    }

    #[test]
    fn dates_become_nt_times() {
        assert_eq!(nt_time(date(1601, 1, 1, 0, 0, 0)), Some(0));
        assert_eq!(nt_time(date(1970, 1, 1, 0, 0, 0)), Some(116_444_736_000_000_000), "the Unix epoch");
        assert_eq!(nt_time(date(2000, 1, 1, 0, 0, 0)), Some(125_911_584_000_000_000));
        assert_eq!(nt_time(date(2000, 3, 1, 0, 0, 0)), Some(125_963_424_000_000_000), "after 2000-02-29");
        assert_eq!(nt_time(date(2026, 11, 2, 12, 34, 56)), Some(134_380_964_960_000_000));
        assert_eq!(nt_time(date(1900, 2, 29, 0, 0, 0)), None, "1900 is not a leap year");
        assert!(nt_time(date(2000, 2, 29, 0, 0, 0)).is_some(), "2000 is");
        assert_eq!(nt_time(date(2026, 13, 1, 0, 0, 0)), None);
        assert_eq!(nt_time(date(2026, 4, 31, 0, 0, 0)), None);
        assert_eq!(nt_time(date(1600, 12, 31, 0, 0, 0)), None);
    }

    #[test]
    fn registers_in_bcd_or_binary_on_12_or_24_hours() {
        // 2026-11-02 12:34:56, BCD, 24 h.
        let bcd = [0x56, 0x34, 0x12, 0x02, 0x11, 0x26, 0x20];
        assert_eq!(decode(bcd, STATUS_B_24_HOUR), Some(date(2026, 11, 2, 12, 34, 56)));
        let binary = [56, 34, 12, 2, 11, 26, 20];
        assert_eq!(decode(binary, STATUS_B_24_HOUR | STATUS_B_BINARY), Some(date(2026, 11, 2, 12, 34, 56)));
        // 12 h: 12 AM is midnight, 12 PM noon, 1 PM 13.
        let hour = |byte: u8| decode([0, 0, byte, 2, 11, 0x26, 0x20], 0).map(|d| d.hour);
        assert_eq!((hour(0x12), hour(0x92), hour(0x81), hour(0x11)), (Some(0), Some(12), Some(13), Some(11)));
        assert_eq!(decode([0, 0, 0, 1, 1, 0x99, 0x19], STATUS_B_24_HOUR).map(|d| d.year), Some(1999));
        assert_eq!(decode([0, 0, 0, 1, 1, 0x26, 0x00], STATUS_B_24_HOUR).map(|d| d.year), Some(2026), "no century");
        assert_eq!(decode([0, 0, 0, 0x31, 0x02, 0x26, 0x20], STATUS_B_24_HOUR), None, "February 31st");
    }
}
