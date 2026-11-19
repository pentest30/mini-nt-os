//! L'ACPI, pour éteindre la machine (l'état S5, « soft off ») : de la RSDP
//! que donne le chargeur, la RSDT ou la XSDT, puis la FADT (signature
//! `FACP` : PM1a_CNT_BLK, PM1b_CNT_BLK, SMI_CMD, ACPI_ENABLE, la DSDT), et
//! dans le code AML de la DSDT l'objet `\_S5_`, un paquet dont les deux
//! premiers éléments sont SLP_TYPa et SLP_TYPb (spécification ACPI, 7.4.2 et
//! 4.8.3.2.1). Éteindre, c'est écrire SLP_TYP et SLP_EN dans PM1a_CNT (et
//! PM1b_CNT s'il y en a un) : [`crate::power::power_off`].
//!
//! Pas d'interpréteur AML : `\_S5_` doit être un nom défini par un paquet
//! de constantes (`Name (_S5, Package () {…})`), comme sous QEMU et
//! VirtualBox ; sinon la machine s'arrête sans s'éteindre. Toutes les tables
//! lues sont vérifiées (signature, longueur, somme de contrôle).
//!
//! Pas encore : le reste de l'ACPI (SCI, GPE, MADT, les autres états de
//! veille).

use core::sync::atomic::Ordering;

use crate::sync::Once;

/// Ce qu'il faut pour éteindre la machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoftOff {
    /// Le port de PM1a_CNT.
    pub pm1a_control: u16,
    /// Le port de PM1b_CNT ; 0 sans lui.
    pub pm1b_control: u16,
    /// SLP_TYPa et SLP_TYPb de `\_S5_`.
    pub sleep_type_a: u16,
    pub sleep_type_b: u16,
    /// Le port de SMI_CMD, où écrire ACPI_ENABLE pour passer en mode ACPI ;
    /// 0 sans lui (la machine y est déjà).
    pub smi_command: u16,
    pub acpi_enable: u8,
}

/// De la mémoire physique, lue par adresse.
pub trait Physical {
    /// Les `length` octets à l'adresse physique `address`, s'ils sont lisibles.
    fn bytes(&self, address: u64, length: usize) -> Option<&[u8]>;
}

/// La mémoire physique par le HHDM, qui projette [0, 4 Gio).
struct Hhdm;

impl Physical for Hhdm {
    fn bytes(&self, address: u64, length: usize) -> Option<&[u8]> {
        let end = address.checked_add(length as u64)?;
        let offset = crate::HHDM_OFFSET.load(Ordering::Acquire);
        if address == 0 || end > crate::HHDM_SIZE || offset == 0 {
            return None;
        }
        // SAFETY: the HHDM maps [0, 4 GiB) for good (checked above), and the
        // ACPI tables are only read.
        Some(unsafe { core::slice::from_raw_parts((offset + address) as *const u8, length) })
    }
}

/// Ce que [`init`] a trouvé.
static SOFT_OFF: Once<Option<SoftOff>> = Once::new();

/// Lit les tables de la RSDP `rsdp` (une adresse physique, 0 sans elle) et
/// garde ce qu'il faut pour éteindre la machine ; rend ce qu'il a trouvé.
///
/// # IRQL
/// PASSIVE_LEVEL, une fois, au démarrage, le HHDM en place.
pub fn init(rsdp: u64) -> Option<SoftOff> {
    *SOFT_OFF.call_once(|| find_soft_off(&Hhdm, rsdp))
}

/// Ce que [`init`] a trouvé ; `None` avant lui, ou sans `\_S5_`.
///
/// # IRQL
/// Tout niveau.
pub fn soft_off() -> Option<SoftOff> {
    SOFT_OFF.get().copied().flatten()
}

/// La taille de l'en-tête d'une table (System Description Table Header).
const HEADER: usize = 36;

/// Ce qu'il faut pour éteindre la machine d'après les tables de la RSDP à
/// `rsdp` ; `None` s'il manque une table, si l'une est abîmée, ou sans
/// `\_S5_`.
pub fn find_soft_off(memory: &impl Physical, rsdp: u64) -> Option<SoftOff> {
    let fadt = find_table(memory, rsdp, b"FACP")?;
    let word = |at: usize| fadt.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let pm1a_control = u16::try_from(word(64)?).ok().filter(|&port| port != 0)?;
    let pm1b_control = u16::try_from(word(68)?).unwrap_or(0);
    // X_DSDT (ACPI 2.0, 64 bits), when the FADT has it, else DSDT.
    let x_dsdt = fadt.get(140..148).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));
    let dsdt = x_dsdt.filter(|&address| address != 0).or(word(40).map(u64::from))?;
    let dsdt = table(memory, dsdt, b"DSDT")?;
    let (sleep_type_a, sleep_type_b) = s5(&dsdt[HEADER..])?;
    Some(SoftOff {
        pm1a_control,
        pm1b_control,
        sleep_type_a: u16::from(sleep_type_a),
        sleep_type_b: u16::from(sleep_type_b),
        smi_command: u16::try_from(word(48)?).unwrap_or(0),
        acpi_enable: *fadt.get(52)?,
    })
}

/// La somme des octets de `bytes` est nulle.
fn sums_to_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte)) == 0
}

/// La table à `address`, de signature `signature`, entière et vérifiée.
fn table<'a>(memory: &'a impl Physical, address: u64, signature: &[u8; 4]) -> Option<&'a [u8]> {
    let header = memory.bytes(address, HEADER)?;
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if &header[..4] != signature || length < HEADER {
        return None;
    }
    let whole = memory.bytes(address, length)?;
    sums_to_zero(whole).then_some(whole)
}

/// La table de signature `signature` que désigne la RSDT ou la XSDT de la
/// RSDP à `rsdp`.
fn find_table<'a>(memory: &'a impl Physical, rsdp: u64, signature: &[u8; 4]) -> Option<&'a [u8]> {
    let pointer = memory.bytes(rsdp, 20)?;
    if &pointer[..8] != b"RSD PTR " || !sums_to_zero(pointer) {
        return None;
    }
    // Revision 2 (ACPI 2.0): the XSDT, 64-bit entries, when there is one.
    if pointer[15] >= 2 {
        let extended = memory.bytes(rsdp, 36)?;
        let xsdt = u64::from_le_bytes(extended[24..32].try_into().ok()?);
        if sums_to_zero(extended) && xsdt != 0 {
            if let Some(found) = find_in(memory, table(memory, xsdt, b"XSDT"), 8, signature) {
                return Some(found);
            }
        }
    }
    let rsdt = u32::from_le_bytes(pointer[16..20].try_into().ok()?);
    find_in(memory, table(memory, u64::from(rsdt), b"RSDT"), 4, signature)
}

/// La table de signature `signature` parmi les entrées de `root` (des
/// adresses de `width` octets après son en-tête).
fn find_in<'a>(memory: &'a impl Physical, root: Option<&[u8]>, width: usize, signature: &[u8; 4]) -> Option<&'a [u8]> {
    root?[HEADER..].chunks_exact(width).find_map(|entry| {
        let mut address = [0u8; 8];
        address[..width].copy_from_slice(entry);
        table(memory, u64::from_le_bytes(address), signature)
    })
}

/// NameOp, PackageOp, BytePrefix, ZeroOp, OneOp de l'AML.
const NAME_OP: u8 = 0x08;
const PACKAGE_OP: u8 = 0x12;
const BYTE_PREFIX: u8 = 0x0A;
const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;

/// SLP_TYPa et SLP_TYPb de `\_S5_` dans le code AML `aml` : un NameOp (le
/// nom avec ou sans `\`), un PackageOp, sa longueur (PkgLength, de 1 à 4
/// octets), son nombre d'éléments, puis deux constantes d'un octet (ZeroOp,
/// OneOp, BytePrefix et l'octet).
pub fn s5(aml: &[u8]) -> Option<(u8, u8)> {
    let mut from = 0;
    while let Some(found) = aml.get(from..)?.windows(4).position(|name| name == b"_S5_") {
        let at = from + found;
        from = at + 1;
        let named = (at >= 1 && aml[at - 1] == NAME_OP) || (at >= 2 && aml[at - 1] == b'\\' && aml[at - 2] == NAME_OP);
        if !named || aml.get(at + 4) != Some(&PACKAGE_OP) {
            continue;
        }
        // PkgLength: bits 6-7 of its first byte count the bytes after it.
        let length_bytes = 1 + usize::from(*aml.get(at + 5)? >> 6);
        let mut cursor = at + 5 + length_bytes + 1;
        let mut constant = || -> Option<u8> {
            let value = match *aml.get(cursor)? {
                BYTE_PREFIX => {
                    cursor += 1;
                    *aml.get(cursor)?
                }
                ZERO_OP => 0,
                ONE_OP => 1,
                _ => return None,
            };
            cursor += 1;
            Some(value)
        };
        return Some((constant()?, constant()?));
    }
    None
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Physical memory made of tables at given addresses.
    struct Tables(Vec<(u64, Vec<u8>)>);

    impl Physical for Tables {
        fn bytes(&self, address: u64, length: usize) -> Option<&[u8]> {
            self.0.iter().find_map(|(at, bytes)| {
                let start = usize::try_from(address.checked_sub(*at)?).ok()?;
                bytes.get(start..start + length)
            })
        }
    }

    /// Sets the byte at `at` so that `bytes` sums to zero.
    fn fix_checksum(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        bytes[at] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)));
    }

    /// A table: its header (signature, length, checksum), then `body`.
    fn sdt(signature: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut bytes = std::vec![0u8; HEADER];
        bytes[..4].copy_from_slice(signature);
        bytes.extend_from_slice(body);
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        fix_checksum(&mut bytes, 9);
        bytes
    }

    /// What QEMU's DSDT (PIIX4) says of S5: `Name (\_S5, Package (0x04) {Zero, Zero, Zero, Zero})`.
    const QEMU_S5: &[u8] = &[NAME_OP, b'\\', b'_', b'S', b'5', b'_', PACKAGE_OP, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00];

    /// RSDP (revision `revision`), RSDT and XSDT, FADT and DSDT, at fixed addresses.
    fn machine(revision: u8, aml: &[u8], x_dsdt: bool) -> Tables {
        let (rsdp, rsdt, xsdt, fadt, dsdt) =
            (0xE0000u64, 0x7FF0_0000u64, 0x7FF0_1000u64, 0x7FF0_2000u64, 0x7FF0_3000u64);
        let mut fadt_body = std::vec![0u8; 244 - HEADER];
        let field = |body: &mut Vec<u8>, at: usize, value: &[u8]| {
            body[at - HEADER..at - HEADER + value.len()].copy_from_slice(value)
        };
        field(&mut fadt_body, 40, &(if x_dsdt { 0 } else { dsdt as u32 }).to_le_bytes());
        field(&mut fadt_body, 48, &0xB2u32.to_le_bytes());
        field(&mut fadt_body, 52, &[0xF1]);
        field(&mut fadt_body, 64, &0x604u32.to_le_bytes());
        if x_dsdt {
            field(&mut fadt_body, 140, &dsdt.to_le_bytes());
        }
        let mut pointer = std::vec![0u8; 36];
        pointer[..8].copy_from_slice(b"RSD PTR ");
        pointer[15] = revision;
        pointer[16..20].copy_from_slice(&(rsdt as u32).to_le_bytes());
        pointer[20..24].copy_from_slice(&36u32.to_le_bytes());
        pointer[24..32].copy_from_slice(&xsdt.to_le_bytes());
        fix_checksum(&mut pointer[..20], 8);
        fix_checksum(&mut pointer, 32);
        let other = sdt(b"APIC", &[0; 8]);
        Tables(std::vec![
            (rsdp, pointer),
            (rsdt, sdt(b"RSDT", &[0x7FF0_4000u32.to_le_bytes(), (fadt as u32).to_le_bytes()].concat())),
            (xsdt, sdt(b"XSDT", &[0x7FF0_4000u64.to_le_bytes(), fadt.to_le_bytes()].concat())),
            (fadt, sdt(b"FACP", &fadt_body)),
            (dsdt, sdt(b"DSDT", &[&[0x10, 0x20][..], aml, &[0x5B, 0x80]].concat())),
            (0x7FF0_4000, other),
        ])
    }

    #[test]
    fn the_s5_package_of_qemu_and_virtualbox_is_found() {
        let expected = SoftOff {
            pm1a_control: 0x604,
            pm1b_control: 0,
            sleep_type_a: 0,
            sleep_type_b: 0,
            smi_command: 0xB2,
            acpi_enable: 0xF1,
        };
        assert_eq!(find_soft_off(&machine(0, QEMU_S5, false), 0xE0000), Some(expected), "ACPI 1.0: the RSDT");
        assert_eq!(find_soft_off(&machine(2, QEMU_S5, true), 0xE0000), Some(expected), "ACPI 2.0: the XSDT, X_DSDT");
        // VirtualBox: `Name (_S5, Package (0x02) {0x05, 0x05})`, BytePrefix.
        let vbox = [NAME_OP, b'_', b'S', b'5', b'_', PACKAGE_OP, 0x07, 0x02, BYTE_PREFIX, 0x05, BYTE_PREFIX, 0x05];
        let found = find_soft_off(&machine(2, &vbox, false), 0xE0000).unwrap();
        assert_eq!((found.sleep_type_a, found.sleep_type_b), (5, 5));
        // A PkgLength of two bytes.
        let long = [NAME_OP, b'_', b'S', b'5', b'_', PACKAGE_OP, 0x47, 0x01, 0x02, ONE_OP, ZERO_OP];
        assert_eq!(s5(&long), Some((1, 0)));
    }

    #[test]
    fn what_cannot_power_off_is_none() {
        assert_eq!(find_soft_off(&machine(0, b"no sleep state", false), 0xE0000), None, "no \\_S5_");
        // `_S5_` used, not defined, before its definition: the definition counts.
        let used_first = [&b"\x70_S5_"[..], QEMU_S5].concat();
        assert_eq!(s5(&used_first), Some((0, 0)));
        // A computed _S5 (a method): not understood.
        assert_eq!(s5(&[0x14, 0x08, b'_', b'S', b'5', b'_', 0x00, 0xA4]), None);
        let mut broken = machine(0, QEMU_S5, false);
        broken.0[3].1[30] ^= 1;
        assert_eq!(find_soft_off(&broken, 0xE0000), None, "a FADT with a wrong checksum");
        assert_eq!(find_soft_off(&machine(0, QEMU_S5, false), 0xE0010), None, "no RSDP there");
        assert_eq!(find_soft_off(&machine(0, QEMU_S5, false), 0), None);
    }
}
