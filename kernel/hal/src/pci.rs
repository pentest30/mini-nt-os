//! L'espace de configuration PCI, par le mécanisme n° 1 : l'adresse d'un
//! registre de 32 bits au port 0xCF8, sa valeur au port 0xCFC. Assez pour
//! trouver une fonction par son fabricant et son modèle, et lire ses barres
//! d'adresse (BAR). Pas encore : l'écriture, PCIe (ECAM), les interruptions.
//!
//! # IRQL
//! Les deux ports forment une paire : un seul appelant à la fois. Le noyau
//! ne s'en sert qu'au démarrage, à PASSIVE_LEVEL, avant les autres
//! processeurs.

/// Une fonction PCI : bus, périphérique (0 à 31), fonction (0 à 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// Le fabricant d'un emplacement vide : tous les bits à 1.
const NO_VENDOR: u16 = 0xFFFF;
/// Le registre de l'en-tête qui porte le type d'en-tête (octet 0x0E), dont
/// le bit 7 dit la fonction multiple.
const HEADER_TYPE: u8 = 0x0C;
/// La première barre d'adresse d'un en-tête de type 0.
const BAR0: u8 = 0x10;

/// L'adresse de configuration (port 0xCF8) d'un registre de 32 bits.
pub fn config_address(f: Function, offset: u8) -> u32 {
    0x8000_0000
        | u32::from(f.bus) << 16
        | u32::from(f.device & 0x1F) << 11
        | u32::from(f.function & 0x07) << 8
        | u32::from(offset & 0xFC)
}

/// Le registre de 32 bits en `offset` de l'espace de configuration de `f` ;
/// `0xFFFF_FFFF` pour une fonction absente (et toujours sur l'hôte).
///
/// # IRQL
/// Voir le module.
pub fn read32(f: Function, offset: u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        use x86_64::instructions::port::Port;
        // SAFETY: les ports 0xCF8 et 0xCFC du mécanisme n° 1 ; écrire une
        // adresse de configuration puis lire la donnée n'a d'effet sur aucun
        // périphérique. Un seul appelant à la fois (voir le module).
        unsafe {
            Port::<u32>::new(0xCF8).write(config_address(f, offset));
            Port::<u32>::new(0xCFC).read()
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (f, offset);
        u32::MAX
    }
}

/// La première fonction de fabricant `vendor` et de modèle `device`, en
/// parcourant les 256 bus.
///
/// # IRQL
/// Voir le module.
pub fn find(vendor: u16, device: u16) -> Option<Function> {
    find_in(read32, vendor, device)
}

/// [`find`], sur un espace de configuration lu par `read`.
fn find_in(read: impl Fn(Function, u8) -> u32, vendor: u16, device: u16) -> Option<Function> {
    for bus in 0..=255u8 {
        for slot in 0..32u8 {
            let first = Function { bus, device: slot, function: 0 };
            let id = read(first, 0);
            if id as u16 == NO_VENDOR {
                continue;
            }
            let functions = if read(first, HEADER_TYPE) & 0x0080_0000 != 0 { 8 } else { 1 };
            for function in 0..functions {
                let f = Function { bus, device: slot, function };
                let id = if function == 0 { id } else { read(f, 0) };
                if id as u16 == vendor && (id >> 16) as u16 == device {
                    return Some(f);
                }
            }
        }
    }
    None
}

/// Le port de base de la barre `index` (0 à 5) de `f`, si c'est une barre
/// d'entrées-sorties.
///
/// # IRQL
/// Voir le module.
pub fn io_bar(f: Function, index: u8) -> Option<u16> {
    io_port_of(read32(f, BAR0 + 4 * index))
}

/// Le port d'une barre d'entrées-sorties (bit 0 à 1), ou `None` pour une
/// barre de mémoire.
fn io_port_of(bar: u32) -> Option<u16> {
    (bar & 1 == 1).then_some((bar & 0xFFFC) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_register_address_has_the_enable_bit_and_a_dword_offset() {
        let f = Function { bus: 0, device: 4, function: 0 };
        assert_eq!(config_address(f, 0x10), 0x8000_2010);
        assert_eq!(config_address(Function { bus: 1, device: 31, function: 7 }, 0x3E), 0x8001_FF3C);
    }

    #[test]
    fn the_scan_finds_a_function_and_skips_empty_slots() {
        // VirtualBox : VMMDev en 00:04.0 ; une fonction multiple en 00:01.
        let space = |f: Function, offset: u8| match (f.bus, f.device, f.function, offset) {
            (0, 0, 0, 0) => 0x1237_8086,
            (0, 1, 0, 0) => 0x7000_8086,
            (0, 1, 0, HEADER_TYPE) => 0x0080_0000,
            (0, 1, 1, 0) => 0x7111_8086,
            (0, 4, 0, 0) => 0xCAFE_80EE,
            _ => u32::MAX,
        };
        assert_eq!(find_in(space, 0x80EE, 0xCAFE), Some(Function { bus: 0, device: 4, function: 0 }));
        assert_eq!(find_in(space, 0x8086, 0x7111), Some(Function { bus: 0, device: 1, function: 1 }));
        assert_eq!(find_in(space, 0x1234, 0x1111), None);
    }

    #[test]
    fn only_an_io_bar_gives_a_port() {
        assert_eq!(io_port_of(0xD021), Some(0xD020));
        assert_eq!(io_port_of(0xF040_0000), None);
    }
}
