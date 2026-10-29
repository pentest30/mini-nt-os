//! Les symboles du noyau, pour l'écran d'erreur fatale : la table `.symtab` et
//! les noms `.strtab` de son ELF, que le chargeur lui transmet.
//!
//! Tout se lit sans verrou ni allocation, pour servir quand le système
//! s'arrête : [`lookup`] trouve la fonction qui contient une adresse, et
//! [`write_demangled`] rend son nom lisible.

pub mod demangle;

use core::fmt;

pub use demangle::write_demangled;

use crate::sync::Once;

/// Taille d'une entrée de `.symtab` (`Elf64_Sym`).
const SYM_SIZE: usize = 24;
/// Type de symbole (4 bits bas de `st_info`) d'une fonction.
const STT_FUNC: u8 = 2;

/// La table des symboles de l'ELF du noyau.
#[derive(Clone, Copy)]
pub struct SymbolTable {
    symtab: &'static [u8],
    strtab: &'static [u8],
}

impl SymbolTable {
    /// `symtab` : les entrées `Elf64_Sym` ; `strtab` : les noms qu'elles
    /// désignent.
    pub const fn new(symtab: &'static [u8], strtab: &'static [u8]) -> Self {
        Self { symtab, strtab }
    }

    /// Les fonctions (symboles `STT_FUNC`) : adresse, taille, nom.
    fn functions(&self) -> impl Iterator<Item = (u64, u64, u32)> + '_ {
        self.symtab.chunks_exact(SYM_SIZE).filter(|e| e[4] & 0xF == STT_FUNC).map(|e| {
            let field = |at: usize| u64::from_le_bytes(e[at..at + 8].try_into().unwrap_or_default());
            (field(8), field(16), u32::from_le_bytes(e[0..4].try_into().unwrap_or_default()))
        })
    }

    /// Nombre de fonctions de la table.
    pub fn function_count(&self) -> usize {
        self.functions().count()
    }

    /// La fonction qui contient `addr` : son nom (tel que dans l'ELF) et le
    /// décalage d'`addr` dans celle-ci.
    pub fn lookup(&self, addr: u64) -> Option<(&'static str, u64)> {
        let (start, _, name) = self.functions().find(|&(start, size, _)| addr >= start && addr - start < size)?;
        Some((self.name(name)?, addr - start))
    }

    /// Le nom au décalage `offset` de `.strtab`, terminé par un octet nul.
    fn name(&self, offset: u32) -> Option<&'static str> {
        let strtab: &'static [u8] = self.strtab;
        let rest = strtab.get(usize::try_from(offset).ok()?..)?;
        let len = rest.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&rest[..len]).ok()
    }
}

/// La table du noyau, une fois enregistrée.
static TABLE: Once<SymbolTable> = Once::new();

/// Enregistre la table des symboles du noyau.
///
/// # IRQL
/// Une fois, au démarrage.
pub fn init(table: SymbolTable) {
    TABLE.call_once(|| table);
}

/// La table enregistrée, s'il y en a une.
///
/// # IRQL
/// Tout niveau.
pub fn table() -> Option<&'static SymbolTable> {
    TABLE.get()
}

/// La fonction du noyau qui contient `addr` (voir [`SymbolTable::lookup`]),
/// si la table est enregistrée.
///
/// # IRQL
/// Tout niveau ; sans verrou ni allocation.
pub fn lookup(addr: u64) -> Option<(&'static str, u64)> {
    TABLE.get()?.lookup(addr)
}

/// Texte dans un tampon de taille fixe, pour démangler sans allouer ; ce qui
/// ne tient pas est perdu.
pub struct FixedBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> FixedBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Le texte écrit, tronqué à la capacité.
    pub fn as_str(&self) -> &str {
        // Seuls des `str` entiers ou coupés sur une frontière de caractère y
        // sont copiés.
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for FixedBuf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let mut take = s.len().min(room);
        while !s.is_char_boundary(take) {
            take -= 1;
        }
        self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::fmt::Write;
    use std::boxed::Box;
    use std::vec::Vec;

    /// Une entrée `Elf64_Sym`.
    fn sym(name: u32, info: u8, value: u64, size: u64) -> [u8; SYM_SIZE] {
        let mut e = [0u8; SYM_SIZE];
        e[0..4].copy_from_slice(&name.to_le_bytes());
        e[4] = info;
        e[8..16].copy_from_slice(&value.to_le_bytes());
        e[16..24].copy_from_slice(&size.to_le_bytes());
        e
    }

    fn table() -> SymbolTable {
        let strtab: &'static [u8] = b"\0first\0second\0data\0";
        let entries = [
            sym(0, 0, 0, 0), // entrée nulle de tête
            sym(1, 0x12, 0x1000, 0x40),
            sym(7, 0x12, 0x1040, 0x20),
            sym(14, 0x11, 0x1060, 0x100), // un objet, pas une fonction
            sym(99, 0x12, 0x2000, 0x10),  // nom hors de .strtab
        ];
        let symtab: Vec<u8> = entries.iter().flatten().copied().collect();
        SymbolTable::new(Box::leak(symtab.into_boxed_slice()), strtab)
    }

    #[test]
    fn lookup_finds_the_function_that_contains_the_address() {
        let t = table();
        assert_eq!(t.function_count(), 3);
        assert_eq!(t.lookup(0x1000), Some(("first", 0)));
        assert_eq!(t.lookup(0x103f), Some(("first", 0x3f)));
        assert_eq!(t.lookup(0x1040), Some(("second", 0)));
        assert_eq!(t.lookup(0x1070), None, "inside an object, not a function");
        assert_eq!(t.lookup(0x0fff), None);
        assert_eq!(t.lookup(0x2004), None, "name outside .strtab");
    }

    #[test]
    fn a_fixed_buffer_keeps_what_fits_on_a_character_boundary() {
        let mut storage = [0u8; 8];
        let mut buf = FixedBuf::new(&mut storage);
        write!(buf, "abc").unwrap();
        write!(buf, "dé€fgh").unwrap();
        assert_eq!(buf.as_str(), "abcdé", "the euro sign does not fit whole");
    }
}
