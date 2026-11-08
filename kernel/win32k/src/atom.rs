//! La table des atomes de USER (gAtomTable de ReactOS) : les noms des
//! classes de fenêtres. Ses règles sont celles de RtlAddAtomToAtomTable
//! (`sdk/lib/rtl/atom.c` de ReactOS, comme spécification) :
//!
//! - un atome entier (un nom de 16 bits, ou `#` suivi de chiffres en
//!   décimal) vaut lui-même, de 1 à `0xBFFF`, sans entrée dans la table ;
//! - un nom en chaîne (255 caractères au plus) reçoit un atome à partir de
//!   [`FIRST_STRING_ATOM`] ; le même nom, sans tenir compte de la casse,
//!   rend le même atome, dont le compte de références augmente ; l'atome
//!   disparaît à sa dernière suppression.

use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_INVALID};
use hal::sync::KSpinLock;

/// Le premier atome d'un nom en chaîne (MAXINTATOM).
pub const FIRST_STRING_ATOM: u16 = 0xC000;
/// La longueur maximale d'un nom, en caractères (RTL_MAXIMUM_ATOM_LENGTH).
pub const MAXIMUM_ATOM_LENGTH: usize = 255;

/// Un nom d'atome : un atome entier, passé tel quel (MAKEINTATOM), ou une
/// chaîne.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomName<'a> {
    Integer(u16),
    String(&'a [u16]),
}

impl AtomName<'_> {
    /// L'atome entier que désigne le nom, s'il en est un
    /// (RtlpCheckIntegerAtom) : le nombre lui-même, ou celui qui suit `#`
    /// (les 16 bits de poids faible ; `#` seul vaut 0).
    pub fn integer(&self) -> Option<u16> {
        match *self {
            AtomName::Integer(value) => Some(value),
            AtomName::String([b, digits @ ..])
                if *b == u16::from(b'#')
                    && digits.iter().all(|&c| (u16::from(b'0')..=u16::from(b'9')).contains(&c)) =>
            {
                let value =
                    digits.iter().fold(0u32, |n, &c| n.wrapping_mul(10).wrapping_add(u32::from(c - u16::from(b'0'))));
                Some(value as u16)
            }
            AtomName::String(_) => None,
        }
    }
}

/// Un caractère en majuscule, pour comparer les noms sans tenir compte de
/// la casse (un caractère qui n'a pas une seule majuscule reste lui-même).
fn upper(unit: u16) -> u16 {
    char::from_u32(u32::from(unit))
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) if (u as u32) <= 0xFFFF => u as u32 as u16,
                _ => unit,
            }
        })
        .unwrap_or(unit)
}

/// Deux noms sont égaux sans tenir compte de la casse.
fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| x == y || upper(x) == upper(y))
}

/// Une entrée de la table : un nom et son compte de références.
#[derive(Debug)]
struct Entry {
    name: Vec<u16>,
    references: u32,
}

/// Une table d'atomes : l'atome `FIRST_STRING_ATOM + i` est l'entrée `i`.
#[derive(Debug, Default)]
pub struct AtomTable {
    entries: Vec<Option<Entry>>,
}

impl AtomTable {
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// RtlAddAtomToAtomTable : l'atome de `name`, créé s'il le faut ; une
    /// référence de plus à un nom en chaîne.
    ///
    /// # Errors
    /// `STATUS_INVALID_PARAMETER` pour un atome entier de `0xC000` ou plus
    /// (ou nul) et pour un nom de plus de 255 caractères ;
    /// `STATUS_OBJECT_NAME_INVALID` pour un nom vide.
    pub fn add(&mut self, name: AtomName<'_>) -> Result<u16, NtStatus> {
        if let Some(value) = name.integer() {
            return integer_atom(value, &name);
        }
        let AtomName::String(name) = name else { unreachable!("an integer atom") };
        if let Some(atom) = self.find_string(name) {
            let entry = self.entry_mut(atom).expect("an atom just found");
            entry.references = entry.references.saturating_add(1);
            return Ok(atom);
        }
        if name.is_empty() {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if name.len() > MAXIMUM_ATOM_LENGTH {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let entry = Some(Entry { name: name.to_vec(), references: 1 });
        let index = match self.entries.iter().position(Option::is_none) {
            Some(index) => {
                self.entries[index] = entry;
                index
            }
            None if self.entries.len() < usize::from(u16::MAX - FIRST_STRING_ATOM) => {
                self.entries.push(entry);
                self.entries.len() - 1
            }
            None => return Err(abi::ntstatus::STATUS_NO_MEMORY),
        };
        Ok(FIRST_STRING_ATOM + index as u16)
    }

    /// RtlLookupAtomInAtomTable : l'atome de `name`, sans en créer ;
    /// `None` pour un nom en chaîne absent ou un atome entier invalide.
    pub fn find(&self, name: AtomName<'_>) -> Option<u16> {
        match name.integer() {
            Some(value) => integer_atom(value, &name).ok(),
            None => match name {
                AtomName::String(name) => self.find_string(name),
                AtomName::Integer(_) => None,
            },
        }
    }

    /// RtlDeleteAtomFromAtomTable : une référence de moins à `atom` ; il
    /// disparaît à la dernière. Un atome entier n'a rien à supprimer.
    ///
    /// # Errors
    /// `STATUS_INVALID_HANDLE` pour un atome en chaîne qui n'existe pas.
    pub fn delete(&mut self, atom: u16) -> Result<(), NtStatus> {
        if atom < FIRST_STRING_ATOM {
            return Ok(());
        }
        let index = usize::from(atom - FIRST_STRING_ATOM);
        let entry = self.entries.get_mut(index).and_then(Option::as_mut).ok_or(STATUS_INVALID_HANDLE)?;
        entry.references -= 1;
        if entry.references == 0 {
            self.entries[index] = None;
        }
        Ok(())
    }

    /// RtlQueryAtomInAtomTable : le nom de l'atome en chaîne `atom`.
    pub fn name(&self, atom: u16) -> Option<Vec<u16>> {
        self.entry(atom).map(|entry| entry.name.clone())
    }

    /// Le compte de références de l'atome en chaîne `atom`.
    pub fn references(&self, atom: u16) -> Option<u32> {
        self.entry(atom).map(|entry| entry.references)
    }

    fn find_string(&self, name: &[u16]) -> Option<u16> {
        self.entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| same_name(&entry.name, name)))
            .map(|index| FIRST_STRING_ATOM + index as u16)
    }

    fn entry(&self, atom: u16) -> Option<&Entry> {
        let index = usize::from(atom.checked_sub(FIRST_STRING_ATOM)?);
        self.entries.get(index)?.as_ref()
    }

    fn entry_mut(&mut self, atom: u16) -> Option<&mut Entry> {
        let index = usize::from(atom.checked_sub(FIRST_STRING_ATOM)?);
        self.entries.get_mut(index)?.as_mut()
    }
}

/// Un atome entier : de 1 à `0xBFFF` (0, passé tel quel, vaut `0xC000`,
/// refusé comme lui), ou `#` et un nombre dont les 16 bits de poids faible
/// sont sous `0xC000` (`#0` vaut 0).
fn integer_atom(value: u16, name: &AtomName<'_>) -> Result<u16, NtStatus> {
    let value = if value == 0 && matches!(name, AtomName::Integer(_)) { FIRST_STRING_ATOM } else { value };
    if value >= FIRST_STRING_ATOM {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(value)
}

/// La table de USER.
static USER_ATOMS: KSpinLock<AtomTable> = KSpinLock::new(AtomTable::new());

/// L'atome de `name` dans la table de USER, créé s'il le faut
/// (IntRegisterClassAtom).
///
/// # Errors
/// Voir [`AtomTable::add`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn add(name: AtomName<'_>) -> Result<u16, NtStatus> {
    USER_ATOMS.lock().add(name)
}

/// L'atome de `name` dans la table de USER, s'il existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn find(name: AtomName<'_>) -> Option<u16> {
    USER_ATOMS.lock().find(name)
}

/// Une référence de moins à `atom` dans la table de USER
/// (IntDeregisterClassAtom).
///
/// # Errors
/// Voir [`AtomTable::delete`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn delete(atom: u16) -> Result<(), NtStatus> {
    USER_ATOMS.lock().delete(atom)
}

/// Le nom de l'atome en chaîne `atom` de la table de USER.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn name(atom: u16) -> Option<Vec<u16>> {
    USER_ATOMS.lock().name(atom)
}

/// Le compte de références de l'atome en chaîne `atom` de la table de USER.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn references(atom: u16) -> Option<u32> {
    USER_ATOMS.lock().references(atom)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn a_name_gets_one_atom_whatever_its_case() {
        let mut table = AtomTable::new();
        let button = table.add(AtomName::String(&w("Button"))).unwrap();
        assert_eq!(button, FIRST_STRING_ATOM);
        assert_eq!(table.add(AtomName::String(&w("BUTTON"))), Ok(button), "the same atom, without case");
        assert_eq!(table.references(button), Some(2));
        let edit = table.add(AtomName::String(&w("Edit"))).unwrap();
        assert_eq!(edit, FIRST_STRING_ATOM + 1);
        assert_eq!(table.find(AtomName::String(&w("edit"))), Some(edit));
        assert_eq!(table.find(AtomName::String(&w("Static"))), None, "found, not added");
        assert_eq!(table.name(edit), Some(w("Edit")), "the first spelling");
        let accented = table.add(AtomName::String(&w("Fenêtre"))).unwrap();
        assert_eq!(table.find(AtomName::String(&w("FENÊTRE"))), Some(accented), "beyond ASCII");
    }

    #[test]
    fn integer_atoms_stand_for_themselves() {
        let mut table = AtomTable::new();
        assert_eq!(table.add(AtomName::Integer(0x8001)), Ok(0x8001));
        assert_eq!(table.add(AtomName::String(&w("#32770"))), Ok(32770));
        assert_eq!(table.add(AtomName::String(&w("#0"))), Ok(0));
        assert_eq!(table.add(AtomName::String(&w("#49152"))), Err(STATUS_INVALID_PARAMETER), "0xC000");
        assert_eq!(table.add(AtomName::String(&w("#65537"))), Ok(1), "its low 16 bits");
        assert_eq!(table.add(AtomName::Integer(0xC000)), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(table.add(AtomName::Integer(0)), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(table.find(AtomName::Integer(0x10)), Some(0x10));
        assert!(table.entries.is_empty(), "no entry for an integer atom");
        assert_eq!(table.add(AtomName::String(&w("#12a"))), Ok(FIRST_STRING_ATOM), "not a number: a string");
        assert_eq!(table.delete(0x8001), Ok(()), "nothing to delete");
    }

    #[test]
    fn names_are_neither_empty_nor_too_long() {
        let mut table = AtomTable::new();
        assert_eq!(table.add(AtomName::String(&[])), Err(STATUS_OBJECT_NAME_INVALID));
        let long = alloc::vec![u16::from(b'a'); MAXIMUM_ATOM_LENGTH];
        assert!(table.add(AtomName::String(&long)).is_ok());
        let longer = alloc::vec![u16::from(b'b'); MAXIMUM_ATOM_LENGTH + 1];
        assert_eq!(table.add(AtomName::String(&longer)), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn an_atom_goes_at_its_last_deletion_and_its_slot_comes_back() {
        let mut table = AtomTable::new();
        let first = table.add(AtomName::String(&w("First"))).unwrap();
        let second = table.add(AtomName::String(&w("Second"))).unwrap();
        table.add(AtomName::String(&w("first"))).unwrap();
        assert_eq!(table.delete(first), Ok(()));
        assert_eq!(table.find(AtomName::String(&w("First"))), Some(first), "one reference left");
        assert_eq!(table.delete(first), Ok(()));
        assert_eq!(table.find(AtomName::String(&w("First"))), None, "gone");
        assert_eq!(table.delete(first), Err(STATUS_INVALID_HANDLE));
        assert_eq!(table.add(AtomName::String(&w("Third"))), Ok(first), "its slot again");
        assert_eq!(table.name(second), Some(w("Second")));
    }
}
