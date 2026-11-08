//! Les services des atomes (win32k::atom) : NtAddAtom, NtFindAtom,
//! NtDeleteAtom, NtQueryInformationAtom — la table globale des atomes, où
//! les noms de classes de fenêtres et les chaînes de GlobalAddAtom vivent.
//! Les noms arrivent en UTF-16 par (pointeur, octets) ; les atomes rendus
//! repartent dans le pointeur `Atom` de l'appelant.

use abi::ntstatus::{NtStatus, STATUS_INVALID_HANDLE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS};
use alloc::vec::Vec;
use ke::usermem::UserPtr;
use win32k::atom::{self, AtomName, FIRST_STRING_ATOM};

/// `AtomBasicInformation` : la classe 0 de NtQueryInformationAtom.
const ATOM_BASIC_INFORMATION: u32 = 0;

/// Les classes de NtQueryInformationAtom demandées sans être implémentées.
static UNSUPPORTED_ATOM_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryInformationAtom");

/// Les unités UTF-16 que `length` octets portent à l'adresse `name`.
fn capture_units(name: u32, length: u32) -> Result<Vec<u16>, NtStatus> {
    let mut bytes = alloc::vec![0u8; (length as usize / 2) * 2];
    ke::usermem::copy_from_user(&mut bytes, u64::from(name))?;
    Ok(bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}

/// L'atome rendu dans le pointeur `atom` de l'appelant, s'il n'est pas nul.
fn write_atom_back(atom: u32, value: u16) -> Result<(), NtStatus> {
    if atom != 0 {
        UserPtr::<u16>::new(atom).write(&value)?;
    }
    Ok(())
}

/// Les unités du nom d'un atome : celles de la table pour un atome en
/// chaîne, ses chiffres décimaux pour un atome entier.
fn name_of(atom: u16) -> Result<Vec<u16>, NtStatus> {
    match atom::name(atom) {
        Some(name) => Ok(name),
        None if atom < FIRST_STRING_ATOM => {
            let digits = alloc::format!("{atom}");
            Ok(digits.encode_utf16().collect())
        }
        None => Err(STATUS_INVALID_HANDLE),
    }
}

/// NtAddAtom(AtomName, Length, Atom) : l'atome du nom, créé s'il le faut,
/// une référence de plus s'il existe ; rendu dans `Atom`.
pub(super) fn nt_add_atom(arguments: &[u32]) -> NtStatus {
    let (name, length, atom) = (arguments[0], arguments[1], arguments[2]);
    let add = || {
        let units = capture_units(name, length)?;
        let added = atom::add(AtomName::String(&units))?;
        write_atom_back(atom, added)
    };
    add().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtFindAtom(AtomName, Length, Atom) : l'atome du nom, sans le créer ;
/// `STATUS_OBJECT_NAME_NOT_FOUND` sans lui.
pub(super) fn nt_find_atom(arguments: &[u32]) -> NtStatus {
    let (name, length, atom) = (arguments[0], arguments[1], arguments[2]);
    let find = || {
        let units = capture_units(name, length)?;
        let found = atom::find(AtomName::String(&units)).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        write_atom_back(atom, found)
    };
    find().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtDeleteAtom(Atom) : une référence de moins ; une chaîne disparaît à sa
/// dernière référence (`STATUS_INVALID_HANDLE` sans elle).
pub(super) fn nt_delete_atom(arguments: &[u32]) -> NtStatus {
    atom::delete(arguments[0] as u16).map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtQueryInformationAtom(Atom, InformationClass, Buffer, Length,
/// ReturnLength) : `AtomBasicInformation` — ATOM_BASIC_INFORMATION de XP :
/// UsageCount, Flags et NameLength, trois USHORT consécutifs (la longueur du
/// nom en octets, sans son nul), puis le nom à l'offset 6. Sans la place
/// pour l'entête, seul le besoin est rendu (`ReturnLength`).
/// `AtomTableInformation` (le compte des entrées) et les autres classes
/// rendent `STATUS_NOT_IMPLEMENTED`, journalisées une fois.
pub(super) fn nt_query_information_atom(arguments: &[u32]) -> NtStatus {
    /// L'offset du nom dans ATOM_BASIC_INFORMATION.
    const NAME_AT: usize = 6;
    let [atom, class, buffer, length, return_length] = arguments[..5] else { unreachable!("5 arguments") };
    if class != ATOM_BASIC_INFORMATION {
        return UNSUPPORTED_ATOM_CLASSES.report(class);
    }
    let query = || {
        let name = name_of(atom as u16)?;
        let usage =
            if (atom as u16) >= FIRST_STRING_ATOM { win32k::atom::references(atom as u16).unwrap_or(0) } else { 1 };
        let needed = NAME_AT + name.len() * 2;
        if (length as usize) < needed {
            if return_length != 0 {
                UserPtr::<u32>::new(return_length).write(&(needed as u32))?;
            }
            return Err(abi::ntstatus::STATUS_INFO_LENGTH_MISMATCH);
        }
        let mut out = Vec::with_capacity(needed);
        out.extend_from_slice(&(usage.min(u32::from(u16::MAX)) as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // Flags.
        out.extend_from_slice(&((name.len() * 2) as u16).to_le_bytes());
        for unit in &name {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        ke::usermem::copy_to_user(u64::from(buffer), &out)?;
        if return_length != 0 {
            UserPtr::<u32>::new(return_length).write(&(needed as u32))?;
        }
        Ok(())
    };
    query().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtUserGetAtomName(Atom, Buffer) : le nom de l'atome, en WCHAR terminés
/// par nul, dans le tampon de l'appelant ; le nombre d'unités écrites sans
/// le nul. Les atomes entiers rendent leurs chiffres décimaux.
pub(super) fn nt_user_get_atom_name(arguments: &[u32]) -> NtStatus {
    let [atom, buffer] = arguments[..2] else { unreachable!("2 arguments") };
    let get = || -> Result<u32, NtStatus> {
        if buffer == 0 {
            return Ok(0);
        }
        let name = name_of(atom as u16)?;
        let mut units: Vec<u16> = name;
        units.push(0);
        let bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        ke::usermem::copy_to_user(u64::from(buffer), &bytes)?;
        Ok(units.len() as u32 - 1)
    };
    match get() {
        Ok(count) => NtStatus(count),
        Err(status) => status,
    }
}
