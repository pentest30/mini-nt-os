//! Les services d'Ob.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};

/// NtClose(Handle) : ferme un handle du processus courant.
pub(super) fn nt_close(arguments: &[u32]) -> NtStatus {
    match super::current_process().handle_table.close(ob::Handle(arguments[0])) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// OBJECT_ATTRIBUTES, capturés une fois.
pub(super) struct Attributes {
    /// L'objet auquel le nom est relatif.
    pub root: Option<ob::ObjectRef>,
    pub name: Option<alloc::string::String>,
    /// `OBJ_*`.
    pub attributes: u32,
}

/// Capture les OBJECT_ATTRIBUTES en `address` : leur taille, leur nom, et
/// l'objet que désigne leur `RootDirectory` dans le processus courant.
/// `STATUS_INVALID_PARAMETER` pour une taille autre que 24 ; celles de
/// [`capture_name`] et du handle.
pub(super) fn capture_attributes(address: u32) -> Result<Attributes, NtStatus> {
    let captured = ke::usermem::UserPtr::<abi::object::ObjectAttributes32>::new(address).read()?;
    if captured.length as usize != core::mem::size_of::<abi::object::ObjectAttributes32>() {
        return Err(abi::ntstatus::STATUS_INVALID_PARAMETER);
    }
    let name = match captured.object_name {
        0 => None,
        at => {
            let units = capture_unicode_string(at)?;
            Some(alloc::string::String::from_utf16(&units).map_err(|_| abi::ntstatus::STATUS_OBJECT_NAME_INVALID)?)
        }
    };
    let root = match captured.root_directory {
        0 => None,
        handle => {
            Some(super::current_process().handle_table.reference(ob::Handle(handle), None, ob::AccessMask::NONE)?)
        }
    };
    Ok(Attributes { root, name, attributes: captured.attributes })
}

/// Capture le UNICODE_STRING en `address` et ses caractères.
/// `STATUS_OBJECT_NAME_INVALID` pour une longueur impaire ou plus grande
/// que sa longueur maximale.
pub(super) fn capture_unicode_string(address: u32) -> Result<alloc::vec::Vec<u16>, NtStatus> {
    let string = ke::usermem::UserPtr::<abi::peb32::UnicodeString32>::new(address).read()?;
    if string.length % 2 != 0 || string.length > string.maximum_length {
        return Err(abi::ntstatus::STATUS_OBJECT_NAME_INVALID);
    }
    let mut bytes = alloc::vec![0u8; usize::from(string.length)];
    ke::usermem::probe_for_read(u64::from(string.buffer), bytes.len(), 2)?;
    ke::usermem::copy_from_user(&mut bytes, u64::from(string.buffer))?;
    Ok(bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect())
}
