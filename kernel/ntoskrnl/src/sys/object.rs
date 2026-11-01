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

/// Ouvre l'objet de type `expected` que désignent les attributs en
/// `attributes`, et met son handle en `out` (0 d'abord, puis le handle ; le
/// handle est refermé si cette écriture faute).
pub(super) fn open_by_name(out: u32, desired: u32, attributes: u32, expected: &ob::ObjectType) -> Result<(), NtStatus> {
    let out = ke::usermem::UserPtr::<u32>::new(out);
    out.write(&0)?;
    let mut captured = capture_attributes(attributes)?;
    // A link opened as a link is not followed at the end of the name.
    if core::ptr::eq(expected, &ob::SYMBOLIC_LINK_TYPE) {
        captured.attributes |= abi::object::OBJ_OPENLINK;
    }
    let name = captured.name.unwrap_or_default();
    let process = super::current_process();
    let handle = ob::open_object_by_name(
        ob::namespace(),
        &name,
        captured.root.as_ref(),
        Some(expected),
        captured.attributes,
        &process.handle_table,
        ob::AccessMask(desired),
    )?;
    give_handle(&out, handle)
}

/// Nomme `object` d'après les attributs en `attributes` (`OBJ_PERMANENT`,
/// `OBJ_OPENIF`), qui peuvent manquer (adresse nulle : un objet sans nom,
/// comme ObCreateObject le permet), et met son handle en `out`, 0 d'abord.
/// Rend le statut d'ObInsertObject : `STATUS_OBJECT_NAME_EXISTS` avec
/// `OBJ_OPENIF` et un nom déjà pris par un objet du même type.
pub(super) fn create_named(
    out: u32,
    desired: u32,
    attributes: u32,
    object: ob::ObjectRef,
) -> Result<NtStatus, NtStatus> {
    let out = ke::usermem::UserPtr::<u32>::new(out);
    out.write(&0)?;
    let captured = match attributes {
        0 => Attributes { root: None, name: None, attributes: 0 },
        at => capture_attributes(at)?,
    };
    let process = super::current_process();
    let (handle, status) = ob::insert_object(
        ob::namespace(),
        object,
        captured.name.as_deref(),
        captured.root.as_ref(),
        captured.attributes,
        &process.handle_table,
        ob::AccessMask(desired),
    )?;
    give_handle(&out, handle)?;
    Ok(status)
}

/// Écrit `handle` en `out` ; le referme si l'écriture faute.
pub(super) fn give_handle(out: &ke::usermem::UserPtr<u32>, handle: ob::Handle) -> Result<(), NtStatus> {
    if let Err(fault) = out.write(&handle.0) {
        let _ = super::current_process().handle_table.close(handle);
        return Err(fault);
    }
    Ok(())
}

fn result(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// NtOpenDirectoryObject(*DirectoryHandle, DesiredAccess, ObjectAttributes) :
/// un handle sur le répertoire d'Ob que désignent les attributs.
pub(super) fn nt_open_directory_object(arguments: &[u32]) -> NtStatus {
    result(open_by_name(arguments[0], arguments[1], arguments[2], &ob::DIRECTORY_TYPE).map(|()| STATUS_SUCCESS))
}

/// NtCreateDirectoryObject(*DirectoryHandle, DesiredAccess, ObjectAttributes) :
/// un répertoire d'Ob neuf, nommé (ou non) d'après les attributs.
pub(super) fn nt_create_directory_object(arguments: &[u32]) -> NtStatus {
    result(create_named(arguments[0], arguments[1], arguments[2], ob::Directory::create()))
}

/// NtOpenSymbolicLinkObject(*LinkHandle, DesiredAccess, ObjectAttributes) :
/// un handle sur le lien que désignent les attributs : le lien lui-même, non
/// suivi en fin de nom.
pub(super) fn nt_open_symbolic_link_object(arguments: &[u32]) -> NtStatus {
    result(open_by_name(arguments[0], arguments[1], arguments[2], &ob::SYMBOLIC_LINK_TYPE).map(|()| STATUS_SUCCESS))
}

/// NtCreateSymbolicLinkObject(*LinkHandle, DesiredAccess, ObjectAttributes,
/// LinkTarget) : un lien d'Ob vers le nom `LinkTarget`.
pub(super) fn nt_create_symbolic_link_object(arguments: &[u32]) -> NtStatus {
    result(capture_unicode_string(arguments[3]).and_then(|units| {
        let target =
            alloc::string::String::from_utf16(&units).map_err(|_| abi::ntstatus::STATUS_OBJECT_NAME_INVALID)?;
        let link: ob::ObjectRef = ob::SymbolicLink::create(&target);
        create_named(arguments[0], arguments[1], arguments[2], link)
    }))
}
