//! Les services d'Ob.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};

/// NtClose(Handle) : ferme un handle du processus courant.
pub(super) fn nt_close(arguments: &[u32]) -> NtStatus {
    match super::current_process().handle_table.close(ob::Handle(arguments[0])) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
/// *TargetHandle, DesiredAccess, HandleAttributes, Options) : un handle dans
/// le processus cible sur l'objet d'un handle du processus source (Ob,
/// [`ob::duplicate`]). Les deux processus se désignent dans le processus
/// courant, avec `PROCESS_DUP_HANDLE`. `NtCurrentProcess()` comme handle
/// source désigne le processus source, `NtCurrentThread()` le thread courant,
/// avec tous les droits de leur type. Sans processus cible, le handle source
/// se ferme seulement (`DUPLICATE_CLOSE_SOURCE`, sinon
/// `STATUS_INVALID_PARAMETER`). Les attributs du handle neuf : `OBJ_INHERIT`
/// et `OBJ_PROTECT_CLOSE`. `*TargetHandle`, s'il est donné, est sondé et mis
/// à zéro d'abord, puis reçoit le handle ; s'il faute alors, le handle neuf
/// se referme.
///
/// Un processus cible qui ne s'ouvre pas rend son statut, après avoir fermé
/// le handle source avec `DUPLICATE_CLOSE_SOURCE` (que DuplicateHandle
/// promet « quel que soit le résultat ») ; ReactOS rend alors le résultat
/// d'une duplication sans cible.
pub(super) fn nt_duplicate_object(arguments: &[u32]) -> NtStatus {
    use abi::object::{DUPLICATE_CLOSE_SOURCE, OBJ_INHERIT, OBJ_PROTECT_CLOSE};
    use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
    use ob::DuplicateSource;
    use ps::eprocess::{PROCESS_DUP_HANDLE, PROCESS_TYPE};
    use ps::ethread::THREAD_TYPE;

    let (source_process, source_handle, target_process) = (arguments[0], arguments[1], arguments[2]);
    let out = ke::usermem::UserPtr::<u32>::new(arguments[3]);
    let (desired, attributes, options) = (ob::AccessMask(arguments[4]), arguments[5], arguments[6]);
    let duplicate = || {
        if !out.is_null() {
            out.write(&0)?;
        }
        let source = super::reference_process(source_process, PROCESS_DUP_HANDLE)?;
        let from = match source_handle {
            NT_CURRENT_PROCESS => {
                DuplicateSource::Pseudo { object: source.clone(), access: PROCESS_TYPE.generic_mapping.all }
            }
            NT_CURRENT_THREAD => DuplicateSource::Pseudo {
                object: ps::ethread::current_thread().expect("a system service outside a Ps thread"),
                access: THREAD_TYPE.generic_mapping.all,
            },
            handle => DuplicateSource::Handle(ob::Handle(handle)),
        };
        let target = match target_process {
            0 => None,
            handle => match super::reference_process(handle, PROCESS_DUP_HANDLE) {
                Ok(target) => Some(target),
                Err(status) => {
                    if let (DuplicateSource::Handle(handle), true) = (from, options & DUPLICATE_CLOSE_SOURCE != 0) {
                        let _ = source.handle_table.close(handle);
                    }
                    return Err(status);
                }
            },
        };
        let attributes = ob::HandleAttributes {
            inherit: attributes & OBJ_INHERIT != 0,
            protect_from_close: attributes & OBJ_PROTECT_CLOSE != 0,
        };
        let table = target.as_ref().map(|target| &target.handle_table);
        let handle = ob::duplicate(&source.handle_table, from, table, desired, attributes, options)?;
        if let (Some(handle), Some(table), false) = (handle, table, out.is_null()) {
            if let Err(fault) = out.write(&handle.0) {
                let _ = table.close(handle);
                return Err(fault);
            }
        }
        Ok(STATUS_SUCCESS)
    };
    result(duplicate())
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

/// NtQuerySymbolicLinkObject(LinkHandle, *LinkTarget, *ReturnedLength) : la
/// cible du lien (`SYMBOLIC_LINK_QUERY`) dans le UNICODE_STRING `LinkTarget`,
/// dont le tampon a `MaximumLength` octets, et sa longueur dans `Length`.
/// Comme ReactOS : avec `ReturnedLength`, la cible est copiée avec son zéro
/// final, et sa taille ainsi comptée y est rendue, même quand le tampon est
/// trop petit (`STATUS_BUFFER_TOO_SMALL`) ; sans lui, sans le zéro.
pub(super) fn nt_query_symbolic_link_object(arguments: &[u32]) -> NtStatus {
    use abi::peb32::UnicodeString32;
    use ke::usermem::UserPtr;

    let (handle, target, returned) = (arguments[0], arguments[1], arguments[2]);
    let query = || {
        let string = UserPtr::<UnicodeString32>::new(target).read()?;
        if returned != 0 {
            ke::usermem::probe_for_write(u64::from(returned), 4, 4)?;
        }
        let link = super::current_process().handle_table.reference_as::<ob::SymbolicLink>(
            ob::Handle(handle),
            &ob::SYMBOLIC_LINK_TYPE,
            ob::symlink::SYMBOLIC_LINK_QUERY,
        )?;
        let mut bytes: alloc::vec::Vec<u8> = link.target().encode_utf16().flat_map(u16::to_le_bytes).collect();
        let length = u16::try_from(bytes.len()).map_err(|_| abi::ntstatus::STATUS_NAME_TOO_LONG)?;
        let maximum = u32::from(length) + 2;
        if returned != 0 {
            bytes.extend_from_slice(&[0, 0]);
        }
        let status = if bytes.len() <= usize::from(string.maximum_length) {
            ke::usermem::probe_for_write(u64::from(string.buffer), bytes.len(), 2)?;
            ke::usermem::copy_to_user(u64::from(string.buffer), &bytes)?;
            UserPtr::<u16>::new(target).write(&length)?;
            STATUS_SUCCESS
        } else {
            abi::ntstatus::STATUS_BUFFER_TOO_SMALL
        };
        if returned != 0 {
            UserPtr::<u32>::new(returned).write(&maximum)?;
        }
        Ok(status)
    };
    result(query())
}

/// Les classes de NtQueryObject demandées sans être implémentées.
static UNSUPPORTED_QUERY_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryObject");

/// NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, Length,
/// ReturnLength) : ce que l'on sait d'un handle ou de son objet.
/// `ObjectBasicInformation` (0) : [`query_basic_information`].
/// `ObjectHandleFlagInformation` (4) : les attributs du handle, héritable et
/// protégé contre la fermeture (deux BOOLEAN, `STATUS_INFO_LENGTH_MISMATCH`
/// pour une autre taille, alignés sur un octet). Les autres classes rendent
/// `STATUS_NOT_IMPLEMENTED`, journalisé à leur premier appel.
pub(super) fn nt_query_object(arguments: &[u32]) -> NtStatus {
    use abi::object::OBJECT_HANDLE_FLAG_INFORMATION;

    let (handle, class, information, length, return_length) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    if class == abi::object::OBJECT_BASIC_INFORMATION {
        return query_basic_information(handle, information, length, return_length);
    }
    if class != OBJECT_HANDLE_FLAG_INFORMATION {
        return UNSUPPORTED_QUERY_CLASSES.report(class);
    }
    match super::current_process().handle_table.query(ob::Handle(handle)) {
        Ok((_, attributes)) => super::return_aligned_information(
            &[u8::from(attributes.inherit), u8::from(attributes.protect_from_close)],
            information,
            length,
            return_length,
            1,
        ),
        Err(status) => status,
    }
}

/// NtQueryObject(`ObjectBasicInformation`) : l'OBJECT_BASIC_INFORMATION du
/// handle (ObjectBasicInformation de NtQueryObject dans ReactOS) : les
/// attributs du handle (OBJ_INHERIT, OBJ_PROTECT_CLOSE) et OBJ_PERMANENT de
/// l'objet, les droits accordés, les comptes de handles et de pointeurs, la
/// place qu'il faut pour son nom complet (0 sans nom) et pour son type, et
/// celle de son descripteur de sécurité si le handle a READ_CONTROL. Pas de
/// quotas du pool (0), ni la date de création d'un lien symbolique (0).
/// `STATUS_INFO_LENGTH_MISMATCH` pour une autre taille que 56 octets.
fn query_basic_information(handle: u32, information: u32, length: u32, return_length: u32) -> NtStatus {
    use abi::object::{
        ObjectBasicInformation32, OBJECT_NAME_INFORMATION_SIZE, OBJECT_TYPE_INFORMATION_SIZE, OBJ_INHERIT,
        OBJ_PERMANENT, OBJ_PROTECT_CLOSE,
    };
    let size = core::mem::size_of::<ObjectBasicInformation32>() as u32;
    let query = || -> Result<ObjectBasicInformation32, NtStatus> {
        if return_length != 0 {
            ke::usermem::UserPtr::<u32>::new(return_length).write(&size)?;
        }
        if length != size {
            return Err(abi::ntstatus::STATUS_INFO_LENGTH_MISMATCH);
        }
        let (object, access, attributes) = super::current_process().handle_table.query_entry(ob::Handle(handle))?;
        let mut flags = 0;
        if attributes.inherit {
            flags |= OBJ_INHERIT;
        }
        if attributes.protect_from_close {
            flags |= OBJ_PROTECT_CLOSE;
        }
        if object.is_permanent() {
            flags |= OBJ_PERMANENT;
        }
        let name_info_size = match ob::namespace().full_name(&object) {
            Some(name) if name != "\\" => (name.encode_utf16().count() * 2) as u32 + OBJECT_NAME_INFORMATION_SIZE + 2,
            _ => 0,
        };
        let type_name = object.object_type().name.encode_utf16().count() as u32 * 2;
        let security_descriptor_size = if access.contains(ob::AccessMask::READ_CONTROL) {
            object.security_descriptor().map_or(0, |descriptor| descriptor.len() as u32)
        } else {
            0
        };
        Ok(ObjectBasicInformation32 {
            attributes: flags,
            granted_access: access.0,
            handle_count: object.handle_count(),
            pointer_count: alloc::sync::Arc::strong_count(&object) as u32,
            name_info_size,
            type_info_size: OBJECT_TYPE_INFORMATION_SIZE + type_name + 2,
            security_descriptor_size,
            ..ObjectBasicInformation32::default()
        })
    };
    match query() {
        Ok(info) => match ke::usermem::copy_to_user(u64::from(information), &info.to_bytes()) {
            Ok(()) => abi::ntstatus::STATUS_SUCCESS,
            Err(status) => status,
        },
        Err(status) => status,
    }
}

/// NtSetInformationObject(Handle, ObjectInformationClass, ObjectInformation,
/// Length) : ce qu'on change d'un handle ou de son objet.
///
/// | Classe | Effet |
/// |---|---|
/// | `ObjectHandleFlagInformation` (4) | les attributs du handle : héritable, protégé contre la fermeture (deux BOOLEAN, `STATUS_INFO_LENGTH_MISMATCH` pour une autre taille) |
/// | `ObjectSessionInformation` (5) | le répertoire devient celui de la session de l'appelant, sous `SeTcbPrivilege` (`STATUS_PRIVILEGE_NOT_HELD`) ; un autre objet rend `STATUS_OBJECT_TYPE_MISMATCH` |
///
/// Les autres classes rendent `STATUS_INVALID_INFO_CLASS`.
pub(super) fn nt_set_information_object(arguments: &[u32]) -> NtStatus {
    use abi::ntstatus::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS, STATUS_PRIVILEGE_NOT_HELD};
    use abi::object::{OBJECT_HANDLE_FLAG_INFORMATION, OBJECT_SESSION_INFORMATION};

    let (handle, class, information, length) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let process = super::current_process();
    let set = || match class {
        OBJECT_HANDLE_FLAG_INFORMATION => {
            if length != 2 {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            }
            let mut flags = [0u8; 2];
            ke::usermem::copy_from_user(&mut flags, u64::from(information))?;
            let attributes = ob::HandleAttributes { inherit: flags[0] != 0, protect_from_close: flags[1] != 0 };
            process.handle_table.set_attributes(ob::Handle(handle), attributes)?;
            Ok(STATUS_SUCCESS)
        }
        OBJECT_SESSION_INFORMATION => {
            if !super::security::privilege_enabled(abi::security::SE_TCB_PRIVILEGE) {
                return Err(STATUS_PRIVILEGE_NOT_HELD);
            }
            let directory = process.handle_table.reference_as::<ob::Directory>(
                ob::Handle(handle),
                &ob::DIRECTORY_TYPE,
                ob::AccessMask::NONE,
            )?;
            directory.set_session_id(process.session_id());
            Ok(STATUS_SUCCESS)
        }
        _ => Err(STATUS_INVALID_INFO_CLASS),
    };
    set().unwrap_or_else(|status| status)
}
