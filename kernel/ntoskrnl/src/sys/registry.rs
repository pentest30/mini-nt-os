//! Les services de Cm : ouvrir ou créer une clé, la décrire, énumérer ses
//! sous-clés et ses valeurs, lire, écrire et effacer une valeur. Les classes
//! d'information viennent de `cm::info` ; ce qui ne tient pas dans le tampon
//! de l'appelant suit la règle d'XP ([`return_variable`]).
//!
//! Pas encore : les clés liens (`REG_OPTION_CREATE_LINK`,
//! `STATUS_NOT_IMPLEMENTED`, journalisé une fois), NtDeleteKey, NtFlushKey.

use abi::ntstatus::{
    NtStatus, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_NO_MORE_ENTRIES, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_SUCCESS,
};
use abi::registry::{
    KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_CREATED_NEW_KEY, REG_LEGAL_OPTION,
    REG_OPENED_EXISTING_KEY, REG_OPTION_CREATE_LINK, REG_OPTION_VOLATILE,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, Object};

use super::object::{capture_attributes, capture_unicode_string, give_handle};

/// Les classes demandées sans être implémentées.
static KEY_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryKey/NtEnumerateKey");
static VALUE_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryValueKey/NtEnumerateValueKey");

fn status(result: Result<(), NtStatus>) -> NtStatus {
    match result {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// La clé que désigne `handle` dans le processus courant, avec `access`.
fn reference_key(handle: u32, access: u32) -> Result<Arc<Object<cm::Key>>, NtStatus> {
    super::current_process().handle_table.reference_as::<cm::Key>(Handle(handle), &cm::KEY_TYPE, AccessMask(access))
}

/// Rend `encoded` dans le tampon de `length` octets en `buffer`, et sa
/// taille entière en `result_length`. Sous sa partie fixe,
/// `STATUS_BUFFER_TOO_SMALL` sans rien écrire ; au-delà, ce qui tient, et
/// `STATUS_BUFFER_OVERFLOW` si ce n'est pas tout.
fn return_variable(encoded: cm::info::Encoded, buffer: u32, length: u32, result_length: u32) -> Result<(), NtStatus> {
    let size = encoded.bytes.len();
    UserPtr::<u32>::new(result_length).write(&(size as u32))?;
    if (length as usize) < encoded.minimum {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let take = size.min(length as usize);
    ke::usermem::probe_for_write(u64::from(buffer), take, 4)?;
    ke::usermem::copy_to_user(u64::from(buffer), &encoded.bytes[..take])?;
    if take < size {
        return Err(STATUS_BUFFER_OVERFLOW);
    }
    Ok(())
}

/// NtOpenKey(*KeyHandle, DesiredAccess, ObjectAttributes) : un handle sur la
/// clé que désignent les attributs, absolue (`\Registry\…`) ou relative à
/// une clé ouverte. `*KeyHandle` reçoit 0 d'abord, puis le handle.
pub(super) fn nt_open_key(arguments: &[u32]) -> NtStatus {
    status(open_key(arguments))
}

fn open_key(arguments: &[u32]) -> Result<(), NtStatus> {
    let out = UserPtr::<u32>::new(arguments[0]);
    out.write(&0)?;
    let attributes = capture_attributes(arguments[2])?;
    let name = attributes.name.unwrap_or_default();
    let process = super::current_process();
    let handle = ob::open_object_by_name(
        ob::namespace(),
        &name,
        attributes.root.as_ref(),
        Some(&cm::KEY_TYPE),
        attributes.attributes,
        &process.handle_table,
        AccessMask(arguments[1]),
    )?;
    if let Err(fault) = out.write(&handle.0) {
        let _ = process.handle_table.close(handle);
        return Err(fault);
    }
    Ok(())
}

/// NtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length,
/// ResultLength) : KEY_BASIC, NODE ou FULL_INFORMATION de la clé
/// (`KEY_QUERY_VALUE`).
pub(super) fn nt_query_key(arguments: &[u32]) -> NtStatus {
    status(query_key(arguments))
}

fn query_key(arguments: &[u32]) -> Result<(), NtStatus> {
    let key = reference_key(arguments[0], KEY_QUERY_VALUE)?;
    let class = arguments[1];
    let encoded = cm::info::key_information(&key.facts()?, class).ok_or_else(|| KEY_CLASSES.report(class))?;
    return_variable(encoded, arguments[2], arguments[3], arguments[4])
}

/// NtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation,
/// Length, ResultLength) : la sous-clé numéro `Index` (`KEY_ENUMERATE_SUB_KEYS`),
/// `STATUS_NO_MORE_ENTRIES` au-delà.
pub(super) fn nt_enumerate_key(arguments: &[u32]) -> NtStatus {
    status(enumerate_key(arguments))
}

fn enumerate_key(arguments: &[u32]) -> Result<(), NtStatus> {
    let key = reference_key(arguments[0], KEY_ENUMERATE_SUB_KEYS)?;
    let class = arguments[2];
    let subkey = key.subkey_at(arguments[1])?.ok_or(STATUS_NO_MORE_ENTRIES)?;
    let encoded = cm::info::key_information(&subkey.facts()?, class).ok_or_else(|| KEY_CLASSES.report(class))?;
    return_variable(encoded, arguments[3], arguments[4], arguments[5])
}

/// NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
/// KeyValueInformation, Length, ResultLength) : la valeur nommée, sans
/// casse (`KEY_QUERY_VALUE`) ; `STATUS_OBJECT_NAME_NOT_FOUND` sans elle.
pub(super) fn nt_query_value_key(arguments: &[u32]) -> NtStatus {
    status(query_value_key(arguments))
}

fn query_value_key(arguments: &[u32]) -> Result<(), NtStatus> {
    let key = reference_key(arguments[0], KEY_QUERY_VALUE)?;
    let name = capture_unicode_string(arguments[1])?;
    let class = arguments[2];
    let value = key.value(&name)?.ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let encoded = cm::info::value_information(&value, class).ok_or_else(|| VALUE_CLASSES.report(class))?;
    return_variable(encoded, arguments[3], arguments[4], arguments[5])
}

/// NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass,
/// KeyValueInformation, Length, ResultLength) : la valeur numéro `Index`
/// (`KEY_QUERY_VALUE`), `STATUS_NO_MORE_ENTRIES` au-delà.
pub(super) fn nt_enumerate_value_key(arguments: &[u32]) -> NtStatus {
    status(enumerate_value_key(arguments))
}

fn enumerate_value_key(arguments: &[u32]) -> Result<(), NtStatus> {
    let key = reference_key(arguments[0], KEY_QUERY_VALUE)?;
    let class = arguments[2];
    let values = key.values()?;
    let value = values.get(arguments[1] as usize).ok_or(STATUS_NO_MORE_ENTRIES)?;
    let encoded = cm::info::value_information(value, class).ok_or_else(|| VALUE_CLASSES.report(class))?;
    return_variable(encoded, arguments[3], arguments[4], arguments[5])
}

/// Les données d'une valeur, au plus : 16 Mio.
const MAX_VALUE_DATA: u32 = 16 << 20;

/// `REG_OPTION_CREATE_LINK` a déjà été demandé.
static LINK_REPORTED: AtomicBool = AtomicBool::new(false);

/// NtCreateKey(*KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex,
/// Class, CreateOptions, *Disposition) : un handle sur la clé que désignent
/// les attributs, ouverte si elle existe (`REG_OPENED_EXISTING_KEY`), créée
/// sinon sous son parent, qui doit exister (`REG_CREATED_NEW_KEY`) ; volatile
/// avec `REG_OPTION_VOLATILE`. `*KeyHandle` reçoit 0 d'abord ; `Disposition`
/// peut manquer.
pub(super) fn nt_create_key(arguments: &[u32]) -> NtStatus {
    status(create_key(arguments))
}

fn create_key(arguments: &[u32]) -> Result<(), NtStatus> {
    let [out, desired, attributes, _title_index, class, options, disposition] = arguments[..7] else {
        unreachable!("7 arguments")
    };
    if options & !REG_LEGAL_OPTION != 0 {
        return Err(abi::ntstatus::STATUS_INVALID_PARAMETER);
    }
    if options & REG_OPTION_CREATE_LINK != 0 {
        if !LINK_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtCreateKey with REG_OPTION_CREATE_LINK is not implemented");
        }
        return Err(abi::ntstatus::STATUS_NOT_IMPLEMENTED);
    }
    let out = UserPtr::<u32>::new(out);
    out.write(&0)?;
    let captured = capture_attributes(attributes)?;
    let class = if class == 0 { alloc::vec::Vec::new() } else { capture_unicode_string(class)? };
    let name = captured.name.unwrap_or_default();
    let root = captured.root.as_ref();
    let namespace = ob::namespace();
    let (object, how) = match namespace.open(&name, root, Some(&cm::KEY_TYPE), captured.attributes) {
        Ok(object) => (object, REG_OPENED_EXISTING_KEY),
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => {
            // The parent must exist: NtCreateKey makes the last key only.
            let (parent_name, last) = match name.rsplit_once('\\') {
                Some(("", last)) => ("\\", last),
                Some((parent, last)) => (parent, last),
                None => ("", name.as_str()),
            };
            let parent = namespace.open(parent_name, root, Some(&cm::KEY_TYPE), captured.attributes)?;
            let parent = ob::downcast::<cm::Key>(&parent).ok_or(abi::ntstatus::STATUS_OBJECT_TYPE_MISMATCH)?;
            let (key, created) = parent.create_subkey(last, &class, options & REG_OPTION_VOLATILE != 0)?;
            let object: ob::ObjectRef = ob::create_object(&cm::KEY_TYPE, key);
            (object, if created { REG_CREATED_NEW_KEY } else { REG_OPENED_EXISTING_KEY })
        }
        Err(status) => return Err(status),
    };
    let process = super::current_process();
    let handle_attributes = ob::HandleAttributes {
        inherit: captured.attributes & abi::object::OBJ_INHERIT != 0,
        protect_from_close: false,
    };
    let handle = process.handle_table.insert(object, AccessMask(desired), handle_attributes)?;
    give_handle(&out, handle)?;
    if disposition != 0 {
        if let Err(fault) = UserPtr::<u32>::new(disposition).write(&how) {
            let _ = process.handle_table.close(handle);
            return Err(fault);
        }
    }
    Ok(())
}

/// NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize) :
/// écrit la valeur (`KEY_SET_VALUE`), la crée sinon. Au-delà de 16 Mio de
/// données : `STATUS_INSUFFICIENT_RESOURCES`.
pub(super) fn nt_set_value_key(arguments: &[u32]) -> NtStatus {
    status(set_value_key(arguments))
}

fn set_value_key(arguments: &[u32]) -> Result<(), NtStatus> {
    let [handle, name, _title_index, data_type, data, size] = arguments[..6] else { unreachable!("6 arguments") };
    let key = reference_key(handle, KEY_SET_VALUE)?;
    let name = capture_unicode_string(name)?;
    if size > MAX_VALUE_DATA {
        return Err(abi::ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    }
    let mut bytes = alloc::vec![0u8; size as usize];
    ke::usermem::probe_for_read(u64::from(data), bytes.len(), 1)?;
    ke::usermem::copy_from_user(&mut bytes, u64::from(data))?;
    key.set_value(&name, data_type, bytes)
}

/// NtDeleteValueKey(KeyHandle, ValueName) : efface la valeur
/// (`KEY_SET_VALUE`) ; `STATUS_OBJECT_NAME_NOT_FOUND` sans elle.
pub(super) fn nt_delete_value_key(arguments: &[u32]) -> NtStatus {
    status(reference_key(arguments[0], KEY_SET_VALUE).and_then(|key| {
        let name = capture_unicode_string(arguments[1])?;
        key.delete_value(&name)
    }))
}
