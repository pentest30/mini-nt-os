//! Les services de Cm, en lecture : ouvrir une clé, la décrire, énumérer
//! ses sous-clés et ses valeurs, lire une valeur. Les classes d'information
//! viennent de `cm::info` ; ce qui ne tient pas dans le tampon de l'appelant
//! suit la règle d'XP ([`return_variable`]).

use abi::ntstatus::{
    NtStatus, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_NO_MORE_ENTRIES, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_SUCCESS,
};
use abi::registry::{KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE};
use alloc::sync::Arc;
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, Object};

use super::object::{capture_attributes, capture_unicode_string};

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
