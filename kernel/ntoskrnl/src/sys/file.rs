//! Les services d'Io sur les fichiers : ouvrir un fichier ou un répertoire
//! par son nom (NtCreateFile, NtOpenFile), lire ses attributs sans l'ouvrir
//! (NtQueryAttributesFile, NtQueryFullAttributesFile), décrire un fichier
//! ouvert (NtQueryInformationFile).
//!
//! Ob trouve le fichier (la procédure *parse* du volume, `io_manager`), puis
//! `io_manager::check_open` vérifie la disposition et les options, comme le
//! ferait le pilote du système de fichiers. Le bloc d'état (IO_STATUS_BLOCK)
//! n'est écrit qu'en cas de succès.
//!
//! Pas encore : les attributs étendus (`STATUS_EAS_NOT_SUPPORTED`), la
//! création (le volume est en lecture seule), le partage.

use abi::file::{
    FileBasicInformation, FileNetworkOpenInformation, FilePositionInformation, FileStandardInformation,
    IoStatusBlock32, FILE_BASIC_INFORMATION, FILE_DIRECTORY_FILE, FILE_MAXIMUM_DISPOSITION,
    FILE_NETWORK_OPEN_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_POSITION_INFORMATION, FILE_READ_ATTRIBUTES,
    FILE_SHARE_VALID_FLAGS, FILE_STANDARD_INFORMATION, FILE_VALID_OPTION_FLAGS,
};
use abi::ntstatus::{
    NtStatus, STATUS_EAS_NOT_SUPPORTED, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS,
};
use abi::object::OBJ_INHERIT;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use io_manager::{File, FILE_TYPE};
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, HandleAttributes, Object};

use super::object::{capture_attributes, give_handle};

/// Les classes demandées sans être implémentées.
static FILE_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryInformationFile");

/// FileMaximumInformation d'XP : les classes vont de 1 à 40.
const FILE_MAXIMUM_INFORMATION: u32 = 41;

fn status(result: Result<(), NtStatus>) -> NtStatus {
    result.map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// Le fichier que désignent les attributs en `attributes`.
fn open_by_attributes(attributes: u32) -> Result<(Arc<Object<File>>, u32), NtStatus> {
    let captured = capture_attributes(attributes)?;
    let name = captured.name.unwrap_or_default();
    let object = ob::namespace().open(&name, captured.root.as_ref(), Some(&FILE_TYPE), captured.attributes)?;
    let file = ob::downcast::<File>(&object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    Ok((file, captured.attributes))
}

/// Ce que demande une ouverture (NtCreateFile, NtOpenFile).
struct Open {
    desired: u32,
    share: u32,
    disposition: u32,
    options: u32,
    ea_length: u32,
}

/// IoCreateFile : ouvre le fichier que désignent les attributs en
/// `attributes` selon `open`, met son handle en `out` (0 d'abord) et le bloc
/// d'état en `iosb`.
fn create_file(out: u32, attributes: u32, iosb: u32, open: Open) -> Result<(), NtStatus> {
    let both = FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE;
    if open.options & !FILE_VALID_OPTION_FLAGS != 0
        || open.share & !FILE_SHARE_VALID_FLAGS != 0
        || open.disposition > FILE_MAXIMUM_DISPOSITION
        || open.options & both == both
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if open.ea_length != 0 {
        return Err(STATUS_EAS_NOT_SUPPORTED);
    }
    let out = UserPtr::<u32>::new(out);
    out.write(&0)?;
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    let (file, attributes) = open_by_attributes(attributes)?;
    let information = io_manager::check_open(&file, open.disposition, open.options)?;
    file.set_mode(open.options);
    let process = super::current_process();
    let handle_attributes = HandleAttributes { inherit: attributes & OBJ_INHERIT != 0, protect_from_close: false };
    let handle = process.handle_table.insert(file, AccessMask(open.desired), handle_attributes)?;
    give_handle(&out, handle)?;
    let block = IoStatusBlock32 { status: STATUS_SUCCESS.0, information };
    if let Err(fault) = ke::usermem::copy_to_user(u64::from(iosb), &block.to_bytes()) {
        let _ = process.handle_table.close(handle);
        return Err(fault);
    }
    Ok(())
}

/// NtCreateFile(*FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
/// AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
/// CreateOptions, EaBuffer, EaLength) : un handle sur le fichier ou le
/// répertoire que désignent les attributs, s'il existe.
pub(super) fn nt_create_file(arguments: &[u32]) -> NtStatus {
    let [out, desired, attributes, iosb, _allocation, _file_attributes, share, disposition, options, _ea, ea_length] =
        arguments[..11]
    else {
        unreachable!("11 arguments")
    };
    status(create_file(out, attributes, iosb, Open { desired, share, disposition, options, ea_length }))
}

/// NtOpenFile(*FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
/// ShareAccess, OpenOptions) : NtCreateFile avec `FILE_OPEN`.
pub(super) fn nt_open_file(arguments: &[u32]) -> NtStatus {
    let [out, desired, attributes, iosb, share, options] = arguments[..6] else { unreachable!("6 arguments") };
    status(create_file(out, attributes, iosb, Open { desired, share, disposition: FILE_OPEN, options, ea_length: 0 }))
}

/// Écrit `bytes` en `buffer`, d'au moins leur taille.
fn write_information(bytes: &[u8], buffer: u32) -> Result<(), NtStatus> {
    ke::usermem::probe_for_write(u64::from(buffer), bytes.len(), 4)?;
    ke::usermem::copy_to_user(u64::from(buffer), bytes)
}

/// NtQueryAttributesFile(ObjectAttributes, *FileInformation) : la
/// FILE_BASIC_INFORMATION du fichier que désignent les attributs, sans
/// handle.
pub(super) fn nt_query_attributes_file(arguments: &[u32]) -> NtStatus {
    status(
        open_by_attributes(arguments[0])
            .and_then(|(file, _)| write_information(&file.basic_information().to_bytes(), arguments[1])),
    )
}

/// NtQueryFullAttributesFile(ObjectAttributes, *FileInformation) : sa
/// FILE_NETWORK_OPEN_INFORMATION.
pub(super) fn nt_query_full_attributes_file(arguments: &[u32]) -> NtStatus {
    status(
        open_by_attributes(arguments[0])
            .and_then(|(file, _)| write_information(&file.network_open_information().to_bytes(), arguments[1])),
    )
}

/// NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,
/// Length, FileInformationClass) : FileBasic (`FILE_READ_ATTRIBUTES`),
/// FileStandard, FilePosition ou FileNetworkOpenInformation
/// (`FILE_READ_ATTRIBUTES`). `STATUS_INFO_LENGTH_MISMATCH` sous la taille
/// de la classe.
pub(super) fn nt_query_information_file(arguments: &[u32]) -> NtStatus {
    status(query_information_file(arguments))
}

fn query_information_file(arguments: &[u32]) -> Result<(), NtStatus> {
    let [handle, iosb, buffer, length, class] = arguments[..5] else { unreachable!("5 arguments") };
    if class == 0 || class >= FILE_MAXIMUM_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    // The size and the right of each class, checked in this order, as on XP.
    let (size, access) = match class {
        FILE_BASIC_INFORMATION => (size_of::<FileBasicInformation>(), FILE_READ_ATTRIBUTES),
        FILE_STANDARD_INFORMATION => (size_of::<FileStandardInformation>(), 0),
        FILE_POSITION_INFORMATION => (size_of::<FilePositionInformation>(), 0),
        FILE_NETWORK_OPEN_INFORMATION => (size_of::<FileNetworkOpenInformation>(), FILE_READ_ATTRIBUTES),
        _ => return Err(FILE_CLASSES.report(class)),
    };
    if (length as usize) < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let file =
        super::current_process().handle_table.reference_as::<File>(Handle(handle), &FILE_TYPE, AccessMask(access))?;
    let information: Vec<u8> = match class {
        FILE_BASIC_INFORMATION => file.basic_information().to_bytes().into(),
        FILE_STANDARD_INFORMATION => file.standard_information().to_bytes().into(),
        FILE_POSITION_INFORMATION => FilePositionInformation { current_byte_offset: file.position() }.to_bytes().into(),
        _ => file.network_open_information().to_bytes().into(),
    };
    let block = IoStatusBlock32 { status: STATUS_SUCCESS.0, information: information.len() as u32 };
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    write_information(&information, buffer)?;
    ke::usermem::copy_to_user(u64::from(iosb), &block.to_bytes())
}
