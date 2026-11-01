//! Les services d'Io sur les fichiers : ouvrir ou créer un fichier ou un
//! répertoire par son nom (NtCreateFile, NtOpenFile), lire ses attributs sans
//! l'ouvrir (NtQueryAttributesFile, NtQueryFullAttributesFile), le lire et
//! l'écrire (NtReadFile, NtWriteFile ; NtFlushBuffersFile vide le cache du
//! disque), le décrire et le
//! changer (NtQueryInformationFile, NtSetInformationFile), décrire son volume
//! (NtQueryVolumeInformationFile).
//!
//! Ob trouve le fichier (la procédure *parse* du volume, `io_manager`), puis
//! `io_manager::check_open` fait ce que ferait le pilote du système de
//! fichiers (disposition, options) ; un nom absent se crée dans son
//! répertoire, qu'Ob trouve de la même façon. Les E/S sont synchrones : les
//! données passent par des tampons du noyau, 64 Kio à la fois, et la
//! position d'un fichier synchrone (`FILE_SYNCHRONOUS_IO_*`) avance avec
//! elles.
//!
//! Pas encore : les attributs étendus (`STATUS_EAS_NOT_SUPPORTED`), le
//! partage, les E/S asynchrones (un événement ou une APC de fin :
//! `STATUS_NOT_IMPLEMENTED`, journalisé une fois), la suppression.

use abi::file::{
    FileBasicInformation, FileFsDeviceInformation, FileNetworkOpenInformation, FilePositionInformation,
    FileStandardInformation, IoStatusBlock32, FILE_BASIC_INFORMATION, FILE_DIRECTORY_FILE, FILE_FS_DEVICE_INFORMATION,
    FILE_FS_MAXIMUM_INFORMATION, FILE_MAXIMUM_DISPOSITION, FILE_NETWORK_OPEN_INFORMATION, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_POSITION_INFORMATION, FILE_READ_ATTRIBUTES, FILE_SHARE_VALID_FLAGS, FILE_STANDARD_INFORMATION,
    FILE_VALID_OPTION_FLAGS,
};
use abi::file::{
    FILE_APPEND_DATA, FILE_CREATED, FILE_END_OF_FILE_INFORMATION, FILE_READ_DATA, FILE_USE_FILE_POINTER_POSITION,
    FILE_WRITE_DATA, FILE_WRITE_TO_END_OF_FILE,
};
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_DISK_FULL, STATUS_EAS_NOT_SUPPORTED, STATUS_END_OF_FILE,
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_TYPE_MISMATCH,
    STATUS_SUCCESS,
};
use abi::object::OBJ_INHERIT;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};
use io_manager::{File, FILE_TYPE};
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, HandleAttributes, Object};

use super::object::{capture_attributes, give_handle};

/// Les classes demandées sans être implémentées.
static FILE_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryInformationFile");
static VOLUME_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryVolumeInformationFile");

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
    /// `FILE_ATTRIBUTE_*` d'un fichier créé.
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    ea_length: u32,
}

/// Le répertoire d'un nom, son `\` final compris (`\??\C:\` pour la
/// racine), et son dernier composant ; un nom sans `\` est relatif.
fn split_last(name: &str) -> (&str, &str) {
    match name.rfind('\\') {
        Some(at) => (&name[..=at], &name[at + 1..]),
        None => ("", name),
    }
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
    let captured = capture_attributes(attributes)?;
    let attributes = captured.attributes;
    let name = captured.name.unwrap_or_default();
    let root = captured.root.as_ref();
    let namespace = ob::namespace();
    let granted = FILE_TYPE.granted_access(AccessMask(open.desired));
    let (file, information) = match namespace.open(&name, root, Some(&FILE_TYPE), attributes) {
        Ok(object) => {
            let file = ob::downcast::<File>(&object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
            let information = io_manager::check_open(&file, open.disposition, open.options, granted)?;
            (file, information)
        }
        Err(STATUS_OBJECT_NAME_NOT_FOUND) if io_manager::creates(open.disposition) => {
            io_manager::check_disposition(open.disposition, open.options)?;
            let (directory, last) = split_last(&name);
            if last.is_empty() {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            // The directory exists: without it, the name's own lookup would
            // have found its path missing (STATUS_OBJECT_PATH_NOT_FOUND).
            let directory = namespace.open(directory, root, Some(&FILE_TYPE), attributes)?;
            let directory = ob::downcast::<File>(&directory).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
            let as_directory = open.options & FILE_DIRECTORY_FILE != 0;
            (directory.create_child(last, as_directory, open.file_attributes)?, FILE_CREATED)
        }
        Err(status) => return Err(status),
    };
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
/// répertoire que désignent les attributs, ouvert, écrasé ou créé selon la
/// disposition (`FILE_CREATED` pour un nom absent, dans un répertoire qui
/// existe : `STATUS_OBJECT_PATH_NOT_FOUND` sinon).
pub(super) fn nt_create_file(arguments: &[u32]) -> NtStatus {
    let [out, desired, attributes, iosb, _allocation, file_attributes, share, disposition, options, _ea, ea_length] =
        arguments[..11]
    else {
        unreachable!("11 arguments")
    };
    status(create_file(
        out,
        attributes,
        iosb,
        Open { desired, file_attributes, share, disposition, options, ea_length },
    ))
}

/// NtOpenFile(*FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
/// ShareAccess, OpenOptions) : NtCreateFile avec `FILE_OPEN`.
pub(super) fn nt_open_file(arguments: &[u32]) -> NtStatus {
    let [out, desired, attributes, iosb, share, options] = arguments[..6] else { unreachable!("6 arguments") };
    let open = Open { desired, file_attributes: 0, share, disposition: FILE_OPEN, options, ea_length: 0 };
    status(create_file(out, attributes, iosb, open))
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
            .and_then(|(file, _)| write_information(&file.basic_information()?.to_bytes(), arguments[1])),
    )
}

/// NtQueryFullAttributesFile(ObjectAttributes, *FileInformation) : sa
/// FILE_NETWORK_OPEN_INFORMATION.
pub(super) fn nt_query_full_attributes_file(arguments: &[u32]) -> NtStatus {
    status(
        open_by_attributes(arguments[0])
            .and_then(|(file, _)| write_information(&file.network_open_information()?.to_bytes(), arguments[1])),
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
        FILE_BASIC_INFORMATION => file.basic_information()?.to_bytes().into(),
        FILE_STANDARD_INFORMATION => file.standard_information()?.to_bytes().into(),
        FILE_POSITION_INFORMATION => FilePositionInformation { current_byte_offset: file.position() }.to_bytes().into(),
        _ => file.network_open_information()?.to_bytes().into(),
    };
    let block = IoStatusBlock32 { status: STATUS_SUCCESS.0, information: information.len() as u32 };
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    write_information(&information, buffer)?;
    ke::usermem::copy_to_user(u64::from(iosb), &block.to_bytes())
}

/// NtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation,
/// Length, FsInformationClass) : FileFsDeviceInformation, que le
/// gestionnaire d'E/S rend lui-même, sans droit particulier.
/// `STATUS_INFO_LENGTH_MISMATCH` sous la taille de la classe.
pub(super) fn nt_query_volume_information_file(arguments: &[u32]) -> NtStatus {
    status(query_volume_information_file(arguments))
}

fn query_volume_information_file(arguments: &[u32]) -> Result<(), NtStatus> {
    let [handle, iosb, buffer, length, class] = arguments[..5] else { unreachable!("5 arguments") };
    if class == 0 || class >= FILE_FS_MAXIMUM_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    if class != FILE_FS_DEVICE_INFORMATION {
        return Err(VOLUME_CLASSES.report(class));
    }
    if (length as usize) < size_of::<FileFsDeviceInformation>() {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let file =
        super::current_process().handle_table.reference_as::<File>(Handle(handle), &FILE_TYPE, AccessMask::NONE)?;
    let information = file.device_information().to_bytes();
    let block = IoStatusBlock32 { status: STATUS_SUCCESS.0, information: information.len() as u32 };
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    write_information(&information, buffer)?;
    ke::usermem::copy_to_user(u64::from(iosb), &block.to_bytes())
}

/// Les données d'un appel passent par des tampons de cette taille.
const CHUNK: usize = 64 << 10;

/// Une E/S asynchrone a déjà été demandée.
static ASYNC_REPORTED: AtomicBool = AtomicBool::new(false);

/// Le bloc d'état `block` en `iosb`.
fn write_iosb(iosb: u32, status: NtStatus, information: u32) -> Result<(), NtStatus> {
    let block = IoStatusBlock32 { status: status.0, information };
    ke::usermem::copy_to_user(u64::from(iosb), &block.to_bytes())
}

/// NtReadFile et NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
/// IoStatusBlock, Buffer, Length, ByteOffset, Key) : la position vient de
/// `ByteOffset`, ou de celle du fichier s'il est synchrone (sans
/// `ByteOffset`, ou `FILE_USE_FILE_POINTER_POSITION`) ;
/// `FILE_WRITE_TO_END_OF_FILE` écrit à la fin.
fn transfer(arguments: &[u32], write: bool) -> Result<(), NtStatus> {
    let [handle, event, apc_routine, _apc_context, iosb, buffer, length, byte_offset, _key] = arguments[..9] else {
        unreachable!("9 arguments")
    };
    if event != 0 || apc_routine != 0 {
        if !ASYNC_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtReadFile/NtWriteFile with an event or an APC is not implemented");
        }
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let table = &super::current_process().handle_table;
    let file = table.reference_as::<File>(Handle(handle), &FILE_TYPE, AccessMask::NONE)?;
    let (granted, _) = table.query(Handle(handle))?;
    if file.is_directory() {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    let requested = match byte_offset {
        0 => None,
        at => Some(UserPtr::<u64>::new(at).read()? as i64),
    };
    let synchronous = file.is_synchronous();
    let offset = match requested {
        None | Some(FILE_USE_FILE_POINTER_POSITION) if synchronous => file.position(),
        Some(FILE_WRITE_TO_END_OF_FILE) if write => u64::from(file.node()?.size),
        Some(offset) if offset >= 0 => offset as u64,
        _ => return Err(STATUS_INVALID_PARAMETER),
    };
    let needed = match (write, requested) {
        (true, Some(FILE_WRITE_TO_END_OF_FILE)) => FILE_WRITE_DATA | FILE_APPEND_DATA,
        (true, _) => FILE_WRITE_DATA,
        (false, _) => FILE_READ_DATA,
    };
    if !granted.intersects(AccessMask(needed)) {
        return Err(STATUS_ACCESS_DENIED);
    }
    let length = length as usize;
    if write {
        ke::usermem::probe_for_read(u64::from(buffer), length, 1)?;
    } else {
        ke::usermem::probe_for_write(u64::from(buffer), length, 1)?;
        if length > 0 && offset >= u64::from(file.node()?.size) {
            write_iosb(iosb, STATUS_END_OF_FILE, 0)?;
            return Err(STATUS_END_OF_FILE);
        }
    }
    let mut done = 0usize;
    let mut chunk = alloc::vec![0u8; length.min(CHUNK)];
    while done < length {
        let take = (length - done).min(CHUNK);
        let at = u64::from(buffer) + done as u64;
        if write {
            ke::usermem::copy_from_user(&mut chunk[..take], at)?;
            file.write(offset + done as u64, &chunk[..take])?;
            done += take;
        } else {
            let read = file.read(offset + done as u64, &mut chunk[..take])?;
            ke::usermem::copy_to_user(at, &chunk[..read])?;
            done += read;
            if read < take {
                break;
            }
        }
    }
    if synchronous {
        file.set_position(offset + done as u64);
    }
    write_iosb(iosb, STATUS_SUCCESS, done as u32)
}

/// NtReadFile : lit au plus `Length` octets (`FILE_READ_DATA`) ;
/// `STATUS_END_OF_FILE` à la fin, le bloc d'état écrit.
pub(super) fn nt_read_file(arguments: &[u32]) -> NtStatus {
    status(transfer(arguments, false))
}

/// NtWriteFile : écrit `Length` octets (`FILE_WRITE_DATA`, ou
/// `FILE_APPEND_DATA` à la fin), le fichier grandit pour les tenir.
pub(super) fn nt_write_file(arguments: &[u32]) -> NtStatus {
    status(transfer(arguments, true))
}

/// NtFlushBuffersFile(FileHandle, IoStatusBlock) : chaque écriture va droit
/// au périphérique, qui vide son cache (FLUSH CACHE d'un disque ATA) ; le
/// bloc d'état est écrit.
pub(super) fn nt_flush_buffers_file(arguments: &[u32]) -> NtStatus {
    status((|| {
        let file = super::current_process().handle_table.reference_as::<File>(
            Handle(arguments[0]),
            &FILE_TYPE,
            AccessMask::NONE,
        )?;
        ke::usermem::probe_for_write(u64::from(arguments[1]), size_of::<IoStatusBlock32>(), 4)?;
        file.flush()?;
        write_iosb(arguments[1], STATUS_SUCCESS, 0)
    })())
}

/// Les classes de NtSetInformationFile demandées sans être implémentées.
static SET_CLASSES: super::ClassReport = super::ClassReport::new("NtSetInformationFile");

/// NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
/// FileInformationClass) : FilePositionInformation (la position) et
/// FileEndOfFileInformation (la taille, `FILE_WRITE_DATA`).
pub(super) fn nt_set_information_file(arguments: &[u32]) -> NtStatus {
    status(set_information_file(arguments))
}

fn set_information_file(arguments: &[u32]) -> Result<(), NtStatus> {
    let [handle, iosb, buffer, length, class] = arguments[..5] else { unreachable!("5 arguments") };
    if class == 0 || class >= FILE_MAXIMUM_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    let access = match class {
        FILE_POSITION_INFORMATION => 0,
        FILE_END_OF_FILE_INFORMATION => FILE_WRITE_DATA,
        _ => return Err(SET_CLASSES.report(class)),
    };
    if length < 8 {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let file =
        super::current_process().handle_table.reference_as::<File>(Handle(handle), &FILE_TYPE, AccessMask(access))?;
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    let value = UserPtr::<u64>::new(buffer).read()?;
    match class {
        FILE_POSITION_INFORMATION => file.set_position(value),
        _ => {
            if file.is_directory() {
                return Err(STATUS_INVALID_PARAMETER);
            }
            file.set_size(u32::try_from(value).map_err(|_| STATUS_DISK_FULL)?)?;
        }
    }
    write_iosb(iosb, STATUS_SUCCESS, 0)
}
