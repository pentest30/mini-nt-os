//! Les services d'Io sur les fichiers : ouvrir ou créer un fichier ou un
//! répertoire par son nom (NtCreateFile, NtOpenFile), lire ses attributs sans
//! l'ouvrir (NtQueryAttributesFile, NtQueryFullAttributesFile), le lire et
//! l'écrire (NtReadFile, NtWriteFile ; NtFlushBuffersFile vide le cache du
//! disque), le décrire et le
//! changer (NtQueryInformationFile, NtSetInformationFile), décrire son volume
//! (NtQueryVolumeInformationFile), énumérer un répertoire
//! (NtQueryDirectoryFile), et demander l'aperçu en lecture seule du plan
//! d'installation (NtDeviceIoControlFile).
//!
//! Ob trouve le fichier (la procédure *parse* du volume, `io_manager`), puis
//! `io_manager::check_open` fait ce que ferait le pilote du système de
//! fichiers (disposition, options) ; un nom absent se crée dans son
//! répertoire, qu'Ob trouve de la même façon. Les E/S sont synchrones : les
//! données passent par des tampons du noyau, 64 Kio à la fois, et la
//! position d'un fichier synchrone (`FILE_SYNCHRONOUS_IO_*`) avance avec
//! elles.
//!
//! Un nom sous `\Device\NamedPipe` ouvre un tube, et les services d'un
//! fichier de tube passent par [`super::pipe`] (NPFS).
//!
//! Pas encore : les attributs étendus (`STATUS_EAS_NOT_SUPPORTED`), le
//! partage, les E/S asynchrones des volumes (un événement ou une APC de fin :
//! `STATUS_NOT_IMPLEMENTED`, journalisé une fois ; celles des tubes sont
//! faites), la suppression.

use abi::file::{
    directory_entry_layout, FILE_APPEND_DATA, FILE_CREATED, FILE_END_OF_FILE_INFORMATION,
    FILE_ID_BOTH_DIRECTORY_INFORMATION, FILE_ID_FULL_DIRECTORY_INFORMATION, FILE_LIST_DIRECTORY, FILE_READ_DATA,
    FILE_USE_FILE_POINTER_POSITION, FILE_WRITE_DATA, FILE_WRITE_TO_END_OF_FILE,
};
use abi::file::{
    FileBasicInformation, FileFsAttributeInformation, FileFsDeviceInformation, FileFsFullSizeInformation,
    FileFsSizeInformation, FileFsVolumeInformation, FileNameInformation, FileNetworkOpenInformation,
    FilePositionInformation, FileStandardInformation, IoStatusBlock32, FILE_BASIC_INFORMATION, FILE_DIRECTORY_FILE,
    FILE_FS_ATTRIBUTE_INFORMATION, FILE_FS_DEVICE_INFORMATION, FILE_FS_FULL_SIZE_INFORMATION,
    FILE_FS_MAXIMUM_INFORMATION, FILE_FS_SIZE_INFORMATION, FILE_FS_VOLUME_INFORMATION, FILE_MAXIMUM_DISPOSITION,
    FILE_NAME_INFORMATION, FILE_NETWORK_OPEN_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_POSITION_INFORMATION, FILE_READ_ATTRIBUTES, FILE_SHARE_VALID_FLAGS, FILE_STANDARD_INFORMATION,
    FILE_VALID_OPTION_FLAGS, FILE_WRITE_ATTRIBUTES,
};
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_DEVICE_BUSY, STATUS_DEVICE_NOT_READY,
    STATUS_DISK_FULL, STATUS_EAS_NOT_SUPPORTED, STATUS_END_OF_FILE, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_IO_DEVICE_ERROR,
    STATUS_NOT_IMPLEMENTED, STATUS_NO_MORE_FILES, STATUS_NO_SUCH_DEVICE, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_TYPE_MISMATCH, STATUS_REVISION_MISMATCH,
    STATUS_SUCCESS,
};
use abi::object::OBJ_INHERIT;
use abi::pipe::{FilePipeInformation, FilePipeLocalInformation, FILE_PIPE_INFORMATION, FILE_PIPE_LOCAL_INFORMATION};
use abi::setup::{
    SetupPrepare, IOCTL_MINO_SETUP_COPY, IOCTL_MINO_SETUP_FORMAT, IOCTL_MINO_SETUP_PREPARE, IOCTL_MINO_SETUP_QUERY,
    SETUP_PREPARE_SIZE, SETUP_PREVIEW_SIZE,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};
use io_manager::{File, FILE_TYPE};
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, HandleAttributes, Object};

use super::object::{capture_attributes, capture_unicode_string, give_handle};

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
            if let Some(pipe) = ob::downcast::<io_manager::PipeFile>(&object) {
                return super::pipe::open(pipe, &out, iosb, open.desired, open.options, attributes);
            }
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
/// FileStandard, FileName (le chemin depuis la racine du volume),
/// FilePosition ou FileNetworkOpenInformation (`FILE_READ_ATTRIBUTES`) ;
/// sur un tube, FileName (`\nom`), FilePipe et FilePipeLocalInformation
/// (`FILE_READ_ATTRIBUTES`, [`super::pipe::query_information`]).
/// `STATUS_INFO_LENGTH_MISMATCH` sous la taille de la classe ; un nom
/// coupé : `STATUS_BUFFER_OVERFLOW`, sa longueur entière dans
/// `FileNameLength`.
pub(super) fn nt_query_information_file(arguments: &[u32]) -> NtStatus {
    query_information_file(arguments).unwrap_or_else(|status| status)
}

/// Le plus grand tampon que remplit une classe de longueur variable : un
/// chemin (`MAX_PATH`), un nom de volume.
const VARIABLE_INFORMATION: usize = 4096;

/// Écrit `information` en `buffer` et le bloc d'état en `iosb` : `status`
/// (un succès ou `STATUS_BUFFER_OVERFLOW`) et la taille écrite.
fn give_information(information: &[u8], status: NtStatus, iosb: u32, buffer: u32) -> Result<NtStatus, NtStatus> {
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    write_information(information, buffer)?;
    write_iosb(iosb, status, information.len() as u32)?;
    Ok(status)
}

/// Les octets de `encoded` (une structure suivie d'un nom, dans `out`), et
/// `STATUS_BUFFER_OVERFLOW` si le nom est coupé.
fn variable(out: &[u8], encoded: Option<(usize, bool)>) -> (Vec<u8>, NtStatus) {
    let (written, cut) = encoded.unwrap_or((0, false));
    (out[..written].to_vec(), if cut { STATUS_BUFFER_OVERFLOW } else { STATUS_SUCCESS })
}

fn query_information_file(arguments: &[u32]) -> Result<NtStatus, NtStatus> {
    let [handle, iosb, buffer, length, class] = arguments[..5] else { unreachable!("5 arguments") };
    if class == 0 || class >= FILE_MAXIMUM_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    // The size and the right of each class, checked in this order, as on XP.
    let (size, access) = match class {
        FILE_BASIC_INFORMATION => (size_of::<FileBasicInformation>(), FILE_READ_ATTRIBUTES),
        FILE_STANDARD_INFORMATION => (size_of::<FileStandardInformation>(), 0),
        FILE_NAME_INFORMATION => (size_of::<FileNameInformation>(), 0),
        FILE_POSITION_INFORMATION => (size_of::<FilePositionInformation>(), 0),
        FILE_NETWORK_OPEN_INFORMATION => (size_of::<FileNetworkOpenInformation>(), FILE_READ_ATTRIBUTES),
        FILE_PIPE_INFORMATION => (size_of::<FilePipeInformation>(), FILE_READ_ATTRIBUTES),
        FILE_PIPE_LOCAL_INFORMATION => (size_of::<FilePipeLocalInformation>(), FILE_READ_ATTRIBUTES),
        _ => return Err(FILE_CLASSES.report(class)),
    };
    if (length as usize) < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    if let Some(pipe) = super::pipe::pipe_file(handle, AccessMask(access))? {
        let (information, status) = match class {
            FILE_NAME_INFORMATION => {
                let name: Vec<u16> = pipe.pipe_name().encode_utf16().collect();
                let mut out = alloc::vec![0u8; (length as usize).min(VARIABLE_INFORMATION)];
                let encoded = FileNameInformation::encode(&name, &mut out);
                variable(&out, encoded)
            }
            _ => (super::pipe::query_information(&pipe, class)?, STATUS_SUCCESS),
        };
        return give_information(&information, status, iosb, buffer);
    }
    if matches!(class, FILE_PIPE_INFORMATION | FILE_PIPE_LOCAL_INFORMATION) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let file =
        super::current_process().handle_table.reference_as::<File>(Handle(handle), &FILE_TYPE, AccessMask(access))?;
    let (information, status): (Vec<u8>, NtStatus) = match class {
        FILE_BASIC_INFORMATION => (file.basic_information()?.to_bytes().into(), STATUS_SUCCESS),
        FILE_STANDARD_INFORMATION => (file.standard_information()?.to_bytes().into(), STATUS_SUCCESS),
        FILE_NAME_INFORMATION => {
            let name: Vec<u16> = file.path().encode_utf16().collect();
            let mut out = alloc::vec![0u8; (length as usize).min(VARIABLE_INFORMATION)];
            let encoded = FileNameInformation::encode(&name, &mut out);
            variable(&out, encoded)
        }
        FILE_POSITION_INFORMATION => {
            (FilePositionInformation { current_byte_offset: file.position() }.to_bytes().into(), STATUS_SUCCESS)
        }
        _ => (file.network_open_information()?.to_bytes().into(), STATUS_SUCCESS),
    };
    give_information(&information, status, iosb, buffer)
}

/// NtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation,
/// Length, FsInformationClass), sans droit particulier :
/// FileFsVolumeInformation (le numéro de série et le nom du volume),
/// FileFsSizeInformation et FileFsFullSizeInformation (ses clusters, dont
/// les libres), FileFsDeviceInformation (que le gestionnaire d'E/S rend
/// lui-même), FileFsAttributeInformation (FAT32 : noms gardés avec leur
/// casse, en Unicode, de 255 caractères au plus) ; d'un tube, seulement
/// FileFsDeviceInformation (FILE_DEVICE_NAMED_PIPE).
/// `STATUS_INFO_LENGTH_MISMATCH` sous la taille de la classe ; un nom coupé :
/// `STATUS_BUFFER_OVERFLOW`, sa longueur entière dans la structure.
pub(super) fn nt_query_volume_information_file(arguments: &[u32]) -> NtStatus {
    query_volume_information_file(arguments).unwrap_or_else(|status| status)
}

/// Le nom du système de fichiers des volumes (FileFsAttributeInformation).

/// La longueur la plus grande d'un composant d'un chemin sur FAT (VFAT).
const MAXIMUM_COMPONENT_LENGTH: u32 = 255;

fn query_volume_information_file(arguments: &[u32]) -> Result<NtStatus, NtStatus> {
    let [handle, iosb, buffer, length, class] = arguments[..5] else { unreachable!("5 arguments") };
    if class == 0 || class >= FILE_FS_MAXIMUM_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    let size = match class {
        FILE_FS_VOLUME_INFORMATION => size_of::<FileFsVolumeInformation>(),
        FILE_FS_SIZE_INFORMATION => size_of::<FileFsSizeInformation>(),
        FILE_FS_DEVICE_INFORMATION => size_of::<FileFsDeviceInformation>(),
        FILE_FS_ATTRIBUTE_INFORMATION => size_of::<FileFsAttributeInformation>(),
        FILE_FS_FULL_SIZE_INFORMATION => size_of::<FileFsFullSizeInformation>(),
        _ => return Err(VOLUME_CLASSES.report(class)),
    };
    if (length as usize) < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    if super::pipe::pipe_file(handle, AccessMask::NONE)?.is_some() {
        if class != FILE_FS_DEVICE_INFORMATION {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        return give_information(&super::pipe::device_information().to_bytes(), STATUS_SUCCESS, iosb, buffer);
    }
    let file =
        super::current_process().handle_table.reference_as::<File>(Handle(handle), &FILE_TYPE, AccessMask::NONE)?;
    let mut out = alloc::vec![0u8; (length as usize).min(VARIABLE_INFORMATION)];
    let (information, status): (Vec<u8>, NtStatus) = match class {
        FILE_FS_VOLUME_INFORMATION => {
            let volume = file.volume_label()?;
            let label: Vec<u16> = volume.label.encode_utf16().collect();
            let fixed = FileFsVolumeInformation { volume_serial_number: volume.serial, ..Default::default() };
            let encoded = fixed.encode(&label, &mut out);
            variable(&out, encoded)
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let (filesystem, attributes) = file.filesystem_information();
            let name: Vec<u16> = filesystem.encode_utf16().collect();
            let fixed = FileFsAttributeInformation {
                file_system_attributes: attributes,
                maximum_component_name_length: MAXIMUM_COMPONENT_LENGTH,
                ..Default::default()
            };
            let encoded = fixed.encode(&name, &mut out);
            variable(&out, encoded)
        }
        FILE_FS_SIZE_INFORMATION => {
            let space = file.space()?;
            let information = FileFsSizeInformation {
                total_allocation_units: space.total_clusters,
                available_allocation_units: space.free_clusters,
                sectors_per_allocation_unit: space.sectors_per_cluster,
                bytes_per_sector: space.bytes_per_sector,
            };
            (information.to_bytes().into(), STATUS_SUCCESS)
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            let space = file.space()?;
            let information = FileFsFullSizeInformation {
                total_allocation_units: space.total_clusters,
                caller_available_allocation_units: space.free_clusters,
                actual_available_allocation_units: space.free_clusters,
                sectors_per_allocation_unit: space.sectors_per_cluster,
                bytes_per_sector: space.bytes_per_sector,
            };
            (information.to_bytes().into(), STATUS_SUCCESS)
        }
        _ => (file.device_information().to_bytes().into(), STATUS_SUCCESS),
    };
    give_information(&information, status, iosb, buffer)
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
/// `STATUS_END_OF_FILE` à la fin, le bloc d'état écrit. Un tube :
/// [`super::pipe::read_write`].
pub(super) fn nt_read_file(arguments: &[u32]) -> NtStatus {
    match super::pipe::pipe_file(arguments[0], AccessMask::NONE) {
        Ok(Some(pipe)) => super::pipe::read_write(pipe, arguments, false),
        _ => status(transfer(arguments, false)),
    }
}

/// NtWriteFile : écrit `Length` octets (`FILE_WRITE_DATA`, ou
/// `FILE_APPEND_DATA` à la fin), le fichier grandit pour les tenir. Un
/// tube : [`super::pipe::read_write`].
pub(super) fn nt_write_file(arguments: &[u32]) -> NtStatus {
    match super::pipe::pipe_file(arguments[0], AccessMask::NONE) {
        Ok(Some(pipe)) => super::pipe::read_write(pipe, arguments, true),
        _ => status(transfer(arguments, true)),
    }
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

/// NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext,
/// IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
/// OutputBuffer, OutputBufferLength). Les contrôles privés de Mino :
/// l'aperçu (`IOCTL_MINO_SETUP_QUERY`) rend l'inventaire sûr et le plan
/// GPT/FAT de l'installateur ; la préparation (`IOCTL_MINO_SETUP_PREPARE`)
/// écrit les tables GPT du plan sur le disque que son jeton décrit, puis
/// les relit pour les vérifier — elle ne formate pas et ne copie rien. Le
/// handle d'un fichier du volume courant sert d'ancrage : l'aperçu exige
/// `FILE_READ_ATTRIBUTES`, la préparation `FILE_WRITE_ATTRIBUTES`, en plus
/// du jeton.
pub(super) fn nt_device_io_control_file(arguments: &[u32]) -> NtStatus {
    status(device_io_control_file(arguments))
}

fn device_io_control_file(arguments: &[u32]) -> Result<(), NtStatus> {
    let [handle, event, apc_routine, _apc_context, iosb, code, input, input_length, output, output_length] =
        arguments[..10]
    else {
        unreachable!("10 arguments")
    };
    if event != 0 || apc_routine != 0 {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    match code {
        IOCTL_MINO_SETUP_QUERY => {
            if input != 0 || input_length != 0 {
                return Err(STATUS_INVALID_DEVICE_REQUEST);
            }
            if (output_length as usize) < SETUP_PREVIEW_SIZE {
                return Err(abi::ntstatus::STATUS_BUFFER_TOO_SMALL);
            }
            ke::usermem::probe_for_write(u64::from(output), SETUP_PREVIEW_SIZE, 4)?;
            let _file = super::current_process().handle_table.reference_as::<File>(
                Handle(handle),
                &FILE_TYPE,
                AccessMask(FILE_READ_ATTRIBUTES),
            )?;
            let bytes = io_manager::install::preview().to_bytes();
            ke::usermem::copy_to_user(u64::from(output), &bytes)?;
            write_iosb(iosb, STATUS_SUCCESS, bytes.len() as u32)
        }
        IOCTL_MINO_SETUP_PREPARE => {
            if (input_length as usize) != SETUP_PREPARE_SIZE || output_length != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            ke::usermem::probe_for_read(u64::from(input), SETUP_PREPARE_SIZE, 4)?;
            let mut request_bytes = [0u8; SETUP_PREPARE_SIZE];
            ke::usermem::copy_from_user(&mut request_bytes, u64::from(input))?;
            // Une autre version du contrat ne se discute pas.
            let request = SetupPrepare::from_bytes(request_bytes).ok_or(STATUS_REVISION_MISMATCH)?;
            let _file = super::current_process().handle_table.reference_as::<File>(
                Handle(handle),
                &FILE_TYPE,
                AccessMask(FILE_WRITE_ATTRIBUTES),
            )?;
            match io_manager::install::prepare(request.disk_number, request.plan_token) {
                Ok(layout) => {
                    let [esp, system] = [layout.partitions().first(), layout.partitions().get(1)];
                    log::info!(
                        "[m4] install: prepare: GPT of disk {} written and re-read (ESP {:?}, system {:?})",
                        request.disk_number,
                        esp.map(|partition| partition.first_lba..=partition.last_lba),
                        system.map(|partition| partition.first_lba..=partition.last_lba)
                    );
                    write_iosb(iosb, STATUS_SUCCESS, 0)
                }
                Err(error) => {
                    log::warn!("[m4] install: prepare refused: {error:?}");
                    Err(prepare_status(error))
                }
            }
        }
        IOCTL_MINO_SETUP_FORMAT => {
            if (input_length as usize) != SETUP_PREPARE_SIZE || output_length != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            ke::usermem::probe_for_read(u64::from(input), SETUP_PREPARE_SIZE, 4)?;
            let mut request_bytes = [0u8; SETUP_PREPARE_SIZE];
            ke::usermem::copy_from_user(&mut request_bytes, u64::from(input))?;
            let request = SetupPrepare::from_bytes(request_bytes).ok_or(STATUS_REVISION_MISMATCH)?;
            let _file = super::current_process().handle_table.reference_as::<File>(
                Handle(handle),
                &FILE_TYPE,
                AccessMask(FILE_WRITE_ATTRIBUTES),
            )?;
            match io_manager::install::format(request.disk_number, request.plan_token) {
                Ok((esp, system)) => {
                    log::info!(
                        "[m4] install: format: ESP {} sectors, system {} sectors, FAT32 mounted by the kernel",
                        esp.total_sectors,
                        system.total_sectors
                    );
                    write_iosb(iosb, STATUS_SUCCESS, 0)
                }
                Err(error) => {
                    log::warn!("[m4] install: format refused: {error:?}");
                    Err(prepare_status(error))
                }
            }
        }
        IOCTL_MINO_SETUP_COPY => {
            if (input_length as usize) != SETUP_PREPARE_SIZE || output_length != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            ke::usermem::probe_for_read(u64::from(input), SETUP_PREPARE_SIZE, 4)?;
            let mut request_bytes = [0u8; SETUP_PREPARE_SIZE];
            ke::usermem::copy_from_user(&mut request_bytes, u64::from(input))?;
            let request = SetupPrepare::from_bytes(request_bytes).ok_or(STATUS_REVISION_MISMATCH)?;
            let _file = super::current_process().handle_table.reference_as::<File>(
                Handle(handle),
                &FILE_TYPE,
                AccessMask(FILE_WRITE_ATTRIBUTES),
            )?;
            match io_manager::install::copy_files(request.disk_number, request.plan_token) {
                Ok(report) => {
                    log::info!(
                        "[m4] install: copy: {} files, {} directories, {} bytes to disk {}",
                        report.files,
                        report.directories,
                        report.bytes,
                        request.disk_number
                    );
                    write_iosb(iosb, STATUS_SUCCESS, 0)
                }
                Err(error) => {
                    log::warn!("[m4] install: copy refused: {error:?}");
                    Err(prepare_status(error))
                }
            }
        }
        _ => Err(STATUS_INVALID_DEVICE_REQUEST),
    }
}

/// Le statut NT de chaque refus de la préparation.
fn prepare_status(error: io_manager::install::PrepareError) -> NtStatus {
    use io_manager::install::PrepareError as Error;
    match error {
        Error::Protected => STATUS_ACCESS_DENIED,
        Error::NoTarget => STATUS_NO_SUCH_DEVICE,
        Error::TokenMismatch => STATUS_REVISION_MISMATCH,
        Error::NotBlank => STATUS_OBJECT_NAME_COLLISION,
        Error::CapacityMismatch => STATUS_INVALID_PARAMETER,
        Error::Busy => STATUS_DEVICE_BUSY,
        Error::NotPrepared => STATUS_DEVICE_NOT_READY,
        Error::Io => STATUS_IO_DEVICE_ERROR,
    }
}

/// Les classes de NtSetInformationFile demandées sans être implémentées.
static SET_CLASSES: super::ClassReport = super::ClassReport::new("NtSetInformationFile");

/// NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length,
/// FileInformationClass) : FileBasicInformation (les dates et les attributs,
/// `FILE_WRITE_ATTRIBUTES` ; 0 laisse un champ comme il est),
/// FilePositionInformation (la position) et FileEndOfFileInformation (la
/// taille, `FILE_WRITE_DATA`) ; FilePipeInformation d'un tube (ses modes,
/// `FILE_WRITE_ATTRIBUTES`).
pub(super) fn nt_set_information_file(arguments: &[u32]) -> NtStatus {
    status(set_information_file(arguments))
}

fn set_information_file(arguments: &[u32]) -> Result<(), NtStatus> {
    let [handle, iosb, buffer, length, class] = arguments[..5] else { unreachable!("5 arguments") };
    if class == 0 || class >= FILE_MAXIMUM_INFORMATION {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    let (size, access) = match class {
        FILE_BASIC_INFORMATION => (size_of::<FileBasicInformation>(), FILE_WRITE_ATTRIBUTES),
        FILE_POSITION_INFORMATION => (size_of::<FilePositionInformation>(), 0),
        FILE_END_OF_FILE_INFORMATION => (8, FILE_WRITE_DATA),
        FILE_PIPE_INFORMATION => (size_of::<FilePipeInformation>(), FILE_WRITE_ATTRIBUTES),
        _ => return Err(SET_CLASSES.report(class)),
    };
    if (length as usize) < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    if let Some(pipe) = super::pipe::pipe_file(handle, AccessMask(access))? {
        if class != FILE_PIPE_INFORMATION {
            return Err(STATUS_INVALID_PARAMETER);
        }
        ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
        let mut bytes = [0u8; size_of::<FilePipeInformation>()];
        ke::usermem::probe_for_read(u64::from(buffer), bytes.len(), 4)?;
        ke::usermem::copy_from_user(&mut bytes, u64::from(buffer))?;
        super::pipe::set_pipe_information(&pipe, &bytes)?;
        return write_iosb(iosb, STATUS_SUCCESS, 0);
    }
    if class == FILE_PIPE_INFORMATION {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let file =
        super::current_process().handle_table.reference_as::<File>(Handle(handle), &FILE_TYPE, AccessMask(access))?;
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    match class {
        FILE_BASIC_INFORMATION => {
            let mut bytes = [0u8; size_of::<FileBasicInformation>()];
            ke::usermem::probe_for_read(u64::from(buffer), bytes.len(), 8)?;
            ke::usermem::copy_from_user(&mut bytes, u64::from(buffer))?;
            file.set_basic_information(&FileBasicInformation::from_bytes(&bytes))?;
        }
        FILE_POSITION_INFORMATION => file.set_position(UserPtr::<u64>::new(buffer).read()?),
        _ => {
            let value = UserPtr::<u64>::new(buffer).read()?;
            if file.is_directory() {
                return Err(STATUS_INVALID_PARAMETER);
            }
            file.set_size(u32::try_from(value).map_err(|_| STATUS_DISK_FULL)?)?;
        }
    }
    write_iosb(iosb, STATUS_SUCCESS, 0)
}

/// Les classes de NtQueryDirectoryFile demandées sans être implémentées.
static DIRECTORY_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryDirectoryFile");

/// NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
/// IoStatusBlock, FileInformation, Length, FileInformationClass,
/// ReturnSingleEntry, FileName, RestartScan) : les entrées suivantes du
/// répertoire ouvert (`FILE_LIST_DIRECTORY`) qui répondent à l'expression de
/// sa première requête (`io_manager::File::query_directory`), en
/// FileDirectory, FileFullDirectory, FileBothDirectory ou FileNamesInformation.
///
/// Comme le gestionnaire d'E/S d'XP : le bloc d'état et le tampon sondés et
/// le nom capturé d'abord, puis `STATUS_INFO_LENGTH_MISMATCH` sous la taille
/// de la classe, puis le handle. Le bloc d'état est écrit pour un succès et
/// pour les avertissements (`STATUS_BUFFER_OVERFLOW`, la première entrée
/// coupée ; `STATUS_NO_MORE_FILES`) ; `STATUS_NO_SUCH_FILE` quand la première
/// requête ne trouve rien, `STATUS_INVALID_PARAMETER` pour un fichier.
/// FileIdBothDirectory et FileIdFullDirectoryInformation (sans identifiants
/// de fichiers sur FAT) : `STATUS_NOT_IMPLEMENTED`, journalisé une fois ;
/// une autre classe : `STATUS_INVALID_INFO_CLASS`. Un événement ou une APC
/// de fin : `STATUS_NOT_IMPLEMENTED`, comme NtReadFile.
pub(super) fn nt_query_directory_file(arguments: &[u32]) -> NtStatus {
    query_directory_file(arguments).unwrap_or_else(|status| status)
}

fn query_directory_file(arguments: &[u32]) -> Result<NtStatus, NtStatus> {
    let [handle, event, apc_routine, _apc_context, iosb, buffer, length, class, single, name, restart] =
        arguments[..11]
    else {
        unreachable!("11 arguments")
    };
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    ke::usermem::probe_for_write(u64::from(buffer), length as usize, 4)?;
    let expression = match name {
        0 => None,
        address => Some(capture_unicode_string(address)?),
    };
    if directory_entry_layout(class).is_some_and(|(_, size)| (length as usize) < size) {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let file = super::current_process().handle_table.reference_as::<File>(
        Handle(handle),
        &FILE_TYPE,
        AccessMask(FILE_LIST_DIRECTORY),
    )?;
    if event != 0 || apc_routine != 0 {
        if !ASYNC_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("sys: NtQueryDirectoryFile with an event or an APC is not implemented");
        }
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    if directory_entry_layout(class).is_none() {
        return Err(match class {
            FILE_ID_BOTH_DIRECTORY_INFORMATION | FILE_ID_FULL_DIRECTORY_INFORMATION => DIRECTORY_CLASSES.report(class),
            _ => STATUS_INVALID_INFO_CLASS,
        });
    }
    // BOOLEANs: their low byte.
    let (single, restart) = (single & 0xFF != 0, restart & 0xFF != 0);
    match file.query_directory(class, length as usize, single, expression.as_deref(), restart) {
        Ok((bytes, status)) => {
            ke::usermem::copy_to_user(u64::from(buffer), &bytes)?;
            write_iosb(iosb, status, bytes.len() as u32)?;
            Ok(status)
        }
        Err(STATUS_NO_MORE_FILES) => {
            write_iosb(iosb, STATUS_NO_MORE_FILES, 0)?;
            Err(STATUS_NO_MORE_FILES)
        }
        Err(status) => Err(status),
    }
}
