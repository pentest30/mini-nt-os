//! Les fichiers ouverts (FILE_OBJECT, 02 §5.6) et le type `File`.
//!
//! Un objet `File` naît de la procédure *parse* d'un périphérique qui porte
//! un volume (`device`), ou de la sienne pour un nom relatif à un répertoire
//! ouvert (IopParseFile) : il désigne un fichier ou un répertoire du volume,
//! par son chemin depuis la racine. Il garde la position courante et le mode
//! synchrone (`FILE_SYNCHRONOUS_IO_*`, FO_SYNCHRONOUS_IO).
//!
//! [`check_open`] fait ce que NtCreateFile vérifie une fois le fichier
//! trouvé : disposition, répertoire ou non.
//!
//! Pas encore : les IRP (les lectures vont droit au volume, synchrones), le
//! partage (IoCheckShareAccess), la création (le volume est en lecture
//! seule : une disposition qui écrirait rend `STATUS_MEDIA_WRITE_PROTECTED`,
//! et un nom absent `STATUS_OBJECT_NAME_NOT_FOUND`, quelle que soit la
//! disposition), l'ouverture d'un volume comme fichier.
//!
//! [`FileObject`] est celui de l'ancien chargeur (`syscall.rs`) : ne pas
//! l'étendre.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use abi::file::{
    FileBasicInformation, FileNetworkOpenInformation, FileStandardInformation, FILE_ALL_ACCESS, FILE_CREATE,
    FILE_DIRECTORY_FILE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_MAXIMUM_DISPOSITION,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPENED, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_ALERT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use abi::ntstatus::{
    NtStatus, STATUS_FILE_CORRUPT_ERROR, STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_TYPE_MISMATCH,
};
use ob::{create_object, downcast, AccessMask, GenericMapping, Object, ObjectRef, ObjectType, Parsed};

use crate::volume::{Node, Volume};

/// FILE_ALL_ACCESS.
pub const FILE_ALL_ACCESS_MASK: AccessMask = AccessMask(FILE_ALL_ACCESS);

/// La correspondance générique des fichiers et des périphériques
/// (FILE_GENERIC_*).
pub const FILE_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: AccessMask(FILE_GENERIC_READ),
    write: AccessMask(FILE_GENERIC_WRITE),
    execute: AccessMask(FILE_GENERIC_EXECUTE),
    all: FILE_ALL_ACCESS_MASK,
};

/// Le type `File`.
pub static FILE_TYPE: ObjectType =
    ObjectType::new("File", FILE_ALL_ACCESS_MASK, FILE_GENERIC_MAPPING).with_parse(parse_file);

/// Le corps d'un objet `File` ouvert sur un volume.
pub struct File {
    volume: Arc<Volume>,
    /// Son chemin depuis la racine du volume : `\` pour la racine,
    /// `\WINDOWS\system32` pour un répertoire, sans `\` final.
    path: String,
    node: Node,
    /// FO_SYNCHRONOUS_IO.
    synchronous: AtomicBool,
    /// CurrentByteOffset.
    position: AtomicU64,
}

impl File {
    /// Ouvre `path` sur `volume` : `\` pour la racine, `\a\b` en dessous.
    /// Erreurs : celles de [`Volume::lookup`] ; `STATUS_OBJECT_NAME_INVALID`
    /// pour un chemin qui ne commence pas par `\`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn open(volume: &Arc<Volume>, path: &str) -> Result<Arc<Object<File>>, NtStatus> {
        let rest = path.strip_prefix('\\').ok_or(STATUS_OBJECT_NAME_INVALID)?;
        let root = volume.root();
        if rest.is_empty() {
            return Ok(Self::create(volume.clone(), String::from("\\"), root));
        }
        let node = volume.lookup(&root, rest)?;
        Ok(Self::create(volume.clone(), format!("\\{}", rest.trim_end_matches('\\')), node))
    }

    /// Ouvre `name`, relatif à ce répertoire ; `STATUS_OBJECT_PATH_NOT_FOUND`
    /// si ce n'est pas un répertoire.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn open_relative(&self, name: &str) -> Result<Arc<Object<File>>, NtStatus> {
        let node = self.volume.lookup(&self.node, name)?;
        let name = name.trim_end_matches('\\');
        let path = if self.path == "\\" { format!("\\{name}") } else { format!("{}\\{name}", self.path) };
        Ok(Self::create(self.volume.clone(), path, node))
    }

    fn create(volume: Arc<Volume>, path: String, node: Node) -> Arc<Object<File>> {
        let file = File { volume, path, node, synchronous: AtomicBool::new(false), position: AtomicU64::new(0) };
        create_object(&FILE_TYPE, file)
    }

    /// Son chemin depuis la racine de son volume.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Ce qu'il désigne.
    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn is_directory(&self) -> bool {
        self.node.directory
    }

    /// Ses E/S sont synchrones (FO_SYNCHRONOUS_IO).
    pub fn is_synchronous(&self) -> bool {
        self.synchronous.load(Ordering::Relaxed)
    }

    /// Note le mode que donnent les options d'ouverture `options`.
    pub fn set_mode(&self, options: u32) {
        let synchronous = options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0;
        self.synchronous.store(synchronous, Ordering::Relaxed);
    }

    /// Sa position courante.
    pub fn position(&self) -> u64 {
        self.position.load(Ordering::Relaxed)
    }

    pub fn set_position(&self, position: u64) {
        self.position.store(position, Ordering::Relaxed);
    }

    /// FILE_BASIC_INFORMATION.
    pub fn basic_information(&self) -> FileBasicInformation {
        let node = &self.node;
        FileBasicInformation {
            creation_time: node.creation_time,
            last_access_time: node.last_access_time,
            last_write_time: node.last_write_time,
            // FAT has no change time: the last write stands for it.
            change_time: node.last_write_time,
            file_attributes: node.attributes,
        }
    }

    /// La place qu'il occupe : sa taille, au cluster supérieur.
    fn allocation_size(&self) -> u64 {
        u64::from(self.node.size).next_multiple_of(u64::from(self.volume.cluster_bytes()))
    }

    /// FILE_STANDARD_INFORMATION.
    pub fn standard_information(&self) -> FileStandardInformation {
        FileStandardInformation {
            allocation_size: self.allocation_size(),
            end_of_file: u64::from(self.node.size),
            number_of_links: 1,
            delete_pending: 0,
            directory: u8::from(self.node.directory),
        }
    }

    /// FILE_NETWORK_OPEN_INFORMATION.
    pub fn network_open_information(&self) -> FileNetworkOpenInformation {
        let basic = self.basic_information();
        FileNetworkOpenInformation {
            creation_time: basic.creation_time,
            last_access_time: basic.last_access_time,
            last_write_time: basic.last_write_time,
            change_time: basic.change_time,
            allocation_size: self.allocation_size(),
            end_of_file: u64::from(self.node.size),
            file_attributes: basic.file_attributes,
        }
    }

    /// Lit à partir de l'octet `offset` dans `out` ; rend le nombre d'octets
    /// lus, 0 à la fin. `STATUS_INVALID_DEVICE_REQUEST` pour un répertoire.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn read(&self, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
        if self.node.directory {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        self.volume.read(&self.node, offset, out)
    }

    /// Le fichier en entier.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn read_all(&self) -> Result<Vec<u8>, NtStatus> {
        let mut bytes = vec![0u8; self.node.size as usize];
        if self.read(0, &mut bytes)? != bytes.len() {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        Ok(bytes)
    }
}

/// La procédure *parse* des fichiers : un nom relatif à un répertoire ouvert.
fn parse_file(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
    let file = downcast::<File>(object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    if remaining.is_empty() {
        return Ok(Parsed::Object(object.clone()));
    }
    let name = remaining.strip_prefix('\\').ok_or(STATUS_OBJECT_NAME_INVALID)?;
    Ok(Parsed::Object(file.open_relative(name)?))
}

/// Ce que NtCreateFile vérifie une fois `file` trouvé, avec la disposition
/// `disposition` et les options `options` : rend l'`Information` de son bloc
/// d'état (`FILE_OPENED`). `STATUS_INVALID_PARAMETER` pour une disposition
/// inconnue, des options contraires, ou `FILE_DIRECTORY_FILE` avec une
/// disposition autre que `FILE_CREATE`, `FILE_OPEN` ou `FILE_OPEN_IF` ;
/// `STATUS_OBJECT_NAME_COLLISION` pour `FILE_CREATE` ; `STATUS_NOT_A_DIRECTORY`
/// et `STATUS_FILE_IS_A_DIRECTORY` ; `STATUS_MEDIA_WRITE_PROTECTED` pour une
/// disposition qui écrirait.
pub fn check_open(file: &File, disposition: u32, options: u32) -> Result<u32, NtStatus> {
    let directory_only = options & FILE_DIRECTORY_FILE != 0;
    if disposition > FILE_MAXIMUM_DISPOSITION
        || (directory_only && options & FILE_NON_DIRECTORY_FILE != 0)
        || (directory_only && !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF))
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if disposition == FILE_CREATE {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if directory_only && !file.is_directory() {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    if options & FILE_NON_DIRECTORY_FILE != 0 && file.is_directory() {
        return Err(STATUS_FILE_IS_A_DIRECTORY);
    }
    match disposition {
        FILE_OPEN | FILE_OPEN_IF => Ok(FILE_OPENED),
        _ => Err(STATUS_MEDIA_WRITE_PROTECTED),
    }
}

/// Le fichier ouvert de l'ancien chargeur (`syscall.rs`).
pub struct FileObject {
    pub path: String,
    pub current_offset: u64,
    pub flags: u32,
}

impl FileObject {
    pub fn new(path: &str, flags: u32) -> Self {
        Self { path: path.into(), current_offset: 0, flags }
    }
}
