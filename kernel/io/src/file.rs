//! Les fichiers ouverts (FILE_OBJECT, 02 §5.6) et le type `File`.
//!
//! Un objet `File` naît de la procédure *parse* d'un périphérique qui porte
//! un volume (`device`), ou de la sienne pour un nom relatif à un répertoire
//! ouvert (IopParseFile) : il désigne un fichier ou un répertoire du volume,
//! par son chemin depuis la racine. Il garde la position courante et le mode
//! synchrone (`FILE_SYNCHRONOUS_IO_*`, FO_SYNCHRONOUS_IO).
//!
//! [`check_open`] fait ce que NtCreateFile fait d'un fichier qui existe :
//! disposition (l'écraser, `FILE_OVERWRITE`, `FILE_SUPERSEDE`), répertoire
//! ou non, lecture seule ; [`File::create_child`] crée un fichier ou un
//! répertoire dans un répertoire ouvert, pour un nom absent.
//!
//! Le fichier ouvert garde ce que son entrée disait à l'ouverture, et
//! redemande au volume sa taille (`Volume::current`) : tous les fichiers
//! ouverts sur lui la voient pareil.
//!
//! Pas encore : les IRP (les lectures et les écritures vont droit au volume,
//! synchrones), le partage (IoCheckShareAccess), la suppression,
//! l'ouverture d'un volume comme fichier.
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
    FileBasicInformation, FileNetworkOpenInformation, FileStandardInformation, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_READONLY, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_MAXIMUM_DISPOSITION, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPENED, FILE_OPEN_IF,
    FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_OVERWRITTEN, FILE_SUPERSEDE, FILE_SUPERSEDED, FILE_SYNCHRONOUS_IO_ALERT,
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_DATA,
};
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_FILE_CORRUPT_ERROR, STATUS_FILE_IS_A_DIRECTORY,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
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
    /// Ce que son entrée disait à l'ouverture, et où elle est.
    opened: Node,
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
        let node = self.volume.lookup(&self.opened, name)?;
        Ok(Self::create(self.volume.clone(), self.child_path(name), node))
    }

    fn child_path(&self, name: &str) -> String {
        let name = name.trim_end_matches('\\');
        if self.path == "\\" {
            format!("\\{name}")
        } else {
            format!("{}\\{name}", self.path)
        }
    }

    /// Crée dans ce répertoire le fichier vide (ou, avec `as_directory`, le
    /// répertoire) `name`, avec les attributs `attributes`, et l'ouvre.
    /// Erreurs : celles de `Volume::create`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_child(&self, name: &str, as_directory: bool, attributes: u32) -> Result<Arc<Object<File>>, NtStatus> {
        let node = self.volume.create(&self.opened, name, as_directory, attributes)?;
        Ok(Self::create(self.volume.clone(), self.child_path(name), node))
    }

    fn create(volume: Arc<Volume>, path: String, opened: Node) -> Arc<Object<File>> {
        let file = File { volume, path, opened, synchronous: AtomicBool::new(false), position: AtomicU64::new(0) };
        create_object(&FILE_TYPE, file)
    }

    /// Son chemin depuis la racine de son volume.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Ce qu'il désigne, tel que son entrée le dit maintenant.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn node(&self) -> Result<Node, NtStatus> {
        self.volume.current(&self.opened)
    }

    pub fn is_directory(&self) -> bool {
        self.opened.directory
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

    /// FILE_FS_DEVICE_INFORMATION de son volume.
    pub fn device_information(&self) -> abi::file::FileFsDeviceInformation {
        self.volume.device_information()
    }

    /// FILE_BASIC_INFORMATION.
    pub fn basic_information(&self) -> Result<FileBasicInformation, NtStatus> {
        let node = self.node()?;
        Ok(FileBasicInformation {
            creation_time: node.creation_time,
            last_access_time: node.last_access_time,
            last_write_time: node.last_write_time,
            // FAT has no change time: the last write stands for it.
            change_time: node.last_write_time,
            file_attributes: node.attributes,
        })
    }

    /// La place que `node` occupe : sa taille, au cluster supérieur.
    fn allocation_size(&self, node: &Node) -> u64 {
        u64::from(node.size).next_multiple_of(u64::from(self.volume.cluster_bytes()))
    }

    /// FILE_STANDARD_INFORMATION.
    pub fn standard_information(&self) -> Result<FileStandardInformation, NtStatus> {
        let node = self.node()?;
        Ok(FileStandardInformation {
            allocation_size: self.allocation_size(&node),
            end_of_file: u64::from(node.size),
            number_of_links: 1,
            delete_pending: 0,
            directory: u8::from(node.directory),
        })
    }

    /// FILE_NETWORK_OPEN_INFORMATION.
    pub fn network_open_information(&self) -> Result<FileNetworkOpenInformation, NtStatus> {
        let node = self.node()?;
        let basic = self.basic_information()?;
        Ok(FileNetworkOpenInformation {
            creation_time: basic.creation_time,
            last_access_time: basic.last_access_time,
            last_write_time: basic.last_write_time,
            change_time: basic.change_time,
            allocation_size: self.allocation_size(&node),
            end_of_file: u64::from(node.size),
            file_attributes: basic.file_attributes,
        })
    }

    /// Lit à partir de l'octet `offset` dans `out` (de la mémoire du noyau) ;
    /// rend le nombre d'octets lus, 0 à la fin. `STATUS_INVALID_DEVICE_REQUEST`
    /// pour un répertoire.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn read(&self, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
        if self.opened.directory {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        self.volume.read(&self.opened, offset, out)
    }

    /// Le fichier en entier.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn read_all(&self) -> Result<Vec<u8>, NtStatus> {
        let mut bytes = vec![0u8; self.node()?.size as usize];
        if self.read(0, &mut bytes)? != bytes.len() {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        Ok(bytes)
    }

    /// Écrit `data` (de la mémoire du noyau) à l'octet `offset` ; le fichier
    /// grandit pour le tenir. Erreurs : celles de `Volume::write`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn write(&self, offset: u64, data: &[u8]) -> Result<(), NtStatus> {
        self.volume.write(&self.opened, offset, data).map(|_| ())
    }

    /// Fait atteindre le support à ce qui est écrit sur son volume.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn flush(&self) -> Result<(), NtStatus> {
        self.volume.flush()
    }

    /// Donne au fichier la taille `size`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set_size(&self, size: u32) -> Result<(), NtStatus> {
        self.volume.set_size(&self.opened, size).map(|_| ())
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

/// La disposition `disposition` crée le fichier s'il manque.
pub fn creates(disposition: u32) -> bool {
    matches!(disposition, FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE)
}

/// Vérifie la disposition `disposition` et les options `options` d'une
/// ouverture, avant de chercher le fichier : `STATUS_INVALID_PARAMETER` pour
/// une disposition inconnue, des options contraires, ou
/// `FILE_DIRECTORY_FILE` avec une disposition autre que `FILE_CREATE`,
/// `FILE_OPEN` ou `FILE_OPEN_IF`.
pub fn check_disposition(disposition: u32, options: u32) -> Result<(), NtStatus> {
    let directory_only = options & FILE_DIRECTORY_FILE != 0;
    if disposition > FILE_MAXIMUM_DISPOSITION
        || (directory_only && options & FILE_NON_DIRECTORY_FILE != 0)
        || (directory_only && !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF))
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// Ce que NtCreateFile fait de `file`, qui existe, avec la disposition
/// `disposition`, les options `options` et les droits accordés `granted` :
/// rend l'`Information` de son bloc d'état (`FILE_OPENED`, ou
/// `FILE_OVERWRITTEN` et `FILE_SUPERSEDED` après l'avoir vidé). Erreurs :
/// celles de [`check_disposition`] ; `STATUS_OBJECT_NAME_COLLISION` pour
/// `FILE_CREATE` ; `STATUS_NOT_A_DIRECTORY` et `STATUS_FILE_IS_A_DIRECTORY`
/// (écraser un répertoire aussi) ; `STATUS_ACCESS_DENIED` pour écrire dans un
/// fichier en lecture seule.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn check_open(file: &File, disposition: u32, options: u32, granted: AccessMask) -> Result<u32, NtStatus> {
    check_disposition(disposition, options)?;
    if disposition == FILE_CREATE {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if options & FILE_DIRECTORY_FILE != 0 && !file.is_directory() {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    let overwrite = matches!(disposition, FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE);
    if file.is_directory() && (options & FILE_NON_DIRECTORY_FILE != 0 || overwrite) {
        return Err(STATUS_FILE_IS_A_DIRECTORY);
    }
    let writes = granted.intersects(AccessMask(FILE_WRITE_DATA | FILE_APPEND_DATA)) || overwrite;
    if writes && file.node()?.attributes & FILE_ATTRIBUTE_READONLY != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    match disposition {
        FILE_OPEN | FILE_OPEN_IF => Ok(FILE_OPENED),
        _ => {
            file.set_size(0)?;
            Ok(if disposition == FILE_SUPERSEDE { FILE_SUPERSEDED } else { FILE_OVERWRITTEN })
        }
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
