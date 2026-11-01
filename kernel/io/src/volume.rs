//! Les volumes (02 §5.6) : un système de fichiers monté sur un périphérique
//! de blocs, FAT32 pour l'instant (ADR-017), en lecture et en écriture.
//!
//! [`Volume::lookup`] résout un chemin (composants séparés par `\`) depuis
//! un répertoire du volume, sans casse, et rend un [`Node`] : un fichier, ou
//! un répertoire, avec la place de son entrée. Les erreurs sont celles qu'un
//! pilote de système de fichiers d'XP rend à IopParseDevice : composant vide,
//! `.`, `..` ou caractère interdit (`STATUS_OBJECT_NAME_INVALID`), composant
//! intermédiaire absent ou qui n'est pas un répertoire
//! (`STATUS_OBJECT_PATH_NOT_FOUND`), dernier composant absent
//! (`STATUS_OBJECT_NAME_NOT_FOUND`).
//!
//! L'écriture : [`Volume::create`] crée un fichier ou un répertoire,
//! [`Volume::write`] écrit dans un fichier, [`Volume::set_size`] change sa
//! taille ; l'entrée du fichier est réécrite à chaque fois. Un [`Node`] garde
//! la place de son entrée : [`Volume::current`] relit ce qu'elle dit, que
//! tous les fichiers ouverts sur lui voient donc pareil.
//!
//! Un verrou sérialise les opérations du volume : un verrou tournant, tant
//! que le disque est en mémoire (un mutex viendra avec les vrais disques) ;
//! les données passent par des tampons du noyau, jamais par la mémoire
//! utilisateur sous le verrou.
//!
//! Pas encore : les noms longs (VFAT) ; un nom valide que le format 8.3 ne
//! peut pas tenir n'existe donc pas sur le volume, et ne s'y crée pas
//! (`STATUS_OBJECT_NAME_INVALID`). La suppression, le renommage, les dates
//! (les dates de FAT sont en heure locale ; sans fuseau horaire, elles
//! passent pour de l'UTC, et rien ne les écrit encore).

use alloc::boxed::Box;

use abi::file::{
    FileFsDeviceInformation, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FILE_DEVICE_DISK, FILE_DEVICE_IS_MOUNTED,
};
use abi::ntstatus::{
    NtStatus, STATUS_DISK_CORRUPT_ERROR, STATUS_DISK_FULL, STATUS_FILE_CORRUPT_ERROR, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_IO_DEVICE_ERROR, STATUS_MEDIA_WRITE_PROTECTED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_UNRECOGNIZED_VOLUME,
};
use hal::sync::KSpinLock;

use crate::fat::{make_entry, nt_time, short_name, BlockDevice, DirEntry, EntryRef, FatError, FatFile, FatVolume};

/// Un périphérique de blocs que plusieurs threads peuvent lire.
pub type SharedBlockDevice = Box<dyn BlockDevice + Send + Sync>;

/// Un système de fichiers monté.
pub struct Volume {
    fat: FatVolume<SharedBlockDevice>,
    /// Le cluster d'où chercher un cluster libre ; sous lui, tout le volume.
    lock: KSpinLock<u32>,
}

/// Ce que désigne un nom sur un volume : un fichier ou un répertoire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Node {
    pub directory: bool,
    /// `FILE_ATTRIBUTE_*`.
    pub attributes: u32,
    /// En octets ; 0 pour un répertoire.
    pub size: u32,
    /// En 100 ns depuis 1601 ; 0 si FAT ne la connaît pas.
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    first_cluster: u32,
    /// Son entrée ; `None` pour la racine, qui n'en a pas.
    entry: Option<EntryRef>,
}

impl Node {
    fn from_entry(entry: &DirEntry, at: EntryRef) -> Self {
        let directory = entry.attr & 0x10 != 0;
        let attributes = u32::from(entry.attr & 0x37);
        Self {
            directory,
            attributes: if attributes == 0 { FILE_ATTRIBUTE_NORMAL } else { attributes },
            size: if directory { 0 } else { entry.file_size },
            creation_time: nt_time(entry.creation_date, entry.creation_time, entry.creation_tenths),
            last_access_time: nt_time(entry.access_date, 0, 0),
            last_write_time: nt_time(entry.write_date, entry.write_time, 0),
            first_cluster: entry.first_cluster,
            entry: Some(at),
        }
    }
}

/// Les caractères qu'aucun nom de fichier ne peut tenir.
fn is_invalid_character(c: char) -> bool {
    (c as u32) < 0x20 || matches!(c, '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|')
}

/// Un nom qu'un fichier ne peut pas porter.
fn is_invalid_name(name: &str) -> bool {
    name.is_empty() || name == "." || name == ".." || name.chars().any(is_invalid_character)
}

/// Les attributs qu'on donne à un fichier créé.
const SETTABLE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;

impl Volume {
    /// Monte le système de fichiers de `device` ; `STATUS_UNRECOGNIZED_VOLUME`
    /// s'il n'est pas en FAT32.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn mount(device: SharedBlockDevice) -> Result<Self, NtStatus> {
        let fat = FatVolume::mount(device).map_err(|_| STATUS_UNRECOGNIZED_VOLUME)?;
        Ok(Self { fat, lock: KSpinLock::new(2) })
    }

    /// Son répertoire racine.
    pub fn root(&self) -> Node {
        Node {
            directory: true,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            first_cluster: self.fat.root_cluster(),
            ..Node::default()
        }
    }

    /// FILE_FS_DEVICE_INFORMATION : le disque qui le porte, fixe, monté.
    pub fn device_information(&self) -> FileFsDeviceInformation {
        FileFsDeviceInformation { device_type: FILE_DEVICE_DISK, characteristics: FILE_DEVICE_IS_MOUNTED }
    }

    /// La taille d'un cluster, en octets.
    pub fn cluster_bytes(&self) -> u32 {
        self.fat.cluster_bytes()
    }

    /// Ce que désigne `path` depuis le répertoire `from` : des composants
    /// séparés par `\`, sans `\` au début ; un `\` à la fin ne va qu'à un
    /// répertoire. Erreurs : voir le module.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn lookup(&self, from: &Node, path: &str) -> Result<Node, NtStatus> {
        let (path, trailing) = match path.strip_suffix('\\') {
            Some(path) if !path.is_empty() => (path, true),
            _ => (path, false),
        };
        let _guard = self.lock.lock();
        let mut node = *from;
        let mut components = path.split('\\').peekable();
        while let Some(name) = components.next() {
            let last = components.peek().is_none();
            if is_invalid_name(name) {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            let missing = if last { STATUS_OBJECT_NAME_NOT_FOUND } else { STATUS_OBJECT_PATH_NOT_FOUND };
            if !node.directory {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            }
            node = match self.fat.find_entry(node.first_cluster, name) {
                Ok((entry, at)) => Node::from_entry(&entry, at),
                Err(FatError::NotFound | FatError::Unsupported | FatError::PathFormat) => return Err(missing),
                Err(error) => return Err(device_error(error)),
            };
        }
        if trailing && !node.directory {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(node)
    }

    /// Ce que dit maintenant l'entrée de `node`.
    fn current_locked(&self, node: &Node) -> Result<Node, NtStatus> {
        let Some(at) = node.entry else { return Ok(*node) };
        let entry = self.fat.read_entry(at).map_err(device_error)?;
        Ok(Node::from_entry(&DirEntry::parse(&entry), at))
    }

    /// Ce que dit maintenant l'entrée de `node` : sa taille après des
    /// écritures, d'où qu'elles viennent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn current(&self, node: &Node) -> Result<Node, NtStatus> {
        let _guard = self.lock.lock();
        self.current_locked(node)
    }

    /// Lit le fichier `node` à partir de l'octet `offset` dans `out` ; rend
    /// le nombre d'octets lus, 0 à la fin du fichier.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn read(&self, node: &Node, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
        let _guard = self.lock.lock();
        let node = self.current_locked(node)?;
        if node.directory || offset >= u64::from(node.size) {
            return Ok(0);
        }
        let mut file = FatFile { first_cluster: node.first_cluster, file_size: node.size, position: offset as u32 };
        self.fat.read(&mut file, out).map_err(|error| match error {
            // The chain ends before the size.
            FatError::NotFound | FatError::InvalidBpb => STATUS_FILE_CORRUPT_ERROR,
            error => device_error(error),
        })
    }

    /// Écrit `data` à l'octet `offset` du fichier `node`, qui grandit pour
    /// les tenir ; rend ce que dit ensuite son entrée.
    /// `STATUS_INVALID_DEVICE_REQUEST` pour un répertoire, `STATUS_DISK_FULL`
    /// sans place (ou au-delà de 4 Gio), `STATUS_MEDIA_WRITE_PROTECTED` sur un
    /// disque en lecture seule.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn write(&self, node: &Node, offset: u64, data: &[u8]) -> Result<Node, NtStatus> {
        self.change(node, |fat, first, size, hint| fat.write_file(first, size, offset, data, hint))
    }

    /// Donne au fichier `node` la taille `size` (des zéros s'il grandit) ;
    /// rend ce que dit ensuite son entrée. Erreurs : celles de [`write`].
    ///
    /// [`write`]: Self::write
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set_size(&self, node: &Node, size: u32) -> Result<Node, NtStatus> {
        self.change(node, |fat, first, old, hint| fat.set_file_size(first, old, size, hint))
    }

    /// Change la chaîne et la taille du fichier `node` par `change`, puis
    /// réécrit son entrée.
    fn change(
        &self,
        node: &Node,
        change: impl FnOnce(&FatVolume<SharedBlockDevice>, &mut u32, &mut u32, u32) -> Result<(), FatError>,
    ) -> Result<Node, NtStatus> {
        let mut hint = self.lock.lock();
        let node = self.current_locked(node)?;
        let Some(at) = node.entry.filter(|_| !node.directory) else { return Err(STATUS_INVALID_DEVICE_REQUEST) };
        let (mut first, mut size) = (node.first_cluster, node.size);
        let changed = change(&self.fat, &mut first, &mut size, *hint);
        // What `change` did to the chain stays described, even if it failed.
        self.fat.update_entry(at, first, size).map_err(device_error)?;
        changed.map_err(device_error)?;
        *hint = first.max(2);
        self.current_locked(&node)
    }

    /// Fait atteindre le support à ce qui est écrit (le cache du disque).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn flush(&self) -> Result<(), NtStatus> {
        let _guard = self.lock.lock();
        self.fat.flush().map_err(device_error)
    }

    /// Crée dans le répertoire `directory` le fichier vide (ou, avec
    /// `as_directory`, le répertoire) `name`, avec les attributs
    /// `attributes` (lecture seule, caché, système ; archive pour un
    /// fichier). `STATUS_OBJECT_NAME_COLLISION` s'il existe ;
    /// `STATUS_OBJECT_NAME_INVALID` pour un nom interdit ou que le format 8.3
    /// ne tient pas ; `STATUS_OBJECT_PATH_NOT_FOUND` si `directory` n'est pas
    /// un répertoire ; celles de [`write`](Self::write).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(&self, directory: &Node, name: &str, as_directory: bool, attributes: u32) -> Result<Node, NtStatus> {
        if is_invalid_name(name) {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let short = short_name(name).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
        if !directory.directory {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        let mut hint = self.lock.lock();
        match self.fat.find_entry(directory.first_cluster, name) {
            Ok(_) => return Err(STATUS_OBJECT_NAME_COLLISION),
            Err(FatError::NotFound) => {}
            Err(error) => return Err(device_error(error)),
        }
        let at = if as_directory {
            let (cluster, at) =
                self.fat.create_directory(directory.first_cluster, &short, *hint).map_err(device_error)?;
            *hint = cluster + 1;
            at
        } else {
            let attr = (attributes & SETTABLE_ATTRIBUTES) as u8 | FILE_ATTRIBUTE_ARCHIVE as u8;
            self.fat.add_entry(directory.first_cluster, &make_entry(&short, attr, 0, 0), *hint).map_err(device_error)?
        };
        let entry = self.fat.read_entry(at).map_err(device_error)?;
        Ok(Node::from_entry(&DirEntry::parse(&entry), at))
    }
}

fn device_error(error: FatError) -> NtStatus {
    match error {
        FatError::Io => STATUS_IO_DEVICE_ERROR,
        FatError::Full => STATUS_DISK_FULL,
        FatError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FatError::Corrupt => STATUS_FILE_CORRUPT_ERROR,
        _ => STATUS_DISK_CORRUPT_ERROR,
    }
}
