//! Les volumes (02 §5.6) : un système de fichiers monté sur un périphérique
//! de blocs, FAT32 pour l'instant (ADR-017), en lecture et en écriture.
//!
//! [`FatMount::lookup`] résout un chemin (composants séparés par `\`) depuis
//! un répertoire du volume, sans casse, et rend un [`Node`] : un fichier, ou
//! un répertoire, avec la place de son entrée. Les erreurs sont celles qu'un
//! pilote de système de fichiers d'XP rend à IopParseDevice : composant vide,
//! `.`, `..` ou caractère interdit (`STATUS_OBJECT_NAME_INVALID`), composant
//! intermédiaire absent ou qui n'est pas un répertoire
//! (`STATUS_OBJECT_PATH_NOT_FOUND`), dernier composant absent
//! (`STATUS_OBJECT_NAME_NOT_FOUND`).
//!
//! L'écriture : [`FatMount::create`] crée un fichier ou un répertoire,
//! [`FatMount::write`] écrit dans un fichier, [`FatMount::set_size`] change sa
//! taille ; l'entrée du fichier est réécrite à chaque fois. Un [`Node`] garde
//! la place de son entrée : [`FatMount::current`] relit ce qu'elle dit, que
//! tous les fichiers ouverts sur lui voient donc pareil.
//!
//! Un verrou sérialise les opérations du volume : un verrou tournant, tant
//! que le disque est en mémoire (un mutex viendra avec les vrais disques) ;
//! les données passent par des tampons du noyau, jamais par la mémoire
//! utilisateur sous le verrou.
//!
//! Un composant se trouve par son nom 8.3 ou par son nom long (VFAT), sans
//! casse (`fat::FatVolume::find_entry`).
//!
//! Les dates : un fichier créé prend le temps système pour création,
//! dernière écriture et dernier accès ; une écriture ou un changement de
//! taille, pour dernière écriture et dernier accès. Les dates de FAT sont en
//! heure locale ; sans fuseau horaire, elles passent pour de l'UTC.
//!
//! Un nom que le format 8.3 ne tient pas, fichier ou répertoire, se crée
//! avec ses entrées de nom long (VFAT) et un alias 8.3 unique.
//!
//! Pas encore : la suppression, le renommage ; le dernier accès à la
//! lecture.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use abi::file::{
    FileBasicInformation, FileFsDeviceInformation, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FILE_DEVICE_DISK,
    FILE_DEVICE_IS_MOUNTED,
};
use abi::ntstatus::{
    NtStatus, STATUS_DISK_CORRUPT_ERROR, STATUS_DISK_FULL, STATUS_FILE_CORRUPT_ERROR, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_PARAMETER, STATUS_IO_DEVICE_ERROR, STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_UNRECOGNIZED_VOLUME,
};
use hal::sync::KSpinLock;

use crate::fat::{fat_time, nt_time, BlockDevice, DirEntry, EntryRef, FatError, FatFile, FatTime, FatVolume};

/// Un périphérique de blocs que plusieurs threads peuvent lire.
pub type SharedBlockDevice = Box<dyn BlockDevice + Send + Sync>;

/// Un système de fichiers monté.
pub struct FatMount {
    fat: FatVolume<SharedBlockDevice>,
    /// Le cluster d'où chercher un cluster libre ; sous lui, tout le volume.
    lock: KSpinLock<u32>,
    /// Le temps système (KeQuerySystemTime) : la date d'un fichier créé ou
    /// écrit.
    clock: fn() -> u64,
}

/// Ce que dit un volume de lui-même (FileFsVolumeInformation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeLabel {
    /// Son numéro de série (BS_VolID).
    pub serial: u32,
    /// Le nom de son entrée de volume, à la racine ; vide sans elle.
    pub label: String,
}

/// La place d'un volume, en clusters (FileFsSizeInformation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Space {
    pub total_clusters: u64,
    pub free_clusters: u64,
    pub sectors_per_cluster: u32,
    pub bytes_per_sector: u32,
}

/// Ce que désigne un nom sur un volume : un fichier ou un répertoire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Node {
    pub directory: bool,
    /// `FILE_ATTRIBUTE_*`.
    pub attributes: u32,
    /// En octets ; 0 pour un répertoire.
    pub size: u64,
    /// En 100 ns depuis 1601 ; 0 si FAT ne la connaît pas.
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub(crate) first_cluster: u32,
    /// Son entrée ; `None` pour la racine, qui n'en a pas.
    pub(crate) entry: Option<EntryRef>,
    /// Sequenced NTFS identity, absent on FAT nodes.
    pub(crate) reference: Option<ntfs::FileReference>,
}

impl Node {
    /// Ce que dit `entry`, dont l'entrée est en `at` (`None` : une description seule,
    /// qui ne relit rien).
    fn from_entry(entry: &DirEntry, at: Option<EntryRef>) -> Self {
        let directory = entry.attr & 0x10 != 0;
        let attributes = u32::from(entry.attr & 0x37);
        Self {
            directory,
            attributes: if attributes == 0 { FILE_ATTRIBUTE_NORMAL } else { attributes },
            size: if directory { 0 } else { u64::from(entry.file_size) },
            creation_time: nt_time(entry.creation_date, entry.creation_time, entry.creation_tenths),
            last_access_time: nt_time(entry.access_date, 0, 0),
            last_write_time: nt_time(entry.write_date, entry.write_time, 0),
            first_cluster: entry.first_cluster,
            entry: at,
            reference: None,
        }
    }
}

/// Une entrée d'un répertoire, telle que la décrit NtQueryDirectoryFile
/// ([`FatMount::entries`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listed {
    /// Raw UTF-16 long name, or the 8.3 name when no long name exists.
    pub name: Vec<u16>,
    /// Raw UTF-16 DOS alias, when paired with a long name.
    pub short_name: Option<Vec<u16>>,
    /// La place de son entrée dans le répertoire, en octets (`FileIndex`).
    pub offset: u32,
    pub directory: bool,
    /// `FILE_ATTRIBUTE_*`.
    pub attributes: u32,
    /// En octets ; 0 pour un répertoire.
    pub size: u64,
    /// En 100 ns depuis 1601 ; 0 si FAT ne la connaît pas.
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
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

impl FatMount {
    /// Monte le système de fichiers de `device` ; `STATUS_UNRECOGNIZED_VOLUME`
    /// s'il n'est pas en FAT32.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn mount(device: SharedBlockDevice) -> Result<Self, NtStatus> {
        let fat = FatVolume::mount(device).map_err(|_| STATUS_UNRECOGNIZED_VOLUME)?;
        Ok(Self { fat, lock: KSpinLock::new(2), clock: hal::rtc::system_time })
    }

    /// Le même volume, dont `clock` donne le temps système (des tests).
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        Self { clock, ..self }
    }

    /// Maintenant, comme FAT le note ; `None` hors de ses années.
    fn now(&self) -> Option<FatTime> {
        fat_time((self.clock)())
    }

    /// Son numéro de série et son nom (l'entrée de volume de la racine,
    /// sans les espaces de la fin).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn label(&self) -> Result<VolumeLabel, NtStatus> {
        let entries = {
            let _guard = self.lock.lock();
            self.fat.dir_entries(self.fat.root_cluster()).map_err(device_error)?
        };
        let label = entries
            .iter()
            .find(|entry| entry.attr & 0x08 != 0)
            .map(|entry| entry.raw_name.iter().map(|&byte| char::from(byte)).collect::<String>())
            .unwrap_or_default();
        Ok(VolumeLabel { serial: self.fat.bpb().volume_id, label: String::from(label.trim_end_matches(' ')) })
    }

    /// Sa place : ses clusters, dont ceux qui sont libres.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn space(&self) -> Result<Space, NtStatus> {
        let free_clusters = {
            let _guard = self.lock.lock();
            self.fat.free_clusters().map_err(device_error)?
        };
        let bpb = self.fat.bpb();
        Ok(Space {
            total_clusters: u64::from(self.fat.clusters()),
            free_clusters: u64::from(free_clusters),
            sectors_per_cluster: u32::from(bpb.sectors_per_cluster),
            bytes_per_sector: u32::from(bpb.bytes_per_sector),
        })
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
                Ok((entry, at)) => Node::from_entry(&entry, Some(at)),
                Err(FatError::NotFound | FatError::Unsupported | FatError::PathFormat) => return Err(missing),
                Err(error) => return Err(device_error(error)),
            };
        }
        if trailing && !node.directory {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(node)
    }

    /// Les noms des fichiers et des répertoires du répertoire `directory`,
    /// dans l'ordre de leurs entrées : leur nom long s'ils en ont un, sinon
    /// leur nom 8.3 ; ni `.`, ni `..`, ni le nom du volume.
    /// `STATUS_NOT_A_DIRECTORY` pour un fichier.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn list(&self, directory: &Node) -> Result<Vec<String>, NtStatus> {
        if !directory.directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let _guard = self.lock.lock();
        let entries = self.fat.dir_entries(directory.first_cluster).map_err(device_error)?;
        Ok(entries
            .into_iter()
            .filter(|entry| entry.attr & 0x08 == 0 && entry.name != "." && entry.name != "..")
            .map(|entry| entry.name)
            .collect())
    }

    /// Ce que tient le répertoire `directory`, dans l'ordre de ses entrées,
    /// décrit pour NtQueryDirectoryFile : `.` et `..` compris (un
    /// sous-répertoire de FAT les tient ; la racine, non), sans le nom du
    /// volume. `STATUS_NOT_A_DIRECTORY` pour un fichier.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn entries(&self, directory: &Node) -> Result<Vec<Listed>, NtStatus> {
        if !directory.directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let entries = {
            let _guard = self.lock.lock();
            self.fat.dir_entries(directory.first_cluster).map_err(device_error)?
        };
        Ok(entries
            .into_iter()
            .filter(|listed| listed.attr & 0x08 == 0)
            .map(|listed| {
                // What its entry says, as `lookup` would give it.
                let node = Node::from_entry(&listed.entry, None);
                Listed {
                    name: listed.name.encode_utf16().collect(),
                    short_name: listed.short_name.map(|name| name.encode_utf16().collect()),
                    offset: listed.offset,
                    directory: node.directory,
                    attributes: node.attributes,
                    size: node.size,
                    creation_time: node.creation_time,
                    last_access_time: node.last_access_time,
                    last_write_time: node.last_write_time,
                }
            })
            .collect())
    }

    /// Ce que dit maintenant l'entrée de `node`.
    fn current_locked(&self, node: &Node) -> Result<Node, NtStatus> {
        let Some(at) = node.entry else { return Ok(*node) };
        let entry = self.fat.read_entry(at).map_err(device_error)?;
        Ok(Node::from_entry(&DirEntry::parse(&entry), Some(at)))
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
        if node.directory || offset >= node.size {
            return Ok(0);
        }
        let mut file = FatFile {
            first_cluster: node.first_cluster,
            file_size: u32::try_from(node.size).map_err(|_| STATUS_FILE_CORRUPT_ERROR)?,
            position: offset as u32,
        };
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
        let (mut first, mut size) =
            (node.first_cluster, u32::try_from(node.size).map_err(|_| STATUS_FILE_CORRUPT_ERROR)?);
        let changed = change(&self.fat, &mut first, &mut size, *hint);
        // What `change` did to the chain stays described, even if it failed.
        self.fat.update_entry(at, first, size).map_err(device_error)?;
        self.fat.set_times(at, None, self.now()).map_err(device_error)?;
        changed.map_err(device_error)?;
        *hint = first.max(2);
        self.current_locked(&node)
    }

    /// Change ce que NtSetInformationFile(FileBasicInformation) change de
    /// `node` : ses dates (en 100 ns depuis 1601 ; 0 la laisse) de création,
    /// de dernier accès, de dernière écriture (FAT n'a pas de date de
    /// changement), et ses attributs (0 les laisse ; `FILE_ATTRIBUTE_NORMAL`
    /// les efface ; lecture seule, caché, système, archive). Rend ce que dit
    /// ensuite son entrée. `STATUS_INVALID_PARAMETER` pour une date que FAT
    /// ne tient pas (avant 1980, après 2107) ou pour la racine, qui n'a pas
    /// d'entrée.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set_basic(&self, node: &Node, basic: &FileBasicInformation) -> Result<Node, NtStatus> {
        let time = |nt: u64| match nt {
            0 => Ok(None),
            nt => fat_time(nt).map(Some).ok_or(STATUS_INVALID_PARAMETER),
        };
        let (created, accessed, written) =
            (time(basic.creation_time)?, time(basic.last_access_time)?, time(basic.last_write_time)?);
        let attributes = match basic.file_attributes {
            0 => None,
            FILE_ATTRIBUTE_NORMAL => Some(0),
            attributes => Some((attributes & (SETTABLE_ATTRIBUTES | FILE_ATTRIBUTE_ARCHIVE)) as u8),
        };
        let _guard = self.lock.lock();
        let Some(at) = node.entry else { return Err(STATUS_INVALID_PARAMETER) };
        self.fat.set_basic(at, attributes, created, accessed, written).map_err(device_error)?;
        self.current_locked(node)
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
    /// `STATUS_OBJECT_NAME_INVALID` pour un nom interdit ;
    /// `STATUS_OBJECT_PATH_NOT_FOUND` si `directory` n'est pas
    /// un répertoire ; celles de [`write`](Self::write).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(&self, directory: &Node, name: &str, as_directory: bool, attributes: u32) -> Result<Node, NtStatus> {
        if is_invalid_name(name) {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if !directory.directory {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        let mut hint = self.lock.lock();
        match self.fat.find_entry(directory.first_cluster, name) {
            Ok(_) => return Err(STATUS_OBJECT_NAME_COLLISION),
            Err(FatError::NotFound) => {}
            Err(error) => return Err(device_error(error)),
        }
        // Un nom que le format 8.3 tient : son entrée 8.3 seule ; sinon ses
        // entrées de nom long (VFAT) et l'entrée 8.3 de son alias.
        let at = if as_directory {
            let (cluster, at) =
                self.fat.create_directory(directory.first_cluster, name, *hint).map_err(device_error)?;
            *hint = cluster + 1;
            at
        } else {
            let attr = (attributes & SETTABLE_ATTRIBUTES) as u8 | FILE_ATTRIBUTE_ARCHIVE as u8;
            self.fat.add_entry_long(directory.first_cluster, name, attr, *hint).map_err(device_error)?
        };
        self.fat.set_times(at, self.now(), None).map_err(device_error)?;
        let entry = self.fat.read_entry(at).map_err(device_error)?;
        Ok(Node::from_entry(&DirEntry::parse(&entry), Some(at)))
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
