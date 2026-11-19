//! Les volumes (02 §5.6) : un système de fichiers monté sur un périphérique
//! de blocs, FAT32 pour l'instant (ADR-017), en lecture et en écriture.
//!
//! [`FatMount::lookup`] résout un chemin (composants séparés par `\`) depuis
//! un répertoire du volume, sans casse, et rend un [`Node`] : un fichier, ou
//! un répertoire, avec la place de son entrée. Les erreurs sont celles qu'un
//! pilote de système de fichiers d'XP rend à IopParseDevice : composant vide,
//! `.`, `..`, caractère interdit ou plus de 255 unités UTF-16
//! (`STATUS_OBJECT_NAME_INVALID`), composant
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
//! avec ses entrées de nom long (VFAT) et un alias 8.3 unique. Un nom qu'il
//! tient garde sa casse comme vfatfs de ReactOS la garde : tout en
//! majuscules, son entrée 8.3 seule ; une base ou une extension toute en
//! minuscules, les drapeaux de casse de NT de l'entrée 8.3 (octet 12 :
//! 0x08 la base, 0x10 l'extension), qu'Io relit ; une base ou une extension
//! à casse mixte (`Recent`), des entrées de nom long devant son entrée 8.3,
//! le nom en majuscules sans `~N`.
//!
//! [`FatMount::delete`] efface un fichier ou un répertoire vide (son
//! entrée, celles de son nom long, ses clusters), quand le gestionnaire d'E/S
//! ferme le dernier handle d'un fichier dont l'effacement est en attente
//! (`Volume::cleanup`).
//!
//! Pas encore : le renommage ; le dernier accès à la lecture.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use abi::file::{
    FileBasicInformation, FileFsDeviceInformation, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FILE_DEVICE_DISK,
    FILE_DEVICE_IS_MOUNTED,
};
use abi::ntstatus::{
    NtStatus, STATUS_CANNOT_DELETE, STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_CORRUPT_ERROR, STATUS_DISK_FULL,
    STATUS_FILE_CORRUPT_ERROR, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER, STATUS_IO_DEVICE_ERROR,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_UNRECOGNIZED_VOLUME,
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
    /// Son nom, en UTF-16 tel quel (FileFsVolumeInformation le recopie) :
    /// celui de l'entrée de volume de la racine pour FAT, vide sans elle ;
    /// `$VOLUME_NAME` pour NTFS, qui accepte toute suite de 16 bits (un
    /// demi-caractère isolé compris).
    pub label: Vec<u16>,
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
    /// Le nom 8.3 de son entrée (FAT) : de quoi la reconnaître
    /// ([`FatMount::still_names`]).
    pub(crate) short_name: [u8; 11],
    /// Sequenced NTFS identity, absent on FAT nodes.
    pub(crate) reference: Option<ntfs::FileReference>,
}

impl Node {
    /// Ce qui le désigne sur son volume, tant qu'il existe : la place de son
    /// entrée (FAT : son cluster et son rang), ou sa référence (NTFS : son
    /// enregistrement et sa séquence) ; aucune pour la racine.
    pub fn identity(&self) -> Option<u64> {
        match (self.entry, self.reference) {
            (Some(at), _) => Some((u64::from(at.cluster) << 32) | u64::from(at.index)),
            (None, Some(reference)) => {
                Some((u64::from(reference.sequence) << 48) | (reference.record & 0xFFFF_FFFF_FFFF))
            }
            (None, None) => None,
        }
    }

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
            short_name: entry.name,
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
    /// Son nom 8.3 (FILE_BOTH_DIR_INFORMATION.ShortName) : sur FAT, celui de
    /// toute entrée, avec ses drapeaux de casse, `.` et `..` compris, comme
    /// vfatfs de ReactOS le rend ; sur NTFS, le nom DOS apparié à un nom long.
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

/// Un nom qu'un fichier ne peut pas porter : vide, `.`, `..`, un caractère
/// interdit, ou plus long que VFAT ne le tient (255 unités UTF-16).
fn is_invalid_name(name: &str) -> bool {
    name.is_empty()
        || name == "."
        || name == ".."
        || name.chars().any(is_invalid_character)
        || name.encode_utf16().count() > crate::fat::MAX_LONG_NAME_UNITS
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
    /// sans les espaces de la fin ; chaque octet est un caractère de 0 à 255,
    /// comme avant).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn label(&self) -> Result<VolumeLabel, NtStatus> {
        let entries = {
            let _guard = self.lock.lock();
            self.fat.dir_entries(self.fat.root_cluster()).map_err(device_error)?
        };
        let mut label: Vec<u16> = entries
            .iter()
            .find(|entry| entry.attr & 0x08 != 0)
            .map(|entry| entry.raw_name.iter().map(|&byte| u16::from(byte)).collect())
            .unwrap_or_default();
        while label.last() == Some(&u16::from(b' ')) {
            label.pop();
        }
        Ok(VolumeLabel { serial: self.fat.bpb().volume_id, label })
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
    /// volume ; chaque entrée avec son nom 8.3, même sans nom long (vfatfs).
    /// `STATUS_NOT_A_DIRECTORY` pour un fichier.
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
                    // Its 8.3 name: beside a long name, or the name itself.
                    short_name: Some(listed.short_name.as_ref().unwrap_or(&listed.name).encode_utf16().collect()),
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

    /// Efface `node` (le dernier handle d'un fichier dont l'effacement était
    /// en attente) : son entrée et celles de son nom long, puis ses
    /// clusters. `STATUS_CANNOT_DELETE` pour la racine, qui n'a pas
    /// d'entrée ; `STATUS_DIRECTORY_NOT_EMPTY` pour un répertoire qui tient
    /// quelque chose.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn delete(&self, node: &Node) -> Result<(), NtStatus> {
        let _guard = self.lock.lock();
        let node = self.current_locked(node)?;
        let Some(at) = node.entry else { return Err(STATUS_CANNOT_DELETE) };
        if node.directory && !self.fat.is_empty_directory(node.first_cluster).map_err(device_error)? {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        self.fat.delete_entry(at, node.first_cluster).map_err(device_error)
    }

    /// L'entrée de `node` le désigne toujours : ni effacée, ni reprise par un
    /// autre nom ou un fichier d'un autre type depuis que `node` a été lu (la
    /// racine, sans entrée, toujours).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn still_names(&self, node: &Node) -> Result<bool, NtStatus> {
        let Some(at) = node.entry else { return Ok(true) };
        let _guard = self.lock.lock();
        let entry = self.fat.read_entry(at).map_err(device_error)?;
        let directory = entry[11] & 0x10 != 0;
        Ok(entry[0] != 0x00 && entry[0] != 0xE5 && entry[..11] == node.short_name && directory == node.directory)
    }

    /// Le répertoire `node` ne tient rien (ses entrées `.` et `..` seules).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_empty_directory(&self, node: &Node) -> Result<bool, NtStatus> {
        let _guard = self.lock.lock();
        let node = self.current_locked(node)?;
        if !node.directory {
            return Ok(false);
        }
        self.fat.is_empty_directory(node.first_cluster).map_err(device_error)
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

    /// Le passage de l'écrivain paresseux (`crate::lazy_writer`) : si ce
    /// qui est écrit n'a pas tout atteint le support (des secteurs de la FAT
    /// en mémoire, des écritures depuis le dernier vidage du disque), le
    /// vidage, sous le verrou du volume, entre deux opérations ; rend s'il y
    /// en avait un à faire.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn write_behind(&self) -> Result<bool, NtStatus> {
        let _guard = self.lock.lock();
        if !self.fat.is_dirty() {
            return Ok(false);
        }
        self.fat.flush().map_err(device_error)?;
        Ok(true)
    }

    /// Ce qui est écrit n'a pas tout atteint le support.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_dirty(&self) -> bool {
        self.fat.is_dirty()
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
        // Un nom que le format 8.3 tient : son entrée 8.3 seule, avec les
        // drapeaux de casse de NT, ou, à casse mixte, des entrées de nom long
        // devant elle ; sinon ses entrées de nom long (VFAT) et l'entrée 8.3
        // de son alias (`fat::FatVolume::add_entry_long`).
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
