//! Les volumes (02 §5.6) : un système de fichiers monté sur un périphérique
//! de blocs, FAT32 pour l'instant (ADR-017), en lecture seule.
//!
//! [`Volume::lookup`] résout un chemin (composants séparés par `\`) depuis
//! un répertoire du volume, sans casse, et rend un [`Node`] : un fichier, ou
//! un répertoire. Les erreurs sont celles qu'un pilote de système de fichiers
//! d'XP rend à IopParseDevice : composant vide, `.`, `..` ou caractère
//! interdit (`STATUS_OBJECT_NAME_INVALID`), composant intermédiaire absent ou
//! qui n'est pas un répertoire (`STATUS_OBJECT_PATH_NOT_FOUND`), dernier
//! composant absent (`STATUS_OBJECT_NAME_NOT_FOUND`).
//!
//! Pas encore : les noms longs (VFAT) ; un nom valide que le format 8.3 ne
//! peut pas tenir n'existe donc pas sur le volume. L'écriture viendra avec
//! le FAT32 en écriture (M4, ADR-017). Les dates de FAT sont en heure
//! locale ; sans fuseau horaire, elles passent pour de l'UTC.

use alloc::boxed::Box;

use abi::file::{
    FileFsDeviceInformation, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_DEVICE_DISK, FILE_DEVICE_IS_MOUNTED,
};
use abi::ntstatus::{
    NtStatus, STATUS_DISK_CORRUPT_ERROR, STATUS_FILE_CORRUPT_ERROR, STATUS_IO_DEVICE_ERROR, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_UNRECOGNIZED_VOLUME,
};

use crate::fat::{nt_time, BlockDevice, DirEntry, FatError, FatFile, FatVolume};

/// Un périphérique de blocs que plusieurs threads peuvent lire.
pub type SharedBlockDevice = Box<dyn BlockDevice + Send + Sync>;

/// Un système de fichiers monté.
pub struct Volume {
    fat: FatVolume<SharedBlockDevice>,
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
}

impl Node {
    fn from_entry(entry: &DirEntry) -> Self {
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
        }
    }
}

/// Les caractères qu'aucun nom de fichier ne peut tenir.
fn is_invalid_character(c: char) -> bool {
    (c as u32) < 0x20 || matches!(c, '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|')
}

impl Volume {
    /// Monte le système de fichiers de `device` ; `STATUS_UNRECOGNIZED_VOLUME`
    /// s'il n'est pas en FAT32.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn mount(device: SharedBlockDevice) -> Result<Self, NtStatus> {
        let fat = FatVolume::mount(device).map_err(|_| STATUS_UNRECOGNIZED_VOLUME)?;
        Ok(Self { fat })
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
    /// PASSIVE_LEVEL.
    pub fn lookup(&self, from: &Node, path: &str) -> Result<Node, NtStatus> {
        let (path, trailing) = match path.strip_suffix('\\') {
            Some(path) if !path.is_empty() => (path, true),
            _ => (path, false),
        };
        let mut node = *from;
        let mut components = path.split('\\').peekable();
        while let Some(name) = components.next() {
            let last = components.peek().is_none();
            if name.is_empty() || name == "." || name == ".." || name.chars().any(is_invalid_character) {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            let missing = if last { STATUS_OBJECT_NAME_NOT_FOUND } else { STATUS_OBJECT_PATH_NOT_FOUND };
            if !node.directory {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            }
            node = match self.fat.find_in_dir(node.first_cluster, name) {
                Ok(entry) => Node::from_entry(&entry),
                Err(FatError::NotFound | FatError::Unsupported | FatError::PathFormat) => return Err(missing),
                Err(error) => return Err(device_error(error)),
            };
        }
        if trailing && !node.directory {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(node)
    }

    /// Lit le fichier `node` à partir de l'octet `offset` dans `out` ; rend
    /// le nombre d'octets lus, 0 à la fin du fichier.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn read(&self, node: &Node, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
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
}

fn device_error(error: FatError) -> NtStatus {
    match error {
        FatError::Io => STATUS_IO_DEVICE_ERROR,
        _ => STATUS_DISK_CORRUPT_ERROR,
    }
}
