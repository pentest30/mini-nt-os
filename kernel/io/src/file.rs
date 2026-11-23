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
//! Un répertoire ouvert garde aussi où en est son énumération
//! ([`File::query_directory`], NtQueryDirectoryFile) : l'expression de sa
//! première requête et la place de la prochaine entrée.
//!
//! L'effacement : un objet fichier qui va recevoir son premier handle compte
//! parmi les ouvertures du fichier ([`File::begin_open`]) ; à la
//! fermeture de son dernier handle (la procédure de fermeture du type), il
//! n'y compte plus, et le fichier dont l'effacement est en attente
//! (FileDispositionInformation, [`File::set_delete_pending`], ou
//! FILE_DELETE_ON_CLOSE de cette ouverture) part avec la dernière
//! (`Volume::cleanup`). Une ouverture d'un tel fichier rend
//! `STATUS_DELETE_PENDING` ([`check_open`]).
//!
//! Les verrous de plages d'octets (NtLockFile, NtUnlockFile) sont ceux du
//! FCB (`Volume::lock`, [`crate::file_lock`]) ; un objet fichier les désigne
//! par son adresse ([`File::lock_owner`]), et ils partent avec son dernier
//! handle.
//!
//! Pas encore : les IRP (les lectures et les écritures vont droit au volume,
//! synchrones), le partage (IoCheckShareAccess), le renommage, l'ouverture
//! d'un volume comme fichier.
//!
//! [`FileObject`] est celui de l'ancien chargeur (`syscall.rs`) : ne pas
//! l'étendre.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use abi::file::DirectoryEntry;
use abi::file::{
    FileAttributeTagInformation, FileBasicInformation, FileNetworkOpenInformation, FileStandardInformation,
    FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_ATTRIBUTE_READONLY, FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_MAXIMUM_DISPOSITION, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPENED, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_OVERWRITTEN, FILE_SUPERSEDE,
    FILE_SUPERSEDED, FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_DATA,
};
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_CANNOT_DELETE, STATUS_DELETE_PENDING,
    STATUS_DISK_FULL, STATUS_FILE_CORRUPT_ERROR, STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_NO_MORE_FILES,
    STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_TYPE_MISMATCH,
    STATUS_SUCCESS,
};
use hal::sync::KSpinLock;
use ob::{create_object, downcast, AccessMask, GenericMapping, Object, ObjectRef, ObjectType, Parsed};

use crate::directory;
use crate::file_lock::LockOwner;
use crate::volume::{Listed, Node, Space, Volume, VolumeLabel};

const MUTATION_ACCESS: AccessMask = AccessMask(
    FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | abi::file::FILE_WRITE_ATTRIBUTES
        | abi::file::FILE_WRITE_EA
        | abi::file::FILE_DELETE_CHILD
        | AccessMask::DELETE.0
        | AccessMask::WRITE_DAC.0
        | AccessMask::WRITE_OWNER.0,
);

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

/// Le type `File` : les fichiers et répertoires des volumes ([`File`]) et
/// les objets fichiers des tubes nommés ([`crate::npfs::PipeFile`]).
pub static FILE_TYPE: ObjectType =
    ObjectType::new("File", FILE_ALL_ACCESS_MASK, FILE_GENERIC_MAPPING).with_parse(parse_file).with_close(close_file);

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
    /// Où en est l'énumération d'un répertoire ouvert.
    search: KSpinLock<Search>,
    /// Il compte parmi les ouvertures du fichier : il a reçu un handle, et
    /// son dernier n'est pas encore fermé.
    counted: AtomicBool,
    /// FILE_DELETE_ON_CLOSE (CCB_DELETE_ON_CLOSE) : l'effacement du fichier
    /// est mis en attente à la fermeture de son dernier handle.
    delete_on_close: AtomicBool,
}

/// Où en est l'énumération d'un répertoire ouvert (ce que le CCB d'un pilote
/// de système de fichiers en garde).
#[derive(Default)]
struct Search {
    /// Son expression, en majuscules : celle de la première requête, `*`
    /// sans nom ; `None` avant la première.
    expression: Option<Vec<u16>>,
    /// La place, dans le répertoire, de la première entrée à considérer.
    resume: u32,
}

impl File {
    /// Map generic rights and restrict MAXIMUM_ALLOWED to what this volume
    /// supports. Explicit write requests still fail on read-only volumes.
    /// Insert the returned concrete mask into the handle table, not `desired`.
    /// # IRQL
    /// <= DISPATCH_LEVEL; no allocation or device I/O.
    pub fn granted_access(&self, desired: AccessMask) -> Result<AccessMask, NtStatus> {
        if !self.volume.is_read_only() {
            return Ok(FILE_TYPE.granted_access(desired));
        }
        let explicit = FILE_TYPE.granted_access(desired.without(AccessMask::MAXIMUM_ALLOWED));
        if explicit.intersects(MUTATION_ACCESS) {
            return Err(abi::ntstatus::STATUS_MEDIA_WRITE_PROTECTED);
        }
        Ok(FILE_TYPE.granted_access(desired).without(MUTATION_ACCESS))
    }
    /// Filesystem name and capability bits for NtQueryVolumeInformationFile.
    /// # IRQL
    /// <= DISPATCH_LEVEL; no allocation or device I/O.
    pub fn filesystem_information(&self) -> (&'static str, u32) {
        (self.volume.filesystem_name(), self.volume.filesystem_attributes())
    }
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
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn create_child(&self, name: &str, as_directory: bool, attributes: u32) -> Result<Arc<Object<File>>, NtStatus> {
        let node = self.volume.create(&self.opened, name, as_directory, attributes)?;
        Ok(Self::create(self.volume.clone(), self.child_path(name), node))
    }

    fn create(volume: Arc<Volume>, path: String, opened: Node) -> Arc<Object<File>> {
        let file = File {
            volume,
            path,
            opened,
            synchronous: AtomicBool::new(false),
            position: AtomicU64::new(0),
            search: KSpinLock::new(Search::default()),
            counted: AtomicBool::new(false),
            delete_on_close: AtomicBool::new(false),
        };
        create_object(&FILE_TYPE, file)
    }

    /// Son chemin depuis la racine de son volume.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Ce qu'il désigne, tel que son entrée le dit maintenant.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
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

    /// Le numéro de série et le nom de son volume (FileFsVolumeInformation).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn volume_label(&self) -> Result<VolumeLabel, NtStatus> {
        self.volume.label()
    }

    /// La place de son volume (FileFsSizeInformation,
    /// FileFsFullSizeInformation).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn space(&self) -> Result<Space, NtStatus> {
        self.volume.space()
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

    /// Change ses dates et ses attributs (NtSetInformationFile,
    /// FileBasicInformation) : voir `Volume::set_basic`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn set_basic_information(&self, basic: &FileBasicInformation) -> Result<(), NtStatus> {
        self.volume.set_basic(&self.opened, basic).map(|_| ())
    }

    /// La place que `node` occupe : sa taille, au cluster supérieur.
    fn allocation_size(&self, node: &Node) -> u64 {
        node.size.next_multiple_of(u64::from(self.volume.cluster_bytes()))
    }

    /// FILE_STANDARD_INFORMATION.
    pub fn standard_information(&self) -> Result<FileStandardInformation, NtStatus> {
        let node = self.node()?;
        Ok(FileStandardInformation {
            allocation_size: self.allocation_size(&node),
            end_of_file: node.size,
            number_of_links: 1,
            delete_pending: u8::from(self.volume.delete_pending(&self.opened)),
            directory: u8::from(node.directory),
        })
    }

    /// Il va recevoir un handle (NtCreateFile, NtOpenFile), ouvert avec les
    /// options `options` : il compte parmi les ouvertures du fichier, et
    /// FILE_DELETE_ON_CLOSE est noté. Erreurs : celles de
    /// `Volume::begin_open` (le fichier effacé depuis sa recherche, son
    /// effacement en attente). Une ouverture qui échoue ensuite, avant son
    /// handle, se défait par [`File::abandon_open`].
    ///
    /// # IRQL
    /// PASSIVE_LEVEL; may read the device.
    pub fn begin_open(&self, options: u32) -> Result<(), NtStatus> {
        if self.counted.load(Ordering::Acquire) {
            return Ok(());
        }
        self.volume.begin_open(&self.opened)?;
        self.delete_on_close.store(options & FILE_DELETE_ON_CLOSE != 0, Ordering::Relaxed);
        self.counted.store(true, Ordering::Release);
        Ok(())
    }

    /// L'ouverture comptée par [`File::begin_open`] échoue avant son handle :
    /// elle ne compte plus, sans FILE_DELETE_ON_CLOSE ; si elle retenait un
    /// effacement en attente, il se fait.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL; may write the device.
    pub fn abandon_open(&self) {
        if self.counted.swap(false, Ordering::AcqRel) {
            let _ = self.volume.cleanup(&self.opened, false);
        }
    }

    /// NtSetInformationFile(FileDispositionInformation) : met l'effacement
    /// du fichier en attente (`delete`), ou l'annule ; voir
    /// `Volume::set_delete_pending`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may perform device reads.
    pub fn set_delete_pending(&self, delete: bool) -> Result<(), NtStatus> {
        self.volume.set_delete_pending(&self.opened, delete)
    }

    /// Son dernier handle est fermé (IRP_MJ_CLEANUP) : il ne compte plus
    /// parmi les ouvertures du fichier, qui est effacé s'il était la
    /// dernière et que son effacement est en attente. Une erreur de
    /// l'effacement le laisse en place : il n'y a plus personne pour la
    /// recevoir.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL; may write the device.
    fn cleanup(&self) {
        self.volume.unlock_all(&self.opened, self.object_id());
        if self.counted.swap(false, Ordering::AcqRel) {
            let _ = self.volume.cleanup(&self.opened, self.delete_on_close.load(Ordering::Relaxed));
        }
    }

    /// Ce qui désigne cet objet fichier parmi les propriétaires des verrous :
    /// son adresse, stable tant qu'il vit.
    fn object_id(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }

    /// Le propriétaire d'un verrou pris par cet objet fichier, pour le
    /// processus `process` avec la clé `key`.
    pub fn lock_owner(&self, process: u32, key: u32) -> LockOwner {
        LockOwner { file_object: self.object_id(), process, key }
    }

    /// NtLockFile : verrouille `[offset, offset + length)` (voir
    /// [`crate::file_lock::FileLocks::lock`]) ; un répertoire ne se verrouille
    /// pas (`STATUS_INVALID_PARAMETER`, comme vfatfs).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL; allocates from the non-paged pool.
    pub fn lock(&self, offset: u64, length: u64, exclusive: bool, owner: LockOwner) -> Result<(), NtStatus> {
        if self.opened.directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.volume.lock(&self.opened, offset, length, exclusive, owner)
    }

    /// NtUnlockFile : retire le verrou de `owner` sur exactement cette plage.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn unlock(&self, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        if self.opened.directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.volume.unlock(&self.opened, offset, length, owner)
    }

    /// Une lecture de `length` octets en `offset` par `owner` : les verrous
    /// la permettent-ils ? `STATUS_FILE_LOCK_CONFLICT` sinon.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn check_read(&self, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        self.volume.check_read(&self.opened, offset, length, owner)
    }

    /// Une écriture de `length` octets en `offset` par `owner` : les verrous
    /// la permettent-ils ? `STATUS_FILE_LOCK_CONFLICT` sinon.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn check_write(&self, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        self.volume.check_write(&self.opened, offset, length, owner)
    }

    /// FILE_ATTRIBUTE_TAG_INFORMATION : ses attributs, et l'étiquette 0 :
    /// ni la FAT ni le NTFS en lecture d'Io n'ont de point d'analyse
    /// (FILE_ATTRIBUTE_REPARSE_POINT n'est jamais dans les attributs).
    pub fn attribute_tag_information(&self) -> Result<FileAttributeTagInformation, NtStatus> {
        Ok(FileAttributeTagInformation { file_attributes: self.node()?.attributes, reparse_tag: 0 })
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
            end_of_file: node.size,
            file_attributes: basic.file_attributes,
        })
    }

    /// Lit à partir de l'octet `offset` dans `out` (de la mémoire du noyau) ;
    /// rend le nombre d'octets lus, 0 à la fin. `STATUS_INVALID_DEVICE_REQUEST`
    /// pour un répertoire.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn read(&self, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
        if self.opened.directory {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        self.volume.read(&self.opened, offset, out)
    }

    /// Les noms de ce que tient ce répertoire (`Volume::list`) ;
    /// `STATUS_NOT_A_DIRECTORY` pour un fichier.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn list(&self) -> Result<Vec<String>, NtStatus> {
        self.volume.list(&self.opened)
    }

    /// Énumère ce répertoire (NtQueryDirectoryFile) : les entrées suivantes
    /// qui répondent à son expression, dans un tampon de `length` octets de
    /// la classe `class` (`abi::file::directory_entry_layout`), une seule si
    /// `single`, depuis la première si `restart`. L'expression est
    /// `expression` à la première requête (`*` sans elle, ou vide), et reste
    /// celle-là ensuite ; un nom y répond par son nom long ou par son nom
    /// 8.3. Rend les octets et `STATUS_SUCCESS`, ou `STATUS_BUFFER_OVERFLOW`
    /// si la première entrée est coupée.
    ///
    /// Erreurs : `STATUS_INVALID_PARAMETER` pour un fichier ;
    /// `STATUS_NO_SUCH_FILE` si la première requête ne trouve rien,
    /// `STATUS_NO_MORE_FILES` (un avertissement) si une autre ne trouve plus
    /// rien ; celles du volume.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn query_directory(
        &self,
        class: u32,
        length: usize,
        single: bool,
        expression: Option<&[u16]>,
        restart: bool,
    ) -> Result<(Vec<u8>, NtStatus), NtStatus> {
        if !self.opened.directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let (expression, resume, first) = {
            let mut search = self.search.lock();
            let first = search.expression.is_none();
            if first {
                search.expression = Some(match expression {
                    Some(expression) if !expression.is_empty() => directory::upcase(expression),
                    _ => vec![u16::from(b'*')],
                });
            }
            if restart {
                search.resume = 0;
            }
            (search.expression.clone().unwrap_or_default(), search.resume, first)
        };
        let cluster = u64::from(self.volume.cluster_bytes());
        let entries = self.volume.entries(&self.opened)?;
        let matching: Vec<(&Listed, Vec<u16>, Vec<u16>)> = entries
            .iter()
            .filter(|listed| listed.offset >= resume)
            .map(|listed| {
                let name = listed.name.clone();
                let short = listed.short_name.clone().unwrap_or_default();
                (listed, name, short)
            })
            .filter(|(_, name, short)| {
                directory::is_name_in_expression(&expression, name)
                    || (!short.is_empty() && directory::is_name_in_expression(&expression, short))
            })
            .collect();
        let described = matching.iter().map(|(listed, name, short)| {
            let entry = DirectoryEntry {
                file_index: listed.offset,
                creation_time: listed.creation_time,
                last_access_time: listed.last_access_time,
                last_write_time: listed.last_write_time,
                // FAT has no change time: the last write stands for it.
                change_time: listed.last_write_time,
                end_of_file: listed.size,
                allocation_size: listed.size.next_multiple_of(cluster),
                file_attributes: listed.attributes,
                name,
                short_name: short,
            };
            (listed.offset, entry)
        });
        let filled = directory::fill(class, length, single, described, resume);
        if filled.count == 0 {
            return Err(if first { STATUS_NO_SUCH_FILE } else { STATUS_NO_MORE_FILES });
        }
        self.search.lock().resume = filled.resume;
        Ok((filled.bytes, if filled.overflow { STATUS_BUFFER_OVERFLOW } else { STATUS_SUCCESS }))
    }

    /// Ce qui désigne le contenu du fichier `node` dans les caches des
    /// sections (`crate::section_cache`) ; `None` pour un répertoire ou un
    /// fichier sans identité.
    fn cache_key(&self, node: &Node) -> Option<crate::section_cache::Key> {
        node.identity().filter(|_| !node.directory).map(|identity| crate::section_cache::Key {
            volume: self.volume.cache_id(),
            identity,
            size: node.size,
            first_cluster: node.first_cluster,
        })
    }

    /// Le segment des sections de données du fichier (NtCreateSection, le
    /// `DataSectionObject` de NT) : celui que tient déjà une section du même
    /// fichier inchangé, sinon celui que `create` fait pour un fichier de
    /// cette taille, gardé pour les suivantes (`crate::section_cache::DATA`) ;
    /// celui d'une autre section du même fichier, faite en même temps, s'il
    /// est gardé le premier. Rien n'est lu du fichier.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn data_segment<T: core::any::Any + Send + Sync>(
        &self,
        create: impl FnOnce(u64) -> Result<Arc<T>, NtStatus>,
    ) -> Result<Arc<T>, NtStatus> {
        let node = self.node()?;
        let cache = &crate::section_cache::DATA;
        let key = self.cache_key(&node);
        if let Some(found) = key.as_ref().and_then(|key| cache.lookup(key)) {
            if let Ok(segment) = found.downcast::<T>() {
                return Ok(segment);
            }
        }
        let made_at = cache.generation(self.volume.cache_id());
        let segment = create(node.size)?;
        if let Some(key) = key {
            let shared: Arc<dyn core::any::Any + Send + Sync> = segment.clone();
            if let Ok(kept) = cache.insert(key, &shared, made_at).downcast::<T>() {
                return Ok(kept);
            }
        }
        Ok(segment)
    }

    /// Les octets du fichier pour une section d'image (NtCreateSection), et
    /// la taille du fichier : ceux que tient déjà une section d'image du même
    /// fichier inchangé, sinon son début, que `extent` mesure d'après ses
    /// premiers 64 Kio et la taille du fichier (`mm::section::ImageLayout::extent` :
    /// ses en-têtes et les données de ses sections, pas ce qu'un installeur
    /// y ajoute) ; gardés pour les suivantes (`crate::section_cache::IMAGES`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn image_contents(&self, extent: impl FnOnce(&[u8], u64) -> u64) -> Result<(Arc<[u8]>, u64), NtStatus> {
        const HEAD: u64 = 64 * 1024;
        let node = self.node()?;
        let cache = &crate::section_cache::IMAGES;
        let key = self.cache_key(&node);
        if let Some(bytes) = key.as_ref().and_then(|key| cache.lookup(key)) {
            return Ok((bytes, node.size));
        }
        let read_at = cache.generation(self.volume.cache_id());
        let mut bytes = vec![0u8; node.size.min(HEAD) as usize];
        if self.read(0, &mut bytes)? != bytes.len() {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        let wanted = extent(&bytes, node.size).min(node.size) as usize;
        if wanted > bytes.len() {
            let start = bytes.len();
            bytes.resize(wanted, 0);
            if self.read(start as u64, &mut bytes[start..])? != wanted - start {
                return Err(STATUS_FILE_CORRUPT_ERROR);
            }
        } else {
            bytes.truncate(wanted);
        }
        let bytes: Arc<[u8]> = Arc::from(bytes);
        let bytes = match key {
            Some(key) => cache.insert(key, &bytes, read_at),
            None => bytes,
        };
        Ok((bytes, node.size))
    }

    /// Le fichier en entier.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
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
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn write(&self, offset: u64, data: &[u8]) -> Result<(), NtStatus> {
        self.volume.write(&self.opened, offset, data).map(|_| ())
    }

    /// Fait atteindre le support à ce qui est écrit sur son volume.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn flush(&self) -> Result<(), NtStatus> {
        self.volume.flush()
    }

    /// Donne au fichier la taille `size`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn set_size(&self, size: u32) -> Result<(), NtStatus> {
        self.volume.set_size(&self.opened, size).map(|_| ())
    }

    /// Change la place réservée au fichier (NtSetInformationFile,
    /// FileAllocationInformation ; `SetEndOfFile` la demande après la fin
    /// du fichier, à la même valeur). Sous la fin du fichier, le fichier est
    /// coupé là ; au-dessus, la taille ne change pas, et le volume doit
    /// avoir les clusters qui manquent (`STATUS_DISK_FULL` sinon, et au-delà
    /// de 4 Gio, que la FAT ne tient pas).
    ///
    /// Une réservation au-delà de la fin du fichier n'est pas gardée : la
    /// place que le fichier occupe reste sa taille au cluster supérieur
    /// (FileStandardInformation), et une écriture plus loin cherche ses
    /// clusters à ce moment-là.
    ///
    /// Erreurs : `STATUS_INVALID_PARAMETER` pour un répertoire,
    /// `STATUS_MEDIA_WRITE_PROTECTED` sur un volume en lecture seule ; celles
    /// de `Volume::set_size`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
    pub fn set_allocation_size(&self, allocation: u64) -> Result<(), NtStatus> {
        if self.opened.directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.volume.is_read_only() {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let node = self.node()?;
        if allocation < node.size {
            // Below the end of file: the file is cut there.
            return self.set_size(u32::try_from(allocation).map_err(|_| STATUS_FILE_CORRUPT_ERROR)?);
        }
        if allocation > u64::from(u32::MAX) {
            return Err(STATUS_DISK_FULL);
        }
        let cluster = u64::from(self.volume.cluster_bytes());
        let missing = allocation.div_ceil(cluster).saturating_sub(node.size.div_ceil(cluster));
        if missing > 0 && missing > self.volume.space()?.free_clusters {
            return Err(STATUS_DISK_FULL);
        }
        Ok(())
    }
}

/// La procédure *parse* des fichiers : un nom relatif à un répertoire ouvert.
fn parse_file(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
    if remaining.is_empty() {
        return Ok(Parsed::Object(object.clone()));
    }
    if let Some(pipe) = downcast::<crate::npfs::PipeFile>(object) {
        return pipe.parse_relative(remaining);
    }
    let file = downcast::<File>(object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    let name = remaining.strip_prefix('\\').ok_or(STATUS_OBJECT_NAME_INVALID)?;
    Ok(Parsed::Object(file.open_relative(name)?))
}

/// La procédure de fermeture du type `File` : au dernier handle d'un objet
/// fichier, sa fermeture (IRP_MJ_CLEANUP), de NPFS ou d'un volume.
fn close_file(object: &ObjectRef, handles_left: u32) {
    if handles_left == 0 {
        if let Some(pipe) = downcast::<crate::npfs::PipeFile>(object) {
            pipe.cleanup();
        } else if let Some(file) = downcast::<File>(object) {
            file.cleanup();
        }
    }
}

/// Le répertoire d'un nom à créer et son dernier composant
/// ([`split_last`], NtCreateFile). Comme vfatfs (VfatCreateFile), un `\` final est permis à
/// un répertoire (FILE_DIRECTORY_FILE) : CreateDirectoryW de `kernel32` le
/// garde, et `msi` crée ainsi `C:\WINDOWS\Installer\`. Un fichier ainsi
/// nommé, deux `\` finaux ou un nom vide rendent
/// `STATUS_OBJECT_NAME_INVALID`.
pub fn split_to_create(name: &str, options: u32) -> Result<(&str, &str), NtStatus> {
    let (directory, last) = split_last(name);
    if !last.is_empty() {
        return Ok((directory, last));
    }
    if options & FILE_DIRECTORY_FILE == 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    match split_last(&name[..name.len().saturating_sub(1)]) {
        (directory, last) if !last.is_empty() => Ok((directory, last)),
        _ => Err(STATUS_OBJECT_NAME_INVALID),
    }
}

/// Le répertoire d'un nom, son `\` final compris (`\??\C:\` pour la
/// racine), et son dernier composant ; un nom sans `\` est relatif.
pub fn split_last(name: &str) -> (&str, &str) {
    match name.rfind('\\') {
        Some(at) => (&name[..=at], &name[at + 1..]),
        None => ("", name),
    }
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
/// PASSIVE_LEVEL for filesystem I/O; may allocate and perform device reads.
pub fn check_open(file: &File, disposition: u32, options: u32, granted: AccessMask) -> Result<u32, NtStatus> {
    check_disposition(disposition, options)?;
    if file.volume.delete_pending(&file.opened) {
        return Err(STATUS_DELETE_PENDING);
    }
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
    let mutation = overwrite || granted.intersects(MUTATION_ACCESS);
    if file.volume.is_read_only() && mutation {
        return Err(abi::ntstatus::STATUS_MEDIA_WRITE_PROTECTED);
    }
    if writes && file.node()?.attributes & FILE_ATTRIBUTE_READONLY != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if options & FILE_DELETE_ON_CLOSE != 0 {
        let root = file.opened.identity().is_none();
        delete_on_close_allowed(file.volume.is_read_only(), root, file.node()?.attributes)?;
    }
    match disposition {
        FILE_OPEN | FILE_OPEN_IF => Ok(FILE_OPENED),
        _ => {
            file.set_size(0)?;
            Ok(if disposition == FILE_SUPERSEDE { FILE_SUPERSEDED } else { FILE_OVERWRITTEN })
        }
    }
}

/// FILE_DELETE_ON_CLOSE sur un fichier : `STATUS_MEDIA_WRITE_PROTECTED` sur
/// un volume en lecture seule (NtCreateFile n'y arrive pas : DELETE y est
/// refusé avant), `STATUS_CANNOT_DELETE` pour la racine ou un fichier en
/// lecture seule, comme vfatfs.
pub fn delete_on_close_allowed(read_only_volume: bool, root: bool, attributes: u32) -> Result<(), NtStatus> {
    if read_only_volume {
        return Err(abi::ntstatus::STATUS_MEDIA_WRITE_PROTECTED);
    }
    if root || attributes & FILE_ATTRIBUTE_READONLY != 0 {
        return Err(STATUS_CANNOT_DELETE);
    }
    Ok(())
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

#[cfg(test)]
mod name_tests {
    use super::*;
    use abi::ntstatus::STATUS_OBJECT_NAME_INVALID;

    #[test]
    fn a_trailing_backslash_names_a_directory_to_create_only() {
        // CreateDirectoryW keeps it: msi creates `C:\WINDOWS\Installer\`.
        let installer = r"\??\C:\WINDOWS\Installer\";
        assert_eq!(split_to_create(installer, FILE_DIRECTORY_FILE), Ok((r"\??\C:\WINDOWS\", "Installer")));
        assert_eq!(split_to_create(installer, FILE_NON_DIRECTORY_FILE), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(split_to_create(installer, 0), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(
            split_to_create(r"\??\C:\WINDOWS\Installer\\", FILE_DIRECTORY_FILE),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(split_to_create(r"\", FILE_DIRECTORY_FILE), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(split_to_create(r"\??\C:\a.txt", 0), Ok((r"\??\C:\", "a.txt")));
        assert_eq!(split_to_create("relative", 0), Ok(("", "relative")));
    }
}
