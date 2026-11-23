//! Ce que les sections d'un fichier partagent (le rôle des
//! SECTION_OBJECT_POINTERS d'un fichier dans NT) :
//!
//! - [`DATA`] : le segment des sections de données d'un fichier (le
//!   `DataSectionObject` de NT, `mm::section::FileSegment`), qui tient ses
//!   pages lues à la faute ([`crate::File::data_segment`]). Une section de
//!   données du même fichier inchangé reprend le segment : ce qui est lu
//!   pour l'une sert à toutes ; `shell32` ouvre ainsi `shell32.dll`
//!   (11 Mio) comme fichier de données pour chaque icône qu'il extrait ;
//! - [`IMAGES`] : les octets qu'une section d'image a lus du fichier (ses
//!   en-têtes et les données de ses sections, [`crate::File::image_contents`]),
//!   que reprend une autre section d'image du même fichier inchangé : tant
//!   qu'une section les tient (une DLL chargée, une section de `\KnownDlls`),
//!   le fichier n'est lu qu'une fois.
//!
//! Io ne connaît pas Mm : un segment est ici un `dyn Any`, que
//! `ntoskrnl::sys::section` crée et reconnaît.
//!
//! Un fichier est désigné par son volume et son entrée ([`Key`] : la place de
//! son entrée de répertoire sur FAT, sa référence sur NTFS), avec sa taille
//! et son premier cluster au moment où sa section est créée. Le cache ne
//! retient rien lui-même ([`Weak`]) : un segment ou des octets partent avec
//! la dernière section qui les tient. Toute écriture, tout changement de
//! taille et tout effacement d'un fichier ([`invalidate`], par
//! `Volume::write`, `Volume::set_size` et l'effacement) retire ses entrées ;
//! ce qui a été fait pendant qu'un fichier du même volume changeait n'est pas
//! gardé (la génération des écritures de chaque volume, [`Cache::generation`]).
//! Un segment retiré reste à ses sections : les pages qu'il n'a pas encore
//! lues se lisent du fichier tel qu'il est à leur faute (`mm::section`).
//!
//! Pas encore : le renommage de fichiers, que les volumes ne font pas.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use hal::sync::KSpinLock;

/// Ce qui désigne le contenu d'un fichier : son volume (l'adresse de son
/// `Volume`), son identité sur le volume, sa taille et son premier cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub volume: usize,
    pub identity: u64,
    pub size: u64,
    pub first_cluster: u32,
}

struct Entry<T: ?Sized> {
    key: Key,
    content: Weak<T>,
}

struct Inner<T: ?Sized> {
    entries: Vec<Entry<T>>,
    /// Le nombre d'invalidations de chaque volume depuis la création du
    /// cache.
    generations: BTreeMap<usize, u64>,
}

/// Un cache : ce que tiennent des sections, par fichier.
pub struct Cache<T: ?Sized> {
    inner: KSpinLock<Inner<T>>,
}

impl<T: ?Sized> Cache<T> {
    pub const fn new() -> Self {
        Self { inner: KSpinLock::new(Inner { entries: Vec::new(), generations: BTreeMap::new() }) }
    }

    /// Ce que tient encore une section pour le fichier `key`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn lookup(&self, key: &Key) -> Option<Arc<T>> {
        let mut inner = self.inner.lock();
        inner.entries.retain(|entry| entry.content.strong_count() > 0);
        inner.entries.iter().find(|entry| entry.key == *key).and_then(|entry| entry.content.upgrade())
    }

    /// La génération des écritures du volume `volume`, à prendre avant de
    /// lire un fichier ou d'en créer le segment, pour
    /// [`insert`](Self::insert).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn generation(&self, volume: usize) -> u64 {
        self.inner.lock().generations.get(&volume).copied().unwrap_or(0)
    }

    /// `content`, fait pour le fichier `key` depuis la génération `read_at`
    /// de son volume, sert aux sections suivantes, sauf si un fichier du
    /// volume a changé depuis. Rend ce qui sert à la section qui l'a fait :
    /// ce qu'une autre section du même fichier y a mis entre-temps, sous le
    /// même verrou que la recherche (deux NtCreateSection du même fichier,
    /// qui ne l'avaient trouvé ni l'une ni l'autre, prennent le même segment ;
    /// chacune gardait le sien, et des vues partagées de l'une et de l'autre
    /// n'avaient pas les mêmes pages), sinon `content`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn insert(&self, key: Key, content: &Arc<T>, read_at: u64) -> Arc<T> {
        let mut inner = self.inner.lock();
        if inner.generations.get(&key.volume).copied().unwrap_or(0) != read_at {
            return content.clone();
        }
        if let Some(kept) =
            inner.entries.iter().find(|entry| entry.key == key).and_then(|entry| entry.content.upgrade())
        {
            return kept;
        }
        inner.entries.retain(|entry| {
            entry.content.strong_count() > 0 && (entry.key.volume, entry.key.identity) != (key.volume, key.identity)
        });
        inner.entries.push(Entry { key, content: Arc::downgrade(content) });
        content.clone()
    }

    /// Le fichier `identity` du volume `volume` (tous ses fichiers sans
    /// `identity`) change : ce qui en a été fait ne sert plus.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn invalidate(&self, volume: usize, identity: Option<u64>) {
        let mut inner = self.inner.lock();
        *inner.generations.entry(volume).or_insert(0) += 1;
        inner.entries.retain(|entry| {
            entry.key.volume != volume || identity.is_some_and(|identity| entry.key.identity != identity)
        });
    }
}

impl<T: ?Sized> Default for Cache<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Les segments des sections de données des fichiers des volumes montés.
pub static DATA: Cache<dyn Any + Send + Sync> = Cache::new();

/// Les octets des sections d'image des fichiers des volumes montés.
pub static IMAGES: Cache<[u8]> = Cache::new();

/// Le fichier `identity` du volume `volume` (tous ses fichiers sans
/// `identity`) change : ses sections suivantes ne reprennent rien.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn invalidate(volume: usize, identity: Option<u64>) {
    DATA.invalidate(volume, identity);
    IMAGES.invalidate(volume, identity);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(volume: usize, identity: u64, size: u64) -> Key {
        Key { volume, identity, size, first_cluster: 5 }
    }

    #[test]
    fn bytes_serve_while_a_section_holds_them() {
        let cache = Cache::<[u8]>::new();
        let bytes: Arc<[u8]> = Arc::from(&b"MZ shell32"[..]);
        cache.insert(key(0x1000, 7, 10), &bytes, cache.generation(0x1000));
        let found = cache.lookup(&key(0x1000, 7, 10)).expect("held by a section");
        assert!(Arc::ptr_eq(&found, &bytes), "the same bytes, not a copy");
        assert!(cache.lookup(&key(0x1000, 7, 11)).is_none(), "another size: another content");
        assert!(cache.lookup(&key(0x2000, 7, 10)).is_none(), "another volume");
        drop((found, bytes));
        assert!(cache.lookup(&key(0x1000, 7, 10)).is_none(), "gone with the last section");
    }

    #[test]
    fn a_write_drops_the_file_and_what_was_read_during_it() {
        let cache = Cache::<[u8]>::new();
        let bytes: Arc<[u8]> = Arc::from(&b"old"[..]);
        let other: Arc<[u8]> = Arc::from(&b"other"[..]);
        cache.insert(key(0x3000, 1, 3), &bytes, cache.generation(0x3000));
        cache.insert(key(0x3000, 2, 5), &other, cache.generation(0x3000));
        cache.invalidate(0x3000, Some(1));
        assert!(cache.lookup(&key(0x3000, 1, 3)).is_none(), "written");
        assert!(cache.lookup(&key(0x3000, 2, 5)).is_some(), "another file of the volume stays");
        let read_at = cache.generation(0x3000);
        cache.invalidate(0x3000, Some(9));
        cache.insert(key(0x3000, 1, 3), &bytes, read_at);
        assert!(cache.lookup(&key(0x3000, 1, 3)).is_none(), "read while a file changed: not kept");
        cache.invalidate(0x3000, None);
        assert!(cache.lookup(&key(0x3000, 2, 5)).is_none(), "the whole volume");
    }

    #[test]
    fn a_write_on_another_volume_does_not_drop_what_was_read() {
        // Tests run in parallel on volumes of their own: a write on one did
        // not keep what another read (`sections_share_the_bytes_of_an_unchanged_file`
        // failed now and then).
        let cache = Cache::<[u8]>::new();
        let bytes: Arc<[u8]> = Arc::from(&b"kept"[..]);
        let read_at = cache.generation(0x5000);
        cache.invalidate(0x6000, None);
        cache.insert(key(0x5000, 1, 4), &bytes, read_at);
        assert!(cache.lookup(&key(0x5000, 1, 4)).is_some());
    }

    /// Two sections of one file made at once, neither finding the other's:
    /// the second takes what the first put (an atomic get-or-insert).
    #[test]
    fn the_second_of_two_sections_made_at_once_takes_the_first_ones_content() {
        let cache = Cache::<[u8]>::new();
        let read_at = cache.generation(0x8000);
        let first: Arc<[u8]> = Arc::from(&b"first"[..]);
        let second: Arc<[u8]> = Arc::from(&b"second"[..]);
        assert!(Arc::ptr_eq(&cache.insert(key(0x8000, 4, 5), &first, read_at), &first));
        assert!(Arc::ptr_eq(&cache.insert(key(0x8000, 4, 5), &second, read_at), &first), "the first one's");
        assert!(Arc::ptr_eq(&cache.lookup(&key(0x8000, 4, 5)).unwrap(), &first));
        let resized: Arc<[u8]> = Arc::from(&b"resized"[..]);
        assert!(Arc::ptr_eq(&cache.insert(key(0x8000, 4, 7), &resized, read_at), &resized), "another size: its own");
        cache.invalidate(0x8000, Some(4));
        let stale = cache.generation(0x8000) - 1;
        assert!(Arc::ptr_eq(&cache.insert(key(0x8000, 4, 7), &second, stale), &second), "not kept, its own");
    }

    #[test]
    fn a_segment_is_found_by_its_type() {
        struct Segment(u32);
        let cache = Cache::<dyn Any + Send + Sync>::new();
        let segment = Arc::new(Segment(42));
        let any: Arc<dyn Any + Send + Sync> = segment.clone();
        cache.insert(key(0x7000, 3, 1), &any, cache.generation(0x7000));
        drop(any);
        let found = cache.lookup(&key(0x7000, 3, 1)).expect("held by its section").downcast::<Segment>().unwrap();
        assert!(Arc::ptr_eq(&found, &segment) && found.0 == 42);
        drop((found, segment));
        assert!(cache.lookup(&key(0x7000, 3, 1)).is_none(), "gone with its last section");
    }
}
