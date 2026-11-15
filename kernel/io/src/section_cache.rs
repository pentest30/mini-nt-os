//! Les octets des fichiers que tiennent des sections (le rôle des
//! SECTION_OBJECT_POINTERS d'un fichier dans NT) : une section d'un fichier
//! (NtCreateSection, de données ou d'image) garde le contenu du fichier lu à
//! sa création ([`crate::File::contents`]). Une autre section du même
//! fichier, inchangé, reprend ces octets au lieu de relire le fichier : tant
//! qu'une section les tient (une DLL chargée, une section de `\KnownDlls`),
//! le fichier n'est lu qu'une fois. `shell32` ouvre ainsi `shell32.dll`
//! (11 Mio) comme fichier de données pour chaque icône qu'il extrait.
//!
//! Un fichier est désigné par son volume et son entrée ([`Key`] : la place de
//! son entrée de répertoire sur FAT, sa référence sur NTFS), avec sa taille
//! et son premier cluster au moment de la lecture. Le cache ne retient rien
//! lui-même ([`Weak`]) : les octets partent avec la dernière section qui les
//! tient. Toute écriture ou tout changement de taille d'un fichier
//! ([`invalidate`], par `Volume::write` et `Volume::set_size`) retire son
//! entrée ; des octets lus pendant qu'un fichier changeait ne sont pas
//! gardés (la génération des écritures, [`generation`]).
//!
//! Pas encore : la suppression et le renommage de fichiers, que les volumes
//! ne font pas.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

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

struct Entry {
    key: Key,
    bytes: Weak<[u8]>,
}

/// Le cache : ses entrées, et le nombre d'invalidations depuis sa création.
pub struct Cache {
    entries: KSpinLock<Vec<Entry>>,
    generation: AtomicU64,
}

impl Cache {
    pub const fn new() -> Self {
        Self { entries: KSpinLock::new(Vec::new()), generation: AtomicU64::new(0) }
    }

    /// Les octets du fichier `key`, si une section les tient encore.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn lookup(&self, key: &Key) -> Option<Arc<[u8]>> {
        let mut entries = self.entries.lock();
        entries.retain(|entry| entry.bytes.strong_count() > 0);
        entries.iter().find(|entry| entry.key == *key).and_then(|entry| entry.bytes.upgrade())
    }

    /// La génération des écritures, à prendre avant de lire un fichier pour
    /// [`insert`](Self::insert).
    ///
    /// # IRQL
    /// Any level.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// `bytes`, le contenu du fichier `key` lu depuis la génération
    /// `read_at`, sert aux sections suivantes, sauf si un fichier a changé
    /// depuis.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn insert(&self, key: Key, bytes: &Arc<[u8]>, read_at: u64) {
        let mut entries = self.entries.lock();
        if self.generation.load(Ordering::Acquire) != read_at {
            return;
        }
        entries.retain(|entry| {
            entry.bytes.strong_count() > 0 && (entry.key.volume, entry.key.identity) != (key.volume, key.identity)
        });
        entries.push(Entry { key, bytes: Arc::downgrade(bytes) });
    }

    /// Le fichier `identity` du volume `volume` (tous ses fichiers sans
    /// `identity`) change : ses octets ne servent plus.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn invalidate(&self, volume: usize, identity: Option<u64>) {
        let mut entries = self.entries.lock();
        self.generation.fetch_add(1, Ordering::AcqRel);
        entries.retain(|entry| {
            entry.key.volume != volume || identity.is_some_and(|identity| entry.key.identity != identity)
        });
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

/// Le cache des volumes montés.
pub static CACHE: Cache = Cache::new();

#[cfg(test)]
mod tests {
    use super::*;

    fn key(volume: usize, identity: u64, size: u64) -> Key {
        Key { volume, identity, size, first_cluster: 5 }
    }

    #[test]
    fn bytes_serve_while_a_section_holds_them() {
        let cache = Cache::new();
        let bytes: Arc<[u8]> = Arc::from(&b"MZ shell32"[..]);
        cache.insert(key(0x1000, 7, 10), &bytes, cache.generation());
        let found = cache.lookup(&key(0x1000, 7, 10)).expect("held by a section");
        assert!(Arc::ptr_eq(&found, &bytes), "the same bytes, not a copy");
        assert!(cache.lookup(&key(0x1000, 7, 11)).is_none(), "another size: another content");
        assert!(cache.lookup(&key(0x2000, 7, 10)).is_none(), "another volume");
        drop((found, bytes));
        assert!(cache.lookup(&key(0x1000, 7, 10)).is_none(), "gone with the last section");
    }

    #[test]
    fn a_write_drops_the_file_and_what_was_read_during_it() {
        let cache = Cache::new();
        let bytes: Arc<[u8]> = Arc::from(&b"old"[..]);
        let other: Arc<[u8]> = Arc::from(&b"other"[..]);
        cache.insert(key(0x3000, 1, 3), &bytes, cache.generation());
        cache.insert(key(0x3000, 2, 5), &other, cache.generation());
        cache.invalidate(0x3000, Some(1));
        assert!(cache.lookup(&key(0x3000, 1, 3)).is_none(), "written");
        assert!(cache.lookup(&key(0x3000, 2, 5)).is_some(), "another file of the volume stays");
        let read_at = cache.generation();
        cache.invalidate(0x3000, Some(9));
        cache.insert(key(0x3000, 1, 3), &bytes, read_at);
        assert!(cache.lookup(&key(0x3000, 1, 3)).is_none(), "read while a file changed: not kept");
        cache.invalidate(0x3000, None);
        assert!(cache.lookup(&key(0x3000, 2, 5)).is_none(), "the whole volume");
    }
}
