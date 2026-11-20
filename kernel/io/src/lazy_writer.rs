//! L'écriture différée des volumes montés (ce que l'écrivain paresseux du
//! gestionnaire de cache fait pour les métadonnées des systèmes de fichiers,
//! 02 §5.6 ; CcLazyWriteScan de ReactOS, comme spécification).
//!
//! Chaque volume monté au démarrage s'inscrit dans [`MOUNTED`]
//! ([`MountedVolumes::register`]). Le thread de l'écrivain paresseux du noyau
//! (`ntoskrnl::lazy_writer`) demande chaque seconde ce qui attend
//! ([`MountedVolumes::write_behind`]) ; l'arrêt les vide tous
//! ([`MountedVolumes::flush`]).
//!
//! Sur un volume FAT, ce qui attend est le cache du disque, et les secteurs
//! de la première FAT gardée en mémoire (`fat::FatVolume`) qu'aucune entrée
//! n'a encore fait écrire : les données et les entrées des répertoires vont
//! au disque dès qu'elles sont écrites, et la FAT avant chaque entrée qui
//! la désigne, puis après la chaîne libérée d'une entrée effacée. Une
//! coupure de courant laisse ainsi un volume que fsck trouve propre ; elle
//! ne perd que ce que le cache du disque tenait encore. (Avant cet ordre,
//! une entrée écrite moins d'une seconde avant la coupure désignait une
//! chaîne restée en mémoire : `C:\RECYCLED` du scénario `logon`.)
//!
//! Avant lui, la FAT de `C:` n'allait sur le disque qu'à un vidage explicite
//! (NtFlushBuffersFile, la réécriture d'une ruche) : ce qu'une session
//! écrivait était perdu à l'arrêt de la machine, et la FAT du disque
//! laissait des chaînes qui finissaient sur un cluster libre.

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::NtStatus;
use hal::sync::KSpinLock;

use crate::volume::Volume;

/// Les volumes montés au démarrage.
pub static MOUNTED: MountedVolumes = MountedVolumes::new();

/// Des volumes montés, que l'écrivain paresseux et l'arrêt vident.
pub struct MountedVolumes {
    volumes: KSpinLock<Vec<Arc<Volume>>>,
}

/// Ce qu'un passage de l'écrivain paresseux a fait.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WrittenBehind {
    /// Les volumes vidés.
    pub volumes: u32,
    /// La première erreur ; les autres volumes ont été vidés quand même.
    pub error: Option<NtStatus>,
}

impl MountedVolumes {
    /// Aucun volume.
    pub const fn new() -> Self {
        Self { volumes: KSpinLock::new(Vec::new()) }
    }

    /// Inscrit `volume` (une fois).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn register(&self, volume: &Arc<Volume>) {
        let mut volumes = self.volumes.lock();
        if !volumes.iter().any(|known| Arc::ptr_eq(known, volume)) {
            volumes.push(volume.clone());
        }
    }

    /// Les volumes inscrits, pris sous le verrou, vidés hors de lui.
    fn snapshot(&self) -> Vec<Arc<Volume>> {
        self.volumes.lock().clone()
    }

    /// Le passage de l'écrivain paresseux : chaque volume dont quelque
    /// chose attend est vidé (`Volume::write_behind`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn write_behind(&self) -> WrittenBehind {
        let mut written = WrittenBehind::default();
        for volume in self.snapshot() {
            match volume.write_behind() {
                Ok(true) => written.volumes += 1,
                Ok(false) => {}
                Err(status) => {
                    written.error.get_or_insert(status);
                }
            }
        }
        written
    }

    /// Quelque chose attend sur un des volumes.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_dirty(&self) -> bool {
        self.snapshot().iter().any(|volume| volume.is_dirty())
    }

    /// L'arrêt (IoShutdownSystem) : chaque volume vidé, son disque compris ;
    /// rend la première erreur, après avoir essayé les autres.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn flush(&self) -> Result<(), NtStatus> {
        let mut first = Ok(());
        for volume in self.snapshot() {
            if let Err(status) = volume.flush() {
                first = first.and(Err(status));
            }
        }
        first
    }
}

impl Default for MountedVolumes {
    fn default() -> Self {
        Self::new()
    }
}
