//! Les verrous de plages d'octets d'un fichier (le FILE_LOCK du FCB) :
//! NtLockFile, NtUnlockFile, et ce qu'ils interdisent aux lectures et aux
//! écritures (IRP_MJ_LOCK_CONTROL, FsRtlCheckLockFor*Access).
//!
//! Spécification : FsRtl de ReactOS 0.4.16 (`ntoskrnl/fsrtl/filelock.c`) et
//! la documentation publique de LockFileEx ; pas de portage de code.
//!
//! - Un verrou exclusif ne chevauche aucun autre verrou, et un verrou
//!   partagé aucun verrou exclusif, quel que soit leur propriétaire
//!   (FsRtlPrivateLock) : `STATUS_FILE_LOCK_CONFLICT`, le code de FsRtl
//!   (`kernel32` en fait ERROR_LOCK_VIOLATION).
//! - Une plage vide ne chevauche rien ; une plage qui dépasse 2^64 est
//!   refusée (`STATUS_INVALID_PARAMETER`).
//! - Le déverrouillage désigne exactement la plage d'un verrou du même
//!   processus et de la même clé (FsRtlFastUnlockSingle), sinon
//!   `STATUS_RANGE_NOT_LOCKED`.
//! - Une lecture est refusée sur un verrou exclusif d'un autre propriétaire
//!   (processus et clé) ; une écriture, sur tout verrou partagé (même le
//!   sien) et sur un verrou exclusif d'un autre propriétaire :
//!   `STATUS_FILE_LOCK_CONFLICT`.
//! - À la fermeture du dernier handle d'un objet fichier (IRP_MJ_CLEANUP,
//!   FsRtlFastUnlockAll), ses verrous partent.

use abi::ntstatus::{NtStatus, STATUS_FILE_LOCK_CONFLICT, STATUS_INVALID_PARAMETER, STATUS_RANGE_NOT_LOCKED};
use alloc::vec::Vec;

/// Qui tient un verrou : l'objet fichier par lequel il a été pris, le
/// processus de l'appelant, la clé (`Key` de NtLockFile).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockOwner {
    /// L'adresse de l'objet fichier : elle ne change pas tant qu'il vit, et
    /// ses verrous partent avec son dernier handle.
    pub file_object: usize,
    /// UniqueProcessId de l'appelant.
    pub process: u32,
    /// La clé de l'appelant.
    pub key: u32,
}

impl LockOwner {
    /// Le même processus et la même clé (ce que FsRtl compare pour les E/S
    /// et le déverrouillage).
    fn same_caller(&self, other: &LockOwner) -> bool {
        self.process == other.process && self.key == other.key
    }
}

/// Une plage verrouillée : `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lock {
    start: u64,
    end: u64,
    exclusive: bool,
    owner: LockOwner,
}

/// La plage `[offset, offset + length)`, ou `STATUS_INVALID_PARAMETER` si
/// elle dépasse 2^64.
fn range(offset: u64, length: u64) -> Result<(u64, u64), NtStatus> {
    offset.checked_add(length).map(|end| (offset, end)).ok_or(STATUS_INVALID_PARAMETER)
}

/// Deux plages non vides qui ont un octet en commun.
fn overlaps(start: u64, end: u64, lock: &Lock) -> bool {
    start < end && lock.start < lock.end && start < lock.end && lock.start < end
}

/// Les verrous d'un fichier.
#[derive(Debug, Default)]
pub struct FileLocks {
    locks: Vec<Lock>,
}

impl FileLocks {
    /// Aucun verrou.
    pub const fn new() -> Self {
        Self { locks: Vec::new() }
    }

    /// Il n'en tient aucun.
    pub fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }

    /// NtLockFile : verrouille `[offset, offset + length)` pour `owner`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL; allocates from the non-paged pool.
    pub fn lock(&mut self, offset: u64, length: u64, exclusive: bool, owner: LockOwner) -> Result<(), NtStatus> {
        let (start, end) = range(offset, length)?;
        if self.locks.iter().any(|lock| overlaps(start, end, lock) && (exclusive || lock.exclusive)) {
            return Err(STATUS_FILE_LOCK_CONFLICT);
        }
        self.locks.push(Lock { start, end, exclusive, owner });
        Ok(())
    }

    /// NtUnlockFile : retire le verrou de `owner` (son processus et sa clé)
    /// qui couvre exactement `[offset, offset + length)` ; un verrou
    /// exclusif d'abord, comme FsRtlFastUnlockSingle.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn unlock(&mut self, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        let (start, end) = range(offset, length).map_err(|_| STATUS_RANGE_NOT_LOCKED)?;
        let matches = |lock: &Lock| lock.start == start && lock.end == end && lock.owner.same_caller(&owner);
        let at = self
            .locks
            .iter()
            .position(|lock| matches(lock) && lock.exclusive)
            .or_else(|| self.locks.iter().position(matches))
            .ok_or(STATUS_RANGE_NOT_LOCKED)?;
        self.locks.swap_remove(at);
        Ok(())
    }

    /// La fermeture du dernier handle de l'objet fichier `file_object` :
    /// ses verrous partent. Rend s'il en tenait.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn unlock_all(&mut self, file_object: usize) -> bool {
        let before = self.locks.len();
        self.locks.retain(|lock| lock.owner.file_object != file_object);
        self.locks.len() != before
    }

    /// Une lecture de `[offset, offset + length)` par `owner` :
    /// `STATUS_FILE_LOCK_CONFLICT` sur un verrou exclusif d'un autre.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn check_read(&self, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        let end = offset.saturating_add(length);
        let conflict = |lock: &Lock| lock.exclusive && !lock.owner.same_caller(&owner);
        if self.locks.iter().any(|lock| overlaps(offset, end, lock) && conflict(lock)) {
            return Err(STATUS_FILE_LOCK_CONFLICT);
        }
        Ok(())
    }

    /// Une écriture de `[offset, offset + length)` par `owner` :
    /// `STATUS_FILE_LOCK_CONFLICT` sur un verrou partagé, ou exclusif d'un
    /// autre.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn check_write(&self, offset: u64, length: u64, owner: LockOwner) -> Result<(), NtStatus> {
        let end = offset.saturating_add(length);
        let conflict = |lock: &Lock| !lock.exclusive || !lock.owner.same_caller(&owner);
        if self.locks.iter().any(|lock| overlaps(offset, end, lock) && conflict(lock)) {
            return Err(STATUS_FILE_LOCK_CONFLICT);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: LockOwner = LockOwner { file_object: 0x1000, process: 8, key: 0 };
    const A2: LockOwner = LockOwner { file_object: 0x2000, process: 8, key: 0 };
    const B: LockOwner = LockOwner { file_object: 0x3000, process: 12, key: 0 };

    #[test]
    fn an_exclusive_lock_overlaps_nothing_and_a_shared_one_no_exclusive_lock() {
        let mut locks = FileLocks::new();
        locks.lock(100, 10, true, A).unwrap();
        // Même propriétaire : un verrou exclusif ne se reprend pas.
        assert_eq!(locks.lock(105, 1, true, A), Err(STATUS_FILE_LOCK_CONFLICT));
        assert_eq!(locks.lock(109, 5, false, B), Err(STATUS_FILE_LOCK_CONFLICT));
        // Contigus, sans chevauchement.
        locks.lock(110, 10, true, B).unwrap();
        locks.lock(90, 10, false, B).unwrap();
        locks.lock(95, 2, false, A).unwrap();
        assert_eq!(locks.lock(96, 1, true, A), Err(STATUS_FILE_LOCK_CONFLICT));
    }

    #[test]
    fn an_empty_range_overlaps_nothing_and_an_overflowing_one_is_refused() {
        let mut locks = FileLocks::new();
        locks.lock(0, 100, true, A).unwrap();
        locks.lock(50, 0, true, B).unwrap();
        assert_eq!(locks.lock(u64::MAX, 2, true, B), Err(STATUS_INVALID_PARAMETER));
        // Jusqu'à la dernière adresse : le stockage structuré verrouille
        // loin derrière la fin du fichier.
        locks.lock(u64::MAX - 1, 1, true, B).unwrap();
    }

    #[test]
    fn an_unlock_names_the_exact_range_of_the_same_process_and_key() {
        let mut locks = FileLocks::new();
        locks.lock(0, 10, true, A).unwrap();
        assert_eq!(locks.unlock(0, 5, A), Err(STATUS_RANGE_NOT_LOCKED));
        assert_eq!(locks.unlock(0, 10, B), Err(STATUS_RANGE_NOT_LOCKED));
        assert_eq!(locks.unlock(0, 10, LockOwner { key: 1, ..A }), Err(STATUS_RANGE_NOT_LOCKED));
        // Un autre handle du même processus, la même clé : FsRtl le permet.
        locks.unlock(0, 10, A2).unwrap();
        assert!(locks.is_empty());
        assert_eq!(locks.unlock(0, 10, A), Err(STATUS_RANGE_NOT_LOCKED));
    }

    #[test]
    fn a_lock_taken_twice_shared_goes_once_per_unlock() {
        let mut locks = FileLocks::new();
        locks.lock(0, 10, false, A).unwrap();
        locks.lock(0, 10, false, A).unwrap();
        locks.unlock(0, 10, A).unwrap();
        assert_eq!(locks.lock(0, 10, true, B), Err(STATUS_FILE_LOCK_CONFLICT));
        locks.unlock(0, 10, A).unwrap();
        locks.lock(0, 10, true, B).unwrap();
    }

    #[test]
    fn reads_stop_at_the_exclusive_locks_of_others_and_writes_at_any_other_lock() {
        let mut locks = FileLocks::new();
        locks.lock(0, 10, true, A).unwrap();
        locks.lock(20, 10, false, A).unwrap();
        locks.check_read(0, 10, A).unwrap();
        locks.check_write(0, 10, A).unwrap();
        assert_eq!(locks.check_read(5, 10, B), Err(STATUS_FILE_LOCK_CONFLICT));
        assert_eq!(locks.check_write(5, 1, B), Err(STATUS_FILE_LOCK_CONFLICT));
        // Un verrou partagé : tout le monde lit, personne n'écrit.
        locks.check_read(20, 10, B).unwrap();
        assert_eq!(locks.check_write(25, 1, A), Err(STATUS_FILE_LOCK_CONFLICT));
        assert_eq!(locks.check_write(25, 1, B), Err(STATUS_FILE_LOCK_CONFLICT));
        // Hors des plages, ou sans octet.
        locks.check_write(10, 10, B).unwrap();
        locks.check_write(5, 0, B).unwrap();
    }

    #[test]
    fn the_last_handle_of_a_file_object_takes_its_locks_away() {
        let mut locks = FileLocks::new();
        locks.lock(0, 10, true, A).unwrap();
        locks.lock(20, 10, true, A2).unwrap();
        assert!(locks.unlock_all(A.file_object));
        assert!(!locks.unlock_all(A.file_object));
        locks.lock(0, 10, true, B).unwrap();
        assert_eq!(locks.lock(20, 1, true, B), Err(STATUS_FILE_LOCK_CONFLICT));
    }
}
