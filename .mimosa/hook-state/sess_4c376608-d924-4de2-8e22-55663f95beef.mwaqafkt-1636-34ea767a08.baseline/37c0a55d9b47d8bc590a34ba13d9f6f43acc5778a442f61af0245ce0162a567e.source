//! Les sémaphores (ExSemaphoreObjectType) : un KSEMAPHORE de Ke dans un
//! objet d'Ob.
//!
//! Un sémaphore est signalé tant que son compte est positif ; chaque attente
//! satisfaite le décrémente, une libération l'augmente sans dépasser sa
//! limite. Le KSEMAPHORE est à adresse fixe (Ke y chaîne ses blocs
//! d'attente) et vit autant que l'objet.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use ke::dispatcher::{ke_initialize_semaphore, ke_release_semaphore, DispatcherHeader, KSemaphore};
use ke::sched::KePlatform;
use ob::{create_object, AccessMask, GenericMapping, Object, ObjectType};

/// Lire le compte (NtQuerySemaphore).
pub const SEMAPHORE_QUERY_STATE: AccessMask = AccessMask(0x0001);
/// Libérer (NtReleaseSemaphore).
pub const SEMAPHORE_MODIFY_STATE: AccessMask = AccessMask(0x0002);
/// SEMAPHORE_ALL_ACCESS d'XP.
pub const SEMAPHORE_ALL_ACCESS: AccessMask =
    AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | AccessMask::SYNCHRONIZE.0 | 0x0003);

/// Le type `Semaphore` (ExSemaphoreObjectType), avec la correspondance
/// générique d'XP.
pub static SEMAPHORE_TYPE: ObjectType = ObjectType::new(
    "Semaphore",
    SEMAPHORE_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | SEMAPHORE_QUERY_STATE.0),
        write: AccessMask(AccessMask::STANDARD_RIGHTS_WRITE.0 | SEMAPHORE_MODIFY_STATE.0),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | AccessMask::SYNCHRONIZE.0),
        all: SEMAPHORE_ALL_ACCESS,
    },
);

/// Le corps d'un objet sémaphore.
pub struct Semaphore {
    semaphore: *mut KSemaphore,
}

// SAFETY: Ke ne touche au KSEMAPHORE que sous le verrou dispatcher ; le
// pointeur ne change pas.
unsafe impl Send for Semaphore {}
// SAFETY: voir `Send`.
unsafe impl Sync for Semaphore {}

impl Semaphore {
    /// ExCreateSemaphore : un sémaphore de compte `count` et de limite
    /// `limit` ; `STATUS_INVALID_PARAMETER` sans `0 <= count <= limit` et
    /// `limit > 0`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(count: i32, limit: i32) -> Result<Arc<Object<Self>>, NtStatus> {
        if limit <= 0 || count < 0 || count > limit {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let semaphore = Box::into_raw(Box::<KSemaphore>::new_uninit()).cast::<KSemaphore>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_semaphore(semaphore, count, limit) };
        Ok(create_object(&SEMAPHORE_TYPE, Self { semaphore }))
    }

    /// Son compte (KeReadStateSemaphore).
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn count(&self) -> i32 {
        // SAFETY: initialisé par `create`, vivant autant que `self` ; un mot
        // lu d'un bloc, sans le verrou, comme le fait XP.
        unsafe { ptr::addr_of!((*self.semaphore).header.signal_state).read_volatile() }
    }

    /// Sa limite.
    pub fn limit(&self) -> i32 {
        // SAFETY: initialisé par `create` ; la limite ne change pas.
        unsafe { (*self.semaphore).limit }
    }

    /// KeReleaseSemaphore : ajoute `count` à son compte, sans relever ceux
    /// qu'il réveille (IO_NO_INCREMENT, comme NtReleaseSemaphore) ; rend le
    /// compte d'avant. `STATUS_SEMAPHORE_LIMIT_EXCEEDED` au-delà de sa limite
    /// ou pour un `count` qui n'est pas positif.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn release(&self, count: i32) -> Result<i32, NtStatus> {
        // SAFETY: initialisé par `create`.
        unsafe { ke_release_semaphore::<KePlatform>(self.semaphore, 0, count) }
    }

    /// Son en-tête, à attendre tant qu'on tient l'objet.
    pub fn dispatcher_object(&self) -> *mut DispatcherHeader {
        // SAFETY: le KSEMAPHORE vit autant que `self`.
        unsafe { ptr::addr_of_mut!((*self.semaphore).header) }
    }
}

impl Drop for Semaphore {
    fn drop(&mut self) {
        // SAFETY: alloué par `create` ; l'objet meurt, et qui l'attendait le
        // tenait.
        drop(unsafe { Box::from_raw(self.semaphore) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::ntstatus::STATUS_SEMAPHORE_LIMIT_EXCEEDED;

    #[test]
    fn counts_must_fit_the_limit() {
        assert!(Semaphore::create(0, 1).is_ok());
        assert!(Semaphore::create(3, 3).is_ok());
        assert_eq!(Semaphore::create(0, 0).err(), Some(STATUS_INVALID_PARAMETER), "no room");
        assert_eq!(Semaphore::create(-1, 2).err(), Some(STATUS_INVALID_PARAMETER));
        assert_eq!(Semaphore::create(3, 2).err(), Some(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn a_release_says_the_count_before_and_stops_at_the_limit() {
        let semaphore = Semaphore::create(1, 4).expect("a semaphore");
        assert_eq!((semaphore.count(), semaphore.limit()), (1, 4));
        assert_eq!(semaphore.release(2), Ok(1));
        assert_eq!(semaphore.count(), 3);
        assert_eq!(semaphore.release(2), Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED), "5 is past 4");
        assert_eq!(semaphore.release(1), Ok(3));
        assert_eq!(semaphore.count(), 4);
    }
}
