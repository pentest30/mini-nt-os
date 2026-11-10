//! Les mutants (ExMutantObjectType) : un KMUTANT de Ke dans un objet d'Ob —
//! le mutex de NT, avec son propriétaire et l'abandon à la mort du
//! propriétaire (le mécanisme de Ke connaît le type `Mutant` et le gère à
//! l'attente comme à la sortie d'un thread).
//!
//! Le créateur qui demande `InitialOwner` acquiert par l'attente qui suit la
//! création : le mécanisme d'attente pose le propriétaire et enchaîne le
//! mutant dans la liste du thread, que sa fin abandonne.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;

use abi::ntstatus::NtStatus;
use ke::dispatcher::{ke_initialize_mutant, ke_release_mutant, DispatcherHeader, KMutant, MUTANT_INCREMENT};
use ke::sched::KePlatform;
use ob::{create_object, AccessMask, GenericMapping, Object, ObjectType};

/// Lire l'état (NtQueryMutant).
pub const MUTANT_QUERY_STATE: AccessMask = AccessMask(0x0001);
/// MUTANT_ALL_ACCESS d'XP.
pub const MUTANT_ALL_ACCESS: AccessMask =
    AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | AccessMask::SYNCHRONIZE.0 | 0x0001);

/// Le type `Mutant` (ExMutantObjectType), avec la correspondance générique
/// d'XP.
pub static MUTANT_TYPE: ObjectType = ObjectType::new(
    "Mutant",
    MUTANT_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | MUTANT_QUERY_STATE.0),
        write: AccessMask(AccessMask::STANDARD_RIGHTS_WRITE.0),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | AccessMask::SYNCHRONIZE.0),
        all: MUTANT_ALL_ACCESS,
    },
);

/// Le corps d'un objet mutant.
pub struct Mutant {
    mutant: *mut KMutant,
}

// SAFETY: Ke ne touche au KMUTANT que sous le verrou dispatcher ; le pointeur
// ne change pas.
unsafe impl Send for Mutant {}
// SAFETY: voir `Send`.
unsafe impl Sync for Mutant {}

impl Mutant {
    /// ExCreateMutant : un objet mutant libre (l'état signalé).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create() -> Arc<Object<Self>> {
        let mutant = Box::into_raw(Box::<KMutant>::new_uninit()).cast::<KMutant>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_mutant(mutant) };
        create_object(&MUTANT_TYPE, Self { mutant })
    }

    /// NtReleaseMutant : le propriétaire rend le mutant ; le thread relevé
    /// est celui qui l'acquiert. Rend l'état d'avant.
    ///
    /// # Errors
    /// `STATUS_MUTANT_NOT_OWNED` quand le thread courant ne le possède pas.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn release(&self) -> Result<i32, NtStatus> {
        // SAFETY: initialisé par `create`, vivant autant que `self`.
        unsafe { ke_release_mutant::<KePlatform>(self.mutant, MUTANT_INCREMENT, false) }
    }

    /// Son en-tête, à attendre tant qu'on tient l'objet.
    pub fn dispatcher_object(&self) -> *mut DispatcherHeader {
        // SAFETY: le KMUTANT vit autant que `self`.
        unsafe { ptr::addr_of_mut!((*self.mutant).header) }
    }
}

impl Drop for Mutant {
    fn drop(&mut self) {
        // Un mutant possédé au moment du Drop reste en vie : la liste du
        // thread propriétaire y pointe encore, et sa fin l'abandonnera
        // (ki_thread_exit) depuis cette liste. Sa mémoire n'est rendue
        // qu'au reboot — quelques dizaines d'octets par mutex d'instance
        // unique, au plus. Libre, il se rend.
        // SAFETY: le KMUTANT est initialisé et à adresse fixe ; la lecture
        // de son état ne modifie rien.
        let owned = unsafe { ptr::addr_of!((*self.mutant).header).read_volatile().signal_state == 0 };
        if owned {
            return;
        }
        // SAFETY: alloué par `create` ; personne ne l'attend ni ne le
        // possède (qui l'attendait tenait une référence sur l'objet).
        drop(unsafe { Box::from_raw(self.mutant) });
    }
}
