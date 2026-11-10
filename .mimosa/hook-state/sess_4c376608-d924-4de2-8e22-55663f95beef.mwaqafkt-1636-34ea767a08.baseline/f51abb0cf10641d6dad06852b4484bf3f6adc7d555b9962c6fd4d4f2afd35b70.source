//! Les services des mutants (`ex::mutant`) : NtCreateMutant, NtOpenMutant,
//! NtReleaseMutant — le mutex de NT, celui du mutex d'instance unique de
//! taskmgr et des verrous de bibliothèques.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};
use ke::dispatcher::ProcessorMode;
use ke::sched::KePlatform;
use ob::AccessMask;

/// Un statut de service : l'erreur comme la réussite.
fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// NtCreateMutant(*MutantHandle, DesiredAccess, ObjectAttributes,
/// InitialOwner) : un objet mutant, nommé ou non (`create_named`) ; le
/// créateur qui demande `InitialOwner` l'acquiert par l'attente qui suit la
/// création.
pub(super) fn nt_create_mutant(arguments: &[u32]) -> NtStatus {
    let [out, desired, attributes, initial_owner] = arguments[..4] else { unreachable!("4 arguments") };
    let mutant = ex::mutant::Mutant::create();
    if initial_owner as u8 != 0 {
        // SAFETY: l'en-tête du mutant vit autant que l'objet, tenu ici.
        let wait = unsafe {
            ke::dispatcher::ke_wait_for_single_object::<KePlatform>(
                mutant.dispatcher_object(),
                ProcessorMode::Kernel,
                false,
                None,
            )
        };
        if wait != STATUS_SUCCESS {
            return wait;
        }
    }
    status(super::object::create_named(out, desired, attributes, mutant))
}

/// NtOpenMutant(*MutantHandle, DesiredAccess, ObjectAttributes) : un handle
/// sur le mutant que désignent les attributs.
pub(super) fn nt_open_mutant(arguments: &[u32]) -> NtStatus {
    status(
        super::object::open_by_name(arguments[0], arguments[1], arguments[2], &ex::mutant::MUTANT_TYPE)
            .map(|()| STATUS_SUCCESS),
    )
}

/// NtReleaseMutant(MutantHandle, *PreviousCount) : le propriétaire rend le
/// mutant (`MUTANT_INCREMENT`) ; rend l'état d'avant si on le demande.
pub(super) fn nt_release_mutant(arguments: &[u32]) -> NtStatus {
    let release = || {
        let mutant = super::current_process().handle_table.reference(
            ob::Handle(arguments[0]),
            Some(&ex::mutant::MUTANT_TYPE),
            AccessMask(0),
        )?;
        let mutant = ob::downcast::<ex::mutant::Mutant>(&mutant).ok_or(abi::ntstatus::STATUS_OBJECT_TYPE_MISMATCH)?;
        let previous = mutant.release()?;
        if arguments[1] != 0 {
            ke::usermem::copy_to_user(u64::from(arguments[1]), &previous.to_le_bytes())?;
        }
        Ok(())
    };
    release().map_or_else(|status| status, |()| STATUS_SUCCESS)
}
