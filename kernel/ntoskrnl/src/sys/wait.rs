//! Les attentes du mode utilisateur (`ke::dispatcher`).
//!
//! On attend un objet du dispatcher : un processus (signalé à sa fin), un
//! thread (à sa fin) ou un événement d'Ex. Les autres types d'objets rendent
//! `STATUS_OBJECT_TYPE_MISMATCH` : un fichier, qu'XP attend par son
//! événement, viendra avec les E/S asynchrones.

use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER_1, STATUS_INVALID_PARAMETER_3,
    STATUS_INVALID_PARAMETER_MIX, STATUS_OBJECT_TYPE_MISMATCH,
};
use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
use ke::dispatcher::{
    ke_delay_execution_thread, ke_wait_for_multiple_objects, DispatcherHeader, ProcessorMode, WaitBlock, WaitType,
    MAXIMUM_WAIT_OBJECTS, THREAD_WAIT_OBJECTS,
};
use ke::sched::KePlatform;
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, ObjectRef};
use ps::{EProcess, EThread};

/// NtDelayExecution(Alertable, DelayInterval) : attend l'intervalle (format
/// NT : négatif relatif, positif absolu), STATUS_SUCCESS à l'échéance ; une
/// attente alertable finit sur un APC utilisateur (STATUS_USER_APC).
pub(super) fn nt_delay_execution(arguments: &[u32]) -> NtStatus {
    let interval = match UserPtr::<i64>::new(arguments[1]).read() {
        Ok(interval) => interval,
        Err(status) => return status,
    };
    // A BOOLEAN, in the low byte of its argument.
    let alertable = arguments[0] as u8 != 0;
    // SAFETY: a Ps thread, at PASSIVE_LEVEL, interrupts enabled.
    unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::User, alertable, interval) }
}

/// L'échéance en `timeout` (format NT) ; `None` sans elle (pointeur nul).
fn capture_timeout(timeout: u32) -> Result<Option<i64>, NtStatus> {
    match timeout {
        0 => Ok(None),
        at => UserPtr::<i64>::new(at).read().map(Some),
    }
}

/// L'objet que désigne `handle` dans le processus courant, avec `SYNCHRONIZE` ;
/// `NtCurrentProcess()` et `NtCurrentThread()` désignent le processus et le
/// thread courants.
fn reference_waitable(handle: u32) -> Result<ObjectRef, NtStatus> {
    match handle {
        NT_CURRENT_PROCESS => Ok(super::current_process() as ObjectRef),
        NT_CURRENT_THREAD => {
            Ok(ps::ethread::current_thread().expect("a system service outside a Ps thread") as ObjectRef)
        }
        _ => super::current_process().handle_table.reference(Handle(handle), None, AccessMask::SYNCHRONIZE),
    }
}

/// L'objet du dispatcher de `object`, valide tant qu'on tient `object`.
fn dispatcher_object(object: &ObjectRef) -> Result<*mut DispatcherHeader, NtStatus> {
    if let Some(event) = ob::downcast::<ex::Event>(object) {
        return Ok(event.dispatcher_object());
    }
    if let Some(process) = ob::downcast::<EProcess>(object) {
        return Ok(process.dispatcher_object());
    }
    if let Some(thread) = ob::downcast::<EThread>(object) {
        // A thread handed out has its Ke thread.
        return thread.dispatcher_object().ok_or(STATUS_INVALID_HANDLE);
    }
    Err(STATUS_OBJECT_TYPE_MISMATCH)
}

/// NtWaitForSingleObject(Handle, Alertable, Timeout) : attend que l'objet
/// soit signalé (`SYNCHRONIZE`), jusqu'à l'échéance s'il y en a une. Rend
/// `STATUS_WAIT_0`, `STATUS_TIMEOUT`, ou, alertable, `STATUS_USER_APC`.
pub(super) fn nt_wait_for_single_object(arguments: &[u32]) -> NtStatus {
    let wait = || {
        let timeout = capture_timeout(arguments[2])?;
        let object = reference_waitable(arguments[0])?;
        let header = dispatcher_object(&object)?;
        // A BOOLEAN, in the low byte of its argument.
        let alertable = arguments[1] as u8 != 0;
        // SAFETY: a Ps thread, at PASSIVE_LEVEL; `object`, held until the
        // wait ends, keeps its dispatcher object.
        Ok(unsafe {
            ke_wait_for_multiple_objects::<KePlatform>(
                &[header],
                WaitType::WaitAny,
                ProcessorMode::User,
                alertable,
                timeout,
                None,
            )
        })
    };
    wait().unwrap_or_else(|status| status)
}

/// NtWaitForMultipleObjects(Count, Handles, WaitType, Alertable, Timeout) :
/// attend que l'un (`WaitAny`) ou tous (`WaitAll`) des `Count` objets soient
/// signalés, de 1 à 64 (`STATUS_INVALID_PARAMETER_1` sinon) ;
/// `STATUS_INVALID_PARAMETER_3` pour une autre sorte d'attente,
/// `STATUS_INVALID_PARAMETER_MIX` pour un objet nommé deux fois dans un
/// `WaitAll`. Rend `STATUS_WAIT_0 + n` (le premier objet signalé pour
/// `WaitAny`), `STATUS_TIMEOUT`, ou, alertable, `STATUS_USER_APC`.
pub(super) fn nt_wait_for_multiple_objects(arguments: &[u32]) -> NtStatus {
    let wait = || {
        let count = arguments[0] as usize;
        if count == 0 || count > MAXIMUM_WAIT_OBJECTS {
            return Err(STATUS_INVALID_PARAMETER_1);
        }
        let wait_type = match arguments[2] {
            0 => WaitType::WaitAll,
            1 => WaitType::WaitAny,
            _ => return Err(STATUS_INVALID_PARAMETER_3),
        };
        let mut bytes = alloc::vec![0u8; count * 4];
        ke::usermem::probe_for_read(u64::from(arguments[1]), bytes.len(), 4)?;
        ke::usermem::copy_from_user(&mut bytes, u64::from(arguments[1]))?;
        let timeout = capture_timeout(arguments[4])?;
        let objects = bytes
            .chunks_exact(4)
            .map(|word| reference_waitable(u32::from_le_bytes([word[0], word[1], word[2], word[3]])))
            .collect::<Result<Vec<ObjectRef>, NtStatus>>()?;
        let headers = objects.iter().map(dispatcher_object).collect::<Result<Vec<_>, NtStatus>>()?;
        if wait_type == WaitType::WaitAll && headers.iter().enumerate().any(|(i, h)| headers[..i].contains(h)) {
            return Err(STATUS_INVALID_PARAMETER_MIX);
        }
        // Past the thread's own blocks, the wait takes an array of its own.
        let mut blocks: Vec<WaitBlock> = Vec::new();
        if count > THREAD_WAIT_OBJECTS {
            blocks.resize_with(count, WaitBlock::new);
        }
        let array = (count > THREAD_WAIT_OBJECTS).then_some(blocks.as_mut_slice());
        // A BOOLEAN, in the low byte of its argument.
        let alertable = arguments[3] as u8 != 0;
        // SAFETY: a Ps thread, at PASSIVE_LEVEL; `objects`, held until the
        // wait ends, keep their dispatcher objects, and `blocks` stays put.
        Ok(unsafe {
            ke_wait_for_multiple_objects::<KePlatform>(
                &headers,
                wait_type,
                ProcessorMode::User,
                alertable,
                timeout,
                array,
            )
        })
    };
    wait().unwrap_or_else(|status| status)
}
