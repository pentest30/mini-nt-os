//! Les ports de complétion d'E/S (`io_manager::IoCompletion`) :
//! NtCreateIoCompletion, NtOpenIoCompletion, NtSetIoCompletion,
//! NtRemoveIoCompletion, NtQueryIoCompletion. Le pool de threads de `ntdll`
//! (RtlQueueWorkItem) en crée un et y fait attendre ses threads ; sans lui,
//! QueueUserWorkItem échoue, et le serveur RPC de `rpcrt4` perd chaque
//! requête qu'il reçoit.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS, STATUS_TIMEOUT};
use alloc::sync::Arc;
use io_manager::{IoCompletion, Packet, IO_COMPLETION_MODIFY_STATE, IO_COMPLETION_QUERY_STATE, IO_COMPLETION_TYPE};
use ke::dispatcher::ProcessorMode;
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, Object};

/// IoCompletionBasicInformation.
const IO_COMPLETION_BASIC_INFORMATION: u32 = 0;

static UNSUPPORTED_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryIoCompletion");

fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// Le port que désigne `handle` dans le processus courant, avec les droits
/// `access`.
fn reference(handle: u32, access: AccessMask) -> Result<Arc<Object<IoCompletion>>, NtStatus> {
    super::current_process().handle_table.reference_as::<IoCompletion>(Handle(handle), &IO_COMPLETION_TYPE, access)
}

/// NtCreateIoCompletion(*IoCompletionHandle, DesiredAccess, ObjectAttributes,
/// NumberOfConcurrentThreads) : un port vide, nommé si les attributs le
/// nomment (le pool de `ntdll` n'en donne pas).
pub(super) fn nt_create_io_completion(arguments: &[u32]) -> NtStatus {
    let port = IoCompletion::create(arguments[3]);
    status(super::object::create_named(arguments[0], arguments[1], arguments[2], port))
}

/// NtOpenIoCompletion(*IoCompletionHandle, DesiredAccess, ObjectAttributes) :
/// un handle sur le port que désignent les attributs.
pub(super) fn nt_open_io_completion(arguments: &[u32]) -> NtStatus {
    status(
        super::object::open_by_name(arguments[0], arguments[1], arguments[2], &IO_COMPLETION_TYPE)
            .map(|()| STATUS_SUCCESS),
    )
}

/// NtSetIoCompletion(IoCompletionHandle, KeyContext, ApcContext, IoStatus,
/// IoStatusInformation) : met un paquet dans le port
/// (`IO_COMPLETION_MODIFY_STATE`).
pub(super) fn nt_set_io_completion(arguments: &[u32]) -> NtStatus {
    let packet =
        Packet { key: arguments[1], context: arguments[2], status: NtStatus(arguments[3]), information: arguments[4] };
    status(
        reference(arguments[0], IO_COMPLETION_MODIFY_STATE)
            .and_then(|port| port.insert(packet))
            .map(|()| STATUS_SUCCESS),
    )
}

/// NtRemoveIoCompletion(IoCompletionHandle, *KeyContext, *ApcContext,
/// *IoStatusBlock, Timeout) : le premier paquet du port
/// (`IO_COMPLETION_MODIFY_STATE`), attendu en mode utilisateur sans alerte
/// jusqu'à `Timeout` (sans lui, sans fin) ; sa clé, son contexte et son bloc
/// d'état écrits chez l'appelant. `STATUS_TIMEOUT` sans paquet à l'échéance,
/// sans rien écrire.
pub(super) fn nt_remove_io_completion(arguments: &[u32]) -> NtStatus {
    status(remove(arguments))
}

fn remove(arguments: &[u32]) -> Result<NtStatus, NtStatus> {
    let [handle, key, context, iosb, timeout] = arguments[..5] else { unreachable!("5 arguments") };
    let port = reference(handle, IO_COMPLETION_MODIFY_STATE)?;
    let timeout = super::wait::capture_timeout(timeout)?;
    let Some(packet) = port.remove(ProcessorMode::User, timeout)? else {
        return Ok(STATUS_TIMEOUT);
    };
    UserPtr::<u32>::new(key).write(&packet.key)?;
    UserPtr::<u32>::new(context).write(&packet.context)?;
    UserPtr::<u32>::new(iosb).write(&packet.status.0)?;
    UserPtr::<u32>::new(iosb.wrapping_add(4)).write(&packet.information)?;
    Ok(STATUS_SUCCESS)
}

/// NtQueryIoCompletion(IoCompletionHandle, InformationClass, Information,
/// Length, *ResultLength) : `IoCompletionBasicInformation`, le nombre de
/// paquets en file (`IO_COMPLETION_QUERY_STATE`). Les autres classes rendent
/// `STATUS_NOT_IMPLEMENTED`, journalisé à leur premier appel.
pub(super) fn nt_query_io_completion(arguments: &[u32]) -> NtStatus {
    if arguments[1] != IO_COMPLETION_BASIC_INFORMATION {
        return UNSUPPORTED_CLASSES.report(arguments[1]);
    }
    match reference(arguments[0], IO_COMPLETION_QUERY_STATE) {
        Ok(port) => {
            let depth = i32::try_from(port.depth()).unwrap_or(i32::MAX);
            super::return_information(&depth.to_le_bytes(), arguments[2], arguments[3], arguments[4])
        }
        Err(status) => status,
    }
}
