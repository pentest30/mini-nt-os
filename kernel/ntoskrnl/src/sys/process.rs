//! Les services de Ps : créer un processus (NtCreateProcess,
//! NtCreateProcessEx) et un thread (NtCreateThread), comme
//! `RtlCreateUserProcess` les demande ; suspendre et reprendre un thread ;
//! terminer un processus ou un thread ; dire et changer ce que sait un
//! processus.
//!
//! Pas encore : le clonage d'un espace d'adresses (une section nulle, le
//! `fork` de POSIX), les ports de débogage et d'exception, les jobs ; ils
//! rendent `STATUS_NOT_IMPLEMENTED`, journalisé une fois.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::context::Context32;
use abi::ntstatus::{
    NtStatus, STATUS_CANT_TERMINATE_SELF, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS,
};
use abi::process::{
    InitialTeb32, ProcessBasicInformation32, PROCESS_BASIC_INFORMATION, PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
    PROCESS_CREATE_FLAGS_LEGAL_MASK, PROCESS_SESSION_INFORMATION,
};
use abi::teb32::ClientId32;
use ke::usermem::UserPtr;
use mm::section::{Section, SECTION_MAP_EXECUTE, SECTION_TYPE};
use ob::{Handle, ObjectRef};
use ps::eprocess::{
    PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SET_SESSIONID, PROCESS_TERMINATE,
};
use ps::ethread::{THREAD_SUSPEND_RESUME, THREAD_TERMINATE};

/// Les classes de NtQueryInformationProcess demandées sans être implémentées.
static UNSUPPORTED_QUERY_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryInformationProcess");
/// Les classes de NtSetInformationProcess demandées sans être implémentées.
static UNSUPPORTED_SET_CLASSES: super::ClassReport = super::ClassReport::new("NtSetInformationProcess");

/// La priorité de base d'un processus de la classe normale.
const NORMAL_BASE_PRIORITY: i32 = 8;

fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// Ce qui manque à une création, journalisé à sa première demande.
fn not_implemented(seen: &AtomicBool, what: &str) -> NtStatus {
    if !seen.swap(true, Ordering::Relaxed) {
        log::warn!("sys: {what} is not implemented");
    }
    STATUS_NOT_IMPLEMENTED
}

/// ImageFileName : le dernier élément du chemin de l'image de la section.
fn image_file_name(section: &Section) -> &str {
    let path = section.file_name().unwrap_or("");
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// NtTerminateProcess(ProcessHandle, ExitStatus) :
/// - NULL : les autres threads du processus courant se terminent ;
/// - `NtCurrentProcess()` ou un handle avec `PROCESS_TERMINATE` : le
///   processus se termine avec `ExitStatus`, et l'appel ne revient pas s'il
///   s'agit de celui de l'appelant.
pub(super) fn nt_terminate_process(arguments: &[u32]) -> NtStatus {
    let (handle, status) = (arguments[0], NtStatus(arguments[1]));
    if handle == 0 {
        ps::terminate_other_threads(status);
        return STATUS_SUCCESS;
    }
    let process = match super::reference_process(handle, PROCESS_TERMINATE) {
        Ok(process) => process,
        Err(status) => return status,
    };
    // Ends the calling thread if the process is its own: nothing on this
    // stack may own memory by then.
    match ps::terminate_process(process, status) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// PspCreateProcess depuis le mode utilisateur : un processus sans thread
/// pour l'image de la section (`SECTION_MAP_EXECUTE`), fils du processus
/// `ParentProcess` (`PROCESS_CREATE_PROCESS`, obligatoire), dont il hérite les
/// handles héritables avec `PROCESS_CREATE_FLAGS_INHERIT_HANDLES` ; son handle
/// en `ProcessHandle`, nommé (ou non) d'après les attributs. Son PEB n'a pas
/// encore de paramètres : le créateur les écrit (`RtlpInitEnvironment`).
fn create_process(arguments: &[u32], flags: u32, job_level: u32) -> Result<NtStatus, NtStatus> {
    static FORK: AtomicBool = AtomicBool::new(false);
    static PORTS: AtomicBool = AtomicBool::new(false);
    static JOBS: AtomicBool = AtomicBool::new(false);
    let (out, desired, attributes, parent) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let (section, debug_port, exception_port) = (arguments[5], arguments[6], arguments[7]);
    if flags & !PROCESS_CREATE_FLAGS_LEGAL_MASK != 0 || parent == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if section == 0 {
        return Err(not_implemented(&FORK, "NtCreateProcess without a section (a cloned address space)"));
    }
    if debug_port != 0 || exception_port != 0 {
        return Err(not_implemented(&PORTS, "NtCreateProcess with a debug or exception port"));
    }
    if job_level != 0 {
        return Err(not_implemented(&JOBS, "NtCreateProcessEx in a job"));
    }
    let parent = super::reference_process(parent, PROCESS_CREATE_PROCESS)?;
    let section = super::current_process().handle_table.reference_as::<Arc<Section>>(
        Handle(section),
        &SECTION_TYPE,
        SECTION_MAP_EXECUTE,
    )?;
    let inherit = flags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES != 0;
    let process = ps::create_process(&parent, &section, image_file_name(&section), inherit)?;
    drop(parent);
    let object: ObjectRef = process.clone();
    super::object::create_named(out, desired, attributes, object).inspect_err(|&failure| {
        // Without a handle, nobody will end it: give back what it holds.
        let _ = ps::terminate_process(process, failure);
    })
}

/// NtCreateProcess(*ProcessHandle, DesiredAccess, ObjectAttributes,
/// ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort).
pub(super) fn nt_create_process(arguments: &[u32]) -> NtStatus {
    // A BOOLEAN, in the low byte of its argument.
    let flags = if arguments[4] as u8 != 0 { PROCESS_CREATE_FLAGS_INHERIT_HANDLES } else { 0 };
    status(create_process(arguments, flags, 0))
}

/// NtCreateProcessEx(*ProcessHandle, DesiredAccess, ObjectAttributes,
/// ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort,
/// JobMemberLevel).
pub(super) fn nt_create_process_ex(arguments: &[u32]) -> NtStatus {
    status(create_process(arguments, arguments[4], arguments[8]))
}

/// NtCreateThread(*ThreadHandle, DesiredAccess, ObjectAttributes,
/// ProcessHandle, *ClientId, ThreadContext, InitialTeb, CreateSuspended) : un
/// thread du processus (`PROCESS_CREATE_THREAD`), qui démarre avec le
/// contexte donné (assaini), sur la pile que décrit `InitialTeb` ; son handle,
/// nommé (ou non) d'après les attributs, et son CLIENT_ID s'il est demandé.
/// Il ne part qu'une fois son handle donné, et pas avant sa reprise s'il est
/// créé suspendu. `STATUS_INVALID_PARAMETER` sans contexte.
pub(super) fn nt_create_thread(arguments: &[u32]) -> NtStatus {
    let (out, desired, attributes, process) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let (client_id, context, initial_teb) = (arguments[4], arguments[5], arguments[6]);
    // A BOOLEAN, in the low byte of its argument.
    let suspended = arguments[7] as u8 != 0;
    let create = || {
        if context == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if client_id != 0 {
            ke::usermem::probe_for_write(u64::from(client_id), core::mem::size_of::<ClientId32>(), 4)?;
        }
        let context = UserPtr::<Context32>::new(context).read()?;
        let teb = UserPtr::<InitialTeb32>::new(initial_teb).read()?;
        let process = super::reference_process(process, PROCESS_CREATE_THREAD)?;
        let stack = ps::InitialTeb {
            stack_base: teb.stack_base,
            stack_limit: teb.stack_limit,
            stack_allocation_base: teb.stack_allocation_base,
        };
        let thread = ps::create_thread_with_context(&process, &context, &stack, true)?;
        drop(process);
        let object: ObjectRef = thread.clone();
        let given = super::object::create_named(out, desired, attributes, object).and_then(|status| {
            if client_id != 0 {
                let id = ClientId32 { unique_process: thread.pid(), unique_thread: thread.tid() };
                UserPtr::<ClientId32>::new(client_id).write(&id)?;
            }
            Ok(status)
        });
        match given {
            Ok(status) => {
                if !suspended {
                    thread.resume();
                }
                Ok(status)
            }
            Err(failure) => {
                let _ = ps::terminate_thread(thread, failure);
                Err(failure)
            }
        }
    };
    status(create())
}

/// Écrit `count` en `previous`, s'il n'est pas nul.
fn give_previous_count(previous: u32, count: u32) -> Result<NtStatus, NtStatus> {
    if previous != 0 {
        UserPtr::<u32>::new(previous).write(&count)?;
    }
    Ok(STATUS_SUCCESS)
}

/// NtSuspendThread(ThreadHandle, *PreviousSuspendCount) : suspend le thread
/// (`THREAD_SUSPEND_RESUME`) ; rend le compte d'avant s'il est demandé.
pub(super) fn nt_suspend_thread(arguments: &[u32]) -> NtStatus {
    status(
        super::reference_thread(arguments[0], THREAD_SUSPEND_RESUME)
            .and_then(|thread| thread.suspend())
            .and_then(|count| give_previous_count(arguments[1], count)),
    )
}

/// NtResumeThread(ThreadHandle, *PreviousSuspendCount) : reprend le thread
/// (`THREAD_SUSPEND_RESUME`), qui repart quand le compte retombe à 0 ; rend
/// le compte d'avant s'il est demandé.
pub(super) fn nt_resume_thread(arguments: &[u32]) -> NtStatus {
    status(
        super::reference_thread(arguments[0], THREAD_SUSPEND_RESUME)
            .and_then(|thread| give_previous_count(arguments[1], thread.resume())),
    )
}

/// NtTerminateThread(ThreadHandle, ExitStatus) : termine le thread
/// (`THREAD_TERMINATE`, ou `NtCurrentThread()`) ; l'appel ne revient pas
/// s'il s'agit de l'appelant. NULL désigne le thread courant, sauf s'il est
/// le dernier de son processus (`STATUS_CANT_TERMINATE_SELF` : c'est au
/// processus de se terminer).
pub(super) fn nt_terminate_thread(arguments: &[u32]) -> NtStatus {
    let (handle, exit_status) = (arguments[0], NtStatus(arguments[1]));
    let terminate = || {
        let thread = match handle {
            0 => {
                let current = ps::ethread::current_thread().expect("a system service outside a Ps thread");
                if current.process().active_threads() == 1 {
                    return Err(STATUS_CANT_TERMINATE_SELF);
                }
                current
            }
            _ => super::reference_thread(handle, THREAD_TERMINATE)?,
        };
        // Ends the calling thread if it is the one: nothing on this stack may
        // own memory by then.
        ps::terminate_thread(thread, exit_status).map(|()| STATUS_SUCCESS)
    };
    status(terminate())
}

/// NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
/// ProcessInformation, ProcessInformationLength, ReturnLength) : ce que sait
/// le processus (`PROCESS_QUERY_INFORMATION`) :
/// - `ProcessBasicInformation` : son statut de sortie, son PEB, son masque
///   d'affinité, sa priorité de base, son PID et celui de son créateur ;
/// - `ProcessSessionInformation` : sa session.
///
/// Les autres classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur
/// premier appel.
pub(super) fn nt_query_information_process(arguments: &[u32]) -> NtStatus {
    let (handle, class, buffer, length, return_length) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    if class != PROCESS_BASIC_INFORMATION && class != PROCESS_SESSION_INFORMATION {
        return UNSUPPORTED_QUERY_CLASSES.report(class);
    }
    let process = match super::reference_process(handle, PROCESS_QUERY_INFORMATION) {
        Ok(process) => process,
        Err(status) => return status,
    };
    let word: [u8; 4];
    let basic: ProcessBasicInformation32;
    let information: &[u8] = match class {
        PROCESS_BASIC_INFORMATION => {
            basic = ProcessBasicInformation32 {
                exit_status: process.exit_status().0,
                peb_base_address: process.peb(),
                affinity_mask: 1,
                base_priority: NORMAL_BASE_PRIORITY,
                unique_process_id: process.pid(),
                inherited_from_unique_process_id: process.parent_pid(),
            };
            basic.as_bytes()
        }
        _ => {
            word = process.session_id().to_le_bytes();
            &word
        }
    };
    super::return_information(information, buffer, length, return_length)
}

/// NtSetInformationProcess(ProcessHandle, ProcessInformationClass,
/// ProcessInformation, ProcessInformationLength) : change ce que sait le
/// processus : `ProcessSessionInformation` (`PROCESS_SET_SESSIONID`), sa
/// session, que son PEB dit aussi ; `STATUS_INFO_LENGTH_MISMATCH` pour une
/// autre taille que 4 octets.
///
/// Les autres classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur
/// premier appel. `ProcessExecuteFlags` en est encore : le `ntdll` de
/// ReactOS y passe 0 sous `OptIn`, que `ps::eprocess::changed_execute_options`
/// refuse (il veut `DISABLE` ou `ENABLE`) ; à trancher avec l'ADR-020.
pub(super) fn nt_set_information_process(arguments: &[u32]) -> NtStatus {
    let (handle, class, buffer, length) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let set = || {
        if class != PROCESS_SESSION_INFORMATION {
            return Err(UNSUPPORTED_SET_CLASSES.report(class));
        }
        if length != 4 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let session_id = UserPtr::<u32>::new(buffer).read()?;
        super::reference_process(handle, PROCESS_SET_SESSIONID)?.set_session_id(session_id)?;
        Ok(STATUS_SUCCESS)
    };
    status(set())
}
