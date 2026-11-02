//! Les services de Ps : créer un processus (NtCreateProcess,
//! NtCreateProcessEx) et un thread (NtCreateThread), comme
//! `RtlCreateUserProcess` les demande ; suspendre et reprendre un thread ;
//! terminer un processus ou un thread ; dire et changer ce que sait un
//! processus, et rendre un thread critique.
//!
//! Pas encore : le clonage d'un espace d'adresses (une section nulle, le
//! `fork` de POSIX), les ports de débogage et d'exception, les jobs ; ils
//! rendent `STATUS_NOT_IMPLEMENTED`, journalisé une fois.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::context::Context32;
use abi::ntstatus::{
    NtStatus, STATUS_CANT_TERMINATE_SELF, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER,
    STATUS_NOT_IMPLEMENTED, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS,
};
use abi::process::{
    InitialTeb32, ProcessBasicInformation32, NT_CURRENT_PROCESS, PROCESS_BASE_PRIORITY, PROCESS_BASIC_INFORMATION,
    PROCESS_BREAK_ON_TERMINATION, PROCESS_COOKIE, PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
    PROCESS_CREATE_FLAGS_LEGAL_MASK, PROCESS_DEFAULT_HARD_ERROR_MODE, PROCESS_EXCEPTION_PORT,
    PROCESS_LUID_DEVICE_MAPS_ENABLED, PROCESS_SESSION_INFORMATION, THREAD_BREAK_ON_TERMINATION,
};
use abi::security::{SE_DEBUG_PRIVILEGE, SE_INC_BASE_PRIORITY_PRIVILEGE, SE_TCB_PRIVILEGE};
use abi::teb32::ClientId32;
use ke::usermem::UserPtr;
use mm::section::{Section, SECTION_MAP_EXECUTE, SECTION_TYPE};
use ob::{AccessMask, Handle, ObjectRef};
use ps::eprocess::{
    PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION,
    PROCESS_SET_SESSIONID, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
};
use ps::ethread::{THREAD_QUERY_INFORMATION, THREAD_SET_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_TERMINATE};

/// Les classes de NtQueryInformationProcess demandées sans être implémentées.
static UNSUPPORTED_QUERY_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryInformationProcess");
/// Les classes de NtSetInformationProcess demandées sans être implémentées.
static UNSUPPORTED_SET_CLASSES: super::ClassReport = super::ClassReport::new("NtSetInformationProcess");
/// Les classes de NtQueryInformationThread demandées sans être implémentées.
static UNSUPPORTED_THREAD_QUERY_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryInformationThread");
/// Les classes de NtSetInformationThread demandées sans être implémentées.
static UNSUPPORTED_THREAD_SET_CLASSES: super::ClassReport = super::ClassReport::new("NtSetInformationThread");

/// HIGH_PRIORITY : la plus haute priorité de base d'un processus.
const HIGH_PRIORITY: u32 = 31;
/// Le bit de ProcessBasePriority qui demande la priorité mémoire du premier
/// plan (MEMORY_PRIORITY_FOREGROUND).
const FOREGROUND_MEMORY_PRIORITY: u32 = 0x8000_0000;

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
/// - `ProcessSessionInformation` : sa session ;
/// - `ProcessDefaultHardErrorMode` : ses `SEM_*` ;
/// - `ProcessBreakOnTermination` : 1 s'il est critique, 0 sinon ;
/// - `ProcessLUIDDeviceMapsEnabled` : 0, les périphériques DOS sont ceux de
///   tous (le défaut d'XP) ;
/// - `ProcessCookie` : son cookie, tiré à la première demande, pour le
///   processus de l'appelant seulement (`NtCurrentProcess()`,
///   `STATUS_INVALID_PARAMETER` sinon).
///
/// Les autres classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur
/// premier appel.
pub(super) fn nt_query_information_process(arguments: &[u32]) -> NtStatus {
    let (handle, class, buffer, length, return_length) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    match class {
        PROCESS_BASIC_INFORMATION
        | PROCESS_SESSION_INFORMATION
        | PROCESS_DEFAULT_HARD_ERROR_MODE
        | PROCESS_BREAK_ON_TERMINATION => {}
        PROCESS_LUID_DEVICE_MAPS_ENABLED => {
            return super::return_information(&0u32.to_le_bytes(), buffer, length, return_length)
        }
        PROCESS_COOKIE if handle != NT_CURRENT_PROCESS => return STATUS_INVALID_PARAMETER,
        PROCESS_COOKIE => {
            // KeSystemCalls ^ InterruptTime ^ SystemTime for XP: the time
            // and the cycle counter here.
            let cookie = super::current_process().cookie(|| {
                let time = hal::rtc::system_time() ^ hal::timer::performance_counter().0;
                (time ^ (time >> 32)) as u32
            });
            return super::return_information(&cookie.to_le_bytes(), buffer, length, return_length);
        }
        _ => return UNSUPPORTED_QUERY_CLASSES.report(class),
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
                base_priority: i32::from(process.base_priority()),
                unique_process_id: process.pid(),
                inherited_from_unique_process_id: process.parent_pid(),
            };
            basic.as_bytes()
        }
        _ => {
            word = match class {
                PROCESS_SESSION_INFORMATION => process.session_id(),
                PROCESS_DEFAULT_HARD_ERROR_MODE => process.hard_error_mode(),
                _ => u32::from(process.is_critical()),
            }
            .to_le_bytes();
            &word
        }
    };
    super::return_information(information, buffer, length, return_length)
}

/// NtQueryInformationThread(ThreadHandle, ThreadInformationClass,
/// ThreadInformation, ThreadInformationLength, ReturnLength) : ce que sait le
/// thread (`THREAD_QUERY_INFORMATION`), à la taille exacte de la classe
/// (`STATUS_INFO_LENGTH_MISMATCH` sinon) :
/// - `ThreadBasicInformation` : son statut de sortie, son TEB, son
///   CLIENT_ID, son masque d'affinité (un processeur), sa priorité courante
///   et sa priorité de base relative à celle de son processus ;
/// - `ThreadTimes` : ses heures de création et de fin (0 tant qu'il vit).
///   Ses temps passés en mode noyau et en mode utilisateur sont nuls : Ke ne
///   les compte pas encore.
///
/// Les autres classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur
/// premier appel.
pub(super) fn nt_query_information_thread(arguments: &[u32]) -> NtStatus {
    use abi::process::{KernelUserTimes, ThreadBasicInformation32, THREAD_BASIC_INFORMATION, THREAD_TIMES};

    let (handle, class, buffer, length, return_length) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    if !matches!(class, THREAD_BASIC_INFORMATION | THREAD_TIMES) {
        return UNSUPPORTED_THREAD_QUERY_CLASSES.report(class);
    }
    let thread = match super::reference_thread(handle, THREAD_QUERY_INFORMATION) {
        Ok(thread) => thread,
        Err(status) => return status,
    };
    let basic: ThreadBasicInformation32;
    let times: KernelUserTimes;
    let information = if class == THREAD_BASIC_INFORMATION {
        let process_base = thread.process().base_priority();
        let priority = thread.priority().unwrap_or(process_base);
        let base = thread.base_priority().unwrap_or(process_base);
        basic = ThreadBasicInformation32 {
            exit_status: thread.exit_status().0,
            teb_base_address: thread.teb(),
            client_id: ClientId32 { unique_process: thread.pid(), unique_thread: thread.tid() },
            affinity_mask: 1,
            priority: i32::from(priority),
            base_priority: i32::from(base) - i32::from(process_base),
        };
        basic.as_bytes()
    } else {
        times = KernelUserTimes {
            create_time: thread.create_time(),
            exit_time: thread.exit_time().unwrap_or(0),
            kernel_time: 0,
            user_time: 0,
        };
        times.as_bytes()
    };
    super::return_information(information, buffer, length, return_length)
}

/// NtSetInformationProcess(ProcessHandle, ProcessInformationClass,
/// ProcessInformation, ProcessInformationLength) : change ce que sait le
/// processus, une valeur de 4 octets (`STATUS_INFO_LENGTH_MISMATCH` pour une
/// autre taille) :
/// - `ProcessSessionInformation` (`PROCESS_SET_SESSIONID`) : sa session, que
///   son PEB dit aussi ;
/// - `ProcessBasePriority` (`PROCESS_SET_INFORMATION`) : la priorité de base
///   de ses threads, de 1 à 31 (`STATUS_INVALID_PARAMETER` sinon) ; la
///   relever demande `SeIncreaseBasePriorityPrivilege`
///   (`STATUS_PRIVILEGE_NOT_HELD`). Le bit de poids fort, la priorité mémoire
///   du premier plan, est ignoré : pas de pagination ;
/// - `ProcessDefaultHardErrorMode` (`PROCESS_SET_INFORMATION`) : ses
///   `SEM_*`, que ses enfants héritent ;
/// - `ProcessBreakOnTermination` (`PROCESS_SET_INFORMATION`,
///   `SeDebugPrivilege`) : non nul, il devient critique, et sa fin arrête le
///   système ; nul, il ne l'est plus ;
/// - `ProcessExceptionPort` (`PROCESS_SET_INFORMATION`,
///   `PROCESS_SUSPEND_RESUME`, `SeTcbPrivilege`) : le handle d'un port LPC
///   (`STATUS_OBJECT_TYPE_MISMATCH` pour un autre objet), où iraient ses
///   exceptions non traitées ; une fois (`STATUS_PORT_ALREADY_SET`). Le
///   noyau ne s'en sert pas encore.
///
/// Les autres classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur
/// premier appel. `ProcessExecuteFlags` en est encore : le `ntdll` de
/// ReactOS y passe 0 sous `OptIn`, que `ps::eprocess::changed_execute_options`
/// refuse (il veut `DISABLE` ou `ENABLE`) ; à trancher avec l'ADR-020.
pub(super) fn nt_set_information_process(arguments: &[u32]) -> NtStatus {
    let (handle, class, buffer, length) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let set = || {
        if !matches!(
            class,
            PROCESS_SESSION_INFORMATION
                | PROCESS_BASE_PRIORITY
                | PROCESS_DEFAULT_HARD_ERROR_MODE
                | PROCESS_BREAK_ON_TERMINATION
                | PROCESS_EXCEPTION_PORT
        ) {
            return Err(UNSUPPORTED_SET_CLASSES.report(class));
        }
        if length != 4 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let value = UserPtr::<u32>::new(buffer).read()?;
        if class == PROCESS_SESSION_INFORMATION {
            super::reference_process(handle, PROCESS_SET_SESSIONID)?.set_session_id(value)?;
            return Ok(STATUS_SUCCESS);
        }
        if class == PROCESS_EXCEPTION_PORT {
            let process = super::reference_process(handle, PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME)?;
            if !super::security::privilege_enabled(SE_TCB_PRIVILEGE) {
                return Err(STATUS_PRIVILEGE_NOT_HELD);
            }
            let port = super::current_process().handle_table.reference(
                Handle(value),
                Some(&lpc::PORT_TYPE),
                AccessMask::NONE,
            )?;
            process.set_exception_port(port)?;
            return Ok(STATUS_SUCCESS);
        }
        let process = super::reference_process(handle, PROCESS_SET_INFORMATION)?;
        match class {
            PROCESS_BASE_PRIORITY => {
                let base = value & !FOREGROUND_MEMORY_PRIORITY;
                if base == 0 || base > HIGH_PRIORITY {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let base = base as u8;
                if base > process.base_priority() && !super::security::privilege_enabled(SE_INC_BASE_PRIORITY_PRIVILEGE)
                {
                    return Err(STATUS_PRIVILEGE_NOT_HELD);
                }
                process.set_base_priority(base);
            }
            PROCESS_DEFAULT_HARD_ERROR_MODE => process.set_hard_error_mode(value),
            _ => {
                if !super::security::privilege_enabled(SE_DEBUG_PRIVILEGE) {
                    return Err(STATUS_PRIVILEGE_NOT_HELD);
                }
                process.set_critical(value != 0);
            }
        }
        Ok(STATUS_SUCCESS)
    };
    status(set())
}

/// NtSetInformationThread(ThreadHandle, ThreadInformationClass,
/// ThreadInformation, ThreadInformationLength) : change ce que sait le
/// thread : `ThreadBreakOnTermination` (`THREAD_SET_INFORMATION`,
/// `SeDebugPrivilege`), 4 octets : non nul, il devient critique, et sa fin
/// arrête le système ; nul, il ne l'est plus. `STATUS_INFO_LENGTH_MISMATCH`
/// pour une autre taille.
///
/// Les autres classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur
/// premier appel.
pub(super) fn nt_set_information_thread(arguments: &[u32]) -> NtStatus {
    let (handle, class, buffer, length) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let set = || {
        if class != THREAD_BREAK_ON_TERMINATION {
            return Err(UNSUPPORTED_THREAD_SET_CLASSES.report(class));
        }
        if length != 4 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let critical = UserPtr::<u32>::new(buffer).read()? != 0;
        let thread = super::reference_thread(handle, THREAD_SET_INFORMATION)?;
        if !super::security::privilege_enabled(SE_DEBUG_PRIVILEGE) {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        thread.set_critical(critical);
        Ok(STATUS_SUCCESS)
    };
    status(set())
}

/// NtFlushInstructionCache(ProcessHandle, BaseAddress, Length) : rien à
/// vider, le cache d'instructions d'x86 suit les écritures ; le processus est
/// vérifié (`PROCESS_VM_WRITE`, ou `NtCurrentProcess()`).
pub(super) fn nt_flush_instruction_cache(arguments: &[u32]) -> NtStatus {
    status(super::reference_process(arguments[0], ps::eprocess::PROCESS_VM_WRITE).map(|_| STATUS_SUCCESS))
}

/// Ce qu'ouvrent NtOpenProcess et NtOpenThread.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Opened {
    Process,
    Thread,
}

/// NtOpenProcess et NtOpenThread(*Handle, DesiredAccess, ObjectAttributes,
/// ClientId) : un handle sur le processus ou le thread que désigne le
/// CLIENT_ID (un thread et son processus, ou un processus seul pour
/// NtOpenProcess ; un thread seul ou dans son processus pour NtOpenThread),
/// ou le nom des attributs, avec les droits demandés et l'héritage des
/// attributs (`OBJ_INHERIT`). `STATUS_INVALID_PARAMETER_MIX` pour un nom et
/// un CLIENT_ID, ou ni l'un ni l'autre ; `STATUS_INVALID_CID` pour un
/// CLIENT_ID qui ne désigne rien. Le contrôle d'accès est permissif
/// (ADR-011).
fn open(arguments: &[u32], opened: Opened) -> Result<NtStatus, NtStatus> {
    use abi::ntstatus::{STATUS_INVALID_CID, STATUS_INVALID_PARAMETER_MIX};

    let (out, desired, attributes, client_id) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let out = UserPtr::<u32>::new(out);
    out.write(&0)?;
    let captured = super::object::capture_attributes(attributes)?;
    let client = match client_id {
        0 => None,
        at => Some(UserPtr::<ClientId32>::new(at).read()?),
    };
    let expected: &ob::ObjectType = match opened {
        Opened::Process => &ps::PROCESS_TYPE,
        Opened::Thread => &ps::THREAD_TYPE,
    };
    let process = super::current_process();
    let handle = match (captured.name, client) {
        (Some(_), Some(_)) | (None, None) => return Err(STATUS_INVALID_PARAMETER_MIX),
        (Some(name), None) => ob::open_object_by_name(
            ob::namespace(),
            &name,
            captured.root.as_ref(),
            Some(expected),
            captured.attributes,
            &process.handle_table,
            ob::AccessMask(desired),
        )?,
        (None, Some(client)) => {
            let thread = match (opened, client.unique_thread, client.unique_process) {
                (_, 0, _) | (Opened::Thread, _, 0) => None,
                (_, tid, _) => Some(ps::ethread::lookup_thread(tid)?),
            };
            let checked = opened == Opened::Process || client.unique_process != 0;
            if thread.as_ref().is_some_and(|thread| checked && thread.pid() != client.unique_process) {
                return Err(STATUS_INVALID_CID);
            }
            let object: ObjectRef = match (opened, thread) {
                (Opened::Process, Some(thread)) => thread.process().clone(),
                (Opened::Process, None) => ps::lookup_process(client.unique_process)?,
                (Opened::Thread, Some(thread)) => thread,
                (Opened::Thread, None) => ps::ethread::lookup_thread(client.unique_thread)?,
            };
            let inherit = captured.attributes & abi::object::OBJ_INHERIT != 0;
            let attributes = ob::HandleAttributes { inherit, protect_from_close: false };
            process.handle_table.insert(object, ob::AccessMask(desired), attributes)?
        }
    };
    super::object::give_handle(&out, handle)?;
    Ok(STATUS_SUCCESS)
}

/// NtOpenProcess(*ProcessHandle, DesiredAccess, ObjectAttributes, ClientId) :
/// voir [`open`].
pub(super) fn nt_open_process(arguments: &[u32]) -> NtStatus {
    status(open(arguments, Opened::Process))
}

/// NtOpenThread(*ThreadHandle, DesiredAccess, ObjectAttributes, ClientId) :
/// voir [`open`].
pub(super) fn nt_open_thread(arguments: &[u32]) -> NtStatus {
    status(open(arguments, Opened::Thread))
}
