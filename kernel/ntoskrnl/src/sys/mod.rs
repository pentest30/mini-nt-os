//! Les services système (02 §6.2) : KiSystemService pour les threads de Ps,
//! sur les tables générées à partir de ReactOS (`abi::services`).
//!
//! Un appel système arrive par `int 2Eh` ou SYSENTER ([`gates`], sur la
//! trame de trap) avec le numéro du service dans EAX et ses arguments dans
//! la pile utilisateur. [`dispatch`] trouve le service, copie
//! ses arguments (`ke::usermem`) et appelle son handler, interruptions
//! actives, à PASSIVE_LEVEL : il peut attendre ou être préempté. Un numéro
//! hors des tables rend `STATUS_INVALID_SYSTEM_SERVICE` ; un service sans
//! handler, `STATUS_NOT_IMPLEMENTED`, journalisé à son premier appel.
//!
//! Un service peut aussi donner au thread un nouveau contexte, dans sa trame
//! de trap ([`Handler::Frame`] : NtContinue, NtRaiseException).
//!
//! Chaque appel est compté, par service ; [`service_calls`] rend les
//! services appelés depuis [`reset_service_calls`], dans l'ordre de leur
//! premier appel, avec ce qu'il a rendu (spike S1 : les appels système que
//! fait `ntdll`).
//!
//! Les threads de l'ancien chargeur gardent leur dispatcher (`syscall.rs`),
//! qui a ses propres numéros, jusqu'à sa suppression.

pub mod apc;
pub mod exceptions;
mod file;
pub mod gates;
mod memory;
mod object;
mod process;
mod registry;
mod section;
mod system;
mod wait;

pub(crate) use system::processor_information;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_SYSTEM_SERVICE, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS,
};
use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
use abi::service::{lookup, Table};
use abi::services::{self, NTOSKRNL, WIN32K};
use hal::trap::KTrapFrame;
use ob::{AccessMask, Handle, Object};
use ps::{EProcess, EThread, PROCESS_TYPE, THREAD_TYPE};

/// Le handler d'un service, qui reçoit ses arguments, un mot de 32 bits
/// chacun.
#[derive(Clone, Copy)]
pub enum Handler {
    /// Rend un statut, pour EAX.
    Status(fn(&[u32]) -> NtStatus),
    /// Met dans la trame de trap le nouveau contexte du thread, ou rend un
    /// statut d'erreur pour EAX.
    Frame(fn(&[u32], &mut KTrapFrame) -> Result<(), NtStatus>),
}

/// Ce qu'un service laisse au thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Un statut, pour EAX.
    Status(NtStatus),
    /// Sa trame de trap tient son nouveau contexte.
    Frame,
}

/// Les services implémentés, par numéro. `tools/syscall-gen` en tire le
/// rapport de couverture (`docs/compat/syscalls.md`) : une entrée par ligne,
/// `(services::NtNom, Handler::…(module::handler)),`.
pub const IMPLEMENTED: &[(u32, Handler)] = &[
    (services::NtAllocateVirtualMemory, Handler::Status(memory::nt_allocate_virtual_memory)),
    (services::NtClose, Handler::Status(object::nt_close)),
    (services::NtContinue, Handler::Frame(exceptions::nt_continue)),
    (services::NtCreateDirectoryObject, Handler::Status(object::nt_create_directory_object)),
    (services::NtCreateFile, Handler::Status(file::nt_create_file)),
    (services::NtCreateKey, Handler::Status(registry::nt_create_key)),
    (services::NtCreateSection, Handler::Status(section::nt_create_section)),
    (services::NtCreateSymbolicLinkObject, Handler::Status(object::nt_create_symbolic_link_object)),
    (services::NtDelayExecution, Handler::Status(wait::nt_delay_execution)),
    (services::NtDeleteValueKey, Handler::Status(registry::nt_delete_value_key)),
    (services::NtEnumerateKey, Handler::Status(registry::nt_enumerate_key)),
    (services::NtEnumerateValueKey, Handler::Status(registry::nt_enumerate_value_key)),
    (services::NtFlushBuffersFile, Handler::Status(file::nt_flush_buffers_file)),
    (services::NtFlushKey, Handler::Status(registry::nt_flush_key)),
    (services::NtFreeVirtualMemory, Handler::Status(memory::nt_free_virtual_memory)),
    (services::NtMapViewOfSection, Handler::Status(section::nt_map_view_of_section)),
    (services::NtOpenDirectoryObject, Handler::Status(object::nt_open_directory_object)),
    (services::NtOpenFile, Handler::Status(file::nt_open_file)),
    (services::NtOpenKey, Handler::Status(registry::nt_open_key)),
    (services::NtOpenSection, Handler::Status(section::nt_open_section)),
    (services::NtOpenSymbolicLinkObject, Handler::Status(object::nt_open_symbolic_link_object)),
    (services::NtProtectVirtualMemory, Handler::Status(memory::nt_protect_virtual_memory)),
    (services::NtQueryAttributesFile, Handler::Status(file::nt_query_attributes_file)),
    (services::NtQueryFullAttributesFile, Handler::Status(file::nt_query_full_attributes_file)),
    (services::NtQueryInformationFile, Handler::Status(file::nt_query_information_file)),
    (services::NtQueryKey, Handler::Status(registry::nt_query_key)),
    (services::NtQuerySystemInformation, Handler::Status(system::nt_query_system_information)),
    (services::NtQueryValueKey, Handler::Status(registry::nt_query_value_key)),
    (services::NtQueryVirtualMemory, Handler::Status(memory::nt_query_virtual_memory)),
    (services::NtQueryVolumeInformationFile, Handler::Status(file::nt_query_volume_information_file)),
    (services::NtQueueApcThread, Handler::Status(apc::nt_queue_apc_thread)),
    (services::NtRaiseException, Handler::Frame(exceptions::nt_raise_exception)),
    (services::NtReadFile, Handler::Status(file::nt_read_file)),
    (services::NtSetInformationFile, Handler::Status(file::nt_set_information_file)),
    (services::NtSetValueKey, Handler::Status(registry::nt_set_value_key)),
    (services::NtTerminateProcess, Handler::Status(process::nt_terminate_process)),
    (services::NtTestAlert, Handler::Status(apc::nt_test_alert)),
    (services::NtUnmapViewOfSection, Handler::Status(section::nt_unmap_view_of_section)),
    (services::NtWriteFile, Handler::Status(file::nt_write_file)),
];

/// Au plus 63 arguments par service (`tools/syscall-gen`).
const MAX_ARGUMENTS: usize = 63;

/// Le handler de chaque service de ntoskrnl, par numéro.
static HANDLERS: [Option<Handler>; NTOSKRNL.len()] = handlers();

const fn handlers() -> [Option<Handler>; NTOSKRNL.len()] {
    let mut table: [Option<Handler>; NTOSKRNL.len()] = [None; NTOSKRNL.len()];
    let mut i = 0;
    while i < IMPLEMENTED.len() {
        let (number, handler) = IMPLEMENTED[i];
        assert!((number as usize) < NTOSKRNL.len(), "an implemented service outside the ntoskrnl table");
        assert!(table[number as usize].is_none(), "a service implemented twice");
        table[number as usize] = Some(handler);
        i += 1;
    }
    table
}

/// Le service `number` a un handler.
pub fn is_implemented(number: u32) -> bool {
    matches!(lookup(number), Some((Table::Ntoskrnl, _))) && HANDLERS[number as usize].is_some()
}

/// Les services sans handler déjà appelés : un bit par service, ntoskrnl
/// puis win32k.
static REPORTED: [AtomicU32; (NTOSKRNL.len() + WIN32K.len()).div_ceil(32)] =
    [const { AtomicU32::new(0) }; (NTOSKRNL.len() + WIN32K.len()).div_ceil(32)];

/// Autant de services, ntoskrnl puis win32k.
const SERVICES: usize = NTOSKRNL.len() + WIN32K.len();

/// Les appels de chaque service, ntoskrnl puis win32k.
static CALLS: [AtomicU32; SERVICES] = [const { AtomicU32::new(0) }; SERVICES];
/// Ce qu'a rendu son premier appel : un statut, [`NEW_CONTEXT`] ou
/// [`NOT_RETURNED`].
static FIRST_COMPLETION: [AtomicU64; SERVICES] = [const { AtomicU64::new(0) }; SERVICES];
/// Dans `FIRST_COMPLETION`, hors des statuts : un nouveau contexte.
const NEW_CONTEXT: u64 = 1 << 32;
/// Dans `FIRST_COMPLETION`, hors des statuts : le premier appel n'est pas
/// revenu (encore en cours, ou le thread s'est terminé dedans).
const NOT_RETURNED: u64 = 2 << 32;
/// Les services, dans l'ordre de leur premier appel : les `FIRST_COUNT`
/// premières entrées.
static FIRST_CALLS: [AtomicU16; SERVICES] = [const { AtomicU16::new(0) }; SERVICES];
static FIRST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Un service appelé : son nom, son numéro, ses appels et ce qu'a rendu le
/// premier ; `None` s'il n'est pas revenu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceCalls {
    pub name: &'static str,
    pub number: u32,
    pub calls: u32,
    pub first: Option<Completion>,
}

/// Remet à zéro les compteurs de [`service_calls`].
///
/// # IRQL
/// <= DISPATCH_LEVEL, quand aucun thread de Ps n'appelle de service.
pub fn reset_service_calls() {
    for calls in &CALLS {
        calls.store(0, Ordering::Relaxed);
    }
    FIRST_COUNT.store(0, Ordering::Release);
}

/// Les services appelés depuis [`reset_service_calls`], dans l'ordre de leur
/// premier appel.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn service_calls() -> Vec<ServiceCalls> {
    let count = FIRST_COUNT.load(Ordering::Acquire).min(SERVICES);
    FIRST_CALLS[..count]
        .iter()
        .map(|slot| {
            let bit = usize::from(slot.load(Ordering::Relaxed));
            let number = if bit < NTOSKRNL.len() { bit as u32 } else { WIN32K_BASE | (bit - NTOSKRNL.len()) as u32 };
            let name = lookup(number).map_or("?", |(_, service)| service.name);
            let first = match FIRST_COMPLETION[bit].load(Ordering::Relaxed) {
                NOT_RETURNED => None,
                NEW_CONTEXT => Some(Completion::Frame),
                status => Some(Completion::Status(NtStatus(status as u32))),
            };
            ServiceCalls { name, number, calls: CALLS[bit].load(Ordering::Relaxed), first }
        })
        .collect()
}

/// Le premier numéro de la table de win32k.
const WIN32K_BASE: u32 = 1 << abi::service::TABLE_SHIFT;

/// Compte un appel du service d'indice `bit` ; `true` pour le premier.
fn count_call(bit: usize) -> bool {
    if CALLS[bit].fetch_add(1, Ordering::Relaxed) != 0 {
        return false;
    }
    FIRST_COMPLETION[bit].store(NOT_RETURNED, Ordering::Relaxed);
    let at = FIRST_COUNT.fetch_add(1, Ordering::AcqRel);
    if let Some(slot) = FIRST_CALLS.get(at) {
        slot.store(bit as u16, Ordering::Relaxed);
    }
    true
}

/// Note ce qu'a rendu le premier appel du service d'indice `bit`.
fn note_first(bit: usize, completion: Completion) {
    let value = match completion {
        Completion::Status(status) => u64::from(status.0),
        Completion::Frame => NEW_CONTEXT,
    };
    FIRST_COMPLETION[bit].store(value, Ordering::Relaxed);
}

/// KiSystemService : le service `number`, avec ses arguments copiés depuis
/// l'adresse utilisateur `arguments` ; `frame` est la trame de trap du
/// thread.
///
/// # IRQL
/// PASSIVE_LEVEL, interruptions actives, dans un thread de Ps.
pub fn dispatch(number: u32, arguments: u32, frame: &mut KTrapFrame) -> Completion {
    let Some((table, service)) = lookup(number) else {
        return Completion::Status(STATUS_INVALID_SYSTEM_SERVICE);
    };
    let count = service.argument_bytes as usize / 4;
    let mut bytes = [0u8; MAX_ARGUMENTS * 4];
    if let Err(status) = ke::usermem::copy_from_user(&mut bytes[..count * 4], u64::from(arguments)) {
        return Completion::Status(status);
    }
    let mut words = [0u32; MAX_ARGUMENTS];
    for (word, chunk) in words.iter_mut().zip(bytes[..count * 4].chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let index = (number & abi::service::INDEX_MASK) as usize;
    let handler = match table {
        Table::Ntoskrnl => HANDLERS[index],
        Table::Win32k => None,
    };
    let bit = if table == Table::Ntoskrnl { index } else { NTOSKRNL.len() + index };
    let first = count_call(bit);
    let words = &words[..count];
    let completion = match handler {
        Some(Handler::Status(handler)) => Completion::Status(handler(words)),
        Some(Handler::Frame(handler)) => handler(words, frame).map_or_else(Completion::Status, |()| Completion::Frame),
        None => {
            let mask = 1 << (bit % 32);
            if REPORTED[bit / 32].fetch_or(mask, Ordering::Relaxed) & mask == 0 {
                // In both ABIs, the return address into the caller of the
                // `Zw` stub sits just under the arguments.
                let caller = arguments.checked_sub(4).and_then(|at| ke::usermem::UserPtr::<u32>::new(at).read().ok());
                log::warn!(
                    "sys: {} ({number:#06x}) is not implemented; called from {:#x?} with {:x?}",
                    service.name,
                    caller.unwrap_or(0),
                    words
                );
            }
            Completion::Status(STATUS_NOT_IMPLEMENTED)
        }
    };
    if first {
        note_first(bit, completion);
    }
    completion
}

/// Les classes d'information d'un service demandées sans être
/// implémentées : chacune est journalisée à son premier appel.
pub(super) struct ClassReport {
    service: &'static str,
    /// Un bit par classe ; la dernière vaut pour toutes celles au-delà.
    seen: [AtomicU32; 4],
}

impl ClassReport {
    pub(super) const fn new(service: &'static str) -> Self {
        Self { service, seen: [const { AtomicU32::new(0) }; 4] }
    }

    /// La classe `class` n'est pas implémentée : journalisée la première
    /// fois ; rend `STATUS_NOT_IMPLEMENTED`.
    pub(super) fn report(&self, class: u32) -> NtStatus {
        let bit = class.min(127) as usize;
        let mask = 1 << (bit % 32);
        if self.seen[bit / 32].fetch_or(mask, Ordering::Relaxed) & mask == 0 {
            log::warn!("sys: {} class {class:#x} is not implemented", self.service);
        }
        STATUS_NOT_IMPLEMENTED
    }
}

/// Rend l'information `information`, d'une taille fixe, dans le tampon
/// utilisateur de `length` octets en `buffer`, et sa taille en
/// `return_length` s'il n'est pas nul. `STATUS_INFO_LENGTH_MISMATCH` si
/// `length` n'est pas sa taille, la taille étant rendue quand même ;
/// `STATUS_DATATYPE_MISALIGNMENT` pour un tampon qui n'est pas aligné sur 4
/// octets ; `STATUS_ACCESS_VIOLATION` si l'écriture faute.
fn return_information(information: &[u8], buffer: u32, length: u32, return_length: u32) -> NtStatus {
    let size = information.len() as u32;
    let status = if length != size {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        match ke::usermem::probe_for_write(u64::from(buffer), information.len(), 4)
            .and_then(|()| ke::usermem::copy_to_user(u64::from(buffer), information))
        {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => return status,
        }
    };
    if return_length != 0 {
        if let Err(fault) = ke::usermem::UserPtr::<u32>::new(return_length).write(&size) {
            return fault;
        }
    }
    status
}

/// Le processus du thread courant, un thread de Ps.
fn current_process() -> Arc<Object<EProcess>> {
    ps::ethread::current_thread().expect("a system service outside a Ps thread").process().clone()
}

/// Le processus que désigne `handle` dans le processus courant, avec les
/// droits `access` ; `NtCurrentProcess()` désigne le processus courant.
fn reference_process(handle: u32, access: AccessMask) -> Result<Arc<Object<EProcess>>, NtStatus> {
    let current = current_process();
    if handle == NT_CURRENT_PROCESS {
        return Ok(current);
    }
    current.handle_table.reference_as::<EProcess>(Handle(handle), &PROCESS_TYPE, access)
}

/// Le thread que désigne `handle` dans le processus courant, avec les droits
/// `access` ; `NtCurrentThread()` désigne le thread courant.
fn reference_thread(handle: u32, access: AccessMask) -> Result<Arc<Object<EThread>>, NtStatus> {
    if handle == NT_CURRENT_THREAD {
        return Ok(ps::ethread::current_thread().expect("a system service outside a Ps thread"));
    }
    current_process().handle_table.reference_as::<EThread>(Handle(handle), &THREAD_TYPE, access)
}
