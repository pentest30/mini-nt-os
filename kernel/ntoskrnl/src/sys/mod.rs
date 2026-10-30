//! Les services système (02 §6.2) : KiSystemService pour les threads de Ps,
//! sur les tables générées à partir de ReactOS (`abi::services`).
//!
//! Un appel système arrive par `int 2Eh` ([`gates`], sur la trame de trap)
//! ou SYSENTER (`hal::sysenter`) avec le numéro du service dans EAX et
//! l'adresse de ses arguments dans la pile utilisateur. [`dispatch`] trouve le service, copie
//! ses arguments (`ke::usermem`) et appelle son handler, interruptions
//! actives, à PASSIVE_LEVEL : il peut attendre ou être préempté. Un numéro
//! hors des tables rend `STATUS_INVALID_SYSTEM_SERVICE` ; un service sans
//! handler, `STATUS_NOT_IMPLEMENTED`, journalisé à son premier appel.
//!
//! Un service peut aussi donner au thread un nouveau contexte, dans sa trame
//! de trap ([`Handler::Frame`] : NtContinue, NtRaiseException). SYSENTER n'a
//! pas encore de trame (son retour passe par ntdll, M3) : ces services y
//! rendent `STATUS_NOT_IMPLEMENTED`.
//!
//! Les threads de l'ancien chargeur gardent leur dispatcher (`syscall.rs`),
//! qui a ses propres numéros, jusqu'à sa suppression.

pub mod exceptions;
pub mod gates;
mod memory;
mod object;
mod process;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::ntstatus::{NtStatus, STATUS_INVALID_SYSTEM_SERVICE, STATUS_NOT_IMPLEMENTED};
use abi::process::NT_CURRENT_PROCESS;
use abi::service::{lookup, Table};
use abi::services::{self, NTOSKRNL, WIN32K};
use hal::trap::KTrapFrame;
use ob::{AccessMask, Handle, Object};
use ps::{EProcess, PROCESS_TYPE};

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
    (services::NtFreeVirtualMemory, Handler::Status(memory::nt_free_virtual_memory)),
    (services::NtRaiseException, Handler::Frame(exceptions::nt_raise_exception)),
    (services::NtTerminateProcess, Handler::Status(process::nt_terminate_process)),
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

/// KiSystemService : le service `number`, avec ses arguments copiés depuis
/// l'adresse utilisateur `arguments` ; `frame` est la trame de trap du
/// thread, s'il en a une.
///
/// # IRQL
/// PASSIVE_LEVEL, interruptions actives, dans un thread de Ps.
pub fn dispatch(number: u32, arguments: u32, frame: Option<&mut KTrapFrame>) -> Completion {
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
    let arguments = &words[..count];
    match (handler, frame) {
        (Some(Handler::Status(handler)), _) => Completion::Status(handler(arguments)),
        (Some(Handler::Frame(handler)), Some(frame)) => {
            handler(arguments, frame).map_or_else(Completion::Status, |()| Completion::Frame)
        }
        // SYSENTER, without a trap frame.
        (Some(Handler::Frame(_)), None) => Completion::Status(STATUS_NOT_IMPLEMENTED),
        (None, _) => {
            let bit = if table == Table::Ntoskrnl { index } else { NTOSKRNL.len() + index };
            let mask = 1 << (bit % 32);
            if REPORTED[bit / 32].fetch_or(mask, Ordering::Relaxed) & mask == 0 {
                log::warn!("sys: {} ({number:#06x}) is not implemented", service.name);
            }
            Completion::Status(STATUS_NOT_IMPLEMENTED)
        }
    }
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
