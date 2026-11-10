//! Ce que le client enregistre auprès de USER : les procédures de fenêtre
//! de `user32` (NtUserInitializeClientPfnArrays), une fois pour toutes, dans
//! le `SERVERINFO` de la section partagée, où chaque client les relit
//! (`GETPFNCLIENTA`, `GETPFNCLIENTW`). win32k en garde une copie, pour
//! reconnaître une procédure du serveur ([`server_procedure_of`]).

use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use abi::ntstatus::{NtStatus, STATUS_UNSUCCESSFUL};
use abi::user::{PfnClient32, PfnClientWorker32, ServerInfoHead32, FNID_FIRST, FNID_NUMSERVERPROC};
use hal::sync::KSpinLock;

use crate::shared;

/// Les procédures ANSI et Unicode du client, dans l'ordre des FNID.
static PROCEDURES: KSpinLock<Option<(PfnClient32, PfnClient32)>> = KSpinLock::new(None);

/// Les procédures sont enregistrées (ClientPfnInit).
static REGISTERED: AtomicBool = AtomicBool::new(false);
/// L'adresse de `user32` dans le client qui les a enregistrées
/// (hModClient).
static CLIENT_MODULE: AtomicU32 = AtomicU32::new(0);

/// NtUserInitializeClientPfnArrays : au premier appel, les procédures de
/// fenêtre du client (`PFNCLIENT` ANSI et Unicode en `client_a` et
/// `client_w`, `PFNCLIENTWORKER` en `worker`, dans le processus courant)
/// vont dans le `SERVERINFO`, et `module` (l'adresse de `user32`) est
/// retenu ; les appels suivants ne font rien. Comme ReactOS tant que ses
/// procédures du serveur manquent, `aStoCidPfn` reçoit les premières
/// procédures Unicode du client.
///
/// # Errors
/// `STATUS_ACCESS_VIOLATION` si la lecture d'un tableau faute ;
/// `STATUS_UNSUCCESSFUL` avant la section partagée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn initialize_client_pfn_arrays(client_a: u32, client_w: u32, worker: u32, module: u32) -> Result<(), NtStatus> {
    if REGISTERED.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut a = [0u8; size_of::<PfnClient32>()];
    let mut w = [0u8; size_of::<PfnClient32>()];
    let mut workers = [0u8; size_of::<PfnClientWorker32>()];
    ke::usermem::copy_from_user(&mut a, u64::from(client_a))?;
    ke::usermem::copy_from_user(&mut w, u64::from(client_w))?;
    ke::usermem::copy_from_user(&mut workers, u64::from(worker))?;
    if REGISTERED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let section = shared::section().ok_or(STATUS_UNSUCCESSFUL)?;
    let at = |field: usize| u64::from(shared::SERVER_INFO) + field as u64;
    section.write_kernel(at(offset_of!(ServerInfoHead32, apfn_client_a)), &a)?;
    section.write_kernel(at(offset_of!(ServerInfoHead32, apfn_client_w)), &w)?;
    section.write_kernel(at(offset_of!(ServerInfoHead32, apfn_client_worker)), &workers)?;
    section.write_kernel(at(offset_of!(ServerInfoHead32, a_sto_cid_pfn)), &w[..FNID_NUMSERVERPROC * 4])?;
    let words = |bytes: &[u8]| -> PfnClient32 {
        core::array::from_fn(|i| {
            u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]])
        })
    };
    *PROCEDURES.lock() = Some((words(&a), words(&w)));
    CLIENT_MODULE.store(module, Ordering::Release);
    Ok(())
}

/// Les procédures du client d'un test hôte.
#[cfg(test)]
pub(crate) fn set_procedures_for_test(ansi: PfnClient32, unicode: PfnClient32) {
    *PROCEDURES.lock() = Some((ansi, unicode));
}

/// GETPFNCLIENTA, GETPFNCLIENTW : la procédure du client (ANSI ou non) de
/// `fnid`, une fois les procédures enregistrées.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn client_procedure(fnid: u32, ansi: bool) -> Option<u32> {
    let index = usize::try_from(fnid.checked_sub(FNID_FIRST)?).ok()?;
    let procedures = PROCEDURES.lock();
    let (a, w) = procedures.as_ref()?;
    if ansi {
        a.get(index).copied()
    } else {
        w.get(index).copied()
    }
}

/// GETPFNSERVER : la procédure du serveur de `fnid` (de `FNID_SCROLLBAR` à
/// `FNID_SWITCH`). Comme ReactOS tant que ses procédures du serveur
/// manquent (`aStoCidPfn`), c'est celle, Unicode, du client.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn server_procedure(fnid: u32) -> Option<u32> {
    let index = usize::try_from(fnid.checked_sub(FNID_FIRST)?).ok()?;
    if index >= FNID_NUMSERVERPROC {
        return None;
    }
    client_procedure(fnid, false)
}

/// Si `procedure` est la procédure du client (ANSI ou non) d'un FNID qui a
/// une procédure du serveur, ce FNID (IntCreateClass, qui donne alors à la
/// classe la procédure du serveur).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn server_procedure_of(procedure: u32) -> Option<u32> {
    let procedures = PROCEDURES.lock();
    let (a, w) = procedures.as_ref()?;
    (0..FNID_NUMSERVERPROC).find(|&i| a[i] == procedure || w[i] == procedure).map(|i| FNID_FIRST + i as u32)
}

/// L'adresse de `user32` dans le client qui a enregistré ses procédures ;
/// 0 avant.
///
/// # IRQL
/// Tout niveau.
pub fn client_module() -> u32 {
    CLIENT_MODULE.load(Ordering::Acquire)
}
