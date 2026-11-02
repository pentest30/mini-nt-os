//! Ce que le client enregistre auprès de USER : les procédures de fenêtre
//! de `user32` (NtUserInitializeClientPfnArrays), une fois pour toutes, dans
//! le `SERVERINFO` de la section partagée, où chaque client les relit
//! (`GETPFNCLIENTA`, `GETPFNCLIENTW`).

use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use abi::ntstatus::{NtStatus, STATUS_UNSUCCESSFUL};
use abi::user::{PfnClient32, PfnClientWorker32, ServerInfoHead32, FNID_NUMSERVERPROC};

use crate::shared;

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
    CLIENT_MODULE.store(module, Ordering::Release);
    Ok(())
}

/// L'adresse de `user32` dans le client qui a enregistré ses procédures ;
/// 0 avant.
///
/// # IRQL
/// Tout niveau.
pub fn client_module() -> u32 {
    CLIENT_MODULE.load(Ordering::Acquire)
}
