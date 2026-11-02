//! Les processus et threads GUI : ce que win32k garde d'eux
//! (`PROCESSINFO`, `THREADINFO`), créé quand un thread fait son premier
//! appel à win32k (PsConvertToGuiThread, puis les rappels de win32k pour le
//! processus et le thread : InitProcessCallback, InitThreadCallback).
//!
//! Un processus GUI reçoit sa vue de la section partagée de USER
//! ([`crate::shared`]), et son PEB la limite des lots de GDI
//! (`GdiDCAttributeList`). Un thread GUI reçoit, dans son TEB, son
//! `THREADINFO` (`Win32ThreadInfo`) et son `CLIENTINFO`
//! (`Win32ClientInfo`), que `user32` lit.
//!
//! Le `PROCESSINFO` et le `THREADINFO` ne sont vus des clients que par une
//! adresse du serveur, qu'ils comparent sans la suivre (ADR-021) :
//! [`process_server_address`], [`thread_server_address`].
//!
//! Pas encore : la pile noyau agrandie d'un thread GUI (pour les rappels du
//! mode utilisateur), la file de messages, le bureau et la disposition du
//! clavier (`hKL` et `CodePage` restent nuls, comme sous ReactOS sans
//! disposition chargée), la table des handles de GDI
//! (`GdiSharedHandleTable` reste nul).

use alloc::sync::Arc;
use core::mem::offset_of;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use abi::peb32::Peb32;
use abi::teb32::Teb32;
use abi::user::{ClientInfo32, TIF_CSRSSTHREAD, TIF_DONTATTACHQUEUE};
use ob::Object;
use ps::{EProcess, EThread};

/// GDI_BATCH_LIMIT : les appels de GDI qu'un client met en lot au plus
/// (`PEB.GdiDCAttributeList`).
pub const GDI_BATCH_LIMIT: u32 = 20;

/// Ce que win32k garde d'un processus GUI (`PROCESSINFO`).
#[derive(Debug)]
pub struct ProcessInfo {
    /// Son adresse du serveur, que voient les clients (`CLIENTINFO.ppi`).
    pub server: u32,
    /// L'adresse de sa vue de la section partagée de USER.
    pub shared_view: u32,
}

/// Ce que win32k garde d'un thread GUI (`THREADINFO`).
#[derive(Debug)]
pub struct ThreadInfo {
    /// Son adresse du serveur (`TEB.Win32ThreadInfo`).
    pub server: u32,
    /// Ses `TIF_*`.
    pub ti_flags: u32,
}

/// L'adresse du serveur du `PROCESSINFO` du processus `pid` : une adresse
/// de 16 octets par PID dans `0x80000000`–`0x8FFFFFFF`, unique tant qu'il
/// vit, où un client ne peut rien lire. Les PID sont sous 2^26 (la table des
/// CID a 2^24 entrées).
pub const fn process_server_address(pid: u32) -> u32 {
    0x8000_0000 | ((pid >> 2) << 4)
}

/// L'adresse du serveur du `THREADINFO` du thread `tid`, de même dans
/// `0x90000000`–`0x9FFFFFFF`.
pub const fn thread_server_address(tid: u32) -> u32 {
    0x9000_0000 | ((tid >> 2) << 4)
}

/// RtlGetExpWinVer : la version du système qu'attend une image de
/// sous-système `major.minor`, `MAKEWORD(minor, major)` ; une version 1
/// compte pour 3.10 (Windows 3.1).
pub const fn exp_win_ver(major: u32, minor: u32) -> u32 {
    if major == 1 {
        0x030A
    } else {
        ((major & 0xFF) << 8) | (minor & 0xFF)
    }
}

/// Les `TIF_*` d'un nouveau thread GUI : ceux de `csrss`
/// (`TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE`) pour un thread de `csrss`, et
/// pour tous tant que `csrss` ne s'est pas déclaré (InitThreadCallback de
/// ReactOS) ; aucun sinon.
pub const fn thread_flags(csrss: u32, pid: u32) -> u32 {
    if csrss == 0 || csrss == pid {
        TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE
    } else {
        0
    }
}

/// Le `PROCESSINFO` de `process`, créé s'il n'en a pas : sa vue de la
/// section partagée, la limite des lots de GDI dans son PEB.
///
/// # Errors
/// Celles de la projection de la section ; `STATUS_PROCESS_IS_TERMINATING`
/// pour un processus sans espace d'adresses.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn process_info(process: &Arc<Object<EProcess>>) -> Result<Arc<ProcessInfo>, NtStatus> {
    if let Some(info) = process.win32_process() {
        return Ok(downcast(info));
    }
    let view = process.with_space(crate::shared::map_into)??;
    let unmap = || {
        let _ = process.with_space(|space| space.unmap_view(u64::from(view)));
    };
    let peb = u64::from(process.peb()) + offset_of!(Peb32, gdi_dc_attribute_list) as u64;
    if let Err(status) = process.write_memory(peb, &GDI_BATCH_LIMIT.to_le_bytes()) {
        unmap();
        return Err(status);
    }
    let created = Arc::new(ProcessInfo { server: process_server_address(process.pid()), shared_view: view });
    let kept = downcast(process.set_win32_process(created.clone()));
    if !Arc::ptr_eq(&kept, &created) {
        // Another thread of the process converted it first: its view is
        // the process's, not this one.
        unmap();
    }
    Ok(kept)
}

/// PsConvertToGuiThread : le thread courant devient un thread GUI, s'il ne
/// l'est pas, et son processus un processus GUI ; rend son `THREADINFO`.
/// Son TEB reçoit son `THREADINFO` et son `CLIENTINFO`.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` hors d'un thread de Ps ; celles de
/// [`process_info`] et de l'écriture du TEB.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread, à son appel système.
pub fn convert_current_thread() -> Result<Arc<ThreadInfo>, NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    if let Some(info) = thread.win32_thread() {
        return Ok(downcast(info));
    }
    let process = thread.process().clone();
    let process_info = process_info(&process)?;
    let info = Arc::new(ThreadInfo {
        server: thread_server_address(thread.tid()),
        ti_flags: thread_flags(crate::csrss::csrss(), process.pid()),
    });
    write_teb(&thread, &process, &process_info, &info)?;
    Ok(downcast(thread.set_win32_thread(info)))
}

/// Écrit dans le TEB de `thread` son `THREADINFO` et son `CLIENTINFO`.
fn write_teb(
    thread: &EThread,
    process: &EProcess,
    process_info: &ProcessInfo,
    info: &ThreadInfo,
) -> Result<(), NtStatus> {
    let mut version = [0u8; 8];
    let at = u64::from(process.peb()) + offset_of!(Peb32, image_subsystem_major_version) as u64;
    process.read_memory(at, &mut version)?;
    let major = u32::from_le_bytes([version[0], version[1], version[2], version[3]]);
    let minor = u32::from_le_bytes([version[4], version[5], version[6], version[7]]);
    let client = ClientInfo32 {
        exp_win_ver: exp_win_ver(major, minor),
        ti_flags: info.ti_flags,
        ppi: process_info.server,
        ..ClientInfo32::default()
    };
    let teb = u64::from(thread.teb());
    process.write_memory(teb + offset_of!(Teb32, win32_thread_info) as u64, &info.server.to_le_bytes())?;
    process.write_memory(teb + offset_of!(Teb32, win32_client_info) as u64, client.as_bytes())
}

/// Ce que Ps garde pour win32k est toujours de ses types.
fn downcast<T: Send + Sync + 'static>(any: Arc<dyn core::any::Any + Send + Sync>) -> Arc<T> {
    any.downcast::<T>().unwrap_or_else(|_| panic!("a Win32 slot of Ps holds another type"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_are_unique_per_id_and_out_of_reach() {
        assert_eq!(process_server_address(4), 0x8000_0010);
        assert_eq!(process_server_address(0x03FF_FFFC), 0x8FFF_FFF0, "the last PID");
        assert_eq!(thread_server_address(8), 0x9000_0020);
        assert_ne!(process_server_address(8), process_server_address(12));
    }

    #[test]
    fn the_expected_version_comes_from_the_subsystem_version() {
        assert_eq!(exp_win_ver(4, 0), 0x0400);
        assert_eq!(exp_win_ver(5, 1), 0x0501);
        assert_eq!(exp_win_ver(1, 0), 0x030A, "1.x is Windows 3.1");
    }

    #[test]
    fn threads_are_csrss_threads_until_csrss_is_known() {
        assert_eq!(thread_flags(0, 20), TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE);
        assert_eq!(thread_flags(20, 20), TIF_CSRSSTHREAD | TIF_DONTATTACHQUEUE);
        assert_eq!(thread_flags(20, 24), 0);
    }
}
