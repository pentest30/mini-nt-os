//! Les services de win32k (la seconde table) : NtUserProcessConnect,
//! NtUserInitializeClientPfnArrays, NtUserInitialize, NtGdiInit.
//!
//! Le thread qui les appelle est déjà un thread GUI (`super::dispatch`).

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};
use ex::{Event, EVENT_ALL_ACCESS, EVENT_TYPE};
use ob::Handle;
use ps::eprocess::PROCESS_VM_OPERATION;

/// NtUserProcessConnect(ProcessHandle, UserConnect, Size) : le processus
/// (`PROCESS_VM_OPERATION`) devient un processus GUI, et le `USERCONNECT` de
/// l'appelant reçoit ce qu'il partage avec USER (`win32k::process_connect`) :
/// le `SERVERINFO`, la table des handles, l'écart vers sa vue de la section
/// partagée. `STATUS_UNSUCCESSFUL` pour un tampon nul ou d'une autre taille
/// que 0x124 octets, avant le handle.
pub(super) fn nt_user_process_connect(arguments: &[u32]) -> NtStatus {
    let (handle, buffer, size) = (arguments[0], arguments[1], arguments[2]);
    let connect = || {
        win32k::check_connect_buffer(buffer, size)?;
        let process = super::reference_process(handle, PROCESS_VM_OPERATION)?;
        win32k::process_connect(&process, buffer)
    };
    connect().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtUserInitializeClientPfnArrays(pfnClientA, pfnClientW, pfnClientWorker,
/// hmodUser) : au premier appel, les procédures de fenêtre de `user32` vont
/// dans le `SERVERINFO` partagé (`win32k::client`).
pub(super) fn nt_user_initialize_client_pfn_arrays(arguments: &[u32]) -> NtStatus {
    win32k::client::initialize_client_pfn_arrays(arguments[0], arguments[1], arguments[2], arguments[3])
        .map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtUserInitialize(dwWinVersion, hPowerRequestEvent, hMediaRequestEvent),
/// dans `csrss` : USER démarre (`win32k::csrss::initialize`) avec
/// l'événement des demandes d'alimentation (`EVENT_ALL_ACCESS`) ; celui des
/// changements de média n'est pas gardé (ReactOS non plus).
pub(super) fn nt_user_initialize(arguments: &[u32]) -> NtStatus {
    let (version, power_event) = (arguments[0], arguments[1]);
    let reference = || {
        super::current_process().handle_table.reference_as::<Event>(Handle(power_event), &EVENT_TYPE, EVENT_ALL_ACCESS)
    };
    win32k::csrss::initialize(version, reference).map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtGdiInit() : TRUE, GDI n'a rien à préparer pour le client (ReactOS non
/// plus).
pub(super) fn nt_gdi_init(_arguments: &[u32]) -> NtStatus {
    NtStatus(1)
}
