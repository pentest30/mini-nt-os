//! Les services de win32k (la seconde table) : NtUserProcessConnect,
//! NtUserInitializeClientPfnArrays, NtUserInitialize, NtGdiInit,
//! NtUserCallTwoParam (RegisterLogonProcess), NtUserSetInformationThread
//! (le port d'API de `csrss`).
//!
//! Le thread qui les appelle est déjà un thread GUI (`super::dispatch`).

use abi::ntstatus::{NtStatus, STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use abi::user::{TWOPARAM_ROUTINE_REGISTERLOGONPROCESS, USER_THREAD_CSR_API_PORT};
use abi::winerror::ERROR_CALL_NOT_IMPLEMENTED;
use ex::{Event, EVENT_ALL_ACCESS, EVENT_TYPE};
use ke::usermem::UserPtr;
use lpc::port::PORT_TYPE;
use ob::{AccessMask, Handle};
use ps::eprocess::PROCESS_VM_OPERATION;
use ps::ethread::THREAD_SET_INFORMATION;

/// Les routines de NtUserCallTwoParam demandées sans être implémentées.
static UNSUPPORTED_TWO_PARAM_ROUTINES: super::ClassReport = super::ClassReport::new("NtUserCallTwoParam");
/// Les classes de NtUserSetInformationThread demandées sans être
/// implémentées.
static UNSUPPORTED_USER_THREAD_CLASSES: super::ClassReport = super::ClassReport::new("NtUserSetInformationThread");

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

/// NtUserCallTwoParam(Param1, Param2, Routine) : la routine `Routine`,
/// qui rend une valeur. `TWOPARAM_ROUTINE_REGISTERLOGONPROCESS` : inscrit
/// le processus `Param1` comme processus de logon (`Param2` TRUE), ou le
/// désinscrit (`win32k::logon`). Une autre routine rend 0, avec
/// `ERROR_CALL_NOT_IMPLEMENTED` comme dernière erreur, journalisée une fois.
pub(super) fn nt_user_call_two_param(arguments: &[u32]) -> NtStatus {
    let (first, second, routine) = (arguments[0], arguments[1], arguments[2]);
    if routine == TWOPARAM_ROUTINE_REGISTERLOGONPROCESS {
        return NtStatus(u32::from(win32k::logon::register_logon_process(first, second != 0)));
    }
    UNSUPPORTED_TWO_PARAM_ROUTINES.report(routine);
    let _ = win32k::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    NtStatus(0)
}

/// NtUserSetInformationThread(ThreadHandle, ThreadInformationClass,
/// ThreadInformation, ThreadInformationLength), pour `csrss` seul
/// (`STATUS_ACCESS_DENIED` sinon), sur un thread ouvert avec
/// `THREAD_SET_INFORMATION`. `UserThreadCsrApiPort` : le handle d'un port
/// LPC (4 octets) devient le port d'API de `csrss` pour win32k
/// (`win32k::csrss::set_api_port`). Les autres classes rendent
/// `STATUS_NOT_IMPLEMENTED`, journalisées une fois.
pub(super) fn nt_user_set_information_thread(arguments: &[u32]) -> NtStatus {
    let [handle, class, information, length] = arguments[..4] else { unreachable!("4 arguments") };
    let set = || {
        let process = super::current_process();
        if process.pid() != win32k::csrss::csrss() {
            return Err(STATUS_ACCESS_DENIED);
        }
        super::reference_thread(handle, THREAD_SET_INFORMATION)?;
        if class != USER_THREAD_CSR_API_PORT {
            return Err(UNSUPPORTED_USER_THREAD_CLASSES.report(class));
        }
        if length != 4 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let port = UserPtr::<u32>::new(information).read()?;
        let port = process.handle_table.reference(Handle(port), Some(&PORT_TYPE), AccessMask(0))?;
        win32k::csrss::set_api_port(port);
        Ok(())
    };
    set().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtGdiInit() : TRUE, GDI n'a rien à préparer pour le client (ReactOS non
/// plus).
pub(super) fn nt_gdi_init(_arguments: &[u32]) -> NtStatus {
    NtStatus(1)
}
