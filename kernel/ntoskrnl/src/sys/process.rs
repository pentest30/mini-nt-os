//! Les services de Ps.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};
use ps::eprocess::PROCESS_TERMINATE;

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
