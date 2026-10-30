//! Les services d'Ob.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};

/// NtClose(Handle) : ferme un handle du processus courant.
pub(super) fn nt_close(arguments: &[u32]) -> NtStatus {
    match super::current_process().handle_table.close(ob::Handle(arguments[0])) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}
