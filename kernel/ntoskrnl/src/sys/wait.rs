//! Les attentes du mode utilisateur (`ke::dispatcher`).

use abi::ntstatus::NtStatus;
use ke::dispatcher::{ke_delay_execution_thread, ProcessorMode};
use ke::sched::KePlatform;
use ke::usermem::UserPtr;

/// NtDelayExecution(Alertable, DelayInterval) : attend l'intervalle (format
/// NT : négatif relatif, positif absolu), STATUS_SUCCESS à l'échéance ; une
/// attente alertable finit sur un APC utilisateur (STATUS_USER_APC).
pub(super) fn nt_delay_execution(arguments: &[u32]) -> NtStatus {
    let interval = match UserPtr::<i64>::new(arguments[1]).read() {
        Ok(interval) => interval,
        Err(status) => return status,
    };
    // A BOOLEAN, in the low byte of its argument.
    let alertable = arguments[0] as u8 != 0;
    // SAFETY: a Ps thread, at PASSIVE_LEVEL, interrupts enabled.
    unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::User, alertable, interval) }
}
