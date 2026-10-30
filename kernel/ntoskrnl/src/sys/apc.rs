//! Les APC utilisateur (02 §6.5, `ke::apc`) : NtQueueApcThread les met en
//! file, une attente alertable ou NtTestAlert les rend livrables, et le
//! retour en mode utilisateur par la trame de trap ([`install`]) les livre à
//! `ntdll!KiUserApcDispatcher`, après `int 2Eh` comme après SYSENTER.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};
use hal::trap::{set_user_return_hook, KTrapFrame};
use ke::sched::KePlatform;
use ps::ethread::THREAD_SET_CONTEXT;

/// Branche la livraison des APC utilisateur au retour en mode utilisateur.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn install() {
    set_user_return_hook(Some(user_return));
}

/// Le retour en mode utilisateur d'un thread de Ps, interruptions masquées :
/// le premier APC utilisateur qu'il doit recevoir. Une pile qui ne reçoit pas
/// le contexte lève l'exception de la copie.
fn user_return(frame: &mut KTrapFrame) {
    if ke::sched::current_thread_owner().is_null() {
        return;
    }
    x86_64::instructions::interrupts::enable();
    if let Err(status) = ke::apc::ki_deliver_user_apc(frame) {
        super::exceptions::raise(frame, status, &[]);
    }
    x86_64::instructions::interrupts::disable();
}

/// NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2,
/// ApcArgument3) : `ApcRoutine(ApcArgument1, ApcArgument2, ApcArgument3)`
/// dans le mode utilisateur du thread, après sa prochaine attente alertable ;
/// le handle demande `THREAD_SET_CONTEXT`.
pub(super) fn nt_queue_apc_thread(arguments: &[u32]) -> NtStatus {
    let thread = match super::reference_thread(arguments[0], THREAD_SET_CONTEXT) {
        Ok(thread) => thread,
        Err(status) => return status,
    };
    match thread.queue_user_apc(arguments[1], arguments[2], arguments[3], arguments[4]) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// NtTestAlert() : les APC utilisateur en file seront livrés au retour en
/// mode utilisateur. (Pas encore d'alertes : jamais STATUS_ALERTED.)
pub(super) fn nt_test_alert(_arguments: &[u32]) -> NtStatus {
    ke::apc::ke_test_alert_thread::<KePlatform>();
    STATUS_SUCCESS
}
