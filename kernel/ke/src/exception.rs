//! KiDispatchException pour le mode utilisateur (02 §6.5).
//!
//! Une exception d'un thread en mode utilisateur se livre sur sa pile : son
//! `CONTEXT`, tiré de la trame de trap, puis son `EXCEPTION_RECORD`, puis
//! leurs deux adresses ; le thread reprend dans le répartiteur d'exceptions
//! de ntdll (`KiUserExceptionDispatcher`). Celui-ci cherche un gestionnaire
//! (SEH), puis appelle NtContinue avec le contexte, ou NtRaiseException en
//! seconde chance.
//!
//! Sans débogueur ni port d'exception, une seconde chance, une exception
//! sans répartiteur, ou une pile qui ne reçoit pas le contexte terminent le
//! processus avec le code de l'exception ; c'est à l'appelant de le faire.

use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::context::{Context32, CONTEXT_FULL};
use abi::exception::ExceptionRecord32;
use abi::ntstatus::NtStatus;
use hal::trap::KTrapFrame;

use crate::context::{context_from_trap_frame, UserSelectors};
use crate::usermem::{copy_to_user, UserPtr};

/// KeUserExceptionDispatcher : l'adresse de `ntdll!KiUserExceptionDispatcher`,
/// la même dans chaque processus ; 0 sans ntdll.
static USER_EXCEPTION_DISPATCHER: AtomicU32 = AtomicU32::new(0);

/// TF : le pas à pas, qui ne suit pas le thread dans le répartiteur.
const EFLAGS_TF: u64 = 0x100;

/// Fixe le répartiteur d'exceptions du mode utilisateur ; 0 n'en laisse
/// aucun.
///
/// # IRQL
/// Tout niveau.
pub fn set_user_exception_dispatcher(address: u32) {
    USER_EXCEPTION_DISPATCHER.store(address, Ordering::Release);
}

/// Le répartiteur d'exceptions du mode utilisateur ; 0 sans ntdll.
///
/// # IRQL
/// Tout niveau.
pub fn user_exception_dispatcher() -> u32 {
    USER_EXCEPTION_DISPATCHER.load(Ordering::Acquire)
}

/// KiDispatchException pour une exception du mode utilisateur, dont la trame
/// est `frame`. En première chance, avec un répartiteur, le contexte et
/// l'enregistrement vont sur la pile du thread et la trame reprend dans le
/// répartiteur. Sinon, ou si la pile ne les reçoit pas, `Err` donne le code
/// avec lequel le processus doit se terminer.
///
/// # IRQL
/// PASSIVE_LEVEL. Écrit sur la pile utilisateur.
pub fn dispatch_user_exception(
    record: &ExceptionRecord32,
    frame: &mut KTrapFrame,
    first_chance: bool,
) -> Result<(), NtStatus> {
    let code = NtStatus(record.exception_code);
    let dispatcher = user_exception_dispatcher();
    if !first_chance || dispatcher == 0 {
        return Err(code);
    }
    let mut context = Context32::zeroed();
    context.context_flags = CONTEXT_FULL;
    context_from_trap_frame(frame, CONTEXT_FULL, &mut context);
    // CONTEXT, then the record's used part, then their two addresses, each
    // 4-byte aligned under the thread's stack pointer.
    let context_at = (frame.rsp as u32 & !3).checked_sub(size_of::<Context32>() as u32).ok_or(code)?;
    let record_size = record.stack_size();
    let record_at = context_at.checked_sub(record_size as u32).ok_or(code)?;
    let arguments_at = record_at.checked_sub(8).ok_or(code)?;
    UserPtr::<Context32>::new(context_at).write(&context).map_err(|_| code)?;
    copy_to_user(u64::from(record_at), &record.as_bytes()[..record_size]).map_err(|_| code)?;
    UserPtr::<[u32; 2]>::new(arguments_at).write(&[record_at, context_at]).map_err(|_| code)?;

    let selectors = UserSelectors::current();
    frame.rsp = u64::from(arguments_at);
    frame.rip = u64::from(dispatcher);
    frame.rflags &= !EFLAGS_TF;
    frame.cs = u64::from(selectors.code);
    frame.ss = u64::from(selectors.data);
    frame.ds = u64::from(selectors.data);
    frame.es = u64::from(selectors.data);
    frame.fs = u64::from(selectors.teb);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_dispatcher_in_second_chance_or_without_stack_the_process_ends() {
        let record = ExceptionRecord32::new(0xC000_0005, 0x40_1000, &[1, 0]);
        let mut frame = KTrapFrame { rip: 0x40_1000, rsp: 0x12_FF00, ..KTrapFrame::default() };
        let before = frame;
        let code = Err(NtStatus(0xC000_0005));
        assert_eq!(dispatch_user_exception(&record, &mut frame, true), code, "no dispatcher");
        set_user_exception_dispatcher(0x7C90_0000);
        assert_eq!(dispatch_user_exception(&record, &mut frame, false), code, "second chance");
        let mut low = KTrapFrame { rsp: 0x100, ..before };
        assert_eq!(dispatch_user_exception(&record, &mut low, true), code, "no room under ESP");
        set_user_exception_dispatcher(0);
        assert_eq!((frame, low.rsp), (before, 0x100), "the frame does not change");
    }
}
