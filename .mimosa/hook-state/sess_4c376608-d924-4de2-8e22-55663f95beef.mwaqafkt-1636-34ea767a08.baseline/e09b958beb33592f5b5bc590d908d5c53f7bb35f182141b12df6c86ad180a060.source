//! Les rappels en mode utilisateur : le passage en mode utilisateur de
//! KeUserModeCallback (KiCallUserMode) et le retour de NtCallbackReturn,
//! sur `hal::callout`. `ps::callback` prépare la pile utilisateur et le TEB.
//!
//! Un thread dans un service système part en mode utilisateur sans quitter
//! ses trames noyau : pendant le rappel, sa pile initiale — où les entrées
//! depuis le mode utilisateur empilent leur trame de trap (TSS.RSP0,
//! SYSENTER_ESP) — descend sous elles. Le rappel finit par
//! NtCallbackReturn ([`callback_return`]), dont les trames sont abandonnées :
//! le thread revient dans [`call_user_mode`], qui rend ce que le rappel a
//! donné. Les rappels s'emboîtent : chaque [`Callout`], dans la pile noyau,
//! garde la pile initiale d'avant et le rappel qui l'englobe.
//!
//! Un thread qui se termine pendant un rappel le fait sur la pile du rappel
//! (comme NT) : les trames des rappels en cours sont abandonnées, sans que
//! ce qu'elles possèdent soit rendu.

use core::ffi::c_void;
use core::mem::size_of;

use abi::ntstatus::{NtStatus, STATUS_CALLBACK_POP_STACK, STATUS_NO_CALLBACK_ACTIVE};
use hal::trap::KTrapFrame;

use crate::sched;

/// Ce que NtCallbackReturn rend à KeUserModeCallback : l'adresse utilisateur
/// et la longueur du résultat, et le statut du rappel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackReturn {
    pub output: u32,
    pub length: u32,
    pub status: NtStatus,
}

/// Un rappel en cours (KCALLOUT_FRAME), dans la trame de
/// [`call_user_mode`].
struct Callout {
    /// Le pointeur de pile où `hal::callout::enter` revient.
    resume: u64,
    /// La pile initiale du thread avant le rappel.
    initial_stack: u64,
    /// Le rappel qui englobe celui-ci, ou nul.
    previous: *mut c_void,
    /// Ce qu'a rendu NtCallbackReturn.
    result: Option<CallbackReturn>,
}

/// KiCallUserMode : le thread courant exécute en mode utilisateur la trame
/// `frame` (en général, celle de son service, dont EIP et ESP mènent au
/// répartiteur des rappels de ntdll) jusqu'à son NtCallbackReturn ; rend ce
/// que celui-ci a donné.
///
/// # Safety
/// Le thread courant est un thread utilisateur, dans un service système,
/// à PASSIVE_LEVEL, interruptions actives ; `frame` le mène en mode
/// utilisateur (RPL 3). S'il se termine pendant le rappel, ses trames sont
/// abandonnées : l'appelant ne tient rien qui doive être rendu à ce
/// moment-là (verrou, objet attendu par d'autres).
///
/// # IRQL
/// PASSIVE_LEVEL. Peut ne pas revenir.
pub unsafe fn call_user_mode(frame: &KTrapFrame) -> CallbackReturn {
    debug_assert_eq!(frame.cs & 3, 3, "a callback to kernel mode");
    let (initial_stack, previous) = sched::current_callout_state();
    let mut callout = Callout { resume: 0, initial_stack, previous, result: None };
    let callout = &raw mut callout;
    x86_64::instructions::interrupts::without_interrupts(|| {
        // SAFETY: interrupts masked; `frame` goes to user mode (contract);
        // `on_switch` installs the initial stack it gets; `callout` lives in
        // this frame, which stays as it is until `callback_return` comes
        // back to it.
        unsafe { hal::callout::enter(frame, &raw mut (*callout).resume, on_switch, callout.cast()) };
    });
    // SAFETY: `callback_return` wrote the result before coming back.
    unsafe { (*callout).result }.expect("a callback came back without its result")
}

/// Le rappel `context` commence : sa pile initiale devient celle du thread.
extern "sysv64" fn on_switch(context: *mut c_void, initial_stack: u64) {
    // SAFETY: called by `hal::callout::enter`, interrupts masked, with an
    // initial stack under every live frame of the thread.
    unsafe { sched::set_current_callout_state(initial_stack, context) };
}

/// NtCallbackReturn : le rappel le plus interne du thread courant finit avec
/// `result` ; son [`call_user_mode`] le rend. Avec
/// `STATUS_CALLBACK_POP_STACK` (une exception déroulée au-delà du
/// répartiteur de ntdll), la trame du service d'où part le rappel reprend
/// l'état utilisateur de cet appel ([`pop_stack`]) : le service, à son
/// retour, rend la main au déroulement.
///
/// Ne revient que sans rappel en cours : `STATUS_NO_CALLBACK_ACTIVE`.
///
/// # Safety
/// Appelé dans le service (ou l'`int 2Bh`) d'un thread utilisateur, sur la
/// trame de trap de cette entrée ; les trames de l'appel sont abandonnées :
/// rien de ce qu'elles possèdent ne doit l'être encore.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub unsafe fn callback_return(result: CallbackReturn) -> NtStatus {
    let (initial_stack, callout) = sched::current_callout_state();
    let callout = callout.cast::<Callout>();
    if callout.is_null() {
        return STATUS_NO_CALLBACK_ACTIVE;
    }
    x86_64::instructions::interrupts::disable();
    // SAFETY: `callout` lives in the frame of its `call_user_mode`, above
    // the current initial stack, untouched since; the trap frames sit under
    // the two initial stacks, where the entries from user mode pushed them.
    unsafe {
        if result.status == STATUS_CALLBACK_POP_STACK {
            pop_stack(&mut *trap_frame_under((*callout).initial_stack), &*trap_frame_under(initial_stack));
        }
        (*callout).result = Some(result);
        sched::set_current_callout_state((*callout).initial_stack, (*callout).previous);
        hal::callout::resume((*callout).resume, 0)
    }
}

/// Le thread courant est dans un rappel en mode utilisateur.
///
/// # IRQL
/// Tout niveau.
pub fn in_callback() -> bool {
    !sched::current_callout_state().1.is_null()
}

/// La trame de trap de l'entrée depuis le mode utilisateur où se trouve le
/// thread courant (KiGetUserModeStackAddress) : sous sa pile initiale.
///
/// # IRQL
/// Tout niveau, dans un thread utilisateur entré dans le noyau depuis le
/// mode utilisateur.
pub fn current_trap_frame() -> *mut KTrapFrame {
    trap_frame_under(sched::current_callout_state().0)
}

/// La trame qu'une entrée depuis le mode utilisateur empile sous la pile
/// initiale `initial_stack` (alignée sur 16 octets : le CPU n'y ajoute rien).
fn trap_frame_under(initial_stack: u64) -> *mut KTrapFrame {
    core::ptr::without_provenance_mut(initial_stack as usize - size_of::<KTrapFrame>())
}

/// `STATUS_CALLBACK_POP_STACK` : la trame `original` du service d'où part un
/// rappel reprend, de la trame `callback` de son NtCallbackReturn, l'état
/// utilisateur qu'un appel garde (FS, EDI, ESI, EBX, EBP, EIP, CS, EFLAGS,
/// ESP, SS) : le service revient là où le répartiteur l'a appelé.
pub fn pop_stack(original: &mut KTrapFrame, callback: &KTrapFrame) {
    original.fs = callback.fs;
    original.rdi = callback.rdi;
    original.rsi = callback.rsi;
    original.rbx = callback.rbx;
    original.rbp = callback.rbp;
    original.rip = callback.rip;
    original.cs = callback.cs;
    original.rflags = callback.rflags;
    original.rsp = callback.rsp;
    original.ss = callback.ss;
}

/// Le pointeur de pile courant.
///
/// # IRQL
/// Tout niveau.
#[inline(always)]
pub fn stack_pointer() -> u64 {
    let rsp: u64;
    // SAFETY: reads RSP, nothing else.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_trap_frame_of_an_entry_lies_under_the_initial_stack() {
        let frame = trap_frame_under(0x10_0000);
        assert_eq!(frame.addr(), 0x10_0000 - 26 * 8);
        // The CPU's frame ends at the initial stack: SS is its last word.
        assert_eq!(frame.addr() + core::mem::offset_of!(KTrapFrame, ss) + 8, 0x10_0000);
    }

    #[test]
    fn pop_stack_takes_what_a_call_keeps_and_nothing_else() {
        let callback = KTrapFrame {
            gs: 1,
            fs: 2,
            es: 3,
            ds: 4,
            rax: 5,
            rbx: 6,
            rcx: 7,
            rdx: 8,
            rsi: 9,
            rdi: 10,
            rbp: 11,
            rip: 12,
            cs: 13,
            rflags: 14,
            rsp: 15,
            ss: 16,
            vector: 17,
            ..KTrapFrame::default()
        };
        let mut original = KTrapFrame { rax: 0x55, gs: 0x66, vector: 0x2E, ..KTrapFrame::default() };
        pop_stack(&mut original, &callback);
        let expected = KTrapFrame {
            gs: 0x66,
            fs: 2,
            rax: 0x55,
            rbx: 6,
            rsi: 9,
            rdi: 10,
            rbp: 11,
            rip: 12,
            cs: 13,
            rflags: 14,
            rsp: 15,
            ss: 16,
            vector: 0x2E,
            ..KTrapFrame::default()
        };
        assert_eq!(original, expected);
    }

    #[test]
    fn the_stack_pointer_is_on_the_current_stack() {
        let local = 0u64;
        let rsp = stack_pointer();
        let at = (&raw const local).addr() as u64;
        assert!(rsp <= at && at - rsp < 4096, "{rsp:#x} {at:#x}");
    }
}
