//! KeUserModeCallback : un service système appelle une routine du mode
//! utilisateur du thread courant, et en reçoit le résultat. win32k s'en
//! sert pour user32 (`PEB.KernelCallbackTable`, appelée par
//! `ntdll!KiUserCallbackDispatcher`).
//!
//! [`user_mode_callback`] met sur la pile utilisateur l'argument, puis le
//! cadre que lit le répartiteur de ntdll (`[0, index, &argument, longueur]`
//! et deux mots pour son enregistrement SEH), et passe en mode utilisateur
//! au répartiteur (`ke::callout`), avec le reste de la trame du service. La
//! routine finit par NtCallbackReturn (`sys`, [`callback_return`]) ; la pile
//! utilisateur et la liste SEH du TEB (`ExceptionList`) redeviennent celles
//! d'avant, et le résultat est copié dans le noyau.
//!
//! La pile noyau grandit en place (`mm::kstack::grow`) pour garder
//! [`CALLBACK_STACK`] octets libres sous le rappel (MmGrowKernelStack),
//! jusqu'à `KERNEL_LARGE_STACK_SIZE`.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_VIOLATION, STATUS_CALLBACK_POP_STACK, STATUS_ENTRYPOINT_NOT_FOUND,
    STATUS_THREAD_IS_TERMINATING,
};
use abi::teb32::Teb32;
use hal::sync::Once;
use ke::callout::CallbackReturn;
use ke::usermem::{copy_from_user, copy_to_user, UserPtr};

use crate::ethread;

/// La pile noyau libre qu'un rappel garde sous lui : KERNEL_STACK_SIZE d'un
/// noyau i386 (12 Kio), plus pour les trames d'un noyau 64 bits.
pub const CALLBACK_STACK: u64 = 16 * 1024;

/// Octets du cadre du répartiteur sous l'argument : un mot nul, l'index,
/// l'adresse et la longueur de l'argument, puis l'enregistrement SEH que le
/// répartiteur y écrit.
pub const DISPATCHER_FRAME: u32 = 24;

/// La pile utilisateur d'un rappel, depuis l'ESP `esp` de la trame du
/// service, pour un argument de `length` octets : l'adresse de l'argument
/// (alignée sur 4 octets), puis celle du cadre du répartiteur, le nouvel
/// ESP. `None` si elle sort de l'espace d'adresses.
pub fn callback_stack(esp: u32, length: u32) -> Option<(u32, u32)> {
    let argument = esp.checked_sub(length)? & !3;
    Some((argument, argument.checked_sub(DISPATCHER_FRAME)?))
}

/// Le cadre du répartiteur : ce que `KiUserCallbackDispatcher` dépile
/// (un mot ignoré, l'index), puis les deux arguments de la routine.
fn dispatcher_frame(index: u32, argument: u32, length: u32) -> [u8; 16] {
    let mut frame = [0u8; 16];
    for (slot, word) in frame.chunks_exact_mut(4).zip([0, index, argument, length]) {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    frame
}

/// KeUserModeCallback : appelle la routine `index` de la table des rappels
/// du processus (`PEB.KernelCallbackTable`) avec une copie de `argument`, et
/// rend au plus `max_output` octets de son résultat, copiés depuis le mode
/// utilisateur.
///
/// # Errors
/// - le statut que donne la routine à NtCallbackReturn, s'il n'est pas un
///   succès (`STATUS_CALLBACK_POP_STACK` si une exception a déroulé la pile
///   utilisateur au-delà du rappel) ;
/// - `STATUS_THREAD_IS_TERMINATING` pour un thread dont la fin est demandée ;
/// - `STATUS_STACK_OVERFLOW` (pile noyau à sa taille maximale),
///   `STATUS_NO_MEMORY` ;
/// - `STATUS_ACCESS_VIOLATION`… : la pile utilisateur ou le TEB ne peuvent
///   pas être écrits, le résultat pas lu ;
/// - `STATUS_ENTRYPOINT_NOT_FOUND` sans DLL système.
///
/// # Panics
/// Hors d'un thread de Ps.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir qu'il faille
/// rendre si le thread se termine pendant le rappel (ses trames sont
/// alors abandonnées : `ke::callout`). Peut ne pas revenir.
pub fn user_mode_callback(index: u32, argument: &[u8], max_output: usize) -> Result<Vec<u8>, NtStatus> {
    let dispatcher =
        crate::system_dll::current().map(|dll| dll.user_callback_dispatcher).ok_or(STATUS_ENTRYPOINT_NOT_FOUND)?;
    user_mode_callback_through(dispatcher, index, argument, max_output)
}

/// [`user_mode_callback`], par le répartiteur en `dispatcher` au lieu de
/// celui de ntdll (les auto-tests, sans ntdll).
///
/// # Errors
/// Comme [`user_mode_callback`].
///
/// # Panics
/// Hors d'un thread de Ps.
///
/// # IRQL
/// Comme [`user_mode_callback`].
pub fn user_mode_callback_through(
    dispatcher: u32,
    index: u32,
    argument: &[u8],
    max_output: usize,
) -> Result<Vec<u8>, NtStatus> {
    let thread = ethread::current_thread().expect("a user-mode callback from a thread of Ps");
    debug_assert_eq!(hal::irql::current(), hal::irql::Irql::Passive, "a user-mode callback above PASSIVE_LEVEL");
    if thread.is_terminating() {
        return Err(STATUS_THREAD_IS_TERMINATING);
    }
    grow_kernel_stack(&thread)?;
    let teb = thread.teb();
    drop(thread);

    // SAFETY: the current thread entered the kernel from user mode for the
    // service it runs: its trap frame lies under its initial stack.
    let frame = unsafe { *ke::callout::current_trap_frame() };
    let length = u32::try_from(argument.len()).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let (argument_at, esp) = callback_stack(frame.rsp as u32, length).ok_or(STATUS_ACCESS_VIOLATION)?;
    copy_to_user(u64::from(argument_at), argument)?;
    copy_to_user(u64::from(esp), &dispatcher_frame(index, argument_at, length))?;
    let exception_list = UserPtr::<u32>::new(teb).read()?;

    let mut callback = frame;
    callback.rip = u64::from(dispatcher);
    callback.rsp = u64::from(esp);
    // SAFETY: a thread of Ps in a service, at PASSIVE_LEVEL, interrupts on
    // (`sys`); `callback` is the service's frame, for user mode; this frame
    // holds nothing that a thread ending in its callback must give back.
    let CallbackReturn { output, length, status } = unsafe { ke::callout::call_user_mode(&callback) };

    if status != STATUS_CALLBACK_POP_STACK {
        UserPtr::<u32>::new(teb).write(&exception_list)?;
    }
    let batch = UserPtr::<u32>::new(teb + core::mem::offset_of!(Teb32, gdi_batch_count) as u32).read()?;
    if batch != 0 {
        match GDI_BATCH_FLUSH.get() {
            Some(flush) => flush(),
            None => report_unflushed_batch(batch),
        }
    }
    if !status.is_success() {
        return Err(status);
    }
    let mut result = vec![0u8; (length as usize).min(max_output)];
    copy_from_user(&mut result, u64::from(output))?;
    Ok(result)
}

/// NtCallbackReturn(Result, ResultLength, Status) : le rappel en cours du
/// thread courant finit. Ne revient que sans rappel en cours :
/// `STATUS_NO_CALLBACK_ACTIVE`.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le service (ou l'`int 2Bh`) du thread, sans rien
/// tenir : ses trames sont abandonnées.
pub fn callback_return(output: u32, length: u32, status: NtStatus) -> NtStatus {
    // SAFETY: guaranteed by the caller.
    unsafe { ke::callout::callback_return(CallbackReturn { output, length, status }) }
}

/// MmGrowKernelStack : la pile noyau du thread grandit, s'il le faut, pour
/// garder [`CALLBACK_STACK`] octets libres sous la trame courante.
fn grow_kernel_stack(thread: &ethread::EThread) -> Result<(), NtStatus> {
    let needed = ke::callout::stack_pointer() - CALLBACK_STACK;
    let mut stack = thread.kernel_stack.lock().expect("a running thread has its kernel stack");
    if needed >= stack.bottom {
        return Ok(());
    }
    if let Err(status) = mm::kstack::grow(&mut stack, needed) {
        log::warn!("ps: thread {} wants too much kernel stack for a callback ({status:?})", thread.tid());
        return Err(status);
    }
    *thread.kernel_stack.lock() = Some(stack);
    Ok(())
}

/// KeGdiFlushUserBatch : ce qui exécute les appels GDI en lot du thread
/// courant (win32k, PsEstablishWin32Callouts).
static GDI_BATCH_FLUSH: Once<fn()> = Once::new();

/// `flush` exécutera les appels GDI qu'un thread a mis en lot pendant un
/// rappel, à son retour (`BatchFlushRoutine` de PsEstablishWin32Callouts).
/// Un second appel ne change rien.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_gdi_batch_flush(flush: fn()) {
    GDI_BATCH_FLUSH.call_once(|| flush);
}

/// Le TEB compte des appels GDI en lot après un rappel, sans rien pour les
/// exécuter (win32k pas encore là). Journalisé une fois.
fn report_unflushed_batch(count: u32) {
    static REPORTED: AtomicBool = AtomicBool::new(false);
    if !REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!("ps: {count} batched GDI calls not flushed after a user-mode callback (no GDI yet)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_argument_then_the_dispatcher_frame_go_under_the_user_stack() {
        // KeUserModeCallback: (ESP - length) & ~3, then 24 bytes.
        assert_eq!(callback_stack(0x0013_FF00, 8), Some((0x0013_FEF8, 0x0013_FEE0)));
        assert_eq!(callback_stack(0x0013_FF00, 5), Some((0x0013_FEF8, 0x0013_FEE0)), "aligned on 4 bytes");
        assert_eq!(callback_stack(0x0013_FF02, 0), Some((0x0013_FF00, 0x0013_FEE8)));
        assert_eq!(callback_stack(16, 8), None, "out of the address space");
        assert_eq!(callback_stack(4, 8), None);
    }

    #[test]
    fn the_dispatcher_pops_a_word_then_the_index() {
        let frame = dispatcher_frame(7, 0x0013_FEF8, 8);
        let words: Vec<u32> = frame.chunks_exact(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        assert_eq!(words, [0, 7, 0x0013_FEF8, 8]);
    }
}
