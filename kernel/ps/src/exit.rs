//! Fin des threads et des processus.
//!
//! - [`exit_thread`] (PspExitThread) : le thread courant se termine. Il passe
//!   dans l'espace du système, fait le rundown de ses APC, quitte la liste
//!   de son processus et rend son TEB. Le dernier thread termine aussi le
//!   processus : rundown de la table de handles, espace d'adresses rendu une
//!   fois finis les accès en cours, objet processus signalé. Le thread se
//!   confie ensuite au *reaper*, puis quitte le processeur pour de bon.
//! - [`terminate_process`] et [`terminate_thread`] (NtTerminateProcess,
//!   NtTerminateThread) : chaque thread visé reçoit un APC noyau qui appelle
//!   [`exit_thread`] dans son contexte ; un thread qui se vise lui-même se
//!   termine en dernier.
//! - Le *reaper* (PspReaper, sur un thread système en attendant les files de
//!   travail d'Ex) attend que chaque thread terminé ait quitté le
//!   processeur, puis rend sa pile noyau et lâche l'objet thread ; à son
//!   dernier pointeur, le thread Ke est libéré.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;

use abi::ntstatus::{NtStatus, STATUS_PROCESS_IS_TERMINATING, STATUS_THREAD_IS_TERMINATING};
use hal::sync::{KSpinLock, Once};
use ke::dispatcher::{ObjectType as KObjectType, Platform, ProcessorMode};
use ke::sched::KePlatform;
use ob::Object;

use crate::eprocess::EProcess;
use crate::ethread::{self, EThread};
use crate::DispatcherEvent;

/// Priorité du reaper : celle de la file de travail différé d'XP.
pub const REAPER_PRIORITY: u8 = 12;

/// Threads terminés que le reaper n'a pas encore récupérés.
static REAPER_LIST: KSpinLock<Vec<Arc<Object<EThread>>>> = KSpinLock::new(Vec::new());

struct ReaperEvents {
    /// Du travail pour le reaper.
    work: DispatcherEvent,
    /// La liste est vide : tout thread terminé a été récupéré.
    idle: DispatcherEvent,
}

static REAPER: Once<ReaperEvents> = Once::new();

fn reaper() -> &'static ReaperEvents {
    REAPER.get().expect("Ps not initialised")
}

/// Lance le reaper sur son thread système.
///
/// # IRQL
/// PASSIVE_LEVEL, une fois.
pub(crate) fn start_reaper() {
    let events = REAPER.call_once(|| ReaperEvents {
        work: DispatcherEvent::new(KObjectType::SynchronizationEvent),
        idle: DispatcherEvent::new(KObjectType::NotificationEvent),
    });
    events.idle.set();
    let stack = mm::kstack::allocate().expect("no kernel stack for the reaper");
    // SAFETY: la pile est au reaper pour toujours ; il n'utilise pas son
    // contexte.
    unsafe { ke::sched::create_kernel_thread(stack.top, REAPER_PRIORITY, reaper_main, core::ptr::null_mut()) }
        .expect("thread table full");
}

fn reaper_main(_context: *mut c_void) {
    let events = reaper();
    loop {
        events.work.wait();
        loop {
            let next = REAPER_LIST.lock().pop();
            let Some(thread) = next else { break };
            reap(thread);
        }
        let list = REAPER_LIST.lock();
        if list.is_empty() {
            events.idle.set();
        }
    }
}

/// Attend la fin de `thread`, puis rend sa pile noyau et lâche l'objet.
fn reap(thread: Arc<Object<EThread>>) {
    let object = thread.dispatcher_object().expect("a terminated thread was never started");
    // SAFETY: l'objet thread vit tant que `thread` est tenu.
    unsafe { ke::dispatcher::ke_wait_for_single_object::<KePlatform>(object, ProcessorMode::Kernel, false, None) };
    // Signalé quand il a quitté le processeur (un seul processeur, ADR-015).
    let stack = thread.kernel_stack.lock().take();
    if let Some(stack) = stack {
        // SAFETY: le thread est terminé et ne s'exécute plus ; rien ne pointe
        // plus dans sa pile.
        unsafe { mm::kstack::free(stack) };
    }
}

/// Confie le thread courant, qui se termine, au reaper.
fn queue_for_reaping(thread: Arc<Object<EThread>>) {
    let events = reaper();
    {
        let mut list = REAPER_LIST.lock();
        list.push(thread);
        events.idle.reset();
    }
    events.work.set();
}

/// Attend que le reaper ait récupéré tous les threads terminés jusqu'ici :
/// leurs piles noyau et leurs threads Ke sont rendus, sauf pour les objets
/// thread encore référencés.
///
/// # IRQL
/// PASSIVE_LEVEL. Peut attendre.
pub fn wait_for_reaper() {
    reaper().idle.wait();
}

/// PspExitThread : termine le thread courant avec `status`. Un thread noyau
/// ou de l'ancien chargeur se termine directement dans Ke.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn exit_thread(status: NtStatus) -> ! {
    let Some(thread) = ethread::current_thread() else {
        ke::sched::terminate_current_thread();
        unreachable!("a terminated thread was resumed");
    };
    // Hors de l'espace du processus, que le dernier thread va détruire.
    // SAFETY: l'espace du système vit toujours ; le thread n'en repart pas.
    let _attached_for_good = unsafe { ke::sched::ke_stack_attach(mm::address_space::system_directory_table_base()) };
    thread.mark_terminating();
    // SAFETY: le thread courant est valide.
    unsafe { ke::apc::ke_rundown_apcs::<KePlatform>(KePlatform::current_thread()) };
    thread.set_exit_status(status);

    let process = thread.process().clone();
    let last = {
        let mut threads = process.threads.lock();
        let index = threads.list.iter().position(|t| Arc::ptr_eq(t, &thread)).expect("a thread out of its process");
        // `thread` keeps it alive, for the reaper.
        drop(threads.list.swap_remove(index));
        let last = threads.list.is_empty();
        if last {
            threads.terminating = true;
            threads.exited = true;
        }
        last
    };
    if last {
        process.set_exit_status(status);
        run_down_process(&process);
    } else {
        ethread::delete_teb(&process, thread.teb());
    }
    // Queued before the process is signaled: whoever waits for its end, then
    // for the reaper, finds this thread in the reaper's hands.
    queue_for_reaping(thread);
    if last {
        process.signal_exited();
    }
    // This frame is never unwound: nothing that owns memory may outlive this.
    drop(process);
    ke::sched::terminate_current_thread();
    unreachable!("a terminated thread was resumed");
}

/// PspExitProcess : ferme les handles du processus et rend son espace
/// d'adresses. Aucun de ses threads ne s'y exécute plus.
fn run_down_process(process: &EProcess) {
    process.handle_table.rundown();
    process.delete_space();
}

/// NtTerminateProcess : termine chaque thread de `process` avec `status`, qui
/// devient son statut de sortie. Un processus sans thread rend ses
/// ressources tout de suite.
///
/// Le thread appelant, s'il en fait partie, se termine en dernier : l'appel
/// ne revient pas. C'est pourquoi il prend la référence de l'appelant, qui
/// ne doit rien tenir d'autre qui possède de la mémoire.
///
/// # Errors
/// `STATUS_PROCESS_IS_TERMINATING` s'il a déjà rendu ses ressources.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn terminate_process(process: Arc<Object<EProcess>>, status: NtStatus) -> Result<(), NtStatus> {
    let (threads, rundown) = {
        let mut threads = process.threads.lock();
        if threads.exited {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        threads.terminating = true;
        let rundown = threads.list.is_empty();
        threads.exited = rundown;
        (threads.list.clone(), rundown)
    };
    process.set_exit_status(status);
    if rundown {
        run_down_process(&process);
        process.signal_exited();
        return Ok(());
    }
    let current = ethread::current_thread();
    let mut ends_self = false;
    for thread in &threads {
        if current.as_ref().is_some_and(|c| Arc::ptr_eq(c, thread)) {
            ends_self = true;
        } else {
            thread.request_termination(status);
        }
    }
    if ends_self {
        drop((threads, current, process));
        exit_thread(status);
    }
    Ok(())
}

/// Termine le processus du thread courant avec `status` (un thread noyau ou
/// de l'ancien chargeur se termine seul).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn terminate_current_process(status: NtStatus) -> ! {
    if let Some(thread) = ethread::current_thread() {
        let process = thread.process().clone();
        drop(thread);
        // It returns only if the current thread already left its process.
        let _ = terminate_process(process, status);
    }
    exit_thread(status);
}

/// NtTerminateThread : termine `thread` avec `status`. S'il s'agit du thread
/// appelant, l'appel ne revient pas (voir [`terminate_process`]).
///
/// # Errors
/// `STATUS_THREAD_IS_TERMINATING` si sa fin est déjà demandée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn terminate_thread(thread: Arc<Object<EThread>>, status: NtStatus) -> Result<(), NtStatus> {
    if ethread::current_thread().is_some_and(|current| Arc::ptr_eq(&current, &thread)) {
        drop(thread);
        exit_thread(status);
    }
    if thread.request_termination(status) {
        Ok(())
    } else {
        Err(STATUS_THREAD_IS_TERMINATING)
    }
}
