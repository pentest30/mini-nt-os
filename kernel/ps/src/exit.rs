//! Fin des threads et des processus.
//!
//! - [`exit_thread`] (PspExitThread) : le thread courant se termine. Il passe
//!   dans l'espace du système, fait le rundown de ses APC, quitte la liste
//!   de son processus, annonce sa fin à son port de fin ou au port
//!   d'exception de son processus (`LPC_CLIENT_DIED`, ce qu'attend `csrss`)
//!   et rend son TEB. Le dernier thread termine aussi le
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
//! - Les rappels de win32k ([`set_win32_callouts`]) : la fin d'un thread GUI
//!   (PsW32ThreadCalloutExit), puis celle de son processus GUI s'il est le
//!   dernier (PspW32ProcessCallout), avant que ses handles soient fermés et
//!   son espace d'adresses rendu.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use abi::lpc::LPC_CLIENT_DIED;
use abi::ntstatus::{NtStatus, STATUS_PROCESS_IS_TERMINATING, STATUS_THREAD_IS_TERMINATING};
use abi::teb32::ClientId32;
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

/// Ce qu'appelle la fin d'un thread GUI, puis celle d'un processus GUI
/// ([`set_win32_callouts`]) ; 0 : rien.
static WIN32_THREAD_EXIT: AtomicUsize = AtomicUsize::new(0);
static WIN32_PROCESS_EXIT: AtomicUsize = AtomicUsize::new(0);

/// PsEstablishWin32Callouts (comme) : `thread_exit` reçoit chaque thread qui
/// se termine en ayant un `Win32Thread` (un thread GUI), `process_exit` chaque
/// processus qui a un `Win32Process` quand il se termine (par son dernier
/// thread, ou par NtTerminateProcess d'un processus sans thread), avant que
/// ses handles soient fermés et son espace d'adresses rendu.
///
/// # IRQL
/// Tout niveau. Les rappels sont appelés à PASSIVE_LEVEL, sans verrou de Ps
/// tenu, dans le thread qui se termine : rattaché à l'espace du système, ses
/// APC faits, il ne peut plus rappeler le mode utilisateur. Seul celui d'un
/// processus sans thread vient du thread qui le termine.
pub fn set_win32_callouts(thread_exit: fn(&Arc<Object<EThread>>), process_exit: fn(&Arc<Object<EProcess>>)) {
    WIN32_THREAD_EXIT.store(thread_exit as usize, Ordering::Release);
    WIN32_PROCESS_EXIT.store(process_exit as usize, Ordering::Release);
}

/// PsW32ThreadCalloutExit : `thread`, un thread GUI, se termine.
fn win32_thread_callout(thread: &Arc<Object<EThread>>) {
    let callout = WIN32_THREAD_EXIT.load(Ordering::Acquire);
    if callout != 0 && thread.win32_thread().is_some() {
        // SAFETY: only `set_win32_callouts` stores here, the address of a
        // `fn(&Arc<Object<EThread>>)`.
        let callout: fn(&Arc<Object<EThread>>) = unsafe { core::mem::transmute::<usize, _>(callout) };
        callout(thread);
    }
}

/// PspW32ProcessCallout(…, FALSE) : `process`, un processus GUI, se termine.
fn win32_process_callout(process: &Arc<Object<EProcess>>) {
    let callout = WIN32_PROCESS_EXIT.load(Ordering::Acquire);
    if callout != 0 && process.win32_process().is_some() {
        // SAFETY: only `set_win32_callouts` stores here, the address of a
        // `fn(&Arc<Object<EProcess>>)`.
        let callout: fn(&Arc<Object<EProcess>>) = unsafe { core::mem::transmute::<usize, _>(callout) };
        callout(process);
    }
}

/// La fin d'un objet critique est laissée passer, comme le ferait un
/// débogueur qui répond « ignorer » ([`set_critical_breaks_ignored`]).
static CRITICAL_BREAKS_IGNORED: AtomicBool = AtomicBool::new(false);

/// Avec `ignored`, la fin d'un processus ou d'un thread critique est
/// journalisée et laissée passer, comme le ferait un débogueur qui répond
/// « ignorer » à PspCatchCriticalBreak ; sans, elle arrête le système. Pour
/// la sonde du noyau, qui lance `smss` et veut voir où il s'arrête.
///
/// # IRQL
/// Tout niveau.
pub fn set_critical_breaks_ignored(ignored: bool) {
    CRITICAL_BREAKS_IGNORED.store(ignored, Ordering::Release);
}

/// PspCatchCriticalBreak : la fin d'un processus (`kind` 3) ou d'un thread
/// (`kind` 6) critique arrête le système (CRITICAL_OBJECT_TERMINATION), sauf
/// si elle est laissée passer ([`set_critical_breaks_ignored`]). `image` :
/// le nom de l'image de son processus.
fn critical_break(message: &str, kind: u64, object: *const u8, image: &str) {
    if CRITICAL_BREAKS_IGNORED.load(Ordering::Acquire) {
        log::warn!("ps: {message} {object:p} ({image}): ignored, as a debugger would");
        return;
    }
    ke::bugcheck::ke_bug_check_with_reason(
        ke::bugcheck::BugCheckCode::CRITICAL_OBJECT_TERMINATION,
        [kind, object as u64, image.as_ptr() as u64, message.as_ptr() as u64],
        &format_args!("{message} {object:p} ({image})"),
    )
}

/// PspExitThread : termine le thread courant avec `status`. Un thread noyau
/// ou de l'ancien chargeur se termine directement dans Ke. Sa fin est
/// annoncée par `LPC_CLIENT_DIED` ([`notify_client_died`]). La fin d'un thread
/// critique, ou du dernier thread d'un processus critique, arrête le système
/// (CRITICAL_OBJECT_TERMINATION). Un thread GUI, puis son processus GUI s'il
/// est le dernier, passent par les rappels de win32k
/// ([`set_win32_callouts`]).
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
    if thread.is_critical() {
        critical_break("Critical thread exited:", 6, Arc::as_ptr(&thread).cast(), process.image_file_name());
    }
    win32_thread_callout(&thread);
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
    if last && process.is_critical() {
        critical_break("Critical process exited:", 3, Arc::as_ptr(&process).cast(), process.image_file_name());
    }
    notify_client_died(&thread, &process);
    if last {
        process.set_exit_status(status);
        win32_process_callout(&process);
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

/// L'avis de la fin d'un thread (PspExitThread) : `LPC_CLIENT_DIED` à son
/// port de fin (NtRegisterThreadTerminatePort), sinon au port d'exception
/// de son processus — celui que `csrss` pose sur chaque processus de Win32
/// (CsrCreateProcess) et par lequel il apprend la mort de ses clients :
/// CsrDestroyThread, puis CsrDestroyProcess au dernier thread, ferment les
/// handles qu'il tient sur eux. Sans cet avis, chaque processus fini
/// resterait référencé, et ses threads Ke avec. Le message porte le
/// CLIENT_ID du thread et son heure de création (CLIENT_DIED_MSG), que
/// `csrss` compare à celle qu'il a lue (ThreadTimes). Un serveur parti n'a
/// plus rien à apprendre : l'échec de l'envoi est ignoré.
fn notify_client_died(thread: &EThread, process: &EProcess) {
    let Some(port) = thread.take_terminate_port().or_else(|| process.exception_port()) else { return };
    let Some(port) = ob::downcast::<lpc::Port>(&port) else { return };
    let client = ClientId32 { unique_process: thread.pid(), unique_thread: thread.tid() };
    let _ = lpc::request_port(&port, client, LPC_CLIENT_DIED, thread.create_time().to_le_bytes().to_vec());
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
/// Terminer un processus critique arrête le système
/// (CRITICAL_OBJECT_TERMINATION).
///
/// # Errors
/// `STATUS_PROCESS_IS_TERMINATING` s'il a déjà rendu ses ressources.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn terminate_process(process: Arc<Object<EProcess>>, status: NtStatus) -> Result<(), NtStatus> {
    if process.is_critical() {
        critical_break("Terminating critical process", 3, Arc::as_ptr(&process).cast(), process.image_file_name());
    }
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
        win32_process_callout(&process);
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

/// NtTerminateProcess(NULL) : termine les autres threads du processus du
/// thread courant avec `status` ; le thread courant continue, et le statut de
/// sortie du processus reste à fixer (kernel32 appelle ensuite
/// NtTerminateProcess sur lui-même). Sans effet pour un thread hors de Ps.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn terminate_other_threads(status: NtStatus) {
    let Some(current) = ethread::current_thread() else { return };
    let threads = current.process().threads.lock().list.clone();
    for thread in threads.iter().filter(|thread| !Arc::ptr_eq(thread, &current)) {
        thread.request_termination(status);
    }
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
/// appelant, l'appel ne revient pas (voir [`terminate_process`]). Terminer un
/// thread critique arrête le système (CRITICAL_OBJECT_TERMINATION).
///
/// # Errors
/// `STATUS_THREAD_IS_TERMINATING` si sa fin est déjà demandée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn terminate_thread(thread: Arc<Object<EThread>>, status: NtStatus) -> Result<(), NtStatus> {
    if thread.is_critical() {
        critical_break(
            "Terminating critical thread",
            6,
            Arc::as_ptr(&thread).cast(),
            thread.process().image_file_name(),
        );
    }
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
