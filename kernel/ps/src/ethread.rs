//! ETHREAD : le thread de l'exécutif.
//!
//! Un thread utilisateur appartient à un processus, qu'il garde en vie. Il a
//! son CLIENT_ID, son TEB (une page de son processus, placée sous le PEB),
//! sa pile noyau (`mm::kstack`) et son thread Ke, qui démarre en mode
//! utilisateur 32 bits à l'adresse et sur la pile données
//! ([`create_thread`]). La pile utilisateur vient de l'appelant, comme le
//! fait `RtlCreateUserThread` ; [`create_user_stack`] la prépare.
//!
//! Sa fin passe par un APC noyau ([`EThread::request_termination`]), qui
//! appelle `crate::exit::exit_thread` dans son contexte. Une fois qu'il a
//! quitté le processeur, le *reaper* rend sa pile noyau ; son thread Ke est
//! libéré avec l'objet, à son dernier pointeur.

use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_CONFLICTING_ADDRESSES, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_CID,
    STATUS_INVALID_PARAMETER, STATUS_PENDING, STATUS_PROCESS_IS_TERMINATING,
};
use abi::teb32::Teb32;
use hal::sync::KSpinLock;
use ke::apc::{ke_insert_queue_apc, KApc, NormalRoutine};
use ke::dispatcher::{DispatcherHeader, ProcessorMode};
use ke::sched::KePlatform;
use mm::kstack::KernelStack;
use mm::vad::PageProtect;
use mm::virtual_alloc::{AllocType, FreeType, ALLOC_GRANULARITY, PAGE_SIZE};
use ob::{create_object, AccessMask, GenericMapping, Object, ObjectType};

use crate::eprocess::{EProcess, ProcessId};
use crate::{CidEntry, CID_TABLE};

pub type ThreadId = u32;

pub const THREAD_TERMINATE: AccessMask = AccessMask(0x0001);
pub const THREAD_SUSPEND_RESUME: AccessMask = AccessMask(0x0002);
pub const THREAD_ALERT: AccessMask = AccessMask(0x0004);
pub const THREAD_GET_CONTEXT: AccessMask = AccessMask(0x0008);
pub const THREAD_SET_CONTEXT: AccessMask = AccessMask(0x0010);
pub const THREAD_SET_INFORMATION: AccessMask = AccessMask(0x0020);
pub const THREAD_QUERY_INFORMATION: AccessMask = AccessMask(0x0040);
pub const THREAD_SET_THREAD_TOKEN: AccessMask = AccessMask(0x0080);
pub const THREAD_IMPERSONATE: AccessMask = AccessMask(0x0100);
pub const THREAD_DIRECT_IMPERSONATION: AccessMask = AccessMask(0x0200);
/// THREAD_ALL_ACCESS d'XP.
pub const THREAD_ALL_ACCESS: AccessMask =
    AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | AccessMask::SYNCHRONIZE.0 | 0x03FF);

/// Le type `Thread`.
pub static THREAD_TYPE: ObjectType = ObjectType::new(
    "Thread",
    THREAD_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | THREAD_GET_CONTEXT.0 | THREAD_QUERY_INFORMATION.0),
        write: AccessMask(
            AccessMask::STANDARD_RIGHTS_WRITE.0
                | THREAD_TERMINATE.0
                | THREAD_SUSPEND_RESUME.0
                | THREAD_ALERT.0
                | THREAD_SET_INFORMATION.0
                | THREAD_SET_CONTEXT.0,
        ),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | AccessMask::SYNCHRONIZE.0),
        all: THREAD_ALL_ACCESS,
    },
);

/// Le TEB du premier thread d'un processus, sous le PEB ; les suivants
/// descendent page par page.
pub const FIRST_TEB_VA: u32 = 0x7FFD_E000;

/// Au plus autant de TEB sous le PEB : bien plus que de threads possibles
/// (`ke::sched::MAX_THREADS`).
const MAX_TEBS: u32 = 0x1000;

/// Pas de thread Ke (pas encore créé).
const NO_KE_THREAD: usize = usize::MAX;

/// INITIAL_TEB : la pile utilisateur d'un thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialTeb {
    /// Haut de la pile (StackBase).
    pub stack_base: u32,
    /// Bas de sa partie commitée, au-dessus de la page de garde (StackLimit).
    pub stack_limit: u32,
    /// Début de la réservation (DeallocationStack).
    pub stack_allocation_base: u32,
}

/// Le corps d'un objet thread.
pub struct EThread {
    pid: ProcessId,
    tid: ThreadId,
    /// ThreadsProcess : il garde son processus en vie.
    process: Arc<Object<EProcess>>,
    /// Son thread Ke, une fois lancé.
    ke_tid: AtomicUsize,
    /// Adresse de son TEB.
    teb: u32,
    start_address: u32,
    /// Sa pile noyau, jusqu'à ce que le reaper la rende.
    pub(crate) kernel_stack: KSpinLock<Option<KernelStack>>,
    /// ExitStatus : `STATUS_PENDING` tant qu'il vit.
    exit_status: AtomicU32,
    /// Sa fin est demandée : l'APC de fin est en file, ou il se termine.
    terminating: AtomicBool,
    /// L'APC qui le termine, écrit une fois par qui pose `terminating`.
    exit_apc: UnsafeCell<MaybeUninit<KApc>>,
}

// SAFETY: `exit_apc` n'est écrit qu'une fois, par qui fait passer
// `terminating` à `true`, avant sa mise en file ; Ke n'y touche ensuite que
// sous le verrou dispatcher. Le reste est immuable ou synchronisé.
unsafe impl Send for EThread {}
// SAFETY: voir `Send`.
unsafe impl Sync for EThread {}

impl EThread {
    /// CLIENT_ID.UniqueProcess.
    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    /// CLIENT_ID.UniqueThread.
    pub fn tid(&self) -> ThreadId {
        self.tid
    }

    /// Son processus.
    pub fn process(&self) -> &Arc<Object<EProcess>> {
        &self.process
    }

    /// Adresse de son TEB.
    pub fn teb(&self) -> u32 {
        self.teb
    }

    /// Adresse de départ (StartAddress).
    pub fn start_address(&self) -> u32 {
        self.start_address
    }

    /// ExitStatus : `STATUS_PENDING` tant qu'il vit.
    pub fn exit_status(&self) -> NtStatus {
        NtStatus(self.exit_status.load(Ordering::Acquire))
    }

    pub(crate) fn set_exit_status(&self, status: NtStatus) {
        let _ = self.exit_status.compare_exchange(STATUS_PENDING.0, status.0, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Son thread Ke ; `None` avant son lancement.
    pub(crate) fn ke_tid(&self) -> Option<usize> {
        let tid = self.ke_tid.load(Ordering::Acquire);
        (tid != NO_KE_THREAD).then_some(tid)
    }

    /// L'objet du dispatcher signalé à sa fin, à attendre ; `None` avant son
    /// lancement. Il vit autant que l'objet thread.
    pub fn dispatcher_object(&self) -> Option<*mut DispatcherHeader> {
        ke::sched::thread_object(self.ke_tid()?)
    }

    /// Met en file l'APC qui le terminera avec `status` : le thread s'arrête
    /// à sa prochaine reprise sous APC_LEVEL, en mode utilisateur compris.
    /// `false` si sa fin était déjà demandée, ou s'il n'est pas lancé.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn request_termination(&self, status: NtStatus) -> bool {
        let Some(ke_tid) = self.ke_tid() else { return false };
        if self.terminating.swap(true, Ordering::AcqRel) {
            return false;
        }
        let kthread = ke::sched::kernel_thread(ke_tid).expect("a live thread without its Ke thread");
        let apc = self.exit_apc.get().cast::<KApc>();
        // SAFETY: seul l'appelant qui a posé `terminating` écrit l'APC, à
        // l'adresse fixe du corps de l'objet ; le thread Ke vit tant que
        // l'objet vit, et l'objet tant que le thread n'est pas récupéré.
        unsafe {
            apc.write(KApc::new(
                kthread,
                exit_kernel_routine,
                None,
                Some(NormalRoutine::Kernel(exit_normal_routine)),
                ProcessorMode::Kernel,
                core::ptr::null_mut(),
            ));
            // Relevé de 2, comme XP, pour qu'il se termine vite.
            ke_insert_queue_apc::<KePlatform>(
                apc,
                core::ptr::without_provenance_mut(status.0 as usize),
                core::ptr::null_mut(),
                2,
            )
        }
    }

    /// Le thread s'est terminé lui-même : plus d'APC de fin à mettre en file.
    pub(crate) fn mark_terminating(&self) {
        self.terminating.store(true, Ordering::Release);
    }
}

impl Drop for EThread {
    fn drop(&mut self) {
        CID_TABLE.lock().remove(self.tid);
        if let Some(ke_tid) = self.ke_tid() {
            // SAFETY: l'objet ne meurt qu'après que le reaper a vu son thread
            // Ke terminé et sorti du processeur ; plus personne n'attend son
            // objet thread, qui vit autant que lui.
            let deleted = unsafe { ke::sched::delete_thread(ke_tid) };
            assert!(deleted, "thread {} lost its Ke thread", self.tid);
        }
        debug_assert!(self.kernel_stack.lock().is_none(), "thread {} keeps its kernel stack", self.tid);
    }
}

/// Routine noyau de l'APC de fin, à APC_LEVEL : la routine normale fera tout.
fn exit_kernel_routine(
    _apc: *mut KApc,
    _normal_routine: &mut Option<NormalRoutine>,
    _normal_context: &mut *mut c_void,
    _argument1: &mut *mut c_void,
    _argument2: &mut *mut c_void,
) {
}

/// Routine normale de l'APC de fin, à PASSIVE_LEVEL dans le thread : il se
/// termine avec le statut passé en premier argument.
fn exit_normal_routine(_context: *mut c_void, status: *mut c_void, _argument2: *mut c_void) {
    crate::exit::exit_thread(NtStatus(status.addr() as u32));
}

/// PsLookupThreadByThreadId : le thread `tid`, tant que son objet vit.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn lookup_thread(tid: ThreadId) -> Result<Arc<Object<EThread>>, NtStatus> {
    match CID_TABLE.lock().get(tid) {
        Some(CidEntry::Thread(thread)) => thread.upgrade().ok_or(STATUS_INVALID_CID),
        _ => Err(STATUS_INVALID_CID),
    }
}

/// Le thread de l'exécutif qui s'exécute ; `None` pour un thread noyau ou un
/// thread de l'ancien chargeur.
///
/// # IRQL
/// Tout niveau.
pub fn current_thread() -> Option<Arc<Object<EThread>>> {
    let owner = ke::sched::current_thread_owner().cast::<Object<EThread>>();
    if owner.is_null() {
        return None;
    }
    // SAFETY: `owner` vient d'`Arc::as_ptr` à la création du thread, et la
    // liste de son processus, puis le reaper, en tiennent un pointeur tant
    // qu'il s'exécute.
    unsafe {
        Arc::increment_strong_count(owner);
        Some(Arc::from_raw(owner))
    }
}

/// RtlpCreateUserStack : réserve dans `process` une pile de `reserve` octets
/// (arrondis à 64 Kio), dont les `commit` du haut (arrondis à la page) sont
/// commités, avec une page de garde juste en dessous s'il y a la place.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create_user_stack(process: &EProcess, reserve: u64, commit: u64) -> Result<InitialTeb, NtStatus> {
    let commit = commit.max(PAGE_SIZE).next_multiple_of(PAGE_SIZE);
    let reserve = reserve.max(commit).next_multiple_of(ALLOC_GRANULARITY);
    let read_write = PageProtect::READWRITE;
    process.with_space(|space| {
        let base = space.allocate(0, reserve, AllocType::MEM_RESERVE, read_write)?;
        let top = base + reserve;
        let limit = top - commit;
        let committed = space.allocate(limit, commit, AllocType::MEM_COMMIT, read_write).and_then(|_| {
            if limit - base >= PAGE_SIZE {
                let guard = limit - PAGE_SIZE;
                space.allocate(guard, PAGE_SIZE, AllocType::MEM_COMMIT, read_write | PageProtect::GUARD)?;
            }
            Ok(())
        });
        if let Err(status) = committed {
            space.free(base, 0, FreeType::MEM_RELEASE).expect("the reservation just made");
            return Err(status);
        }
        Ok(InitialTeb { stack_base: top as u32, stack_limit: limit as u32, stack_allocation_base: base as u32 })
    })?
}

/// PspCreateThread : un thread de `process`, qui démarre en mode utilisateur
/// en `start_address`, avec ESP à `stack.stack_base`. Son TEB est la première
/// page libre sous le PEB.
///
/// # Errors
/// `STATUS_PROCESS_IS_TERMINATING` si le processus se termine ou n'a pas
/// d'espace d'adresses à lui ; `STATUS_INSUFFICIENT_RESOURCES` faute de pile
/// noyau, de TID, de TEB ou de place dans l'ordonnanceur.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create_thread(
    process: &Arc<Object<EProcess>>,
    start_address: u32,
    stack: &InitialTeb,
) -> Result<Arc<Object<EThread>>, NtStatus> {
    if process.peb() == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if process.threads.lock().terminating {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    let tid = CID_TABLE.lock().insert(CidEntry::Thread(Weak::new())).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let teb = match create_teb(process, tid, stack) {
        Ok(teb) => teb,
        Err(status) => {
            CID_TABLE.lock().remove(tid);
            return Err(status);
        }
    };
    let Some(kernel_stack) = mm::kstack::allocate() else {
        delete_teb(process, teb);
        CID_TABLE.lock().remove(tid);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let thread = create_object(
        &THREAD_TYPE,
        EThread {
            pid: process.pid(),
            tid,
            process: process.clone(),
            ke_tid: AtomicUsize::new(NO_KE_THREAD),
            teb,
            start_address,
            kernel_stack: KSpinLock::new(Some(kernel_stack)),
            exit_status: AtomicU32::new(STATUS_PENDING.0),
            terminating: AtomicBool::new(false),
            exit_apc: UnsafeCell::new(MaybeUninit::uninit()),
        },
    );
    CID_TABLE.lock().set(tid, CidEntry::Thread(Arc::downgrade(&thread)));

    // Il entre dans la liste avant de démarrer : une fin du processus
    // demandée entre-temps le verra.
    let failed = {
        let mut threads = process.threads.lock();
        let failed = threads.terminating;
        if !failed {
            threads.list.push(thread.clone());
        }
        failed
    };
    if failed {
        abandon(process, &thread);
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    let start = ke::sched::UserThreadStart {
        directory_table_base: process.directory_table_base(),
        kernel_stack_top: kernel_stack.top,
        entry: start_address,
        stack: stack.stack_base,
        teb,
        owner: Arc::as_ptr(&thread).cast(),
    };
    // SAFETY: la pile noyau est à ce thread jusqu'à ce que le reaper la rende,
    // après sa fin ; l'espace d'adresses vit tant qu'un thread du processus
    // s'exécute (le dernier le rend en se terminant).
    let Some(ke_tid) = (unsafe { ke::sched::create_user_thread(&start) }) else {
        process.threads.lock().list.retain(|t| !Arc::ptr_eq(t, &thread));
        abandon(process, &thread);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    thread.ke_tid.store(ke_tid, Ordering::Release);
    // Une fin du processus demandée avant que le thread Ke existe n'a pas pu
    // lui envoyer son APC.
    let terminating = process.threads.lock().terminating;
    if terminating {
        thread.request_termination(process.exit_status());
    }
    Ok(thread)
}

/// Défait la création d'un thread qui n'a pas démarré.
fn abandon(process: &EProcess, thread: &EThread) {
    delete_teb(process, thread.teb);
    let stack = thread.kernel_stack.lock().take().expect("an unstarted thread has its kernel stack");
    // SAFETY: le thread n'a jamais démarré : rien ne s'exécute sur sa pile.
    unsafe { mm::kstack::free(stack) };
}

/// MmCreateTeb : réserve et commite la première page libre sous le PEB, et y
/// écrit le TEB du thread `tid`.
fn create_teb(process: &EProcess, tid: ThreadId, stack: &InitialTeb) -> Result<u32, NtStatus> {
    process.with_space(|space| {
        let mut va = u64::from(FIRST_TEB_VA);
        let lowest = va - u64::from(MAX_TEBS - 1) * PAGE_SIZE;
        let teb = loop {
            let commit = AllocType::MEM_RESERVE | AllocType::MEM_COMMIT;
            match space.allocate(va, PAGE_SIZE, commit, PageProtect::READWRITE) {
                Ok(_) => break va as u32,
                Err(STATUS_CONFLICTING_ADDRESSES) if va > lowest => va -= PAGE_SIZE,
                Err(STATUS_CONFLICTING_ADDRESSES) => return Err(STATUS_INSUFFICIENT_RESOURCES),
                Err(status) => return Err(status),
            }
        };
        let data = Teb32::new(
            teb,
            process.pid(),
            tid,
            process.peb(),
            stack.stack_base,
            stack.stack_limit,
            stack.stack_allocation_base,
        );
        if let Err(status) = space.write_bytes(u64::from(teb), data.as_bytes()) {
            space.free(u64::from(teb), 0, FreeType::MEM_RELEASE).expect("the TEB just allocated");
            return Err(status);
        }
        Ok(teb)
    })?
}

/// MmDeleteTeb : rend la page du TEB, si l'espace d'adresses existe encore.
pub(crate) fn delete_teb(process: &EProcess, teb: u32) {
    let _ = process.with_space(|space| space.free(u64::from(teb), 0, FreeType::MEM_RELEASE));
}
