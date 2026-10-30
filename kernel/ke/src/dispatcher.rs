//! Dispatcher NT (Ke) pour Mino — objets attendables, wait blocks, attente/signal
//! (ADR-005 ; point de départ du jalon M1, audit §3).
//!
//! Invariants :
//! - Un seul verrou global (`DISPATCHER_LOCK`) protège tous les DispatcherHeader, les
//!   listes d'attente et l'état d'attente des threads. XP faisait de même.
//! - Les objets sont à adresse stable (alloués par Ob, jamais déplacés) : les listes
//!   d'attente sont intrusives et utilisent des pointeurs bruts, comme LIST_ENTRY.
//! - Le signaleur consomme l'objet *au nom* du thread réveillé (KiWaitTest). Le thread
//!   réveillé ne revérifie rien : son `wait_status` est déjà le résultat final.
//! - Le timeout est un 4e wait block (WaitAny) pointant sur le KTIMER du thread.
//! - Chaque réveil porte un relèvement de priorité (`increment`, par exemple
//!   [`EVENT_INCREMENT`]), que l'ordonnanceur applique au thread réveillé
//!   (`Platform::ready_thread`, `ke::sched`).
//!
//! Seules les structures visibles en user mode (TEB, PEB, KUSER_SHARED_DATA) doivent
//! respecter le layout XP. DispatcherHeader et WaitBlock reprennent ici le layout x86
//! d'XP par commodité, pas par obligation.
//!
//! L'ordonnanceur, les timers et l'IRQL sont atteints par le trait [`Platform`] :
//! Ke l'implémente pour le noyau, les tests hôte par une simulation.

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ABANDONED_WAIT_0, STATUS_KERNEL_APC, STATUS_MUTANT_NOT_OWNED, STATUS_SEMAPHORE_LIMIT_EXCEEDED,
    STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_USER_APC, STATUS_WAIT_0,
};
use hal::irql::Irql;

use crate::dpc::KDpc;

pub const THREAD_WAIT_OBJECTS: usize = 3;

// Relèvements de priorité d'un thread réveillé, selon ce qui le réveille :
// noms et valeurs de l'interface noyau XP.

/// Aucun relèvement.
pub const IO_NO_INCREMENT: u8 = 0;
/// Un événement signalé.
pub const EVENT_INCREMENT: u8 = 1;
/// Un sémaphore libéré.
pub const SEMAPHORE_INCREMENT: u8 = 1;
/// Un mutant libéré ou abandonné.
pub const MUTANT_INCREMENT: u8 = 1;
pub const TIMER_WAIT_BLOCK: usize = 3;
pub const MAXIMUM_WAIT_OBJECTS: usize = 64;

// ---------------------------------------------------------------------------
// Points d'accroche fournis par l'ordonnanceur, les timers et la gestion d'IRQL
// ---------------------------------------------------------------------------

/// Services de l'ordonnanceur, des timers et de l'IRQL dont le dispatcher a besoin.
///
/// # Safety
/// Une implémentation respecte le contrat de chaque méthode : les invariants du
/// dispatcher (listes d'attente, états des threads, verrou) en dépendent.
pub unsafe trait Platform {
    /// Thread courant.
    fn current_thread() -> *mut KThread;

    /// Verrou dispatcher tenu. Place le thread dans la file prêt de sa priorité,
    /// relevée d'`increment` selon les règles de l'ordonnanceur.
    ///
    /// # Safety
    /// Verrou dispatcher tenu ; `thread` est valide et vient de passer `Ready`.
    unsafe fn ready_thread(thread: *mut KThread, increment: u8);

    /// Verrou dispatcher tenu, thread courant en état `Waiting`. Bascule vers le
    /// prochain thread prêt. À la reprise de ce thread, le verrou a été relâché et
    /// l'IRQL rabaissé à `old_irql`. Retourne `wait_status` du thread.
    ///
    /// # Safety
    /// Verrou dispatcher tenu, pris depuis `old_irql` ; le thread courant est chaîné
    /// dans les objets qu'il attend.
    unsafe fn swap_thread(old_irql: Irql) -> NtStatus;

    /// Format NT : négatif = relatif (unités de 100 ns), positif = absolu.
    /// Retourne `false` si l'échéance est déjà passée (timer non inséré).
    /// Inséré, le timer a `header.inserted` à 1 ; `cancel_timer` et son
    /// expiration le remettent à 0 (`ke::timer::TimerTable` le fait).
    ///
    /// # Safety
    /// Verrou dispatcher tenu ; `timer` reste valide jusqu'à son échéance ou son
    /// annulation.
    unsafe fn insert_timer(timer: *mut KTimer, due_time: i64) -> bool;

    /// Doit être idempotent (peut être appelé sur un timer déjà expiré).
    ///
    /// # Safety
    /// Verrou dispatcher tenu ; `timer` est valide.
    unsafe fn cancel_timer(timer: *mut KTimer);

    /// KeRaiseIrql : retourne l'IRQL précédent.
    fn raise_irql(new: Irql) -> Irql;

    /// KeLowerIrql.
    fn lower_irql(new: Irql);

    /// Demande l'interruption APC du processeur courant : la livraison des APC
    /// noyau du thread courant (`ke::apc::ki_deliver_apc`) dès que l'IRQL passe
    /// sous APC_LEVEL, avant de revenir si c'est déjà le cas.
    fn request_apc_interrupt();
}

// ---------------------------------------------------------------------------
// Liste doublement chaînée intrusive (LIST_ENTRY)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl Default for ListEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl ListEntry {
    pub const fn new() -> Self {
        Self { flink: ptr::null_mut(), blink: ptr::null_mut() }
    }

    /// # Safety
    /// `head` est valide en écriture et à adresse stable.
    pub unsafe fn init(head: *mut ListEntry) {
        // SAFETY: garanti par l'appelant.
        unsafe {
            (*head).flink = head;
            (*head).blink = head;
        }
    }

    /// # Safety
    /// `head` est une tête de liste initialisée.
    pub unsafe fn is_empty(head: *const ListEntry) -> bool {
        // SAFETY: garanti par l'appelant.
        unsafe { ptr::eq((*head).flink, head) }
    }

    /// # Safety
    /// `head` est une liste bien formée ; `entry` est valide, à adresse stable, et
    /// n'est dans aucune liste.
    pub unsafe fn insert_tail(head: *mut ListEntry, entry: *mut ListEntry) {
        // SAFETY: garanti par l'appelant ; les quatre pointeurs touchés sont des
        // éléments de la même liste bien formée.
        unsafe {
            let last = (*head).blink;
            (*entry).flink = head;
            (*entry).blink = last;
            (*last).flink = entry;
            (*head).blink = entry;
        }
    }

    /// # Safety
    /// `entry` est chaîné dans une liste bien formée.
    pub unsafe fn remove(entry: *mut ListEntry) {
        // SAFETY: garanti par l'appelant ; les voisins de `entry` sont valides.
        unsafe {
            let f = (*entry).flink;
            let b = (*entry).blink;
            (*b).flink = f;
            (*f).blink = b;
            (*entry).flink = entry;
            (*entry).blink = entry;
        }
    }
}

/// CONTAINING_RECORD. À employer dans un bloc `unsafe` : `$ptr` doit pointer sur le
/// champ `$field` d'un `$ty` valide.
macro_rules! containing_record {
    ($ptr:expr, $ty:ty, $field:ident) => {
        ($ptr as *mut u8).sub(core::mem::offset_of!($ty, $field)) as *mut $ty
    };
}
pub(crate) use containing_record;

// ---------------------------------------------------------------------------
// Objets dispatcher
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    NotificationEvent = 0,
    SynchronizationEvent = 1,
    Mutant = 2,
    Process = 3,
    Queue = 4,
    Semaphore = 5,
    Thread = 6,
    NotificationTimer = 8,
    SynchronizationTimer = 9,
}

/// DISPATCHER_HEADER (16 octets sur x86, comme XP).
#[repr(C)]
pub struct DispatcherHeader {
    pub kind: ObjectType,
    pub absolute: u8,
    pub size: u8,
    pub inserted: u8,
    pub signal_state: i32,
    pub wait_list_head: ListEntry,
}

impl DispatcherHeader {
    /// # Safety
    /// `this` est valide en écriture et à adresse stable ; aucun thread ne l'attend.
    pub unsafe fn init(this: *mut Self, kind: ObjectType, signal_state: i32) {
        // SAFETY: garanti par l'appelant ; champs sans destructeur.
        unsafe {
            (*this).kind = kind;
            (*this).absolute = 0;
            (*this).size = 0;
            (*this).inserted = 0;
            (*this).signal_state = signal_state;
            ListEntry::init(ptr::addr_of_mut!((*this).wait_list_head));
        }
    }
}

#[repr(C)]
pub struct KEvent {
    pub header: DispatcherHeader,
}

#[repr(C)]
pub struct KSemaphore {
    pub header: DispatcherHeader,
    pub limit: i32,
}

/// SignalState : 1 = libre, <= 0 = possédé (récursion = valeurs négatives).
#[repr(C)]
pub struct KMutant {
    pub header: DispatcherHeader,
    pub mutant_list_entry: ListEntry,
    pub owner_thread: *mut KThread,
    pub abandoned: bool,
    pub apc_disable: u8,
}

#[repr(C)]
pub struct KTimer {
    pub header: DispatcherHeader,
    /// Échéance en interrupt time (100 ns), tant que le timer est armé.
    pub due_time: u64,
    pub timer_list_entry: ListEntry,
    /// Période en millisecondes ; 0 pour un timer à une seule échéance.
    pub period: i32,
    /// DPC inséré à chaque échéance, ou nul (`ke::timer::ke_set_timer`).
    pub dpc: *const KDpc,
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitType {
    WaitAll = 0,
    WaitAny = 1,
}

/// KWAIT_BLOCK : relie un thread à un objet qu'il attend.
#[repr(C)]
pub struct WaitBlock {
    pub wait_list_entry: ListEntry, // chaîné dans object.wait_list_head
    pub thread: *mut KThread,
    pub object: *mut DispatcherHeader,
    pub next_wait_block: *mut WaitBlock, // non utilisé ici (on garde liste + compteur)
    pub wait_key: u16,                   // index de l'objet, ou STATUS_TIMEOUT pour le timer
    pub wait_type: WaitType,
}

impl Default for WaitBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitBlock {
    pub const fn new() -> Self {
        Self {
            wait_list_entry: ListEntry::new(),
            thread: ptr::null_mut(),
            object: ptr::null_mut(),
            next_wait_block: ptr::null_mut(),
            wait_key: 0,
            wait_type: WaitType::WaitAny,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadState {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessorMode {
    Kernel = 0,
    User = 1,
}

/// Tranche de KTHREAD utile au dispatcher. Le KTHREAD réel (Ps/Ke) l'embarque.
#[repr(C)]
pub struct KThread {
    pub header: DispatcherHeader, // un thread est attendable (signalé à sa terminaison)
    pub state: ThreadState,
    pub wait_mode: ProcessorMode,
    pub alertable: bool,
    pub user_apc_pending: bool,
    pub timer_armed: bool,
    pub wait_count: u8,
    pub wait_status: NtStatus,
    pub wait_block_list: *mut WaitBlock,
    pub wait_blocks: [WaitBlock; THREAD_WAIT_OBJECTS + 1],
    pub timer: KTimer,
    pub mutant_list_head: ListEntry,
    /// APC en file (`ke::apc`) : noyau à l'indice `ProcessorMode::Kernel`,
    /// utilisateur à l'indice `ProcessorMode::User`.
    pub apc_list_head: [ListEntry; 2],
    /// Un APC noyau attend sa livraison.
    pub kernel_apc_pending: bool,
    /// La routine normale d'un APC noyau s'exécute.
    pub kernel_apc_in_progress: bool,
    /// Profondeur de région critique : les APC noyau normaux attendent.
    pub kernel_apc_disable: u16,
    /// Profondeur de région gardée : tous les APC noyau attendent.
    pub special_apc_disable: u16,
    /// IRQL de l'attente en cours : un APC noyau ne l'interrompt qu'à
    /// PASSIVE_LEVEL.
    pub wait_irql: Irql,
    /// Des APC peuvent encore lui être mis en file : faux une fois terminé.
    pub apc_queueable: bool,
}

impl KThread {
    /// Initialise la tranche dispatcher d'un thread, en place : en-tête attendable,
    /// timer de timeout (KTIMER de notification), wait blocks, liste des mutants
    /// possédés.
    ///
    /// # Safety
    /// `this` est valide en écriture pour un `KThread`, à adresse stable pour toute
    /// la vie du thread.
    ///
    /// # IRQL
    /// Tout niveau.
    pub unsafe fn init(this: *mut Self) {
        // SAFETY: garanti par l'appelant. Chaque champ est écrit par pointeur
        // brut, sans référence vers de la mémoire non initialisée.
        unsafe {
            DispatcherHeader::init(ptr::addr_of_mut!((*this).header), ObjectType::Thread, 0);
            ptr::addr_of_mut!((*this).state).write(ThreadState::Initialized);
            ptr::addr_of_mut!((*this).wait_mode).write(ProcessorMode::Kernel);
            ptr::addr_of_mut!((*this).alertable).write(false);
            ptr::addr_of_mut!((*this).user_apc_pending).write(false);
            ptr::addr_of_mut!((*this).timer_armed).write(false);
            ptr::addr_of_mut!((*this).wait_count).write(0);
            ptr::addr_of_mut!((*this).wait_status).write(STATUS_WAIT_0);
            ptr::addr_of_mut!((*this).wait_block_list).write(ptr::null_mut());
            ptr::addr_of_mut!((*this).wait_blocks).write([const { WaitBlock::new() }; THREAD_WAIT_OBJECTS + 1]);
            let timer = ptr::addr_of_mut!((*this).timer);
            DispatcherHeader::init(ptr::addr_of_mut!((*timer).header), ObjectType::NotificationTimer, 0);
            ptr::addr_of_mut!((*timer).due_time).write(0);
            ListEntry::init(ptr::addr_of_mut!((*timer).timer_list_entry));
            ptr::addr_of_mut!((*timer).period).write(0);
            ptr::addr_of_mut!((*timer).dpc).write(ptr::null());
            ListEntry::init(ptr::addr_of_mut!((*this).mutant_list_head));
            ptr::addr_of_mut!((*this).apc_list_head).write([ListEntry::new(), ListEntry::new()]);
            ListEntry::init(ptr::addr_of_mut!((*this).apc_list_head[ProcessorMode::Kernel as usize]));
            ListEntry::init(ptr::addr_of_mut!((*this).apc_list_head[ProcessorMode::User as usize]));
            ptr::addr_of_mut!((*this).kernel_apc_pending).write(false);
            ptr::addr_of_mut!((*this).kernel_apc_in_progress).write(false);
            ptr::addr_of_mut!((*this).kernel_apc_disable).write(0);
            ptr::addr_of_mut!((*this).special_apc_disable).write(0);
            ptr::addr_of_mut!((*this).wait_irql).write(Irql::Passive);
            ptr::addr_of_mut!((*this).apc_queueable).write(true);
        }
    }
}

// ---------------------------------------------------------------------------
// Verrou dispatcher
// ---------------------------------------------------------------------------

pub struct DispatcherLock {
    locked: AtomicBool,
}

impl Default for DispatcherLock {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatcherLock {
    pub const fn new() -> Self {
        Self { locked: AtomicBool::new(false) }
    }

    /// Élève l'IRQL à DISPATCH_LEVEL, puis prend le verrou ; retourne l'IRQL
    /// précédent, à rendre à [`release`](Self::release).
    ///
    /// # Safety
    /// Le verrou n'est pas déjà tenu par ce CPU (il n'est pas réentrant).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub unsafe fn acquire<P: Platform>(&self) -> Irql {
        let old = P::raise_irql(Irql::Dispatch);
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        old
    }

    /// # Safety
    /// Le verrou est tenu par ce CPU, pris depuis `old_irql`.
    ///
    /// # IRQL
    /// DISPATCH_LEVEL ; rabaisse à `old_irql`.
    pub unsafe fn release<P: Platform>(&self, old_irql: Irql) {
        self.locked.store(false, Ordering::Release);
        P::lower_irql(old_irql);
    }

    /// Relâche le verrou en restant à DISPATCH_LEVEL : juste avant une commutation
    /// de thread, dont le thread repris rabaisse lui-même son IRQL (`ke::sched`).
    ///
    /// # Safety
    /// Le verrou est tenu par ce CPU ; rien ne s'exécute sur ce CPU avant la
    /// commutation qui touche à l'état qu'il protège.
    ///
    /// # IRQL
    /// DISPATCH_LEVEL, inchangé.
    pub unsafe fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

pub static DISPATCHER_LOCK: DispatcherLock = DispatcherLock::new();

// ---------------------------------------------------------------------------
// Sémantique de satisfaction / consommation (verrou tenu)
// ---------------------------------------------------------------------------

/// # Safety
/// Verrou dispatcher tenu ; `obj` est valide (un `KMutant` s'il en a le type).
unsafe fn is_signaled_for(obj: *mut DispatcherHeader, thread: *mut KThread) -> bool {
    // SAFETY: garanti par l'appelant.
    unsafe {
        match (*obj).kind {
            // Le propriétaire d'un mutant peut le réacquérir (récursion).
            ObjectType::Mutant => (*obj).signal_state > 0 || (*(obj as *mut KMutant)).owner_thread == thread,
            _ => (*obj).signal_state > 0,
        }
    }
}

/// Applique l'effet de bord d'une attente satisfaite. Retourne `true` si un mutant
/// abandonné vient d'être acquis.
///
/// # Safety
/// Verrou dispatcher tenu ; `obj` est valide et satisfait pour `thread`.
unsafe fn consume(obj: *mut DispatcherHeader, thread: *mut KThread) -> bool {
    // SAFETY: garanti par l'appelant ; `obj` est un `KMutant` quand il en a le type.
    unsafe {
        match (*obj).kind {
            ObjectType::SynchronizationEvent | ObjectType::SynchronizationTimer => {
                (*obj).signal_state = 0;
                false
            }
            ObjectType::Semaphore => {
                (*obj).signal_state -= 1;
                false
            }
            ObjectType::Mutant => {
                let m = obj as *mut KMutant;
                (*obj).signal_state -= 1;
                if (*obj).signal_state == 0 {
                    // Passage libre -> possédé.
                    (*m).owner_thread = thread;
                    ListEntry::insert_tail(
                        ptr::addr_of_mut!((*thread).mutant_list_head),
                        ptr::addr_of_mut!((*m).mutant_list_entry),
                    );
                    let abandoned = (*m).abandoned;
                    (*m).abandoned = false;
                    abandoned
                } else {
                    false
                }
            }
            // Événements/timers de notification, process, thread : aucun effet.
            _ => false,
        }
    }
}

/// # Safety
/// Verrou dispatcher tenu ; `thread` est en attente (wait blocks chaînés).
unsafe fn ki_all_satisfied(thread: *mut KThread) -> bool {
    // SAFETY: garanti par l'appelant ; `wait_block_list` a `wait_count` blocs.
    unsafe {
        let blocks = (*thread).wait_block_list;
        (0..(*thread).wait_count as usize).all(|i| is_signaled_for((*blocks.add(i)).object, thread))
    }
}

/// # Safety
/// Comme [`ki_all_satisfied`], qui vient de retourner `true`.
unsafe fn ki_consume_all(thread: *mut KThread) -> bool {
    // SAFETY: garanti par l'appelant.
    unsafe {
        let blocks = (*thread).wait_block_list;
        let mut abandoned = false;
        for i in 0..(*thread).wait_count as usize {
            abandoned |= consume((*blocks.add(i)).object, thread);
        }
        abandoned
    }
}

/// # Safety
/// Verrou dispatcher tenu ; `thread` est en attente (wait blocks chaînés).
unsafe fn ki_unlink_wait_blocks<P: Platform>(thread: *mut KThread) {
    // SAFETY: garanti par l'appelant ; chaque bloc compté est chaîné dans son objet.
    unsafe {
        let blocks = (*thread).wait_block_list;
        for i in 0..(*thread).wait_count as usize {
            ListEntry::remove(ptr::addr_of_mut!((*blocks.add(i)).wait_list_entry));
        }
        (*thread).wait_count = 0;

        if (*thread).timer_armed {
            let twb = ptr::addr_of_mut!((*thread).wait_blocks[TIMER_WAIT_BLOCK]);
            ListEntry::remove(ptr::addr_of_mut!((*twb).wait_list_entry));
            P::cancel_timer(ptr::addr_of_mut!((*thread).timer));
            (*thread).timer_armed = false;
        }
    }
}

/// Sort un thread de l'attente avec un statut final, relevé d'`increment`.
/// Verrou tenu.
///
/// # Safety
/// Verrou dispatcher tenu ; `thread` est en attente (wait blocks chaînés).
///
/// # IRQL
/// DISPATCH_LEVEL.
pub unsafe fn ki_unwait_thread<P: Platform>(thread: *mut KThread, status: NtStatus, increment: u8) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        ki_unlink_wait_blocks::<P>(thread);
        (*thread).wait_status = status;
        (*thread).state = ThreadState::Ready;
        P::ready_thread(thread, increment);
    }
}

/// Réveille les attentes satisfaisables sur `obj` (KiWaitTest), chaque thread
/// réveillé relevé d'`increment`. Verrou tenu.
///
/// # Safety
/// Verrou dispatcher tenu ; `obj` est valide et ses wait blocks appartiennent à des
/// threads en attente.
unsafe fn ki_wait_test<P: Platform>(obj: *mut DispatcherHeader, increment: u8) {
    // SAFETY: garanti par l'appelant ; chaque entrée de la liste est le
    // `wait_list_entry` d'un WaitBlock valide.
    unsafe {
        let head = ptr::addr_of_mut!((*obj).wait_list_head);
        let mut entry = (*head).flink;

        while entry != head && (*obj).signal_state > 0 {
            let wb = containing_record!(entry, WaitBlock, wait_list_entry);
            let thread = (*wb).thread;

            if (*wb).wait_type == WaitType::WaitAny {
                let mut status = NtStatus(u32::from((*wb).wait_key));
                if consume(obj, thread) {
                    status.0 |= STATUS_ABANDONED_WAIT_0.0;
                }
                ki_unwait_thread::<P>(thread, status, increment);
                // La liste a été modifiée (tous les blocs du thread retirés) : on repart
                // de la tête. Termine car chaque tour retire au moins un attendant.
                entry = (*head).flink;
            } else if ki_all_satisfied(thread) {
                let status = if ki_consume_all(thread) { STATUS_ABANDONED_WAIT_0 } else { STATUS_WAIT_0 };
                ki_unwait_thread::<P>(thread, status, increment);
                entry = (*head).flink;
            } else {
                entry = (*entry).flink;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Attente
// ---------------------------------------------------------------------------

/// KeWaitForMultipleObjects. Pour plus de 3 objets, l'appelant fournit un tableau
/// de wait blocks (comme NT). Les doublons en WaitAll doivent être rejetés en amont
/// (STATUS_INVALID_PARAMETER_MIX côté Nt*). Sans objet, un WaitAny avec timeout
/// n'attend que celui-ci ([`ke_delay_execution_thread`]).
///
/// # Safety
/// Les objets sont initialisés et restent valides pendant l'attente ; le thread
/// courant a été initialisé par [`KThread::init`].
///
/// # IRQL
/// <= APC_LEVEL ; DISPATCH_LEVEL seulement avec un timeout nul. Peut bloquer.
pub unsafe fn ke_wait_for_multiple_objects<P: Platform>(
    objects: &[*mut DispatcherHeader],
    wait_type: WaitType,
    wait_mode: ProcessorMode,
    alertable: bool,
    timeout: Option<i64>,
    wait_block_array: Option<&mut [WaitBlock]>,
) -> NtStatus {
    let count = objects.len();
    assert!(count <= MAXIMUM_WAIT_OBJECTS, "wait on {count} objects");
    assert!(count > 0 || (wait_type == WaitType::WaitAny && timeout.is_some()), "wait on nothing, forever");

    let thread = P::current_thread();
    let blocks: *mut WaitBlock = match wait_block_array {
        Some(a) => {
            assert!(a.len() >= count);
            a.as_mut_ptr()
        }
        None => {
            assert!(count <= THREAD_WAIT_OBJECTS);
            // SAFETY: le thread courant est valide (garanti par l'appelant).
            unsafe { ptr::addr_of_mut!((*thread).wait_blocks) as *mut WaitBlock }
        }
    };

    loop {
        // SAFETY: le thread courant ne tient pas le verrou en entrant ici.
        let old_irql = unsafe { DISPATCHER_LOCK.acquire::<P>() };

        // SAFETY (jusqu'à la fin de l'itération) : verrou tenu ; les objets, le
        // thread et `blocks` (count blocs) sont valides (garanti par l'appelant).
        unsafe {
            // APC utilisateur déjà en attente : une attente alertable retourne immédiatement.
            if alertable && wait_mode == ProcessorMode::User && (*thread).user_apc_pending {
                DISPATCHER_LOCK.release::<P>(old_irql);
                return STATUS_USER_APC;
            }

            // Chemin rapide : déjà satisfaisable.
            match wait_type {
                WaitType::WaitAny => {
                    for (i, &obj) in objects.iter().enumerate() {
                        if is_signaled_for(obj, thread) {
                            let abandoned = consume(obj, thread);
                            DISPATCHER_LOCK.release::<P>(old_irql);
                            return if abandoned {
                                NtStatus::abandoned_wait(i as u32)
                            } else {
                                NtStatus::wait(i as u32)
                            };
                        }
                    }
                }
                WaitType::WaitAll => {
                    if objects.iter().all(|&o| is_signaled_for(o, thread)) {
                        let mut abandoned = false;
                        for &o in objects {
                            abandoned |= consume(o, thread);
                        }
                        DISPATCHER_LOCK.release::<P>(old_irql);
                        return if abandoned { STATUS_ABANDONED_WAIT_0 } else { STATUS_WAIT_0 };
                    }
                }
            }

            if timeout == Some(0) {
                DISPATCHER_LOCK.release::<P>(old_irql);
                return STATUS_TIMEOUT;
            }

            // Chemin lent : chaîner les wait blocks dans les objets.
            for (i, &obj) in objects.iter().enumerate() {
                let wb = blocks.add(i);
                (*wb).thread = thread;
                (*wb).object = obj;
                (*wb).wait_key = i as u16;
                (*wb).wait_type = wait_type;
                ListEntry::insert_tail(
                    ptr::addr_of_mut!((*obj).wait_list_head),
                    ptr::addr_of_mut!((*wb).wait_list_entry),
                );
            }
            (*thread).wait_block_list = blocks;
            (*thread).wait_count = count as u8;
            (*thread).timer_armed = false;

            // Timeout : 4e wait block, toujours WaitAny, même pour un WaitAll.
            if let Some(due) = timeout {
                let timer = ptr::addr_of_mut!((*thread).timer);
                let twb = ptr::addr_of_mut!((*thread).wait_blocks[TIMER_WAIT_BLOCK]);
                (*timer).header.signal_state = 0;
                (*twb).thread = thread;
                (*twb).object = ptr::addr_of_mut!((*timer).header);
                (*twb).wait_key = STATUS_TIMEOUT.0 as u16;
                (*twb).wait_type = WaitType::WaitAny;
                ListEntry::insert_tail(
                    ptr::addr_of_mut!((*timer).header.wait_list_head),
                    ptr::addr_of_mut!((*twb).wait_list_entry),
                );
                (*thread).timer_armed = true;

                if !P::insert_timer(timer, due) {
                    // Échéance déjà passée.
                    (*thread).timer_armed = false;
                    ListEntry::remove(ptr::addr_of_mut!((*twb).wait_list_entry));
                    ki_unlink_wait_blocks::<P>(thread);
                    DISPATCHER_LOCK.release::<P>(old_irql);
                    return STATUS_TIMEOUT;
                }
            }

            (*thread).wait_mode = wait_mode;
            (*thread).alertable = alertable;
            (*thread).wait_irql = old_irql;
            (*thread).wait_status = STATUS_WAIT_0;
            (*thread).state = ThreadState::Waiting;

            let status = P::swap_thread(old_irql);

            // Un APC noyau a interrompu l'attente (et l'a défaite) ; il a été
            // livré à la reprise, en redescendant sous APC_LEVEL : on la relance.
            // TODO : recalculer un timeout relatif à partir du temps déjà écoulé.
            if status != STATUS_KERNEL_APC {
                return status;
            }
        }
    }
}

/// KeDelayExecutionThread : bloque le thread courant pendant `interval` (format NT
/// des échéances) ; STATUS_SUCCESS à l'échéance. Une attente alertable peut finir
/// plus tôt (STATUS_USER_APC). Un intervalle nul ou déjà échu retourne aussitôt,
/// sans céder le processeur.
///
/// # Safety
/// Le thread courant a été initialisé par [`KThread::init`].
///
/// # IRQL
/// <= APC_LEVEL. Peut bloquer.
pub unsafe fn ke_delay_execution_thread<P: Platform>(
    wait_mode: ProcessorMode,
    alertable: bool,
    interval: i64,
) -> NtStatus {
    // SAFETY: garanti par l'appelant ; aucun objet à garder valide.
    match unsafe {
        ke_wait_for_multiple_objects::<P>(&[], WaitType::WaitAny, wait_mode, alertable, Some(interval), None)
    } {
        STATUS_TIMEOUT => STATUS_SUCCESS,
        status => status,
    }
}

/// # Safety
/// Comme [`ke_wait_for_multiple_objects`].
///
/// # IRQL
/// <= APC_LEVEL ; DISPATCH_LEVEL seulement avec un timeout nul. Peut bloquer.
pub unsafe fn ke_wait_for_single_object<P: Platform>(
    object: *mut DispatcherHeader,
    wait_mode: ProcessorMode,
    alertable: bool,
    timeout: Option<i64>,
) -> NtStatus {
    // SAFETY: garanti par l'appelant.
    unsafe { ke_wait_for_multiple_objects::<P>(&[object], WaitType::WaitAny, wait_mode, alertable, timeout, None) }
}

// ---------------------------------------------------------------------------
// Signalisation
// ---------------------------------------------------------------------------

/// # Safety
/// `ev` est valide en écriture et à adresse stable ; aucun thread ne l'attend.
///
/// # IRQL
/// Tout niveau.
pub unsafe fn ke_initialize_event(ev: *mut KEvent, kind: ObjectType, signaled: bool) {
    debug_assert!(matches!(kind, ObjectType::NotificationEvent | ObjectType::SynchronizationEvent));
    // SAFETY: garanti par l'appelant.
    unsafe { DispatcherHeader::init(ptr::addr_of_mut!((*ev).header), kind, signaled as i32) };
}

/// KeSetEvent : retourne l'état précédent. Les threads réveillés sont relevés
/// d'`increment` (en général [`EVENT_INCREMENT`]).
///
/// # Safety
/// `ev` est un événement initialisé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_set_event<P: Platform>(ev: *mut KEvent, increment: u8) -> i32 {
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let h = ptr::addr_of_mut!((*ev).header);
        let prev = (*h).signal_state;
        if prev == 0 {
            (*h).signal_state = 1;
            // Notification : réveille tout le monde. Synchronisation : un seul, puis
            // consume() remet l'état à 0 et la boucle de ki_wait_test s'arrête.
            ki_wait_test::<P>(h, increment);
        }
        DISPATCHER_LOCK.release::<P>(old_irql);
        prev
    }
}

/// # Safety
/// `ev` est un événement initialisé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_reset_event<P: Platform>(ev: *mut KEvent) -> i32 {
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let prev = (*ev).header.signal_state;
        (*ev).header.signal_state = 0;
        DISPATCHER_LOCK.release::<P>(old_irql);
        prev
    }
}

/// KePulseEvent : réveille les attendants actuels, relevés d'`increment`, puis
/// repasse à non signalé.
///
/// # Safety
/// `ev` est un événement initialisé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_pulse_event<P: Platform>(ev: *mut KEvent, increment: u8) -> i32 {
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let h = ptr::addr_of_mut!((*ev).header);
        let prev = (*h).signal_state;
        if prev == 0 {
            (*h).signal_state = 1;
            ki_wait_test::<P>(h, increment);
        }
        (*h).signal_state = 0;
        DISPATCHER_LOCK.release::<P>(old_irql);
        prev
    }
}

/// # Safety
/// `s` est valide en écriture et à adresse stable ; aucun thread ne l'attend.
///
/// # IRQL
/// Tout niveau.
pub unsafe fn ke_initialize_semaphore(s: *mut KSemaphore, count: i32, limit: i32) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        DispatcherHeader::init(ptr::addr_of_mut!((*s).header), ObjectType::Semaphore, count);
        (*s).limit = limit;
    }
}

/// KeReleaseSemaphore : ajoute `adjustment` au compte ; les threads réveillés
/// sont relevés d'`increment` (en général [`SEMAPHORE_INCREMENT`]).
///
/// # Safety
/// `s` est un sémaphore initialisé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_release_semaphore<P: Platform>(
    s: *mut KSemaphore,
    increment: u8,
    adjustment: i32,
) -> Result<i32, NtStatus> {
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let h = ptr::addr_of_mut!((*s).header);
        let prev = (*h).signal_state;
        let exceeded = adjustment <= 0 || prev.checked_add(adjustment).is_none_or(|n| n > (*s).limit);
        if exceeded {
            DISPATCHER_LOCK.release::<P>(old_irql);
            return Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED);
        }
        (*h).signal_state = prev + adjustment;
        if prev == 0 {
            ki_wait_test::<P>(h, increment);
        }
        DISPATCHER_LOCK.release::<P>(old_irql);
        Ok(prev)
    }
}

/// # Safety
/// `m` est valide en écriture et à adresse stable ; aucun thread ne l'attend.
///
/// # IRQL
/// Tout niveau.
pub unsafe fn ke_initialize_mutant(m: *mut KMutant) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        DispatcherHeader::init(ptr::addr_of_mut!((*m).header), ObjectType::Mutant, 1);
        ListEntry::init(ptr::addr_of_mut!((*m).mutant_list_entry));
        (*m).owner_thread = ptr::null_mut();
        (*m).abandoned = false;
        (*m).apc_disable = 0;
    }
}

/// KeReleaseMutant. `abandoned = true` abandonne le mutant, quel que soit son
/// propriétaire ([`ki_thread_exit`] le fait, verrou tenu, pour ceux d'un thread qui
/// se termine). Le thread qui l'acquiert est relevé d'`increment` (en général
/// [`MUTANT_INCREMENT`]).
///
/// # Safety
/// `m` est un mutant initialisé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_release_mutant<P: Platform>(m: *mut KMutant, increment: u8, abandoned: bool) -> Result<i32, NtStatus> {
    let thread = P::current_thread();
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let h = ptr::addr_of_mut!((*m).header);
        let prev = (*h).signal_state;

        if abandoned {
            (*h).signal_state = 1;
            (*m).abandoned = true;
        } else {
            if (*m).owner_thread != thread {
                DISPATCHER_LOCK.release::<P>(old_irql);
                return Err(STATUS_MUTANT_NOT_OWNED);
            }
            (*h).signal_state += 1;
        }

        if (*h).signal_state == 1 {
            if !(*m).owner_thread.is_null() {
                ListEntry::remove(ptr::addr_of_mut!((*m).mutant_list_entry));
            }
            (*m).owner_thread = ptr::null_mut();
            ki_wait_test::<P>(h, increment);
        }

        DISPATCHER_LOCK.release::<P>(old_irql);
        Ok(prev)
    }
}

// ---------------------------------------------------------------------------
// Intégrations timers / APC (appelées verrou tenu)
// ---------------------------------------------------------------------------

/// Appelé par le DPC d'expiration quand un timer arrive à échéance (déjà retiré de
/// la roue). Réveille notamment les threads dont c'est le timeout, sans relever
/// leur priorité. Le DPC du timer et le réarmement d'un timer périodique
/// reviennent à `ke::timer`.
///
/// # Safety
/// Verrou dispatcher tenu ; `timer` est valide.
///
/// # IRQL
/// DISPATCH_LEVEL.
pub unsafe fn ki_timer_expired<P: Platform>(timer: *mut KTimer) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        let h = ptr::addr_of_mut!((*timer).header);
        (*h).signal_state = 1;
        ki_wait_test::<P>(h, IO_NO_INCREMENT);
    }
}

/// Fin d'un thread : son attente éventuelle est défaite, les mutants qu'il possède
/// sont abandonnés (le suivant à les acquérir reçoit STATUS_ABANDONED_WAIT_0,
/// relevé de [`MUTANT_INCREMENT`]), et l'objet thread est signalé, ce qui réveille
/// sans relèvement ceux qui attendent sa fin. Le retirer de l'ordonnancement
/// revient à l'appelant.
///
/// # Safety
/// Verrou dispatcher tenu ; `thread` est valide.
///
/// # IRQL
/// DISPATCH_LEVEL.
pub unsafe fn ki_thread_exit<P: Platform>(thread: *mut KThread) {
    // SAFETY: garanti par l'appelant ; la liste des mutants ne contient que les
    // `mutant_list_entry` de mutants valides que le thread possède.
    unsafe {
        if (*thread).state == ThreadState::Waiting {
            ki_unlink_wait_blocks::<P>(thread);
        }
        (*thread).state = ThreadState::Terminated;
        // Ses APC encore en file y restent : Ps en a fait le rundown avant
        // (`ke_rundown_apcs`).
        (*thread).apc_queueable = false;
        let mutants = ptr::addr_of_mut!((*thread).mutant_list_head);
        while !ListEntry::is_empty(mutants) {
            let entry = (*mutants).flink;
            ListEntry::remove(entry);
            let m = containing_record!(entry, KMutant, mutant_list_entry);
            (*m).owner_thread = ptr::null_mut();
            (*m).abandoned = true;
            (*m).header.signal_state = 1;
            ki_wait_test::<P>(ptr::addr_of_mut!((*m).header), MUTANT_INCREMENT);
        }
        (*thread).header.signal_state = 1;
        ki_wait_test::<P>(ptr::addr_of_mut!((*thread).header), IO_NO_INCREMENT);
    }
}

/// Appelé après l'insertion d'un APC utilisateur. Un thread en attente alertable
/// en mode utilisateur sort avec STATUS_USER_APC (SleepEx, WaitForSingleObjectEx...),
/// relevé d'`increment` (celui de l'insertion de l'APC).
///
/// # Safety
/// Verrou dispatcher tenu ; `thread` est valide.
///
/// # IRQL
/// DISPATCH_LEVEL.
pub unsafe fn ki_try_unwait_for_user_apc<P: Platform>(thread: *mut KThread, increment: u8) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        (*thread).user_apc_pending = true;
        if (*thread).state == ThreadState::Waiting && (*thread).alertable && (*thread).wait_mode == ProcessorMode::User
        {
            ki_unwait_thread::<P>(thread, STATUS_USER_APC, increment);
        }
    }
}

/// Appelé après l'insertion d'un APC noyau : l'attente est défaite, l'APC s'exécute
/// à la reprise, relevé d'`increment` (celui de l'insertion de l'APC), puis
/// ke_wait_for_multiple_objects relance l'attente.
///
/// # Safety
/// Verrou dispatcher tenu ; `thread` est valide.
///
/// # IRQL
/// DISPATCH_LEVEL.
pub unsafe fn ki_unwait_for_kernel_apc<P: Platform>(thread: *mut KThread, increment: u8) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        if (*thread).state == ThreadState::Waiting {
            ki_unwait_thread::<P>(thread, STATUS_KERNEL_APC, increment);
        }
    }
}

#[cfg(test)]
mod tests;
