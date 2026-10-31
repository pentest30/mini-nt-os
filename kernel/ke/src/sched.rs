//! Ordonnanceur (M1, 02 §Ke) : 32 priorités, quantum, attente, préemption.
//!
//! Un thread est un [`Thread`] : la tranche dispatcher (`dispatcher::KThread`) en
//! tête, puis son contexte de commutation, sa priorité, son quantum, son état
//! FPU (ADR-009) et la base de répertoire (CR3) de son espace d'adresses, que
//! chaque commutation charge (`mm::address_space`). La table des threads ([`ThreadTable`], TID → thread) est
//! commune aux processeurs ; l'ordonnancement ([`Scheduler`]) est propre à
//! chacun et vit dans son KPRCB (`ke::prcb`, ADR-015). Les threads prêts d'un
//! processeur attendent dans une file par priorité (anneau, [`ReadyQueue`]) ; un
//! bitmap résume les files non vides. Le thread idle n'est dans aucune file : il
//! tourne quand aucun autre n'est prêt.
//!
//! - Préemption : un thread qui devient prêt avec une priorité supérieure à celle
//!   du thread courant le préempte à la prochaine interruption DISPATCH ; le
//!   préempté repasse en tête de sa file, avec le reste de son quantum.
//! - Quantum : deux ticks d'horloge, comptés en tiers de tick. Une attente en
//!   coûte un tiers : un thread qui attend souvent finit aussi ses quanta. Au
//!   terme d'un quantum, le thread cède la place aux threads prêts de même
//!   priorité et repasse en queue de sa file.
//! - Attente : le dispatcher (`Platform::swap_thread`) bascule vers le thread prêt
//!   le plus prioritaire, ou vers idle.
//! - Boosts : un thread a une priorité de base et une priorité courante. Réveillé
//!   par un signal, un thread de priorité variable (base 1 à 15) passe à sa base
//!   plus le relèvement du signal (`dispatcher::EVENT_INCREMENT`…), sans dépasser
//!   15 ni redescendre s'il était déjà plus haut ([`wait_boost`]) ; relevé, il
//!   reçoit un quantum neuf. À chaque fin de quantum, la priorité courante perd un
//!   niveau jusqu'à sa base ([`decay`]). Les threads temps réel (base 16 à 31)
//!   gardent leur priorité.
//! - Famine : un thread de priorité variable prêt depuis au moins 4 s passe à 15
//!   pour un double quantum, puis revient à sa base, ou dès qu'il attend
//!   ([`Scheduler::scan_starved`], que le balance set manager, `ke::balance`,
//!   lance chaque seconde). Un thread
//!   moins prioritaire finit ainsi par s'exécuter, et par rendre un verrou qu'un
//!   thread plus prioritaire attend.
//!
//! Table et ordonnancement sont protégés par le verrou dispatcher (ADR-005). Une
//! commutation relâche ce verrou juste avant de changer de pile, en restant à
//! DISPATCH_LEVEL : sur un seul CPU (ADR-015), rien de ce qui touche à cet état ne
//! peut s'exécuter entre-temps. Le thread repris rabaisse lui-même son IRQL.
//!
//! Pas encore : changement de priorité, récupération des threads terminés (leur
//! objet et leur pile restent alloués).
//!
//! [`KePlatform`] relie le dispatcher, les timers et l'IRQL à cet ordonnanceur.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use abi::fpu::FxSaveArea;
use abi::ntstatus::NtStatus;
use hal::irql::Irql;

use crate::dispatcher::{ki_thread_exit, DispatcherHeader, KThread, KTimer, Platform, ThreadState, DISPATCHER_LOCK};
use crate::prcb;
use crate::thread::{context_switch_raw, KContext};

// ── Constantes ───────────────────────────────────────────────────────────────

/// Nombre maximal de threads.
pub const MAX_THREADS: usize = 64;

/// Niveaux de priorité : 0 (idle) à 31.
pub const PRIORITY_LEVELS: usize = 32;

/// Priorité du thread idle, qui n'appartient qu'à lui.
pub const IDLE_PRIORITY: u8 = 0;

/// Priorité normale : celle du thread de démarrage et des threads utilisateur.
pub const NORMAL_PRIORITY: u8 = 8;

/// Première priorité temps réel : en dessous, la priorité est variable et les
/// boosts la relèvent, sans jamais l'atteindre.
pub const LOW_REALTIME_PRIORITY: u8 = 16;

/// Durée d'un quantum, en ticks d'horloge.
const QUANTUM_TICKS: u32 = 2;

/// Base de répertoire (CR3) de l'espace du système, celle du démarrage : celle
/// des threads noyau, et des threads utilisateur de l'ancien chargeur, qui
/// n'ont pas encore chacun leur espace.
static SYSTEM_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// Le quantum se compte en unités, trois par tick : une attente en coûte une.
const QUANTUM_UNITS_PER_TICK: i32 = 3;

/// Un quantum entier, en unités.
const QUANTUM: i32 = QUANTUM_TICKS as i32 * QUANTUM_UNITS_PER_TICK;

/// Un thread prêt depuis autant de ticks est affamé : 4 s.
pub const STARVATION_TICKS: u64 = 4000 / hal::timer::TICK_INTERVAL_MS;

/// Threads affamés relevés au plus par examen des files prêtes.
const STARVATION_BOOSTS: usize = 10;

// ── File prête ───────────────────────────────────────────────────────────────

/// File FIFO de threads, en anneau de capacité fixe : l'ordonnanceur n'alloue
/// jamais (il s'exécute à DISPATCH_LEVEL). Un thread y figure au plus une fois.
#[derive(Clone, Copy)]
pub struct ReadyQueue {
    buf: [*mut Thread; MAX_THREADS],
    head: usize,
    len: usize,
}

impl Default for ReadyQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadyQueue {
    pub const fn new() -> Self {
        Self { buf: [ptr::null_mut(); MAX_THREADS], head: 0, len: 0 }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == MAX_THREADS
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Ajoute en queue ; `false` si la file est pleine.
    pub fn push(&mut self, thread: *mut Thread) -> bool {
        if self.is_full() {
            return false;
        }
        self.buf[(self.head + self.len) % MAX_THREADS] = thread;
        self.len += 1;
        true
    }

    /// Ajoute en tête ; `false` si la file est pleine.
    pub fn push_front(&mut self, thread: *mut Thread) -> bool {
        if self.is_full() {
            return false;
        }
        self.head = (self.head + MAX_THREADS - 1) % MAX_THREADS;
        self.buf[self.head] = thread;
        self.len += 1;
        true
    }

    /// Les threads de la file, du premier au dernier.
    pub fn iter(&self) -> impl Iterator<Item = *mut Thread> + '_ {
        (0..self.len).map(move |i| self.buf[(self.head + i) % MAX_THREADS])
    }

    /// Sort le premier thread.
    pub fn pop(&mut self) -> Option<*mut Thread> {
        if self.is_empty() {
            return None;
        }
        let thread = self.buf[self.head];
        self.head = (self.head + 1) % MAX_THREADS;
        self.len -= 1;
        Some(thread)
    }

    /// Retire `thread` où qu'il soit, sans changer l'ordre des autres ; `false`
    /// s'il n'y est pas.
    pub fn remove(&mut self, thread: *mut Thread) -> bool {
        let Some(at) = (0..self.len).find(|&i| self.buf[(self.head + i) % MAX_THREADS] == thread) else {
            return false;
        };
        for i in at..self.len - 1 {
            self.buf[(self.head + i) % MAX_THREADS] = self.buf[(self.head + i + 1) % MAX_THREADS];
        }
        self.len -= 1;
        true
    }
}

// ── Thread ───────────────────────────────────────────────────────────────────

/// Routine d'un thread noyau.
pub type ThreadRoutine = fn(context: *mut c_void);

/// Un thread : la tranche dispatcher en tête, à la même adresse que le
/// `KThread` que voit le dispatcher, puis ce que l'ordonnanceur en sait.
#[repr(C)]
pub struct Thread {
    pub tcb: KThread,
    ctx: KContext,
    tid: usize,
    /// Priorité de base, fixée à la création.
    base_priority: u8,
    /// Priorité courante : la base, ou plus pendant un boost. Elle choisit la
    /// file prête du thread ; elle ne change pas tant qu'il y est.
    priority: u8,
    /// Unités restantes du quantum (un tick en vaut [`QUANTUM_UNITS_PER_TICK`]).
    quantum: i32,
    /// Heure (horloge de l'ordonnanceur, en ticks) de son entrée en file prête.
    ready_since: u64,
    /// Relevé à 15 contre la famine, jusqu'à la fin de ce quantum ou sa
    /// prochaine attente.
    starvation_boost: bool,
    /// Thread utilisateur : TSS.RSP0 doit pointer sur sa pile noyau.
    user_mode: bool,
    kernel_stack_top: u64,
    /// Routine d'un thread noyau, lancée par [`ki_thread_startup`].
    start: Option<(ThreadRoutine, *mut c_void)>,
    /// État x87/SSE, sauvegardé et restauré à chaque commutation (ADR-009).
    fpu: FxSaveArea,
    /// CR3 de son espace d'adresses, chargé à chaque commutation ; celui d'un
    /// autre espace tant qu'il y est attaché ([`ke_stack_attach`]).
    directory_table_base: u64,
    /// Adresse de son TEB (thread utilisateur), base du segment FS en mode
    /// utilisateur : écrite dans le descripteur du TEB à chaque commutation.
    teb: u32,
    /// Le thread de l'exécutif qui le possède (ETHREAD de Ps), opaque pour Ke ;
    /// nul pour un thread noyau.
    owner: *const c_void,
}

impl Thread {
    /// Alloue un thread et l'initialise ; [`delete_thread`] le libère une fois
    /// terminé.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL (alloue).
    fn create(
        priority: u8,
        ctx: KContext,
        user_mode: bool,
        kernel_stack_top: u64,
        start: Option<(ThreadRoutine, *mut c_void)>,
    ) -> *mut Thread {
        let t = Box::into_raw(Box::<Thread>::new_uninit()).cast::<Thread>();
        // SAFETY: mémoire fraîche, à adresse stable ; chaque champ est écrit par
        // pointeur brut, sans référence vers de la mémoire non initialisée.
        unsafe {
            KThread::init(ptr::addr_of_mut!((*t).tcb));
            ptr::addr_of_mut!((*t).ctx).write(ctx);
            ptr::addr_of_mut!((*t).tid).write(usize::MAX);
            ptr::addr_of_mut!((*t).base_priority).write(priority);
            ptr::addr_of_mut!((*t).priority).write(priority);
            ptr::addr_of_mut!((*t).quantum).write(QUANTUM);
            ptr::addr_of_mut!((*t).ready_since).write(0);
            ptr::addr_of_mut!((*t).starvation_boost).write(false);
            ptr::addr_of_mut!((*t).user_mode).write(user_mode);
            ptr::addr_of_mut!((*t).kernel_stack_top).write(kernel_stack_top);
            ptr::addr_of_mut!((*t).start).write(start);
            ptr::addr_of_mut!((*t).fpu).write(FxSaveArea::initial());
            ptr::addr_of_mut!((*t).directory_table_base).write(SYSTEM_DIRECTORY.load(Ordering::Relaxed));
            ptr::addr_of_mut!((*t).teb).write(0);
            ptr::addr_of_mut!((*t).owner).write(ptr::null());
        }
        t
    }
}

// ── Table des threads ────────────────────────────────────────────────────────

/// TID → thread, commune aux processeurs. Dans le noyau, sous le verrou
/// dispatcher.
pub struct ThreadTable {
    threads: [*mut Thread; MAX_THREADS],
}

impl Default for ThreadTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadTable {
    pub const fn new() -> Self {
        Self { threads: [ptr::null_mut(); MAX_THREADS] }
    }

    /// Enregistre `thread` et lui donne son TID ; `None` si la table est pleine.
    ///
    /// # Safety
    /// `thread` est valide pour toute la vie de la table.
    pub unsafe fn register(&mut self, thread: *mut Thread) -> Option<usize> {
        let tid = self.threads.iter().position(|t| t.is_null())?;
        self.threads[tid] = thread;
        // SAFETY: garanti par l'appelant.
        unsafe { (*thread).tid = tid };
        Some(tid)
    }

    /// Le thread `tid`, ou nul.
    pub fn get(&self, tid: usize) -> *mut Thread {
        self.threads.get(tid).copied().unwrap_or(ptr::null_mut())
    }

    /// Retire le thread `tid` de la table et le rend ; nul s'il n'y est pas.
    /// Son TID pourra servir à un autre thread.
    pub fn unregister(&mut self, tid: usize) -> *mut Thread {
        self.threads.get_mut(tid).map(|slot| core::mem::replace(slot, ptr::null_mut())).unwrap_or(ptr::null_mut())
    }
}

// ── Ordonnancement d'un processeur ───────────────────────────────────────────

/// Files prêtes, thread courant et thread idle d'un processeur (son KPRCB).
/// Dans le noyau, sous le verrou dispatcher. Ne tient que des threads valides
/// (contrat de [`start`](Self::start) et de [`ready`](Self::ready)).
pub struct Scheduler {
    ready: [ReadyQueue; PRIORITY_LEVELS],
    /// Bit `p` : la file de priorité `p` n'est pas vide.
    summary: u32,
    current: *mut Thread,
    idle: *mut Thread,
    /// Ticks d'horloge vus par ce processeur ([`dispatch`](Self::dispatch)).
    clock: u64,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready: [const { ReadyQueue::new() }; PRIORITY_LEVELS],
            summary: 0,
            current: ptr::null_mut(),
            idle: ptr::null_mut(),
            clock: 0,
        }
    }

    /// `current` s'exécute sur ce processeur ; `idle` y tournera quand rien
    /// d'autre n'est prêt.
    ///
    /// # Safety
    /// Les deux threads sont valides pour toute la vie de l'ordonnanceur.
    pub unsafe fn start(&mut self, current: *mut Thread, idle: *mut Thread) {
        self.idle = idle;
        self.make_current(current);
    }

    /// `thread` devient prêt : en queue de la file de sa priorité, ou en tête
    /// s'il vient d'être préempté. `true` s'il doit préempter le thread courant.
    ///
    /// # Safety
    /// `thread` est valide pour toute la vie de l'ordonnanceur ; il n'est ni
    /// courant ni déjà en file.
    pub unsafe fn ready(&mut self, thread: *mut Thread, front: bool) -> bool {
        // SAFETY: garanti par l'appelant.
        let p = unsafe {
            (*thread).tcb.state = ThreadState::Ready;
            (*thread).ready_since = self.clock;
            (*thread).priority
        };
        let queue = &mut self.ready[usize::from(p)];
        let queued = if front { queue.push_front(thread) } else { queue.push(thread) };
        assert!(queued, "ready queue overflow: a thread is queued twice");
        self.summary |= 1 << p;
        self.current == self.idle || p > priority(self.current)
    }

    /// `thread` sort d'une attente, réveillé avec le relèvement `increment`, et
    /// devient prêt ([`ready`](Self::ready)). Si le relèvement élève sa priorité
    /// ([`wait_boost`]), il reçoit un quantum neuf ; sinon l'attente coûte une
    /// unité de son quantum, dont la fin fait décroître sa priorité ([`decay`]).
    /// `true` s'il doit préempter le thread courant.
    ///
    /// # Safety
    /// Comme [`ready`](Self::ready).
    pub unsafe fn ready_unwaited(&mut self, thread: *mut Thread, increment: u8) -> bool {
        // SAFETY: garanti par l'appelant ; hors file, la priorité peut changer.
        unsafe {
            if (*thread).starvation_boost {
                // Il a attendu : le relèvement contre la famine a servi.
                end_quantum(thread);
            }
            let (base, current) = ((*thread).base_priority, (*thread).priority);
            let boosted = wait_boost(base, current, increment);
            if boosted > current {
                (*thread).priority = boosted;
                (*thread).quantum = QUANTUM;
            } else {
                (*thread).quantum -= 1;
                if (*thread).quantum <= 0 {
                    end_quantum(thread);
                }
            }
            self.ready(thread, false)
        }
    }

    /// Retire de sa file un thread prêt.
    ///
    /// # Safety
    /// `thread` est valide.
    pub unsafe fn unready(&mut self, thread: *mut Thread) {
        // SAFETY: garanti par l'appelant.
        let p = usize::from(unsafe { (*thread).priority });
        self.ready[p].remove(thread);
        if self.ready[p].is_empty() {
            self.summary &= !(1 << p);
        }
    }

    /// Priorité du plus prioritaire des threads prêts.
    fn highest(&self) -> Option<u8> {
        (self.summary != 0).then(|| 31 - self.summary.leading_zeros() as u8)
    }

    fn pop_highest(&mut self) -> Option<*mut Thread> {
        let p = usize::from(self.highest()?);
        let thread = self.ready[p].pop();
        if self.ready[p].is_empty() {
            self.summary &= !(1 << p);
        }
        thread
    }

    fn make_current(&mut self, thread: *mut Thread) -> *mut Thread {
        // SAFETY: l'ordonnanceur ne tient que des threads valides.
        unsafe { (*thread).tcb.state = ThreadState::Running };
        self.current = thread;
        thread
    }

    /// Le thread courant cède le processeur (il attend, ou se termine) : le plus
    /// prioritaire des threads prêts devient courant, ou idle.
    pub fn select_next(&mut self) -> *mut Thread {
        let next = self.pop_highest().unwrap_or(self.idle);
        self.make_current(next)
    }

    /// Interruption DISPATCH, `ticks` d'horloge après la précédente : le
    /// prochain thread s'il faut commuter, le courant étant remis en file.
    pub fn dispatch(&mut self, ticks: u32) -> Option<*mut Thread> {
        self.clock += u64::from(ticks);
        let cur = self.current;
        if cur == self.idle {
            let next = self.pop_highest()?;
            return Some(self.make_current(next));
        }
        // SAFETY: l'ordonnanceur ne tient que des threads valides ; le thread
        // courant n'est dans aucune file, sa priorité peut changer.
        let expired = unsafe {
            let used = i32::try_from(ticks).unwrap_or(i32::MAX).saturating_mul(QUANTUM_UNITS_PER_TICK);
            (*cur).quantum = (*cur).quantum.saturating_sub(used);
            let expired = (*cur).quantum <= 0;
            if expired {
                end_quantum(cur);
            }
            expired
        };
        let best = self.highest()?;
        if best > priority(cur) || (expired && best == priority(cur)) {
            // SAFETY: le thread courant est valide, et n'est pas en file.
            unsafe { self.ready(cur, !expired) };
            let next = self.pop_highest()?;
            Some(self.make_current(next))
        } else {
            None
        }
    }

    /// Relève les threads affamés : ceux de priorité variable, sous 15, prêts
    /// depuis au moins `threshold` ticks passent à 15 pour un double quantum,
    /// au bout duquel ils reviennent à leur base. Au plus [`STARVATION_BOOSTS`]
    /// par appel, les moins prioritaires d'abord ; toutes les files sont
    /// examinées (au plus [`MAX_THREADS`] threads). `true` si l'un d'eux doit
    /// préempter le thread courant.
    pub fn scan_starved(&mut self, threshold: u64) -> bool {
        let mut starved = [ptr::null_mut(); STARVATION_BOOSTS];
        let mut found = 0;
        'scan: for queue in &self.ready[1..usize::from(LOW_REALTIME_PRIORITY - 1)] {
            for thread in queue.iter() {
                // SAFETY: l'ordonnanceur ne tient que des threads valides.
                let since = unsafe { (*thread).ready_since };
                if self.clock.saturating_sub(since) >= threshold {
                    starved[found] = thread;
                    found += 1;
                    if found == STARVATION_BOOSTS {
                        break 'scan;
                    }
                }
            }
        }
        let mut preempt = false;
        for &thread in &starved[..found] {
            // SAFETY: un thread prêt de ces files, valide ; retiré de sa file
            // avant de changer de priorité.
            unsafe {
                self.unready(thread);
                (*thread).priority = LOW_REALTIME_PRIORITY - 1;
                (*thread).quantum = 2 * QUANTUM;
                (*thread).starvation_boost = true;
                preempt |= self.ready(thread, false);
            }
        }
        preempt
    }
}

/// Fin du quantum d'un thread qui n'est dans aucune file : quantum neuf, et sa
/// priorité perd un niveau ([`decay`]), ou revient à sa base après un
/// relèvement contre la famine.
///
/// # Safety
/// `thread` est valide et n'est dans aucune file.
unsafe fn end_quantum(thread: *mut Thread) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        (*thread).quantum = QUANTUM;
        let base = (*thread).base_priority;
        (*thread).priority = if (*thread).starvation_boost { base } else { decay(base, (*thread).priority) };
        (*thread).starvation_boost = false;
    }
}

/// Priorité courante d'un thread réveillé par un signal de relèvement
/// `increment` : sa base plus `increment` pour une priorité variable, bornée à
/// 15, si c'est plus que sa priorité `current` ; un thread temps réel garde la
/// sienne.
pub fn wait_boost(base: u8, current: u8, increment: u8) -> u8 {
    if base >= LOW_REALTIME_PRIORITY {
        return current;
    }
    let boosted = base.saturating_add(increment).min(LOW_REALTIME_PRIORITY - 1);
    current.max(boosted)
}

/// Priorité courante à la fin d'un quantum : un niveau de moins, jusqu'à la base.
pub fn decay(base: u8, current: u8) -> u8 {
    current.saturating_sub(1).max(base)
}

/// Priorité d'un thread que tient l'ordonnanceur (valide).
fn priority(thread: *mut Thread) -> u8 {
    // SAFETY: l'ordonnanceur ne tient que des threads valides.
    unsafe { (*thread).priority }
}

// ── Ordonnanceur du noyau ────────────────────────────────────────────────────

/// La table des threads du noyau, sous le verrou dispatcher.
struct ThreadTableCell(UnsafeCell<ThreadTable>);

// SAFETY: la table n'est touchée que verrou dispatcher tenu (voir `threads`).
unsafe impl Sync for ThreadTableCell {}

static THREADS: ThreadTableCell = ThreadTableCell(UnsafeCell::new(ThreadTable::new()));

/// La table des threads, le temps d'un appel de méthode.
///
/// # Safety
/// Verrou dispatcher tenu.
unsafe fn threads() -> *mut ThreadTable {
    THREADS.0.get()
}

/// L'ordonnancement du processeur courant, dans son KPRCB.
///
/// # Safety
/// Verrou dispatcher tenu (voir `KPrcb::scheduler`).
unsafe fn sched() -> *mut Scheduler {
    // SAFETY: garanti par l'appelant.
    unsafe { prcb::current().scheduler() }
}

/// Le thread courant de ce processeur. Seule une commutation le change ; lu
/// sans verrou.
fn current_thread() -> *mut Thread {
    prcb::current().current_thread.load(Ordering::Relaxed)
}

/// TID du thread courant, sans verrou ni assertion (écran d'erreur fatale) ;
/// `None` avant `ke::init` ou sans thread courant.
///
/// # IRQL
/// Tout niveau.
pub(crate) fn try_current_tid() -> Option<usize> {
    let thread = prcb::try_current()?.current_thread.load(Ordering::Relaxed);
    // SAFETY: le thread courant vit tant qu'il s'exécute, donc pendant cet appel.
    (!thread.is_null()).then(|| unsafe { (*thread).tid })
}

/// Commutations effectuées depuis le démarrage (statistiques, auto-tests).
static CONTEXT_SWITCHES: AtomicU64 = AtomicU64::new(0);

/// Nombre de commutations depuis le démarrage.
///
/// # IRQL
/// Tout niveau.
pub fn context_switches() -> u64 {
    CONTEXT_SWITCHES.load(Ordering::Relaxed)
}

/// Demande l'examen d'une commutation à la prochaine interruption DISPATCH :
/// aussitôt sous DISPATCH_LEVEL avec les interruptions actives, sinon quand
/// l'IRQL redescend.
///
/// # IRQL
/// Tout niveau, ISR comprise.
pub fn request_reschedule() {
    prcb::current().reschedule.store(true, Ordering::Release);
    hal::irql::request_dispatch();
}

/// Consomme une demande d'examen (`ke::dpc::ki_dispatch_interrupt`).
pub(crate) fn take_reschedule() -> bool {
    prcb::current().reschedule.swap(false, Ordering::AcqRel)
}

/// Partie ordonnancement de l'interruption d'horloge (`ke::clock`) : un tick à
/// imputer au quantum du thread courant.
///
/// # IRQL
/// Dans l'ISR d'horloge.
pub(crate) fn clock_tick() {
    prcb::current().clock_ticks.fetch_add(1, Ordering::Relaxed);
    request_reschedule();
}

/// Commute de `old` vers `new`, qui vient de devenir courant : relâche le verrou
/// dispatcher juste avant de changer de pile, en restant à DISPATCH_LEVEL.
/// Revient quand `old` est repris, à DISPATCH_LEVEL, verrou non tenu.
///
/// # Safety
/// Verrou dispatcher tenu, à DISPATCH_LEVEL ; `old` est le thread qui
/// s'exécute ; `new` est un autre thread enregistré.
unsafe fn switch_to(old: *mut Thread, new: *mut Thread) {
    // SAFETY: garanti par l'appelant ; à DISPATCH_LEVEL, rien d'autre ne
    // s'exécute sur ce CPU (ADR-015) entre le relâchement du verrou et la
    // commutation, faite interruptions masquées.
    unsafe {
        if (*new).user_mode {
            // Interrupts and system calls from user mode land on its own
            // kernel stack, so a system call can block or be preempted.
            hal::gdt::set_kernel_stack_top((*new).kernel_stack_top);
            hal::sysenter::set_entry_stack((*new).kernel_stack_top);
            hal::gdt::set_teb_base((*new).teb);
        }
        hal::pcr::current().set_teb((*new).teb);
        ki_request_pending_apcs(new);
        prcb::current().current_thread.store(new, Ordering::Relaxed);
        CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
        DISPATCHER_LOCK.unlock();
        x86_64::instructions::interrupts::without_interrupts(|| {
            // ADR-009 : l'état FPU suit chaque thread, sans commutation
            // paresseuse. Le noyau, compilé sans SSE, ne touche plus ces
            // registres d'ici la reprise de `new`.
            hal::fpu::save(ptr::addr_of_mut!((*old).fpu));
            hal::fpu::restore(ptr::addr_of!((*new).fpu));
            load_directory_table_base((*new).directory_table_base);
            context_switch_raw(ptr::addr_of_mut!((*old).ctx), ptr::addr_of!((*new).ctx))
        });
        // `old` est repris.
    }
}

/// Charge `directory` dans CR3 s'il n'y est pas déjà (changer CR3 vide le TLB
/// des pages non globales).
fn load_directory_table_base(directory: u64) {
    #[cfg(target_os = "none")]
    {
        use x86_64::registers::control::Cr3;
        let (frame, flags) = Cr3::read_raw();
        if frame.start_address().as_u64() != directory {
            let frame = x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(directory));
            // SAFETY: `directory` est la PML4 d'un espace vivant, dont la
            // moitié haute est celle du système : le code, les données et les
            // piles du noyau y restent projetés.
            unsafe { Cr3::write_raw(frame, flags) };
        }
    }
    #[cfg(not(target_os = "none"))]
    let _ = directory;
}

/// `thread` va s'exécuter sur ce processeur, qu'il reprenne ou démarre, avec
/// des APC noyau en attente : l'interruption APC, demandée pour ce
/// processeur, les livrera quand il passera sous APC_LEVEL. Un thread
/// utilisateur qui démarre passe en mode utilisateur sans redescendre par
/// `hal::irql::lower` : ses APC partent à la première interruption qui l'y
/// trouve.
///
/// # Safety
/// Verrou dispatcher tenu ; `thread` est valide et devient le thread courant
/// de ce processeur.
unsafe fn ki_request_pending_apcs(thread: *mut Thread) {
    // SAFETY: garanti par l'appelant.
    if unsafe { (*thread).tcb.kernel_apc_pending } {
        hal::irql::request_apc();
    }
}

/// La plateforme du dispatcher dans le noyau : cet ordonnanceur, la roue de
/// timers de `ke::timer` et l'IRQL de `hal::irql`.
pub struct KePlatform;

// SAFETY: chaque méthode respecte le contrat du trait : `ready_thread` met le
// thread en file, `swap_thread` relâche le verrou et ne revient qu'au thread
// repris, à son IRQL ; les timers sont ceux de `ke::timer`, qui tient
// `header.inserted`.
unsafe impl Platform for KePlatform {
    fn current_thread() -> *mut KThread {
        // `tcb` est le premier champ d'un `Thread` `#[repr(C)]`.
        current_thread().cast()
    }

    unsafe fn ready_thread(thread: *mut KThread, increment: u8) {
        let t = thread.cast::<Thread>();
        // SAFETY: verrou tenu ; tout `KThread` du noyau est le `tcb` d'un `Thread`
        // enregistré, qui attendait : il n'est dans aucune file.
        unsafe {
            if (*sched()).ready_unwaited(t, increment) {
                request_reschedule();
            }
        }
    }

    unsafe fn swap_thread(old_irql: Irql) -> NtStatus {
        let old = current_thread();
        // SAFETY: verrou tenu (contrat du trait) ; le thread courant attend, il
        // n'est donc dans aucune file : le suivant est un autre thread.
        unsafe {
            let next = (*sched()).select_next();
            switch_to(old, next);
        }
        hal::irql::lower(old_irql);
        // SAFETY: le thread repris est valide ; son statut a été fixé par qui l'a
        // réveillé.
        unsafe { (*old).tcb.wait_status }
    }

    unsafe fn insert_timer(timer: *mut KTimer, due_time: i64) -> bool {
        // SAFETY: contrat du trait.
        unsafe { crate::timer::ki_insert_timer(timer, due_time) }
    }

    unsafe fn cancel_timer(timer: *mut KTimer) {
        // SAFETY: contrat du trait.
        unsafe { crate::timer::ki_cancel_timer(timer) };
    }

    fn raise_irql(new: Irql) -> Irql {
        hal::irql::raise(new)
    }

    fn lower_irql(new: Irql) {
        hal::irql::lower(new)
    }

    fn request_apc_interrupt() {
        hal::irql::request_apc();
    }
}

/// Initialise l'ordonnanceur du processeur de démarrage : le code en cours
/// devient le thread de démarrage (TID 0, priorité normale), et le thread idle
/// (TID 1) est créé sur la pile `idle_stack_top` ; branche l'expiration des
/// timers. Le KPRCB de ce processeur est déjà enregistré (`ke::init`).
///
/// # Safety
/// `idle_stack_top` est le haut, aligné sur 16 octets, d'une pile noyau projetée
/// et réservée au thread idle pour toute la vie du système.
///
/// # IRQL
/// PASSIVE_LEVEL, interruptions masquées, une seule fois.
pub unsafe fn init(idle_stack_top: u64) {
    #[cfg(target_os = "none")]
    SYSTEM_DIRECTORY.store(x86_64::registers::control::Cr3::read_raw().0.start_address().as_u64(), Ordering::Relaxed);
    let boot = Thread::create(NORMAL_PRIORITY, KContext::default(), false, 0, None);
    let idle = Thread::create(
        IDLE_PRIORITY,
        KContext::initial(idle_stack_top, idle_thread_main as *const () as u64),
        false,
        0,
        None,
    );
    // SAFETY: rien d'autre n'utilise encore l'ordonnanceur ; verrou tenu de
    // acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let table = &mut *threads();
        assert!(table.get(0).is_null(), "scheduler initialised twice");
        table.register(boot).expect("thread table");
        table.register(idle).expect("thread table");
        (*sched()).start(boot, idle);
        prcb::current().current_thread.store(boot, Ordering::Relaxed);
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
    }
    crate::timer::init::<KePlatform>();
    log::info!("Ke scheduler: initialised (boot TID=0, idle TID=1, {} priorities)", PRIORITY_LEVELS);
}

/// Enregistre `t` et le rend prêt ; il préempte l'appelant à la libération du
/// verrou s'il est plus prioritaire. Son TID va dans `published`, s'il y en a
/// un, avant qu'il soit prêt : il peut s'exécuter, et finir, avant que
/// l'appelant reprenne. Libère `t` si la table est pleine.
///
/// # IRQL
/// PASSIVE_LEVEL.
fn start_thread(t: *mut Thread, published: Option<&AtomicUsize>) -> Option<usize> {
    // SAFETY: `t` est un thread neuf, valide pour toujours s'il est enregistré ;
    // verrou tenu de acquire à release.
    let tid = unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let tid = (*threads()).register(t);
        if let (Some(tid), Some(slot)) = (tid, published) {
            slot.store(tid, Ordering::Release);
        }
        if tid.is_some() && (*sched()).ready(t, false) {
            request_reschedule();
        }
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        tid
    };
    if tid.is_none() {
        // SAFETY: jamais enregistré : personne d'autre ne le connaît.
        drop(unsafe { Box::from_raw(t) });
    }
    tid
}

/// Crée un thread noyau qui exécute `routine(context)` à la priorité
/// `priority`, sur la pile `stack_top`, puis se termine. Son TID, ou `None` si
/// la table est pleine. S'il est plus prioritaire que l'appelant, il s'exécute
/// avant le retour.
///
/// # Safety
/// `stack_top` est le haut, aligné sur 16 octets, d'une pile noyau projetée,
/// réservée à ce thread et gardée pour toute sa vie ; `context` reste valide
/// tant que `routine` s'en sert.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub unsafe fn create_kernel_thread(
    stack_top: u64,
    priority: u8,
    routine: ThreadRoutine,
    context: *mut c_void,
) -> Option<usize> {
    // SAFETY: forwarded; l'espace du système vit toujours.
    unsafe { create_kernel_thread_in(SYSTEM_DIRECTORY.load(Ordering::Relaxed), stack_top, priority, routine, context) }
}

/// Comme [`create_kernel_thread`], dans l'espace d'adresses de base de
/// répertoire `directory_table_base` (un thread système dans un autre
/// processus).
///
/// # Safety
/// Comme [`create_kernel_thread`] ; l'espace reste vivant tant que le thread
/// s'exécute.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub unsafe fn create_kernel_thread_in(
    directory_table_base: u64,
    stack_top: u64,
    priority: u8,
    routine: ThreadRoutine,
    context: *mut c_void,
) -> Option<usize> {
    assert!((1..PRIORITY_LEVELS as u8).contains(&priority), "priority {priority} (0 is the idle thread's)");
    let ctx = KContext::initial(stack_top, ki_thread_startup as *const () as u64);
    let t = Thread::create(priority, ctx, false, 0, Some((routine, context)));
    // SAFETY: un thread neuf, encore inconnu de l'ordonnanceur.
    unsafe { (*t).directory_table_base = directory_table_base };
    start_thread(t, None)
}

/// L'espace d'adresses où se trouvait le thread courant avant
/// [`ke_stack_attach`], à rendre à [`ke_unstack_detach`].
#[must_use = "the thread stays attached until ke_unstack_detach"]
pub struct AttachedAddressSpace {
    previous: u64,
}

/// KeStackAttachProcess : le thread courant passe dans l'espace d'adresses de
/// base de répertoire `directory_table_base`, où une commutation le garde,
/// jusqu'à [`ke_unstack_detach`].
///
/// # Safety
/// L'espace reste vivant jusqu'au détachement.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_stack_attach(directory_table_base: u64) -> AttachedAddressSpace {
    AttachedAddressSpace { previous: set_current_directory(directory_table_base) }
}

/// KeUnstackDetachProcess : le thread courant revient dans l'espace d'avant
/// [`ke_stack_attach`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn ke_unstack_detach(attached: AttachedAddressSpace) {
    set_current_directory(attached.previous);
}

/// Le thread courant passe dans l'espace `directory` ; rend l'ancien.
fn set_current_directory(directory: u64) -> u64 {
    // SAFETY: verrou tenu de acquire à release ; le thread courant est valide.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let t = current_thread();
        let previous = (*t).directory_table_base;
        (*t).directory_table_base = directory;
        load_directory_table_base(directory);
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        previous
    }
}

/// Premier code d'un thread noyau, où arrive sa première commutation (verrou
/// relâché, DISPATCH_LEVEL, interruptions masquées).
extern "C" fn ki_thread_startup() -> ! {
    x86_64::instructions::interrupts::enable();
    // Ses APC en attente, demandés par la commutation, partent ici.
    hal::irql::lower(Irql::Passive);
    // SAFETY: le thread courant est valide ; `start` ne change plus après sa
    // création.
    let start = unsafe { (*current_thread()).start };
    let (routine, context) = start.expect("kernel thread without a start routine");
    routine(context);
    terminate_current_thread();
    unreachable!("a terminated thread was resumed");
}

/// Ce qu'il faut pour lancer un thread utilisateur ([`create_user_thread`]).
#[derive(Clone, Copy, Debug)]
pub struct UserThreadStart {
    /// CR3 de l'espace d'adresses de son processus.
    pub directory_table_base: u64,
    /// Haut, aligné sur 16 octets, de sa pile noyau.
    pub kernel_stack_top: u64,
    /// EIP de départ, en mode utilisateur 32 bits.
    pub entry: u32,
    /// ESP de départ.
    pub stack: u32,
    /// Son TEB : la base de FS en mode utilisateur.
    pub teb: u32,
    /// Le thread de l'exécutif qui le possède ([`current_thread_owner`]).
    pub owner: *const c_void,
    /// Où Ke écrit son TID avant qu'il soit prêt (`start_thread`), car le
    /// thread peut s'exécuter, et finir, avant que `create_user_thread`
    /// revienne ; nul si personne n'en a besoin (l'ancien chargeur).
    pub tid: *const AtomicUsize,
}

/// Enregistre un thread utilisateur (ring 3, 32 bits), prêt à s'exécuter dans
/// l'espace d'adresses `start.directory_table_base`.
///
/// Construit sur sa pile noyau la trame de `ring3_iretq_trampoline`, où arrive
/// sa première commutation :
///
/// ```text
///   [top-56]  adresse de reprise (écrite par la commutation)
///   [top-48]  sélecteur FS (TEB), dépilé dans RAX par le trampoline
///   [top-40]  EIP 32 bits  ┐
///   [top-32]  CS | 3       │
///   [top-24]  RFLAGS       ├─ trame d'IRETQ
///   [top-16]  ESP 32 bits  │
///   [top- 8]  SS | 3       ┘
/// ```
///
/// Chaque commutation vers lui pointe le descripteur du TEB sur `start.teb`
/// (`hal::gdt::set_teb_base`). La pile vient de Mm par l'appelant ; Ke n'en
/// alloue jamais. Son TID, ou `None` si la table est pleine.
///
/// # Safety
/// `start.kernel_stack_top` est le haut, aligné sur 16 octets, d'une pile
/// noyau projetée d'au moins 4 Kio, réservée à ce thread et gardée jusqu'à sa
/// fin ; l'espace d'adresses reste vivant tant que le thread s'exécute ;
/// `start.tid` est nul ou désigne un `AtomicUsize` valide jusqu'au retour.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub unsafe fn create_user_thread(start: &UserThreadStart) -> Option<usize> {
    let frame = (start.kernel_stack_top - 7 * 8) as *mut u64;
    // SAFETY: les 56 octets du haut de la pile, projetée, accessible en écriture
    // et réservée à ce thread (contrat).
    unsafe {
        frame.add(0).write(0);
        frame.add(1).write(u64::from(hal::gdt::user_teb_fs_selector()));
        frame.add(2).write(u64::from(start.entry));
        frame.add(3).write(u64::from(hal::gdt::user_code32_selector()) | 3);
        frame.add(4).write(hal::ring3::USER_RFLAGS);
        frame.add(5).write(u64::from(start.stack));
        frame.add(6).write(u64::from(hal::gdt::user_data32_selector()) | 3);
    }
    let ctx = KContext { rsp: frame as u64, rip: hal::ring3::ring3_iretq_trampoline_fn(), ..KContext::default() };
    let t = Thread::create(NORMAL_PRIORITY, ctx, true, start.kernel_stack_top, None);
    // SAFETY: un thread neuf, encore inconnu de l'ordonnanceur.
    unsafe {
        (*t).directory_table_base = start.directory_table_base;
        (*t).teb = start.teb;
        (*t).owner = start.owner;
    }
    // SAFETY: `start.tid`, s'il n'est pas nul, vaut pour toute la création
    // (contrat).
    let tid = start_thread(t, unsafe { start.tid.as_ref() })?;
    log::info!(
        "Ke scheduler: spawned user-mode thread TID={} entry={:#010x} usp={:#010x} teb={:#010x}",
        tid,
        start.entry,
        start.stack,
        start.teb,
    );
    Some(tid)
}

/// Le thread de l'exécutif qui possède le thread courant
/// ([`UserThreadStart::owner`]) ; nul pour un thread noyau.
///
/// # IRQL
/// Tout niveau.
pub fn current_thread_owner() -> *const c_void {
    // SAFETY: le thread courant vit tant qu'il s'exécute ; `owner` ne change
    // plus après sa création.
    unsafe { (*current_thread()).owner }
}

/// Supprime le thread `tid`, terminé : il quitte la table, qui pourra donner
/// son TID à un autre, et sa mémoire est rendue. Sa pile noyau revient à qui
/// l'a fournie. `false` s'il n'existe pas.
///
/// # Panics
/// S'il n'est pas terminé.
///
/// # Safety
/// Le thread a quitté le processeur après sa fin : sur ce processeur unique
/// (ADR-015), c'est le cas dès qu'un autre thread le voit terminé. Personne
/// n'attend plus son objet thread ni n'en garde l'adresse
/// ([`thread_object`]).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn delete_thread(tid: usize) -> bool {
    // SAFETY: verrou tenu de acquire à release ; un thread enregistré est valide.
    let t = unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let t = (*threads()).get(tid);
        let terminated = t.is_null() || (*t).tcb.state == ThreadState::Terminated;
        let t = if terminated { (*threads()).unregister(tid) } else { ptr::null_mut() };
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        assert!(terminated, "thread {tid} deleted before its end");
        t
    };
    if t.is_null() {
        return false;
    }
    // SAFETY: terminé, il n'est dans aucune file ni attente (`ki_thread_exit`),
    // ni sur le processeur (contrat) ; retiré de la table, plus rien ne le
    // désigne.
    drop(unsafe { Box::from_raw(t) });
    true
}

/// `true` si le thread `tid` existe et n'est pas terminé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn is_thread_running(tid: usize) -> bool {
    // SAFETY: verrou tenu de acquire à release ; les threads enregistrés sont
    // valides.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let t = (*threads()).get(tid);
        let running = !t.is_null() && (*t).tcb.state != ThreadState::Terminated;
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        running
    }
}

/// Priorité courante du thread `tid` (KeQueryPriorityThread), boost compris ;
/// `None` s'il n'existe pas.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn thread_priority(tid: usize) -> Option<u8> {
    // SAFETY: verrou tenu de acquire à release ; un thread enregistré est valide.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let t = (*threads()).get(tid);
        let priority = (!t.is_null()).then(|| (*t).priority);
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        priority
    }
}

/// Examine les files prêtes de ce processeur et relève les threads affamés
/// ([`Scheduler::scan_starved`]) ; appelé chaque seconde par le balance set
/// manager (`ke::balance`).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn ki_scan_ready_queues() {
    // SAFETY: verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        if (*sched()).scan_starved(STARVATION_TICKS) {
            request_reschedule();
        }
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
    }
}

/// Priorité courante du thread appelant, boost compris.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn current_priority() -> u8 {
    // SAFETY: verrou tenu de acquire à release ; le thread courant est valide.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let priority = (*current_thread()).priority;
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        priority
    }
}

/// L'objet thread de `tid`, à attendre pour connaître sa fin ; il reste valide
/// jusqu'à [`delete_thread`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn thread_object(tid: usize) -> Option<*mut DispatcherHeader> {
    // SAFETY: verrou tenu de acquire à release ; un thread enregistré est valide.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let t = (*threads()).get(tid);
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        (!t.is_null()).then(|| ptr::addr_of_mut!((*t).tcb.header))
    }
}

/// Le `KThread` de `tid`, pour lui envoyer un APC ; il reste valide jusqu'à
/// [`delete_thread`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn kernel_thread(tid: usize) -> Option<*mut KThread> {
    // SAFETY: verrou tenu de acquire à release ; un thread enregistré est valide.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let t = (*threads()).get(tid);
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
        (!t.is_null()).then(|| ptr::addr_of_mut!((*t).tcb))
    }
}

/// Termine tous les threads utilisateur, sauf le thread courant : le shell du
/// noyau prend la console.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn terminate_user_threads() {
    // SAFETY: verrou tenu de acquire à release ; les threads enregistrés sont
    // valides.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let current = current_thread();
        for tid in 0..MAX_THREADS {
            let t = (*threads()).get(tid);
            if t.is_null() || t == current || !(*t).user_mode || (*t).tcb.state == ThreadState::Terminated {
                continue;
            }
            if (*t).tcb.state == ThreadState::Ready {
                (*sched()).unready(t);
            }
            ki_thread_exit::<KePlatform>(ptr::addr_of_mut!((*t).tcb));
        }
        DISPATCHER_LOCK.release::<KePlatform>(old_irql);
    }
}

/// Termine le thread courant : objet thread signalé, mutants abandonnés, puis
/// commutation vers le suivant. Ne revient pas, sauf avant `init`.
///
/// Appelé par `NtTerminateProcess`/`NtTerminateThread` et par le gestionnaire
/// des fautes en mode utilisateur, interruptions masquées.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn terminate_current_thread() {
    if hal::pcr::current().prcb().is_null() {
        return;
    }
    let current = current_thread();
    // SAFETY: le verrou, pris ici, est relâché par la commutation ; le thread
    // courant est valide et, terminé, n'est dans aucune file : le suivant est un
    // autre thread.
    unsafe {
        DISPATCHER_LOCK.acquire::<KePlatform>();
        assert!(current != (*sched()).idle, "the idle thread cannot end");
        ki_thread_exit::<KePlatform>(ptr::addr_of_mut!((*current).tcb));
        let next = (*sched()).select_next();
        switch_to(current, next);
    }
    unreachable!("a terminated thread was resumed");
}

/// Interruption DISPATCH (`ke::dpc::ki_dispatch_interrupt`) : impute les ticks
/// au quantum, puis commute si un thread plus prioritaire est prêt, ou à la fin
/// du quantum si un thread de même priorité l'est.
///
/// # IRQL
/// DISPATCH_LEVEL, interruptions masquées.
pub fn schedule() {
    let old = current_thread();
    let ticks = prcb::current().clock_ticks.swap(0, Ordering::Relaxed);
    // SAFETY: l'interruption DISPATCH ne s'exécute que si le code interrompu
    // était sous DISPATCH_LEVEL : il ne tient pas le verrou. Verrou tenu jusqu'à
    // la commutation, qui le relâche, ou jusqu'au release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        match (*sched()).dispatch(ticks) {
            Some(next) => switch_to(old, next),
            None => DISPATCHER_LOCK.release::<KePlatform>(old_irql),
        }
    }
}

/// Le thread idle, à priorité 0, quand aucun autre n'est prêt. Sa première
/// commutation l'amène ici verrou relâché, à DISPATCH_LEVEL, interruptions
/// masquées.
extern "C" fn idle_thread_main() -> ! {
    x86_64::instructions::interrupts::enable();
    hal::irql::lower(Irql::Passive);
    loop {
        x86_64::instructions::hlt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Thread factice pour les files : jamais déréférencé.
    fn fake(n: usize) -> *mut Thread {
        ptr::without_provenance_mut(n)
    }

    // ── ReadyQueue ───────────────────────────────────────────────────────────

    #[test]
    fn ready_queue_push_pop_fifo_order() {
        let mut q = ReadyQueue::new();
        assert!(q.is_empty());
        q.push(fake(10));
        q.push(fake(20));
        q.push(fake(30));
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop(), Some(fake(10)));
        assert_eq!(q.pop(), Some(fake(20)));
        assert_eq!(q.pop(), Some(fake(30)));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn ready_queue_wraps_around_and_refuses_overflow() {
        let mut q = ReadyQueue::new();
        for i in 0..MAX_THREADS {
            assert!(q.push(fake(i)));
        }
        assert!(q.is_full());
        assert!(!q.push(fake(99)));
        assert!(!q.push_front(fake(99)));
        for _ in 0..MAX_THREADS / 2 {
            q.pop();
        }
        for i in 0..MAX_THREADS / 2 {
            assert!(q.push(fake(100 + i)));
        }
        assert_eq!(q.len(), MAX_THREADS);
        assert_eq!(q.pop(), Some(fake(MAX_THREADS / 2)));
    }

    #[test]
    fn ready_queue_push_front_goes_first() {
        let mut q = ReadyQueue::new();
        q.push(fake(1));
        q.push(fake(2));
        q.push_front(fake(0));
        assert_eq!([q.pop(), q.pop(), q.pop()], [Some(fake(0)), Some(fake(1)), Some(fake(2))]);
    }

    #[test]
    fn ready_queue_remove_keeps_the_order_of_the_others() {
        let mut q = ReadyQueue::new();
        for _ in 0..MAX_THREADS - 2 {
            q.push(fake(9));
            q.pop();
        }
        for n in 1..=5 {
            q.push(fake(n));
        }
        assert!(q.remove(fake(3)), "across the end of the ring");
        assert!(q.remove(fake(1)));
        assert!(q.remove(fake(5)));
        assert!(!q.remove(fake(5)));
        assert_eq!([q.pop(), q.pop(), q.pop()], [Some(fake(2)), Some(fake(4)), None]);
    }

    // ── ThreadTable ──────────────────────────────────────────────────────────

    fn thread(priority: u8) -> *mut Thread {
        Thread::create(priority, KContext::default(), false, 0, None)
    }

    #[test]
    fn an_unregistered_tid_goes_to_the_next_thread() {
        let mut table = Box::new(ThreadTable::new());
        let threads = [thread(1), thread(1), thread(1)];
        for &t in &threads {
            // SAFETY: libérés en fin de test.
            unsafe { table.register(t) }.unwrap();
        }
        assert_eq!(table.unregister(1), threads[1]);
        assert!(table.get(1).is_null());
        assert!(table.unregister(1).is_null(), "already gone");
        assert!(table.unregister(MAX_THREADS).is_null());
        let next = thread(1);
        // SAFETY: libéré en fin de test.
        assert_eq!(unsafe { table.register(next) }, Some(1));
        for t in [threads[0], threads[1], threads[2], next] {
            // SAFETY: threads du test, libérés une fois.
            drop(unsafe { Box::from_raw(t) });
        }
    }

    #[test]
    fn register_gives_the_first_free_tid_and_fails_when_full() {
        let mut table = Box::new(ThreadTable::new());
        for tid in 0..MAX_THREADS {
            let t = thread(1);
            // SAFETY: jamais libéré.
            assert_eq!(unsafe { table.register(t) }, Some(tid));
            assert_eq!(table.get(tid), t);
            // SAFETY: thread du test.
            assert_eq!(unsafe { (*t).tid }, tid);
        }
        let extra = thread(1);
        // SAFETY: refusé, donc libre ; libéré aussitôt.
        unsafe {
            assert!(table.register(extra).is_none());
            drop(Box::from_raw(extra));
        }
        assert!(table.get(MAX_THREADS).is_null());
    }

    // ── Scheduler ────────────────────────────────────────────────────────────

    /// Ordonnanceur d'un processeur : le thread de démarrage (priorité
    /// normale) courant, et idle.
    fn scheduler() -> (Box<Scheduler>, *mut Thread) {
        let mut s = Box::new(Scheduler::new());
        let boot = thread(NORMAL_PRIORITY);
        // SAFETY: threads du test, jamais libérés.
        unsafe { s.start(boot, thread(IDLE_PRIORITY)) };
        (s, boot)
    }

    fn ready(s: &mut Scheduler, t: *mut Thread, front: bool) -> bool {
        // SAFETY: thread du test, valide, ni courant ni en file.
        unsafe { s.ready(t, front) }
    }

    fn state(t: *mut Thread) -> ThreadState {
        // SAFETY: thread du test.
        unsafe { (*t).tcb.state }
    }

    #[test]
    fn a_higher_priority_thread_preempts_at_the_next_dispatch() {
        let (mut s, boot) = scheduler();
        let high = thread(NORMAL_PRIORITY + 1);
        assert!(ready(&mut s, high, false), "preempts the current thread");
        assert_eq!(s.dispatch(0), Some(high));
        assert_eq!(s.current, high);
        assert_eq!(state(high), ThreadState::Running);
        assert_eq!(state(boot), ThreadState::Ready, "the preempted thread is queued");
    }

    #[test]
    fn an_equal_priority_thread_waits_for_the_end_of_the_quantum() {
        let (mut s, boot) = scheduler();
        let peer = thread(NORMAL_PRIORITY);
        assert!(!ready(&mut s, peer, false));
        assert_eq!(s.dispatch(1), None, "one tick of the quantum left");
        assert_eq!(s.dispatch(1), Some(peer));
        assert_eq!(s.dispatch(2), Some(boot), "round robin");
    }

    #[test]
    fn a_lower_priority_thread_waits_while_a_higher_one_runs() {
        let (mut s, boot) = scheduler();
        let low = thread(NORMAL_PRIORITY - 1);
        assert!(!ready(&mut s, low, false));
        assert_eq!(s.dispatch(QUANTUM_TICKS * 3), None, "quantum over, but no peer");
        assert_eq!(s.current, boot);
        assert_eq!(s.select_next(), low, "it runs once the current thread waits");
    }

    #[test]
    fn a_preempted_thread_resumes_before_its_peers() {
        let (mut s, boot) = scheduler();
        let peer = thread(NORMAL_PRIORITY);
        let high = thread(NORMAL_PRIORITY + 1);
        ready(&mut s, peer, false);
        ready(&mut s, high, false);
        assert_eq!(s.dispatch(0), Some(high));
        assert_eq!(s.select_next(), boot, "back at the head of its queue, before its peer");
        assert_eq!(s.select_next(), peer);
    }

    #[test]
    fn a_thread_preempted_at_the_end_of_its_quantum_goes_after_its_peers() {
        let (mut s, boot) = scheduler();
        let peer = thread(NORMAL_PRIORITY);
        let high = thread(NORMAL_PRIORITY + 1);
        ready(&mut s, peer, false);
        ready(&mut s, high, false);
        assert_eq!(s.dispatch(QUANTUM_TICKS), Some(high));
        assert_eq!(s.select_next(), peer);
        assert_eq!(s.select_next(), boot);
    }

    #[test]
    fn idle_runs_when_nothing_is_ready_and_is_never_queued() {
        let (mut s, boot) = scheduler();
        assert_eq!(s.select_next(), s.idle, "the boot thread waits");
        assert_eq!(s.dispatch(5), None, "idle keeps the processor");
        assert_eq!(s.summary, 0);
        assert!(ready(&mut s, boot, false), "any ready thread preempts idle");
        assert_eq!(s.dispatch(0), Some(boot));
        assert_eq!(s.summary, 0, "idle was not queued");
        assert_eq!(state(boot), ThreadState::Running);
    }

    // ── Boosts ───────────────────────────────────────────────────────────────

    #[test]
    fn a_wait_boost_raises_from_the_base_up_to_fifteen() {
        assert_eq!(wait_boost(8, 8, 1), 9);
        assert_eq!(wait_boost(7, 7, 0), 7, "no increment, no boost");
        assert_eq!(wait_boost(12, 12, 6), 15, "variable priorities stay below real time");
        assert_eq!(wait_boost(4, 10, 2), 10, "a higher current priority is kept");
        assert_eq!(wait_boost(4, 5, 2), 6, "from the base, not from the current priority");
        assert_eq!(wait_boost(16, 16, 6), 16, "real-time threads are never boosted");
        assert_eq!(wait_boost(15, 15, 6), 15);
    }

    #[test]
    fn a_boost_decays_one_level_per_quantum_down_to_the_base() {
        assert_eq!(decay(7, 9), 8);
        assert_eq!(decay(7, 8), 7);
        assert_eq!(decay(7, 7), 7, "never below the base");
        assert_eq!(decay(0, 0), 0);
    }

    #[test]
    fn a_woken_thread_preempts_then_yields_as_its_boost_decays() {
        let (mut s, boot) = scheduler();
        let woken = thread(NORMAL_PRIORITY - 1);
        // SAFETY: thread du test, hors file.
        assert!(unsafe { s.ready_unwaited(woken, 2) }, "boosted above the boot thread");
        assert_eq!(s.dispatch(0), Some(woken));
        assert_eq!(s.dispatch(QUANTUM_TICKS), Some(boot), "one level down: a peer of the boot thread");
        assert_eq!(priority(woken), NORMAL_PRIORITY);
        assert_eq!(s.dispatch(QUANTUM_TICKS), Some(woken), "round robin at the decayed priority");
        assert_eq!(s.dispatch(QUANTUM_TICKS), Some(boot), "back at its base, below the boot thread");
        assert_eq!(priority(woken), NORMAL_PRIORITY - 1);
        assert_eq!(priority(boot), NORMAL_PRIORITY, "an unboosted thread keeps its priority");
    }

    fn quantum(t: *mut Thread) -> i32 {
        // SAFETY: thread du test.
        unsafe { (*t).quantum }
    }

    #[test]
    fn a_wake_that_raises_the_priority_gives_a_fresh_quantum() {
        let (mut s, _) = scheduler();
        let t = thread(NORMAL_PRIORITY - 1);
        // SAFETY: thread du test, hors file.
        unsafe {
            (*t).quantum = 1;
            s.ready_unwaited(t, 2);
        }
        assert_eq!((priority(t), quantum(t)), (NORMAL_PRIORITY + 1, QUANTUM));
    }

    #[test]
    fn a_thread_that_waits_often_still_ends_its_quantum_and_decays() {
        let (mut s, _) = scheduler();
        let t = thread(NORMAL_PRIORITY);
        // SAFETY: thread du test, retiré de sa file entre deux réveils.
        let wake = |s: &mut Scheduler| unsafe {
            s.ready_unwaited(t, 1);
            s.unready(t);
        };
        wake(&mut s);
        assert_eq!((priority(t), quantum(t)), (NORMAL_PRIORITY + 1, QUANTUM), "boosted, fresh quantum");
        for left in (1..QUANTUM).rev() {
            wake(&mut s);
            assert_eq!((priority(t), quantum(t)), (NORMAL_PRIORITY + 1, left), "each wait costs one unit");
        }
        wake(&mut s);
        assert_eq!((priority(t), quantum(t)), (NORMAL_PRIORITY, QUANTUM), "quantum over: one level down");
        wake(&mut s);
        assert_eq!(priority(t), NORMAL_PRIORITY + 1, "boosted again from its base");
    }

    #[test]
    fn a_real_time_thread_keeps_its_priority_when_woken() {
        let (mut s, _) = scheduler();
        let t = thread(LOW_REALTIME_PRIORITY + 2);
        // SAFETY: thread du test, hors file.
        unsafe { s.ready_unwaited(t, 6) };
        assert_eq!(priority(t), LOW_REALTIME_PRIORITY + 2);
    }

    // ── Famine ───────────────────────────────────────────────────────────────

    #[test]
    fn a_starved_thread_runs_at_fifteen_for_a_double_quantum_then_returns_to_its_base() {
        let (mut s, boot) = scheduler();
        let low = thread(4);
        ready(&mut s, low, false);
        assert_eq!(s.dispatch(STARVATION_TICKS as u32 - 1), None, "the boot thread keeps the processor");
        assert!(!s.scan_starved(STARVATION_TICKS), "not starved yet");
        assert_eq!(priority(low), 4);
        assert_eq!(s.dispatch(1), None);
        assert!(s.scan_starved(STARVATION_TICKS), "starved: raised above the boot thread");
        assert_eq!(priority(low), LOW_REALTIME_PRIORITY - 1);
        assert_eq!(s.dispatch(0), Some(low));
        assert_eq!(s.dispatch(2 * QUANTUM_TICKS - 1), None, "a double quantum");
        assert_eq!(s.dispatch(1), Some(boot), "back at its base once it is over");
        assert_eq!(priority(low), 4);
    }

    #[test]
    fn a_scan_raises_ten_variable_priority_threads_below_fifteen_at_most() {
        let (mut s, _) = scheduler();
        let lows: alloc::vec::Vec<_> = (0..STARVATION_BOOSTS + 2).map(|_| thread(3)).collect();
        let others = [thread(LOW_REALTIME_PRIORITY - 1), thread(LOW_REALTIME_PRIORITY)];
        for &t in lows.iter().chain(&others) {
            ready(&mut s, t, false);
        }
        s.clock = STARVATION_TICKS;
        s.scan_starved(STARVATION_TICKS);
        let raised = |lows: &[*mut Thread]| lows.iter().filter(|&&t| priority(t) == LOW_REALTIME_PRIORITY - 1).count();
        assert_eq!(raised(&lows), STARVATION_BOOSTS);
        assert_eq!(others.map(priority), [LOW_REALTIME_PRIORITY - 1, LOW_REALTIME_PRIORITY]);
        // SAFETY: threads du test.
        assert!(others.iter().all(|&t| !unsafe { (*t).starvation_boost }), "nothing to raise at 15 and above");
        s.clock += STARVATION_TICKS;
        s.scan_starved(STARVATION_TICKS);
        assert_eq!(raised(&lows), lows.len(), "the rest at the next scan");
    }

    #[test]
    fn a_starved_thread_that_waits_loses_its_raise() {
        let (mut s, _) = scheduler();
        let low = thread(4);
        ready(&mut s, low, false);
        s.clock = STARVATION_TICKS;
        s.scan_starved(STARVATION_TICKS);
        // SAFETY: thread du test : il s'exécute, attend, puis est réveillé.
        unsafe {
            s.unready(low);
            s.ready_unwaited(low, 1);
        }
        assert_eq!((priority(low), quantum(low)), (5, QUANTUM), "its base plus the wake's increment");
    }

    #[test]
    fn a_boosted_thread_alone_still_decays() {
        let (mut s, boot) = scheduler();
        // SAFETY: thread courant du test, hors file.
        unsafe { (*boot).priority = NORMAL_PRIORITY + 2 };
        assert_eq!(s.dispatch(QUANTUM_TICKS), None, "nothing else is ready");
        assert_eq!(priority(boot), NORMAL_PRIORITY + 1);
    }

    #[test]
    fn unready_removes_a_thread_and_clears_its_priority() {
        let (mut s, _) = scheduler();
        let a = thread(4);
        let b = thread(4);
        ready(&mut s, a, false);
        ready(&mut s, b, false);
        // SAFETY: threads du test.
        unsafe { s.unready(a) };
        assert_eq!(s.highest(), Some(4));
        // SAFETY: comme ci-dessus.
        unsafe { s.unready(b) };
        assert_eq!(s.highest(), None);
        assert_eq!(s.select_next(), s.idle);
    }
}
