//! Ordonnanceur (M1, 02 §Ke) : 32 priorités, quantum, attente, préemption.
//!
//! Un thread est un [`Thread`] : la tranche dispatcher (`dispatcher::KThread`) en
//! tête, puis son contexte de commutation, sa priorité, son quantum et son état
//! FPU (ADR-009). La table des threads ([`ThreadTable`], TID → thread) est
//! commune aux processeurs ; l'ordonnancement ([`Scheduler`]) est propre à
//! chacun et vit dans son KPRCB (`ke::prcb`, ADR-015). Les threads prêts d'un
//! processeur attendent dans une file par priorité (anneau, [`ReadyQueue`]) ; un
//! bitmap résume les files non vides. Le thread idle n'est dans aucune file : il
//! tourne quand aucun autre n'est prêt.
//!
//! - Préemption : un thread qui devient prêt avec une priorité supérieure à celle
//!   du thread courant le préempte à la prochaine interruption DISPATCH ; le
//!   préempté repasse en tête de sa file, avec le reste de son quantum.
//! - Quantum : deux ticks d'horloge. À son terme, le thread cède la place aux
//!   threads prêts de même priorité et repasse en queue de sa file.
//! - Attente : le dispatcher (`Platform::swap_thread`) bascule vers le thread prêt
//!   le plus prioritaire, ou vers idle.
//!
//! Table et ordonnancement sont protégés par le verrou dispatcher (ADR-005). Une
//! commutation relâche ce verrou juste avant de changer de pile, en restant à
//! DISPATCH_LEVEL : sur un seul CPU (ADR-015), rien de ce qui touche à cet état ne
//! peut s'exécuter entre-temps. Le thread repris rabaisse lui-même son IRQL.
//!
//! Pas encore : boosts de priorité, changement de priorité, récupération des
//! threads terminés (leur objet et leur pile restent alloués).
//!
//! [`KePlatform`] relie le dispatcher, les timers et l'IRQL à cet ordonnanceur.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

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

/// Durée d'un quantum, en ticks d'horloge.
const QUANTUM_TICKS: i32 = 2;

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
    priority: u8,
    /// Ticks d'horloge restants du quantum.
    quantum: i32,
    /// Thread utilisateur : TSS.RSP0 doit pointer sur sa pile noyau.
    user_mode: bool,
    kernel_stack_top: u64,
    /// Routine d'un thread noyau, lancée par [`ki_thread_startup`].
    start: Option<(ThreadRoutine, *mut c_void)>,
    /// État x87/SSE, sauvegardé et restauré à chaque commutation (ADR-009).
    fpu: FxSaveArea,
}

impl Thread {
    /// Alloue un thread et l'initialise ; il n'est jamais libéré (les threads ne
    /// sont pas encore récupérés).
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
            ptr::addr_of_mut!((*t).priority).write(priority);
            ptr::addr_of_mut!((*t).quantum).write(QUANTUM_TICKS);
            ptr::addr_of_mut!((*t).user_mode).write(user_mode);
            ptr::addr_of_mut!((*t).kernel_stack_top).write(kernel_stack_top);
            ptr::addr_of_mut!((*t).start).write(start);
            ptr::addr_of_mut!((*t).fpu).write(FxSaveArea::initial());
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
            (*thread).priority
        };
        let queue = &mut self.ready[usize::from(p)];
        let queued = if front { queue.push_front(thread) } else { queue.push(thread) };
        assert!(queued, "ready queue overflow: a thread is queued twice");
        self.summary |= 1 << p;
        self.current == self.idle || p > priority(self.current)
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
        let cur = self.current;
        if cur == self.idle {
            let next = self.pop_highest()?;
            return Some(self.make_current(next));
        }
        // SAFETY: l'ordonnanceur ne tient que des threads valides.
        let expired = unsafe {
            (*cur).quantum = (*cur).quantum.saturating_sub(ticks as i32);
            let expired = (*cur).quantum <= 0;
            if expired {
                (*cur).quantum = QUANTUM_TICKS;
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
            hal::gdt::set_kernel_stack_top((*new).kernel_stack_top);
        }
        prcb::current().current_thread.store(new, Ordering::Relaxed);
        CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
        DISPATCHER_LOCK.unlock();
        x86_64::instructions::interrupts::without_interrupts(|| {
            // ADR-009 : l'état FPU suit chaque thread, sans commutation
            // paresseuse. Le noyau, compilé sans SSE, ne touche plus ces
            // registres d'ici la reprise de `new`.
            hal::fpu::save(ptr::addr_of_mut!((*old).fpu));
            hal::fpu::restore(ptr::addr_of!((*new).fpu));
            context_switch_raw(ptr::addr_of_mut!((*old).ctx), ptr::addr_of!((*new).ctx))
        });
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

    unsafe fn ready_thread(thread: *mut KThread) {
        let t = thread.cast::<Thread>();
        // SAFETY: verrou tenu ; tout `KThread` du noyau est le `tcb` d'un `Thread`
        // enregistré.
        unsafe {
            (*t).quantum = QUANTUM_TICKS;
            if (*sched()).ready(t, false) {
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
/// verrou s'il est plus prioritaire. Libère `t` si la table est pleine.
///
/// # IRQL
/// PASSIVE_LEVEL.
fn start_thread(t: *mut Thread) -> Option<usize> {
    // SAFETY: `t` est un thread neuf, valide pour toujours s'il est enregistré ;
    // verrou tenu de acquire à release.
    let tid = unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<KePlatform>();
        let tid = (*threads()).register(t);
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
    assert!((1..PRIORITY_LEVELS as u8).contains(&priority), "priority {priority} (0 is the idle thread's)");
    let ctx = KContext::initial(stack_top, ki_thread_startup as *const () as u64);
    start_thread(Thread::create(priority, ctx, false, 0, Some((routine, context))))
}

/// Premier code d'un thread noyau, où arrive sa première commutation (verrou
/// relâché, DISPATCH_LEVEL, interruptions masquées).
extern "C" fn ki_thread_startup() -> ! {
    x86_64::instructions::interrupts::enable();
    hal::irql::lower(Irql::Passive);
    // SAFETY: le thread courant est valide ; `start` ne change plus après sa
    // création.
    let start = unsafe { (*current_thread()).start };
    let (routine, context) = start.expect("kernel thread without a start routine");
    routine(context);
    terminate_current_thread();
    unreachable!("a terminated thread was resumed");
}

/// Enregistre un thread utilisateur (ring 3), prêt à s'exécuter.
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
/// La pile vient de Mm par l'appelant ; Ke n'en alloue jamais. Son TID, ou
/// `None` si la table est pleine.
///
/// # Safety
/// `kernel_stack_top` est le haut, aligné sur 16 octets, d'une pile noyau
/// projetée d'au moins 4 Kio, réservée à ce thread et gardée pour toute sa vie.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub unsafe fn spawn_user_thread(
    kernel_stack_top: u64,
    entry32: u32,
    stack32: u32,
    cs: u16,
    ss: u16,
    fs: u16,
) -> Option<usize> {
    let frame = (kernel_stack_top - 7 * 8) as *mut u64;
    // SAFETY: les 56 octets du haut de la pile, projetée, accessible en écriture
    // et réservée à ce thread (contrat).
    unsafe {
        frame.add(0).write(0);
        frame.add(1).write(u64::from(fs));
        frame.add(2).write(u64::from(entry32));
        frame.add(3).write(u64::from(cs) | 3);
        frame.add(4).write(hal::ring3::USER_RFLAGS);
        frame.add(5).write(u64::from(stack32));
        frame.add(6).write(u64::from(ss) | 3);
    }
    let ctx = KContext { rsp: frame as u64, rip: hal::ring3::ring3_iretq_trampoline_fn(), ..KContext::default() };
    let tid = start_thread(Thread::create(NORMAL_PRIORITY, ctx, true, kernel_stack_top, None))?;
    log::info!(
        "Ke scheduler: spawned user-mode thread TID={} entry={:#010x} usp={:#010x} kstack_top={:#x}",
        tid,
        entry32,
        stack32,
        kernel_stack_top,
    );
    Some(tid)
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

/// L'objet thread de `tid`, à attendre pour connaître sa fin ; il reste valide
/// (les threads ne sont jamais libérés).
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
        assert_eq!(s.dispatch(QUANTUM_TICKS as u32 * 3), None, "quantum over, but no peer");
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
        assert_eq!(s.dispatch(QUANTUM_TICKS as u32), Some(high));
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
