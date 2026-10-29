//! Tests hôte du dispatcher (critère de sortie de M1, 05).
//!
//! `Sim` simule l'ordonnanceur et l'IRQL ; ses timers sont ceux de la vraie roue
//! (`ke::timer`), à une heure figée que les tests avancent. Un thread ne se bloque que
//! dans `Sim::swap_thread` : il relâche le verrou, exécute l'action suivante de la
//! file (les autres threads : signaler, livrer un APC, faire expirer un timer, ou
//! attendre à leur tour), puis exige que le thread ait été réveillé. Une action qui
//! attend consomme l'action suivante : plusieurs threads peuvent ainsi attendre en
//! même temps.

extern crate std;

use core::ffi::c_void;
use std::boxed::Box;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::vec::Vec;

use super::*;
use crate::timer::{
    deadline, ke_cancel_timer, ke_initialize_timer, ke_read_state_timer, ke_set_timer, ki_expire_timers, TimerTable,
};

struct Sim;

/// Heure système simulée (format NT, unités de 100 ns).
const NOW: i64 = 1_000_000;

type Action = Box<dyn FnOnce()>;

std::thread_local! {
    static CURRENT: Cell<*mut KThread> = const { Cell::new(ptr::null_mut()) };
    static IRQL: Cell<Irql> = const { Cell::new(Irql::Passive) };
    static ACTIONS: RefCell<VecDeque<Action>> = RefCell::new(VecDeque::new());
    static READIED: RefCell<Vec<*mut KThread>> = const { RefCell::new(Vec::new()) };
    static TABLE: Cell<*const TimerTable> = const { Cell::new(ptr::null()) };
}

// SAFETY: chaque méthode respecte le contrat du trait ; swap_thread relâche le
// verrou et ne rend la main qu'au thread réveillé.
unsafe impl Platform for Sim {
    fn current_thread() -> *mut KThread {
        CURRENT.get()
    }

    unsafe fn ready_thread(thread: *mut KThread) {
        READIED.with_borrow_mut(|r| r.push(thread));
    }

    unsafe fn swap_thread(old_irql: Irql) -> NtStatus {
        let me = CURRENT.get();
        // SAFETY: verrou tenu par l'appelant, pris depuis `old_irql`.
        unsafe { DISPATCHER_LOCK.release::<Sim>(old_irql) };
        let action = ACTIONS
            .with_borrow_mut(|a| a.pop_front())
            .expect("the thread blocks and no other thread can run: deadlock");
        action();
        CURRENT.set(me);
        // SAFETY: `me` est un thread du test, valide.
        unsafe {
            assert_ne!((*me).state, ThreadState::Waiting, "lost wake-up: still waiting once the others ran");
            (*me).state = ThreadState::Running;
            (*me).wait_status
        }
    }

    unsafe fn insert_timer(timer: *mut KTimer, due_time: i64) -> bool {
        let now = NOW as u64;
        // SAFETY: verrou tenu, `timer` valide (contrat du trait).
        unsafe { table().insert(timer, deadline(due_time, now, now), || now) }
    }

    unsafe fn cancel_timer(timer: *mut KTimer) {
        // SAFETY: verrou tenu, `timer` valide (contrat du trait).
        unsafe { table().remove(timer) };
    }

    fn raise_irql(new: Irql) -> Irql {
        let old = IRQL.replace(new);
        assert!(new >= old, "raise from {old:?} to {new:?}");
        old
    }

    fn lower_irql(new: Irql) {
        assert!(new <= IRQL.get(), "lower from {:?} to {new:?}", IRQL.get());
        IRQL.set(new);
    }
}

// ── Outils ───────────────────────────────────────────────────────────────────

/// Alloue un objet du dispatcher et l'initialise en place. Les tests ne le
/// libèrent pas : le dispatcher garde des pointeurs bruts vers lui.
fn alloc<T>(init: impl FnOnce(*mut T)) -> *mut T {
    let mut b = Box::<T>::new_uninit();
    init(b.as_mut_ptr());
    // SAFETY: `init` a écrit chaque champ.
    Box::into_raw(unsafe { b.assume_init() })
}

fn new_thread() -> *mut KThread {
    // SAFETY: mémoire fraîche, adresse stable (jamais libérée).
    alloc(|t| unsafe { KThread::init(t) })
}

fn event(kind: ObjectType, signaled: bool) -> *mut KEvent {
    // SAFETY: mémoire fraîche, adresse stable.
    alloc(|e| unsafe { ke_initialize_event(e, kind, signaled) })
}

fn semaphore(count: i32, limit: i32) -> *mut KSemaphore {
    // SAFETY: mémoire fraîche, adresse stable.
    alloc(|s| unsafe { ke_initialize_semaphore(s, count, limit) })
}

fn mutant() -> *mut KMutant {
    // SAFETY: mémoire fraîche, adresse stable.
    alloc(|m| unsafe { ke_initialize_mutant(m) })
}

fn timer(kind: ObjectType) -> *mut KTimer {
    // SAFETY: mémoire fraîche, adresse stable.
    alloc(|t| unsafe { ke_initialize_timer(t, kind) })
}

/// La roue de timers du thread de test.
fn table() -> &'static TimerTable {
    // SAFETY: posée par `setup`, jamais libérée.
    unsafe { &*TABLE.get() }
}

/// Le DPC d'expiration s'exécute à l'heure `now`.
fn expire_at(now: i64) {
    // SAFETY: verrou tenu par `locked` ; la roue est celle de `Sim::insert_timer`.
    locked(|| unsafe { ki_expire_timers::<Sim>(table(), || now as u64) });
}

fn armed(t: *mut KTimer) -> bool {
    // SAFETY: timer initialisé du test.
    unsafe { (*t).header.inserted != 0 }
}

/// En-tête d'un objet : premier champ de chaque objet `#[repr(C)]`.
fn hdr<T>(obj: *mut T) -> *mut DispatcherHeader {
    obj.cast()
}

/// Thread courant pour le dispatcher (le « CPU » exécute ce thread).
fn run_as(t: *mut KThread) {
    CURRENT.set(t);
}

/// Ce que feront les autres threads la prochaine fois qu'un thread se bloque.
fn then(action: impl FnOnce() + 'static) {
    ACTIONS.with_borrow_mut(|a| a.push_back(Box::new(action)));
}

/// État simulé neuf, et un thread courant.
fn setup() -> *mut KThread {
    ACTIONS.with_borrow_mut(VecDeque::clear);
    READIED.with_borrow_mut(Vec::clear);
    TABLE.set(Box::leak(Box::new(TimerTable::new())));
    IRQL.set(Irql::Passive);
    let t = new_thread();
    run_as(t);
    t
}

/// Chaque action prévue a servi ; l'IRQL est revenu à PASSIVE_LEVEL.
fn finish() {
    assert!(ACTIONS.with_borrow(VecDeque::is_empty), "an expected wait did not block");
    assert_eq!(IRQL.get(), Irql::Passive);
}

/// Exécute `f` verrou tenu, comme le code noyau qui signale depuis un DPC.
fn locked(f: impl FnOnce()) {
    // SAFETY: le verrou n'est jamais tenu pendant une action.
    let irql = unsafe { DISPATCHER_LOCK.acquire::<Sim>() };
    f();
    // SAFETY: pris juste au-dessus.
    unsafe { DISPATCHER_LOCK.release::<Sim>(irql) };
}

fn no_waiter(obj: *mut DispatcherHeader) -> bool {
    // SAFETY: objet initialisé du test.
    unsafe { ListEntry::is_empty(ptr::addr_of!((*obj).wait_list_head)) }
}

fn wait_one(obj: *mut DispatcherHeader, timeout: Option<i64>) -> NtStatus {
    // SAFETY: objet initialisé, thread courant initialisé.
    unsafe { ke_wait_for_single_object::<Sim>(obj, ProcessorMode::Kernel, false, timeout) }
}

fn wait_many(objects: &[*mut DispatcherHeader], wait_type: WaitType) -> NtStatus {
    // SAFETY: objets initialisés, thread courant initialisé.
    unsafe { ke_wait_for_multiple_objects::<Sim>(objects, wait_type, ProcessorMode::Kernel, false, None, None) }
}

fn set(e: *mut KEvent) {
    // SAFETY: événement initialisé.
    unsafe { ke_set_event::<Sim>(e) };
}

fn signal_state<T>(obj: *mut T) -> i32 {
    // SAFETY: objet initialisé du test.
    unsafe { (*hdr(obj)).signal_state }
}

fn state(t: *mut KThread) -> ThreadState {
    // SAFETY: thread initialisé du test.
    unsafe { (*t).state }
}

// ── WaitAny, WaitAll ─────────────────────────────────────────────────────────

#[test]
fn wait_any_on_a_signaled_object_returns_its_index_without_blocking() {
    setup();
    let e0 = event(ObjectType::SynchronizationEvent, false);
    let e1 = event(ObjectType::SynchronizationEvent, true);
    assert_eq!(wait_many(&[hdr(e0), hdr(e1)], WaitType::WaitAny), NtStatus::wait(1));
    assert_eq!(signal_state(e1), 0, "a synchronization event is consumed");
    finish();
}

#[test]
fn wait_any_blocks_until_one_object_is_signaled() {
    let t = setup();
    let e0 = event(ObjectType::NotificationEvent, false);
    let e1 = event(ObjectType::NotificationEvent, false);
    then(move || set(e1));
    assert_eq!(wait_many(&[hdr(e0), hdr(e1)], WaitType::WaitAny), NtStatus::wait(1));
    assert!(no_waiter(hdr(e0)) && no_waiter(hdr(e1)), "every wait block is unlinked");
    assert_eq!(READIED.with_borrow(Vec::clone), [t]);
    finish();
}

#[test]
fn wait_all_partly_satisfied_keeps_waiting_and_consumes_nothing() {
    let t = setup();
    let e0 = event(ObjectType::SynchronizationEvent, false);
    let e1 = event(ObjectType::SynchronizationEvent, false);
    then(move || {
        set(e0);
        assert_eq!(state(t), ThreadState::Waiting, "one object of two: still waiting");
        assert_eq!(signal_state(e0), 1, "nothing is consumed until every object is signaled");
        set(e1);
    });
    assert_eq!(wait_many(&[hdr(e0), hdr(e1)], WaitType::WaitAll), STATUS_WAIT_0);
    assert_eq!((signal_state(e0), signal_state(e1)), (0, 0), "both consumed together");
    finish();
}

#[test]
fn wait_on_more_than_three_objects_uses_the_callers_wait_blocks() {
    setup();
    let events: Vec<_> = (0..5).map(|_| event(ObjectType::NotificationEvent, false)).collect();
    let objects: Vec<_> = events.iter().map(|&e| hdr(e)).collect();
    let all = events.clone();
    then(move || all.iter().for_each(|&e| set(e)));
    let mut blocks: Vec<WaitBlock> = (0..5).map(|_| WaitBlock::new()).collect();
    // SAFETY: objets et thread initialisés ; `blocks` vit pendant l'attente.
    let status = unsafe {
        ke_wait_for_multiple_objects::<Sim>(
            &objects,
            WaitType::WaitAll,
            ProcessorMode::Kernel,
            false,
            None,
            Some(&mut blocks),
        )
    };
    assert_eq!(status, STATUS_WAIT_0);
    assert!(objects.iter().all(|&o| no_waiter(o)));
    finish();
}

// ── Événements, sémaphores ───────────────────────────────────────────────────

#[test]
fn notification_event_wakes_every_waiter() {
    let a = setup();
    let b = new_thread();
    let e = event(ObjectType::NotificationEvent, false);
    then(move || {
        // b attend aussi pendant que a est bloqué.
        run_as(b);
        then(move || set(e));
        assert_eq!(wait_one(hdr(e), None), STATUS_WAIT_0);
    });
    assert_eq!(wait_one(hdr(e), None), STATUS_WAIT_0);
    assert_eq!(READIED.with_borrow(Vec::clone), [a, b], "woken in wait order");
    assert_eq!(signal_state(e), 1, "a notification event stays signaled");
    finish();
}

#[test]
fn synchronization_event_wakes_one_waiter_per_signal() {
    let a = setup();
    let b = new_thread();
    let e = event(ObjectType::SynchronizationEvent, false);
    then(move || {
        run_as(b);
        then(move || {
            set(e);
            assert_eq!(state(a), ThreadState::Ready, "the first waiter is woken");
            assert_eq!(state(b), ThreadState::Waiting, "one waiter per signal");
            assert_eq!(signal_state(e), 0, "auto-reset");
            set(e);
        });
        assert_eq!(wait_one(hdr(e), None), STATUS_WAIT_0);
    });
    assert_eq!(wait_one(hdr(e), None), STATUS_WAIT_0);
    finish();
}

#[test]
fn pulse_event_wakes_the_current_waiters_and_leaves_it_reset() {
    setup();
    let e = event(ObjectType::NotificationEvent, false);
    // SAFETY: événement initialisé.
    then(move || assert_eq!(unsafe { ke_pulse_event::<Sim>(e) }, 0));
    assert_eq!(wait_one(hdr(e), None), STATUS_WAIT_0);
    assert_eq!(signal_state(e), 0);
    finish();
}

#[test]
fn semaphore_release_wakes_as_many_waiters_as_its_adjustment() {
    setup();
    let b = new_thread();
    let s = semaphore(0, 2);
    then(move || {
        run_as(b);
        // SAFETY: sémaphore initialisé.
        then(move || assert_eq!(unsafe { ke_release_semaphore::<Sim>(s, 2) }, Ok(0)));
        assert_eq!(wait_one(hdr(s), None), STATUS_WAIT_0);
    });
    assert_eq!(wait_one(hdr(s), None), STATUS_WAIT_0);
    assert_eq!(signal_state(s), 0, "both units taken");
    finish();
}

#[test]
fn semaphore_release_beyond_its_limit_fails() {
    setup();
    let s = semaphore(1, 2);
    // SAFETY: sémaphore initialisé.
    unsafe {
        assert_eq!(ke_release_semaphore::<Sim>(s, 2), Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED));
        assert_eq!(ke_release_semaphore::<Sim>(s, 0), Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED));
        assert_eq!(ke_release_semaphore::<Sim>(s, i32::MAX), Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED));
        assert_eq!(ke_release_semaphore::<Sim>(s, 1), Ok(1));
    }
    assert_eq!(signal_state(s), 2);
    finish();
}

// ── Mutants ──────────────────────────────────────────────────────────────────

#[test]
fn mutant_is_recursive_for_its_owner() {
    let t = setup();
    let m = mutant();
    assert_eq!(wait_one(hdr(m), None), STATUS_WAIT_0);
    assert_eq!(wait_one(hdr(m), None), STATUS_WAIT_0, "the owner acquires it again");
    assert_eq!(signal_state(m), -1);
    // SAFETY: mutant et thread initialisés.
    unsafe {
        assert_eq!((*m).owner_thread, t);
        assert_eq!(ke_release_mutant::<Sim>(m, false), Ok(-1));
        assert_eq!((*m).owner_thread, t, "still owned after one release of two");
        assert_eq!(ke_release_mutant::<Sim>(m, false), Ok(0));
        assert!((*m).owner_thread.is_null());
        assert!(ListEntry::is_empty(ptr::addr_of!((*t).mutant_list_head)));
        assert_eq!(ke_release_mutant::<Sim>(m, false), Err(STATUS_MUTANT_NOT_OWNED));
    }
    assert_eq!(signal_state(m), 1);
    finish();
}

#[test]
fn mutant_released_by_another_thread_is_not_owned() {
    setup();
    let m = mutant();
    assert_eq!(wait_one(hdr(m), None), STATUS_WAIT_0);
    run_as(new_thread());
    // SAFETY: mutant initialisé.
    assert_eq!(unsafe { ke_release_mutant::<Sim>(m, false) }, Err(STATUS_MUTANT_NOT_OWNED));
    finish();
}

#[test]
fn abandoned_mutant_goes_to_the_next_waiter_as_abandoned() {
    let owner = setup();
    let m = mutant();
    assert_eq!(wait_one(hdr(m), None), STATUS_WAIT_0);
    assert_eq!(wait_one(hdr(m), None), STATUS_WAIT_0, "held recursively when its owner dies");
    let waiter = new_thread();
    run_as(waiter);
    then(move || {
        // L'owner se termine en le possédant encore.
        run_as(owner);
        // SAFETY: mutant initialisé.
        assert_eq!(unsafe { ke_release_mutant::<Sim>(m, true) }, Ok(-1));
    });
    assert_eq!(wait_one(hdr(m), None), STATUS_ABANDONED_WAIT_0);
    // SAFETY: objets du test initialisés.
    unsafe {
        assert_eq!((*m).owner_thread, waiter);
        assert!(!(*m).abandoned, "reported once, to its new owner");
        assert!(ListEntry::is_empty(ptr::addr_of!((*owner).mutant_list_head)));
        assert!(!ListEntry::is_empty(ptr::addr_of!((*waiter).mutant_list_head)));
    }
    assert_eq!(signal_state(m), 0);
    finish();
}

// ── Timeouts ─────────────────────────────────────────────────────────────────

#[test]
fn timeout_already_expired_returns_at_once() {
    let t = setup();
    let e = event(ObjectType::NotificationEvent, false);
    assert_eq!(wait_one(hdr(e), Some(NOW)), STATUS_TIMEOUT, "absolute due time already reached");
    assert_eq!(wait_one(hdr(e), Some(0)), STATUS_TIMEOUT, "zero timeout: a poll");
    assert!(no_waiter(hdr(e)));
    // SAFETY: thread initialisé.
    assert!(!unsafe { (*t).timer_armed });
    assert!(table().is_empty());
    finish();
}

#[test]
fn timeout_expiring_during_the_wait_returns_timeout() {
    let t = setup();
    let e = event(ObjectType::NotificationEvent, false);
    then(move || {
        expire_at(NOW + 9_999);
        // SAFETY: thread initialisé.
        assert_eq!(unsafe { (*t).state }, ThreadState::Waiting, "1 ms is not over yet");
        expire_at(NOW + 10_000);
    });
    assert_eq!(wait_one(hdr(e), Some(-10_000)), STATUS_TIMEOUT);
    assert!(no_waiter(hdr(e)), "the object's wait block is unlinked too");
    assert!(table().is_empty());
    finish();
}

#[test]
fn signal_before_the_timeout_cancels_the_timer() {
    let t = setup();
    let e = event(ObjectType::NotificationEvent, false);
    then(move || set(e));
    assert_eq!(wait_one(hdr(e), Some(-10_000)), STATUS_WAIT_0);
    assert!(table().is_empty(), "timer cancelled");
    // SAFETY: thread initialisé.
    unsafe {
        assert!(!(*t).timer_armed);
        assert!(no_waiter(ptr::addr_of_mut!((*t).timer.header)));
    }
    finish();
}

// ── Objets KTIMER ────────────────────────────────────────────────────────────

fn set_timer(t: *mut KTimer, due_time: i64, period_ms: i32, dpc: *const crate::dpc::KDpc) -> bool {
    // SAFETY: timer initialisé ; le DPC éventuel vit jusqu'à la fin du test.
    unsafe { ke_set_timer::<Sim>(t, due_time, period_ms, dpc) }
}

fn timer_signaled(t: *mut KTimer) -> bool {
    // SAFETY: timer initialisé.
    unsafe { ke_read_state_timer(t) }
}

#[test]
fn waiting_on_a_notification_timer_returns_when_it_expires() {
    setup();
    let t = timer(ObjectType::NotificationTimer);
    assert!(!set_timer(t, -20_000, 0, ptr::null()), "was not set");
    assert!(armed(t));
    then(move || expire_at(NOW + 20_000));
    assert_eq!(wait_one(hdr(t), None), STATUS_WAIT_0);
    assert!(timer_signaled(t), "a notification timer stays signaled");
    assert!(!armed(t));
    assert_eq!(wait_one(hdr(t), None), STATUS_WAIT_0, "signaled: no wait");
    finish();
}

#[test]
fn a_synchronization_timer_releases_one_waiter_per_expiry() {
    let a = setup();
    let b = new_thread();
    let t = timer(ObjectType::SynchronizationTimer);
    set_timer(t, -10_000, 0, ptr::null());
    then(move || {
        run_as(b);
        then(move || {
            expire_at(NOW + 10_000);
            assert_eq!(state(a), ThreadState::Ready, "the first waiter is woken");
            assert_eq!(state(b), ThreadState::Waiting, "one waiter per expiry");
            assert!(!timer_signaled(t), "auto-reset");
            set_timer(t, -10_000, 0, ptr::null());
            expire_at(NOW + 10_000);
        });
        assert_eq!(wait_one(hdr(t), None), STATUS_WAIT_0);
    });
    assert_eq!(wait_one(hdr(t), None), STATUS_WAIT_0);
    finish();
}

#[test]
fn a_periodic_timer_is_rearmed_at_its_next_deadline_still_to_come() {
    setup();
    let t = timer(ObjectType::NotificationTimer);
    set_timer(t, -10_000, 5, ptr::null());
    expire_at(NOW + 10_000);
    assert!(timer_signaled(t));
    // SAFETY: timer initialisé.
    let due = || unsafe { (*t).due_time } as i64;
    assert!(armed(t));
    assert_eq!(due(), NOW + 60_000, "one period after the first deadline");
    expire_at(NOW + 130_000);
    assert_eq!(due(), NOW + 160_000, "missed periods are skipped");
    // SAFETY: timer initialisé.
    unsafe {
        assert!(ke_cancel_timer::<Sim>(t));
        assert!(!ke_cancel_timer::<Sim>(t));
    }
    assert!(table().is_empty());
    finish();
}

#[test]
fn an_expiring_timer_queues_its_dpc() {
    let _queue = crate::dpc::tests::GLOBAL_QUEUE.lock().unwrap();
    setup();
    fn nop(_: *const crate::dpc::KDpc, _: *mut c_void, _: *mut c_void, _: *mut c_void) {}
    let dpc = Box::leak(Box::new(crate::dpc::KDpc::new(nop, ptr::null_mut())));
    let t = timer(ObjectType::NotificationTimer);
    set_timer(t, -10_000, 0, dpc);
    // SAFETY: DPC du test, jamais libéré.
    assert!(!unsafe { crate::dpc::ke_remove_queue_dpc(dpc) }, "not before the deadline");
    expire_at(NOW + 10_000);
    // SAFETY: comme ci-dessus.
    assert!(unsafe { crate::dpc::ke_remove_queue_dpc(dpc) }, "queued at the deadline");
    finish();
}

#[test]
fn setting_a_timer_already_due_fires_it_at_once() {
    setup();
    let t = timer(ObjectType::NotificationTimer);
    assert!(!set_timer(t, NOW, 0, ptr::null()), "absolute deadline, already reached");
    assert!(timer_signaled(t));
    assert!(!armed(t));
    set_timer(t, NOW, 5, ptr::null());
    assert!(timer_signaled(t));
    // SAFETY: timer initialisé.
    assert_eq!(unsafe { (*t).due_time } as i64, NOW + 50_000, "a periodic series starts from now");
    finish();
}

#[test]
fn setting_an_armed_timer_again_moves_its_deadline_and_resets_it() {
    setup();
    let t = timer(ObjectType::NotificationTimer);
    set_timer(t, NOW, 0, ptr::null());
    assert!(!set_timer(t, -10_000, 0, ptr::null()), "fired, so not armed any more");
    assert!(!timer_signaled(t), "setting resets the signal state");
    assert!(set_timer(t, -30_000, 0, ptr::null()), "was armed");
    expire_at(NOW + 10_000);
    assert!(!timer_signaled(t), "the first deadline is gone");
    expire_at(NOW + 30_000);
    assert!(timer_signaled(t));
    finish();
}

// ── Délais et fin de thread ──────────────────────────────────────────────────

fn delay(wait_mode: ProcessorMode, alertable: bool, interval: i64) -> NtStatus {
    // SAFETY: thread courant initialisé.
    unsafe { ke_delay_execution_thread::<Sim>(wait_mode, alertable, interval) }
}

#[test]
fn delay_execution_returns_success_once_the_interval_is_over() {
    let t = setup();
    then(move || {
        expire_at(NOW + 19_999);
        assert_eq!(state(t), ThreadState::Waiting, "2 ms are not over yet");
        expire_at(NOW + 20_000);
    });
    assert_eq!(delay(ProcessorMode::Kernel, false, -20_000), STATUS_SUCCESS);
    assert!(table().is_empty());
    finish();
}

#[test]
fn a_zero_or_past_delay_returns_at_once() {
    setup();
    assert_eq!(delay(ProcessorMode::Kernel, false, 0), STATUS_SUCCESS);
    assert_eq!(delay(ProcessorMode::Kernel, false, NOW), STATUS_SUCCESS, "absolute, already reached");
    assert!(table().is_empty());
    finish();
}

#[test]
fn an_alertable_user_mode_delay_ends_on_a_user_apc() {
    let t = setup();
    // SAFETY: verrou tenu par `locked` ; thread initialisé.
    then(move || locked(|| unsafe { ki_try_unwait_for_user_apc::<Sim>(t) }));
    assert_eq!(delay(ProcessorMode::User, true, -10_000), STATUS_USER_APC);
    assert!(table().is_empty(), "its timer is cancelled");
    finish();
}

fn exit_thread(t: *mut KThread) {
    // SAFETY: verrou tenu par `locked` ; thread initialisé.
    locked(|| unsafe { ki_thread_exit::<Sim>(t) });
}

#[test]
fn a_thread_that_exits_wakes_its_waiters_and_abandons_its_mutants() {
    let waiter = setup();
    let owner = new_thread();
    let m = mutant();
    run_as(owner);
    assert_eq!(wait_one(hdr(m), None), STATUS_WAIT_0);
    assert_eq!(wait_one(hdr(m), None), STATUS_WAIT_0, "held recursively when it exits");
    run_as(waiter);
    then(move || exit_thread(owner));
    assert_eq!(wait_one(hdr(owner), None), STATUS_WAIT_0, "the thread object is signaled at its end");
    assert_eq!(state(owner), ThreadState::Terminated);
    assert_eq!(wait_one(hdr(m), None), STATUS_ABANDONED_WAIT_0);
    // SAFETY: objets du test initialisés.
    unsafe {
        assert_eq!((*m).owner_thread, waiter);
        assert!(ListEntry::is_empty(ptr::addr_of!((*owner).mutant_list_head)));
    }
    finish();
}

#[test]
fn a_waiting_thread_that_exits_leaves_no_wait_block_behind() {
    let t = setup();
    let e = event(ObjectType::NotificationEvent, false);
    then(move || {
        exit_thread(t);
        assert_eq!(state(t), ThreadState::Terminated);
        assert!(no_waiter(hdr(e)));
        assert!(table().is_empty(), "its timeout is cancelled");
    });
    // Le thread ne reprend jamais dans le noyau ; Sim, lui, rend la main.
    wait_one(hdr(e), Some(-10_000));
    finish();
}

// ── APC ──────────────────────────────────────────────────────────────────────

fn alertable_user_wait(obj: *mut DispatcherHeader) -> NtStatus {
    // SAFETY: objet et thread courant initialisés.
    unsafe { ke_wait_for_single_object::<Sim>(obj, ProcessorMode::User, true, None) }
}

#[test]
fn user_apc_ends_an_alertable_user_mode_wait() {
    let t = setup();
    let e = event(ObjectType::NotificationEvent, false);
    // SAFETY: verrou tenu par `locked`.
    then(move || locked(|| unsafe { ki_try_unwait_for_user_apc::<Sim>(t) }));
    assert_eq!(alertable_user_wait(hdr(e)), STATUS_USER_APC);
    assert!(no_waiter(hdr(e)));
    finish();
}

#[test]
fn pending_user_apc_makes_an_alertable_wait_return_at_once() {
    let t = setup();
    let e = event(ObjectType::NotificationEvent, false);
    // SAFETY: thread initialisé.
    unsafe { (*t).user_apc_pending = true };
    assert_eq!(alertable_user_wait(hdr(e)), STATUS_USER_APC);
    finish();
}

#[test]
fn user_apc_leaves_non_alertable_and_kernel_mode_waits_alone() {
    let t = setup();
    let e = event(ObjectType::SynchronizationEvent, false);
    let deliver_then_signal = move || {
        // SAFETY: verrou tenu par `locked`.
        locked(|| unsafe { ki_try_unwait_for_user_apc::<Sim>(t) });
        assert_eq!(state(t), ThreadState::Waiting, "the APC does not end this wait");
        set(e);
    };
    then(deliver_then_signal);
    // SAFETY: objet et thread initialisés.
    let non_alertable = unsafe { ke_wait_for_single_object::<Sim>(hdr(e), ProcessorMode::User, false, None) };
    assert_eq!(non_alertable, STATUS_WAIT_0);
    then(deliver_then_signal);
    // SAFETY: objet et thread initialisés.
    let kernel_mode = unsafe { ke_wait_for_single_object::<Sim>(hdr(e), ProcessorMode::Kernel, true, None) };
    assert_eq!(kernel_mode, STATUS_WAIT_0);
    finish();
}

#[test]
fn kernel_apc_interrupts_the_wait_which_then_resumes() {
    let t = setup();
    let e = event(ObjectType::SynchronizationEvent, false);
    // SAFETY: verrou tenu par `locked`.
    then(move || locked(|| unsafe { ki_unwait_for_kernel_apc::<Sim>(t) }));
    then(move || set(e));
    assert_eq!(wait_one(hdr(e), None), STATUS_WAIT_0, "the wait resumes after the APC");
    assert_eq!(signal_state(e), 0);
    assert_eq!(READIED.with_borrow(Vec::len), 2, "woken for the APC, then by the event");
    finish();
}
