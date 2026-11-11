//! Les minuteries de USER (02 §7.2 ; `timer.c` de ReactOS comme
//! spécification) : SetTimer, SetSystemTimer, KillTimer.
//!
//! Une minuterie (`TIMER`) appartient à un thread GUI, dont la file reçoit
//! ses messages : celui de sa fenêtre (TMRF_TIFROMWND), ou celui qui l'a
//! posée s'il n'y a pas de fenêtre. Elle a un délai (`cmsRate`, borné à
//! USER_TIMER_MINIMUM ; au-delà de USER_TIMER_MAXIMUM, le délai devient
//! 1 ms, comme XP) et une échéance, en temps d'interruption.
//!
//! Le thread d'entrée brute (`ntoskrnl::input`, comme le RIT de ReactOS)
//! attend jusqu'à l'échéance la plus proche ([`next_due`]) et fait expirer
//! les minuteries échues ([`expire`]) : chacune devient prête
//! (TMRF_READY), son échéance repart de maintenant, et la file de son
//! thread prend `QS_TIMER` et est réveillée. Poser une minuterie réveille
//! ce thread ([`set_wake`]), qui recalcule son attente.
//!
//! WM_TIMER (WM_SYSTIMER pour une minuterie du système) n'est jamais dans
//! la file : PeekMessage le fabrique ([`message`]) pour une minuterie prête
//! quand rien d'autre ne sort (messages postés, WM_QUIT, entrées, WM_PAINT),
//! comme `PostTimerMessages` en fin de co_IntPeekMessage. Il porte
//! l'identifiant en `wParam` et la procédure en `lParam` ; le sortir rend
//! la minuterie de nouveau en attente, et `QS_TIMER` s'éteint avec la
//! dernière prête du thread. Une minuterie prête ne donne qu'un message,
//! quel que soit le nombre d'échéances passées.
//!
//! Une minuterie sans fenêtre reçoit un identifiant libre, de 32 768 vers 1
//! (NUM_WINDOW_LESS_TIMERS), sauf si le thread en a déjà une de cet
//! identifiant, qu'il remplace. Une minuterie de fenêtre se remplace par sa
//! fenêtre et son identifiant ; SetTimer d'une fenêtre d'un autre processus
//! est refusé.
//!
//! Les minuteries d'un thread qui se termine s'en vont avec lui
//! ([`destroy_thread_timers`], par le rappel de Ps à la fin d'un thread GUI) ;
//! celles d'une fenêtre détruite, par [`destroy_window_timers`]. Par sûreté,
//! celles d'un thread fini qui resteraient s'en vont à l'échéance suivante
//! de l'une d'elles.
//!
//! Une minuterie du système peut avoir une procédure du noyau
//! ([`set_kernel_timer`] : le clignotement du caret, `crate::caret`) : son
//! WM_SYSTIMER porte [`KERNEL_PROCEDURE`] en `lParam`, que `user32` rend au
//! noyau (NtUserDispatchMessage), qui l'appelle ([`kernel_procedure`],
//! FindSystemTimer).
//!
//! Pas encore : les minuteries du RIT (TMRF_RIT : le curseur, le clavier),
//! TMRF_ONESHOT, le nombre maximal de minuteries d'un processus.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use abi::user::{Msg32, WM_SYSTIMER, WM_TIMER};
use hal::sync::KSpinLock;

use crate::gui::ThreadInfo;
use crate::queue::Filter;

/// USER_TIMER_MINIMUM, USER_TIMER_MAXIMUM : les bornes d'un délai, en
/// millisecondes.
pub const USER_TIMER_MINIMUM: u32 = 0x0000_000A;
pub const USER_TIMER_MAXIMUM: u32 = 0x7FFF_FFFF;
/// NUM_WINDOW_LESS_TIMERS : les identifiants des minuteries sans fenêtre,
/// de ce nombre vers 1.
pub const WINDOWLESS_IDS: u32 = 32_768;
/// Le `lParam` du WM_SYSTIMER d'une minuterie à procédure du noyau : une
/// adresse de la moitié du noyau, que le client ne peut pas appeler, et
/// non nulle, pour que DispatchMessage de `user32` la rende au noyau.
pub const KERNEL_PROCEDURE: u32 = 0x8000_0000;
/// La procédure du noyau d'une minuterie du système : sa fenêtre et son
/// identifiant.
pub type KernelProcedure = fn(u32, u32);

/// Une milliseconde en unités du temps d'interruption (100 ns).
const MILLISECOND: u64 = 10_000;

/// Le délai d'une minuterie, borné (IntSetTimer) : au-delà de
/// USER_TIMER_MAXIMUM, 1 ms (XP), puis au moins USER_TIMER_MINIMUM (XP SP2).
pub const fn rate_of(elapse: u32) -> u32 {
    let elapse = if elapse > USER_TIMER_MAXIMUM { 1 } else { elapse };
    if elapse < USER_TIMER_MINIMUM {
        USER_TIMER_MINIMUM
    } else {
        elapse
    }
}

/// Ce qui désigne une minuterie : sa fenêtre (0 : aucune), son identifiant,
/// et si elle est du système (WM_SYSTIMER).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerKey {
    pub hwnd: u32,
    pub id: u32,
    pub system: bool,
}

impl TimerKey {
    /// Une minuterie sans fenêtre, hors du système : son identifiant est
    /// donné par win32k.
    const fn windowless(&self) -> bool {
        self.hwnd == 0 && !self.system
    }
}

/// Une minuterie (`TIMER`) ; `O` désigne le thread dont la file reçoit ses
/// messages.
#[derive(Clone, Debug)]
struct Timer<O> {
    key: TimerKey,
    owner: O,
    /// Le PID du processus qui l'a posée (ValidateTimerCallback).
    process: u32,
    /// `cmsRate`, en millisecondes.
    rate: u32,
    /// Son échéance, en temps d'interruption.
    due: u64,
    /// Sa procédure (`TIMERPROC`), le `lParam` de son message ; 0 sans.
    procedure: u32,
    /// Sa procédure du noyau, pour une minuterie du système.
    kernel: Option<KernelProcedure>,
    /// TMRF_READY : échue, son message pas encore sorti.
    ready: bool,
}

impl<O> Timer<O> {
    /// WM_TIMER ou WM_SYSTIMER, daté de `time`.
    fn message(&self, time: u32) -> Msg32 {
        Msg32 {
            hwnd: self.key.hwnd,
            message: if self.key.system { WM_SYSTIMER } else { WM_TIMER },
            w_param: self.key.id,
            l_param: self.procedure,
            time,
            ..Msg32::default()
        }
    }
}

/// Ce qu'on demande à [`Timers::set`].
#[derive(Clone, Copy, Debug)]
pub struct NewTimer {
    pub key: TimerKey,
    /// Le PID du processus qui la pose.
    pub process: u32,
    /// Le délai demandé, en millisecondes (borné par [`rate_of`]).
    pub elapse: u32,
    pub procedure: u32,
    pub kernel: Option<KernelProcedure>,
}

/// Un thread dont une minuterie vient d'échoir ([`Timers::expire`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expired<O> {
    pub owner: O,
    /// Une de ses minuteries vient de devenir prête : sa file prend
    /// `QS_TIMER` et il est réveillé. Sinon, elles l'étaient déjà (leur
    /// message n'est pas sorti) : il faut seulement voir s'il vit encore.
    pub newly_ready: bool,
}

/// Les minuteries de tous les threads (`TimersListHead`), dans l'ordre où
/// elles ont été posées.
#[derive(Debug)]
pub struct Timers<O> {
    list: Vec<Timer<O>>,
}

impl<O> Default for Timers<O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O> Timers<O> {
    /// Aucune minuterie.
    pub const fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Le nombre de minuteries.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Aucune minuterie.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// IntSetTimer : la minuterie `new`, pour `owner`, échue dans son délai
    /// à partir de `now`. Celle de même fenêtre et même identifiant (d'une
    /// minuterie sans fenêtre : du même thread) est remplacée ; une
    /// minuterie sans fenêtre nouvelle reçoit un identifiant libre. Rend
    /// l'identifiant ; `None` quand il n'en reste aucun de libre.
    pub fn set(&mut self, new: NewTimer, owner: O, now: u64, is_owner: impl Fn(&O) -> bool) -> Option<u32> {
        let rate = rate_of(new.elapse);
        let due = now + u64::from(rate) * MILLISECOND;
        let mut key = new.key;
        let existing = self
            .list
            .iter()
            .position(|timer| timer.key == key && (!key.windowless() || (key.id != 0 && is_owner(&timer.owner))));
        if let Some(index) = existing {
            let timer = &mut self.list[index];
            timer.rate = rate;
            timer.due = due;
            timer.procedure = new.procedure;
            timer.kernel = new.kernel;
            return Some(key.id);
        }
        if key.windowless() {
            key.id = self.free_windowless_id()?;
        }
        let (procedure, kernel) = (new.procedure, new.kernel);
        self.list.push(Timer { key, owner, process: new.process, rate, due, procedure, kernel, ready: false });
        Some(key.id)
    }

    /// Le premier identifiant sans fenêtre libre, de [`WINDOWLESS_IDS`]
    /// vers 1.
    fn free_windowless_id(&self) -> Option<u32> {
        (1..=WINDOWLESS_IDS)
            .rev()
            .find(|&id| !self.list.iter().any(|timer| timer.key.windowless() && timer.key.id == id))
    }

    /// IntKillTimer : retire la minuterie `key` (sans fenêtre : du thread
    /// que reconnaît `is_owner`) ; rend son thread, si elle existait.
    pub fn kill(&mut self, key: TimerKey, is_owner: impl Fn(&O) -> bool) -> Option<O> {
        let index =
            self.list.iter().position(|timer| timer.key == key && (!key.windowless() || is_owner(&timer.owner)))?;
        Some(self.list.remove(index).owner)
    }

    /// DestroyTimersForWindow : retire les minuteries de la fenêtre `hwnd` ;
    /// rend leurs threads.
    pub fn kill_window(&mut self, hwnd: u32) -> Vec<O> {
        let mut owners = Vec::new();
        let mut index = 0;
        while index < self.list.len() {
            if hwnd != 0 && self.list[index].key.hwnd == hwnd {
                owners.push(self.list.remove(index).owner);
            } else {
                index += 1;
            }
        }
        owners
    }

    /// Retire les minuteries des threads que `dead` reconnaît.
    pub fn purge(&mut self, dead: impl Fn(&O) -> bool) {
        self.list.retain(|timer| !dead(&timer.owner));
    }

    /// ProcessTimers : les minuteries échues à `now` deviennent prêtes, et
    /// leur échéance repart de `now`. Rend une fois (selon `same`) chaque
    /// thread dont une minuterie est échue, même déjà prête : un thread fini
    /// avant d'en sortir le message doit perdre ses minuteries.
    pub fn expire(&mut self, now: u64, same: impl Fn(&O, &O) -> bool) -> Vec<Expired<O>>
    where
        O: Clone,
    {
        let mut expired: Vec<Expired<O>> = Vec::new();
        for timer in self.list.iter_mut().filter(|timer| timer.due <= now) {
            timer.due = now + u64::from(timer.rate) * MILLISECOND;
            let newly_ready = !timer.ready;
            timer.ready = true;
            match expired.iter_mut().find(|seen| same(&seen.owner, &timer.owner)) {
                Some(seen) => seen.newly_ready |= newly_ready,
                None => expired.push(Expired { owner: timer.owner.clone(), newly_ready }),
            }
        }
        expired
    }

    /// L'échéance la plus proche, s'il y a une minuterie.
    pub fn next_due(&self) -> Option<u64> {
        self.list.iter().map(|timer| timer.due).min()
    }

    /// PostTimerMessages : le message de la première minuterie prête du
    /// thread que reconnaît `is_owner` que demande `filter`, daté de
    /// `time` ; elle n'est plus prête si `remove`. Rend aussi s'il reste au
    /// thread une minuterie prête (`QS_TIMER`).
    pub fn take(
        &mut self,
        filter: &Filter,
        remove: bool,
        time: u32,
        is_owner: impl Fn(&O) -> bool,
    ) -> (Option<Msg32>, bool) {
        let found = self
            .list
            .iter_mut()
            .find(|timer| timer.ready && is_owner(&timer.owner) && filter.matches(&timer.message(time)))
            .map(|timer| {
                if remove {
                    timer.ready = false;
                }
                timer.message(time)
            });
        let still_ready = self.list.iter().any(|timer| timer.ready && is_owner(&timer.owner));
        (found, still_ready)
    }

    /// FindSystemTimer : la procédure du noyau de la minuterie du système
    /// `id` de la fenêtre `hwnd`, à un thread que dit `is_owner`.
    pub fn kernel_procedure(&self, hwnd: u32, id: u32, is_owner: impl Fn(&O) -> bool) -> Option<KernelProcedure> {
        let key = TimerKey { hwnd, id, system: true };
        self.list.iter().find(|timer| timer.key == key && is_owner(&timer.owner))?.kernel
    }

    /// ValidateTimerCallback : une minuterie hors du système du processus
    /// `process` a `procedure` pour procédure.
    pub fn validates(&self, process: u32, procedure: u32) -> bool {
        procedure != 0
            && self
                .list
                .iter()
                .any(|timer| !timer.key.system && timer.process == process && timer.procedure == procedure)
    }
}

/// Le thread GUI d'une minuterie, sans le garder vivant.
#[derive(Clone)]
struct Owner(Weak<ThreadInfo>);

impl Owner {
    fn is(&self, thread: &ThreadInfo) -> bool {
        core::ptr::eq(self.0.as_ptr(), thread)
    }

    fn same(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.0, &other.0)
    }
}

/// Les minuteries de tous les threads GUI. Pris avant la file d'un thread,
/// jamais après.
static TIMERS: KSpinLock<Timers<Owner>> = KSpinLock::new(Timers::new());
/// Ce qui réveille le thread qui fait expirer les minuteries ([`set_wake`]).
static WAKE: AtomicUsize = AtomicUsize::new(0);

/// Le thread qui attend jusqu'à [`next_due`] et appelle [`expire`] se fait
/// réveiller par `wake` quand une minuterie est posée.
///
/// # IRQL
/// Tout niveau.
pub fn set_wake(wake: fn()) {
    WAKE.store(wake as usize, Ordering::Release);
}

/// Réveille le thread des minuteries, s'il s'est inscrit.
fn wake_expirer() {
    let wake = WAKE.load(Ordering::Acquire);
    if wake != 0 {
        // SAFETY: only `set_wake` stores here, the address of a `fn()`.
        let wake: fn() = unsafe { core::mem::transmute::<usize, fn()>(wake) };
        wake();
    }
}

/// Le temps d'interruption, horloge des minuteries.
fn now() -> u64 {
    hal::timer::interrupt_time()
}

/// Les bits de réveil et de changement d'une file, à reporter dans le
/// `CLIENTTHREADINFO` de son thread.
type QueueBits = (u16, u16);

/// Met `QS_TIMER` dans la file de `thread` ou l'en retire, sous le verrou
/// des minuteries ; rend les bits à reporter dans son `CLIENTTHREADINFO`.
fn set_ready_bit(thread: &ThreadInfo, ready: bool) -> QueueBits {
    let ((), wake, change) = thread.queue.with(|queue| queue.set_timers_ready(ready));
    (wake, change)
}

/// Il reste à `thread` une minuterie prête.
fn any_ready(timers: &mut Timers<Owner>, thread: &ThreadInfo) -> bool {
    timers.take(&Filter { hwnd: 0, min: 0, max: 0 }, false, 0, |timer| timer.is(thread)).1
}

/// IntSetTimer : la minuterie `key` (SetTimer, SetSystemTimer), de délai
/// `elapse` et de procédure `procedure`, pour le thread de sa fenêtre
/// `window`, ou pour `current` sans fenêtre ; rend son identifiant.
///
/// # Errors
/// L'erreur Win32 : `ERROR_ACCESS_DENIED` pour une fenêtre d'un autre
/// processus ou sans thread, `ERROR_NO_SYSTEM_RESOURCES` quand aucun
/// identifiant sans fenêtre n'est libre.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système.
pub fn set_timer(
    current: &Arc<ThreadInfo>,
    window: Option<&crate::window::Window>,
    key: TimerKey,
    elapse: u32,
    procedure: u32,
) -> Result<u32, u32> {
    use abi::winerror::{ERROR_ACCESS_DENIED, ERROR_NO_SYSTEM_RESOURCES};
    let process = ps::ethread::current_thread().map(|thread| thread.process().pid()).ok_or(ERROR_ACCESS_DENIED)?;
    let owner = match window {
        Some(window) => {
            if crate::gui::process_id_of(window.pti) != Some(process) {
                return Err(ERROR_ACCESS_DENIED);
            }
            crate::gui::thread_info_of(window.pti).ok_or(ERROR_ACCESS_DENIED)?
        }
        None => current.clone(),
    };
    let new = NewTimer { key, process, elapse, procedure, kernel: None };
    let id = TIMERS
        .lock()
        .set(new, Owner(Arc::downgrade(&owner)), now(), |timer| timer.is(current))
        .ok_or(ERROR_NO_SYSTEM_RESOURCES)?;
    wake_expirer();
    Ok(id)
}

/// IntSetTimer d'une minuterie du système de la fenêtre `window`,
/// d'identifiant `id`, de délai `elapse`, dont le message appelle
/// `procedure` dans le noyau (TMRF_SYSTEM avec une procédure : le
/// clignotement du caret).
///
/// # Errors
/// `ERROR_ACCESS_DENIED` pour une fenêtre sans thread.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_kernel_timer(
    window: &crate::window::Window,
    id: u32,
    elapse: u32,
    procedure: KernelProcedure,
) -> Result<u32, u32> {
    let owner = crate::gui::thread_info_of(window.pti).ok_or(abi::winerror::ERROR_ACCESS_DENIED)?;
    let process = crate::gui::process_id_of(window.pti).unwrap_or(0);
    let key = TimerKey { hwnd: window.handle, id, system: true };
    let new = NewTimer { key, process, elapse, procedure: KERNEL_PROCEDURE, kernel: Some(procedure) };
    let id = TIMERS
        .lock()
        .set(new, Owner(Arc::downgrade(&owner)), now(), |_| false)
        .ok_or(abi::winerror::ERROR_NO_SYSTEM_RESOURCES)?;
    wake_expirer();
    Ok(id)
}

/// FindSystemTimer : la procédure du noyau de la minuterie du système `id`
/// de la fenêtre `hwnd`, au thread `thread` (DispatchMessage de son
/// WM_SYSTIMER) ; `None` sans elle.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn kernel_procedure(thread: &ThreadInfo, hwnd: u32, id: u32) -> Option<KernelProcedure> {
    TIMERS.lock().kernel_procedure(hwnd, id, |timer| timer.is(thread))
}

/// IntKillTimer : retire la minuterie `key` (sans fenêtre : du thread
/// `current`) ; rend si elle existait. Son message ne sort plus.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn kill_timer(current: &ThreadInfo, key: TimerKey) -> bool {
    let mut timers = TIMERS.lock();
    let Some(owner) = timers.kill(key, |timer| timer.is(current)) else { return false };
    let thread = owner.0.upgrade();
    let bits = thread.as_ref().map(|thread| {
        let still_ready = any_ready(&mut timers, thread);
        set_ready_bit(thread, still_ready)
    });
    drop(timers);
    if let (Some(thread), Some((wake, change))) = (thread, bits) {
        thread.mirror_queue_bits(wake, change);
    }
    true
}

/// DestroyTimersForWindow : retire les minuteries de la fenêtre `hwnd`
/// (DestroyWindow).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy_window_timers(hwnd: u32) {
    let mut timers = TIMERS.lock();
    let owners = timers.kill_window(hwnd);
    let mut threads: Vec<(Arc<ThreadInfo>, (u16, u16))> = Vec::new();
    for owner in owners {
        let Some(thread) = owner.0.upgrade() else { continue };
        if threads.iter().any(|(seen, _)| Arc::ptr_eq(seen, &thread)) {
            continue;
        }
        let still_ready = any_ready(&mut timers, &thread);
        let bits = set_ready_bit(&thread, still_ready);
        threads.push((thread, bits));
    }
    drop(timers);
    for (thread, (wake, change)) in threads {
        thread.mirror_queue_bits(wake, change);
    }
}

/// DestroyTimersForThread : retire les minuteries de `thread`, qui se
/// termine (celles de ses fenêtres et celles sans fenêtre).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy_thread_timers(thread: &ThreadInfo) {
    TIMERS.lock().purge(|owner| owner.is(thread));
}

/// L'échéance la plus proche, en temps d'interruption, s'il y a une
/// minuterie.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn next_due() -> Option<u64> {
    TIMERS.lock().next_due()
}

/// ProcessTimers : les minuteries échues deviennent prêtes, et la file de
/// leurs threads prend `QS_TIMER` et est réveillée ; les minuteries des
/// threads finis s'en vont, que leur message soit sorti ou non.
///
/// # IRQL
/// PASSIVE_LEVEL (le thread d'entrée brute).
pub fn expire() {
    let mut timers = TIMERS.lock();
    let expired = timers.expire(now(), Owner::same);
    // Each thread, with the bits to mirror when a timer became ready.
    let mut threads: Vec<(Arc<ThreadInfo>, Option<QueueBits>)> = Vec::new();
    let mut dead: Vec<Owner> = Vec::new();
    for Expired { owner, newly_ready } in expired {
        match owner.0.upgrade() {
            Some(thread) => {
                let bits = newly_ready.then(|| set_ready_bit(&thread, true));
                threads.push((thread, bits));
            }
            None => dead.push(owner),
        }
    }
    drop(timers);
    for (thread, bits) in &threads {
        if !crate::gui::thread_alive(thread) {
            dead.push(Owner(Arc::downgrade(thread)));
            continue;
        }
        if let Some((wake, change)) = bits {
            thread.mirror_queue_bits(*wake, *change);
            thread.queue.wake();
        }
    }
    if !dead.is_empty() {
        TIMERS.lock().purge(|owner| dead.iter().any(|gone| gone.same(owner)));
    }
    // The last references to the threads go here, the lock released.
    drop(threads);
}

/// Le message d'une minuterie prête de `thread` que demande `filter`
/// (WM_TIMER, WM_SYSTIMER), qui ne l'est plus si `remove` ; `QS_TIMER`
/// s'éteint avec sa dernière minuterie prête.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn message(thread: &ThreadInfo, filter: &Filter, remove: bool) -> Option<Msg32> {
    let time = hal::timer::get_tick_count() as u32;
    let mut timers = TIMERS.lock();
    let (found, still_ready) = timers.take(filter, remove, time, |timer| timer.is(thread));
    let (wake, change) = set_ready_bit(thread, still_ready);
    drop(timers);
    thread.mirror_queue_bits(wake, change);
    found
}

/// ValidateTimerCallback : le processus courant a posé une minuterie de
/// procédure `procedure` (DispatchMessage de `user32` ne l'appelle qu'à
/// cette condition).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn validate_callback(procedure: u32) -> bool {
    let Some(process) = ps::ethread::current_thread().map(|thread| thread.process().pid()) else { return false };
    TIMERS.lock().validates(process, procedure)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: Filter = Filter { hwnd: 0, min: 0, max: 0 };
    const MS: u64 = MILLISECOND;

    fn window_timer(hwnd: u32, id: u32, elapse: u32) -> NewTimer {
        NewTimer { key: TimerKey { hwnd, id, system: false }, process: 8, elapse, procedure: 0, kernel: None }
    }

    fn thread_timer(id: u32, elapse: u32) -> NewTimer {
        window_timer(0, id, elapse)
    }

    fn same(a: &u32, b: &u32) -> bool {
        a == b
    }

    fn expired(owner: u32, newly_ready: bool) -> Expired<u32> {
        Expired { owner, newly_ready }
    }

    #[test]
    fn rates_are_bounded_like_xp() {
        assert_eq!(rate_of(0), USER_TIMER_MINIMUM);
        assert_eq!(rate_of(9), USER_TIMER_MINIMUM);
        assert_eq!(rate_of(1000), 1000);
        assert_eq!(rate_of(USER_TIMER_MAXIMUM), USER_TIMER_MAXIMUM);
        assert_eq!(rate_of(USER_TIMER_MAXIMUM + 1), USER_TIMER_MINIMUM, "1 ms, then the minimum");
    }

    #[test]
    fn a_timer_expires_once_per_message_and_starts_again_from_then() {
        let mut timers: Timers<u32> = Timers::new();
        assert_eq!(timers.set(window_timer(0x20, 1, 1000), 7, 0, |&o| o == 7), Some(1));
        assert_eq!(timers.next_due(), Some(1000 * MS));
        assert!(timers.expire(999 * MS, same).is_empty(), "not yet");
        assert_eq!(timers.take(&ALL, true, 0, |&o| o == 7), (None, false));
        assert_eq!(timers.expire(1000 * MS, same), [expired(7, true)]);
        assert_eq!(timers.next_due(), Some(2000 * MS), "from the expiry");
        assert_eq!(timers.expire(5000 * MS, same), [expired(7, false)], "ready already: one message");
        assert_eq!(timers.next_due(), Some(6000 * MS));
        let (peeked, still) = timers.take(&ALL, false, 42, |&o| o == 7);
        let peeked = peeked.unwrap();
        assert_eq!((peeked.hwnd, peeked.message, peeked.w_param, peeked.time), (0x20, WM_TIMER, 1, 42));
        assert!(still, "not removed");
        assert_eq!(timers.take(&ALL, true, 0, |&o| o == 8), (None, false), "another thread's");
        let (taken, still) = timers.take(&ALL, true, 0, |&o| o == 7);
        assert!(taken.is_some() && !still);
        assert_eq!(timers.take(&ALL, true, 0, |&o| o == 7), (None, false), "once");
        assert_eq!(timers.expire(6000 * MS, same), [expired(7, true)], "again at the next expiry");
    }

    #[test]
    fn a_thread_gone_with_a_ready_timer_is_still_reported_and_purged() {
        // Codex's review of #83: a timer whose message never came out, its
        // thread gone, was never reported again, so never purged; a
        // windowless one kept its id for good.
        let mut timers: Timers<u32> = Timers::new();
        timers.set(window_timer(0x20, 1, 50), 8, 0, |&o| o == 8);
        assert_eq!(timers.set(thread_timer(0, 100), 7, 0, |&o| o == 7), Some(WINDOWLESS_IDS));
        assert_eq!(timers.expire(100 * MS, same), [expired(8, true), expired(7, true)]);
        // 7 ends without taking its WM_TIMER: its next expiry reports it.
        let again = timers.expire(200 * MS, same);
        assert_eq!(again, [expired(8, false), expired(7, false)]);
        timers.purge(|&o| o == 7);
        assert_eq!(timers.len(), 1, "8's is left");
        assert_eq!(timers.set(thread_timer(0, 100), 9, 0, |&o| o == 9), Some(WINDOWLESS_IDS), "its id is free");
        // A thread with one ready timer and one newly due is woken once.
        timers.expire(250 * MS, same);
        timers.set(window_timer(0x30, 2, 10), 8, 250 * MS, |&o| o == 8);
        assert!(timers.expire(300 * MS, same).contains(&expired(8, true)), "0x30's became ready");
    }

    #[test]
    fn a_window_timer_is_replaced_by_its_window_and_id() {
        let mut timers: Timers<u32> = Timers::new();
        timers.set(window_timer(0x20, 1, 1000), 7, 0, |&o| o == 7);
        timers.set(window_timer(0x20, 2, 50), 7, 0, |&o| o == 7);
        timers.set(window_timer(0x30, 1, 50), 7, 0, |&o| o == 7);
        assert_eq!(timers.set(window_timer(0x20, 1, 100), 7, 500 * MS, |&o| o == 7), Some(1));
        assert_eq!(timers.len(), 3, "replaced");
        assert_eq!(timers.next_due(), Some(50 * MS));
        timers.expire(100 * MS, same);
        let filter = Filter { hwnd: 0x20, min: 0, max: 0 };
        assert_eq!(timers.take(&filter, true, 0, |&o| o == 7).0.map(|m| m.w_param), Some(2), "only 0x20's");
        assert_eq!(timers.take(&filter, true, 0, |&o| o == 7).0, None, "1 is due at 600 ms");
        timers.expire(600 * MS, same);
        assert_eq!(timers.take(&filter, true, 0, |&o| o == 7).0.map(|m| m.w_param), Some(1));
        let one = TimerKey { hwnd: 0x20, id: 1, system: false };
        assert_eq!(timers.kill(one, |_| false), Some(7));
        assert_eq!(timers.kill(one, |_| false), None, "gone");
        assert_eq!(timers.kill(TimerKey { system: true, id: 2, ..one }, |_| false), None, "not a system one");
        assert_eq!(timers.kill_window(0x20), [7]);
        assert_eq!(timers.len(), 1, "0x30's is left");
    }

    #[test]
    fn windowless_timers_get_free_ids_unless_the_thread_has_that_one() {
        let mut timers: Timers<u32> = Timers::new();
        let top = WINDOWLESS_IDS;
        assert_eq!(timers.set(thread_timer(0, 100), 7, 0, |&o| o == 7), Some(top));
        assert_eq!(timers.set(thread_timer(5, 100), 7, 0, |&o| o == 7), Some(top - 1), "5: no such timer");
        assert_eq!(timers.set(thread_timer(top, 300), 7, 0, |&o| o == 7), Some(top), "its own");
        assert_eq!(timers.set(thread_timer(top, 300), 8, 0, |&o| o == 8), Some(top - 2), "not 8's");
        assert_eq!(timers.len(), 3);
        timers.expire(100 * MS, same);
        let thread_only = Filter { hwnd: u32::MAX, min: 0, max: 0 };
        let message = timers.take(&thread_only, true, 0, |&o| o == 7).0.unwrap();
        assert_eq!((message.hwnd, message.w_param), (0, top - 1), "the first one due");
        let key = TimerKey { hwnd: 0, id: top, system: false };
        assert_eq!(timers.kill(key, |&o| o == 9), None, "not 9's");
        assert_eq!(timers.kill(key, |&o| o == 7), Some(7));
        assert_eq!(timers.set(thread_timer(0, 100), 7, 0, |&o| o == 7), Some(top), "free again");
    }

    #[test]
    fn system_timers_send_wm_systimer_and_filters_apply_to_the_message() {
        let mut timers: Timers<u32> = Timers::new();
        let system = NewTimer { key: TimerKey { hwnd: 0x20, id: 0xFFFF, system: true }, ..window_timer(0x20, 0, 10) };
        timers.set(system, 7, 0, |_| true);
        timers.set(NewTimer { procedure: 0x0040_1000, ..window_timer(0x20, 3, 10) }, 7, 0, |_| true);
        timers.expire(10 * MS, same);
        let only_timer = Filter { hwnd: 0, min: WM_TIMER, max: WM_TIMER };
        let message = timers.take(&only_timer, true, 0, |&o| o == 7).0.unwrap();
        assert_eq!((message.message, message.w_param, message.l_param), (WM_TIMER, 3, 0x0040_1000));
        let message = timers.take(&ALL, true, 0, |&o| o == 7).0.unwrap();
        assert_eq!((message.message, message.w_param, message.l_param), (WM_SYSTIMER, 0xFFFF, 0));
        assert!(timers.validates(8, 0x0040_1000));
        assert!(!timers.validates(12, 0x0040_1000), "another process");
        assert!(!timers.validates(8, 0), "no procedure");
        timers.purge(|&o| o == 7);
        assert!(timers.is_empty());
    }

    fn blink(_: u32, _: u32) {}

    #[test]
    fn a_system_timer_may_call_into_the_kernel() {
        let mut timers: Timers<u32> = Timers::new();
        let key = TimerKey { hwnd: 0x20, id: 0xFFFF, system: true };
        let caret = NewTimer { key, procedure: KERNEL_PROCEDURE, kernel: Some(blink), ..window_timer(0x20, 0, 10) };
        timers.set(caret, 7, 0, |_| true);
        timers.set(window_timer(0x20, 0xFFFF, 10), 7, 0, |_| true);
        assert!(timers.kernel_procedure(0x20, 0xFFFF, |&o| o == 7).is_some());
        assert!(timers.kernel_procedure(0x20, 0xFFFF, |&o| o == 9).is_none(), "another thread's");
        assert!(timers.kernel_procedure(0x20, 3, |&o| o == 7).is_none());
        timers.expire(10 * MS, same);
        let message = timers.take(&ALL, true, 0, |&o| o == 7).0.unwrap();
        assert_eq!(message.message, WM_SYSTIMER, "the system timer, from the kernel");
        assert_eq!(message.l_param, KERNEL_PROCEDURE, "user32 gives it back to the kernel");
        // SetSystemTimer again without the procedure: none.
        timers.set(NewTimer { key, ..window_timer(0x20, 0, 10) }, 7, 0, |_| true);
        assert!(timers.kernel_procedure(0x20, 0xFFFF, |&o| o == 7).is_none());
    }
}
