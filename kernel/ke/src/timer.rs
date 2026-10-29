//! Timers (02 §Ke) : la roue de timers et les objets KTIMER.
//!
//! La roue range chaque timer armé dans l'emplacement de son échéance, à la
//! milliseconde ; une échéance au-delà d'un tour de roue (512 ms) partage son
//! emplacement et attend son tour. L'ISR d'horloge ne lit, sans verrou, que le
//! bitmap des emplacements occupés ([`TimerTable::scan`]) : quand l'heure atteint
//! un emplacement occupé, elle insère le DPC d'expiration. Celui-ci, verrou
//! dispatcher tenu, sort de la roue les timers échus, les signale (ce qui réveille
//! les threads qui les attendent), insère leur DPC et réarme les timers
//! périodiques.
//!
//! Le temps est l'interrupt time (`hal::timer::interrupt_time`, en 100 ns depuis
//! le démarrage). Les échéances suivent le format NT : négatives, relatives ;
//! positives, heure système absolue ([`deadline`]).

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use hal::sync::Once;

use crate::dispatcher::{ki_timer_expired, DispatcherHeader, KTimer, ListEntry, ObjectType, Platform, DISPATCHER_LOCK};
use crate::dpc::{ke_insert_queue_dpc, KDpc};

/// Durée d'un emplacement : 1 ms, la meilleure résolution de l'horloge
/// (`timeBeginPeriod(1)`).
const SLOT_TIME: u64 = 10_000;

/// Nombre d'emplacements de la roue : un tour dure 512 ms.
pub const TIMER_TABLE_SIZE: usize = 512;

const SLOTS: u64 = TIMER_TABLE_SIZE as u64;

/// Échéance en interrupt time d'un `due_time` au format NT. Négatif : relatif
/// à `interrupt_now`. Positif : heure système absolue, ramenée par `system_now`,
/// l'heure système au même instant. Une échéance passée vaut `interrupt_now`.
pub fn deadline(due_time: i64, interrupt_now: u64, system_now: u64) -> u64 {
    if due_time < 0 {
        interrupt_now.saturating_add(due_time.unsigned_abs())
    } else {
        interrupt_now.saturating_add((due_time as u64).saturating_sub(system_now))
    }
}

/// Roue de timers. Les listes sont protégées par le verrou dispatcher ; le
/// bitmap des emplacements occupés est lu sans verrou par l'ISR d'horloge.
pub struct TimerTable {
    /// Timers armés, par emplacement. Listes circulaires : initialisées au
    /// premier usage, à leur adresse définitive.
    lists: UnsafeCell<[ListEntry; TIMER_TABLE_SIZE]>,
    lists_ready: UnsafeCell<bool>,
    /// Emplacements (en ms d'interrupt time) entièrement écoulés et déjà
    /// expirés : ceux qui précèdent celui-ci (verrou dispatcher).
    expired_before: UnsafeCell<u64>,
    /// Bit `i` : la liste `i` contient un timer. Écrit verrou tenu.
    occupied: [AtomicU64; TIMER_TABLE_SIZE / 64],
    /// Emplacements entièrement écoulés et déjà examinés par [`scan`](Self::scan).
    scanned_before: AtomicU64,
}

// SAFETY: les champs `UnsafeCell` ne sont touchés que verrou dispatcher tenu
// (contrat des méthodes `unsafe`) ; les autres sont atomiques.
unsafe impl Sync for TimerTable {}

impl Default for TimerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerTable {
    pub const fn new() -> Self {
        Self {
            lists: UnsafeCell::new([const { ListEntry::new() }; TIMER_TABLE_SIZE]),
            lists_ready: UnsafeCell::new(false),
            expired_before: UnsafeCell::new(0),
            occupied: [const { AtomicU64::new(0) }; TIMER_TABLE_SIZE / 64],
            scanned_before: AtomicU64::new(0),
        }
    }

    /// Arme `timer` pour `deadline` (interrupt time). `false`, sans l'insérer, si
    /// `clock` l'a déjà atteinte, y compris juste après l'insertion : une ISR
    /// d'horloge survenue entre-temps a pu examiner l'emplacement avant qu'il soit
    /// marqué.
    ///
    /// # Safety
    /// Verrou dispatcher tenu ; `timer` est initialisé, hors de la roue, et garde
    /// son adresse tant qu'il y est.
    pub unsafe fn insert(&self, timer: *mut KTimer, deadline: u64, clock: impl Fn() -> u64) -> bool {
        if deadline <= clock() {
            return false;
        }
        let slot = slot_of(deadline / SLOT_TIME);
        // SAFETY: verrou tenu ; `timer` est valide et hors de toute liste.
        unsafe {
            ListEntry::insert_tail(self.list(slot), ptr::addr_of_mut!((*timer).timer_list_entry));
            (*timer).due_time = deadline;
            (*timer).header.inserted = 1;
        }
        self.occupied[slot / 64].fetch_or(1 << (slot % 64), Ordering::Relaxed);
        // L'ISR d'horloge, sur ce CPU, lit le bitmap : il est marqué avant la
        // relecture de l'heure.
        compiler_fence(Ordering::SeqCst);
        if deadline <= clock() {
            // SAFETY: inséré juste au-dessus, verrou tenu.
            unsafe { self.remove(timer) };
            return false;
        }
        true
    }

    /// Désarme `timer` ; `true` s'il était dans la roue.
    ///
    /// # Safety
    /// Verrou dispatcher tenu ; `timer` est initialisé.
    pub unsafe fn remove(&self, timer: *mut KTimer) -> bool {
        // SAFETY: verrou tenu ; inséré, `timer` est chaîné dans la liste de son
        // échéance.
        unsafe {
            if (*timer).header.inserted == 0 {
                return false;
            }
            (*timer).header.inserted = 0;
            ListEntry::remove(ptr::addr_of_mut!((*timer).timer_list_entry));
            self.release_if_empty(slot_of((*timer).due_time / SLOT_TIME));
        }
        true
    }

    /// Pour l'ISR d'horloge : `true` si un emplacement atteint par l'heure `now`
    /// depuis l'appel précédent contient un timer (échu, ou d'un tour suivant).
    ///
    /// # IRQL
    /// Tout niveau, sans verrou ; un seul appelant (l'ISR d'horloge).
    pub fn scan(&self, now: u64) -> bool {
        let first = self.scanned_before.load(Ordering::Relaxed);
        self.scanned_before.store(first.max((now + 1) / SLOT_TIME), Ordering::Relaxed);
        reached(first, now).any(|t| {
            let slot = slot_of(t);
            self.occupied[slot / 64].load(Ordering::Relaxed) & (1 << (slot % 64)) != 0
        })
    }

    /// Sort de la roue les timers échus à `now` (échéance `<= now`) et appelle
    /// `fire` pour chacun, dans l'ordre des emplacements. `fire` peut réarmer le
    /// timer qu'il reçoit, et seulement lui.
    ///
    /// # Safety
    /// Verrou dispatcher tenu.
    pub unsafe fn expire(&self, now: u64, mut fire: impl FnMut(*mut KTimer)) {
        // SAFETY (toute la fonction) : verrou tenu ; les listes ne contiennent que
        // des timers valides (contrat de `insert`).
        unsafe {
            let first = *self.expired_before.get();
            *self.expired_before.get() = first.max((now + 1) / SLOT_TIME);
            if !*self.lists_ready.get() {
                return;
            }
            let mut due = ListEntry::new();
            let due = ptr::addr_of_mut!(due);
            ListEntry::init(due);
            for t in reached(first, now) {
                let slot = slot_of(t);
                let head = self.list(slot);
                let mut entry = (*head).flink;
                while entry != head {
                    let next = (*entry).flink;
                    let timer = timer_of(entry);
                    if (*timer).due_time <= now {
                        (*timer).header.inserted = 0;
                        ListEntry::remove(entry);
                        ListEntry::insert_tail(due, entry);
                    }
                    entry = next;
                }
                self.release_if_empty(slot);
            }
            while !ListEntry::is_empty(due) {
                let entry = (*due).flink;
                ListEntry::remove(entry);
                fire(timer_of(entry));
            }
        }
    }

    /// `true` si aucun timer n'est armé.
    pub fn is_empty(&self) -> bool {
        self.occupied.iter().all(|w| w.load(Ordering::Relaxed) == 0)
    }

    /// Tête de la liste `slot`.
    ///
    /// # Safety
    /// Verrou dispatcher tenu.
    unsafe fn list(&self, slot: usize) -> *mut ListEntry {
        // SAFETY: verrou tenu ; la table garde son adresse (statique, ou fuie par
        // les tests) : les têtes initialisées ici ne bougent plus.
        unsafe {
            let lists = self.lists.get().cast::<ListEntry>();
            if !*self.lists_ready.get() {
                for i in 0..TIMER_TABLE_SIZE {
                    ListEntry::init(lists.add(i));
                }
                *self.lists_ready.get() = true;
            }
            lists.add(slot)
        }
    }

    /// Efface le bit de `slot` si sa liste est vide.
    ///
    /// # Safety
    /// Verrou dispatcher tenu.
    unsafe fn release_if_empty(&self, slot: usize) {
        // SAFETY: verrou tenu.
        if unsafe { ListEntry::is_empty(self.list(slot)) } {
            self.occupied[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::Relaxed);
        }
    }
}

/// Emplacements à examiner à l'heure `now` quand ceux d'avant `first` l'ont été :
/// jusqu'à celui qui contient `now`, au plus un tour de roue.
fn reached(first: u64, now: u64) -> core::ops::RangeInclusive<u64> {
    let last = now / SLOT_TIME;
    first.max((last + 1).saturating_sub(SLOTS))..=last
}

fn slot_of(t: u64) -> usize {
    (t % SLOTS) as usize
}

/// CONTAINING_RECORD d'un `KTimer` par son `timer_list_entry`.
///
/// # Safety
/// `entry` est le `timer_list_entry` d'un `KTimer` valide.
unsafe fn timer_of(entry: *mut ListEntry) -> *mut KTimer {
    // SAFETY: garanti par l'appelant.
    unsafe { entry.byte_sub(core::mem::offset_of!(KTimer, timer_list_entry)).cast() }
}

/// Expire les timers échus de `table` à l'heure `clock()` : chacun est signalé,
/// son DPC inséré, et il est réarmé s'il est périodique.
///
/// # Safety
/// Verrou dispatcher tenu ; `P::insert_timer` arme les timers dans `table`.
///
/// # IRQL
/// DISPATCH_LEVEL.
pub unsafe fn ki_expire_timers<P: Platform>(table: &TimerTable, clock: impl Fn() -> u64) {
    // SAFETY: garanti par l'appelant ; `expire` ne donne que des timers valides,
    // sortis de la roue.
    unsafe {
        table.expire(clock(), |timer| {
            ki_fire_timer::<P>(timer, |t, period| {
                // À la première échéance de la série encore à venir : `insert`
                // refuse une échéance passée.
                let mut next = (*t).due_time + period;
                while !table.insert(t, next, &clock) {
                    next += period;
                }
            })
        })
    };
}

/// Échéance de `timer`, hors de la roue : signalement, DPC, puis, s'il est
/// périodique, `rearm(timer, période en 100 ns)`.
///
/// # Safety
/// Verrou dispatcher tenu ; `timer` est valide, hors de la roue.
unsafe fn ki_fire_timer<P: Platform>(timer: *mut KTimer, rearm: impl FnOnce(*mut KTimer, u64)) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        ki_timer_expired::<P>(timer);
        if !(*timer).dpc.is_null() {
            // SAFETY: le DPC reste valide tant que le timer peut expirer (contrat
            // de `ke_set_timer`).
            ke_insert_queue_dpc((*timer).dpc, ptr::null_mut(), ptr::null_mut());
        }
        let period = (*timer).period.max(0) as u64 * SLOT_TIME;
        if period != 0 {
            rearm(timer, period);
        }
    }
}

// ── La roue du noyau ─────────────────────────────────────────────────────────

/// La roue de timers, commune aux processeurs comme celle d'XP : l'ADR-015 ne
/// demande par processeur que les files DPC et les files prêtes.
static TIMER_TABLE: TimerTable = TimerTable::new();

/// Le DPC d'expiration, pour la plateforme du noyau ([`init`]).
static EXPIRATION_DPC: Once<KDpc> = Once::new();

/// Branche l'expiration sur la plateforme `P` du noyau : l'horloge insère dès
/// lors le DPC d'expiration quand l'heure atteint un emplacement occupé.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn init<P: Platform>() {
    EXPIRATION_DPC.call_once(|| KDpc::new(ki_timer_expiration_dpc::<P>, ptr::null_mut()));
}

fn ki_timer_expiration_dpc<P: Platform>(_: *const KDpc, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    // SAFETY: à DISPATCH_LEVEL dans un DPC, le verrou n'est pas tenu ; la roue du
    // noyau est celle de `ki_insert_timer`, que la plateforme du noyau utilise.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        ki_expire_timers::<P>(&TIMER_TABLE, hal::timer::interrupt_time);
        DISPATCHER_LOCK.release::<P>(old_irql);
    }
}

/// `Platform::insert_timer` du noyau : arme `timer` dans la roue du noyau.
/// L'heure système vaut l'interrupt time tant que l'horloge temps réel n'est pas
/// lue (`hal::timer` écrit la même valeur dans KUSER_SHARED_DATA.SystemTime).
///
/// # Safety
/// Comme `Platform::insert_timer`.
///
/// # IRQL
/// DISPATCH_LEVEL, verrou dispatcher tenu.
pub unsafe fn ki_insert_timer(timer: *mut KTimer, due_time: i64) -> bool {
    let now = hal::timer::interrupt_time();
    // SAFETY: garanti par l'appelant.
    unsafe { TIMER_TABLE.insert(timer, deadline(due_time, now, now), hal::timer::interrupt_time) }
}

/// `Platform::cancel_timer` du noyau.
///
/// # Safety
/// Comme `Platform::cancel_timer`.
///
/// # IRQL
/// DISPATCH_LEVEL, verrou dispatcher tenu.
pub unsafe fn ki_cancel_timer(timer: *mut KTimer) {
    // SAFETY: garanti par l'appelant.
    unsafe { TIMER_TABLE.remove(timer) };
}

/// Partie timers de l'interruption d'horloge (`ke::clock`).
///
/// # IRQL
/// Dans l'ISR d'horloge.
pub(crate) fn ki_check_timers() {
    if TIMER_TABLE.scan(hal::timer::interrupt_time()) {
        if let Some(dpc) = EXPIRATION_DPC.get() {
            // SAFETY: le DPC est dans un statique.
            unsafe { ke_insert_queue_dpc(dpc, ptr::null_mut(), ptr::null_mut()) };
        }
    }
}

// ── Objets KTIMER ────────────────────────────────────────────────────────────

/// KeInitializeTimerEx : timer non armé, non signalé.
///
/// # Safety
/// `timer` est valide en écriture et garde son adresse ; aucun thread ne
/// l'attend.
///
/// # IRQL
/// Tout niveau.
pub unsafe fn ke_initialize_timer(timer: *mut KTimer, kind: ObjectType) {
    debug_assert!(matches!(kind, ObjectType::NotificationTimer | ObjectType::SynchronizationTimer));
    // SAFETY: garanti par l'appelant ; chaque champ est écrit par pointeur brut.
    unsafe {
        DispatcherHeader::init(ptr::addr_of_mut!((*timer).header), kind, 0);
        ptr::addr_of_mut!((*timer).due_time).write(0);
        ListEntry::init(ptr::addr_of_mut!((*timer).timer_list_entry));
        ptr::addr_of_mut!((*timer).period).write(0);
        ptr::addr_of_mut!((*timer).dpc).write(ptr::null());
    }
}

/// KeSetTimerEx : arme `timer` pour `due_time` (format NT), puis toutes les
/// `period_ms` millisecondes si ce n'est pas 0. À chaque échéance, le timer est
/// signalé et `dpc` (s'il n'est pas nul) est inséré. Retourne `true` si le
/// timer était déjà armé : il est réarmé.
///
/// # Safety
/// `timer` est initialisé ; lui et `dpc` gardent leur adresse tant que le timer
/// est armé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_set_timer<P: Platform>(timer: *mut KTimer, due_time: i64, period_ms: i32, dpc: *const KDpc) -> bool {
    debug_assert!(period_ms >= 0, "negative timer period");
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let was_set = (*timer).header.inserted != 0;
        P::cancel_timer(timer);
        (*timer).header.signal_state = 0;
        (*timer).header.absolute = u8::from(due_time > 0);
        (*timer).period = period_ms;
        (*timer).dpc = dpc;
        if !P::insert_timer(timer, due_time) {
            // Déjà échu : expire aussitôt ; une série périodique repart de
            // maintenant (l'insertion ne refuse une échéance relative que si
            // l'heure a avancé d'une période pendant l'insertion).
            ki_fire_timer::<P>(timer, |t, period| while !P::insert_timer(t, -(period as i64)) {});
        }
        DISPATCHER_LOCK.release::<P>(old_irql);
        was_set
    }
}

/// KeCancelTimer : `true` si le timer était armé. Son état signalé ne change
/// pas.
///
/// # Safety
/// `timer` est initialisé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_cancel_timer<P: Platform>(timer: *mut KTimer) -> bool {
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let was_set = (*timer).header.inserted != 0;
        P::cancel_timer(timer);
        DISPATCHER_LOCK.release::<P>(old_irql);
        was_set
    }
}

/// KeReadStateTimer : `true` si le timer est signalé.
///
/// # Safety
/// `timer` est initialisé.
///
/// # IRQL
/// Tout niveau.
pub unsafe fn ke_read_state_timer(timer: *const KTimer) -> bool {
    // SAFETY: garanti par l'appelant ; lecture d'un entier, comme KeReadStateTimer.
    unsafe { (*timer).header.signal_state != 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;
    use std::boxed::Box;
    use std::vec::Vec;

    use super::*;

    const MS: u64 = SLOT_TIME;
    /// Heure de départ : 1 s, un emplacement entier.
    const T0: u64 = 1_000 * MS;

    /// Timer initialisé, jamais libéré (la roue garde des pointeurs vers lui).
    fn timer() -> *mut KTimer {
        let t = Box::into_raw(Box::<KTimer>::new_uninit()).cast::<KTimer>();
        // SAFETY: mémoire fraîche, adresse stable.
        unsafe { ke_initialize_timer(t, ObjectType::NotificationTimer) };
        t
    }

    /// Roue neuve, à adresse stable. Un test n'a qu'un thread : il tient lieu de
    /// verrou dispatcher pour les appels `unsafe` ci-dessous.
    fn table() -> &'static TimerTable {
        Box::leak(Box::new(TimerTable::new()))
    }

    fn insert(table: &TimerTable, t: *mut KTimer, deadline: u64, now: u64) -> bool {
        // SAFETY: timer du test, hors de la roue ; un seul thread.
        unsafe { table.insert(t, deadline, || now) }
    }

    fn expire(table: &TimerTable, now: u64) -> Vec<*mut KTimer> {
        let mut fired = Vec::new();
        // SAFETY: un seul thread.
        unsafe { table.expire(now, |t| fired.push(t)) };
        fired
    }

    fn armed(t: *mut KTimer) -> bool {
        // SAFETY: timer du test.
        unsafe { (*t).header.inserted != 0 }
    }

    #[test]
    fn deadline_converts_relative_and_absolute_due_times() {
        let system_t0 = 120_000_000_000;
        assert_eq!(deadline(-5 * MS as i64, T0, system_t0), T0 + 5 * MS);
        assert_eq!(deadline((system_t0 + 7 * MS) as i64, T0, system_t0), T0 + 7 * MS);
        assert_eq!(deadline((system_t0 - 1) as i64, T0, system_t0), T0, "absolute, already past");
        assert_eq!(deadline(i64::MIN, T0, system_t0), T0 + (1 << 63), "no overflow");
    }

    #[test]
    fn a_deadline_already_reached_is_not_armed() {
        let (table, t) = (table(), timer());
        assert!(!insert(table, t, T0, T0));
        assert!(!insert(table, t, T0 - MS, T0));
        assert!(!armed(t));
        assert!(table.is_empty());
    }

    #[test]
    fn a_timer_expires_once_its_deadline_is_reached() {
        let (table, t) = (table(), timer());
        table.scan(T0);
        expire(table, T0);
        assert!(insert(table, t, T0 + 5 * MS, T0));
        assert!(armed(t));
        assert!(!table.scan(T0 + 4 * MS), "its slot is not reached yet");
        assert!(expire(table, T0 + 4 * MS).is_empty());
        assert!(table.scan(T0 + 5 * MS));
        assert_eq!(expire(table, T0 + 5 * MS), [t]);
        assert!(!armed(t));
        assert!(table.is_empty());
    }

    #[test]
    fn a_deadline_beyond_one_turn_waits_for_its_turn() {
        let (table, t) = (table(), timer());
        expire(table, T0);
        assert!(insert(table, t, T0 + 600 * MS, T0));
        assert!(expire(table, T0 + 88 * MS).is_empty(), "same slot, one turn earlier");
        assert!(armed(t));
        assert_eq!(expire(table, T0 + 600 * MS), [t]);
    }

    #[test]
    fn expiration_catches_up_after_missed_ticks() {
        let (table, a, b, c) = (table(), timer(), timer(), timer());
        expire(table, T0);
        assert!(insert(table, c, T0 + 600 * MS, T0));
        assert!(insert(table, b, T0 + 3 * MS, T0));
        assert!(insert(table, a, T0 + MS, T0));
        assert_eq!(expire(table, T0 + 700 * MS), [a, b, c], "every slot once, in deadline order");
        assert!(table.is_empty());
    }

    #[test]
    fn a_deadline_later_in_the_current_millisecond_is_not_skipped() {
        let (table, t) = (table(), timer());
        table.scan(T0 + MS / 2);
        expire(table, T0 + MS / 2);
        assert!(insert(table, t, T0 + 3 * MS / 4, T0 + MS / 2));
        assert!(table.scan(T0 + MS), "its slot was not over at the previous scan");
        assert_eq!(expire(table, T0 + MS), [t], "nor at the previous expiration");
    }

    #[test]
    fn remove_disarms_and_frees_the_slot() {
        let (table, t) = (table(), timer());
        assert!(insert(table, t, T0 + MS, T0));
        // SAFETY: timer du test ; un seul thread.
        unsafe {
            assert!(table.remove(t));
            assert!(!table.remove(t), "no longer armed");
        }
        assert!(!armed(t));
        assert!(table.is_empty());
        assert!(expire(table, T0 + MS).is_empty());
    }

    /// Une ISR d'horloge entre la lecture de l'heure et le marquage de
    /// l'emplacement a pu l'examiner trop tôt : le timer compte comme échu.
    #[test]
    fn a_tick_during_the_insertion_counts_as_expiry() {
        let (table, t) = (table(), timer());
        let reads = Cell::new(0);
        let clock = || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                T0
            } else {
                T0 + 5 * MS
            }
        };
        // SAFETY: timer du test, hors de la roue ; un seul thread.
        assert!(!unsafe { table.insert(t, T0 + 5 * MS, clock) });
        assert!(!armed(t));
        assert!(table.is_empty());
    }
}
