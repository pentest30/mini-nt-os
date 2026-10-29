//! DPC (appels de procédure différés) : une file par CPU, qui n'alloue jamais
//! (02 §Ke, audit §3).
//!
//! Le KDPC appartient à l'appelant (statique, objet, extension de périphérique)
//! et se chaîne dans la file par ses propres champs : l'insertion n'alloue pas et
//! se fait à tout IRQL, ISR comprise. La file est vidée par l'interruption
//! DISPATCH ([`ki_dispatch_interrupt`]) dès que l'IRQL passe sous DISPATCH_LEVEL :
//! chaque routine s'exécute à DISPATCH_LEVEL, interruptions actives.
//!
//! Un seul CPU pour l'instant : la file passera dans le KPRCB (ADR-015).

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr;

use hal::sync::IrqLock;

/// Routine d'un DPC : `(dpc, contexte, argument système 1, argument système 2)`.
pub type DpcRoutine = fn(dpc: *const KDpc, context: *mut c_void, arg1: *mut c_void, arg2: *mut c_void);

/// KDPC. Il garde son adresse tant qu'il est dans la file.
pub struct KDpc {
    routine: DpcRoutine,
    context: *mut c_void,
    /// Chaînage et arguments, touchés seulement sous le verrou de la file.
    link: UnsafeCell<DpcLink>,
}

struct DpcLink {
    next: *const KDpc,
    prev: *const KDpc,
    queued: bool,
    arg1: *mut c_void,
    arg2: *mut c_void,
}

// SAFETY: `routine` et `context` ne changent plus après `new` ; `link` n'est lu
// ou écrit que par le détenteur de la file où le DPC est inséré.
unsafe impl Sync for KDpc {}
// SAFETY: un KDPC n'est lié à aucun thread : `context` est opaque, à la charge
// de sa routine.
unsafe impl Send for KDpc {}

impl KDpc {
    /// KeInitializeDpc.
    pub const fn new(routine: DpcRoutine, context: *mut c_void) -> Self {
        Self {
            routine,
            context,
            link: UnsafeCell::new(DpcLink {
                next: ptr::null(),
                prev: ptr::null(),
                queued: false,
                arg1: ptr::null_mut(),
                arg2: ptr::null_mut(),
            }),
        }
    }
}

/// File de DPC d'un CPU, doublement chaînée par les KDPC eux-mêmes (FIFO).
pub struct DpcQueue {
    head: *const KDpc,
    tail: *const KDpc,
}

// SAFETY: la file ne contient que des KDPC valides (contrat de `insert`), qui
// sont `Sync`.
unsafe impl Send for DpcQueue {}

impl Default for DpcQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl DpcQueue {
    pub const fn new() -> Self {
        Self { head: ptr::null(), tail: ptr::null() }
    }

    /// Ajoute `dpc` en queue avec ses arguments ; `false` s'il y est déjà (ses
    /// arguments ne changent pas).
    ///
    /// # Safety
    /// `dpc` est valide et garde son adresse jusqu'à ce qu'il sorte de la file ;
    /// il n'est jamais inséré dans une autre file.
    pub unsafe fn insert(&mut self, dpc: *const KDpc, arg1: *mut c_void, arg2: *mut c_void) -> bool {
        // SAFETY: `dpc` est valide (appelant) ; `&mut self` donne l'accès exclusif
        // aux chaînages des DPC de cette file, dont la queue actuelle.
        unsafe {
            let link = &mut *(*dpc).link.get();
            if link.queued {
                return false;
            }
            *link = DpcLink { next: ptr::null(), prev: self.tail, queued: true, arg1, arg2 };
            if self.tail.is_null() {
                self.head = dpc;
            } else {
                (*(*self.tail).link.get()).next = dpc;
            }
        }
        self.tail = dpc;
        true
    }

    /// Retire `dpc` ; `true` s'il était dans la file.
    ///
    /// # Safety
    /// `dpc` est valide ; il n'est jamais inséré dans une autre file.
    pub unsafe fn remove(&mut self, dpc: *const KDpc) -> bool {
        // SAFETY: `dpc` est valide (appelant) ; ses voisins sont dans cette file,
        // donc valides, et `&mut self` en donne l'accès exclusif.
        unsafe {
            let link = &mut *(*dpc).link.get();
            if !link.queued {
                return false;
            }
            link.queued = false;
            if link.prev.is_null() {
                self.head = link.next;
            } else {
                (*(*link.prev).link.get()).next = link.next;
            }
            if link.next.is_null() {
                self.tail = link.prev;
            } else {
                (*(*link.next).link.get()).prev = link.prev;
            }
        }
        true
    }

    /// Sort le premier DPC avec ses arguments ; il peut aussitôt être réinséré.
    pub fn pop(&mut self) -> Option<(*const KDpc, *mut c_void, *mut c_void)> {
        let dpc = self.head;
        if dpc.is_null() {
            return None;
        }
        // SAFETY: les DPC de la file sont valides (contrat de `insert`) ; `&mut
        // self` donne l'accès exclusif à leurs chaînages.
        unsafe {
            let link = &*(*dpc).link.get();
            let args = (link.arg1, link.arg2);
            self.remove(dpc);
            Some((dpc, args.0, args.1))
        }
    }
}

/// La file de DPC du CPU. Les ISR y insèrent : elle se prend interruptions
/// masquées.
static DPC_QUEUE: IrqLock<DpcQueue> = IrqLock::new(DpcQueue::new());

/// KeInsertQueueDpc : la routine s'exécutera à DISPATCH_LEVEL, dès que l'IRQL
/// passera sous DISPATCH_LEVEL (aussitôt si l'appelant y est déjà). `false` si
/// le DPC est déjà dans la file : il ne s'exécutera qu'une fois, avec ses
/// premiers arguments.
///
/// # Safety
/// `dpc` est valide et garde son adresse jusqu'à l'exécution de sa routine ou
/// son retrait.
///
/// # IRQL
/// Tout niveau, ISR comprise.
pub unsafe fn ke_insert_queue_dpc(dpc: *const KDpc, arg1: *mut c_void, arg2: *mut c_void) -> bool {
    // SAFETY: garanti par l'appelant ; une seule file existe.
    let inserted = DPC_QUEUE.with(|q| unsafe { q.insert(dpc, arg1, arg2) });
    if inserted {
        hal::irql::request_dispatch();
    }
    inserted
}

/// KeRemoveQueueDpc : `true` si le DPC était dans la file, et sa routine ne
/// s'exécutera pas.
///
/// # Safety
/// `dpc` est valide.
///
/// # IRQL
/// Tout niveau, ISR comprise.
pub unsafe fn ke_remove_queue_dpc(dpc: *const KDpc) -> bool {
    // SAFETY: garanti par l'appelant ; une seule file existe.
    DPC_QUEUE.with(|q| unsafe { q.remove(dpc) })
}

/// L'interruption DISPATCH, crochet de `hal::irql` : vide la file de DPC, puis
/// commute de thread si une fin de quantum l'a demandé.
///
/// # IRQL
/// DISPATCH_LEVEL, interruptions masquées à l'entrée et à la sortie.
pub fn ki_dispatch_interrupt() {
    ki_retire_dpc_list();
    if crate::sched::take_reschedule() {
        crate::sched::schedule();
    }
}

/// Exécute les DPC de la file jusqu'à la vider, y compris ceux insérés pendant
/// ce temps.
pub(crate) fn ki_retire_dpc_list() {
    while let Some((dpc, arg1, arg2)) = DPC_QUEUE.with(DpcQueue::pop) {
        // SAFETY: un DPC reste valide jusqu'à l'exécution de sa routine (contrat
        // de `ke_insert_queue_dpc`).
        let (routine, context) = unsafe { ((*dpc).routine, (*dpc).context) };
        with_interrupts_enabled(|| routine(dpc, context, arg1, arg2));
    }
}

/// Les routines de DPC s'exécutent interruptions actives : une ISR qui survient
/// à DISPATCH_LEVEL laisse l'interruption DISPATCH en attente (`hal::irql`). Sur
/// l'hôte (tests), `f` s'exécute tel quel.
fn with_interrupts_enabled(f: impl FnOnce()) {
    if cfg!(target_os = "none") {
        x86_64::instructions::interrupts::enable();
        f();
        x86_64::instructions::interrupts::disable();
    } else {
        f();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::vec::Vec;

    use super::*;

    /// Les tests hôte s'exécutent en parallèle : ceux qui passent par la file
    /// globale la prennent tour à tour.
    pub(crate) static GLOBAL_QUEUE: Mutex<()> = Mutex::new(());

    fn nop(_: *const KDpc, _: *mut c_void, _: *mut c_void, _: *mut c_void) {}

    fn arg(n: usize) -> *mut c_void {
        ptr::without_provenance_mut(n)
    }

    fn drain(q: &mut DpcQueue) -> Vec<(*const KDpc, usize)> {
        core::iter::from_fn(|| q.pop()).map(|(d, a1, _)| (d, a1 as usize)).collect()
    }

    #[test]
    fn pops_in_insertion_order_with_their_arguments() {
        let (a, b, c) =
            (KDpc::new(nop, ptr::null_mut()), KDpc::new(nop, ptr::null_mut()), KDpc::new(nop, ptr::null_mut()));
        let mut q = DpcQueue::new();
        // SAFETY: les DPC vivent plus longtemps que la file, qui est la seule.
        unsafe {
            assert!(q.insert(&a, arg(1), arg(0)));
            assert!(q.insert(&b, arg(2), arg(0)));
            assert!(q.insert(&c, arg(3), arg(0)));
        }
        assert_eq!(drain(&mut q), [(&a as *const _, 1), (&b as *const _, 2), (&c as *const _, 3)]);
    }

    #[test]
    fn a_queued_dpc_is_not_queued_twice() {
        let a = KDpc::new(nop, ptr::null_mut());
        let mut q = DpcQueue::new();
        // SAFETY: comme ci-dessus.
        unsafe {
            assert!(q.insert(&a, arg(1), arg(0)));
            assert!(!q.insert(&a, arg(2), arg(0)), "already queued");
        }
        assert_eq!(drain(&mut q), [(&a as *const _, 1)], "once, with its first arguments");
        // SAFETY: comme ci-dessus.
        assert!(unsafe { q.insert(&a, arg(3), arg(0)) }, "out of the queue, it can be queued again");
    }

    #[test]
    fn remove_unlinks_at_the_head_in_the_middle_and_at_the_tail() {
        let d: [KDpc; 5] = core::array::from_fn(|_| KDpc::new(nop, ptr::null_mut()));
        let mut q = DpcQueue::new();
        // SAFETY: comme ci-dessus.
        unsafe {
            for (i, dpc) in d.iter().enumerate() {
                q.insert(dpc, arg(i), arg(0));
            }
            assert!(q.remove(&d[0]));
            assert!(q.remove(&d[2]));
            assert!(q.remove(&d[4]));
            assert!(!q.remove(&d[4]), "no longer queued");
            assert!(q.insert(&d[0], arg(5), arg(0)), "after the new tail");
        }
        assert_eq!(drain(&mut q), [(&d[1] as *const _, 1), (&d[3] as *const _, 3), (&d[0] as *const _, 5)]);
        // SAFETY: comme ci-dessus.
        assert!(!unsafe { q.remove(&d[1]) }, "popped");
    }

    #[test]
    fn retiring_the_queue_runs_each_routine_with_its_context_and_arguments() {
        let _queue = GLOBAL_QUEUE.lock().unwrap();
        static SUM: AtomicUsize = AtomicUsize::new(0);
        fn add(dpc: *const KDpc, context: *mut c_void, arg1: *mut c_void, arg2: *mut c_void) {
            assert!(!dpc.is_null());
            SUM.fetch_add(context as usize * (arg1 as usize + arg2 as usize), Ordering::Relaxed);
        }
        let a = KDpc::new(add, arg(10));
        let b = KDpc::new(add, arg(100));
        let removed = KDpc::new(add, arg(1000));
        // SAFETY: les DPC vivent jusqu'à la fin du test, où la file est vide.
        unsafe {
            assert!(ke_insert_queue_dpc(&a, arg(1), arg(2)));
            assert!(ke_insert_queue_dpc(&b, arg(3), arg(4)));
            assert!(ke_insert_queue_dpc(&removed, arg(1), arg(0)));
            assert!(ke_remove_queue_dpc(&removed));
        }
        ki_retire_dpc_list();
        assert_eq!(SUM.load(Ordering::Relaxed), 10 * 3 + 100 * 7);
        assert!(DPC_QUEUE.with(|q| q.pop()).is_none());
    }
}
