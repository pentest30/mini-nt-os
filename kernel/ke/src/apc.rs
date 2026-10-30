//! APC (02 §Ke) : appels de procédure asynchrones, qui exécutent du code dans le
//! contexte d'un thread donné.
//!
//! - APC noyau spécial (sans routine normale) : sa routine noyau seule, à
//!   APC_LEVEL. Il passe avant les APC normaux ; seule une région gardée
//!   ([`ke_enter_guarded_region`]) le retient.
//! - APC noyau normal : sa routine noyau à APC_LEVEL, qui peut changer ou
//!   annuler la suite, puis sa routine normale à PASSIVE_LEVEL. Une région
//!   critique ([`ke_enter_critical_region`]) le retient, comme la routine
//!   normale d'un autre APC normal en cours.
//! - APC utilisateur : mis en file ici, il défait une attente alertable en mode
//!   utilisateur ; sa livraison au retour en mode utilisateur
//!   (`ntdll!KiUserApcDispatcher`) vient au M3.
//!
//! Un APC noyau mis en file pour le thread courant se livre dès que l'IRQL
//! passe sous APC_LEVEL (interruption APC de la HAL, [`ki_deliver_apc`]). Pour
//! un thread qui attend à PASSIVE_LEVEL, l'attente est défaite
//! (STATUS_KERNEL_APC) : l'APC est livré à sa reprise, puis l'attente relancée.
//! Pour un thread prêt, à sa prochaine reprise.
//!
//! Les files et l'état APC des threads (`dispatcher::KThread`) sont sous le
//! verrou dispatcher. Rien n'est alloué : l'appelant fournit le [`KApc`], qui
//! reste valide jusqu'à l'appel de sa routine noyau ou son retrait de la file.
//!
//! Pas encore : rundown des APC d'un thread qui se termine (Ps, M2) ; ils
//! restent en file.

use core::ffi::c_void;
use core::ptr;

use hal::irql::Irql;

use crate::dispatcher::{
    containing_record, ki_try_unwait_for_user_apc, ki_unwait_for_kernel_apc, KThread, ListEntry, Platform,
    ProcessorMode, ThreadState, DISPATCHER_LOCK,
};

/// Routine noyau d'un APC, à APC_LEVEL. Elle peut changer la routine normale
/// (ou l'annuler en la mettant à `None`), son contexte et ses arguments.
pub type KernelRoutine = fn(
    apc: *mut KApc,
    normal_routine: &mut Option<NormalRoutine>,
    normal_context: &mut *mut c_void,
    argument1: &mut *mut c_void,
    argument2: &mut *mut c_void,
);

/// Routine normale d'un APC : à PASSIVE_LEVEL pour un APC noyau, en mode
/// utilisateur pour un APC utilisateur.
pub type NormalRoutine = fn(normal_context: *mut c_void, argument1: *mut c_void, argument2: *mut c_void);

/// Routine appelée à la place de la routine noyau quand un APC ne peut plus
/// être livré (son thread se termine).
pub type RundownRoutine = fn(apc: *mut KApc);

/// KAPC : un APC, à mettre en file pour un thread par [`ke_insert_queue_apc`].
#[repr(C)]
pub struct KApc {
    apc_list_entry: ListEntry,
    thread: *mut KThread,
    kernel_routine: KernelRoutine,
    rundown_routine: Option<RundownRoutine>,
    normal_routine: Option<NormalRoutine>,
    normal_context: *mut c_void,
    system_argument1: *mut c_void,
    system_argument2: *mut c_void,
    apc_mode: ProcessorMode,
    inserted: bool,
}

impl KApc {
    /// KeInitializeApc : un APC pour `thread`. Sans routine normale, c'est un
    /// APC noyau spécial : `mode` et `normal_context` sont ignorés.
    pub const fn new(
        thread: *mut KThread,
        kernel_routine: KernelRoutine,
        rundown_routine: Option<RundownRoutine>,
        normal_routine: Option<NormalRoutine>,
        mode: ProcessorMode,
        normal_context: *mut c_void,
    ) -> Self {
        let special = normal_routine.is_none();
        Self {
            apc_list_entry: ListEntry::new(),
            thread,
            kernel_routine,
            rundown_routine,
            normal_routine,
            normal_context: if special { ptr::null_mut() } else { normal_context },
            system_argument1: ptr::null_mut(),
            system_argument2: ptr::null_mut(),
            apc_mode: if special { ProcessorMode::Kernel } else { mode },
            inserted: false,
        }
    }

    /// APC noyau spécial : sans routine normale.
    fn is_special(&self) -> bool {
        self.apc_mode == ProcessorMode::Kernel && self.normal_routine.is_none()
    }

    /// L'APC est en file.
    ///
    /// # IRQL
    /// Tout niveau ; une lecture sans verrou, à confirmer sous le verrou
    /// dispatcher si un autre processeur peut le livrer.
    pub fn is_inserted(&self) -> bool {
        self.inserted
    }

    /// La routine appelée si l'APC ne peut plus être livré.
    pub fn rundown_routine(&self) -> Option<RundownRoutine> {
        self.rundown_routine
    }
}

/// L'APC dont `entry` est le chaînage.
///
/// # Safety
/// `entry` est le `apc_list_entry` d'un [`KApc`] valide.
unsafe fn apc_of(entry: *mut ListEntry) -> *mut KApc {
    // SAFETY: garanti par l'appelant.
    unsafe { containing_record!(entry, KApc, apc_list_entry) }
}

/// Un APC noyau, spécial ou non, peut être livré à `thread` maintenant.
///
/// # Safety
/// Verrou dispatcher tenu ; `thread` est valide.
unsafe fn deliverable(thread: *mut KThread, special: bool) -> bool {
    // SAFETY: garanti par l'appelant.
    unsafe {
        (*thread).special_apc_disable == 0
            && (special || ((*thread).kernel_apc_disable == 0 && !(*thread).kernel_apc_in_progress))
    }
}

/// KeInsertQueueApc : met `apc` en file pour son thread, avec ses deux
/// arguments système ; `false` s'il y est déjà ou si le thread ne reçoit plus
/// d'APC (terminé). Un APC spécial passe après les spéciaux déjà en file et
/// avant les normaux ; un normal, en queue. Un thread que l'APC réveille est
/// relevé d'`increment`.
///
/// # Safety
/// `apc` est initialisé ([`KApc::new`]) pour un thread valide, à adresse
/// stable, et reste valide jusqu'à l'appel de sa routine noyau ou son retrait
/// de la file.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_insert_queue_apc<P: Platform>(
    apc: *mut KApc,
    argument1: *mut c_void,
    argument2: *mut c_void,
    increment: u8,
) -> bool {
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release ; les
    // entrées des files d'APC sont celles de KApc valides.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let thread = (*apc).thread;
        if (*apc).inserted || !(*thread).apc_queueable {
            DISPATCHER_LOCK.release::<P>(old_irql);
            return false;
        }
        (*apc).system_argument1 = argument1;
        (*apc).system_argument2 = argument2;
        (*apc).inserted = true;
        let mode = (*apc).apc_mode;
        let special = (*apc).is_special();
        let head = ptr::addr_of_mut!((*thread).apc_list_head[mode as usize]);
        let mut before = head;
        if special {
            before = (*head).flink;
            while before != head && (*apc_of(before)).is_special() {
                before = (*before).flink;
            }
        }
        // Chaîné juste avant `before` : en queue si c'est la tête.
        ListEntry::insert_tail(before, ptr::addr_of_mut!((*apc).apc_list_entry));

        match mode {
            ProcessorMode::Kernel => {
                (*thread).kernel_apc_pending = true;
                if thread == P::current_thread() {
                    // Livré quand l'IRQL passera sous APC_LEVEL (au plus tard
                    // à la libération du verrou).
                    P::request_apc_interrupt();
                } else if (*thread).state == ThreadState::Waiting
                    && (*thread).wait_irql == Irql::Passive
                    && deliverable(thread, special)
                {
                    ki_unwait_for_kernel_apc::<P>(thread, increment);
                }
            }
            ProcessorMode::User => ki_try_unwait_for_user_apc::<P>(thread, increment),
        }
        DISPATCHER_LOCK.release::<P>(old_irql);
        true
    }
}

/// KeRemoveQueueApc : retire `apc` de la file de son thread ; `false` s'il n'y
/// était pas.
///
/// # Safety
/// `apc` est initialisé pour un thread valide.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub unsafe fn ke_remove_queue_apc<P: Platform>(apc: *mut KApc) -> bool {
    // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        let inserted = (*apc).inserted;
        if inserted {
            ListEntry::remove(ptr::addr_of_mut!((*apc).apc_list_entry));
            (*apc).inserted = false;
            let thread = (*apc).thread;
            let mode = (*apc).apc_mode;
            if ListEntry::is_empty(ptr::addr_of!((*thread).apc_list_head[mode as usize])) {
                match mode {
                    ProcessorMode::Kernel => (*thread).kernel_apc_pending = false,
                    ProcessorMode::User => (*thread).user_apc_pending = false,
                }
            }
        }
        DISPATCHER_LOCK.release::<P>(old_irql);
        inserted
    }
}

/// KiDeliverApc : livre les APC noyau du thread courant, les spéciaux puis les
/// normaux, chacun dans l'ordre de sa file, jusqu'au premier retenu (région
/// critique ou gardée, routine normale en cours). Pour un APC normal, la
/// routine noyau s'exécute à APC_LEVEL, puis la routine normale qu'elle a
/// laissée à PASSIVE_LEVEL ; un APC spécial peut s'y livrer à son tour.
///
/// # Safety
/// Le thread courant a été initialisé (`KThread::init`).
///
/// # IRQL
/// APC_LEVEL, interruptions actives (interruption APC de la HAL).
pub unsafe fn ki_deliver_apc<P: Platform>() {
    let thread = P::current_thread();
    loop {
        // SAFETY: le thread courant est valide (garanti par l'appelant) ; verrou
        // tenu de acquire à release ; la file noyau ne contient que des KApc
        // valides (contrat de `ke_insert_queue_apc`).
        let (apc, special, kernel_routine, mut normal, mut context, mut argument1, mut argument2) = unsafe {
            let old_irql = DISPATCHER_LOCK.acquire::<P>();
            (*thread).kernel_apc_pending = false;
            let head = ptr::addr_of_mut!((*thread).apc_list_head[ProcessorMode::Kernel as usize]);
            if ListEntry::is_empty(head) {
                DISPATCHER_LOCK.release::<P>(old_irql);
                return;
            }
            let apc = apc_of((*head).flink);
            let special = (*apc).is_special();
            if !deliverable(thread, special) {
                // La sortie de la région, ou la fin de la routine normale en
                // cours, redemandera la livraison.
                DISPATCHER_LOCK.release::<P>(old_irql);
                return;
            }
            ListEntry::remove(ptr::addr_of_mut!((*apc).apc_list_entry));
            (*apc).inserted = false;
            if !special {
                (*thread).kernel_apc_in_progress = true;
            }
            let fields = (
                apc,
                special,
                (*apc).kernel_routine,
                (*apc).normal_routine,
                (*apc).normal_context,
                (*apc).system_argument1,
                (*apc).system_argument2,
            );
            DISPATCHER_LOCK.release::<P>(old_irql);
            fields
        };
        // L'APC n'est plus en file : sa routine noyau peut le libérer.
        kernel_routine(apc, &mut normal, &mut context, &mut argument1, &mut argument2);
        if special {
            continue;
        }
        if let Some(normal) = normal {
            P::lower_irql(Irql::Passive);
            normal(context, argument1, argument2);
            P::raise_irql(Irql::Apc);
        }
        // SAFETY: comme plus haut.
        unsafe {
            let old_irql = DISPATCHER_LOCK.acquire::<P>();
            (*thread).kernel_apc_in_progress = false;
            DISPATCHER_LOCK.release::<P>(old_irql);
        }
    }
}

/// Après la sortie d'une région ou la fin d'une routine normale : demande la
/// livraison des APC noyau du thread courant s'il en reste. Verrou tenu.
///
/// # Safety
/// Verrou dispatcher tenu ; `thread` est le thread courant.
unsafe fn ki_check_for_kernel_apc_delivery<P: Platform>(thread: *mut KThread) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        if !ListEntry::is_empty(ptr::addr_of!((*thread).apc_list_head[ProcessorMode::Kernel as usize])) {
            (*thread).kernel_apc_pending = true;
            P::request_apc_interrupt();
        }
    }
}

/// Change, verrou tenu, l'état APC du thread courant par `f`, puis demande la
/// livraison de ses APC noyau si `f` le dit.
fn with_current_thread<P: Platform>(f: impl FnOnce(*mut KThread) -> bool) {
    let thread = P::current_thread();
    // SAFETY: le thread courant est valide (contrat de `Platform`) ; verrou
    // tenu de acquire à release.
    unsafe {
        let old_irql = DISPATCHER_LOCK.acquire::<P>();
        if f(thread) {
            ki_check_for_kernel_apc_delivery::<P>(thread);
        }
        DISPATCHER_LOCK.release::<P>(old_irql);
    }
}

/// KeEnterCriticalRegion : les APC noyau normaux du thread courant attendent
/// jusqu'à la sortie correspondante.
///
/// # IRQL
/// <= APC_LEVEL.
pub fn ke_enter_critical_region<P: Platform>() {
    with_current_thread::<P>(|thread| {
        // SAFETY: verrou tenu, thread courant valide (`with_current_thread`).
        unsafe { (*thread).kernel_apc_disable += 1 };
        false
    });
}

/// KeLeaveCriticalRegion : la sortie la plus externe livre les APC noyau
/// retenus.
///
/// # Panics
/// Hors de toute région critique.
///
/// # IRQL
/// <= APC_LEVEL.
pub fn ke_leave_critical_region<P: Platform>() {
    with_current_thread::<P>(|thread| {
        // SAFETY: verrou tenu, thread courant valide (`with_current_thread`).
        unsafe {
            assert!((*thread).kernel_apc_disable > 0, "leaving a critical region never entered");
            (*thread).kernel_apc_disable -= 1;
            (*thread).kernel_apc_disable == 0 && (*thread).special_apc_disable == 0
        }
    });
}

/// KeEnterGuardedRegion : tous les APC noyau du thread courant attendent
/// jusqu'à la sortie correspondante.
///
/// # IRQL
/// <= APC_LEVEL.
pub fn ke_enter_guarded_region<P: Platform>() {
    with_current_thread::<P>(|thread| {
        // SAFETY: verrou tenu, thread courant valide (`with_current_thread`).
        unsafe { (*thread).special_apc_disable += 1 };
        false
    });
}

/// KeLeaveGuardedRegion : la sortie la plus externe livre les APC noyau
/// retenus.
///
/// # Panics
/// Hors de toute région gardée.
///
/// # IRQL
/// <= APC_LEVEL.
pub fn ke_leave_guarded_region<P: Platform>() {
    with_current_thread::<P>(|thread| {
        // SAFETY: verrou tenu, thread courant valide (`with_current_thread`).
        unsafe {
            assert!((*thread).special_apc_disable > 0, "leaving a guarded region never entered");
            (*thread).special_apc_disable -= 1;
            (*thread).special_apc_disable == 0
        }
    });
}

/// KeAreApcsDisabled : le thread courant est dans une région critique ou
/// gardée.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn ke_are_apcs_disabled<P: Platform>() -> bool {
    let mut disabled = false;
    with_current_thread::<P>(|thread| {
        // SAFETY: verrou tenu, thread courant valide (`with_current_thread`).
        disabled = unsafe { (*thread).kernel_apc_disable != 0 || (*thread).special_apc_disable != 0 };
        false
    });
    disabled
}

/// L'interruption APC du noyau (`hal::irql::set_apc_hook`) : livre les APC
/// noyau du thread courant.
///
/// # IRQL
/// APC_LEVEL, interruptions actives.
pub fn ki_apc_interrupt() {
    // SAFETY: l'interruption APC ne survient qu'après `ke::init`, sur un thread
    // de l'ordonnanceur.
    unsafe { ki_deliver_apc::<crate::sched::KePlatform>() };
}
