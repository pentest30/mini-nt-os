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
//! - APC utilisateur : sa routine normale est une adresse du mode
//!   utilisateur. Il défait une attente alertable en mode utilisateur, qui
//!   rend STATUS_USER_APC. Le thread ne le reçoit qu'après une attente
//!   alertable ou un test d'alerte ([`ke_test_alert_thread`]), au retour en
//!   mode utilisateur ([`ki_deliver_user_apc`]) : sa routine noyau, à
//!   APC_LEVEL, puis `ntdll!KiUserApcDispatcher`, qui appelle la routine
//!   normale puis NtContinue avec le contexte interrompu, en testant l'alerte
//!   pour livrer le suivant.
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
//! Un thread qui se termine ne reçoit plus d'APC, et ceux qui restaient en
//! file passent à leur routine de rundown ([`ke_rundown_apcs`], appelé par
//! Ps).

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::ntstatus::NtStatus;
use hal::irql::Irql;
use hal::trap::KTrapFrame;

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

/// Routine normale d'un APC noyau, à PASSIVE_LEVEL.
pub type KernelNormalRoutine = fn(normal_context: *mut c_void, argument1: *mut c_void, argument2: *mut c_void);

/// Routine normale d'un APC.
#[derive(Clone, Copy, Debug)]
pub enum NormalRoutine {
    /// Une fonction du noyau, pour un APC noyau.
    Kernel(KernelNormalRoutine),
    /// L'adresse d'une routine du mode utilisateur, pour un APC utilisateur :
    /// `routine(normal_context, argument1, argument2)`, en stdcall.
    User(u32),
}

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
    ///
    /// # Panics
    /// Si la routine normale n'est pas du mode de l'APC.
    pub const fn new(
        thread: *mut KThread,
        kernel_routine: KernelRoutine,
        rundown_routine: Option<RundownRoutine>,
        normal_routine: Option<NormalRoutine>,
        mode: ProcessorMode,
        normal_context: *mut c_void,
    ) -> Self {
        let special = normal_routine.is_none();
        assert!(
            matches!(
                (normal_routine, mode),
                (None, _)
                    | (Some(NormalRoutine::Kernel(_)), ProcessorMode::Kernel)
                    | (Some(NormalRoutine::User(_)), ProcessorMode::User)
            ),
            "the normal routine of an APC runs in its mode"
        );
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

/// Rundown des APC de `thread`, qui se termine (PspExitThread) : il n'en
/// reçoit plus ([`ke_insert_queue_apc`] rend `false`), et chaque APC encore en
/// file, noyau puis utilisateur, en est retiré puis passé à sa routine de
/// rundown s'il en a une, verrou relâché. Un APC sans routine de rundown est
/// seulement retiré : il revient à qui l'a fourni. Rend le nombre d'APC
/// retirés.
///
/// # Safety
/// `thread` est valide ; les APC en file le sont aussi (contrat de
/// [`ke_insert_queue_apc`]).
///
/// # IRQL
/// <= APC_LEVEL.
pub unsafe fn ke_rundown_apcs<P: Platform>(thread: *mut KThread) -> usize {
    let mut count = 0;
    loop {
        // SAFETY: garanti par l'appelant ; verrou tenu de acquire à release ;
        // les entrées des files d'APC sont celles de KApc valides.
        let apc = unsafe {
            let old_irql = DISPATCHER_LOCK.acquire::<P>();
            (*thread).apc_queueable = false;
            let mut apc = ptr::null_mut::<KApc>();
            for mode in [ProcessorMode::Kernel, ProcessorMode::User] {
                let head = ptr::addr_of_mut!((*thread).apc_list_head[mode as usize]);
                if !ListEntry::is_empty(head) {
                    let entry = (*head).flink;
                    ListEntry::remove(entry);
                    apc = apc_of(entry);
                    (*apc).inserted = false;
                    break;
                }
            }
            if ListEntry::is_empty(ptr::addr_of!((*thread).apc_list_head[ProcessorMode::Kernel as usize])) {
                (*thread).kernel_apc_pending = false;
            }
            if ListEntry::is_empty(ptr::addr_of!((*thread).apc_list_head[ProcessorMode::User as usize])) {
                (*thread).user_apc_pending = false;
            }
            DISPATCHER_LOCK.release::<P>(old_irql);
            apc
        };
        if apc.is_null() {
            return count;
        }
        count += 1;
        // SAFETY: l'APC, retiré de la file, est encore valide (contrat).
        if let Some(rundown) = unsafe { (*apc).rundown_routine } {
            rundown(apc);
        }
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
        match normal {
            Some(NormalRoutine::Kernel(normal)) => {
                P::lower_irql(Irql::Passive);
                normal(context, argument1, argument2);
                P::raise_irql(Irql::Apc);
            }
            Some(NormalRoutine::User(_)) => panic!("a kernel APC with a user-mode normal routine"),
            None => {}
        }
        // SAFETY: comme plus haut.
        unsafe {
            let old_irql = DISPATCHER_LOCK.acquire::<P>();
            (*thread).kernel_apc_in_progress = false;
            DISPATCHER_LOCK.release::<P>(old_irql);
        }
    }
}

/// KeUserApcDispatcher : l'adresse de `ntdll!KiUserApcDispatcher`, la même
/// dans chaque processus ; 0 sans ntdll.
static USER_APC_DISPATCHER: AtomicU32 = AtomicU32::new(0);

/// Fixe le répartiteur des APC utilisateur ; 0 n'en laisse aucun, et les APC
/// utilisateur restent en file.
///
/// # IRQL
/// Tout niveau.
pub fn set_user_apc_dispatcher(address: u32) {
    USER_APC_DISPATCHER.store(address, Ordering::Release);
}

/// Le répartiteur des APC utilisateur ; 0 sans ntdll.
///
/// # IRQL
/// Tout niveau.
pub fn user_apc_dispatcher() -> u32 {
    USER_APC_DISPATCHER.load(Ordering::Acquire)
}

/// Un APC utilisateur à livrer : sa routine du mode utilisateur, son contexte
/// et ses deux arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserApc {
    pub routine: u32,
    pub context: u32,
    pub argument1: u32,
    pub argument2: u32,
}

/// KeTestAlertThread pour le mode utilisateur : si des APC utilisateur sont
/// en file, le thread courant les recevra au retour en mode utilisateur.
/// (Pas encore d'alertes, NtAlertThread.)
///
/// # IRQL
/// <= APC_LEVEL.
pub fn ke_test_alert_thread<P: Platform>() {
    with_current_thread::<P>(|thread| {
        // SAFETY: verrou tenu, thread courant valide (`with_current_thread`).
        unsafe {
            if !ListEntry::is_empty(ptr::addr_of!((*thread).apc_list_head[ProcessorMode::User as usize])) {
                (*thread).user_apc_pending = true;
            }
        }
        false
    });
}

/// KiDeliverApc pour le mode utilisateur : si le thread courant doit recevoir
/// ses APC utilisateur, retire le premier de sa file et appelle sa routine
/// noyau à APC_LEVEL ; rend ce qui reste à livrer en mode utilisateur. Les
/// suivants attendent un nouveau test d'alerte (NtContinue). Un APC dont la
/// routine noyau annule la routine normale fait passer au suivant.
///
/// # Safety
/// Le thread courant a été initialisé (`KThread::init`).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub unsafe fn ki_take_user_apc<P: Platform>() -> Option<UserApc> {
    let thread = P::current_thread();
    loop {
        // SAFETY: comme dans `ki_deliver_apc` ; la file utilisateur ne contient
        // que des KApc valides.
        let (apc, kernel_routine, mut normal, mut context, mut argument1, mut argument2) = unsafe {
            let old_irql = DISPATCHER_LOCK.acquire::<P>();
            let head = ptr::addr_of_mut!((*thread).apc_list_head[ProcessorMode::User as usize]);
            let pending = (*thread).user_apc_pending;
            (*thread).user_apc_pending = false;
            if !pending || ListEntry::is_empty(head) {
                DISPATCHER_LOCK.release::<P>(old_irql);
                return None;
            }
            let apc = apc_of((*head).flink);
            ListEntry::remove(ptr::addr_of_mut!((*apc).apc_list_entry));
            (*apc).inserted = false;
            let fields = (
                apc,
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
        let old_irql = P::raise_irql(Irql::Apc);
        kernel_routine(apc, &mut normal, &mut context, &mut argument1, &mut argument2);
        P::lower_irql(old_irql);
        match normal {
            Some(NormalRoutine::User(routine)) => {
                // User-mode values, 32 bits wide.
                let value = |pointer: *mut c_void| pointer.addr() as u32;
                return Some(UserApc {
                    routine,
                    context: value(context),
                    argument1: value(argument1),
                    argument2: value(argument2),
                });
            }
            Some(NormalRoutine::Kernel(_)) => panic!("a user APC with a kernel normal routine"),
            None => ke_test_alert_thread::<P>(),
        }
    }
}

/// KiInitializeUserApc : au retour en mode utilisateur, livre le premier APC
/// utilisateur que le thread courant doit recevoir ([`ki_take_user_apc`]).
/// Son `CONTEXT`, tiré de la trame, va sur la pile du thread, sous la
/// routine, son contexte et ses deux arguments ; la trame reprend dans
/// `ntdll!KiUserApcDispatcher`. Sans répartiteur, les APC restent en file.
/// `Err` si la pile ne reçoit pas le contexte : l'APC est perdu, l'appelant
/// lève l'exception.
///
/// # IRQL
/// PASSIVE_LEVEL, interruptions actives, dans un thread de l'ordonnanceur.
/// Écrit sur la pile utilisateur.
pub fn ki_deliver_user_apc(frame: &mut KTrapFrame) -> Result<(), NtStatus> {
    use crate::context::{enter_user_dispatcher, push_user_context};
    use crate::usermem::UserPtr;

    let dispatcher = user_apc_dispatcher();
    if dispatcher == 0 {
        return Ok(());
    }
    // SAFETY: a thread of the scheduler (guaranteed by the caller).
    let Some(apc) = (unsafe { ki_take_user_apc::<crate::sched::KePlatform>() }) else {
        return Ok(());
    };
    let context_at = push_user_context(frame)?;
    let arguments_at = context_at.checked_sub(16).ok_or(abi::ntstatus::STATUS_ACCESS_VIOLATION)?;
    UserPtr::<[u32; 4]>::new(arguments_at).write(&[apc.routine, apc.context, apc.argument1, apc.argument2])?;
    enter_user_dispatcher(frame, dispatcher, arguments_at);
    Ok(())
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
