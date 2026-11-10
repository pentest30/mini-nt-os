//! Les demandes d'E/S en attente : ce que garde un IRP mis en attente par
//! un pilote (IoMarkIrpPending), et sa fin (IoCompleteRequest).
//!
//! Un pilote (NPFS, [`crate::npfs`]) qui ne peut pas finir une demande tout
//! de suite garde son [`Request`] et le termine plus tard, depuis un autre
//! thread, hors de ses verrous ([`Request::finish`]). Ce qui doit se passer
//! alors chez le demandeur (le tampon et le bloc d'état écrits dans son
//! processus, son événement signalé, son APC de fin mise en file) dépend
//! du service qui a fait la demande : c'est son [`Requester`], fourni par
//! le gestionnaire d'E/S des appels système. Une demande d'un fichier
//! synchrone (`FILE_SYNCHRONOUS_IO_*`) est attendue par le thread qui l'a
//! faite ([`Request::wait`]), qui reprend lui-même le résultat
//! ([`Request::take`]).
//!
//! Pas encore : les routines d'annulation (IoSetCancelRoutine) ; un pilote
//! annule lui-même (NtCancelIoFile, la fin d'une attente bornée), et une
//! demande dont le thread se termine est abandonnée ([`Requester::abandoned`]).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;

use abi::ntstatus::NtStatus;
use hal::sync::KSpinLock;
use ke::dispatcher::{
    ke_initialize_event, ke_reset_event, ke_set_event, ke_wait_for_single_object, DispatcherHeader, KEvent,
    ObjectType as KObjectType, ProcessorMode, EVENT_INCREMENT,
};
use ke::sched::KePlatform;

/// Un événement de notification de Ke, à une adresse fixe : celui d'un
/// objet fichier (FILE_OBJECT.Event), ou celui qui dit qu'une demande est
/// finie.
pub struct IoEvent(*mut KEvent);

// SAFETY: Ke ne touche à l'événement que sous le verrou dispatcher ; le
// pointeur ne change pas.
unsafe impl Send for IoEvent {}
// SAFETY: voir `Send`.
unsafe impl Sync for IoEvent {}

impl IoEvent {
    /// Un événement de notification, signalé ou non.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new(signaled: bool) -> Self {
        let event = Box::into_raw(Box::<KEvent>::new_uninit()).cast::<KEvent>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_event(event, KObjectType::NotificationEvent, signaled) };
        Self(event)
    }

    /// KeSetEvent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set(&self) {
        // SAFETY: initialisé par `new`, vivant autant que `self`.
        unsafe { ke_set_event::<KePlatform>(self.0, EVENT_INCREMENT) };
    }

    /// KeClearEvent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn clear(&self) {
        // SAFETY: initialisé par `new`, vivant autant que `self`.
        unsafe { ke_reset_event::<KePlatform>(self.0) };
    }

    /// Signalé.
    pub fn is_set(&self) -> bool {
        // SAFETY: initialisé par `new` ; une lecture d'un mot.
        unsafe { ptr::read_volatile(ptr::addr_of!((*self.0).header.signal_state)) != 0 }
    }

    /// L'objet du dispatcher, valide tant qu'on tient `self`.
    pub fn header(&self) -> *mut DispatcherHeader {
        // SAFETY: initialisé par `new`, vivant autant que `self`.
        unsafe { ptr::addr_of_mut!((*self.0).header) }
    }
}

impl Drop for IoEvent {
    fn drop(&mut self) {
        // SAFETY: alloué par `new` ; qui l'attendait tenait `self`.
        drop(unsafe { Box::from_raw(self.0) });
    }
}

/// La fin d'une demande : le bloc d'état (Status, Information) et, pour
/// une lecture, les octets lus, à copier dans le tampon du demandeur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completed {
    pub status: NtStatus,
    pub information: u32,
    pub data: Vec<u8>,
}

impl Completed {
    /// Une fin sans données.
    pub fn status(status: NtStatus, information: u32) -> Self {
        Self { status, information, data: Vec::new() }
    }
}

/// Le demandeur d'une demande : ce que le service qui l'a faite fait à sa
/// fin.
pub trait Requester: Send + Sync {
    /// Le thread demandeur (son TID) : NtCancelIoFile annule les demandes de
    /// son thread.
    fn thread_id(&self) -> u32;

    /// Le thread demandeur se termine : la demande n'est plus servie (une
    /// lecture ne prend plus de données), elle se termine sans rien livrer.
    fn abandoned(&self) -> bool;

    /// La demande finit : livre `completed` au demandeur. Appelé une fois,
    /// hors des verrous du pilote, avant que la demande ne soit signalée.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    fn deliver(&self, completed: &Completed);
}

/// Une demande d'E/S en attente.
pub struct Request {
    /// L'objet fichier de la demande (son identifiant, `crate::npfs`).
    file: u64,
    requester: Box<dyn Requester>,
    /// Sa fin, jusqu'à ce que le demandeur la reprenne.
    result: KSpinLock<Option<Completed>>,
    /// Signalé à sa fin.
    done: IoEvent,
}

impl Request {
    /// Une demande sur l'objet fichier `file`, de `requester`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new(file: u64, requester: Box<dyn Requester>) -> Arc<Self> {
        Arc::new(Self { file, requester, result: KSpinLock::new(None), done: IoEvent::new(false) })
    }

    /// L'objet fichier de la demande.
    pub fn file(&self) -> u64 {
        self.file
    }

    /// Son demandeur.
    pub fn requester(&self) -> &dyn Requester {
        &*self.requester
    }

    /// Son thread se termine ([`Requester::abandoned`]).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn abandoned(&self) -> bool {
        self.requester.abandoned()
    }

    /// IoCompleteRequest : livre `completed` au demandeur, la garde pour
    /// [`take`](Self::take), puis signale la demande.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, hors des verrous du pilote.
    pub fn finish(&self, completed: Completed) {
        if !self.requester.abandoned() {
            self.requester.deliver(&completed);
        }
        *self.result.lock() = Some(completed);
        self.done.set();
    }

    /// Finie.
    pub fn is_finished(&self) -> bool {
        self.done.is_set()
    }

    /// Sa fin, reprise une fois.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn take(&self) -> Option<Completed> {
        self.result.lock().take()
    }

    /// Attend sa fin, sans alerte, jusqu'à `timeout` (format NT) s'il y en
    /// a une : `STATUS_SUCCESS` (STATUS_WAIT_0) ou `STATUS_TIMEOUT`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL. Peut attendre.
    pub fn wait(&self, timeout: Option<i64>) -> NtStatus {
        // SAFETY: l'événement vit autant que `self`, que l'appelant tient
        // pendant l'attente.
        unsafe { ke_wait_for_single_object::<KePlatform>(self.done.header(), ProcessorMode::User, false, timeout) }
    }
}

/// Les demandes qu'un pilote a terminées sous son verrou : finies une fois
/// le verrou rendu (NpCompleteDeferredIrps). Celles qui sont seulement
/// retirées (abandonnées) partent aussi hors du verrou.
#[derive(Default)]
#[must_use = "the requests finish once the lock is released"]
pub struct Deferred {
    finished: Vec<(Arc<Request>, Completed)>,
    dropped: Vec<Arc<Request>>,
}

impl Deferred {
    /// Une liste vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// `request` finira avec `completed`.
    pub fn finish(&mut self, request: Arc<Request>, completed: Completed) {
        self.finished.push((request, completed));
    }

    /// `request` finira avec `status`, sans données.
    pub fn finish_status(&mut self, request: Arc<Request>, status: NtStatus, information: u32) {
        self.finish(request, Completed::status(status, information));
    }

    /// `request`, retirée sans être servie, part hors du verrou.
    pub fn drop_later(&mut self, request: Arc<Request>) {
        self.dropped.push(request);
    }

    /// Le nombre de demandes à finir.
    pub fn len(&self) -> usize {
        self.finished.len()
    }

    pub fn is_empty(&self) -> bool {
        self.finished.is_empty()
    }

    /// Finit chaque demande, dans l'ordre.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, sans verrou.
    pub fn run(self) {
        for (request, completed) in self.finished {
            request.finish(completed);
        }
        drop(self.dropped);
    }
}
