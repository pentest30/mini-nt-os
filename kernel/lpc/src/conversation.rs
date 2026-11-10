//! Les conversations : un client se connecte à un port de connexion
//! ([`connect`]), le serveur accepte ou refuse ([`accept`]) puis réveille le
//! client ([`complete`]) ; ensuite le client envoie une requête et attend sa
//! réponse ([`request_wait_reply`]), ou un datagramme ([`send`]), et le
//! serveur répond ([`reply`]).
//!
//! Un thread qui attend (sa connexion, une réponse) est inscrit, par son TID,
//! avec l'identifiant du message qui attend : c'est par le CLIENT_ID et
//! l'identifiant que le serveur le désigne. Il attend son propre événement,
//! comme le sémaphore de réponse d'un thread d'XP (LpcReplySemaphore).
//!
//! Un client peut partager une section avec le serveur ([`ClientView`]) : il
//! la voit déjà, le serveur la voit à son tour quand il accepte, et chacun
//! apprend où l'autre la voit.
//!
//! Le noyau envoie aussi ses messages ([`request_port`]) : Ps y annonce la
//! fin d'un thread (`LPC_CLIENT_DIED`).
//!
//! Pas encore : la section d'un serveur (`ServerView`), les rappels (une
//! requête envoyée en réponse), le message `LPC_PORT_CLOSED` (le dernier
//! handle d'un port client fermé), NtReadRequestData et NtWriteRequestData.
//! Un thread qui se termine pendant son attente laisse son inscription,
//! qu'écrase la suivante de son TID.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;

use abi::lpc::{PortMessage32, LPC_CLIENT_DIED, LPC_CONNECTION_REQUEST, LPC_DATAGRAM, LPC_REPLY, LPC_REQUEST};
use abi::ntstatus::{
    NtStatus, STATUS_INVALID_PARAMETER, STATUS_INVALID_PORT_HANDLE, STATUS_LPC_REPLY_LOST,
    STATUS_PORT_CONNECTION_REFUSED, STATUS_PORT_MESSAGE_TOO_LONG, STATUS_REPLY_MESSAGE_MISMATCH, STATUS_WAIT_0,
};
use abi::teb32::ClientId32;
use hal::sync::KSpinLock;
use ke::dispatcher::{
    ke_initialize_event, ke_set_event, ke_wait_for_single_object, KEvent, ObjectType as KObjectType, ProcessorMode,
    EVENT_INCREMENT,
};
use ke::sched::KePlatform;
use mm::section::Section;
use ob::Object;

use crate::port::{next_message_id, Message, Port, PortKind, HEADER_LENGTH};

/// La section qu'un client partage avec le serveur (PORT_VIEW de
/// NtConnectPort).
#[derive(Clone)]
pub struct ClientView {
    pub section: Arc<Section>,
    pub offset: u32,
    pub size: u32,
    /// Où le client la voit.
    pub base: u32,
    /// Où le serveur la voit, une fois la connexion acceptée ; 0 avant.
    pub remote_base: u32,
}

/// Ce qu'attend un thread.
enum Waiting {
    /// Sa connexion : son port client, les données de connexion, que le
    /// serveur peut récrire, et la section qu'il partage.
    Connection { client_port: Arc<Object<Port>>, info: Vec<u8>, view: Option<ClientView>, answer: Answer },
    /// La réponse à sa requête.
    Reply(Option<Message>),
}

/// Où en est une demande de connexion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// Le serveur ne l'a pas encore traitée.
    Pending,
    Refused,
    Accepted,
}

/// Un thread qui attend.
struct Waiter {
    client: ClientId32,
    message_id: u32,
    state: KSpinLock<Waiting>,
    /// Son événement, à lui ; il le rend avec lui.
    event: *mut KEvent,
}

// SAFETY: Ke ne touche à l'événement que sous le verrou dispatcher ; l'état
// est sous son verrou.
unsafe impl Send for Waiter {}
// SAFETY: voir `Send`.
unsafe impl Sync for Waiter {}

impl Waiter {
    fn new(client: ClientId32, message_id: u32, state: Waiting) -> Arc<Self> {
        let event = Box::into_raw(Box::<KEvent>::new_uninit()).cast::<KEvent>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_event(event, KObjectType::SynchronizationEvent, false) };
        Arc::new(Self { client, message_id, state: KSpinLock::new(state), event })
    }

    /// LpcpCompleteWait : le réveille.
    fn wake(&self) {
        // SAFETY: initialisé par `new`, vivant autant que `self`.
        unsafe { ke_set_event::<KePlatform>(self.event, EVENT_INCREMENT) };
    }

    /// Attend d'être réveillé, en mode `mode`, sans alerte ni délai.
    fn wait(&self, mode: ProcessorMode) -> NtStatus {
        // SAFETY: initialisé par `new`, vivant autant que `self`, que
        // l'appelant tient pendant l'attente.
        unsafe { ke_wait_for_single_object::<KePlatform>(ptr::addr_of_mut!((*self.event).header), mode, false, None) }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        // SAFETY: alloué par `new` ; plus personne ne l'attend.
        drop(unsafe { Box::from_raw(self.event) });
    }
}

/// Les threads qui attendent, par TID.
static WAITERS: KSpinLock<BTreeMap<u32, Arc<Waiter>>> = KSpinLock::new(BTreeMap::new());

/// Inscrit `waiter` sous son TID ; une inscription laissée par un thread
/// mort du même TID est remplacée.
fn register(waiter: &Arc<Waiter>) {
    WAITERS.lock().insert(waiter.client.unique_thread, waiter.clone());
}

/// Désinscrit `waiter`, s'il l'est encore.
fn unregister(waiter: &Arc<Waiter>) {
    let mut waiters = WAITERS.lock();
    if waiters.get(&waiter.client.unique_thread).is_some_and(|w| Arc::ptr_eq(w, waiter)) {
        waiters.remove(&waiter.client.unique_thread);
    }
}

/// Le thread `client` qui attend le message `message_id` ;
/// `STATUS_REPLY_MESSAGE_MISMATCH` s'il n'attend rien, ou autre chose.
fn waiter(client: ClientId32, message_id: u32) -> Result<Arc<Waiter>, NtStatus> {
    let waiters = WAITERS.lock();
    let waiter = waiters.get(&client.unique_thread).ok_or(STATUS_REPLY_MESSAGE_MISMATCH)?;
    if message_id == 0 || waiter.message_id != message_id || waiter.client != client {
        return Err(STATUS_REPLY_MESSAGE_MISMATCH);
    }
    Ok(waiter.clone())
}

/// Ce que rend une connexion acceptée.
pub struct Connected {
    /// Le port client, à donner au client.
    pub port: Arc<Object<Port>>,
    /// Les données de connexion, telles que le serveur les a laissées.
    pub info: Vec<u8>,
    /// La taille au plus d'un message.
    pub max_message_length: u32,
    /// La section partagée, avec où le serveur la voit.
    pub view: Option<ClientView>,
}

/// Ce que rend une connexion acceptée au serveur.
pub struct Accepted {
    /// Le port de communication du serveur.
    pub port: Arc<Object<Port>>,
    /// Où le serveur voit la section du client, et sa taille.
    pub client_view: Option<(u32, u32)>,
}

/// NtConnectPort, le port de connexion référencé : le thread `client` met en
/// file sur `port` une demande de connexion (`LPC_CONNECTION_REQUEST`) avec
/// les données `info` (déjà tronquées par l'appelant à ce que le port
/// admet, `max_connection_info_length`) et la section
/// `view` qu'il partage, déjà projetée chez lui, puis attend que le serveur
/// l'accepte et le réveille, ou la refuse.
///
/// # Errors
/// `STATUS_INVALID_PORT_HANDLE` pour un autre port qu'un port de connexion ;
/// `STATUS_PORT_CONNECTION_REFUSED` si le serveur refuse ; le statut de
/// l'attente si elle finit autrement.
///
/// # IRQL
/// PASSIVE_LEVEL. Peut attendre.
pub fn connect(
    port: &Arc<Object<Port>>,
    client: ClientId32,
    info: &[u8],
    view: Option<ClientView>,
    mode: ProcessorMode,
) -> Result<Connected, NtStatus> {
    if port.kind() != PortKind::Connection {
        return Err(STATUS_INVALID_PORT_HANDLE);
    }
    let client_port = Port::communication(PortKind::Client, port);
    let message_id = next_message_id();
    let client_view_size = view.as_ref().map_or(0, |view| view.size);
    let waiter = Waiter::new(
        client,
        message_id,
        Waiting::Connection { client_port, info: info.to_vec(), view, answer: Answer::Pending },
    );
    register(&waiter);
    let header = PortMessage32 {
        data_length: info.len() as u16,
        total_length: (HEADER_LENGTH as usize + info.len()) as u16,
        kind: LPC_CONNECTION_REQUEST,
        data_info_offset: 0,
        client_id: client,
        message_id,
        client_view_size,
    };
    if let Err(status) = port.queue(Message { header, data: info.to_vec(), context: 0 }) {
        unregister(&waiter);
        return Err(status);
    }
    let waited = waiter.wait(mode);
    unregister(&waiter);
    if waited != STATUS_WAIT_0 {
        return Err(waited);
    }
    let state = core::mem::replace(&mut *waiter.state.lock(), Waiting::Reply(None));
    match state {
        Waiting::Connection { client_port, info, view, answer: Answer::Accepted } => {
            Ok(Connected { max_message_length: client_port.max_message_length(), port: client_port, info, view })
        }
        _ => Err(STATUS_PORT_CONNECTION_REFUSED),
    }
}

/// NtAcceptConnectPort : le serveur du processus `server_pid` répond à la
/// demande de connexion `message_id` du thread `client`, avec les données
/// `info` (tronquées à ce que le port admet), que le client reçoit. Refusée,
/// le client est réveillé aussitôt, et rien n'est rendu ; acceptée, la
/// section du client est projetée chez le serveur (`map`, qui rend
/// l'adresse de la vue), et le port de communication du serveur, de
/// contexte `context`, relié au port client, est rendu : le client attend
/// [`complete`]. Une projection qui échoue refuse la connexion.
///
/// # Errors
/// `STATUS_REPLY_MESSAGE_MISMATCH` si le thread n'attend pas cette
/// connexion, si elle a déjà sa réponse, ou si le serveur n'est pas celui de
/// son port ; celles de `map`.
///
/// # IRQL
/// PASSIVE_LEVEL (`map` projette une vue).
pub fn accept(
    client: ClientId32,
    message_id: u32,
    server_pid: u32,
    info: &[u8],
    accept: bool,
    context: u32,
    map: impl FnOnce(&ClientView) -> Result<u32, NtStatus>,
) -> Result<Option<Accepted>, NtStatus> {
    let waiter = waiter(client, message_id)?;
    let mut state = waiter.state.lock();
    let Waiting::Connection { client_port, info: client_info, view, answer } = &mut *state else {
        return Err(STATUS_REPLY_MESSAGE_MISMATCH);
    };
    let connection = client_port.connection().expect("a client port has its connection port").clone();
    if *answer != Answer::Pending || connection.server_pid() != server_pid {
        return Err(STATUS_REPLY_MESSAGE_MISMATCH);
    }
    *client_info = info[..info.len().min(connection.max_connection_info_length() as usize)].to_vec();
    // Answered now: no other accept takes it while the view is mapped,
    // outside the lock.
    *answer = Answer::Refused;
    let view = view.clone();
    let client_port = client_port.clone();
    drop(state);
    let mapped = match (accept, &view) {
        (true, Some(view)) => map(view).map(Some),
        _ => Ok(None),
    };
    if !accept || mapped.is_err() {
        waiter.wake();
        return mapped.map(|_| None);
    }
    let remote_base = mapped.expect("checked above");
    let server_port = Port::communication(PortKind::ServerCommunication, &connection);
    server_port.set_context(context);
    server_port.connect_to(&client_port);
    client_port.connect_to(&server_port);
    {
        let mut state = waiter.state.lock();
        if let Waiting::Connection { view, answer, .. } = &mut *state {
            if let Some(view) = view {
                view.remote_base = remote_base.unwrap_or(0);
            }
            *answer = Answer::Accepted;
        }
    }
    PENDING_COMPLETIONS.lock().insert(Arc::as_ptr(&server_port) as usize, waiter);
    let client_view = view.zip(remote_base).map(|(view, base)| (base, view.size));
    Ok(Some(Accepted { port: server_port, client_view }))
}

/// Les clients acceptés qui attendent [`complete`], par port de
/// communication du serveur (ClientThread).
static PENDING_COMPLETIONS: KSpinLock<BTreeMap<usize, Arc<Waiter>>> = KSpinLock::new(BTreeMap::new());

/// NtCompleteConnectPort : réveille le client dont le serveur a accepté la
/// connexion par `server_port`.
///
/// # Errors
/// `STATUS_INVALID_PORT_HANDLE` pour un autre port qu'un port de
/// communication du serveur ; `STATUS_INVALID_PARAMETER` si aucun client
/// n'attend par lui.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn complete(server_port: &Arc<Object<Port>>) -> Result<(), NtStatus> {
    if server_port.kind() != PortKind::ServerCommunication {
        return Err(STATUS_INVALID_PORT_HANDLE);
    }
    let waiter =
        PENDING_COMPLETIONS.lock().remove(&(Arc::as_ptr(server_port) as usize)).ok_or(STATUS_INVALID_PARAMETER)?;
    waiter.wake();
    Ok(())
}

/// Vérifie l'en-tête d'un message envoyé par un port de messages de
/// `max_message_length` octets au plus : `STATUS_INVALID_PARAMETER` si ses
/// données et l'en-tête dépassent sa taille ; `STATUS_PORT_MESSAGE_TOO_LONG`
/// s'il dépasse le port.
pub fn check_message(header: &PortMessage32, max_message_length: u32) -> Result<(), NtStatus> {
    let (data, total) = (u32::from(header.data_length), u32::from(header.total_length));
    if data + HEADER_LENGTH > total {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if total > max_message_length {
        return Err(STATUS_PORT_MESSAGE_TOO_LONG);
    }
    Ok(())
}

/// Le message que le thread `client` envoie par `port`, de type `kind` :
/// son en-tête refait (type, client, identifiant neuf), ses données, le
/// contexte du port du serveur ; avec le port qui le reçoit.
fn outgoing(
    port: &Arc<Object<Port>>,
    client: ClientId32,
    header: &PortMessage32,
    data: Vec<u8>,
    kind: u16,
) -> Result<(Arc<Object<Port>>, Message), NtStatus> {
    check_message(header, port.max_message_length())?;
    let (to, context) = Port::send_port(port)?;
    let header =
        PortMessage32 { kind, client_id: client, message_id: next_message_id(), client_view_size: 0, ..*header };
    Ok((to, Message { header, data, context }))
}

/// NtRequestWaitReplyPort, le port référencé : le thread `client` envoie par
/// `port` la requête d'en-tête `header` et de données `data`
/// (`LPC_REQUEST`), puis attend sa réponse et la rend.
///
/// # Errors
/// Celles de [`check_message`] ; `STATUS_PORT_DISCONNECTED` sans serveur ;
/// `STATUS_LPC_REPLY_LOST` réveillé sans réponse ; le statut de l'attente si
/// elle finit autrement.
///
/// # IRQL
/// PASSIVE_LEVEL. Peut attendre.
pub fn request_wait_reply(
    port: &Arc<Object<Port>>,
    client: ClientId32,
    header: &PortMessage32,
    data: Vec<u8>,
    mode: ProcessorMode,
) -> Result<Message, NtStatus> {
    let (to, message) = outgoing(port, client, header, data, LPC_REQUEST)?;
    let waiter = Waiter::new(client, message.header.message_id, Waiting::Reply(None));
    register(&waiter);
    if let Err(status) = to.queue(message) {
        unregister(&waiter);
        return Err(status);
    }
    let waited = waiter.wait(mode);
    unregister(&waiter);
    if waited != STATUS_WAIT_0 {
        return Err(waited);
    }
    let state = core::mem::replace(&mut *waiter.state.lock(), Waiting::Reply(None));
    match state {
        Waiting::Reply(Some(reply)) => Ok(reply),
        _ => Err(STATUS_LPC_REPLY_LOST),
    }
}

/// NtRequestPort, le port référencé : le thread `client` envoie par `port`
/// le datagramme d'en-tête `header` et de données `data` (`LPC_DATAGRAM`),
/// sans attendre de réponse.
///
/// # Errors
/// Celles de [`check_message`] ; `STATUS_PORT_DISCONNECTED` sans serveur.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn send(
    port: &Arc<Object<Port>>,
    client: ClientId32,
    header: &PortMessage32,
    data: Vec<u8>,
) -> Result<(), NtStatus> {
    let (to, message) = outgoing(port, client, header, data, LPC_DATAGRAM)?;
    to.queue(message)
}

/// LpcRequestPort, pour le noyau : le message de sorte `kind` et de données
/// `data` part par `port` au nom du thread `client`, sans attendre de
/// réponse ; il va où irait un datagramme ([`Port::send_port`]). La sorte va
/// de `LPC_DATAGRAM` à `LPC_CLIENT_DIED`, comme dans ReactOS, et reste telle
/// quelle : sans `LPC_KERNELMODE_MESSAGE`, que `csrss` ne reconnaîtrait pas.
/// C'est ainsi que Ps annonce la fin d'un thread (`LPC_CLIENT_DIED`).
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` pour une autre sorte ;
/// `STATUS_PORT_MESSAGE_TOO_LONG` au-delà des messages du port ;
/// `STATUS_PORT_DISCONNECTED` sans serveur.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn request_port(port: &Arc<Object<Port>>, client: ClientId32, kind: u16, data: Vec<u8>) -> Result<(), NtStatus> {
    if !(LPC_DATAGRAM..=LPC_CLIENT_DIED).contains(&kind) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let data_length = u16::try_from(data.len()).map_err(|_| STATUS_PORT_MESSAGE_TOO_LONG)?;
    let total_length = data_length.checked_add(HEADER_LENGTH as u16).ok_or(STATUS_PORT_MESSAGE_TOO_LONG)?;
    let header = PortMessage32 { data_length, total_length, ..PortMessage32::default() };
    let (to, message) = outgoing(port, client, &header, data, kind)?;
    to.queue(message)
}

/// NtReplyPort, et la réponse de NtReplyWaitReceivePort : le serveur répond
/// par `port` au message que désignent le CLIENT_ID et l'identifiant de
/// `header`, avec les données `data` ; le thread qui l'attend est réveillé.
///
/// # Errors
/// Celles de [`check_message`] ; `STATUS_INVALID_PARAMETER` pour un
/// identifiant nul ; `STATUS_REPLY_MESSAGE_MISMATCH` si le thread n'attend
/// pas de réponse à ce message.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn reply(port: &Port, header: &PortMessage32, data: Vec<u8>) -> Result<(), NtStatus> {
    check_message(header, port.max_message_length())?;
    if header.message_id == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let waiter = waiter(header.client_id, header.message_id)?;
    let mut state = waiter.state.lock();
    let Waiting::Reply(answer @ None) = &mut *state else {
        return Err(STATUS_REPLY_MESSAGE_MISMATCH);
    };
    let header = PortMessage32 { kind: LPC_REPLY, data_info_offset: 0, client_view_size: 0, ..*header };
    *answer = Some(Message { header, data, context: 0 });
    drop(state);
    waiter.wake();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(data: u16, total: u16) -> PortMessage32 {
        PortMessage32 { data_length: data, total_length: total, ..PortMessage32::default() }
    }

    #[test]
    fn a_message_fits_its_port() {
        assert_eq!(check_message(&header(8, 0x20), 0x100), Ok(()));
        assert_eq!(check_message(&header(9, 0x20), 0x100), Err(STATUS_INVALID_PARAMETER), "data past the total");
        assert_eq!(check_message(&header(8, 0x101), 0x100), Err(STATUS_PORT_MESSAGE_TOO_LONG), "past the port");
        assert_eq!(check_message(&header(0, 0), 0x100), Err(STATUS_INVALID_PARAMETER), "no room for the header");
        assert_eq!(check_message(&header(0, 0x18), 0x18), Ok(()), "a header alone, as long as the port's messages");
    }

    #[test]
    fn a_server_answers_the_thread_that_waits_for_it() {
        let connection = Port::create(0x10, 0x100, 16).expect("a port");
        let client = ClientId32 { unique_process: 20, unique_thread: 24 };
        let waiter = Waiter::new(
            client,
            7,
            Waiting::Connection {
                client_port: Port::communication(PortKind::Client, &connection),
                info: alloc::vec![1, 2],
                view: None,
                answer: Answer::Pending,
            },
        );
        register(&waiter);
        assert_eq!(
            accept(client, 8, 16, &[], true, 0, |_| Ok(0)).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH),
            "another message"
        );
        let stranger = ClientId32 { unique_process: 28, unique_thread: 24 };
        assert_eq!(
            accept(stranger, 7, 16, &[], true, 0, |_| Ok(0)).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH),
            "another process"
        );
        assert_eq!(
            accept(client, 7, 12, &[], true, 0, |_| Ok(0)).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH),
            "another server"
        );
        let long = [9u8; 0x20];
        let server =
            accept(client, 7, 16, &long, true, 0x40, |_| Ok(0)).expect("accepted").expect("a server port").port;
        assert_eq!((server.kind(), server.context()), (PortKind::ServerCommunication, 0x40));
        {
            let state = waiter.state.lock();
            let Waiting::Connection { client_port, info, answer, .. } = &*state else { panic!("a connection") };
            assert_eq!((info.len(), *answer), (0x10, Answer::Accepted), "the server's data, cut to the port's");
            assert!(Arc::ptr_eq(&client_port.connected().expect("connected"), &server));
            assert!(Arc::ptr_eq(&server.connected().expect("connected"), client_port));
        }
        assert_eq!(
            accept(client, 7, 16, &[], true, 0, |_| Ok(0)).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH),
            "answered once"
        );
        assert_eq!(complete(&connection).err(), Some(STATUS_INVALID_PORT_HANDLE));
        assert_eq!(complete(&server), Ok(()));
        assert_eq!(complete(&server).err(), Some(STATUS_INVALID_PARAMETER), "woken once");
        unregister(&waiter);
    }

    #[test]
    fn the_kernel_tells_a_server_that_a_client_died() {
        use abi::lpc::LPC_KERNELMODE_MESSAGE;
        let connection = Port::create(0, 0x100, 16).expect("a port");
        let dying = ClientId32 { unique_process: 20, unique_thread: 48 };
        let created = 0x01D2_0000_1234_5678u64.to_le_bytes().to_vec();
        for kind in [LPC_REQUEST, LPC_REPLY, LPC_CONNECTION_REQUEST, LPC_CLIENT_DIED | LPC_KERNELMODE_MESSAGE] {
            assert_eq!(request_port(&connection, dying, kind, created.clone()), Err(STATUS_INVALID_PARAMETER));
        }
        assert_eq!(connection.queued(), 0, "nothing sent");
        assert_eq!(request_port(&connection, dying, LPC_CLIENT_DIED, created.clone()), Ok(()));
        assert_eq!(connection.queued(), 1, "a connection port receives what is sent by it");
        let message = connection.receive(ProcessorMode::Kernel, None).expect("the message");
        assert_eq!(message.header.kind, LPC_CLIENT_DIED, "its kind as is: csrss compares it");
        assert_eq!(message.header.client_id, dying, "from the thread that ends");
        assert_eq!((message.header.data_length, message.header.total_length), (8, 0x20));
        assert_ne!(message.header.message_id, 0);
        assert_eq!((message.data, message.context), (created, 0));
        let too_long = alloc::vec![0; 0x100];
        assert_eq!(
            request_port(&connection, dying, LPC_CLIENT_DIED, too_long),
            Err(STATUS_PORT_MESSAGE_TOO_LONG),
            "past the port"
        );
        let client = Port::communication(PortKind::Client, &connection);
        assert_eq!(
            request_port(&client, dying, LPC_CLIENT_DIED, alloc::vec![0; 8]),
            Err(abi::ntstatus::STATUS_PORT_DISCONNECTED),
            "a client port without its server"
        );
    }

    #[test]
    fn a_client_connects_to_a_connection_port_only() {
        let connection = Port::create(0x10, 0x100, 16).expect("a port");
        let client = Port::communication(PortKind::Client, &connection);
        let me = ClientId32 { unique_process: 20, unique_thread: 40 };
        let refused = connect(&client, me, &[], None, ProcessorMode::Kernel).err();
        assert_eq!(refused, Some(STATUS_INVALID_PORT_HANDLE));
        assert_eq!(connection.queued(), 0, "nothing sent");
    }

    #[test]
    fn a_refused_client_is_woken_with_the_servers_data() {
        let connection = Port::create(0x10, 0x100, 16).expect("a port");
        let client = ClientId32 { unique_process: 20, unique_thread: 44 };
        let waiter = Waiter::new(
            client,
            9,
            Waiting::Connection {
                client_port: Port::communication(PortKind::Client, &connection),
                info: alloc::vec![1],
                view: None,
                answer: Answer::Pending,
            },
        );
        register(&waiter);
        assert!(accept(client, 9, 16, &[7, 7], false, 0, |_| Ok(0)).expect("answered").is_none(), "no server port");
        {
            let state = waiter.state.lock();
            let Waiting::Connection { client_port, info, answer, .. } = &*state else { panic!("a connection") };
            assert_eq!((&info[..], *answer), (&[7u8, 7][..], Answer::Refused));
            assert!(client_port.connected().is_none(), "not connected");
        }
        // SAFETY: the event was set by `accept`: the wait returns at once.
        assert_eq!(waiter.wait(ProcessorMode::Kernel), STATUS_WAIT_0, "woken");
        unregister(&waiter);
    }

    #[test]
    fn a_reply_goes_to_the_request_it_answers() {
        let port = Port::create(0, 0x100, 16).expect("a port");
        let client = ClientId32 { unique_process: 20, unique_thread: 32 };
        let waiter = Waiter::new(client, 11, Waiting::Reply(None));
        register(&waiter);
        let answer = PortMessage32 { client_id: client, message_id: 11, ..header(4, 0x1C) };
        assert_eq!(
            reply(&port, &PortMessage32 { message_id: 0, ..answer }, alloc::vec![0; 4]),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            reply(&port, &PortMessage32 { message_id: 12, ..answer }, alloc::vec![0; 4]),
            Err(STATUS_REPLY_MESSAGE_MISMATCH)
        );
        assert_eq!(reply(&port, &answer, alloc::vec![1, 2, 3, 4]), Ok(()));
        assert_eq!(reply(&port, &answer, alloc::vec![0; 4]), Err(STATUS_REPLY_MESSAGE_MISMATCH), "answered once");
        {
            let state = waiter.state.lock();
            let Waiting::Reply(Some(message)) = &*state else { panic!("a reply") };
            assert_eq!((message.header.kind, message.header.message_id), (LPC_REPLY, 11));
            assert_eq!(&message.data[..], &[1, 2, 3, 4]);
        }
        unregister(&waiter);
    }
}
