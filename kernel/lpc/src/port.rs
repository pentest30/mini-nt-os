//! Les ports (LpcPortObjectType), de trois sortes.
//!
//! - Un **port de connexion**, nommé, que crée un serveur (NtCreatePort) :
//!   les demandes de connexion et les messages de ses clients arrivent dans
//!   sa file, que le serveur lit (NtReplyWaitReceivePort).
//! - Un **port client**, que reçoit un client connecté (NtConnectPort) : ce
//!   qu'il envoie va dans la file du port de connexion, avec le contexte du
//!   port du serveur ; il a sa propre file, pour ce que le serveur lui envoie.
//! - Un **port de communication du serveur**, que reçoit le serveur en
//!   acceptant une connexion (NtAcceptConnectPort) : il en a le contexte, et
//!   lit par lui la file de son port de connexion.
//!
//! Les deux extrémités d'une connexion se désignent sans se garder en vie :
//! quand l'une disparaît, l'autre est déconnectée (`STATUS_PORT_DISCONNECTED`).
//! La file compte ses messages dans un sémaphore ; le noyau peut y mettre un
//! datagramme ([`Port::request`], LpcRequestPort).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::lpc::{PortMessage32, LPC_DATAGRAM, LPC_KERNELMODE_MESSAGE, PORT_MAXIMUM_MESSAGE_LENGTH};
use abi::ntstatus::{
    NtStatus, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER_3, STATUS_INVALID_PARAMETER_4,
    STATUS_PORT_DISCONNECTED, STATUS_PORT_MESSAGE_TOO_LONG, STATUS_WAIT_0,
};
use abi::teb32::ClientId32;
use hal::sync::KSpinLock;
use ke::dispatcher::{
    ke_initialize_semaphore, ke_release_semaphore, ke_wait_for_single_object, KSemaphore, ProcessorMode,
    SEMAPHORE_INCREMENT,
};
use ke::sched::KePlatform;
use ob::{create_object, AccessMask, GenericMapping, Object, ObjectType};

/// Se connecter au port.
pub const PORT_CONNECT: AccessMask = AccessMask(0x0001);
/// PORT_ALL_ACCESS d'XP.
pub const PORT_ALL_ACCESS: AccessMask =
    AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | AccessMask::SYNCHRONIZE.0 | 0x1);

/// Le type `Port` (LpcPortObjectType), avec la correspondance générique
/// d'XP.
pub static PORT_TYPE: ObjectType = ObjectType::new(
    "Port",
    PORT_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::READ_CONTROL.0 | PORT_CONNECT.0),
        write: AccessMask(AccessMask::DELETE.0 | PORT_CONNECT.0),
        execute: AccessMask::NONE,
        all: PORT_ALL_ACCESS,
    },
);

/// Les messages en file d'un port, au plus.
const MAXIMUM_QUEUED: i32 = i32::MAX;

/// LpcpNextMessageId : l'identifiant du prochain message, jamais 0.
static NEXT_MESSAGE_ID: AtomicU32 = AtomicU32::new(1);

/// Un identifiant de message neuf, jamais 0.
pub(crate) fn next_message_id() -> u32 {
    loop {
        let id = NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

/// La taille de l'en-tête d'un message.
pub const HEADER_LENGTH: u32 = core::mem::size_of::<PortMessage32>() as u32;

/// Un message en file : son en-tête, ses données, et le contexte du port du
/// serveur par lequel il est venu (PortContext ; 0 pour une demande de
/// connexion ou un message du noyau).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub header: PortMessage32,
    pub data: Vec<u8>,
    pub context: u32,
}

impl Message {
    /// Ses octets, en-tête puis données, tels qu'ils vont au destinataire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LENGTH as usize + self.data.len());
        bytes.extend_from_slice(self.header.as_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

/// Les sortes de ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortKind {
    /// LPCP_CONNECTION_PORT : nommé, créé par un serveur.
    Connection,
    /// LPCP_COMMUNICATION_PORT : le côté serveur d'une connexion.
    ServerCommunication,
    /// LPCP_CLIENT_PORT : le côté client d'une connexion.
    Client,
}

/// Le corps d'un objet port.
pub struct Port {
    kind: PortKind,
    /// La taille au plus des données de connexion.
    max_connection_info_length: u32,
    /// La taille au plus d'un message, en-tête compris.
    max_message_length: u32,
    /// Le PID du serveur : le créateur du port de connexion.
    server_pid: u32,
    /// Le port de connexion d'un port de communication, client ou serveur.
    connection: Option<Arc<Object<Port>>>,
    /// L'autre extrémité d'une connexion, sans la garder en vie.
    connected: KSpinLock<Weak<Object<Port>>>,
    /// PortContext d'un port de communication du serveur.
    context: AtomicU32,
    /// Les messages qui attendent d'être reçus.
    queue: KSpinLock<VecDeque<Message>>,
    /// Compte les messages en file ; qui reçoit l'attend.
    semaphore: *mut KSemaphore,
}

// SAFETY: Ke ne touche au sémaphore que sous le verrou dispatcher ; le
// pointeur ne change pas ; la file et les liens sont sous leurs verrous.
unsafe impl Send for Port {}
// SAFETY: voir `Send`.
unsafe impl Sync for Port {}

impl Port {
    fn new(
        kind: PortKind,
        max_connection_info_length: u32,
        max_message_length: u32,
        server_pid: u32,
        connection: Option<Arc<Object<Port>>>,
    ) -> Arc<Object<Self>> {
        let semaphore = Box::into_raw(Box::<KSemaphore>::new_uninit()).cast::<KSemaphore>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_semaphore(semaphore, 0, MAXIMUM_QUEUED) };
        create_object(
            &PORT_TYPE,
            Port {
                kind,
                max_connection_info_length,
                max_message_length,
                server_pid,
                connection,
                connected: KSpinLock::new(Weak::new()),
                context: AtomicU32::new(0),
                queue: KSpinLock::new(VecDeque::new()),
                semaphore,
            },
        )
    }

    /// NtCreatePort : un port de connexion du serveur `server_pid`, dont les
    /// données de connexion font au plus `max_connection_info_length` octets
    /// et les messages `max_message_length` ; `STATUS_INVALID_PARAMETER_3`
    /// ou `_4` au-delà de `PORT_MAXIMUM_MESSAGE_LENGTH`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(
        max_connection_info_length: u32,
        max_message_length: u32,
        server_pid: u32,
    ) -> Result<Arc<Object<Self>>, NtStatus> {
        if max_connection_info_length > PORT_MAXIMUM_MESSAGE_LENGTH {
            return Err(STATUS_INVALID_PARAMETER_3);
        }
        if max_message_length > PORT_MAXIMUM_MESSAGE_LENGTH {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        Ok(Self::new(PortKind::Connection, max_connection_info_length, max_message_length, server_pid, None))
    }

    /// Un port de communication de sorte `kind` sur le port de connexion
    /// `connection` : il en a les tailles et le serveur.
    pub(crate) fn communication(kind: PortKind, connection: &Arc<Object<Port>>) -> Arc<Object<Self>> {
        Self::new(
            kind,
            connection.max_connection_info_length,
            connection.max_message_length,
            connection.server_pid,
            Some(connection.clone()),
        )
    }

    /// Sa sorte.
    pub fn kind(&self) -> PortKind {
        self.kind
    }

    /// MaxConnectionInfoLength.
    pub fn max_connection_info_length(&self) -> u32 {
        self.max_connection_info_length
    }

    /// MaxMessageLength.
    pub fn max_message_length(&self) -> u32 {
        self.max_message_length
    }

    /// Le PID du serveur.
    pub fn server_pid(&self) -> u32 {
        self.server_pid
    }

    /// Le port de connexion d'un port de communication.
    pub fn connection(&self) -> Option<&Arc<Object<Port>>> {
        self.connection.as_ref()
    }

    /// L'autre extrémité d'une connexion, si elle vit.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn connected(&self) -> Option<Arc<Object<Port>>> {
        self.connected.lock().upgrade()
    }

    /// Relie `self` à l'autre extrémité `other`.
    pub(crate) fn connect_to(&self, other: &Arc<Object<Port>>) {
        *self.connected.lock() = Arc::downgrade(other);
    }

    /// PortContext d'un port de communication du serveur.
    pub fn context(&self) -> u32 {
        self.context.load(Ordering::Acquire)
    }

    /// Fixe son PortContext (le handle du port quand le serveur n'en donne
    /// pas).
    pub fn set_context(&self, context: u32) {
        self.context.store(context, Ordering::Release);
    }

    /// Le port dont la file reçoit ce qu'on lit par lui : le port de
    /// connexion pour un port de communication du serveur, lui-même sinon.
    pub fn receive_port(port: &Arc<Object<Self>>) -> &Arc<Object<Self>> {
        match (port.kind, &port.connection) {
            (PortKind::ServerCommunication, Some(connection)) => connection,
            _ => port,
        }
    }

    /// Le port dont la file reçoit ce qu'on envoie par lui, et le contexte
    /// du message : le port de connexion et le contexte du port du serveur
    /// pour un port client ; le port client pour un port du serveur ; le
    /// port lui-même pour un port de connexion. `STATUS_PORT_DISCONNECTED`
    /// si l'autre extrémité n'est plus.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn send_port(port: &Arc<Object<Self>>) -> Result<(Arc<Object<Self>>, u32), NtStatus> {
        match port.kind {
            PortKind::Connection => Ok((port.clone(), 0)),
            PortKind::ServerCommunication => Ok((port.connected().ok_or(STATUS_PORT_DISCONNECTED)?, 0)),
            PortKind::Client => {
                let server = port.connected().ok_or(STATUS_PORT_DISCONNECTED)?;
                let connection = port.connection.clone().ok_or(STATUS_PORT_DISCONNECTED)?;
                Ok((connection, server.context()))
            }
        }
    }

    /// Met `message` en file et réveille un receveur.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub(crate) fn queue(&self, message: Message) -> Result<(), NtStatus> {
        self.queue.lock().push_back(message);
        // SAFETY: initialisé par `new`, vivant autant que `self`.
        unsafe { ke_release_semaphore::<KePlatform>(self.semaphore, SEMAPHORE_INCREMENT, 1) }.map(drop).map_err(|_| {
            self.queue.lock().pop_back();
            STATUS_INSUFFICIENT_RESOURCES
        })
    }

    /// LpcRequestPort, du noyau : met en file un datagramme de données
    /// `data`, marqué comme venu du mode noyau, sans client ;
    /// `STATUS_PORT_MESSAGE_TOO_LONG` au-delà de la taille des messages du
    /// port. Rend son identifiant.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn request(&self, data: &[u8]) -> Result<u32, NtStatus> {
        let total = HEADER_LENGTH + data.len() as u32;
        if total > self.max_message_length.max(HEADER_LENGTH) {
            return Err(STATUS_PORT_MESSAGE_TOO_LONG);
        }
        let message_id = next_message_id();
        let header = PortMessage32 {
            data_length: data.len() as u16,
            total_length: total as u16,
            kind: LPC_DATAGRAM | LPC_KERNELMODE_MESSAGE,
            data_info_offset: 0,
            client_id: ClientId32::default(),
            message_id,
            client_view_size: 0,
        };
        self.queue(Message { header, data: data.to_vec(), context: 0 })?;
        Ok(message_id)
    }

    /// Attend le prochain message de la file du port, en mode `mode`,
    /// jusqu'à `timeout` (format NT) s'il y en a une, et le rend ; `Err` avec
    /// le statut de l'attente si elle finit sans lui (`STATUS_TIMEOUT`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL. Peut attendre.
    pub fn receive(&self, mode: ProcessorMode, timeout: Option<i64>) -> Result<Message, NtStatus> {
        loop {
            // SAFETY: initialisé par `new`, vivant autant que `self`, que
            // l'appelant tient pendant l'attente.
            let waited =
                unsafe { ke_wait_for_single_object::<KePlatform>(self.semaphore_header(), mode, false, timeout) };
            if waited != STATUS_WAIT_0 {
                return Err(waited);
            }
            // The semaphore counts the queued messages: one is there.
            if let Some(message) = self.queue.lock().pop_front() {
                return Ok(message);
            }
        }
    }

    /// Les messages en file.
    pub fn queued(&self) -> usize {
        self.queue.lock().len()
    }

    fn semaphore_header(&self) -> *mut ke::dispatcher::DispatcherHeader {
        // SAFETY: le sémaphore vit autant que `self`.
        unsafe { ptr::addr_of_mut!((*self.semaphore).header) }
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        // SAFETY: alloué par `new` ; l'objet meurt, et qui l'attendait le
        // tenait.
        drop(unsafe { Box::from_raw(self.semaphore) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_keeps_its_limits() {
        let port = Port::create(0x28, 0x130, 16).expect("a port");
        assert_eq!((port.max_connection_info_length(), port.max_message_length()), (0x28, 0x130));
        assert_eq!((port.kind(), port.server_pid()), (PortKind::Connection, 16));
        assert_eq!(Port::create(0x149, 0x130, 16).err(), Some(STATUS_INVALID_PARAMETER_3));
        assert_eq!(Port::create(0x28, 0x149, 16).err(), Some(STATUS_INVALID_PARAMETER_4));
    }

    #[test]
    fn a_kernel_datagram_waits_in_the_queue() {
        let port = Port::create(0, 0x20, 16).expect("a port");
        let first = port.request(b"Mino").expect("a datagram");
        let second = port.request(&[7; 8]).expect("another");
        assert_ne!(first, second, "each message has its id");
        assert_eq!(port.request(&[0; 9]), Err(STATUS_PORT_MESSAGE_TOO_LONG), "past the port's message length");
        assert_eq!(port.queued(), 2);
        let message = port.queue.lock().pop_front().expect("the first");
        assert_eq!((message.header.data_length, message.header.total_length), (4, 0x1C));
        assert_eq!(message.header.kind, LPC_DATAGRAM | LPC_KERNELMODE_MESSAGE);
        assert_eq!(&message.to_bytes()[0x18..], b"Mino");
    }

    #[test]
    fn messages_go_where_the_kind_of_port_says() {
        let connection = Port::create(0x10, 0x100, 16).expect("a port");
        let client = Port::communication(PortKind::Client, &connection);
        let server = Port::communication(PortKind::ServerCommunication, &connection);
        assert_eq!((client.max_message_length(), server.server_pid()), (0x100, 16), "the connection's sizes");
        assert_eq!(Port::send_port(&client).err(), Some(STATUS_PORT_DISCONNECTED), "not connected yet");
        client.connect_to(&server);
        server.connect_to(&client);
        server.set_context(0x1234);
        let (to, context) = Port::send_port(&client).expect("connected");
        assert!(Arc::ptr_eq(&to, &connection) && context == 0x1234, "a client sends to the connection port");
        assert!(Arc::ptr_eq(&Port::send_port(&server).expect("connected").0, &client), "a server to its client");
        assert!(Arc::ptr_eq(&Port::send_port(&connection).expect("itself").0, &connection));
        assert!(Arc::ptr_eq(Port::receive_port(&server), &connection), "a server reads its connection port");
        assert!(Arc::ptr_eq(Port::receive_port(&client), &client));
        drop(server);
        assert_eq!(Port::send_port(&client).err(), Some(STATUS_PORT_DISCONNECTED), "the server is gone");
    }
}
