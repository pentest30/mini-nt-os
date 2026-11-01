//! Les ports (LpcPortObjectType).
//!
//! Un serveur crée un port de connexion (NtCreatePort), puis attend ses
//! messages (NtReplyWaitReceivePort) : ils arrivent dans la file du port,
//! que compte un sémaphore. Le noyau peut y envoyer un datagramme
//! ([`Port::request`], LpcRequestPort) ; les clients viendront avec la
//! connexion.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::lpc::{PortMessage32, LPC_DATAGRAM, LPC_KERNELMODE_MESSAGE, PORT_MAXIMUM_MESSAGE_LENGTH};
use abi::ntstatus::{
    NtStatus, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER_3, STATUS_INVALID_PARAMETER_4,
    STATUS_PORT_MESSAGE_TOO_LONG,
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

fn next_message_id() -> u32 {
    loop {
        let id = NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

/// Un message en file : son en-tête, puis ses données.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub header: PortMessage32,
    pub data: Vec<u8>,
}

impl Message {
    /// Ses octets, en-tête puis données, tels qu'ils vont au destinataire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(usize::from(self.header.total_length));
        bytes.extend_from_slice(self.header.as_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

/// Le corps d'un objet port.
pub struct Port {
    /// La taille au plus des données de connexion.
    max_connection_info_length: u32,
    /// La taille au plus d'un message, en-tête compris.
    max_message_length: u32,
    /// Les messages qui attendent d'être reçus.
    queue: KSpinLock<VecDeque<Message>>,
    /// Compte les messages en file ; qui reçoit l'attend.
    semaphore: *mut KSemaphore,
}

// SAFETY: Ke ne touche au sémaphore que sous le verrou dispatcher ; le
// pointeur ne change pas ; la file est sous son verrou.
unsafe impl Send for Port {}
// SAFETY: voir `Send`.
unsafe impl Sync for Port {}

impl Port {
    /// NtCreatePort : un port de connexion, dont les données de connexion
    /// font au plus `max_connection_info_length` octets et les messages
    /// `max_message_length` ; `STATUS_INVALID_PARAMETER_3` ou `_4` au-delà de
    /// `PORT_MAXIMUM_MESSAGE_LENGTH`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(max_connection_info_length: u32, max_message_length: u32) -> Result<Arc<Object<Self>>, NtStatus> {
        if max_connection_info_length > PORT_MAXIMUM_MESSAGE_LENGTH {
            return Err(STATUS_INVALID_PARAMETER_3);
        }
        if max_message_length > PORT_MAXIMUM_MESSAGE_LENGTH {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        let semaphore = Box::into_raw(Box::<KSemaphore>::new_uninit()).cast::<KSemaphore>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_semaphore(semaphore, 0, MAXIMUM_QUEUED) };
        let port =
            Port { max_connection_info_length, max_message_length, queue: KSpinLock::new(VecDeque::new()), semaphore };
        Ok(create_object(&PORT_TYPE, port))
    }

    /// MaxConnectionInfoLength.
    pub fn max_connection_info_length(&self) -> u32 {
        self.max_connection_info_length
    }

    /// MaxMessageLength.
    pub fn max_message_length(&self) -> u32 {
        self.max_message_length
    }

    /// Met `message` en file et réveille un receveur.
    fn queue(&self, message: Message) -> Result<(), NtStatus> {
        self.queue.lock().push_back(message);
        // SAFETY: initialisé par `create`, vivant autant que `self`.
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
        let header_length = core::mem::size_of::<PortMessage32>() as u32;
        let total = header_length + data.len() as u32;
        if total > self.max_message_length.max(header_length) {
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
        self.queue(Message { header, data: data.to_vec() })?;
        Ok(message_id)
    }

    /// Attend le prochain message du port (NtReplyWaitReceivePort), en mode
    /// utilisateur ou noyau, et le rend ; `Err` avec le statut de l'attente
    /// si elle finit sans lui.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL. Peut attendre.
    pub fn receive(&self, mode: ProcessorMode) -> Result<Message, NtStatus> {
        loop {
            // SAFETY: initialisé par `create`, vivant autant que `self`, que
            // l'appelant tient pendant l'attente.
            let waited = unsafe { ke_wait_for_single_object::<KePlatform>(self.semaphore_header(), mode, false, None) };
            if waited != abi::ntstatus::STATUS_WAIT_0 {
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
        // SAFETY: alloué par `create` ; l'objet meurt, et qui l'attendait le
        // tenait.
        drop(unsafe { Box::from_raw(self.semaphore) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_keeps_its_limits() {
        let port = Port::create(0x28, 0x130).expect("a port");
        assert_eq!((port.max_connection_info_length(), port.max_message_length()), (0x28, 0x130));
        assert_eq!(Port::create(0x149, 0x130).err(), Some(STATUS_INVALID_PARAMETER_3));
        assert_eq!(Port::create(0x28, 0x149).err(), Some(STATUS_INVALID_PARAMETER_4));
    }

    #[test]
    fn a_kernel_datagram_waits_in_the_queue() {
        let port = Port::create(0, 0x20).expect("a port");
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
}
