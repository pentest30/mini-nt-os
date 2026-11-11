//! Les ports de complétion d'E/S : le type `IoCompletion` (IopCompletionType,
//! autour du KQUEUE de Ke). Un port tient une file de paquets — une clé, un
//! contexte, un statut et une information, ce qu'une E/S finie y mettrait —
//! qu'un thread retire en l'attendant (NtRemoveIoCompletion, KeRemoveQueue)
//! et que d'autres y mettent (NtSetIoCompletion, KeInsertQueue). Le pool de
//! threads de `ntdll` fait travailler ses threads sur un port
//! (RtlQueueWorkItem, QueueUserWorkItem) ; le serveur RPC de `rpcrt4` y
//! confie chaque requête qu'il reçoit (sans port, `lsass` ne répond à
//! aucun appel, ADR-023).
//!
//! Comme la file d'un port LPC : les paquets sous un verrou, et un sémaphore
//! de Ke qui les compte ; qui retire attend le sémaphore, puis prend le
//! premier paquet. Les paquets sortent dans l'ordre où ils sont entrés.
//!
//! Pas encore : le nombre de threads concurrents (KeRemoveQueue ne laisse
//! courir que `NumberOfConcurrentThreads` threads du port à la fois ; ici,
//! tous) ; l'association d'un fichier (FileCompletionInformation : la fin
//! d'une E/S du fichier met son paquet dans le port) ; l'attente d'un port
//! par NtWaitForSingleObject.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ptr;

use abi::ntstatus::{NtStatus, STATUS_INSUFFICIENT_RESOURCES, STATUS_WAIT_0};
use hal::sync::KSpinLock;
use ke::dispatcher::{
    ke_initialize_semaphore, ke_release_semaphore, ke_wait_for_single_object, KSemaphore, ProcessorMode,
};
use ke::sched::KePlatform;
use ob::{create_object, AccessMask, GenericMapping, Object, ObjectType};

/// Lire l'état du port (NtQueryIoCompletion).
pub const IO_COMPLETION_QUERY_STATE: AccessMask = AccessMask(0x0001);
/// Y mettre et en retirer des paquets.
pub const IO_COMPLETION_MODIFY_STATE: AccessMask = AccessMask(0x0002);
/// IO_COMPLETION_ALL_ACCESS d'XP.
pub const IO_COMPLETION_ALL_ACCESS: AccessMask =
    AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | AccessMask::SYNCHRONIZE.0 | 0x0003);

/// Le type `IoCompletion`, avec la correspondance générique d'XP.
pub static IO_COMPLETION_TYPE: ObjectType = ObjectType::new(
    "IoCompletion",
    IO_COMPLETION_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | IO_COMPLETION_QUERY_STATE.0),
        write: AccessMask(AccessMask::STANDARD_RIGHTS_WRITE.0 | IO_COMPLETION_MODIFY_STATE.0),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | AccessMask::SYNCHRONIZE.0),
        all: IO_COMPLETION_ALL_ACCESS,
    },
);

/// Un paquet : ce que rend NtRemoveIoCompletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    /// KeyContext (la clé du fichier associé, ou ce que donne NtSetIoCompletion).
    pub key: u32,
    /// ApcContext.
    pub context: u32,
    /// Le bloc d'état : statut et information.
    pub status: NtStatus,
    pub information: u32,
}

/// Le corps d'un port de complétion.
pub struct IoCompletion {
    packets: KSpinLock<VecDeque<Packet>>,
    /// Compte les paquets en file ; qui retire l'attend.
    semaphore: *mut KSemaphore,
    /// NumberOfConcurrentThreads, gardé pour NtQueryIoCompletion (pas encore
    /// appliqué : voir le module).
    concurrency: u32,
}

// SAFETY: Ke ne touche au sémaphore que sous le verrou dispatcher ; le
// pointeur ne change pas ; la file est sous son verrou.
unsafe impl Send for IoCompletion {}
// SAFETY: voir `Send`.
unsafe impl Sync for IoCompletion {}

impl IoCompletion {
    /// IoCreateCompletion (NtCreateIoCompletion) : un port vide.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(concurrency: u32) -> Arc<Object<Self>> {
        let semaphore = Box::into_raw(Box::<KSemaphore>::new_uninit()).cast::<KSemaphore>();
        // SAFETY: mémoire neuve, à adresse fixe ; personne ne l'attend.
        unsafe { ke_initialize_semaphore(semaphore, 0, i32::MAX) };
        create_object(&IO_COMPLETION_TYPE, Self { packets: KSpinLock::new(VecDeque::new()), semaphore, concurrency })
    }

    /// KeInsertQueue (NtSetIoCompletion) : met `packet` en file et réveille
    /// un thread qui attend. `STATUS_INSUFFICIENT_RESOURCES` si le compte
    /// des paquets est au plus haut.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn insert(&self, packet: Packet) -> Result<(), NtStatus> {
        self.packets.lock().push_back(packet);
        // SAFETY: initialisé par `create`, vivant autant que `self`.
        unsafe { ke_release_semaphore::<KePlatform>(self.semaphore, 0, 1) }.map(drop).map_err(|_| {
            self.packets.lock().pop_back();
            STATUS_INSUFFICIENT_RESOURCES
        })
    }

    /// KeRemoveQueue (NtRemoveIoCompletion) : le premier paquet, attendu en
    /// mode `mode`, sans alerte, jusqu'à `timeout` (format NT) s'il y en a
    /// une ; `Ok(None)` si elle passe sans paquet (`STATUS_TIMEOUT`), `Err`
    /// avec le statut d'une attente qui finit autrement.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL. Peut attendre.
    pub fn remove(&self, mode: ProcessorMode, timeout: Option<i64>) -> Result<Option<Packet>, NtStatus> {
        loop {
            // SAFETY: initialisé par `create`, vivant autant que `self`, que
            // l'appelant tient pendant l'attente.
            let header = unsafe { ptr::addr_of_mut!((*self.semaphore).header) };
            // SAFETY: voir ci-dessus.
            let waited = unsafe { ke_wait_for_single_object::<KePlatform>(header, mode, false, timeout) };
            if waited == abi::ntstatus::STATUS_TIMEOUT {
                return Ok(None);
            }
            if waited != STATUS_WAIT_0 {
                return Err(waited);
            }
            // The semaphore counts the queued packets: one is there.
            if let Some(packet) = self.packets.lock().pop_front() {
                return Ok(Some(packet));
            }
        }
    }

    /// Les paquets en file (IoCompletionBasicInformation : `Depth`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn depth(&self) -> usize {
        self.packets.lock().len()
    }

    /// Le nombre de threads concurrents demandé à sa création.
    pub fn concurrency(&self) -> u32 {
        self.concurrency
    }
}

impl Drop for IoCompletion {
    fn drop(&mut self) {
        // SAFETY: alloué par `create` ; l'objet meurt, et qui l'attendait le
        // tenait.
        drop(unsafe { Box::from_raw(self.semaphore) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::ntstatus::{STATUS_PENDING, STATUS_SUCCESS};

    fn packet(key: u32) -> Packet {
        Packet { key, context: key + 1, status: STATUS_SUCCESS, information: key * 2 }
    }

    #[test]
    fn packets_come_out_in_the_order_they_went_in() {
        let port = IoCompletion::create(0);
        assert_eq!(port.depth(), 0);
        port.insert(packet(1)).unwrap();
        port.insert(Packet { status: STATUS_PENDING, ..packet(7) }).unwrap();
        assert_eq!(port.depth(), 2);
        assert_eq!(port.remove(ProcessorMode::Kernel, Some(0)), Ok(Some(packet(1))));
        let second = port.remove(ProcessorMode::Kernel, None).unwrap().expect("queued");
        assert_eq!((second.key, second.context, second.status, second.information), (7, 8, STATUS_PENDING, 14));
        assert_eq!(port.depth(), 0);
    }

    #[test]
    fn an_empty_port_times_out() {
        let port = IoCompletion::create(2);
        assert_eq!(port.concurrency(), 2);
        assert_eq!(port.remove(ProcessorMode::Kernel, Some(0)), Ok(None), "a zero timeout, nothing queued");
        port.insert(packet(3)).unwrap();
        assert_eq!(port.remove(ProcessorMode::Kernel, Some(0)), Ok(Some(packet(3))), "then one");
        assert_eq!(port.remove(ProcessorMode::Kernel, Some(0)), Ok(None), "taken once");
    }
}
