//! Les services de Lpc (`lpc::port`) : créer un port de connexion
//! (NtCreatePort), y attendre un message (NtReplyWaitReceivePort).
//!
//! Pas encore : la connexion et les réponses. NtReplyWaitReceivePort avec un
//! message de réponse rend `STATUS_NOT_IMPLEMENTED`, journalisé une fois :
//! sans client, aucune requête n'attend de réponse.

use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{NtStatus, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
use ke::dispatcher::ProcessorMode;
use ke::usermem::UserPtr;
use lpc::{Port, PORT_ALL_ACCESS, PORT_TYPE};
use ob::{AccessMask, Handle, ObjectRef};

fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// NtCreatePort(*PortHandle, ObjectAttributes, MaxConnectionInfoLength,
/// MaxMessageLength, MaxPoolUsage) : un port de connexion, nommé (ou non)
/// d'après les attributs, avec `PORT_ALL_ACCESS` ; `STATUS_INVALID_PARAMETER_3` ou `_4` pour une
/// taille au-delà de `PORT_MAXIMUM_MESSAGE_LENGTH`. `MaxPoolUsage` n'a pas
/// d'effet (pas de quotas).
pub(super) fn nt_create_port(arguments: &[u32]) -> NtStatus {
    status(Port::create(arguments[2], arguments[3]).and_then(|port| {
        let object: ObjectRef = port;
        super::object::create_named(arguments[0], PORT_ALL_ACCESS.0, arguments[1], object)
    }))
}

/// NtReplyWaitReceivePort(PortHandle, *PortContext, ReplyMessage,
/// ReceiveMessage) : attend le prochain message du port et le copie en
/// `ReceiveMessage` (en-tête puis données), avec le contexte de son client
/// en `PortContext` s'il est demandé (0 : un message du noyau, sans client).
pub(super) fn nt_reply_wait_receive_port(arguments: &[u32]) -> NtStatus {
    static REPLIES: AtomicBool = AtomicBool::new(false);
    let (handle, context, reply, receive) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let wait = || {
        if reply != 0 {
            if !REPLIES.swap(true, Ordering::Relaxed) {
                log::warn!("sys: NtReplyWaitReceivePort with a reply is not implemented (no connections yet)");
            }
            return Err(STATUS_NOT_IMPLEMENTED);
        }
        let port =
            super::current_process().handle_table.reference_as::<Port>(Handle(handle), &PORT_TYPE, AccessMask::NONE)?;
        ke::usermem::probe_for_write(u64::from(receive), port.max_message_length().max(0x18) as usize, 4)?;
        if context != 0 {
            ke::usermem::probe_for_write(u64::from(context), 4, 4)?;
        }
        let message = port.receive(ProcessorMode::User)?;
        ke::usermem::copy_to_user(u64::from(receive), &message.to_bytes())?;
        if context != 0 {
            UserPtr::<u32>::new(context).write(&0)?;
        }
        Ok(STATUS_SUCCESS)
    };
    status(wait())
}
