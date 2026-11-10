//! Les services de Lpc (`lpc`) : créer un port de connexion (NtCreatePort),
//! s'y connecter (NtConnectPort, NtSecureConnectPort), accepter ou refuser
//! une connexion (NtAcceptConnectPort, NtCompleteConnectPort, NtListenPort),
//! envoyer une requête et attendre sa réponse (NtRequestWaitReplyPort), un
//! datagramme (NtRequestPort), répondre (NtReplyPort), recevoir
//! (NtReplyWaitReceivePort, NtReplyWaitReceivePortEx) ; et donner le port
//! des erreurs graves (NtSetDefaultHardErrorPort).
//!
//! Pas encore, journalisés une fois et rendant `STATUS_NOT_IMPLEMENTED` : la
//! section d'un serveur (`ServerView` de NtAcceptConnectPort ; ReactOS non
//! plus), les rappels (une requête `LPC_REQUEST` envoyée par
//! NtRequestWaitReplyPort), les données décrites par `DataInfoOffset`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use abi::lpc::{
    PortMessage32, PortView32, RemotePortView32, SecurityQualityOfService32, LPC_CONNECTION_REQUEST, LPC_REQUEST,
};
use abi::ntstatus::{
    NtStatus, STATUS_INVALID_CID, STATUS_INVALID_PARAMETER, STATUS_INVALID_PORT_HANDLE, STATUS_NOT_IMPLEMENTED,
    STATUS_OBJECT_NAME_INVALID, STATUS_SERVER_SID_MISMATCH, STATUS_SUCCESS,
};
use abi::teb32::ClientId32;
use ke::dispatcher::ProcessorMode;
use ke::usermem::UserPtr;
use lpc::{Message, Port, HEADER_LENGTH, PORT_ALL_ACCESS, PORT_TYPE};
use mm::section::{Section, SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_TYPE};
use mm::vad::PageProtect;
use ob::{AccessMask, Handle, Object, ObjectRef};

fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// Ce qui manque encore, journalisé à sa première demande.
fn not_implemented(seen: &AtomicBool, what: &str) -> NtStatus {
    if !seen.swap(true, Ordering::Relaxed) {
        log::warn!("sys: {what} is not implemented");
    }
    STATUS_NOT_IMPLEMENTED
}

/// Le CLIENT_ID du thread courant.
fn current_client() -> ClientId32 {
    let thread = ps::ethread::current_thread().expect("a system service outside a Ps thread");
    ClientId32 { unique_process: thread.pid(), unique_thread: thread.tid() }
}

/// Le port que désigne `handle` dans le processus courant, avec les droits
/// `access`.
fn reference_port(handle: u32, access: AccessMask) -> Result<Arc<Object<Port>>, NtStatus> {
    super::current_process().handle_table.reference_as::<Port>(Handle(handle), &PORT_TYPE, access)
}

/// PsLookupProcessThreadByCid : `client` désigne un thread vivant de ce
/// processus, ou le thread noyau du moniteur de références (`ntoskrnl::srm`) ;
/// `STATUS_INVALID_CID` sinon.
fn check_client(client: ClientId32) -> Result<(), NtStatus> {
    if !ps::ethread::client_exists(client.unique_process, client.unique_thread) {
        return Err(STATUS_INVALID_CID);
    }
    Ok(())
}

/// L'en-tête du message en `address` et ses `DataLength` octets de données.
fn read_message(address: u32) -> Result<(PortMessage32, Vec<u8>), NtStatus> {
    let header = UserPtr::<PortMessage32>::new(address).read()?;
    let mut data = alloc::vec![0u8; usize::from(header.data_length)];
    ke::usermem::copy_from_user(&mut data, u64::from(address) + u64::from(HEADER_LENGTH))?;
    Ok((header, data))
}

/// Écrit `message`, en-tête puis données, en `address`.
fn write_message(address: u32, message: &Message) -> Result<(), NtStatus> {
    ke::usermem::copy_to_user(u64::from(address), &message.to_bytes())
}

/// Donne `port` au processus courant, avec `PORT_ALL_ACCESS`, et rend son
/// handle.
fn insert_port(port: Arc<Object<Port>>) -> Result<Handle, NtStatus> {
    let object: ObjectRef = port;
    let process = super::current_process();
    let (handle, _) =
        ob::insert_object(ob::namespace(), object, None, None, 0, &process.handle_table, PORT_ALL_ACCESS)?;
    Ok(handle)
}

/// Projette en lecture-écriture dans le processus courant la vue de
/// `section` en `offset`, de `size` octets (toute la suite pour 0) ; rend
/// son adresse et sa taille.
fn map_view(section: &Arc<Section>, offset: u32, size: u32) -> Result<(u32, u32), NtStatus> {
    let process = super::current_process();
    let view = process
        .with_space(|space| space.map_view(section, 0, u64::from(offset), u64::from(size), PageProtect::READWRITE))??;
    Ok((view.base as u32, view.size as u32))
}

/// Défait une vue projetée par [`map_view`].
fn unmap_view(base: u32) {
    let _ = super::current_process().with_space(|space| space.unmap_view(u64::from(base)));
}

/// NtCreatePort(*PortHandle, ObjectAttributes, MaxConnectionInfoLength,
/// MaxMessageLength, MaxPoolUsage) : un port de connexion du processus
/// courant, son serveur, nommé (ou non) d'après les attributs, avec
/// `PORT_ALL_ACCESS` ; `STATUS_INVALID_PARAMETER_3` ou `_4` pour une taille
/// au-delà de `PORT_MAXIMUM_MESSAGE_LENGTH`. `MaxPoolUsage` n'a pas d'effet
/// (pas de quotas).
pub(super) fn nt_create_port(arguments: &[u32]) -> NtStatus {
    let server = super::current_process().pid();
    status(Port::create(arguments[2], arguments[3], server).and_then(|port| {
        let object: ObjectRef = port;
        super::object::create_named(arguments[0], PORT_ALL_ACCESS.0, arguments[1], object)
    }))
}

/// NtConnectPort(*PortHandle, PortName, SecurityQos, ClientView, ServerView,
/// *MaxMessageLength, ConnectionInformation, ConnectionInformationLength) :
/// NtSecureConnectPort sans SID du serveur.
pub(super) fn nt_connect_port(arguments: &[u32]) -> NtStatus {
    let [handle, name, qos, client_view, server_view, max_length, info, info_length] = arguments[..8] else {
        unreachable!("eight arguments")
    };
    status(connect(handle, name, qos, client_view, 0, server_view, max_length, info, info_length))
}

/// NtSecureConnectPort(*PortHandle, PortName, SecurityQos, ClientView,
/// ServerSid, ServerView, *MaxMessageLength, ConnectionInformation,
/// ConnectionInformationLength) : le thread se connecte au port de connexion
/// nommé `PortName` (`PORT_CONNECT`) et attend la réponse du serveur ; le
/// serveur doit avoir `ServerSid` pour utilisateur, s'il est donné
/// (`STATUS_SERVER_SID_MISMATCH`). Les données de connexion vont au serveur
/// et en reviennent, telles qu'il les laisse ; la section de `ClientView`
/// est projetée chez le client, puis chez le serveur qui accepte, et
/// `ClientView` dit où chacun la voit. Acceptée, l'appelant reçoit son port
/// client et la taille des messages ; refusée,
/// `STATUS_PORT_CONNECTION_REFUSED`. `SecurityQos` est lu, sans effet (pas
/// d'emprunt d'identité).
pub(super) fn nt_secure_connect_port(arguments: &[u32]) -> NtStatus {
    let [handle, name, qos, client_view, sid, server_view, max_length, info, info_length] = arguments[..9] else {
        unreachable!("nine arguments")
    };
    status(connect(handle, name, qos, client_view, sid, server_view, max_length, info, info_length))
}

/// Le SID en `address`.
fn capture_sid(address: u32) -> Result<se::Sid, NtStatus> {
    let mut header = [0u8; 8];
    ke::usermem::copy_from_user(&mut header, u64::from(address))?;
    let count = se::Sid::check_header(&header)?;
    let mut bytes = alloc::vec![0u8; se::Sid::length_required(count)];
    ke::usermem::copy_from_user(&mut bytes, u64::from(address))?;
    se::Sid::parse(&bytes)
}

#[expect(clippy::too_many_arguments, reason = "the arguments of NtSecureConnectPort")]
fn connect(
    handle: u32,
    name: u32,
    qos: u32,
    client_view: u32,
    sid: u32,
    server_view: u32,
    max_length: u32,
    info: u32,
    info_length: u32,
) -> Result<NtStatus, NtStatus> {
    let out = UserPtr::<u32>::new(handle);
    ke::usermem::probe_for_write(u64::from(handle), 4, 4)?;
    UserPtr::<SecurityQualityOfService32>::new(qos).read()?;
    let view = match client_view {
        0 => None,
        at => {
            ke::usermem::probe_for_write(u64::from(at), size_of::<PortView32>(), 4)?;
            Some(UserPtr::<PortView32>::new(at).read()?)
        }
    };
    if view.is_some_and(|view| view.length as usize != size_of::<PortView32>()) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if server_view != 0 {
        ke::usermem::probe_for_write(u64::from(server_view), size_of::<RemotePortView32>(), 4)?;
        if UserPtr::<RemotePortView32>::new(server_view).read()?.length as usize != size_of::<RemotePortView32>() {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    if max_length != 0 {
        ke::usermem::probe_for_write(u64::from(max_length), 4, 4)?;
    }
    let mut length = match info_length {
        0 => 0,
        at => {
            ke::usermem::probe_for_write(u64::from(at), 4, 4)?;
            UserPtr::<u32>::new(at).read()?
        }
    };
    if info != 0 {
        ke::usermem::probe_for_write(u64::from(info), length as usize, 4)?;
    }
    let sid = match sid {
        0 => None,
        at => Some(capture_sid(at)?),
    };
    let units = super::object::capture_unicode_string(name)?;
    let name = alloc::string::String::from_utf16(&units).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
    let object = ob::namespace().open(&name, None, Some(&PORT_TYPE), 0)?;
    let port = ob::downcast::<Port>(&object).ok_or(STATUS_INVALID_PORT_HANDLE)?;
    if let Some(sid) = sid {
        let server = ps::eprocess::lookup_process(port.server_pid()).map_err(|_| STATUS_SERVER_SID_MISMATCH)?;
        if server.primary_token().user().sid != sid {
            return Err(STATUS_SERVER_SID_MISMATCH);
        }
    }
    let view = match view {
        None => None,
        Some(view) => {
            let section = super::current_process().handle_table.reference_as::<Arc<Section>>(
                Handle(view.section_handle),
                &SECTION_TYPE,
                AccessMask(SECTION_MAP_READ.0 | SECTION_MAP_WRITE.0),
            )?;
            let section: Arc<Section> = (**section).clone();
            let (base, size) = map_view(&section, view.section_offset, view.view_size)?;
            Some(lpc::ClientView { section, offset: view.section_offset, size, base, remote_base: 0 })
        }
    };
    let mapped = view.as_ref().map(|view| view.base);
    length = length.min(port.max_connection_info_length());
    let mut data = alloc::vec![0u8; length as usize];
    if info != 0 {
        ke::usermem::copy_from_user(&mut data, u64::from(info))?;
    }
    let connected = match lpc::connect(&port, current_client(), &data, view, ProcessorMode::User) {
        Ok(connected) => connected,
        Err(status) => {
            if let Some(base) = mapped {
                unmap_view(base);
            }
            return Err(status);
        }
    };
    let max_message_length = connected.max_message_length;
    let returned = connected.info.clone();
    let view = connected.view.clone();
    let handle = insert_port(connected.port)?;
    let write = || {
        super::object::give_handle(&out, handle)?;
        if max_length != 0 {
            UserPtr::<u32>::new(max_length).write(&max_message_length)?;
        }
        if info != 0 {
            let length = (length as usize).min(returned.len());
            if info_length != 0 {
                UserPtr::<u32>::new(info_length).write(&(length as u32))?;
            }
            ke::usermem::copy_to_user(u64::from(info), &returned[..length])?;
        }
        if let (Some(view), true) = (view, client_view != 0) {
            let at = |field: usize| UserPtr::<u32>::new(client_view + field as u32);
            at(offset_of!(PortView32, section_offset)).write(&view.offset)?;
            at(offset_of!(PortView32, view_size)).write(&view.size)?;
            at(offset_of!(PortView32, view_base)).write(&view.base)?;
            at(offset_of!(PortView32, view_remote_base)).write(&view.remote_base)?;
        }
        if server_view != 0 {
            // No server sections: the view the server shared is none.
            ke::usermem::copy_to_user(u64::from(server_view), &[0; size_of::<RemotePortView32>()])?;
        }
        Ok(STATUS_SUCCESS)
    };
    write().inspect_err(|_| {
        let _ = super::current_process().handle_table.close(handle);
    })
}

/// NtAcceptConnectPort(*PortHandle, PortContext, ConnectionRequest,
/// AcceptConnection, ServerView, ClientView) : le serveur répond à la
/// demande de connexion que désignent le CLIENT_ID et l'identifiant de
/// `ConnectionRequest`, dont les données reviennent au client. Acceptée,
/// l'appelant reçoit son port de communication, de contexte `PortContext`
/// (son handle s'il est nul), la section du client est projetée chez lui et
/// `ClientView` dit où ; le client attend NtCompleteConnectPort. Refusée, le
/// client se réveille aussitôt, et rien n'est rendu. `STATUS_INVALID_CID`
/// pour un client qui n'existe pas ; `STATUS_REPLY_MESSAGE_MISMATCH` s'il
/// n'attend pas cette réponse de ce serveur.
pub(super) fn nt_accept_connect_port(arguments: &[u32]) -> NtStatus {
    static SERVER_VIEWS: AtomicBool = AtomicBool::new(false);
    let [handle, context, request, accept, server_view, client_view] = arguments[..6] else {
        unreachable!("six arguments")
    };
    let accept_connection = || {
        let out = UserPtr::<u32>::new(handle);
        ke::usermem::probe_for_write(u64::from(handle), 4, 4)?;
        let (header, info) = read_message(request)?;
        if server_view != 0 {
            ke::usermem::probe_for_write(u64::from(server_view), size_of::<PortView32>(), 4)?;
            if UserPtr::<PortView32>::new(server_view).read()?.length as usize != size_of::<PortView32>() {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
        if client_view != 0 {
            ke::usermem::probe_for_write(u64::from(client_view), size_of::<RemotePortView32>(), 4)?;
            if UserPtr::<RemotePortView32>::new(client_view).read()?.length as usize != size_of::<RemotePortView32>() {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
        check_client(header.client_id)?;
        if server_view != 0 {
            return Err(not_implemented(&SERVER_VIEWS, "NtAcceptConnectPort with a server view"));
        }
        // A BOOLEAN, in the low byte of its argument.
        let accept = accept as u8 != 0;
        let server = super::current_process().pid();
        let map = |view: &lpc::ClientView| map_view(&view.section, view.offset, view.size).map(|(base, _)| base);
        let Some(accepted) = lpc::accept(header.client_id, header.message_id, server, &info, accept, context, map)?
        else {
            return Ok(STATUS_SUCCESS);
        };
        let port = accepted.port.clone();
        let handle = insert_port(accepted.port)?;
        if context == 0 {
            port.set_context(handle.0);
        }
        super::object::give_handle(&out, handle)?;
        if client_view != 0 {
            let (base, size) = accepted.client_view.unwrap_or((0, 0));
            UserPtr::<u32>::new(client_view + offset_of!(RemotePortView32, view_size) as u32).write(&size)?;
            UserPtr::<u32>::new(client_view + offset_of!(RemotePortView32, view_base) as u32).write(&base)?;
        }
        Ok(STATUS_SUCCESS)
    };
    status(accept_connection())
}

/// NtCompleteConnectPort(PortHandle) : réveille le client dont le serveur a
/// accepté la connexion par ce port de communication (`PORT_ALL_ACCESS`) ;
/// `STATUS_INVALID_PORT_HANDLE` pour un autre port ;
/// `STATUS_INVALID_PARAMETER` si aucun client n'attend.
pub(super) fn nt_complete_connect_port(arguments: &[u32]) -> NtStatus {
    status(reference_port(arguments[0], PORT_ALL_ACCESS).and_then(|port| lpc::complete(&port)).map(|()| STATUS_SUCCESS))
}

/// L'en-tête et les données d'un message que le mode utilisateur envoie, son
/// type vérifié : 0 (le noyau en fait une requête ou un datagramme), le
/// drapeau `0x4000` ôté ; une requête `LPC_REQUEST` (un rappel) n'est pas
/// encore servie ; un autre type rend `STATUS_INVALID_PARAMETER`.
fn outgoing(address: u32) -> Result<(PortMessage32, Vec<u8>), NtStatus> {
    static CALLBACKS: AtomicBool = AtomicBool::new(false);
    static DATA_INFO: AtomicBool = AtomicBool::new(false);
    let (header, data) = read_message(address)?;
    let kind = header.kind & !0x4000;
    if kind == LPC_REQUEST {
        return Err(not_implemented(&CALLBACKS, "an LPC callback (an LPC_REQUEST sent while replying)"));
    }
    if kind != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if header.data_info_offset != 0 {
        return Err(not_implemented(&DATA_INFO, "an LPC message with data information (DataInfoOffset)"));
    }
    Ok((header, data))
}

/// NtRequestWaitReplyPort(PortHandle, Request, Reply) : envoie la requête
/// (`LPC_REQUEST`) par le port et attend sa réponse, copiée en `Reply`.
/// `STATUS_INVALID_PARAMETER` pour des données plus longues que le message
/// ou un type de message donné ; `STATUS_PORT_MESSAGE_TOO_LONG` au-delà de
/// la taille des messages du port ; `STATUS_PORT_DISCONNECTED` sans serveur.
pub(super) fn nt_request_wait_reply_port(arguments: &[u32]) -> NtStatus {
    let (handle, request, reply) = (arguments[0], arguments[1], arguments[2]);
    let call = || {
        let (header, data) = outgoing(request)?;
        ke::usermem::probe_for_write(u64::from(reply), HEADER_LENGTH as usize, 4)?;
        let port = reference_port(handle, AccessMask::NONE)?;
        let answer = lpc::request_wait_reply(&port, current_client(), &header, data, ProcessorMode::User)?;
        write_message(reply, &answer)?;
        Ok(STATUS_SUCCESS)
    };
    status(call())
}

/// NtRequestPort(PortHandle, Request) : envoie un datagramme (`LPC_DATAGRAM`)
/// par le port, sans attendre de réponse ; les refus de
/// NtRequestWaitReplyPort.
pub(super) fn nt_request_port(arguments: &[u32]) -> NtStatus {
    let send = || {
        let (header, data) = outgoing(arguments[1])?;
        let port = reference_port(arguments[0], AccessMask::NONE)?;
        lpc::send(&port, current_client(), &header, data)?;
        Ok(STATUS_SUCCESS)
    };
    status(send())
}

/// Répond par `port` avec le message en `address` (`lpc::reply`).
fn reply_with(port: &Port, address: u32) -> Result<(), NtStatus> {
    let (header, data) = read_message(address)?;
    lpc::check_message(&header, port.max_message_length())?;
    if header.message_id == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    check_client(header.client_id)?;
    lpc::reply(port, &header, data)
}

/// NtReplyPort(PortHandle, ReplyMessage) : répond au message que désignent
/// le CLIENT_ID et l'identifiant de la réponse ; le thread qui l'attend se
/// réveille avec elle. `STATUS_INVALID_CID` pour un thread qui n'existe pas ;
/// `STATUS_REPLY_MESSAGE_MISMATCH` s'il n'attend pas cette réponse.
pub(super) fn nt_reply_port(arguments: &[u32]) -> NtStatus {
    let reply = || {
        let port = reference_port(arguments[0], AccessMask::NONE)?;
        reply_with(&port, arguments[1])?;
        Ok(STATUS_SUCCESS)
    };
    status(reply())
}

/// NtReplyWaitReceivePort(PortHandle, *PortContext, ReplyMessage,
/// ReceiveMessage) : NtReplyWaitReceivePortEx sans délai.
pub(super) fn nt_reply_wait_receive_port(arguments: &[u32]) -> NtStatus {
    status(reply_wait_receive(arguments[0], arguments[1], arguments[2], arguments[3], 0))
}

/// NtReplyWaitReceivePortEx(PortHandle, *PortContext, ReplyMessage,
/// ReceiveMessage, Timeout) : répond s'il y a une réponse (NtReplyPort),
/// puis attend le prochain message du port, jusqu'à l'échéance s'il y en a
/// une (`STATUS_TIMEOUT`), et le copie en `ReceiveMessage`, avec le contexte
/// du port du serveur par lequel il est venu en `PortContext`. Une demande
/// de connexion arrive avec ses seules données de connexion, et un contexte
/// nul. Un port de communication du serveur reçoit ce qui arrive à son port
/// de connexion.
pub(super) fn nt_reply_wait_receive_port_ex(arguments: &[u32]) -> NtStatus {
    status(reply_wait_receive(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]))
}

fn reply_wait_receive(handle: u32, context: u32, reply: u32, receive: u32, timeout: u32) -> Result<NtStatus, NtStatus> {
    if context != 0 {
        ke::usermem::probe_for_write(u64::from(context), 4, 4)?;
    }
    let timeout = match timeout {
        0 => None,
        at => Some(UserPtr::<i64>::new(at).read()?),
    };
    let port = reference_port(handle, AccessMask::NONE)?;
    if reply != 0 {
        reply_with(&port, reply)?;
    }
    let message = match Port::receive_port(&port).receive(ProcessorMode::User, timeout) {
        Ok(message) => message,
        Err(abi::ntstatus::STATUS_TIMEOUT) => return Ok(abi::ntstatus::STATUS_TIMEOUT),
        Err(status) => return Err(status),
    };
    write_message(receive, &message)?;
    if context != 0 {
        // 0 for a connection request: it comes through no server port.
        UserPtr::<u32>::new(context).write(&message.context)?;
    }
    Ok(STATUS_SUCCESS)
}

/// NtListenPort(PortHandle, ConnectionRequest) : attend une demande de
/// connexion sur le port ; les autres messages reçus en attendant sont
/// perdus (ReactOS fait de même).
pub(super) fn nt_listen_port(arguments: &[u32]) -> NtStatus {
    loop {
        match reply_wait_receive(arguments[0], 0, 0, arguments[1], 0) {
            Ok(STATUS_SUCCESS) => {}
            other => return status(other),
        }
        match UserPtr::<PortMessage32>::new(arguments[1]).read() {
            Ok(header) if header.kind != LPC_CONNECTION_REQUEST => continue,
            Ok(_) => return STATUS_SUCCESS,
            Err(fault) => return fault,
        }
    }
}

/// Le port par lequel le noyau envoie les erreurs graves à `csrss`
/// (ExpDefaultErrorPort), et le PID de son processus ; fixé une fois.
static DEFAULT_HARD_ERROR_PORT: hal::sync::Once<(Arc<Object<Port>>, u32)> = hal::sync::Once::new();

/// NtSetDefaultHardErrorPort(PortHandle) : le port devient celui des erreurs
/// graves, le processus courant celui qui les traite, une fois au démarrage
/// (`STATUS_UNSUCCESSFUL` ensuite) ; sous `SeTcbPrivilege`
/// (`STATUS_PRIVILEGE_NOT_HELD`). Rien ne l'emploie encore (NtRaiseHardError
/// manque).
pub(super) fn nt_set_default_hard_error_port(arguments: &[u32]) -> NtStatus {
    use abi::ntstatus::{STATUS_PRIVILEGE_NOT_HELD, STATUS_UNSUCCESSFUL};

    let set = || {
        if !super::security::privilege_enabled(abi::security::SE_TCB_PRIVILEGE) {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        if DEFAULT_HARD_ERROR_PORT.get().is_some() {
            return Err(STATUS_UNSUCCESSFUL);
        }
        let port = reference_port(arguments[0], AccessMask::NONE)?;
        let process = super::current_process().pid();
        DEFAULT_HARD_ERROR_PORT.call_once(|| (port, process));
        Ok(STATUS_SUCCESS)
    };
    status(set())
}
