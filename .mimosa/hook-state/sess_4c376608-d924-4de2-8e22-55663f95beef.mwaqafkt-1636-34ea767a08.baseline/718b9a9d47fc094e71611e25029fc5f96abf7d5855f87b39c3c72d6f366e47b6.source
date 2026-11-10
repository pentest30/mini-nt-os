//! Le serveur de commandes du moniteur de références (SRM, Se, 02 §5.8) :
//! ce que `lsass` attend du noyau à son démarrage (LsapRmInitializeServer de
//! `lsasrv`).
//!
//! Au démarrage, [`start`] crée d'abord le répertoire `\Security` et son
//! événement de notification `LSA_AUTHENTICATION_INITIALIZED`, permanents
//! (SepInitializationPhase1), que `lsass` signale quand son port
//! d'authentification est prêt. Puis le port de connexion `\SeRmCommandPort` (du
//! processus System, des données de connexion d'un ULONG) et l'événement de
//! notification `\SeLsaInitEvent`, permanents, puis un thread noyau qui
//! attend l'événement. `lsass` crée son port `\SeLsaCommandPort`, signale
//! l'événement et se connecte à `\SeRmCommandPort` ; le thread accepte cette
//! connexion, se connecte en retour à `\SeLsaCommandPort`
//! (SepRmCommandServerThreadInit), puis sert les requêtes de `lsass`
//! (SepRmCommandServerThread) : RmCreateLogonSession, RmDeleteLogonSession
//! et RmAuditSetCommand (`se::logon`), chacune avec sa réponse, le message
//! reçu dont `u.ResultStatus` porte le statut. Une autre connexion est
//! refusée ; un autre numéro d'API n'a pas de réponse, comme dans ReactOS.
//!
//! La spécification suivie est ReactOS 0.4.16 (`ntoskrnl/se/srm.c`,
//! `dll/win32/lsasrv/srm.c`, `sdk/include/reactos/srmp.h`).
//!
//! Écarts : le thread est un thread noyau sans objet thread (pas encore de
//! PsCreateSystemThread) ; Lpc le connaît par un TID réservé du processus
//! System (`ps::ethread::reserve_system_thread_id`). Le noyau ne partage pas
//! de section avec `lsass` (ReactOS en crée une pour ses messages d'audit) et
//! ne lui envoie encore rien (fin d'une session, audit) ; la fin de `lsass`
//! n'est pas vue (pas de `LPC_PORT_CLOSED`) : le thread attend pour de bon.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;

use abi::lpc::{LPC_CLIENT_DIED, LPC_CONNECTION_REQUEST, LPC_PORT_CLOSED, LPC_REQUEST, PORT_MAXIMUM_MESSAGE_LENGTH};
use abi::ntstatus::{
    NtStatus, STATUS_INVALID_PARAMETER, STATUS_OBJECT_TYPE_MISMATCH, STATUS_PORT_CONNECTION_REFUSED, STATUS_SUCCESS,
    STATUS_WAIT_0,
};
use abi::object::OBJ_PERMANENT;
use abi::security::{set_rm_result, RmRequest};
use abi::teb32::ClientId32;
use ex::{Event, EventType};
use hal::sync::Once;
use ke::dispatcher::{ke_wait_for_single_object, ProcessorMode};
use ke::sched::KePlatform;
use lpc::{Port, PORT_TYPE};
use ob::{Object, ObjectRef};
use se::logon::LOGON_SESSIONS;

/// Le port de connexion du moniteur de références.
pub const COMMAND_PORT: &str = "\\SeRmCommandPort";
/// L'événement que `lsass` signale quand son port est prêt.
pub const LSA_INIT_EVENT: &str = "\\SeLsaInitEvent";
/// Le répertoire de Se.
pub const SECURITY_DIRECTORY: &str = "\\Security";
/// L'événement que `lsass` signale quand son port d'authentification
/// (`\LsaAuthenticationPort`) est prêt.
pub const LSA_AUTHENTICATION_INITIALIZED: &str = "\\Security\\LSA_AUTHENTICATION_INITIALIZED";
/// Le port de connexion de `lsass`, où le noyau se connecte.
pub const LSA_COMMAND_PORT: &str = "\\SeLsaCommandPort";

/// La taille des données de connexion du port (un ULONG).
const CONNECTION_INFO: u32 = 4;

/// Ce que le serveur garde.
struct Server {
    port: Arc<Object<Port>>,
    init: Arc<Object<Event>>,
}

static SERVER: Once<Server> = Once::new();

/// Le port client du noyau vers `lsass`, une fois connecté.
static LSA_PORT: Once<Arc<Object<Port>>> = Once::new();

/// SepInitializationPhase1 puis SeRmInitPhase1 : crée `\Security` et
/// `\Security\LSA_AUTHENTICATION_INITIALIZED`, `\SeRmCommandPort` et
/// `\SeLsaInitEvent`, puis le thread du serveur, qui attend `lsass`.
///
/// # IRQL
/// PASSIVE_LEVEL, une fois, au démarrage.
pub fn start() -> Result<(), NtStatus> {
    let namespace = ob::namespace();
    let directory: ObjectRef = ob::Directory::create();
    namespace.insert(&directory, SECURITY_DIRECTORY, None, OBJ_PERMANENT)?;
    let authentication: ObjectRef = Event::create(EventType::NotificationEvent, false);
    namespace.insert(&authentication, LSA_AUTHENTICATION_INITIALIZED, None, OBJ_PERMANENT)?;
    let system = ps::eprocess::system_process().pid();
    let port = Port::create(CONNECTION_INFO, PORT_MAXIMUM_MESSAGE_LENGTH, system)?;
    let init = Event::create(EventType::NotificationEvent, false);
    let named: ObjectRef = port.clone();
    namespace.insert(&named, COMMAND_PORT, None, OBJ_PERMANENT)?;
    let named: ObjectRef = init.clone();
    namespace.insert(&named, LSA_INIT_EVENT, None, OBJ_PERMANENT)?;
    SERVER.call_once(|| Server { port, init });
    crate::spawn_kernel_thread(ke::sched::NORMAL_PRIORITY, server_main, core::ptr::null_mut());
    Ok(())
}

/// Le thread du serveur (SepRmCommandServerThread).
fn server_main(_context: *mut c_void) {
    let server = SERVER.get().expect("the server is set before its thread starts");
    match connect(server) {
        Ok(communication) => serve(server, &communication),
        Err(status) => log::warn!("[boot] Se: the reference monitor's command server stops: {status}"),
    }
}

/// SepRmCommandServerThreadInit : attend que `lsass` soit prêt, accepte sa
/// connexion, puis se connecte à son port. Rend le port de communication
/// du serveur.
///
/// Le TID du thread, que Lpc donne à `lsass` comme celui de son client, est
/// réservé ici, une fois `lsass` là : sans `lsass`, les PID et TID des
/// processus restent ceux d'avant le serveur.
fn connect(server: &Server) -> Result<Arc<Object<Port>>, NtStatus> {
    // SAFETY: a kernel thread at PASSIVE_LEVEL; the event lives in SERVER
    // for good.
    let waited = unsafe {
        ke_wait_for_single_object::<KePlatform>(server.init.dispatcher_object(), ProcessorMode::Kernel, false, None)
    };
    if waited != STATUS_WAIT_0 {
        return Err(waited);
    }
    // Only lsass connects: the first connection request is its.
    let request = loop {
        let message = server.port.receive(ProcessorMode::Kernel, None)?;
        if message.header.kind == LPC_CONNECTION_REQUEST {
            break message;
        }
    };
    let no_view = |_: &lpc::ClientView| Err(STATUS_INVALID_PARAMETER);
    let pid = server.port.server_pid();
    let client = ClientId32 { unique_process: pid, unique_thread: ps::ethread::reserve_system_thread_id()? };
    let accepted = lpc::accept(request.header.client_id, request.header.message_id, pid, &[], true, 0, no_view)?
        .ok_or(STATUS_PORT_CONNECTION_REFUSED)?;
    lpc::complete(&accepted.port)?;
    let lsa = ob::namespace().open(LSA_COMMAND_PORT, None, Some(&PORT_TYPE), 0)?;
    let lsa = ob::downcast::<Port>(&lsa).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    let connected = lpc::connect(&lsa, client, &[], None, ProcessorMode::Kernel)?;
    LSA_PORT.call_once(|| connected.port);
    log::info!(
        "[boot] Se: lsass (PID {}) connected to {COMMAND_PORT}, the kernel to {LSA_COMMAND_PORT}",
        request.header.client_id.unique_process
    );
    Ok(accepted.port)
}

/// SepRmCommandServerThread : sert les requêtes de `lsass`.
fn serve(server: &Server, communication: &Arc<Object<Port>>) {
    loop {
        let message = match Port::receive_port(communication).receive(ProcessorMode::Kernel, None) {
            Ok(message) => message,
            Err(status) => {
                log::warn!("[boot] Se: the reference monitor's command port: {status}");
                continue;
            }
        };
        match message.header.kind {
            LPC_CONNECTION_REQUEST => {
                let refuse = |_: &lpc::ClientView| Err(STATUS_INVALID_PARAMETER);
                let (client, id) = (message.header.client_id, message.header.message_id);
                let _ = lpc::accept(client, id, server.port.server_pid(), &[], false, 0, refuse);
            }
            LPC_PORT_CLOSED | LPC_CLIENT_DIED => return,
            LPC_REQUEST => match answer(&message.data) {
                Some(reply) => {
                    if let Err(status) = lpc::reply(communication, &message.header, reply) {
                        log::warn!("[boot] Se: a reply to lsass failed: {status}");
                    }
                }
                None => {
                    log::warn!("[boot] Se: an unknown request of lsass, without a reply: {:x?}", message.data.get(..4))
                }
            },
            _ => {}
        }
    }
}

/// La réponse à la requête `data` (les données d'un SEP_RM_API_MESSAGE),
/// ou `None` pour une requête inconnue ou trop courte.
fn answer(data: &[u8]) -> Option<Vec<u8>> {
    let status = |result: Result<(), NtStatus>| result.map_or_else(|status| status, |()| STATUS_SUCCESS);
    let status = match RmRequest::parse(data)? {
        RmRequest::SetAudit { enabled, flags } => {
            LOGON_SESSIONS.set_audit(enabled, &flags);
            STATUS_SUCCESS
        }
        RmRequest::CreateLogonSession(luid) => status(LOGON_SESSIONS.create(luid)),
        RmRequest::DeleteLogonSession(luid) => status(LOGON_SESSIONS.delete(luid)),
        RmRequest::Unknown(_) => return None,
    };
    let mut reply = data.to_vec();
    set_rm_result(&mut reply, status.0).then_some(reply)
}
