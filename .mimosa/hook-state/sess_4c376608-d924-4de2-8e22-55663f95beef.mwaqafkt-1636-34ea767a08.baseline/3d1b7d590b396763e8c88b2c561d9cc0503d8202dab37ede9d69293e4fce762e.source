//! NPFS : le système de fichiers des tubes nommés (`\Device\NamedPipe`,
//! 02 §5.6).
//!
//! Un tube (FCB) a un nom, sans casse, un type (octets ou messages), une
//! configuration (le serveur lit, écrit, ou les deux : selon le partage de
//! sa création), un nombre d'instances au plus et un délai par défaut. Une
//! instance (CCB) naît de NtCreateNamedPipeFile, du côté du serveur, à
//! l'écoute ; un client s'y connecte en ouvrant le nom (NtCreateFile,
//! NtOpenFile). Chaque instance a deux files de données
//! ([`queue::DataQueue`]), une par sens, chacune avec son quota, et un
//! état : déconnectée, à l'écoute, connectée, ou en fermeture (une extrémité
//! est fermée, l'autre peut encore lire ce qui reste).
//!
//! Les objets fichiers des tubes ([`PipeFile`]) sont du type `File` d'Io :
//! la procédure *parse* de `\Device\NamedPipe` en crée un, pour la racine
//! (`\`) ou pour un nom ; l'ouverture (côté client, [`PipeFile::open_client`])
//! ou la création d'une instance ([`PipeFile::create_instance`]) le lie
//! ensuite à son instance, comme le ferait IRP_MJ_CREATE ou
//! IRP_MJ_CREATE_NAMED_PIPE.
//!
//! Une opération qui ne peut pas finir tout de suite (une lecture sans
//! données, une écriture au-delà du quota, une écoute sans client, une
//! attente d'instance) garde sa [`Request`] et rend [`Io::Pending`] ; elle
//! finit quand l'état change, depuis le thread qui le change, une fois le
//! verrou rendu ([`Deferred`]). Tout NPFS tient sous un verrou, comme le
//! VCB de ReactOS.
//!
//! La spécification suivie est le pilote de ReactOS 0.4.16,
//! `drivers/filesystems/npfs` (`create.c`, `statesup.c`, `fsctrl.c`,
//! `read.c`, `write.c`, `fileinfo.c`, `waitsup.c`), sans en porter le code.
//!
//! Pas encore : la sécurité des tubes (le descripteur de leur création est
//! ignoré ; l'emprunt d'identité du client, FSCTL_PIPE_IMPERSONATE),
//! FSCTL_PIPE_TRANSCEIVE, les événements de tube (FSCTL_PIPE_ASSIGN_EVENT,
//! FSCTL_PIPE_QUERY_EVENT), l'énumération de la racine
//! (NtQueryDirectoryFile), les notifications de changement, les alias de
//! noms ; les lectures en attente ne prennent pas de quota.

pub mod queue;
#[cfg(test)]
mod tests;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use abi::file::{
    FILE_CREATE, FILE_CREATED, FILE_OPEN, FILE_OPENED, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_DATA,
};
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_CANCELLED, STATUS_ILLEGAL_FUNCTION,
    STATUS_INSTANCE_NOT_AVAILABLE, STATUS_INVALID_PARAMETER, STATUS_INVALID_PIPE_STATE, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_PIPE_BROKEN, STATUS_PIPE_BUSY, STATUS_PIPE_CLOSING, STATUS_PIPE_CONNECTED,
    STATUS_PIPE_DISCONNECTED, STATUS_PIPE_EMPTY, STATUS_PIPE_LISTENING, STATUS_PIPE_NOT_AVAILABLE, STATUS_SUCCESS,
};
use abi::pipe::{
    FilePipeInformation, FilePipeLocalInformation, FilePipePeekHeader, FILE_PIPE_BYTE_STREAM_MODE,
    FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_CLIENT_END, FILE_PIPE_CLOSING_STATE, FILE_PIPE_COMPLETE_OPERATION,
    FILE_PIPE_CONNECTED_STATE, FILE_PIPE_DISCONNECTED_STATE, FILE_PIPE_FULL_DUPLEX, FILE_PIPE_INBOUND,
    FILE_PIPE_LISTENING_STATE, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_OUTBOUND,
    FILE_PIPE_QUEUE_OPERATION, FILE_PIPE_SERVER_END, PEEK_HEADER_SIZE, WAIT_FOREVER,
};
use hal::sync::KSpinLock;
use ob::{create_object, Object, ObjectRef, Parsed};

use crate::file::FILE_TYPE;
use crate::request::{Completed, Deferred, IoEvent, Request};
use queue::{DataQueue, QueueState};

/// Le nom du périphérique.
pub const DEVICE_NAME: &str = "\\Device\\NamedPipe";

/// Le sens client vers serveur (ce que lit le serveur), puis l'autre.
const INBOUND: usize = 0;
const OUTBOUND: usize = 1;

/// Une extrémité d'une instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Client,
    Server,
}

impl End {
    fn index(self) -> usize {
        match self {
            End::Client => FILE_PIPE_CLIENT_END as usize,
            End::Server => FILE_PIPE_SERVER_END as usize,
        }
    }

    /// FILE_PIPE_CLIENT_END ou FILE_PIPE_SERVER_END.
    pub fn value(self) -> u32 {
        self.index() as u32
    }

    fn other(self) -> End {
        match self {
            End::Client => End::Server,
            End::Server => End::Client,
        }
    }

    /// La file qu'elle lit.
    fn read_queue(self) -> usize {
        match self {
            End::Server => INBOUND,
            End::Client => OUTBOUND,
        }
    }

    fn write_queue(self) -> usize {
        self.other().read_queue()
    }

    /// Elle ne lit pas dans un tube de configuration `configuration`.
    fn cannot_read(self, configuration: u32) -> bool {
        match self {
            End::Server => configuration == FILE_PIPE_OUTBOUND,
            End::Client => configuration == FILE_PIPE_INBOUND,
        }
    }

    fn cannot_write(self, configuration: u32) -> bool {
        self.other().cannot_read(configuration)
    }
}

/// Ce que demande NtCreateNamedPipeFile (NAMED_PIPE_CREATE_PARAMETERS, la
/// disposition et le partage).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatePipe {
    pub disposition: u32,
    pub share: u32,
    pub pipe_type: u32,
    pub read_mode: u32,
    pub completion_mode: u32,
    /// [`abi::pipe::FILE_PIPE_UNLIMITED_INSTANCES`] : sans limite.
    pub maximum_instances: u32,
    pub inbound_quota: u32,
    pub outbound_quota: u32,
    /// Le délai par défaut de FSCTL_PIPE_WAIT, `None` sans lui.
    pub default_timeout: Option<i64>,
}

/// Ce que devient une opération.
#[derive(Debug, PartialEq, Eq)]
pub enum Io {
    /// Finie tout de suite (un succès ou un avertissement).
    Done(Completed),
    /// Sa demande attend ; elle finira par [`Request::finish`].
    Pending,
}

/// Ce que devient FSCTL_PIPE_WAIT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Une instance écoute.
    Ready,
    /// La demande attend une instance, au plus ce délai (format NT ; `None` :
    /// sans fin) ; [`PipeFile::cancel_request`] la retire à son échéance.
    Pending(Option<i64>),
}

/// Une instance (CCB).
struct Ccb {
    id: u64,
    state: u32,
    /// Par extrémité (FILE_PIPE_CLIENT_END, FILE_PIPE_SERVER_END).
    read_mode: [u32; 2],
    completion_mode: [u32; 2],
    /// INBOUND, OUTBOUND.
    queues: [DataQueue; 2],
    /// Les écoutes en attente (FSCTL_PIPE_LISTEN).
    listeners: Vec<Arc<Request>>,
    /// Les objets fichiers liés à chaque extrémité.
    client: Option<u64>,
    server: Option<u64>,
}

/// Un tube (FCB).
struct Fcb {
    /// Son nom, `\nom`, tel que créé.
    name: String,
    /// En majuscules.
    key: String,
    pipe_type: u32,
    configuration: u32,
    maximum_instances: u32,
    default_timeout: i64,
    instances: Vec<Ccb>,
}

/// Une attente d'instance (FSCTL_PIPE_WAIT).
struct Waiter {
    key: String,
    request: Arc<Request>,
}

#[derive(Default)]
struct State {
    pipes: Vec<Fcb>,
    waiters: Vec<Waiter>,
    next_ccb: u64,
}

impl State {
    fn fcb(&self, key: &str) -> Option<usize> {
        self.pipes.iter().position(|fcb| fcb.key == key)
    }

    /// Le tube et la place de l'instance `ccb`.
    fn locate(&self, ccb: u64) -> Option<(usize, usize)> {
        self.pipes.iter().enumerate().find_map(|(f, fcb)| Some((f, fcb.instances.iter().position(|c| c.id == ccb)?)))
    }

    /// NpCancelWaiter : les attentes d'instance du tube `key` finissent avec
    /// `status`.
    fn cancel_waiters(&mut self, key: &str, status: NtStatus, deferred: &mut Deferred) {
        let mut index = 0;
        while index < self.waiters.len() {
            if self.waiters[index].key == key {
                deferred.finish_status(self.waiters.remove(index).request, status, 0);
            } else {
                index += 1;
            }
        }
    }

    /// NpDeleteCcb, puis NpDeleteFcb s'il ne reste aucune instance (ses
    /// attentes finissent avec `STATUS_OBJECT_NAME_NOT_FOUND`).
    fn delete_instance(&mut self, f: usize, c: usize, deferred: &mut Deferred) {
        let mut ccb = self.pipes[f].instances.remove(c);
        for queue in &mut ccb.queues {
            queue.flush(STATUS_PIPE_BROKEN, deferred);
        }
        for request in ccb.listeners.drain(..) {
            deferred.finish_status(request, STATUS_PIPE_BROKEN, 0);
        }
        if self.pipes[f].instances.is_empty() {
            let fcb = self.pipes.remove(f);
            self.cancel_waiters(&fcb.key, STATUS_OBJECT_NAME_NOT_FOUND, deferred);
        }
    }

    /// Retire et finit avec `status` les demandes pour lesquelles `matches`
    /// est vrai : attentes d'instance, écoutes, lectures et écritures.
    fn cancel(&mut self, matches: &dyn Fn(&Request) -> bool, status: NtStatus, deferred: &mut Deferred) -> usize {
        let mut cancelled = 0;
        let mut index = 0;
        while index < self.waiters.len() {
            if matches(&self.waiters[index].request) {
                deferred.finish_status(self.waiters.remove(index).request, status, 0);
                cancelled += 1;
            } else {
                index += 1;
            }
        }
        for ccb in self.pipes.iter_mut().flat_map(|fcb| fcb.instances.iter_mut()) {
            let mut index = 0;
            while index < ccb.listeners.len() {
                if matches(&ccb.listeners[index]) {
                    deferred.finish_status(ccb.listeners.remove(index), status, 0);
                    cancelled += 1;
                } else {
                    index += 1;
                }
            }
            for queue in &mut ccb.queues {
                cancelled += queue.cancel(matches, status, deferred);
            }
        }
        cancelled
    }
}

/// Le système de fichiers des tubes nommés : ses tubes, ses attentes.
pub struct Npfs {
    state: KSpinLock<State>,
    next_file: AtomicU64,
}

impl Npfs {
    /// Un NPFS sans tube.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new() -> Arc<Self> {
        Arc::new(Self { state: KSpinLock::new(State::default()), next_file: AtomicU64::new(1) })
    }

    /// Les noms des tubes, tels que créés (`\nom`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn pipe_names(&self) -> Vec<String> {
        self.state.lock().pipes.iter().map(|fcb| fcb.name.clone()).collect()
    }

    /// Le nombre d'instances du tube `name` (`\nom`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn instances(&self, name: &str) -> usize {
        let state = self.state.lock();
        state.fcb(&name.to_uppercase()).map_or(0, |f| state.pipes[f].instances.len())
    }

    /// Fait `operation` sous le verrou, puis finit les demandes qu'elle a
    /// terminées.
    fn locked<R>(&self, operation: impl FnOnce(&mut State, &mut Deferred) -> R) -> R {
        let mut deferred = Deferred::new();
        let result = operation(&mut self.state.lock(), &mut deferred);
        deferred.run();
        result
    }

    /// La procédure *parse* de `\Device\NamedPipe` : un objet fichier pour la
    /// racine (`\`) ou pour le nom `remaining` (`\nom`), pas encore ouvert.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn parse(self: &Arc<Self>, remaining: &str) -> Result<Parsed, NtStatus> {
        if !remaining.starts_with('\\') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let file: ObjectRef = PipeFile::create(self.clone(), remaining);
        Ok(Parsed::Object(file))
    }
}

/// Ce qu'un objet fichier de NPFS désigne.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opened {
    /// Un nom, pas encore ouvert ni créé.
    Unopened,
    /// La racine (`\Device\NamedPipe\`), où l'on attend une instance.
    Root,
    /// Une extrémité d'une instance.
    End { ccb: u64, end: End },
    /// Fermé (IRP_MJ_CLEANUP).
    Closed,
}

/// Un objet fichier de NPFS (FILE_OBJECT et son contexte : FsContext).
pub struct PipeFile {
    npfs: Arc<Npfs>,
    /// Son identifiant, unique : les demandes et les instances le gardent.
    id: u64,
    /// `\` pour la racine, `\nom` pour un tube.
    name: String,
    opened: KSpinLock<Opened>,
    /// FO_SYNCHRONOUS_IO.
    synchronous: AtomicBool,
    /// FILE_OBJECT.Event : remis à zéro au début de chaque E/S, signalé à sa
    /// fin.
    event: IoEvent,
}

impl PipeFile {
    /// Un objet fichier pour `name` (`\` : la racine).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(npfs: Arc<Npfs>, name: &str) -> Arc<Object<PipeFile>> {
        let id = npfs.next_file.fetch_add(1, Ordering::Relaxed);
        let opened = if name == "\\" { Opened::Root } else { Opened::Unopened };
        let file = PipeFile {
            npfs,
            id,
            name: String::from(name),
            opened: KSpinLock::new(opened),
            synchronous: AtomicBool::new(false),
            event: IoEvent::new(false),
        };
        create_object(&FILE_TYPE, file)
    }

    /// Son identifiant.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Son nom : `\` pour la racine, `\nom` pour un tube (FileNameInformation).
    pub fn pipe_name(&self) -> &str {
        &self.name
    }

    /// La racine de NPFS.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_root(&self) -> bool {
        *self.opened.lock() == Opened::Root
    }

    /// L'extrémité qu'il ouvre, s'il en ouvre une.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn end(&self) -> Option<End> {
        match *self.opened.lock() {
            Opened::End { end, .. } => Some(end),
            _ => None,
        }
    }

    /// Ses E/S sont synchrones (FO_SYNCHRONOUS_IO).
    pub fn is_synchronous(&self) -> bool {
        self.synchronous.load(Ordering::Relaxed)
    }

    /// Note le mode que donnent les options d'ouverture `options`.
    pub fn set_mode(&self, options: u32) {
        let synchronous = options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0;
        self.synchronous.store(synchronous, Ordering::Relaxed);
    }

    /// FILE_OBJECT.Event.
    pub fn event(&self) -> &IoEvent {
        &self.event
    }

    /// Le nom de la racine, relatif : un objet pour `\nom`. Rien d'autre ne
    /// s'ouvre relativement à un objet de NPFS.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn parse_relative(&self, remaining: &str) -> Result<Parsed, NtStatus> {
        if !self.is_root() || remaining.len() <= 1 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        self.npfs.parse(remaining)
    }

    /// Le nom du tube, en majuscules ; `STATUS_OBJECT_NAME_INVALID` pour un
    /// objet qui n'attend pas d'être ouvert.
    fn unopened_key(&self) -> Result<String, NtStatus> {
        if *self.opened.lock() != Opened::Unopened || self.name.len() <= 1 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(self.name.to_uppercase())
    }

    fn bind(&self, ccb: u64, end: End) {
        *self.opened.lock() = Opened::End { ccb, end };
    }

    /// NtCreateNamedPipeFile (NpFsdCreateNamedPipe) : une instance du tube,
    /// créé s'il n'existe pas ; l'objet devient son extrémité serveur, à
    /// l'écoute. Rend `FILE_CREATED` ou `FILE_OPENED`.
    ///
    /// Erreurs : pour un tube neuf, sans délai par défaut négatif ou sans
    /// instance (`STATUS_INVALID_PARAMETER`), `FILE_OPEN`
    /// (`STATUS_OBJECT_NAME_NOT_FOUND`), un partage qui n'est pas une
    /// configuration, ou le mode message d'un tube d'octets
    /// (`STATUS_INVALID_PARAMETER`) ; pour un tube qui existe, toutes ses
    /// instances prises (`STATUS_INSTANCE_NOT_AVAILABLE`), `FILE_CREATE` ou
    /// un autre partage (`STATUS_ACCESS_DENIED`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn create_instance(&self, create: &CreatePipe) -> Result<u32, NtStatus> {
        let key = self.unopened_key()?;
        if create.pipe_type == FILE_PIPE_BYTE_STREAM_TYPE && create.read_mode == FILE_PIPE_MESSAGE_MODE {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let id = self.id;
        let (ccb, information) = self.npfs.locked(|state, deferred| {
            let ccb_id = state.next_ccb;
            let ccb = Ccb {
                id: ccb_id,
                state: FILE_PIPE_LISTENING_STATE,
                read_mode: [FILE_PIPE_BYTE_STREAM_MODE, create.read_mode],
                completion_mode: [FILE_PIPE_QUEUE_OPERATION, create.completion_mode],
                queues: [DataQueue::new(create.inbound_quota as usize), DataQueue::new(create.outbound_quota as usize)],
                listeners: Vec::new(),
                client: None,
                server: Some(id),
            };
            match state.fcb(&key) {
                None => {
                    let timeout = match create.default_timeout {
                        Some(timeout) if timeout < 0 && create.maximum_instances != 0 => timeout,
                        _ => return Err(STATUS_INVALID_PARAMETER),
                    };
                    if create.disposition == FILE_OPEN {
                        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                    }
                    let configuration = match create.share {
                        share if share == FILE_SHARE_READ | FILE_SHARE_WRITE => FILE_PIPE_FULL_DUPLEX,
                        FILE_SHARE_READ => FILE_PIPE_OUTBOUND,
                        FILE_SHARE_WRITE => FILE_PIPE_INBOUND,
                        _ => return Err(STATUS_INVALID_PARAMETER),
                    };
                    state.pipes.push(Fcb {
                        name: self.name.clone(),
                        key: key.clone(),
                        pipe_type: create.pipe_type,
                        configuration,
                        maximum_instances: create.maximum_instances,
                        default_timeout: timeout,
                        instances: alloc::vec![ccb],
                    });
                    state.next_ccb += 1;
                    Ok((ccb_id, FILE_CREATED))
                }
                Some(f) => {
                    let fcb = &mut state.pipes[f];
                    if fcb.instances.len() as u64 >= u64::from(fcb.maximum_instances) {
                        return Err(STATUS_INSTANCE_NOT_AVAILABLE);
                    }
                    if create.disposition == FILE_CREATE {
                        return Err(STATUS_ACCESS_DENIED);
                    }
                    let share = match fcb.configuration {
                        FILE_PIPE_FULL_DUPLEX => FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_PIPE_OUTBOUND => FILE_SHARE_READ,
                        _ => FILE_SHARE_WRITE,
                    };
                    if create.share != share
                        || (fcb.pipe_type == FILE_PIPE_BYTE_STREAM_TYPE && create.read_mode == FILE_PIPE_MESSAGE_MODE)
                    {
                        return Err(if create.share != share {
                            STATUS_ACCESS_DENIED
                        } else {
                            STATUS_INVALID_PARAMETER
                        });
                    }
                    fcb.instances.push(ccb);
                    state.next_ccb += 1;
                    // A new instance listens: whoever waits for one goes on.
                    state.cancel_waiters(&key, STATUS_SUCCESS, deferred);
                    Ok((ccb_id, FILE_OPENED))
                }
            }
        })?;
        self.bind(ccb, End::Server);
        Ok(information)
    }

    /// L'ouverture d'un client (NpCreateClientEnd) avec les droits accordés
    /// `granted` : la première instance à l'écoute devient connectée
    /// (NpSetConnectedPipeState : ses écoutes finissent), l'objet son
    /// extrémité client, en mode octet et bloquant. Rend `FILE_OPENED`.
    ///
    /// Erreurs : un tube absent (`STATUS_OBJECT_NAME_NOT_FOUND`), la
    /// lecture d'un tube entrant ou l'écriture d'un tube sortant
    /// (`STATUS_ACCESS_DENIED`), aucune instance à l'écoute
    /// (`STATUS_PIPE_NOT_AVAILABLE`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn open_client(&self, granted: u32) -> Result<u32, NtStatus> {
        let key = self.unopened_key()?;
        let id = self.id;
        let ccb = self.npfs.locked(|state, deferred| {
            let f = state.fcb(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            let fcb = &mut state.pipes[f];
            if (granted & FILE_READ_DATA != 0 && fcb.configuration == FILE_PIPE_INBOUND)
                || (granted & FILE_WRITE_DATA != 0 && fcb.configuration == FILE_PIPE_OUTBOUND)
            {
                return Err(STATUS_ACCESS_DENIED);
            }
            let ccb = fcb
                .instances
                .iter_mut()
                .find(|ccb| ccb.state == FILE_PIPE_LISTENING_STATE)
                .ok_or(STATUS_PIPE_NOT_AVAILABLE)?;
            ccb.read_mode[End::Client.index()] = FILE_PIPE_BYTE_STREAM_MODE;
            ccb.completion_mode[End::Client.index()] = FILE_PIPE_QUEUE_OPERATION;
            ccb.state = FILE_PIPE_CONNECTED_STATE;
            ccb.client = Some(id);
            for request in ccb.listeners.drain(..) {
                deferred.finish_status(request, STATUS_SUCCESS, 0);
            }
            Ok(ccb.id)
        })?;
        self.bind(ccb, End::Client);
        Ok(FILE_OPENED)
    }

    /// L'instance et l'extrémité de cet objet, s'il y est encore lié
    /// (NpDecodeFileObject) : `STATUS_PIPE_DISCONNECTED` sinon ;
    /// `not_an_end` pour la racine.
    fn attached(&self, state: &State, not_an_end: NtStatus) -> Result<(usize, usize, End), NtStatus> {
        let (ccb, end) = match *self.opened.lock() {
            Opened::End { ccb, end } => (ccb, end),
            Opened::Root => return Err(not_an_end),
            Opened::Unopened | Opened::Closed => return Err(STATUS_PIPE_DISCONNECTED),
        };
        let (f, c) = state.locate(ccb).ok_or(STATUS_PIPE_DISCONNECTED)?;
        let instance = &state.pipes[f].instances[c];
        let bound = match end {
            End::Client => instance.client,
            End::Server => instance.server,
        };
        if bound != Some(self.id) {
            return Err(STATUS_PIPE_DISCONNECTED);
        }
        Ok((f, c, end))
    }

    /// NpCommonRead : lit au plus `size` octets de ce que l'autre extrémité
    /// a écrit. Sans données : `STATUS_PIPE_BROKEN` si l'autre extrémité est
    /// fermée, `STATUS_PIPE_EMPTY` en mode non bloquant, sinon `request`
    /// attend des données. Erreurs : une instance déconnectée ou à l'écoute
    /// (`STATUS_PIPE_DISCONNECTED`, `STATUS_PIPE_LISTENING`), une extrémité
    /// qui n'a pas le droit de lire (`STATUS_INVALID_PARAMETER`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn read(&self, size: usize, request: &Arc<Request>) -> Result<Io, NtStatus> {
        self.npfs.locked(|state, deferred| {
            let (f, c, end) = self.attached(state, STATUS_INVALID_PARAMETER)?;
            let fcb = &mut state.pipes[f];
            let configuration = fcb.configuration;
            let ccb = &mut fcb.instances[c];
            match ccb.state {
                FILE_PIPE_DISCONNECTED_STATE => return Err(STATUS_PIPE_DISCONNECTED),
                FILE_PIPE_LISTENING_STATE => return Err(STATUS_PIPE_LISTENING),
                _ => {}
            }
            if end.cannot_read(configuration) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let read_mode = ccb.read_mode[end.index()];
            let completion_mode = ccb.completion_mode[end.index()];
            let closing = ccb.state == FILE_PIPE_CLOSING_STATE;
            let queue = &mut ccb.queues[end.read_queue()];
            if queue.state() == QueueState::WriteEntries {
                let (data, status) = queue.read(size, read_mode, false, deferred);
                return Ok(Io::Done(Completed { status, information: data.len() as u32, data }));
            }
            if closing {
                return Err(STATUS_PIPE_BROKEN);
            }
            if completion_mode == FILE_PIPE_COMPLETE_OPERATION {
                return Err(STATUS_PIPE_EMPTY);
            }
            queue.add_read(request.clone(), size);
            Ok(Io::Pending)
        })
    }

    /// NpCommonWrite : écrit `data` vers l'autre extrémité. Les lectures en
    /// attente le prennent d'abord ; le reste attend d'être lu. Une écriture
    /// qui dépasse le quota attend (`request`) que des lectures le libèrent,
    /// sauf en mode non bloquant : un message qui ne tient pas n'est pas
    /// écrit (0 octet), des octets sont écrits en partie. Erreurs : une
    /// instance qui n'est pas connectée (`STATUS_PIPE_DISCONNECTED`,
    /// `STATUS_PIPE_LISTENING`, `STATUS_PIPE_CLOSING`), une extrémité qui
    /// n'a pas le droit d'écrire (`STATUS_INVALID_PARAMETER`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn write(&self, data: Vec<u8>, request: &Arc<Request>) -> Result<Io, NtStatus> {
        self.npfs.locked(|state, deferred| {
            let (f, c, end) = self.attached(state, STATUS_INVALID_PARAMETER)?;
            let fcb = &mut state.pipes[f];
            let (configuration, pipe_type) = (fcb.configuration, fcb.pipe_type);
            let ccb = &mut fcb.instances[c];
            match ccb.state {
                FILE_PIPE_CONNECTED_STATE => {}
                FILE_PIPE_DISCONNECTED_STATE => return Err(STATUS_PIPE_DISCONNECTED),
                FILE_PIPE_LISTENING_STATE => return Err(STATUS_PIPE_LISTENING),
                _ => return Err(STATUS_PIPE_CLOSING),
            }
            if end.cannot_write(configuration) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let size = data.len();
            let nonblocking = ccb.completion_mode[end.index()] == FILE_PIPE_COMPLETE_OPERATION;
            let read_mode = ccb.read_mode[end.other().index()];
            let queue = &mut ccb.queues[end.write_queue()];
            if !queue.has_room_for(size) && pipe_type == FILE_PIPE_MESSAGE_TYPE && nonblocking {
                return Ok(Io::Done(Completed::status(STATUS_SUCCESS, 0)));
            }
            let Some(left) = queue.write_to_readers(&data, read_mode, pipe_type, deferred) else {
                return Ok(Io::Done(Completed::status(STATUS_SUCCESS, size as u32)));
            };
            if nonblocking && queue.quota_left() < left {
                return Ok(Io::Done(Completed::status(STATUS_SUCCESS, (size - left) as u32)));
            }
            if queue.add_write(data, size - left, Some(request.clone())) {
                Ok(Io::Pending)
            } else {
                Ok(Io::Done(Completed::status(STATUS_SUCCESS, size as u32)))
            }
        })
    }

    /// FSCTL_PIPE_LISTEN (NpSetListeningPipeState), du serveur : l'instance
    /// se met à l'écoute et `request` attend un client ; en mode non
    /// bloquant, `STATUS_PIPE_LISTENING` tout de suite. Une instance
    /// déconnectée qui se remet à l'écoute libère qui attend une instance.
    /// Erreurs : un client (`STATUS_ILLEGAL_FUNCTION`), une instance
    /// connectée (`STATUS_PIPE_CONNECTED`, que `rpcrt4` prend pour un succès)
    /// ou en fermeture (`STATUS_PIPE_CLOSING`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn listen(&self, request: &Arc<Request>) -> Result<Io, NtStatus> {
        self.npfs.locked(|state, deferred| {
            let (f, c, end) = self.attached(state, STATUS_ILLEGAL_FUNCTION)?;
            if end != End::Server {
                return Err(STATUS_ILLEGAL_FUNCTION);
            }
            match state.pipes[f].instances[c].state {
                FILE_PIPE_CONNECTED_STATE => return Err(STATUS_PIPE_CONNECTED),
                FILE_PIPE_CLOSING_STATE => return Err(STATUS_PIPE_CLOSING),
                FILE_PIPE_DISCONNECTED_STATE => {
                    let key = state.pipes[f].key.clone();
                    state.cancel_waiters(&key, STATUS_SUCCESS, deferred);
                }
                _ => {}
            }
            let ccb = &mut state.pipes[f].instances[c];
            ccb.state = FILE_PIPE_LISTENING_STATE;
            if ccb.completion_mode[End::Server.index()] == FILE_PIPE_COMPLETE_OPERATION {
                return Err(STATUS_PIPE_LISTENING);
            }
            ccb.listeners.push(request.clone());
            Ok(Io::Pending)
        })
    }

    /// FSCTL_PIPE_DISCONNECT (NpSetDisconnectedPipeState), du serveur : les
    /// écoutes en attente, les données et les demandes des deux sens
    /// finissent (`STATUS_PIPE_DISCONNECTED`), le client perd l'instance.
    /// Erreurs : un client (`STATUS_ILLEGAL_FUNCTION`), une instance déjà
    /// déconnectée (`STATUS_PIPE_DISCONNECTED`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn disconnect(&self) -> Result<(), NtStatus> {
        self.npfs.locked(|state, deferred| {
            let (f, c, end) = self.attached(state, STATUS_PIPE_DISCONNECTED)?;
            if end != End::Server {
                return Err(STATUS_ILLEGAL_FUNCTION);
            }
            let ccb = &mut state.pipes[f].instances[c];
            match ccb.state {
                FILE_PIPE_DISCONNECTED_STATE => return Err(STATUS_PIPE_DISCONNECTED),
                FILE_PIPE_LISTENING_STATE => {
                    for request in ccb.listeners.drain(..) {
                        deferred.finish_status(request, STATUS_PIPE_DISCONNECTED, 0);
                    }
                }
                _ => {
                    for queue in &mut ccb.queues {
                        queue.flush(STATUS_PIPE_DISCONNECTED, deferred);
                    }
                    ccb.client = None;
                }
            }
            ccb.state = FILE_PIPE_DISCONNECTED_STATE;
            Ok(())
        })
    }

    /// FSCTL_PIPE_PEEK (NpPeek) : FILE_PIPE_PEEK_BUFFER dans au plus
    /// `length` octets (l'état, les octets à lire, et pour un tube de
    /// messages leur nombre et la longueur du premier), suivi d'autant de
    /// données qu'il en tient, sans les prendre ; `STATUS_BUFFER_OVERFLOW`
    /// si elles n'y tiennent pas. Erreurs : la racine ou moins que l'en-tête
    /// (`STATUS_INVALID_PARAMETER`), une instance qui n'est pas connectée
    /// (`STATUS_INVALID_PIPE_STATE`), ou fermée sans données
    /// (`STATUS_PIPE_BROKEN`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn peek(&self, length: usize) -> Result<(Vec<u8>, NtStatus), NtStatus> {
        self.npfs.locked(|state, deferred| {
            let (f, c, end) = self.attached(state, STATUS_INVALID_PARAMETER)?;
            if length < PEEK_HEADER_SIZE {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let fcb = &mut state.pipes[f];
            let message_type = fcb.pipe_type == FILE_PIPE_MESSAGE_TYPE;
            let ccb = &mut fcb.instances[c];
            let named_pipe_state = ccb.state;
            let queue = &mut ccb.queues[end.read_queue()];
            if named_pipe_state != FILE_PIPE_CONNECTED_STATE {
                if named_pipe_state != FILE_PIPE_CLOSING_STATE {
                    return Err(STATUS_INVALID_PIPE_STATE);
                }
                if queue.state() != QueueState::WriteEntries {
                    return Err(STATUS_PIPE_BROKEN);
                }
            }
            let mut header = FilePipePeekHeader { named_pipe_state, ..Default::default() };
            let (mut data, mut status) = (Vec::new(), STATUS_SUCCESS);
            if queue.state() == QueueState::WriteEntries {
                header.read_data_available = queue.readable() as u32;
                if message_type {
                    let (messages, first) = queue.messages();
                    header.number_of_messages = messages as u32;
                    header.message_length = first as u32;
                }
                if length == PEEK_HEADER_SIZE {
                    if header.read_data_available > 0 {
                        status = STATUS_BUFFER_OVERFLOW;
                    }
                } else {
                    let mode = if message_type { FILE_PIPE_MESSAGE_MODE } else { FILE_PIPE_BYTE_STREAM_MODE };
                    (data, status) = queue.read(length - PEEK_HEADER_SIZE, mode, true, deferred);
                }
            }
            let mut out = Vec::with_capacity(PEEK_HEADER_SIZE + data.len());
            out.extend_from_slice(&header.to_bytes());
            out.extend_from_slice(&data);
            Ok((out, status))
        })
    }

    /// FSCTL_PIPE_WAIT (NpWaitForNamedPipe), sur la racine : une instance du
    /// tube `name` (sans son `\`) écoute-t-elle ? Sinon `request` attend
    /// qu'une instance soit créée ou se remette à l'écoute, au plus
    /// `timeout`, ou le délai par défaut du tube. Erreurs : un autre objet
    /// que la racine (`STATUS_ILLEGAL_FUNCTION`), un tube absent
    /// (`STATUS_OBJECT_NAME_NOT_FOUND`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn wait(&self, name: &str, timeout: Option<i64>, request: &Arc<Request>) -> Result<Wait, NtStatus> {
        if !self.is_root() {
            return Err(STATUS_ILLEGAL_FUNCTION);
        }
        let key = alloc::format!("\\{}", name.to_uppercase());
        self.npfs.locked(|state, _| {
            let f = state.fcb(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            let fcb = &state.pipes[f];
            if fcb.instances.iter().any(|ccb| ccb.state == FILE_PIPE_LISTENING_STATE) {
                return Ok(Wait::Ready);
            }
            let due = match timeout.unwrap_or(fcb.default_timeout) {
                WAIT_FOREVER => None,
                due => Some(due),
            };
            state.waiters.push(Waiter { key, request: request.clone() });
            Ok(Wait::Pending(due))
        })
    }

    /// FilePipeInformation : ses modes de lecture et de fin.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn pipe_information(&self) -> Result<FilePipeInformation, NtStatus> {
        let state = self.npfs.state.lock();
        let (f, c, end) = self.attached(&state, STATUS_INVALID_PARAMETER)?;
        let ccb = &state.pipes[f].instances[c];
        Ok(FilePipeInformation {
            read_mode: ccb.read_mode[end.index()],
            completion_mode: ccb.completion_mode[end.index()],
        })
    }

    /// NtSetInformationFile(FilePipeInformation) (NpSetPipeInfo) : ses modes.
    /// Erreurs : un mode inconnu, ou le mode message d'un tube d'octets
    /// (`STATUS_INVALID_PARAMETER`) ; le mode non bloquant pendant que des
    /// lectures ou des écritures de cette extrémité attendent
    /// (`STATUS_PIPE_BUSY`).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_pipe_information(&self, information: &FilePipeInformation) -> Result<(), NtStatus> {
        let mut state = self.npfs.state.lock();
        let (f, c, end) = self.attached(&state, STATUS_INVALID_PARAMETER)?;
        let fcb = &mut state.pipes[f];
        if information.read_mode > FILE_PIPE_MESSAGE_MODE
            || information.completion_mode > FILE_PIPE_COMPLETE_OPERATION
            || (information.read_mode == FILE_PIPE_MESSAGE_MODE && fcb.pipe_type == FILE_PIPE_BYTE_STREAM_TYPE)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let ccb = &mut fcb.instances[c];
        let waiting = ccb.queues[end.read_queue()].state() == QueueState::ReadEntries
            || ccb.queues[end.write_queue()].state() == QueueState::WriteEntries;
        if information.completion_mode == FILE_PIPE_COMPLETE_OPERATION
            && ccb.completion_mode[end.index()] != FILE_PIPE_COMPLETE_OPERATION
            && waiting
        {
            return Err(STATUS_PIPE_BUSY);
        }
        ccb.read_mode[end.index()] = information.read_mode;
        ccb.completion_mode[end.index()] = information.completion_mode;
        Ok(())
    }

    /// FilePipeLocalInformation (NpQueryPipeLocalInfo) : le tube et son
    /// instance, vus de cette extrémité ; ce qu'elle peut écrire est le
    /// quota libre du sens où elle écrit.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn local_information(&self) -> Result<FilePipeLocalInformation, NtStatus> {
        let state = self.npfs.state.lock();
        let (f, c, end) = self.attached(&state, STATUS_INVALID_PARAMETER)?;
        let fcb = &state.pipes[f];
        let ccb = &fcb.instances[c];
        Ok(FilePipeLocalInformation {
            named_pipe_type: fcb.pipe_type,
            named_pipe_configuration: fcb.configuration,
            maximum_instances: fcb.maximum_instances,
            current_instances: fcb.instances.len() as u32,
            inbound_quota: ccb.queues[INBOUND].quota() as u32,
            read_data_available: ccb.queues[end.read_queue()].readable() as u32,
            outbound_quota: ccb.queues[OUTBOUND].quota() as u32,
            write_quota_available: ccb.queues[end.write_queue()].quota_left() as u32,
            named_pipe_state: ccb.state,
            named_pipe_end: end.value(),
        })
    }

    /// NtCancelIoFile : les demandes de ce fichier faites par le thread
    /// `thread_id` finissent avec `STATUS_CANCELLED`. Rend leur nombre.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn cancel(&self, thread_id: u32) -> usize {
        let id = self.id;
        self.npfs.locked(|state, deferred| {
            state.cancel(
                &|request| request.file() == id && request.requester().thread_id() == thread_id,
                STATUS_CANCELLED,
                deferred,
            )
        })
    }

    /// Retire `request` si elle attend encore et la finit avec `status`
    /// (l'échéance de FSCTL_PIPE_WAIT : `STATUS_IO_TIMEOUT`) ; faux si elle
    /// a déjà fini.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn cancel_request(&self, request: &Arc<Request>, status: NtStatus) -> bool {
        let target: *const Request = Arc::as_ptr(request);
        self.npfs.locked(|state, deferred| state.cancel(&|r| core::ptr::eq(r, target), status, deferred) > 0)
    }

    /// IRP_MJ_CLEANUP (NpSetClosingPipeState), au dernier handle : une
    /// extrémité serveur à l'écoute ou déconnectée détruit son instance (le
    /// tube avec sa dernière) ; une extrémité connectée met l'instance en
    /// fermeture, où l'autre lit ce qui reste puis trouve le tube cassé ; la
    /// seconde extrémité fermée détruit l'instance. Les demandes de ce
    /// fichier qui attendent encore finissent (`STATUS_PIPE_BROKEN`, ou
    /// `STATUS_CANCELLED` pour une attente d'instance), sauf ses écritures
    /// bloquées, qui finissent quand l'autre extrémité les lit.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn cleanup(&self) {
        let opened = core::mem::replace(&mut *self.opened.lock(), Opened::Closed);
        let id = self.id;
        self.npfs.locked(|state, deferred| match opened {
            Opened::End { ccb, end } => close_end(state, ccb, end, id, deferred),
            // Only the root waits (FSCTL_PIPE_WAIT).
            Opened::Root => {
                state.cancel(&|request| request.file() == id, STATUS_CANCELLED, deferred);
            }
            Opened::Unopened | Opened::Closed => {}
        });
    }
}

/// NpSetClosingPipeState : l'extrémité `end` de l'instance `ccb`, liée au
/// fichier `id`, se ferme.
fn close_end(state: &mut State, ccb: u64, end: End, id: u64, deferred: &mut Deferred) {
    let Some((f, c)) = state.locate(ccb) else { return };
    let instance = &mut state.pipes[f].instances[c];
    let bound = match end {
        End::Client => &mut instance.client,
        End::Server => &mut instance.server,
    };
    if *bound != Some(id) {
        // Disconnected by the server earlier: nothing left to close.
        return;
    }
    *bound = None;
    match instance.state {
        FILE_PIPE_CONNECTED_STATE => {
            instance.state = FILE_PIPE_CLOSING_STATE;
            // What it would have read is lost; the other end's reads end,
            // what it wrote stays for the other end to read.
            instance.queues[end.read_queue()].flush(STATUS_PIPE_BROKEN, deferred);
            instance.queues[end.write_queue()].flush_reads(STATUS_PIPE_BROKEN, deferred);
        }
        FILE_PIPE_CLOSING_STATE => {
            instance.queues[end.read_queue()].flush(STATUS_PIPE_BROKEN, deferred);
            state.delete_instance(f, c, deferred);
        }
        // Listening or disconnected: the server's own end.
        _ => state.delete_instance(f, c, deferred),
    }
}
