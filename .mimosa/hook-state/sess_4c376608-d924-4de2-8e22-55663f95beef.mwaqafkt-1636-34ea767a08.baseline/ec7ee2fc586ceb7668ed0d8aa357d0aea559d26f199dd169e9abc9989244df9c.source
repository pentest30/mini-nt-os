//! Les services d'Io sur les tubes nommés (NPFS, `io_manager::npfs`) :
//! créer une instance (NtCreateNamedPipeFile), s'y connecter (NtCreateFile,
//! NtOpenFile, par `file`), lire et écrire (NtReadFile, NtWriteFile), les
//! contrôles du système de fichiers (NtFsControlFile : écoute, déconnexion,
//! aperçu, attente d'une instance), les modes et l'état d'une extrémité
//! (NtQueryInformationFile, NtSetInformationFile), et l'annulation des E/S
//! d'un thread (NtCancelIoFile).
//!
//! Une E/S de tube finit tout de suite ou attend ([`io_manager::npfs::Io`]).
//! Sur un fichier synchrone (`FILE_SYNCHRONOUS_IO_*`), le thread attend sa
//! fin dans l'appel, sans alerte, puis écrit lui-même les données et le bloc
//! d'état. Sur un fichier asynchrone, l'appel rend `STATUS_PENDING` ; à sa
//! fin, le thread qui la termine écrit les données et le bloc d'état dans le
//! processus du demandeur (MmCopyVirtualMemory : `EProcess::write_memory`),
//! signale son événement et l'événement du fichier (FILE_OBJECT.Event), et
//! met en file son APC de fin (`ApcRoutine(ApcContext, IoStatusBlock, 0)`),
//! comme IopCompleteRequest. Une erreur rendue tout de suite n'écrit ni le
//! bloc d'état ni l'événement, comme sous NT.
//!
//! Pas encore : l'attente d'une instance (FSCTL_PIPE_WAIT) d'un fichier
//! asynchrone se fait aussi dans l'appel ; une attente synchrone ne
//! s'interrompt pas pour une APC (`FILE_SYNCHRONOUS_IO_ALERT` est traité
//! comme `NONALERT`) ; les ports de complétion (ApcContext) ;
//! FSCTL_PIPE_IMPERSONATE, FSCTL_PIPE_TRANSCEIVE et les événements de tube
//! (`STATUS_NOT_IMPLEMENTED`, journalisé une fois) ; les attributs d'un
//! tube autres que ses modes, son état et son nom.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use abi::file::{
    FileFsDeviceInformation, IoStatusBlock32, FILE_CREATE, FILE_OPEN, FILE_OPEN_IF, FILE_READ_DATA, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_DATA, FILE_WRITE_THROUGH,
};
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_PARAMETER, STATUS_IO_TIMEOUT, STATUS_PENDING, STATUS_SUCCESS, STATUS_TIMEOUT,
};
use abi::object::OBJ_INHERIT;
use abi::pipe::{
    FilePipeInformation, PipeWait, FILE_DEVICE_NAMED_PIPE, FILE_PIPE_COMPLETE_OPERATION, FILE_PIPE_MESSAGE_MODE,
    FILE_PIPE_MESSAGE_TYPE, FSCTL_PIPE_DISCONNECT, FSCTL_PIPE_LISTEN, FSCTL_PIPE_PEEK, FSCTL_PIPE_WAIT,
};
use ex::event::{Event, EVENT_MODIFY_STATE, EVENT_TYPE};
use io_manager::npfs::{CreatePipe, Io, Wait};
use io_manager::request::{Completed, Request, Requester};
use io_manager::{PipeFile, FILE_TYPE};
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, HandleAttributes, Object};
use ps::EThread;

use super::object::{capture_attributes, give_handle};

/// Le fichier de tube que désigne `handle`, s'il en désigne un, avec les
/// droits `access` ; `None` pour un autre fichier ou un autre objet (le
/// service le traite comme avant).
pub(super) fn pipe_file(handle: u32, access: AccessMask) -> Result<Option<Arc<Object<PipeFile>>>, NtStatus> {
    let object = super::current_process().handle_table.reference(Handle(handle), Some(&FILE_TYPE), access)?;
    Ok(ob::downcast::<PipeFile>(&object))
}

/// Le thread courant, un thread de Ps.
fn current_thread() -> Arc<Object<EThread>> {
    ps::ethread::current_thread().expect("a system service outside a Ps thread")
}

/// Le bloc d'état en `iosb`, dans le processus courant.
fn write_iosb(iosb: u32, status: NtStatus, information: u32) -> Result<(), NtStatus> {
    let block = IoStatusBlock32 { status: status.0, information };
    ke::usermem::copy_to_user(u64::from(iosb), &block.to_bytes())
}

/// Ce que l'appelant d'une E/S donne pour sa fin.
struct Call {
    file: Arc<Object<PipeFile>>,
    /// Son événement (Event), remis à zéro au début de l'E/S.
    event: Option<Arc<Object<Event>>>,
    /// ApcRoutine et ApcContext.
    apc: Option<(u32, u32)>,
    iosb: u32,
    /// Où vont les données d'une lecture.
    buffer: u32,
}

impl Call {
    /// Le début d'une E/S sur `file` : l'événement de l'appelant (`event`,
    /// avec `EVENT_MODIFY_STATE`) et celui du fichier remis à zéro, le bloc
    /// d'état sondé.
    fn start(
        file: Arc<Object<PipeFile>>,
        event: u32,
        apc: (u32, u32),
        iosb: u32,
        buffer: u32,
    ) -> Result<Self, NtStatus> {
        let event = match event {
            0 => None,
            handle => Some(super::current_process().handle_table.reference_as::<Event>(
                Handle(handle),
                &EVENT_TYPE,
                EVENT_MODIFY_STATE,
            )?),
        };
        ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
        if let Some(event) = &event {
            event.reset();
        }
        file.event().clear();
        let apc = (apc.0 != 0).then_some(apc);
        Ok(Self { file, event, apc, iosb, buffer })
    }

    /// La demande de l'appel : livrée par le thread qui la termine si le
    /// fichier est asynchrone, par l'appelant sinon.
    fn request(&self) -> Arc<Request> {
        let thread = current_thread();
        let delivery = (!self.file.is_synchronous()).then(|| Delivery {
            file: self.file.clone(),
            event: self.event.clone(),
            apc: self.apc,
            iosb: self.iosb,
            buffer: self.buffer,
        });
        Request::new(self.file.id(), Box::new(Caller { thread, delivery }))
    }

    /// La fin d'une E/S qui a fini tout de suite, ou qu'un fichier synchrone
    /// a attendue : données, bloc d'état, événements, APC ; rend son statut.
    fn complete(&self, completed: &Completed) -> NtStatus {
        if !completed.data.is_empty() {
            if let Err(fault) = ke::usermem::copy_to_user(u64::from(self.buffer), &completed.data) {
                return fault;
            }
        }
        if let Err(fault) = write_iosb(self.iosb, completed.status, completed.information) {
            return fault;
        }
        signal(&self.file, self.event.as_ref());
        if let Some((routine, context)) = self.apc {
            let _ = current_thread().queue_user_apc(routine, context, self.iosb, 0);
        }
        completed.status
    }

    /// Ce que devient l'appel pour ce que rend l'opération : une erreur
    /// tout de suite, sans rien écrire ; une fin tout de suite ; ou une
    /// attente, dans l'appel pour un fichier synchrone (`STATUS_PENDING`
    /// sinon).
    fn finish(&self, result: Result<Io, NtStatus>, request: &Request) -> NtStatus {
        match result {
            Err(status) => status,
            Ok(Io::Done(completed)) => self.complete(&completed),
            Ok(Io::Pending) if self.file.is_synchronous() => {
                request.wait(None);
                let completed = request.take().expect("a finished request keeps its end");
                self.complete(&completed)
            }
            Ok(Io::Pending) => STATUS_PENDING,
        }
    }
}

/// Signale l'événement de l'appelant et celui du fichier.
fn signal(file: &PipeFile, event: Option<&Arc<Object<Event>>>) {
    if let Some(event) = event {
        event.set();
    }
    file.event().set();
}

/// Ce que livre la fin d'une E/S asynchrone.
struct Delivery {
    file: Arc<Object<PipeFile>>,
    event: Option<Arc<Object<Event>>>,
    apc: Option<(u32, u32)>,
    iosb: u32,
    buffer: u32,
}

/// Le demandeur d'une E/S de tube : son thread, et pour un fichier
/// asynchrone ce que livre sa fin.
struct Caller {
    thread: Arc<Object<EThread>>,
    delivery: Option<Delivery>,
}

impl Requester for Caller {
    fn thread_id(&self) -> u32 {
        self.thread.tid()
    }

    fn abandoned(&self) -> bool {
        self.thread.is_terminating()
    }

    /// IopCompleteRequest, depuis le thread qui termine la demande : écrit
    /// dans le processus du demandeur (une faute laisse la donnée non
    /// écrite, comme l'APC de fin de NT sous son `try`).
    fn deliver(&self, completed: &Completed) {
        let Some(delivery) = &self.delivery else { return };
        let process = self.thread.process();
        if !completed.data.is_empty() {
            let _ = process.write_memory(u64::from(delivery.buffer), &completed.data);
        }
        let block = IoStatusBlock32 { status: completed.status.0, information: completed.information };
        let _ = process.write_memory(u64::from(delivery.iosb), &block.to_bytes());
        signal(&delivery.file, delivery.event.as_ref());
        if let Some((routine, context)) = delivery.apc {
            let _ = self.thread.queue_user_apc(routine, context, delivery.iosb, 0);
        }
    }
}

/// NtCreateNamedPipeFile(*FileHandle, DesiredAccess, ObjectAttributes,
/// IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions,
/// NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota,
/// OutboundQuota, DefaultTimeout) : une instance du tube que désignent les
/// attributs (sous `\Device\NamedPipe`), créé s'il n'existe pas
/// (`io_manager::PipeFile::create_instance`) ; le handle est son extrémité
/// serveur, à l'écoute. Comme IoCreateFile : `FILE_CREATE`, `FILE_OPEN` ou
/// `FILE_OPEN_IF`, les options d'un tube (synchrone, écriture directe), des
/// modes connus, sinon `STATUS_INVALID_PARAMETER` ; un nom hors de NPFS :
/// `STATUS_INVALID_DEVICE_REQUEST` (que `kernel32` rend en
/// `ERROR_INVALID_NAME`).
pub(super) fn nt_create_named_pipe_file(arguments: &[u32]) -> NtStatus {
    create_named_pipe_file(arguments).map_or_else(|status| status, |()| STATUS_SUCCESS)
}

fn create_named_pipe_file(arguments: &[u32]) -> Result<(), NtStatus> {
    let [out, desired, attributes, iosb, share, disposition, options, pipe_type, read_mode, completion_mode, maximum_instances, inbound_quota, outbound_quota, timeout] =
        arguments[..14]
    else {
        unreachable!("14 arguments")
    };
    let pipe_options = FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH;
    if !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF)
        || options & !pipe_options != 0
        || share & !(FILE_SHARE_READ | FILE_SHARE_WRITE) != 0
        || pipe_type > FILE_PIPE_MESSAGE_TYPE
        || read_mode > FILE_PIPE_MESSAGE_MODE
        || completion_mode > FILE_PIPE_COMPLETE_OPERATION
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let out = UserPtr::<u32>::new(out);
    out.write(&0)?;
    ke::usermem::probe_for_write(u64::from(iosb), size_of::<IoStatusBlock32>(), 4)?;
    let default_timeout = match timeout {
        0 => None,
        at => Some(UserPtr::<i64>::new(at).read()?),
    };
    let captured = capture_attributes(attributes)?;
    let name = captured.name.unwrap_or_default();
    let object = ob::namespace().open(&name, captured.root.as_ref(), Some(&FILE_TYPE), captured.attributes)?;
    let pipe = ob::downcast::<PipeFile>(&object).ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    let create = CreatePipe {
        disposition,
        share,
        pipe_type,
        read_mode,
        completion_mode,
        maximum_instances,
        inbound_quota,
        outbound_quota,
        default_timeout,
    };
    let information = pipe.create_instance(&create)?;
    pipe.set_mode(options);
    give_pipe_handle(pipe, &out, iosb, desired, captured.attributes, information)
}

/// Le handle d'un fichier de tube ouvert ou créé, et le bloc d'état
/// (`information`) ; le fichier se ferme si l'un ou l'autre échoue.
fn give_pipe_handle(
    pipe: Arc<Object<PipeFile>>,
    out: &UserPtr<u32>,
    iosb: u32,
    desired: u32,
    attributes: u32,
    information: u32,
) -> Result<(), NtStatus> {
    let process = super::current_process();
    let handle_attributes = HandleAttributes { inherit: attributes & OBJ_INHERIT != 0, protect_from_close: false };
    let handle = match process.handle_table.insert(pipe.clone(), AccessMask(desired), handle_attributes) {
        Ok(handle) => handle,
        Err(status) => {
            pipe.cleanup();
            return Err(status);
        }
    };
    // From here on, closing the handle closes the pipe's end.
    give_handle(out, handle)?;
    if let Err(fault) = write_iosb(iosb, STATUS_SUCCESS, information) {
        let _ = process.handle_table.close(handle);
        return Err(fault);
    }
    Ok(())
}

/// NtCreateFile et NtOpenFile d'un nom de NPFS : la racine (`\`), ou un
/// client connecté à la première instance à l'écoute
/// (`io_manager::PipeFile::open_client`, avec les droits accordés pour
/// `desired`). Rend `FILE_OPENED`.
pub(super) fn open(
    pipe: Arc<Object<PipeFile>>,
    out: &UserPtr<u32>,
    iosb: u32,
    desired: u32,
    options: u32,
    attributes: u32,
) -> Result<(), NtStatus> {
    let information = if pipe.is_root() {
        abi::file::FILE_OPENED
    } else {
        pipe.open_client(FILE_TYPE.granted_access(AccessMask(desired)).0)?
    };
    pipe.set_mode(options);
    give_pipe_handle(pipe, out, iosb, desired, attributes, information)
}

/// NtReadFile et NtWriteFile sur un tube (`FILE_READ_DATA`,
/// `FILE_WRITE_DATA`) ; `ByteOffset` et `Key` sont ignorés, comme par
/// NPFS.
pub(super) fn read_write(pipe: Arc<Object<PipeFile>>, arguments: &[u32], write: bool) -> NtStatus {
    transfer(pipe, arguments, write).unwrap_or_else(|status| status)
}

fn transfer(pipe: Arc<Object<PipeFile>>, arguments: &[u32], write: bool) -> Result<NtStatus, NtStatus> {
    let [handle, event, apc_routine, apc_context, iosb, buffer, length, _byte_offset, _key] = arguments[..9] else {
        unreachable!("9 arguments")
    };
    let (granted, _) = super::current_process().handle_table.query(Handle(handle))?;
    let needed = if write { FILE_WRITE_DATA } else { FILE_READ_DATA };
    if !granted.intersects(AccessMask(needed)) {
        return Err(STATUS_ACCESS_DENIED);
    }
    let length = length as usize;
    if write {
        ke::usermem::probe_for_read(u64::from(buffer), length, 1)?;
    } else {
        ke::usermem::probe_for_write(u64::from(buffer), length, 1)?;
    }
    let call = Call::start(pipe, event, (apc_routine, apc_context), iosb, buffer)?;
    let request = call.request();
    let result = if write {
        let mut data = Vec::new();
        data.try_reserve_exact(length).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        data.resize(length, 0);
        ke::usermem::copy_from_user(&mut data, u64::from(buffer))?;
        call.file.write(data, &request)
    } else {
        call.file.read(length, &request)
    };
    Ok(call.finish(result, &request))
}

/// Les contrôles de tube demandés sans être implémentés (par numéro de
/// fonction).
static PIPE_CONTROLS: super::ClassReport = super::ClassReport::new("NtFsControlFile (named pipe)");

/// NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
/// FsControlCode, InputBuffer, InputBufferLength, OutputBuffer,
/// OutputBufferLength) : les contrôles de NPFS sur un fichier de tube
/// (FSCTL_PIPE_LISTEN, FSCTL_PIPE_DISCONNECT, FSCTL_PIPE_PEEK,
/// FSCTL_PIPE_WAIT sur la racine). Le droit qu'un contrôle demande (ses
/// bits 14 et 15 : `FILE_READ_DATA`, `FILE_WRITE_DATA`) se vérifie sur le
/// handle ; un contrôle sur un autre fichier : `STATUS_INVALID_DEVICE_REQUEST`.
pub(super) fn nt_fs_control_file(arguments: &[u32]) -> NtStatus {
    fs_control_file(arguments).unwrap_or_else(|status| status)
}

fn fs_control_file(arguments: &[u32]) -> Result<NtStatus, NtStatus> {
    let [handle, event, apc_routine, apc_context, iosb, code, input, input_length, output, output_length] =
        arguments[..10]
    else {
        unreachable!("10 arguments")
    };
    let Some(pipe) = pipe_file(handle, AccessMask::NONE)? else {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    };
    let (granted, _) = super::current_process().handle_table.query(Handle(handle))?;
    let required = (code >> 14) & 3;
    let needed =
        (if required & 1 != 0 { FILE_READ_DATA } else { 0 }) | (if required & 2 != 0 { FILE_WRITE_DATA } else { 0 });
    if !granted.contains(AccessMask(needed)) {
        return Err(STATUS_ACCESS_DENIED);
    }
    let mut captured = Vec::new();
    if input_length > 0 {
        ke::usermem::probe_for_read(u64::from(input), input_length as usize, 1)?;
        captured.try_reserve_exact(input_length as usize).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        captured.resize(input_length as usize, 0);
        ke::usermem::copy_from_user(&mut captured, u64::from(input))?;
    }
    if output_length > 0 {
        ke::usermem::probe_for_write(u64::from(output), output_length as usize, 1)?;
    }
    let call = Call::start(pipe, event, (apc_routine, apc_context), iosb, output)?;
    match code {
        FSCTL_PIPE_LISTEN => {
            let request = call.request();
            let result = call.file.listen(&request);
            Ok(call.finish(result, &request))
        }
        FSCTL_PIPE_DISCONNECT => {
            call.file.disconnect()?;
            Ok(call.complete(&Completed::status(STATUS_SUCCESS, 0)))
        }
        FSCTL_PIPE_PEEK => {
            let (data, status) = call.file.peek(output_length as usize)?;
            let information = data.len() as u32;
            Ok(call.complete(&Completed { status, information, data }))
        }
        FSCTL_PIPE_WAIT => {
            let wait = PipeWait::parse(&captured).ok_or(STATUS_INVALID_PARAMETER)?;
            let name = alloc::string::String::from_utf16(&wait.name_units(&captured).collect::<Vec<u16>>())
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            let request = call.request();
            let status = match call.file.wait(&name, wait.timeout, &request)? {
                Wait::Ready => STATUS_SUCCESS,
                // Waited here, whatever the file's mode (see the module).
                Wait::Pending(due) => {
                    // At its due time, the wait is withdrawn; unless an
                    // instance took it meanwhile, which finishes it once
                    // NPFS's lock is released: wait for that.
                    if request.wait(due) == STATUS_TIMEOUT && !call.file.cancel_request(&request, STATUS_IO_TIMEOUT) {
                        request.wait(None);
                    }
                    request.take().expect("a finished wait keeps its end").status
                }
            };
            if status.is_error() {
                return Err(status);
            }
            Ok(call.complete(&Completed::status(status, 0)))
        }
        _ if code >> 16 == FILE_DEVICE_NAMED_PIPE => Err(PIPE_CONTROLS.report((code >> 2) & 0xFFF)),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// NtCancelIoFile(FileHandle, IoStatusBlock) : les E/S du thread courant sur
/// ce fichier finissent avec `STATUS_CANCELLED` (celles d'un tube : les
/// autres fichiers n'en gardent pas) ; le bloc d'état dit `STATUS_SUCCESS`.
pub(super) fn nt_cancel_io_file(arguments: &[u32]) -> NtStatus {
    let cancel = || {
        let object = super::current_process().handle_table.reference(
            Handle(arguments[0]),
            Some(&FILE_TYPE),
            AccessMask::NONE,
        )?;
        ke::usermem::probe_for_write(u64::from(arguments[1]), size_of::<IoStatusBlock32>(), 4)?;
        if let Some(pipe) = ob::downcast::<PipeFile>(&object) {
            pipe.cancel(current_thread().tid());
        }
        write_iosb(arguments[1], STATUS_SUCCESS, 0)
    };
    cancel().map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtQueryInformationFile sur un tube : FilePipeInformation,
/// FilePipeLocalInformation, FileNameInformation (le nom du tube, `\nom`) ;
/// une autre classe : `STATUS_INVALID_PARAMETER`, comme NPFS.
pub(super) fn query_information(pipe: &PipeFile, class: u32) -> Result<Vec<u8>, NtStatus> {
    match class {
        abi::pipe::FILE_PIPE_INFORMATION => Ok(pipe.pipe_information()?.to_bytes().into()),
        abi::pipe::FILE_PIPE_LOCAL_INFORMATION => Ok(pipe.local_information()?.to_bytes().into()),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// NtSetInformationFile(FilePipeInformation) sur un tube.
pub(super) fn set_pipe_information(pipe: &PipeFile, bytes: &[u8; 8]) -> Result<(), NtStatus> {
    pipe.set_pipe_information(&FilePipeInformation::from_bytes(bytes))
}

/// FileFsDeviceInformation d'un tube : FILE_DEVICE_NAMED_PIPE, ce que
/// `kernel32` (GetFileType) rend en FILE_TYPE_PIPE.
pub(super) fn device_information() -> FileFsDeviceInformation {
    FileFsDeviceInformation { device_type: FILE_DEVICE_NAMED_PIPE, characteristics: 0 }
}
