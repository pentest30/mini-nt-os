//! Les tubes de NPFS, sur l'hôte : création et ouverture, états des
//! instances, messages et octets, lectures partielles, quotas, attentes,
//! annulations, fermetures.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::file::{FILE_CREATE, FILE_CREATED, FILE_OPEN, FILE_OPENED, FILE_OPEN_IF, FILE_SHARE_READ, FILE_SHARE_WRITE};
use abi::ntstatus::*;
use abi::pipe::*;
use ob::{downcast, Object, Parsed};

use super::*;
use crate::request::{Completed, Request, Requester};

/// Un demandeur de test : son thread, abandonné ou non.
struct Tester {
    thread: u32,
    abandoned: Arc<AtomicBool>,
}

impl Requester for Tester {
    fn thread_id(&self) -> u32 {
        self.thread
    }
    fn abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Relaxed)
    }
    fn deliver(&self, _completed: &Completed) {}
}

fn request_of(file: &PipeFile, thread: u32) -> Arc<Request> {
    Request::new(file.id(), Box::new(Tester { thread, abandoned: Arc::new(AtomicBool::new(false)) }))
}

fn request(file: &PipeFile) -> Arc<Request> {
    request_of(file, 1)
}

const RW: u32 = FILE_READ_DATA | FILE_WRITE_DATA;

fn parameters(pipe_type: u32, read_mode: u32) -> CreatePipe {
    CreatePipe {
        disposition: FILE_OPEN_IF,
        share: FILE_SHARE_READ | FILE_SHARE_WRITE,
        pipe_type,
        read_mode,
        completion_mode: FILE_PIPE_QUEUE_OPERATION,
        maximum_instances: FILE_PIPE_UNLIMITED_INSTANCES,
        inbound_quota: 64,
        outbound_quota: 64,
        default_timeout: Some(-500_000),
    }
}

fn file(npfs: &Arc<Npfs>, name: &str) -> Arc<Object<PipeFile>> {
    match npfs.parse(name).expect("a name") {
        Parsed::Object(object) => downcast::<PipeFile>(&object).expect("a pipe file"),
        Parsed::Reparse(_) => panic!("no reparse"),
    }
}

fn server(npfs: &Arc<Npfs>, name: &str, create: &CreatePipe) -> Arc<Object<PipeFile>> {
    let file = file(npfs, name);
    file.create_instance(create).expect("an instance");
    file
}

fn client(npfs: &Arc<Npfs>, name: &str) -> Arc<Object<PipeFile>> {
    let file = file(npfs, name);
    assert_eq!(file.open_client(RW), Ok(FILE_OPENED));
    file
}

/// Un serveur et son client connectés, sur un tube de messages lu en mode
/// message par le serveur.
fn connected_messages() -> (Arc<Npfs>, Arc<Object<PipeFile>>, Arc<Object<PipeFile>>) {
    let npfs = Npfs::new();
    let server = server(&npfs, "\\mino", &parameters(FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_MODE));
    let client = client(&npfs, "\\mino");
    (npfs, server, client)
}

fn done(io: Result<Io, NtStatus>) -> Completed {
    match io {
        Ok(Io::Done(completed)) => completed,
        other => panic!("not done: {other:?}"),
    }
}

fn written(file: &PipeFile, data: &[u8]) -> u32 {
    let completed = done(file.write(data.to_vec(), &request(file)));
    assert_eq!(completed.status, STATUS_SUCCESS);
    completed.information
}

fn read(file: &PipeFile, size: usize) -> (Vec<u8>, NtStatus) {
    let completed = done(file.read(size, &request(file)));
    assert_eq!(completed.information as usize, completed.data.len());
    (completed.data, completed.status)
}

#[test]
fn a_pipe_is_created_then_gets_instances_up_to_its_maximum() {
    let npfs = Npfs::new();
    let mut create = parameters(FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_MODE);
    create.maximum_instances = 2;
    assert_eq!(file(&npfs, "\\winreg").create_instance(&create), Ok(FILE_CREATED));
    assert_eq!(file(&npfs, "\\WINREG").create_instance(&create), Ok(FILE_OPENED), "names have no case");
    assert_eq!(file(&npfs, "\\winreg").create_instance(&create), Err(STATUS_INSTANCE_NOT_AVAILABLE));
    assert_eq!(npfs.instances("\\winreg"), 2);
    assert_eq!(npfs.pipe_names(), vec![alloc::string::String::from("\\winreg")]);
}

#[test]
fn a_creation_checks_its_parameters() {
    let npfs = Npfs::new();
    let good = parameters(FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_MODE);
    let refused = |create: CreatePipe, status| assert_eq!(file(&npfs, "\\p").create_instance(&create), Err(status));
    refused(CreatePipe { default_timeout: None, ..good }, STATUS_INVALID_PARAMETER);
    refused(CreatePipe { default_timeout: Some(0), ..good }, STATUS_INVALID_PARAMETER);
    refused(CreatePipe { maximum_instances: 0, ..good }, STATUS_INVALID_PARAMETER);
    refused(CreatePipe { disposition: FILE_OPEN, ..good }, STATUS_OBJECT_NAME_NOT_FOUND);
    refused(CreatePipe { share: 0, ..good }, STATUS_INVALID_PARAMETER);
    refused(parameters(FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_MESSAGE_MODE), STATUS_INVALID_PARAMETER);
    assert_eq!(file(&npfs, "\\p").create_instance(&good), Ok(FILE_CREATED));
    refused(CreatePipe { disposition: FILE_CREATE, ..good }, STATUS_ACCESS_DENIED);
    refused(CreatePipe { share: FILE_SHARE_READ, ..good }, STATUS_ACCESS_DENIED);
    assert_eq!(file(&npfs, "\\").create_instance(&good), Err(STATUS_OBJECT_NAME_INVALID), "the root");
}

#[test]
fn a_client_connects_to_a_listening_instance_and_ends_its_listen() {
    let npfs = Npfs::new();
    assert_eq!(file(&npfs, "\\none").open_client(RW), Err(STATUS_OBJECT_NAME_NOT_FOUND));
    let server = server(&npfs, "\\mino", &parameters(FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_BYTE_STREAM_MODE));
    let listen = request(&server);
    assert_eq!(server.listen(&listen), Ok(Io::Pending));
    assert!(!listen.is_finished());
    let client = client(&npfs, "\\MINO");
    assert!(listen.is_finished());
    assert_eq!(listen.take().map(|c| c.status), Some(STATUS_SUCCESS));
    assert_eq!(client.end(), Some(End::Client));
    assert_eq!(server.listen(&request(&server)), Err(STATUS_PIPE_CONNECTED));
    assert_eq!(client.listen(&request(&client)), Err(STATUS_ILLEGAL_FUNCTION));
    assert_eq!(file(&npfs, "\\mino").open_client(RW), Err(STATUS_PIPE_NOT_AVAILABLE), "its only instance is taken");
}

#[test]
fn a_client_may_not_read_an_inbound_pipe_nor_write_an_outbound_one() {
    let npfs = Npfs::new();
    let inbound = CreatePipe { share: FILE_SHARE_WRITE, ..parameters(FILE_PIPE_BYTE_STREAM_TYPE, 0) };
    server(&npfs, "\\in", &inbound);
    assert_eq!(file(&npfs, "\\in").open_client(FILE_READ_DATA), Err(STATUS_ACCESS_DENIED));
    let client = file(&npfs, "\\in");
    assert_eq!(client.open_client(FILE_WRITE_DATA), Ok(FILE_OPENED));
    assert_eq!(client.read(4, &request(&client)), Err(STATUS_INVALID_PARAMETER));
    let outbound = CreatePipe { share: FILE_SHARE_READ, ..parameters(FILE_PIPE_BYTE_STREAM_TYPE, 0) };
    server(&npfs, "\\out", &outbound);
    assert_eq!(file(&npfs, "\\out").open_client(FILE_WRITE_DATA), Err(STATUS_ACCESS_DENIED));
}

#[test]
fn a_nonblocking_listen_returns_at_once() {
    let npfs = Npfs::new();
    let create = CreatePipe {
        completion_mode: FILE_PIPE_COMPLETE_OPERATION,
        ..parameters(FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_BYTE_STREAM_MODE)
    };
    let server = server(&npfs, "\\nb", &create);
    assert_eq!(server.listen(&request(&server)), Err(STATUS_PIPE_LISTENING));
}

#[test]
fn messages_are_read_one_at_a_time_and_a_short_buffer_reads_part_of_one() {
    let (_npfs, server, client) = connected_messages();
    assert_eq!(written(&client, b"hello"), 5);
    assert_eq!(written(&client, b"world!!"), 7);
    assert_eq!(read(&server, 3), (b"hel".to_vec(), STATUS_BUFFER_OVERFLOW));
    assert_eq!(read(&server, 64), (b"lo".to_vec(), STATUS_SUCCESS), "the rest of the first message");
    assert_eq!(read(&server, 64), (b"world!!".to_vec(), STATUS_SUCCESS));
}

#[test]
fn a_byte_mode_reader_reads_across_messages() {
    let npfs = Npfs::new();
    let server = server(&npfs, "\\b", &parameters(FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_BYTE_STREAM_MODE));
    let client = client(&npfs, "\\b");
    written(&client, b"abc");
    written(&client, b"defgh");
    assert_eq!(read(&server, 6), (b"abcdef".to_vec(), STATUS_SUCCESS));
    assert_eq!(read(&server, 64), (b"gh".to_vec(), STATUS_SUCCESS));
    // The client reads in byte mode too: the server's messages run together.
    written(&server, b"12");
    written(&server, b"345");
    assert_eq!(read(&client, 64), (b"12345".to_vec(), STATUS_SUCCESS));
}

#[test]
fn a_waiting_read_gets_the_next_write() {
    let (_npfs, server, client) = connected_messages();
    let pending = request(&server);
    assert_eq!(server.read(4, &pending), Ok(Io::Pending));
    assert_eq!(written(&client, b"abcdef"), 6);
    let completed = pending.take().expect("finished");
    assert_eq!((completed.status, completed.information), (STATUS_BUFFER_OVERFLOW, 4));
    assert_eq!(completed.data, b"abcd");
    assert_eq!(read(&server, 64), (b"ef".to_vec(), STATUS_SUCCESS), "the rest stays");
    // An empty message ends a waiting read, without data.
    let pending = request(&server);
    assert_eq!(server.read(4, &pending), Ok(Io::Pending));
    assert_eq!(written(&client, b""), 0);
    assert_eq!(pending.take().map(|c| (c.status, c.information)), Some((STATUS_SUCCESS, 0)));
}

#[test]
fn a_read_of_an_abandoned_thread_takes_no_data() {
    let (_npfs, server, client) = connected_messages();
    let abandoned = Arc::new(AtomicBool::new(false));
    let gone = Request::new(server.id(), Box::new(Tester { thread: 7, abandoned: abandoned.clone() }));
    assert_eq!(server.read(16, &gone), Ok(Io::Pending));
    abandoned.store(true, Ordering::Relaxed);
    written(&client, b"kept");
    assert!(!gone.is_finished());
    assert_eq!(read(&server, 16), (b"kept".to_vec(), STATUS_SUCCESS));
}

#[test]
fn a_write_past_the_quota_waits_until_reads_free_it() {
    let npfs = Npfs::new();
    let create = CreatePipe { inbound_quota: 16, ..parameters(FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_BYTE_STREAM_MODE) };
    let server = server(&npfs, "\\q", &create);
    let client = client(&npfs, "\\q");
    let data: Vec<u8> = (0..40).collect();
    let stalled = request(&client);
    assert_eq!(client.write(data.clone(), &stalled), Ok(Io::Pending));
    assert_eq!(server.local_information().unwrap().read_data_available, 40, "its data is in the queue");
    assert_eq!(client.local_information().unwrap().write_quota_available, 0);
    let (first, _) = read(&server, 10);
    assert!(!stalled.is_finished(), "30 bytes left, 16 of quota");
    let (second, _) = read(&server, 14);
    assert_eq!(stalled.take().map(|c| (c.status, c.information)), Some((STATUS_SUCCESS, 40)), "16 left: they fit");
    let (third, _) = read(&server, 64);
    assert_eq!([first, second, third].concat(), data);
    assert_eq!(client.local_information().unwrap().write_quota_available, 16);
}

#[test]
fn a_nonblocking_message_that_does_not_fit_is_not_written() {
    let npfs = Npfs::new();
    let create = CreatePipe { inbound_quota: 4, ..parameters(FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_MODE) };
    let server = server(&npfs, "\\nb", &create);
    let client = client(&npfs, "\\nb");
    client
        .set_pipe_information(&FilePipeInformation {
            read_mode: FILE_PIPE_MESSAGE_MODE,
            completion_mode: FILE_PIPE_COMPLETE_OPERATION,
        })
        .unwrap();
    assert_eq!(written(&client, b"too long"), 0);
    assert_eq!(server.local_information().unwrap().read_data_available, 0, "nothing written");
    assert_eq!(written(&client, b"fits"), 4);
    assert_eq!(read(&server, 8), (b"fits".to_vec(), STATUS_SUCCESS));
}

#[test]
fn a_peek_sees_the_data_without_taking_it() {
    let (_npfs, server, client) = connected_messages();
    let (header, status) = server.peek(PEEK_HEADER_SIZE).unwrap();
    assert_eq!((header.len(), status), (PEEK_HEADER_SIZE, STATUS_SUCCESS));
    assert_eq!(u32::from_le_bytes(header[0..4].try_into().unwrap()), FILE_PIPE_CONNECTED_STATE);
    written(&client, b"hello");
    written(&client, b"world!!");
    let (out, status) = server.peek(PEEK_HEADER_SIZE).unwrap();
    assert_eq!(status, STATUS_BUFFER_OVERFLOW, "data that does not fit");
    let field = |at: usize| u32::from_le_bytes(out[at..at + 4].try_into().unwrap());
    assert_eq!((field(4), field(8), field(12)), (12, 2, 5), "available, messages, first message");
    let (out, status) = server.peek(PEEK_HEADER_SIZE + 3).unwrap();
    assert_eq!((&out[PEEK_HEADER_SIZE..], status), (&b"hel"[..], STATUS_BUFFER_OVERFLOW));
    let (out, status) = server.peek(PEEK_HEADER_SIZE + 64).unwrap();
    assert_eq!((&out[PEEK_HEADER_SIZE..], status), (&b"hello"[..], STATUS_SUCCESS), "one message");
    assert_eq!(read(&server, 64), (b"hello".to_vec(), STATUS_SUCCESS), "still there");
    assert_eq!(server.peek(8), Err(STATUS_INVALID_PARAMETER));
}

#[test]
fn a_closed_client_leaves_its_data_then_the_pipe_is_broken() {
    let (npfs, server, client) = connected_messages();
    let waiting = request(&client);
    assert_eq!(client.read(8, &waiting), Ok(Io::Pending));
    written(&client, b"last");
    client.cleanup();
    assert_eq!(waiting.take().map(|c| c.status), Some(STATUS_PIPE_BROKEN), "its own read ends");
    assert_eq!(written_status(&server, b"x"), Err(STATUS_PIPE_CLOSING));
    assert_eq!(read(&server, 8), (b"last".to_vec(), STATUS_SUCCESS));
    assert_eq!(server.read(8, &request(&server)), Err(STATUS_PIPE_BROKEN));
    assert_eq!(server.peek(PEEK_HEADER_SIZE), Err(STATUS_PIPE_BROKEN));
    server.cleanup();
    assert_eq!(npfs.instances("\\mino"), 0, "the second end deletes the instance");
    assert!(npfs.pipe_names().is_empty(), "and its last instance the pipe");
}

fn written_status(file: &PipeFile, data: &[u8]) -> Result<u32, NtStatus> {
    file.write(data.to_vec(), &request(file)).map(|io| match io {
        Io::Done(completed) => completed.information,
        Io::Pending => panic!("pending"),
    })
}

#[test]
fn a_closed_server_ends_the_reads_of_its_client() {
    let (npfs, server, client) = connected_messages();
    let waiting = request(&client);
    assert_eq!(client.read(8, &waiting), Ok(Io::Pending));
    let listening = file(&npfs, "\\mino");
    listening.create_instance(&parameters(FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_MODE)).unwrap();
    server.cleanup();
    assert_eq!(waiting.take().map(|c| c.status), Some(STATUS_PIPE_BROKEN));
    assert_eq!(client.read(8, &request(&client)), Err(STATUS_PIPE_BROKEN));
    client.cleanup();
    assert_eq!(npfs.instances("\\mino"), 1, "the other instance stays");
    let listen = request(&listening);
    listening.cleanup();
    assert_eq!(listening.listen(&listen), Err(STATUS_PIPE_DISCONNECTED), "closed");
    assert!(npfs.pipe_names().is_empty());
}

#[test]
fn a_disconnected_instance_drops_its_client_then_listens_again() {
    let (npfs, server, client) = connected_messages();
    written(&client, b"lost");
    let waiting = request(&client);
    assert_eq!(client.read(8, &waiting), Ok(Io::Pending));
    assert_eq!(client.disconnect(), Err(STATUS_ILLEGAL_FUNCTION));
    assert_eq!(server.disconnect(), Ok(()));
    assert_eq!(waiting.take().map(|c| c.status), Some(STATUS_PIPE_DISCONNECTED));
    assert_eq!(client.read(8, &request(&client)), Err(STATUS_PIPE_DISCONNECTED));
    assert_eq!(server.read(8, &request(&server)), Err(STATUS_PIPE_DISCONNECTED), "the data went with it");
    assert_eq!(server.disconnect(), Err(STATUS_PIPE_DISCONNECTED));
    let listen = request(&server);
    assert_eq!(server.listen(&listen), Ok(Io::Pending));
    assert_eq!(server.read(8, &request(&server)), Err(STATUS_PIPE_LISTENING));
    let again = client_of(&npfs);
    assert_eq!(listen.take().map(|c| c.status), Some(STATUS_SUCCESS));
    written(&server, b"hi");
    assert_eq!(client.read(8, &request(&client)), Err(STATUS_PIPE_DISCONNECTED), "the old client lost the instance");
    assert_eq!(read(&again, 8), (b"hi".to_vec(), STATUS_SUCCESS));
    written(&again, b"new");
    assert_eq!(read(&server, 8), (b"new".to_vec(), STATUS_SUCCESS));
    client.cleanup();
    assert_eq!(npfs.instances("\\mino"), 1, "the old client closed nothing");
}

fn client_of(npfs: &Arc<Npfs>) -> Arc<Object<PipeFile>> {
    client(npfs, "\\mino")
}

#[test]
fn a_disconnect_ends_a_listen() {
    let npfs = Npfs::new();
    let server = server(&npfs, "\\l", &parameters(FILE_PIPE_BYTE_STREAM_TYPE, 0));
    let listen = request(&server);
    assert_eq!(server.listen(&listen), Ok(Io::Pending));
    assert_eq!(server.disconnect(), Ok(()));
    assert_eq!(listen.take().map(|c| c.status), Some(STATUS_PIPE_DISCONNECTED));
    let listen = request(&server);
    assert_eq!(server.listen(&listen), Ok(Io::Pending));
    server.cleanup();
    assert_eq!(listen.take().map(|c| c.status), Some(STATUS_PIPE_BROKEN), "closed while listening");
}

#[test]
fn a_wait_ends_when_an_instance_listens() {
    let npfs = Npfs::new();
    let root = file(&npfs, "\\");
    assert!(root.is_root());
    assert_eq!(root.wait("none", None, &request(&root)), Err(STATUS_OBJECT_NAME_NOT_FOUND));
    let first = server(&npfs, "\\w", &parameters(FILE_PIPE_BYTE_STREAM_TYPE, 0));
    assert_eq!(root.wait("W", None, &request(&root)), Ok(Wait::Ready));
    let _client = client(&npfs, "\\w");
    let waiting = request(&root);
    assert_eq!(root.wait("w", None, &waiting), Ok(Wait::Pending(Some(-500_000))), "the pipe's timeout");
    let forever = request(&root);
    assert_eq!(root.wait("w", Some(WAIT_FOREVER), &forever), Ok(Wait::Pending(None)));
    let _second = server(&npfs, "\\w", &parameters(FILE_PIPE_BYTE_STREAM_TYPE, 0));
    assert_eq!(waiting.take().map(|c| c.status), Some(STATUS_SUCCESS));
    assert_eq!(forever.take().map(|c| c.status), Some(STATUS_SUCCESS));
    assert_eq!(first.wait("w", None, &request(&first)), Err(STATUS_ILLEGAL_FUNCTION), "not the root");
}

#[test]
fn a_wait_runs_out_of_time_or_loses_its_pipe() {
    let npfs = Npfs::new();
    let root = file(&npfs, "\\");
    let server = server(&npfs, "\\t", &parameters(FILE_PIPE_BYTE_STREAM_TYPE, 0));
    let _client = client(&npfs, "\\t");
    let timed = request(&root);
    assert_eq!(root.wait("t", Some(-10), &timed), Ok(Wait::Pending(Some(-10))));
    assert!(root.cancel_request(&timed, STATUS_IO_TIMEOUT));
    assert_eq!(timed.take().map(|c| c.status), Some(STATUS_IO_TIMEOUT));
    assert!(!root.cancel_request(&timed, STATUS_IO_TIMEOUT), "already finished");
    let orphan = request(&root);
    assert_eq!(root.wait("t", None, &orphan), Ok(Wait::Pending(Some(-500_000))));
    // A disconnected instance that listens again lets the wait go on.
    server.disconnect().unwrap();
    assert_eq!(server.listen(&request(&server)), Ok(Io::Pending));
    assert_eq!(orphan.take().map(|c| c.status), Some(STATUS_SUCCESS));
    let lost = request(&root);
    _client.cleanup();
    let busy = file(&npfs, "\\t");
    busy.open_client(RW).unwrap();
    assert_eq!(root.wait("t", None, &lost), Ok(Wait::Pending(Some(-500_000))));
    busy.cleanup();
    server.cleanup();
    assert_eq!(lost.take().map(|c| c.status), Some(STATUS_OBJECT_NAME_NOT_FOUND), "the pipe is gone");
}

#[test]
fn a_cancel_ends_the_requests_of_its_thread_on_its_file() {
    let (_npfs, server, client) = connected_messages();
    let mine = request_of(&server, 1);
    let other = request_of(&server, 2);
    assert_eq!(server.read(8, &mine), Ok(Io::Pending));
    assert_eq!(server.read(8, &other), Ok(Io::Pending));
    assert_eq!(client.cancel(1), 0, "another file");
    assert_eq!(server.cancel(1), 1);
    assert_eq!(mine.take().map(|c| c.status), Some(STATUS_CANCELLED));
    assert!(!other.is_finished());
    written(&client, b"x");
    assert_eq!(other.take().map(|c| c.data), Some(b"x".to_vec()));
}

#[test]
fn pipe_modes_change_within_their_rules() {
    let npfs = Npfs::new();
    let server = server(&npfs, "\\m", &parameters(FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_BYTE_STREAM_MODE));
    let client = client(&npfs, "\\m");
    let message = FilePipeInformation { read_mode: FILE_PIPE_MESSAGE_MODE, completion_mode: 0 };
    assert_eq!(client.set_pipe_information(&message), Err(STATUS_INVALID_PARAMETER), "a byte pipe");
    let pending = request(&client);
    assert_eq!(client.read(4, &pending), Ok(Io::Pending));
    let nonblocking = FilePipeInformation { read_mode: 0, completion_mode: FILE_PIPE_COMPLETE_OPERATION };
    assert_eq!(client.set_pipe_information(&nonblocking), Err(STATUS_PIPE_BUSY), "a read waits");
    written(&server, b"done");
    assert!(pending.is_finished());
    assert_eq!(client.set_pipe_information(&nonblocking), Ok(()));
    assert_eq!(client.pipe_information(), Ok(nonblocking));
    assert_eq!(client.read(4, &request(&client)), Err(STATUS_PIPE_EMPTY));
    assert_eq!(server.pipe_information().unwrap().completion_mode, FILE_PIPE_QUEUE_OPERATION, "per end");
}

#[test]
fn the_local_information_is_seen_from_each_end() {
    let (_npfs, server, client) = connected_messages();
    written(&client, b"abc");
    let seen = server.local_information().unwrap();
    assert_eq!(
        seen,
        FilePipeLocalInformation {
            named_pipe_type: FILE_PIPE_MESSAGE_TYPE,
            named_pipe_configuration: FILE_PIPE_FULL_DUPLEX,
            maximum_instances: FILE_PIPE_UNLIMITED_INSTANCES,
            current_instances: 1,
            inbound_quota: 64,
            read_data_available: 3,
            outbound_quota: 64,
            write_quota_available: 64,
            named_pipe_state: FILE_PIPE_CONNECTED_STATE,
            named_pipe_end: FILE_PIPE_SERVER_END,
        }
    );
    let seen = client.local_information().unwrap();
    assert_eq!((seen.read_data_available, seen.write_quota_available), (0, 61));
    assert_eq!(seen.named_pipe_end, FILE_PIPE_CLIENT_END);
}

#[test]
fn the_root_parses_relative_names() {
    let npfs = Npfs::new();
    let root = file(&npfs, "\\");
    assert!(matches!(root.parse_relative("\\x"), Ok(Parsed::Object(_))));
    assert!(root.parse_relative("\\").is_err());
    assert!(file(&npfs, "\\x").parse_relative("\\y").is_err(), "only the root");
    assert!(npfs.parse("x").is_err(), "a name starts with \\");
}
