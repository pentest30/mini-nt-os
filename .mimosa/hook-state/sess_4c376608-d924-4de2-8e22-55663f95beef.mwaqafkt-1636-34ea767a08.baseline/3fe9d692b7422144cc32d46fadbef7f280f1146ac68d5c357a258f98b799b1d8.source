//! What the named pipe services take and return to an i386 process
//! (CLAUDE.md, rule 5), laid out as on XP SP2: the values of
//! NtCreateNamedPipeFile, the file system controls of the named pipe file
//! system (`FSCTL_PIPE_*`) and their buffers, and the pipe information
//! classes of NtQueryInformationFile and NtSetInformationFile. Values are
//! those of the XP DDK headers (`ntifs.h`); offsets are checked at compile
//! time.

use core::mem::{offset_of, size_of};

/// FILE_DEVICE_NAMED_PIPE: the device type of `\Device\NamedPipe`
/// (FileFsDeviceInformation), and of its controls.
pub const FILE_DEVICE_NAMED_PIPE: u32 = 0x0000_0011;

/// NamedPipeType (NtCreateNamedPipeFile, FilePipeLocalInformation).
pub const FILE_PIPE_BYTE_STREAM_TYPE: u32 = 0;
pub const FILE_PIPE_MESSAGE_TYPE: u32 = 1;

/// ReadMode (NtCreateNamedPipeFile, FilePipeInformation).
pub const FILE_PIPE_BYTE_STREAM_MODE: u32 = 0;
pub const FILE_PIPE_MESSAGE_MODE: u32 = 1;

/// CompletionMode: a read or a listen waits (queue), or returns at once
/// (complete).
pub const FILE_PIPE_QUEUE_OPERATION: u32 = 0;
pub const FILE_PIPE_COMPLETE_OPERATION: u32 = 1;

/// NamedPipeConfiguration, from the share access of the pipe's creation:
/// the server reads only (inbound), writes only (outbound), or both.
pub const FILE_PIPE_INBOUND: u32 = 0;
pub const FILE_PIPE_OUTBOUND: u32 = 1;
pub const FILE_PIPE_FULL_DUPLEX: u32 = 2;

/// NamedPipeState of an instance.
pub const FILE_PIPE_DISCONNECTED_STATE: u32 = 1;
pub const FILE_PIPE_LISTENING_STATE: u32 = 2;
pub const FILE_PIPE_CONNECTED_STATE: u32 = 3;
pub const FILE_PIPE_CLOSING_STATE: u32 = 4;

/// NamedPipeEnd.
pub const FILE_PIPE_CLIENT_END: u32 = 0;
pub const FILE_PIPE_SERVER_END: u32 = 1;

/// The MaximumInstances of a pipe without limit (`PIPE_UNLIMITED_INSTANCES`
/// becomes -1 in kernel32's CreateNamedPipeW).
pub const FILE_PIPE_UNLIMITED_INSTANCES: u32 = 0xFFFF_FFFF;

/// CTL_CODE(FILE_DEVICE_NAMED_PIPE, function, method, access).
const fn pipe_control(function: u32, method: u32, access: u32) -> u32 {
    (FILE_DEVICE_NAMED_PIPE << 16) | (access << 14) | (function << 2) | method
}

const METHOD_BUFFERED: u32 = 0;
const METHOD_NEITHER: u32 = 3;
const FILE_ANY_ACCESS: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;

pub const FSCTL_PIPE_ASSIGN_EVENT: u32 = pipe_control(0, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const FSCTL_PIPE_DISCONNECT: u32 = pipe_control(1, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const FSCTL_PIPE_LISTEN: u32 = pipe_control(2, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const FSCTL_PIPE_PEEK: u32 = pipe_control(3, METHOD_BUFFERED, FILE_READ_ACCESS);
pub const FSCTL_PIPE_QUERY_EVENT: u32 = pipe_control(4, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const FSCTL_PIPE_TRANSCEIVE: u32 = pipe_control(5, METHOD_NEITHER, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const FSCTL_PIPE_WAIT: u32 = pipe_control(6, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const FSCTL_PIPE_IMPERSONATE: u32 = pipe_control(7, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// The pipe information classes (FILE_INFORMATION_CLASS).
pub const FILE_PIPE_INFORMATION: u32 = 23;
pub const FILE_PIPE_LOCAL_INFORMATION: u32 = 24;
pub const FILE_PIPE_REMOTE_INFORMATION: u32 = 25;

/// FILE_PIPE_INFORMATION: the read and completion modes of one end.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilePipeInformation {
    pub read_mode: u32,
    pub completion_mode: u32,
}

/// FILE_PIPE_LOCAL_INFORMATION: a pipe and its instance, seen from one end.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilePipeLocalInformation {
    pub named_pipe_type: u32,
    pub named_pipe_configuration: u32,
    pub maximum_instances: u32,
    pub current_instances: u32,
    pub inbound_quota: u32,
    pub read_data_available: u32,
    pub outbound_quota: u32,
    pub write_quota_available: u32,
    pub named_pipe_state: u32,
    pub named_pipe_end: u32,
}

/// The header of FILE_PIPE_PEEK_BUFFER (FSCTL_PIPE_PEEK); the data peeked
/// follows it (`Data[1]`, at [`PEEK_HEADER_SIZE`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilePipePeekHeader {
    pub named_pipe_state: u32,
    pub read_data_available: u32,
    pub number_of_messages: u32,
    pub message_length: u32,
}

/// FIELD_OFFSET(FILE_PIPE_PEEK_BUFFER, Data).
pub const PEEK_HEADER_SIZE: usize = size_of::<FilePipePeekHeader>();

/// FILE_PIPE_WAIT_FOR_BUFFER (FSCTL_PIPE_WAIT): `Timeout` (a LARGE_INTEGER,
/// relative when negative), `NameLength` in bytes, `TimeoutSpecified` (a
/// BOOLEAN), then the pipe's name without its `\` (`Name[1]`, at
/// [`WAIT_NAME_OFFSET`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilePipeWaitForBuffer {
    pub timeout: i64,
    pub name_length: u32,
    pub timeout_specified: u8,
    _padding: u8,
    pub name: [u16; 1],
}

/// FIELD_OFFSET(FILE_PIPE_WAIT_FOR_BUFFER, Name), which kernel32's
/// WaitNamedPipeW adds to the name's length.
pub const WAIT_NAME_OFFSET: usize = offset_of!(FilePipeWaitForBuffer, name);

/// The timeout of FILE_PIPE_WAIT_FOR_BUFFER that means "forever"
/// (`NMPWAIT_WAIT_FOREVER` in WaitNamedPipeW: the largest negative value).
pub const WAIT_FOREVER: i64 = i64::MIN;

const _: () = {
    assert!(size_of::<FilePipeInformation>() == 8);
    assert!(size_of::<FilePipeLocalInformation>() == 40);
    assert!(offset_of!(FilePipeLocalInformation, read_data_available) == 20);
    assert!(offset_of!(FilePipeLocalInformation, named_pipe_end) == 36);
    assert!(PEEK_HEADER_SIZE == 16);
    assert!(offset_of!(FilePipeWaitForBuffer, name_length) == 8);
    assert!(offset_of!(FilePipeWaitForBuffer, timeout_specified) == 12);
    assert!(WAIT_NAME_OFFSET == 14);
    assert!(size_of::<FilePipeWaitForBuffer>() == 16);
    assert!(FSCTL_PIPE_LISTEN == 0x0011_0008);
    assert!(FSCTL_PIPE_PEEK == 0x0011_400C);
    assert!(FSCTL_PIPE_TRANSCEIVE == 0x0011_C017);
    assert!(FSCTL_PIPE_WAIT == 0x0011_0018);
};

fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn get32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

impl FilePipeInformation {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        let mut out = [0; size_of::<Self>()];
        put32(&mut out, offset_of!(Self, read_mode), self.read_mode);
        put32(&mut out, offset_of!(Self, completion_mode), self.completion_mode);
        out
    }

    /// The structure that the caller gave.
    pub fn from_bytes(bytes: &[u8; size_of::<Self>()]) -> Self {
        Self {
            read_mode: get32(bytes, offset_of!(Self, read_mode)),
            completion_mode: get32(bytes, offset_of!(Self, completion_mode)),
        }
    }
}

impl FilePipeLocalInformation {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        let mut out = [0; size_of::<Self>()];
        let fields = [
            self.named_pipe_type,
            self.named_pipe_configuration,
            self.maximum_instances,
            self.current_instances,
            self.inbound_quota,
            self.read_data_available,
            self.outbound_quota,
            self.write_quota_available,
            self.named_pipe_state,
            self.named_pipe_end,
        ];
        for (index, value) in fields.into_iter().enumerate() {
            put32(&mut out, index * 4, value);
        }
        out
    }
}

impl FilePipePeekHeader {
    /// Its bytes, as they go to the caller.
    pub fn to_bytes(&self) -> [u8; PEEK_HEADER_SIZE] {
        let mut out = [0; PEEK_HEADER_SIZE];
        put32(&mut out, offset_of!(Self, named_pipe_state), self.named_pipe_state);
        put32(&mut out, offset_of!(Self, read_data_available), self.read_data_available);
        put32(&mut out, offset_of!(Self, number_of_messages), self.number_of_messages);
        put32(&mut out, offset_of!(Self, message_length), self.message_length);
        out
    }
}

/// FILE_PIPE_WAIT_FOR_BUFFER as the caller gave it: its timeout (`None`
/// without `TimeoutSpecified`) and where the pipe's name is in the buffer
/// (UTF-16, without its `\`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeWait {
    pub timeout: Option<i64>,
    pub name: core::ops::Range<usize>,
}

impl PipeWait {
    /// FILE_PIPE_WAIT_FOR_BUFFER in `bytes` (its whole input buffer), as
    /// NPFS reads it: `None` under its size (16 bytes, as NpWaitForNamedPipe
    /// checks), for a name past the buffer or of an odd length.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<FilePipeWaitForBuffer>() {
            return None;
        }
        let length = get32(bytes, offset_of!(FilePipeWaitForBuffer, name_length)) as usize;
        let end = WAIT_NAME_OFFSET.checked_add(length)?;
        if !length.is_multiple_of(2) || end > bytes.len() {
            return None;
        }
        let timeout = i64::from_le_bytes(bytes[..8].try_into().ok()?);
        let specified = bytes[offset_of!(FilePipeWaitForBuffer, timeout_specified)] != 0;
        Some(Self { timeout: specified.then_some(timeout), name: WAIT_NAME_OFFSET..end })
    }

    /// The UTF-16 units of the name, in `bytes` (the buffer it was parsed
    /// from).
    pub fn name_units<'a>(&self, bytes: &'a [u8]) -> impl Iterator<Item = u16> + 'a {
        bytes[self.name.clone()].chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn wait_buffer(timeout: Option<i64>, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut out = std::vec![0u8; WAIT_NAME_OFFSET + 2 * units.len().max(1)];
        out[..8].copy_from_slice(&timeout.unwrap_or(0).to_le_bytes());
        put32(&mut out, 8, 2 * units.len() as u32);
        out[12] = u8::from(timeout.is_some());
        for (i, unit) in units.iter().enumerate() {
            out[WAIT_NAME_OFFSET + 2 * i..WAIT_NAME_OFFSET + 2 * i + 2].copy_from_slice(&unit.to_le_bytes());
        }
        out
    }

    #[test]
    fn a_wait_buffer_gives_its_timeout_and_name() {
        let bytes = wait_buffer(Some(-500_000), "winreg");
        let wait = PipeWait::parse(&bytes).expect("a wait buffer");
        assert_eq!(wait.timeout, Some(-500_000));
        assert_eq!(String::from_utf16(&wait.name_units(&bytes).collect::<Vec<_>>()).unwrap(), "winreg");
        let wait = PipeWait::parse(&wait_buffer(None, "x")).expect("a wait buffer");
        assert_eq!(wait.timeout, None);
    }

    #[test]
    fn a_wait_buffer_is_refused_short_or_with_its_name_past_its_end() {
        let bytes = wait_buffer(None, "winreg");
        assert!(PipeWait::parse(&bytes[..15]).is_none(), "under 16 bytes");
        assert!(PipeWait::parse(&bytes[..bytes.len() - 2]).is_none(), "the name past the buffer");
        let mut odd = bytes;
        put32(&mut odd, 8, 3);
        assert!(PipeWait::parse(&odd).is_none(), "an odd length");
    }

    #[test]
    fn pipe_information_round_trips() {
        let information = FilePipeInformation { read_mode: 1, completion_mode: 0 };
        assert_eq!(FilePipeInformation::from_bytes(&information.to_bytes()), information);
        let local = FilePipeLocalInformation { named_pipe_end: FILE_PIPE_SERVER_END, ..Default::default() };
        assert_eq!(local.to_bytes()[36], 1);
    }

    use std::string::String;
}
