//! LPC as XP's i386 user mode sees it (02 §5.9): the header of every port
//! message, the message types, the size limit. ReactOS's NDK headers
//! (`lpctypes.h`) serve as the specification of the format; offsets are
//! checked at compile time.

use core::mem::{offset_of, size_of};

use crate::teb32::ClientId32;

/// A message is at most this long, its header included (PORT_MAXIMUM_MESSAGE_LENGTH, i386).
pub const PORT_MAXIMUM_MESSAGE_LENGTH: u32 = 0x148;

/// The types of messages (`PORT_MESSAGE.u2.s2.Type`).
pub const LPC_REQUEST: u16 = 1;
pub const LPC_REPLY: u16 = 2;
pub const LPC_DATAGRAM: u16 = 3;
pub const LPC_LOST_REPLY: u16 = 4;
pub const LPC_PORT_CLOSED: u16 = 5;
pub const LPC_CLIENT_DIED: u16 = 6;
pub const LPC_EXCEPTION: u16 = 7;
pub const LPC_DEBUG_EVENT: u16 = 8;
pub const LPC_ERROR_EVENT: u16 = 9;
pub const LPC_CONNECTION_REQUEST: u16 = 10;
/// Set in the type of a message the kernel sends.
pub const LPC_KERNELMODE_MESSAGE: u16 = 0x8000;

/// PORT_MESSAGE: the header before the data of every message.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortMessage32 {
    /// The length of the data after the header.
    pub data_length: u16,
    /// The length of the whole message, header included.
    pub total_length: u16,
    /// `LPC_*`.
    pub kind: u16,
    pub data_info_offset: u16,
    /// Who sent it.
    pub client_id: ClientId32,
    pub message_id: u32,
    /// `ClientViewSize` of a connection request, `CallbackId` otherwise.
    pub client_view_size: u32,
}

const _: () = {
    assert!(size_of::<PortMessage32>() == 0x18);
    assert!(offset_of!(PortMessage32, total_length) == 0x02);
    assert!(offset_of!(PortMessage32, kind) == 0x04);
    assert!(offset_of!(PortMessage32, client_id) == 0x08);
    assert!(offset_of!(PortMessage32, message_id) == 0x10);
    assert!(offset_of!(PortMessage32, client_view_size) == 0x14);
};

impl PortMessage32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: integers back to back, no padding (offsets and size checked
        // above): every byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}
