//! IRP — I/O Request Packet.
//!
//! Every I/O operation in NT is represented as an IRP sent down a
//! driver stack. Drivers complete the IRP or forward it downward.
//!
//! XP-era games trigger IRPs via:
//!   ReadFile / WriteFile  → IRP_MJ_READ / IRP_MJ_WRITE
//!   DeviceIoControl       → IRP_MJ_DEVICE_CONTROL
//!   CreateFile            → IRP_MJ_CREATE

use alloc::boxed::Box;
use ke::event::{KEvent, EventType};

/// IRP major function codes (IRP_MJ_*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IrpMajor {
    Create          = 0x00,
    Close           = 0x02,
    Read            = 0x03,
    Write           = 0x04,
    QueryInformation = 0x05,
    SetInformation  = 0x06,
    DeviceControl   = 0x0E,
    Cleanup         = 0x12,
}

/// I/O status block — filled by the driver on completion.
#[derive(Default, Clone, Copy)]
pub struct IoStatusBlock {
    pub status:      i32,   // NTSTATUS
    pub information: usize, // bytes transferred / other info
}

/// I/O Request Packet.
pub struct Irp {
    pub major:      IrpMajor,
    pub status:     IoStatusBlock,
    /// Optional event to signal on completion (overlapped I/O).
    pub event:      Option<KEvent>,
    /// Buffer for read/write operations.
    pub buffer:     Option<Box<[u8]>>,
    pub buffer_len: usize,
    pub offset:     u64,
}

impl Irp {
    pub fn new(major: IrpMajor) -> Self {
        Self {
            major,
            status:     IoStatusBlock::default(),
            event:      None,
            buffer:     None,
            buffer_len: 0,
            offset:     0,
        }
    }

    /// Complete the IRP with a status code.
    pub fn complete(&mut self, status: i32, information: usize) {
        self.status.status      = status;
        self.status.information = information;
        // Signal the completion event if present (overlapped I/O).
        if let Some(ref ev) = self.event {
            ev.set();
        }
    }
}
