//! What `NtQueryVirtualMemory` returns to an i386 process (CLAUDE.md,
//! rule 5), laid out as on XP SP2. ReactOS's NDK headers (`mmtypes.h`) serve
//! as the specification of the format; offsets are checked at compile time.

use core::mem::{offset_of, size_of};

/// MemoryBasicInformation: the range of pages of the same state and
/// protection that starts at an address.
pub const MEMORY_BASIC_INFORMATION: u32 = 0;

/// MEMORY_BASIC_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryBasicInformation32 {
    /// The page the range starts at.
    pub base_address: u32,
    /// The start of its reservation; 0 for a free range.
    pub allocation_base: u32,
    /// The protection the reservation was made with (`PAGE_*`).
    pub allocation_protect: u32,
    pub region_size: u32,
    /// `MEM_COMMIT`, `MEM_RESERVE` or `MEM_FREE`.
    pub state: u32,
    /// The protection of its pages, if committed (`PAGE_*`).
    pub protect: u32,
    /// `MEM_PRIVATE`, `MEM_MAPPED` or `MEM_IMAGE`; 0 for a free range.
    pub kind: u32,
}

const _: () = {
    assert!(size_of::<MemoryBasicInformation32>() == 0x1C);
    assert!(offset_of!(MemoryBasicInformation32, allocation_protect) == 0x08);
    assert!(offset_of!(MemoryBasicInformation32, region_size) == 0x0C);
    assert!(offset_of!(MemoryBasicInformation32, state) == 0x10);
    assert!(offset_of!(MemoryBasicInformation32, protect) == 0x14);
    assert!(offset_of!(MemoryBasicInformation32, kind) == 0x18);
};

impl MemoryBasicInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: seven u32 fields, no padding (size checked above): every
        // byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}
