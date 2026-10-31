//! What `NtQuerySystemInformation` returns to an i386 process (CLAUDE.md,
//! rule 5), laid out as on XP SP2. ReactOS's NDK headers (`exfuncs.h`,
//! `extypes.h`) serve as the specification of the formats; offsets are
//! checked at compile time.

use core::mem::{offset_of, size_of};

/// SystemBasicInformation: the page size, the physical pages, the user-mode
/// address range and the processors.
pub const SYSTEM_BASIC_INFORMATION: u32 = 0;

/// MM_LOWEST_USER_ADDRESS: the first 64 KiB are never mapped.
pub const MINIMUM_USER_MODE_ADDRESS: u32 = 0x0001_0000;
/// MM_HIGHEST_USER_ADDRESS of XP x86 (2 GiB of user space, the last 64 KiB
/// left out).
pub const MAXIMUM_USER_MODE_ADDRESS: u32 = 0x7FFE_FFFF;

/// SYSTEM_BASIC_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemBasicInformation32 {
    pub reserved: u32,
    /// The longest clock interval, in 100 ns units (KeMaximumIncrement).
    pub timer_resolution: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: u32,
    pub maximum_user_mode_address: u32,
    pub active_processors_affinity_mask: u32,
    pub number_of_processors: u8,
    _pad: [u8; 3],
}

const _: () = {
    assert!(size_of::<SystemBasicInformation32>() == 0x2C);
    assert!(offset_of!(SystemBasicInformation32, timer_resolution) == 0x04);
    assert!(offset_of!(SystemBasicInformation32, page_size) == 0x08);
    assert!(offset_of!(SystemBasicInformation32, number_of_physical_pages) == 0x0C);
    assert!(offset_of!(SystemBasicInformation32, allocation_granularity) == 0x18);
    assert!(offset_of!(SystemBasicInformation32, minimum_user_mode_address) == 0x1C);
    assert!(offset_of!(SystemBasicInformation32, maximum_user_mode_address) == 0x20);
    assert!(offset_of!(SystemBasicInformation32, active_processors_affinity_mask) == 0x24);
    assert!(offset_of!(SystemBasicInformation32, number_of_processors) == 0x28);
};

impl SystemBasicInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: integer fields and explicit padding (size checked above):
        // every byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}
