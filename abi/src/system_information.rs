//! What `NtQuerySystemInformation` returns to an i386 process (CLAUDE.md,
//! rule 5), laid out as on XP SP2. ReactOS's NDK headers (`exfuncs.h`,
//! `extypes.h`) serve as the specification of the formats; offsets are
//! checked at compile time.

use core::mem::{offset_of, size_of};

/// SystemBasicInformation: the page size, the physical pages, the user-mode
/// address range and the processors.
pub const SYSTEM_BASIC_INFORMATION: u32 = 0;

/// SystemProcessorInformation: the architecture, level, revision and
/// feature bits of the processors.
pub const SYSTEM_PROCESSOR_INFORMATION: u32 = 1;

/// PROCESSOR_ARCHITECTURE_INTEL: x86.
pub const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;

/// The feature bits of XP SP2 (`KeFeatureBits`, `KF_*`), which
/// SystemProcessorInformation returns; the later ones are left out.
pub const KF_V86_VIS: u32 = 0x0000_0001;
pub const KF_RDTSC: u32 = 0x0000_0002;
pub const KF_CR4: u32 = 0x0000_0004;
pub const KF_CMOV: u32 = 0x0000_0008;
pub const KF_GLOBAL_PAGE: u32 = 0x0000_0010;
pub const KF_LARGE_PAGE: u32 = 0x0000_0020;
pub const KF_MTRR: u32 = 0x0000_0040;
pub const KF_CMPXCHG8B: u32 = 0x0000_0080;
pub const KF_MMX: u32 = 0x0000_0100;
pub const KF_WORKING_PTE: u32 = 0x0000_0200;
pub const KF_PAT: u32 = 0x0000_0400;
pub const KF_FXSR: u32 = 0x0000_0800;
pub const KF_FAST_SYSCALL: u32 = 0x0000_1000;
pub const KF_XMMI: u32 = 0x0000_2000;
pub const KF_3DNOW: u32 = 0x0000_4000;
pub const KF_XMMI64: u32 = 0x0001_0000;
pub const KF_DTS: u32 = 0x0002_0000;
pub const KF_NX_BIT: u32 = 0x2000_0000;
pub const KF_NX_DISABLED: u32 = 0x4000_0000;
pub const KF_NX_ENABLED: u32 = 0x8000_0000;

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

/// SYSTEM_PROCESSOR_INFORMATION of XP.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemProcessorInformation32 {
    /// `PROCESSOR_ARCHITECTURE_*`.
    pub processor_architecture: u16,
    /// The family (KeProcessorLevel).
    pub processor_level: u16,
    /// The model, then the stepping (KeProcessorRevision).
    pub processor_revision: u16,
    pub reserved: u16,
    /// `KF_*` (KeFeatureBits).
    pub processor_feature_bits: u32,
}

const _: () = {
    assert!(size_of::<SystemProcessorInformation32>() == 12);
    assert!(offset_of!(SystemProcessorInformation32, processor_level) == 2);
    assert!(offset_of!(SystemProcessorInformation32, processor_revision) == 4);
    assert!(offset_of!(SystemProcessorInformation32, processor_feature_bits) == 8);
};

impl SystemProcessorInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: integer fields without padding (offsets checked above):
        // every byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
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
