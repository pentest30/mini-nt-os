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

/// SystemTimeOfDayInformation: the boot time, the current time and the time
/// zone ([`SystemTimeOfDayInformation32`]).
pub const SYSTEM_TIME_OF_DAY_INFORMATION: u32 = 3;

/// SystemFlagsInformation: the system's global flags (NtGlobalFlag,
/// `FLG_*`), a ULONG.
pub const SYSTEM_FLAGS_INFORMATION: u32 = 9;

/// SystemRangeStartInformation: where the system half of the address space
/// starts (MmSystemRangeStart), a ULONG_PTR.
pub const SYSTEM_RANGE_START_INFORMATION: u32 = 50;

/// SystemFirmwareTableInformation: the ACPI, SMBIOS and firmware tables that
/// kernel32's EnumSystemFirmwareTables and GetSystemFirmwareTable read.
pub const SYSTEM_FIRMWARE_TABLE_INFORMATION: u32 = 76;

/// SystemPerformanceInformation: the CPU, memory and IO counters, the ones
/// taskmgr's header and graphs read ([`SystemPerformanceInformation32`]).
pub const SYSTEM_PERFORMANCE_INFORMATION: u32 = 2;

/// SystemProcessInformation: every process and its threads, what a task
/// manager lists ([`SystemProcessInformation32`]).
pub const SYSTEM_PROCESS_INFORMATION: u32 = 5;

/// SystemProcessorPerformanceInformation: the kernel, user, idle, DPC and
/// interrupt times of each processor.
pub const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION: u32 = 8;

/// SystemHandleInformation: the number of open handles.
pub const SYSTEM_HANDLE_INFORMATION: u32 = 16;

/// SystemFileCacheInformation: the file cache's working sizes.
pub const SYSTEM_FILECACHE_INFORMATION: u32 = 21;

/// MmSystemRangeStart as an i386 process sees it: 2 GiB.
pub const SYSTEM_RANGE_START: u32 = 0x8000_0000;

/// SystemExtendServiceTableInformation (NtSetSystemInformation): load
/// win32k, whose UNICODE_STRING name it is given.
pub const SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION: u32 = 38;

/// SystemSessionCreate (NtSetSystemInformation): a new session, the caller
/// in it; its ID goes back in the buffer.
pub const SYSTEM_SESSION_CREATE: u32 = 47;

/// SystemSessionDetach (NtSetSystemInformation): the caller leaves the
/// session it created.
pub const SYSTEM_SESSION_DETACH: u32 = 48;

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

/// SYSTEM_TIMEOFDAY_INFORMATION: times in 100 ns since 1601 (UTC), the time
/// zone's bias from UTC in 100 ns, and its identifier.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemTimeOfDayInformation32 {
    pub boot_time: i64,
    pub current_time: i64,
    pub time_zone_bias: i64,
    pub time_zone_id: u32,
    pub reserved: u32,
    pub boot_time_bias: u64,
    pub sleep_time_bias: u64,
}

const _: () = {
    assert!(size_of::<SystemTimeOfDayInformation32>() == 0x30);
    assert!(offset_of!(SystemTimeOfDayInformation32, current_time) == 0x08);
    assert!(offset_of!(SystemTimeOfDayInformation32, time_zone_bias) == 0x10);
    assert!(offset_of!(SystemTimeOfDayInformation32, time_zone_id) == 0x18);
    assert!(offset_of!(SystemTimeOfDayInformation32, boot_time_bias) == 0x20);
    assert!(offset_of!(SystemTimeOfDayInformation32, sleep_time_bias) == 0x28);
};

impl SystemTimeOfDayInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: integer fields without padding (size checked above): every
        // byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

/// SYSTEM_THREAD_INFORMATION of XP i386 (packed to 4): a thread of a
/// [`SystemProcessInformation32`] entry, 0x40 bytes, the large integers at
/// offsets the packing keeps to 4.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemThreadInformation32 {
    /// The kernel time the thread consumed, in 100 ns (0: not counted yet).
    pub kernel_time: u64,
    pub user_time: u64,
    /// Its creation time, in 100 ns since 1601 (0: not tracked yet).
    pub create_time: u64,
    /// How long it has waited, in ticks.
    pub wait_time: u32,
    /// Where its execution started (user or kernel, as it is).
    pub start_address: u32,
    /// CLIENT_ID: the process's id, then the thread's.
    pub client_id_process: u32,
    pub client_id_thread: u32,
    /// Its current priority.
    pub priority: i32,
    /// Its process's base priority.
    pub base_priority: i32,
    pub context_switches: u32,
    /// Its scheduler state (`THREAD_STATE_*`).
    pub thread_state: u32,
    /// Why it waits (`KWAIT_REASON`).
    pub wait_reason: u32,
    pub pad: u32,
}

const _: () = {
    assert!(size_of::<SystemThreadInformation32>() == 0x40);
    assert!(offset_of!(SystemThreadInformation32, create_time) == 0x10);
    assert!(offset_of!(SystemThreadInformation32, client_id_process) == 0x20);
    assert!(offset_of!(SystemThreadInformation32, thread_state) == 0x34);
};

impl SystemThreadInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: integer fields without padding (size checked above): every
        // byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

/// The header of a `SystemProcessInformation` entry of XP i386 (packed to 4):
/// 0xB8 bytes, then its [`SystemThreadInformation32`] threads, then its
/// image name, UTF-16, that [`image_name_buffer`]
/// points at, inside the caller's own buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemProcessInformation32 {
    /// The bytes to the next entry; 0 for the last one.
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: u64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    /// Its creation time, in 100 ns since 1601 (0: not tracked yet).
    pub create_time: u64,
    pub user_time: u64,
    pub kernel_time: u64,
    /// The image name's length, in bytes, without a terminator.
    pub image_name_length: u16,
    pub image_name_maximum_length: u16,
    /// Where the name's units sit, inside the caller's buffer.
    pub image_name_buffer: u32,
    pub base_priority: i32,
    /// UniqueProcessId.
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
    pub handle_count: u32,
    pub session_id: u32,
    /// CR3 of its address space.
    pub page_directory_base: u32,
    pub peak_virtual_size: u32,
    pub virtual_size: u32,
    pub page_fault_count: u32,
    pub peak_working_set_size: u32,
    pub working_set_size: u32,
    pub quota_peak_paged_pool_usage: u32,
    pub quota_paged_pool_usage: u32,
    pub quota_peak_non_paged_pool_usage: u32,
    pub quota_non_paged_pool_usage: u32,
    pub pagefile_usage: u32,
    pub peak_pagefile_usage: u32,
    pub private_page_count: u32,
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

/// Where an entry's image name sits, from the entry's start: after its
/// threads.
pub const SYSTEM_PROCESS_INFORMATION_NAME_AT: u32 = 0xB8;
/// The size of an entry's threads, each.
pub const SYSTEM_THREAD_INFORMATION_SIZE: u32 = 0x40;

const _: () = {
    assert!(size_of::<SystemProcessInformation32>() == 0xB8);
    assert!(offset_of!(SystemProcessInformation32, working_set_private_size) == 0x08);
    assert!(offset_of!(SystemProcessInformation32, cycle_time) == 0x18);
    assert!(offset_of!(SystemProcessInformation32, image_name_length) == 0x38);
    assert!(offset_of!(SystemProcessInformation32, image_name_buffer) == 0x3C);
    assert!(offset_of!(SystemProcessInformation32, unique_process_id) == 0x44);
    assert!(offset_of!(SystemProcessInformation32, page_directory_base) == 0x54);
    assert!(offset_of!(SystemProcessInformation32, read_operation_count) == 0x88);
    assert!(offset_of!(SystemProcessInformation32, other_transfer_count) == 0xB0);
};

impl SystemProcessInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: integer fields without padding (size checked above): every
        // byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}
