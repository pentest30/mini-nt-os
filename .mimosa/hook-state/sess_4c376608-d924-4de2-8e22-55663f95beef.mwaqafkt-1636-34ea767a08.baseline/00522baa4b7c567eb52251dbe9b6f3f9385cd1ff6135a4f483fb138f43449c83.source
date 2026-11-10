//! `KUSER_SHARED_DATA` as XP SP2 lays it out for i386 processes (0x338
//! bytes): the page the kernel shares read-only with every process, at
//! [`KUSER_SHARED_DATA_VA`] (02 §4.1). ntdll reads the time, the version and
//! the system call stub (`SystemCall`) from it.
//!
//! Layout: ReactOS 0.4.16, `sdk/include/xdk/ketypes.h` (`KUSER_SHARED_DATA`),
//! cut down to the fields of XP SP2.

use core::mem::{offset_of, size_of};

use crate::peb32::{OS_MAJOR_VERSION, OS_MINOR_VERSION};

/// Where every process sees it.
pub const KUSER_SHARED_DATA_VA: u32 = 0x7FFE_0000;

/// `NtProductType`: a workstation (`NtProductWinNt`).
pub const NT_PRODUCT_WIN_NT: u32 = 1;
/// `SuiteMask` of XP Professional: `VER_SUITE_SINGLEUSERTS`.
pub const VER_SUITE_SINGLEUSERTS: u32 = 0x0100;
/// `ImageNumberLow` and `ImageNumberHigh`: `IMAGE_FILE_MACHINE_I386`.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
/// The system root that XP shows.
pub const NT_SYSTEM_ROOT: &str = "C:\\WINDOWS";
/// `TestRetInstruction`: a `ret`.
pub const TEST_RET_INSTRUCTION: u64 = 0xC3;

/// `NXSupportPolicy` (ADR-020).
pub const NX_SUPPORT_POLICY_ALWAYSOFF: u8 = 0;
pub const NX_SUPPORT_POLICY_ALWAYSON: u8 = 1;
pub const NX_SUPPORT_POLICY_OPTIN: u8 = 2;
pub const NX_SUPPORT_POLICY_OPTOUT: u8 = 3;

/// Indices of `ProcessorFeatures` (`PF_*`).
pub const PF_COMPARE_EXCHANGE_DOUBLE: usize = 2;
pub const PF_MMX_INSTRUCTIONS_AVAILABLE: usize = 3;
pub const PF_XMMI_INSTRUCTIONS_AVAILABLE: usize = 6;
pub const PF_3DNOW_INSTRUCTIONS_AVAILABLE: usize = 7;
pub const PF_RDTSC_INSTRUCTION_AVAILABLE: usize = 8;
pub const PF_PAE_ENABLED: usize = 9;
pub const PF_XMMI64_INSTRUCTIONS_AVAILABLE: usize = 10;
pub const PF_NX_ENABLED: usize = 12;
pub const PF_SSE3_INSTRUCTIONS_AVAILABLE: usize = 13;

/// `KSYSTEM_TIME`: a 64-bit time that user mode reads without a lock. The
/// kernel writes `high2_time`, then `low_part`, then `high1_time`; a reader
/// retries until `high1_time` equals `high2_time`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KSystemTime {
    pub low_part: u32,
    pub high1_time: i32,
    pub high2_time: i32,
}

/// `KUSER_SHARED_DATA` (XP SP2, i386).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KUserSharedData {
    pub tick_count_low_deprecated: u32,
    /// `GetTickCount() = (TickCountQuad * TickCountMultiplier) >> 24`.
    pub tick_count_multiplier: u32,
    pub interrupt_time: KSystemTime,
    pub system_time: KSystemTime,
    pub time_zone_bias: KSystemTime,
    pub image_number_low: u16,
    pub image_number_high: u16,
    pub nt_system_root: [u16; 260],
    pub max_stack_trace_depth: u32,
    pub crypto_exponent: u32,
    pub time_zone_id: u32,
    pub reserved2: [u32; 8],
    pub nt_product_type: u32,
    pub product_type_is_valid: u8,
    pub _padding0: [u8; 3],
    pub nt_major_version: u32,
    pub nt_minor_version: u32,
    pub processor_features: [u8; 64],
    pub reserved1: u32,
    pub reserved3: u32,
    pub time_slip: u32,
    pub alternative_architecture: u32,
    pub _padding1: u32,
    pub system_expiration_date: u64,
    pub suite_mask: u32,
    pub kd_debugger_enabled: u8,
    pub nx_support_policy: u8,
    pub _padding2: [u8; 2],
    pub active_console_id: u32,
    pub dismount_count: u32,
    pub com_plus_package: u32,
    pub last_system_rit_event_tick_count: u32,
    pub number_of_physical_pages: u32,
    pub safe_boot_mode: u8,
    pub _padding3: [u8; 3],
    pub trace_logging: u32,
    pub _padding4: u32,
    pub test_ret_instruction: u64,
    /// The system call stub that ntdll's stubs call through
    /// (`ntdll!KiFastSystemCall` or `ntdll!KiIntSystemCall`, ADR-004).
    pub system_call: u32,
    /// Where SYSENTER returns: `ntdll!KiFastSystemCallRet`.
    pub system_call_return: u32,
    pub system_call_pad: [u64; 3],
    /// A union with `TickCountQuad` (its first 8 bytes), 16 bytes long.
    pub tick_count: KSystemTime,
    pub _padding5: u32,
    pub cookie: u32,
    pub _padding6: u32,
}

const _: () = {
    assert!(size_of::<KSystemTime>() == 12);
    assert!(offset_of!(KUserSharedData, tick_count_multiplier) == 0x004);
    assert!(offset_of!(KUserSharedData, interrupt_time) == 0x008);
    assert!(offset_of!(KUserSharedData, system_time) == 0x014);
    assert!(offset_of!(KUserSharedData, time_zone_bias) == 0x020);
    assert!(offset_of!(KUserSharedData, image_number_low) == 0x02C);
    assert!(offset_of!(KUserSharedData, nt_system_root) == 0x030);
    assert!(offset_of!(KUserSharedData, max_stack_trace_depth) == 0x238);
    assert!(offset_of!(KUserSharedData, time_zone_id) == 0x240);
    assert!(offset_of!(KUserSharedData, nt_product_type) == 0x264);
    assert!(offset_of!(KUserSharedData, product_type_is_valid) == 0x268);
    assert!(offset_of!(KUserSharedData, nt_major_version) == 0x26C);
    assert!(offset_of!(KUserSharedData, nt_minor_version) == 0x270);
    assert!(offset_of!(KUserSharedData, processor_features) == 0x274);
    assert!(offset_of!(KUserSharedData, alternative_architecture) == 0x2C0);
    assert!(offset_of!(KUserSharedData, system_expiration_date) == 0x2C8);
    assert!(offset_of!(KUserSharedData, suite_mask) == 0x2D0);
    assert!(offset_of!(KUserSharedData, kd_debugger_enabled) == 0x2D4);
    assert!(offset_of!(KUserSharedData, nx_support_policy) == 0x2D5);
    assert!(offset_of!(KUserSharedData, active_console_id) == 0x2D8);
    assert!(offset_of!(KUserSharedData, number_of_physical_pages) == 0x2E8);
    assert!(offset_of!(KUserSharedData, safe_boot_mode) == 0x2EC);
    assert!(offset_of!(KUserSharedData, trace_logging) == 0x2F0);
    assert!(offset_of!(KUserSharedData, test_ret_instruction) == 0x2F8);
    assert!(offset_of!(KUserSharedData, system_call) == 0x300);
    assert!(offset_of!(KUserSharedData, system_call_return) == 0x304);
    assert!(offset_of!(KUserSharedData, system_call_pad) == 0x308);
    assert!(offset_of!(KUserSharedData, tick_count) == 0x320);
    assert!(offset_of!(KUserSharedData, cookie) == 0x330);
    assert!(size_of::<KUserSharedData>() == 0x338);
};

impl KUserSharedData {
    /// What XP SP2 shows before the clock, the processor and ntdll fill the
    /// rest: the version (ADR-003), a workstation, the i386 image number, the
    /// system root, a tick count in milliseconds and the `ret` that
    /// `TestRetInstruction` holds.
    pub fn xp() -> Self {
        // SAFETY: integers and arrays of integers, valid all-zero.
        let mut data: Self = unsafe { core::mem::zeroed() };
        data.tick_count_multiplier = 1 << 24;
        data.image_number_low = IMAGE_FILE_MACHINE_I386;
        data.image_number_high = IMAGE_FILE_MACHINE_I386;
        for (unit, c) in data.nt_system_root.iter_mut().zip(NT_SYSTEM_ROOT.encode_utf16()) {
            *unit = c;
        }
        data.nt_product_type = NT_PRODUCT_WIN_NT;
        data.product_type_is_valid = 1;
        data.nt_major_version = OS_MAJOR_VERSION;
        data.nt_minor_version = OS_MINOR_VERSION;
        data.suite_mask = VER_SUITE_SINGLEUSERTS;
        data.test_ret_instruction = TEST_RET_INSTRUCTION;
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xp_shows_version_5_1_and_its_system_root() {
        let data = KUserSharedData::xp();
        assert_eq!((data.nt_major_version, data.nt_minor_version), (5, 1));
        assert_eq!((data.nt_product_type, data.product_type_is_valid), (1, 1));
        let root: [u16; 11] = core::array::from_fn(|i| data.nt_system_root[i]);
        assert_eq!(root, [0x43, 0x3A, 0x5C, 0x57, 0x49, 0x4E, 0x44, 0x4F, 0x57, 0x53, 0], "C:\\WINDOWS, terminated");
        assert_eq!((data.tick_count_multiplier, data.test_ret_instruction), (0x0100_0000, 0xC3));
        assert_eq!(data.system_call, 0, "set once ntdll is mapped");
    }
}
