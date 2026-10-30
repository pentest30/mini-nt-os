//! The x86 `CONTEXT` of an i386 thread, as XP exchanges it with user mode
//! (exceptions, `NtGetContextThread`, `NtSetContextThread`, `NtContinue`).
//! The kernel's trap frame (`hal::trap::KTrapFrame`) converts to and from it
//! (`ke::context`).

use core::mem::{offset_of, size_of};

/// `CONTEXT_i386`: the architecture bit of the flags.
pub const CONTEXT_I386: u32 = 0x0001_0000;
/// SegSs, Esp, SegCs, Eip, EFlags, Ebp.
pub const CONTEXT_CONTROL: u32 = CONTEXT_I386 | 0x01;
/// Eax, Ebx, Ecx, Edx, Esi, Edi.
pub const CONTEXT_INTEGER: u32 = CONTEXT_I386 | 0x02;
/// SegDs, SegEs, SegFs, SegGs.
pub const CONTEXT_SEGMENTS: u32 = CONTEXT_I386 | 0x04;
/// The x87 state (`FloatSave`).
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_I386 | 0x08;
/// Dr0–3, Dr6, Dr7.
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_I386 | 0x10;
/// The FXSAVE area (`ExtendedRegisters`).
pub const CONTEXT_EXTENDED_REGISTERS: u32 = CONTEXT_I386 | 0x20;
/// Control, integer and segment registers.
pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

/// `FLOATING_SAVE_AREA`: the x87 state as FSAVE stores it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloatingSaveArea {
    pub control_word: u32,
    pub status_word: u32,
    pub tag_word: u32,
    pub error_offset: u32,
    pub error_selector: u32,
    pub data_offset: u32,
    pub data_selector: u32,
    pub register_area: [u8; 80],
    pub cr0_npx_state: u32,
}

/// `CONTEXT` (x86).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context32 {
    pub context_flags: u32,
    pub dr0: u32,
    pub dr1: u32,
    pub dr2: u32,
    pub dr3: u32,
    pub dr6: u32,
    pub dr7: u32,
    pub float_save: FloatingSaveArea,
    pub seg_gs: u32,
    pub seg_fs: u32,
    pub seg_es: u32,
    pub seg_ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub ebp: u32,
    pub eip: u32,
    pub seg_cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub seg_ss: u32,
    pub extended_registers: [u8; 512],
}

const _: () = {
    assert!(size_of::<FloatingSaveArea>() == 112);
    assert!(offset_of!(FloatingSaveArea, register_area) == 0x1C);
    assert!(offset_of!(FloatingSaveArea, cr0_npx_state) == 0x6C);
    assert!(offset_of!(Context32, dr0) == 0x04);
    assert!(offset_of!(Context32, dr7) == 0x18);
    assert!(offset_of!(Context32, float_save) == 0x1C);
    assert!(offset_of!(Context32, seg_gs) == 0x8C);
    assert!(offset_of!(Context32, seg_ds) == 0x98);
    assert!(offset_of!(Context32, edi) == 0x9C);
    assert!(offset_of!(Context32, eax) == 0xB0);
    assert!(offset_of!(Context32, ebp) == 0xB4);
    assert!(offset_of!(Context32, eip) == 0xB8);
    assert!(offset_of!(Context32, seg_cs) == 0xBC);
    assert!(offset_of!(Context32, eflags) == 0xC0);
    assert!(offset_of!(Context32, esp) == 0xC4);
    assert!(offset_of!(Context32, seg_ss) == 0xC8);
    assert!(offset_of!(Context32, extended_registers) == 0xCC);
    assert!(size_of::<Context32>() == 0x2CC);
};

impl Context32 {
    /// A context with every field zero.
    pub fn zeroed() -> Self {
        // SAFETY: every field is an integer or an array of integers, for
        // which all-zero bytes are a valid value.
        unsafe { core::mem::zeroed() }
    }
}
