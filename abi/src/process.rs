//! Process values shared with user mode.
//!
//! - The pseudo-handles of the current process and thread.
//! - `MEM_EXECUTE_OPTION_*`: a process's execute options (DEP, ADR-020), as
//!   `NtQueryInformationProcess` and `NtSetInformationProcess` exchange them
//!   (`ProcessExecuteFlags`, M3).
//! - The classes of those two services this kernel knows, and what they
//!   exchange (PROCESS_BASIC_INFORMATION) ; NtCreateProcessEx's flags ;
//!   INITIAL_TEB, the stack NtCreateThread is given (M5). ReactOS's NDK
//!   headers (`pstypes.h`) serve as the specification of the formats;
//!   offsets are checked at compile time.

use core::mem::{offset_of, size_of};

/// `NtCurrentProcess()`: the calling process, without a handle.
pub const NT_CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
/// `NtCurrentThread()`: the calling thread, without a handle.
pub const NT_CURRENT_THREAD: u32 = 0xFFFF_FFFE;

/// DEP is on: pages without an execute protection do not execute.
pub const MEM_EXECUTE_OPTION_DISABLE: u32 = 0x01;
/// DEP is off: every readable page executes.
pub const MEM_EXECUTE_OPTION_ENABLE: u32 = 0x02;
/// Under DEP, the ATL thunks of old programs are not emulated.
pub const MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION: u32 = 0x04;
/// The options can no longer change.
pub const MEM_EXECUTE_OPTION_PERMANENT: u32 = 0x08;
/// The flags this kernel accepts.
pub const MEM_EXECUTE_OPTION_VALID_FLAGS: u32 = 0x0F;

/// ProcessBasicInformation (NtQueryInformationProcess).
pub const PROCESS_BASIC_INFORMATION: u32 = 0;
/// ProcessSessionInformation: the process's session.
pub const PROCESS_SESSION_INFORMATION: u32 = 24;

/// NtCreateProcessEx: the new process inherits the inheritable handles of
/// its parent (NtCreateProcess's InheritObjectTable).
pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x04;
/// The flags NtCreateProcessEx knows: breakaway from a job, no debug
/// inheritance, inherited handles, an address space given by the caller.
pub const PROCESS_CREATE_FLAGS_LEGAL_MASK: u32 = 0x0F;

/// PROCESS_BASIC_INFORMATION.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessBasicInformation32 {
    /// `STATUS_PENDING` while it lives.
    pub exit_status: u32,
    pub peb_base_address: u32,
    pub affinity_mask: u32,
    /// KPRIORITY.
    pub base_priority: i32,
    pub unique_process_id: u32,
    pub inherited_from_unique_process_id: u32,
}

const _: () = {
    assert!(size_of::<ProcessBasicInformation32>() == 0x18);
    assert!(offset_of!(ProcessBasicInformation32, peb_base_address) == 0x04);
    assert!(offset_of!(ProcessBasicInformation32, base_priority) == 0x0C);
    assert!(offset_of!(ProcessBasicInformation32, unique_process_id) == 0x10);
    assert!(offset_of!(ProcessBasicInformation32, inherited_from_unique_process_id) == 0x14);
};

impl ProcessBasicInformation32 {
    /// Its bytes, as they go to the caller.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: six 32-bit fields, no padding (size checked above): every
        // byte is initialised.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
    }
}

/// INITIAL_TEB: the user stack a new thread is given (RtlCreateUserThread).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InitialTeb32 {
    /// The stack of a fixed-size thread (OS/2); null otherwise.
    pub old_stack_base: u32,
    pub old_stack_limit: u32,
    /// Its top.
    pub stack_base: u32,
    /// The bottom of its committed part.
    pub stack_limit: u32,
    /// The start of its reservation.
    pub stack_allocation_base: u32,
}

const _: () = {
    assert!(size_of::<InitialTeb32>() == 0x14);
    assert!(offset_of!(InitialTeb32, stack_base) == 0x08);
    assert!(offset_of!(InitialTeb32, stack_allocation_base) == 0x10);
};
