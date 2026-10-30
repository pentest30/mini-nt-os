//! Process values shared with user mode.
//!
//! - `MEM_EXECUTE_OPTION_*`: a process's execute options (DEP, ADR-020), as
//!   `NtQueryInformationProcess` and `NtSetInformationProcess` exchange them
//!   (`ProcessExecuteFlags`, M3).

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
