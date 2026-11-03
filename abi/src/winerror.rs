//! Win32 error codes (`winerror.h`), which win32k writes as a thread's last
//! error (`TEB.LastErrorValue`, read by GetLastError).

/// ERROR_INVALID_PARAMETER.
pub const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_CALL_NOT_IMPLEMENTED.
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
