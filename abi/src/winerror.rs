//! Win32 error codes (`winerror.h`), which win32k writes as a thread's last
//! error (`TEB.LastErrorValue`, read by GetLastError).

/// ERROR_INVALID_PARAMETER.
pub const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_CALL_NOT_IMPLEMENTED.
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
/// ERROR_INVALID_FUNCTION.
pub const ERROR_INVALID_FUNCTION: u32 = 1;
/// ERROR_FILE_NOT_FOUND.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
/// ERROR_PATH_NOT_FOUND.
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
/// ERROR_ACCESS_DENIED.
pub const ERROR_ACCESS_DENIED: u32 = 5;
/// ERROR_INVALID_HANDLE.
pub const ERROR_INVALID_HANDLE: u32 = 6;
/// ERROR_NOT_ENOUGH_MEMORY.
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// ERROR_INVALID_NAME.
pub const ERROR_INVALID_NAME: u32 = 123;
/// ERROR_BUSY.
pub const ERROR_BUSY: u32 = 170;
/// ERROR_ALREADY_EXISTS.
pub const ERROR_ALREADY_EXISTS: u32 = 183;
/// ERROR_MR_MID_NOT_FOUND: what RtlNtStatusToDosError gives a status it
/// does not know.
pub const ERROR_MR_MID_NOT_FOUND: u32 = 317;
/// ERROR_NOACCESS.
pub const ERROR_NOACCESS: u32 = 998;

/// RtlNtStatusToDosError, for the statuses the kernel gives win32k's
/// callers; the others are `ERROR_MR_MID_NOT_FOUND`.
pub const fn dos_error(status: crate::ntstatus::NtStatus) -> u32 {
    use crate::ntstatus as s;
    match status {
        s::STATUS_SUCCESS => 0,
        s::STATUS_NOT_IMPLEMENTED => ERROR_INVALID_FUNCTION,
        s::STATUS_OBJECT_NAME_NOT_FOUND => ERROR_FILE_NOT_FOUND,
        s::STATUS_OBJECT_PATH_NOT_FOUND => ERROR_PATH_NOT_FOUND,
        s::STATUS_ACCESS_DENIED => ERROR_ACCESS_DENIED,
        s::STATUS_INVALID_HANDLE | s::STATUS_OBJECT_TYPE_MISMATCH => ERROR_INVALID_HANDLE,
        s::STATUS_NO_MEMORY | s::STATUS_INSUFFICIENT_RESOURCES => ERROR_NOT_ENOUGH_MEMORY,
        s::STATUS_INVALID_PARAMETER => ERROR_INVALID_PARAMETER,
        s::STATUS_OBJECT_NAME_INVALID => ERROR_INVALID_NAME,
        s::STATUS_OBJECT_NAME_COLLISION => ERROR_ALREADY_EXISTS,
        s::STATUS_ACCESS_VIOLATION => ERROR_NOACCESS,
        _ => ERROR_MR_MID_NOT_FOUND,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntstatus::{NtStatus, STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS};

    #[test]
    fn statuses_become_win32_errors() {
        assert_eq!(dos_error(STATUS_SUCCESS), 0);
        assert_eq!(dos_error(STATUS_INVALID_HANDLE), ERROR_INVALID_HANDLE);
        assert_eq!(dos_error(STATUS_OBJECT_TYPE_MISMATCH), ERROR_INVALID_HANDLE, "a handle of another type");
        assert_eq!(dos_error(NtStatus(0xC000_0999)), ERROR_MR_MID_NOT_FOUND, "unknown");
    }
}
