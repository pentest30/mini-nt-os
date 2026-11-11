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
/// ERROR_INVALID_INDEX.
pub const ERROR_INVALID_INDEX: u32 = 1413;
/// ERROR_NO_SYSTEM_RESOURCES: not enough memory for what was asked
/// (a bitmap, for GDI).
pub const ERROR_NO_SYSTEM_RESOURCES: u32 = 1450;
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
/// ERROR_INVALID_FLAGS.
pub const ERROR_INVALID_FLAGS: u32 = 1004;
/// ERROR_MESSAGE_SYNC_ONLY: a message with a pointer cannot be posted.
pub const ERROR_MESSAGE_SYNC_ONLY: u32 = 1159;
/// ERROR_INVALID_WINDOW_HANDLE.
pub const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
/// ERROR_TIMEOUT: SendMessageTimeout ran out of time.
pub const ERROR_TIMEOUT: u32 = 1460;
/// ERROR_SUCCESS.
pub const ERROR_SUCCESS: u32 = 0;
/// ERROR_INVALID_MENU_HANDLE.
pub const ERROR_INVALID_MENU_HANDLE: u32 = 1401;
/// ERROR_INVALID_ACCEL_HANDLE.
pub const ERROR_INVALID_ACCEL_HANDLE: u32 = 1403;
/// ERROR_MENU_ITEM_NOT_FOUND.
pub const ERROR_MENU_ITEM_NOT_FOUND: u32 = 1456;
/// ERROR_POPUP_ALREADY_ACTIVE: TrackPopupMenu on a menu already shown.
pub const ERROR_POPUP_ALREADY_ACTIVE: u32 = 1446;
/// ERROR_INVALID_CURSOR_HANDLE.
pub const ERROR_INVALID_CURSOR_HANDLE: u32 = 1402;
/// The window has no scroll bars (GetScrollInfo before any).
pub const ERROR_NO_SCROLLBARS: u32 = 1447;
/// ERROR_TLW_WITH_WSCHILD: a child window without a parent.
pub const ERROR_TLW_WITH_WSCHILD: u32 = 1406;
/// ERROR_CANNOT_FIND_WND_CLASS.
pub const ERROR_CANNOT_FIND_WND_CLASS: u32 = 1407;
/// ERROR_INVALID_MONITOR_HANDLE.
pub const ERROR_INVALID_MONITOR_HANDLE: u32 = 1461;
/// ERROR_CLASS_ALREADY_EXISTS.
pub const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
/// ERROR_CLASS_DOES_NOT_EXIST.
pub const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1411;
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
        s::STATUS_INVALID_PARAMETER | s::STATUS_INVALID_CID => ERROR_INVALID_PARAMETER,
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
