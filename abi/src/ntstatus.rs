//! NTSTATUS (CLAUDE.md, rule 7): the result of a kernel operation, never a
//! bare `u32`. Values are those of the XP SDK headers (`ntstatus.h`).
//!
//! Layout of the 32 bits: severity (2), customer (1), reserved (1),
//! facility (12), code (16). Success and informational values are
//! non-negative as `i32`; warnings and errors are negative.

/// An NTSTATUS value.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

impl NtStatus {
    /// `NT_SUCCESS`: success or informational.
    pub const fn is_success(self) -> bool {
        (self.0 as i32) >= 0
    }

    /// Severity `STATUS_SEVERITY_ERROR`.
    pub const fn is_error(self) -> bool {
        self.0 >> 30 == 3
    }

    /// `STATUS_WAIT_0 + index`: object `index` satisfied a wait.
    pub const fn wait(index: u32) -> Self {
        Self(STATUS_WAIT_0.0 + index)
    }

    /// `STATUS_ABANDONED_WAIT_0 + index`: the wait acquired abandoned mutant
    /// `index`.
    pub const fn abandoned_wait(index: u32) -> Self {
        Self(STATUS_ABANDONED_WAIT_0.0 + index)
    }
}

impl core::fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NtStatus({:#010x})", self.0)
    }
}

/// The value in hex, as `0xc0000018`.
impl core::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

pub const STATUS_SUCCESS: NtStatus = NtStatus(0x0000_0000);
pub const STATUS_WAIT_0: NtStatus = NtStatus(0x0000_0000);
pub const STATUS_ABANDONED_WAIT_0: NtStatus = NtStatus(0x0000_0080);
pub const STATUS_USER_APC: NtStatus = NtStatus(0x0000_00C0);
pub const STATUS_KERNEL_APC: NtStatus = NtStatus(0x0000_0100);
pub const STATUS_ALERTED: NtStatus = NtStatus(0x0000_0101);
pub const STATUS_TIMEOUT: NtStatus = NtStatus(0x0000_0102);
pub const STATUS_PENDING: NtStatus = NtStatus(0x0000_0103);
pub const STATUS_REPARSE: NtStatus = NtStatus(0x0000_0104);
pub const STATUS_OBJECT_NAME_EXISTS: NtStatus = NtStatus(0x4000_0000);
pub const STATUS_IMAGE_NOT_AT_BASE: NtStatus = NtStatus(0x4000_0003);
pub const STATUS_GUARD_PAGE_VIOLATION: NtStatus = NtStatus(0x8000_0001);
pub const STATUS_DATATYPE_MISALIGNMENT: NtStatus = NtStatus(0x8000_0002);
pub const STATUS_BREAKPOINT: NtStatus = NtStatus(0x8000_0003);
pub const STATUS_BUFFER_OVERFLOW: NtStatus = NtStatus(0x8000_0005);
pub const STATUS_NO_MORE_ENTRIES: NtStatus = NtStatus(0x8000_001A);
pub const STATUS_UNSUCCESSFUL: NtStatus = NtStatus(0xC000_0001);
pub const STATUS_NOT_IMPLEMENTED: NtStatus = NtStatus(0xC000_0002);
pub const STATUS_INVALID_INFO_CLASS: NtStatus = NtStatus(0xC000_0003);
pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = NtStatus(0xC000_0004);
pub const STATUS_ACCESS_VIOLATION: NtStatus = NtStatus(0xC000_0005);
pub const STATUS_INVALID_HANDLE: NtStatus = NtStatus(0xC000_0008);
pub const STATUS_INVALID_CID: NtStatus = NtStatus(0xC000_000B);
pub const STATUS_INVALID_PARAMETER: NtStatus = NtStatus(0xC000_000D);
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = NtStatus(0xC000_0010);
pub const STATUS_END_OF_FILE: NtStatus = NtStatus(0xC000_0011);
pub const STATUS_NO_MEMORY: NtStatus = NtStatus(0xC000_0017);
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = NtStatus(0xC000_0023);
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = NtStatus(0xC000_0018);
pub const STATUS_NOT_MAPPED_VIEW: NtStatus = NtStatus(0xC000_0019);
pub const STATUS_UNABLE_TO_FREE_VM: NtStatus = NtStatus(0xC000_001A);
pub const STATUS_UNABLE_TO_DELETE_SECTION: NtStatus = NtStatus(0xC000_001B);
pub const STATUS_INVALID_SYSTEM_SERVICE: NtStatus = NtStatus(0xC000_001C);
pub const STATUS_ILLEGAL_INSTRUCTION: NtStatus = NtStatus(0xC000_001D);
pub const STATUS_INVALID_VIEW_SIZE: NtStatus = NtStatus(0xC000_001F);
pub const STATUS_ACCESS_DENIED: NtStatus = NtStatus(0xC000_0022);
pub const STATUS_OBJECT_TYPE_MISMATCH: NtStatus = NtStatus(0xC000_0024);
pub const STATUS_NOT_COMMITTED: NtStatus = NtStatus(0xC000_002D);
pub const STATUS_EAS_NOT_SUPPORTED: NtStatus = NtStatus(0xC000_004F);
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = NtStatus(0xC000_0033);
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xC000_0034);
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xC000_0035);
pub const STATUS_OBJECT_PATH_INVALID: NtStatus = NtStatus(0xC000_0039);
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = NtStatus(0xC000_003A);
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: NtStatus = NtStatus(0xC000_003B);
pub const STATUS_DISK_CORRUPT_ERROR: NtStatus = NtStatus(0xC000_0032);
pub const STATUS_MEDIA_WRITE_PROTECTED: NtStatus = NtStatus(0xC000_00A2);
pub const STATUS_FILE_IS_A_DIRECTORY: NtStatus = NtStatus(0xC000_00BA);
pub const STATUS_FILE_CORRUPT_ERROR: NtStatus = NtStatus(0xC000_0102);
pub const STATUS_NOT_A_DIRECTORY: NtStatus = NtStatus(0xC000_0103);
pub const STATUS_UNRECOGNIZED_VOLUME: NtStatus = NtStatus(0xC000_014F);
pub const STATUS_IO_DEVICE_ERROR: NtStatus = NtStatus(0xC000_0185);
pub const STATUS_INVALID_PAGE_PROTECTION: NtStatus = NtStatus(0xC000_0045);
pub const STATUS_MUTANT_NOT_OWNED: NtStatus = NtStatus(0xC000_0046);
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: NtStatus = NtStatus(0xC000_0047);
pub const STATUS_THREAD_IS_TERMINATING: NtStatus = NtStatus(0xC000_004B);
pub const STATUS_SECTION_TOO_BIG: NtStatus = NtStatus(0xC000_0040);
pub const STATUS_SECTION_NOT_IMAGE: NtStatus = NtStatus(0xC000_0049);
pub const STATUS_SECTION_PROTECTION: NtStatus = NtStatus(0xC000_004E);
pub const STATUS_PROCEDURE_NOT_FOUND: NtStatus = NtStatus(0xC000_007A);
pub const STATUS_INVALID_IMAGE_FORMAT: NtStatus = NtStatus(0xC000_007B);
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: NtStatus = NtStatus(0xC000_0094);
pub const STATUS_PRIVILEGED_INSTRUCTION: NtStatus = NtStatus(0xC000_0096);
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = NtStatus(0xC000_009A);
pub const STATUS_FREE_VM_NOT_AT_BASE: NtStatus = NtStatus(0xC000_009F);
pub const STATUS_MEMORY_NOT_ALLOCATED: NtStatus = NtStatus(0xC000_00A0);
pub const STATUS_STACK_OVERFLOW: NtStatus = NtStatus(0xC000_00FD);
pub const STATUS_REGISTRY_CORRUPT: NtStatus = NtStatus(0xC000_014C);
pub const STATUS_NAME_TOO_LONG: NtStatus = NtStatus(0xC000_0106);
pub const STATUS_INVALID_PARAMETER_3: NtStatus = NtStatus(0xC000_00F1);
pub const STATUS_PROCESS_IS_TERMINATING: NtStatus = NtStatus(0xC000_010A);
pub const STATUS_MAPPED_FILE_SIZE_ZERO: NtStatus = NtStatus(0xC000_011E);
pub const STATUS_MAPPED_ALIGNMENT: NtStatus = NtStatus(0xC000_0220);
pub const STATUS_HANDLE_NOT_CLOSABLE: NtStatus = NtStatus(0xC000_0235);
pub const STATUS_NO_CALLBACK_ACTIVE: NtStatus = NtStatus(0xC000_0258);
pub const STATUS_ASSERTION_FAILURE: NtStatus = NtStatus(0xC000_0420);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn classifies_severity() {
        assert!(STATUS_SUCCESS.is_success());
        assert!(STATUS_TIMEOUT.is_success(), "informational wait status");
        assert!(!STATUS_MUTANT_NOT_OWNED.is_success());
        assert!(STATUS_MUTANT_NOT_OWNED.is_error());
        assert!(!STATUS_USER_APC.is_error());
    }

    #[test]
    fn displays_in_hex() {
        assert_eq!(std::format!("{STATUS_CONFLICTING_ADDRESSES}"), "0xc0000018");
        assert_eq!(std::format!("{STATUS_SUCCESS}"), "0x00000000");
    }

    #[test]
    fn wait_statuses_carry_the_object_index() {
        assert_eq!(NtStatus::wait(3), NtStatus(3));
        assert_eq!(NtStatus::abandoned_wait(2), NtStatus(0x82));
    }
}
