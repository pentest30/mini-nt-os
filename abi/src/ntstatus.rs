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
pub const STATUS_BREAKPOINT: NtStatus = NtStatus(0x8000_0003);
pub const STATUS_INVALID_PARAMETER: NtStatus = NtStatus(0xC000_000D);
pub const STATUS_NO_MEMORY: NtStatus = NtStatus(0xC000_0017);
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = NtStatus(0xC000_0018);
pub const STATUS_UNABLE_TO_FREE_VM: NtStatus = NtStatus(0xC000_001A);
pub const STATUS_UNABLE_TO_DELETE_SECTION: NtStatus = NtStatus(0xC000_001B);
pub const STATUS_NOT_COMMITTED: NtStatus = NtStatus(0xC000_002D);
pub const STATUS_INVALID_PAGE_PROTECTION: NtStatus = NtStatus(0xC000_0045);
pub const STATUS_MUTANT_NOT_OWNED: NtStatus = NtStatus(0xC000_0046);
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: NtStatus = NtStatus(0xC000_0047);
pub const STATUS_FREE_VM_NOT_AT_BASE: NtStatus = NtStatus(0xC000_009F);
pub const STATUS_MEMORY_NOT_ALLOCATED: NtStatus = NtStatus(0xC000_00A0);

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
