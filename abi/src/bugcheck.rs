//! Bug check codes: the first value of the fatal error screen
//! (`KeBugCheckEx`), with the meaning that XP gives them and their documented
//! parameters.

/// A bug check code.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BugCheckCode(pub u32);

impl BugCheckCode {
    /// A reference to pageable or invalid memory at DISPATCH_LEVEL or above.
    /// P1: the address; P2: the IRQL; P3: bit 0 set for a write, bit 3 for
    /// an instruction fetch; P4: the instruction that referenced it.
    pub const IRQL_NOT_LESS_OR_EQUAL: Self = Self(0x0A);
    /// A kernel-mode exception that nothing handled. P1: the exception code
    /// (NTSTATUS); P2: where it happened; P3, P4: its first two parameters.
    ///
    /// A violated invariant (`panic!`, 06 §5) ends here with P1 =
    /// `STATUS_BREAKPOINT`, as a failed assertion does on XP when no kernel
    /// debugger is attached.
    pub const KMODE_EXCEPTION_NOT_HANDLED: Self = Self(0x1E);
    /// A kernel-mode reference to an invalid address. P1: the address; P2: 0
    /// for a read, 1 for a write; P3: the instruction that referenced it.
    pub const PAGE_FAULT_IN_NONPAGED_AREA: Self = Self(0x50);
    /// A CPU trap that the kernel cannot handle (double fault, stack overflow
    /// into a guard page…). P1: the trap number.
    pub const UNEXPECTED_KERNEL_MODE_TRAP: Self = Self(0x7F);

    /// The symbolic name of a known code, or `None`.
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::IRQL_NOT_LESS_OR_EQUAL => Some("IRQL_NOT_LESS_OR_EQUAL"),
            Self::KMODE_EXCEPTION_NOT_HANDLED => Some("KMODE_EXCEPTION_NOT_HANDLED"),
            Self::PAGE_FAULT_IN_NONPAGED_AREA => Some("PAGE_FAULT_IN_NONPAGED_AREA"),
            Self::UNEXPECTED_KERNEL_MODE_TRAP => Some("UNEXPECTED_KERNEL_MODE_TRAP"),
            _ => None,
        }
    }
}

impl core::fmt::Debug for BugCheckCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({:#x})", self.0),
            None => write!(f, "BugCheckCode({:#x})", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_have_their_name() {
        assert_eq!(BugCheckCode(0x0A).name(), Some("IRQL_NOT_LESS_OR_EQUAL"));
        assert_eq!(BugCheckCode(0x7F).name(), Some("UNEXPECTED_KERNEL_MODE_TRAP"));
        assert_eq!(BugCheckCode(0x1E).name(), Some("KMODE_EXCEPTION_NOT_HANDLED"));
        assert_eq!(BugCheckCode(0x50).name(), Some("PAGE_FAULT_IN_NONPAGED_AREA"));
        assert_eq!(BugCheckCode(0x1234).name(), None);
    }
}
