//! Copies to and from user memory that survive a fault (02 §6.4).
//!
//! The exception table lists each instruction that may fault on a user
//! address, with its fixup. A kernel-mode page fault on a user address that
//! the memory manager does not resolve, at such an instruction, resumes at
//! its fixup (`idt`), which returns an error instead of stopping the system.
//! `ke::usermem` builds the kernel's user memory primitives on [`copy`].

/// Copies `len` bytes from `src` to `dst`; `false` if a fault on a user
/// address ended the copy, the bytes before it copied.
///
/// # Safety
/// Each range is kernel memory valid for the access, or user memory (below
/// the end of the user half) that the caller has probed; a fault there ends
/// the copy. The ranges do not overlap.
///
/// # IRQL
/// < DISPATCH_LEVEL: a user page may fault in.
pub unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) -> bool {
    #[cfg(target_os = "none")]
    {
        // SAFETY: forwarded; the routine faults only where the exception
        // table recovers it.
        unsafe { hal_usermem_copy(dst, src, len) != 0 }
    }
    #[cfg(not(target_os = "none"))]
    {
        // SAFETY: forwarded. The host has no user memory: both ranges are
        // valid.
        unsafe { core::ptr::copy_nonoverlapping(src, dst, len) };
        true
    }
}

/// The fixup of an instruction that may fault on user memory, if `rip` is
/// one.
///
/// # IRQL
/// Any level.
pub(crate) fn fixup(rip: u64) -> Option<u64> {
    #[cfg(target_os = "none")]
    {
        // (faulting instruction, fixup)
        let table: [(unsafe extern "C" fn(), unsafe extern "C" fn()); 1] =
            [(hal_usermem_copy_fault, hal_usermem_copy_fixup)];
        table.iter().find(|&&(fault, _)| fault as usize as u64 == rip).map(|&(_, fixup)| fixup as usize as u64)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = rip;
        None
    }
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    /// `rep movsb` of `len` bytes; 1, or 0 from the fixup after a fault.
    fn hal_usermem_copy(dst: *mut u8, src: *const u8, len: usize) -> u32;
    /// The instruction of `hal_usermem_copy` that may fault.
    fn hal_usermem_copy_fault();
    /// Where a fault of `hal_usermem_copy_fault` resumes.
    fn hal_usermem_copy_fixup();
}

// SysV: RDI = dst, RSI = src, RDX = len. A fault in `rep movsb` leaves RSP
// as at the call: the fixup returns 0 to the caller.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global hal_usermem_copy",
    ".global hal_usermem_copy_fault",
    ".global hal_usermem_copy_fixup",
    "hal_usermem_copy:",
    "   cld",
    "   mov rcx, rdx",
    "hal_usermem_copy_fault:",
    "   rep movsb",
    "   mov eax, 1",
    "   ret",
    "hal_usermem_copy_fixup:",
    "   xor eax, eax",
    "   ret",
);
