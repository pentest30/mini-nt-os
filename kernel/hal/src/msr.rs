use core::arch::asm;

pub const IA32_SYSENTER_CS: u32 = 0x174;
pub const IA32_SYSENTER_ESP: u32 = 0x175;
pub const IA32_SYSENTER_EIP: u32 = 0x176;

/// Reads model-specific register `msr`.
///
/// # Safety
/// The CPU must implement `msr`, or `rdmsr` raises #GP.
///
/// # IRQL
/// Any level.
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Writes `value` to model-specific register `msr`.
///
/// # Safety
/// The CPU must implement `msr` and accept `value` (else #GP), and the
/// caller answers for what the new value does (e.g. the SYSENTER entry).
///
/// # IRQL
/// Any level.
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}
