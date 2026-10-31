//! CPUID queries.
//!
//! ADR-004: SYSENTER from 32-bit compatibility mode only exists on Intel CPUs
//! in long mode (AMD raises #UD there), so the fast system-call path depends on
//! the CPU vendor. Every other vendor uses `int 0x2E`.

/// Returns `true` when CPUID leaf 0 reports the "GenuineIntel" vendor.
///
/// # IRQL
/// Any level. No side effects.
pub fn is_intel() -> bool {
    // Leaf 0: highest leaf in EAX, vendor string in EBX, EDX, ECX.
    let r = core::arch::x86_64::__cpuid(0);
    is_intel_vendor(r.ebx, r.edx, r.ecx)
}

/// The processor signature (CPUID leaf 1, EAX), the features of leaf 1
/// (EDX), and the extended features of leaf 0x8000_0001 (EDX, 0 without it).
///
/// # IRQL
/// Any level. No side effects.
pub fn signature_and_features() -> (u32, u32, u32) {
    let leaf1 = core::arch::x86_64::__cpuid(1);
    let extended = if core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001 {
        core::arch::x86_64::__cpuid(0x8000_0001).edx
    } else {
        0
    };
    (leaf1.eax, leaf1.edx, extended)
}

/// The processor level and revision of XP SP2 (KeProcessorLevel,
/// KeProcessorRevision) for the signature `signature` (CPUID leaf 1, EAX):
/// the level is the family, plus the extended family for family 15; the
/// revision is the model, then the stepping, one byte each. The model takes
/// the extended model for family 15, and for family 6 on Intel (`intel`).
/// ReactOS (`KiSetProcessorType`) serves as the specification.
pub fn level_and_revision(signature: u32, intel: bool) -> (u16, u16) {
    let stepping = signature & 0xF;
    let mut model = (signature >> 4) & 0xF;
    let family = (signature >> 8) & 0xF;
    let (extended_model, extended_family) = ((signature >> 16) & 0xF, (signature >> 20) & 0xFF);
    if family == 15 || (family == 6 && intel) {
        model |= extended_model << 4;
    }
    let level = if family == 15 { family + extended_family.min(0xF0) } else { family };
    (level as u16, ((model << 8) | stepping) as u16)
}

/// The feature bits of XP SP2 (KeFeatureBits, `abi::system_information::KF_*`)
/// for the features `leaf1_edx` (CPUID leaf 1) and `extended_edx` (leaf
/// 0x8000_0001). `fast_syscall`: the kernel uses SYSENTER (ADR-004 : on
/// Intel), which needs SEP; `nx_enabled`: EFER.NXE is set. Every x86-64
/// processor has working PTEs and CR4.
pub fn feature_bits(leaf1_edx: u32, extended_edx: u32, fast_syscall: bool, nx_enabled: bool) -> u32 {
    use abi::system_information::*;

    let has = |bit: u32| leaf1_edx & (1 << bit) != 0;
    let mut bits = KF_WORKING_PTE | KF_CR4;
    for (bit, kf) in [
        (1, KF_V86_VIS),
        (3, KF_LARGE_PAGE),
        (4, KF_RDTSC),
        (8, KF_CMPXCHG8B),
        (12, KF_MTRR),
        (13, KF_GLOBAL_PAGE),
        (15, KF_CMOV),
        (16, KF_PAT),
        (21, KF_DTS),
        (23, KF_MMX),
        (24, KF_FXSR),
        (25, KF_XMMI),
        (26, KF_XMMI64),
    ] {
        if has(bit) {
            bits |= kf;
        }
    }
    if fast_syscall && has(11) {
        bits |= KF_FAST_SYSCALL;
    }
    if extended_edx & (1 << 31) != 0 {
        bits |= KF_3DNOW;
    }
    if extended_edx & (1 << 20) != 0 {
        bits |= KF_NX_BIT | if nx_enabled { KF_NX_ENABLED } else { KF_NX_DISABLED };
    }
    bits
}

/// Vendor check on the CPUID leaf 0 registers, in vendor-string order (EBX, EDX, ECX).
fn is_intel_vendor(ebx: u32, edx: u32, ecx: u32) -> bool {
    ebx == u32::from_le_bytes(*b"Genu") && edx == u32::from_le_bytes(*b"ineI") && ecx == u32::from_le_bytes(*b"ntel")
}

#[cfg(test)]
mod tests {
    use super::{feature_bits, is_intel_vendor, level_and_revision};
    use abi::system_information::*;

    /// A CPUID leaf 1 signature.
    fn signature(extended_family: u32, extended_model: u32, family: u32, model: u32, stepping: u32) -> u32 {
        (extended_family << 20) | (extended_model << 16) | (family << 8) | (model << 4) | stepping
    }

    #[test]
    fn level_and_revision_follow_xp_sp2() {
        // Core 2: family 6, model 15, stepping 11.
        assert_eq!(level_and_revision(signature(0, 0, 6, 15, 11), true), (6, 0x0F0B));
        // Sandy Bridge: family 6, model 0x2A, on Intel the extended model counts.
        assert_eq!(level_and_revision(signature(0, 2, 6, 0xA, 7), true), (6, 0x2A07));
        assert_eq!(level_and_revision(signature(0, 2, 6, 0xA, 7), false), (6, 0x0A07), "family 6 elsewhere");
        // QEMU's qemu64: family 15, model 0x6B, stepping 1.
        assert_eq!(level_and_revision(signature(0, 6, 15, 0xB, 1), false), (15, 0x6B01));
        // Zen: family 0x17, model 1, stepping 1.
        assert_eq!(level_and_revision(signature(8, 0, 15, 1, 1), false), (0x17, 0x0101));
        // Pentium: family 5, nothing extended.
        assert_eq!(level_and_revision(signature(3, 3, 5, 2, 0xC), true), (5, 0x020C));
    }

    #[test]
    fn feature_bits_follow_cpuid() {
        // An x86-64 processor: TSC, PSE, CX8, SEP, MTRR, PGE, CMOV, PAT, MMX,
        // FXSR, SSE, SSE2; NX in the extended features.
        let edx = [3, 4, 8, 11, 12, 13, 15, 16, 23, 24, 25, 26].iter().fold(0, |edx, bit| edx | (1 << bit));
        let common = KF_WORKING_PTE
            | KF_CR4
            | KF_LARGE_PAGE
            | KF_RDTSC
            | KF_CMPXCHG8B
            | KF_MTRR
            | KF_GLOBAL_PAGE
            | KF_CMOV
            | KF_PAT
            | KF_MMX
            | KF_FXSR
            | KF_XMMI
            | KF_XMMI64;
        assert_eq!(feature_bits(edx, 1 << 20, true, true), common | KF_FAST_SYSCALL | KF_NX_BIT | KF_NX_ENABLED);
        assert_eq!(feature_bits(edx, 1 << 20, false, false), common | KF_NX_BIT | KF_NX_DISABLED, "int 2Eh, NX off");
        assert_eq!(feature_bits(edx & !(1 << 11), 0, true, true), common, "SYSENTER needs SEP; no NX bit");
        assert_eq!(
            feature_bits(1 << 1 | 1 << 21, 1 << 31, false, false),
            KF_WORKING_PTE | KF_CR4 | KF_V86_VIS | KF_DTS | KF_3DNOW
        );
    }

    /// Splits a 12-byte vendor string into (EBX, EDX, ECX) as CPUID returns it.
    fn regs(vendor: &[u8; 12]) -> (u32, u32, u32) {
        let w = |i: usize| u32::from_le_bytes([vendor[i], vendor[i + 1], vendor[i + 2], vendor[i + 3]]);
        (w(0), w(4), w(8))
    }

    #[test]
    fn intel_is_detected() {
        let (b, d, c) = regs(b"GenuineIntel");
        assert!(is_intel_vendor(b, d, c));
    }

    #[test]
    fn other_vendors_are_not_intel() {
        for v in [b"AuthenticAMD", b"HygonGenuine", b"CentaurHauls", b"  Shanghai  ", b"TCGTCGTCGTCG"] {
            let (b, d, c) = regs(v);
            assert!(!is_intel_vendor(b, d, c), "{}", core::str::from_utf8(v).unwrap());
        }
    }

    #[test]
    fn register_order_matters() {
        // Same three words in EBX, ECX, EDX order (the natural reading order) must not match.
        let (b, d, c) = regs(b"GenuineIntel");
        assert!(!is_intel_vendor(b, c, d));
    }
}
