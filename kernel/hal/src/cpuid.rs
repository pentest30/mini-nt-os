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

/// Vendor check on the CPUID leaf 0 registers, in vendor-string order (EBX, EDX, ECX).
fn is_intel_vendor(ebx: u32, edx: u32, ecx: u32) -> bool {
    ebx == u32::from_le_bytes(*b"Genu")
        && edx == u32::from_le_bytes(*b"ineI")
        && ecx == u32::from_le_bytes(*b"ntel")
}

#[cfg(test)]
mod tests {
    use super::is_intel_vendor;

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
