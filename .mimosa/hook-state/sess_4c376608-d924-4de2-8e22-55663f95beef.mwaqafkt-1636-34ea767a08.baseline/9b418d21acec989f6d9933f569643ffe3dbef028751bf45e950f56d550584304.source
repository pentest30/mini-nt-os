//! Charge de calcul du scénario `fpu` (critère de sortie de M1, 05) : quatre
//! threads calculent en parallèle et doivent obtenir les résultats de l'hôte.
//!
//! Chaque charge itère l'application logistique `x ← r·x·(1 − x)` en SSE
//! (double précision) et, en même temps, en x87 (précision étendue), avec ses
//! propres modes d'arrondi (MXCSR, FCW). L'application est chaotique : une
//! valeur, un registre ou un mode d'arrondi corrompu par un autre thread change
//! le résultat sans que les itérations suivantes le corrigent. Les tests de ce
//! module vérifient sur l'hôte les résultats attendus, [`EXPECTED`], que le
//! scénario compare à ceux du noyau.

/// Paramètres d'une charge (lus par l'assembleur : layout fixe).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Workload {
    pub sse_x0: f64,
    pub sse_r: f64,
    pub x87_x0: f64,
    pub x87_r: f64,
    /// Modes SSE pendant le calcul (arrondi dans les bits 13-14).
    pub mxcsr: u32,
    /// Mot de contrôle x87 pendant le calcul (précision 64 bits ; arrondi dans
    /// les bits 10-11).
    pub fcw: u16,
    pub iterations: u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(Workload, sse_x0) == 0);
    assert!(offset_of!(Workload, sse_r) == 8);
    assert!(offset_of!(Workload, x87_x0) == 16);
    assert!(offset_of!(Workload, x87_r) == 24);
    assert!(offset_of!(Workload, mxcsr) == 32);
    assert!(offset_of!(Workload, fcw) == 36);
    assert!(offset_of!(Workload, iterations) == 40);
};

/// Itérations d'une charge.
const ITERATIONS: u32 = 100_000;

/// Les quatre charges, une par thread : un mode d'arrondi différent pour
/// chacune (au plus proche, vers zéro, vers le bas, vers le haut).
pub const WORKLOADS: [Workload; 4] = [
    Workload {
        sse_x0: 0.1234,
        sse_r: 3.91,
        x87_x0: 0.4321,
        x87_r: 3.97,
        mxcsr: 0x1F80,
        fcw: 0x037F,
        iterations: ITERATIONS,
    },
    Workload {
        sse_x0: 0.2345,
        sse_r: 3.93,
        x87_x0: 0.5432,
        x87_r: 3.95,
        mxcsr: 0x7F80,
        fcw: 0x0F7F,
        iterations: ITERATIONS,
    },
    Workload {
        sse_x0: 0.3456,
        sse_r: 3.95,
        x87_x0: 0.6543,
        x87_r: 3.93,
        mxcsr: 0x3F80,
        fcw: 0x077F,
        iterations: ITERATIONS,
    },
    Workload {
        sse_x0: 0.4567,
        sse_r: 3.97,
        x87_x0: 0.7654,
        x87_r: 3.91,
        mxcsr: 0x5F80,
        fcw: 0x0B7F,
        iterations: ITERATIONS,
    },
];

/// Résultats de [`WORKLOADS`] (bits des `f64` SSE et x87), calculés sur l'hôte
/// et vérifiés par les tests de ce module.
pub const EXPECTED: [[u64; 2]; 4] = [
    [0x3FEA_A7F4_1BC6_987F, 0x3FED_3531_D1DB_D3D2], // 0.8330021421904944, 0.9127434824755432
    [0x3FE6_0B01_6ECC_9E41, 0x3FED_DDD5_3A3D_F5EC], // 0.6888434566544178, 0.9333292138614389
    [0x3FE7_EA79_0F70_B6A9, 0x3FEF_7088_7A1F_A7C6], // 0.7473721791809186, 0.9824869523265469
    [0x3FA6_984C_2DA9_D013, 0x3FE0_08F0_E6EC_37B1], // 0.04413068826116286, 0.5010914335450619
];

unsafe extern "sysv64" {
    fn ke_fpu_workload(workload: *const Workload, results: *mut [u64; 2]);
}

/// Exécute `workload` : les bits des résultats SSE et x87. Dans le noyau, à
/// encadrer de [`super::with_floating_point`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn run(workload: &Workload) -> [u64; 2] {
    assert!(workload.iterations > 0);
    let mut results = [0u64; 2];
    // SAFETY: la routine lit `workload`, écrit `results`, et suit l'ABI sysv64 :
    // elle ne touche qu'aux registres volatils, rend la pile x87 vide, et
    // restaure MXCSR et FCW.
    unsafe { ke_fpu_workload(workload, &mut results) };
    results
}

core::arch::global_asm!(
    ".global ke_fpu_workload",
    "ke_fpu_workload:",
    // rdi = workload, rsi = results. MXCSR et FCW de l'appelant, sauvegardés.
    "    sub rsp, 8",
    "    stmxcsr dword ptr [rsp]",
    "    fnstcw word ptr [rsp + 4]",
    "    ldmxcsr dword ptr [rdi + 32]",
    "    fldcw word ptr [rdi + 36]",
    // SSE : xmm0 = x, xmm1 = r, xmm2 = 1.0. x87 : st0 = y, st1 = r.
    "    movsd xmm0, qword ptr [rdi]",
    "    movsd xmm1, qword ptr [rdi + 8]",
    "    mov rax, 0x3FF0000000000000",
    "    movq xmm2, rax",
    "    fld qword ptr [rdi + 24]",
    "    fld qword ptr [rdi + 16]",
    "    mov ecx, dword ptr [rdi + 40]",
    "2:",
    "    movapd xmm3, xmm2",
    "    subsd xmm3, xmm0",
    "    mulsd xmm3, xmm0",
    "    mulsd xmm3, xmm1",
    "    movapd xmm0, xmm3",
    "    fld1",
    "    fsub st, st(1)",
    "    fmul st, st(1)",
    "    fmul st, st(2)",
    "    fstp st(1)",
    "    dec ecx",
    "    jnz 2b",
    "    movsd qword ptr [rsi], xmm0",
    "    fstp qword ptr [rsi + 8]",
    "    fstp st(0)",
    "    ldmxcsr dword ptr [rsp]",
    "    fldcw word ptr [rsp + 4]",
    "    add rsp, 8",
    "    ret",
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fpu::with_floating_point;

    #[test]
    fn the_host_gets_the_expected_results_whatever_the_callers_modes() {
        with_floating_point(|| {
            for (w, expected) in WORKLOADS.iter().zip(EXPECTED) {
                assert_eq!(run(w), expected, "{w:?}");
            }
            hal::fpu::set_control_words(0x0F7F, 0x7F80);
            for (w, expected) in WORKLOADS.iter().zip(EXPECTED) {
                assert_eq!(run(w), expected, "the workload loads its own modes: {w:?}");
            }
        });
    }

    /// Un mode d'arrondi corrompu (par un autre thread) change le résultat.
    #[test]
    fn a_wrong_rounding_mode_changes_the_result() {
        with_floating_point(|| {
            let [sse, x87] = EXPECTED[0];
            let wrong_mxcsr = Workload { mxcsr: WORKLOADS[1].mxcsr, ..WORKLOADS[0] };
            assert_ne!(run(&wrong_mxcsr)[0], sse);
            let wrong_fcw = Workload { fcw: WORKLOADS[1].fcw, ..WORKLOADS[0] };
            assert_ne!(run(&wrong_fcw)[1], x87);
        });
    }

    #[test]
    fn the_caller_keeps_its_control_words() {
        with_floating_point(|| {
            hal::fpu::set_control_words(0x0B7F, 0x5F80);
            run(&WORKLOADS[1]);
            assert_eq!(hal::fpu::control_words(), (0x0B7F, 0x5F80));
        });
    }

    #[test]
    fn the_results_are_distinct_and_inside_the_unit_interval() {
        let values = EXPECTED.as_flattened().iter().map(|&b| f64::from_bits(b));
        assert!(values.clone().all(|v| v > 0.0 && v < 1.0));
        let mut bits = EXPECTED.as_flattened().to_vec();
        bits.sort_unstable();
        bits.dedup();
        assert_eq!(bits.len(), 8);
    }
}
