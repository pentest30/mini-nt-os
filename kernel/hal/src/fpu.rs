//! FPU x87 et SSE (ADR-009).
//!
//! L'état d'un thread (zone FXSAVE de 512 octets) est sauvegardé et restauré à
//! chaque commutation (`ke::sched`), sans commutation paresseuse : CR0.TS reste
//! à 0 et #NM ne doit jamais survenir. Le noyau est compilé sans SSE ; un code
//! noyau qui a besoin de la FPU l'encadre (`ke::fpu::with_floating_point`).
//!
//! FXSAVE suffit tant que XCR0 n'active pas AVX : les instructions AVX restent
//! invalides (#UD) et il n'y a pas d'état étendu à sauvegarder. XSAVE viendra
//! avec AVX.

use abi::fpu::{FxSaveArea, INITIAL_FCW, INITIAL_MXCSR};
use core::arch::asm;

/// Active la FPU et SSE sur ce CPU (CR0.MP et NE, ni EM ni TS ; CR4.OSFXSR et
/// OSXMMEXCPT), puis charge l'état initial d'un thread.
///
/// # Safety
/// Une fois par CPU, au démarrage, avant la première commutation.
///
/// # IRQL
/// HIGH_LEVEL (démarrage, interruptions masquées).
pub unsafe fn init() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    // SAFETY: x86-64 garantit x87, FXSR, SSE et SSE2 ; ces bits ne font que
    // les activer, et rien n'utilise encore la FPU.
    unsafe {
        Cr0::update(|f| {
            f.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR);
            f.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
        });
        Cr4::update(|f| f.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE));
    }
    load_initial_state();
}

/// Charge l'état d'un thread neuf : FNINIT (pile x87 vide), puis FCW et MXCSR
/// initiaux. Les registres XMM ne changent pas.
///
/// # IRQL
/// Tout niveau.
pub fn load_initial_state() {
    set_control_words(INITIAL_FCW, INITIAL_MXCSR);
}

/// Sauvegarde l'état x87/SSE du CPU dans `area` (FXSAVE64).
///
/// # Safety
/// `area` est valide en écriture.
///
/// # IRQL
/// Tout niveau.
#[inline]
pub unsafe fn save(area: *mut FxSaveArea) {
    // SAFETY: `area` est valide en écriture (appelant) et alignée sur 16 octets
    // (type) ; FXSAVE64 n'écrit que ses 512 octets.
    unsafe { asm!("fxsave64 [{}]", in(reg) area, options(nostack, preserves_flags)) };
}

/// Restaure l'état x87/SSE du CPU depuis `area` (FXRSTOR64).
///
/// # Safety
/// `area` est une image FXSAVE valide : écrite par [`save`], ou un
/// [`FxSaveArea::initial`] (sinon, des bits réservés de MXCSR lèvent #GP).
///
/// # IRQL
/// Tout niveau.
#[inline]
pub unsafe fn restore(area: *const FxSaveArea) {
    // SAFETY: garanti par l'appelant ; alignée sur 16 octets (type).
    unsafe { asm!("fxrstor64 [{}]", in(reg) area, options(nostack, preserves_flags, readonly)) };
}

/// FCW et MXCSR courants.
///
/// # IRQL
/// Tout niveau.
pub fn control_words() -> (u16, u32) {
    let mut fcw = 0u16;
    let mut mxcsr = 0u32;
    // SAFETY: FNSTCW et STMXCSR n'écrivent que les deux variables locales.
    unsafe {
        asm!(
            "fnstcw [{fcw}]",
            "stmxcsr [{mxcsr}]",
            fcw = in(reg) &mut fcw,
            mxcsr = in(reg) &mut mxcsr,
            options(nostack, preserves_flags),
        )
    };
    (fcw, mxcsr)
}

/// Vide la pile x87 (FNINIT), puis charge `fcw` et `mxcsr`. Le code qui
/// s'exécute ensuite calcule avec ces modes : à n'appeler que dans un
/// encadrement (`ke::fpu::with_floating_point`) ou pour un thread neuf.
///
/// # IRQL
/// Tout niveau.
pub fn set_control_words(fcw: u16, mxcsr: u32) {
    assert_eq!(mxcsr & !0xFFFF, 0, "reserved MXCSR bits");
    // SAFETY: FNINIT, FLDCW et LDMXCSR ne touchent que l'état x87/SSE, et ne lisent
    // que les deux variables locales ; les bits réservés de MXCSR sont à 0.
    unsafe {
        asm!(
            "fninit",
            "fldcw [{fcw}]",
            "ldmxcsr [{mxcsr}]",
            fcw = in(reg) &fcw,
            mxcsr = in(reg) &mxcsr,
            options(nostack, preserves_flags, readonly),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sur l'hôte, comme sur la cible : FXSAVE/FXRSTOR ne sont pas privilégiés.
    #[test]
    fn restore_brings_back_the_saved_control_words() {
        let mut before = FxSaveArea::initial();
        // SAFETY: zone locale, alignée ; image écrite par `save`.
        unsafe { save(&mut before) };
        set_control_words(0x0F7F, 0x7F80);
        assert_eq!(control_words(), (0x0F7F, 0x7F80));
        // SAFETY: image écrite par `save` ci-dessus.
        unsafe { restore(&before) };
        assert_eq!(control_words(), (before.fcw, before.mxcsr));
    }

    #[test]
    fn the_initial_area_loads_the_initial_control_words() {
        let mut before = FxSaveArea::initial();
        // SAFETY: zone locale, alignée.
        unsafe { save(&mut before) };
        set_control_words(0x0F7F, 0x7F80);
        // SAFETY: image initiale valide (MXCSR sans bit réservé).
        unsafe { restore(&FxSaveArea::initial()) };
        assert_eq!(control_words(), (INITIAL_FCW, INITIAL_MXCSR));
        // SAFETY: image écrite par `save`.
        unsafe { restore(&before) };
    }
}
