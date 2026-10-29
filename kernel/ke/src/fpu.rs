//! La FPU dans le noyau (ADR-009). Le noyau est compilé sans SSE : un code
//! noyau qui calcule en flottant (en assembleur) s'encadre de
//! [`with_floating_point`], la paire KeSaveFloatingPointState /
//! KeRestoreFloatingPointState.

use abi::fpu::FxSaveArea;

/// Exécute `f` avec un état x87/SSE propre (pile x87 vide, FCW et MXCSR
/// initiaux), puis rend à l'appelant l'état qu'il avait : par exemple celui du
/// thread utilisateur dont un appel système s'exécute. Préempté pendant `f`, le
/// thread garde son état FPU, comme tout thread (`ke::sched`).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn with_floating_point<R>(f: impl FnOnce() -> R) -> R {
    let mut saved = FxSaveArea::initial();
    // SAFETY: zone locale, valide en écriture.
    unsafe { hal::fpu::save(&mut saved) };
    hal::fpu::load_initial_state();
    let result = f();
    // SAFETY: image écrite par `save` ci-dessus.
    unsafe { hal::fpu::restore(&saved) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::fpu::{INITIAL_FCW, INITIAL_MXCSR};

    #[test]
    fn the_caller_gets_its_state_back_and_the_bracket_starts_clean() {
        let mut host = FxSaveArea::initial();
        // SAFETY: zone locale.
        unsafe { hal::fpu::save(&mut host) };
        hal::fpu::set_control_words(0x0F7F, 0x7F80);
        let inside = with_floating_point(|| {
            let clean = hal::fpu::control_words();
            hal::fpu::set_control_words(0x0B7F, 0x5F80);
            clean
        });
        assert_eq!(inside, (INITIAL_FCW, INITIAL_MXCSR));
        assert_eq!(hal::fpu::control_words(), (0x0F7F, 0x7F80), "the caller's state is back");
        // SAFETY: image écrite par `save`.
        unsafe { hal::fpu::restore(&host) };
    }
}
