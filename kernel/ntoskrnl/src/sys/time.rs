//! Les services du temps : le temps système et le compteur de performance
//! (`hal::rtc`, `hal::timer`).

use core::sync::atomic::Ordering;

use abi::ntstatus::{NtStatus, STATUS_SUCCESS, STATUS_TIMER_RESOLUTION_NOT_SET};

/// Écrit le LARGE_INTEGER `value` en `at`, sondé (aligné sur 4 octets).
fn give(at: u32, value: u64) -> Result<(), NtStatus> {
    ke::usermem::probe_for_write(u64::from(at), 8, 4)?;
    ke::usermem::copy_to_user(u64::from(at), &value.to_le_bytes())
}

/// NtQuerySystemTime(*SystemTime) : le temps système (KeQuerySystemTime),
/// en 100 ns depuis 1601, UTC.
pub(super) fn nt_query_system_time(arguments: &[u32]) -> NtStatus {
    give(arguments[0], hal::rtc::system_time()).map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtQueryPerformanceCounter(*PerformanceCounter, *PerformanceFrequency) :
/// le compteur de performance, et sa fréquence si elle est demandée (le
/// compteur de temps du processeur, `hal::timer::performance_counter`).
pub(super) fn nt_query_performance_counter(arguments: &[u32]) -> NtStatus {
    let (counter, frequency) = hal::timer::performance_counter();
    let give_both = || {
        give(arguments[0], counter)?;
        if arguments[1] != 0 {
            give(arguments[1], frequency)?;
        }
        Ok(STATUS_SUCCESS)
    };
    give_both().unwrap_or_else(|status| status)
}

/// Écrit les trois ULONG demandés (chacun peut être omis — NT l'accepte).
fn give_ulongs(at: [u32; 3], values: [u32; 3]) -> Result<(), NtStatus> {
    for (at, value) in at.iter().zip(values) {
        if *at != 0 {
            ke::usermem::probe_for_write(u64::from(*at), 4, 4)?;
            ke::usermem::copy_to_user(u64::from(*at), &value.to_le_bytes())?;
        }
    }
    Ok(())
}

/// NtQueryTimerResolution(*Minimum, *Maximum, *Current) : les bornes et la
/// valeur courante de la résolution du temporisateur, en 100 ns. Chez Mino
/// le temporisateur est fixe : les trois rendent son intervalle (les
/// bornes «_minimum ≥ maximum» de NT s'inversent avec la résolution — un
/// temporisateur fixe les rend égales).
pub(super) fn nt_query_timer_resolution(arguments: &[u32]) -> NtStatus {
    let current = hal::timer::TICK_INTERVAL_100NS.load(Ordering::Relaxed) as u32;
    give_ulongs([arguments[0], arguments[1], arguments[2]], [current, current, current])
        .map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// NtSetTimerResolution(RequestedResolution, Set, *ActualResolution) : la
/// résolution demandée est **ignorée** — le temporisateur de Mino est fixe
/// (son intervalle rend). `Set` pose la résolution du processus ; sans en
/// avoir posé, la demande rend `STATUS_TIMER_RESOLUTION_NOT_SET`, et la
/// première après en avoir posé rend `STATUS_SUCCESS` en la retirant (ce
/// que NT rend, et que les apitests vérifient).
pub(super) fn nt_set_timer_resolution(arguments: &[u32]) -> NtStatus {
    let (set, actual) = (arguments[1] != 0, arguments[2]);
    let interval = hal::timer::TICK_INTERVAL_100NS.load(Ordering::Relaxed) as u32;
    if actual != 0 {
        if let Err(status) = give_ulongs([actual, 0, 0], [interval, 0, 0]) {
            return status;
        }
    }
    let process = ps::ethread::current_thread().map(|thread| thread.process().clone());
    let Some(process) = process else { return STATUS_TIMER_RESOLUTION_NOT_SET };
    if set {
        process.set_timer_resolution(true);
        return STATUS_SUCCESS;
    }
    if process.timer_resolution_set() {
        process.set_timer_resolution(false);
        STATUS_SUCCESS
    } else {
        STATUS_TIMER_RESOLUTION_NOT_SET
    }
}
