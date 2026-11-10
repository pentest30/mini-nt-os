//! Les services du temps : le temps système et le compteur de performance
//! (`hal::rtc`, `hal::timer`).

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};

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
