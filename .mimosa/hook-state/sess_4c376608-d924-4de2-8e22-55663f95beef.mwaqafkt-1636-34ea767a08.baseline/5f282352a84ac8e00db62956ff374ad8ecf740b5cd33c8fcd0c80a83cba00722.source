//! Le processus de logon (`winlogon`) : USER retient celui qui s'inscrit
//! (RegisterLogonProcess, par NtUserCallTwoParam) ; c'est lui qui crée la
//! station de fenêtres interactive.
//!
//! Pas encore : l'oubli du processus de logon à sa fin (le rappel de sortie
//! d'un processus GUI n'existe pas encore).

use core::sync::atomic::{AtomicU32, Ordering};

use abi::winerror::ERROR_INVALID_PARAMETER;

/// Le PID du processus de logon ; 0 sans lui (gpidLogon).
static LOGON_PROCESS: AtomicU32 = AtomicU32::new(0);

/// Le PID du processus de logon ; 0 sans lui.
///
/// # IRQL
/// Tout niveau.
pub fn logon_process() -> u32 {
    LOGON_PROCESS.load(Ordering::Acquire)
}

/// Ce que décide l'inscription (`register`) ou la désinscription du
/// processus `pid` quand le processus de logon est `current` : le nouveau
/// processus de logon, ou `None` si c'est refusé (un autre est déjà inscrit,
/// ou `pid` ne l'est pas).
pub const fn registration(current: u32, pid: u32, register: bool) -> Option<u32> {
    match (register, current) {
        (true, 0) => Some(pid),
        (true, _) => None,
        (false, current) if current == pid => Some(0),
        (false, _) => None,
    }
}

/// co_IntRegisterLogonProcess : inscrit le processus `pid` comme processus
/// de logon (`register`), ou le désinscrit. FALSE si `pid` ne désigne aucun
/// processus vivant (dernière erreur : `ERROR_INVALID_PARAMETER`), si un
/// autre processus est déjà inscrit, ou si `pid` n'est pas celui qui l'est.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un thread GUI.
pub fn register_logon_process(pid: u32, register: bool) -> bool {
    if ps::eprocess::lookup_process(pid).is_err() {
        let _ = crate::set_last_error(ERROR_INVALID_PARAMETER);
        return false;
    }
    let current = LOGON_PROCESS.load(Ordering::Acquire);
    match registration(current, pid, register) {
        Some(next) => LOGON_PROCESS.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire).is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_logon_process_at_a_time() {
        assert_eq!(registration(0, 28, true), Some(28), "the first");
        assert_eq!(registration(28, 32, true), None, "another while one is registered");
        assert_eq!(registration(28, 28, true), None, "itself again");
        assert_eq!(registration(28, 28, false), Some(0), "it leaves");
        assert_eq!(registration(28, 32, false), None, "only it can leave");
        assert_eq!(registration(0, 28, false), None, "none registered");
    }
}
