//! `csrss` et le démarrage de USER : NtUserInitialize, que `winsrv` appelle
//! une fois dans `csrss` (UserServerDllInitialization). USER retient alors
//! `csrss` (gpepCSRSS : ses threads GUI sont des threads de `csrss`), garde
//! l'événement des demandes d'alimentation que `csrss` attend, et crée le
//! répertoire des stations de fenêtres de sa session. `csrss` lui donne
//! ensuite son port d'API (NtUserSetInformationThread,
//! `UserThreadCsrApiPort`), par lequel win32k l'appellera (pas encore).
//!
//! Pas encore (M6, 05) : la vidéo (InitVideo, le pilote d'affichage), GDI
//! (DirectX, polices, `InitializeGreCSRSS`), les paramètres système de
//! l'utilisateur et le pinceau gris du `SERVERINFO` ; NtUserInitialize
//! réussit sans eux, pour que le mode console avance (M5).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::bugcheck::BugCheckCode;
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL};
use abi::user::USER_VERSION;
use ex::Event;
use hal::sync::{KSpinLock, Once};
use ob::{Object, ObjectRef};

/// Le PID de `csrss`, une fois qu'il a démarré USER ; 0 avant.
static CSRSS: AtomicU32 = AtomicU32::new(0);
/// L'événement des demandes d'alimentation (gpPowerRequestCalloutEvent).
static POWER_EVENT: Once<Arc<Object<Event>>> = Once::new();
/// Le port d'API de `csrss` (CsrApiPort), une fois donné.
static API_PORT: KSpinLock<Option<ObjectRef>> = KSpinLock::new(None);

/// Le PID de `csrss`, une fois qu'il a démarré USER ; 0 avant.
///
/// # IRQL
/// Tout niveau.
pub fn csrss() -> u32 {
    CSRSS.load(Ordering::Acquire)
}

/// Le répertoire des stations de fenêtres de la session `session`
/// (`\Windows\WindowStations`, ou `\Sessions\N\Windows\WindowStations`).
pub fn window_stations_directory(session: u32) -> String {
    match session {
        0 => String::from("\\Windows\\WindowStations"),
        _ => format!("\\Sessions\\{session}\\Windows\\WindowStations"),
    }
}

/// NtUserInitialize, dans `csrss` : USER retient le processus courant comme
/// `csrss`, puis l'événement que rend `power_event` (le handle de
/// l'appelant, référencé par lui), et crée le répertoire des stations de
/// fenêtres de sa session.
///
/// # Errors
/// `STATUS_UNSUCCESSFUL` si USER a déjà démarré ; celles de `power_event`
/// (`csrss` reste retenu, comme sous ReactOS) et de la création du
/// répertoire ; `STATUS_INVALID_PARAMETER` hors d'un thread de Ps.
///
/// # Panics
/// Arrête le système (`WIN32K_INIT_OR_RIT_FAILURE`) si `version` n'est pas
/// celle de USER.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn initialize(
    version: u32,
    power_event: impl FnOnce() -> Result<Arc<Object<Event>>, NtStatus>,
) -> Result<(), NtStatus> {
    if csrss() != 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }
    if version != USER_VERSION {
        ke::bugcheck::ke_bug_check_with_reason(
            BugCheckCode::WIN32K_INIT_OR_RIT_FAILURE,
            [0, 0, u64::from(version), u64::from(USER_VERSION)],
            &format_args!("NtUserInitialize: USER version {version:#x}, not {USER_VERSION:#x}"),
        );
    }
    let process = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?.process().clone();
    if CSRSS.compare_exchange(0, process.pid(), Ordering::AcqRel, Ordering::Acquire).is_err() {
        return Err(STATUS_UNSUCCESSFUL);
    }
    let event = power_event()?;
    POWER_EVENT.call_once(|| event);
    // InitVideo: the system metrics and colours.
    crate::metrics::write()?;
    let directory: ob::ObjectRef = ob::Directory::create();
    let name = window_stations_directory(process.session_id());
    ob::namespace().insert(&directory, &name, None, abi::object::OBJ_PERMANENT)?;
    Ok(())
}

/// InitCsrApiPort : `port`, un port LPC référencé par `csrss`, devient le
/// port d'API de `csrss` pour win32k ; il remplace le précédent.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn set_api_port(port: ObjectRef) {
    // The previous port goes once the lock is released.
    let previous = API_PORT.lock().replace(port);
    drop(previous);
}

/// Le port d'API de `csrss`, s'il l'a donné.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn api_port() -> Option<ObjectRef> {
    API_PORT.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_session_has_its_window_stations() {
        assert_eq!(window_stations_directory(0), "\\Windows\\WindowStations");
        assert_eq!(window_stations_directory(3), "\\Sessions\\3\\Windows\\WindowStations");
    }
}
