//! La fin d'une session et l'arrêt, du côté de USER (`ntuser/shutdown.c` et
//! NtUserSetInformationThread de `ntstubs.c` de ReactOS, comme
//! spécification). ExitWindowsEx passe par `csrss` (SrvExitWindowsEx de
//! `winsrv`), dont le thread se met sur le bureau d'entrée
//! ([`use_active_desktop`]), demande à win32k d'ouvrir la fin
//! ([`initiate`]), ferme les processus de la session, puis le dit à win32k
//! ([`end`]) et quitte le bureau ([`restore_desktop`]).
//!
//! Quand ce n'est pas le processus de logon qui demande, USER vérifie la
//! station et le privilège de l'appelant, puis poste WM_LOGONNOTIFY
//! (LN_LOGOFF et les drapeaux EWX_*) à la fenêtre SAS de `winlogon`
//! ([`crate::logon::sas_window`]), et répond `STATUS_PENDING` : `csrss` en
//! reste là, et c'est `winlogon` qui ferme la session puis arrête le système
//! par son propre ExitWindowsEx (`EWX_CALLER_WINLOGON`), puis
//! NtShutdownSystem. Quand c'est lui, USER garde ses drapeaux, que la fin
//! lui renvoie (LN_LOGOFF, ou LN_LOGOFF_CANCELED et le statut).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_HANDLE, STATUS_PENDING,
    STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS,
};
use abi::user::{
    Msg32, EWX_CALLER_SYSTEM, EWX_CALLER_WINLOGON, EWX_NONOTIFY, EWX_SHUTDOWN, EWX_SHUTDOWN_CANCELED, LN_LOGOFF,
    LN_LOGOFF_CANCELED, WM_LOGONNOTIFY,
};
use ob::{AccessMask, HandleAttributes, Object, ObjectRef};
use ps::eprocess::EProcess;

/// Ce que USER sait de qui demande la fin d'une session : le thread client
/// de `csrss`, et `csrss` lui-même, qui emprunte son identité.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requester {
    /// Son processus est un processus GUI (il a un PROCESSINFO).
    pub gui: bool,
    /// Son processus est le processus de logon (gpidLogon).
    pub logon: bool,
    /// Sa session d'ouverture est celle de LocalSystem (SYSTEM_LUID).
    pub system: bool,
    /// La station de son processus, s'il en a une : le droit
    /// WINSTA_EXITWINDOWS accordé, et si elle est sans entrée ni sortie
    /// (WSS_NOIO).
    pub station: Option<StationRights>,
    /// Le sujet courant (`csrss`, qui emprunte son identité) a
    /// SeShutdownPrivilege actif.
    pub shutdown_privilege: bool,
}

/// La station de qui demande la fin d'une session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StationRights {
    /// WINSTA_EXITWINDOWS accordé à son handle.
    pub exit_windows: bool,
    /// Une station sans entrée ni sortie (WSS_NOIO).
    pub no_io: bool,
}

/// UserInitiateShutdown, sa décision pour les drapeaux EWX_* `flags` : le
/// statut et les drapeaux rendus à `csrss`. `EWX_CALLER_SYSTEM` suit la
/// session de l'appelant ; un autre processus que celui de logon perd
/// `EWX_CALLER_WINLOGON`, doit avoir une station avec WINSTA_EXITWINDOWS,
/// et SeShutdownPrivilege pour un arrêt (`STATUS_PRIVILEGE_NOT_HELD`), une
/// station d'entrée et de sortie pour une fin de session
/// (`STATUS_INVALID_DEVICE_REQUEST`) ; c'est alors à `winlogon` de faire la
/// fin : `STATUS_PENDING`. Le processus de logon reçoit
/// `EWX_CALLER_WINLOGON` et `STATUS_SUCCESS`.
pub fn decide(flags: u32, requester: &Requester) -> (NtStatus, u32) {
    let mut flags = if requester.system { flags | EWX_CALLER_SYSTEM } else { flags & !EWX_CALLER_SYSTEM };
    if !requester.gui {
        return (STATUS_INVALID_HANDLE, flags);
    }
    if requester.logon {
        return (STATUS_SUCCESS, flags | EWX_CALLER_WINLOGON);
    }
    flags &= !EWX_CALLER_WINLOGON;
    let Some(station) = requester.station else { return (STATUS_INVALID_HANDLE, flags) };
    if !station.exit_windows {
        return (STATUS_ACCESS_DENIED, flags);
    }
    if flags & EWX_SHUTDOWN != 0 {
        if !requester.shutdown_privilege {
            return (STATUS_PRIVILEGE_NOT_HELD, flags);
        }
    } else if station.no_io {
        return (STATUS_INVALID_DEVICE_REQUEST, flags);
    }
    (STATUS_PENDING, flags)
}

/// NotifyLogon, le message : le wParam et le lParam du WM_LOGONNOTIFY que
/// reçoit `winlogon` pour les drapeaux `flags` et le statut `status` de la
/// fin — LN_LOGOFF et les drapeaux, ou LN_LOGOFF_CANCELED et le statut si
/// la fin est annulée ; `None` avec `EWX_NONOTIFY`.
pub fn logon_notification(flags: u32, status: NtStatus) -> Option<(u32, u32)> {
    if flags & EWX_NONOTIFY != 0 {
        return None;
    }
    Some(if flags & EWX_SHUTDOWN_CANCELED != 0 { (LN_LOGOFF_CANCELED, status.0) } else { (LN_LOGOFF, flags) })
}

/// Les drapeaux de la fin que fait `winlogon` (gdwShutdownFlags).
static SHUTDOWN_FLAGS: AtomicU32 = AtomicU32::new(0);

/// UserInitiateShutdown : la décision ([`decide`]) pour `requester` ; un
/// autre processus que celui de logon le fait savoir à `winlogon`, celui de
/// logon voit ses drapeaux gardés pour [`end`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn initiate(flags: u32, requester: &Requester) -> (NtStatus, u32) {
    let (status, flags) = decide(flags, requester);
    if status == STATUS_PENDING {
        notify_logon(flags, STATUS_SUCCESS);
    } else if status == STATUS_SUCCESS {
        SHUTDOWN_FLAGS.store(flags, Ordering::Release);
    }
    (status, flags)
}

/// UserEndShutdown : la fin est faite, avec le statut `status` ; `winlogon`
/// reçoit les drapeaux gardés, avec `EWX_SHUTDOWN_CANCELED` si elle a
/// échoué.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn end(status: NtStatus) {
    let mut flags = SHUTDOWN_FLAGS.load(Ordering::Acquire);
    let status = if status.is_success() {
        STATUS_SUCCESS
    } else {
        flags |= EWX_SHUTDOWN_CANCELED;
        status
    };
    notify_logon(flags, status);
}

/// NotifyLogon : WM_LOGONNOTIFY posté à la fenêtre SAS, s'il y en a une.
fn notify_logon(flags: u32, status: NtStatus) {
    let Some((w_param, l_param)) = logon_notification(flags, status) else { return };
    let hwnd = crate::logon::sas_window();
    let Some(window) = crate::window::get(hwnd) else {
        log::warn!("win32k: no SAS window to tell of the end of the session");
        return;
    };
    if let Some(thread) = crate::gui::thread_info_of(window.pti) {
        let time = hal::timer::get_tick_count() as u32;
        crate::queue::post(
            &thread,
            Msg32 { hwnd, message: WM_LOGONNOTIFY, w_param, l_param, time, ..Msg32::default() },
        );
    }
}

/// UserThreadUseActiveDesktop : le thread courant (de `csrss`, `process`)
/// va sur le bureau d'entrée, par un handle de son processus
/// (IntGetDesktopObjectHandle : le premier qu'il a sur lui, ou un handle
/// ouvert sans droit) ; rien sans bureau d'entrée.
///
/// # Errors
/// Celles de la table des handles et de [`crate::gui::set_thread_desktop`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
pub fn use_active_desktop(process: &Arc<Object<EProcess>>) -> Result<(), NtStatus> {
    let Some(desktop) = crate::desktop::input_desktop() else { return Ok(()) };
    let object: ObjectRef = desktop.clone();
    let table = &process.handle_table;
    let handle = match table.find_object(&object) {
        Some(handle) => handle,
        None => table.insert(object, AccessMask::NONE, HandleAttributes::default())?,
    };
    crate::gui::set_thread_desktop(handle.0, Some(desktop))
}

/// UserThreadRestoreDesktop : le thread courant quitte son bureau.
///
/// # Errors
/// Celles de [`crate::gui::set_thread_desktop`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
pub fn restore_desktop() -> Result<(), NtStatus> {
    crate::gui::set_thread_desktop(0, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::{EWX_FORCE, EWX_LOGOFF, EWX_POWEROFF};

    fn user() -> Requester {
        Requester {
            gui: true,
            logon: false,
            system: false,
            station: Some(StationRights { exit_windows: true, no_io: false }),
            shutdown_privilege: true,
        }
    }

    #[test]
    fn a_session_program_asks_winlogon() {
        let power_off = EWX_SHUTDOWN | EWX_POWEROFF;
        assert_eq!(decide(power_off, &user()), (STATUS_PENDING, power_off), "winlogon does it");
        let spoofed = power_off | EWX_CALLER_WINLOGON | EWX_CALLER_SYSTEM;
        assert_eq!(decide(spoofed, &user()), (STATUS_PENDING, power_off), "the caller flags are not its to give");
        let without = Requester { shutdown_privilege: false, ..user() };
        assert_eq!(decide(power_off, &without), (STATUS_PRIVILEGE_NOT_HELD, power_off));
        assert_eq!(decide(EWX_LOGOFF, &without), (STATUS_PENDING, EWX_LOGOFF), "a logoff needs no privilege");
        let no_io = Requester { station: Some(StationRights { exit_windows: true, no_io: true }), ..user() };
        assert_eq!(decide(EWX_LOGOFF, &no_io), (STATUS_INVALID_DEVICE_REQUEST, EWX_LOGOFF));
        assert_eq!(decide(power_off, &no_io), (STATUS_PENDING, power_off), "a shutdown from a service's station");
        let denied = Requester { station: Some(StationRights { exit_windows: false, no_io: false }), ..user() };
        assert_eq!(decide(EWX_LOGOFF, &denied).0, STATUS_ACCESS_DENIED);
        assert_eq!(decide(EWX_LOGOFF, &Requester { station: None, ..user() }).0, STATUS_INVALID_HANDLE);
        assert_eq!(decide(EWX_LOGOFF, &Requester { gui: false, ..user() }).0, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn winlogon_does_the_end() {
        let winlogon = Requester { logon: true, system: true, station: None, shutdown_privilege: false, ..user() };
        let flags = EWX_SHUTDOWN | EWX_FORCE | EWX_POWEROFF;
        assert_eq!(decide(flags, &winlogon), (STATUS_SUCCESS, flags | EWX_CALLER_WINLOGON | EWX_CALLER_SYSTEM));
        let impersonating = Requester { system: false, ..winlogon };
        assert_eq!(decide(EWX_LOGOFF, &impersonating), (STATUS_SUCCESS, EWX_CALLER_WINLOGON), "the user's logoff");
    }

    #[test]
    fn winlogon_is_told_of_the_end() {
        let flags = EWX_CALLER_WINLOGON | EWX_SHUTDOWN | EWX_POWEROFF;
        assert_eq!(logon_notification(flags, STATUS_SUCCESS), Some((LN_LOGOFF, flags)));
        let canceled = logon_notification(flags | EWX_SHUTDOWN_CANCELED, STATUS_ACCESS_DENIED);
        assert_eq!(canceled, Some((LN_LOGOFF_CANCELED, STATUS_ACCESS_DENIED.0)), "the status, not the flags");
        assert_eq!(logon_notification(flags | EWX_NONOTIFY, STATUS_SUCCESS), None);
    }
}
