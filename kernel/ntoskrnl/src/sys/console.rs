//! Les services de USER pour la console de `csrss` (`consrv`), que seul
//! `csrss` peut appeler (`win32ss/user/ntuser/console.c` et `desktop.c` de
//! ReactOS comme spécification) :
//! - NtUserConsoleControl : le thread d'entrée des consoles d'un bureau,
//!   l'atome de la classe des fenêtres console (`win32k::console`) ;
//! - NtUserResolveDesktop : la station et le bureau d'un processus console
//!   (IntResolveDesktop), ouverts dans `csrss`.
//!
//! Pas encore : ConsoleMakePalettePublic (pas de palettes dans GDI), la
//! propriété de l'affichage (ReactOS non plus), et, pour NtUserResolveDesktop,
//! la station par défaut d'un chemin qui n'en nomme pas (une station
//! héritée, ou celle des services, `Service-0x0-3e7$`, que crée ReactOS pour
//! un processus de System) : `STATUS_NOT_IMPLEMENTED`, journalisé une fois.

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS, STATUS_NOT_IMPLEMENTED,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use abi::object::{OBJ_CASE_INSENSITIVE, OBJ_INHERIT};
use abi::security::SYSTEM_LUID;
use abi::user::{
    DesktopConsoleThread32, CONSOLE_ACQUIRE_DISPLAY_OWNERSHIP, CONSOLE_CTRL_DESKTOP_CONSOLE_THREAD,
    CONSOLE_MAKE_PALETTE_PUBLIC, GUI_CONSOLE_WND_CLASS_ATOM,
};
use abi::winerror::dos_error;
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, HandleAttributes, Object};
use ps::eprocess::PROCESS_QUERY_INFORMATION;
use win32k::desktop::{Desktop, DESKTOP_TYPE};
use win32k::winsta::{WindowStation, WINDOW_STATION_TYPE};

/// Le thread d'entrée est seulement demandé (INVALID_HANDLE_VALUE).
const READ_ONLY: u32 = u32::MAX;

/// Une classe de NtUserConsoleControl, ou la station par défaut de
/// NtUserResolveDesktop, demandée sans être faite.
static PALETTE_REPORTED: AtomicBool = AtomicBool::new(false);
static DISPLAY_REPORTED: AtomicBool = AtomicBool::new(false);
static DEFAULT_STATION_REPORTED: AtomicBool = AtomicBool::new(false);

fn not_implemented(reported: &AtomicBool, what: &str) -> NtStatus {
    if !reported.swap(true, Ordering::Relaxed) {
        log::warn!("sys: {what} is not implemented");
    }
    STATUS_NOT_IMPLEMENTED
}

/// L'appelant est `csrss`.
fn called_by_csrss() -> bool {
    super::current_process().pid() == win32k::csrss::csrss()
}

/// Le bureau que désigne `handle` dans le processus courant, sans droit
/// demandé.
fn reference_desktop(handle: u32) -> Result<Arc<Object<Desktop>>, NtStatus> {
    super::current_process().handle_table.reference_as::<Desktop>(Handle(handle), &DESKTOP_TYPE, AccessMask::NONE)
}

/// NtUserConsoleControl(ConsoleCtrl, ConsoleCtrlInfo, ConsoleCtrlInfoLength) :
/// - ConsoleCtrlDesktopConsoleThread (DESKTOP_CONSOLE_THREAD, 8 octets) : le
///   thread d'entrée des consoles du bureau devient celui donné, sauf
///   INVALID_HANDLE_VALUE ; celui d'avant est rendu à sa place ;
/// - GuiConsoleWndClassAtom (un ATOM, 2 octets) : l'atome de la classe des
///   fenêtres console.
///
/// `STATUS_ACCESS_DENIED` hors de `csrss`, `STATUS_INFO_LENGTH_MISMATCH` pour
/// une autre taille, `STATUS_INVALID_INFO_CLASS` pour une classe inconnue.
pub(super) fn nt_user_console_control(arguments: &[u32]) -> NtStatus {
    let [control, info, length] = arguments[..3] else { unreachable!("3 arguments") };
    if !called_by_csrss() {
        return STATUS_ACCESS_DENIED;
    }
    let control = || match control {
        CONSOLE_CTRL_DESKTOP_CONSOLE_THREAD => {
            if length as usize != core::mem::size_of::<DesktopConsoleThread32>() {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            }
            let at = UserPtr::<DesktopConsoleThread32>::new(info);
            ke::usermem::probe_for_write(u64::from(info), length as usize, 2)?;
            let mut asked = at.read()?;
            let desktop = reference_desktop(asked.desktop_handle)?;
            asked.thread_id =
                desktop.exchange_console_thread((asked.thread_id != READ_ONLY).then_some(asked.thread_id));
            at.write(&asked)?;
            Ok(STATUS_SUCCESS)
        }
        GUI_CONSOLE_WND_CLASS_ATOM => {
            if length != 2 {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            }
            win32k::console::set_console_window_class(UserPtr::<u16>::new(info).read()?);
            Ok(STATUS_SUCCESS)
        }
        CONSOLE_MAKE_PALETTE_PUBLIC => {
            Err(not_implemented(&PALETTE_REPORTED, "NtUserConsoleControl(ConsoleMakePalettePublic)"))
        }
        CONSOLE_ACQUIRE_DISPLAY_OWNERSHIP => {
            Err(not_implemented(&DISPLAY_REPORTED, "NtUserConsoleControl(ConsoleAcquireDisplayOwnership)"))
        }
        _ => Err(STATUS_INVALID_INFO_CLASS),
    };
    control().unwrap_or_else(|status| status)
}

/// NtUserResolveDesktop(ProcessHandle, DesktopPath, bInherit, *phWinSta) :
/// la station et le bureau où va le processus (`PROCESS_QUERY_INFORMATION`),
/// ouverts dans `csrss` (avec `OBJ_INHERIT` si `bInherit`) : le handle du
/// bureau est rendu, celui de la station écrit en `phWinSta`.
///
/// Un processus GUI qui a déjà sa station et son bureau de démarrage les
/// garde ; sinon le chemin dit `Station\Bureau` (le bureau seul, ou rien :
/// `Default`). La station interactive (WinSta0) n'est donnée qu'à un
/// processus de la session d'ouverture de System ou de celle de son
/// utilisateur.
///
/// Rend 0 hors de `csrss` et en cas d'échec (avec la dernière erreur).
pub(super) fn nt_user_resolve_desktop(arguments: &[u32]) -> NtStatus {
    let [process, path, inherit, out_station] = arguments[..4] else { unreachable!("4 arguments") };
    if !called_by_csrss() {
        return NtStatus(0);
    }
    let resolve = || {
        let target = super::reference_process(process, PROCESS_QUERY_INFORMATION)?;
        ke::usermem::probe_for_write(u64::from(out_station), 4, 4)?;
        let path = String::from_utf16_lossy(&super::object::capture_unicode_string(path)?);
        let (station, desktop) = resolve_desktop(&target, &path, inherit != 0)?;
        if let Err(fault) = UserPtr::<u32>::new(out_station).write(&station.0) {
            let table = &super::current_process().handle_table;
            let _ = table.close(desktop);
            let _ = table.close(station);
            return Err(fault);
        }
        Ok(desktop.0)
    };
    NtStatus(resolve().unwrap_or_else(|status| {
        let _ = win32k::set_last_error(dos_error(status));
        0
    }))
}

/// IntResolveDesktop : les handles, dans le processus courant, de la station
/// et du bureau de `target` d'après `path`.
fn resolve_desktop(
    target: &Arc<Object<ps::EProcess>>,
    path: &str,
    inherit: bool,
) -> Result<(Handle, Handle), NtStatus> {
    let current = super::current_process();
    let table = &current.handle_table;
    let attributes = HandleAttributes { inherit, protect_from_close: false };
    if let Some(info) = win32k::existing_process_info(target) {
        if let (Some(station), Some((desktop_handle, desktop))) = (info.window_station(), info.startup_desktop()) {
            if Arc::ptr_eq(target, &current) {
                return Ok((Handle(station.handle), Handle(desktop_handle)));
            }
            let no_inherit = HandleAttributes { inherit: false, protect_from_close: false };
            let station = table.insert(station.station, AccessMask::MAXIMUM_ALLOWED, no_inherit)?;
            return match table.insert(desktop, AccessMask::MAXIMUM_ALLOWED, no_inherit) {
                Ok(desktop) => Ok((station, desktop)),
                Err(status) => {
                    let _ = table.close(station);
                    Err(status)
                }
            };
        }
    }
    let (station_name, desktop_name) = match path.split_once('\\') {
        Some((station, desktop)) if !station.is_empty() => (station, desktop),
        _ => return Err(not_implemented(&DEFAULT_STATION_REPORTED, "NtUserResolveDesktop without a window station")),
    };
    let desktop_name = if desktop_name.is_empty() { "Default" } else { desktop_name };
    let name = alloc::format!("{}\\{station_name}", win32k::csrss::window_stations_directory(current.session_id()));
    let flags = OBJ_CASE_INSENSITIVE | if inherit { OBJ_INHERIT } else { 0 };
    let object = ob::namespace().open(&name, None, Some(&WINDOW_STATION_TYPE), flags)?;
    let station = ob::downcast::<WindowStation>(&object).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    if station_name.eq_ignore_ascii_case("WinSta0") {
        let luid = target.primary_token().authentication_id().to_abi();
        let user = station.user().luid;
        if luid != SYSTEM_LUID && luid != user {
            return Err(STATUS_ACCESS_DENIED);
        }
    }
    let desktop = win32k::desktop::find(&station, desktop_name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let station = table.insert(station, AccessMask::MAXIMUM_ALLOWED, attributes)?;
    match table.insert(desktop, AccessMask::MAXIMUM_ALLOWED, attributes) {
        Ok(desktop) => Ok((station, desktop)),
        Err(status) => {
            let _ = table.close(station);
            Err(status)
        }
    }
}
