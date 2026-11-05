//! Les services de USER pour la console de `csrss` (`consrv`), que seul
//! `csrss` peut appeler (`win32ss/user/ntuser/console.c` et `desktop.c` de
//! ReactOS comme spécification) :
//! - NtUserConsoleControl : le thread d'entrée des consoles d'un bureau,
//!   l'atome de la classe des fenêtres console (`win32k::console`) ;
//! - NtUserResolveDesktop : la station et le bureau d'un processus console
//!   (IntResolveDesktop), ouverts dans `csrss`.
//!
//! IntResolveDesktop est `win32k::startup::resolve_desktop` (la conversion
//! d'un thread s'en sert aussi).
//!
//! Pas encore : ConsoleMakePalettePublic (pas de palettes dans GDI), la
//! propriété de l'affichage (ReactOS non plus).

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS, STATUS_NOT_IMPLEMENTED,
    STATUS_SUCCESS,
};
use abi::user::{
    DesktopConsoleThread32, CONSOLE_ACQUIRE_DISPLAY_OWNERSHIP, CONSOLE_CTRL_DESKTOP_CONSOLE_THREAD,
    CONSOLE_MAKE_PALETTE_PUBLIC, GUI_CONSOLE_WND_CLASS_ATOM,
};
use abi::winerror::dos_error;
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, Object};
use ps::eprocess::PROCESS_QUERY_INFORMATION;
use win32k::desktop::{Desktop, DESKTOP_TYPE};

/// Le thread d'entrée est seulement demandé (INVALID_HANDLE_VALUE).
const READ_ONLY: u32 = u32::MAX;

/// Une classe de NtUserConsoleControl demandée sans être faite.
static PALETTE_REPORTED: AtomicBool = AtomicBool::new(false);
static DISPLAY_REPORTED: AtomicBool = AtomicBool::new(false);

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
        let (station, desktop) = win32k::startup::resolve_desktop(&target, &path, inherit != 0)?;
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
