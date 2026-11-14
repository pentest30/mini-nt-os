//! Le bureau où va un processus (`desktop.c` et `main.c` de ReactOS, comme
//! spécification) : IntResolveDesktop ([`resolve_desktop`], pour
//! NtUserResolveDesktop de `csrss` et pour la conversion d'un thread), et, à
//! la conversion d'un thread client en thread GUI (InitThreadCallback), la
//! station et le bureau de démarrage de son processus pris de ses
//! paramètres (`DesktopInfo`, ce que CreateProcess tient de `lpDesktop`),
//! puis le thread placé sur ce bureau ([`assign_startup_desktop`]).
//!
//! Un chemin qui ne nomme pas de station (`Default`, ce que `msgina` donne
//! à `userinit`, puis `explorer`) prend la station héritée du processus ou
//! WinSta0 ([`default_station`]). Pas encore, journalisé une fois : la
//! station des services (`Service-0x…$`, que crée ReactOS pour un processus
//! sans accès à WinSta0 ni station héritée) ; le thread converti reste alors
//! sans bureau (ReactOS fait échouer la conversion). Un chemin sans bureau
//! prend `Default`, pas encore le bureau hérité.

use alloc::string::String;
use alloc::sync::Arc;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_OBJECT_NAME_NOT_FOUND,
};
use abi::object::{OBJ_CASE_INSENSITIVE, OBJ_INHERIT, OBJ_OPENIF};
use abi::peb32::Peb32;
use abi::process_parameters::RtlUserProcessParameters32;
use abi::security::SYSTEM_LUID;
use ke::usermem::{copy_from_user, UserPtr};
use ob::{AccessMask, Handle, HandleAttributes, Object};
use ps::EProcess;

use crate::desktop::{Desktop, DESKTOP_TYPE};
use crate::gui::{ProcessInfo, ProcessWindowStation};
use crate::winsta::{WindowStation, WINDOW_STATION_TYPE};

/// STARTF_INHERITDESKTOP (ReactOS) : le bureau vient du processus parent.
pub const STARTF_INHERITDESKTOP: u32 = 0x4000_0000;

/// La station d'un chemin qui n'en nomme pas (IntResolveDesktop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultStation {
    /// La station héritée par le processus (un handle dans sa table).
    Inherited,
    /// La station interactive, WinSta0.
    Interactive,
    /// La station des services de son ouverture de session (`Service-0x…$`).
    Service,
    /// Aucune : une station héritée interactive sans accès à WinSta0.
    Refused,
}

/// IntResolveDesktop, pour un chemin sans station : la station héritée
/// (`inherited` : son interactivité, `!WSS_NOIO`, s'il y en a une) est
/// gardée si elle est interactive autant que le processus a accès à
/// WinSta0 (`winsta0_allowed`) ; sinon WinSta0 s'il y a accès ; sinon la
/// station des services, faute de station héritée.
pub fn default_station(inherited: Option<bool>, winsta0_allowed: bool) -> DefaultStation {
    let interactive = inherited == Some(true);
    if interactive == winsta0_allowed {
        if inherited.is_some() {
            DefaultStation::Inherited
        } else {
            DefaultStation::Service
        }
    } else if winsta0_allowed {
        DefaultStation::Interactive
    } else {
        DefaultStation::Refused
    }
}

/// Le processus courant.
fn current_process() -> Result<Arc<Object<EProcess>>, NtStatus> {
    Ok(ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?.process().clone())
}

/// IntResolveDesktop : les handles, dans le processus courant, de la station
/// et du bureau de `target` d'après `path`. Un processus GUI qui a déjà sa
/// station et son bureau de démarrage les garde ; sinon `path` dit
/// `Station\Bureau` (le bureau seul, ou rien : `Default`). La station
/// interactive (WinSta0) ne va qu'à un processus de la session d'ouverture
/// de son utilisateur, ou de celle de System quand le chemin la nomme ou
/// que les handles sont hérités (`inherit`). Sans station dans le chemin :
/// [`default_station`], la station héritée cherchée dans la table de
/// `target` (ObFindHandleForObject).
///
/// # Errors
/// `STATUS_NOT_IMPLEMENTED` pour la station des services (journalisé une
/// fois) ; `STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_ACCESS_DENIED` ; celles
/// de la table des handles.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn resolve_desktop(
    target: &Arc<Object<ps::EProcess>>,
    path: &str,
    inherit: bool,
) -> Result<(Handle, Handle), NtStatus> {
    let current = current_process()?;
    let table = &current.handle_table;
    let attributes = HandleAttributes { inherit, protect_from_close: false };
    if let Some(info) = crate::existing_process_info(target) {
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
        Some((station, desktop)) if !station.is_empty() => (Some(station), desktop),
        Some((_, desktop)) => (None, desktop),
        None => (None, path),
    };
    let desktop_name = if desktop_name.is_empty() { "Default" } else { desktop_name };
    let luid = target.primary_token().authentication_id().to_abi();
    let open_station = |name: &str| -> Result<Arc<Object<WindowStation>>, NtStatus> {
        let name = alloc::format!("{}\\{name}", crate::csrss::window_stations_directory(current.session_id()));
        let flags = OBJ_CASE_INSENSITIVE | if inherit { OBJ_INHERIT } else { 0 };
        let object = ob::namespace().open(&name, None, Some(&WINDOW_STATION_TYPE), flags)?;
        ob::downcast::<WindowStation>(&object).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    };
    let station = match station_name {
        Some(station_name) => {
            let station = open_station(station_name)?;
            if station_name.eq_ignore_ascii_case("WinSta0") {
                let user = station.user().luid;
                if luid != SYSTEM_LUID && luid != user {
                    return Err(STATUS_ACCESS_DENIED);
                }
            }
            station
        }
        None => {
            let inherited = target
                .handle_table
                .find_by_type(&WINDOW_STATION_TYPE)
                .and_then(|(_, object)| ob::downcast::<WindowStation>(&object));
            let winsta0 = open_station("WinSta0").ok();
            let allowed =
                winsta0.as_ref().is_some_and(|station| luid == station.user().luid || (inherit && luid == SYSTEM_LUID));
            match (default_station(inherited.as_ref().map(|station| !station.no_io()), allowed), inherited, winsta0) {
                (DefaultStation::Inherited, Some(station), _) | (DefaultStation::Interactive, _, Some(station)) => {
                    station
                }
                (DefaultStation::Refused, ..) => return Err(STATUS_ACCESS_DENIED),
                _ => {
                    static REPORTED: AtomicBool = AtomicBool::new(false);
                    if !REPORTED.swap(true, Ordering::Relaxed) {
                        log::warn!("win32k: the service window station of a logon session (Service-0x…$): not yet");
                    }
                    return Err(STATUS_NOT_IMPLEMENTED);
                }
            }
        }
    };
    let desktop = crate::desktop::find(&station, desktop_name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let station = table.insert(station, AccessMask::MAXIMUM_ALLOWED, attributes)?;
    match table.insert(desktop, AccessMask::MAXIMUM_ALLOWED, attributes) {
        Ok(desktop) => Ok((station, desktop)),
        Err(status) => {
            let _ = table.close(station);
            Err(status)
        }
    }
}

/// Le bureau que demandent les paramètres du processus courant
/// (`DesktopInfo`, et `STARTF_INHERITDESKTOP` de `WindowFlags`).
fn desktop_info(process: &EProcess) -> Result<(String, bool), NtStatus> {
    let parameters = UserPtr::<u32>::new(process.peb() + offset_of!(Peb32, process_parameters) as u32).read()?;
    let field = |offset: usize| UserPtr::<u32>::new(parameters + offset as u32).read();
    let flags = field(offset_of!(RtlUserProcessParameters32, window_flags))?;
    let at = offset_of!(RtlUserProcessParameters32, desktop_info);
    let length = field(at)? & 0xFFFF;
    let buffer = field(at + 4)?;
    let mut bytes = alloc::vec![0u8; (length & !1) as usize];
    if !bytes.is_empty() {
        copy_from_user(&mut bytes, u64::from(buffer))?;
    }
    let units: alloc::vec::Vec<u16> =
        bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
    Ok((String::from_utf16_lossy(&units), flags & STARTF_INHERITDESKTOP != 0))
}

/// InitThreadCallback, pour un thread client qui devient un thread GUI : un
/// processus sans bureau de démarrage, une fois la station interactive
/// créée, reçoit la station et le bureau de ses paramètres
/// ([`resolve_desktop`] ; UserSetProcessWindowStation) ; puis le thread va
/// sur le bureau de démarrage de son processus, s'il en a un.
///
/// # Errors
/// Celles de [`resolve_desktop`] (le thread reste sans bureau) et de
/// [`crate::gui::set_thread_desktop`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread qui se convertit.
pub fn assign_startup_desktop(process: &Arc<Object<EProcess>>, info: &ProcessInfo) -> Result<(), NtStatus> {
    if info.startup_desktop().is_none() {
        if crate::winsta::input_window_station().is_none() {
            return Ok(());
        }
        let (path, inherit) = desktop_info(process)?;
        let (station, desktop) = resolve_desktop(process, &path, inherit)?;
        let table = &process.handle_table;
        let station_object = table.reference_as::<WindowStation>(station, &WINDOW_STATION_TYPE, AccessMask::NONE)?;
        let (access, _) = table.query(station)?;
        info.set_window_station(Some(ProcessWindowStation { handle: station.0, station: station_object, access }));
        let desktop_object = table.reference_as::<Desktop>(desktop, &DESKTOP_TYPE, AccessMask::NONE)?;
        return crate::gui::set_thread_desktop(desktop.0, Some(desktop_object));
    }
    match info.startup_desktop() {
        Some((handle, desktop)) => crate::gui::set_thread_desktop(handle, Some(desktop)),
        None => Ok(()),
    }
}

/// Comme le SwitchDesktop de winlogon : le bureau Default que le noyau vient
/// de créer pour le shell de session prend l'écran (sa fenêtre montrée et
/// peinte) ; sans quoi l'écran du démarrage resterait, et les fenêtres du
/// shell n'y paraîtraient pas.
fn take_the_screen(desktop: &Arc<Object<Desktop>>, process: &EProcess) {
    if !crate::desktop::switch_to(desktop, process.session_id()) {
        log::warn!("win32k: the session shell's desktop did not take the screen");
    }
}

/// Le bureau d'une fenêtre sans bureau : le shell de session (taskmgr, la
/// première application, démarrant comme winlogon) ne crée ni la station
/// interactive ni son bureau Default — le vrai winlogon le fait avant de
/// lancer qui que ce soit, et ne passe pas ici : sa station, il la crée
/// avant sa première fenêtre. Le noyau crée WinSta0 et Default s'il le
/// faut — sans prendre l'enregistrement du processus de logon, qui reste
/// au winlogon d'une vraie session — puis le thread les prend, et rend le
/// bureau. Le bureau Default qu'il crée prend l'écran ([`take_the_screen`]).
///
/// # IRQL
/// PASSIVE_LEVEL, dans le service de création d'une fenêtre, sans rien
/// tenir.
pub fn session_desktop(process: &Arc<Object<EProcess>>) -> Result<Arc<Object<Desktop>>, NtStatus> {
    match crate::winsta::input_window_station() {
        Some(station) => {
            if crate::desktop::find(&station, "Default").is_none() {
                let desktop = crate::desktop::create(&station, "Default")?;
                take_the_screen(&desktop, process);
                // L'Arc lâché tuerait le bureau que la station garde par un
                // Weak : il vit pour le reste de la session.
                core::mem::forget(desktop);
            }
        }
        None => {
            let station = crate::winsta::create(process.session_id());
            let object: ob::ObjectRef = station.clone();
            let directory = ob::namespace().open(
                &crate::csrss::window_stations_directory(process.session_id()),
                None,
                None,
                OBJ_CASE_INSENSITIVE,
            )?;
            let (_handle, status) = ob::insert_object(
                ob::namespace(),
                object,
                Some("WinSta0"),
                Some(&directory),
                OBJ_OPENIF | OBJ_CASE_INSENSITIVE,
                &process.handle_table,
                AccessMask::MAXIMUM_ALLOWED,
            )?;
            if status != abi::ntstatus::STATUS_OBJECT_NAME_EXISTS {
                crate::winsta::make_interactive(&station);
            }
            let desktop = crate::desktop::create(&station, "Default")?;
            take_the_screen(&desktop, process);
            core::mem::forget(desktop);
        }
    }
    let (station, desktop) = resolve_desktop(process, "WinSta0\\Default", false)?;
    let desktop_object = process.handle_table.reference_as::<Desktop>(desktop, &DESKTOP_TYPE, AccessMask::NONE)?;
    let _ = station;
    crate::gui::set_thread_desktop(desktop.0, Some(desktop_object.clone()))?;
    Ok(desktop_object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_without_a_station_takes_the_inherited_one_or_winsta0() {
        use DefaultStation::{Inherited, Interactive, Refused, Service};
        assert_eq!(default_station(None, true), Interactive, "explorer: nothing inherited, its user's WinSta0");
        assert_eq!(default_station(None, false), Service, "a service: nothing inherited, no WinSta0");
        assert_eq!(default_station(Some(true), true), Inherited, "an interactive station inherited, WinSta0 allowed");
        assert_eq!(default_station(Some(false), false), Inherited, "a service station inherited");
        assert_eq!(default_station(Some(false), true), Interactive, "WinSta0 over a service station");
        assert_eq!(default_station(Some(true), false), Refused, "an interactive station without its access");
    }
}
