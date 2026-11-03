//! Les services des stations de fenêtres (`win32k::winsta`) :
//! NtUserCreateWindowStation, NtUserOpenWindowStation,
//! NtUserCloseWindowStation, NtUserGetProcessWindowStation,
//! NtUserSetProcessWindowStation, NtUserSetWindowStationUser.
//!
//! Ils rendent une valeur (un handle, un BOOL) : un échec rend 0, avec
//! l'erreur Win32 du statut comme dernière erreur (SetLastNtError).

use alloc::sync::Arc;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_EXISTS};
use abi::object::OBJ_OPENIF;
use abi::security::Luid32;
use abi::winerror::{dos_error, ERROR_ACCESS_DENIED, ERROR_BUSY};
use ob::{AccessMask, Handle, Object, ObjectRef};
use win32k::gui::ProcessWindowStation;
use win32k::winsta::{StationUser, WindowStation, WINDOW_STATION_TYPE};

use super::object::capture_attributes;

/// SECURITY_MAX_SID_SIZE : le plus grand SID (15 sous-autorités).
const MAX_SID_SIZE: u32 = 68;

/// Une station sans nom (nommée d'après la session de logon) a déjà été
/// demandée.
static UNNAMED_REPORTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Ce que rend un service de USER qui rend une valeur : la valeur, ou 0
/// avec l'erreur Win32 du statut comme dernière erreur.
fn value(result: Result<u32, NtStatus>) -> NtStatus {
    result.map_or_else(
        |status| {
            let _ = win32k::set_last_error(dos_error(status));
            NtStatus(0)
        },
        NtStatus,
    )
}

/// Un BOOL : TRUE, ou FALSE avec l'erreur Win32 du statut.
fn boolean(result: Result<(), NtStatus>) -> NtStatus {
    value(result.map(|()| 1))
}

/// La station que désigne `handle` dans le processus courant
/// (IntValidateWindowStationHandle, sans droit demandé).
fn reference_station(handle: u32) -> Result<Arc<Object<WindowStation>>, NtStatus> {
    super::current_process().handle_table.reference_as::<WindowStation>(
        Handle(handle),
        &WINDOW_STATION_TYPE,
        AccessMask::NONE,
    )
}

/// NtUserCreateWindowStation(ObjectAttributes, DesiredAccess, …) : la
/// station que nomment les attributs, ouverte si elle existe, créée sinon
/// (la première du processus de logon devient la station interactive) ;
/// rend son handle. Une station sans nom (nommée d'après la session de
/// logon de l'appelant) n'est pas encore faite : `STATUS_NOT_IMPLEMENTED`,
/// journalisé une fois.
pub(super) fn nt_user_create_window_station(arguments: &[u32]) -> NtStatus {
    let (attributes, desired) = (arguments[0], arguments[1]);
    let create = || {
        let captured = capture_attributes(attributes)?;
        let Some(name) = captured.name.filter(|name| !name.is_empty() && !name.starts_with('\0')) else {
            if !UNNAMED_REPORTED.swap(true, core::sync::atomic::Ordering::Relaxed) {
                log::warn!("sys: NtUserCreateWindowStation without a name is not implemented");
            }
            return Err(abi::ntstatus::STATUS_NOT_IMPLEMENTED);
        };
        let process = super::current_process();
        let station = win32k::winsta::create(process.session_id());
        let object: ObjectRef = station.clone();
        let (handle, status) = ob::insert_object(
            ob::namespace(),
            object,
            Some(&name),
            captured.root.as_ref(),
            captured.attributes | OBJ_OPENIF,
            &process.handle_table,
            AccessMask(desired),
        )?;
        if status != STATUS_OBJECT_NAME_EXISTS {
            win32k::winsta::inserted(&station, process.pid());
        }
        Ok(handle.0)
    };
    value(create())
}

/// NtUserOpenWindowStation(ObjectAttributes, DesiredAccess) : un handle sur
/// la station que nomment les attributs.
pub(super) fn nt_user_open_window_station(arguments: &[u32]) -> NtStatus {
    let (attributes, desired) = (arguments[0], arguments[1]);
    let open = || {
        let captured = capture_attributes(attributes)?;
        let process = super::current_process();
        let handle = ob::open_object_by_name(
            ob::namespace(),
            &captured.name.unwrap_or_default(),
            captured.root.as_ref(),
            Some(&WINDOW_STATION_TYPE),
            captured.attributes,
            &process.handle_table,
            AccessMask(desired),
        )?;
        Ok(handle.0)
    };
    value(open())
}

/// NtUserCloseWindowStation(hWinSta) : ferme le handle d'une station ;
/// FALSE (`ERROR_BUSY`) pour celui de la station du processus.
pub(super) fn nt_user_close_window_station(arguments: &[u32]) -> NtStatus {
    let handle = arguments[0];
    let current = win32k::process_info(&super::current_process()).ok().and_then(|info| info.window_station());
    if current.is_some_and(|station| station.handle == handle) {
        let _ = win32k::set_last_error(ERROR_BUSY);
        return NtStatus(0);
    }
    boolean(reference_station(handle).and_then(|_| super::current_process().handle_table.close(Handle(handle))))
}

/// NtUserGetProcessWindowStation() : le handle de la station du processus ;
/// 0 s'il n'en a pas.
pub(super) fn nt_user_get_process_window_station(_arguments: &[u32]) -> NtStatus {
    let station = win32k::process_info(&super::current_process()).ok().and_then(|info| info.window_station());
    NtStatus(station.map_or(0, |station| station.handle))
}

/// NtUserSetProcessWindowStation(hWinSta) : la station du handle (0 : plus
/// aucune) devient celle du processus, avec les droits du handle.
pub(super) fn nt_user_set_process_window_station(arguments: &[u32]) -> NtStatus {
    let handle = arguments[0];
    let set = || {
        let process = super::current_process();
        let info = win32k::process_info(&process)?;
        let station = match handle {
            0 => None,
            handle => {
                let station = reference_station(handle)?;
                let (access, _) = process.handle_table.query(Handle(handle))?;
                Some(ProcessWindowStation { handle, station, access })
            }
        };
        info.set_window_station(station);
        Ok(())
    };
    boolean(set())
}

/// NtUserSetWindowStationUser(hWinSta, pluid, psid, size) : pour le
/// processus de logon seul (`ERROR_ACCESS_DENIED`), la station prend
/// l'utilisateur de la LUID, et son SID s'il est donné (au plus
/// SECURITY_MAX_SID_SIZE octets : `STATUS_INVALID_PARAMETER` au-delà, une
/// limite que ReactOS n'a pas).
pub(super) fn nt_user_set_window_station_user(arguments: &[u32]) -> NtStatus {
    let [handle, luid, sid, size] = arguments[..4] else { unreachable!("4 arguments") };
    if super::current_process().pid() != win32k::logon::logon_process() {
        let _ = win32k::set_last_error(ERROR_ACCESS_DENIED);
        return NtStatus(0);
    }
    let set = || {
        let station = reference_station(handle)?;
        let mut bytes = [0u8; 8];
        ke::usermem::copy_from_user(&mut bytes, u64::from(luid))?;
        let [l0, l1, l2, l3, h0, h1, h2, h3] = bytes;
        let luid =
            Luid32 { low_part: u32::from_le_bytes([l0, l1, l2, l3]), high_part: i32::from_le_bytes([h0, h1, h2, h3]) };
        let sid = match sid {
            0 => None,
            _ if size > MAX_SID_SIZE => return Err(STATUS_INVALID_PARAMETER),
            at => {
                let mut bytes = alloc::vec![0u8; size as usize];
                ke::usermem::copy_from_user(&mut bytes, u64::from(at))?;
                Some(bytes)
            }
        };
        station.set_user(StationUser { luid, sid });
        Ok(())
    };
    boolean(set())
}
