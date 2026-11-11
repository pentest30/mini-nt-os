//! Les services des bureaux (`win32k::desktop`, `win32k::gui`) :
//! NtUserCreateDesktop, NtUserOpenDesktop, NtUserCloseDesktop,
//! NtUserSetThreadDesktop, NtUserSwitchDesktop.
//!
//! Ils rendent une valeur (un handle, un BOOL) : un échec rend 0, avec
//! l'erreur Win32 du statut comme dernière erreur (SetLastNtError).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use ke::usermem::UserPtr;

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS,
};
use abi::object::{OBJ_INHERIT, OBJ_OPENIF};
use abi::winerror::{dos_error, ERROR_BUSY};
use ob::{AccessMask, Handle, HandleAttributes, Object, ObjectRef};
use win32k::desktop::{Desktop, DESKTOP_SWITCHDESKTOP, DESKTOP_TYPE};
use win32k::winsta::{WindowStation, WINDOW_STATION_TYPE};

use super::object::{capture_attributes, Attributes};

/// Un handle, ou 0 avec l'erreur Win32 du statut.
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

/// Le bureau que désigne `handle` dans le processus courant, avec les
/// droits `access` (IntValidateDesktopHandle).
fn reference_desktop(handle: u32, access: AccessMask) -> Result<Arc<Object<Desktop>>, NtStatus> {
    super::current_process().handle_table.reference_as::<Desktop>(Handle(handle), &DESKTOP_TYPE, access)
}

/// NtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, cHwnd,
/// phwndList, pcHwndNeeded) : NTSTATUS. La liste des fenêtres que demandent
/// EnumWindows, EnumChildWindows, EnumThreadWindows, GetDlgItem
/// (`WIN_ListChildren`) :
/// - avec `hwndParent`, ou sans thread : les enfants de `hwndParent` (sans
///   lui, de la fenêtre du bureau `hDesktop`, ou de celui du thread
///   courant), dans leur ordre Z, et avec `bChildren` leurs enfants à toute
///   profondeur ([`win32k::window::children`]) ;
/// - sinon, les fenêtres de premier niveau du thread `dwThreadId` sur son
///   bureau.
///
/// Les `cHwnd` premiers handles vont en `phwndList` (s'il est donné), leur
/// nombre total en `pcHwndNeeded` : `user32` appelle une fois pour le
/// compter, une fois pour les lire. Un parent inconnu donne une liste vide.
/// `STATUS_INVALID_PARAMETER` sans `pcHwndNeeded` ou pour un thread inconnu
/// ou qui n'est pas un thread GUI ; `STATUS_INVALID_HANDLE` pour un bureau
/// qu'on ne peut pas énumérer.
pub(super) fn nt_user_build_hwnd_list(arguments: &[u32]) -> NtStatus {
    let [desktop, parent, children, tid, capacity, list, needed] = arguments[..7] else { unreachable!("7 arguments") };
    if needed == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // A BOOLEAN, in the low byte of its argument.
    let deep = children as u8 != 0;
    let handles = if parent != 0 || tid == 0 {
        let root = if parent != 0 {
            win32k::window::get(parent)
        } else if desktop != 0 {
            match reference_desktop(desktop, AccessMask(win32k::desktop::DESKTOP_ENUMERATE)) {
                Ok(desktop) => Some(desktop.window.clone()),
                Err(_) => return STATUS_INVALID_HANDLE,
            }
        } else {
            match win32k::convert_current_thread().ok().and_then(|thread| thread.desktop()) {
                Some(desktop) => Some(desktop.desktop.window.clone()),
                None => return STATUS_INVALID_HANDLE,
            }
        };
        root.map_or_else(Vec::new, |root| win32k::window::children(&root, deep))
    } else {
        let Ok(thread) = ps::ethread::lookup_thread(tid) else { return STATUS_INVALID_PARAMETER };
        let Some(info) = thread.win32_thread().map(win32k::gui::thread_info) else { return STATUS_INVALID_PARAMETER };
        let Some(desktop) = info.desktop() else { return STATUS_INVALID_PARAMETER };
        win32k::window::children(&desktop.desktop.window, false)
            .into_iter()
            .filter(|&handle| win32k::window::get(handle).is_some_and(|window| window.pti == info.server))
            .collect()
    };
    if list != 0 {
        let bytes: Vec<u8> = handles.iter().take(capacity as usize).flat_map(|handle| handle.to_le_bytes()).collect();
        if let Err(status) = ke::usermem::copy_to_user(u64::from(list), &bytes) {
            return status;
        }
    }
    match UserPtr::<u32>::new(needed).write(&(handles.len() as u32)) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// La station et le nom du bureau que désignent les attributs : le dernier
/// composant du nom est le bureau, ce qui le précède désigne la station
/// (relatif à la racine) ; sans rien avant, la racine est la station.
fn station_and_name(captured: &Attributes) -> Result<(Arc<Object<WindowStation>>, String), NtStatus> {
    let name = captured.name.as_deref().unwrap_or_default();
    let (prefix, desktop) = name.rsplit_once('\\').unwrap_or(("", name));
    if desktop.is_empty() {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let station: ObjectRef = match (prefix, &captured.root) {
        ("", Some(root)) => root.clone(),
        ("", None) => return Err(STATUS_OBJECT_NAME_INVALID),
        (prefix, root) => {
            ob::namespace().open(prefix, root.as_ref(), Some(&WINDOW_STATION_TYPE), captured.attributes)?
        }
    };
    let station = ob::downcast::<WindowStation>(&station).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    Ok((station, String::from(desktop)))
}

/// NtUserCreateDesktop(ObjectAttributes, lpszDesktopDevice, pDevmode,
/// dwFlags, DesiredAccess) : le bureau que nomment les attributs, sur sa
/// station (la racine : celle du processus pour `user32`), ouvert s'il
/// existe (`OBJ_OPENIF`, sinon `STATUS_OBJECT_NAME_COLLISION`), créé sinon
/// avec son tas (`win32k::desktop::create`) ; rend son handle. Le
/// périphérique et le mode d'affichage sont ignorés (pas de vidéo, M6).
pub(super) fn nt_user_create_desktop(arguments: &[u32]) -> NtStatus {
    let (attributes, desired) = (arguments[0], arguments[4]);
    let create = || {
        let captured = capture_attributes(attributes)?;
        let (station, name) = station_and_name(&captured)?;
        let desktop = match win32k::desktop::find(&station, &name) {
            Some(_) if captured.attributes & OBJ_OPENIF == 0 => return Err(STATUS_OBJECT_NAME_COLLISION),
            Some(existing) => existing,
            None => win32k::desktop::create(&station, &name)?,
        };
        let inherit = captured.attributes & OBJ_INHERIT != 0;
        let handle = super::current_process().handle_table.insert(
            desktop,
            AccessMask(desired),
            HandleAttributes { inherit, protect_from_close: false },
        )?;
        Ok(handle.0)
    };
    value(create())
}

/// NtUserOpenDesktop(ObjectAttributes, dwFlags, DesiredAccess) : un handle
/// sur le bureau que nomment les attributs.
pub(super) fn nt_user_open_desktop(arguments: &[u32]) -> NtStatus {
    let (attributes, desired) = (arguments[0], arguments[2]);
    let open = || {
        let captured = capture_attributes(attributes)?;
        let (station, name) = station_and_name(&captured)?;
        let desktop = win32k::desktop::find(&station, &name).ok_or(abi::ntstatus::STATUS_OBJECT_NAME_NOT_FOUND)?;
        let inherit = captured.attributes & OBJ_INHERIT != 0;
        let handle = super::current_process().handle_table.insert(
            desktop,
            AccessMask(desired),
            HandleAttributes { inherit, protect_from_close: false },
        )?;
        Ok(handle.0)
    };
    value(open())
}

/// NtUserCloseDesktop(hDesktop) : ferme le handle d'un bureau ; FALSE
/// (`ERROR_BUSY`) pour celui du bureau du thread ou du bureau de démarrage
/// du processus (IntDesktopOkToClose).
pub(super) fn nt_user_close_desktop(arguments: &[u32]) -> NtStatus {
    let handle = arguments[0];
    let process = super::current_process();
    let thread = win32k::convert_current_thread().ok().and_then(|info| info.desktop());
    let startup = win32k::process_info(&process).ok().and_then(|info| info.startup_desktop());
    if thread.is_some_and(|desktop| desktop.handle == handle) || startup.is_some_and(|(other, _)| other == handle) {
        let _ = win32k::set_last_error(ERROR_BUSY);
        return NtStatus(0);
    }
    boolean(reference_desktop(handle, AccessMask::NONE).and_then(|_| process.handle_table.close(Handle(handle))))
}

/// NtUserSetThreadDesktop(hDesktop) : le thread passe sur le bureau du
/// handle (`win32k::gui::set_thread_desktop`) ; un handle nul (plus aucun
/// bureau) n'est permis qu'à `csrss`.
pub(super) fn nt_user_set_thread_desktop(arguments: &[u32]) -> NtStatus {
    let handle = arguments[0];
    let set = || {
        let desktop = match handle {
            0 if super::current_process().pid() == win32k::csrss::csrss() => None,
            0 => return Err(STATUS_ACCESS_DENIED),
            handle => Some(reference_desktop(handle, AccessMask::NONE)?),
        };
        win32k::gui::set_thread_desktop(handle, desktop)
    };
    boolean(set())
}

/// NtUserSwitchDesktop(hDesktop) : le bureau du handle
/// (`DESKTOP_SWITCHDESKTOP`) devient le bureau d'entrée, s'il est sur la
/// station interactive de la session de l'appelant ; FALSE sinon
/// (`ERROR_ACCESS_DENIED`). Le premier bureau mis à l'écran fait charger à
/// `user32` les curseurs du système (`win32k::cursor::load_system_cursors`),
/// puis ses icônes (`load_system_icons`).
pub(super) fn nt_user_switch_desktop(arguments: &[u32]) -> NtStatus {
    let switch = || {
        let desktop = reference_desktop(arguments[0], AccessMask(DESKTOP_SWITCHDESKTOP))?;
        match win32k::desktop::switch_to(&desktop, super::current_process().session_id()) {
            true => Ok(()),
            false => Err(STATUS_ACCESS_DENIED),
        }
    };
    let switched = switch();
    if switched.is_ok() {
        // co_IntInitializeDesktopGraphics: the first desktop on the screen
        // has user32 load the system cursors, then the system icons.
        win32k::cursor::load_system_cursors();
        win32k::cursor::load_system_icons();
    }
    boolean(switched)
}
