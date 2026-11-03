//! Les stations de fenêtres (02 §7.2) : des objets d'Ob du type
//! `WindowStation`, nommés dans le répertoire des stations de la session
//! (`\Windows\WindowStations`, créé par NtUserInitialize). Une station tient
//! des bureaux (pas encore) et, pour la station interactive, l'écran, le
//! clavier et la souris.
//!
//! La première station que crée le processus de logon ([`crate::logon`]) est
//! la station interactive (InputWindowStation, `WinSta0`) ; les autres n'ont
//! ni entrée ni sortie (`WSS_NOIO`). Chaque processus GUI a sa station
//! ([`set_process_window_station`]), par un handle à lui.
//!
//! Une station tient ses bureaux ([`crate::desktop`]) et les nomme (sa
//! procédure *parse*).
//!
//! Pas encore : la table des atomes, le nom tiré de la session de logon pour une station sans nom,
//! le thread du bureau et le thread d'entrée (RIT) qu'ReactOS crée avec la
//! station interactive, le handle de station que garde l'EPROCESS (hérité
//! par les processus créés), le verrouillage (NtUserLockWindowStation).

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::object::{AccessMask, GenericMapping};
use abi::security::Luid32;
use hal::sync::KSpinLock;
use ob::{Object, ObjectType};

use crate::desktop::Desktop;

/// WINSTA_ENUMDESKTOPS.
pub const WINSTA_ENUMDESKTOPS: u32 = 0x0001;
/// WINSTA_READATTRIBUTES.
pub const WINSTA_READATTRIBUTES: u32 = 0x0002;
/// WINSTA_ACCESSCLIPBOARD.
pub const WINSTA_ACCESSCLIPBOARD: u32 = 0x0004;
/// WINSTA_CREATEDESKTOP.
pub const WINSTA_CREATEDESKTOP: u32 = 0x0008;
/// WINSTA_WRITEATTRIBUTES.
pub const WINSTA_WRITEATTRIBUTES: u32 = 0x0010;
/// WINSTA_ACCESSGLOBALATOMS.
pub const WINSTA_ACCESSGLOBALATOMS: u32 = 0x0020;
/// WINSTA_EXITWINDOWS.
pub const WINSTA_EXITWINDOWS: u32 = 0x0040;
/// WINSTA_ENUMERATE.
pub const WINSTA_ENUMERATE: u32 = 0x0100;
/// WINSTA_READSCREEN.
pub const WINSTA_READSCREEN: u32 = 0x0200;

/// WINSTA_ACCESS_ALL : tous les droits sur une station.
pub const WINSTA_ACCESS_ALL: AccessMask = AccessMask(
    AccessMask::STANDARD_RIGHTS_REQUIRED.0
        | WINSTA_ACCESSCLIPBOARD
        | WINSTA_ACCESSGLOBALATOMS
        | WINSTA_CREATEDESKTOP
        | WINSTA_ENUMDESKTOPS
        | WINSTA_ENUMERATE
        | WINSTA_EXITWINDOWS
        | WINSTA_READATTRIBUTES
        | WINSTA_READSCREEN
        | WINSTA_WRITEATTRIBUTES,
);

/// Le type `WindowStation` (ExWindowStationObjectType), avec la
/// correspondance générique de ReactOS (`ntuser/security.h`).
pub static WINDOW_STATION_TYPE: ObjectType = ObjectType::new(
    "WindowStation",
    WINSTA_ACCESS_ALL,
    GenericMapping {
        read: AccessMask(
            AccessMask::STANDARD_RIGHTS_READ.0
                | WINSTA_ENUMDESKTOPS
                | WINSTA_ENUMERATE
                | WINSTA_READATTRIBUTES
                | WINSTA_READSCREEN,
        ),
        write: AccessMask(
            AccessMask::STANDARD_RIGHTS_WRITE.0
                | WINSTA_ACCESSCLIPBOARD
                | WINSTA_CREATEDESKTOP
                | WINSTA_WRITEATTRIBUTES,
        ),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS),
        all: WINSTA_ACCESS_ALL,
    },
)
.with_parse(crate::desktop::parse_station);

/// L'utilisateur d'une station (NtUserSetWindowStationUser) : la LUID de sa
/// session de logon, et son SID tel que le processus de logon l'a donné.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StationUser {
    pub luid: Luid32,
    pub sid: Option<Vec<u8>>,
}

/// Une station de fenêtres (WINSTATION_OBJECT).
pub struct WindowStation {
    /// La session de son créateur.
    pub session: u32,
    /// Sans entrée ni sortie (`WSS_NOIO`) : toute station, sauf
    /// l'interactive.
    no_io: AtomicBool,
    user: KSpinLock<StationUser>,
    /// Ses bureaux (DesktopListHead), qui la tiennent.
    desktops: KSpinLock<Vec<Weak<Object<Desktop>>>>,
}

impl WindowStation {
    /// Une station de la session `session`, sans entrée ni sortie.
    pub fn new(session: u32) -> Self {
        Self {
            session,
            no_io: AtomicBool::new(true),
            user: KSpinLock::new(StationUser::default()),
            desktops: KSpinLock::new(Vec::new()),
        }
    }

    /// Ses bureaux vivants.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn desktops(&self) -> Vec<Arc<Object<Desktop>>> {
        self.desktops.lock().iter().filter_map(Weak::upgrade).collect()
    }

    /// Ajoute un bureau à ses bureaux, et oublie ceux qui ne sont plus.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn add_desktop(&self, desktop: Weak<Object<Desktop>>) {
        let mut desktops = self.desktops.lock();
        desktops.retain(|other| other.strong_count() > 0);
        desktops.push(desktop);
    }

    /// Sans entrée ni sortie (`WSS_NOIO`) : ce n'est pas la station
    /// interactive.
    pub fn no_io(&self) -> bool {
        self.no_io.load(Ordering::Acquire)
    }

    /// Son utilisateur.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn user(&self) -> StationUser {
        self.user.lock().clone()
    }

    /// Change son utilisateur ; l'ancien part une fois le verrou rendu.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_user(&self, user: StationUser) {
        let previous = core::mem::replace(&mut *self.user.lock(), user);
        drop(previous);
    }
}

/// La station interactive, une fois créée.
static INPUT_WINDOW_STATION: KSpinLock<Option<Weak<Object<WindowStation>>>> = KSpinLock::new(None);

/// La station interactive, tant qu'elle existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn input_window_station() -> Option<Arc<Object<WindowStation>>> {
    INPUT_WINDOW_STATION.lock().as_ref().and_then(Weak::upgrade)
}

/// Si une station créée par `creator` sera la station interactive : la
/// première que crée le processus de logon (`logon`), tant qu'aucune autre
/// ne l'est (`taken`).
pub const fn becomes_interactive(creator: u32, logon: u32, taken: bool) -> bool {
    !taken && logon != 0 && creator == logon
}

/// Une station neuve, de la session `session`, pas encore nommée, sans
/// entrée ni sortie jusqu'à [`inserted`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create(session: u32) -> Arc<Object<WindowStation>> {
    ob::create_object(&WINDOW_STATION_TYPE, WindowStation::new(session))
}

/// IntCreateWindowStation, une fois la station nommée par le processus
/// `creator` : la première du processus de logon devient la station
/// interactive (journalisé). Rend si elle l'est devenue.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn inserted(station: &Arc<Object<WindowStation>>, creator: u32) -> bool {
    let mut input = INPUT_WINDOW_STATION.lock();
    let taken = input.as_ref().and_then(Weak::upgrade).is_some();
    if !becomes_interactive(creator, crate::logon::logon_process(), taken) {
        return false;
    }
    station.no_io.store(false, Ordering::Release);
    *input = Some(Arc::downgrade(station));
    drop(input);
    log::info!("win32k: the interactive window station, created by the logon process (PID {creator})");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_logon_process_makes_the_interactive_station_once() {
        assert!(becomes_interactive(28, 28, false), "winlogon's first");
        assert!(!becomes_interactive(28, 28, true), "once only");
        assert!(!becomes_interactive(32, 28, false), "another process");
        assert!(!becomes_interactive(28, 0, false), "no logon process");
    }

    #[test]
    fn the_mapping_gives_all_rights_for_generic_all() {
        let all = WINDOW_STATION_TYPE.granted_access(AccessMask(0x1000_0000));
        assert_eq!(all, WINSTA_ACCESS_ALL);
        assert_eq!(WINSTA_ACCESS_ALL.0, 0x000F_037F, "WINSTA_ALL_ACCESS and the standard rights");
        let read = WINDOW_STATION_TYPE.granted_access(AccessMask(0x8000_0000));
        assert_eq!(read.0 & 0xFFFF, WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE | WINSTA_READATTRIBUTES | WINSTA_READSCREEN);
    }

    #[test]
    fn a_station_keeps_its_user() {
        let station = WindowStation::new(0);
        assert!(station.no_io(), "until it is made the interactive station");
        assert_eq!(station.user(), StationUser::default());
        let user = StationUser { luid: Luid32 { low_part: 0x3E7, high_part: 0 }, sid: Some(alloc::vec![1, 1]) };
        station.set_user(user.clone());
        assert_eq!(station.user(), user);
    }
}
