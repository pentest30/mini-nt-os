//! Les bureaux (02 §7.2) : des objets d'Ob du type `Desktop`, tenus par leur
//! station de fenêtres, qui les nomme (`WinSta0\Default` : sa procédure
//! *parse*, [`parse_station`]).
//!
//! Chaque bureau a son tas ([`DesktopHeap`]) : une section du fichier
//! d'échange que win32k écrit (`Section::write_kernel`) et que chaque
//! processus dont un thread est sur le bureau voit en lecture seule
//! (`SEC_NO_CHANGE`). Comme la section partagée de USER, ce qu'il contient
//! pointe par des *adresses du serveur* sur 32 bits (ADR-021) : le tas a la
//! sienne, prise dans `0xA0000000`–`0xBBFFFFFF` (où un client ne lit rien),
//! et un client y retrouve un octet en ôtant `ulClientDelta`, l'écart entre
//! cette adresse et celle de sa vue. Le tas commence par le `DESKTOPINFO` du
//! bureau ; le `CLIENTTHREADINFO` de chaque thread sur le bureau y est pris.
//!
//! Chaque bureau a sa fenêtre ([`crate::window`]), créée avec lui ; celle
//! du bureau d'entrée est montrée et peinte ([`switch_to`]).
//!
//! Pas encore : la fenêtre des messages (ReactOS la crée avec le bureau),
//! le fond d'écran (une image), les crochets, le descripteur de sécurité d'un bureau créé,
//! les droits de la station sur la création (`WINSTA_CREATEDESKTOP`).

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

use abi::ntstatus::{NtStatus, STATUS_NO_MEMORY, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_INVALID};
use abi::object::{AccessMask, GenericMapping};
use abi::user::{DeskInfoHead32, ListEntry32, NB_HOOKS};
use hal::sync::KSpinLock;
use mm::section::Section;
use mm::vad::PageProtect;
use ob::{Object, ObjectRef, ObjectType, Parsed};

use crate::winsta::WindowStation;

/// DESKTOP_READOBJECTS.
pub const DESKTOP_READOBJECTS: u32 = 0x0001;
/// DESKTOP_CREATEWINDOW.
pub const DESKTOP_CREATEWINDOW: u32 = 0x0002;
/// DESKTOP_CREATEMENU.
pub const DESKTOP_CREATEMENU: u32 = 0x0004;
/// DESKTOP_HOOKCONTROL.
pub const DESKTOP_HOOKCONTROL: u32 = 0x0008;
/// DESKTOP_JOURNALRECORD.
pub const DESKTOP_JOURNALRECORD: u32 = 0x0010;
/// DESKTOP_JOURNALPLAYBACK.
pub const DESKTOP_JOURNALPLAYBACK: u32 = 0x0020;
/// DESKTOP_ENUMERATE.
pub const DESKTOP_ENUMERATE: u32 = 0x0040;
/// DESKTOP_WRITEOBJECTS.
pub const DESKTOP_WRITEOBJECTS: u32 = 0x0080;
/// DESKTOP_SWITCHDESKTOP.
pub const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;

/// DESKTOP_ALL_ACCESS : tous les droits sur un bureau.
pub const DESKTOP_ALL_ACCESS: AccessMask = AccessMask(
    AccessMask::STANDARD_RIGHTS_REQUIRED.0
        | DESKTOP_CREATEMENU
        | DESKTOP_CREATEWINDOW
        | DESKTOP_ENUMERATE
        | DESKTOP_HOOKCONTROL
        | DESKTOP_JOURNALPLAYBACK
        | DESKTOP_JOURNALRECORD
        | DESKTOP_READOBJECTS
        | DESKTOP_SWITCHDESKTOP
        | DESKTOP_WRITEOBJECTS,
);

/// Le type `Desktop` (ExDesktopObjectType), avec la correspondance générique
/// de ReactOS (`ntuser/security.h`).
pub static DESKTOP_TYPE: ObjectType = ObjectType::new(
    "Desktop",
    DESKTOP_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | DESKTOP_ENUMERATE | DESKTOP_READOBJECTS),
        write: AccessMask(
            AccessMask::STANDARD_RIGHTS_WRITE.0
                | DESKTOP_CREATEMENU
                | DESKTOP_CREATEWINDOW
                | DESKTOP_HOOKCONTROL
                | DESKTOP_JOURNALPLAYBACK
                | DESKTOP_JOURNALRECORD
                | DESKTOP_WRITEOBJECTS,
        ),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | DESKTOP_SWITCHDESKTOP),
        all: DESKTOP_ALL_ACCESS,
    },
);

/// La taille du tas d'un bureau de la station interactive (3 Mio, comme
/// gdwDesktopSectionSize de ReactOS avant Windows 7).
pub const DESKTOP_HEAP_SIZE: u32 = 3 * 1024 * 1024;
/// Celle du bureau `Winlogon` et des bureaux d'une station sans entrée ni
/// sortie (gdwWinlogonSectionSize, gdwNOIOSectionSize).
pub const SMALL_DESKTOP_HEAP_SIZE: u32 = 128 * 1024;

/// La taille du tas d'un bureau nommé `name`, sur une station interactive
/// ou non.
pub fn heap_size(name: &str, interactive: bool) -> u32 {
    if interactive && !name.eq_ignore_ascii_case("Winlogon") {
        DESKTOP_HEAP_SIZE
    } else {
        SMALL_DESKTOP_HEAP_SIZE
    }
}

/// Les adresses du serveur des tas de bureau.
const SERVER_FIRST: u32 = 0xA000_0000;
const SERVER_END: u32 = 0xBC00_0000;
/// Leur granularité, celle d'une vue.
const SERVER_GRANULARITY: u32 = 0x1_0000;

/// Une liste de plages libres `(début, taille)`, triée : la première qui
/// tient `size` (arrondie à `align`) en donne le début ; une plage rendue se
/// fond avec ses voisines.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FreeRanges(Vec<(u32, u32)>);

impl FreeRanges {
    /// Une seule plage libre.
    pub fn new(start: u32, size: u32) -> Self {
        Self(alloc::vec![(start, size)])
    }

    /// Prend `size` octets arrondis à `align` (une puissance de 2) ; `None`
    /// si rien ne les tient.
    pub fn take(&mut self, size: u32, align: u32) -> Option<u32> {
        let size = size.checked_add(align - 1)? & !(align - 1);
        let index = self.0.iter().position(|&(_, length)| length >= size)?;
        let (start, length) = self.0[index];
        if length == size {
            self.0.remove(index);
        } else {
            self.0[index] = (start + size, length - size);
        }
        Some(start)
    }

    /// Rend `size` octets arrondis à `align` en `start`.
    pub fn give(&mut self, start: u32, size: u32, align: u32) {
        let size = (size + align - 1) & !(align - 1);
        let index = self.0.partition_point(|&(other, _)| other < start);
        self.0.insert(index, (start, size));
        if index + 1 < self.0.len() && start + size == self.0[index + 1].0 {
            self.0[index].1 += self.0[index + 1].1;
            self.0.remove(index + 1);
        }
        if index > 0 && self.0[index - 1].0 + self.0[index - 1].1 == start {
            self.0[index - 1].1 += self.0[index].1;
            self.0.remove(index);
        }
    }
}

/// Les adresses du serveur libres pour les tas de bureau.
static SERVER_RANGES: KSpinLock<Option<FreeRanges>> = KSpinLock::new(None);

fn take_server_range(size: u32) -> Option<u32> {
    let mut ranges = SERVER_RANGES.lock();
    ranges
        .get_or_insert_with(|| FreeRanges::new(SERVER_FIRST, SERVER_END - SERVER_FIRST))
        .take(size, SERVER_GRANULARITY)
}

/// Le granule d'un bloc du tas.
const HEAP_GRANULARITY: u32 = 8;

/// Le tas d'un bureau : sa section, son adresse du serveur, ses blocs
/// libres.
pub struct DesktopHeap {
    pub section: Arc<Section>,
    /// L'adresse du serveur de son premier octet.
    pub server_base: u32,
    pub size: u32,
    free: KSpinLock<FreeRanges>,
}

impl DesktopHeap {
    /// Un tas de `size` octets (multiple de 64 Kio), à zéro.
    ///
    /// # Errors
    /// `STATUS_NO_MEMORY` sans adresse du serveur libre ; celles de la
    /// section.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn create(size: u32) -> Result<Self, NtStatus> {
        let section = Section::create_pagefile(u64::from(size), PageProtect::READWRITE)?;
        let server_base = take_server_range(size).ok_or(STATUS_NO_MEMORY)?;
        Ok(Self { section, server_base, size, free: KSpinLock::new(FreeRanges::new(0, size)) })
    }

    /// DesktopHeapAlloc : `size` octets à zéro ; rend leur position dans le
    /// tas. `STATUS_NO_MEMORY` si le tas est plein.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (le pool non paginé, `Section::write_kernel`) : les
    /// menus y publient leurs items sous leur verrou (`crate::menu`).
    pub fn alloc(&self, size: u32) -> Result<u32, NtStatus> {
        let offset = self.free.lock().take(size.max(1), HEAP_GRANULARITY).ok_or(STATUS_NO_MEMORY)?;
        let zeros = alloc::vec![0u8; size as usize];
        if let Err(status) = self.section.write_kernel(u64::from(offset), &zeros) {
            self.free(offset, size);
            return Err(status);
        }
        Ok(offset)
    }

    /// DesktopHeapFree : rend le bloc de `size` octets en `offset`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn free(&self, offset: u32, size: u32) {
        self.free.lock().give(offset, size.max(1), HEAP_GRANULARITY);
    }

    /// L'adresse du serveur de l'octet `offset`.
    pub const fn server_address(&self, offset: u32) -> u32 {
        self.server_base + offset
    }
}

impl Drop for DesktopHeap {
    fn drop(&mut self) {
        if let Some(ranges) = SERVER_RANGES.lock().as_mut() {
            ranges.give(self.server_base, self.size, SERVER_GRANULARITY);
        }
    }
}

/// Un bureau (DESKTOP).
pub struct Desktop {
    /// Son nom dans sa station.
    pub name: String,
    /// Sa station (rpwinstaParent).
    pub station: Arc<Object<WindowStation>>,
    /// Son tas, que ses fenêtres et les images des classes tiennent aussi.
    pub heap: Arc<DesktopHeap>,
    /// La position de son `DESKTOPINFO` dans son tas.
    pub desk_info: u32,
    /// Sa fenêtre (`DesktopWindow`, `pDeskInfo->spwnd`).
    pub window: Arc<crate::window::Window>,
    /// dwConsoleThreadId : le thread d'entrée des consoles de `consrv` sur
    /// ce bureau ; 0 sans lui.
    console_thread: AtomicU32,
}

impl Desktop {
    /// NtUserSetShellWindowEx : son `DESKTOPINFO` reçoit la fenêtre du shell
    /// (`hShellWindow`, `spwndShell`), celle de son fond (`spwndBkGnd`) et
    /// le `PROCESSINFO` de son processus (`ppiShellProcess`, son adresse du
    /// serveur) ; `user32` y lit GetShellWindow.
    ///
    /// # Errors
    /// Celles de l'écriture du tas.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn set_shell(
        &self,
        shell: &crate::window::Window,
        background: &crate::window::Window,
        process: u32,
    ) -> Result<(), NtStatus> {
        let at = u64::from(self.desk_info);
        let fields = [
            (offset_of!(DeskInfoHead32, shell_window), shell.handle),
            (offset_of!(DeskInfoHead32, spwnd_shell), shell.server_address()),
            (offset_of!(DeskInfoHead32, spwnd_bk_gnd), background.server_address()),
            (offset_of!(DeskInfoHead32, ppi_shell_process), process),
        ];
        for (offset, value) in fields {
            self.heap.section.write_kernel(at + offset as u64, &value.to_le_bytes())?;
        }
        Ok(())
    }

    /// co_UserDestroyWindow : `hwnd`, détruite, n'est plus la fenêtre du
    /// shell de son `DESKTOPINFO` (`hShellWindow` à NULL ; comme ReactOS,
    /// `spwndShell` et `spwndBkGnd` restent).
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn forget_shell_window(&self, hwnd: u32) {
        let at = u64::from(self.desk_info) + offset_of!(DeskInfoHead32, shell_window) as u64;
        let mut current = [0u8; 4];
        if self.heap.section.read_kernel(at, &mut current).is_ok() && u32::from_le_bytes(current) == hwnd {
            let _ = self.heap.section.write_kernel(at, &0u32.to_le_bytes());
        }
    }

    /// ConsoleCtrlDesktopConsoleThread : le thread d'entrée des consoles du
    /// bureau devient `thread`, s'il est donné ; rend celui d'avant.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn exchange_console_thread(&self, thread: Option<u32>) -> u32 {
        match thread {
            Some(thread) => self.console_thread.swap(thread, Ordering::AcqRel),
            None => self.console_thread.load(Ordering::Acquire),
        }
    }
}

/// Le `DESKTOPINFO` d'un bureau dont le tas va de `base` à `limit`
/// (adresses du serveur) et dont il occupe l'adresse `at` : ses chaînes de
/// crochets vides (chaque tête pointe sur elle-même), ni fenêtre ni shell.
pub fn initial_desk_info(base: u32, limit: u32, at: u32) -> DeskInfoHead32 {
    let mut aphk_start = [ListEntry32::default(); NB_HOOKS];
    for (i, head) in aphk_start.iter_mut().enumerate() {
        let address = at + core::mem::offset_of!(DeskInfoHead32, aphk_start) as u32 + (i * 8) as u32;
        *head = ListEntry32 { flink: address, blink: address };
    }
    DeskInfoHead32 { desktop_base: base, desktop_limit: limit, aphk_start, ..DeskInfoHead32::default() }
}

/// UserInitializeDesktop, puis IntDesktopObjectParse qui crée : un bureau
/// `name` neuf sur `station`, son tas (de la taille de [`heap_size`]) et son
/// `DESKTOPINFO` (son nom à la suite) ; la station le tient.
///
/// # Errors
/// Celles du tas.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create(station: &Arc<Object<WindowStation>>, name: &str) -> Result<Arc<Object<Desktop>>, NtStatus> {
    let heap = Arc::new(DesktopHeap::create(heap_size(name, !station.no_io()))?);
    let units: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
    // sizeof(DESKTOPINFO) + the name's length + its NUL.
    let size = size_of::<DeskInfoHead32>() as u32 + 4 + 2 * units.len() as u32;
    let at = heap.alloc(size)?;
    let info = initial_desk_info(heap.server_base, heap.server_base + heap.size, heap.server_address(at));
    heap.section.write_kernel(u64::from(at), info.as_bytes())?;
    let name_bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    heap.section.write_kernel(u64::from(at) + size_of::<DeskInfoHead32>() as u64, &name_bytes)?;
    // The window of the desktop, the size of the screen (SM_CXVIRTUALSCREEN).
    let (width, height) = crate::display::mode().map_or((0, 0), |mode| (mode.width, mode.height));
    let window = crate::window::create_desktop_window(&heap, name, at, width, height)?;
    let desktop = ob::create_object(
        &DESKTOP_TYPE,
        Desktop {
            name: String::from(name),
            station: station.clone(),
            heap,
            desk_info: at,
            window,
            console_thread: AtomicU32::new(0),
        },
    );
    station.add_desktop(Arc::downgrade(&desktop));
    Ok(desktop)
}

/// Le bureau `name` de `station`, sans casse.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn find(station: &WindowStation, name: &str) -> Option<Arc<Object<Desktop>>> {
    station.desktops().into_iter().find(|desktop| desktop.name.eq_ignore_ascii_case(name))
}

/// La procédure *parse* d'une station (IntWinStaObjectParse) : la station
/// elle-même pour un nom vide, son bureau pour `\Nom` ;
/// `STATUS_OBJECT_PATH_INVALID` sous un bureau, `STATUS_OBJECT_NAME_NOT_FOUND`
/// pour un bureau qu'elle n'a pas.
pub fn parse_station(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
    if remaining.is_empty() {
        return Ok(Parsed::Object(object.clone()));
    }
    let name = remaining.strip_prefix('\\').unwrap_or(remaining);
    if name.contains('\\') {
        return Err(STATUS_OBJECT_PATH_INVALID);
    }
    let station = ob::downcast::<WindowStation>(object).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let desktop: ObjectRef = find(&station, name).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    Ok(Parsed::Object(desktop))
}

/// Le bureau d'entrée (gpdeskInputDesktop), une fois choisi.
static INPUT_DESKTOP: KSpinLock<Option<Weak<Object<Desktop>>>> = KSpinLock::new(None);

/// Le bureau d'entrée, tant qu'il existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn input_desktop() -> Option<Arc<Object<Desktop>>> {
    INPUT_DESKTOP.lock().as_ref().and_then(Weak::upgrade)
}

/// NtUserSwitchDesktop, une fois le handle validé : `desktop` devient le
/// bureau d'entrée, s'il est sur la station interactive, de la session
/// `session` ; la fenêtre du bureau d'avant est cachée, la sienne montrée et
/// peinte (WM_PAINT) ; rend s'il l'est. Le
/// processus de logon passe outre au verrouillage de la station (pas encore
/// de verrouillage).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn switch_to(desktop: &Arc<Object<Desktop>>, session: u32) -> bool {
    if desktop.station.session != session {
        return false;
    }
    let interactive = crate::winsta::input_window_station();
    if !interactive.is_some_and(|station| Arc::ptr_eq(&station, &desktop.station)) {
        return false;
    }
    let previous = INPUT_DESKTOP.lock().replace(Arc::downgrade(desktop)).and_then(|previous| previous.upgrade());
    if let Some(previous) = previous.filter(|previous| !Arc::ptr_eq(previous, desktop)) {
        crate::window::hide_desktop_window(&previous);
    }
    let (width, height) = crate::display::mode().map_or((0, 0), |mode| (mode.width, mode.height));
    crate::window::show_desktop_window(desktop, width, height);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_ranges_are_taken_first_fit_and_merged_back() {
        let mut ranges = FreeRanges::new(0, 0x100);
        assert_eq!(ranges.take(0x10, 8), Some(0));
        assert_eq!(ranges.take(0x0C, 8), Some(0x10), "rounded to 0x10");
        assert_eq!(ranges.take(0x08, 8), Some(0x20));
        ranges.give(0x10, 0x0C, 8);
        assert_eq!(ranges.take(0x10, 8), Some(0x10), "the first hole that fits");
        ranges.give(0, 0x10, 8);
        ranges.give(0x20, 8, 8);
        ranges.give(0x10, 0x10, 8);
        assert_eq!(ranges, FreeRanges::new(0, 0x100), "all merged back");
        assert_eq!(ranges.take(0x101, 8), None, "too big");
    }

    #[test]
    fn desk_info_hooks_are_empty_lists() {
        let info = initial_desk_info(0xA000_0000, 0xA030_0000, 0xA000_0000);
        assert_eq!((info.desktop_base, info.desktop_limit, info.spwnd), (0xA000_0000, 0xA030_0000, 0));
        assert_eq!(info.aphk_start[0], ListEntry32 { flink: 0xA000_0010, blink: 0xA000_0010 });
        assert_eq!(info.aphk_start[15].flink, 0xA000_0010 + 15 * 8);
    }

    #[test]
    fn winlogon_and_non_interactive_desktops_get_small_heaps() {
        assert_eq!(heap_size("Default", true), 3 * 1024 * 1024);
        assert_eq!(heap_size("winlogon", true), 128 * 1024);
        assert_eq!(heap_size("Default", false), 128 * 1024);
    }
}
