//! Les tables d'accélérateurs : CreateAcceleratorTable, CopyAcceleratorTable,
//! DestroyAcceleratorTable et TranslateAccelerator, comme `accelerator.c` de
//! win32k (ReactOS, comme spécification).
//!
//! Une table (`ACCELERATOR_TABLE`) est un objet USER du processus qui la
//! crée (`TYPE_ACCELTABLE`), rendu par DestroyAcceleratorTable ou à la fin
//! du processus (`crate::destroy`). Ses entrées sont celles de l'appelant,
//! `fVirt` sans FVIRT_TBL_END (toute la table est donc parcourue, comme dans
//! ReactOS) ; la touche d'une entrée sans FVIRTKEY est un caractère ANSI,
//! converti en UTF-16 (en ASCII seulement : au-delà, l'octet est gardé tel
//! quel, journalisé une fois, faute de conversion par la page de code dans
//! le noyau).
//!
//! TranslateAccelerator ([`translate`]) : à WM_KEYDOWN et WM_SYSKEYDOWN
//! répond une entrée FVIRTKEY dont la touche et les touches Maj, Ctrl et Alt
//! sont celles que le thread voit enfoncées ([`matches`]) ; à WM_CHAR et
//! WM_SYSCHAR, une entrée de caractère, Alt seul comparé. Pour l'entrée
//! trouvée : si sa commande est un item du menu de la fenêtre (une fenêtre
//! qui n'est pas fille), WM_INITMENU puis WM_INITMENUPOPUP du menu qui porte
//! l'item, sauf quand une fenêtre a la souris (la capture) ; puis WM_COMMAND
//! (HIWORD 1 : un accélérateur), sauf pour une fenêtre désactivée, un item
//! désactivé ou grisé, ou une fenêtre réduite. Le message est alors traduit.
//!
//! Écarts voulus avec ReactOS, qui cherche l'item à la position égale à la
//! commande et donne WM_INITMENUPOPUP comme pour le menu de la fenêtre
//! (HIWORD 1) : Mino cherche l'item par son identifiant et donne HIWORD 0,
//! comme Wine (`dlls/user32/menu.c`, translate_accelerator) et comme le
//! documente l'API ; pas de WM_INITMENUPOPUP pour un item de la barre
//! elle-même. Pas encore : le menu de la fenêtre (WM_SYSCOMMAND d'une
//! commande qui y est).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::menu::{mfs, wm};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use abi::user::vk::{VK_CONTROL, VK_MENU, VK_SHIFT};
use abi::user::{fvirt, Accel32, Msg32, TYPE_ACCELTABLE, WM_CHAR, WM_KEYDOWN, WM_SYSCHAR, WM_SYSKEYDOWN};
use abi::user::{WS_CHILD, WS_DISABLED, WS_MINIMIZE};
use hal::sync::KSpinLock;

use crate::gui::ThreadInfo;
use crate::window::{LParam, Window};

/// Une entrée d'une table : `fVirt` (sans FVIRT_TBL_END), la touche (un code
/// virtuel, ou un caractère UTF-16), la commande.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accel {
    pub f_virt: u8,
    pub key: u16,
    pub cmd: u16,
}

impl Accel {
    /// L'entrée que donne l'ACCEL de l'appelant : `fVirt` sans
    /// FVIRT_TBL_END, le caractère ANSI d'une entrée sans FVIRTKEY en UTF-16
    /// (son octet bas, comme RtlMultiByteToUnicodeN d'un octet).
    pub fn from_user(entry: &Accel32) -> Self {
        let f_virt = entry.f_virt & fvirt::MASK;
        let key = if f_virt & fvirt::FVIRTKEY != 0 {
            entry.key
        } else {
            let byte = entry.key as u8;
            if byte >= 0x80 {
                static REPORTED: AtomicBool = AtomicBool::new(false);
                if !REPORTED.swap(true, Ordering::Relaxed) {
                    log::warn!("win32k: an accelerator's ANSI character beyond ASCII: no code page conversion yet");
                }
            }
            u16::from(byte)
        };
        Self { f_virt, key, cmd: entry.cmd }
    }

    /// L'ACCEL que CopyAcceleratorTable rend.
    pub fn to_user(self) -> Accel32 {
        Accel32 { f_virt: self.f_virt, pad: 0, key: self.key, cmd: self.cmd }
    }
}

/// Une table d'accélérateurs.
struct Table {
    handle: u32,
    entries: Vec<Accel>,
}

/// Les tables vivantes.
static TABLES: KSpinLock<Vec<Arc<Table>>> = KSpinLock::new(Vec::new());

/// NtUserCreateAcceleratorTable : une table de `entries`, au processus
/// courant ; rend son handle.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` sans entrée ; l'erreur de la table des
/// handles (pleine).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create(entries: Vec<Accel>) -> Result<u32, NtStatus> {
    if entries.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let owner = ps::ethread::current_thread()
        .and_then(|thread| crate::existing_process_info(thread.process()))
        .map_or(0, |info| info.server);
    // `user32` ne lit pas l'objet d'une table : l'entrée en porte une valeur
    // non nulle, sans plus.
    let handle = crate::handles::alloc(1, owner, TYPE_ACCELTABLE)?;
    TABLES.lock().push(Arc::new(Table { handle, entries }));
    Ok(handle)
}

/// UserGetAccelObject : les entrées de la table `handle`, si elle existe.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn entries(handle: u32) -> Option<Vec<Accel>> {
    let table = TABLES.lock().iter().find(|table| table.handle == handle).cloned()?;
    Some(table.entries.clone())
}

/// UserDestroyAccelTable : la table `handle` et son handle sont rendus ;
/// rend si elle existait.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn destroy(handle: u32) -> bool {
    let removed = {
        let mut tables = TABLES.lock();
        let at = tables.iter().position(|table| table.handle == handle);
        at.map(|at| tables.swap_remove(at))
    };
    if removed.is_none() {
        return false;
    }
    let _ = crate::handles::free(handle);
    true
}

/// co_IntTranslateAccelerator, sa première moitié : l'entrée `accel`
/// répond-elle au message `message` (`wparam`) quand les touches
/// `modifiers` (FSHIFT, FCONTROL, FALT) sont enfoncées ?
pub fn matches(accel: &Accel, message: u32, wparam: u32, modifiers: u8) -> bool {
    let wanted = fvirt::FSHIFT | fvirt::FCONTROL | fvirt::FALT;
    if accel.f_virt & fvirt::FVIRTKEY != 0 {
        matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN)
            && wparam == u32::from(accel.key)
            && modifiers == accel.f_virt & wanted
    } else {
        matches!(message, WM_CHAR | WM_SYSCHAR)
            && wparam == u32::from(accel.key)
            && modifiers & fvirt::FALT == accel.f_virt & fvirt::FALT
    }
}

/// Les touches Maj, Ctrl et Alt que `thread` voit enfoncées (UserGetKeyState).
fn modifiers(thread: &ThreadInfo) -> u8 {
    let mut mask = 0;
    for (key, flag) in [(VK_CONTROL, fvirt::FCONTROL), (VK_MENU, fvirt::FALT), (VK_SHIFT, fvirt::FSHIFT)] {
        if crate::input::key_state(thread, key) & 0x8000 != 0 {
            mask |= flag;
        }
    }
    mask
}

/// Ce qu'envoie un accélérateur trouvé ([`translate`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sending {
    /// WM_INITMENU du menu (`Some`), puis WM_INITMENUPOPUP du menu qui
    /// porte l'item et sa position (`Some`).
    pub init_menu: Option<u32>,
    pub init_popup: Option<(u32, u32)>,
}

/// Ce que l'accélérateur de commande `cmd` envoie à une fenêtre de style
/// `style` et de menu `menu`, l'item trouvé dans `found` (le menu qui le
/// porte), la souris capturée ou non : WM_INITMENU et WM_INITMENUPOPUP.
/// `submenu_position` donne la position du menu qui porte l'item.
pub fn init_messages(
    style: u32,
    menu: u32,
    found: Option<u32>,
    captured: bool,
    submenu_position: impl FnOnce(u32) -> u32,
) -> Sending {
    let menu = if style & WS_CHILD != 0 { 0 } else { menu };
    match found {
        Some(holder) if menu != 0 && !captured => {
            Sending { init_menu: Some(menu), init_popup: (holder != menu).then(|| (holder, submenu_position(holder))) }
        }
        _ => Sending { init_menu: None, init_popup: None },
    }
}

/// WM_COMMAND part-il ? Pas pour une fenêtre désactivée, un item du menu
/// désactivé ou grisé (`item_state`), ni une fenêtre réduite dont le menu
/// porte l'item.
pub fn sends_command(style: u32, item_state: Option<u32>) -> bool {
    style & WS_DISABLED == 0
        && item_state.is_none_or(|state| state & mfs::GRAYED == 0)
        && !(item_state.is_some() && style & WS_MINIMIZE != 0)
}

/// NtUserTranslateAccelerator : le message `message` du thread `thread`
/// est-il un accélérateur de la table `entries` pour `window` ? Si oui,
/// envoie ce que dit le module (WM_INITMENU, WM_INITMENUPOPUP, WM_COMMAND)
/// et rend `true`.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn translate(thread: &ThreadInfo, window: &Arc<Window>, entries: &[Accel], message: &Msg32) -> bool {
    let modifiers = modifiers(thread);
    let Some(accel) = entries.iter().find(|accel| matches(accel, message.message, message.w_param, modifiers)).copied()
    else {
        return false;
    };
    let cmd = u32::from(accel.cmd);
    let state = window.state();
    let menu = if state.style & WS_CHILD != 0 { 0 } else { state.menu };
    let found = (menu != 0).then(|| crate::menu::find_command(menu, cmd)).flatten();
    let sending = init_messages(
        state.style,
        menu,
        found.map(|(holder, _)| holder),
        crate::mouse::capture_window() != 0,
        |holder| crate::menu::find_submenu(menu, holder),
    );
    if let Some(menu) = sending.init_menu {
        let _ = crate::window::send_message(window, wm::INITMENU, menu, LParam::Value(0));
    }
    if let Some((holder, position)) = sending.init_popup {
        let _ = crate::window::send_message(window, wm::INITMENUPOPUP, holder, LParam::Value(position & 0xFFFF));
    }
    // The procedure may have changed the item (WM_INITMENUPOPUP) or the window.
    let state = window.state();
    let item_state = (found.is_some() && menu != 0)
        .then(|| crate::menu::find_command(menu, cmd).map_or(mfs::GRAYED, |(_, state)| state));
    if sends_command(state.style, item_state) {
        let _ = crate::window::send_message(window, wm::COMMAND, 0x1_0000 | cmd, LParam::Value(0));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTRL_S: Accel = Accel { f_virt: fvirt::FVIRTKEY | fvirt::FCONTROL, key: b'S' as u16, cmd: 0x101 };

    #[test]
    fn a_virtual_key_wants_its_modifiers_exactly() {
        assert!(matches(&CTRL_S, WM_KEYDOWN, u32::from(b'S'), fvirt::FCONTROL));
        assert!(!matches(&CTRL_S, WM_KEYDOWN, u32::from(b'S'), 0), "without Ctrl");
        assert!(!matches(&CTRL_S, WM_KEYDOWN, u32::from(b'S'), fvirt::FCONTROL | fvirt::FSHIFT), "Ctrl+Shift");
        assert!(!matches(&CTRL_S, WM_CHAR, u32::from(b'S'), fvirt::FCONTROL), "not a character");
        assert!(matches(&CTRL_S, WM_SYSKEYDOWN, u32::from(b'S'), fvirt::FCONTROL));
        assert!(!matches(&CTRL_S, WM_KEYDOWN, u32::from(b'O'), fvirt::FCONTROL));
    }

    #[test]
    fn a_character_wants_alt_alone() {
        let question = Accel { f_virt: 0, key: u16::from(b'?'), cmd: 7 };
        assert!(matches(&question, WM_CHAR, u32::from(b'?'), fvirt::FSHIFT), "Shift is not compared");
        assert!(!matches(&question, WM_CHAR, u32::from(b'?'), fvirt::FALT));
        assert!(!matches(&question, WM_KEYDOWN, u32::from(b'?'), 0), "not a virtual key");
        let alt = Accel { f_virt: fvirt::FALT, ..question };
        assert!(matches(&alt, WM_SYSCHAR, u32::from(b'?'), fvirt::FALT | fvirt::FCONTROL));
    }

    #[test]
    fn the_table_end_flag_is_removed_and_ansi_becomes_utf16() {
        let entry = Accel32 { f_virt: 0x80 | fvirt::FVIRTKEY, pad: 0, key: 0x74, cmd: 3 };
        assert_eq!(Accel::from_user(&entry), Accel { f_virt: fvirt::FVIRTKEY, key: 0x74, cmd: 3 });
        let character = Accel32 { f_virt: 0, pad: 0, key: 0x1241, cmd: 4 };
        assert_eq!(Accel::from_user(&character).key, 0x41, "the low byte, an ANSI character");
        assert_eq!(Accel::from_user(&entry).to_user(), Accel32 { f_virt: fvirt::FVIRTKEY, pad: 0, key: 0x74, cmd: 3 });
    }

    #[test]
    fn a_menu_command_initializes_its_menu_first() {
        let popup = init_messages(0, 0x10, Some(0x20), false, |_| 2);
        assert_eq!(popup, Sending { init_menu: Some(0x10), init_popup: Some((0x20, 2)) });
        let bar_item = init_messages(0, 0x10, Some(0x10), false, |_| 9);
        assert_eq!(bar_item, Sending { init_menu: Some(0x10), init_popup: None }, "an item of the bar itself");
        let captured = init_messages(0, 0x10, Some(0x20), true, |_| 2);
        assert_eq!(captured.init_menu, None, "the mouse is captured");
        let child = init_messages(WS_CHILD, 0x10, Some(0x20), false, |_| 2);
        assert_eq!(child.init_menu, None, "a child has no menu");
        assert_eq!(init_messages(0, 0x10, None, false, |_| 2).init_menu, None, "not a menu item");
    }

    #[test]
    fn a_disabled_window_or_item_gets_no_command() {
        assert!(sends_command(0, None));
        assert!(sends_command(0, Some(0)));
        assert!(!sends_command(WS_DISABLED, None));
        assert!(!sends_command(0, Some(mfs::GRAYED)));
        assert!(!sends_command(0, Some(0x0002)), "MF_DISABLED");
        assert!(!sends_command(WS_MINIMIZE, Some(0)), "minimized, a menu item");
        assert!(sends_command(WS_MINIMIZE, None), "minimized, not a menu item");
    }
}
