//! Le menu de la fenêtre, ou menu système (`menu.c` de win32k, ReactOS
//! épinglé, comme spécification : IntGetSystemMenu, MENU_GetSystemMenu,
//! IntSetSystemMenu, MENU_InitSysMenuPopup ; NC_GetSysPopupPos de
//! `nonclient.c`).
//!
//! Le menu système d'une fenêtre (`WND.SystemMenu`) est un menu d'un seul
//! item (MNF_SYSMENU), la « barre » que suit la boucle des menus quand on
//! clique sur l'icône du titre ou qu'on tape Alt+Espace ; le sous-menu de cet
//! item est le menu déroulant que rend GetSystemMenu. C'est le gabarit
//! SYSMENU de `user32` (SYSMENUMDI d'une fenêtre fille MDI) chargé par le
//! rappel LoadMenu : Rétablir, Déplacer, Taille, Réduire, Agrandir, Fermer ;
//! Rétablir, Réduire, Agrandir et Fermer reçoivent les glyphes de Marlett
//! (HBMMENU_POPUP_*, dessinés par `crate::menupopup`), le menu MNS_CHECKORBMP,
//! Fermer est l'item par défaut, et il est retiré d'une classe CS_NOCLOSE.
//! Avant d'être montré, ses items suivent l'état de la fenêtre
//! ([`init_popup`] : Rétablir grisé pour une fenêtre normale, Réduire pour
//! une fenêtre réduite ou sans WS_MINIMIZEBOX…). Un item choisi poste
//! WM_SYSCOMMAND (`crate::menutrack`), que DefWindowProc exécute
//! (`crate::sizemove::sys_command`).
//!
//! Écarts voulus avec ReactOS : le menu est créé au premier besoin
//! (GetSystemMenu, le suivi du menu), pas au premier dessin du bouton de
//! fermeture, qui lit chez ReactOS l'état de SC_CLOSE : le cadre se peint
//! aussi hors du processus de la fenêtre, où le rappel LoadMenu est
//! impossible ; le menu chargé est gardé tel quel, ReactOS le clone
//! (IntCloneMenu) avant de détruire l'original.
//!
//! Pas encore : le bouton de fermeture grisé quand SC_CLOSE l'est, le menu
//! système d'un bureau (MNF_SYSDESKMN), WM_POPUPSYSTEMMENU, SC_MOVE et
//! SC_SIZE au clavier.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use abi::menu::{hbmmenu, mf, miim, mnf, mns, MenuItemInfoW32};
use abi::user::{
    sm, CS_NOCLOSE, HTCAPTION, SC_CLOSE, SC_MAXIMIZE, SC_MINIMIZE, SC_MOVE, SC_RESTORE, SC_SIZE, WS_EX_MDICHILD,
    WS_MAXIMIZE, WS_MAXIMIZEBOX, WS_MINIMIZE, WS_MINIMIZEBOX, WS_SYSMENU, WS_THICKFRAME,
};

use crate::callback::MenuResource;
use crate::gdi::dib::Rect;
use crate::window::{self, Window};

/// MF_ENABLED.
const ENABLED: u32 = 0;

/// Les items du gabarit et leurs glyphes (MENU_GetSystemMenu).
const GLYPHS: [(u32, u32); 4] = [
    (SC_CLOSE, hbmmenu::POPUP_CLOSE),
    (SC_RESTORE, hbmmenu::POPUP_RESTORE),
    (SC_MAXIMIZE, hbmmenu::POPUP_MAXIMIZE),
    (SC_MINIMIZE, hbmmenu::POPUP_MINIMIZE),
];

/// get_win_sys_menu : le menu système de `window` (le menu d'un seul item),
/// s'il en a un.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn of(window: &Window) -> Option<u32> {
    let menu = window.state().system_menu;
    (menu != 0 && crate::menu::exists(menu)).then_some(menu)
}

/// Le menu déroulant du menu système `system` : le sous-menu de son item.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn popup_of(system: u32) -> Option<u32> {
    let state = crate::menu::state(system)?;
    let submenu = state.items.first()?.submenu;
    (submenu != 0 && crate::menu::exists(submenu)).then_some(submenu)
}

/// IntGetSystemMenu : le menu déroulant du menu système de `window`, créé
/// s'il n'existe pas et que la fenêtre a WS_SYSMENU (GetSystemMenu) ; avec
/// `revert`, le menu système est détruit, et rien n'est rendu (le prochain
/// sera neuf, GetSystemMenu(TRUE)).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système d'un thread GUI. Rappelle le mode
/// utilisateur (LoadMenu).
pub fn get(window: &Arc<Window>, revert: bool) -> Option<u32> {
    if revert {
        if let Some(system) = of(window) {
            crate::menu::destroy(system);
        }
        window::change(window, |state| state.system_menu = 0);
    } else if of(window).is_none() && window.state().style & WS_SYSMENU != 0 {
        let system = build(window, None).unwrap_or(0);
        window::change(window, |state| state.system_menu = system);
    }
    let popup = of(window).and_then(popup_of)?;
    crate::menu::add_flags(popup, mnf::SYSSUBMENU);
    Some(popup)
}

/// IntSetSystemMenu : le menu déroulant `menu` devient le menu système de
/// `window`, l'ancien détruit ; faux sans WS_SYSMENU ou si le menu
/// système n'a pas pu être fait.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système d'un thread GUI.
pub fn set(window: &Arc<Window>, menu: u32) -> bool {
    if window.state().style & WS_SYSMENU == 0 {
        return false;
    }
    if let Some(old) = of(window) {
        crate::menu::destroy(old);
    }
    let system = build(window, Some(menu));
    window::change(window, |state| state.system_menu = system.unwrap_or(0));
    system.is_some()
}

/// IntGetMenuState(SC_CLOSE) du menu système de `window` : Fermer y est, et
/// actif ; un double-clic sur l'icône du titre ferme alors la fenêtre
/// (NC_HandleNCLButtonDblClk).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système d'un thread GUI. Rappelle le mode
/// utilisateur (LoadMenu).
pub fn close_enabled(window: &Arc<Window>) -> bool {
    let Some(popup) = get(window, false) else { return false };
    crate::menu::find_command(popup, SC_CLOSE).is_some_and(|(_, state)| state & (mf::GRAYED | mf::DISABLED) == 0)
}

/// Le menu système de `window`, détruit avec elle (co_UserFreeWindow).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn destroy_of(window: &Window) {
    if let Some(system) = of(window) {
        crate::menu::destroy(system);
    }
    window::change(window, |state| state.system_menu = 0);
}

/// Un MENUITEMINFOW de `mask`, le reste à zéro.
fn item_info(mask: u32) -> MenuItemInfoW32 {
    MenuItemInfoW32 { cb_size: size_of::<MenuItemInfoW32>() as u32, f_mask: mask, ..MenuItemInfoW32::default() }
}

/// Le gabarit du menu système de `window`, chargé de `user32` par le rappel
/// LoadMenu, ses glyphes posés et Fermer par défaut.
fn load_template(window: &Window) -> Option<u32> {
    let name = if window.state().ex_style & WS_EX_MDICHILD != 0 { "SYSMENUMDI" } else { "SYSMENU" };
    let name: Vec<u16> = name.encode_utf16().collect();
    let module = crate::client::client_module();
    let menu = crate::callback::load_menu(module, MenuResource::Name(&name)).ok()?;
    if menu == 0 || !crate::menu::exists(menu) {
        log::warn!("win32k: the window menu: LoadMenu of SYSMENU failed");
        return None;
    }
    crate::menu::add_flags(menu, mns::CHECKORBMP | mnf::SYSMENU | mnf::POPUP);
    for (id, glyph) in GLYPHS {
        let info = MenuItemInfoW32 { hbmp_item: glyph, ..item_info(miim::BITMAP) };
        let _ = crate::menu::set_item_info(menu, id, false, &info, None);
    }
    crate::menu::set_default(menu, SC_CLOSE, false);
    Some(menu)
}

/// MENU_GetSystemMenu : un menu système neuf pour `window`, d'un item dont
/// le sous-menu est `popup` (IntSetSystemMenu) ou le gabarit chargé.
fn build(window: &Arc<Window>, popup: Option<u32>) -> Option<u32> {
    let system = crate::menu::create(false).ok()?;
    crate::menu::add_flags(system, mnf::SYSMENU);
    crate::menu::set_hwnd(system, window.handle);
    let Some(popup) = popup.or_else(|| load_template(window)) else {
        crate::menu::destroy(system);
        return None;
    };
    crate::menu::add_flags(popup, mnf::SYSMENU | mnf::POPUP);
    if window.class.as_ref().is_some_and(|class| class.info.style & CS_NOCLOSE != 0) {
        crate::menu::remove(popup, SC_CLOSE, 0, true);
    }
    let info = MenuItemInfoW32 {
        f_type: mf::POPUP,
        f_state: ENABLED,
        h_sub_menu: popup,
        ..item_info(miim::FTYPE | miim::STRING | miim::STATE | miim::SUBMENU)
    };
    if crate::menu::insert_item(system, u32::MAX, true, &info, None).is_err() {
        crate::menu::destroy(system);
        crate::menu::destroy(popup);
        return None;
    }
    Some(system)
}

/// MENU_InitSysMenuPopup, la règle : pour une fenêtre de style `style` et de
/// classe de style `class_style`, ouverte depuis `hit`, l'état de chaque
/// item (grisé ou non : MF_GRAYED, MF_ENABLED ; Fermer n'est grisé que pour
/// une classe CS_NOCLOSE, il garde sinon l'état qu'on lui a donné) et
/// l'item par défaut : Rétablir pour une fenêtre réduite ; depuis le titre,
/// Rétablir pour une fenêtre agrandie et Agrandir sinon ; Fermer ailleurs.
pub fn popup_states(style: u32, class_style: u32, hit: u32) -> (Vec<(u32, u32)>, u32) {
    let gray = |grayed: bool| if grayed { mf::GRAYED } else { ENABLED };
    let sized = style & (WS_MAXIMIZE | WS_MINIMIZE) != 0;
    let mut states = alloc::vec![
        (SC_SIZE, gray(style & WS_THICKFRAME == 0 || sized)),
        (SC_MOVE, gray(sized)),
        (SC_MINIMIZE, gray(style & WS_MINIMIZEBOX == 0 || style & WS_MINIMIZE != 0)),
        (SC_MAXIMIZE, gray(style & WS_MAXIMIZEBOX == 0 || style & WS_MAXIMIZE != 0)),
        (SC_RESTORE, gray(!sized)),
    ];
    if class_style & CS_NOCLOSE != 0 {
        states.push((SC_CLOSE, mf::GRAYED));
    }
    let default = if style & WS_MINIMIZE != 0 {
        SC_RESTORE
    } else if hit == HTCAPTION {
        if sized {
            SC_RESTORE
        } else {
            SC_MAXIMIZE
        }
    } else {
        SC_CLOSE
    };
    (states, default)
}

/// MENU_InitSysMenuPopup : les items du menu déroulant `menu` suivent l'état
/// de `window` ([`popup_states`]), ouvert depuis `hit`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn init_popup(menu: u32, window: &Window, hit: u32) {
    let class_style = window.class.as_ref().map_or(0, |class| class.info.style);
    let (states, default) = popup_states(window.state().style, class_style, hit);
    for (id, flags) in states {
        crate::menu::enable(menu, id, flags);
    }
    crate::menu::set_default(menu, default, false);
}

/// NC_GetSysPopupPos, la règle : sous l'icône du titre d'une fenêtre de
/// rectangle `window` (à l'écran) et de bordures `borders`, un carré de la
/// hauteur du titre moins un ; toute la fenêtre si elle est réduite.
pub fn popup_rect(window: Rect, borders: (i32, i32), minimized: bool, caption: i32) -> Rect {
    if minimized {
        return window;
    }
    let (left, top) = (window.left + borders.0, window.top + borders.1);
    Rect::new(left, top, left + caption - 1, top + caption - 1)
}

/// NC_GetSysPopupPos : le rectangle de l'icône du titre de `window`, à
/// l'écran ([`popup_rect`]) ; le menu système s'ouvre dessous.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn icon_rect(window: &Window) -> Rect {
    let state = window.state();
    let m = crate::metrics::get;
    // The window's rectangle is already at the screen's, a child's too.
    let borders = crate::defwnd::window_borders(state.style, state.ex_style, &m);
    popup_rect(state.window, borders, state.style & WS_MINIMIZE != 0, m(sm::CYCAPTION))
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::WS_OVERLAPPEDWINDOW;

    fn state_of(states: &[(u32, u32)], id: u32) -> Option<u32> {
        states.iter().find(|(each, _)| *each == id).map(|&(_, flags)| flags)
    }

    #[test]
    fn a_normal_window_can_be_minimized_and_maximized_not_restored() {
        let (states, default) = popup_states(WS_OVERLAPPEDWINDOW, 0, HTCAPTION);
        assert_eq!(state_of(&states, SC_RESTORE), Some(mf::GRAYED));
        assert_eq!(state_of(&states, SC_MINIMIZE), Some(ENABLED));
        assert_eq!(state_of(&states, SC_MAXIMIZE), Some(ENABLED));
        assert_eq!(state_of(&states, SC_MOVE), Some(ENABLED));
        assert_eq!(state_of(&states, SC_SIZE), Some(ENABLED));
        assert_eq!(state_of(&states, SC_CLOSE), None, "Close keeps the state it was given");
        assert_eq!(default, SC_MAXIMIZE, "from the caption");
        assert_eq!(popup_states(WS_OVERLAPPEDWINDOW, 0, abi::user::HTSYSMENU).1, SC_CLOSE, "from the icon");
    }

    #[test]
    fn a_maximized_window_restores_and_a_minimized_one_too() {
        let (states, default) = popup_states(WS_OVERLAPPEDWINDOW | WS_MAXIMIZE, 0, HTCAPTION);
        assert_eq!(state_of(&states, SC_RESTORE), Some(ENABLED));
        assert_eq!(state_of(&states, SC_MAXIMIZE), Some(mf::GRAYED));
        assert_eq!(state_of(&states, SC_MOVE), Some(mf::GRAYED));
        assert_eq!(state_of(&states, SC_SIZE), Some(mf::GRAYED));
        assert_eq!(default, SC_RESTORE);
        let (states, default) = popup_states(WS_OVERLAPPEDWINDOW | WS_MINIMIZE, 0, abi::user::HTSYSMENU);
        assert_eq!(state_of(&states, SC_MINIMIZE), Some(mf::GRAYED));
        assert_eq!(state_of(&states, SC_MAXIMIZE), Some(ENABLED));
        assert_eq!(default, SC_RESTORE, "minimized: Restore, wherever it opens from");
    }

    #[test]
    fn the_boxes_and_the_class_gray_their_items() {
        let dialog = abi::user::WS_POPUP | abi::user::WS_CAPTION | WS_SYSMENU;
        let (states, _) = popup_states(dialog, CS_NOCLOSE, HTCAPTION);
        assert_eq!(state_of(&states, SC_MINIMIZE), Some(mf::GRAYED), "no minimize box");
        assert_eq!(state_of(&states, SC_MAXIMIZE), Some(mf::GRAYED), "no maximize box");
        assert_eq!(state_of(&states, SC_SIZE), Some(mf::GRAYED), "no thick frame");
        assert_eq!(state_of(&states, SC_CLOSE), Some(mf::GRAYED), "CS_NOCLOSE");
    }

    #[test]
    fn the_menu_opens_under_the_icon() {
        let window = Rect::new(100, 100, 500, 400);
        assert_eq!(popup_rect(window, (4, 4), false, 19), Rect::new(104, 104, 122, 122));
        let icon = Rect::new(1, 774, 167, 799);
        assert_eq!(popup_rect(icon, (3, 3), true, 19), icon, "a minimized window: all of it");
    }
}
