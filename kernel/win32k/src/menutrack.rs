//! Le suivi des menus (`menu.c` de win32k, ReactOS épinglé, comme
//! spécification) : TrackPopupMenuEx ([`track_popup_menu`],
//! IntTrackPopupMenuEx) et la boucle du menu ([`track_menu`],
//! MENU_TrackMenu), dans le thread de la fenêtre propriétaire.
//!
//! Un menu déroulant se montre dans une fenêtre de la classe #32768
//! (`crate::menupopup`), créée par win32k, au-dessus de tout et sans
//! activation ; la souris est capturée par elle. La boucle lit la file du
//! thread sans en sortir le message, puis décide : la souris sélectionne
//! l'item sous elle (un sous-menu s'ouvre), un clic relâché sur un item
//! l'exécute, un clic hors des menus finit le suivi (le message reste pour
//! l'application) ; le clavier : flèches, Début, Fin, Entrée, Échap, une
//! lettre soulignée (WM_MENUCHAR si aucun item ne l'a) ; WM_CANCELMODE
//! (EndMenu) le finit ; les autres messages sont distribués. Exécuter un
//! item : son identifiant rendu avec TPM_RETURNCMD, sinon WM_COMMAND posté
//! (WM_SYSCOMMAND d'un menu système, WM_MENUCOMMAND avec MNS_NOTIFYBYPOS).
//!
//! La propriétaire reçoit WM_ENTERMENULOOP, WM_INITMENU, WM_INITMENUPOPUP
//! (de chaque menu qui s'ouvre), WM_MENUSELECT (à chaque sélection, et
//! (0xFFFF, 0) à la fin), WM_ENTERIDLE (une fois la file vide),
//! WM_UNINITMENUPOPUP (de chaque menu qui se ferme), WM_EXITMENULOOP, sauf
//! TPM_NONOTIFY. Le caret du thread est caché pendant le suivi.
//!
//! Pas encore : le suivi de la barre (le clic, F10, Alt : l'étape suivante),
//! les colonnes au clavier (MENU_GetStartOfNextColumn), WM_NEXTMENU,
//! l'aide (F1, WM_HELP), les menus système.

use alloc::sync::Arc;

use abi::menu::{mf, mft, mnc, mnf, mns, tpm, wm, MSGF_MENU, NO_SELECTED_ITEM};
use abi::user::vk::{VK_DOWN, VK_END, VK_ESCAPE, VK_F10, VK_HOME, VK_LEFT, VK_MENU, VK_RIGHT, VK_UP};
use abi::user::{
    sm, Msg32, HTCAPTION, HWND_TOPMOST, RDW_ALLCHILDREN, SWP_NOACTIVATE, SWP_SHOWWINDOW, WC_MENU, WM_CHAR, WM_KEYDOWN,
    WM_KEYFIRST, WM_KEYLAST, WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEFIRST, WM_MOUSELAST, WM_MOUSEMOVE,
    WM_RBUTTONDBLCLK, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SETCURSOR, WM_SYSCHAR, WM_SYSKEYDOWN, WM_SYSTIMER, WM_TIMER,
    WS_BORDER, WS_CLIPSIBLINGS, WS_EX_DLGMODALFRAME, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_WINDOWEDGE, WS_POPUP,
};
use abi::winerror::ERROR_POPUP_ALREADY_ACTIVE;
use hal::sync::KSpinLock;

use crate::class::ClassName;
use crate::gdi::dib::Rect;
use crate::gui::ThreadInfo;
use crate::queue::Filter;
use crate::window::{self, CreateParams, LParam, Window};

/// Le menu suivi (`top_popup`, `top_popup_hmenu`) : sa fenêtre, lui ; un à
/// la fois dans le système.
static TOP: KSpinLock<Option<(u32, u32)>> = KSpinLock::new(None);

/// MTRACKER.
struct Tracker {
    /// Le menu dont la sélection bouge (le plus profond ouvert).
    current: u32,
    /// Le menu suivi.
    top: u32,
    owner: Arc<Window>,
    /// Le point du dernier message, à l'écran.
    pt: (i32, i32),
}

/// MAKELONG.
const fn make_long(low: u32, high: u32) -> u32 {
    (low & 0xFFFF) | (high << 16)
}

/// Envoie `message` à `window` (son retour, 0 si l'envoi échoue).
fn send(window: &Window, message: u32, wparam: u32, lparam: u32) -> u32 {
    window::get(window.handle)
        .and_then(|window| window::send_message(&window, message, wparam, LParam::Value(lparam)).ok())
        .unwrap_or(0)
}

/// Poste `message` à `window`, dans la file de son thread.
fn post(window: &Window, message: u32, wparam: u32, lparam: u32) {
    if let Some(thread) = crate::gui::thread_info_of(window.pti) {
        let time = hal::timer::get_tick_count() as u32;
        let message =
            Msg32 { hwnd: window.handle, message, w_param: wparam, l_param: lparam, time, ..Msg32::default() };
        crate::queue::post(&thread, message);
    }
}

/// Vrai pour un menu déroulant (MNF_POPUP), faux pour la barre d'une
/// fenêtre.
fn is_popup(menu: u32) -> bool {
    crate::menu::state(menu).is_some_and(|state| state.flags & mnf::POPUP != 0)
}

/// MF_SYSMENU pour un menu système (MNF_SYSMENU).
fn system_flag(menu: u32) -> u32 {
    crate::menu::state(menu).map_or(0, |state| if state.flags & mnf::SYSMENU != 0 { mf::SYSMENU } else { 0 })
}

/// La fenêtre qui montre le menu `menu` (la sienne, ou celle de sa barre).
fn window_of(menu: u32) -> Option<Arc<Window>> {
    window::get(crate::menu::state(menu)?.hwnd)
}

/// Le menu redessiné : sa fenêtre de menu déroulant, ou le cadre de la
/// fenêtre dont il est la barre.
fn redraw(menu: u32) {
    let Some(window) = window_of(menu) else { return };
    if is_popup(menu) {
        crate::menupopup::paint(&window);
    } else {
        crate::paint::nc_paint(&window, abi::user::HRGN_WINDOW);
    }
}

/// MENU_FindSubMenu : l'item qui ouvre `menu`, dans `top` ou l'un de ses
/// sous-menus (à toute profondeur) : le menu qui le porte, sa position.
fn find_submenu(top: u32, menu: u32) -> Option<(u32, u32)> {
    fn search(at: u32, target: u32, depth: u32) -> Option<(u32, u32)> {
        let state = crate::menu::state(at)?;
        for (position, item) in state.items.iter().enumerate() {
            if item.submenu == 0 {
                continue;
            }
            if item.submenu == target {
                return Some((at, position as u32));
            }
            // A branch is 30 menus deep at most (`menu::Menus::depth`).
            if depth < 32 {
                if let Some(found) = search(item.submenu, target, depth + 1) {
                    return Some(found);
                }
            }
        }
        None
    }
    search(top, menu, 0)
}

/// MENU_SelectItem : l'item `index` de `menu` est sélectionné (et dessiné),
/// l'ancien ne l'est plus ; avec `send_select`, WM_MENUSELECT à la
/// propriétaire (l'identifiant de l'item, ou sa position s'il ouvre un
/// sous-menu ; sans item, celui de `top` qui ouvre `menu`).
fn select_item(owner: &Window, menu: u32, index: u32, send_select: bool, top: Option<u32>) {
    let Some(state) = crate::menu::state(menu) else { return };
    if state.items.is_empty() || window::get(state.hwnd).is_none() || !crate::menu::select(menu, index) {
        return;
    }
    redraw(menu);
    if !send_select {
        return;
    }
    let Some(state) = crate::menu::state(menu) else { return };
    let flags_of = |item: &crate::menu::Item, menu: u32| {
        item.f_type | item.f_state | if item.submenu != 0 { mf::POPUP } else { 0 } | system_flag(menu)
    };
    if let Some(item) = state.items.get(index as usize) {
        let first = if item.submenu != 0 { index } else { item.id };
        send(owner, wm::MENUSELECT, make_long(first, flags_of(item, menu) & 0xFFFF), menu);
    } else if let Some(top) = top {
        let found = find_submenu(top, menu)
            .and_then(|(parent, at)| Some((parent, at, crate::menu::state(parent)?.items.get(at as usize)?.clone())));
        if let Some((parent, at, item)) = found {
            send(owner, wm::MENUSELECT, make_long(at, flags_of(&item, parent) & 0xFFFF), parent);
        }
    }
}

/// MENU_MoveSelection : l'item suivant (`offset` 1) ou précédent (-1) qui
/// n'est pas un séparateur, depuis la sélection (sans elle, le premier ou le
/// dernier).
fn move_selection(owner: &Window, menu: u32, offset: i32) {
    let Some(state) = crate::menu::state(menu) else { return };
    let count = state.items.len() as i32;
    let selectable = |at: i32| state.items[at as usize].f_type & mft::SEPARATOR == 0;
    if state.focused != NO_SELECTED_ITEM {
        if count == 1 {
            return;
        }
        let mut at = state.focused as i32 + offset;
        while (0..count).contains(&at) {
            if selectable(at) {
                select_item(owner, menu, at as u32, true, None);
                return;
            }
            at += offset;
        }
    }
    let mut at = if offset > 0 { 0 } else { count - 1 };
    while (0..count).contains(&at) {
        if selectable(at) {
            select_item(owner, menu, at as u32, true, None);
            return;
        }
        at += offset;
    }
}

/// MENU_GetSubPopup : le sous-menu ouvert de l'item sélectionné de `menu`.
fn sub_popup(menu: u32) -> Option<u32> {
    let state = crate::menu::state(menu)?;
    let item = state.items.get(state.focused as usize)?;
    (item.submenu != 0 && item.f_state & mf::MOUSESELECT != 0).then_some(item.submenu)
}

/// MENU_HideSubPopups : le sous-menu ouvert de `menu` (et les siens) se
/// ferme : sa fenêtre détruite, WM_UNINITMENUPOPUP.
fn hide_sub_popups(owner: &Window, menu: u32, send_select: bool, flags: u32) {
    let Some(submenu) = sub_popup(menu) else { return };
    if let Some(state) = crate::menu::state(menu) {
        crate::menu::set_mouse_select(menu, state.focused, false);
    }
    if !crate::menu::exists(submenu) {
        return;
    }
    hide_sub_popups(owner, submenu, false, flags);
    select_item(owner, submenu, NO_SELECTED_ITEM, send_select, None);
    if let Some(window) = window_of(submenu) {
        let _ = crate::destroy::destroy_window(&window);
    }
    if flags & tpm::NONOTIFY == 0 {
        send(owner, wm::UNINITMENUPOPUP, submenu, make_long(0, system_flag(submenu)));
    }
    crate::menu::set_hwnd(submenu, 0);
}

/// MENU_InitPopup : la fenêtre du menu déroulant `menu` (#32768, cachée),
/// à `owner` ; faux si elle n'a pas pu être créée.
fn init_popup(owner: &Window, menu: u32) -> bool {
    let params = CreateParams {
        ex_style: WS_EX_TOOLWINDOW | WS_EX_WINDOWEDGE | WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        class: Some(ClassName::Atom(WC_MENU)),
        style: WS_POPUP | WS_CLIPSIBLINGS | WS_BORDER,
        parent: owner.handle,
        instance: crate::client::client_module(),
        param: menu,
        expected_version: 0x0501,
        ..CreateParams::default()
    };
    let Ok(window) = window::create_window(params) else { return false };
    crate::menupopup::register(window.handle, menu);
    crate::menu::set_hwnd(menu, window.handle);
    true
}

/// MENU_MoveRect : la place d'un menu `width` × `height` à côté de
/// `exclude`, selon `flags` (TPM_VERTICAL : dessous ou dessus ; sinon à
/// droite ou à gauche), si elle tient sur le moniteur `monitor`.
fn move_rect(
    flags: u32,
    (x, y): (i32, i32),
    (width, height): (i32, i32),
    exclude: Rect,
    monitor: Rect,
) -> Option<(i32, i32)> {
    if flags & tpm::VERTICAL != 0 {
        if flags & tpm::BOTTOMALIGN != 0 {
            (exclude.top - height >= monitor.top).then_some((x, exclude.top - height))
        } else {
            (exclude.bottom + height < monitor.bottom).then_some((x, exclude.bottom))
        }
    } else if flags & tpm::RIGHTALIGN != 0 {
        (exclude.left - width >= monitor.left).then_some((exclude.left - width, y))
    } else {
        (exclude.right + width < monitor.right).then_some((exclude.right, y))
    }
}

/// MENU_ShowPopup, pour la place : `width` × `height` à placer en
/// (`x`, `y`) selon `flags` (l'alignement), sur le moniteur `monitor`, à
/// côté de `exclude` s'il la couvrirait.
pub fn popup_place(
    flags: u32,
    (mut x, mut y): (i32, i32),
    (width, height): (i32, i32),
    exclude: Option<Rect>,
    monitor: Rect,
    m: &impl Fn(usize) -> i32,
) -> (i32, i32) {
    let popup = flags & tpm::POPUPMENU != 0;
    let flags = if flags & tpm::LAYOUTRTL != 0 { flags ^ tpm::RIGHTALIGN } else { flags };
    if flags & tpm::RIGHTALIGN != 0 {
        x -= width;
    }
    if flags & tpm::CENTERALIGN != 0 {
        x -= width / 2;
    }
    if flags & tpm::BOTTOMALIGN != 0 {
        y -= height;
    }
    if flags & tpm::VCENTERALIGN != 0 {
        y -= height / 2;
    }
    if x + width > monitor.right {
        x = monitor.right - width;
    }
    if x < monitor.left {
        x = monitor.left;
    }
    if y < monitor.top {
        y += height;
        if y < monitor.top || y >= monitor.bottom || popup {
            y = monitor.top;
        }
    }
    if y + height > monitor.bottom {
        if y - height < monitor.top || y >= monitor.bottom {
            y = monitor.bottom - height;
        } else {
            let lower = y + m(sm::CYMENUSIZE) + 2 * m(sm::CYDLGFRAME);
            y = if lower >= monitor.bottom { y - height } else { lower - height };
        }
    }
    if let Some(exclude) = exclude.map(|exclude| exclude.intersect(&monitor)).filter(|exclude| !exclude.is_empty()) {
        let covers = |(x, y): (i32, i32)| !Rect::new(x, y, x + width, y + height).intersect(&exclude).is_empty();
        if covers((x, y)) {
            let tries = [
                0,
                tpm::BOTTOMALIGN | tpm::RIGHTALIGN,
                tpm::VERTICAL,
                tpm::BOTTOMALIGN | tpm::RIGHTALIGN | tpm::VERTICAL,
            ];
            for change in tries {
                if let Some(place) = move_rect(flags ^ change, (x, y), (width, height), exclude, monitor) {
                    if !covers(place) {
                        return place;
                    }
                }
            }
        }
    }
    (x, y)
}

/// MENU_ShowPopup : le menu `menu` mis en page (MENU_PopupMenuCalcSize), sa
/// fenêtre placée en (`x`, `y`) selon `flags`, à côté de `exclude`, montrée
/// au-dessus de tout sans activation, et peinte.
fn show_popup(menu: u32, flags: u32, (x, y): (i32, i32), exclude: Option<Rect>) -> bool {
    let Some(state) = crate::menu::state(menu) else { return false };
    if state.focused != NO_SELECTED_ITEM {
        crate::menu::select(menu, NO_SELECTED_ITEM);
    }
    let mut items = state.items.clone();
    let no_check = state.flags & mns::NOCHECK != 0;
    let m = crate::metrics::get;
    let (width, height) = crate::menupopup::layout(&mut items, no_check, &crate::menubar::system_font(), &m);
    crate::menu::set_places(menu, &items, width as u32, height as u32);
    let size = (width + 2 * m(sm::CXDLGFRAME), height + 2 * m(sm::CYDLGFRAME));
    let monitor = crate::monitor::primary().map_or_else(|| Rect::new(0, 0, 640, 480), |monitor| monitor.rect);
    let (x, y) = popup_place(flags, (x, y), size, exclude, monitor, &m);
    let Some(window) = window::get(state.hwnd) else { return false };
    TOP.lock().get_or_insert((window.handle, menu));
    crate::winpos::set_window_pos(&window, HWND_TOPMOST, x, y, size.0, size.1, SWP_SHOWWINDOW | SWP_NOACTIVATE);
    crate::paint::update_window(&window, RDW_ALLCHILDREN);
    true
}

/// MENU_ShowSubPopup : le sous-menu de l'item sélectionné de `menu` s'ouvre
/// (WM_INITMENUPOPUP d'abord), à droite de l'item d'un menu déroulant ou
/// sous celui d'une barre, son premier item sélectionné avec `select_first`.
/// Rend le menu ouvert, ou `menu` sans sous-menu à ouvrir.
fn show_sub_popup(owner: &Window, menu: u32, select_first: bool, flags: u32) -> u32 {
    let Some(state) = crate::menu::state(menu) else { return menu };
    let index = state.focused;
    let Some(item) = state.items.get(index as usize) else { return menu };
    if item.submenu == 0 || item.f_state & (mf::GRAYED | mf::DISABLED) != 0 {
        return menu;
    }
    let submenu = item.submenu;
    if flags & tpm::NONOTIFY == 0 {
        send(owner, wm::INITMENUPOPUP, submenu, make_long(index, u32::from(system_flag(menu) != 0)));
    }
    let Some(state) = crate::menu::state(menu) else { return menu };
    let Some(item) = state.items.get(index as usize).cloned() else { return menu };
    if item.submenu != submenu || !crate::menu::exists(submenu) {
        return menu;
    }
    let Some(window) = window::get(state.hwnd) else { return menu };
    let window_rect = window.state().window;
    let popup = state.flags & mnf::POPUP != 0;
    let m = crate::metrics::get;
    let item_rect = Rect::new(item.x as i32, item.y as i32, item.cx as i32, item.cy as i32);
    let exclude = if popup {
        let edge = 2 * m(sm::CXEDGE);
        Rect::new(window_rect.left + edge, window_rect.top, window_rect.right - edge, window_rect.bottom)
    } else {
        Rect::new(
            item_rect.left + window_rect.left,
            item_rect.top + window_rect.top,
            item_rect.right + window_rect.left,
            item_rect.bottom + window_rect.top,
        )
    };
    if item.f_state & mf::HILITE == 0 {
        crate::menu::hilite(menu, index, mf::BYPOSITION | mf::HILITE);
        redraw(menu);
    }
    crate::menu::set_mouse_select(menu, index, true);
    let place = if popup {
        (window_rect.left + item_rect.right - m(sm::CXDLGFRAME), window_rect.top + item_rect.top)
    } else {
        (window_rect.left + item_rect.left, window_rect.top + item_rect.bottom)
    };
    let mut flags = flags & !(tpm::CENTERALIGN | tpm::RIGHTALIGN | tpm::VCENTERALIGN | tpm::BOTTOMALIGN);
    if popup {
        flags &= !tpm::VERTICAL;
    }
    if !init_popup(owner, submenu) || !show_popup(submenu, flags, place, Some(exclude)) {
        return menu;
    }
    if select_first {
        move_selection(owner, submenu, 1);
    }
    submenu
}

/// MENU_ExecFocusedItem : l'item sélectionné de `menu` : un sous-menu
/// s'ouvre (-2) ; un item actif est exécuté (son identifiant, et le message
/// posté à la propriétaire sans TPM_RETURNCMD) ; -1 sinon.
fn exec_focused(tracker: &mut Tracker, menu: u32, flags: u32) -> i32 {
    let Some(state) = crate::menu::state(menu) else { return -1 };
    let Some(item) = state.items.get(state.focused as usize) else { return -1 };
    if item.submenu != 0 {
        tracker.current = show_sub_popup(&tracker.owner, menu, true, flags);
        return -2;
    }
    if item.f_state & (mf::GRAYED | mf::DISABLED) != 0 || item.f_type & mft::SEPARATOR != 0 {
        return -1;
    }
    if flags & tpm::RETURNCMD == 0 {
        let owner = &tracker.owner;
        if state.flags & mnf::SYSMENU != 0 {
            let point = make_long(tracker.pt.0 as u32, tracker.pt.1 as u32 & 0xFFFF);
            post(owner, wm::SYSCOMMAND, item.id, point);
        } else {
            let top_style = crate::menu::state(tracker.top).map_or(0, |top| top.flags);
            if (state.flags | top_style) & mns::NOTIFYBYPOS != 0 {
                post(owner, wm::MENUCOMMAND, state.focused, menu);
            } else {
                post(owner, wm::COMMAND, item.id, 0);
            }
        }
    }
    item.id as i32
}

/// MENU_SwitchTracking : la sélection va à l'item `index` de `menu`, les
/// sous-menus ouverts de celui-ci fermés.
fn switch_tracking(tracker: &mut Tracker, menu: u32, index: u32, flags: u32) {
    let owner = tracker.owner.clone();
    if tracker.top != menu && !is_popup(menu) && !is_popup(tracker.top) {
        hide_sub_popups(&owner, tracker.top, false, flags);
        select_item(&owner, tracker.top, NO_SELECTED_ITEM, false, None);
        tracker.top = menu;
    } else {
        hide_sub_popups(&owner, menu, false, flags);
    }
    select_item(&owner, menu, index, true, None);
}

/// MENU_FindItemByCoords : la position de l'item de `menu` sous `pt` (à
/// l'écran) : dans la zone cliente d'un menu déroulant, dans la fenêtre de
/// sa barre.
fn item_at(menu: u32, (x, y): (i32, i32)) -> Option<u32> {
    let state = crate::menu::state(menu)?;
    let window = window::get(state.hwnd)?;
    let window_state = window.state();
    let origin = if state.flags & mnf::POPUP != 0 { window_state.client } else { window_state.window };
    let (x, y) = (x - origin.left, y - origin.top);
    state
        .items
        .iter()
        .position(|item| x >= item.x as i32 && x < item.cx as i32 && y >= item.y as i32 && y < item.cy as i32)
        .map(|at| at as u32)
}

/// MENU_PtMenu : le menu sous `pt` : un sous-menu ouvert d'abord, puis la
/// fenêtre de `menu` (un menu déroulant), ou l'un des items de sa barre.
fn menu_at(menu: u32, pt: (i32, i32)) -> Option<u32> {
    if let Some(found) = sub_popup(menu).and_then(|submenu| menu_at(submenu, pt)) {
        return Some(found);
    }
    let window = window_of(menu)?;
    let rect = window.state().window;
    if is_popup(menu) {
        let inside = pt.0 >= rect.left && pt.0 < rect.right && pt.1 >= rect.top && pt.1 < rect.bottom;
        inside.then_some(menu)
    } else {
        item_at(menu, pt).map(|_| menu)
    }
}

/// MENU_ButtonDown : un bouton enfoncé sur un item de `menu` le sélectionne
/// et ouvre son sous-menu ; faux ailleurs (le suivi finit).
fn button_down(tracker: &mut Tracker, menu: Option<u32>, flags: u32) -> bool {
    let Some(menu) = menu else { return false };
    let Some(index) = item_at(menu, tracker.pt) else { return false };
    if crate::menu::state(menu).is_some_and(|state| state.focused != index) {
        switch_tracking(tracker, menu, index, flags);
    }
    let opened = crate::menu::state(menu)
        .and_then(|state| state.items.get(index as usize).map(|item| item.f_state & mf::MOUSESELECT != 0))
        .unwrap_or(false);
    if !opened {
        let owner = tracker.owner.clone();
        tracker.current = show_sub_popup(&owner, menu, false, flags);
    }
    true
}

/// MENU_ButtonUp : relâché sur l'item sélectionné de `menu` qui n'ouvre pas
/// de sous-menu, il est exécuté (son identifiant) ; -1 sinon (le suivi
/// continue).
fn button_up(tracker: &mut Tracker, menu: Option<u32>, flags: u32) -> i32 {
    let Some(menu) = menu else { return -1 };
    let Some(index) = item_at(menu, tracker.pt) else { return -1 };
    let Some(state) = crate::menu::state(menu) else { return -1 };
    if state.focused != index || state.items.get(index as usize).is_none_or(|item| item.submenu != 0) {
        return -1;
    }
    match exec_focused(tracker, menu, flags) {
        -1 | -2 => -1,
        id => id,
    }
}

/// MENU_MouseMove : l'item sous la souris est sélectionné et son
/// sous-menu ouvert ; hors des items, plus de sélection.
fn mouse_move(tracker: &mut Tracker, menu: Option<u32>, flags: u32) {
    let owner = tracker.owner.clone();
    match menu.and_then(|menu| Some((menu, item_at(menu, tracker.pt)?))) {
        None => select_item(&owner, tracker.current, NO_SELECTED_ITEM, true, Some(tracker.top)),
        Some((menu, index)) => {
            if crate::menu::state(menu).is_some_and(|state| state.focused != index) {
                switch_tracking(tracker, menu, index, flags);
                tracker.current = show_sub_popup(&owner, menu, false, flags);
            }
        }
    }
}

/// Le menu qui ouvre le menu courant (le parent du plus profond ouvert).
fn parent_of_current(tracker: &Tracker) -> u32 {
    let mut previous = tracker.top;
    let mut menu = tracker.top;
    while menu != tracker.current {
        previous = menu;
        match sub_popup(previous) {
            Some(next) => menu = next,
            None => break,
        }
    }
    previous
}

/// MENU_KeyEscape : le sous-menu le plus profond se ferme ; vrai s'il n'y en
/// avait pas (le suivi finit).
fn key_escape(tracker: &mut Tracker, flags: u32) -> bool {
    if tracker.current == tracker.top || !is_popup(tracker.current) {
        return true;
    }
    let previous = parent_of_current(tracker);
    let owner = tracker.owner.clone();
    hide_sub_popups(&owner, previous, true, flags);
    tracker.current = previous;
    false
}

/// MENU_KeyLeft, pour les menus déroulants : le sous-menu le plus profond se
/// ferme.
fn key_left(tracker: &mut Tracker, flags: u32) {
    let previous = parent_of_current(tracker);
    let owner = tracker.owner.clone();
    hide_sub_popups(&owner, previous, true, flags);
    tracker.current = previous;
}

/// MENU_KeyRight, pour les menus déroulants : le sous-menu de l'item
/// sélectionné s'ouvre, son premier item sélectionné.
fn key_right(tracker: &mut Tracker, flags: u32) {
    if is_popup(tracker.top) || tracker.current != tracker.top {
        let owner = tracker.owner.clone();
        tracker.current = show_sub_popup(&owner, tracker.current, true, flags);
    }
}

/// La lettre soulignée de `text` : celle qui suit le premier `&` qui n'est
/// pas doublé.
fn mnemonic(text: &[u16]) -> Option<u16> {
    let mut at = 0;
    while at + 1 < text.len() {
        if text[at] == u16::from(b'&') {
            if text[at + 1] != u16::from(b'&') {
                return Some(text[at + 1]);
            }
            at += 2;
        } else {
            at += 1;
        }
    }
    None
}

/// Une lettre en majuscule (towupper, pour l'ASCII et le Latin-1).
fn upper(unit: u16) -> u16 {
    match unit {
        0x61..=0x7A | 0xE0..=0xFE if unit != 0xF7 => unit - 0x20,
        _ => unit,
    }
}

/// MENU_FindItemByKey : la position de l'item de `menu` dont la lettre
/// soulignée est `key` ; sans lui, WM_MENUCHAR à la propriétaire :
/// MNC_EXECUTE donne la position, MNC_CLOSE -2 (le suivi finit) ; -1 sinon.
fn find_item_by_key(owner: &Window, menu: u32, key: u16) -> i32 {
    let Some(state) = crate::menu::state(menu) else { return -1 };
    if let Some(at) = state.items.iter().position(|item| mnemonic(&item.text).map(upper) == Some(upper(key))) {
        return at as i32;
    }
    let flags = if state.flags & mnf::POPUP != 0 { mf::POPUP } else { 0 } | system_flag(menu);
    let answer = send(owner, wm::MENUCHAR, make_long(u32::from(key), flags), menu);
    match answer >> 16 {
        mnc::EXECUTE => (answer & 0xFFFF) as i32,
        mnc::CLOSE => -2,
        _ => -1,
    }
}

/// La souris rendue (et le thread ne suit plus de menu : MSQ_STATE_MENUOWNER
/// retiré).
fn release_capture(thread: &ThreadInfo) {
    thread.queue.with(|queue| queue.menu_owner = 0);
    crate::mouse::set_capture(thread, None);
}

/// Le filtre d'un message de type `message`.
fn only(message: u32) -> Filter {
    Filter { hwnd: 0, min: message, max: message }
}

/// Le premier message de la file du thread, laissé dedans ; attend qu'il en
/// arrive un (WM_ENTERIDLE à la propriétaire la première fois que la file
/// est vide). `None` si l'attente finit autrement (le thread finit) ou si la
/// propriétaire ou la fenêtre du menu courant n'est plus.
fn next_message(thread: &ThreadInfo, tracker: &Tracker, idle_sent: &mut bool) -> Option<Msg32> {
    loop {
        if let Some(message) = crate::queue::peek(thread, &Filter { hwnd: 0, min: 0, max: 0 }, false) {
            return Some(message);
        }
        window::get(tracker.owner.handle)?;
        window_of(tracker.current)?;
        if !*idle_sent {
            *idle_sent = true;
            let popup = if is_popup(tracker.current) { window_of(tracker.current).map_or(0, |w| w.handle) } else { 0 };
            send(&tracker.owner, wm::ENTERIDLE, MSGF_MENU, popup);
        }
        crate::queue::wait_message(thread).ok()?;
    }
}

/// MENU_TrackMenu : la boucle du menu `menu` à `owner`, depuis (`x`, `y`) ;
/// rend, avec TPM_RETURNCMD, l'identifiant de l'item exécuté (0 sans) ;
/// sinon 1.
fn track_menu(menu: u32, flags: u32, (x, y): (i32, i32), owner: &Arc<Window>) -> i32 {
    let Ok(thread) = crate::convert_current_thread() else { return 0 };
    let mut tracker = Tracker { current: menu, top: menu, owner: owner.clone(), pt: (x, y) };
    let mut inside = true;
    if flags & tpm::BUTTONDOWN != 0 {
        inside = button_down(&mut tracker, Some(menu), flags);
    }
    if flags & tpm::POPUPMENU != 0 && crate::menu::state(menu).is_none_or(|state| state.items.is_empty()) {
        release_capture(&thread);
        return 0;
    }
    let mut executed = -1;
    let mut idle_sent = false;
    while inside {
        if !crate::menu::exists(tracker.current) {
            break;
        }
        let Some(message) = next_message(&thread, &tracker, &mut idle_sent) else { break };
        if message.message == wm::CANCELMODE {
            let _ = crate::queue::peek(&thread, &only(message.message), true);
            break;
        }
        tracker.pt = (message.pt_x, message.pt_y);
        if (WM_MOUSEFIRST..=WM_MOUSELAST).contains(&message.message) {
            // The place in lParam, at the screen's (the thread tracks a
            // menu), so that a message posted by a program counts too.
            let (x, y) = (message.l_param as u16 as i16, (message.l_param >> 16) as u16 as i16);
            tracker.pt = (i32::from(x), i32::from(y));
        }
        let current_window = window_of(tracker.current).map_or(0, |window| window.handle);
        if message.hwnd == current_window || (message.message != WM_TIMER && message.message != WM_SYSTIMER) {
            idle_sent = false;
        }
        let kind = message.message;
        let mut remove = false;
        // No frame's mouse message: the menu has the capture.
        if (WM_MOUSEFIRST..=WM_MOUSELAST).contains(&kind) {
            let under = menu_at(tracker.top, tracker.pt);
            let right = flags & tpm::RIGHTBUTTON != 0;
            match kind {
                // Without TPM_RIGHTBUTTON, a double click of the right button
                // still ends the tracking.
                WM_RBUTTONDBLCLK if !right => inside = false,
                WM_RBUTTONDOWN if !right => {}
                WM_LBUTTONDOWN | WM_LBUTTONDBLCLK | WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => {
                    remove = button_down(&mut tracker, under, flags);
                    inside = remove && kind != WM_RBUTTONDBLCLK;
                }
                WM_RBUTTONUP if !right => {}
                WM_LBUTTONUP | WM_RBUTTONUP => {
                    if under.is_some() {
                        executed = button_up(&mut tracker, under, flags);
                        remove = executed != -1;
                        inside = !remove;
                    } else {
                        inside = flags & tpm::POPUPMENU != 0;
                    }
                }
                WM_MOUSEMOVE if under.is_some() => mouse_move(&mut tracker, under, flags),
                _ => {}
            }
        } else if (WM_KEYFIRST..=WM_KEYLAST).contains(&message.message) {
            remove = true;
            let owner = tracker.owner.clone();
            match message.message {
                WM_KEYDOWN | WM_SYSKEYDOWN => match message.w_param as u8 {
                    VK_MENU | VK_F10 => inside = false,
                    key @ (VK_HOME | VK_END) => {
                        select_item(&owner, tracker.current, NO_SELECTED_ITEM, false, None);
                        move_selection(&owner, tracker.current, if key == VK_HOME { 1 } else { -1 });
                    }
                    key @ (VK_UP | VK_DOWN) => {
                        if is_popup(tracker.current) {
                            move_selection(&owner, tracker.current, if key == VK_UP { -1 } else { 1 });
                        } else {
                            tracker.current = show_sub_popup(&owner, tracker.top, true, flags);
                        }
                    }
                    VK_LEFT => key_left(&mut tracker, flags),
                    VK_RIGHT => key_right(&mut tracker, flags),
                    VK_ESCAPE => inside = !key_escape(&mut tracker, flags),
                    _ => {
                        crate::input::translate_message(&thread, &message);
                    }
                },
                WM_CHAR | WM_SYSCHAR => {
                    let key = message.w_param as u16;
                    if key == u16::from(b'\r') || key == u16::from(b' ') {
                        let current = tracker.current;
                        executed = exec_focused(&mut tracker, current, flags);
                        inside = executed == -2;
                    } else if key >= 32 {
                        match find_item_by_key(&owner, tracker.current, key) {
                            -2 => inside = false,
                            -1 => {}
                            at => {
                                select_item(&owner, tracker.current, at as u32, true, None);
                                let current = tracker.current;
                                executed = exec_focused(&mut tracker, current, flags);
                                inside = executed == -2;
                            }
                        }
                    }
                }
                _ => {}
            }
        } else {
            if let Some(message) = crate::queue::peek(&thread, &only(message.message), true) {
                let _ = window::dispatch_message(&message);
            }
            continue;
        }
        if inside {
            remove = true;
        }
        if remove {
            let _ = crate::queue::peek(&thread, &only(message.message), true);
        }
    }
    release_capture(&thread);
    let owner = tracker.owner.clone();
    if crate::menu::exists(tracker.top) && window::get(owner.handle).is_some() {
        hide_sub_popups(&owner, tracker.top, false, flags);
        if is_popup(tracker.top) {
            if let Some(window) = window_of(tracker.top) {
                let _ = crate::destroy::destroy_window(&window);
            }
            crate::menu::set_hwnd(tracker.top, 0);
            if flags & tpm::NONOTIFY == 0 {
                send(&owner, wm::UNINITMENUPOPUP, tracker.top, make_long(0, system_flag(tracker.top)));
            }
        }
        select_item(&owner, tracker.top, NO_SELECTED_ITEM, false, None);
        send(&owner, wm::MENUSELECT, make_long(0, 0xFFFF), 0);
    }
    let _ = crate::set_last_error(0);
    if flags & tpm::RETURNCMD == 0 {
        return 1;
    }
    executed.max(0)
}

/// MENU_InitTracking : le caret caché, WM_ENTERMENULOOP, la souris capturée
/// (par la fenêtre du menu déroulant, ou par la propriétaire), WM_SETCURSOR,
/// WM_INITMENU.
fn init_tracking(owner: &Arc<Window>, menu: u32, popup: bool, flags: u32) {
    let _ = crate::caret::hide(0);
    if !popup {
        crate::menu::set_hwnd(menu, owner.handle);
    }
    let mut top = TOP.lock();
    if top.is_none() {
        let hwnd = crate::menu::state(menu).map_or(0, |state| state.hwnd);
        *top = Some((hwnd, menu));
    }
    drop(top);
    if flags & tpm::NONOTIFY == 0 {
        send(owner, wm::ENTERMENULOOP, u32::from(popup), 0);
    }
    // The capture before WM_INITMENU, after WM_ENTERMENULOOP.
    let capture = if flags & tpm::POPUPMENU != 0 { window_of(menu) } else { Some(owner.clone()) };
    if let (Ok(thread), Some(capture)) = (crate::convert_current_thread(), capture) {
        thread.queue.with(|queue| queue.menu_owner = capture.handle);
        crate::mouse::set_capture(&thread, Some(&capture));
    }
    send(owner, WM_SETCURSOR, owner.handle, HTCAPTION);
    if flags & tpm::NONOTIFY == 0 {
        send(owner, wm::INITMENU, menu, 0);
    }
}

/// MENU_ExitTracking : WM_EXITMENULOOP, le caret remontré, plus de menu
/// suivi.
fn exit_tracking(owner: &Window, popup: bool, flags: u32) {
    if flags & tpm::NONOTIFY == 0 {
        send(owner, wm::EXITMENULOOP, u32::from(popup), 0);
    }
    let _ = crate::caret::show(0);
    *TOP.lock() = None;
}

/// IntTrackPopupMenuEx : le menu déroulant `menu` montré en (`x`, `y`)
/// (selon `flags`, à côté de `exclude`) et suivi pour `owner`, une fenêtre
/// du thread courant ; rend ce que la boucle rend (l'identifiant de l'item
/// choisi avec TPM_RETURNCMD).
///
/// # Errors
/// `ERROR_POPUP_ALREADY_ACTIVE` pour un menu déjà montré.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn track_popup_menu(
    menu: u32,
    flags: u32,
    (x, y): (i32, i32),
    owner: &Arc<Window>,
    exclude: Option<Rect>,
) -> Result<u32, u32> {
    if window_of(menu).is_some() {
        return Err(ERROR_POPUP_ALREADY_ACTIVE);
    }
    if !init_popup(owner, menu) {
        return Ok(0);
    }
    init_tracking(owner, menu, true, flags);
    if flags & tpm::NONOTIFY == 0 {
        send(owner, wm::INITMENUPOPUP, menu, make_long(0, u32::from(system_flag(menu) != 0)));
    }
    let result = if show_popup(menu, flags | tpm::POPUPMENU, (x, y), exclude) {
        track_menu(menu, flags | tpm::POPUPMENU, (0, 0), owner)
    } else {
        if let Ok(thread) = crate::convert_current_thread() {
            release_capture(&thread);
        }
        0
    };
    exit_tracking(owner, true, flags);
    if let Some(window) = window_of(menu) {
        let _ = crate::destroy::destroy_window(&window);
        crate::menu::set_hwnd(menu, 0);
        if flags & tpm::NONOTIFY == 0 {
            send(owner, wm::UNINITMENUPOPUP, menu, make_long(0, system_flag(menu)));
        }
    }
    Ok(result as u32)
}

/// NtUserEndMenu : le suivi en cours finit (WM_CANCELMODE posté à la
/// fenêtre du menu suivi) ; rien sans lui.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn end_menu() {
    let top = *TOP.lock();
    if let Some(window) = top.and_then(|(hwnd, _)| window::get(hwnd)) {
        post(&window, wm::CANCELMODE, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric(index: usize) -> i32 {
        match index {
            sm::CYMENUSIZE => 18,
            sm::CYDLGFRAME => 3,
            _ => 0,
        }
    }

    const SCREEN: Rect = Rect { left: 0, top: 0, right: 640, bottom: 480 };

    #[test]
    fn a_popup_goes_where_asked_and_stays_on_the_screen() {
        let size = (100, 60);
        assert_eq!(popup_place(tpm::POPUPMENU, (50, 40), size, None, SCREEN, &metric), (50, 40));
        assert_eq!(popup_place(tpm::POPUPMENU | tpm::RIGHTALIGN, (150, 40), size, None, SCREEN, &metric), (50, 40));
        assert_eq!(popup_place(tpm::POPUPMENU | tpm::BOTTOMALIGN, (50, 100), size, None, SCREEN, &metric), (50, 40));
        assert_eq!(popup_place(tpm::POPUPMENU, (600, 40), size, None, SCREEN, &metric), (540, 40), "the right edge");
        assert_eq!(popup_place(tpm::POPUPMENU, (-20, 40), size, None, SCREEN, &metric), (0, 40), "the left edge");
        // Too low: its bottom a menu bar's height under the point (450 + 18 +
        // 2 * 3), or above the point when that is off the screen too.
        assert_eq!(popup_place(tpm::POPUPMENU, (50, 450), size, None, SCREEN, &metric), (50, 414));
        assert_eq!(popup_place(tpm::POPUPMENU, (50, 470), size, None, SCREEN, &metric), (50, 410));
        // Off the bottom from the start: the screen's bottom.
        assert_eq!(popup_place(tpm::POPUPMENU, (50, 500), size, None, SCREEN, &metric), (50, 420));
    }

    #[test]
    fn a_submenu_avoids_its_parent() {
        // To the right of the parent, unless it does not fit: then left.
        let parent = Rect::new(500, 100, 600, 200);
        assert_eq!(popup_place(0, (597, 100), (100, 60), Some(parent), SCREEN, &metric), (400, 100));
        let room = Rect::new(100, 100, 200, 200);
        assert_eq!(popup_place(0, (197, 100), (100, 60), Some(room), SCREEN, &metric), (200, 100));
    }

    #[test]
    fn the_underlined_letter_of_an_item() {
        let wide = |text: &str| -> alloc::vec::Vec<u16> { text.encode_utf16().collect() };
        assert_eq!(mnemonic(&wide("&Open")), Some(u16::from(b'O')));
        assert_eq!(mnemonic(&wide("Save && E&xit")), Some(u16::from(b'x')));
        assert_eq!(mnemonic(&wide("Plain")), None);
        assert_eq!(mnemonic(&wide("End&")), None);
        assert_eq!((upper(u16::from(b'x')), upper(0xE9)), (u16::from(b'X'), 0xC9));
    }
}
