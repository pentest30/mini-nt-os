//! Déplacer et redimensionner une fenêtre à la souris, et les boutons de son
//! titre : ce que DefWindowProc fait d'un appui sur le cadre
//! (NC_HandleNCLButtonDown, NC_DoButton, DefWndHandleSysCommand et
//! DefWndDoSizeMove de ReactOS, `nonclient.c` et `defwnd.c`, comme
//! spécification).
//!
//! Un appui sur la barre de titre active la fenêtre et demande SC_MOVE ; sur
//! un bord ou un coin d'un cadre épais, SC_SIZE avec le bord (WMSZ_*). La
//! boucle de déplacement ([`size_move`]) prend la capture, envoie
//! WM_ENTERSIZEMOVE, puis tire les messages de la file du thread : chaque
//! mouvement place la fenêtre (le contenu suit, comme « afficher le contenu
//! des fenêtres pendant leur déplacement », le réglage d'XP par défaut), la
//! taille bornée par WM_GETMINMAXINFO ; le relâchement ou Entrée finit,
//! Échap rend la place de départ ; les autres messages sont distribués.
//! Elle rend la capture et envoie WM_EXITSIZEMOVE.
//!
//! Un appui sur un bouton du titre le suit ([`track_button`]) jusqu'au
//! relâchement : sur le même bouton, WM_SYSCOMMAND (SC_CLOSE, SC_MINIMIZE,
//! SC_MAXIMIZE ou SC_RESTORE). SC_CLOSE envoie WM_CLOSE ; réduire et
//! agrandir passent par ShowWindow (`crate::winpos`). Un appui sur la barre
//! de menus demande SC_MOUSEMENU, que le suivi de la barre traite comme
//! SC_KEYMENU (`crate::menutrack`).
//!
//! Le bouton est peint enfoncé pendant son suivi, tant que la souris est
//! dessus. Un double-clic sur le titre agrandit ou rétablit la fenêtre
//! (`crate::defwnd::double_click`).
//!
//! Au clavier (SC_MOVE ou SC_SIZE sans endroit, le menu de la fenêtre :
//! [`keyboard_start`], DefWndStartSizeMove), le curseur va au milieu du
//! titre pour déplacer ; pour redimensionner, une flèche choisit le bord
//! (le curseur va en son milieu), ou la souris l'atteint. Dans la boucle,
//! chaque flèche déplace le curseur de 8 pixels ([`arrow_step`]), ce qui
//! produit le mouvement de la souris que la boucle suit ; la souris aussi
//! déplace ou redimensionne, Entrée ou un clic finit, Échap rend la place de
//! départ. Les autres touches enfoncées sont mangées.
//!
//! Pas encore : le cadre en pointillés (sans le contenu), WM_MOVING et
//! WM_SIZING, WH_MSGFILTER (MSGF_SIZE) dans les boucles, le curseur borné à
//! la zone de travail (ReactOS borne le point à SPI_GETWORKAREA), le
//! curseur en flèches croisées pendant le déplacement au clavier.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::user::vk::{VK_DOWN, VK_ESCAPE, VK_LEFT, VK_RETURN, VK_RIGHT, VK_UP};
use abi::user::{
    sm, Msg32, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTCAPTION, HTCLOSE, HTHSCROLL, HTLEFT, HTMAXBUTTON, HTMENU,
    HTMINBUTTON, HTRIGHT, HTSYSMENU, HTTOP, HTTOPLEFT, HTTOPRIGHT, HTVSCROLL, SC_CLOSE, SC_HSCROLL, SC_KEYMENU,
    SC_MAXIMIZE, SC_MINIMIZE, SC_MOUSEMENU, SC_MOVE, SC_RESTORE, SC_SIZE, SC_VSCROLL, SWP_NOACTIVATE, SWP_NOSIZE,
    SWP_NOZORDER, SW_MINIMIZE, SW_RESTORE, SW_SHOWMAXIMIZED, WMSZ_BOTTOMRIGHT, WMSZ_LEFT, WM_CLOSE, WM_ENTERSIZEMOVE,
    WM_EXITSIZEMOVE, WM_KEYDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_QUIT, WM_SETCURSOR, WM_SYSCOMMAND, WS_BORDER, WS_CHILD,
    WS_DLGFRAME, WS_MAXIMIZE, WS_MAXIMIZEBOX, WS_MINIMIZE, WS_MINIMIZEBOX, WS_SYSMENU, WS_THICKFRAME, WS_VISIBLE,
};

use crate::gdi::dib::Rect;
use crate::gui::ThreadInfo;
use crate::queue::Filter;
use crate::window::{LParam, Window};

/// HTLEFT, le premier bord : WMSZ_* = HT* − (HTLEFT − WMSZ_LEFT).
const EDGE_OFFSET: u32 = HTLEFT - WMSZ_LEFT;

/// Le point (signé sur 16 bits) d'un `lParam` de la souris.
fn point_of(lparam: u32) -> (i32, i32) {
    (i32::from(lparam as u16 as i16), i32::from((lparam >> 16) as u16 as i16))
}

/// Ce qu'on tire d'une fenêtre : son titre (déplacer) ou un bord (HTLEFT à
/// HTBOTTOMRIGHT), d'après le `wParam` de SC_MOVE ou SC_SIZE ; `None` pour
/// une commande du clavier (les 4 bits bas à 0) ou un bord inconnu.
pub fn dragged_part(wparam: u32) -> Option<u32> {
    let low = wparam & 0x000F;
    match wparam & 0xFFF0 {
        SC_MOVE if low != 0 => Some(HTCAPTION),
        SC_SIZE if (WMSZ_LEFT..=WMSZ_BOTTOMRIGHT).contains(&low) => Some(low + EDGE_OFFSET),
        _ => None,
    }
}

/// DefWndDoSizeMove, la règle : la commande `command` (SC_MOVE ou SC_SIZE)
/// peut commencer pour une fenêtre de style `style` : visible, pas agrandie ;
/// pour redimensionner, un cadre épais (UserHasThickFrameStyle : pas
/// seulement un cadre de dialogue), et pas réduite.
pub fn can_size_move(style: u32, command: u32) -> bool {
    if style & WS_VISIBLE == 0 || style & WS_MAXIMIZE != 0 {
        return false;
    }
    let thick = style & WS_THICKFRAME != 0 && style & (WS_DLGFRAME | WS_BORDER) != WS_DLGFRAME;
    command != SC_SIZE || (thick && style & WS_MINIMIZE == 0)
}

/// DefWndStartSizeMove, la règle de SC_MOVE au clavier : le point où le
/// curseur va pour déplacer une fenêtre de rectangle `window` (à l'écran) et
/// de style `style` : au milieu du titre sans l'icône ni les boutons Réduire
/// et Agrandir, à une demi-hauteur de bouton sous le haut de la fenêtre,
/// d'après les métriques `m`.
pub fn move_start_point(window: Rect, style: u32, m: &impl Fn(usize) -> i32) -> (i32, i32) {
    let button = m(sm::CXSIZE) + 1;
    let mut rect = window;
    if style & WS_SYSMENU != 0 {
        rect.left += button;
    }
    if style & WS_MINIMIZEBOX != 0 {
        rect.right -= button;
    }
    if style & WS_MAXIMIZEBOX != 0 {
        rect.right -= button;
    }
    ((rect.left + rect.right) / 2, rect.top + m(sm::CYSIZE) / 2)
}

/// DefWndStartSizeMove, la règle de SC_SIZE au clavier : le bord que la
/// flèche `key` (VK_*) choisit sur une fenêtre de rectangle `window` et de
/// cadre épais `frame` (SM_CXFRAME, SM_CYFRAME), et le point où le curseur va :
/// le milieu de ce bord, à mi-épaisseur du cadre ; `None` pour une autre
/// touche.
pub fn size_start_edge(key: u32, window: Rect, frame: (i32, i32)) -> Option<(u32, (i32, i32))> {
    let (middle_x, middle_y) = ((window.left + window.right) / 2, (window.top + window.bottom) / 2);
    match u8::try_from(key).ok()? {
        VK_UP => Some((HTTOP, (middle_x, window.top + frame.1 / 2))),
        VK_DOWN => Some((HTBOTTOM, (middle_x, window.bottom - frame.1 / 2))),
        VK_LEFT => Some((HTLEFT, (window.left + frame.0 / 2, middle_y))),
        VK_RIGHT => Some((HTRIGHT, (window.right - frame.0 / 2, middle_y))),
        _ => None,
    }
}

/// DefWndStartSizeMove, la règle : le point (`x`, `y`) ramené dans le
/// rectangle `rect`, pour chercher le bord que la souris atteint. Comme
/// ReactOS (`min(max(x, gauche), droite - 1)`), un rectangle vide ne fait pas
/// d'erreur : le point va à droite - 1 (ou en bas - 1).
pub fn point_into((x, y): (i32, i32), rect: Rect) -> (i32, i32) {
    (x.max(rect.left).min(rect.right - 1), y.max(rect.top).min(rect.bottom - 1))
}

/// DefWndDoSizeMove, la règle : ce dont la flèche `key` (VK_*) déplace le
/// curseur pendant la boucle, 8 pixels ; `None` pour une autre touche.
pub fn arrow_step(key: u32) -> Option<(i32, i32)> {
    const STEP: i32 = 8;
    match u8::try_from(key).ok()? {
        VK_UP => Some((0, -STEP)),
        VK_DOWN => Some((0, STEP)),
        VK_LEFT => Some((-STEP, 0)),
        VK_RIGHT => Some((STEP, 0)),
        _ => None,
    }
}

/// Le rectangle de la fenêtre partie de `start` quand la souris a bougé de
/// (`dx`, `dy`) : tout entier pour le titre, sinon les bords saisis (`part`,
/// HTLEFT…), sa largeur et sa hauteur bornées par `min` et `max` (le bord
/// opposé ne bouge pas).
pub fn dragged_rect(start: Rect, part: u32, (dx, dy): (i32, i32), min: [i32; 2], max: [i32; 2]) -> Rect {
    if part == HTCAPTION {
        return Rect::new(start.left + dx, start.top + dy, start.right + dx, start.bottom + dy);
    }
    let (left, right) =
        (matches!(part, HTLEFT | HTTOPLEFT | HTBOTTOMLEFT), matches!(part, HTRIGHT | HTTOPRIGHT | HTBOTTOMRIGHT));
    let (top, bottom) =
        (matches!(part, HTTOP | HTTOPLEFT | HTTOPRIGHT), matches!(part, HTBOTTOM | HTBOTTOMLEFT | HTBOTTOMRIGHT));
    let limit = |size: i32, axis: usize| size.min(max[axis]).max(min[axis]);
    let mut rect = start;
    if left {
        rect.left = start.right - limit(start.right - start.left - dx, 0);
    } else if right {
        rect.right = start.left + limit(start.right - start.left + dx, 0);
    }
    if top {
        rect.top = start.bottom - limit(start.bottom - start.top - dy, 1);
    } else if bottom {
        rect.bottom = start.top + limit(start.bottom - start.top + dy, 1);
    }
    rect
}

/// La commande d'un bouton du titre `hit` d'une fenêtre de style `style` :
/// fermer (si Close est actif, `close_enabled` :
/// `crate::sysmenu::close_enabled`), réduire ou rétablir une fenêtre
/// réduite, agrandir ou rétablir une fenêtre agrandie ; `None` pour un
/// bouton que le style ou Close désactive (NC_DoButton : rien ne se passe).
pub fn button_command(hit: u32, style: u32, close_enabled: bool) -> Option<u32> {
    match hit {
        HTCLOSE => close_enabled.then_some(SC_CLOSE),
        HTMINBUTTON if style & WS_MINIMIZEBOX != 0 => {
            Some(if style & WS_MINIMIZE != 0 { SC_RESTORE } else { SC_MINIMIZE })
        }
        HTMAXBUTTON if style & WS_MAXIMIZEBOX != 0 => {
            Some(if style & WS_MAXIMIZE != 0 { SC_RESTORE } else { SC_MAXIMIZE })
        }
        _ => None,
    }
}

/// Ce qui n'est pas encore fait, journalisé une fois.
fn report_missing(what: &str, reported: &AtomicBool) {
    if !reported.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: DefWindowProc: {what}: not yet");
    }
}

/// Le message suivant de la file du thread, dans une boucle modale ; `None`
/// quand elle doit finir (WM_QUIT, qui est reposté ; une attente
/// interrompue).
fn next_message(thread: &ThreadInfo) -> Option<Msg32> {
    let message = crate::queue::get(thread, &Filter { hwnd: 0, min: 0, max: 0 }).ok()?;
    if message.message == WM_QUIT {
        crate::queue::post_quit(thread, message.w_param);
        return None;
    }
    Some(message)
}

/// Un message que la boucle modale ne prend pas : traduit et distribué,
/// comme dans la boucle du programme.
fn pass_on(thread: &ThreadInfo, message: &Msg32) {
    crate::input::translate_message(thread, message);
    let _ = crate::window::dispatch_message(message);
}

/// Place `window` sur le rectangle `rect` de l'écran (dans la zone cliente
/// de son parent pour une fenêtre fille), sans changer sa taille pour un
/// déplacement (`moving`).
fn place(window: &Arc<Window>, rect: Rect, moving: bool) {
    let state = window.state();
    let origin = match crate::window::get(state.parent) {
        Some(parent) if state.style & WS_CHILD != 0 => (parent.state().client.left, parent.state().client.top),
        _ => (0, 0),
    };
    let mut flags = SWP_NOZORDER | SWP_NOACTIVATE;
    if moving {
        flags |= SWP_NOSIZE;
    }
    let (x, y) = (rect.left - origin.0, rect.top - origin.1);
    crate::winpos::set_window_pos(window, 0, x, y, rect.right - rect.left, rect.bottom - rect.top, flags);
}

/// DefWndStartSizeMove : le départ au clavier de la commande `command`
/// (SC_MOVE ou SC_SIZE) pour `window`, du thread `thread` : l'endroit tiré
/// (HTCAPTION, ou le bord choisi) et le point où le curseur est allé, que
/// [`size_move`] suit. Pour déplacer, le milieu du titre
/// ([`move_start_point`]) ; pour redimensionner, la boucle attend une flèche
/// ([`size_start_edge`]) ou que la souris, ramenée dans la fenêtre,
/// atteigne un bord ; Entrée, Échap ou un clic relâché renoncent (`None`) ;
/// les autres messages sont distribués. Le curseur va au point
/// ([`crate::mouse::set_cursor_pos`]), puis WM_SETCURSOR (l'endroit,
/// WM_MOUSEMOVE).
fn keyboard_start(thread: &ThreadInfo, window: &Arc<Window>, command: u32) -> Option<(u32, (i32, i32))> {
    let m = crate::metrics::get;
    let (part, point) = if command == SC_MOVE {
        let state = window.state();
        (HTCAPTION, move_start_point(state.window, state.style, &m))
    } else {
        loop {
            let message = next_message(thread)?;
            let rect = window.state().window;
            match message.message {
                WM_MOUSEMOVE => {
                    let point = point_into((message.pt_x, message.pt_y), rect);
                    let hit = crate::defwnd::window_hit_test(window, point);
                    if (HTLEFT..=HTBOTTOMRIGHT).contains(&hit) {
                        break (hit, point);
                    }
                }
                WM_LBUTTONUP => return None,
                WM_KEYDOWN if [VK_RETURN, VK_ESCAPE].map(u32::from).contains(&message.w_param) => return None,
                WM_KEYDOWN => {
                    if let Some(found) = size_start_edge(message.w_param, rect, (m(sm::CXFRAME), m(sm::CYFRAME))) {
                        break found;
                    }
                }
                _ => pass_on(thread, &message),
            }
        }
    };
    let point = crate::mouse::set_cursor_pos(point.0, point.1);
    let lparam = (part & 0xFFFF) | (WM_MOUSEMOVE << 16);
    let _ = crate::window::send_message(window, WM_SETCURSOR, window.handle, LParam::Value(lparam));
    Some((part, point))
}

/// DefWndDoSizeMove : la boucle qui déplace (`wparam` SC_MOVE) ou
/// redimensionne (SC_SIZE) `window`, si elle le peut ([`can_size_move`]) :
/// à la souris, depuis l'endroit du `wparam` et le point `lparam` de
/// l'écran ; sans endroit (le menu de la fenêtre), d'abord le départ au
/// clavier ([`keyboard_start`]). La souris déplace ou redimensionne, chaque
/// flèche déplace le curseur ([`arrow_step`]) ; un clic relâché ou Entrée
/// finit, Échap rend la place de départ.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système du thread de la fenêtre, sans
/// rien tenir.
pub fn size_move(window: &Arc<Window>, wparam: u32, lparam: u32) {
    let Ok(thread) = crate::convert_current_thread() else { return };
    if window.pti != thread.server {
        return;
    }
    let command = wparam & 0xFFF0;
    let state = window.state();
    if !can_size_move(state.style, command) {
        return;
    }
    let (part, origin) = match dragged_part(wparam) {
        Some(part) => (part, point_of(lparam)),
        None => {
            // Sizing: the mouse is the window's while an edge is chosen.
            if command == SC_SIZE {
                crate::mouse::set_capture(&thread, Some(window));
            }
            match keyboard_start(&thread, window, command) {
                Some(start) => start,
                None => {
                    if thread.queue.with(|queue| queue.capture).0 == window.handle {
                        crate::mouse::set_capture(&thread, None);
                    }
                    return;
                }
            }
        }
    };
    let start = window.state().window;
    let info = crate::window::min_max_info(window);
    let moving = part == HTCAPTION;

    crate::mouse::set_capture(&thread, Some(window));
    let _ = crate::window::send_message(window, WM_ENTERSIZEMOVE, 0, LParam::Value(0));
    let mut current = start;
    // Where the cursor is, as far as the loop knows: an arrow moves it from
    // there even before the move it makes comes out of the queue.
    let mut pointer = origin;
    while let Some(message) = next_message(&thread) {
        match message.message {
            WM_MOUSEMOVE => {
                pointer = (message.pt_x, message.pt_y);
                let delta = (message.pt_x - origin.0, message.pt_y - origin.1);
                let rect = dragged_rect(start, part, delta, info.min_track_size, info.max_track_size);
                if rect != current {
                    current = rect;
                    place(window, rect, moving);
                }
            }
            WM_LBUTTONUP => break,
            WM_KEYDOWN if message.w_param == u32::from(VK_RETURN) => break,
            WM_KEYDOWN if message.w_param == u32::from(VK_ESCAPE) => {
                if current != start {
                    place(window, start, moving);
                }
                break;
            }
            WM_KEYDOWN => {
                if let Some((dx, dy)) = arrow_step(message.w_param) {
                    pointer = crate::mouse::set_cursor_pos(pointer.0 + dx, pointer.1 + dy);
                }
            }
            _ => pass_on(&thread, &message),
        }
        if thread.queue.with(|queue| queue.capture).0 != window.handle {
            // Someone else took the capture: the loop is over.
            break;
        }
    }
    if thread.queue.with(|queue| queue.capture).0 == window.handle {
        crate::mouse::set_capture(&thread, None);
    }
    let _ = crate::window::send_message(window, WM_EXITSIZEMOVE, 0, LParam::Value(0));
}

/// NC_DoButton : suit l'appui sur le bouton du titre `hit` de `window`
/// jusqu'au relâchement. Le bouton est peint enfoncé tant que la souris est
/// dessus, relevé quand elle en sort ou qu'il est relâché
/// ([`crate::paint::draw_caption_button`]) ; relâché sur lui, sa commande
/// (WM_SYSCOMMAND, [`button_command`]).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système du thread de la fenêtre, sans
/// rien tenir.
pub fn track_button(window: &Arc<Window>, hit: u32) {
    let Some(command) = button_command(hit, window.state().style, crate::sysmenu::close_enabled(window)) else {
        return;
    };
    let Ok(thread) = crate::convert_current_thread() else { return };
    if window.pti != thread.server {
        return;
    }
    // Pending updates first: the button is drawn over what shows.
    crate::paint::update_windows(window, abi::user::RDW_ALLCHILDREN);
    let mut pressed = true;
    crate::paint::draw_caption_button(window, hit, pressed);
    crate::mouse::set_capture(&thread, Some(window));
    let mut released = None;
    while let Some(message) = next_message(&thread) {
        match message.message {
            WM_LBUTTONUP => {
                released = Some((message.pt_x, message.pt_y));
                break;
            }
            WM_MOUSEMOVE => {
                let over = crate::defwnd::window_hit_test(window, (message.pt_x, message.pt_y)) == hit;
                if over != pressed {
                    pressed = over;
                    crate::paint::draw_caption_button(window, hit, pressed);
                }
            }
            _ => pass_on(&thread, &message),
        }
        if thread.queue.with(|queue| queue.capture).0 != window.handle {
            break;
        }
    }
    if pressed {
        crate::paint::draw_caption_button(window, hit, false);
    }
    if thread.queue.with(|queue| queue.capture).0 == window.handle {
        crate::mouse::set_capture(&thread, None);
    }
    let Some(point) = released else { return };
    if crate::defwnd::window_hit_test(window, point) == hit {
        let lparam = crate::mouse::make_lparam(point.0, point.1);
        let _ = crate::window::send_message(window, WM_SYSCOMMAND, command, LParam::Value(lparam));
    }
}

/// NC_HandleNCLButtonDown : un appui gauche sur le cadre de `window`, à
/// l'endroit `hit`, au point `lparam` de l'écran.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système du thread de la fenêtre, sans
/// rien tenir.
pub fn nc_lbutton_down(window: &Arc<Window>, hit: u32, lparam: u32) {
    match hit {
        HTCAPTION => {
            crate::mouse::activate_by_mouse(window);
            let _ = crate::window::send_message(window, WM_SYSCOMMAND, SC_MOVE + HTCAPTION, LParam::Value(lparam));
        }
        HTLEFT..=HTBOTTOMRIGHT => {
            let command = SC_SIZE + hit - EDGE_OFFSET;
            let _ = crate::window::send_message(window, WM_SYSCOMMAND, command, LParam::Value(lparam));
        }
        HTCLOSE | HTMINBUTTON | HTMAXBUTTON => track_button(window, hit),
        // The menu bar: DefWindowProc tracks it (SC_MOUSEMENU).
        HTMENU => {
            let _ = crate::window::send_message(window, WM_SYSCOMMAND, SC_MOUSEMENU + HTMENU, LParam::Value(lparam));
        }
        // The caption's icon: the window menu.
        HTSYSMENU if window.state().style & WS_SYSMENU != 0 => {
            let command = SC_MOUSEMENU + HTSYSMENU;
            let _ = crate::window::send_message(window, WM_SYSCOMMAND, command, LParam::Value(lparam));
        }
        // user32 follows the mouse on the bar (DefWndTrackScrollBar).
        HTHSCROLL => {
            let _ = crate::window::send_message(window, WM_SYSCOMMAND, SC_HSCROLL + HTHSCROLL, LParam::Value(lparam));
        }
        HTVSCROLL => {
            let _ = crate::window::send_message(window, WM_SYSCOMMAND, SC_VSCROLL + HTVSCROLL, LParam::Value(lparam));
        }
        _ => {}
    }
}

/// DefWndHandleSysCommand : la commande `wparam` (SC_*) pour `window`.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système du thread de la fenêtre, sans
/// rien tenir.
pub fn sys_command(window: &Arc<Window>, wparam: u32, lparam: u32) {
    match wparam & 0xFFF0 {
        SC_MOVE | SC_SIZE => size_move(window, wparam, lparam),
        SC_CLOSE => {
            let _ = crate::window::send_message(window, WM_CLOSE, 0, LParam::Value(0));
        }
        SC_MINIMIZE => {
            crate::winpos::show_window(window, SW_MINIMIZE);
        }
        SC_MAXIMIZE => {
            crate::winpos::show_window(window, SW_SHOWMAXIMIZED);
        }
        SC_RESTORE => {
            crate::winpos::show_window(window, SW_RESTORE);
        }
        // user32 follows the mouse on a scroll bar itself; it gives the
        // kernel these only under a CBT hook.
        SC_VSCROLL | SC_HSCROLL => {}
        SC_MOUSEMENU => crate::menutrack::track_mouse_menu_bar(window, wparam & 0x000F, point_of(lparam)),
        SC_KEYMENU => crate::menutrack::track_kbd_menu_bar(window, lparam as u16),
        _ => {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            report_missing(
                "WM_SYSCOMMAND other than move, size, close, minimize, maximize, restore and the menus",
                &REPORTED,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::{HTCLIENT, WS_OVERLAPPEDWINDOW};

    #[test]
    fn the_part_a_command_drags() {
        assert_eq!(dragged_part(SC_MOVE + HTCAPTION), Some(HTCAPTION));
        assert_eq!(dragged_part(SC_MOVE), None, "from the keyboard");
        assert_eq!(dragged_part(SC_SIZE), None, "from the keyboard");
        assert_eq!(dragged_part(SC_SIZE + 1), Some(HTLEFT));
        assert_eq!(dragged_part(SC_SIZE + 8), Some(HTBOTTOMRIGHT));
        assert_eq!(dragged_part(SC_SIZE + 9), None);
        assert_eq!(dragged_part(SC_CLOSE), None);
    }

    #[test]
    fn what_may_be_moved_or_sized() {
        let style = WS_OVERLAPPEDWINDOW | WS_VISIBLE;
        assert!(can_size_move(style, SC_MOVE));
        assert!(can_size_move(style, SC_SIZE));
        assert!(!can_size_move(style & !WS_VISIBLE, SC_MOVE), "hidden");
        assert!(!can_size_move(style | WS_MAXIMIZE, SC_MOVE), "maximized");
        assert!(can_size_move(style | WS_MINIMIZE, SC_MOVE), "a minimized window moves");
        assert!(!can_size_move(style | WS_MINIMIZE, SC_SIZE), "but is not sized");
        let dialog = abi::user::WS_POPUP | abi::user::WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
        assert!(can_size_move(dialog, SC_MOVE));
        assert!(!can_size_move(dialog, SC_SIZE), "no thick frame");
        assert!(!can_size_move(WS_THICKFRAME | WS_DLGFRAME | WS_VISIBLE, SC_SIZE), "a dialog frame only");
    }

    #[test]
    fn the_keyboard_moves_from_the_middle_of_the_caption() {
        let m = |index: usize| match index {
            sm::CXSIZE => 18,
            sm::CYSIZE => 18,
            _ => 0,
        };
        let window = Rect::new(100, 100, 500, 400);
        // The icon (19) on the left, two boxes (2 × 19) on the right.
        assert_eq!(move_start_point(window, WS_OVERLAPPEDWINDOW, &m), (290, 109));
        let bare = abi::user::WS_POPUP | abi::user::WS_CAPTION;
        assert_eq!(move_start_point(window, bare, &m), (300, 109), "no icon, no boxes");
    }

    #[test]
    fn an_arrow_picks_the_edge_to_size() {
        let window = Rect::new(100, 100, 500, 400);
        let frame = (4, 4);
        assert_eq!(size_start_edge(u32::from(VK_UP), window, frame), Some((HTTOP, (300, 102))));
        assert_eq!(size_start_edge(u32::from(VK_DOWN), window, frame), Some((HTBOTTOM, (300, 398))));
        assert_eq!(size_start_edge(u32::from(VK_LEFT), window, frame), Some((HTLEFT, (102, 250))));
        assert_eq!(size_start_edge(u32::from(VK_RIGHT), window, frame), Some((HTRIGHT, (498, 250))));
        assert_eq!(size_start_edge(u32::from(VK_RETURN), window, frame), None);
        assert_eq!(size_start_edge(0x125, window, frame), None, "not a key code");
    }

    #[test]
    fn the_mouse_is_brought_into_the_window_to_pick_an_edge() {
        let window = Rect::new(100, 100, 500, 400);
        assert_eq!(point_into((50, 250), window), (100, 250), "left of it");
        assert_eq!(point_into((700, 900), window), (499, 399), "below right");
        assert_eq!(point_into((300, 200), window), (300, 200), "inside");
        // A window of no width or height (WM_WINDOWPOSCHANGING answered by
        // the program): i32::clamp would panic, its minimum above its maximum.
        assert_eq!(point_into((300, 200), Rect::new(100, 100, 100, 100)), (99, 99));
    }

    #[test]
    fn an_arrow_moves_the_cursor_by_eight_pixels() {
        assert_eq!(arrow_step(u32::from(VK_UP)), Some((0, -8)));
        assert_eq!(arrow_step(u32::from(VK_DOWN)), Some((0, 8)));
        assert_eq!(arrow_step(u32::from(VK_LEFT)), Some((-8, 0)));
        assert_eq!(arrow_step(u32::from(VK_RIGHT)), Some((8, 0)));
        assert_eq!(arrow_step(u32::from(VK_ESCAPE)), None);
    }

    #[test]
    fn a_dragged_window_follows_the_mouse() {
        let start = Rect::new(100, 100, 500, 400);
        let (min, max) = ([112, 28], [1292, 812]);
        assert_eq!(dragged_rect(start, HTCAPTION, (30, -20), min, max), Rect::new(130, 80, 530, 380));
        assert_eq!(dragged_rect(start, HTBOTTOMRIGHT, (50, 40), min, max), Rect::new(100, 100, 550, 440));
        assert_eq!(dragged_rect(start, HTLEFT, (25, 99), min, max), Rect::new(125, 100, 500, 400), "x only");
        assert_eq!(dragged_rect(start, HTTOPLEFT, (-10, -10), min, max), Rect::new(90, 90, 500, 400));
        assert_eq!(dragged_rect(start, HTTOP, (7, 20), min, max), Rect::new(100, 120, 500, 400), "y only");
    }

    #[test]
    fn a_sized_window_keeps_within_its_limits() {
        let start = Rect::new(100, 100, 500, 400);
        let (min, max) = ([112, 28], [600, 450]);
        assert_eq!(dragged_rect(start, HTLEFT, (390, 0), min, max), Rect::new(388, 100, 500, 400), "the minimum");
        assert_eq!(dragged_rect(start, HTRIGHT, (500, 0), min, max), Rect::new(100, 100, 700, 400), "the maximum");
        assert_eq!(dragged_rect(start, HTBOTTOM, (0, -400), min, max), Rect::new(100, 100, 500, 128));
        assert_eq!(dragged_rect(start, HTTOP, (0, -300), min, max), Rect::new(100, -50, 500, 400));
    }

    #[test]
    fn caption_buttons_and_their_commands() {
        let style = WS_OVERLAPPEDWINDOW;
        assert_eq!(button_command(HTCLOSE, style, true), Some(SC_CLOSE));
        assert_eq!(button_command(HTMINBUTTON, style, true), Some(SC_MINIMIZE));
        assert_eq!(button_command(HTMAXBUTTON, style, true), Some(SC_MAXIMIZE));
        assert_eq!(button_command(HTMAXBUTTON, style | WS_MAXIMIZE, true), Some(SC_RESTORE));
        assert_eq!(button_command(HTMINBUTTON, style | WS_MINIMIZE, true), Some(SC_RESTORE), "minimized: restore");
        assert_eq!(button_command(HTMAXBUTTON, style | WS_MINIMIZE, true), Some(SC_MAXIMIZE));
        assert_eq!(button_command(HTMINBUTTON, style & !WS_MINIMIZEBOX, true), None, "a disabled box");
        assert_eq!(button_command(HTCLIENT, style, true), None);
        assert_eq!(button_command(HTCLOSE, style, false), None, "Close grayed: nothing");
        assert_eq!(button_command(HTMAXBUTTON, style, false), Some(SC_MAXIMIZE), "Close only");
    }
}
