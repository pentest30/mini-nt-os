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
//! Pas encore : le déplacement au clavier (SC_MOVE du menu de la fenêtre),
//! le cadre en pointillés (sans le contenu), WM_MOVING et WM_SIZING, le
//! menu de la fenêtre.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::user::vk::{VK_ESCAPE, VK_RETURN};
use abi::user::{
    Msg32, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTCAPTION, HTCLOSE, HTHSCROLL, HTLEFT, HTMAXBUTTON, HTMENU,
    HTMINBUTTON, HTRIGHT, HTTOP, HTTOPLEFT, HTTOPRIGHT, HTVSCROLL, SC_CLOSE, SC_HSCROLL, SC_KEYMENU, SC_MAXIMIZE,
    SC_MINIMIZE, SC_MOUSEMENU, SC_MOVE, SC_RESTORE, SC_SIZE, SC_VSCROLL, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER,
    SW_MINIMIZE, SW_RESTORE, SW_SHOWMAXIMIZED, WMSZ_BOTTOMRIGHT, WMSZ_LEFT, WM_CLOSE, WM_ENTERSIZEMOVE,
    WM_EXITSIZEMOVE, WM_KEYDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_QUIT, WM_SYSCOMMAND, WS_CHILD, WS_MAXIMIZE,
    WS_MAXIMIZEBOX, WS_MINIMIZE, WS_MINIMIZEBOX,
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
/// fermer, réduire ou rétablir une fenêtre réduite, agrandir ou rétablir
/// une fenêtre agrandie ; `None` pour un bouton que le style désactive.
pub fn button_command(hit: u32, style: u32) -> Option<u32> {
    match hit {
        HTCLOSE => Some(SC_CLOSE),
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

/// DefWndDoSizeMove : la boucle qui déplace (`wparam` SC_MOVE) ou
/// redimensionne (SC_SIZE et un bord) `window` à la souris, depuis le point
/// `lparam` de l'écran.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système du thread de la fenêtre, sans
/// rien tenir.
pub fn size_move(window: &Arc<Window>, wparam: u32, lparam: u32) {
    let Some(part) = dragged_part(wparam) else {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        return report_missing("moving or sizing with the keyboard", &REPORTED);
    };
    let Ok(thread) = crate::convert_current_thread() else { return };
    if window.pti != thread.server {
        return;
    }
    let state = window.state();
    if state.style & WS_MAXIMIZE != 0 {
        return;
    }
    let start = state.window;
    let origin = point_of(lparam);
    let info = crate::window::min_max_info(window);
    let moving = part == HTCAPTION;

    crate::mouse::set_capture(&thread, Some(window));
    let _ = crate::window::send_message(window, WM_ENTERSIZEMOVE, 0, LParam::Value(0));
    let mut current = start;
    while let Some(message) = next_message(&thread) {
        match message.message {
            WM_MOUSEMOVE => {
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
    let Some(command) = button_command(hit, window.state().style) else { return };
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
        assert_eq!(dragged_part(SC_SIZE + 1), Some(HTLEFT));
        assert_eq!(dragged_part(SC_SIZE + 8), Some(HTBOTTOMRIGHT));
        assert_eq!(dragged_part(SC_SIZE + 9), None);
        assert_eq!(dragged_part(SC_CLOSE), None);
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
        assert_eq!(button_command(HTCLOSE, style), Some(SC_CLOSE));
        assert_eq!(button_command(HTMINBUTTON, style), Some(SC_MINIMIZE));
        assert_eq!(button_command(HTMAXBUTTON, style), Some(SC_MAXIMIZE));
        assert_eq!(button_command(HTMAXBUTTON, style | WS_MAXIMIZE), Some(SC_RESTORE));
        assert_eq!(button_command(HTMINBUTTON, style | WS_MINIMIZE), Some(SC_RESTORE), "minimized: restore");
        assert_eq!(button_command(HTMAXBUTTON, style | WS_MINIMIZE), Some(SC_MAXIMIZE));
        assert_eq!(button_command(HTMINBUTTON, style & !WS_MINIMIZEBOX), None, "a disabled box");
        assert_eq!(button_command(HTCLIENT, style), None);
    }
}
