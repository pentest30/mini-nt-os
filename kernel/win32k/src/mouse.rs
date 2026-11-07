//! La souris (02 §7.2 ; `mouse.c`, `msgqueue.c` — co_MsqInsertMouseMessage —
//! et `winpos.c` — co_WinPosWindowFromPoint — de ReactOS, comme
//! spécification) : le thread d'entrée brute remet chaque mouvement du
//! pilote ([`process_mouse_input`]) ; le curseur se déplace (borné à
//! l'écran, dessiné par `display`), et la fenêtre sous lui reçoit, dans la
//! file de son thread, WM_MOUSEMOVE, les boutons (WM_LBUTTONDOWN…, un second
//! clic proche et rapide en WM_LBUTTONDBLCLK pour une classe CS_DBLCLKS),
//! leurs pendants hors de la zone cliente (WM_NCMOUSEMOVE…, avec le code de
//! l'endroit, HTCAPTION ou HTBORDER) ; la molette va à la fenêtre qui a le
//! clavier (WM_MOUSEWHEEL).
//!
//! Pas encore : la capture (SetCapture), WM_NCHITTEST envoyé à la fenêtre
//! (l'endroit est calculé ici, d'après ses rectangles), WM_MOUSEACTIVATE et
//! l'activation par un clic, WM_SETCURSOR et les formes du curseur,
//! les boutons X, ClipCursor, GetCursorPos (gpsi->ptCursor).

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::mou::{
    MouseInputData, MOUSE_LEFT_BUTTON_DOWN, MOUSE_LEFT_BUTTON_UP, MOUSE_MIDDLE_BUTTON_DOWN, MOUSE_MIDDLE_BUTTON_UP,
    MOUSE_RIGHT_BUTTON_DOWN, MOUSE_RIGHT_BUTTON_UP, MOUSE_WHEEL,
};
use abi::user::vk::{VK_CONTROL, VK_SHIFT};
use abi::user::{
    Msg32, CS_DBLCLKS, HTBORDER, HTCAPTION, HTCLIENT, MK_CONTROL, MK_LBUTTON, MK_MBUTTON, MK_RBUTTON, MK_SHIFT,
    WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_NC_MOUSE_OFFSET, WS_CAPTION,
    WS_VISIBLE,
};
use hal::sync::KSpinLock;

use crate::gdi::dib::Rect;
use crate::window::Window;

/// GetDoubleClickTime : deux clics plus proches font un double-clic.
pub const DOUBLE_CLICK_TIME: u32 = 500;
/// SM_CXDOUBLECLK, SM_CYDOUBLECLK : le rectangle où le second clic doit
/// tomber, centré sur le premier.
pub const DOUBLE_CLICK_SIZE: i32 = 4;

/// Les boutons, dans l'ordre de MK_* et des messages : gauche, droit,
/// milieu.
const BUTTONS: [(u16, u16, u32, u8); 3] = [
    (MOUSE_LEFT_BUTTON_DOWN, MOUSE_LEFT_BUTTON_UP, MK_LBUTTON, 1),
    (MOUSE_RIGHT_BUTTON_DOWN, MOUSE_RIGHT_BUTTON_UP, MK_RBUTTON, 2),
    (MOUSE_MIDDLE_BUTTON_DOWN, MOUSE_MIDDLE_BUTTON_UP, MK_MBUTTON, 4),
];

/// Un clic, pour reconnaître le second d'un double-clic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Click {
    pub time: u32,
    pub hwnd: u32,
    /// L'indice du bouton (0 gauche, 1 droit, 2 milieu).
    pub button: usize,
    pub x: i32,
    pub y: i32,
}

/// L'état de la souris : la place du curseur, les boutons enfoncés (MK_*),
/// le dernier clic.
#[derive(Debug)]
struct MouseState {
    x: i32,
    y: i32,
    buttons: u32,
    last_click: Option<Click>,
}

/// `None` avant le premier mouvement : le curseur part du centre de l'écran.
static STATE: KSpinLock<Option<MouseState>> = KSpinLock::new(None);

/// La place du curseur, `None` avant le premier mouvement de la souris.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn cursor_position() -> Option<(i32, i32)> {
    STATE.lock().as_ref().map(|state| (state.x, state.y))
}

/// La place du curseur après un mouvement de `dx`, `dy`, bornée à l'écran de
/// `width` × `height`.
pub fn moved((x, y): (i32, i32), dx: i32, dy: i32, width: u32, height: u32) -> (i32, i32) {
    let clamp = |value: i32, size: u32| value.clamp(0, (size as i32 - 1).max(0));
    (clamp(x.saturating_add(dx), width), clamp(y.saturating_add(dy), height))
}

fn contains(rect: &Rect, x: i32, y: i32) -> bool {
    x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
}

/// L'endroit de (`x`, `y`) dans une fenêtre de rectangles `window` et
/// `client` (sur l'écran) et de style `style` (DefWindowProc de
/// WM_NCHITTEST, réduit) : HTCLIENT dans la zone cliente ; au-dessus d'elle,
/// HTCAPTION pour une fenêtre à barre de titre ; ailleurs, HTBORDER.
pub fn hit_code(window: &Rect, client: &Rect, style: u32, x: i32, y: i32) -> u32 {
    if contains(client, x, y) {
        HTCLIENT
    } else if y < client.top && y >= window.top && style & WS_CAPTION == WS_CAPTION {
        HTCAPTION
    } else {
        HTBORDER
    }
}

/// Le message d'un bouton (`button` : 0 gauche, 1 droit, 2 milieu) qui
/// s'enfonce (`down`), d'un second clic (`double`) ou qui se relâche, dans
/// la zone cliente (`client`) ou non.
pub fn button_message(button: usize, down: bool, double: bool, client: bool) -> u32 {
    let base = WM_LBUTTONDOWN + 3 * button as u32;
    let message = match (down, double) {
        (true, true) => base + (WM_LBUTTONDBLCLK - WM_LBUTTONDOWN),
        (true, false) => base,
        (false, _) => base + (WM_LBUTTONUP - WM_LBUTTONDOWN),
    };
    if client {
        message
    } else {
        message - WM_NC_MOUSE_OFFSET
    }
}

/// Le clic `now` est le second d'un double-clic après `previous` : même
/// fenêtre et même bouton, assez tôt, assez près.
pub fn is_double_click(previous: Option<&Click>, now: &Click) -> bool {
    previous.is_some_and(|previous| {
        previous.hwnd == now.hwnd
            && previous.button == now.button
            && now.time.wrapping_sub(previous.time) <= DOUBLE_CLICK_TIME
            && (now.x - previous.x).abs() <= DOUBLE_CLICK_SIZE / 2
            && (now.y - previous.y).abs() <= DOUBLE_CLICK_SIZE / 2
    })
}

/// MAKELPARAM de deux coordonnées signées sur 16 bits.
pub fn make_lparam(x: i32, y: i32) -> u32 {
    (x as u16 as u32) | (y as u16 as u32) << 16
}

/// co_WinPosWindowFromPoint : la fenêtre visible la plus haute sous
/// (`x`, `y`) parmi les enfants de `parent`, et, si le point tombe dans sa
/// zone cliente, la plus haute de ses enfants à elle, à toute profondeur.
fn window_at(parent: &Window, x: i32, y: i32) -> Option<Arc<Window>> {
    let mut next = parent.state().child;
    while let Some(window) = crate::window::get(next) {
        let state = window.state();
        if state.style & WS_VISIBLE != 0 && contains(&state.window, x, y) {
            if contains(&state.client, x, y) {
                if let Some(inner) = window_at(&window, x, y) {
                    return Some(inner);
                }
            }
            return Some(window);
        }
        next = state.next;
    }
    None
}

/// Les touches et boutons enfoncés, en MK_*.
fn key_flags(buttons: u32) -> u32 {
    let down = |vk| crate::input::async_key_state(vk) & 0x8000 != 0;
    let mut flags = buttons;
    if down(VK_SHIFT) {
        flags |= MK_SHIFT;
    }
    if down(VK_CONTROL) {
        flags |= MK_CONTROL;
    }
    flags
}

/// Un message de la souris pour `window`, à la place (`x`, `y`) de l'écran.
fn message_for(window: &Window, message: u32, buttons: u32, x: i32, y: i32, time: u32, client: Option<u32>) -> Msg32 {
    let state = window.state();
    let (w_param, l_param) = match client {
        // Dans la zone cliente : MK_*, et la place depuis son coin.
        None => (key_flags(buttons), make_lparam(x - state.client.left, y - state.client.top)),
        // Ailleurs : le code de l'endroit, et la place sur l'écran.
        Some(hit) => (hit, make_lparam(x, y)),
    };
    Msg32 { hwnd: window.handle, message, w_param, l_param, time, pt_x: x, pt_y: y }
}

/// Va à la file du thread de `window`, qui est réveillé.
fn post(window: &Window, message: Msg32) {
    if let Some(thread) = crate::gui::thread_info_of(window.pti) {
        crate::queue::post_input(&thread, message);
    }
}

/// UserProcessMouseInput : le mouvement `data` du pilote déplace le curseur
/// et va, en messages, à la fenêtre sous lui (la molette, à celle qui a le
/// clavier). Rien avant que win32k ait l'écran.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread d'entrée brute.
pub fn process_mouse_input(data: &MouseInputData) {
    let Some(mode) = crate::display::mode() else { return };
    let time = crate::input::message_time();
    // L'état change sous son verrou ; les messages partent après.
    let (x, y, moved_now, first, buttons, transitions) = {
        let mut guard = STATE.lock();
        let first = guard.is_none();
        let state = guard.get_or_insert(MouseState {
            x: mode.width as i32 / 2,
            y: mode.height as i32 / 2,
            buttons: 0,
            last_click: None,
        });
        let (x, y) = moved((state.x, state.y), data.last_x, data.last_y, mode.width, mode.height);
        let moved_now = (x, y) != (state.x, state.y);
        (state.x, state.y) = (x, y);
        let mut transitions = Vec::new();
        for (index, &(down_flag, up_flag, mk, _)) in BUTTONS.iter().enumerate() {
            if data.button_flags & down_flag != 0 {
                state.buttons |= mk;
                transitions.push((index, true));
            }
            if data.button_flags & up_flag != 0 {
                state.buttons &= !mk;
                transitions.push((index, false));
            }
        }
        (x, y, moved_now, first, state.buttons, transitions)
    };
    // The cursor shows at the mouse's first input, then follows it.
    if moved_now || first {
        crate::display::set_cursor(x, y);
    }
    for &(index, down) in &transitions {
        crate::input::update_async_button(BUTTONS[index].3, down);
    }

    let target = crate::desktop::input_desktop().and_then(|desktop| window_at(&desktop.window, x, y));
    if let Some(window) = &target {
        let state = window.state();
        let hit = hit_code(&state.window, &state.client, state.style, x, y);
        let client = hit == HTCLIENT;
        let extra = (!client).then_some(hit);
        if moved_now {
            let message = if client { WM_MOUSEMOVE } else { WM_MOUSEMOVE - WM_NC_MOUSE_OFFSET };
            post(window, message_for(window, message, buttons, x, y, time, extra));
        }
        for &(index, down) in &transitions {
            let double = down && client && {
                let click = Click { time, hwnd: window.handle, button: index, x, y };
                let mut guard = STATE.lock();
                let state = guard.as_mut().expect("set above");
                let wants = window.class.as_ref().is_some_and(|class| class.info.style & CS_DBLCLKS != 0);
                let double = wants && is_double_click(state.last_click.as_ref(), &click);
                // Un double-clic n'en commence pas un autre.
                state.last_click = (!double).then_some(click);
                double
            };
            let message = button_message(index, down, double, client);
            post(window, message_for(window, message, buttons, x, y, time, extra));
        }
    }

    if data.button_flags & MOUSE_WHEEL != 0 {
        wheel(data.button_data as i16, buttons, x, y, time);
    }
}

/// WM_MOUSEWHEEL à la fenêtre qui a le clavier du premier plan (sinon à sa
/// fenêtre active) : `wParam` porte MK_* et le cran (signé), `lParam` la
/// place sur l'écran.
fn wheel(amount: i16, buttons: u32, x: i32, y: i32, time: u32) {
    let Some(thread) = crate::input::foreground() else { return };
    let (active, focus) = thread.queue.with(|queue| (queue.active, queue.focus)).0;
    let hwnd = if focus != 0 { focus } else { active };
    if hwnd == 0 {
        return;
    }
    let w_param = key_flags(buttons) | (amount as u16 as u32) << 16;
    let message = Msg32 { hwnd, message: WM_MOUSEWHEEL, w_param, l_param: make_lparam(x, y), time, pt_x: x, pt_y: y };
    crate::queue::post_input(&thread, message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::{HTNOWHERE, WM_MBUTTONUP, WM_RBUTTONDBLCLK, WM_RBUTTONDOWN};

    #[test]
    fn the_cursor_stays_on_the_screen() {
        assert_eq!(moved((640, 400), 12, -7, 1280, 800), (652, 393));
        assert_eq!(moved((5, 5), -20, -20, 1280, 800), (0, 0));
        assert_eq!(moved((1270, 790), 50, 50, 1280, 800), (1279, 799));
    }

    #[test]
    fn where_a_point_falls() {
        let window = Rect::new(100, 100, 400, 300);
        let client = Rect::new(104, 130, 396, 296);
        assert_eq!(hit_code(&window, &client, WS_CAPTION, 200, 200), HTCLIENT);
        assert_eq!(hit_code(&window, &client, WS_CAPTION, 200, 110), HTCAPTION);
        assert_eq!(hit_code(&window, &client, 0, 200, 110), HTBORDER, "no caption: a border");
        assert_eq!(hit_code(&window, &client, WS_CAPTION, 101, 200), HTBORDER);
        assert_ne!(hit_code(&window, &client, WS_CAPTION, 200, 200), HTNOWHERE);
    }

    #[test]
    fn button_messages() {
        assert_eq!(button_message(0, true, false, true), WM_LBUTTONDOWN);
        assert_eq!(button_message(0, false, false, true), WM_LBUTTONUP);
        assert_eq!(button_message(0, true, true, true), WM_LBUTTONDBLCLK);
        assert_eq!(button_message(1, true, false, true), WM_RBUTTONDOWN);
        assert_eq!(button_message(1, true, true, true), WM_RBUTTONDBLCLK);
        assert_eq!(button_message(2, false, false, true), WM_MBUTTONUP);
        // Outside the client area: WM_NCLBUTTONDOWN (0xA1).
        assert_eq!(button_message(0, true, false, false), 0x00A1);
    }

    #[test]
    fn a_second_click_close_and_soon_is_a_double_click() {
        let first = Click { time: 1000, hwnd: 8, button: 0, x: 50, y: 50 };
        let soon = Click { time: 1300, ..first };
        assert!(is_double_click(Some(&first), &soon));
        assert!(!is_double_click(None, &soon), "no first click");
        assert!(!is_double_click(Some(&first), &Click { time: 1600, ..first }), "too late");
        assert!(!is_double_click(Some(&first), &Click { x: 54, ..soon }), "too far");
        assert!(!is_double_click(Some(&first), &Click { button: 1, ..soon }), "another button");
        assert!(!is_double_click(Some(&first), &Click { hwnd: 9, ..soon }), "another window");
    }

    #[test]
    fn coordinates_pack_signed() {
        assert_eq!(make_lparam(12, 34), 0x0022_000C);
        assert_eq!(make_lparam(-1, 2), 0x0002_FFFF);
    }
}
