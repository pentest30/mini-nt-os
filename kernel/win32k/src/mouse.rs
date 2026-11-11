//! La souris (02 §7.2 ; `mouse.c`, `msgqueue.c` — co_MsqInsertMouseMessage,
//! co_IntProcessMouseMessage — `focus.c` — co_UserSetCapture — et
//! `winpos.c` — co_WinPosWindowFromPoint — de ReactOS, comme
//! spécification).
//!
//! Le thread d'entrée brute remet chaque mouvement du pilote
//! ([`process_mouse_input`]) : le curseur se déplace (borné à l'écran,
//! dessiné par `display`) ou va à une position absolue (la souris de
//! VirtualBox, `vboxmouse`) ; un message brut (WM_MOUSEMOVE, WM_LBUTTONDOWN…,
//! le point à l'écran) va à la file du thread de la fenêtre qui a la capture
//! (SetCapture : toute la souris lui va), sinon de la fenêtre visible la plus
//! haute sous le curseur. Le thread qui le retire de sa file en fait le
//! message final ([`finish`]) : il demande à la fenêtre où tombe le point
//! (WM_NCHITTEST, que DefWindowProc calcule d'après son cadre), lui envoie
//! WM_MOUSEACTIVATE à l'appui d'un bouton si sa fenêtre de premier niveau
//! n'est pas active, et l'active et la fait passer devant selon la réponse
//! ([`activate_by_mouse`]) ; le message devient celui de la zone cliente
//! (MK_*, la place depuis son coin) ou du cadre (WM_NCLBUTTONDOWN…, le code
//! de l'endroit, la place à l'écran) ; un second clic proche et rapide
//! devient WM_LBUTTONDBLCLK (pour une classe CS_DBLCLKS, ou sur le cadre).
//! La molette va à la fenêtre qui a le clavier (WM_MOUSEWHEEL).
//!
//! L'écran montre le curseur du thread de la fenêtre sous le pointeur (ou qui
//! a la capture : `crate::cursor::pointer_over`) ; chaque message qui sort de
//! la file envoie WM_SETCURSOR à sa fenêtre, sauf pendant la capture.
//!
//! Pas encore : les boutons X, ClipCursor, le suivi (TrackMouseEvent), la
//! capture qui passe d'un thread à l'autre, WM_PARENTNOTIFY au clic.

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::mou::{
    MouseInputData, MOUSE_LEFT_BUTTON_DOWN, MOUSE_LEFT_BUTTON_UP, MOUSE_MIDDLE_BUTTON_DOWN, MOUSE_MIDDLE_BUTTON_UP,
    MOUSE_MOVE_ABSOLUTE, MOUSE_RIGHT_BUTTON_DOWN, MOUSE_RIGHT_BUTTON_UP, MOUSE_WHEEL,
};
use abi::user::vk::{VK_CONTROL, VK_SHIFT};
use abi::user::{
    Msg32, CS_DBLCLKS, HTBORDER, HTCAPTION, HTCLIENT, HTNOWHERE, HTTRANSPARENT, HWND_TOP, MA_ACTIVATEANDEAT,
    MA_NOACTIVATE, MA_NOACTIVATEANDEAT, MK_CONTROL, MK_LBUTTON, MK_MBUTTON, MK_RBUTTON, MK_SHIFT, SWP_NOACTIVATE,
    SWP_NOMOVE, SWP_NOSIZE, WM_CAPTURECHANGED, WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDBLCLK,
    WM_MOUSEACTIVATE, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_NCHITTEST, WM_NC_MOUSE_OFFSET, WM_SETCURSOR, WS_CAPTION,
    WS_CHILD, WS_POPUP, WS_VISIBLE,
};
use hal::sync::KSpinLock;

use crate::gdi::dib::Rect;
use crate::gui::ThreadInfo;
use crate::window::{LParam, Window};

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
/// La fenêtre qui a la capture (0 : aucune) : toute la souris va à sa file.
static CAPTURE: KSpinLock<u32> = KSpinLock::new(0);

/// La place du curseur, `None` avant le premier mouvement de la souris.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn cursor_position() -> Option<(i32, i32)> {
    STATE.lock().as_ref().map(|state| (state.x, state.y))
}

/// GetCursorPos : la place du curseur ; avant le premier mouvement, le
/// centre de l'écran, d'où il partira ((0, 0) sans écran).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn cursor_or_center() -> (i32, i32) {
    cursor_position().unwrap_or_else(|| {
        crate::display::mode().map_or((0, 0), |mode| (mode.width as i32 / 2, mode.height as i32 / 2))
    })
}

/// La place du curseur après un mouvement de `dx`, `dy`, bornée à l'écran de
/// `width` × `height`.
pub fn moved((x, y): (i32, i32), dx: i32, dy: i32, width: u32, height: u32) -> (i32, i32) {
    let clamp = |value: i32, size: u32| value.clamp(0, (size as i32 - 1).max(0));
    (clamp(x.saturating_add(dx), width), clamp(y.saturating_add(dy), height))
}

/// La place du curseur pour une position absolue (`x`, `y`), de 0 à 0xFFFF
/// sur chaque axe (MOUSE_MOVE_ABSOLUTE), sur un écran de `width` × `height`
/// (comme UserSendMouseInput : `x * largeur >> 16`).
pub fn absolute_position(x: i32, y: i32, width: u32, height: u32) -> (i32, i32) {
    let scale = |value: i32, size: u32| ((i64::from(value.clamp(0, 0xFFFF)) * i64::from(size)) >> 16) as i32;
    (scale(x, width), scale(y, height))
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

/// Un message de la souris pour `window`, à la place (`x`, `y`) de l'écran :
/// dans la zone cliente (`hit` nul), `flags` (MK_*) et la place depuis son
/// coin ; ailleurs, le code de l'endroit et la place à l'écran.
fn message_for(window: &Window, message: u32, flags: u32, x: i32, y: i32, time: u32, hit: Option<u32>) -> Msg32 {
    let state = window.state();
    let (w_param, l_param) = match hit {
        None => (flags, make_lparam(x - state.client.left, y - state.client.top)),
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
/// et va, en messages bruts, à la fenêtre qui a la capture, sinon à la
/// fenêtre sous le curseur (la molette, à celle qui a le clavier). Rien
/// avant que win32k ait l'écran.
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
        let (x, y) = if data.flags & MOUSE_MOVE_ABSOLUTE != 0 {
            absolute_position(data.last_x, data.last_y, mode.width, mode.height)
        } else {
            moved((state.x, state.y), data.last_x, data.last_y, mode.width, mode.height)
        };
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

    let captured = crate::window::get(*CAPTURE.lock());
    let target =
        captured.or_else(|| crate::desktop::input_desktop().and_then(|desktop| window_at(&desktop.window, x, y)));
    if let Some(window) = &target {
        // gpqCursor: the screen shows the cursor of this window's thread.
        crate::cursor::pointer_over(window.pti);
        let raw = |message| Msg32 {
            hwnd: window.handle,
            message,
            w_param: key_flags(buttons),
            l_param: make_lparam(x, y),
            time,
            pt_x: x,
            pt_y: y,
        };
        if moved_now {
            post(window, raw(WM_MOUSEMOVE));
        }
        for &(index, down) in &transitions {
            post(window, raw(button_message(index, down, false, true)));
        }
    }

    if data.button_flags & MOUSE_WHEEL != 0 {
        wheel(data.button_data as i16, buttons, x, y, time);
    }
}

/// Le bouton (0 gauche, 1 droit, 2 milieu) et l'appui d'un message brut de
/// bouton ; `None` pour un mouvement.
fn button_of(message: u32) -> Option<(usize, bool)> {
    let offset = message.checked_sub(WM_LBUTTONDOWN).filter(|&offset| offset <= WM_MBUTTONDBLCLK - WM_LBUTTONDOWN)?;
    Some(((offset / 3) as usize, offset % 3 != WM_LBUTTONUP - WM_LBUTTONDOWN))
}

/// La fenêtre de premier niveau de `window` : en remontant ses parents tant
/// qu'elle est fille (IntGetNonChildAncestor).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub(crate) fn top_level(window: &Arc<Window>) -> Arc<Window> {
    let mut top = window.clone();
    loop {
        let state = top.state();
        if state.style & (WS_POPUP | WS_CHILD) != WS_CHILD {
            return top;
        }
        match crate::window::get(state.parent) {
            Some(parent) => top = parent,
            None => return top,
        }
    }
}

/// Où tombe (`x`, `y`) dans `window`, d'après elle (WM_NCHITTEST) ; une
/// fenêtre fille transparente au point (HTTRANSPARENT) le laisse à son
/// parent, qui devient la fenêtre du message. Sans réponse (une fenêtre d'un
/// autre thread, un rappel qui échoue), d'après ses rectangles.
fn hit_test(window: &mut Arc<Window>, x: i32, y: i32) -> u32 {
    for _ in 0..16 {
        let hit = crate::window::send_message(window, WM_NCHITTEST, 0, LParam::Value(make_lparam(x, y)));
        match hit {
            Ok(HTTRANSPARENT) => {
                let state = window.state();
                match crate::window::get(state.parent).filter(|_| state.style & WS_CHILD != 0) {
                    Some(parent) => *window = parent,
                    None => return HTNOWHERE,
                }
            }
            Ok(hit) => return hit,
            Err(_) => {
                let state = window.state();
                return hit_code(&state.window, &state.client, state.style, x, y);
            }
        }
    }
    HTNOWHERE
}

/// co_IntMouseActivateWindow : la fenêtre de premier niveau `window` devient
/// active, au premier plan, et passe devant ses sœurs.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn activate_by_mouse(window: &Arc<Window>) {
    let top = top_level(window);
    crate::input::activate(&top);
    crate::winpos::set_window_pos(&top, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

/// Ce qu'un message brut de la souris devient ([`resolve`]), avant qu'il
/// sorte de la file ([`commit`]).
pub struct Resolved {
    /// Le message final : zone cliente ou cadre (WM_NC*), double-clic.
    pub message: Msg32,
    /// Sa fenêtre, celle du point ou de la capture.
    window: Arc<Window>,
    /// Ce que dit WM_NCHITTEST (HTCLIENT avec la capture).
    hit: u32,
    /// Le clic d'un appui de bouton, et s'il en fait un double-clic.
    click: Option<(Click, bool)>,
    /// Le message brut (WM_MOUSEMOVE, WM_LBUTTONDOWN…) que WM_SETCURSOR
    /// porte, sans la capture ; `None` sinon (la capture, la molette).
    set_cursor: Option<u32>,
}

/// co_IntProcessMouseMessage, sans rien changer : le message final du
/// message brut `raw` de la file de `thread`. Le point tombe dans la fenêtre
/// qui a la capture (sa zone cliente, toujours) ou là où le dit
/// WM_NCHITTEST ; l'appui d'un bouton est le second clic d'un double-clic
/// (classe CS_DBLCLKS, ou sur le cadre) d'après le dernier clic sorti. Un
/// autre message (la molette) passe tel quel. `None` : sa fenêtre n'est
/// plus. PeekMessage et GetMessage comparent ce message final à leur filtre
/// avant de sortir `raw` de la file.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread, sans rien tenir (WM_NCHITTEST).
pub fn resolve(thread: &ThreadInfo, raw: Msg32) -> Option<Resolved> {
    let button = button_of(raw.message);
    let mut window = crate::window::get(raw.hwnd)?;
    if raw.message != WM_MOUSEMOVE && button.is_none() {
        return Some(Resolved { message: raw, window, hit: HTCLIENT, click: None, set_cursor: None });
    }
    let (x, y) = (raw.pt_x, raw.pt_y);
    let ((capture, menu_owner), _, _) = thread.queue.with(|queue| (queue.capture, queue.menu_owner));
    let captured = capture != 0 && capture == window.handle;
    let hit = if captured { HTCLIENT } else { hit_test(&mut window, x, y) };
    let set_cursor = (!captured).then_some(raw.message);
    let client = hit == HTCLIENT;
    let extra = (!client).then_some(hit);
    // A menu's tracking: its messages stay in the screen's coordinates.
    let in_menu = menu_owner != 0;
    let screen = |mut message: Msg32| {
        if in_menu && client {
            message.l_param = make_lparam(x, y);
        }
        message
    };
    let Some((index, down)) = button else {
        let message = if client { WM_MOUSEMOVE } else { WM_MOUSEMOVE - WM_NC_MOUSE_OFFSET };
        let message = screen(message_for(&window, message, raw.w_param, x, y, raw.time, extra));
        return Some(Resolved { message, window, hit, click: None, set_cursor });
    };
    let click = down.then(|| {
        let click = Click { time: raw.time, hwnd: window.handle, button: index, x, y };
        let wants = in_menu || !client || window.class.as_ref().is_some_and(|class| class.info.style & CS_DBLCLKS != 0);
        let double =
            wants && STATE.lock().as_ref().is_some_and(|state| is_double_click(state.last_click.as_ref(), &click));
        (click, double)
    });
    let double = click.as_ref().is_some_and(|&(_, double)| double);
    let message = message_for(&window, button_message(index, down, double, client), raw.w_param, x, y, raw.time, extra);
    Some(Resolved { message: screen(message), window, hit, click, set_cursor })
}

/// La fenêtre de premier niveau `top` de `thread` est à activer par un clic :
/// elle n'est pas sa fenêtre active, ou son thread n'est pas au premier plan
/// (sa fenêtre active est restée la sienne quand un autre l'a pris).
fn needs_activation(thread: &ThreadInfo, top: &Window) -> bool {
    let active = thread.queue.with(|queue| queue.active).0;
    let foreground = crate::input::foreground().is_some_and(|foreground| core::ptr::eq(&*foreground, thread));
    top.handle != active || !foreground
}

/// La suite de co_IntProcessMouseMessage, une fois `resolved` sorti de la
/// file de `thread` (`remove`) ou seulement regardé : à un appui qui sort,
/// il devient le dernier clic (un double-clic n'en commence pas un autre),
/// et WM_MOUSEACTIVATE va à sa fenêtre si sa fenêtre de premier niveau est
/// à activer ([`needs_activation`] : MA_ACTIVATE l'active, un `…ANDEAT` mange
/// le message) ; puis, sans la capture, WM_SETCURSOR (la fenêtre, le code de
/// l'endroit et le message brut) lui permet de choisir le curseur, même
/// pour un message mangé. `None` : le message est mangé.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread, sans rien tenir (des rappels).
pub fn commit(thread: &ThreadInfo, resolved: Resolved, remove: bool) -> Option<Msg32> {
    let Resolved { message, window, hit, click, set_cursor } = resolved;
    if !remove {
        return Some(message);
    }
    let kept = match click {
        Some((click, double)) => activate_on_click(thread, &window, hit, click, double),
        None => true,
    };
    if let Some(raw) = set_cursor {
        let lparam = (hit & 0xFFFF) | raw << 16;
        let _ = crate::window::send_message(&window, WM_SETCURSOR, window.handle, LParam::Value(lparam));
    }
    kept.then_some(message)
}

/// L'appui `click` sorti de la file, sur `window` à l'endroit `hit` : il
/// devient le dernier clic, et WM_MOUSEACTIVATE décide de l'activation.
/// Faux : le message est mangé.
fn activate_on_click(thread: &ThreadInfo, window: &Arc<Window>, hit: u32, click: Click, double: bool) -> bool {
    let button = click.button;
    if let Some(state) = STATE.lock().as_mut() {
        state.last_click = (!double).then_some(click);
    }
    let top = top_level(window);
    if !needs_activation(thread, &top) {
        return true;
    }
    let raw_down = button_message(button, true, false, true);
    let lparam = (hit & 0xFFFF) | raw_down << 16;
    let answer = crate::window::send_message(window, WM_MOUSEACTIVATE, top.handle, LParam::Value(lparam));
    match answer.unwrap_or(0) {
        MA_NOACTIVATEANDEAT => false,
        MA_NOACTIVATE => true,
        MA_ACTIVATEANDEAT => {
            activate_by_mouse(&top);
            false
        }
        _ => {
            activate_by_mouse(&top);
            true
        }
    }
}

/// IntReleaseCapture de co_UserFreeWindow : la fenêtre `hwnd`, détruite,
/// n'a plus la capture, sans message.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn forget_capture(hwnd: u32) {
    let mut capture = CAPTURE.lock();
    if *capture == hwnd {
        *capture = 0;
    }
}

/// co_UserSetCapture : `window` (aucune : personne) a la capture pour le
/// thread courant `thread` ; toute la souris lui va. L'ancienne reçoit
/// WM_CAPTURECHANGED. Rend l'ancienne ; 0 sans rien changer pour une
/// fenêtre d'un autre thread.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn set_capture(thread: &ThreadInfo, window: Option<&Arc<Window>>) -> u32 {
    if window.is_some_and(|window| window.pti != thread.server) {
        return 0;
    }
    let hwnd = window.map_or(0, |window| window.handle);
    let previous = thread.queue.with(|queue| core::mem::replace(&mut queue.capture, hwnd)).0;
    {
        let mut capture = CAPTURE.lock();
        if hwnd != 0 || *capture == previous {
            *capture = hwnd;
        }
    }
    if previous != 0 && previous != hwnd {
        if let Some(old) = crate::window::get(previous) {
            let _ = crate::window::send_message(&old, WM_CAPTURECHANGED, 0, LParam::Value(hwnd));
        }
    }
    previous
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
    fn an_absolute_position_spans_the_screen() {
        assert_eq!(absolute_position(0, 0, 1024, 768), (0, 0));
        assert_eq!(absolute_position(0xFFFF, 0xFFFF, 1024, 768), (1023, 767));
        assert_eq!(absolute_position(0x8000, 0x4000, 1024, 768), (512, 192));
        assert_eq!(absolute_position(-5, 0x1_0000, 1280, 800), (0, 799));
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
    fn raw_button_messages() {
        assert_eq!(button_of(WM_LBUTTONDOWN), Some((0, true)));
        assert_eq!(button_of(WM_LBUTTONUP), Some((0, false)));
        assert_eq!(button_of(WM_RBUTTONDOWN), Some((1, true)));
        assert_eq!(button_of(WM_MBUTTONUP), Some((2, false)));
        assert_eq!(button_of(WM_MOUSEMOVE), None);
        assert_eq!(button_of(WM_MOUSEWHEEL), None);
    }

    #[test]
    fn coordinates_pack_signed() {
        assert_eq!(make_lparam(12, 34), 0x0022_000C);
        assert_eq!(make_lparam(-1, 2), 0x0002_FFFF);
    }
}
