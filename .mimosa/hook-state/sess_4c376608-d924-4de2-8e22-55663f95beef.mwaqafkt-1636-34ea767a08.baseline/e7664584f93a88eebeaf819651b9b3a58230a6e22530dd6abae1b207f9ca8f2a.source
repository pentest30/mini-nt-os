//! Le clavier (02 §7.2 ; `keyboard.c`, `msgqueue.c`, `focus.c` de ReactOS,
//! comme spécification).
//!
//! Le thread d'entrée brute (RIT, `ntoskrnl::input`) lit le pilote du
//! clavier et remet chaque touche à [`process_keyboard_input`]
//! (UserProcessKeyboardInput) : son scan code, par les tables de la
//! disposition du thread au premier plan (ou de la première chargée),
//! devient une touche virtuelle ; l'état du clavier (gafAsyncKeyState :
//! enfoncée, basculée) change ([`AsyncKeys`]), puis un WM_KEYDOWN, WM_KEYUP,
//! WM_SYSKEYDOWN ou WM_SYSKEYUP ([`key_message`], ProcessKeyEvent) va à la
//! file du premier plan, pour sa fenêtre qui a le clavier (ou sa fenêtre
//! active).
//!
//! Le premier plan (gpqForeground) est la file du thread dont une fenêtre
//! de premier niveau a été activée en dernier ([`activate`],
//! co_IntSetForegroundWindow) : elle devient sa fenêtre active et celle qui
//! a le clavier ; l'ancienne fenêtre active du thread reçoit WM_NCACTIVATE
//! et WM_ACTIVATE inactifs, la nouvelle WM_NCACTIVATE, WM_ACTIVATE, puis
//! WM_SETFOCUS. Quand le premier plan change de thread, les fenêtres de
//! premier niveau des deux threads reçoivent WM_ACTIVATEAPP
//! ([`send_activate_app`]) : celles du thread qui le perd d'abord, celles du
//! thread qui le gagne avant les messages de sa fenêtre activée. Une
//! fenêtre d'un autre thread ne reçoit pas encore WM_NCACTIVATE ni
//! WM_ACTIVATE : le noyau change et peint son cadre lui-même ; de même pour
//! la fenêtre active du thread qui perd le premier plan.
//!
//! SetFocus ([`set_focus`], co_UserSetFocus) donne le clavier à une autre
//! fenêtre du thread, après avoir activé sa fenêtre de premier niveau s'il
//! le faut.
//!
//! TranslateMessage ([`translate_message`], IntTranslateKbdMessage) poste
//! le caractère d'un WM_KEYDOWN (WM_CHAR, WM_DEADCHAR, ou leurs variantes
//! système) d'après l'état du clavier du thread ; ToUnicodeEx
//! ([`to_unicode_ex`]) traduit une touche selon un état donné.
//!
//! Pas encore : la souris, les crochets (WH_KEYBOARD_LL), les raccourcis
//! (RegisterHotKey), Alt + pavé numérique, Alt + Tab, le changement de
//! disposition par Alt + Maj, les voyants, Impr. écran, SendInput, le
//! premier plan perdu (WM_NCACTIVATE, WM_ACTIVATE inactif et WM_KILLFOCUS
//! à un autre thread), plusieurs bureaux d'entrée.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::kbd::{KeyboardInputData, KBDEXT, KBDNUMPAD, KEY_BREAK, KEY_E0, KEY_E1, KLLF_ALTGR};
use abi::user::vk::{
    VK_CLEAR, VK_CONTROL, VK_DECIMAL, VK_DELETE, VK_DOWN, VK_END, VK_F10, VK_HOME, VK_INSERT, VK_LCONTROL, VK_LEFT,
    VK_LMENU, VK_LSHIFT, VK_MENU, VK_NEXT, VK_NUMLOCK, VK_NUMPAD0, VK_PRIOR, VK_RCONTROL, VK_RIGHT, VK_RMENU,
    VK_RSHIFT, VK_SHIFT, VK_UP,
};
use abi::user::{
    Msg32, KF_ALTDOWN, KF_EXTENDED, KF_REPEAT, KF_UP, WA_ACTIVE, WA_INACTIVE, WM_ACTIVATE, WM_ACTIVATEAPP, WM_CHAR,
    WM_DEADCHAR, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_NCACTIVATE, WM_SETFOCUS, WM_SYSCHAR, WM_SYSDEADCHAR,
    WM_SYSKEYDOWN, WM_SYSKEYUP, WNDS_ACTIVEFRAME, WS_CHILD, WS_DISABLED, WS_MINIMIZE, WS_POPUP,
};
use hal::sync::KSpinLock;

use crate::gui::ThreadInfo;
use crate::kbdtables::{is_down, is_locked, to_unicode, KeyState, Tables, DOWN, LOCKED};
use crate::keyboard::KeyboardLayout;
use crate::window::{LParam, Window};

/// L'état du clavier (gafAsyncKeyState, gafAsyncKeyStateRecentDown).
#[derive(Clone, Debug)]
pub struct AsyncKeys {
    pub state: KeyState,
    /// Les touches enfoncées depuis le dernier GetAsyncKeyState, en bits.
    pub recent: [u8; 32],
    /// Alt enfoncée seule en dernier (`bMenuDownRecently`) : son relâchement
    /// est WM_SYSKEYUP.
    pub menu_down_recently: bool,
}

impl Default for AsyncKeys {
    fn default() -> Self {
        Self { state: [0; 256], recent: [0; 32], menu_down_recently: false }
    }
}

impl AsyncKeys {
    /// UpdateAsyncKeyState : `vk` enfoncée ou relâchée ; une touche qui
    /// s'enfonce se bascule, et compte comme enfoncée récemment.
    fn update(&mut self, vk: u8, down: bool) {
        let key = &mut self.state[usize::from(vk)];
        if down {
            if *key & DOWN == 0 {
                *key ^= LOCKED;
            }
            *key |= DOWN;
            self.recent[usize::from(vk / 8)] |= 1 << (vk % 8);
        } else {
            *key &= !DOWN;
        }
    }

    /// NtUserGetAsyncKeyState : 0x8000 si `vk` est enfoncée, 1 si elle
    /// l'a été depuis le dernier appel (oublié alors).
    pub fn get(&mut self, vk: u8) -> u16 {
        let mut state = 0;
        if is_down(&self.state, vk) {
            state |= 0x8000;
        }
        let bit = 1 << (vk % 8);
        if self.recent[usize::from(vk / 8)] & bit != 0 {
            state |= 1;
        }
        self.recent[usize::from(vk / 8)] &= !bit;
        state
    }
}

/// IntSimplifyVk : la touche commune d'une touche gauche ou droite.
pub const fn simplify_vk(vk: u8) -> u8 {
    match vk {
        VK_LSHIFT | VK_RSHIFT => VK_SHIFT,
        VK_LCONTROL | VK_RCONTROL => VK_CONTROL,
        VK_LMENU | VK_RMENU => VK_MENU,
        _ => vk,
    }
}

/// IntFixVk : la touche gauche (ou droite, `extended`) d'une touche
/// commune.
pub const fn fix_vk(vk: u8, extended: bool) -> u8 {
    match (vk, extended) {
        (VK_SHIFT, false) => VK_LSHIFT,
        (VK_SHIFT, true) => VK_RSHIFT,
        (VK_CONTROL, false) => VK_LCONTROL,
        (VK_CONTROL, true) => VK_RCONTROL,
        (VK_MENU, false) => VK_LMENU,
        (VK_MENU, true) => VK_RMENU,
        _ => vk,
    }
}

/// IntTranslateNumpadKey : la touche du pavé numérique, Verr. Num. allumé.
pub const fn translate_numpad_key(vk: u8) -> u8 {
    match vk {
        VK_INSERT => VK_NUMPAD0,
        VK_END => VK_NUMPAD0 + 1,
        VK_DOWN => VK_NUMPAD0 + 2,
        VK_NEXT => VK_NUMPAD0 + 3,
        VK_LEFT => VK_NUMPAD0 + 4,
        VK_CLEAR => VK_NUMPAD0 + 5,
        VK_RIGHT => VK_NUMPAD0 + 6,
        VK_HOME => VK_NUMPAD0 + 7,
        VK_UP => VK_NUMPAD0 + 8,
        VK_PRIOR => VK_NUMPAD0 + 9,
        VK_DELETE => VK_DECIMAL,
        _ => vk,
    }
}

/// Une touche, comme la donne KEYBDINPUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInput {
    pub vk: u8,
    /// Le scan code, sans préfixe.
    pub scan: u16,
    /// KEYEVENTF_EXTENDEDKEY.
    pub extended: bool,
    /// Relâchée (KEYEVENTF_KEYUP).
    pub up: bool,
}

/// UserProcessKeyboardInput, la touche : `data` traduite par `tables`,
/// dans l'état `keys` (pour Verr. Num.) ; aucune pour un scan code sans
/// touche. Une touche après `E1` (Pause) n'a pas de relâchement : la
/// seconde, relâchée, la suit.
pub fn keyboard_input(data: &KeyboardInputData, tables: &Tables, keys: &KeyState) -> Option<[Option<KeyInput>; 2]> {
    let mut scan = data.make_code & 0x7F;
    if data.flags & KEY_E0 != 0 {
        scan |= 0xE000;
    }
    if data.flags & KEY_E1 != 0 {
        scan |= 0xE100;
    }
    let mut vk = tables.vsc_to_vk(scan);
    if vk == 0 {
        return None;
    }
    if vk & KBDNUMPAD != 0 && is_locked(keys, VK_NUMLOCK) {
        vk = u16::from(translate_numpad_key(vk as u8));
    }
    let key = vk as u8;
    let input = KeyInput {
        vk: key,
        scan: scan & 0x7F,
        // Right Shift is extended: its flag is not in the layout.
        extended: vk & KBDEXT != 0 || key == VK_RSHIFT,
        up: data.flags & KEY_BREAK != 0,
    };
    let release = (data.flags & KEY_E1 != 0).then_some(KeyInput { up: true, ..input });
    Some([Some(input), release])
}

/// ProcessKeyEvent : l'état `keys` après la touche `input`, et le message
/// qu'elle donne pour la file du premier plan (sa fenêtre : `hwnd` ; aucune
/// fenêtre n'y a le clavier : `no_focus`, ce qui en fait une touche
/// système).
pub fn key_message(keys: &mut AsyncKeys, input: &KeyInput, hwnd: u32, no_focus: bool, time: u32) -> Msg32 {
    let simple = simplify_vk(input.vk);
    let was_down = is_down(&keys.state, simple);
    // The common key stays down while either side is.
    let other = fix_vk(simple, !input.extended);
    let simple_down = !input.up || is_down(&keys.state, other);
    keys.update(simple, simple_down);
    let fixed = fix_vk(simple, input.extended);
    let extended = input.extended && simple != VK_SHIFT;
    let menu = is_down(&keys.state, VK_MENU);
    let system = input.vk == VK_F10
        || (simple == VK_MENU && keys.menu_down_recently)
        || (menu && !is_down(&keys.state, VK_CONTROL))
        || no_focus;
    let message = if system {
        keys.menu_down_recently = false;
        if input.up {
            WM_SYSKEYUP
        } else {
            if simple == VK_MENU {
                keys.menu_down_recently = true;
            }
            WM_SYSKEYDOWN
        }
    } else if input.up {
        WM_KEYUP
    } else {
        WM_KEYDOWN
    };
    keys.update(fixed, !input.up);
    let mut flags = 0;
    if extended {
        flags |= KF_EXTENDED;
    }
    if is_down(&keys.state, VK_MENU) {
        flags |= KF_ALTDOWN;
    }
    if was_down {
        flags |= KF_REPEAT;
    }
    if input.up {
        flags |= KF_UP;
    }
    let l_param = 1 | (u32::from(input.scan) | flags) << 16;
    Msg32 { hwnd, message, w_param: u32::from(fixed), l_param, time, ..Msg32::default() }
}

/// L'état du clavier.
static ASYNC: KSpinLock<AsyncKeys> =
    KSpinLock::new(AsyncKeys { state: [0; 256], recent: [0; 32], menu_down_recently: false });
/// Le thread du premier plan (gpqForeground).
static FOREGROUND: KSpinLock<Option<Arc<ThreadInfo>>> = KSpinLock::new(None);

/// Le thread du premier plan, s'il y en a un.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn foreground() -> Option<Arc<ThreadInfo>> {
    FOREGROUND.lock().clone()
}

/// La disposition de `thread` (aucun : la première chargée,
/// W32kGetDefaultKeyLayout).
fn layout_of(thread: Option<&ThreadInfo>) -> Option<Arc<KeyboardLayout>> {
    thread
        .and_then(ThreadInfo::keyboard_layout)
        .or_else(|| crate::keyboard::layouts().first().and_then(|&hkl| crate::keyboard::layout(hkl)))
}

/// Le temps d'un message : les millisecondes depuis le démarrage.
pub(crate) fn message_time() -> u32 {
    hal::timer::get_tick_count() as u32
}

/// Un bouton de la souris (VK_LBUTTON, VK_RBUTTON, VK_MBUTTON) enfoncé ou
/// relâché, dans l'état asynchrone du clavier (GetAsyncKeyState).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub(crate) fn update_async_button(vk: u8, down: bool) {
    ASYNC.lock().update(vk, down);
}

/// UserProcessKeyboardInput : la touche `data` du clavier change l'état du
/// clavier et va, en message, à la file du premier plan. Rien sans
/// disposition chargée ; sans premier plan, l'état change seul.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread d'entrée brute.
pub fn process_keyboard_input(data: &KeyboardInputData) {
    let foreground = foreground();
    let Some(layout) = layout_of(foreground.as_deref()) else { return };
    let tables = &layout.file.kbd;
    let keys = ASYNC.lock().state;
    let Some(inputs) = keyboard_input(data, tables, &keys) else { return };
    for input in inputs.into_iter().flatten() {
        // AltGr: the right Alt also gives Ctrl.
        if input.vk == VK_RMENU && tables.locale_flags & KLLF_ALTGR != 0 {
            let control = KeyInput { vk: VK_LCONTROL, scan: 0, extended: false, up: input.up };
            send_key(&control, foreground.as_deref());
        }
        send_key(&input, foreground.as_deref());
    }
}

/// ProcessKeyEvent : `input` change l'état du clavier et, s'il y a un
/// premier plan, devient un message pour sa fenêtre qui a le clavier (ou sa
/// fenêtre active).
fn send_key(input: &KeyInput, foreground: Option<&ThreadInfo>) {
    let (active, focus) = foreground.map_or((0, 0), |thread| thread.queue.with(|q| (q.active, q.focus)).0);
    let hwnd = if focus != 0 { focus } else { active };
    let message = key_message(&mut ASYNC.lock(), input, hwnd, foreground.is_some() && focus == 0, message_time());
    if let Some(thread) = foreground {
        crate::queue::post_input(thread, message);
    }
}

/// NtUserGetAsyncKeyState pour `vk`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn async_key_state(vk: u8) -> u16 {
    ASYNC.lock().get(vk)
}

/// UserGetKeyState : l'état de `vk` vu du thread `thread` : 0xFF80
/// enfoncée, 1 basculée.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn key_state(thread: &ThreadInfo, vk: u8) -> u16 {
    let keys = thread.queue.with(|queue| queue.keys).0;
    let mut state = 0;
    if is_down(&keys, vk) {
        state |= 0xFF80;
    }
    if is_locked(&keys, vk) {
        state |= 1;
    }
    state
}

/// NtUserGetKeyboardState : l'état du clavier vu du thread `thread`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn keyboard_state(thread: &ThreadInfo) -> KeyState {
    thread.queue.with(|queue| queue.keys).0
}

/// La touche morte en attente (`wchDead` d'IntToUnicodeEx).
static DEAD: KSpinLock<u16> = KSpinLock::new(0);

/// IntToUnicodeEx dans la disposition `hkl` (0, ou une disposition qui
/// n'est pas chargée : celle de `thread`) : les caractères de `vk` dans
/// l'état `keys`, dans `out` ; voir [`to_unicode`]. 0 sans disposition.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn to_unicode_ex(hkl: u32, thread: Option<&ThreadInfo>, vk: u8, keys: &KeyState, out: &mut [u16]) -> i32 {
    let layout = (hkl != 0).then(|| crate::keyboard::layout(hkl)).flatten().or_else(|| layout_of(thread));
    let Some(layout) = layout else { return 0 };
    to_unicode(&layout.file.kbd, vk, keys, &mut DEAD.lock(), out)
}

/// IntTranslateKbdMessage : les caractères de la touche de `message` (un
/// WM_KEYDOWN ou WM_SYSKEYDOWN), selon l'état du clavier du thread
/// `thread`, postés à sa file pour la même fenêtre : WM_CHAR, ou
/// WM_DEADCHAR pour une touche morte (WM_SYS* pour une touche système).
/// Faux sans caractère, ou pour un autre message.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn translate_message(thread: &ThreadInfo, message: &Msg32) -> bool {
    let system = match message.message {
        WM_KEYDOWN => false,
        WM_SYSKEYDOWN => true,
        _ => return false,
    };
    let keys = keyboard_state(thread);
    let mut chars = [0u16; 3];
    let count = to_unicode_ex(0, Some(thread), message.w_param as u8, &keys, &mut chars);
    if count == 0 {
        return false;
    }
    let kind = match (count < 0, system) {
        (false, false) => WM_CHAR,
        (false, true) => WM_SYSCHAR,
        (true, false) => WM_DEADCHAR,
        (true, true) => WM_SYSDEADCHAR,
    };
    for &ch in &chars[..count.unsigned_abs() as usize] {
        let posted = Msg32 {
            hwnd: message.hwnd,
            message: kind,
            w_param: u32::from(ch),
            l_param: message.l_param,
            time: message_time(),
            ..Msg32::default()
        };
        crate::queue::post(thread, posted);
    }
    true
}

/// co_IntSetForegroundWindow puis co_IntSetActiveWindow : la fenêtre de
/// premier niveau `window` devient la fenêtre active de sa file, qui passe
/// au premier plan. Si le premier plan change de thread, les fenêtres de
/// premier niveau du thread qui le perd, puis celles du thread de `window`,
/// reçoivent WM_ACTIVATEAPP ([`send_activate_app`]). Au thread courant,
/// `window` reçoit ensuite WM_ACTIVATE (dont DefWindowProc lui donne le
/// clavier : SetFocus), puis le clavier s'il ne lui a pas été donné. D'un
/// autre thread, elle prend le clavier sans WM_ACTIVATE.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn activate(window: &Arc<Window>) {
    let Some(thread) = crate::gui::thread_info_of(window.pti) else { return };
    let hwnd = window.handle;
    let (previous_active, focus) =
        thread.queue.with(|queue| (core::mem::replace(&mut queue.active, hwnd), queue.focus)).0;
    let previous_foreground = FOREGROUND.lock().replace(thread.clone());
    let same_thread = previous_foreground.as_ref().is_some_and(|left| Arc::ptr_eq(left, &thread));
    let left = previous_foreground.filter(|_| !same_thread);
    let current = crate::convert_current_thread().ok();
    // The foreground leaves another thread: the frame of its active window
    // goes inactive (no WM_NCACTIVATE between threads yet), and its
    // top-level windows get WM_ACTIVATEAPP (FALSE).
    if let Some(left) = &left {
        let left_active = left.queue.with(|queue| queue.active).0;
        if let Some(old) = crate::window::get(left_active) {
            crate::paint::set_frame_active(&old, false, true);
        }
        if let Some(current) = &current {
            send_activate_app(current, left, false, thread_id(&thread));
        }
    }
    // The top-level windows of the thread that gains the foreground get
    // WM_ACTIVATEAPP (TRUE), before the messages of the activated window.
    let announce = || {
        if let (false, Some(current)) = (same_thread, &current) {
            send_activate_app(current, &thread, true, left.as_ref().map_or(0, |left| thread_id(left)));
        }
    };
    let ours = current.as_ref().is_some_and(|current| current.server == window.pti);
    let old = crate::window::get(previous_active).filter(|_| previous_active != hwnd);
    if previous_active == hwnd && focus == hwnd {
        // Already active: WM_ACTIVATEAPP if the foreground comes back to its
        // thread, and its frame, if it went inactive with the foreground.
        announce();
        if window.state().state & WNDS_ACTIVEFRAME == 0 {
            if ours {
                let _ = crate::window::send_message(window, WM_NCACTIVATE, 1, LParam::Value(0));
            } else {
                crate::paint::set_frame_active(window, true, true);
            }
        }
        return;
    }
    if !ours {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: WM_ACTIVATE and WM_SETFOCUS to a window of another thread: not yet");
        }
        thread.queue.with(|queue| queue.focus = hwnd);
        announce();
        if let Some(old) = &old {
            crate::paint::set_frame_active(old, false, true);
        }
        crate::paint::set_frame_active(window, true, true);
        return;
    }
    if let Some(old) = &old {
        let _ = crate::window::send_message(old, WM_NCACTIVATE, 0, LParam::Value(0));
        let _ = crate::window::send_message(old, WM_ACTIVATE, WA_INACTIVE, LParam::Value(hwnd));
    }
    announce();
    let _ = crate::window::send_message(window, WM_NCACTIVATE, 1, LParam::Value(0));
    let _ = crate::window::send_message(window, WM_ACTIVATE, WA_ACTIVE, LParam::Value(previous_active));
    if thread.queue.with(|queue| queue.focus).0 != hwnd {
        send_focus_messages(&thread, Some(window));
    }
}

/// Le TID du thread GUI `thread`.
fn thread_id(thread: &ThreadInfo) -> u32 {
    crate::gui::thread_of_server_address(thread.server).unwrap_or(0)
}

/// `window` est encore une fenêtre de premier niveau : une fille d'une
/// fenêtre de bureau.
fn is_top_level(window: &Window) -> bool {
    crate::window::get(window.handle).is_some()
        && crate::window::get(window.state().parent).is_some_and(|parent| parent.is_desktop_window())
}

/// co_IntSendActivateMessages (WM_ACTIVATEAPP) : chaque fenêtre de premier
/// niveau du thread `thread`, visible ou non, reçoit WM_ACTIVATEAPP :
/// `active` (TRUE pour le thread qui gagne le premier plan), et le TID de
/// l'autre thread `other_tid` (celui qui perd le premier plan, ou qui le
/// gagne ; 0 : aucun). Envoyé depuis le thread courant `current` comme
/// SendNotifyMessage (`sent::notify_window`) : tout de suite à ses propres
/// fenêtres, par la file de leur thread et sans attendre aux autres.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn send_activate_app(current: &ThreadInfo, thread: &ThreadInfo, active: bool, other_tid: u32) {
    let windows = thread.windows.lock().clone();
    for window in windows.iter().filter(|window| is_top_level(window)) {
        let _ = crate::sent::notify_window(current, window, WM_ACTIVATEAPP, u32::from(active), other_tid);
    }
}

/// IntSendFocusMessages : `window` (aucune : personne) a le clavier dans la
/// file de `thread` ; l'ancienne reçoit WM_KILLFOCUS, la nouvelle
/// WM_SETFOCUS. Rend l'ancienne.
fn send_focus_messages(thread: &ThreadInfo, window: Option<&Arc<Window>>) -> u32 {
    let hwnd = window.map_or(0, |window| window.handle);
    let previous = thread.queue.with(|queue| core::mem::replace(&mut queue.focus, hwnd)).0;
    if let Some(old) = crate::window::get(previous).filter(|_| previous != hwnd) {
        let _ = crate::window::send_message(&old, WM_KILLFOCUS, hwnd, LParam::Value(0));
    }
    if let Some(window) = window {
        let _ = crate::window::send_message(window, WM_SETFOCUS, previous, LParam::Value(0));
    }
    previous
}

/// co_UserSetFocus : `window` (aucune : personne) a désormais le clavier
/// dans la file du thread courant `thread`, sa fenêtre de premier niveau
/// activée s'il le faut ([`activate`]). Rend la fenêtre qui l'avait ; 0
/// pour une fenêtre d'un autre thread, ou dont la chaîne des parents a une
/// fenêtre réduite ou désactivée (rien ne change alors).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn set_focus(thread: &ThreadInfo, window: Option<&Arc<Window>>) -> u32 {
    let previous = thread.queue.with(|queue| queue.focus).0;
    let Some(window) = window else { return send_focus_messages(thread, None) };
    if previous == window.handle {
        return previous;
    }
    if window.pti != thread.server {
        return 0;
    }
    let mut top = window.clone();
    loop {
        let state = top.state();
        if state.style & (WS_MINIMIZE | WS_DISABLED) != 0 {
            return 0;
        }
        if state.style & (WS_POPUP | WS_CHILD) != WS_CHILD {
            break;
        }
        match crate::window::get(state.parent) {
            Some(parent) => top = parent,
            None => break,
        }
    }
    if thread.queue.with(|queue| queue.active).0 != top.handle {
        activate(&top);
    }
    // Activating may have given the focus already (WM_ACTIVATE).
    let previous = thread.queue.with(|queue| queue.focus).0;
    if previous != window.handle {
        send_focus_messages(thread, Some(window));
    }
    previous
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(vk: u8, scan: u16, extended: bool, up: bool) -> KeyInput {
        KeyInput { vk, scan, extended, up }
    }

    #[test]
    fn a_letter_goes_down_then_up() {
        let mut keys = AsyncKeys::default();
        let down = key_message(&mut keys, &key(b'A', 0x1E, false, false), 0x10, false, 5);
        assert_eq!((down.hwnd, down.message, down.w_param, down.time), (0x10, WM_KEYDOWN, u32::from(b'A'), 5));
        assert_eq!(down.l_param, 0x001E_0001, "one repeat, the scan code");
        assert!(is_down(&keys.state, b'A'));
        let again = key_message(&mut keys, &key(b'A', 0x1E, false, false), 0x10, false, 6);
        assert_eq!(again.l_param, 0x401E_0001, "held: KF_REPEAT");
        let up = key_message(&mut keys, &key(b'A', 0x1E, false, true), 0x10, false, 7);
        assert_eq!((up.message, up.l_param), (WM_KEYUP, 0xC01E_0001), "KF_UP and the previous state");
        assert!(!is_down(&keys.state, b'A') && is_locked(&keys.state, b'A'), "toggled once");
    }

    #[test]
    fn a_side_key_is_its_side_and_holds_the_common_one() {
        let mut keys = AsyncKeys::default();
        let left = key_message(&mut keys, &key(VK_LSHIFT, 0x2A, false, false), 1, false, 0);
        assert_eq!(left.w_param, u32::from(VK_LSHIFT));
        assert!(is_down(&keys.state, VK_SHIFT) && is_down(&keys.state, VK_LSHIFT));
        let right = key_message(&mut keys, &key(VK_RSHIFT, 0x36, true, false), 1, false, 0);
        assert_eq!(
            (right.w_param, right.l_param & (KF_EXTENDED << 16)),
            (u32::from(VK_RSHIFT), 0),
            "Shift: never extended"
        );
        key_message(&mut keys, &key(VK_LSHIFT, 0x2A, false, true), 1, false, 0);
        assert!(is_down(&keys.state, VK_SHIFT), "the right one still holds it");
        key_message(&mut keys, &key(VK_RSHIFT, 0x36, true, true), 1, false, 0);
        assert!(!is_down(&keys.state, VK_SHIFT));
        let ctrl = key_message(&mut keys, &key(VK_RCONTROL, 0x1D, true, false), 1, false, 0);
        assert_eq!((ctrl.w_param, ctrl.l_param >> 16 & KF_EXTENDED), (u32::from(VK_RCONTROL), KF_EXTENDED));
    }

    #[test]
    fn alt_makes_system_keys() {
        let mut keys = AsyncKeys::default();
        let alt = key_message(&mut keys, &key(VK_LMENU, 0x38, false, false), 1, false, 0);
        assert_eq!((alt.message, alt.l_param >> 16 & KF_ALTDOWN), (WM_SYSKEYDOWN, KF_ALTDOWN));
        let f = key_message(&mut keys, &key(b'F', 0x21, false, false), 1, false, 0);
        assert_eq!(f.message, WM_SYSKEYDOWN, "Alt + F");
        key_message(&mut keys, &key(b'F', 0x21, false, true), 1, false, 0);
        let alt_up = key_message(&mut keys, &key(VK_LMENU, 0x38, false, true), 1, false, 0);
        assert_eq!(alt_up.message, WM_KEYUP, "Alt after Alt + F: not alone any more");
        key_message(&mut keys, &key(VK_LMENU, 0x38, false, false), 1, false, 0);
        let alone = key_message(&mut keys, &key(VK_LMENU, 0x38, false, true), 1, false, 0);
        assert_eq!(alone.message, WM_SYSKEYUP, "Alt alone");
        let f10 = key_message(&mut keys, &key(VK_F10, 0x44, false, false), 1, false, 0);
        assert_eq!(f10.message, WM_SYSKEYDOWN, "F10");
        let ctrl = key_message(&mut keys, &key(VK_LCONTROL, 0x1D, false, false), 1, false, 0);
        assert_eq!(ctrl.message, WM_KEYDOWN);
        key_message(&mut keys, &key(VK_LMENU, 0x38, false, false), 1, false, 0);
        let ctrl_alt = key_message(&mut keys, &key(b'E', 0x12, false, false), 1, false, 0);
        assert_eq!(ctrl_alt.message, WM_KEYDOWN, "Ctrl + Alt: not a system key");
        let unfocused = key_message(&mut AsyncKeys::default(), &key(b'A', 0x1E, false, false), 1, true, 0);
        assert_eq!(unfocused.message, WM_SYSKEYDOWN, "no window has the keyboard");
    }

    #[test]
    fn get_async_key_state_says_down_and_recently_down() {
        let mut keys = AsyncKeys::default();
        key_message(&mut keys, &key(b'A', 0x1E, false, false), 1, false, 0);
        assert_eq!(keys.get(b'A'), 0x8001);
        assert_eq!(keys.get(b'A'), 0x8000, "recently: once");
        key_message(&mut keys, &key(b'A', 0x1E, false, true), 1, false, 0);
        // As in ReactOS: releasing a key without sides first updates its
        // common key (itself) as still down, which marks it recently down.
        assert_eq!((keys.get(b'A'), keys.get(b'A'), keys.get(b'B')), (1, 0, 0));
    }

    #[test]
    fn the_numpad_follows_num_lock() {
        assert_eq!(translate_numpad_key(VK_HOME), VK_NUMPAD0 + 7);
        assert_eq!(translate_numpad_key(VK_DELETE), VK_DECIMAL);
        assert_eq!(translate_numpad_key(b'A'), b'A');
        assert_eq!((simplify_vk(VK_RMENU), fix_vk(VK_CONTROL, true), fix_vk(b'A', true)), (VK_MENU, VK_RCONTROL, b'A'));
    }

    /// Tables mapping scan codes 0x1E (A), 0x47 (Home, numpad) and E0 1D
    /// (right Ctrl), E1 1D (Pause).
    fn tables() -> Tables {
        let mut vsc_to_vk = alloc::vec![0u16; 0x48];
        vsc_to_vk[0x1E] = u16::from(b'A');
        vsc_to_vk[0x47] = u16::from(VK_HOME) | KBDNUMPAD | 0x400;
        vsc_to_vk[0x36] = u16::from(VK_RSHIFT);
        Tables {
            vsc_to_vk,
            vsc_to_vk_e0: alloc::vec![(0x1D, u16::from(VK_RCONTROL) | KBDEXT)],
            vsc_to_vk_e1: alloc::vec![(0x1D, 0x13)],
            ..Tables::default()
        }
    }

    fn data(make_code: u16, flags: u16) -> KeyboardInputData {
        KeyboardInputData { make_code, flags, ..KeyboardInputData::default() }
    }

    #[test]
    fn raw_input_becomes_keys() {
        let (tables, none) = (tables(), [0u8; 256]);
        let a = keyboard_input(&data(0x1E, KEY_BREAK), &tables, &none).unwrap();
        assert_eq!(a, [Some(key(b'A', 0x1E, false, true)), None]);
        let ctrl = keyboard_input(&data(0x1D, KEY_E0), &tables, &none).unwrap();
        assert_eq!(ctrl[0], Some(key(VK_RCONTROL, 0x1D, true, false)), "extended");
        let shift = keyboard_input(&data(0x36, 0), &tables, &none).unwrap();
        assert!(shift[0].unwrap().extended, "right Shift");
        let pause = keyboard_input(&data(0x1D, KEY_E1), &tables, &none).unwrap();
        assert_eq!(pause, [Some(key(0x13, 0x1D, false, false)), Some(key(0x13, 0x1D, false, true))], "no break code");
        assert_eq!(keyboard_input(&data(0x30, 0), &tables, &none), None, "no key");
        let home = keyboard_input(&data(0x47, 0), &tables, &none).unwrap()[0].unwrap();
        assert_eq!(home.vk, VK_HOME, "Num Lock off");
        let mut num = [0u8; 256];
        num[usize::from(VK_NUMLOCK)] = LOCKED;
        assert_eq!(keyboard_input(&data(0x47, 0), &tables, &num).unwrap()[0].unwrap().vk, VK_NUMPAD0 + 7);
    }
}
