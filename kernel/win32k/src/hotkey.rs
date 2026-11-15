//! Les raccourcis clavier (RegisterHotKey ; `hotkey.c` de ReactOS, comme
//! spécification).
//!
//! Un raccourci est une touche virtuelle et des modificateurs (MOD_ALT,
//! MOD_CONTROL, MOD_SHIFT, MOD_WIN), qu'un thread pose pour l'une de ses
//! fenêtres ou pour lui-même ([`register`], UserRegisterHotKey) ; une
//! combinaison n'a qu'un raccourci. Le thread d'entrée brute présente
//! chaque touche ([`process`], co_UserProcessHotKeys) : celle d'un
//! raccourci, enfoncée avec ses modificateurs, poste WM_HOTKEY (son
//! identifiant, MAKELONG(les modificateurs, la touche)) à sa fenêtre ou à
//! son thread, et ne donne pas de message de touche. Un raccourci sans
//! touche (des modificateurs seuls) part au relâchement d'un modificateur,
//! si aucune autre touche n'a été enfoncée depuis le dernier.
//!
//! C'est ainsi que `winlogon` reçoit Ctrl+Alt+Suppr, la SAS : sa fenêtre SAS
//! pose MOD_CONTROL | MOD_ALT et VK_DELETE (RegisterHotKeys de `sas.c`),
//! puis Ctrl+Maj+Échap, Win+L et Win+U ; et la barre des tâches d'`explorer`
//! ses raccourcis de la touche Windows (Win+R, Win+E, Win+D…). La fenêtre
//! du shell reçoit Ctrl+Échap (NtUserSetShellWindowEx, [`HotKey::shell`]) en
//! WM_SYSCOMMAND SC_TASKLIST, qui ouvre le menu Démarrer.
//!
//! Les raccourcis d'une fenêtre partent avec elle ([`forget_window`]), ceux
//! d'un thread à sa fin ([`thread_exit`]). Un écart voulu : UnregisterHotKey
//! sans fenêtre ne retire que ceux du thread appelant ; ReactOS retire ceux
//! de tous les threads qui ont cet identifiant.
//!
//! Pas encore : les autres raccourcis que ReactOS pose lui-même (le
//! débogueur par F12, la touche Windows seule, les fenêtres ancrées par Win
//! et une flèche), WM_SETHOTKEY (SC_HOTKEY), PWND_BOTTOM (la fenêtre qui a
//! le clavier), la notification HSHELL_TASKMAN des crochets du shell.

use alloc::vec::Vec;

use abi::user::vk::{VK_CONTROL, VK_ESCAPE, VK_LWIN, VK_MENU, VK_PACKET, VK_RWIN, VK_SHIFT};
use abi::user::{Msg32, MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, SC_TASKLIST, WM_HOTKEY, WM_SYSCOMMAND};
use abi::winerror::{ERROR_HOTKEY_ALREADY_REGISTERED, ERROR_NOT_ENOUGH_MEMORY};
use hal::sync::KSpinLock;

use crate::kbdtables::{is_down, KeyState};

/// Un raccourci (HOT_KEY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotKey {
    /// Le thread qui le reçoit (l'adresse du serveur de son THREADINFO) :
    /// celui qui l'a posé, ou celui de la fenêtre.
    pub pti: u32,
    /// Sa fenêtre ; 0 : le message va à la file du thread.
    pub hwnd: u32,
    /// Ses MOD_*.
    pub modifiers: u32,
    /// Sa touche virtuelle ; 0 : des modificateurs seuls.
    pub vk: u32,
    /// Son identifiant (le `wParam` de WM_HOTKEY).
    pub id: i32,
    /// Ctrl+Échap de la fenêtre du shell (NtUserSetShellWindowEx) : il
    /// donne WM_SYSCOMMAND SC_TASKLIST, pas WM_HOTKEY.
    pub shell: bool,
}

impl HotKey {
    /// Ctrl+Échap pour `hwnd`, la fenêtre du shell, du thread `pti`
    /// (UserRegisterHotKey(WndShell, SC_TASKLIST, MOD_CONTROL, VK_ESCAPE)).
    pub const fn task_list(pti: u32, hwnd: u32) -> Self {
        Self { pti, hwnd, modifiers: MOD_CONTROL, vk: VK_ESCAPE as u32, id: SC_TASKLIST as i32, shell: true }
    }

    /// Le message qu'il poste quand il part, `modifiers` enfoncés avec la
    /// touche `vk`, daté `time` : WM_HOTKEY (son identifiant,
    /// MAKELONG(modificateurs, touche)) ; WM_SYSCOMMAND SC_TASKLIST pour
    /// Ctrl+Échap du shell.
    pub fn message(&self, modifiers: u32, vk: u8, time: u32) -> Msg32 {
        let (message, w_param, l_param) = if self.shell {
            (WM_SYSCOMMAND, SC_TASKLIST, 0)
        } else {
            (WM_HOTKEY, self.id as u32, modifiers | u32::from(vk) << 16)
        };
        Msg32 { hwnd: self.hwnd, message, w_param, l_param, time, ..Msg32::default() }
    }
}

/// Les raccourcis posés (gphkFirst), et les modificateurs enfoncés seuls
/// depuis la dernière touche (gfsModOnlyCandidate).
#[derive(Debug, Default)]
pub struct HotKeys {
    keys: Vec<HotKey>,
    mod_only_candidate: u32,
}

impl HotKeys {
    /// Aucun raccourci.
    pub const fn new() -> Self {
        Self { keys: Vec::new(), mod_only_candidate: 0 }
    }

    /// IsHotKey : le raccourci de `modifiers` et `vk`.
    fn find(&self, modifiers: u32, vk: u32) -> Option<&HotKey> {
        self.keys.iter().find(|key| key.modifiers == modifiers && key.vk == vk)
    }

    /// UserRegisterHotKey : `key` posé.
    ///
    /// # Errors
    /// `ERROR_HOTKEY_ALREADY_REGISTERED` si sa combinaison a un raccourci,
    /// `ERROR_NOT_ENOUGH_MEMORY` sans mémoire ; `None` (sans erreur, comme
    /// ReactOS) pour VK_PACKET, qui n'est pas une touche.
    pub fn register(&mut self, key: HotKey) -> Result<(), Option<u32>> {
        if key.vk == u32::from(VK_PACKET) {
            return Err(None);
        }
        if self.find(key.modifiers, key.vk).is_some() {
            return Err(Some(ERROR_HOTKEY_ALREADY_REGISTERED));
        }
        self.keys.try_reserve(1).map_err(|_| Some(ERROR_NOT_ENOUGH_MEMORY))?;
        self.keys.push(key);
        Ok(())
    }

    /// UserUnregisterHotKey : les raccourcis `id` de la fenêtre `hwnd` (de
    /// `pti` pour 0) retirés ; s'il y en avait.
    pub fn unregister(&mut self, pti: u32, hwnd: u32, id: i32) -> bool {
        let before = self.keys.len();
        self.keys.retain(|key| !(key.hwnd == hwnd && key.id == id && (hwnd != 0 || key.pti == pti)));
        self.keys.len() != before
    }

    /// UnregisterWindowHotKeys : ceux de la fenêtre `hwnd` retirés.
    pub fn forget_window(&mut self, hwnd: u32) {
        self.keys.retain(|key| key.hwnd != hwnd);
    }

    /// UnregisterThreadHotKeys : ceux du thread `pti` retirés ; leur nombre.
    pub fn forget_thread(&mut self, pti: u32) -> usize {
        let before = self.keys.len();
        self.keys.retain(|key| key.pti != pti);
        before - self.keys.len()
    }

    /// co_UserProcessHotKeys : le raccourci que donne la touche `vk` (sans
    /// côté : VK_SHIFT, pas VK_LSHIFT) enfoncée (`down`) ou relâchée, avec
    /// `modifiers` enfoncés après elle. Une touche ordinaire enfoncée donne
    /// celui de sa combinaison ; un modificateur relâché, celui des
    /// modificateurs enfoncés seuls juste avant.
    pub fn press(&mut self, vk: u8, down: bool, modifiers: u32) -> Option<HotKey> {
        let modifier = matches!(vk, VK_SHIFT | VK_CONTROL | VK_MENU | VK_LWIN | VK_RWIN);
        match (down, modifier) {
            (true, true) => {
                self.mod_only_candidate = modifiers;
                None
            }
            (true, false) => {
                self.mod_only_candidate = 0;
                self.find(modifiers, u32::from(vk)).copied()
            }
            (false, true) => {
                let candidate = core::mem::take(&mut self.mod_only_candidate);
                self.find(candidate, 0).copied()
            }
            (false, false) => {
                self.mod_only_candidate = 0;
                None
            }
        }
    }
}

/// IntGetModifiers : les MOD_* enfoncés dans `keys`.
pub fn modifiers(keys: &KeyState) -> u32 {
    let mut modifiers = 0;
    if is_down(keys, VK_SHIFT) {
        modifiers |= MOD_SHIFT;
    }
    if is_down(keys, VK_CONTROL) {
        modifiers |= MOD_CONTROL;
    }
    if is_down(keys, VK_MENU) {
        modifiers |= MOD_ALT;
    }
    if is_down(keys, VK_LWIN) || is_down(keys, VK_RWIN) {
        modifiers |= MOD_WIN;
    }
    modifiers
}

/// Les raccourcis du système.
static HOTKEYS: KSpinLock<HotKeys> = KSpinLock::new(HotKeys::new());

/// UserRegisterHotKey : `key` posé.
///
/// # Errors
/// Ceux de [`HotKeys::register`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn register(key: HotKey) -> Result<(), Option<u32>> {
    HOTKEYS.lock().register(key)
}

/// UserUnregisterHotKey : les raccourcis `id` de la fenêtre `hwnd` (du
/// thread `pti` pour 0) retirés ; s'il y en avait.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn unregister(pti: u32, hwnd: u32, id: i32) -> bool {
    HOTKEYS.lock().unregister(pti, hwnd, id)
}

/// UnregisterWindowHotKeys : ceux de la fenêtre `hwnd`, détruite.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn forget_window(hwnd: u32) {
    HOTKEYS.lock().forget_window(hwnd);
}

/// UnregisterThreadHotKeys : ceux du thread `pti`, qui se termine ; leur
/// nombre.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn thread_exit(pti: u32) -> usize {
    HOTKEYS.lock().forget_thread(pti)
}

/// co_UserProcessHotKeys : la touche `vk` (sans côté) enfoncée ou relâchée,
/// `modifiers` enfoncés après elle. Si c'est un raccourci, son message
/// ([`HotKey::message`]) va à sa fenêtre ou à son thread (daté `time`), et
/// la touche ne donne pas de message : rend vrai. Un raccourci dont le thread ou la fenêtre n'est plus
/// laisse passer la touche.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread d'entrée brute.
pub fn process(vk: u8, down: bool, modifiers: u32, time: u32) -> bool {
    let Some(key) = HOTKEYS.lock().press(vk, down, modifiers) else { return false };
    let pti = if key.hwnd == 0 {
        key.pti
    } else {
        match crate::window::get(key.hwnd) {
            Some(window) => window.pti,
            None => return false,
        }
    };
    let Some(thread) = crate::gui::thread_info_of(pti) else { return false };
    crate::queue::post(&thread, key.message(modifiers, vk, time));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::user::vk::VK_DELETE;

    /// The SAS window of winlogon (RegisterHotKeys of `sas.c`).
    fn sas(id: i32, modifiers: u32, vk: u8) -> HotKey {
        HotKey { pti: 0x1000, hwnd: 0x0001_0040, modifiers, vk: u32::from(vk), id, shell: false }
    }

    #[test]
    fn ctrl_alt_del_is_the_sas() {
        let mut keys = HotKeys::new();
        assert_eq!(keys.register(sas(0, MOD_CONTROL | MOD_ALT, VK_DELETE)), Ok(()));
        assert_eq!(keys.register(sas(1, MOD_CONTROL | MOD_SHIFT, VK_ESCAPE)), Ok(()));
        // Ctrl, then Alt, then Delete.
        assert_eq!(keys.press(VK_CONTROL, true, MOD_CONTROL), None);
        assert_eq!(keys.press(VK_MENU, true, MOD_CONTROL | MOD_ALT), None);
        assert_eq!(keys.press(VK_DELETE, true, MOD_CONTROL | MOD_ALT).map(|key| key.id), Some(0));
        assert_eq!(keys.press(VK_DELETE, false, MOD_CONTROL | MOD_ALT), None, "not on the release");
        assert_eq!(keys.press(VK_DELETE, true, MOD_CONTROL), None, "Ctrl+Delete is not it");
        assert_eq!(keys.press(VK_DELETE, true, MOD_CONTROL | MOD_ALT | MOD_SHIFT), None, "nor Ctrl+Alt+Shift+Delete");
        assert_eq!(keys.press(VK_ESCAPE, true, MOD_CONTROL | MOD_SHIFT).map(|key| key.id), Some(1));
        let message = sas(0, MOD_CONTROL | MOD_ALT, VK_DELETE).message(MOD_CONTROL | MOD_ALT, VK_DELETE, 7);
        assert_eq!(
            (message.hwnd, message.message, message.w_param, message.l_param, message.time),
            (0x0001_0040, WM_HOTKEY, 0, 0x002E_0003, 7),
            "MAKELONG(the modifiers, the key)"
        );
    }

    /// Ctrl+Esc of the shell window opens the Start menu: WM_SYSCOMMAND
    /// SC_TASKLIST, not WM_HOTKEY.
    #[test]
    fn ctrl_esc_is_the_task_list_of_the_shell() {
        let mut keys = HotKeys::new();
        let shell = HotKey::task_list(0x1000, 0x0002_0010);
        assert_eq!(keys.register(shell), Ok(()));
        let found = keys.press(VK_ESCAPE, true, MOD_CONTROL);
        assert_eq!(found, Some(shell));
        let message = shell.message(MOD_CONTROL, VK_ESCAPE, 0);
        assert_eq!((message.hwnd, message.message, message.w_param), (0x0002_0010, WM_SYSCOMMAND, SC_TASKLIST));
        let other = HotKey { shell: false, ..shell };
        assert_eq!(other.message(MOD_CONTROL, VK_ESCAPE, 0).message, WM_HOTKEY, "the same id elsewhere");
    }

    #[test]
    fn a_combination_has_one_hotkey() {
        let mut keys = HotKeys::new();
        assert_eq!(keys.register(sas(0, MOD_CONTROL | MOD_ALT, VK_DELETE)), Ok(()));
        let other = HotKey { pti: 0x2000, hwnd: 0, ..sas(7, MOD_CONTROL | MOD_ALT, VK_DELETE) };
        assert_eq!(keys.register(other), Err(Some(ERROR_HOTKEY_ALREADY_REGISTERED)));
        assert_eq!(keys.register(sas(2, 0, VK_PACKET)), Err(None), "VK_PACKET is not a key");
        assert!(keys.unregister(0x1000, 0x0001_0040, 0));
        assert!(!keys.unregister(0x1000, 0x0001_0040, 0), "already gone");
        assert_eq!(keys.register(other), Ok(()), "free again");
    }

    #[test]
    fn modifiers_alone_trigger_at_the_release() {
        let mut keys = HotKeys::new();
        let win = HotKey { pti: 0x1000, hwnd: 0, modifiers: MOD_WIN, vk: 0, id: 5, shell: false };
        assert_eq!(keys.register(win), Ok(()));
        assert_eq!(keys.press(VK_LWIN, true, MOD_WIN), None);
        assert_eq!(keys.press(VK_LWIN, false, 0), Some(win));
        // Win+E: another key in between, no Win hotkey at the release.
        assert_eq!(keys.press(VK_LWIN, true, MOD_WIN), None);
        assert_eq!(keys.press(b'E', true, MOD_WIN), None);
        assert_eq!(keys.press(b'E', false, MOD_WIN), None);
        assert_eq!(keys.press(VK_LWIN, false, 0), None);
    }

    #[test]
    fn a_window_and_a_thread_take_their_hotkeys_away() {
        let mut keys = HotKeys::new();
        assert_eq!(keys.register(sas(0, MOD_CONTROL | MOD_ALT, VK_DELETE)), Ok(()));
        let thread_key = |pti, vk| HotKey { pti, hwnd: 0, modifiers: MOD_ALT, vk, id: 3, shell: false };
        assert_eq!(keys.register(thread_key(0x1000, 0x41)), Ok(()));
        assert_eq!(keys.register(thread_key(0x2000, 0x42)), Ok(()));
        assert!(!keys.unregister(0x3000, 0, 3), "another thread's identifier");
        assert!(keys.unregister(0x2000, 0, 3), "the caller's own");
        assert_eq!(keys.press(0x42, true, MOD_ALT), None);
        keys.forget_window(0x0001_0040);
        assert_eq!(keys.press(VK_DELETE, true, MOD_CONTROL | MOD_ALT), None);
        assert_eq!(keys.forget_thread(0x1000), 1);
        assert_eq!(keys.press(0x41, true, MOD_ALT), None);
    }

    #[test]
    fn the_modifiers_come_from_the_key_state() {
        let mut state: KeyState = [0; 256];
        assert_eq!(modifiers(&state), 0);
        state[usize::from(VK_CONTROL)] = crate::kbdtables::DOWN;
        state[usize::from(VK_MENU)] = crate::kbdtables::DOWN;
        assert_eq!(modifiers(&state), MOD_CONTROL | MOD_ALT);
        state[usize::from(VK_RWIN)] = crate::kbdtables::DOWN;
        assert_eq!(modifiers(&state), MOD_CONTROL | MOD_ALT | MOD_WIN);
    }
}
