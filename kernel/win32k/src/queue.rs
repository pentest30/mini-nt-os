//! Les files de messages (02 §7.2) : chaque thread GUI a la sienne, que
//! remplissent PostMessage et PostThreadMessage et que vident PeekMessage et
//! GetMessage.
//!
//! Une file tient ses messages postés dans l'ordre, et WM_QUIT à part
//! (PostQuitMessage) : il ne sort qu'une fois les messages postés tous
//! sortis. Elle tient aussi ses bits de réveil et de changement
//! (`fsWakeBits`, `fsChangeBits`, que `user32` lit dans le
//! `CLIENTTHREADINFO` du thread, dans le tas de son bureau) et un événement
//! de synchronisation, signalé à chaque message, sur lequel GetMessage
//! attend.
//!
//! Pas encore : les messages envoyés (SendMessage entre threads), les
//! entrées (clavier, souris : le thread d'entrée), WM_PAINT et WM_TIMER
//! synthétisés, les crochets, le filtre par fenêtre fille (seule la fenêtre
//! nommée), la position du curseur (`pt` est nul).

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use abi::ntstatus::NtStatus;
use abi::user::{Msg32, POINTER_MESSAGES, QS_ALLPOSTMESSAGE, QS_POSTMESSAGE, WM_DEVICECHANGE, WM_QUIT};
use ex::{Event, EventType};
use hal::sync::KSpinLock;
use ob::Object;

use crate::gui::ThreadInfo;

/// Un message porte un pointeur, et ne peut pas être posté
/// (is_pointer_message : `ERROR_MESSAGE_SYNC_ONLY`).
pub fn is_pointer_message(message: u32, wparam: u32) -> bool {
    if message == WM_DEVICECHANGE && wparam & 0x8000 == 0 {
        return false;
    }
    POINTER_MESSAGES.contains(&message)
}

/// Les messages que demande PeekMessage ou GetMessage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filter {
    /// 0 : tous ; `u32::MAX` (-1) : ceux du thread (sans fenêtre) ;
    /// sinon ceux de cette fenêtre.
    pub hwnd: u32,
    /// De `min` à `max` ; les deux à 0 : tous.
    pub min: u32,
    pub max: u32,
}

impl Filter {
    /// `message` est l'un de ceux qu'il demande.
    pub fn matches(&self, message: &Msg32) -> bool {
        let window = match self.hwnd {
            0 => true,
            u32::MAX => message.hwnd == 0,
            hwnd => message.hwnd == hwnd,
        };
        let range = (self.min == 0 && self.max == 0) || (self.min..=self.max).contains(&message.message);
        window && range
    }
}

/// Ce que tient une file.
#[derive(Debug, Default)]
pub struct QueueState {
    posted: VecDeque<Msg32>,
    /// WM_QUIT demandé, avec son code de sortie.
    quit: Option<u32>,
    /// QS_* : ce qu'il y a dans la file (fsWakeBits), et ce qui y est
    /// arrivé depuis la dernière fois qu'on a regardé (fsChangeBits).
    pub wake: u16,
    pub change: u16,
}

impl QueueState {
    /// Les bits de ce qui est posté, s'il y a quelque chose.
    fn refresh(&mut self) {
        let posted = QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
        if self.posted.is_empty() && self.quit.is_none() {
            self.wake &= !posted;
        } else {
            self.wake |= posted;
        }
    }

    /// MsqPostMessage : `message` à la fin de la file.
    pub fn post(&mut self, message: Msg32) {
        self.posted.push_back(message);
        self.change |= QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
        self.refresh();
    }

    /// MsqPostQuitMessage : WM_QUIT, de code `code`, sortira une fois les
    /// messages postés sortis.
    pub fn post_quit(&mut self, code: u32) {
        self.quit = Some(code);
        self.change |= QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
        self.refresh();
    }

    /// co_IntPeekMessage : le premier message posté que demande `filter`,
    /// sorti de la file si `remove` ; sinon WM_QUIT, s'il est demandé et
    /// qu'aucun message posté ne reste. Les bits de changement des messages
    /// postés sont effacés : on a regardé.
    pub fn peek(&mut self, filter: &Filter, remove: bool) -> Option<Msg32> {
        self.change &= !(QS_POSTMESSAGE | QS_ALLPOSTMESSAGE);
        let found = match self.posted.iter().position(|message| filter.matches(message)) {
            Some(index) if remove => self.posted.remove(index),
            Some(index) => Some(self.posted[index]),
            None if self.posted.is_empty() => self.quit.map(|code| {
                if remove {
                    self.quit = None;
                }
                Msg32 { message: WM_QUIT, w_param: code, ..Msg32::default() }
            }),
            None => None,
        };
        self.refresh();
        found
    }

    /// IntGetQueueStatus : `(fsChangeBits & flags) | (fsWakeBits & flags) << 16`
    /// ; les bits de changement demandés sont effacés.
    pub fn status(&mut self, flags: u16) -> u32 {
        let status = u32::from(self.change & flags) | u32::from(self.wake & flags) << 16;
        self.change &= !flags;
        status
    }
}

/// La file d'un thread GUI.
pub struct MessageQueue {
    state: KSpinLock<QueueState>,
    /// Signalé à chaque message (de synchronisation).
    event: Arc<Object<Event>>,
}

impl MessageQueue {
    /// Une file vide.
    pub fn new() -> Self {
        Self {
            state: KSpinLock::new(QueueState::default()),
            event: Event::create(EventType::SynchronizationEvent, false),
        }
    }

    /// Change la file par `change`, et rend ce qu'il rend avec ses bits de
    /// réveil et de changement après.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn with<R>(&self, change: impl FnOnce(&mut QueueState) -> R) -> (R, u16, u16) {
        let mut state = self.state.lock();
        let result = change(&mut state);
        (result, state.wake, state.change)
    }

    /// Réveille celui qui attend un message.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn wake(&self) {
        self.event.set();
    }

    /// L'événement signalé à chaque message.
    pub fn event(&self) -> &Arc<Object<Event>> {
        &self.event
    }
}

impl Default for MessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// UserPostThreadMessage : `message` à la fin de la file de `thread`, qui
/// est réveillé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn post(thread: &ThreadInfo, message: Msg32) {
    let ((), wake, change) = thread.queue.with(|queue| queue.post(message));
    thread.mirror_queue_bits(wake, change);
    thread.queue.wake();
}

/// MsqPostQuitMessage : WM_QUIT de code `code` pour `thread`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn post_quit(thread: &ThreadInfo, code: u32) {
    let ((), wake, change) = thread.queue.with(|queue| queue.post_quit(code));
    thread.mirror_queue_bits(wake, change);
    thread.queue.wake();
}

/// PeekMessage : le premier message de la file de `thread` que demande
/// `filter`, sorti si `remove`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn peek(thread: &ThreadInfo, filter: &Filter, remove: bool) -> Option<Msg32> {
    let (found, wake, change) = thread.queue.with(|queue| queue.peek(filter, remove));
    thread.mirror_queue_bits(wake, change);
    found
}

/// IntGetQueueStatus pour `thread`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn status(thread: &ThreadInfo, flags: u16) -> u32 {
    let (status, wake, change) = thread.queue.with(|queue| queue.status(flags));
    thread.mirror_queue_bits(wake, change);
    status
}

/// GetMessage : le premier message de la file du thread courant `thread`
/// que demande `filter`, sorti ; attend qu'il en arrive un sinon (une
/// attente du mode utilisateur, que la fin du thread interrompt).
///
/// # Errors
/// Le statut d'une attente qui finit autrement.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
pub fn get(thread: &ThreadInfo, filter: &Filter) -> Result<Msg32, NtStatus> {
    loop {
        if let Some(message) = peek(thread, filter, true) {
            return Ok(message);
        }
        wait(thread)?;
    }
}

/// WaitMessage : attend qu'un message arrive dans la file du thread courant
/// `thread`, s'il n'y en a pas.
///
/// # Errors
/// Le statut d'une attente qui finit autrement.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
pub fn wait_message(thread: &ThreadInfo) -> Result<(), NtStatus> {
    let ((), wake, _) = thread.queue.with(|_| ());
    if wake & QS_POSTMESSAGE != 0 {
        return Ok(());
    }
    wait(thread)
}

/// Attend l'événement de la file du thread courant `thread`.
fn wait(thread: &ThreadInfo) -> Result<(), NtStatus> {
    // SAFETY: the current Ps thread, at PASSIVE_LEVEL; `thread`, held by
    // the caller, keeps its queue and its event.
    let status = unsafe {
        ke::dispatcher::ke_wait_for_single_object::<ke::sched::KePlatform>(
            thread.queue.event().dispatcher_object(),
            ke::dispatcher::ProcessorMode::User,
            false,
            None,
        )
    };
    match status {
        abi::ntstatus::STATUS_WAIT_0 => Ok(()),
        other => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(hwnd: u32, message: u32, w_param: u32) -> Msg32 {
        Msg32 { hwnd, message, w_param, ..Msg32::default() }
    }

    #[test]
    fn pointer_messages_cannot_be_posted() {
        assert!(is_pointer_message(0x0001, 0), "WM_CREATE");
        assert!(is_pointer_message(0x000C, 0), "WM_SETTEXT");
        assert!(!is_pointer_message(0x0400, 0), "WM_USER");
        assert!(!is_pointer_message(WM_DEVICECHANGE, 0x0007), "WM_DEVICECHANGE without a pointer");
        assert!(is_pointer_message(WM_DEVICECHANGE, 0x8000), "WM_DEVICECHANGE with one");
    }

    #[test]
    fn filters_pick_windows_and_ranges() {
        let thread = message(0, 0x401, 0);
        let window = message(0x0002_0020, 0x402, 0);
        let all = Filter { hwnd: 0, min: 0, max: 0 };
        assert!(all.matches(&thread) && all.matches(&window));
        let thread_only = Filter { hwnd: u32::MAX, ..all };
        assert!(thread_only.matches(&thread) && !thread_only.matches(&window));
        let one_window = Filter { hwnd: 0x0002_0020, ..all };
        assert!(!one_window.matches(&thread) && one_window.matches(&window));
        let range = Filter { min: 0x402, max: 0x402, ..all };
        assert!(!range.matches(&thread) && range.matches(&window));
    }

    #[test]
    fn messages_come_out_in_order_then_quit() {
        let mut queue = QueueState::default();
        let all = Filter { hwnd: 0, min: 0, max: 0 };
        assert_eq!(queue.peek(&all, true), None);
        queue.post(message(0, 0x401, 1));
        queue.post(message(0, 0x402, 2));
        queue.post_quit(7);
        let second = Filter { min: 0x402, max: 0x402, ..all };
        assert_eq!(queue.peek(&second, false).map(|m| m.w_param), Some(2), "looked at, left");
        assert_eq!(queue.peek(&all, true).map(|m| m.w_param), Some(1));
        assert_eq!(queue.peek(&all, true).map(|m| m.w_param), Some(2));
        let quit = queue.peek(&all, true).unwrap();
        assert_eq!((quit.message, quit.w_param), (WM_QUIT, 7), "WM_QUIT once the posted ones are out");
        assert_eq!(queue.peek(&all, true), None, "once");
    }

    #[test]
    fn quit_waits_for_posted_messages_even_unfiltered() {
        let mut queue = QueueState::default();
        queue.post(message(0, 0x401, 1));
        queue.post_quit(0);
        let other = Filter { hwnd: 0, min: 0x500, max: 0x500 };
        assert_eq!(queue.peek(&other, true), None, "a posted message remains");
    }

    #[test]
    fn wake_and_change_bits_follow_the_queue() {
        let mut queue = QueueState::default();
        let posted = QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
        assert_eq!(queue.status(0x04FF), 0);
        queue.post(message(0, 0x401, 1));
        assert_eq!((queue.wake, queue.change), (posted, posted));
        assert_eq!(queue.status(0x04FF), 0x0008_0008, "changed and present (QS_ALLINPUT)");
        assert_eq!(queue.status(0x04FF), 0x0008_0000, "the change seen");
        queue.post(message(0, 0x402, 1));
        let all = Filter { hwnd: 0, min: 0, max: 0 };
        queue.peek(&all, true);
        assert_eq!((queue.wake, queue.change), (posted, 0), "looked at; one left");
        queue.peek(&all, true);
        assert_eq!(queue.wake, 0, "empty");
    }
}
