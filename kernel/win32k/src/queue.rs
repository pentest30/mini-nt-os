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
//! WM_PAINT n'est pas dans la file : un compte des fenêtres du thread qui ont
//! à se peindre (`cPaintsReady`, et `QS_PAINT` tant qu'il n'est pas nul)
//! dit d'en chercher une ([`crate::paint::paint_message`]) quand aucun
//! message posté ne sort (co_IntPeekMessage : messages postés, WM_QUIT, puis
//! WM_PAINT). WM_TIMER non plus : il vient d'une minuterie prête
//! ([`crate::timer::message`], `QS_TIMER`) quand rien d'autre ne sort.
//!
//! Les touches du clavier (`crate::input`) arrivent à part, dans l'ordre
//! (les messages matériels, `QS_KEY`) : elles sortent après les messages
//! postés et WM_QUIT, avant WM_PAINT. Une touche qui sort de la file change
//! l'état du clavier du thread ([`QueueState::keys`],
//! UpdateKeyStateFromMsg), que lisent GetKeyState, GetKeyboardState et
//! TranslateMessage : celui des messages déjà traités, pas celui du
//! clavier. La file garde aussi la fenêtre active du thread, celle qui a
//! le clavier et celle qui a la capture de la souris (`spwndActive`,
//! `spwndFocus`, `spwndCapture`).
//!
//! Les messages envoyés par un autre thread (SendMessage, [`crate::sent`])
//! attendent à part (`QS_SENDMESSAGE`) : PeekMessage, GetMessage et
//! WaitMessage les traitent d'abord, sans jamais les rendre.
//!
//! Les messages de la souris arrivent bruts, avec les touches : à leur
//! sortie, le thread en fait les messages finals (`crate::mouse::finish` :
//! WM_NCHITTEST, l'activation, le double-clic). Un filtre les demande sous
//! leur forme de la zone cliente, du cadre ou du double-clic.
//!
//! Pas encore : les crochets, le filtre par fenêtre fille des messages
//! postés (seule la fenêtre nommée), la position du curseur des messages
//! postés (`pt` est nul).

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use abi::ntstatus::NtStatus;
use abi::user::vk::{
    VK_CONTROL, VK_LCONTROL, VK_LMENU, VK_LSHIFT, VK_MENU, VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_SHIFT,
};
use abi::user::{
    Msg32, POINTER_MESSAGES, QS_ALLPOSTMESSAGE, QS_KEY, QS_MOUSEBUTTON, QS_MOUSEMOVE, QS_PAINT, QS_POSTMESSAGE,
    QS_SENDMESSAGE, QS_TIMER, WM_DEVICECHANGE, WM_KEYDOWN, WM_KEYFIRST, WM_KEYLAST, WM_KEYUP, WM_LBUTTONDBLCLK,
    WM_LBUTTONDOWN, WM_MBUTTONDBLCLK, WM_MOUSEMOVE, WM_NCMOUSEMOVE, WM_NC_MOUSE_OFFSET, WM_QUIT, WM_SYSKEYDOWN,
    WM_SYSKEYUP,
};

/// The wake bit of a hardware message: QS_KEY for the keyboard's,
/// QS_MOUSEMOVE for a move, QS_MOUSEBUTTON for the rest of the mouse's.
pub fn input_bit(message: &Msg32) -> u16 {
    match message.message {
        WM_KEYFIRST..=WM_KEYLAST => QS_KEY,
        WM_MOUSEMOVE | WM_NCMOUSEMOVE => QS_MOUSEMOVE,
        _ => QS_MOUSEBUTTON,
    }
}
use ex::{Event, EventType};
use hal::sync::KSpinLock;
use ob::Object;

use crate::gui::ThreadInfo;
use crate::kbdtables::{is_down, KeyState, DOWN, LOCKED};

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

    /// Le message brut de la souris `raw` (WM_MOUSEMOVE, ou l'appui ou le
    /// relâchement d'un bouton, pour la zone cliente) est l'un de ceux
    /// qu'il demande sous l'une des formes qu'il prendra : celle de la zone
    /// cliente, celle du cadre (WM_NC*), le double-clic.
    pub fn matches_mouse(&self, raw: &Msg32) -> bool {
        let forms = [
            raw.message,
            raw.message - WM_NC_MOUSE_OFFSET,
            raw.message + (WM_LBUTTONDBLCLK - WM_LBUTTONDOWN),
            raw.message + (WM_LBUTTONDBLCLK - WM_LBUTTONDOWN) - WM_NC_MOUSE_OFFSET,
        ];
        let is_down = raw.message != WM_MOUSEMOVE && (raw.message - WM_LBUTTONDOWN).is_multiple_of(3);
        let count = if is_down { 4 } else { 2 };
        forms[..count].iter().any(|&message| self.matches(&Msg32 { message, ..*raw }))
    }
}

/// Un message brut de la souris, tel que le thread d'entrée le poste :
/// WM_MOUSEMOVE ou un bouton (pas la molette, déjà finale).
fn is_raw_mouse(message: &Msg32) -> bool {
    (WM_MOUSEMOVE..WM_MBUTTONDBLCLK).contains(&message.message)
}

/// Ce que tient une file.
#[derive(Debug)]
pub struct QueueState {
    posted: VecDeque<Msg32>,
    /// Les touches du clavier, dans l'ordre (`HardwareMessagesListHead`).
    input: VecDeque<Msg32>,
    /// Les messages envoyés par d'autres threads, dans l'ordre
    /// (`SentMessagesListHead`).
    sent: VecDeque<Arc<crate::sent::SentMessage>>,
    /// L'état du clavier vu du thread (`afKeyState`).
    pub keys: KeyState,
    /// La fenêtre active du thread et celle qui a le clavier (0 : aucune).
    pub active: u32,
    pub focus: u32,
    /// La fenêtre du thread qui a la capture de la souris (0 : aucune ;
    /// `crate::mouse::set_capture`).
    pub capture: u32,
    /// WM_QUIT demandé, avec son code de sortie.
    quit: Option<u32>,
    /// `cPaintsReady` : les fenêtres du thread qui ont à se peindre.
    paints: u32,
    /// QS_* : ce qu'il y a dans la file (fsWakeBits), et ce qui y est
    /// arrivé depuis la dernière fois qu'on a regardé (fsChangeBits).
    pub wake: u16,
    pub change: u16,
}

impl Default for QueueState {
    fn default() -> Self {
        Self {
            posted: VecDeque::new(),
            input: VecDeque::new(),
            sent: VecDeque::new(),
            keys: [0; 256],
            active: 0,
            focus: 0,
            capture: 0,
            quit: None,
            paints: 0,
            wake: 0,
            change: 0,
        }
    }
}

/// UpdateKeyState : `vk` enfoncée ou relâchée dans `keys` ; une touche qui
/// s'enfonce se bascule.
fn update_key(keys: &mut KeyState, vk: u8, down: bool) {
    let key = &mut keys[usize::from(vk)];
    if down {
        if *key & DOWN == 0 {
            *key ^= LOCKED;
        }
        *key |= DOWN;
    } else {
        *key &= !DOWN;
    }
}

/// UpdateKeyStateFromMsg : l'état `keys` après la touche de `message` ;
/// une touche gauche ou droite change aussi la touche commune.
pub fn update_keys_from_message(keys: &mut KeyState, message: &Msg32) {
    let down = match message.message {
        WM_KEYDOWN | WM_SYSKEYDOWN => true,
        WM_KEYUP | WM_SYSKEYUP => false,
        _ => return,
    };
    let vk = message.w_param as u8;
    update_key(keys, vk, down);
    let common = match vk {
        VK_LCONTROL | VK_RCONTROL => Some((VK_CONTROL, VK_LCONTROL, VK_RCONTROL)),
        VK_LMENU | VK_RMENU => Some((VK_MENU, VK_LMENU, VK_RMENU)),
        VK_LSHIFT | VK_RSHIFT => Some((VK_SHIFT, VK_LSHIFT, VK_RSHIFT)),
        _ => None,
    };
    if let Some((common, left, right)) = common {
        let down = is_down(keys, left) || is_down(keys, right);
        update_key(keys, common, down);
    }
}

impl QueueState {
    /// Les bits de ce qui est posté, et des touches, s'il y a quelque
    /// chose.
    fn refresh(&mut self) {
        let posted = QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
        if self.posted.is_empty() && self.quit.is_none() {
            self.wake &= !posted;
        } else {
            self.wake |= posted;
        }
        let input = QS_KEY | QS_MOUSEMOVE | QS_MOUSEBUTTON;
        self.wake = (self.wake & !input) | self.input.iter().fold(0, |bits, message| bits | input_bit(message));
        if self.sent.is_empty() {
            self.wake &= !QS_SENDMESSAGE;
        } else {
            self.wake |= QS_SENDMESSAGE;
        }
    }

    /// Un message envoyé par un autre thread, après les autres
    /// (`QS_SENDMESSAGE`).
    pub fn push_sent(&mut self, sent: Arc<crate::sent::SentMessage>) {
        self.sent.push_back(sent);
        self.change |= QS_SENDMESSAGE;
        self.refresh();
    }

    /// Le premier message envoyé, sorti de la file.
    pub fn pop_sent(&mut self) -> Option<Arc<crate::sent::SentMessage>> {
        let sent = self.sent.pop_front();
        self.refresh();
        sent
    }

    /// Retire `sent`, que son envoyeur n'attend plus ; rend s'il y était
    /// encore.
    pub fn remove_sent(&mut self, sent: &Arc<crate::sent::SentMessage>) -> bool {
        let before = self.sent.len();
        self.sent.retain(|queued| !Arc::ptr_eq(queued, sent));
        self.refresh();
        self.sent.len() != before
    }

    /// MsqPostMessage d'un message matériel : `message` à la fin des
    /// messages du clavier et de la souris (`QS_KEY`, `QS_MOUSEMOVE`,
    /// `QS_MOUSEBUTTON`). Un mouvement qui en suit un autre pour la même
    /// fenêtre le remplace (co_MsqInsertMouseMessage) : seule compte la
    /// dernière place.
    pub fn post_input(&mut self, message: Msg32) {
        let bit = input_bit(&message);
        match self.input.back_mut() {
            Some(last) if bit == QS_MOUSEMOVE && last.message == message.message && last.hwnd == message.hwnd => {
                *last = message;
            }
            _ => self.input.push_back(message),
        }
        self.change |= bit;
        self.refresh();
    }

    /// MsqPostMessage : `message` à la fin de la file.
    pub fn post(&mut self, message: Msg32) {
        self.posted.push_back(message);
        self.change |= QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
        self.refresh();
    }

    /// MsqIncPaintCountQueue : une fenêtre de plus a à se peindre
    /// (`QS_PAINT`).
    pub fn inc_paint(&mut self) {
        self.paints += 1;
        self.wake |= QS_PAINT;
        self.change |= QS_PAINT;
    }

    /// MsqDecPaintCountQueue : une de moins ; `QS_PAINT` s'éteint avec la
    /// dernière.
    pub fn dec_paint(&mut self) {
        if self.paints == 0 {
            return;
        }
        self.paints -= 1;
        if self.paints == 0 {
            self.wake &= !QS_PAINT;
            self.change &= !QS_PAINT;
        }
    }

    /// Plus aucune fenêtre n'a à se peindre (IntGetPaintMessage, quand le
    /// compte ne trouve aucune fenêtre : une fenêtre cachée ou détruite avec
    /// sa région à mettre à jour).
    pub fn clear_paints(&mut self) {
        self.paints = 0;
        self.wake &= !QS_PAINT;
        self.change &= !QS_PAINT;
    }

    /// `cPaintsReady`.
    pub fn paints(&self) -> u32 {
        self.paints
    }

    /// Une minuterie du thread est prête (`QS_TIMER`, et son bit de
    /// changement), ou plus aucune (`crate::timer`).
    pub fn set_timers_ready(&mut self, ready: bool) {
        if ready {
            if self.wake & QS_TIMER == 0 {
                self.change |= QS_TIMER;
            }
            self.wake |= QS_TIMER;
        } else {
            self.wake &= !QS_TIMER;
            self.change &= !QS_TIMER;
        }
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
    /// qu'aucun message posté ne reste ; sinon la première touche demandée
    /// (co_MsqPeekHardwareMessage), dont l'état du clavier du thread prend
    /// compte. Les bits de changement des messages postés et des touches
    /// sont effacés : on a regardé.
    pub fn peek(&mut self, filter: &Filter, remove: bool) -> Option<Msg32> {
        self.change &= !(QS_POSTMESSAGE | QS_ALLPOSTMESSAGE | QS_KEY | QS_MOUSEMOVE | QS_MOUSEBUTTON | QS_TIMER);
        let found = match self.posted.iter().position(|message| filter.matches(message)) {
            Some(index) if remove => self.posted.remove(index),
            Some(index) => Some(self.posted[index]),
            None if self.posted.is_empty() && self.quit.is_some() => self.quit.map(|code| {
                if remove {
                    self.quit = None;
                }
                Msg32 { message: WM_QUIT, w_param: code, ..Msg32::default() }
            }),
            None => self.peek_input(filter, remove),
        };
        self.refresh();
        found
    }

    /// La première touche que demande `filter`, sortie si `remove` ; l'état
    /// du clavier du thread en prend compte, puis la touche gauche ou droite
    /// du message devient la touche commune (co_IntProcessKeyboardMessage).
    fn peek_input(&mut self, filter: &Filter, remove: bool) -> Option<Msg32> {
        let index = self.input.iter().position(|message| {
            if is_raw_mouse(message) {
                filter.matches_mouse(message)
            } else {
                filter.matches(message)
            }
        })?;
        let mut message = if remove { self.input.remove(index)? } else { self.input[index] };
        // Only a key: a mouse message's `wParam` is MK_* (and the wheel's
        // amount), not a virtual key.
        if input_bit(&message) == QS_KEY {
            update_keys_from_message(&mut self.keys, &message);
            message.w_param = u32::from(crate::input::simplify_vk(message.w_param as u8));
        }
        Some(message)
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

/// La touche `message` pour `thread` (`QS_KEY`), qui est réveillé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn post_input(thread: &ThreadInfo, message: Msg32) {
    let ((), wake, change) = thread.queue.with(|queue| queue.post_input(message));
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
/// `filter`, sorti si `remove` ; sinon WM_PAINT pour une de ses fenêtres
/// qui a à se peindre, s'il en a (il ne sort pas : il revient tant que la
/// fenêtre n'est pas peinte) ; sinon WM_TIMER pour une de ses minuteries
/// prêtes, qui ne l'est plus si `remove`. Un message brut de la souris en
/// sort final (`crate::mouse::finish`) ; mangé, le suivant est cherché.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread, sans rien tenir (des rappels).
pub fn peek(thread: &ThreadInfo, filter: &Filter, remove: bool) -> Option<Msg32> {
    // The messages other threads sent come first, and never out.
    crate::sent::dispatch_all(thread);
    loop {
        let ((found, paints, timers), wake, change) =
            thread.queue.with(|queue| (queue.peek(filter, remove), queue.paints(), queue.wake & QS_TIMER != 0));
        thread.mirror_queue_bits(wake, change);
        match found {
            Some(raw) if is_raw_mouse(&raw) => match crate::mouse::finish(thread, raw, remove) {
                Some(message) => return Some(message),
                // Eaten (MA_*ANDEAT) or its window gone: out of the queue,
                // look for the next one. Peeked only, it stays: give it raw.
                None if remove => continue,
                None => return Some(raw),
            },
            Some(message) => return Some(message),
            None => {}
        }
        if paints != 0 {
            if let Some(paint) = crate::paint::paint_message(thread, filter) {
                return Some(paint);
            }
        }
        if timers {
            return crate::timer::message(thread, filter, remove);
        }
        return None;
    }
}

/// MsqIncPaintCountQueue pour `thread`, qui est réveillé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn inc_paint(thread: &ThreadInfo) {
    let ((), wake, change) = thread.queue.with(QueueState::inc_paint);
    thread.mirror_queue_bits(wake, change);
    thread.queue.wake();
}

/// MsqDecPaintCountQueue pour `thread`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn dec_paint(thread: &ThreadInfo) {
    let ((), wake, change) = thread.queue.with(QueueState::dec_paint);
    thread.mirror_queue_bits(wake, change);
}

/// Le compte de `thread` sans fenêtre à peindre : remis à zéro.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn clear_paints(thread: &ThreadInfo) {
    let ((), wake, change) = thread.queue.with(QueueState::clear_paints);
    thread.mirror_queue_bits(wake, change);
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
/// `thread`, s'il n'y en a pas (ni message posté, ni entrée, ni fenêtre à
/// peindre, ni minuterie prête) ; les messages envoyés par d'autres threads
/// sont traités, avant et pendant l'attente, sans la finir.
///
/// # Errors
/// Le statut d'une attente qui finit autrement.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
pub fn wait_message(thread: &ThreadInfo) -> Result<(), NtStatus> {
    let waking = QS_POSTMESSAGE | QS_KEY | QS_MOUSEMOVE | QS_MOUSEBUTTON | QS_PAINT | QS_TIMER;
    loop {
        // A message sent while the thread waits is handled here, and the
        // wait goes on: its sender may need it to post what ends the wait.
        crate::sent::dispatch_all(thread);
        let ((), wake, _) = thread.queue.with(|_| ());
        if wake & waking != 0 {
            return Ok(());
        }
        wait(thread)?;
    }
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
    fn keys_come_after_posted_messages_and_change_the_thread_s_keys() {
        let mut queue = QueueState::default();
        let all = Filter { hwnd: 0, min: 0, max: 0 };
        queue.post_input(message(7, WM_KEYDOWN, u32::from(VK_LSHIFT)));
        queue.post_input(message(7, WM_KEYDOWN, u32::from(b'A')));
        queue.post(message(7, 0x0400, 1));
        assert_eq!(queue.wake & (QS_KEY | QS_POSTMESSAGE), QS_KEY | QS_POSTMESSAGE);
        assert_eq!(queue.peek(&all, true).map(|m| m.message), Some(0x0400), "posted first");
        assert!(!is_down(&queue.keys, VK_SHIFT), "no key out yet");
        let peeked = queue.peek(&all, false).unwrap();
        assert_eq!((peeked.message, peeked.w_param), (WM_KEYDOWN, u32::from(VK_SHIFT)), "the common key");
        assert!(is_down(&queue.keys, VK_LSHIFT) && is_down(&queue.keys, VK_SHIFT), "the common key too");
        queue.peek(&all, true);
        let only_window_8 = Filter { hwnd: 8, min: 0, max: 0 };
        assert_eq!(queue.peek(&only_window_8, true), None, "the filter applies");
        assert_eq!(queue.peek(&all, true).map(|m| m.w_param), Some(u32::from(b'A')));
        assert_eq!(queue.wake & QS_KEY, 0, "no key left");
        queue.post_input(message(7, WM_KEYUP, u32::from(VK_LSHIFT)));
        queue.post_quit(0);
        assert_eq!(queue.peek(&all, true).map(|m| m.message), Some(WM_QUIT), "WM_QUIT before the keys");
        queue.peek(&all, true);
        assert!(!is_down(&queue.keys, VK_SHIFT) && is_locked_key(&queue.keys, VK_LSHIFT), "up, toggled once");
    }

    fn is_locked_key(keys: &KeyState, vk: u8) -> bool {
        crate::kbdtables::is_locked(keys, vk)
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
    fn qs_paint_lasts_while_windows_have_to_paint() {
        let mut queue = QueueState::default();
        queue.inc_paint();
        queue.inc_paint();
        assert_eq!((queue.paints(), queue.wake & QS_PAINT, queue.change & QS_PAINT), (2, QS_PAINT, QS_PAINT));
        assert_eq!(queue.status(QS_PAINT), 0x0020_0020, "changed and present");
        queue.dec_paint();
        assert_eq!((queue.paints(), queue.wake & QS_PAINT), (1, QS_PAINT), "one window left");
        queue.dec_paint();
        assert_eq!((queue.paints(), queue.wake & QS_PAINT), (0, 0));
        queue.dec_paint();
        assert_eq!(queue.paints(), 0, "never below zero");
        queue.inc_paint();
        queue.clear_paints();
        assert_eq!((queue.paints(), queue.status(QS_PAINT)), (0, 0));
    }

    #[test]
    fn qs_timer_follows_the_ready_timers_and_is_looked_at_by_peek() {
        let mut queue = QueueState::default();
        queue.set_timers_ready(true);
        assert_eq!(queue.status(QS_TIMER), 0x0010_0010, "changed and present");
        queue.set_timers_ready(true);
        assert_eq!(queue.status(QS_TIMER), 0x0010_0000, "no new change while still ready");
        queue.set_timers_ready(false);
        queue.set_timers_ready(true);
        let all = Filter { hwnd: 0, min: 0, max: 0 };
        assert_eq!(queue.peek(&all, true), None, "WM_TIMER comes from crate::timer");
        assert_eq!((queue.wake & QS_TIMER, queue.change & QS_TIMER), (QS_TIMER, 0), "looked at");
        queue.post(message(0, 0x401, 1));
        queue.peek(&all, true);
        assert_eq!(queue.wake & QS_TIMER, QS_TIMER, "posted messages leave it");
        queue.set_timers_ready(false);
        assert_eq!(queue.status(QS_TIMER), 0);
    }

    #[test]
    fn sent_messages_wait_apart_in_order_and_can_be_withdrawn() {
        let mut queue = QueueState::default();
        let first = crate::sent::SentMessage::new(0x20, 0x400, 1, 0, false);
        let second = crate::sent::SentMessage::new(0x20, 0x401, 2, 0, false);
        queue.push_sent(first.clone());
        queue.push_sent(second.clone());
        assert_eq!(queue.status(QS_SENDMESSAGE), 0x0040_0040, "changed and present");
        let all = Filter { hwnd: 0, min: 0, max: 0 };
        assert_eq!(queue.peek(&all, true), None, "never a message GetMessage returns");
        assert!(queue.remove_sent(&first), "its sender gave up");
        assert!(!queue.remove_sent(&first), "once");
        assert_eq!(queue.pop_sent().map(|sent| sent.wparam), Some(2));
        assert_eq!(queue.wake & QS_SENDMESSAGE, 0, "none left");
        assert!(queue.pop_sent().is_none());
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
