//! Les messages envoyés à la fenêtre d'un autre thread (02 §7.2 ;
//! co_MsqSendMessage et co_MsqDispatchOneSentMessage de `msgqueue.c` de
//! ReactOS, comme spécification).
//!
//! SendMessage vers une fenêtre d'un autre thread met le message parmi les
//! messages envoyés de la file de ce thread (`QS_SENDMESSAGE`) et le
//! réveille ; l'envoyeur attend la réponse ([`send`]). Le destinataire
//! traite ses messages envoyés, dans l'ordre ([`dispatch_all`]) : au début de
//! chaque PeekMessage et GetMessage, dans WaitMessage, et pendant qu'il
//! attend lui-même une réponse, si bien que deux threads qui s'envoient des
//! messages l'un à l'autre ne se bloquent pas. La procédure de la fenêtre
//! est appelée dans le thread qui la possède, et sa valeur revient à
//! l'envoyeur. GetMessage ne rend jamais un message envoyé : il le traite et
//! attend la suite.
//!
//! Dans un même processus, `lParam` passe tel quel (ses pointeurs y restent
//! valides) ; vers un autre processus, un message qui porte un pointeur n'est
//! pas encore traduit (refusé, journalisé une fois). Un message de win32k
//! dont `lParam` est un tampon du noyau (WM_WINDOWPOSCHANGING et son
//! WINDOWPOS, WM_NCCALCSIZE…) emporte une copie du tampon
//! ([`send_buffer`]) : le thread destinataire l'emballe vers son mode
//! utilisateur comme pour un envoi à lui-même, et l'envoyeur reprend à la
//! réponse ce que la procédure y a écrit.
//!
//! Le destinataire peut finir sans répondre (pas de rappel de Ps à la fin
//! d'un thread GUI) : l'envoyeur regarde toutes les [`SLICE_MS`] ms s'il vit
//! encore, quoi qui le réveille entre-temps, et l'envoi échoue sinon.
//! SendMessageTimeout borne l'attente ; SendNotifyMessage n'attend pas
//! ([`notify`]) : un message qui porte un pointeur lui est refusé
//! (`ERROR_MESSAGE_SYNC_ONLY`), l'envoyeur pouvant rendre sa mémoire avant
//! que le destinataire la lise.
//!
//! Pas encore : InSendMessage(Ex), ReplyMessage, SendMessageCallback,
//! SMTO_ABORTIFHUNG et SMTO_BLOCK, les crochets (WH_CALLWNDPROC), la
//! diffusion (HWND_BROADCAST).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::ntstatus::{NtStatus, STATUS_TIMEOUT, STATUS_WAIT_0};
use ex::{Event, EventType};
use hal::sync::KSpinLock;
use ob::Object;

use crate::gui::ThreadInfo;
use crate::window::LParam;

/// L'envoyeur regarde, à ce rythme, si le destinataire vit encore.
pub const SLICE_MS: u32 = 250;

/// Une milliseconde en unités du temps d'interruption (100 ns).
const MILLISECOND: u64 = 10_000;

/// Un message envoyé (`USER_SENT_MESSAGE`).
pub struct SentMessage {
    pub hwnd: u32,
    pub message: u32,
    pub wparam: u32,
    pub lparam: u32,
    /// La valeur de la procédure, une fois revenue.
    reply: KSpinLock<Option<u32>>,
    /// Le tampon du noyau que désigne `lParam`, copié, et si la procédure
    /// y écrit ; le destinataire le prend le temps de la procédure.
    buffer: KSpinLock<Option<(Vec<u8>, bool)>>,
    /// Signalé à la réponse ; `None` pour SendNotifyMessage, que personne
    /// n'attend.
    done: Option<Arc<Object<Event>>>,
}

impl SentMessage {
    /// Le message `message` pour la fenêtre `hwnd` ; `waited` : son
    /// envoyeur en attend la réponse.
    pub fn new(hwnd: u32, message: u32, wparam: u32, lparam: u32, waited: bool) -> Arc<Self> {
        Arc::new(Self {
            hwnd,
            message,
            wparam,
            lparam,
            reply: KSpinLock::new(None),
            buffer: KSpinLock::new(None),
            done: waited.then(|| Event::create(EventType::NotificationEvent, false)),
        })
    }

    /// Le message `message` pour la fenêtre `hwnd`, dont `lParam` est la
    /// copie `bytes` d'un tampon du noyau, où la procédure écrit si
    /// `write_back` ; son envoyeur en attend la réponse.
    pub fn with_buffer(hwnd: u32, message: u32, wparam: u32, bytes: Vec<u8>, write_back: bool) -> Arc<Self> {
        let sent = Self::new(hwnd, message, wparam, 0, true);
        *sent.buffer.lock() = Some((bytes, write_back));
        sent
    }

    /// Prend le tampon, le temps de la procédure.
    fn take_buffer(&self) -> Option<(Vec<u8>, bool)> {
        self.buffer.lock().take()
    }

    /// Rend le tampon, tel que la procédure l'a laissé.
    fn put_back(&self, bytes: Vec<u8>, write_back: bool) {
        *self.buffer.lock() = Some((bytes, write_back));
    }

    /// Recopie dans `bytes` ce que la procédure a écrit dans le tampon, si
    /// elle y écrit (`write_back`) ; rien sinon, ou s'il n'est pas revenu.
    fn copy_back(&self, bytes: &mut [u8]) {
        if let Some((copy, true)) = &*self.buffer.lock() {
            let length = copy.len().min(bytes.len());
            bytes[..length].copy_from_slice(&copy[..length]);
        }
    }

    /// La valeur de la procédure, si elle est revenue.
    pub fn reply(&self) -> Option<u32> {
        *self.reply.lock()
    }

    /// La procédure a rendu `result` : l'envoyeur est réveillé.
    pub fn complete(&self, result: u32) {
        *self.reply.lock() = Some(result);
        if let Some(done) = &self.done {
            done.set();
        }
    }
}

impl core::fmt::Debug for SentMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SentMessage")
            .field("hwnd", &self.hwnd)
            .field("message", &self.message)
            .field("wparam", &self.wparam)
            .field("lparam", &self.lparam)
            .field("reply", &self.reply())
            .finish()
    }
}

/// Pourquoi un envoi n'a pas de réponse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// Le délai de SendMessageTimeout est passé.
    Timeout,
    /// Le thread de la fenêtre est fini.
    Gone,
    /// Le message porte un pointeur vers un autre processus (pas encore).
    Unmarshalled,
    /// SendNotifyMessage d'un message qui porte un pointeur
    /// (`ERROR_MESSAGE_SYNC_ONLY`).
    SyncOnly,
    /// L'attente de l'envoyeur s'est finie autrement (sa fin).
    Wait(NtStatus),
}

impl SendError {
    /// Le statut d'un envoi du noyau sans réponse.
    pub fn status(self) -> NtStatus {
        match self {
            Self::Timeout => abi::ntstatus::STATUS_IO_TIMEOUT,
            Self::Gone => abi::ntstatus::STATUS_INVALID_HANDLE,
            Self::Unmarshalled | Self::SyncOnly => abi::ntstatus::STATUS_NOT_IMPLEMENTED,
            Self::Wait(status) => status,
        }
    }
}

/// SendMessage(Timeout) de `message` à `window`, depuis le thread courant
/// `current` : la procédure appelée directement pour une fenêtre de
/// `current` ou de win32k, par la file de son thread sinon ([`send`]).
///
/// # Errors
/// [`SendError`] ; [`SendError::Wait`] pour un rappel qui échoue.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn send_to_window(
    current: &ThreadInfo,
    window: &Arc<crate::window::Window>,
    message: u32,
    wparam: u32,
    lparam: u32,
    timeout_ms: Option<u32>,
) -> Result<u32, SendError> {
    if window.pti == 0 || window.pti == current.server {
        return crate::window::send_message(window, message, wparam, LParam::Value(lparam)).map_err(SendError::Wait);
    }
    let target = crate::gui::thread_info_of(window.pti).ok_or(SendError::Gone)?;
    send(current, &target, window.handle, message, wparam, lparam, timeout_ms)
}

/// SendNotifyMessage de `message` à `window` : appelée tout de suite pour
/// une fenêtre de `current` ou de win32k, mise dans la file de son thread
/// sans attendre sinon ([`notify`]).
///
/// # Errors
/// [`SendError`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn notify_window(
    current: &ThreadInfo,
    window: &Arc<crate::window::Window>,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> Result<(), SendError> {
    if window.pti == 0 || window.pti == current.server {
        return crate::window::send_message(window, message, wparam, LParam::Value(lparam))
            .map(|_| ())
            .map_err(SendError::Wait);
    }
    let target = crate::gui::thread_info_of(window.pti).ok_or(SendError::Gone)?;
    notify(&target, window.handle, message, wparam, lparam)
}

/// Met `sent` parmi les messages envoyés de `target`, qui est réveillé.
fn queue_to(target: &ThreadInfo, sent: Arc<SentMessage>) {
    let ((), wake, change) = target.queue.with(|queue| queue.push_sent(sent));
    target.mirror_queue_bits(wake, change);
    target.queue.wake();
}

/// Retire `sent` des messages envoyés de `target`, s'il n'en est pas
/// encore sorti.
fn withdraw(target: &ThreadInfo, sent: &Arc<SentMessage>) {
    let (_, wake, change) = target.queue.with(|queue| queue.remove_sent(sent));
    target.mirror_queue_bits(wake, change);
}

/// Le message vers un autre processus que `current` porte un pointeur
/// qu'il faudrait traduire.
fn unmarshalled(current: &ThreadInfo, target: &ThreadInfo, message: u32, wparam: u32) -> bool {
    if !crate::queue::is_pointer_message(message, wparam) {
        return false;
    }
    let process = |thread: &ThreadInfo| crate::gui::process_id_of(thread.server);
    if process(current) == process(target) {
        return false;
    }
    static REPORTED: AtomicBool = AtomicBool::new(false);
    if !REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: message {message:#x} with a pointer sent to another process: not yet");
    }
    true
}

/// co_MsqSendMessage : envoie `message` à la fenêtre `hwnd` du thread
/// `target`, depuis le thread courant `current`, et attend la valeur de sa
/// procédure, au plus `timeout_ms` ms s'il est donné. Pendant l'attente, les
/// messages envoyés à `current` sont traités.
///
/// # Errors
/// [`SendError`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn send(
    current: &ThreadInfo,
    target: &Arc<ThreadInfo>,
    hwnd: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
    timeout_ms: Option<u32>,
) -> Result<u32, SendError> {
    if unmarshalled(current, target, message, wparam) {
        return Err(SendError::Unmarshalled);
    }
    wait_reply(current, target, SentMessage::new(hwnd, message, wparam, lparam, true), timeout_ms)
}

/// co_MsqSendMessage d'un message de win32k dont `lParam` est le tampon du
/// noyau `bytes` : le message emporte sa copie, que le thread `target`
/// emballe vers son mode utilisateur ; à la réponse, ce que la procédure y
/// a écrit revient dans `bytes` (`write_back`). Sans délai.
///
/// # Errors
/// [`SendError`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn send_buffer(
    current: &ThreadInfo,
    target: &Arc<ThreadInfo>,
    hwnd: u32,
    message: u32,
    wparam: u32,
    bytes: &mut [u8],
    write_back: bool,
) -> Result<u32, SendError> {
    let sent = SentMessage::with_buffer(hwnd, message, wparam, bytes.to_vec(), write_back);
    let result = wait_reply(current, target, sent.clone(), None)?;
    sent.copy_back(bytes);
    Ok(result)
}

/// Met `sent` parmi les messages envoyés de `target` et attend sa réponse,
/// au plus `timeout_ms` ms s'il est donné, en traitant les messages envoyés
/// à `current`.
fn wait_reply(
    current: &ThreadInfo,
    target: &Arc<ThreadInfo>,
    sent: Arc<SentMessage>,
    timeout_ms: Option<u32>,
) -> Result<u32, SendError> {
    let done = sent.done.clone().expect("a waited message has its event");
    queue_to(target, sent.clone());
    let slice = u64::from(SLICE_MS) * MILLISECOND;
    let deadline = timeout_ms.map(|ms| hal::timer::interrupt_time() + u64::from(ms) * MILLISECOND);
    // The recipient's liveness is looked at on this schedule, whatever wakes
    // the wait: messages to the sender can wake it more often than a slice.
    let mut next_check = hal::timer::interrupt_time() + slice;
    loop {
        if let Some(result) = sent.reply() {
            return Ok(result);
        }
        let now = hal::timer::interrupt_time();
        if deadline.is_some_and(|deadline| now >= deadline) {
            withdraw(target, &sent);
            return Err(SendError::Timeout);
        }
        if now >= next_check {
            if !crate::gui::thread_alive(target) {
                withdraw(target, &sent);
                return Err(SendError::Gone);
            }
            next_check = now + slice;
        }
        let until = deadline.map_or(next_check, |deadline| deadline.min(next_check));
        let wait = until.saturating_sub(now).max(1);
        let objects = [done.dispatcher_object(), current.queue.event().dispatcher_object()];
        // SAFETY: the current Ps thread, at PASSIVE_LEVEL; `done` and
        // `current`, held here, keep their events for the whole wait.
        let status = unsafe {
            ke::dispatcher::ke_wait_for_multiple_objects::<ke::sched::KePlatform>(
                &objects,
                ke::dispatcher::WaitType::WaitAny,
                ke::dispatcher::ProcessorMode::User,
                false,
                Some(-(wait as i64)),
                None,
            )
        };
        match status {
            // The reply, or a deadline: looked at above.
            STATUS_WAIT_0 | STATUS_TIMEOUT => {}
            status if status == NtStatus::wait(1) => {
                dispatch_all(current);
            }
            other => {
                withdraw(target, &sent);
                return Err(SendError::Wait(other));
            }
        }
    }
}

/// SendNotifyMessage vers la fenêtre `hwnd` du thread `target` : le message
/// est mis parmi ses messages envoyés, sans attendre sa réponse.
///
/// # Errors
/// [`SendError::SyncOnly`] pour un message qui porte un pointeur : rien ne
/// le garde après le retour de l'envoyeur.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn notify(target: &Arc<ThreadInfo>, hwnd: u32, message: u32, wparam: u32, lparam: u32) -> Result<(), SendError> {
    if crate::queue::is_pointer_message(message, wparam) {
        return Err(SendError::SyncOnly);
    }
    queue_to(target, SentMessage::new(hwnd, message, wparam, lparam, false));
    Ok(())
}

/// co_MsqDispatchOneSentMessage : le premier message envoyé au thread
/// courant `thread`, à la procédure de sa fenêtre (0 si elle n'est plus) ;
/// sa valeur réveille l'envoyeur. Rend s'il y en avait un.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread, sans rien tenir. Rappelle le mode
/// utilisateur.
pub fn dispatch_one(thread: &ThreadInfo) -> bool {
    let (sent, wake, change) = thread.queue.with(crate::queue::QueueState::pop_sent);
    thread.mirror_queue_bits(wake, change);
    let Some(sent) = sent else { return false };
    let result = match crate::window::get(sent.hwnd) {
        Some(window) if window.pti == thread.server => match sent.take_buffer() {
            Some((mut bytes, write_back)) => {
                let lparam = LParam::Buffer { bytes: &mut bytes, write_back };
                let result = crate::window::send_message(&window, sent.message, sent.wparam, lparam).unwrap_or(0);
                sent.put_back(bytes, write_back);
                result
            }
            None => {
                crate::window::send_message(&window, sent.message, sent.wparam, LParam::Value(sent.lparam)).unwrap_or(0)
            }
        },
        _ => 0,
    };
    sent.complete(result);
    true
}

/// Traite tous les messages envoyés au thread courant `thread`, y compris
/// ceux qui arrivent pendant qu'on les traite.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread, sans rien tenir.
pub fn dispatch_all(thread: &ThreadInfo) {
    while dispatch_one(thread) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_never_carry_a_pointer() {
        // Codex's review of #84: SendNotifyMessage does not wait, so the
        // sender may free what a pointer designates before it is read.
        let target = Arc::new(ThreadInfo::new(crate::gui::thread_server_address(8), 0));
        let wm_settext = 0x000C;
        assert_eq!(notify(&target, 0x20, wm_settext, 0, 0x0040_1000), Err(SendError::SyncOnly));
        assert!(target.queue.with(crate::queue::QueueState::pop_sent).0.is_none(), "nothing queued");
        assert_eq!(notify(&target, 0x20, 0x0400, 1, 2), Ok(()));
        let sent = target.queue.with(crate::queue::QueueState::pop_sent).0.expect("queued");
        assert_eq!((sent.message, sent.wparam, sent.lparam, sent.reply()), (0x0400, 1, 2, None));
        sent.complete(0);
        assert_eq!(sent.reply(), Some(0), "nobody waits: no event");
    }

    #[test]
    fn a_kernel_buffer_travels_as_a_copy_and_comes_back_when_written() {
        let mut bytes = [1u8, 2, 3, 4];
        let sent = SentMessage::with_buffer(0x20, 0x0046, 0, bytes.to_vec(), true);
        let (mut copy, write_back) = sent.take_buffer().expect("the copy");
        assert!(write_back && sent.take_buffer().is_none(), "taken by the recipient");
        copy[0] = 9; // What the procedure writes.
        sent.put_back(copy, write_back);
        sent.copy_back(&mut bytes);
        assert_eq!(bytes, [9, 2, 3, 4]);
        let mut kept = [1u8, 2];
        let read_only = SentMessage::with_buffer(0x20, 0x0081, 0, alloc::vec![7, 7], false);
        read_only.copy_back(&mut kept);
        assert_eq!(kept, [1, 2], "a buffer the procedure only reads stays");
    }
}
