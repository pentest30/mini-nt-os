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
//! pas encore traduit (refusé, journalisé une fois).
//!
//! Le destinataire peut finir sans répondre (pas de rappel de Ps à la fin
//! d'un thread GUI) : l'envoyeur regarde toutes les [`SLICE_MS`] ms s'il vit
//! encore, et l'envoi échoue sinon. SendMessageTimeout borne l'attente ;
//! SendNotifyMessage n'attend pas ([`notify`]).
//!
//! Pas encore : InSendMessage(Ex), ReplyMessage, SendMessageCallback,
//! SMTO_ABORTIFHUNG et SMTO_BLOCK, les crochets (WH_CALLWNDPROC), la
//! diffusion (HWND_BROADCAST).

use alloc::sync::Arc;
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
            done: waited.then(|| Event::create(EventType::NotificationEvent, false)),
        })
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
    /// L'attente de l'envoyeur s'est finie autrement (sa fin).
    Wait(NtStatus),
}

impl SendError {
    /// Le statut d'un envoi du noyau sans réponse.
    pub fn status(self) -> NtStatus {
        match self {
            Self::Timeout => abi::ntstatus::STATUS_IO_TIMEOUT,
            Self::Gone => abi::ntstatus::STATUS_INVALID_HANDLE,
            Self::Unmarshalled => abi::ntstatus::STATUS_NOT_IMPLEMENTED,
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
    notify(current, &target, window.handle, message, wparam, lparam)
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
    let sent = SentMessage::new(hwnd, message, wparam, lparam, true);
    let done = sent.done.clone().expect("a waited message has its event");
    queue_to(target, sent.clone());
    let deadline = timeout_ms.map(|ms| hal::timer::interrupt_time() + u64::from(ms) * MILLISECOND);
    loop {
        if let Some(result) = sent.reply() {
            return Ok(result);
        }
        let now = hal::timer::interrupt_time();
        let slice = u64::from(SLICE_MS) * MILLISECOND;
        let wait = deadline.map_or(slice, |deadline| deadline.saturating_sub(now).clamp(1, slice));
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
            STATUS_WAIT_0 => {}
            status if status == NtStatus::wait(1) => {
                dispatch_all(current);
            }
            STATUS_TIMEOUT => {
                if sent.reply().is_some() {
                    continue;
                }
                if deadline.is_some_and(|deadline| hal::timer::interrupt_time() >= deadline) {
                    withdraw(target, &sent);
                    return Err(SendError::Timeout);
                }
                if !crate::gui::thread_alive(target) {
                    withdraw(target, &sent);
                    return Err(SendError::Gone);
                }
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
/// [`SendError::Unmarshalled`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn notify(
    current: &ThreadInfo,
    target: &Arc<ThreadInfo>,
    hwnd: u32,
    message: u32,
    wparam: u32,
    lparam: u32,
) -> Result<(), SendError> {
    if unmarshalled(current, target, message, wparam) {
        return Err(SendError::Unmarshalled);
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
        Some(window) if window.pti == thread.server => {
            crate::window::send_message(&window, sent.message, sent.wparam, LParam::Value(sent.lparam)).unwrap_or(0)
        }
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
