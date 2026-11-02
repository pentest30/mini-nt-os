//! Les services des événements d'Ex (`ex::event`) et des événements à clé
//! (`ex::keyed_event`).

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use alloc::sync::Arc;
use ex::{Event, EventType, EVENT_MODIFY_STATE, EVENT_QUERY_STATE, EVENT_TYPE};
use ke::usermem::UserPtr;
use ob::{AccessMask, Handle, Object};

/// Les classes de NtQueryEvent demandées sans être implémentées.
static UNSUPPORTED_EVENT_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryEvent");

/// EventBasicInformation.
const EVENT_BASIC_INFORMATION: u32 = 0;

fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// L'événement que désigne `handle` dans le processus courant, avec les
/// droits `access`.
fn reference_event(handle: u32, access: AccessMask) -> Result<Arc<Object<Event>>, NtStatus> {
    super::current_process().handle_table.reference_as::<Event>(Handle(handle), &EVENT_TYPE, access)
}

/// Écrit `state` en `previous`, s'il n'est pas nul.
fn give_previous_state(previous: u32, state: i32) -> Result<NtStatus, NtStatus> {
    if previous != 0 {
        UserPtr::<i32>::new(previous).write(&state)?;
    }
    Ok(STATUS_SUCCESS)
}

/// NtCreateEvent(*EventHandle, DesiredAccess, ObjectAttributes, EventType,
/// InitialState) : un événement neuf, de notification ou de synchronisation,
/// signalé ou non, nommé (ou non) d'après les attributs, qui peuvent manquer.
/// `STATUS_INVALID_PARAMETER` pour une autre sorte d'événement.
pub(super) fn nt_create_event(arguments: &[u32]) -> NtStatus {
    let Some(kind) = EventType::from_u32(arguments[3]) else { return STATUS_INVALID_PARAMETER };
    // A BOOLEAN, in the low byte of its argument.
    let event = Event::create(kind, arguments[4] as u8 != 0);
    status(super::object::create_named(arguments[0], arguments[1], arguments[2], event))
}

/// NtOpenEvent(*EventHandle, DesiredAccess, ObjectAttributes) : un handle sur
/// l'événement que désignent les attributs.
pub(super) fn nt_open_event(arguments: &[u32]) -> NtStatus {
    status(super::object::open_by_name(arguments[0], arguments[1], arguments[2], &EVENT_TYPE).map(|()| STATUS_SUCCESS))
}

/// NtSetEvent(EventHandle, *PreviousState) : signale l'événement
/// (`EVENT_MODIFY_STATE`) ; rend l'état d'avant si on le demande.
pub(super) fn nt_set_event(arguments: &[u32]) -> NtStatus {
    status(
        reference_event(arguments[0], EVENT_MODIFY_STATE)
            .and_then(|event| give_previous_state(arguments[1], event.set())),
    )
}

/// NtResetEvent(EventHandle, *PreviousState) : remet l'événement à zéro
/// (`EVENT_MODIFY_STATE`) ; rend l'état d'avant si on le demande.
pub(super) fn nt_reset_event(arguments: &[u32]) -> NtStatus {
    status(
        reference_event(arguments[0], EVENT_MODIFY_STATE)
            .and_then(|event| give_previous_state(arguments[1], event.reset())),
    )
}

/// NtClearEvent(EventHandle) : remet l'événement à zéro
/// (`EVENT_MODIFY_STATE`).
pub(super) fn nt_clear_event(arguments: &[u32]) -> NtStatus {
    status(reference_event(arguments[0], EVENT_MODIFY_STATE).map(|event| {
        event.reset();
        STATUS_SUCCESS
    }))
}

/// NtPulseEvent(EventHandle, *PreviousState) : libère ceux qui attendent
/// l'événement, puis le remet à zéro (`EVENT_MODIFY_STATE`) ; rend l'état
/// d'avant si on le demande.
pub(super) fn nt_pulse_event(arguments: &[u32]) -> NtStatus {
    status(
        reference_event(arguments[0], EVENT_MODIFY_STATE)
            .and_then(|event| give_previous_state(arguments[1], event.pulse())),
    )
}

/// NtQueryEvent(EventHandle, EventInformationClass, EventInformation,
/// EventInformationLength, ReturnLength) : `EventBasicInformation`, la sorte
/// et l'état de l'événement (`EVENT_QUERY_STATE`). Les autres classes rendent
/// `STATUS_NOT_IMPLEMENTED`, journalisé à leur premier appel.
pub(super) fn nt_query_event(arguments: &[u32]) -> NtStatus {
    if arguments[1] != EVENT_BASIC_INFORMATION {
        return UNSUPPORTED_EVENT_CLASSES.report(arguments[1]);
    }
    match reference_event(arguments[0], EVENT_QUERY_STATE) {
        Ok(event) => {
            let mut information = [0u8; 8];
            information[..4].copy_from_slice(&(event.kind() as u32).to_le_bytes());
            information[4..].copy_from_slice(&event.state().to_le_bytes());
            super::return_information(&information, arguments[2], arguments[3], arguments[4])
        }
        Err(status) => status,
    }
}

/// NtCreateKeyedEvent(*KeyedEventHandle, DesiredAccess, ObjectAttributes,
/// Flags) : un événement à clé neuf, nommé (ou non) d'après les attributs,
/// qui peuvent manquer. `STATUS_INVALID_PARAMETER` pour des drapeaux non nuls.
pub(super) fn nt_create_keyed_event(arguments: &[u32]) -> NtStatus {
    if arguments[3] != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    status(super::object::create_named(arguments[0], arguments[1], arguments[2], ex::KeyedEvent::create()))
}

/// NtOpenKeyedEvent(*KeyedEventHandle, DesiredAccess, ObjectAttributes) : un
/// handle sur l'événement à clé que désignent les attributs.
pub(super) fn nt_open_keyed_event(arguments: &[u32]) -> NtStatus {
    status(
        super::object::open_by_name(arguments[0], arguments[1], arguments[2], &ex::KEYED_EVENT_TYPE)
            .map(|()| STATUS_SUCCESS),
    )
}

/// NtWaitForKeyedEvent et NtReleaseKeyedEvent(KeyedEventHandle, Key,
/// Alertable, Timeout) : le rendez-vous sur la clé (`ex::KeyedEvent::meet`)
/// avec un thread du même processus qui fait l'inverse ; un handle nul
/// désigne l'événement de `\KernelObjects\CritSecOutOfMemoryEvent`.
fn meet(arguments: &[u32], releasing: bool) -> NtStatus {
    let (handle, key, timeout) = (arguments[0], arguments[1], arguments[3]);
    // A BOOLEAN, in the low byte of its argument.
    let alertable = arguments[2] as u8 != 0;
    let meet = || {
        if key & 1 != 0 {
            return Err(abi::ntstatus::STATUS_INVALID_PARAMETER_1);
        }
        let timeout = match timeout {
            0 => None,
            at => Some(UserPtr::<i64>::new(at).read()?),
        };
        let event = match handle {
            0 => ex::keyed_event::global(),
            _ => {
                let access = if releasing { ex::KEYEDEVENT_WAKE } else { ex::KEYEDEVENT_WAIT };
                super::current_process().handle_table.reference_as::<ex::KeyedEvent>(
                    Handle(handle),
                    &ex::KEYED_EVENT_TYPE,
                    access,
                )?
            }
        };
        Ok(event.meet(super::current_process().pid(), key, releasing, alertable, timeout))
    };
    status(meet())
}

/// NtWaitForKeyedEvent(KeyedEventHandle, Key, Alertable, Timeout) :
/// `KEYEDEVENT_WAIT` ; voir [`meet`].
pub(super) fn nt_wait_for_keyed_event(arguments: &[u32]) -> NtStatus {
    meet(arguments, false)
}

/// NtReleaseKeyedEvent(KeyedEventHandle, Key, Alertable, Timeout) :
/// `KEYEDEVENT_WAKE` ; voir [`meet`].
pub(super) fn nt_release_keyed_event(arguments: &[u32]) -> NtStatus {
    meet(arguments, true)
}
