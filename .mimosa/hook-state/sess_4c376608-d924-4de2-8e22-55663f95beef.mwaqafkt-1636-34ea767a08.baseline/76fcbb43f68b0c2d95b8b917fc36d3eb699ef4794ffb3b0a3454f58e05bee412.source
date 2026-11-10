//! Les sessions (Terminal Services) : MmSessionCreate et MmSessionDelete,
//! comme `smss` les demande (NtSetSystemInformation).
//!
//! Le premier processus qui crée une session en devient le meneur
//! (`smss`) : lui seul en crée ensuite. Il y entre en la créant (son
//! `SessionId` devient le sien, son PEB le dit), et la quitte
//! (SystemSessionDetach) ; un processus qu'il crée entre-temps y naît, comme
//! tout processus naît dans la session de son créateur. Une session reçoit le
//! plus petit identifiant libre : 0 pour la première.
//!
//! Pas encore : l'espace de session de Mm (02 §4.2 : tas de bureau de
//! win32k), le compte des processus d'une session et sa destruction avec le
//! dernier ; un identifiant créé reste pris.

use abi::ntstatus::{
    NtStatus, STATUS_ALREADY_COMMITTED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_SYSTEM_SERVICE,
    STATUS_UNABLE_TO_FREE_VM,
};
use hal::sync::KSpinLock;

use crate::eprocess::{EProcess, ProcessId};

/// Les sessions créées.
pub(crate) struct Sessions {
    /// Un bit par identifiant pris.
    created: u64,
    /// Le meneur : le seul processus qui crée des sessions.
    leader: Option<ProcessId>,
    /// La session où se trouve le meneur, s'il y est entré.
    attached: Option<u32>,
}

impl Sessions {
    pub(crate) const fn new() -> Self {
        Self { created: 0, leader: None, attached: None }
    }

    /// MmSessionCreate : une session neuve pour le processus `pid`, qui y
    /// entre ; rend son identifiant.
    ///
    /// # Errors
    /// `STATUS_INVALID_SYSTEM_SERVICE` pour un autre processus que le
    /// meneur ; `STATUS_ALREADY_COMMITTED` s'il est déjà dans une session ;
    /// `STATUS_INSUFFICIENT_RESOURCES` au-delà de 64 sessions.
    pub(crate) fn create(&mut self, pid: ProcessId) -> Result<u32, NtStatus> {
        if self.leader.is_some_and(|leader| leader != pid) {
            return Err(STATUS_INVALID_SYSTEM_SERVICE);
        }
        if self.attached.is_some() {
            return Err(STATUS_ALREADY_COMMITTED);
        }
        let id = (!self.created).trailing_zeros();
        if id == u64::BITS {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        self.created |= 1 << id;
        self.leader = Some(pid);
        self.attached = Some(id);
        Ok(id)
    }

    /// MmSessionDelete : le processus `pid`, le meneur, quitte sa session.
    /// `STATUS_UNABLE_TO_FREE_VM` s'il n'est pas le meneur ou n'est dans
    /// aucune session.
    pub(crate) fn detach(&mut self, pid: ProcessId) -> Result<(), NtStatus> {
        if self.leader != Some(pid) || self.attached.is_none() {
            return Err(STATUS_UNABLE_TO_FREE_VM);
        }
        self.attached = None;
        Ok(())
    }
}

static SESSIONS: KSpinLock<Sessions> = KSpinLock::new(Sessions::new());

/// SystemSessionCreate : une session neuve, où `process` entre ; rend son
/// identifiant (voir [`Sessions::create`]).
///
/// # IRQL
/// <= APC_LEVEL.
pub fn create_session(process: &EProcess) -> Result<u32, NtStatus> {
    let id = SESSIONS.lock().create(process.pid())?;
    process.set_session_id(id)?;
    Ok(id)
}

/// SystemSessionDetach : `process` quitte la session qu'il a créée (voir
/// [`Sessions::detach`]) ; il garde son identifiant.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn detach_session(process: &EProcess) -> Result<(), NtStatus> {
    SESSIONS.lock().detach(process.pid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_leader_creates_sessions_and_leaves_them() {
        let mut sessions = Sessions::new();
        assert_eq!(sessions.detach(20), Err(STATUS_UNABLE_TO_FREE_VM), "in no session yet");
        assert_eq!(sessions.create(20), Ok(0), "the first is session 0");
        assert_eq!(sessions.create(20), Err(STATUS_ALREADY_COMMITTED), "already in one");
        assert_eq!(sessions.create(24), Err(STATUS_INVALID_SYSTEM_SERVICE), "one leader");
        assert_eq!(sessions.detach(24), Err(STATUS_UNABLE_TO_FREE_VM), "not the leader");
        assert_eq!(sessions.detach(20), Ok(()));
        assert_eq!(sessions.detach(20), Err(STATUS_UNABLE_TO_FREE_VM), "left already");
        assert_eq!(sessions.create(20), Ok(1), "the next free one");
    }

    #[test]
    fn at_most_64_sessions() {
        let mut sessions = Sessions::new();
        for id in 0..64 {
            assert_eq!(sessions.create(20), Ok(id));
            sessions.detach(20).unwrap();
        }
        assert_eq!(sessions.create(20), Err(STATUS_INSUFFICIENT_RESOURCES));
    }
}
