//! Les sessions de logon du moniteur de références (SepLogonSessions) et
//! l'état de l'audit (SeAuditingState) : ce que `lsass` lui dit par son
//! serveur de commandes (`\SeRmCommandPort`, `ntoskrnl::srm`) :
//! RmCreateLogonSession, RmDeleteLogonSession, RmAuditSetCommand.
//!
//! Les sessions de LocalSystem (`SYSTEM_LUID`) et de l'utilisateur anonyme
//! (`ANONYMOUS_LOGON_LUID`) existent dès le démarrage, comme après
//! SeRmInitPhase0 ; des jetons les tiennent pour de bon, elles ne se
//! suppriment pas.
//!
//! La spécification suivie est ReactOS 0.4.16 (`ntoskrnl/se/srm.c`).
//!
//! Pas encore : le compte des jetons de chaque session (la suppression
//! d'une session qu'un jeton tient encore rendrait
//! `STATUS_BAD_LOGON_SESSION_STATE`), son DeviceMap, les notifications de fin
//! de session ; l'audit est gardé, rien ne le lit.

use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_BAD_LOGON_SESSION_STATE, STATUS_LOGON_SESSION_EXISTS, STATUS_NO_SUCH_LOGON_SESSION,
};
use abi::security::{Luid32, ANONYMOUS_LOGON_LUID, AUDIT_EVENT_TYPES, SYSTEM_LUID};
use hal::sync::KSpinLock;

/// L'état de l'audit que `lsass` donne (RmAuditSetCommand).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Audit {
    /// SepAdtAuditingEnabled.
    pub enabled: bool,
    /// Les drapeaux de chaque catégorie (`POLICY_AUDIT_EVENT_*`).
    pub flags: [u8; AUDIT_EVENT_TYPES],
}

/// Les sessions de logon et l'audit.
pub struct LogonSessions {
    /// Les sessions créées par `lsass`, par LUID ; les deux sessions
    /// connues n'y sont pas.
    sessions: KSpinLock<Vec<u64>>,
    audit: KSpinLock<Audit>,
}

/// Une des sessions qui existent dès le démarrage.
fn well_known(luid: Luid32) -> bool {
    luid == SYSTEM_LUID || luid == ANONYMOUS_LOGON_LUID
}

impl LogonSessions {
    /// Seules les deux sessions connues.
    pub const fn new() -> Self {
        Self {
            sessions: KSpinLock::new(Vec::new()),
            audit: KSpinLock::new(Audit { enabled: false, flags: [0; AUDIT_EVENT_TYPES] }),
        }
    }

    /// La session `luid` existe.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn exists(&self, luid: Luid32) -> bool {
        well_known(luid) || self.sessions.lock().contains(&luid.as_u64())
    }

    /// SepRmCreateLogonSession ; `STATUS_LOGON_SESSION_EXISTS` si elle
    /// existe déjà.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(&self, luid: Luid32) -> Result<(), NtStatus> {
        if well_known(luid) {
            return Err(STATUS_LOGON_SESSION_EXISTS);
        }
        let mut sessions = self.sessions.lock();
        if sessions.contains(&luid.as_u64()) {
            return Err(STATUS_LOGON_SESSION_EXISTS);
        }
        sessions.push(luid.as_u64());
        Ok(())
    }

    /// SepRmDeleteLogonSession ; `STATUS_NO_SUCH_LOGON_SESSION` si elle
    /// n'existe pas, `STATUS_BAD_LOGON_SESSION_STATE` pour une des deux
    /// sessions connues, que des jetons tiennent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn delete(&self, luid: Luid32) -> Result<(), NtStatus> {
        if well_known(luid) {
            return Err(STATUS_BAD_LOGON_SESSION_STATE);
        }
        let mut sessions = self.sessions.lock();
        let index = sessions.iter().position(|&id| id == luid.as_u64()).ok_or(STATUS_NO_SUCH_LOGON_SESSION)?;
        sessions.swap_remove(index);
        Ok(())
    }

    /// SepRmSetAuditEvent : l'audit, et l'octet bas des drapeaux de chaque
    /// catégorie.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set_audit(&self, enabled: bool, flags: &[u32; AUDIT_EVENT_TYPES]) {
        *self.audit.lock() = Audit { enabled, flags: flags.map(|flag| flag as u8) };
    }

    /// L'état de l'audit.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn audit(&self) -> Audit {
        *self.audit.lock()
    }
}

impl Default for LogonSessions {
    fn default() -> Self {
        Self::new()
    }
}

/// Les sessions de logon du système.
pub static LOGON_SESSIONS: LogonSessions = LogonSessions::new();

#[cfg(test)]
mod tests {
    use super::*;

    const USER: Luid32 = Luid32 { low_part: 0x1_0000, high_part: 0 };

    #[test]
    fn the_well_known_sessions_exist_and_stay() {
        let sessions = LogonSessions::new();
        assert!(sessions.exists(SYSTEM_LUID) && sessions.exists(ANONYMOUS_LOGON_LUID));
        assert_eq!(sessions.create(SYSTEM_LUID), Err(STATUS_LOGON_SESSION_EXISTS));
        assert_eq!(sessions.delete(ANONYMOUS_LOGON_LUID), Err(STATUS_BAD_LOGON_SESSION_STATE));
    }

    #[test]
    fn a_session_is_created_once_then_deleted_once() {
        let sessions = LogonSessions::new();
        assert!(!sessions.exists(USER));
        assert_eq!(sessions.create(USER), Ok(()));
        assert!(sessions.exists(USER));
        assert_eq!(sessions.create(USER), Err(STATUS_LOGON_SESSION_EXISTS));
        let other = Luid32 { low_part: 0x1_0000, high_part: 1 };
        assert!(!sessions.exists(other), "the high part counts");
        assert_eq!(sessions.delete(USER), Ok(()));
        assert_eq!(sessions.delete(USER), Err(STATUS_NO_SUCH_LOGON_SESSION));
        assert!(!sessions.exists(USER));
    }

    #[test]
    fn the_audit_keeps_the_low_byte_of_each_flag() {
        let sessions = LogonSessions::new();
        assert_eq!(sessions.audit(), Audit::default());
        sessions.set_audit(true, &[0x103, 1, 2, 3, 0, 0, 0, 0, 3]);
        assert_eq!(sessions.audit(), Audit { enabled: true, flags: [3, 1, 2, 3, 0, 0, 0, 0, 3] });
    }
}
