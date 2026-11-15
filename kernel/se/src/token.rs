//! Les jetons (type `Token`) : qui est un processus, à quels groupes il
//! appartient, quels privilèges il a et lesquels sont actifs.
//!
//! Un jeton a son identifiant (une LUID neuve), sa session d'ouverture
//! (`AuthenticationId`), son utilisateur et ses groupes, avec leurs
//! attributs, ses privilèges, son propriétaire et son groupe principal par
//! défaut, sa DACL par défaut, sa source et sa session. Seul l'état de ses
//! privilèges change pour l'instant
//! ([`adjust_privileges`](Token::adjust_privileges)) ; chaque changement lui
//! donne un nouveau `ModifiedId`.
//!
//! Le jeton de System ([`Token::system`], SeMakeSystemToken) : LocalSystem,
//! dans les groupes Administrators (qui porte `SE_GROUP_OWNER` et devient le
//! propriétaire par défaut), Everyone et Authenticated Users ; les privilèges
//! de LocalSystem d'XP SP2, ceux qui sont actifs par défaut actifs ; une DACL
//! par défaut qui donne tout à LocalSystem et la lecture à Administrators.
//! Un processus reçoit une copie du jeton de son créateur
//! ([`Token::duplicate_primary`], SeSubProcessToken).
//!
//! Un jeton créé de toutes pièces ([`Token::create`], SepCreateToken, pour
//! NtCreateToken) : `lsasrv` en fait un pour l'utilisateur qui ouvre sa
//! session (LsaLogonUser). Son propriétaire par défaut est l'utilisateur, ou
//! un de ses groupes qui porte `SE_GROUP_OWNER` ; son groupe principal,
//! l'utilisateur ou un de ses groupes. Sa session (Terminal Services) est 0 ;
//! `winlogon` la change ensuite.
//!
//! [`Token::query`] rend une classe d'information de NtQueryInformationToken
//! telle que le mode utilisateur la reçoit, pointeurs compris.
//!
//! Une copie pour NtDuplicateToken ([`Token::duplicate_as`]) peut ne garder
//! que les groupes et les privilèges actifs (`EffectiveOnly`).
//!
//! Pas encore : NtAdjustGroupsToken, NtSetInformationToken, les SID
//! restreints.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_OWNER, STATUS_INVALID_PRIMARY_GROUP, STATUS_NOT_IMPLEMENTED,
};
use abi::object::{AccessMask, GenericMapping};
use abi::security::{
    LuidAndAttributes32, SidAndAttributes32, TokenSource32, TokenStatistics32, SECURITY_ANONYMOUS, SE_GROUP_ENABLED,
    SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY, SE_GROUP_OWNER, SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_ENABLED_BY_DEFAULT, SYSTEM_LUID, TOKEN_AUDIT_POLICY, TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
    TOKEN_GROUPS_AND_PRIVILEGES, TOKEN_IMPERSONATION_LEVEL, TOKEN_ORIGIN, TOKEN_OWNER, TOKEN_PRIMARY_GROUP,
    TOKEN_PRIVILEGES, TOKEN_RESTRICTED_SIDS, TOKEN_SANDBOX_INERT, TOKEN_SESSION_ID, TOKEN_SESSION_REFERENCE,
    TOKEN_SOURCE, TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_TYPE_PRIMARY, TOKEN_USER,
};
use hal::sync::KSpinLock;
use ob::{create_object, Object, ObjectType};

use crate::acl::Acl;
use crate::sid::Sid;
use crate::{allocate_luid, Luid};

pub const TOKEN_ASSIGN_PRIMARY: AccessMask = AccessMask(0x0001);
pub const TOKEN_DUPLICATE: AccessMask = AccessMask(0x0002);
pub const TOKEN_IMPERSONATE: AccessMask = AccessMask(0x0004);
pub const TOKEN_QUERY: AccessMask = AccessMask(0x0008);
pub const TOKEN_QUERY_SOURCE: AccessMask = AccessMask(0x0010);
pub const TOKEN_ADJUST_PRIVILEGES: AccessMask = AccessMask(0x0020);
pub const TOKEN_ADJUST_GROUPS: AccessMask = AccessMask(0x0040);
pub const TOKEN_ADJUST_DEFAULT: AccessMask = AccessMask(0x0080);
pub const TOKEN_ADJUST_SESSIONID: AccessMask = AccessMask(0x0100);
/// TOKEN_ALL_ACCESS d'XP, avec `TOKEN_ADJUST_SESSIONID`.
pub const TOKEN_ALL_ACCESS: AccessMask = AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | 0x01FF);

/// Le type `Token` (SeTokenObjectType), avec la correspondance générique
/// d'XP : TOKEN_READ, TOKEN_WRITE, TOKEN_EXECUTE.
pub static TOKEN_OBJECT_TYPE: ObjectType = ObjectType::new(
    "Token",
    TOKEN_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | TOKEN_QUERY.0),
        write: AccessMask(
            AccessMask::STANDARD_RIGHTS_WRITE.0
                | TOKEN_ADJUST_PRIVILEGES.0
                | TOKEN_ADJUST_GROUPS.0
                | TOKEN_ADJUST_DEFAULT.0,
        ),
        execute: AccessMask::STANDARD_RIGHTS_EXECUTE,
        all: TOKEN_ALL_ACCESS,
    },
);

/// La réserve d'un jeton pour ses parties qui changent (groupe principal,
/// DACL par défaut), en octets ; comme ReactOS.
const DYNAMIC_CHARGE: u32 = 500;

/// Un SID et ses attributs (`SE_GROUP_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SidAndAttributes {
    pub sid: Sid,
    pub attributes: u32,
}

/// Un privilège et son état (`SE_PRIVILEGE_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Privilege {
    pub luid: Luid,
    pub attributes: u32,
}

impl Privilege {
    /// Il est actif.
    pub const fn is_enabled(&self) -> bool {
        self.attributes & SE_PRIVILEGE_ENABLED != 0
    }
}

/// Le changement que demande NtAdjustPrivilegesToken.
#[derive(Clone, Copy, Debug)]
pub enum PrivilegeChange<'a> {
    /// Désactiver tous les privilèges.
    DisableAll,
    /// Activer ceux qui portent `SE_PRIVILEGE_ENABLED`, désactiver les
    /// autres.
    Set(&'a [Privilege]),
}

/// Ce qu'a fait [`Token::adjust_privileges`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adjusted {
    /// Les privilèges qui ont changé, avec leurs attributs d'avant.
    pub previous: Vec<Privilege>,
    /// Chaque privilège demandé est dans le jeton
    /// (`STATUS_NOT_ALL_ASSIGNED` sinon).
    pub all_assigned: bool,
}

/// Ce que NtCreateToken donne d'un jeton neuf, capturé.
#[derive(Clone, Debug)]
pub struct NewToken {
    /// TOKEN_TYPE_PRIMARY ou TOKEN_TYPE_IMPERSONATION.
    pub token_type: u32,
    /// SECURITY_*, pour un jeton d'emprunt d'identité.
    pub impersonation_level: u32,
    /// Sa session d'ouverture.
    pub authentication_id: Luid,
    pub expiration_time: i64,
    pub user: SidAndAttributes,
    pub groups: Vec<SidAndAttributes>,
    pub privileges: Vec<Privilege>,
    /// Le propriétaire par défaut ; l'utilisateur sans lui.
    pub owner: Option<Sid>,
    pub primary_group: Sid,
    pub default_dacl: Option<Acl>,
    pub source: TokenSource32,
}

/// Ce qui change dans un jeton.
#[derive(Clone)]
struct State {
    privileges: Vec<Privilege>,
    modified_id: Luid,
}

/// Le corps d'un objet jeton.
pub struct Token {
    token_id: Luid,
    authentication_id: Luid,
    /// TOKEN_TYPE.
    token_type: u32,
    /// SECURITY_IMPERSONATION_LEVEL, pour un jeton d'emprunt d'identité.
    impersonation_level: u32,
    source: TokenSource32,
    expiration_time: i64,
    user: SidAndAttributes,
    groups: Vec<SidAndAttributes>,
    /// Le propriétaire par défaut : 0 pour l'utilisateur, `i` pour le
    /// groupe `i - 1`.
    default_owner: usize,
    primary_group: Sid,
    default_dacl: Option<Acl>,
    session_id: AtomicU32,
    state: KSpinLock<State>,
}

/// Les privilèges de LocalSystem, et s'ils sont actifs par défaut.
const SYSTEM_PRIVILEGES: [(u32, bool); 24] = {
    use abi::security::*;
    [
        (SE_TCB_PRIVILEGE, true),
        (SE_CREATE_TOKEN_PRIVILEGE, false),
        (SE_TAKE_OWNERSHIP_PRIVILEGE, false),
        (SE_CREATE_PAGEFILE_PRIVILEGE, true),
        (SE_LOCK_MEMORY_PRIVILEGE, true),
        (SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, false),
        (SE_INCREASE_QUOTA_PRIVILEGE, false),
        (SE_INC_BASE_PRIORITY_PRIVILEGE, true),
        (SE_CREATE_PERMANENT_PRIVILEGE, true),
        (SE_DEBUG_PRIVILEGE, true),
        (SE_AUDIT_PRIVILEGE, true),
        (SE_SECURITY_PRIVILEGE, false),
        (SE_SYSTEM_ENVIRONMENT_PRIVILEGE, false),
        (SE_CHANGE_NOTIFY_PRIVILEGE, true),
        (SE_BACKUP_PRIVILEGE, false),
        (SE_RESTORE_PRIVILEGE, false),
        (SE_SHUTDOWN_PRIVILEGE, false),
        (SE_LOAD_DRIVER_PRIVILEGE, false),
        (SE_PROF_SINGLE_PROCESS_PRIVILEGE, true),
        (SE_SYSTEMTIME_PRIVILEGE, false),
        (SE_UNDOCK_PRIVILEGE, false),
        (SE_MANAGE_VOLUME_PRIVILEGE, false),
        (SE_IMPERSONATE_PRIVILEGE, true),
        (SE_CREATE_GLOBAL_PRIVILEGE, true),
    ]
};

impl Token {
    /// SeMakeSystemToken : le jeton primaire de System (voir le module).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn system() -> Arc<Object<Self>> {
        let group = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
        let owner = SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER;
        let privileges = SYSTEM_PRIVILEGES
            .iter()
            .map(|&(luid, enabled)| Privilege {
                luid: Luid(u64::from(luid)),
                attributes: if enabled { SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED } else { 0 },
            })
            .collect();
        let read = AccessMask::GENERIC_READ.0 | AccessMask::GENERIC_EXECUTE.0 | AccessMask::READ_CONTROL.0;
        let token = Self {
            token_id: allocate_luid(),
            authentication_id: Luid::from_abi(SYSTEM_LUID),
            token_type: TOKEN_TYPE_PRIMARY,
            impersonation_level: SECURITY_ANONYMOUS,
            source: TokenSource32 { source_name: *b"*SYSTEM*", source_identifier: Default::default() },
            expiration_time: i64::MAX,
            user: SidAndAttributes { sid: Sid::LOCAL_SYSTEM, attributes: 0 },
            groups: alloc::vec![
                SidAndAttributes { sid: Sid::ADMINISTRATORS, attributes: owner },
                SidAndAttributes { sid: Sid::EVERYONE, attributes: group },
                SidAndAttributes { sid: Sid::AUTHENTICATED_USERS, attributes: group },
            ],
            default_owner: 1,
            primary_group: Sid::LOCAL_SYSTEM,
            default_dacl: Some(Acl::allowing(&[
                (AccessMask::GENERIC_ALL.0, Sid::LOCAL_SYSTEM),
                (read, Sid::ADMINISTRATORS),
            ])),
            session_id: AtomicU32::new(0),
            state: KSpinLock::new(State { privileges, modified_id: allocate_luid() }),
        };
        create_object(&TOKEN_OBJECT_TYPE, token)
    }

    /// SeSubProcessToken : le jeton primaire d'un processus créé par le
    /// porteur de celui-ci, une copie (même session d'ouverture, mêmes
    /// privilèges dans le même état) qui a son propre identifiant.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn duplicate_primary(&self) -> Arc<Object<Self>> {
        self.duplicate(TOKEN_TYPE_PRIMARY, self.impersonation_level)
    }

    /// SepDuplicateToken : une copie de ce jeton (même session d'ouverture,
    /// mêmes privilèges dans le même état), qui a son propre identifiant, du
    /// type `token_type` (TOKEN_TYPE_*) et, pour un jeton d'emprunt
    /// d'identité, du niveau `impersonation_level` (SECURITY_*).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn duplicate(&self, token_type: u32, impersonation_level: u32) -> Arc<Object<Self>> {
        self.duplicate_as(token_type, impersonation_level, false)
    }

    /// SepDuplicateToken de NtDuplicateToken : comme [`duplicate`](Self::duplicate)
    /// ; avec `effective_only`, la copie ne garde que les groupes actifs
    /// (`SE_GROUP_ENABLED`) et les privilèges actifs, et son propriétaire par
    /// défaut redevient l'utilisateur si son groupe n'y est plus.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn duplicate_as(&self, token_type: u32, impersonation_level: u32, effective_only: bool) -> Arc<Object<Self>> {
        let mut state = self.state.lock().clone();
        let mut groups = self.groups.clone();
        let mut default_owner = self.default_owner;
        if effective_only {
            let owner = self.default_owner();
            groups.retain(|group| group.attributes & SE_GROUP_ENABLED != 0);
            state.privileges.retain(Privilege::is_enabled);
            default_owner = groups.iter().position(|group| group.sid == owner).map_or(0, |index| index + 1);
        }
        let token = Self {
            token_id: allocate_luid(),
            authentication_id: self.authentication_id,
            token_type,
            impersonation_level,
            source: self.source,
            expiration_time: self.expiration_time,
            user: self.user,
            groups,
            default_owner,
            primary_group: self.primary_group,
            default_dacl: self.default_dacl.clone(),
            session_id: AtomicU32::new(self.session_id()),
            state: KSpinLock::new(state),
        };
        create_object(&TOKEN_OBJECT_TYPE, token)
    }

    /// SepCreateToken : un jeton neuf, de son propre identifiant, tel que
    /// `new` le décrit (voir le module).
    ///
    /// # Errors
    /// `STATUS_INVALID_OWNER` pour un propriétaire qui n'est ni
    /// l'utilisateur ni un de ses groupes qui porte `SE_GROUP_OWNER` ;
    /// `STATUS_INVALID_PRIMARY_GROUP` pour un groupe principal qui n'est ni
    /// l'utilisateur ni un de ses groupes.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(new: NewToken) -> Result<Arc<Object<Self>>, NtStatus> {
        let default_owner = match new.owner {
            None => 0,
            Some(owner) if owner == new.user.sid => 0,
            Some(owner) => {
                new.groups
                    .iter()
                    .position(|group| group.sid == owner && group.attributes & SE_GROUP_OWNER != 0)
                    .ok_or(STATUS_INVALID_OWNER)?
                    + 1
            }
        };
        let in_token =
            new.primary_group == new.user.sid || new.groups.iter().any(|group| group.sid == new.primary_group);
        if !in_token {
            return Err(STATUS_INVALID_PRIMARY_GROUP);
        }
        let token = Self {
            token_id: allocate_luid(),
            authentication_id: new.authentication_id,
            token_type: new.token_type,
            impersonation_level: new.impersonation_level,
            source: new.source,
            expiration_time: new.expiration_time,
            user: new.user,
            groups: new.groups,
            default_owner,
            primary_group: new.primary_group,
            default_dacl: new.default_dacl,
            session_id: AtomicU32::new(0),
            state: KSpinLock::new(State { privileges: new.privileges, modified_id: allocate_luid() }),
        };
        Ok(create_object(&TOKEN_OBJECT_TYPE, token))
    }

    /// TokenType : TOKEN_TYPE_PRIMARY ou TOKEN_TYPE_IMPERSONATION.
    pub fn token_type(&self) -> u32 {
        self.token_type
    }

    /// Le niveau d'emprunt d'identité (SECURITY_*) d'un jeton d'emprunt
    /// d'identité.
    pub fn impersonation_level(&self) -> u32 {
        self.impersonation_level
    }

    /// TokenId.
    pub fn token_id(&self) -> Luid {
        self.token_id
    }

    /// AuthenticationId : sa session d'ouverture.
    pub fn authentication_id(&self) -> Luid {
        self.authentication_id
    }

    /// Son utilisateur.
    pub fn user(&self) -> SidAndAttributes {
        self.user
    }

    /// Ses groupes, sans l'utilisateur.
    pub fn groups(&self) -> &[SidAndAttributes] {
        &self.groups
    }

    /// Son propriétaire par défaut.
    pub fn default_owner(&self) -> Sid {
        match self.default_owner {
            0 => self.user.sid,
            group => self.groups[group - 1].sid,
        }
    }

    /// Sa session (Terminal Services).
    pub fn session_id(&self) -> u32 {
        self.session_id.load(Ordering::Relaxed)
    }

    /// ModifiedId : change à chaque changement du jeton.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn modified_id(&self) -> Luid {
        self.state.lock().modified_id
    }

    /// Ses privilèges et leur état.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn privileges(&self) -> Vec<Privilege> {
        self.state.lock().privileges.clone()
    }

    /// Le privilège `luid` est dans le jeton et actif.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_privilege_enabled(&self, luid: Luid) -> bool {
        self.state.lock().privileges.iter().any(|privilege| privilege.luid == luid && privilege.is_enabled())
    }

    /// NtAdjustPrivilegesToken : active ou désactive des privilèges du
    /// jeton ; seuls `SE_PRIVILEGE_ENABLED` change. Rend ceux qui ont changé,
    /// avec leurs attributs d'avant, et si chaque privilège demandé est dans
    /// le jeton (ceux qui y sont changent quand même).
    ///
    /// Avec `room`, ce que l'appelant peut recevoir des privilèges d'avant :
    /// s'il en change davantage, rien ne change et l'erreur dit combien
    /// auraient changé (l'appelant rend `STATUS_BUFFER_TOO_SMALL`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn adjust_privileges(&self, change: PrivilegeChange<'_>, room: Option<usize>) -> Result<Adjusted, usize> {
        let mut state = self.state.lock();
        // The state each privilege of the token ends in.
        let mut wanted: Vec<bool> = state.privileges.iter().map(Privilege::is_enabled).collect();
        let mut all_assigned = true;
        match change {
            PrivilegeChange::DisableAll => wanted.fill(false),
            PrivilegeChange::Set(asked) => {
                for request in asked {
                    match state.privileges.iter().position(|privilege| privilege.luid == request.luid) {
                        Some(index) => wanted[index] = request.is_enabled(),
                        None => all_assigned = false,
                    }
                }
            }
        }
        let previous: Vec<Privilege> = state
            .privileges
            .iter()
            .zip(&wanted)
            .filter(|(privilege, &enabled)| privilege.is_enabled() != enabled)
            .map(|(privilege, _)| *privilege)
            .collect();
        if room.is_some_and(|room| previous.len() > room) {
            return Err(previous.len());
        }
        if !previous.is_empty() {
            for (privilege, enabled) in state.privileges.iter_mut().zip(wanted) {
                privilege.attributes = if enabled {
                    privilege.attributes | SE_PRIVILEGE_ENABLED
                } else {
                    privilege.attributes & !SE_PRIVILEGE_ENABLED
                };
            }
            state.modified_id = allocate_luid();
        }
        Ok(Adjusted { previous, all_assigned })
    }

    /// NtQueryInformationToken : la classe `class` telle que le mode
    /// utilisateur la reçoit dans un tampon en `at`, dont les pointeurs
    /// désignent la suite du tampon. `TokenSource` demande
    /// `TOKEN_QUERY_SOURCE`, les autres `TOKEN_QUERY` : c'est à l'appelant de
    /// le vérifier ([`query_access`]).
    ///
    /// # Errors
    /// `STATUS_INVALID_INFO_CLASS` pour une classe inconnue d'XP, ou le
    /// niveau d'emprunt d'identité d'un jeton primaire ;
    /// `STATUS_NOT_IMPLEMENTED` pour `TokenGroupsAndPrivileges`,
    /// `TokenSessionReference`, `TokenAuditPolicy` et `TokenOrigin`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn query(&self, class: u32, at: u32) -> Result<Vec<u8>, NtStatus> {
        let mut out = Vec::new();
        let word = |value: u32| value.to_le_bytes().to_vec();
        match class {
            TOKEN_USER => write_sids(&mut out, at, None, core::slice::from_ref(&self.user)),
            TOKEN_GROUPS => write_sids(&mut out, at, Some(self.groups.len() as u32), &self.groups),
            TOKEN_RESTRICTED_SIDS => write_sids(&mut out, at, Some(0), &[]),
            TOKEN_PRIVILEGES => {
                let privileges = self.privileges();
                out.extend_from_slice(&(privileges.len() as u32).to_le_bytes());
                for privilege in privileges {
                    let entry = LuidAndAttributes32 { luid: privilege.luid.to_abi(), attributes: privilege.attributes };
                    out.extend_from_slice(entry.as_bytes());
                }
            }
            TOKEN_OWNER => write_pointed(&mut out, at, |out| self.default_owner().write_to(out)),
            TOKEN_PRIMARY_GROUP => write_pointed(&mut out, at, |out| self.primary_group.write_to(out)),
            TOKEN_DEFAULT_DACL => match &self.default_dacl {
                Some(dacl) => write_pointed(&mut out, at, |out| out.extend_from_slice(dacl.bytes())),
                None => out.extend_from_slice(&0u32.to_le_bytes()),
            },
            TOKEN_SOURCE => out.extend_from_slice(self.source.as_bytes()),
            TOKEN_TYPE => out = word(self.token_type),
            TOKEN_IMPERSONATION_LEVEL if self.token_type == TOKEN_TYPE_PRIMARY => {
                return Err(STATUS_INVALID_INFO_CLASS)
            }
            TOKEN_IMPERSONATION_LEVEL => out = word(self.impersonation_level),
            TOKEN_STATISTICS => {
                let state = self.state.lock().clone();
                let dynamic = self.primary_group.length() + self.default_dacl.as_ref().map_or(0, Acl::len);
                let statistics = TokenStatistics32 {
                    token_id: self.token_id.to_abi(),
                    authentication_id: self.authentication_id.to_abi(),
                    expiration_time: self.expiration_time,
                    token_type: self.token_type,
                    impersonation_level: self.impersonation_level,
                    dynamic_charged: DYNAMIC_CHARGE,
                    dynamic_available: DYNAMIC_CHARGE.saturating_sub(dynamic as u32),
                    group_count: self.groups.len() as u32,
                    privilege_count: state.privileges.len() as u32,
                    modified_id: state.modified_id.to_abi(),
                };
                out.extend_from_slice(statistics.as_bytes());
            }
            TOKEN_SESSION_ID => out = word(self.session_id()),
            TOKEN_SANDBOX_INERT => out = word(0),
            TOKEN_GROUPS_AND_PRIVILEGES | TOKEN_SESSION_REFERENCE | TOKEN_AUDIT_POLICY | TOKEN_ORIGIN => {
                return Err(STATUS_NOT_IMPLEMENTED)
            }
            _ => return Err(STATUS_INVALID_INFO_CLASS),
        }
        Ok(out)
    }
}

/// Le droit que demande la classe `class` de NtQueryInformationToken.
pub fn query_access(class: u32) -> AccessMask {
    if class == TOKEN_SOURCE {
        TOKEN_QUERY_SOURCE
    } else {
        TOKEN_QUERY
    }
}

/// TOKEN_USER (sans compte) ou TOKEN_GROUPS (avec `count`) : les
/// SID_AND_ATTRIBUTES, puis les SID qu'ils désignent, dans un tampon en
/// `at`.
fn write_sids(out: &mut Vec<u8>, at: u32, count: Option<u32>, entries: &[SidAndAttributes]) {
    if let Some(count) = count {
        out.extend_from_slice(&count.to_le_bytes());
    }
    let mut sid = out.len() + entries.len() * core::mem::size_of::<SidAndAttributes32>();
    for entry in entries {
        let record = SidAndAttributes32 { sid: at.wrapping_add(sid as u32), attributes: entry.attributes };
        out.extend_from_slice(record.as_bytes());
        sid += entry.sid.length();
    }
    for entry in entries {
        entry.sid.write_to(out);
    }
}

/// Un pointeur vers ce que `write` ajoute juste après lui (TOKEN_OWNER,
/// TOKEN_PRIMARY_GROUP, TOKEN_DEFAULT_DACL), dans un tampon en `at`.
fn write_pointed(out: &mut Vec<u8>, at: u32, write: impl FnOnce(&mut Vec<u8>)) {
    out.extend_from_slice(&at.wrapping_add(4).to_le_bytes());
    write(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::security::*;

    const AT: u32 = 0x0012_0000;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    fn privilege(luid: u32, attributes: u32) -> Privilege {
        Privilege { luid: Luid(u64::from(luid)), attributes }
    }

    #[test]
    fn the_system_token_is_local_system() {
        let token = Token::system();
        assert_eq!(token.authentication_id(), Luid(0x3E7));
        assert_eq!(token.user().sid, Sid::LOCAL_SYSTEM);
        let groups: Vec<Sid> = token.groups().iter().map(|group| group.sid).collect();
        assert_eq!(groups, [Sid::ADMINISTRATORS, Sid::EVERYONE, Sid::AUTHENTICATED_USERS]);
        assert_eq!(token.default_owner(), Sid::ADMINISTRATORS);
        assert!(token.is_privilege_enabled(Luid(SE_TCB_PRIVILEGE.into())));
        assert!(!token.is_privilege_enabled(Luid(SE_LOAD_DRIVER_PRIVILEGE.into())), "held, but disabled");
        assert!(token.privileges().iter().any(|privilege| privilege.luid == Luid(SE_LOAD_DRIVER_PRIVILEGE.into())));
        assert!(token.token_id() > Luid(0x3E7), "after the logon sessions");
    }

    #[test]
    fn a_child_token_is_a_copy_with_its_own_id() {
        let parent = Token::system();
        parent
            .adjust_privileges(PrivilegeChange::Set(&[privilege(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED)]), None)
            .unwrap();
        let child = parent.duplicate_primary();
        assert_ne!(child.token_id(), parent.token_id());
        assert_eq!(child.authentication_id(), parent.authentication_id());
        assert_eq!(child.privileges(), parent.privileges(), "in the same state");
        assert_eq!(child.query(TOKEN_USER, AT), parent.query(TOKEN_USER, AT));
        child.adjust_privileges(PrivilegeChange::DisableAll, None).unwrap();
        assert!(parent.is_privilege_enabled(Luid(SE_SHUTDOWN_PRIVILEGE.into())), "the parent's own");
    }

    #[test]
    fn an_impersonation_copy_has_its_type_and_level() {
        let primary = Token::system();
        let copy = primary.duplicate(TOKEN_TYPE_IMPERSONATION, SECURITY_IMPERSONATION);
        assert_eq!((copy.token_type(), copy.impersonation_level()), (TOKEN_TYPE_IMPERSONATION, SECURITY_IMPERSONATION));
        assert_ne!(copy.token_id(), primary.token_id());
        assert_eq!(copy.authentication_id(), primary.authentication_id());
        assert_eq!(copy.query(TOKEN_TYPE, AT), Ok(TOKEN_TYPE_IMPERSONATION.to_le_bytes().to_vec()));
        assert_eq!(copy.query(TOKEN_IMPERSONATION_LEVEL, AT), Ok(SECURITY_IMPERSONATION.to_le_bytes().to_vec()));
        assert_eq!(primary.query(TOKEN_IMPERSONATION_LEVEL, AT), Err(STATUS_INVALID_INFO_CLASS), "a primary token");
        assert_eq!(primary.duplicate_primary().token_type(), TOKEN_TYPE_PRIMARY);
    }

    #[test]
    fn privileges_held_are_enabled_and_disabled() {
        let token = Token::system();
        let modified = token.modified_id();
        let load = privilege(SE_LOAD_DRIVER_PRIVILEGE, SE_PRIVILEGE_ENABLED);
        let adjusted = token.adjust_privileges(PrivilegeChange::Set(&[load]), Some(1)).unwrap();
        assert_eq!(
            adjusted,
            Adjusted { previous: alloc::vec![privilege(SE_LOAD_DRIVER_PRIVILEGE, 0)], all_assigned: true }
        );
        assert!(token.is_privilege_enabled(load.luid));
        assert_ne!(token.modified_id(), modified, "a change gives a new ModifiedId");
        let modified = token.modified_id();
        let again = token.adjust_privileges(PrivilegeChange::Set(&[load]), Some(0)).unwrap();
        assert_eq!(again, Adjusted { previous: Vec::new(), all_assigned: true }, "already enabled: nothing changes");
        assert_eq!(token.modified_id(), modified);
        let back = token.adjust_privileges(PrivilegeChange::Set(&adjusted.previous), None).unwrap();
        assert_eq!(back.previous, [privilege(SE_LOAD_DRIVER_PRIVILEGE, SE_PRIVILEGE_ENABLED)]);
        assert!(!token.is_privilege_enabled(load.luid), "given back as it was");
    }

    #[test]
    fn privileges_not_held_are_reported() {
        let token = Token::system();
        let asked = [
            privilege(SE_SYNC_AGENT_PRIVILEGE, SE_PRIVILEGE_ENABLED),
            privilege(SE_BACKUP_PRIVILEGE, SE_PRIVILEGE_ENABLED),
        ];
        let adjusted = token.adjust_privileges(PrivilegeChange::Set(&asked), None).unwrap();
        assert!(!adjusted.all_assigned, "SeSyncAgentPrivilege is not LocalSystem's");
        assert_eq!(adjusted.previous, [privilege(SE_BACKUP_PRIVILEGE, 0)], "the other one changes");
    }

    #[test]
    fn nothing_changes_without_room_for_the_previous_state() {
        let token = Token::system();
        let before = token.privileges();
        assert_eq!(token.adjust_privileges(PrivilegeChange::DisableAll, Some(2)), Err(11), "11 enabled by default");
        assert_eq!(token.privileges(), before);
        let adjusted = token.adjust_privileges(PrivilegeChange::DisableAll, Some(11)).unwrap();
        assert_eq!(adjusted.previous.len(), 11);
        assert!(token.privileges().iter().all(|privilege| !privilege.is_enabled()));
        let attributes = token.privileges()[0].attributes;
        assert_eq!(attributes, SE_PRIVILEGE_ENABLED_BY_DEFAULT, "only SE_PRIVILEGE_ENABLED changes");
    }

    /// Administrator d'une machine (S-1-5-21-1-2-3-500).
    const ADMINISTRATOR: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 500]);
    /// None, son groupe principal (S-1-5-21-1-2-3-513).
    const NONE: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 513]);

    /// Un jeton comme celui que `lsasrv` fait pour Administrator.
    fn administrator(owner: Option<Sid>, primary_group: Sid) -> NewToken {
        let group = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
        NewToken {
            token_type: TOKEN_TYPE_PRIMARY,
            impersonation_level: SECURITY_ANONYMOUS,
            authentication_id: Luid(0x4321),
            expiration_time: i64::MAX,
            user: SidAndAttributes { sid: ADMINISTRATOR, attributes: 0 },
            groups: alloc::vec![
                SidAndAttributes { sid: NONE, attributes: group },
                SidAndAttributes { sid: Sid::EVERYONE, attributes: group },
                SidAndAttributes { sid: Sid::ADMINISTRATORS, attributes: group | SE_GROUP_OWNER },
                SidAndAttributes { sid: Sid::AUTHENTICATED_USERS, attributes: group },
            ],
            privileges: alloc::vec![
                privilege(SE_CHANGE_NOTIFY_PRIVILEGE, SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED),
                privilege(SE_SHUTDOWN_PRIVILEGE, 0),
            ],
            owner,
            primary_group,
            default_dacl: Some(crate::Acl::allowing(&[(AccessMask::GENERIC_ALL.0, ADMINISTRATOR)])),
            source: TokenSource32 { source_name: *b"User32  ", source_identifier: Luid(0x4322).to_abi() },
        }
    }

    #[test]
    fn a_created_token_is_what_was_given() {
        let token = Token::create(administrator(Some(Sid::ADMINISTRATORS), NONE)).unwrap();
        assert_eq!((token.token_type(), token.authentication_id()), (TOKEN_TYPE_PRIMARY, Luid(0x4321)));
        assert!(token.token_id() > Luid(0x3E7) && token.token_id() != token.modified_id());
        assert_eq!(token.user().sid, ADMINISTRATOR);
        assert_eq!(token.groups().len(), 4);
        assert_eq!(token.default_owner(), Sid::ADMINISTRATORS, "a group that may own");
        assert!(token.is_privilege_enabled(Luid(SE_CHANGE_NOTIFY_PRIVILEGE.into())));
        assert!(!token.is_privilege_enabled(Luid(SE_SHUTDOWN_PRIVILEGE.into())), "held, but disabled");
        assert_eq!(token.session_id(), 0, "winlogon sets it");
        let group = token.query(TOKEN_PRIMARY_GROUP, AT).unwrap();
        assert_eq!(Sid::parse(&group[4..]), Ok(NONE));
        assert_eq!(token.query(TOKEN_SOURCE, AT).unwrap()[..8], *b"User32  ");
        let statistics = token.query(TOKEN_STATISTICS, AT).unwrap();
        assert_eq!(word(&statistics, 8), 0x4321, "its logon session");
        assert_eq!((word(&statistics, 0x28), word(&statistics, 0x2C)), (4, 2), "groups, privileges");
        let dacl = token.query(TOKEN_DEFAULT_DACL, AT).unwrap();
        let aces: Vec<Option<Sid>> = crate::Acl::parse(&dacl[4..]).unwrap().aces().map(|ace| ace.sid).collect();
        assert_eq!(aces, [Some(ADMINISTRATOR)]);
        let child = token.duplicate_primary();
        assert_eq!((child.user().sid, child.default_owner()), (ADMINISTRATOR, Sid::ADMINISTRATORS));
    }

    #[test]
    fn the_user_owns_by_default() {
        assert_eq!(Token::create(administrator(None, NONE)).unwrap().default_owner(), ADMINISTRATOR);
        assert_eq!(
            Token::create(administrator(Some(ADMINISTRATOR), ADMINISTRATOR)).unwrap().default_owner(),
            ADMINISTRATOR
        );
    }

    #[test]
    fn an_owner_must_be_the_user_or_a_group_that_may_own() {
        let not_owner = Token::create(administrator(Some(Sid::EVERYONE), NONE));
        assert_eq!(not_owner.err(), Some(STATUS_INVALID_OWNER), "Everyone lacks SE_GROUP_OWNER");
        let stranger = Token::create(administrator(Some(Sid::LOCAL_SYSTEM), NONE));
        assert_eq!(stranger.err(), Some(STATUS_INVALID_OWNER), "not in the token");
        let group = Token::create(administrator(None, Sid::LOCAL_SYSTEM));
        assert_eq!(group.err(), Some(STATUS_INVALID_PRIMARY_GROUP), "not in the token");
    }

    #[test]
    fn an_effective_only_copy_keeps_what_is_enabled() {
        let mut new = administrator(Some(Sid::ADMINISTRATORS), NONE);
        new.groups[2].attributes &= !SE_GROUP_ENABLED;
        let token = Token::create(new).unwrap();
        let full = token.duplicate_as(TOKEN_TYPE_IMPERSONATION, SECURITY_IMPERSONATION, false);
        assert_eq!((full.groups().len(), full.privileges().len()), (4, 2));
        assert_eq!(full.default_owner(), Sid::ADMINISTRATORS);
        let effective = token.duplicate_as(TOKEN_TYPE_IMPERSONATION, SECURITY_IMPERSONATION, true);
        let groups: Vec<Sid> = effective.groups().iter().map(|group| group.sid).collect();
        assert_eq!(groups, [NONE, Sid::EVERYONE, Sid::AUTHENTICATED_USERS], "Administrators disabled");
        assert_eq!(effective.privileges(), [privilege(SE_CHANGE_NOTIFY_PRIVILEGE, 3)], "the enabled one");
        assert_eq!(effective.default_owner(), ADMINISTRATOR, "its group gone, the user owns");
        assert_eq!(
            (effective.token_type(), effective.impersonation_level()),
            (TOKEN_TYPE_IMPERSONATION, SECURITY_IMPERSONATION)
        );
        assert_eq!(token.groups().len(), 4, "the source keeps its own");
    }

    #[test]
    fn a_created_impersonation_token_has_its_level() {
        let new = NewToken {
            token_type: TOKEN_TYPE_IMPERSONATION,
            impersonation_level: SECURITY_IMPERSONATION,
            ..administrator(None, NONE)
        };
        let token = Token::create(new).unwrap();
        assert_eq!(token.query(TOKEN_IMPERSONATION_LEVEL, AT), Ok(SECURITY_IMPERSONATION.to_le_bytes().to_vec()));
    }

    #[test]
    fn token_user_points_into_the_buffer() {
        let user = Token::system().query(TOKEN_USER, AT).unwrap();
        assert_eq!(user.len(), 8 + 12);
        assert_eq!((word(&user, 0), word(&user, 4)), (AT + 8, 0));
        assert_eq!(Sid::parse(&user[8..]), Ok(Sid::LOCAL_SYSTEM));
    }

    #[test]
    fn token_groups_lists_then_points() {
        let groups = Token::system().query(TOKEN_GROUPS, AT).unwrap();
        assert_eq!(groups.len(), 4 + 3 * 8 + 16 + 12 + 12);
        assert_eq!(word(&groups, 0), 3);
        assert_eq!((word(&groups, 4), word(&groups, 8)), (AT + 28, 0xE), "Administrators, the owner");
        assert_eq!((word(&groups, 12), word(&groups, 16)), (AT + 44, 7));
        assert_eq!((word(&groups, 20), word(&groups, 24)), (AT + 56, 7));
        assert_eq!(Sid::parse(&groups[44..]), Ok(Sid::EVERYONE));
        assert_eq!(Token::system().query(TOKEN_RESTRICTED_SIDS, AT), Ok(alloc::vec![0, 0, 0, 0]));
    }

    #[test]
    fn the_other_classes() {
        let token = Token::system();
        let privileges = token.query(TOKEN_PRIVILEGES, AT).unwrap();
        assert_eq!((privileges.len(), word(&privileges, 0)), (4 + 24 * 12, 24));
        assert_eq!((word(&privileges, 4), word(&privileges, 12)), (SE_TCB_PRIVILEGE, 3));
        let owner = token.query(TOKEN_OWNER, AT).unwrap();
        assert_eq!((word(&owner, 0), Sid::parse(&owner[4..])), (AT + 4, Ok(Sid::ADMINISTRATORS)));
        let group = token.query(TOKEN_PRIMARY_GROUP, AT).unwrap();
        assert_eq!(Sid::parse(&group[4..]), Ok(Sid::LOCAL_SYSTEM));
        let dacl = token.query(TOKEN_DEFAULT_DACL, AT).unwrap();
        let aces: Vec<(u32, Option<Sid>)> =
            crate::Acl::parse(&dacl[4..]).unwrap().aces().map(|ace| (ace.mask, ace.sid)).collect();
        assert_eq!(aces, [(0x1000_0000, Some(Sid::LOCAL_SYSTEM)), (0xA002_0000, Some(Sid::ADMINISTRATORS))]);
        assert_eq!(token.query(TOKEN_SOURCE, AT).unwrap()[..8], *b"*SYSTEM*");
        assert_eq!(token.query(TOKEN_TYPE, AT), Ok(alloc::vec![1, 0, 0, 0]));
        assert_eq!(token.query(TOKEN_IMPERSONATION_LEVEL, AT), Err(STATUS_INVALID_INFO_CLASS), "a primary token");
        assert_eq!(token.query(TOKEN_SESSION_ID, AT), Ok(alloc::vec![0, 0, 0, 0]));
        let statistics = token.query(TOKEN_STATISTICS, AT).unwrap();
        assert_eq!(statistics.len(), 0x38);
        assert_eq!((word(&statistics, 0), word(&statistics, 8)), (token.token_id().0 as u32, 0x3E7));
        assert_eq!((word(&statistics, 0x18), word(&statistics, 0x28), word(&statistics, 0x2C)), (1, 3, 24));
        assert_eq!((word(&statistics, 0x20), word(&statistics, 0x24)), (500, 500 - 12 - 52));
        assert_eq!(word(&statistics, 0x30), token.modified_id().0 as u32);
        assert_eq!(token.query(TOKEN_ORIGIN, AT), Err(STATUS_NOT_IMPLEMENTED));
        assert_eq!(token.query(0, AT), Err(STATUS_INVALID_INFO_CLASS));
        assert_eq!(token.query(MAX_TOKEN_INFO_CLASS, AT), Err(STATUS_INVALID_INFO_CLASS));
        assert_eq!((query_access(TOKEN_SOURCE), query_access(TOKEN_USER)), (TOKEN_QUERY_SOURCE, TOKEN_QUERY));
    }
}
