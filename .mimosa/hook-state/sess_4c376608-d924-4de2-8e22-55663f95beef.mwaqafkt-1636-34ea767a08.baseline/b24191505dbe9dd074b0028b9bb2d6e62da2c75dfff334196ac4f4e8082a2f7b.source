//! Security (02 §5.8, ADR-011): what an i386 process and the kernel exchange
//! about SIDs, ACLs, security descriptors and tokens.
//!
//! - SIDs: their header, the authorities and RIDs of the well-known SIDs.
//! - ACLs and the ACEs of the first four types (allowed, denied, audit,
//!   alarm): header, mask, then the SID.
//! - Security descriptors: the same 20-byte header in absolute form
//!   (pointers) and in self-relative form (offsets from the header).
//! - Tokens: the classes of NtQueryInformationToken, the attributes of
//!   groups and privileges, the well-known privileges of XP SP2, and the
//!   fixed-size records the services exchange.
//!
//! ReactOS's NDK and PSDK headers (`setypes.h`, `winnt.h`) serve as the
//! specification of the formats; offsets are checked at compile time.

use core::mem::{offset_of, size_of};

// ── SIDs ────────────────────────────────────────────────────────────────

/// The revision of every SID.
pub const SID_REVISION: u8 = 1;
/// A SID has at most this many sub-authorities.
pub const SID_MAX_SUB_AUTHORITIES: u8 = 15;
/// The bytes of a SID before its sub-authorities: revision, count of
/// sub-authorities, identifier authority (6 bytes, big-endian).
pub const SID_HEADER_SIZE: usize = 8;

/// S-1-1: the world authority (Everyone).
pub const SECURITY_WORLD_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 1];
/// S-1-5: the NT authority.
pub const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
/// S-1-1-0: Everyone.
pub const SECURITY_WORLD_RID: u32 = 0;
/// S-1-5-11: Authenticated Users.
pub const SECURITY_AUTHENTICATED_USER_RID: u32 = 11;
/// S-1-5-18: LocalSystem.
pub const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
/// S-1-5-32: the built-in domain.
pub const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;
/// S-1-5-32-544: Administrators.
pub const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;

// ── ACLs ────────────────────────────────────────────────────────────────

/// ACL_REVISION: the ACEs of the first four types only.
pub const ACL_REVISION: u8 = 2;
/// The revisions an ACL may have (ACL_REVISION to ACL_REVISION_DS).
pub const MIN_ACL_REVISION: u8 = 2;
pub const MAX_ACL_REVISION: u8 = 4;

/// ACL: the header of an access control list, its ACEs following.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Acl {
    pub acl_revision: u8,
    pub sbz1: u8,
    /// The size of the whole list, header included.
    pub acl_size: u16,
    pub ace_count: u16,
    pub sbz2: u16,
}

const _: () = {
    assert!(size_of::<Acl>() == 8);
    assert!(offset_of!(Acl, acl_size) == 2);
    assert!(offset_of!(Acl, ace_count) == 4);
};

/// ACE_HEADER.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AceHeader {
    pub ace_type: u8,
    pub ace_flags: u8,
    /// The size of the whole ACE, header included.
    pub ace_size: u16,
}

const _: () = assert!(size_of::<AceHeader>() == 4);

pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
pub const ACCESS_DENIED_ACE_TYPE: u8 = 1;
pub const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
pub const SYSTEM_ALARM_ACE_TYPE: u8 = 3;
/// The last of the four types whose ACE is a header, a mask and a SID.
pub const ACCESS_MAX_MS_V2_ACE_TYPE: u8 = 3;
/// In an ACE of those four types: where the SID starts, after the header
/// and the mask (`SidStart` of ACCESS_ALLOWED_ACE).
pub const KNOWN_ACE_SID_START: usize = 8;

// ── Security descriptors ────────────────────────────────────────────────

/// The revision of every security descriptor.
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
/// The size of a security descriptor without its parts.
pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 20;

// SECURITY_DESCRIPTOR_CONTROL.
pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
pub const SE_DACL_PROTECTED: u16 = 0x1000;
pub const SE_SACL_PROTECTED: u16 = 0x2000;
pub const SE_RM_CONTROL_VALID: u16 = 0x4000;
/// The parts follow the header, at offsets from it.
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// SECURITY_DESCRIPTOR of an i386 process, and SECURITY_DESCRIPTOR_RELATIVE:
/// the same header, where the four parts are pointers in absolute form and
/// offsets from the header with `SE_SELF_RELATIVE` (0 for a part that is
/// not there).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityDescriptor32 {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub owner: u32,
    pub group: u32,
    pub sacl: u32,
    pub dacl: u32,
}

const _: () = {
    assert!(size_of::<SecurityDescriptor32>() == SECURITY_DESCRIPTOR_MIN_LENGTH);
    assert!(offset_of!(SecurityDescriptor32, control) == 2);
    assert!(offset_of!(SecurityDescriptor32, owner) == 4);
    assert!(offset_of!(SecurityDescriptor32, group) == 8);
    assert!(offset_of!(SecurityDescriptor32, sacl) == 12);
    assert!(offset_of!(SecurityDescriptor32, dacl) == 16);
};

// SECURITY_INFORMATION: the parts of a descriptor a service reads or writes.
pub const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
pub const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
pub const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
pub const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
pub const UNPROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x1000_0000;
pub const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
pub const PROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x4000_0000;
pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

// ── Tokens ──────────────────────────────────────────────────────────────

// TOKEN_INFORMATION_CLASS, as on XP SP2.
pub const TOKEN_USER: u32 = 1;
pub const TOKEN_GROUPS: u32 = 2;
pub const TOKEN_PRIVILEGES: u32 = 3;
pub const TOKEN_OWNER: u32 = 4;
pub const TOKEN_PRIMARY_GROUP: u32 = 5;
pub const TOKEN_DEFAULT_DACL: u32 = 6;
pub const TOKEN_SOURCE: u32 = 7;
pub const TOKEN_TYPE: u32 = 8;
pub const TOKEN_IMPERSONATION_LEVEL: u32 = 9;
pub const TOKEN_STATISTICS: u32 = 10;
pub const TOKEN_RESTRICTED_SIDS: u32 = 11;
pub const TOKEN_SESSION_ID: u32 = 12;
pub const TOKEN_GROUPS_AND_PRIVILEGES: u32 = 13;
pub const TOKEN_SESSION_REFERENCE: u32 = 14;
pub const TOKEN_SANDBOX_INERT: u32 = 15;
pub const TOKEN_AUDIT_POLICY: u32 = 16;
pub const TOKEN_ORIGIN: u32 = 17;
/// The first class XP does not know (MaxTokenInfoClass).
pub const MAX_TOKEN_INFO_CLASS: u32 = 18;

// TOKEN_TYPE.
pub const TOKEN_TYPE_PRIMARY: u32 = 1;
pub const TOKEN_TYPE_IMPERSONATION: u32 = 2;

// SECURITY_IMPERSONATION_LEVEL.
pub const SECURITY_ANONYMOUS: u32 = 0;
pub const SECURITY_IDENTIFICATION: u32 = 1;
pub const SECURITY_IMPERSONATION: u32 = 2;
pub const SECURITY_DELEGATION: u32 = 3;

// SECURITY_CONTEXT_TRACKING_MODE (SECURITY_QUALITY_OF_SERVICE): a copy of
// the client's token, or the token itself.
pub const SECURITY_STATIC_TRACKING: u8 = 0;
pub const SECURITY_DYNAMIC_TRACKING: u8 = 1;

// The attributes of a group in a token.
pub const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
pub const SE_GROUP_OWNER: u32 = 0x0000_0008;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
pub const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

// The attributes of a privilege in a token.
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x0000_0001;
pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;

// The well-known privileges of XP SP2: the low part of their LUID.
pub const SE_CREATE_TOKEN_PRIVILEGE: u32 = 2;
pub const SE_ASSIGNPRIMARYTOKEN_PRIVILEGE: u32 = 3;
pub const SE_LOCK_MEMORY_PRIVILEGE: u32 = 4;
pub const SE_INCREASE_QUOTA_PRIVILEGE: u32 = 5;
pub const SE_MACHINE_ACCOUNT_PRIVILEGE: u32 = 6;
pub const SE_TCB_PRIVILEGE: u32 = 7;
pub const SE_SECURITY_PRIVILEGE: u32 = 8;
pub const SE_TAKE_OWNERSHIP_PRIVILEGE: u32 = 9;
pub const SE_LOAD_DRIVER_PRIVILEGE: u32 = 10;
pub const SE_SYSTEM_PROFILE_PRIVILEGE: u32 = 11;
pub const SE_SYSTEMTIME_PRIVILEGE: u32 = 12;
pub const SE_PROF_SINGLE_PROCESS_PRIVILEGE: u32 = 13;
pub const SE_INC_BASE_PRIORITY_PRIVILEGE: u32 = 14;
pub const SE_CREATE_PAGEFILE_PRIVILEGE: u32 = 15;
pub const SE_CREATE_PERMANENT_PRIVILEGE: u32 = 16;
pub const SE_BACKUP_PRIVILEGE: u32 = 17;
pub const SE_RESTORE_PRIVILEGE: u32 = 18;
pub const SE_SHUTDOWN_PRIVILEGE: u32 = 19;
pub const SE_DEBUG_PRIVILEGE: u32 = 20;
pub const SE_AUDIT_PRIVILEGE: u32 = 21;
pub const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: u32 = 22;
pub const SE_CHANGE_NOTIFY_PRIVILEGE: u32 = 23;
pub const SE_REMOTE_SHUTDOWN_PRIVILEGE: u32 = 24;
pub const SE_UNDOCK_PRIVILEGE: u32 = 25;
pub const SE_SYNC_AGENT_PRIVILEGE: u32 = 26;
pub const SE_ENABLE_DELEGATION_PRIVILEGE: u32 = 27;
pub const SE_MANAGE_VOLUME_PRIVILEGE: u32 = 28;
pub const SE_IMPERSONATE_PRIVILEGE: u32 = 29;
pub const SE_CREATE_GLOBAL_PRIVILEGE: u32 = 30;

/// LUID: a value unique while the system runs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Luid32 {
    pub low_part: u32,
    pub high_part: i32,
}

const _: () = assert!(size_of::<Luid32>() == 8);

/// SYSTEM_LUID: the logon session of LocalSystem.
pub const SYSTEM_LUID: Luid32 = Luid32 { low_part: 0x3E7, high_part: 0 };

/// ANONYMOUS_LOGON_LUID: the logon session of the anonymous user.
pub const ANONYMOUS_LOGON_LUID: Luid32 = Luid32 { low_part: 0x3E6, high_part: 0 };

impl Luid32 {
    /// The LUID as one 64-bit value (high part above).
    pub const fn as_u64(self) -> u64 {
        (self.high_part as u32 as u64) << 32 | self.low_part as u64
    }
}

/// The requests of LSA to the reference monitor's command server
/// (`\SeRmCommandPort`, SRM_API_NUMBER of ReactOS's `srmp.h`).
pub const RM_AUDIT_SET_COMMAND: u32 = 1;
pub const RM_CREATE_LOGON_SESSION: u32 = 2;
pub const RM_DELETE_LOGON_SESSION: u32 = 3;

/// POLICY_AUDIT_EVENT_TYPE_COUNT: the audit categories, System to Account
/// Logon.
pub const AUDIT_EVENT_TYPES: usize = 9;

/// The data of SEP_RM_API_MESSAGE, after its PORT_MESSAGE: `ApiNumber`,
/// then a union whose members this module reads (ReactOS's `srmp.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RmApiData32 {
    pub api_number: u32,
    /// `u.ResultStatus`, `u.LogonLuid`, `u.SetAuditEvent` start here.
    pub union: RmSetAuditEvent32,
}

/// The `SetAuditEvent` member of SEP_RM_API_MESSAGE's union: a BOOLEAN,
/// then the flags of each category.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RmSetAuditEvent32 {
    pub enabled: u8,
    pub flags: [u32; AUDIT_EVENT_TYPES],
}

const _: () = {
    assert!(core::mem::offset_of!(RmApiData32, union) == 4);
    assert!(core::mem::offset_of!(RmSetAuditEvent32, flags) == 4);
    assert!(size_of::<RmApiData32>() == 44);
};

/// Where `u` starts in the data of SEP_RM_API_MESSAGE.
pub const RM_UNION_OFFSET: usize = core::mem::offset_of!(RmApiData32, union);

/// A request of SEP_RM_API_MESSAGE, as the data after its header gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RmRequest {
    /// RmAuditSetCommand: auditing on or off, and the flags of each category.
    SetAudit { enabled: bool, flags: [u32; AUDIT_EVENT_TYPES] },
    /// RmCreateLogonSession.
    CreateLogonSession(Luid32),
    /// RmDeleteLogonSession.
    DeleteLogonSession(Luid32),
    /// Another API number.
    Unknown(u32),
}

fn read32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

impl RmRequest {
    /// The request in `data` (a message's data, without its header);
    /// `None` when it is too short for its API number.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let luid = || {
            Some(Luid32 {
                low_part: read32(data, RM_UNION_OFFSET)?,
                high_part: read32(data, RM_UNION_OFFSET + 4)? as i32,
            })
        };
        Some(match read32(data, 0)? {
            RM_AUDIT_SET_COMMAND => {
                let enabled = *data.get(RM_UNION_OFFSET)? != 0;
                let mut flags = [0; AUDIT_EVENT_TYPES];
                for (index, flag) in flags.iter_mut().enumerate() {
                    *flag = read32(data, RM_UNION_OFFSET + 4 + 4 * index)?;
                }
                Self::SetAudit { enabled, flags }
            }
            RM_CREATE_LOGON_SESSION => Self::CreateLogonSession(luid()?),
            RM_DELETE_LOGON_SESSION => Self::DeleteLogonSession(luid()?),
            other => Self::Unknown(other),
        })
    }
}

/// The reply to a request, in place in its data, as the reference monitor
/// sends it back: `u.ResultStatus` set to `status`, the API number cleared
/// for RmAuditSetCommand (SepRmSetAuditEvent). `false` if `data` cannot
/// hold the status.
pub fn set_rm_result(data: &mut [u8], status: u32) -> bool {
    let Some(result) = data.get_mut(RM_UNION_OFFSET..RM_UNION_OFFSET + 4) else { return false };
    result.copy_from_slice(&status.to_le_bytes());
    if read32(data, 0) == Some(RM_AUDIT_SET_COMMAND) {
        data[..4].copy_from_slice(&0u32.to_le_bytes());
    }
    true
}

/// LUID_AND_ATTRIBUTES: a privilege and its state.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LuidAndAttributes32 {
    pub luid: Luid32,
    pub attributes: u32,
}

const _: () = {
    assert!(size_of::<LuidAndAttributes32>() == 12);
    assert!(offset_of!(LuidAndAttributes32, attributes) == 8);
};

/// SID_AND_ATTRIBUTES: the address of a SID, and its attributes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SidAndAttributes32 {
    pub sid: u32,
    pub attributes: u32,
}

const _: () = assert!(size_of::<SidAndAttributes32>() == 8);

/// TOKEN_SOURCE: who made the token.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenSource32 {
    pub source_name: [u8; 8],
    pub source_identifier: Luid32,
}

const _: () = {
    assert!(size_of::<TokenSource32>() == 16);
    assert!(offset_of!(TokenSource32, source_identifier) == 8);
};

/// TOKEN_STATISTICS.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenStatistics32 {
    pub token_id: Luid32,
    /// The logon session.
    pub authentication_id: Luid32,
    /// LARGE_INTEGER.
    pub expiration_time: i64,
    /// TOKEN_TYPE.
    pub token_type: u32,
    /// SECURITY_IMPERSONATION_LEVEL.
    pub impersonation_level: u32,
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
    /// The groups, without the user.
    pub group_count: u32,
    pub privilege_count: u32,
    /// Changes with each change to the token.
    pub modified_id: Luid32,
}

const _: () = {
    assert!(size_of::<TokenStatistics32>() == 0x38);
    assert!(offset_of!(TokenStatistics32, authentication_id) == 0x08);
    assert!(offset_of!(TokenStatistics32, expiration_time) == 0x10);
    assert!(offset_of!(TokenStatistics32, token_type) == 0x18);
    assert!(offset_of!(TokenStatistics32, dynamic_charged) == 0x20);
    assert!(offset_of!(TokenStatistics32, group_count) == 0x28);
    assert!(offset_of!(TokenStatistics32, modified_id) == 0x30);
};

/// `as_bytes` for records of integers whose sizes, checked above, leave no
/// padding.
macro_rules! as_bytes {
    ($($record:ty),*) => {$(
        impl $record {
            /// Its bytes, as they go to user mode.
            pub fn as_bytes(&self) -> &[u8] {
                // SAFETY: a `#[repr(C)]` record of integers without padding
                // (its size is checked above): every byte is initialised.
                unsafe { core::slice::from_raw_parts((self as *const Self).cast::<u8>(), size_of::<Self>()) }
            }
        }
    )*};
}

as_bytes!(
    Acl,
    AceHeader,
    SecurityDescriptor32,
    Luid32,
    LuidAndAttributes32,
    SidAndAttributes32,
    TokenSource32,
    TokenStatistics32
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rm_requests_are_read_from_their_data() {
        let mut data = [0u8; 44];
        data[..4].copy_from_slice(&RM_CREATE_LOGON_SESSION.to_le_bytes());
        data[4..8].copy_from_slice(&0x1234u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        let luid = Luid32 { low_part: 0x1234, high_part: 1 };
        assert_eq!(RmRequest::parse(&data), Some(RmRequest::CreateLogonSession(luid)));
        assert_eq!(luid.as_u64(), 0x1_0000_1234);
        data[..4].copy_from_slice(&RM_DELETE_LOGON_SESSION.to_le_bytes());
        assert_eq!(RmRequest::parse(&data), Some(RmRequest::DeleteLogonSession(luid)));
        assert_eq!(RmRequest::parse(&data[..8]), None, "a LUID cut short");
        data[..4].copy_from_slice(&RM_AUDIT_SET_COMMAND.to_le_bytes());
        data[4] = 1;
        data[8 + 4 * 8..8 + 4 * 9].copy_from_slice(&7u32.to_le_bytes());
        let Some(RmRequest::SetAudit { enabled: true, flags }) = RmRequest::parse(&data) else {
            panic!("an audit request")
        };
        assert_eq!(flags[8], 7);
        assert_eq!(RmRequest::parse(&99u32.to_le_bytes()), Some(RmRequest::Unknown(99)));
    }

    #[test]
    fn the_rm_result_goes_where_the_union_starts() {
        let mut data = [0u8; 12];
        data[..4].copy_from_slice(&RM_CREATE_LOGON_SESSION.to_le_bytes());
        assert!(set_rm_result(&mut data, 0xC000_00EE));
        assert_eq!(&data[4..8], &0xC000_00EEu32.to_le_bytes());
        assert_eq!(&data[..4], &RM_CREATE_LOGON_SESSION.to_le_bytes(), "the API number stays");
        data[..4].copy_from_slice(&RM_AUDIT_SET_COMMAND.to_le_bytes());
        assert!(set_rm_result(&mut data, 0));
        assert_eq!(&data[..4], &[0; 4], "cleared for RmAuditSetCommand");
        assert!(!set_rm_result(&mut [0u8; 6], 0));
    }

    #[test]
    fn records_are_little_endian_bytes() {
        let header = SecurityDescriptor32 {
            revision: SECURITY_DESCRIPTOR_REVISION,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            dacl: 0x14,
            ..Default::default()
        };
        assert_eq!(header.as_bytes()[..4], [1, 0, 0x04, 0x80]);
        assert_eq!(header.as_bytes()[16..], [0x14, 0, 0, 0]);
        let privilege = LuidAndAttributes32 { luid: SYSTEM_LUID, attributes: SE_PRIVILEGE_ENABLED };
        assert_eq!(privilege.as_bytes(), [0xE7, 3, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0]);
    }
}
