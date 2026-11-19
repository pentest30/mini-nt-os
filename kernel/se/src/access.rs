//! SeAccessCheck : les droits qu'un descripteur de sécurité accorde à un
//! jeton (ADR-011). NtAccessCheck les rend tels quels (`CheckTokenMembership`
//! d'`advapi32` s'en sert pour savoir si un jeton tient un groupe) ; Ob ne
//! les applique pas encore aux ouvertures.
//!
//! Comme XP (ReactOS sert de spécification, SepAccessCheck) :
//! - les privilèges d'abord ([`privilege_check`], SePrivilegePolicyCheck) :
//!   `ACCESS_SYSTEM_SECURITY` demande SeSecurityPrivilege actif
//!   (`STATUS_PRIVILEGE_NOT_HELD` sans lui) ; `WRITE_OWNER` est accordé par
//!   SeTakeOwnershipPrivilege s'il est actif ;
//! - le propriétaire du descripteur, s'il est l'utilisateur du jeton ou l'un
//!   de ses groupes actifs, a `READ_CONTROL` et `WRITE_DAC` ;
//! - sans DACL, ou avec une DACL nulle, tout est accordé ; une DACL sans ACE
//!   ne donne rien de plus ;
//! - les ACE, dans l'ordre : une ACE de refus retire les droits pas encore
//!   accordés, une ACE d'autorisation ajoute ceux qui ne sont pas encore
//!   refusés ; une ACE « héritage seulement » ne compte pas ; ses droits
//!   génériques passent par la correspondance de l'objet ;
//! - `MAXIMUM_ALLOWED` rend tout ce que la DACL accorde ; sinon, chaque droit
//!   demandé doit l'être, et ce sont eux qui sont accordés.
//!
//! Pas encore : les listes de types d'objets (NtAccessCheckByType), les SID
//! restreints, PrincipalSelf.

use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_ACCESS_DENIED, STATUS_PRIVILEGE_NOT_HELD};
use abi::object::{AccessMask, GenericMapping};
use abi::security::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, INHERIT_ONLY_ACE, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY,
    SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE,
};

use crate::descriptor::SecurityDescriptor;
use crate::sid::Sid;
use crate::token::Token;
use crate::Luid;

/// Ce que les privilèges du jeton accordent d'une demande
/// ([`privilege_check`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivilegeGrant {
    /// Les droits que les privilèges accordent.
    pub granted: AccessMask,
    /// Ce qui reste à demander au descripteur.
    pub remaining: AccessMask,
    /// Les privilèges dont l'accord s'est servi, dans l'ordre.
    pub used: Vec<Luid>,
}

/// SePrivilegePolicyCheck : ce que les privilèges actifs de `token`
/// accordent de `desired`.
///
/// # Errors
/// `STATUS_PRIVILEGE_NOT_HELD` : `ACCESS_SYSTEM_SECURITY` sans
/// SeSecurityPrivilege actif.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn privilege_check(token: &Token, desired: AccessMask) -> Result<PrivilegeGrant, NtStatus> {
    let mut grant = PrivilegeGrant { granted: AccessMask::NONE, remaining: desired, used: Vec::new() };
    let rules = [
        (AccessMask::ACCESS_SYSTEM_SECURITY, SE_SECURITY_PRIVILEGE, true),
        (AccessMask::WRITE_OWNER, SE_TAKE_OWNERSHIP_PRIVILEGE, false),
    ];
    for (right, privilege, required) in rules {
        if !desired.intersects(right) {
            continue;
        }
        let luid = Luid(u64::from(privilege));
        if token.is_privilege_enabled(luid) {
            grant.granted = grant.granted | right;
            grant.remaining = grant.remaining.without(right);
            grant.used.push(luid);
        } else if required {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
    }
    Ok(grant)
}

/// SepSidInToken : `sid` est l'utilisateur de `token` ou l'un de ses
/// groupes actifs ; pour une ACE de refus (`deny`), aussi un groupe « refus
/// seulement » (`SE_GROUP_USE_FOR_DENY_ONLY`).
pub fn sid_in_token(token: &Token, sid: &Sid, deny: bool) -> bool {
    let user = token.user();
    if user.sid == *sid {
        return deny || user.attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0;
    }
    token.groups().iter().any(|group| {
        group.sid == *sid
            && (group.attributes & SE_GROUP_ENABLED != 0
                || (deny && group.attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0))
    })
}

/// SepAccessCheck, après les privilèges : les droits que `descriptor`
/// accorde à `token` pour `desired` (sans droits génériques, sauf
/// `MAXIMUM_ALLOWED`), en plus de `previously` (ce que les privilèges ont
/// déjà accordé), selon la correspondance `mapping` de l'objet.
///
/// # Errors
/// `STATUS_ACCESS_DENIED` : un droit demandé n'est pas accordé, ou rien ne
/// l'est pour `MAXIMUM_ALLOWED`.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn access_check(
    descriptor: &SecurityDescriptor,
    token: &Token,
    desired: AccessMask,
    previously: AccessMask,
    mapping: &GenericMapping,
) -> Result<AccessMask, NtStatus> {
    let owner_rights = AccessMask::READ_CONTROL | AccessMask::WRITE_DAC;
    let maximum = desired.intersects(AccessMask::MAXIMUM_ALLOWED);
    let mut granted = previously;
    let mut desired = mapping.map(desired);
    if desired.intersects(owner_rights | AccessMask::MAXIMUM_ALLOWED)
        && descriptor.owner.is_some_and(|owner| sid_in_token(token, &owner, false))
    {
        granted = granted | if maximum { owner_rights } else { desired & owner_rights };
        desired = desired.without(owner_rights);
    }
    if desired == AccessMask::NONE {
        return Ok(granted);
    }
    let dacl = match &descriptor.dacl {
        // No DACL, or a NULL DACL: the object is not protected.
        None | Some(None) => {
            let all = if maximum { mapping.all } else { AccessMask::NONE };
            return Ok(granted | desired.without(AccessMask::MAXIMUM_ALLOWED) | all);
        }
        Some(Some(dacl)) => dacl,
    };
    let (mut allowed, mut denied) = (AccessMask::NONE, AccessMask::NONE);
    for ace in dacl.aces().filter(|ace| ace.flags & INHERIT_ONLY_ACE == 0) {
        let Some(sid) = ace.sid else { continue };
        let mask = mapping.map(AccessMask(ace.mask));
        match ace.ace_type {
            ACCESS_DENIED_ACE_TYPE if sid_in_token(token, &sid, true) => denied = denied | mask.without(allowed),
            ACCESS_ALLOWED_ACE_TYPE if sid_in_token(token, &sid, false) => allowed = allowed | mask.without(denied),
            _ => {}
        }
    }
    let wanted = desired.without(AccessMask::MAXIMUM_ALLOWED);
    if !allowed.contains(wanted) {
        return Err(STATUS_ACCESS_DENIED);
    }
    let granted = granted | if maximum { allowed } else { wanted };
    if granted == AccessMask::NONE {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(granted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Acl;
    use crate::token::{NewToken, Privilege, PrivilegeChange, SidAndAttributes};
    use abi::security::*;
    use alloc::sync::Arc;
    use ob::Object;

    /// Administrator d'une machine, et None, son groupe principal.
    const ADMINISTRATOR: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 500]);
    const NONE: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 513]);
    /// BUILTIN\Users et BUILTIN\Power Users.
    const USERS: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[32, 545]);
    const POWER_USERS: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[32, 547]);

    /// La correspondance de CheckTokenMembership.
    const STANDARD: GenericMapping = GenericMapping {
        read: AccessMask::STANDARD_RIGHTS_READ,
        write: AccessMask::STANDARD_RIGHTS_WRITE,
        execute: AccessMask::STANDARD_RIGHTS_EXECUTE,
        all: AccessMask(0x001F_0000),
    };
    /// Celle d'un fichier.
    const FILE: GenericMapping = GenericMapping {
        read: AccessMask(0x0012_0089),
        write: AccessMask(0x0012_0116),
        execute: AccessMask(0x0012_00A0),
        all: AccessMask(0x001F_01FF),
    };

    /// Un jeton d'emprunt d'identité d'Administrator : Users activé, Power
    /// Users « refus seulement », Administrators désactivé.
    fn token() -> Arc<Object<Token>> {
        let enabled = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
        Token::create(NewToken {
            token_type: TOKEN_TYPE_IMPERSONATION,
            impersonation_level: SECURITY_IDENTIFICATION,
            authentication_id: Luid(0x4321),
            expiration_time: i64::MAX,
            user: SidAndAttributes { sid: ADMINISTRATOR, attributes: 0 },
            groups: alloc::vec![
                SidAndAttributes { sid: NONE, attributes: enabled },
                SidAndAttributes { sid: Sid::EVERYONE, attributes: enabled },
                SidAndAttributes { sid: USERS, attributes: enabled },
                SidAndAttributes { sid: POWER_USERS, attributes: SE_GROUP_USE_FOR_DENY_ONLY },
                SidAndAttributes { sid: Sid::ADMINISTRATORS, attributes: 0 },
            ],
            privileges: alloc::vec![
                Privilege { luid: Luid(SE_SECURITY_PRIVILEGE.into()), attributes: 0 },
                Privilege { luid: Luid(SE_TAKE_OWNERSHIP_PRIVILEGE.into()), attributes: 0 },
            ],
            owner: None,
            primary_group: NONE,
            default_dacl: None,
            source: TokenSource32 { source_name: *b"User32  ", source_identifier: Luid(0x4322).to_abi() },
        })
        .unwrap()
    }

    /// Le descripteur que CheckTokenMembership fait pour `sid` : propriétaire,
    /// groupe, et une ACE qui lui donne l'accès 1.
    fn membership(sid: Sid) -> SecurityDescriptor {
        SecurityDescriptor {
            owner: Some(sid),
            group: Some(sid),
            dacl: Some(Some(Acl::allowing(&[(1, sid)]))),
            ..Default::default()
        }
    }

    fn check(
        descriptor: &SecurityDescriptor,
        token: &Token,
        desired: u32,
        mapping: &GenericMapping,
    ) -> Result<u32, NtStatus> {
        access_check(descriptor, token, AccessMask(desired), AccessMask::NONE, mapping).map(|granted| granted.0)
    }

    #[test]
    fn check_token_membership_finds_enabled_groups_only() {
        // Inno Setup asks CheckTokenMembership whether the user is an
        // administrator: without NtAccessCheck, it was told no, and every
        // installer of the M7 bench gave up.
        let system = Token::system().duplicate(TOKEN_TYPE_IMPERSONATION, SECURITY_IDENTIFICATION);
        assert_eq!(check(&membership(Sid::ADMINISTRATORS), &system, 1, &STANDARD), Ok(1), "System is an administrator");
        assert_eq!(check(&membership(POWER_USERS), &system, 1, &STANDARD), Err(STATUS_ACCESS_DENIED));
        let token = token();
        assert_eq!(check(&membership(USERS), &token, 1, &STANDARD), Ok(1), "an enabled group");
        assert_eq!(check(&membership(ADMINISTRATOR), &token, 1, &STANDARD), Ok(1), "the user");
        assert_eq!(
            check(&membership(Sid::ADMINISTRATORS), &token, 1, &STANDARD),
            Err(STATUS_ACCESS_DENIED),
            "disabled"
        );
        assert_eq!(check(&membership(POWER_USERS), &token, 1, &STANDARD), Err(STATUS_ACCESS_DENIED), "deny only");
    }

    #[test]
    fn aces_are_read_in_order_denials_first_if_first() {
        let token = token();
        let read = 0x0012_0089;
        let denied_first = SecurityDescriptor {
            owner: Some(NONE),
            group: Some(NONE),
            dacl: Some(Some(Acl::build(
                ACL_REVISION,
                &[
                    (ACCESS_DENIED_ACE_TYPE, 0, 0x0000_0002, USERS),
                    (ACCESS_ALLOWED_ACE_TYPE, 0, AccessMask::GENERIC_ALL.0, Sid::EVERYONE),
                ],
            ))),
            ..Default::default()
        };
        assert_eq!(check(&denied_first, &token, read, &FILE), Ok(read), "what is asked, not all that is allowed");
        assert_eq!(check(&denied_first, &token, 0x0000_0002, &FILE), Err(STATUS_ACCESS_DENIED), "denied first");
        let maximum = check(&denied_first, &token, AccessMask::MAXIMUM_ALLOWED.0, &FILE).unwrap();
        assert_eq!(maximum, 0x001F_01FF & !0x0000_0002, "GENERIC_ALL mapped, without the denied right");
        let allowed_first = SecurityDescriptor {
            dacl: Some(Some(Acl::build(
                ACL_REVISION,
                &[
                    (ACCESS_ALLOWED_ACE_TYPE, 0, 0x0000_0002, USERS),
                    (ACCESS_DENIED_ACE_TYPE, 0, 0x0000_0002, Sid::EVERYONE),
                ],
            ))),
            ..denied_first.clone()
        };
        assert_eq!(check(&allowed_first, &token, 0x0000_0002, &FILE), Ok(0x0000_0002), "granted before the denial");
        let deny_only = SecurityDescriptor {
            dacl: Some(Some(Acl::build(
                ACL_REVISION,
                &[
                    (ACCESS_DENIED_ACE_TYPE, 0, 0x0000_0001, POWER_USERS),
                    (ACCESS_ALLOWED_ACE_TYPE, INHERIT_ONLY_ACE, 0x0000_0004, USERS),
                    (ACCESS_ALLOWED_ACE_TYPE, 0, 0x0000_0003, USERS),
                ],
            ))),
            ..denied_first
        };
        assert_eq!(
            check(&deny_only, &token, 0x0000_0001, &FILE),
            Err(STATUS_ACCESS_DENIED),
            "a deny-only group denies"
        );
        assert_eq!(check(&deny_only, &token, 0x0000_0002, &FILE), Ok(0x0000_0002));
        assert_eq!(check(&deny_only, &token, 0x0000_0004, &FILE), Err(STATUS_ACCESS_DENIED), "inherit only");
    }

    #[test]
    fn no_dacl_grants_all_an_empty_one_nothing_but_the_owner_s() {
        let token = token();
        let unprotected = SecurityDescriptor { owner: Some(NONE), group: Some(NONE), ..Default::default() };
        assert_eq!(check(&unprotected, &token, 0x0000_0003, &FILE), Ok(0x0000_0003));
        let null = SecurityDescriptor { dacl: Some(None), ..unprotected.clone() };
        assert_eq!(check(&null, &token, AccessMask::MAXIMUM_ALLOWED.0, &FILE), Ok(0x001F_01FF));
        let empty = SecurityDescriptor { dacl: Some(Some(Acl::build(ACL_REVISION, &[]))), ..unprotected.clone() };
        assert_eq!(check(&empty, &token, 0x0000_0001, &FILE), Err(STATUS_ACCESS_DENIED));
        let owner_rights = AccessMask::READ_CONTROL.0 | AccessMask::WRITE_DAC.0;
        assert_eq!(
            check(&empty, &token, owner_rights, &FILE),
            Ok(owner_rights),
            "the owner reads and changes the DACL"
        );
        assert_eq!(check(&empty, &token, AccessMask::MAXIMUM_ALLOWED.0, &FILE), Ok(owner_rights));
        let foreign = SecurityDescriptor { owner: Some(Sid::LOCAL_SYSTEM), ..empty };
        assert_eq!(check(&foreign, &token, AccessMask::READ_CONTROL.0, &FILE), Err(STATUS_ACCESS_DENIED));
        assert_eq!(check(&foreign, &token, AccessMask::MAXIMUM_ALLOWED.0, &FILE), Err(STATUS_ACCESS_DENIED));
    }

    #[test]
    fn privileges_grant_system_security_and_ownership() {
        let token = token();
        let security = AccessMask::ACCESS_SYSTEM_SECURITY;
        assert_eq!(privilege_check(&token, security), Err(STATUS_PRIVILEGE_NOT_HELD), "held, but disabled");
        let taken = privilege_check(&token, AccessMask::WRITE_OWNER | AccessMask(1)).unwrap();
        assert_eq!(
            (taken.granted, taken.remaining, taken.used.len()),
            (AccessMask::NONE, AccessMask::WRITE_OWNER | AccessMask(1), 0)
        );
        let enable = [SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE]
            .map(|luid| Privilege { luid: Luid(luid.into()), attributes: SE_PRIVILEGE_ENABLED });
        token.adjust_privileges(PrivilegeChange::Set(&enable), None).unwrap();
        let grant = privilege_check(&token, security | AccessMask::WRITE_OWNER | AccessMask(1)).unwrap();
        assert_eq!((grant.granted, grant.remaining), (security | AccessMask::WRITE_OWNER, AccessMask(1)));
        assert_eq!(grant.used, [Luid(SE_SECURITY_PRIVILEGE.into()), Luid(SE_TAKE_OWNERSHIP_PRIVILEGE.into())]);
        let empty = SecurityDescriptor {
            owner: Some(Sid::LOCAL_SYSTEM),
            group: Some(NONE),
            dacl: Some(Some(Acl::build(ACL_REVISION, &[]))),
            ..Default::default()
        };
        let granted = access_check(&empty, &token, grant.remaining, grant.granted, &FILE);
        assert_eq!(granted, Err(STATUS_ACCESS_DENIED), "what remains is checked");
        let granted = access_check(&empty, &token, AccessMask::NONE, grant.granted, &FILE);
        assert_eq!(granted, Ok(security | AccessMask::WRITE_OWNER), "nothing remains");
    }
}
