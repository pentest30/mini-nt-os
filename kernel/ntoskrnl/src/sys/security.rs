//! Les services de Se (`se`) : les jetons d'un processus et d'un thread,
//! leurs classes d'information, l'état de leurs privilèges, un jeton créé de
//! toutes pièces (NtCreateToken, celui que `lsasrv` fait pour l'utilisateur
//! qui ouvre sa session) ; les descripteurs de sécurité des objets.
//!
//! L'emprunt d'identité : un serveur prend celle d'un thread client
//! (NtImpersonateThread, comme CsrImpersonateClient), un thread prend celle
//! d'un jeton d'emprunt d'identité ou reprend la sienne (NtSetInformationThread,
//! ThreadImpersonationToken) ; NtOpenThreadToken rend alors son jeton.
//!
//! Contrôle permissif (ADR-011) : Ob accorde les droits demandés, et un
//! descripteur gardé ne refuse encore rien ; le propriétaire qu'un appelant
//! donne n'est pas comparé à son jeton. Pas encore : SeTokenCanImpersonate
//! (un thread peut emprunter tout jeton : ils viennent tous de celui de
//! System), le DACL d'une copie à l'ouverture, OpenAsSelf (sans contrôle
//! d'accès, il ne change rien), `IsImpersonating` dans le TEB,
//! NtAdjustGroupsToken, NtSetInformationToken, les SACL
//! (aucun handle n'a `ACCESS_SYSTEM_SECURITY`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::lpc::SecurityQualityOfService32;
use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_BAD_IMPERSONATION_LEVEL, STATUS_BAD_TOKEN_TYPE, STATUS_BUFFER_TOO_SMALL,
    STATUS_CANT_OPEN_ANONYMOUS, STATUS_INVALID_PARAMETER, STATUS_NOT_ALL_ASSIGNED, STATUS_NOT_IMPLEMENTED,
    STATUS_NO_SUCH_LOGON_SESSION, STATUS_NO_TOKEN, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS,
};
use abi::object::{AccessMask, ObjectAttributes32, OBJ_INHERIT};
use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
use abi::security::{
    LuidAndAttributes32, SidAndAttributes32, TokenSource32, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, SECURITY_ANONYMOUS, SECURITY_DELEGATION,
    SECURITY_IMPERSONATION, SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, SE_CREATE_TOKEN_PRIVILEGE, TOKEN_TYPE_IMPERSONATION,
    TOKEN_TYPE_PRIMARY,
};
use ke::usermem::UserPtr;
use ob::{Handle, Object, ObjectRef};
use ps::eprocess::PROCESS_QUERY_INFORMATION;
use ps::ethread::{Impersonation, THREAD_DIRECT_IMPERSONATION, THREAD_IMPERSONATE, THREAD_QUERY_INFORMATION};
use se::client::ClientToken;
use se::token::{TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY};
use se::{
    Luid, NewToken, Privilege, PrivilegeChange, SecurityDescriptor, Sid, SidAndAttributes, Token, TOKEN_OBJECT_TYPE,
};

/// Les classes de NtQueryInformationToken demandées sans être implémentées.
static UNSUPPORTED_TOKEN_CLASSES: super::ClassReport = super::ClassReport::new("NtQueryInformationToken");

/// Les privilèges que NtAdjustPrivilegesToken accepte en une fois.
const MAX_PRIVILEGES: u32 = 1024;
/// La taille d'un TOKEN_PRIVILEGES avant ses entrées.
const PRIVILEGES_HEADER: usize = 4;
const PRIVILEGE_SIZE: usize = core::mem::size_of::<LuidAndAttributes32>();

fn status(result: Result<NtStatus, NtStatus>) -> NtStatus {
    result.unwrap_or_else(|status| status)
}

/// Le jeton que désigne `handle` dans le processus courant, avec les droits
/// `access`.
fn reference_token(handle: u32, access: AccessMask) -> Result<Arc<Object<Token>>, NtStatus> {
    super::current_process().handle_table.reference_as::<Token>(Handle(handle), &TOKEN_OBJECT_TYPE, access)
}

/// ObReferenceObjectByHandle sans type attendu : l'objet de `handle`, avec
/// les droits `access`. `NtCurrentProcess()` et `NtCurrentThread()`
/// désignent le processus et le thread courants, avec tous les droits de
/// leur type.
fn reference_object(handle: u32, access: AccessMask) -> Result<ObjectRef, NtStatus> {
    let pseudo: ObjectRef = match handle {
        NT_CURRENT_PROCESS => super::current_process(),
        NT_CURRENT_THREAD => ps::ethread::current_thread().expect("a system service outside a Ps thread"),
        _ => return super::current_process().handle_table.reference(Handle(handle), None, access),
    };
    let ty = pseudo.object_type();
    if !ty.generic_mapping.all.contains(ty.generic_mapping.map(access)) {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(pseudo)
}

/// Un handle neuf sur `object` dans le processus courant, avec les droits
/// `desired` et l'attribut `OBJ_INHERIT` de `attributes`, écrit en `out`
/// (sondé d'abord) ; refermé si l'écriture faute.
fn give_new_handle(out: u32, object: ObjectRef, desired: u32, attributes: u32) -> Result<NtStatus, NtStatus> {
    let out = UserPtr::<u32>::new(out);
    out.write(&0)?;
    let process = super::current_process();
    let (handle, status) = ob::insert_object(
        ob::namespace(),
        object,
        None,
        None,
        attributes & OBJ_INHERIT,
        &process.handle_table,
        AccessMask(desired),
    )?;
    super::object::give_handle(&out, handle)?;
    Ok(status)
}

/// NtOpenProcessTokenEx : un handle sur le jeton primaire du processus
/// (`PROCESS_QUERY_INFORMATION`).
fn open_process_token(process: u32, desired: u32, attributes: u32, out: u32) -> NtStatus {
    let open = || {
        let token: ObjectRef = super::reference_process(process, PROCESS_QUERY_INFORMATION)?.primary_token();
        give_new_handle(out, token, desired, attributes)
    };
    status(open())
}

/// NtAllocateLocallyUniqueId(*Luid) : un LUID neuf (ExAllocateLocallyUniqueId,
/// `se::allocate_luid`), écrit chez l'appelant ; `lsasrv` en prend un pour
/// chaque session qu'il ouvre (LsaLogonUser, ADR-023).
pub(super) fn nt_allocate_locally_unique_id(arguments: &[u32]) -> NtStatus {
    // A LUID is LowPart then HighPart: a little-endian u64.
    status(UserPtr::<u64>::new(arguments[0]).write(&se::allocate_luid().0).map(|()| STATUS_SUCCESS))
}

/// NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle).
pub(super) fn nt_open_process_token(arguments: &[u32]) -> NtStatus {
    open_process_token(arguments[0], arguments[1], 0, arguments[2])
}

/// NtOpenProcessTokenEx(ProcessHandle, DesiredAccess, HandleAttributes,
/// *TokenHandle) : seul `OBJ_INHERIT` compte dans les attributs.
pub(super) fn nt_open_process_token_ex(arguments: &[u32]) -> NtStatus {
    open_process_token(arguments[0], arguments[1], arguments[2], arguments[3])
}

/// NtOpenThreadTokenEx : un handle sur le jeton dont le thread
/// (`THREAD_QUERY_INFORMATION`) emprunte l'identité, avec les droits
/// `desired` et l'attribut `OBJ_INHERIT` de `attributes`. Avec CopyOnOpen
/// (l'emprunt d'un serveur), le handle est celui d'une copie, au même niveau,
/// que le thread emprunte désormais (SepOpenThreadToken).
/// `STATUS_NO_TOKEN` pour un thread qui n'emprunte rien, d'après quoi
/// l'appelant prend le jeton de son processus ; `STATUS_CANT_OPEN_ANONYMOUS`
/// au niveau SecurityAnonymous.
fn open_thread_token(thread: u32, desired: u32, attributes: u32, out: u32) -> NtStatus {
    let open = || {
        ke::usermem::probe_for_write(u64::from(out), 4, 4)?;
        let thread = super::reference_thread(thread, THREAD_QUERY_INFORMATION)?;
        let impersonation = thread.impersonation().ok_or(STATUS_NO_TOKEN)?;
        if impersonation.level == SECURITY_ANONYMOUS {
            return Err(STATUS_CANT_OPEN_ANONYMOUS);
        }
        let token = if impersonation.copy_on_open {
            let copy = impersonation.token.duplicate(TOKEN_TYPE_IMPERSONATION, impersonation.level);
            thread.impersonate(Some(Impersonation { token: copy.clone(), copy_on_open: false, ..impersonation }));
            copy
        } else {
            impersonation.token
        };
        give_new_handle(out, token, desired, attributes)
    };
    status(open())
}

/// NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, *TokenHandle).
pub(super) fn nt_open_thread_token(arguments: &[u32]) -> NtStatus {
    open_thread_token(arguments[0], arguments[1], 0, arguments[3])
}

/// NtOpenThreadTokenEx(ThreadHandle, DesiredAccess, OpenAsSelf,
/// HandleAttributes, *TokenHandle).
pub(super) fn nt_open_thread_token_ex(arguments: &[u32]) -> NtStatus {
    open_thread_token(arguments[0], arguments[1], arguments[3], arguments[4])
}

/// NtImpersonateThread(ThreadHandle, ThreadToImpersonateHandle,
/// SecurityQualityOfService) : le thread serveur
/// (`THREAD_DIRECT_IMPERSONATION`) emprunte l'identité du thread client
/// (`THREAD_IMPERSONATE`), selon la qualité de service
/// (SeCreateClientSecurity puis SeImpersonateClient).
pub(super) fn nt_impersonate_thread(arguments: &[u32]) -> NtStatus {
    let [server, client, qos] = arguments[..3] else { unreachable!("3 arguments") };
    let impersonate = || {
        let qos = UserPtr::<SecurityQualityOfService32>::new(qos).read()?;
        let server = super::reference_thread(server, THREAD_DIRECT_IMPERSONATION)?;
        let client = super::reference_thread(client, THREAD_IMPERSONATE)?;
        server.impersonate(Some(client_security(&client, &qos)?));
        Ok(STATUS_SUCCESS)
    };
    status(impersonate())
}

/// L'emprunt d'identité d'un serveur qui prend celle du thread `client`,
/// selon `qos` (`se::client::client_security`, sur le jeton effectif du
/// client : celui qu'il emprunte, ou le jeton primaire de son processus) ;
/// NtOpenThreadToken en donnera une copie (CopyOnOpen).
fn client_security(client: &ps::EThread, qos: &SecurityQualityOfService32) -> Result<Impersonation, NtStatus> {
    let effective = match client.impersonation() {
        Some(own) => ClientToken { token: own.token, impersonating: Some((own.level, own.effective_only)) },
        None => ClientToken { token: client.process().primary_token(), impersonating: None },
    };
    let security = se::client::client_security(effective, qos)?;
    Ok(Impersonation {
        token: security.token,
        level: security.level,
        copy_on_open: true,
        effective_only: security.effective_only,
    })
}

/// PsAssignImpersonationToken : `thread` emprunte l'identité du jeton
/// `handle` (`TOKEN_IMPERSONATE`, un jeton d'emprunt d'identité, à son
/// niveau), ou reprend la sienne si `handle` est nul.
///
/// # Errors
/// `STATUS_BAD_TOKEN_TYPE` pour un jeton primaire.
pub(super) fn assign_impersonation_token(thread: &ps::EThread, handle: u32) -> Result<NtStatus, NtStatus> {
    if handle == 0 {
        thread.impersonate(None);
        return Ok(STATUS_SUCCESS);
    }
    let token = reference_token(handle, TOKEN_IMPERSONATE)?;
    if token.token_type() != TOKEN_TYPE_IMPERSONATION {
        return Err(STATUS_BAD_TOKEN_TYPE);
    }
    let level = token.impersonation_level();
    thread.impersonate(Some(Impersonation { token, level, copy_on_open: false, effective_only: false }));
    Ok(STATUS_SUCCESS)
}

/// NtQueryInformationToken(TokenHandle, TokenInformationClass,
/// TokenInformation, TokenInformationLength, *ReturnLength) : la classe
/// demandée (`TOKEN_QUERY`, `TOKEN_QUERY_SOURCE` pour `TokenSource`), dont
/// les pointeurs désignent la suite du tampon. La taille nécessaire va
/// toujours en `ReturnLength` ; `STATUS_BUFFER_TOO_SMALL` si le tampon est
/// plus petit. Les classes d'XP qui manquent rendent `STATUS_NOT_IMPLEMENTED`,
/// journalisé à leur premier appel ; les autres, `STATUS_INVALID_INFO_CLASS`.
pub(super) fn nt_query_information_token(arguments: &[u32]) -> NtStatus {
    let (handle, class, buffer, length, return_length) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    let query = || {
        let token = reference_token(handle, se::token::query_access(class))?;
        let information = match token.query(class, buffer) {
            Err(STATUS_NOT_IMPLEMENTED) => return Err(UNSUPPORTED_TOKEN_CLASSES.report(class)),
            other => other?,
        };
        UserPtr::<u32>::new(return_length).write(&(information.len() as u32))?;
        if (length as usize) < information.len() {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        ke::usermem::probe_for_write(u64::from(buffer), information.len(), 4)?;
        ke::usermem::copy_to_user(u64::from(buffer), &information)?;
        Ok(STATUS_SUCCESS)
    };
    status(query())
}

/// Capture le TOKEN_PRIVILEGES en `address` : son compte, puis ses entrées.
/// `STATUS_INVALID_PARAMETER` au-delà de [`MAX_PRIVILEGES`] entrées.
fn capture_privileges(address: u32) -> Result<Vec<Privilege>, NtStatus> {
    let count = UserPtr::<u32>::new(address).read()?;
    if count > MAX_PRIVILEGES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut bytes = alloc::vec![0u8; count as usize * PRIVILEGE_SIZE];
    let entries = u64::from(address) + PRIVILEGES_HEADER as u64;
    ke::usermem::probe_for_read(entries, bytes.len(), 4)?;
    ke::usermem::copy_from_user(&mut bytes, entries)?;
    let word = |at: &[u8]| u32::from_le_bytes([at[0], at[1], at[2], at[3]]);
    Ok(bytes
        .chunks_exact(PRIVILEGE_SIZE)
        .map(|entry| Privilege {
            luid: Luid(u64::from(word(&entry[4..8])) << 32 | u64::from(word(&entry[..4]))),
            attributes: word(&entry[8..]),
        })
        .collect())
}

/// NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState,
/// BufferLength, PreviousState, *ReturnLength) : active ou désactive des
/// privilèges du jeton (`TOKEN_ADJUST_PRIVILEGES`), tous désactivés avec
/// `DisableAllPrivileges` (`NewState` est alors ignoré, sinon obligatoire).
///
/// Avec `PreviousState` (et `TOKEN_QUERY`) : les privilèges qui ont changé,
/// avec leur état d'avant, et leur taille en `ReturnLength` ; si
/// `BufferLength` ne suffit pas, rien ne change et l'appel rend
/// `STATUS_BUFFER_TOO_SMALL`. `STATUS_NOT_ALL_ASSIGNED` (un succès) quand un
/// privilège demandé n'est pas dans le jeton ; les autres changent.
pub(super) fn nt_adjust_privileges_token(arguments: &[u32]) -> NtStatus {
    let (handle, new_state, buffer_length) = (arguments[0], arguments[2], arguments[3]);
    let (previous_state, return_length) = (arguments[4], arguments[5]);
    // A BOOLEAN, in the low byte of its argument.
    let disable_all = arguments[1] as u8 != 0;
    let adjust = || {
        if !disable_all && new_state == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut access = TOKEN_ADJUST_PRIVILEGES;
        if previous_state != 0 {
            access = access | TOKEN_QUERY;
            ke::usermem::probe_for_write(u64::from(previous_state), buffer_length as usize, 4)?;
            ke::usermem::probe_for_write(u64::from(return_length), 4, 4)?;
        }
        let asked = if disable_all { Vec::new() } else { capture_privileges(new_state)? };
        let token = reference_token(handle, access)?;
        let change = if disable_all { PrivilegeChange::DisableAll } else { PrivilegeChange::Set(&asked) };
        let room =
            (previous_state != 0).then(|| (buffer_length as usize).saturating_sub(PRIVILEGES_HEADER) / PRIVILEGE_SIZE);
        let required = |count: usize| (PRIVILEGES_HEADER + count * PRIVILEGE_SIZE) as u32;
        let adjusted = match token.adjust_privileges(change, room) {
            Ok(adjusted) => adjusted,
            Err(count) => {
                UserPtr::<u32>::new(return_length).write(&required(count))?;
                return Err(STATUS_BUFFER_TOO_SMALL);
            }
        };
        if previous_state != 0 {
            let size = required(adjusted.previous.len());
            UserPtr::<u32>::new(return_length).write(&size)?;
            if buffer_length < size {
                // Nothing changed: not even room for the count.
                return Err(STATUS_BUFFER_TOO_SMALL);
            }
            let mut bytes = Vec::with_capacity(size as usize);
            bytes.extend_from_slice(&(adjusted.previous.len() as u32).to_le_bytes());
            for privilege in &adjusted.previous {
                let entry = LuidAndAttributes32 { luid: privilege.luid.to_abi(), attributes: privilege.attributes };
                bytes.extend_from_slice(entry.as_bytes());
            }
            ke::usermem::copy_to_user(u64::from(previous_state), &bytes)?;
        }
        Ok(if adjusted.all_assigned { STATUS_SUCCESS } else { STATUS_NOT_ALL_ASSIGNED })
    };
    status(adjust())
}

/// Les groupes que NtCreateToken accepte dans un jeton.
const MAX_GROUPS: u32 = 1024;

/// SeCaptureSid : le SID en `at` de l'appelant.
fn capture_sid(at: u32) -> Result<Sid, NtStatus> {
    se::capture_sid(at, &mut |at, buffer| ke::usermem::copy_from_user(buffer, u64::from(at)))
}

/// Le SID_AND_ATTRIBUTES en `at` de l'appelant, et son SID.
fn capture_sid_and_attributes(at: u32) -> Result<SidAndAttributes, NtStatus> {
    let [sid, attributes] = UserPtr::<[u32; 2]>::new(at).read()?;
    Ok(SidAndAttributes { sid: capture_sid(sid)?, attributes })
}

/// Le TOKEN_GROUPS en `address` : son compte, ses entrées et leurs SID.
/// `STATUS_INVALID_PARAMETER` au-delà de [`MAX_GROUPS`] entrées.
fn capture_groups(address: u32) -> Result<Vec<SidAndAttributes>, NtStatus> {
    let count = UserPtr::<u32>::new(address).read()?;
    if count > MAX_GROUPS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let entry_size = core::mem::size_of::<SidAndAttributes32>() as u32;
    (0..count).map(|index| capture_sid_and_attributes(address.wrapping_add(4 + index * entry_size))).collect()
}

/// Le niveau d'emprunt d'identité que donne la qualité de service des
/// OBJECT_ATTRIBUTES `attributes` (SepCaptureSecurityQualityOfService) ;
/// `None` sans elle.
fn capture_qos_level(attributes: &ObjectAttributes32) -> Result<Option<u32>, NtStatus> {
    match attributes.security_quality_of_service {
        0 => Ok(None),
        at => Ok(Some(UserPtr::<SecurityQualityOfService32>::new(at).read()?.impersonation_level)),
    }
}

/// NtCreateToken(*TokenHandle, DesiredAccess, ObjectAttributes, TokenType,
/// AuthenticationId, ExpirationTime, TokenUser, TokenGroups,
/// TokenPrivileges, TokenOwner, TokenPrimaryGroup, TokenDefaultDacl,
/// TokenSource) : un jeton neuf (`se::Token::create`), tout capturé, et un
/// handle sur lui avec les droits `DesiredAccess` (et `OBJ_INHERIT` des
/// attributs). C'est ainsi que `lsasrv` fait le jeton d'un utilisateur qui
/// ouvre sa session.
///
/// Un jeton d'emprunt d'identité prend son niveau de la qualité de service
/// des attributs. `TokenOwner` et `TokenDefaultDacl` sont facultatifs (le
/// propriétaire est alors l'utilisateur, et il n'y a pas de DACL par
/// défaut), comme la DACL qu'un TOKEN_DEFAULT_DACL désigne.
///
/// # Errors
/// `STATUS_PRIVILEGE_NOT_HELD` sans `SeCreateTokenPrivilege` actif ;
/// `STATUS_BAD_TOKEN_TYPE` pour un autre type ; `STATUS_BAD_IMPERSONATION_LEVEL`
/// pour un jeton d'emprunt d'identité sans qualité de service ou d'un niveau
/// inconnu ; `STATUS_NO_SUCH_LOGON_SESSION` pour une session que le moniteur
/// de références ne connaît pas ; celles des captures et de
/// `se::Token::create`.
pub(super) fn nt_create_token(arguments: &[u32]) -> NtStatus {
    let [out, desired, attributes, token_type, authentication_id, expiration_time, user, groups, privileges, owner, primary_group, default_dacl, source] =
        arguments[..13]
    else {
        unreachable!("13 arguments")
    };
    let create = || {
        // ProbeForWriteHandle: written first, so that a NULL faults.
        UserPtr::<u32>::new(out).write(&0)?;
        if !privilege_enabled(SE_CREATE_TOKEN_PRIVILEGE) {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        if token_type != TOKEN_TYPE_PRIMARY && token_type != TOKEN_TYPE_IMPERSONATION {
            return Err(STATUS_BAD_TOKEN_TYPE);
        }
        let attributes = match attributes {
            0 => ObjectAttributes32::default(),
            at => UserPtr::<ObjectAttributes32>::new(at).read()?,
        };
        let impersonation_level = match (token_type, capture_qos_level(&attributes)?) {
            (TOKEN_TYPE_PRIMARY, _) => SECURITY_ANONYMOUS,
            (_, Some(level)) if level <= SECURITY_DELEGATION => level,
            _ => return Err(STATUS_BAD_IMPERSONATION_LEVEL),
        };
        let authentication_id = Luid(UserPtr::<u64>::new(authentication_id).read()?);
        let expiration_time = UserPtr::<i64>::new(expiration_time).read()?;
        let user = capture_sid_and_attributes(user)?;
        let groups = capture_groups(groups)?;
        let privileges = capture_privileges(privileges)?;
        let owner = match owner {
            0 => None,
            at => Some(capture_sid(UserPtr::<u32>::new(at).read()?)?),
        };
        let primary_group = capture_sid(UserPtr::<u32>::new(primary_group).read()?)?;
        let default_dacl = match default_dacl {
            0 => None,
            at => match UserPtr::<u32>::new(at).read()? {
                0 => None,
                acl => {
                    Some(se::capture_acl(acl, &mut |at, buffer| ke::usermem::copy_from_user(buffer, u64::from(at)))?)
                }
            },
        };
        let source_bytes = UserPtr::<[u8; 16]>::new(source).read()?;
        let mut source = TokenSource32::default();
        source.source_name.copy_from_slice(&source_bytes[..8]);
        source.source_identifier = Luid(u64::from_le_bytes(source_bytes[8..].try_into().expect("8 bytes"))).to_abi();
        if !se::logon::LOGON_SESSIONS.exists(authentication_id.to_abi()) {
            return Err(STATUS_NO_SUCH_LOGON_SESSION);
        }
        let token = Token::create(NewToken {
            token_type,
            impersonation_level,
            authentication_id,
            expiration_time,
            user,
            groups,
            privileges,
            owner,
            primary_group,
            default_dacl,
            source,
        })?;
        give_new_handle(out, token, desired, attributes.attributes)
    };
    status(create())
}

/// NtDuplicateToken(ExistingTokenHandle, DesiredAccess, ObjectAttributes,
/// EffectiveOnly, TokenType, *NewTokenHandle) : une copie du jeton
/// (`TOKEN_DUPLICATE`) du type `TokenType` (`se::Token::duplicate_as`), et un
/// handle sur elle avec les droits `DesiredAccess` (ceux du handle copié si
/// c'est 0, comme DuplicateTokenEx le demande) et `OBJ_INHERIT` des
/// attributs. Une copie d'emprunt d'identité prend son niveau de la qualité
/// de service des attributs (SecurityAnonymous sans elle). Avec
/// `EffectiveOnly`, seuls les groupes et privilèges actifs sont copiés.
/// ImpersonateLoggedOnUser en fait la copie d'emprunt d'identité du jeton
/// d'un utilisateur, que `winlogon` emprunte pour préparer sa session.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` pour un autre type ;
/// `STATUS_BAD_IMPERSONATION_LEVEL` pour un niveau inconnu, au-dessus de
/// celui d'un jeton d'emprunt d'identité copié, ou pour un jeton primaire
/// tiré d'un jeton d'emprunt d'identité sous SecurityImpersonation ; celles
/// des captures et du handle.
pub(super) fn nt_duplicate_token(arguments: &[u32]) -> NtStatus {
    let [existing, desired, attributes, effective_only, token_type, out] = arguments[..6] else {
        unreachable!("6 arguments")
    };
    // A BOOLEAN, in the low byte of its argument.
    let effective_only = effective_only as u8 != 0;
    let duplicate = || {
        // ProbeForWriteHandle: written first, so that a NULL faults
        // (STATUS_ACCESS_VIOLATION, as the NtDuplicateToken apitest wants).
        UserPtr::<u32>::new(out).write(&0)?;
        if token_type != TOKEN_TYPE_PRIMARY && token_type != TOKEN_TYPE_IMPERSONATION {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let attributes = match attributes {
            0 => ObjectAttributes32::default(),
            at => UserPtr::<ObjectAttributes32>::new(at).read()?,
        };
        let asked = capture_qos_level(&attributes)?;
        let level = asked.unwrap_or(SECURITY_ANONYMOUS);
        if level > SECURITY_DELEGATION {
            return Err(STATUS_BAD_IMPERSONATION_LEVEL);
        }
        let token = reference_token(existing, TOKEN_DUPLICATE)?;
        if token.token_type() == TOKEN_TYPE_IMPERSONATION {
            let above_source = asked.is_some() && level > token.impersonation_level();
            let primary_too_low =
                token_type == TOKEN_TYPE_PRIMARY && token.impersonation_level() < SECURITY_IMPERSONATION;
            if above_source || primary_too_low {
                return Err(STATUS_BAD_IMPERSONATION_LEVEL);
            }
        }
        let level = if token_type == TOKEN_TYPE_PRIMARY { SECURITY_ANONYMOUS } else { level };
        let copy = token.duplicate_as(token_type, level, effective_only);
        // DuplicateTokenEx's 0: the access the existing handle has.
        let desired = match desired {
            0 => super::current_process().handle_table.query(Handle(existing))?.0 .0,
            desired => desired,
        };
        give_new_handle(out, copy, desired, attributes.attributes)
    };
    status(duplicate())
}

/// PspSetPrimaryToken (NtSetInformationProcess, `ProcessAccessToken`) :
/// `process` prend pour jeton primaire celui de `handle`
/// (`TOKEN_ASSIGN_PRIMARY`), comme CreateProcessAsUser le fait d'un processus
/// créé suspendu (`userinit.exe`, que `msgina` lance pour l'utilisateur).
///
/// # Errors
/// `STATUS_BAD_TOKEN_TYPE` pour un jeton d'emprunt d'identité ;
/// `STATUS_PRIVILEGE_NOT_HELD` sans `SeAssignPrimaryTokenPrivilege` actif :
/// Mino ne suit pas encore la parenté des jetons (SeIsTokenChild,
/// SeIsTokenSibling), qui en dispense un jeton tiré de celui de l'appelant.
pub(super) fn assign_primary_token(process: &ps::EProcess, handle: u32) -> Result<NtStatus, NtStatus> {
    let token = reference_token(handle, TOKEN_ASSIGN_PRIMARY)?;
    if token.token_type() != TOKEN_TYPE_PRIMARY {
        return Err(STATUS_BAD_TOKEN_TYPE);
    }
    if !privilege_enabled(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE) {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    process.set_primary_token(token);
    Ok(STATUS_SUCCESS)
}

/// SeSinglePrivilegeCheck : le privilège `privilege` (`SE_*_PRIVILEGE`) est
/// actif dans le jeton primaire du processus courant (aucun thread n'emprunte
/// d'identité). Le contrôle des privilèges s'applique : l'appelant active
/// d'abord celui qu'il lui faut, comme `smss` le fait.
pub(super) fn privilege_enabled(privilege: u32) -> bool {
    super::current_process().primary_token().is_privilege_enabled(Luid(u64::from(privilege)))
}

/// SeSetSecurityAccessMask et SeQuerySecurityAccessMask : les droits que
/// demande l'écriture (`write`) ou la lecture des parties `information`
/// d'un descripteur.
fn security_access(information: u32, write: bool) -> AccessMask {
    let mut access = AccessMask::NONE;
    if information & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION) != 0 {
        access = access | if write { AccessMask::WRITE_OWNER } else { AccessMask::READ_CONTROL };
    }
    if information & DACL_SECURITY_INFORMATION != 0 {
        access = access | if write { AccessMask::WRITE_DAC } else { AccessMask::READ_CONTROL };
    }
    if information & SACL_SECURITY_INFORMATION != 0 {
        access = access | AccessMask::ACCESS_SYSTEM_SECURITY;
    }
    access
}

/// Le descripteur que garde `object`, lu ; un descripteur vide s'il n'en a
/// pas.
fn descriptor_of(stored: Option<&[u8]>) -> Result<SecurityDescriptor, NtStatus> {
    stored.map_or(Ok(SecurityDescriptor::default()), SecurityDescriptor::from_self_relative)
}

/// NtSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor) :
/// remplace les parties `SecurityInformation` du descripteur de l'objet
/// (`WRITE_OWNER` pour le propriétaire et le groupe, `WRITE_DAC` pour la
/// DACL, `ACCESS_SYSTEM_SECURITY` pour la SACL) par celles du descripteur
/// donné, absolu ou relatif, capturé et vérifié. Un objet sans descripteur
/// reçoit les parties données.
pub(super) fn nt_set_security_object(arguments: &[u32]) -> NtStatus {
    let (handle, information, address) = (arguments[0], arguments[1], arguments[2]);
    let set = || {
        let object = reference_object(handle, security_access(information, true))?;
        let new =
            SecurityDescriptor::capture(address, &mut |at, buffer| ke::usermem::copy_from_user(buffer, u64::from(at)))?;
        object.update_security_descriptor(|stored| {
            let merged = descriptor_of(stored)?.merge(information, &new)?;
            Ok(Arc::from(merged.to_self_relative()))
        })?;
        Ok(STATUS_SUCCESS)
    };
    status(set())
}

/// NtQuerySecurityObject(Handle, SecurityInformation, SecurityDescriptor,
/// Length, *LengthNeeded) : les parties demandées du descripteur de
/// l'objet (`READ_CONTROL`, `ACCESS_SYSTEM_SECURITY` pour la SACL), sous
/// forme relative ; un descripteur vide pour un objet qui n'en a pas. La
/// taille nécessaire va toujours en `LengthNeeded` ;
/// `STATUS_BUFFER_TOO_SMALL` si `Length` ne suffit pas.
pub(super) fn nt_query_security_object(arguments: &[u32]) -> NtStatus {
    let (handle, information, buffer, length, needed) =
        (arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]);
    let query = || {
        let object = reference_object(handle, security_access(information, false))?;
        let stored = object.security_descriptor();
        let bytes = descriptor_of(stored.as_deref())?.select(information).to_self_relative();
        UserPtr::<u32>::new(needed).write(&(bytes.len() as u32))?;
        if (length as usize) < bytes.len() {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        ke::usermem::probe_for_write(u64::from(buffer), bytes.len(), 4)?;
        ke::usermem::copy_to_user(u64::from(buffer), &bytes)?;
        Ok(STATUS_SUCCESS)
    };
    status(query())
}
