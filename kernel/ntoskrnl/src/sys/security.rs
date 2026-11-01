//! Les services de Se (`se`) : les jetons d'un processus et d'un thread,
//! leurs classes d'information, l'état de leurs privilèges ; les
//! descripteurs de sécurité des objets.
//!
//! Contrôle permissif (ADR-011) : Ob accorde les droits demandés, et un
//! descripteur gardé ne refuse encore rien ; le propriétaire qu'un appelant
//! donne n'est pas comparé à son jeton. Pas encore : l'emprunt d'identité
//! (un thread n'a jamais de jeton à lui), NtDuplicateToken,
//! NtAdjustGroupsToken, NtSetInformationToken, les SACL (aucun handle n'a
//! `ACCESS_SYSTEM_SECURITY`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_NOT_ALL_ASSIGNED,
    STATUS_NOT_IMPLEMENTED, STATUS_NO_TOKEN, STATUS_SUCCESS,
};
use abi::object::{AccessMask, OBJ_INHERIT};
use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
use abi::security::{
    LuidAndAttributes32, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
};
use ke::usermem::UserPtr;
use ob::{Handle, Object, ObjectRef};
use ps::eprocess::PROCESS_QUERY_INFORMATION;
use ps::ethread::THREAD_QUERY_INFORMATION;
use se::token::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
use se::{Luid, Privilege, PrivilegeChange, SecurityDescriptor, Token, TOKEN_OBJECT_TYPE};

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

/// NtOpenProcessToken(ProcessHandle, DesiredAccess, *TokenHandle).
pub(super) fn nt_open_process_token(arguments: &[u32]) -> NtStatus {
    open_process_token(arguments[0], arguments[1], 0, arguments[2])
}

/// NtOpenProcessTokenEx(ProcessHandle, DesiredAccess, HandleAttributes,
/// *TokenHandle) : seul `OBJ_INHERIT` compte dans les attributs.
pub(super) fn nt_open_process_token_ex(arguments: &[u32]) -> NtStatus {
    open_process_token(arguments[0], arguments[1], arguments[2], arguments[3])
}

/// NtOpenThreadTokenEx : le jeton d'emprunt d'identité du thread
/// (`THREAD_QUERY_INFORMATION`). Aucun thread n'en a encore :
/// `STATUS_NO_TOKEN`, d'après quoi l'appelant prend le jeton de son
/// processus.
fn open_thread_token(thread: u32, out: u32) -> NtStatus {
    let open = || {
        ke::usermem::probe_for_write(u64::from(out), 4, 4)?;
        super::reference_thread(thread, THREAD_QUERY_INFORMATION)?;
        Err(STATUS_NO_TOKEN)
    };
    status(open())
}

/// NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, *TokenHandle).
pub(super) fn nt_open_thread_token(arguments: &[u32]) -> NtStatus {
    open_thread_token(arguments[0], arguments[3])
}

/// NtOpenThreadTokenEx(ThreadHandle, DesiredAccess, OpenAsSelf,
/// HandleAttributes, *TokenHandle).
pub(super) fn nt_open_thread_token_ex(arguments: &[u32]) -> NtStatus {
    open_thread_token(arguments[0], arguments[4])
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
