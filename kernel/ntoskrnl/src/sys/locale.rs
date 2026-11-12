//! NtQueryDefaultLocale et NtSetDefaultLocale, sur les paramètres régionaux
//! d'Ex (`ex::locale`), du système et de l'utilisateur ;
//! [`load_system_locale`] prend ceux du système dans le registre, ceux de
//! l'utilisateur viennent de son profil.
//!
//! La spécification suivie est ReactOS 0.4.16 (`ntoskrnl/ex/locale.c`).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS};
use ke::usermem::UserPtr;
use ob::Object;

/// La clé de la valeur `Default` : les paramètres régionaux du système.
const LANGUAGE_KEY: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language";
/// Les paramètres régionaux connus, par LCID (`%08lx`) : leur groupe de
/// langues.
const LOCALE_KEY: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Locale";
/// Les groupes de langues : `1` pour un groupe installé.
const LANGUAGE_GROUPS_KEY: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language Groups";

/// Les ruches des utilisateurs.
const USERS_KEY: &str = "\\REGISTRY\\USER";
/// Les paramètres régionaux d'un utilisateur, sous sa ruche.
const INTERNATIONAL_KEY: &str = "Control Panel\\International";

/// REG_SZ.
const REG_SZ: u32 = 1;

/// Les bits qu'un LCID n'a jamais (BOGUS_LOCALE_ID).
const BOGUS_LOCALE_ID: u32 = 0xFFFF_0000;

/// La chaîne de la valeur `name` de la clé `path`, sans ses NUL de fin ;
/// `None` sans la clé ou sans la valeur.
fn read_string(path: &str, name: &str) -> Option<String> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let value = ob::namespace()
        .open(path, None, Some(&cm::KEY_TYPE), abi::object::OBJ_CASE_INSENSITIVE)
        .ok()
        .and_then(|object| ob::downcast::<cm::Key>(&object))
        .and_then(|key| key.value(&units).ok().flatten())?;
    let text: Vec<u16> = value.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(&text).trim_end_matches('\0').into())
}

/// ExpValidateNlsLocaleId : `Nls\Locale` connaît `locale` et nomme son
/// groupe de langues, qui est installé (`Language Groups`).
///
/// # Errors
/// `STATUS_OBJECT_NAME_NOT_FOUND` pour un LCID que `Nls\Locale` ne connaît
/// pas (sa valeur introuvable, comme l'apitest NtSetDefaultLocale l'attend
/// d'XP) ; `STATUS_INVALID_PARAMETER` pour un groupe vide ou qui n'est pas
/// installé.
fn validate_locale(locale: u32) -> Result<(), NtStatus> {
    let group = read_string(LOCALE_KEY, &format!("{locale:08x}")).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    if group.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    match read_string(LANGUAGE_GROUPS_KEY, &group).as_deref() {
        Some("1") => Ok(()),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Prend les paramètres régionaux du système (et de l'utilisateur) dans la
/// valeur `Default` de `Nls\Language`, de la ruche SYSTEM montée ; les garde
/// à 0x0409 sans elle, ou si elle n'est pas un LCID. Rend ceux qu'il garde.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn load_system_locale() -> u32 {
    let read = read_string(LANGUAGE_KEY, "Default");
    let locale = read.as_deref().and_then(ex::locale::parse_locale).unwrap_or(ex::locale::DEFAULT_LOCALE);
    ex::locale::set_system_locale(locale);
    locale
}

/// NtQueryDefaultLocale(UserProfile, *DefaultLocaleId) : ceux de
/// l'utilisateur si `UserProfile` (ceux du système tant que
/// NtSetDefaultLocale ne les a pas fixés), sinon ceux du système
/// (`ex::locale`).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub(super) fn nt_query_default_locale(arguments: &[u32]) -> NtStatus {
    let [user_profile, out] = arguments[..2] else { unreachable!("2 arguments") };
    // A BOOLEAN, in the low byte of its argument.
    let locale = if user_profile as u8 != 0 { ex::locale::user_locale() } else { ex::locale::system_locale() };
    match UserPtr::<u32>::new(out).write(&locale) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// RtlOpenCurrentUser, puis `Control Panel\International` : la clé des
/// paramètres régionaux de l'utilisateur du jeton effectif du thread (celui
/// qu'il emprunte, sinon le jeton primaire de son processus), sous
/// `\REGISTRY\USER\<SID>` ; sous `\REGISTRY\USER\.DEFAULT` si sa ruche n'est
/// pas chargée.
fn user_international_key() -> Result<Arc<Object<cm::Key>>, NtStatus> {
    let open = |path: &str| ob::namespace().open(path, None, Some(&cm::KEY_TYPE), abi::object::OBJ_CASE_INSENSITIVE);
    let thread = ps::ethread::current_thread().expect("a system service outside a Ps thread");
    let token = match thread.impersonation() {
        Some(impersonation) => impersonation.token,
        None => thread.process().primary_token(),
    };
    let user = format!("{USERS_KEY}\\{}", token.user().sid);
    let root = if open(&user).is_ok() { user } else { format!("{USERS_KEY}\\.DEFAULT") };
    let key = open(&format!("{root}\\{INTERNATIONAL_KEY}"))?;
    ob::downcast::<cm::Key>(&key).ok_or(abi::ntstatus::STATUS_OBJECT_TYPE_MISMATCH)
}

/// La branche `UserProfile` de NtSetDefaultLocale : 0 relit `Locale` du
/// profil ; un autre LCID, validé, y est écrit (`%08x`).
fn set_user_locale(locale: u32) -> Result<(), NtStatus> {
    let key = user_international_key()?;
    let name: Vec<u16> = "Locale".encode_utf16().collect();
    if locale == 0 {
        let value = key.value(&name)?.ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let text: Vec<u16> = value.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let read = ex::locale::parse_locale(&String::from_utf16_lossy(&text)).ok_or(STATUS_INVALID_PARAMETER)?;
        ex::locale::set_user_locale(read);
        return Ok(());
    }
    validate_locale(locale)?;
    let text: Vec<u8> = format!("{locale:08x}\0").encode_utf16().flat_map(u16::to_le_bytes).collect();
    key.set_value(&name, REG_SZ, text)?;
    ex::locale::set_user_locale(locale);
    Ok(())
}

/// NtSetDefaultLocale(UserProfile, DefaultLocaleId) : les paramètres
/// régionaux du système (`UserProfile` faux) deviennent `DefaultLocaleId`,
/// écrit dans `Nls\Language\Default` (`%04x`) une fois validé
/// (ExpValidateNlsLocaleId) ; 0 les relit de cette valeur. Un LCID qui a des
/// bits au-dessus de 16, ou dont le groupe de langues n'est pas installé :
/// `STATUS_INVALID_PARAMETER` ; que `Nls\Locale` ne connaît pas :
/// `STATUS_OBJECT_NAME_NOT_FOUND`. Ceux de l'utilisateur (`UserProfile`) vont, de
/// même, dans la valeur `Locale` de son profil ([`user_international_key`] :
/// `HKCU\Control Panel\International`), que `winlogon` relit et redonne à
/// l'ouverture de sa session (SetDefaultLanguage) ; sans cette clé, l'erreur
/// de son ouverture.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub(super) fn nt_set_default_locale(arguments: &[u32]) -> NtStatus {
    let [user_profile, locale] = arguments[..2] else { unreachable!("2 arguments") };
    let set = || {
        if locale & BOGUS_LOCALE_ID != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // A BOOLEAN, in the low byte of its argument.
        if user_profile as u8 != 0 {
            return set_user_locale(locale);
        }
        if locale == 0 {
            load_system_locale();
            return Ok(());
        }
        validate_locale(locale)?;
        let key = ob::namespace().open(LANGUAGE_KEY, None, Some(&cm::KEY_TYPE), abi::object::OBJ_CASE_INSENSITIVE)?;
        let key = ob::downcast::<cm::Key>(&key).ok_or(abi::ntstatus::STATUS_OBJECT_TYPE_MISMATCH)?;
        let text: Vec<u8> = format!("{:04x}\0", locale & 0xFFFF).encode_utf16().flat_map(u16::to_le_bytes).collect();
        let name: Vec<u16> = "Default".encode_utf16().collect();
        key.set_value(&name, REG_SZ, text)?;
        ex::locale::set_system_locale(locale);
        Ok(())
    };
    set().map_or_else(|status| status, |()| STATUS_SUCCESS)
}
