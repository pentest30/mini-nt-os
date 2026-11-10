//! NtQueryDefaultLocale et NtSetDefaultLocale, sur les paramètres régionaux
//! d'Ex (`ex::locale`) ; [`load_system_locale`] les prend dans le registre.
//!
//! La spécification suivie est ReactOS 0.4.16 (`ntoskrnl/ex/locale.c`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS};
use ke::usermem::UserPtr;

/// La clé de la valeur `Default` : les paramètres régionaux du système.
const LANGUAGE_KEY: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language";
/// Les paramètres régionaux connus, par LCID (`%08lx`) : leur groupe de
/// langues.
const LOCALE_KEY: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Locale";
/// Les groupes de langues : `1` pour un groupe installé.
const LANGUAGE_GROUPS_KEY: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language Groups";

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
/// groupe de langues, qui est installé (`Language Groups`) ;
/// `STATUS_INVALID_PARAMETER` sinon.
fn validate_locale(locale: u32) -> Result<(), NtStatus> {
    let group = read_string(LOCALE_KEY, &format!("{locale:08x}")).filter(|group| !group.is_empty());
    let installed = group.and_then(|group| read_string(LANGUAGE_GROUPS_KEY, &group));
    match installed.as_deref() {
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
/// l'utilisateur si `UserProfile`, sinon ceux du système ; les mêmes tant
/// que NtSetDefaultLocale n'est pas là (`ex::locale`).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub(super) fn nt_query_default_locale(arguments: &[u32]) -> NtStatus {
    let [_user_profile, out] = arguments[..2] else { unreachable!("2 arguments") };
    match UserPtr::<u32>::new(out).write(&ex::locale::default_locale()) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// NtSetDefaultLocale(UserProfile, DefaultLocaleId) : les paramètres
/// régionaux du système (`UserProfile` faux) deviennent `DefaultLocaleId`,
/// écrit dans `Nls\Language\Default` (`%04x`) une fois validé
/// (ExpValidateNlsLocaleId) ; 0 les relit de cette valeur. Un LCID qui a des
/// bits au-dessus de 16, ou que `Nls` ne connaît pas installé :
/// `STATUS_INVALID_PARAMETER`. Ceux de l'utilisateur (`UserProfile`) vont
/// dans son profil (`HKCU\Control Panel\International`), que le registre n'a
/// pas encore (`\REGISTRY\USER` n'est pas monté) :
/// `STATUS_OBJECT_NAME_NOT_FOUND`.
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
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
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
