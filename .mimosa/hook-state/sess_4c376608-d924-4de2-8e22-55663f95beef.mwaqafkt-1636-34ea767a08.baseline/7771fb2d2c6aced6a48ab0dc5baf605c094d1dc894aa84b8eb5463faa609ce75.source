//! NtQueryDefaultLocale, sur les paramètres régionaux d'Ex
//! (`ex::locale`) ; [`load_system_locale`] les prend dans le registre.

use abi::ntstatus::{NtStatus, STATUS_SUCCESS};
use ke::usermem::UserPtr;

/// La clé de la valeur `Default` : les paramètres régionaux du système.
const LANGUAGE_KEY: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language";

/// Prend les paramètres régionaux du système (et de l'utilisateur) dans la
/// valeur `Default` de `Nls\Language`, de la ruche SYSTEM montée ; les garde
/// à 0x0409 sans elle, ou si elle n'est pas un LCID. Rend ceux qu'il garde.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn load_system_locale() -> u32 {
    let units: alloc::vec::Vec<u16> = "Default".encode_utf16().collect();
    let read = ob::namespace()
        .open(LANGUAGE_KEY, None, Some(&cm::KEY_TYPE), 0)
        .ok()
        .and_then(|object| ob::downcast::<cm::Key>(&object))
        .and_then(|key| key.value(&units).ok().flatten())
        .map(|value| {
            let text: alloc::vec::Vec<u16> =
                value.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            alloc::string::String::from_utf16_lossy(&text)
        });
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
