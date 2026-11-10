//! Les paramètres régionaux par défaut (`ex/locale.c` de ReactOS, comme
//! spécification) : PsDefaultSystemLocaleId et PsDefaultThreadLocaleId, que
//! rend NtQueryDefaultLocale.
//!
//! Celui du système vient de la valeur `Default` de
//! `CurrentControlSet\Control\Nls\Language` (une chaîne hexadécimale,
//! `0409`), que le noyau lit une fois la ruche SYSTEM montée
//! ([`set_system_locale`]) ; sans elle, 0x0409 (anglais, États-Unis), comme
//! ReactOS ; NtSetDefaultLocale le change (`ntoskrnl::sys::locale`). Celui de
//! l'utilisateur est le même : il viendra de son profil (`HKCU`), que le
//! registre n'a pas encore ; il les séparera.

use core::sync::atomic::{AtomicU32, Ordering};

/// Les paramètres régionaux d'avant le registre : anglais, États-Unis.
pub const DEFAULT_LOCALE: u32 = 0x0409;

/// PsDefaultSystemLocaleId, et PsDefaultThreadLocaleId (ceux de
/// l'utilisateur) tant que rien ne les sépare.
static SYSTEM_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);

/// L'identifiant que dit la chaîne `text` (des chiffres hexadécimaux, un
/// LCID de 16 bits, comme `Nls\Language\Default`) ; `None` pour une autre
/// chaîne, ou 0.
pub fn parse_locale(text: &str) -> Option<u32> {
    let text = text.trim_end_matches('\0');
    if text.is_empty() || text.len() > 8 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(text, 16).ok().filter(|&locale| locale != 0 && locale <= 0xFFFF)
}

/// Les paramètres régionaux du système deviennent `locale` (ceux de
/// l'utilisateur aussi).
///
/// # IRQL
/// Tout niveau.
pub fn set_system_locale(locale: u32) {
    SYSTEM_LOCALE.store(locale, Ordering::Relaxed);
}

/// Les paramètres régionaux du système, qui sont aussi ceux de
/// l'utilisateur.
///
/// # IRQL
/// Tout niveau.
pub fn default_locale() -> u32 {
    SYSTEM_LOCALE.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locale_is_four_hexadecimal_digits() {
        assert_eq!(parse_locale("0409"), Some(0x0409));
        assert_eq!(parse_locale("040c\0"), Some(0x040C), "the string's terminator");
        assert_eq!(parse_locale(""), None);
        assert_eq!(parse_locale("0000"), None);
        assert_eq!(parse_locale("en-US"), None);
        assert_eq!(parse_locale("10409"), None, "beyond 16 bits");
    }

    #[test]
    fn the_locale_is_the_one_set() {
        assert_eq!(default_locale(), DEFAULT_LOCALE);
        set_system_locale(0x040C);
        assert_eq!(default_locale(), 0x040C);
        set_system_locale(DEFAULT_LOCALE);
    }
}
