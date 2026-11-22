//! Les paramètres régionaux par défaut (`ex/locale.c` de ReactOS, comme
//! spécification) : PsDefaultSystemLocaleId et PsDefaultThreadLocaleId, que
//! rend NtQueryDefaultLocale.
//!
//! Celui du système vient de la valeur `Default` de
//! `CurrentControlSet\Control\Nls\Language` (une chaîne hexadécimale,
//! `0409`), que le noyau lit une fois la ruche SYSTEM montée
//! ([`set_system_locale`]) ; sans elle, 0x0409 (anglais, États-Unis), comme
//! ReactOS ; NtSetDefaultLocale le change (`ntoskrnl::sys::locale`). Celui de
//! l'utilisateur suit celui du système jusqu'à ce que NtSetDefaultLocale le
//! fixe ([`set_user_locale`]) depuis son profil (`HKCU\Control
//! Panel\International`), à l'ouverture de sa session.
//!
//! La langue de l'interface d'installation (PsInstallUILanguageId, que rend
//! NtQueryInstallUILanguage) vient de la valeur `InstallLanguage` de la même
//! clé ([`set_install_ui_language`]) ; sans elle, la langue des paramètres
//! régionaux du système. Celle de l'utilisateur (NtQueryDefaultUILanguage)
//! est lue dans son profil à chaque appel, la langue d'installation à défaut.

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// Les paramètres régionaux d'avant le registre : anglais, États-Unis.
pub const DEFAULT_LOCALE: u32 = 0x0409;

/// PsDefaultSystemLocaleId.
static SYSTEM_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);

/// PsDefaultThreadLocaleId ; 0 tant qu'il suit celui du système.
static USER_LOCALE: AtomicU32 = AtomicU32::new(0);

/// PsInstallUILanguageId : LANGIDFROMLCID(0x00000409) avant le registre.
static INSTALL_UI_LANGUAGE: AtomicU16 = AtomicU16::new(DEFAULT_LOCALE as u16);

/// L'identifiant que dit la chaîne `text` (des chiffres hexadécimaux, un
/// LCID de 16 bits, comme `Nls\Language\Default` ou le `Locale` d'un
/// profil, `00000409`) ; `None` pour une autre chaîne, ou 0.
pub fn parse_locale(text: &str) -> Option<u32> {
    let text = text.trim_end_matches('\0');
    if text.is_empty() || text.len() > 8 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(text, 16).ok().filter(|&locale| locale != 0 && locale <= 0xFFFF)
}

/// RtlUnicodeStringToInteger(`text`, 16), comme ExpGetCurrentUserUILanguage
/// lit `MultiUILanguageId` : des blancs, un signe, puis les chiffres
/// hexadécimaux jusqu'au premier autre caractère (aucun : 0), la valeur
/// coupée à 16 bits (le `(USHORT)` de ReactOS).
pub fn parse_ui_language(text: &str) -> u16 {
    let text = text.trim_start_matches(|c: char| c <= ' ');
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let value = digits
        .chars()
        .map_while(|c| c.to_digit(16))
        .fold(0u32, |value, digit| value.wrapping_mul(16).wrapping_add(digit));
    (if negative { value.wrapping_neg() } else { value }) as u16
}

/// La langue d'installation devient `language`.
///
/// # IRQL
/// Tout niveau.
pub fn set_install_ui_language(language: u16) {
    INSTALL_UI_LANGUAGE.store(language, Ordering::Relaxed);
}

/// PsInstallUILanguageId.
///
/// # IRQL
/// Tout niveau.
pub fn install_ui_language() -> u16 {
    INSTALL_UI_LANGUAGE.load(Ordering::Relaxed)
}

/// Les paramètres régionaux du système deviennent `locale`.
///
/// # IRQL
/// Tout niveau.
pub fn set_system_locale(locale: u32) {
    SYSTEM_LOCALE.store(locale, Ordering::Relaxed);
}

/// Les paramètres régionaux de l'utilisateur deviennent `locale` ; ils ne
/// suivent plus ceux du système.
///
/// # IRQL
/// Tout niveau.
pub fn set_user_locale(locale: u32) {
    USER_LOCALE.store(locale, Ordering::Relaxed);
}

/// Les paramètres régionaux du système.
///
/// # IRQL
/// Tout niveau.
pub fn system_locale() -> u32 {
    SYSTEM_LOCALE.load(Ordering::Relaxed)
}

/// Les paramètres régionaux de l'utilisateur : ceux du système tant que
/// rien ne les a fixés.
///
/// # IRQL
/// Tout niveau.
pub fn user_locale() -> u32 {
    match USER_LOCALE.load(Ordering::Relaxed) {
        0 => system_locale(),
        locale => locale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locale_is_hexadecimal_digits() {
        assert_eq!(parse_locale("0409"), Some(0x0409));
        assert_eq!(parse_locale("00000409"), Some(0x0409), "as a profile keeps it");
        assert_eq!(parse_locale("040c\0"), Some(0x040C), "the string's terminator");
        assert_eq!(parse_locale(""), None);
        assert_eq!(parse_locale("0000"), None);
        assert_eq!(parse_locale("en-US"), None);
        assert_eq!(parse_locale("10409"), None, "beyond 16 bits");
    }

    #[test]
    fn a_ui_language_is_read_as_rtl_unicode_string_to_integer_reads_it() {
        assert_eq!(parse_ui_language("0409"), 0x0409);
        assert_eq!(parse_ui_language("00000407\0"), 0x0407, "with its terminator");
        assert_eq!(parse_ui_language("  40c"), 0x040C, "blanks first");
        assert_eq!(parse_ui_language("0413 junk"), 0x0413, "up to the first other character");
        assert_eq!(parse_ui_language("10409"), 0x0409, "cut to 16 bits");
        assert_eq!(parse_ui_language(""), 0);
        assert_eq!(parse_ui_language("en-US"), 0x0E, "e is a digit, n is not");
    }

    #[test]
    fn the_install_language_is_kept() {
        assert_eq!(install_ui_language(), 0x0409, "before the registry");
        set_install_ui_language(0x0407);
        assert_eq!(install_ui_language(), 0x0407);
        set_install_ui_language(0x0409);
    }

    #[test]
    fn the_user_follows_the_system_until_set() {
        assert_eq!((system_locale(), user_locale()), (DEFAULT_LOCALE, DEFAULT_LOCALE));
        set_system_locale(0x040C);
        assert_eq!((system_locale(), user_locale()), (0x040C, 0x040C), "the user follows");
        set_user_locale(0x0407);
        set_system_locale(DEFAULT_LOCALE);
        assert_eq!((system_locale(), user_locale()), (DEFAULT_LOCALE, 0x0407), "set apart");
        set_user_locale(0);
    }
}
