//! Les rappels de win32k vers `user32` (`ps::callback`), par la table
//! `PEB.KernelCallbackTable` que `user32` remplit à son initialisation
//! (`apfnDispatch`, `u32cb.h` de ReactOS) :
//!
//! - ClientThreadSetup ([`client_thread_setup`]), quand un thread client
//!   devient un thread GUI (`gui::convert_current_thread`) ;
//! - GetCharsetInfo ([`get_charset_info`]), quand une disposition de
//!   clavier est chargée (`keyboard::load`).
//!
//! Chaque rappel est un appel en mode utilisateur du thread courant : son
//! appelant ne tient ni verrou ni rien qu'il faille rendre si le thread se
//! termine pendant le rappel (ses trames sont alors abandonnées).

use abi::ntstatus::{NtStatus, STATUS_INFO_LENGTH_MISMATCH};
use abi::user::{CharsetInfo32, GetCharsetInfo32, USER32_CALLBACK_CLIENTTHREADSTARTUP, USER32_CALLBACK_GETCHARSETINFO};

/// co_IntClientThreadSetup : `user32` prépare le thread courant, qui vient
/// de devenir un thread GUI (User32CallClientThreadSetupFromKernel).
///
/// # Errors
/// Celles du rappel (`ps::callback::user_mode_callback`).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn client_thread_setup() -> Result<(), NtStatus> {
    ps::callback::user_mode_callback(USER32_CALLBACK_CLIENTTHREADSTARTUP, &[], 0).map(drop)
}

/// co_IntGetCharsetInfo : le jeu de caractères, la page de code ANSI et la
/// signature de police de la langue `locale` (TranslateCharsetInfo de
/// `gdi32`, avec `TCI_SRCLOCALE`).
///
/// # Errors
/// Celles du rappel ; `STATUS_INFO_LENGTH_MISMATCH` pour un résultat trop
/// court.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn get_charset_info(locale: u32) -> Result<CharsetInfo32, NtStatus> {
    let argument = GetCharsetInfo32 { locale, ..GetCharsetInfo32::default() };
    let size = argument.as_bytes().len();
    let output = ps::callback::user_mode_callback(USER32_CALLBACK_GETCHARSETINFO, argument.as_bytes(), size)?;
    GetCharsetInfo32::from_bytes(&output).map(|result| result.charset_info).ok_or(STATUS_INFO_LENGTH_MISMATCH)
}
