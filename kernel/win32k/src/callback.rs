//! Les rappels de win32k vers `user32` (`ps::callback`), par la table
//! `PEB.KernelCallbackTable` que `user32` remplit à son initialisation
//! (`apfnDispatch`, `u32cb.h` de ReactOS) :
//!
//! - ClientThreadSetup ([`client_thread_setup`]), quand un thread client
//!   devient un thread GUI (`gui::convert_current_thread`) ;
//! - GetCharsetInfo ([`get_charset_info`]), quand une disposition de
//!   clavier est chargée (`keyboard::load`) ;
//! - WindowProc ([`window_proc`]), un message envoyé à une fenêtre dont la
//!   procédure est dans le client (`window::send_message`).
//!
//! Chaque rappel est un appel en mode utilisateur du thread courant : son
//! appelant ne tient ni verrou ni rien qu'il faille rendre si le thread se
//! termine pendant le rappel (ses trames sont alors abandonnées).

use core::mem::{offset_of, size_of};

use abi::ntstatus::{NtStatus, STATUS_INFO_LENGTH_MISMATCH};
use abi::user::{
    CharsetInfo32, GetCharsetInfo32, WindowProcArguments32, USER32_CALLBACK_CLIENTTHREADSTARTUP,
    USER32_CALLBACK_GETCHARSETINFO, USER32_CALLBACK_WINDOWPROC,
};

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

/// co_IntCallWindowProc : la procédure du client `arguments.proc` reçoit le
/// message (User32CallWindowProcFromKernel) ; rend ce qu'elle a rendu.
/// `buffer`, s'il y en a un, suit les arguments (`lParam` le désigne dans
/// le client : `l_param_buffer_size` est mis à sa longueur) ; avec
/// `write_back`, il reprend ce que la procédure y a laissé.
///
/// # Errors
/// Celles du rappel ; `STATUS_INFO_LENGTH_MISMATCH` pour une réponse trop
/// courte.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn window_proc(
    mut arguments: WindowProcArguments32,
    buffer: Option<&mut [u8]>,
    write_back: bool,
) -> Result<u32, NtStatus> {
    arguments.l_param_buffer_size = buffer.as_ref().map_or(-1, |buffer| buffer.len() as i32);
    let mut bytes = arguments.as_bytes().to_vec();
    if let Some(buffer) = &buffer {
        bytes.extend_from_slice(buffer);
    }
    let output = ps::callback::user_mode_callback(USER32_CALLBACK_WINDOWPROC, &bytes, bytes.len())?;
    let header = size_of::<WindowProcArguments32>();
    let at = offset_of!(WindowProcArguments32, result);
    if output.len() < header {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let result = u32::from_le_bytes([output[at], output[at + 1], output[at + 2], output[at + 3]]);
    if let (true, Some(buffer)) = (write_back, buffer) {
        let returned = &output[header..];
        let length = returned.len().min(buffer.len());
        buffer[..length].copy_from_slice(&returned[..length]);
    }
    Ok(result)
}
