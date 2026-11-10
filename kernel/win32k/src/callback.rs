//! Les rappels de win32k vers `user32` (`ps::callback`), par la table
//! `PEB.KernelCallbackTable` que `user32` remplit à son initialisation
//! (`apfnDispatch`, `u32cb.h` de ReactOS) :
//!
//! - ClientThreadSetup ([`client_thread_setup`]), quand un thread client
//!   devient un thread GUI (`gui::convert_current_thread`) ;
//! - GetCharsetInfo ([`get_charset_info`]), quand une disposition de
//!   clavier est chargée (`keyboard::load`) ;
//! - LoadMenu ([`load_menu`]), le menu de la classe d'une fenêtre créée
//!   sans menu (`window::create_window`) ;
//! - WindowProc ([`window_proc`]), un message envoyé à une fenêtre dont la
//!   procédure est dans le client (`window::send_message`).
//!
//! Chaque rappel est un appel en mode utilisateur du thread courant : son
//! appelant ne tient ni verrou ni rien qu'il faille rendre si le thread se
//! termine pendant le rappel (ses trames sont alors abandonnées).

use alloc::vec::Vec;
use core::mem::{offset_of, size_of};

use abi::ntstatus::{NtStatus, STATUS_INFO_LENGTH_MISMATCH};
use abi::user::{
    CharsetInfo32, GetCharsetInfo32, WindowProcArguments32, USER32_CALLBACK_CLIENTTHREADSTARTUP,
    USER32_CALLBACK_GETCHARSETINFO, USER32_CALLBACK_LOADMENU, USER32_CALLBACK_WINDOWPROC,
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

/// Une ressource de menu : un identifiant (MAKEINTRESOURCE) ou un nom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuResource<'a> {
    Id(u16),
    /// Sans le nul.
    Name(&'a [u16]),
}

/// LOADMENU_CALLBACK_ARGUMENTS : le module, l'identifiant (0 pour un nom),
/// puis le nom terminé par un nul ; 12 octets au moins (la structure avec
/// son premier caractère, alignée).
fn load_menu_argument(module: u32, resource: MenuResource<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&module.to_le_bytes());
    match resource {
        MenuResource::Id(id) => bytes.extend_from_slice(&u32::from(id).to_le_bytes()),
        MenuResource::Name(name) => {
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend(name.iter().flat_map(|unit| unit.to_le_bytes()));
        }
    }
    bytes.resize((bytes.len() + 2).max(12), 0);
    bytes
}

/// co_IntCallLoadMenu : `user32` charge la ressource de menu `resource` du
/// module `module` (User32CallLoadMenuFromKernel : LoadMenuW) ; rend le
/// handle du menu, 0 s'il ne l'a pas trouvé.
///
/// # Errors
/// Celles du rappel ; `STATUS_INFO_LENGTH_MISMATCH` pour un résultat trop
/// court.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn load_menu(module: u32, resource: MenuResource<'_>) -> Result<u32, NtStatus> {
    let argument = load_menu_argument(module, resource);
    let output = ps::callback::user_mode_callback(USER32_CALLBACK_LOADMENU, &argument, size_of::<u32>())?;
    match output[..] {
        [a, b, c, d, ..] => Ok(u32::from_le_bytes([a, b, c, d])),
        _ => Err(STATUS_INFO_LENGTH_MISMATCH),
    }
}

/// co_IntLoadDefaultCursors : `user32` charge les curseurs du système
/// (User32SetupDefaultCursors : LoadSystemCursors, chaque curseur posé par
/// NtUserSetSystemCursor), puis fait de la flèche le curseur du thread
/// courant ; rend la flèche, 0 si `user32` n'en rend pas.
///
/// # Errors
/// Celles du rappel.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn load_default_cursors() -> Result<u32, NtStatus> {
    // L'argument : BOOL DefaultCursor, vrai.
    let output = ps::callback::user_mode_callback(
        abi::user::USER32_CALLBACK_LOADDEFAULTCURSORS,
        &1u32.to_le_bytes(),
        size_of::<u32>(),
    )?;
    Ok(match output[..] {
        [a, b, c, d, ..] => u32::from_le_bytes([a, b, c, d]),
        _ => 0,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_menu_takes_an_identifier_or_a_name_after_the_module() {
        let by_id = load_menu_argument(0x77A2_0000, MenuResource::Id(0x65));
        assert_eq!(by_id, [0x00, 0x00, 0xA2, 0x77, 0x65, 0, 0, 0, 0, 0, 0, 0], "the structure, 12 bytes");
        let name = [u16::from(b'M'), u16::from(b'E')];
        let by_name = load_menu_argument(0x0040_0000, MenuResource::Name(&name));
        assert_eq!(
            by_name,
            [0x00, 0x00, 0x40, 0x00, 0, 0, 0, 0, b'M', 0, b'E', 0, 0, 0],
            "no identifier, the name at 8 and its nul"
        );
        let empty = load_menu_argument(1, MenuResource::Name(&[]));
        assert_eq!(empty.len(), 12, "never shorter than the structure");
    }
}
