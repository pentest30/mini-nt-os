//! Les services du presse-papiers (`win32k::clipboard`) : NtUserOpenClipboard,
//! NtUserCloseClipboard, NtUserEmptyClipboard, NtUserSetClipboardData,
//! NtUserGetClipboardData, NtUserIsClipboardFormatAvailable,
//! NtUserCountClipboardFormats, NtUserGetClipboardOwner,
//! NtUserGetOpenClipboardWindow, NtUserGetClipboardViewer,
//! NtUserGetClipboardSequenceNumber, NtUserGetClipboardFormatName,
//! NtUserGetPriorityClipboardFormat, NtUserSetClipboardViewer,
//! NtUserChangeClipboardChain ; ce que `user32` y ajoute :
//! NtUserConvertMemHandle, NtUserCreateLocalMemHandle et EnumClipboardFormats
//! (ONEPARAM_ROUTINE_ENUMCLIPBOARDFORMATS, [`enum_clipboard_formats`]).
//!
//! Hors de NtUserCreateLocalMemHandle (un NTSTATUS), ils rendent une valeur :
//! un échec rend 0 avec l'erreur Win32 comme dernière erreur.

use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_SUCCESS};
use abi::user::cf::FIRST_REGISTERED;
use abi::user::SetClipbData32;
use abi::winerror::{dos_error, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};
use ke::usermem::{copy_from_user, copy_to_user, probe_for_read};
use win32k::clipboard::{self, Clipboard, MAX_DATA};

/// Met l'erreur Win32 `error` et rend 0.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// TRUE, ou 0 et l'erreur.
fn boolean(result: Result<(), u32>) -> NtStatus {
    match result {
        Ok(()) => NtStatus(1),
        Err(error) => fail(error),
    }
}

/// La valeur, ou 0 et l'erreur.
fn value(result: Result<u32, u32>) -> NtStatus {
    match result {
        Ok(value) => NtStatus(value),
        Err(error) => fail(error),
    }
}

/// Ce que `read` lit du presse-papiers de la station, ou 0 et l'erreur.
fn query(read: impl FnOnce(&Clipboard) -> u32) -> NtStatus {
    value(clipboard::query(read))
}

/// NtUserOpenClipboard(hWnd, Unknown1) : BOOL, le presse-papiers ouvert par
/// le thread avec la fenêtre `hWnd` (`win32k::clipboard::open`).
pub(super) fn nt_user_open_clipboard(arguments: &[u32]) -> NtStatus {
    boolean(clipboard::open(arguments[0]))
}

/// NtUserCloseClipboard() : BOOL (`win32k::clipboard::close`).
pub(super) fn nt_user_close_clipboard(_arguments: &[u32]) -> NtStatus {
    boolean(clipboard::close())
}

/// NtUserEmptyClipboard() : BOOL (`win32k::clipboard::empty`).
pub(super) fn nt_user_empty_clipboard(_arguments: &[u32]) -> NtStatus {
    boolean(clipboard::empty())
}

/// NtUserSetClipboardData(fmt, hData, scd) : HANDLE, `hData` posé pour le
/// format `fmt` (0 : un rendu différé), un objet `TYPE_CLIPDATA` si le
/// SETCLIPBDATA `scd` le dit ; 0 et l'erreur de sa lecture s'il est
/// illisible.
pub(super) fn nt_user_set_clipboard_data(arguments: &[u32]) -> NtStatus {
    let [format, handle, scd] = arguments[..3] else { unreachable!("3 arguments") };
    let mut bytes = [0u8; core::mem::size_of::<SetClipbData32>()];
    if let Err(status) = copy_from_user(&mut bytes, u64::from(scd)) {
        return fail(dos_error(status));
    }
    let scd = SetClipbData32::from_bytes(&bytes).expect("the size of SETCLIPBDATA");
    value(clipboard::set_data(format, handle, scd.global_handle != 0))
}

/// NtUserGetClipboardData(fmt, pgcd) : HANDLE, les données du format `fmt`,
/// dont le GETCLIPBDATA va en `pgcd` ; 0 si elles manquent (sans erreur,
/// comme ReactOS), et l'erreur de l'écriture si `pgcd` ne peut être écrit.
pub(super) fn nt_user_get_clipboard_data(arguments: &[u32]) -> NtStatus {
    let [format, pgcd] = arguments[..2] else { unreachable!("2 arguments") };
    match clipboard::get_data(format) {
        Ok(Some((handle, info))) => match copy_to_user(u64::from(pgcd), info.as_bytes()) {
            Ok(()) => NtStatus(handle),
            Err(status) => fail(dos_error(status)),
        },
        Ok(None) => NtStatus(0),
        Err(error) => fail(error),
    }
}

/// NtUserIsClipboardFormatAvailable(fmt) : BOOL.
pub(super) fn nt_user_is_clipboard_format_available(arguments: &[u32]) -> NtStatus {
    let format = arguments[0];
    query(|clipboard| u32::from(clipboard.is_available(format)))
}

/// NtUserCountClipboardFormats() : DWORD.
pub(super) fn nt_user_count_clipboard_formats(_arguments: &[u32]) -> NtStatus {
    query(Clipboard::count)
}

/// NtUserGetClipboardOwner() : HWND.
pub(super) fn nt_user_get_clipboard_owner(_arguments: &[u32]) -> NtStatus {
    query(Clipboard::owner)
}

/// NtUserGetOpenClipboardWindow() : HWND.
pub(super) fn nt_user_get_open_clipboard_window(_arguments: &[u32]) -> NtStatus {
    query(Clipboard::open_window)
}

/// NtUserGetClipboardViewer() : HWND.
pub(super) fn nt_user_get_clipboard_viewer(_arguments: &[u32]) -> NtStatus {
    query(Clipboard::viewer)
}

/// NtUserGetClipboardSequenceNumber() : DWORD.
pub(super) fn nt_user_get_clipboard_sequence_number(_arguments: &[u32]) -> NtStatus {
    query(Clipboard::sequence)
}

/// NtUserGetClipboardFormatName(fmt, lpszFormatName, cchMaxCount) : INT, le
/// nom du format enregistré `fmt` (un atome de USER, RegisterClipboardFormat)
/// écrit dans les `cchMaxCount` caractères du tampon, tronqué, avec son nul ;
/// le nombre de caractères écrits, nul exclu. 0 sans erreur pour un format
/// prédéfini (sous 0xC000) ; `ERROR_INVALID_PARAMETER` sans tampon ;
/// `ERROR_INVALID_HANDLE` pour un atome inconnu ; l'erreur de l'écriture.
pub(super) fn nt_user_get_clipboard_format_name(arguments: &[u32]) -> NtStatus {
    let [format, buffer, count] = arguments[..3] else { unreachable!("3 arguments") };
    if !(FIRST_REGISTERED..=0xFFFF).contains(&format) {
        return NtStatus(0);
    }
    let count = count as i32;
    if count < 1 || buffer == 0 {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let Some(name) = win32k::atom::queried_name(format as u16) else { return fail(ERROR_INVALID_HANDLE) };
    let maximum = (count as usize * 2).min(0xFFFE) as u16;
    let chars = win32k::atom::copied_name_units(name.len(), maximum);
    let bytes: Vec<u8> = name[..chars].iter().chain(core::iter::once(&0)).flat_map(|unit| unit.to_le_bytes()).collect();
    match copy_to_user(u64::from(buffer), &bytes) {
        Ok(()) => NtStatus(chars as u32),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserGetPriorityClipboardFormat(paFormatPriorityList, cFormats) : INT, le
/// premier des `cFormats` formats de la liste que le presse-papiers a ; -1
/// si aucun ; 0 s'il est vide. Une liste illisible (ou un compte négatif)
/// rend 0 et l'erreur de sa lecture.
pub(super) fn nt_user_get_priority_clipboard_format(arguments: &[u32]) -> NtStatus {
    let [list, count] = arguments[..2] else { unreachable!("2 arguments") };
    let read = |count: u32| -> Result<Vec<u32>, u32> {
        let count = i32::try_from(count).map_err(|_| dos_error(STATUS_ACCESS_VIOLATION))? as usize;
        let length = count.checked_mul(4).ok_or(dos_error(STATUS_ACCESS_VIOLATION))?;
        probe_for_read(u64::from(list), length, 4).map_err(dos_error)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
        bytes.resize(length, 0);
        copy_from_user(&mut bytes, u64::from(list)).map_err(dos_error)?;
        Ok(bytes.chunks_exact(4).map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]])).collect())
    };
    let empty = match clipboard::query(|clipboard| clipboard.count() == 0) {
        Ok(empty) => empty,
        Err(error) => return fail(error),
    };
    if empty {
        return NtStatus(0);
    }
    match read(count) {
        Ok(formats) => query(|clipboard| clipboard.priority(&formats) as u32),
        Err(error) => fail(error),
    }
}

/// NtUserSetClipboardViewer(hWndNewViewer) : HWND, la visionneuse qui la
/// suivra dans la chaîne (`win32k::clipboard::set_viewer`).
pub(super) fn nt_user_set_clipboard_viewer(arguments: &[u32]) -> NtStatus {
    value(clipboard::set_viewer(arguments[0]))
}

/// NtUserChangeClipboardChain(hWndRemove, hWndNewNext) : BOOL, ce que la
/// tête de la chaîne répond à WM_CHANGECBCHAIN
/// (`win32k::clipboard::change_chain`).
pub(super) fn nt_user_change_clipboard_chain(arguments: &[u32]) -> NtStatus {
    value(clipboard::change_chain(arguments[0], arguments[1]))
}

/// NtUserConvertMemHandle(pData, cbData) : HANDLE, un objet `TYPE_CLIPDATA`
/// des `cbData` octets de l'appelant, à son processus jusqu'à ce qu'un
/// presse-papiers le prenne ; 0 et `ERROR_NOT_ENOUGH_MEMORY` au-delà de
/// `MAX_DATA` octets ou sans mémoire, 0 et l'erreur de la lecture.
pub(super) fn nt_user_convert_mem_handle(arguments: &[u32]) -> NtStatus {
    let [address, length] = arguments[..2] else { unreachable!("2 arguments") };
    let length = length as usize;
    if length > MAX_DATA {
        return fail(ERROR_NOT_ENOUGH_MEMORY);
    }
    if let Err(status) = probe_for_read(u64::from(address), length, 1) {
        return fail(dos_error(status));
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() {
        return fail(ERROR_NOT_ENOUGH_MEMORY);
    }
    bytes.resize(length, 0);
    if let Err(status) = copy_from_user(&mut bytes, u64::from(address)) {
        return fail(dos_error(status));
    }
    let owner = ps::ethread::current_thread()
        .and_then(|thread| win32k::existing_process_info(thread.process()))
        .map_or(0, |info| info.server);
    value(clipboard::create_data(bytes, owner))
}

/// NtUserCreateLocalMemHandle(hMem, pData, cbData, pcbData) : NTSTATUS ; la
/// taille des données de l'objet `TYPE_CLIPDATA` `hMem` va en `pcbData` s'il
/// n'est pas nul, et ses `cbData` premiers octets (au plus toutes) en
/// `pData`. `STATUS_INVALID_HANDLE` pour un objet inconnu ; l'erreur d'une
/// écriture.
pub(super) fn nt_user_create_local_mem_handle(arguments: &[u32]) -> NtStatus {
    let [handle, address, length, size_address] = arguments[..4] else { unreachable!("4 arguments") };
    let Some(data) = clipboard::data(handle) else { return STATUS_INVALID_HANDLE };
    if size_address != 0 {
        if let Err(status) = copy_to_user(u64::from(size_address), &(data.len() as u32).to_le_bytes()) {
            return status;
        }
    }
    let copied = (length as usize).min(data.len());
    match copy_to_user(u64::from(address), &data[..copied]) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// EnumClipboardFormats (NtUserCallOneParam,
/// ONEPARAM_ROUTINE_ENUMCLIPBOARDFORMATS) : le format qui suit `after` (le
/// premier pour 0) ; 0 après le dernier, sans erreur (`user32` met
/// NO_ERROR avant l'appel) ; 0 et `ERROR_CLIPBOARD_NOT_OPEN` si le thread ne
/// l'a pas ouvert.
pub(super) fn enum_clipboard_formats(after: u32) -> NtStatus {
    value(clipboard::enum_formats(after))
}
