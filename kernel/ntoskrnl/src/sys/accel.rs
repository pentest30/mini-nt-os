//! Les services des tables d'accélérateurs (`win32k::accel`) :
//! NtUserCreateAcceleratorTable, NtUserCopyAcceleratorTable,
//! NtUserDestroyAcceleratorTable, NtUserTranslateAccelerator.

use alloc::vec::Vec;
use core::mem::size_of;

use abi::ntstatus::NtStatus;
use abi::user::{Accel32, WM_CHAR, WM_KEYDOWN, WM_SYSCHAR, WM_SYSKEYDOWN};
use abi::winerror::{dos_error, ERROR_INVALID_ACCEL_HANDLE, ERROR_INVALID_WINDOW_HANDLE};
use ke::usermem::{copy_from_user, copy_to_user, probe_for_read, probe_for_write};
use win32k::accel::{self, Accel};

/// Met l'erreur Win32 `error` et rend 0.
fn fail(error: u32) -> NtStatus {
    let _ = win32k::set_last_error(error);
    NtStatus(0)
}

/// Les entrées de la table `handle` ; `ERROR_INVALID_ACCEL_HANDLE` sans
/// elle (UserGetAccelObject).
fn table(handle: u32) -> Result<Vec<Accel>, NtStatus> {
    accel::entries(handle).ok_or_else(|| fail(ERROR_INVALID_ACCEL_HANDLE))
}

/// NtUserCreateAcceleratorTable(Entries, EntriesCount) : une table des
/// `EntriesCount` ACCEL de l'appelant (`win32k::accel::create`) ; rend son
/// handle. 0 sans entrée, pour des entrées illisibles (l'erreur de la
/// copie) ou une table des handles pleine.
pub(super) fn nt_user_create_accelerator_table(arguments: &[u32]) -> NtStatus {
    let (address, count) = (arguments[0], arguments[1]);
    if address == 0 || count == 0 {
        return NtStatus(0);
    }
    let Some(length) = (count as usize).checked_mul(size_of::<Accel32>()) else { return NtStatus(0) };
    let mut bytes = alloc::vec![0u8; length];
    let read =
        probe_for_read(u64::from(address), length, 4).and_then(|()| copy_from_user(&mut bytes, u64::from(address)));
    if let Err(status) = read {
        return fail(dos_error(status));
    }
    let entries = bytes
        .chunks_exact(size_of::<Accel32>())
        .map(|entry| {
            let user = Accel32 {
                f_virt: entry[0],
                pad: entry[1],
                key: u16::from_le_bytes([entry[2], entry[3]]),
                cmd: u16::from_le_bytes([entry[4], entry[5]]),
            };
            Accel::from_user(&user)
        })
        .collect();
    match accel::create(entries) {
        Ok(handle) => NtStatus(handle),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserCopyAcceleratorTable(hAccel, Entries, EntriesCount) : le nombre
/// d'entrées de la table sans `Entries` ; sinon ses `EntriesCount` premières
/// entrées (au plus toutes) y sont écrites, et leur nombre rendu. 0 pour une
/// table inconnue (`ERROR_INVALID_ACCEL_HANDLE`) ou un tampon où l'on ne
/// peut écrire (l'erreur de la copie).
pub(super) fn nt_user_copy_accelerator_table(arguments: &[u32]) -> NtStatus {
    let (handle, address, count) = (arguments[0], arguments[1], arguments[2]);
    let entries = match table(handle) {
        Ok(entries) => entries,
        Err(status) => return status,
    };
    if address == 0 {
        return NtStatus(entries.len() as u32);
    }
    let count = (count as usize).min(entries.len());
    let bytes: Vec<u8> = entries[..count]
        .iter()
        .flat_map(|entry| {
            let user = entry.to_user();
            let [key0, key1] = user.key.to_le_bytes();
            let [cmd0, cmd1] = user.cmd.to_le_bytes();
            [user.f_virt, 0, key0, key1, cmd0, cmd1]
        })
        .collect();
    let written =
        probe_for_write(u64::from(address), bytes.len(), 4).and_then(|()| copy_to_user(u64::from(address), &bytes));
    match written {
        Ok(()) => NtStatus(count as u32),
        Err(status) => fail(dos_error(status)),
    }
}

/// NtUserDestroyAcceleratorTable(hAccel) : la table est rendue ; FALSE pour
/// une table inconnue (`ERROR_INVALID_ACCEL_HANDLE`).
pub(super) fn nt_user_destroy_accelerator_table(arguments: &[u32]) -> NtStatus {
    if accel::destroy(arguments[0]) {
        NtStatus(1)
    } else {
        fail(ERROR_INVALID_ACCEL_HANDLE)
    }
}

/// NtUserTranslateAccelerator(hWnd, hAccel, pMsg) : 1 si le message est un
/// accélérateur de la table pour la fenêtre (`win32k::accel::translate`,
/// qui envoie ce qu'il faut), 0 sinon : sans fenêtre, pour un message qui
/// n'est pas une touche enfoncée ou un caractère, une table inconnue
/// (`ERROR_INVALID_ACCEL_HANDLE`), une fenêtre inconnue
/// (`ERROR_INVALID_WINDOW_HANDLE`) ou un message illisible (l'erreur de la
/// copie).
pub(super) fn nt_user_translate_accelerator(arguments: &[u32]) -> NtStatus {
    let (handle, table_handle, message) = (arguments[0], arguments[1], arguments[2]);
    if handle == 0 {
        return NtStatus(0);
    }
    let message = match super::message::read_message(message) {
        Ok(message) => message,
        Err(status) => return fail(dos_error(status)),
    };
    if !matches!(message.message, WM_KEYDOWN | WM_SYSKEYDOWN | WM_SYSCHAR | WM_CHAR) {
        return NtStatus(0);
    }
    let entries = match table(table_handle) {
        Ok(entries) => entries,
        Err(status) => return status,
    };
    let Some(window) = win32k::window::get(handle) else { return fail(ERROR_INVALID_WINDOW_HANDLE) };
    let Ok(thread) = win32k::convert_current_thread() else { return NtStatus(0) };
    NtStatus(u32::from(accel::translate(&thread, &window, &entries, &message)))
}
