//! La section partagée de USER (02 §7.2) : ce que win32k écrit et que
//! chaque processus GUI lit par une vue en lecture seule. Elle tient le
//! `SERVERINFO` (sa première page) puis la table des handles USER (sa tête,
//! puis 4096 entrées, comme `UserCreateHandleTable` de ReactOS), et dans ce
//! qui reste, le tas partagé ([`alloc`], UserHeapAlloc) : les propriétés des
//! fenêtres, que `user32` lit lui-même (GetProp).
//!
//! Les pointeurs qu'elle contient sont des *adresses du serveur* sur 32 bits
//! (ADR-021) : la section y est en [`SERVER_BASE`], et un client y retrouve
//! un octet en ôtant `ulSharedDelta`, l'écart entre cette adresse et celle
//! de sa vue ([`shared_delta`]). `NtUserProcessConnect` lui rend le
//! `SERVERINFO` et la table des handles déjà dans sa vue. Le noyau, en 64 bits, l'écrit par l'alias de ses pages
//! (`mm::section::Section::write_kernel`).

use alloc::sync::Arc;
use core::mem::size_of;

use hal::sync::KSpinLock;

use abi::ntstatus::NtStatus;
use abi::user::{ServerInfoHead32, UserHandleEntry32, UserHandleTable32, FNID_NUM, FNID_NUMSERVERPROC};
use hal::sync::Once;
use mm::address_space::AddressSpace;
use mm::section::Section;
use mm::vad::PageProtect;

/// L'adresse du serveur de la section : celle que voient ses pointeurs. Dans
/// la moitié haute des 4 Gio, où un client ne peut rien lire : un pointeur
/// du serveur suivi tel quel fait une faute, comme sur XP.
pub const SERVER_BASE: u32 = 0xBC00_0000;
/// La taille de la section.
pub const SIZE: u32 = 0x1_0000;
/// Le `SERVERINFO`, au début de la section.
pub const SERVER_INFO: u32 = 0;
/// La tête de la table des handles (`USER_HANDLE_TABLE`), sur la seconde
/// page.
pub const HANDLE_TABLE: u32 = 0x1000;
/// La première entrée de la table, juste après sa tête.
pub const HANDLE_ENTRIES: u32 = HANDLE_TABLE + size_of::<UserHandleTable32>() as u32;
/// Les entrées de la table (`UserCreateHandleTable` : 1024 * 4).
pub const HANDLE_COUNT: u32 = 4096;

/// Le tas partagé, après la table des handles, jusqu'au bout de la section.
pub const HEAP: u32 = (HANDLE_ENTRIES + HANDLE_COUNT * size_of::<UserHandleEntry32>() as u32).next_multiple_of(16);

const _: () = {
    assert!(size_of::<ServerInfoHead32>() as u32 <= HANDLE_TABLE, "SERVERINFO fits in its page");
    assert!(HEAP + 0x2000 <= SIZE, "at least 8 KiB of shared heap");
};

/// Le granule d'un bloc du tas partagé.
const HEAP_GRANULARITY: u32 = 8;
/// Ses plages libres, créées au premier besoin.
static HEAP_FREE: KSpinLock<Option<crate::desktop::FreeRanges>> = KSpinLock::new(None);

/// UserHeapAlloc : `size` octets du tas partagé, à zéro ; rend leur place
/// dans la section. `None` s'il est plein ou avant [`init`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn alloc(size: u32) -> Option<u32> {
    let section = section()?;
    let offset = HEAP_FREE
        .lock()
        .get_or_insert_with(|| crate::desktop::FreeRanges::new(HEAP, SIZE - HEAP))
        .take(size.max(1), HEAP_GRANULARITY)?;
    let zeros = alloc::vec![0u8; size as usize];
    if section.write_kernel(u64::from(offset), &zeros).is_err() {
        free(offset, size);
        return None;
    }
    Some(offset)
}

/// UserHeapFree : rend le bloc de `size` octets en `offset` du tas partagé.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn free(offset: u32, size: u32) {
    if let Some(ranges) = HEAP_FREE.lock().as_mut() {
        ranges.give(offset, size.max(1), HEAP_GRANULARITY);
    }
}

/// L'adresse du serveur de l'octet `offset` de la section.
pub const fn server_address(offset: u32) -> u32 {
    SERVER_BASE + offset
}

/// ulSharedDelta d'un client dont la vue de la section est en `view` : ce
/// qu'il ôte à une adresse du serveur pour lire le même octet chez lui. Le
/// calcul se fait modulo 2^32, comme chez lui.
pub const fn shared_delta(view: u32) -> u32 {
    SERVER_BASE.wrapping_sub(view)
}

/// Le début du `SERVERINFO` à la création : aucune entrée de la table
/// n'est prise, aucun drapeau (`SRVINFO_IMM32` éteint : pas d'IME).
pub fn initial_server_info() -> ServerInfoHead32 {
    ServerInfoHead32 {
        srvi_flags: 0,
        handle_entries: 0,
        mp_fnid_pfn: [0; FNID_NUM],
        a_sto_cid_pfn: [0; FNID_NUMSERVERPROC],
        mp_fnid_server_cb_wnd_proc: [0; FNID_NUM],
        padding: 0,
        apfn_client_a: [0; 23],
        apfn_client_w: [0; 23],
        apfn_client_worker: [0; 11],
        cb_handle_table: 0,
    }
}

/// La tête de la table des handles à la création (UserInitHandleTable) :
/// ses entrées juste après elle, aucune prise, aucune libérée.
pub fn initial_handle_table() -> UserHandleTable32 {
    UserHandleTable32 {
        handles: server_address(HANDLE_ENTRIES),
        freelist: 0,
        nb_handles: 0,
        allocated_handles: HANDLE_COUNT as i32,
    }
}

/// La section, une fois créée.
static SECTION: Once<Arc<Section>> = Once::new();

/// Crée la section (des pages du fichier d'échange, à zéro) et y écrit le
/// `SERVERINFO` et la tête de la table des handles.
///
/// # Panics
/// Au second appel.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn init() -> Result<(), NtStatus> {
    assert!(SECTION.get().is_none(), "the USER shared section created twice");
    let section = Section::create_pagefile(u64::from(SIZE), PageProtect::READWRITE)?;
    section.write_kernel(u64::from(SERVER_INFO), initial_server_info().as_bytes())?;
    section.write_kernel(u64::from(HANDLE_TABLE), initial_handle_table().as_bytes())?;
    SECTION.call_once(|| section);
    Ok(())
}

/// La section ; `None` avant [`init`].
///
/// # IRQL
/// Tout niveau.
pub fn section() -> Option<&'static Arc<Section>> {
    SECTION.get()
}

/// Projette la section en lecture seule dans `space`, au plus haut ; rend
/// l'adresse de la vue. `STATUS_UNSUCCESSFUL` avant [`init`].
///
/// # IRQL
/// <= APC_LEVEL.
pub fn map_into(space: &AddressSpace) -> Result<u32, NtStatus> {
    let section = section().ok_or(abi::ntstatus::STATUS_UNSUCCESSFUL)?;
    let view = space.map_view_top_down(section, 0, 0, u64::from(SIZE), PageProtect::READONLY)?;
    Ok(view.base as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_finds_server_bytes_by_the_delta() {
        let view = 0x7F5F_0000;
        let delta = shared_delta(view);
        assert_eq!(delta, 0x3CA1_0000);
        // SharedPtrToUser: the server address less the delta.
        assert_eq!(server_address(HANDLE_TABLE).wrapping_sub(delta), view + HANDLE_TABLE);
        // A view above the server base: the delta wraps, as on the client.
        assert_eq!(server_address(0x10).wrapping_sub(shared_delta(0xC000_0000)), 0xC000_0010);
    }

    #[test]
    fn the_handle_table_starts_empty_after_its_head() {
        let table = initial_handle_table();
        assert_eq!(table.handles, 0xBC00_1010);
        assert_eq!((table.freelist, table.nb_handles, table.allocated_handles), (0, 0, 4096));
        assert_eq!(initial_server_info().handle_entries, 0);
        assert!(initial_server_info().as_bytes().iter().all(|&b| b == 0));
    }
}
