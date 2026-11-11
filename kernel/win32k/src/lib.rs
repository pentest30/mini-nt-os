//! win32k (02 §7.2) : la partie du sous-système Win32 dans le noyau, en
//! Rust. Ses clients sont les DLL de ReactOS épinglé (`user32`, `gdi32`), qui
//! l'appellent par la seconde table de services et lisent en lecture seule ce
//! qu'il partage avec eux (ADR-002).
//!
//! Pour l'instant, ce qui fait d'un processus un client de USER :
//! - [`shared`] : la section partagée de USER (`SERVERINFO`, la table des
//!   handles), à des adresses du serveur sur 32 bits (ADR-021) ;
//! - [`gui`] : les processus et threads GUI (`PROCESSINFO`, `THREADINFO`),
//!   créés au premier appel d'un thread à win32k, et le `CLIENTINFO` de son
//!   TEB ;
//! - [`process_connect`] : NtUserProcessConnect ;
//! - [`client`] : les procédures de fenêtre du client
//!   (NtUserInitializeClientPfnArrays) ;
//! - [`csrss`] : le démarrage de USER par `csrss` (NtUserInitialize), son
//!   port d'API ;
//! - [`logon`] : le processus de logon (RegisterLogonProcess) ;
//! - [`winsta`] : les stations de fenêtres ;
//! - [`desktop`] : les bureaux et leurs tas ; le bureau d'un thread GUI
//!   ([`gui`]) ;
//! - [`keyboard`] : les dispositions de clavier ;
//! - [`callback`] : les rappels vers `user32` (KeUserModeCallback).
//!
//! Le reste (stations et bureaux, fenêtres, messages, GDI) viendra avec le
//! spike S3 et le M6 (05).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod atom;
pub mod callback;
pub mod caret;
pub mod class;
pub mod client;
pub mod console;
pub mod csrss;
pub mod cursor;
pub mod dce;
pub mod defwnd;
pub mod desktop;
pub mod destroy;
pub mod display;
pub mod font;
pub mod gdi;
pub mod gui;
pub mod handles;
pub mod input;
pub mod kbdtables;
pub mod keyboard;
pub mod logon;
pub mod menu;
pub mod menubar;
pub mod menupopup;
pub mod menutrack;
pub mod metrics;
pub mod monitor;
pub mod mouse;
pub mod nonclient;
pub mod paint;
pub mod queue;
pub mod scroll;
pub mod scrollex;
pub mod sent;
pub mod shared;
pub mod sizemove;
pub mod startup;
pub mod timer;
pub mod window;
pub mod winpos;
pub mod winsta;

use alloc::sync::Arc;
use core::mem::{offset_of, size_of};

use abi::ntstatus::{NtStatus, STATUS_DATATYPE_MISALIGNMENT, STATUS_UNSUCCESSFUL};
use abi::user::{SharedInfo32, UserConnect32, WndMsg32, FNID_NUM};
use ob::Object;
use ps::EProcess;

pub use gui::{convert_current_thread, existing_process_info, process_info, ProcessInfo, ThreadInfo};

/// Le `SHAREDINFO` d'un client dont la vue de la section partagée est en
/// `view` : le `SERVERINFO` et la table des handles dans sa vue (comme
/// `SERVER_TO_CLIENT` de ReactOS), l'écart qui mène des adresses du serveur,
/// celles que la section contient, à sa vue ; ni `DISPLAYINFO` ni messages
/// de classes encore (comme ReactOS).
pub fn shared_info(view: u32) -> SharedInfo32 {
    let delta = shared::shared_delta(view);
    SharedInfo32 {
        psi: shared::server_address(shared::SERVER_INFO).wrapping_sub(delta),
        ahe_list: shared::server_address(shared::HANDLE_TABLE).wrapping_sub(delta),
        disp_info: 0,
        shared_delta: delta,
        aw_control: [WndMsg32::default(); FNID_NUM],
        def_window_msgs: WndMsg32::default(),
        def_window_spec_msgs: WndMsg32::default(),
    }
}

/// NtUserProcessConnect, une fois le processus référencé : `process`
/// devient un processus GUI s'il ne l'est pas, et le `USERCONNECT` du client
/// en `buffer` (dans le processus courant) reçoit son `SHAREDINFO`
/// ([`shared_info`]). `ulVersion` n'est pas vérifiée (ReactOS ne le fait
/// pas).
///
/// # Errors
/// `STATUS_UNSUCCESSFUL` pour un tampon nul ou qui n'a pas la taille d'un
/// `USERCONNECT` (à vérifier avant le handle : [`check_connect_buffer`]) ;
/// `STATUS_DATATYPE_MISALIGNMENT` pour un tampon qui n'est pas aligné sur 4
/// octets ; `STATUS_ACCESS_VIOLATION` si l'écriture faute ; celles de
/// [`process_info`].
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn process_connect(process: &Arc<Object<EProcess>>, buffer: u32) -> Result<(), NtStatus> {
    let info = process_info(process)?;
    if !buffer.is_multiple_of(4) {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    let shared = shared_info(info.shared_view);
    let at = u64::from(buffer) + offset_of!(UserConnect32, si_client) as u64;
    ke::usermem::copy_to_user(at, shared.as_bytes())
}

/// Le tampon de NtUserProcessConnect : non nul, de la taille d'un
/// `USERCONNECT` ; `STATUS_UNSUCCESSFUL` sinon.
pub fn check_connect_buffer(buffer: u32, size: u32) -> Result<(), NtStatus> {
    if buffer == 0 || size as usize != size_of::<UserConnect32>() {
        return Err(STATUS_UNSUCCESSFUL);
    }
    Ok(())
}

/// UserSetLastError (EngSetLastError) : la dernière erreur Win32 du thread
/// courant, dans son TEB (`LastErrorValue`, que lit GetLastError).
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` hors d'un thread de Ps ;
/// `STATUS_ACCESS_VIOLATION` si l'écriture faute.
///
/// # IRQL
/// PASSIVE_LEVEL, dans le thread.
pub fn set_last_error(error: u32) -> Result<(), NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(abi::ntstatus::STATUS_INVALID_PARAMETER)?;
    let at = u64::from(thread.teb()) + offset_of!(abi::teb32::Teb32, last_error_value) as u64;
    ke::usermem::copy_to_user(at, &error.to_le_bytes())
}

/// Crée la section partagée de USER, la table des handles GDI et ses
/// objets de stock (les pinceaux, dont ceux des couleurs du système, dans
/// le `SERVERINFO`) ; Ps exécutera les lots de GDI d'un thread au retour de
/// ses rappels (PsEstablishWin32Callouts, `BatchFlushRoutine`).
///
/// # Panics
/// Au second appel.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, Mm prêt.
pub fn init() -> Result<(), NtStatus> {
    shared::init()?;
    // InitUserAtoms: the system's atoms come before any class's.
    cursor::init_atoms();
    gdi::handles::init()?;
    gdi::brush::init(&metrics::SYSTEM_COLORS)?;
    ps::callback::set_gdi_batch_flush(gdi::batch::flush);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_is_told_where_the_shared_structures_are() {
        let shared = shared_info(0x7F5F_0000);
        assert_eq!((shared.psi, shared.ahe_list, shared.disp_info), (0x7F5F_0000, 0x7F5F_1000, 0), "in the view");
        // SharedPtrToUser(handles): a server address in the section.
        let handles = shared::initial_handle_table().handles;
        assert_eq!(handles.wrapping_sub(shared.shared_delta), 0x7F5F_1010);
        assert!(shared.aw_control.iter().all(|m| *m == WndMsg32::default()));
    }

    #[test]
    fn the_buffer_is_a_userconnect() {
        assert_eq!(check_connect_buffer(0x1000, 0x124), Ok(()));
        assert_eq!(check_connect_buffer(0, 0x124), Err(STATUS_UNSUCCESSFUL));
        assert_eq!(check_connect_buffer(0x1000, 0x120), Err(STATUS_UNSUCCESSFUL));
    }
}
