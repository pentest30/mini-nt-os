//! La DLL système au démarrage (02 §3, §6.5) : `NTDLL.DLL` du disque RAM de
//! démarrage, où `cargo xtask` met celle de ReactOS épinglé
//! (`fetch-userland`), installée comme DLL système (`ps::system_dll`) à la
//! fin des tests de la phase 1. Elle viendra de `\SystemRoot\System32` par
//! Io (M4).

use alloc::sync::Arc;

/// Où le disque RAM de démarrage la tient.
const NTDLL: &str = "/NTDLL.DLL";

/// Installe `NTDLL.DLL` comme DLL système, si le disque RAM de démarrage la
/// tient : les processus créés ensuite la projettent, et leurs threads
/// démarrent par son `LdrInitializeThunk`.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn install_system_dll() {
    let Some(file) = read_boot_file(NTDLL) else {
        log::info!("[boot] no NTDLL.DLL on the boot disk (cargo xtask fetch-userland): no system DLL");
        return;
    };
    let size = file.len();
    match ps::system_dll::SystemDll::new(Arc::from(file)) {
        Ok(dll) => {
            log::info!(
                "[boot] NTDLL.DLL installed as the system DLL: base {:#x}, {} bytes, LdrInitializeThunk {:#x}, \
                 KiUserExceptionDispatcher {:#x}, KiUserApcDispatcher {:#x}",
                dll.base,
                size,
                dll.ldr_initialize_thunk,
                dll.user_exception_dispatcher,
                dll.user_apc_dispatcher
            );
            ps::system_dll::install(Some(dll));
        }
        Err(status) => log::error!("[boot] NTDLL.DLL refused as the system DLL: {status}"),
    }
}

/// Le fichier `path` du disque RAM de démarrage, en entier.
fn read_boot_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let mut file = io_manager::open_fat_file(path).ok()?;
    let mut bytes = alloc::vec![0u8; file.file_size as usize];
    let read = io_manager::read_fat_file_bulk(&mut file, &mut bytes).ok()?;
    (read == bytes.len()).then_some(bytes)
}
