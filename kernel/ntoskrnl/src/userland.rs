//! L'espace utilisateur au démarrage (02 §3, §6.5) : `NTDLL.DLL` et les tables
//! NLS du disque RAM de démarrage, où `cargo xtask` met celles de ReactOS
//! épinglé (`fetch-userland`), installées à la fin des tests de la phase 1
//! (`ps::system_dll`, `ps::nls`) ; puis le spike S1 : la sonde, un programme
//! natif construit dans le noyau, et les programmes natifs de test du disque
//! (`tests/native`), chacun lancé sous la DLL système. Ces fichiers viendront
//! de `\SystemRoot\System32` par Io (M4).

use alloc::sync::Arc;

/// Où le disque RAM de démarrage la tient.
const NTDLL: &str = "/NTDLL.DLL";
/// Les tables NLS du disque RAM de démarrage : pages de code ANSI et OEM,
/// casse Unicode.
const NLS_FILES: [&str; 3] = ["/C_1252.NLS", "/C_437.NLS", "/L_INTL.NLS"];

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

/// Installe les tables NLS (`ps::nls`), si le disque RAM de démarrage les
/// tient : les processus créés ensuite les projettent.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn install_nls_tables() {
    let [Some(ansi), Some(oem), Some(case)] = NLS_FILES.map(read_boot_file) else {
        log::info!("[boot] no NLS tables on the boot disk (cargo xtask fetch-userland)");
        return;
    };
    match ps::nls::NlsTables::new(&ansi, &oem, &case) {
        Ok(tables) => {
            log::info!(
                "[boot] NLS tables installed: ANSI code page {}, OEM code page {}, case table of {} bytes",
                tables.ansi_code_page,
                tables.oem_code_page,
                case.len()
            );
            ps::nls::install(Some(tables));
        }
        Err(status) => log::error!("[boot] NLS tables refused: {status}"),
    }
}

/// La base du programme natif de [`run_native_probe`].
const PROBE_BASE: u32 = 0x40_0000;
/// Son statut de sortie, s'il va au bout.
const PROBE_EXIT_STATUS: u32 = 0x5151;
/// Le chemin de son image et sa ligne de commande, dans ses paramètres.
const PROBE_PATH: &str = "C:\\WINDOWS\\system32\\s1native.exe";
const PROBE_COMMAND_LINE: &str = "s1native.exe";
/// Ce qu'il écrit par `DbgPrint`.
const PROBE_MESSAGE: &[u8] = b"[s1] hello from a native process\n\0";

/// Spike S1 (05, M3) : un programme natif construit dans le noyau, sous la
/// DLL système ([`run_native`]). Son image (sous-système NATIVE) importe
/// `DbgPrint` et `NtTerminateProcess` de `ntdll.dll` ; il écrit par
/// `DbgPrint` et se termine.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, quand aucun autre thread de Ps ne tourne.
pub fn run_native_probe() {
    run_native("probe", probe_image(), PROBE_PATH, PROBE_COMMAND_LINE, PROBE_EXIT_STATUS);
}

/// Les programmes natifs de test du disque de démarrage (`tests/native`,
/// compilés par `cargo xtask`) : leur fichier, leur chemin dans leurs
/// paramètres, et le statut de sortie qu'ils rendent s'ils vont au bout.
const BOOT_PROGRAMS: &[(&str, &str, u32)] = &[
    ("/S1HELLO.EXE", "C:\\WINDOWS\\system32\\s1hello.exe", 0x5152),
    ("/S1SEH.EXE", "C:\\WINDOWS\\system32\\s1seh.exe", 0x5153),
];

/// Lance sous la DLL système les programmes natifs de test que tient le
/// disque de démarrage ([`run_native`]).
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, quand aucun autre thread de Ps ne tourne.
pub fn run_boot_programs() {
    for &(file, path, exit_status) in BOOT_PROGRAMS {
        if let Some(image) = read_boot_file(file) {
            let name = file.trim_start_matches('/');
            run_native(name, image, path, name, exit_status);
        }
    }
}

/// Lance le programme natif `image` sous la DLL système, et attend sa fin
/// (10 s au plus) : ses paramètres sont ceux d'un programme du système
/// (`ps::ProcessParameters::system`, avec `path` et `command_line`) ; son
/// thread démarre par `LdrInitializeThunk`, qui initialise le processus et
/// lie ses imports, puis entre dans son point d'entrée avec le PEB pour
/// argument (`NtProcessStartup(PPEB)`). Journalise, sous le nom `name`, son
/// statut de sortie (`exit_status` s'il va au bout) et les appels système
/// faits, dans l'ordre de leur premier appel.
///
/// Sans DLL système, ne fait rien.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, quand aucun autre thread de Ps ne tourne.
fn run_native(name: &str, image: alloc::vec::Vec<u8>, path: &str, command_line: &str, exit_status: u32) {
    use abi::ntstatus::{NtStatus, STATUS_TIMEOUT};
    use ke::dispatcher::{ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;

    /// Dix secondes, en unités de 100 ns, relatives.
    const TIMEOUT: i64 = -10 * 1000 * 10_000;

    if ps::system_dll::current().is_none() {
        return;
    }
    let section = match mm::section::Section::create_image(Arc::from(image)) {
        Ok(section) => section,
        Err(status) => return log::error!("[s1] {name}: no image section: {status}"),
    };
    let info = section.image().expect("an image section").info;
    crate::sys::reset_service_calls();
    let started = ps::create_process(&ps::system_process(), &section, name, false).and_then(|process| {
        ps::process_parameters::write(&process, &ps::ProcessParameters::system(path, command_line))?;
        let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit)?;
        let entry = process.image_base() + info.entry_point as u32;
        ps::create_thread_with_parameter(&process, entry, process.peb(), &stack)?;
        Ok(process)
    });
    let process = match started {
        Ok(process) => process,
        Err(status) => return log::error!("[s1] {name}: the process did not start: {status}"),
    };
    // SAFETY: the object of a process held here, at PASSIVE_LEVEL.
    let waited = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(TIMEOUT),
        )
    };
    if waited == STATUS_TIMEOUT {
        log::error!("[s1] {name}: the process did not end within 10 s: terminated");
        let _ = ps::terminate_process(process.clone(), STATUS_TIMEOUT);
        // SAFETY: as above.
        unsafe {
            ke_wait_for_single_object::<KePlatform>(process.dispatcher_object(), ProcessorMode::Kernel, false, None)
        };
    }
    let status = process.exit_status();
    let calls = crate::sys::service_calls();
    log::info!(
        "[s1] {name} under the system DLL: exit status {status}{}, {} system services called",
        if status == NtStatus(exit_status) { " (the program ran to its end)" } else { "" },
        calls.len()
    );
    for call in calls {
        let first = match call.first {
            Some(crate::sys::Completion::Status(status)) => alloc::format!("returned {status}"),
            Some(crate::sys::Completion::Frame) => "returned a new context".into(),
            None => "did not return".into(),
        };
        log::info!("[s1]   {} ({:#06x}): {} calls, the first {first}", call.name, call.number, call.calls);
    }
    drop(process);
    ps::wait_for_reaper();
}

/// L'image du programme natif : `.text` à 0x1000, le message à 0x2000, les
/// imports après.
fn probe_image() -> alloc::vec::Vec<u8> {
    use pe::builder::Pe32Builder;

    let image = |text: &[u8]| {
        Pe32Builder::new(PROBE_BASE)
            .entry_point(0x1000)
            .subsystem(pe::SUBSYSTEM_NATIVE)
            .relocs_stripped()
            .section(".text", 0x1000, 0x40, text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
            .section(
                ".rdata",
                0x2000,
                PROBE_MESSAGE.len() as u32,
                PROBE_MESSAGE,
                pe::SCN_CNT_INITIALIZED_DATA | pe::SCN_MEM_READ,
            )
            .imports("ntdll.dll", &["DbgPrint", "NtTerminateProcess"])
    };
    // The slots do not depend on the code, which has a fixed size.
    let layout = image(&[0; 0x40]);
    let slot = |name| PROBE_BASE + layout.import_slot("ntdll.dll", name).expect("imported");
    let mut text = alloc::vec::Vec::with_capacity(0x40);
    let mut op = |bytes: &[u8], word: Option<u32>| {
        text.extend_from_slice(bytes);
        if let Some(word) = word {
            text.extend_from_slice(&word.to_le_bytes());
        }
    };
    op(&[0x68], Some(PROBE_BASE + 0x2000)); // push message
    op(&[0xFF, 0x15], Some(slot("DbgPrint"))); // call [DbgPrint]
    op(&[0x83, 0xC4, 0x04], None); // add esp, 4 (cdecl)
    op(&[0x68], Some(PROBE_EXIT_STATUS)); // push status
    op(&[0x6A, 0xFF], None); // push NtCurrentProcess()
    op(&[0xFF, 0x15], Some(slot("NtTerminateProcess"))); // call [NtTerminateProcess]
    op(&[0xEB, 0xFE], None); // jmp $
    text.resize(0x40, 0xCC);
    image(&text).build()
}

/// Le fichier `path` du disque RAM de démarrage, en entier.
fn read_boot_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let mut file = io_manager::open_fat_file(path).ok()?;
    let mut bytes = alloc::vec![0u8; file.file_size as usize];
    let read = io_manager::read_fat_file_bulk(&mut file, &mut bytes).ok()?;
    (read == bytes.len()).then_some(bytes)
}
