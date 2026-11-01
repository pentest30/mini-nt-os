//! L'espace utilisateur au démarrage (02 §3, §6.5) : `NTDLL.DLL` et les tables
//! NLS du disque RAM de démarrage, où `cargo xtask` met celles de ReactOS
//! épinglé (`fetch-userland`), installées à la fin des tests de la phase 1
//! (`ps::system_dll`, `ps::nls`) ; puis le spike S1 : la sonde, un programme
//! natif construit dans le noyau, et les programmes natifs de test du disque
//! (`tests/native`), chacun lancé sous la DLL système. Les fichiers viennent
//! du volume système par Io (`\SystemRoot\System32`, `\??\C:`) : le disque
//! RAM de démarrage, qui les range comme le volume système (02 §9.1).

use alloc::sync::Arc;

/// La DLL système.
const NTDLL: &str = "\\SystemRoot\\System32\\ntdll.dll";
/// Les tables NLS : pages de code ANSI et OEM, casse Unicode.
const NLS_FILES: [&str; 3] =
    ["\\SystemRoot\\System32\\c_1252.nls", "\\SystemRoot\\System32\\c_437.nls", "\\SystemRoot\\System32\\l_intl.nls"];
/// La ruche SYSTEM.
const SYSTEM_HIVE: &str = "\\SystemRoot\\System32\\config\\SYSTEM";

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

/// Monte la ruche SYSTEM du disque RAM de démarrage en
/// `\REGISTRY\MACHINE\SYSTEM` (`cm::mount_system_hive`), si le disque la tient :
/// en attendant `tools/mkhive` (ADR-012), celle que la version épinglée de
/// ReactOS a générée de ses `.inf`. Elle viendra de `\SystemRoot\System32\Config`,
/// chargée par le chargeur (ADR-017).
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn mount_system_hive() {
    let Some(hive) = read_boot_file(SYSTEM_HIVE) else {
        return log::info!("[boot] no SYSTEM hive on the boot disk (cargo xtask fetch-userland)");
    };
    let size = hive.len();
    match cm::mount_system_hive(Arc::from(hive), Some(SYSTEM_HIVE)) {
        Ok(current) => log::info!(
            "[boot] SYSTEM hive mounted at \\REGISTRY\\MACHINE\\SYSTEM: {size} bytes, CurrentControlSet = ControlSet{current:03}"
        ),
        Err(status) => log::error!("[boot] SYSTEM hive refused: {status}"),
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
    let params = ps::ProcessParameters::system(PROBE_PATH, PROBE_COMMAND_LINE);
    run_native("s1", "probe", probe_image(), &params, Some(PROBE_EXIT_STATUS));
}

/// Les programmes natifs de test du disque de démarrage (`tests/native`,
/// compilés par `cargo xtask`) : leur fichier, leur chemin dans leurs
/// paramètres, et le statut de sortie qu'ils rendent s'ils vont au bout.
const BOOT_PROGRAMS: &[(&str, &str, u32)] = &[
    ("\\??\\C:\\S1HELLO.EXE", "C:\\WINDOWS\\system32\\s1hello.exe", 0x5152),
    ("\\??\\C:\\S1SEH.EXE", "C:\\WINDOWS\\system32\\s1seh.exe", 0x5153),
];

/// Lance sous la DLL système les programmes natifs de test que tient le
/// disque de démarrage ([`run_native`]).
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, quand aucun autre thread de Ps ne tourne.
pub fn run_boot_programs() {
    for &(file, path, exit_status) in BOOT_PROGRAMS {
        if let Some(image) = read_boot_file(file) {
            let name = file.rsplit('\\').next().unwrap_or(file);
            run_native("s1", name, image, &ps::ProcessParameters::system(path, name), Some(exit_status));
        }
    }
}

/// Le gestionnaire de session du disque de démarrage.
const SMSS: &str = "\\SystemRoot\\System32\\smss.exe";

/// M4, découverte : lance le `smss.exe` de ReactOS sous la DLL système
/// ([`run_native`]), avec les paramètres que le noyau donne au premier
/// processus (chemin NT de l'image, `Path` et `SystemRoot`), et journalise
/// les appels système qu'il fait et comment il s'arrête. Il attend `csrss` et
/// `winlogon`, qu'il ne peut pas encore lancer : il est terminé au bout de
/// 10 s s'il ne s'est pas arrêté avant.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, quand aucun autre thread de Ps ne tourne.
pub fn run_smss_probe() {
    let Some(image) = read_boot_file(SMSS) else {
        return log::info!("[m4] no SMSS.EXE on the boot disk (cargo xtask fetch-userland)");
    };
    let params = ps::ProcessParameters {
        image_path_name: "\\SystemRoot\\System32\\smss.exe",
        command_line: "\\SystemRoot\\System32\\smss.exe",
        current_directory: "C:\\WINDOWS\\system32\\",
        dll_path: "C:\\WINDOWS\\system32",
        window_title: "",
        desktop_info: "",
        environment: &["Path=C:\\WINDOWS\\system32", "SystemRoot=C:\\WINDOWS"],
    };
    run_native("m4", "SMSS.EXE", image, &params, None);
    log_known_dlls();
    log_environment();
}

/// Journalise les variables que `smss` a écrites dans
/// `Session Manager\Environment` : celles qu'il tire du processeur.
fn log_environment() {
    const ENVIRONMENT: &str = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    const WRITTEN: [&str; 6] = [
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_LEVEL",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_REVISION",
        "NUMBER_OF_PROCESSORS",
    ];
    let Some(key) = ob::namespace()
        .open(ENVIRONMENT, None, Some(&cm::KEY_TYPE), 0)
        .ok()
        .and_then(|object| ob::downcast::<cm::Key>(&object))
    else {
        return log::warn!("[m4] no Session Manager\\Environment key");
    };
    let found: alloc::vec::Vec<alloc::string::String> = WRITTEN
        .iter()
        .filter_map(|name| {
            let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
            let value = key.value(&units).ok().flatten()?;
            let text: alloc::vec::Vec<u16> =
                value.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
            Some(alloc::format!("{name}={}", alloc::string::String::from_utf16_lossy(&text)))
        })
        .collect();
    log::info!("[m4] Environment: {} of {} variables written: {}", found.len(), WRITTEN.len(), found.join(", "));
}

/// Journalise ce que `smss` a mis dans `\KnownDlls` : les sections d'image
/// des KnownDLLs (permanentes), et le lien `KnownDllPath`.
fn log_known_dlls() {
    let Ok(directory) = ob::namespace().open("\\KnownDlls", None, Some(&ob::DIRECTORY_TYPE), 0) else {
        return log::warn!("[m4] no \\KnownDlls directory");
    };
    let entries = ob::downcast::<ob::Directory>(&directory).expect("a directory").entries();
    let sections: alloc::vec::Vec<&str> =
        entries.iter().filter(|(_, ty)| *ty == mm::section::SECTION_TYPE.name).map(|(name, _)| name.as_str()).collect();
    let path = ob::namespace()
        .open("\\KnownDlls\\KnownDllPath", None, Some(&ob::SYMBOLIC_LINK_TYPE), abi::object::OBJ_OPENLINK)
        .ok()
        .and_then(|link| ob::downcast::<ob::SymbolicLink>(&link));
    log::info!(
        "[m4] \\KnownDlls: {} sections ({}), KnownDllPath -> {}",
        sections.len(),
        sections.join(", "),
        path.as_ref().map_or("none", |link| link.target())
    );
}

/// Lance le programme natif `image` sous la DLL système, avec les paramètres
/// `params`, et attend sa fin (10 s au plus) : son thread démarre par
/// `LdrInitializeThunk`, qui initialise le processus et lie ses imports, puis
/// entre dans son point d'entrée avec le PEB pour argument
/// (`NtProcessStartup(PPEB)`). Journalise, avec le préfixe `[tag]` et sous le
/// nom `name`, son statut de sortie (`exit_status` s'il va au bout), celui de
/// chaque processus qu'il a créé (attendu 2 s, puis terminé), et les appels
/// système faits par eux tous, dans l'ordre de leur premier appel.
///
/// Sans DLL système, ne fait rien.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, quand aucun autre thread de Ps ne tourne.
fn run_native(
    tag: &str,
    name: &str,
    image: alloc::vec::Vec<u8>,
    params: &ps::ProcessParameters<'_>,
    exit_status: Option<u32>,
) {
    use abi::ntstatus::{NtStatus, STATUS_TIMEOUT};
    use ke::dispatcher::{ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;

    /// Dix secondes, en unités de 100 ns, relatives.
    const TIMEOUT: i64 = -10 * 1000 * 10_000;
    /// Deux secondes de plus pour chacun des processus qu'il a créés.
    const CHILD_TIMEOUT: i64 = -2 * 1000 * 10_000;

    if ps::system_dll::current().is_none() {
        return;
    }
    let section = match mm::section::Section::create_image(Arc::from(image)) {
        Ok(section) => section,
        Err(status) => return log::error!("[{tag}] {name}: no image section: {status}"),
    };
    let info = section.image().expect("an image section").info;
    crate::sys::reset_service_calls();
    let started = ps::create_process(&ps::system_process(), &section, name, false).and_then(|process| {
        ps::process_parameters::write(&process, params)?;
        let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit)?;
        let entry = process.image_base() + info.entry_point as u32;
        ps::create_thread_with_parameter(&process, entry, process.peb(), &stack)?;
        Ok(process)
    });
    let process = match started {
        Ok(process) => process,
        Err(status) => return log::error!("[{tag}] {name}: the process did not start: {status}"),
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
    // The processes it created, while its handles still hold those that
    // ended.
    let children = ps::child_processes(process.pid());
    if waited == STATUS_TIMEOUT {
        log::warn!("[{tag}] {name}: the process did not end within 10 s: terminated");
        let _ = ps::terminate_process(process.clone(), STATUS_TIMEOUT);
        // SAFETY: as above.
        unsafe {
            ke_wait_for_single_object::<KePlatform>(process.dispatcher_object(), ProcessorMode::Kernel, false, None)
        };
    }
    let status = process.exit_status();
    log::info!(
        "[{tag}] {name} under the system DLL: exit status {status}{}",
        if exit_status.map(NtStatus) == Some(status) { " (the program ran to its end)" } else { "" },
    );
    // The processes it created (smss: csrss) end too, terminated after 2 s.
    for child in children {
        let (child_name, pid) = (child.image_file_name(), child.pid());
        // SAFETY: the object of a process held here, at PASSIVE_LEVEL.
        let waited = unsafe {
            ke_wait_for_single_object::<KePlatform>(
                child.dispatcher_object(),
                ProcessorMode::Kernel,
                false,
                Some(CHILD_TIMEOUT),
            )
        };
        if waited == STATUS_TIMEOUT {
            log::warn!("[{tag}] {name}: its process {child_name} (PID {pid}) did not end within 2 s: terminated");
            let _ = ps::terminate_process(child.clone(), STATUS_TIMEOUT);
            // SAFETY: as above.
            unsafe {
                ke_wait_for_single_object::<KePlatform>(child.dispatcher_object(), ProcessorMode::Kernel, false, None)
            };
        }
        log::info!("[{tag}] {name} created {child_name} (PID {pid}): exit status {}", child.exit_status());
    }
    let calls = crate::sys::service_calls();
    log::info!("[{tag}] {name} and its processes: {} system services called", calls.len());
    for call in calls {
        let first = match call.first {
            Some(crate::sys::Completion::Status(status)) => alloc::format!("returned {status}"),
            Some(crate::sys::Completion::Frame) => "returned a new context".into(),
            None => "did not return".into(),
        };
        log::info!("[{tag}]   {} ({:#06x}): {} calls, the first {first}", call.name, call.number, call.calls);
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

/// Le fichier `path` (un nom NT) en entier, par Io ; `None` sans lui, ou
/// s'il ne se lit pas (journalisé).
fn read_boot_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    use abi::ntstatus::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND};

    let read = ob::namespace()
        .open(path, None, Some(&io_manager::FILE_TYPE), abi::object::OBJ_CASE_INSENSITIVE)
        .and_then(|object| ob::downcast::<io_manager::File>(&object).ok_or(abi::ntstatus::STATUS_OBJECT_TYPE_MISMATCH))
        .and_then(|file| file.read_all());
    match read {
        Ok(bytes) => Some(bytes),
        Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => None,
        Err(status) => {
            log::warn!("[boot] {path}: not read: {status}");
            None
        }
    }
}
