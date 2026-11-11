//! Les services d'information du système (Ex).

use abi::ntstatus::{
    NtStatus, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, STATUS_PRIVILEGE_NOT_HELD, STATUS_SUCCESS,
};
use abi::security::SE_LOAD_DRIVER_PRIVILEGE;
use abi::system_information::{
    SystemBasicInformation32, SystemProcessInformation32, SystemProcessorInformation32, SystemThreadInformation32,
    MAXIMUM_USER_MODE_ADDRESS, MINIMUM_USER_MODE_ADDRESS, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_BASIC_INFORMATION,
    SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION, SYSTEM_FILECACHE_INFORMATION, SYSTEM_FIRMWARE_TABLE_INFORMATION,
    SYSTEM_FLAGS_INFORMATION, SYSTEM_HANDLE_INFORMATION, SYSTEM_PERFORMANCE_INFORMATION, SYSTEM_PROCESSOR_INFORMATION,
    SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, SYSTEM_PROCESS_INFORMATION, SYSTEM_PROCESS_INFORMATION_NAME_AT,
    SYSTEM_RANGE_START, SYSTEM_RANGE_START_INFORMATION, SYSTEM_SESSION_CREATE, SYSTEM_SESSION_DETACH,
    SYSTEM_THREAD_INFORMATION_SIZE, SYSTEM_TIME_OF_DAY_INFORMATION,
};
use core::sync::atomic::{AtomicBool, Ordering};
use ke::usermem::UserPtr;
use mm::virtual_alloc::{ALLOC_GRANULARITY, PAGE_SIZE};

/// Les classes demandées sans être implémentées.
static UNSUPPORTED: super::ClassReport = super::ClassReport::new("NtQuerySystemInformation");
/// La liste des processus a-t-elle déjà été lue ? Un seul marqueur par
/// démarrage ([`process_information`]).
static PROCESS_LIST_READ: AtomicBool = AtomicBool::new(false);
/// Les classes de NtSetSystemInformation demandées sans être implémentées.
static UNSUPPORTED_SET: super::ClassReport = super::ClassReport::new("NtSetSystemInformation");

/// Le seul module qu'un appelant du mode utilisateur peut faire charger.
const WIN32K: &str = "\\SystemRoot\\System32\\win32k.sys";
/// La taille d'un UNICODE_STRING i386.
const UNICODE_STRING_SIZE: u32 = 8;

/// NtGlobalFlag : aucun drapeau `FLG_*` (XP les lit dans
/// `Session Manager\GlobalFlag` au démarrage ; pas encore), comme le
/// `NtGlobalFlag` du PEB de chaque processus.
const NT_GLOBAL_FLAG: u32 = 0;

/// `SHUTDOWN_ACTION::ShutdownReboot` on XP.
const SHUTDOWN_REBOOT: u32 = 1;

/// NtShutdownSystem(ShutdownAction). The installer uses the reboot action
/// after every target cache has been flushed. Other actions wait for power
/// management and an orderly shutdown path.
pub(super) fn nt_shutdown_system(arguments: &[u32]) -> NtStatus {
    if arguments[0] != SHUTDOWN_REBOOT {
        return STATUS_INVALID_PARAMETER;
    }
    log::info!("[power] NtShutdownSystem: reboot requested");
    hal::power::reset()
}

/// NtQuerySystemInformation(SystemInformationClass, SystemInformation,
/// SystemInformationLength, ReturnLength) : l'information de la classe,
/// d'une taille exacte ([`super::return_information`]) pour les classes à
/// structure fixe, à partir de la taille demandée pour les listes.
///
/// | Classe | Contenu |
/// |---|---|
/// | `SystemBasicInformation` (0) | page, pages physiques, plage du mode utilisateur, processeurs |
/// | `SystemProcessorInformation` (1) | architecture, niveau, révision et fonctions du processeur |
/// | `SystemPerformanceInformation` (2) | les compteurs, tous nuls tant que Ps ne les compte pas |
/// | `SystemProcessInformation` (5) | la liste des processus et de leurs threads ([`process_information`]) |
/// | `SystemProcessorPerformanceInformation` (8) | les temps par processeur, tous nuls |
/// | `SystemTimeOfDayInformation` (3) | l'heure du démarrage, l'heure, le fuseau (nul) ; les premiers octets que demande l'appelant, 48 au plus |
/// | `SystemHandleInformation` (16) | le nombre de handles, nul |
/// | `SystemFileCacheInformation` (21) | les caches de fichiers, nuls |
/// | `SystemFlagsInformation` (9) | les drapeaux globaux (`NtGlobalFlag`), aucun |
/// | `SystemRangeStartInformation` (50) | le début de la moitié système, `0x80000000` |
///
/// Les autres classes rendent `STATUS_INVALID_INFO_CLASS` (ce que NT rend),
/// journalisé à leur premier appel ; `SystemFirmwareTableInformation` (76),
/// que ReactOS connaît sans l'implémenter, `STATUS_NOT_IMPLEMENTED`, comme
/// lui (l'apitest SystemFirmware de kernel32 l'accepte).
pub(super) fn nt_query_system_information(arguments: &[u32]) -> NtStatus {
    let (class, buffer, length, return_length) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    match class {
        SYSTEM_BASIC_INFORMATION => {
            super::return_information(basic_information().as_bytes(), buffer, length, return_length)
        }
        SYSTEM_PROCESSOR_INFORMATION => {
            super::return_information(processor_information().as_bytes(), buffer, length, return_length)
        }
        SYSTEM_PERFORMANCE_INFORMATION
        | SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        | SYSTEM_HANDLE_INFORMATION
        | SYSTEM_FILECACHE_INFORMATION => {
            // Les compteurs, tous nuls tant que Ps ne les compte pas : les
            // structures que taskmgr relit avant chaque rafraîchissement.
            // La taille demandée, plafonnée à une page.
            let zeros = alloc::vec![0u8; (length as usize).min(PAGE_SIZE as usize)];
            super::return_information_flexible(&zeros, buffer, length, return_length)
        }
        SYSTEM_PROCESS_INFORMATION => {
            // La première lecture de la liste par un processus : le moment
            // où un gestionnaire de tâches vit et rafraîchit — le marqueur
            // du scénario taskmgr, une fois par démarrage.
            if !PROCESS_LIST_READ.swap(true, Ordering::AcqRel) {
                let pid = super::current_process().pid();
                log::info!("[apps] the process list was read by PID {pid}");
            }
            process_information(buffer, length, return_length)
        }
        SYSTEM_TIME_OF_DAY_INFORMATION => time_of_day(buffer, length, return_length),
        SYSTEM_RANGE_START_INFORMATION => {
            super::return_information(&SYSTEM_RANGE_START.to_le_bytes(), buffer, length, return_length)
        }
        SYSTEM_FLAGS_INFORMATION => {
            super::return_information(&NT_GLOBAL_FLAG.to_le_bytes(), buffer, length, return_length)
        }
        // A class ReactOS knows without implementing it: kernel32 turns
        // STATUS_NOT_IMPLEMENTED into ERROR_INVALID_FUNCTION, which its
        // SystemFirmware apitest accepts, and not the ERROR_INVALID_PARAMETER
        // of STATUS_INVALID_INFO_CLASS.
        SYSTEM_FIRMWARE_TABLE_INFORMATION => UNSUPPORTED.report(class),
        _ => UNSUPPORTED.report_invalid_class(class),
    }
}

/// NtSetSystemInformation(SystemInformationClass, SystemInformation,
/// SystemInformationLength) : ce que `smss` demande pour sa session, chaque
/// classe sous `SeLoadDriverPrivilege` (`STATUS_PRIVILEGE_NOT_HELD`) :
///
/// | Classe | Effet |
/// |---|---|
/// | `SystemExtendServiceTableInformation` (38) | « charge » win32k, qui fait partie du noyau : sa table de services est déjà là, rien n'est chargé ; tout autre module est refusé, comme ReactOS (`STATUS_PRIVILEGE_NOT_HELD`) |
/// | `SystemSessionCreate` (47) | une session neuve où l'appelant entre (`ps::create_session`), son identifiant rendu dans le tampon |
/// | `SystemSessionDetach` (48) | l'appelant quitte sa session (`ps::detach_session`) |
///
/// Une taille autre que celle de la classe (un ULONG, un UNICODE_STRING)
/// rend `STATUS_INFO_LENGTH_MISMATCH`. Les autres classes rendent
/// `STATUS_NOT_IMPLEMENTED`, journalisé à leur premier appel.
pub(super) fn nt_set_system_information(arguments: &[u32]) -> NtStatus {
    let (class, buffer, length) = (arguments[0], arguments[1], arguments[2]);
    let set = || {
        let size = match class {
            SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION => UNICODE_STRING_SIZE,
            SYSTEM_SESSION_CREATE | SYSTEM_SESSION_DETACH => 4,
            _ => return Err(UNSUPPORTED_SET.report(class)),
        };
        if length != size {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        if !super::security::privilege_enabled(SE_LOAD_DRIVER_PRIVILEGE) {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        let process = super::current_process();
        match class {
            SYSTEM_EXTEND_SERVICE_TABLE_INFORMATION => {
                let name = super::object::capture_unicode_string(buffer)?;
                if !name.iter().copied().eq(WIN32K.encode_utf16()) {
                    return Err(STATUS_PRIVILEGE_NOT_HELD);
                }
            }
            SYSTEM_SESSION_CREATE => {
                let out = UserPtr::<u32>::new(buffer);
                ke::usermem::probe_for_write(u64::from(buffer), 4, 4)?;
                let id = ps::create_session(&process)?;
                out.write(&id)?;
            }
            _ => ps::detach_session(&process)?,
        }
        Ok(STATUS_SUCCESS)
    };
    set().unwrap_or_else(|status| status)
}

/// SystemTimeOfDayInformation : les `length` premiers octets de
/// SYSTEM_TIMEOFDAY_INFORMATION (48 au plus, `STATUS_INFO_LENGTH_MISMATCH`
/// au-delà), et leur nombre en `return_length` s'il n'est pas nul : l'heure
/// du démarrage et l'heure du RTC (`hal::rtc`), un fuseau horaire de biais
/// nul (UTC) en attendant le registre.
fn time_of_day(buffer: u32, length: u32, return_length: u32) -> NtStatus {
    use abi::system_information::SystemTimeOfDayInformation32;

    let information = SystemTimeOfDayInformation32 {
        boot_time: hal::rtc::boot_time() as i64,
        current_time: hal::rtc::system_time() as i64,
        ..Default::default()
    };
    let bytes = information.as_bytes();
    let give = || {
        let length = length as usize;
        if length > bytes.len() {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        ke::usermem::probe_for_write(u64::from(buffer), length, 4)?;
        ke::usermem::copy_to_user(u64::from(buffer), &bytes[..length])?;
        if return_length != 0 {
            UserPtr::<u32>::new(return_length).write(&(length as u32))?;
        }
        Ok(STATUS_SUCCESS)
    };
    give().unwrap_or_else(|status| status)
}

/// SYSTEM_PROCESSOR_INFORMATION : x86, la famille et le modèle comme XP SP2
/// les donne (`hal::cpuid::level_and_revision`), et ses fonctions
/// (KeFeatureBits, `hal::cpuid::feature_bits`) : SYSENTER sur Intel
/// (ADR-004), NX selon EFER.
pub(crate) fn processor_information() -> SystemProcessorInformation32 {
    use x86_64::registers::model_specific::{Efer, EferFlags};

    let (signature, leaf1_edx, extended_edx) = hal::cpuid::signature_and_features();
    let intel = hal::cpuid::is_intel();
    let (level, revision) = hal::cpuid::level_and_revision(signature, intel);
    let nx_enabled = Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE);
    SystemProcessorInformation32 {
        processor_architecture: PROCESSOR_ARCHITECTURE_INTEL,
        processor_level: level,
        processor_revision: revision,
        reserved: 0,
        processor_feature_bits: hal::cpuid::feature_bits(leaf1_edx, extended_edx, intel, nx_enabled),
    }
}

/// SYSTEM_BASIC_INFORMATION : un processeur, les pages de la base PFN, la
/// plage du mode utilisateur d'XP.
fn basic_information() -> SystemBasicInformation32 {
    let pages = mm::pfn::stats();
    let mut info = SystemBasicInformation32::default();
    info.timer_resolution = hal::timer::MAXIMUM_INCREMENT;
    info.page_size = PAGE_SIZE as u32;
    info.number_of_physical_pages = (pages.free + pages.active_total()) as u32;
    // Page 0 stays reserved.
    info.lowest_physical_page_number = 1;
    info.highest_physical_page_number = pages.tracked.saturating_sub(1) as u32;
    info.allocation_granularity = ALLOC_GRANULARITY as u32;
    info.minimum_user_mode_address = MINIMUM_USER_MODE_ADDRESS;
    info.maximum_user_mode_address = MAXIMUM_USER_MODE_ADDRESS;
    info.active_processors_affinity_mask = 1;
    info.number_of_processors = 1;
    info
}

/// `SystemProcessInformation` : la liste des processus vivants et de leurs
/// threads, au format SYSTEM_PROCESS_INFORMATION de ReactOS (i386, paquet
/// 4) : une entête de 0xB8 octets, les threads de 0x40 chacun, puis le nom
/// d'image UTF-16 — chaque entrée alignée sur 8, chaînée par
/// `NextEntryOffset`, le nom pointé à l'intérieur du tampon même. Les temps
/// et les compteurs de mémoire restent à zéro tant que Ps ne les compte
/// pas.
fn process_information(buffer: u32, length: u32, return_length: u32) -> NtStatus {
    let snapshots = ps::eprocess::snapshots();
    let mut data = alloc::vec::Vec::new();
    for (index, snapshot) in snapshots.iter().enumerate() {
        let entry_at = data.len() as u32;
        let name_at = entry_at
            + SYSTEM_PROCESS_INFORMATION_NAME_AT
            + SYSTEM_THREAD_INFORMATION_SIZE * snapshot.threads.len() as u32;
        let name: alloc::vec::Vec<u8> = snapshot.name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let total = (name_at - entry_at + name.len() as u32).next_multiple_of(8);
        let next = if index + 1 == snapshots.len() { 0 } else { total };
        let header = SystemProcessInformation32 {
            next_entry_offset: next,
            number_of_threads: snapshot.threads.len() as u32,
            image_name_length: name.len() as u16,
            image_name_maximum_length: if name.is_empty() { 0 } else { name.len() as u16 + 2 },
            image_name_buffer: if name.is_empty() { 0 } else { buffer + name_at },
            base_priority: snapshot.base_priority,
            unique_process_id: snapshot.pid,
            inherited_from_unique_process_id: snapshot.parent_pid,
            session_id: snapshot.session_id,
            page_directory_base: snapshot.directory_table_base as u32,
            ..Default::default()
        };
        data.extend_from_slice(header.as_bytes());
        for thread in &snapshot.threads {
            let thread_information = SystemThreadInformation32 {
                client_id_process: snapshot.pid,
                client_id_thread: thread.tid,
                start_address: thread.start_address,
                priority: thread.priority,
                base_priority: snapshot.base_priority,
                thread_state: 5, // Waiting : vivant, pas le thread courant.
                ..Default::default()
            };
            data.extend_from_slice(thread_information.as_bytes());
        }
        data.extend_from_slice(&name);
        data.resize(entry_at as usize + total as usize, 0);
    }
    super::return_information_flexible(&data, buffer, length, return_length)
}
