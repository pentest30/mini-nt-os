//! Les services d'information du système (Ex).

use abi::ntstatus::NtStatus;
use abi::system_information::{
    SystemBasicInformation32, MAXIMUM_USER_MODE_ADDRESS, MINIMUM_USER_MODE_ADDRESS, SYSTEM_BASIC_INFORMATION,
};
use mm::virtual_alloc::{ALLOC_GRANULARITY, PAGE_SIZE};

/// Les classes demandées sans être implémentées.
static UNSUPPORTED: super::ClassReport = super::ClassReport::new("NtQuerySystemInformation");

/// NtQuerySystemInformation(SystemInformationClass, SystemInformation,
/// SystemInformationLength, ReturnLength) : l'information de la classe,
/// d'une taille exacte ([`super::return_information`]).
///
/// | Classe | Contenu |
/// |---|---|
/// | `SystemBasicInformation` (0) | page, pages physiques, plage du mode utilisateur, processeurs |
///
/// Les autres classes rendent `STATUS_NOT_IMPLEMENTED`, journalisé à leur
/// premier appel.
pub(super) fn nt_query_system_information(arguments: &[u32]) -> NtStatus {
    let (class, buffer, length, return_length) = (arguments[0], arguments[1], arguments[2], arguments[3]);
    let information = match class {
        SYSTEM_BASIC_INFORMATION => basic_information(),
        _ => return UNSUPPORTED.report(class),
    };
    super::return_information(information.as_bytes(), buffer, length, return_length)
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
