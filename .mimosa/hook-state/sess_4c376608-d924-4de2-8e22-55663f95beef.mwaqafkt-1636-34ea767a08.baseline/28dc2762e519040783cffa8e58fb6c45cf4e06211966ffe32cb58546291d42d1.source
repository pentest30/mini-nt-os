//! `KUSER_SHARED_DATA` au démarrage (02 §4.1, ADR-003) : la page de Mm
//! (`mm::shared_data`), remplie de ce qu'XP SP2 y montre, puis confiée à
//! l'horloge, qui y écrit ses temps à chaque tick. `SystemCall` attend la DLL
//! système (`ps::system_dll`).

use abi::shared_data::{
    KUserSharedData, PF_3DNOW_INSTRUCTIONS_AVAILABLE, PF_COMPARE_EXCHANGE_DOUBLE, PF_MMX_INSTRUCTIONS_AVAILABLE,
    PF_NX_ENABLED, PF_PAE_ENABLED, PF_RDTSC_INSTRUCTION_AVAILABLE, PF_SSE3_INSTRUCTIONS_AVAILABLE,
    PF_XMMI64_INSTRUCTIONS_AVAILABLE, PF_XMMI_INSTRUCTIONS_AVAILABLE,
};
use core::arch::x86_64::__cpuid;
use x86_64::registers::model_specific::{Efer, EferFlags};

/// Crée et remplit la page : version 5.1, poste de travail, racine
/// `C:\WINDOWS`, fonctions du processeur, pages physiques, politique DEP et
/// cookie.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, avant le premier processus.
pub fn init() {
    let alias = mm::shared_data::init().expect("the KUSER_SHARED_DATA page");
    let mut data = KUserSharedData::xp();
    data.processor_features = processor_features();
    let pages = mm::pfn::stats();
    data.number_of_physical_pages = (pages.free + pages.active_total()) as u32;
    data.nx_support_policy = ps::eprocess::DEP_POLICY.nx_support_policy();
    // RtlEncodePointer's secret: different at each boot.
    // SAFETY: RDTSC exists on every x86-64 processor.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    data.cookie = (tsc ^ (tsc >> 32)) as u32;
    // SAFETY: the kernel alias of a fresh page that no process maps yet.
    unsafe { alias.write(data) };
    // SAFETY: the page lives for good.
    unsafe { hal::timer::set_shared_data_alias(alias as u64) };
}

/// `ProcessorFeatures`, from CPUID: CMPXCHG8B, MMX, SSE, SSE2, SSE3, 3DNow!,
/// RDTSC; PAE (long mode) and NX as the kernel runs them.
fn processor_features() -> [u8; 64] {
    let leaf1 = __cpuid(1);
    let extended = if __cpuid(0x8000_0000).eax >= 0x8000_0001 { __cpuid(0x8000_0001).edx } else { 0 };
    let bit = |register: u32, n: u32| u8::from(register & (1 << n) != 0);
    let mut features = [0u8; 64];
    features[PF_COMPARE_EXCHANGE_DOUBLE] = bit(leaf1.edx, 8);
    features[PF_MMX_INSTRUCTIONS_AVAILABLE] = bit(leaf1.edx, 23);
    features[PF_XMMI_INSTRUCTIONS_AVAILABLE] = bit(leaf1.edx, 25);
    features[PF_XMMI64_INSTRUCTIONS_AVAILABLE] = bit(leaf1.edx, 26);
    features[PF_RDTSC_INSTRUCTION_AVAILABLE] = bit(leaf1.edx, 4);
    features[PF_SSE3_INSTRUCTIONS_AVAILABLE] = bit(leaf1.ecx, 0);
    features[PF_3DNOW_INSTRUCTIONS_AVAILABLE] = bit(extended, 31);
    features[PF_PAE_ENABLED] = 1;
    features[PF_NX_ENABLED] = u8::from(Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE));
    features
}
