//! La DLL système (PspSystemDll, 02 §6.5) : ntdll, projetée à sa base dans
//! chaque processus. Le noyau résout ses points d'entrée quand on l'installe
//! ([`install`]) :
//!
//! - les répartiteurs vers le mode utilisateur, `KiUserExceptionDispatcher` et
//!   `KiUserApcDispatcher` (`ke::exception`, `ke::apc`) ;
//! - `LdrInitializeThunk`, par lequel démarre chaque thread
//!   ([`SystemDll::write_start_frame`]) ;
//! - le stub des appels système que `KUSER_SHARED_DATA` désigne
//!   (`SystemCall`, ADR-004) : `KiFastSystemCall` (SYSENTER) sur Intel,
//!   `KiIntSystemCall` (`int 2Eh`) ailleurs ; et `KiFastSystemCallRet`, où
//!   SYSENTER revient (`SystemCallReturn`).

use alloc::sync::Arc;

use abi::context::Context32;
use abi::ntstatus::{NtStatus, STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_PARAMETER, STATUS_PROCEDURE_NOT_FOUND};
use hal::sync::KSpinLock;
use ke::apc::APC_DISPATCHER_RESERVE;
use ke::context::{initial_user_context, user_context_address, UserSelectors};
use mm::section::Section;
use pe::{ExportTarget, Pe32};

use crate::eprocess::EProcess;

/// ntdll et ses points d'entrée, en adresses du mode utilisateur.
pub struct SystemDll {
    section: Arc<Section>,
    /// Sa base préférée, où chaque processus la projette.
    pub base: u32,
    pub ldr_initialize_thunk: u32,
    pub user_exception_dispatcher: u32,
    pub user_apc_dispatcher: u32,
    pub user_callback_dispatcher: u32,
    pub raise_user_exception_dispatcher: u32,
    pub fast_system_call: u32,
    pub fast_system_call_ret: u32,
    pub int_system_call: u32,
}

/// La DLL système installée.
static SYSTEM_DLL: KSpinLock<Option<Arc<SystemDll>>> = KSpinLock::new(None);

impl SystemDll {
    /// PspLookupSystemDllEntryPoint : la DLL système du fichier `file`, ses
    /// points d'entrée résolus. `STATUS_INVALID_IMAGE_FORMAT` si ce n'est pas
    /// une image PE32, `STATUS_PROCEDURE_NOT_FOUND` s'il lui en manque un.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn new(file: Arc<[u8]>) -> Result<Self, NtStatus> {
        let pe = Pe32::parse(&file).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        let base = pe.optional_header().image_base;
        let entry = |name: &str| match pe.export(name) {
            Some(ExportTarget::Rva(rva)) => Ok(base.wrapping_add(rva)),
            _ => {
                log::error!("ps: the system DLL does not export {name}");
                Err(STATUS_PROCEDURE_NOT_FOUND)
            }
        };
        let ldr_initialize_thunk = entry("LdrInitializeThunk")?;
        let user_exception_dispatcher = entry("KiUserExceptionDispatcher")?;
        let user_apc_dispatcher = entry("KiUserApcDispatcher")?;
        let user_callback_dispatcher = entry("KiUserCallbackDispatcher")?;
        let raise_user_exception_dispatcher = entry("KiRaiseUserExceptionDispatcher")?;
        let fast_system_call = entry("KiFastSystemCall")?;
        let fast_system_call_ret = entry("KiFastSystemCallRet")?;
        let int_system_call = entry("KiIntSystemCall")?;
        let section = Section::create_image(file.clone())?;
        Ok(Self {
            section,
            base,
            ldr_initialize_thunk,
            user_exception_dispatcher,
            user_apc_dispatcher,
            user_callback_dispatcher,
            raise_user_exception_dispatcher,
            fast_system_call,
            fast_system_call_ret,
            int_system_call,
        })
    }

    /// Sa section d'image, que chaque processus projette.
    pub fn section(&self) -> &Arc<Section> {
        &self.section
    }

    /// Le cadre par lequel un thread de `process` démarre dans
    /// `LdrInitializeThunk`, comme PspUserThreadStartup le livre : sur sa pile
    /// `stack`, son contexte initial (EIP `start`, ESP `stack`) sous la place
    /// du répartiteur, puis l'APC utilisateur
    /// `LdrInitializeThunk(NULL, base de ntdll, NULL)`. Rend l'ESP avec lequel
    /// le thread entre dans `KiUserApcDispatcher`, qui reprend ensuite le
    /// contexte par NtContinue.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn write_start_frame(&self, process: &EProcess, start: u32, stack: u32) -> Result<u32, NtStatus> {
        self.write_context_frame(process, &initial_user_context(start, stack, UserSelectors::current()))
    }

    /// Comme [`write_start_frame`](Self::write_start_frame), avec le contexte
    /// initial `context`, complet et assaini (NtCreateThread) : sur la pile
    /// en `context.esp`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn write_context_frame(&self, process: &EProcess, context: &Context32) -> Result<u32, NtStatus> {
        let context_at = user_context_address(context.esp, APC_DISPATCHER_RESERVE).ok_or(STATUS_INVALID_PARAMETER)?;
        let arguments_at = context_at - 16;
        process.write_memory(u64::from(context_at), context.as_bytes())?;
        let mut arguments = [0u8; 16];
        for (slot, value) in arguments.chunks_exact_mut(4).zip([self.ldr_initialize_thunk, 0, self.base, 0]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        process.write_memory(u64::from(arguments_at), &arguments)?;
        Ok(arguments_at)
    }
}

/// Installe la DLL système, ou la retire (`None`) : les répartiteurs de Ke,
/// `SystemCall` et `SystemCallReturn` dans `KUSER_SHARED_DATA`. Les
/// processus créés ensuite la projettent, et leurs threads démarrent par
/// `LdrInitializeThunk`.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn install(dll: Option<SystemDll>) {
    let (exception, apc, system_call, system_call_return) = dll.as_ref().map_or((0, 0, 0, 0), |d| {
        // SYSENTER works from compatibility mode on Intel only (ADR-004).
        let system_call = if hal::cpuid::is_intel() { d.fast_system_call } else { d.int_system_call };
        (d.user_exception_dispatcher, d.user_apc_dispatcher, system_call, d.fast_system_call_ret)
    });
    ke::exception::set_user_exception_dispatcher(exception);
    ke::apc::set_user_apc_dispatcher(apc);
    if let Some(shared) = mm::shared_data::kernel_alias() {
        // SAFETY: the kernel alias of the shared page, which only the kernel
        // writes; user mode reads these two words whole.
        unsafe {
            core::ptr::addr_of_mut!((*shared).system_call).write_volatile(system_call);
            core::ptr::addr_of_mut!((*shared).system_call_return).write_volatile(system_call_return);
        }
    }
    *SYSTEM_DLL.lock() = dll.map(Arc::new);
}

/// La DLL système installée.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn current() -> Option<Arc<SystemDll>> {
    SYSTEM_DLL.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pe::builder::Pe32Builder;

    const ENTRY_POINTS: [&str; 8] = [
        "KiFastSystemCall",
        "KiFastSystemCallRet",
        "KiIntSystemCall",
        "KiRaiseUserExceptionDispatcher",
        "KiUserApcDispatcher",
        "KiUserCallbackDispatcher",
        "KiUserExceptionDispatcher",
        "LdrInitializeThunk",
    ];

    fn ntdll(exports: &[&'static str]) -> Arc<[u8]> {
        let exports: alloc::vec::Vec<_> =
            exports.iter().enumerate().map(|(i, &name)| (name, 0x1000 + 0x10 * i as u32)).collect();
        let file = Pe32Builder::new(0x7C90_0000)
            .section(".text", 0x1000, 0x100, &[0xC3; 0x100], pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
            .exports("ntdll.dll", &exports)
            .build();
        Arc::from(file)
    }

    #[test]
    fn its_entry_points_are_its_exports_at_its_base() {
        let dll = SystemDll::new(ntdll(&ENTRY_POINTS)).expect("a system DLL");
        assert_eq!(dll.base, 0x7C90_0000);
        assert_eq!((dll.fast_system_call, dll.int_system_call), (0x7C90_1000, 0x7C90_1020));
        assert_eq!((dll.user_apc_dispatcher, dll.ldr_initialize_thunk), (0x7C90_1040, 0x7C90_1070));
    }

    #[test]
    fn a_missing_entry_point_or_a_bad_image_is_refused() {
        let without = &ENTRY_POINTS[..7];
        assert_eq!(SystemDll::new(ntdll(without)).err(), Some(STATUS_PROCEDURE_NOT_FOUND), "no LdrInitializeThunk");
        assert_eq!(SystemDll::new(Arc::from(&b"MZ"[..])).err(), Some(STATUS_INVALID_IMAGE_FORMAT));
    }
}
