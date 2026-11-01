//! EPROCESS : le processus de l'exécutif.
//!
//! Un processus tient son espace d'adresses (une PML4, `mm::address_space`),
//! sa table de handles, son PEB et la liste de ses threads vivants. Il se
//! crée à partir d'une section d'image ([`create_process`]) : l'image est
//! projetée à sa base, le PEB écrit en `0x7FFDF000` ; ses threads viennent
//! ensuite ([`crate::ethread::create_thread`]).
//!
//! Il se termine quand son dernier thread se termine
//! ([`crate::exit::exit_thread`]), ou à la demande
//! ([`crate::exit::terminate_process`]) : ses handles sont fermés (rundown),
//! son espace d'adresses rendu à Mm, son statut de sortie fixé et son objet
//! signalé. L'objet processus vit ensuite tant qu'on le référence, et rend
//! son PID à sa destruction.
//!
//! Le processus System (PID 4) et ceux de l'ancien chargeur n'ont pas
//! d'espace d'adresses à eux : ils vivent dans celui du système.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_CID, STATUS_INVALID_PARAMETER,
    STATUS_PENDING, STATUS_PROCESS_IS_TERMINATING, STATUS_SECTION_NOT_IMAGE,
};
use abi::peb32::Peb32;
use abi::process::{
    MEM_EXECUTE_OPTION_DISABLE, MEM_EXECUTE_OPTION_ENABLE, MEM_EXECUTE_OPTION_PERMANENT, MEM_EXECUTE_OPTION_VALID_FLAGS,
};
use hal::sync::{KSpinLock, Once};
use ke::dispatcher::{DispatcherHeader, ObjectType as KObjectType};
use mm::address_space::AddressSpace;
use mm::section::Section;
use mm::vad::PageProtect;
use mm::virtual_alloc::{AllocType, PAGE_SIZE};
use ob::{create_object, AccessMask, GenericMapping, HandleTable, Object, ObjectType};

use crate::ethread::EThread;
use crate::rundown::RundownRef;
use crate::{CidEntry, DispatcherEvent, CID_TABLE};

pub type ProcessId = u32;

pub const PROCESS_TERMINATE: AccessMask = AccessMask(0x0001);
pub const PROCESS_CREATE_THREAD: AccessMask = AccessMask(0x0002);
pub const PROCESS_SET_SESSIONID: AccessMask = AccessMask(0x0004);
pub const PROCESS_VM_OPERATION: AccessMask = AccessMask(0x0008);
pub const PROCESS_VM_READ: AccessMask = AccessMask(0x0010);
pub const PROCESS_VM_WRITE: AccessMask = AccessMask(0x0020);
pub const PROCESS_DUP_HANDLE: AccessMask = AccessMask(0x0040);
pub const PROCESS_CREATE_PROCESS: AccessMask = AccessMask(0x0080);
pub const PROCESS_SET_QUOTA: AccessMask = AccessMask(0x0100);
pub const PROCESS_SET_INFORMATION: AccessMask = AccessMask(0x0200);
pub const PROCESS_QUERY_INFORMATION: AccessMask = AccessMask(0x0400);
pub const PROCESS_SUSPEND_RESUME: AccessMask = AccessMask(0x0800);
/// PROCESS_ALL_ACCESS d'XP.
pub const PROCESS_ALL_ACCESS: AccessMask =
    AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | AccessMask::SYNCHRONIZE.0 | 0x0FFF);

/// Le type `Process`.
pub static PROCESS_TYPE: ObjectType = ObjectType::new(
    "Process",
    PROCESS_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | PROCESS_VM_READ.0 | PROCESS_QUERY_INFORMATION.0),
        write: AccessMask(
            AccessMask::STANDARD_RIGHTS_WRITE.0
                | PROCESS_CREATE_PROCESS.0
                | PROCESS_CREATE_THREAD.0
                | PROCESS_VM_OPERATION.0
                | PROCESS_VM_WRITE.0
                | PROCESS_DUP_HANDLE.0
                | PROCESS_TERMINATE.0
                | PROCESS_SET_QUOTA.0
                | PROCESS_SET_INFORMATION.0
                | PROCESS_SUSPEND_RESUME.0,
        ),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | AccessMask::SYNCHRONIZE.0),
        all: PROCESS_ALL_ACCESS,
    },
);

/// Le PEB, à l'adresse fixe d'XP avant SP2 (sans tirage au sort).
pub const PEB_VA: u32 = 0x7FFD_F000;

/// Valeurs par défaut du gestionnaire de session d'XP, reprises dans chaque
/// PEB (MmCreatePeb) : tas de 1 Mio réservé, 8 Kio commités, décommit
/// au-delà de 64 Kio libres ou d'un bloc libre de 4 Kio ; délai des sections
/// critiques de 30 jours.
const HEAP_SEGMENT_RESERVE: u32 = 0x10_0000;
const HEAP_SEGMENT_COMMIT: u32 = 0x2000;
const HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD: u32 = 0x1_0000;
const HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD: u32 = 0x1000;
const CRITICAL_SECTION_TIMEOUT: i64 = -2_592_000 * 10_000_000;

/// La politique DEP du système (ADR-020) : les options d'exécution que
/// reçoit un processus neuf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepPolicy {
    /// DEP coupé, sauf pour les processus qui l'activent : le défaut d'XP SP2.
    OptIn,
    /// DEP actif, sauf pour les processus qui le coupent.
    OptOut,
    /// DEP actif pour tous, sans exception.
    AlwaysOn,
    /// DEP coupé pour tous, sans exception.
    AlwaysOff,
}

impl DepPolicy {
    /// Les options d'exécution (`MEM_EXECUTE_OPTION_*`) d'un processus neuf :
    /// sous AlwaysOn et AlwaysOff, elles ne changent plus.
    pub const fn initial_options(self) -> u32 {
        match self {
            Self::OptIn => MEM_EXECUTE_OPTION_ENABLE,
            Self::OptOut => MEM_EXECUTE_OPTION_DISABLE,
            Self::AlwaysOn => MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_PERMANENT,
            Self::AlwaysOff => MEM_EXECUTE_OPTION_ENABLE | MEM_EXECUTE_OPTION_PERMANENT,
        }
    }
}

impl DepPolicy {
    /// Sa valeur dans `KUSER_SHARED_DATA.NXSupportPolicy`.
    pub const fn nx_support_policy(self) -> u8 {
        use abi::shared_data::*;
        match self {
            Self::OptIn => NX_SUPPORT_POLICY_OPTIN,
            Self::OptOut => NX_SUPPORT_POLICY_OPTOUT,
            Self::AlwaysOn => NX_SUPPORT_POLICY_ALWAYSON,
            Self::AlwaysOff => NX_SUPPORT_POLICY_ALWAYSOFF,
        }
    }
}

/// La politique DEP en vigueur. Une option de démarrage la choisira.
pub const DEP_POLICY: DepPolicy = DepPolicy::OptIn;

/// MmSetExecuteOptions, sans le processus : les options qui remplacent
/// `current` par `requested`. `STATUS_INVALID_PARAMETER` pour un drapeau
/// inconnu, ou sans exactement l'un de `DISABLE` et `ENABLE` ;
/// `STATUS_ACCESS_DENIED` si `current` est permanent.
pub fn changed_execute_options(current: u32, requested: u32) -> Result<u32, NtStatus> {
    let dep = requested & (MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_ENABLE);
    if requested & !MEM_EXECUTE_OPTION_VALID_FLAGS != 0 || dep.count_ones() != 1 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if current & MEM_EXECUTE_OPTION_PERMANENT != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(requested)
}

/// Les threads vivants d'un processus, et où il en est de sa fin.
pub(crate) struct Threads {
    /// Ses threads qui ne se sont pas terminés. La liste les tient en vie
    /// jusqu'à leur fin ; le *reaper* les lâche ensuite.
    pub(crate) list: Vec<Arc<Object<EThread>>>,
    /// Sa fin est demandée ou commencée : plus de nouveau thread.
    pub(crate) terminating: bool,
    /// Ses ressources (handles, espace d'adresses) sont rendues, ou en train
    /// de l'être par qui a posé ce drapeau.
    pub(crate) exited: bool,
}

/// Le corps d'un objet processus.
pub struct EProcess {
    pid: ProcessId,
    /// InheritedFromUniqueProcessId : le processus créateur.
    parent_pid: ProcessId,
    /// ImageFileName : 15 caractères au plus.
    image_file_name: String,
    /// Son espace d'adresses, jusqu'à sa fin ; aucun pour System et les
    /// processus de l'ancien chargeur.
    space: KSpinLock<Option<Arc<AddressSpace>>>,
    /// RundownProtect : qui accède à l'espace d'adresses en retarde la
    /// destruction ([`with_space`](Self::with_space)).
    rundown: RundownRef,
    /// Signalé par le dernier accès quand le rundown attend.
    rundown_done: DispatcherEvent,
    directory_table_base: u64,
    pub handle_table: HandleTable,
    /// Adresse du PEB ; 0 sans espace d'adresses.
    peb: u32,
    /// Base de l'image projetée.
    image_base: u32,
    pub(crate) threads: KSpinLock<Threads>,
    /// ExitStatus : `STATUS_PENDING` tant qu'il vit.
    exit_status: AtomicU32,
    /// Signalé à sa fin : l'objet processus que l'on attend.
    exited: DispatcherEvent,
    /// Options d'exécution (`MEM_EXECUTE_OPTION_*`, ADR-020).
    execute_options: KSpinLock<u32>,
    /// SessionId : sa session (Terminal Services), celle de son créateur au
    /// départ.
    session_id: AtomicU32,
}

impl EProcess {
    /// Un processus sans thread, avec son PID.
    fn create(
        parent_pid: ProcessId,
        image_file_name: &str,
        space: Option<Arc<AddressSpace>>,
        handle_table: HandleTable,
        peb: u32,
        image_base: u32,
        session_id: u32,
    ) -> Result<Arc<Object<Self>>, NtStatus> {
        let pid = CID_TABLE.lock().insert(CidEntry::Process(Weak::new())).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let directory_table_base = space
            .as_ref()
            .map_or_else(mm::address_space::system_directory_table_base, |space| space.directory_table_base());
        let process = create_object(
            &PROCESS_TYPE,
            Self {
                pid,
                parent_pid,
                image_file_name: image_file_name.chars().take(15).collect(),
                space: KSpinLock::new(space),
                rundown: RundownRef::new(),
                rundown_done: DispatcherEvent::new(KObjectType::NotificationEvent),
                directory_table_base,
                handle_table,
                peb,
                image_base,
                threads: KSpinLock::new(Threads { list: Vec::new(), terminating: false, exited: false }),
                exit_status: AtomicU32::new(STATUS_PENDING.0),
                exited: DispatcherEvent::new(KObjectType::NotificationEvent),
                execute_options: KSpinLock::new(DEP_POLICY.initial_options()),
                session_id: AtomicU32::new(session_id),
            },
        );
        CID_TABLE.lock().set(pid, CidEntry::Process(Arc::downgrade(&process)));
        Ok(process)
    }

    /// UniqueProcessId.
    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    /// InheritedFromUniqueProcessId.
    pub fn parent_pid(&self) -> ProcessId {
        self.parent_pid
    }

    /// ImageFileName.
    pub fn image_file_name(&self) -> &str {
        &self.image_file_name
    }

    /// Adresse de son PEB ; 0 sans espace d'adresses à lui.
    pub fn peb(&self) -> u32 {
        self.peb
    }

    /// Base de son image.
    pub fn image_base(&self) -> u32 {
        self.image_base
    }

    /// CR3 de son espace d'adresses.
    pub fn directory_table_base(&self) -> u64 {
        self.directory_table_base
    }

    /// ExitStatus : `STATUS_PENDING` tant qu'il vit.
    pub fn exit_status(&self) -> NtStatus {
        NtStatus(self.exit_status.load(Ordering::Acquire))
    }

    /// Fixe son statut de sortie, s'il ne l'est pas encore.
    pub(crate) fn set_exit_status(&self, status: NtStatus) {
        let _ = self.exit_status.compare_exchange(STATUS_PENDING.0, status.0, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Nombre de ses threads vivants.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn active_threads(&self) -> usize {
        self.threads.lock().list.len()
    }

    /// L'objet du dispatcher signalé à sa fin, à attendre.
    pub fn dispatcher_object(&self) -> *mut DispatcherHeader {
        self.exited.header()
    }

    /// Appelle `f` avec son espace d'adresses, qui ne peut être détruit
    /// pendant ce temps ; `STATUS_PROCESS_IS_TERMINATING` si sa destruction
    /// a commencé, ou s'il n'en a pas à lui.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL ; `f` s'exécute à l'IRQL de l'appelant, donc sous
    /// DISPATCH_LEVEL s'il lit ou écrit la mémoire du processus.
    pub fn with_space<R>(&self, f: impl FnOnce(&AddressSpace) -> R) -> Result<R, NtStatus> {
        if !self.rundown.acquire() {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let space = self.space.lock().clone();
        let result = space.as_deref().map(f).ok_or(STATUS_PROCESS_IS_TERMINATING);
        drop(space);
        if self.rundown.release() {
            self.rundown_done.set();
        }
        result
    }

    /// Rend son espace d'adresses à Mm, une fois finis les accès en cours ;
    /// les suivants échouent. Aucun de ses threads ne doit plus s'y exécuter.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL. Peut attendre.
    pub(crate) fn delete_space(&self) {
        if self.rundown.begin() {
            self.rundown_done.wait();
        }
        let space = self.space.lock().take();
        if let Some(space) = space {
            space.destroy();
        }
    }

    /// Lit `buffer.len()` octets de sa mémoire en `addr` (NtReadVirtualMemory).
    ///
    /// # IRQL
    /// <= APC_LEVEL.
    pub fn read_memory(&self, addr: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
        self.with_space(|space| space.read_bytes(addr, buffer))?
    }

    /// Écrit `data` dans sa mémoire en `addr` (NtWriteVirtualMemory).
    ///
    /// # IRQL
    /// <= APC_LEVEL.
    pub fn write_memory(&self, addr: u64, data: &[u8]) -> Result<(), NtStatus> {
        self.with_space(|space| space.write_bytes(addr, data))?
    }

    /// Ses options d'exécution (`MEM_EXECUTE_OPTION_*`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn execute_options(&self) -> u32 {
        *self.execute_options.lock()
    }

    /// NtSetInformationProcess(ProcessExecuteFlags) : remplace ses options
    /// d'exécution ([`changed_execute_options`]) ; les pages déjà présentes
    /// de son espace d'adresses prennent aussitôt leurs nouveaux droits.
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL.
    pub fn set_execute_options(&self, requested: u32) -> Result<(), NtStatus> {
        let mut options = self.execute_options.lock();
        let changed = changed_execute_options(*options, requested)?;
        *options = changed;
        // Rights follow under the options' lock, so that two changes apply
        // in order; the space is not destroyed meanwhile.
        let _ = self.with_space(|space| space.set_execute_enabled(changed & MEM_EXECUTE_OPTION_ENABLE != 0));
        Ok(())
    }

    /// Signale sa fin à qui l'attend.
    pub(crate) fn signal_exited(&self) {
        self.exited.set();
    }

    /// SessionId.
    pub fn session_id(&self) -> u32 {
        self.session_id.load(Ordering::Acquire)
    }

    /// NtSetInformationProcess(ProcessSessionInformation) : le met dans la
    /// session `session_id`, que son PEB dit aussi (`Peb->SessionId`).
    ///
    /// # IRQL
    /// <= APC_LEVEL.
    pub fn set_session_id(&self, session_id: u32) -> Result<(), NtStatus> {
        if self.peb != 0 {
            let at = u64::from(self.peb) + core::mem::offset_of!(Peb32, session_id) as u64;
            self.write_memory(at, &session_id.to_le_bytes())?;
        }
        self.session_id.store(session_id, Ordering::Release);
        Ok(())
    }
}

impl Drop for EProcess {
    fn drop(&mut self) {
        CID_TABLE.lock().remove(self.pid);
    }
}

/// Le processus System (PID 4), créé au démarrage.
static SYSTEM_PROCESS: Once<Arc<Object<EProcess>>> = Once::new();

/// Crée le processus System, dans l'espace d'adresses du système.
pub(crate) fn init_system_process() {
    SYSTEM_PROCESS.call_once(|| {
        let system = EProcess::create(0, "System", None, HandleTable::new(), 0, 0, 0).expect("no PID for System");
        assert_eq!(system.pid(), 4, "System is not the first process");
        system
    });
}

/// Le processus System.
///
/// # IRQL
/// Tout niveau.
pub fn system_process() -> Arc<Object<EProcess>> {
    SYSTEM_PROCESS.get().expect("System process not initialised").clone()
}

/// PsLookupProcessByProcessId : le processus `pid`, tant que son objet vit.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn lookup_process(pid: ProcessId) -> Result<Arc<Object<EProcess>>, NtStatus> {
    match CID_TABLE.lock().get(pid) {
        Some(CidEntry::Process(process)) => process.upgrade().ok_or(STATUS_INVALID_CID),
        _ => Err(STATUS_INVALID_CID),
    }
}

/// Un processus de l'ancien chargeur (`NtCreateProcess` de `syscall.rs`) :
/// son PID et sa table de handles, dans l'espace du système.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn create_legacy(image_file_name: &str) -> Result<Arc<Object<EProcess>>, NtStatus> {
    EProcess::create(system_process().pid(), image_file_name, None, HandleTable::new(), 0, 0, 0)
}

/// PspCreateProcess : un processus sans thread pour l'image `section`, fils
/// de `parent`, dont il hérite la session, et les handles héritables avec
/// `inherit_handles`.
///
/// Son espace d'adresses est neuf ; l'image y est projetée à sa base
/// préférée, ou ailleurs si elle a des relocations (`ntdll` la relogera), et
/// le PEB est écrit en [`PEB_VA`] : XP 5.1.2600 SP2, base et sous-système de
/// l'image, paramètres du tas.
///
/// # Errors
/// `STATUS_SECTION_NOT_IMAGE` pour une section qui n'est pas une image ;
/// `STATUS_INSUFFICIENT_RESOURCES` faute de PML4 ou de PID ; celles de la
/// projection et de l'écriture du PEB.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn create_process(
    parent: &EProcess,
    section: &Arc<Section>,
    image_file_name: &str,
    inherit_handles: bool,
) -> Result<Arc<Object<EProcess>>, NtStatus> {
    let info = section.image().ok_or(STATUS_SECTION_NOT_IMAGE)?.info;
    let space = AddressSpace::new().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    space.set_execute_enabled(DEP_POLICY.initial_options() & MEM_EXECUTE_OPTION_ENABLE != 0);
    let session_id = parent.session_id();
    let built = build_address_space(&space, section, &info, session_id);
    let image_base = match built {
        Ok(image_base) => image_base,
        Err(status) => {
            space.destroy();
            return Err(status);
        }
    };
    let handle_table = if inherit_handles { parent.handle_table.inherit() } else { HandleTable::new() };
    EProcess::create(parent.pid(), image_file_name, Some(space.clone()), handle_table, PEB_VA, image_base, session_id)
        .inspect_err(|_| {
            space.destroy();
        })
}

/// Projette l'image, `KUSER_SHARED_DATA`, la DLL système (à sa base, sinon
/// `STATUS_CONFLICTING_ADDRESSES`) et les tables NLS (en lecture seule, où il
/// y a la place), et écrit le PEB dans `space` ; rend la base de l'image.
fn build_address_space(
    space: &AddressSpace,
    section: &Arc<Section>,
    info: &mm::section::ImageInfo,
    session_id: u32,
) -> Result<u32, NtStatus> {
    let view = space.map_view(section, 0, 0, 0, PageProtect::READWRITE)?;
    let image_base = view.base as u32;
    space.map_shared_data()?;
    if let Some(dll) = crate::system_dll::current() {
        space.map_view(dll.section(), u64::from(dll.base), 0, 0, PageProtect::READWRITE)?;
    }
    let nls = match crate::nls::current() {
        Some(tables) => {
            let view = space.map_view(tables.section(), 0, 0, 0, PageProtect::READONLY)?;
            tables.addresses(view.base as u32)
        }
        None => (0, 0, 0),
    };
    let page = u64::from(PEB_VA);
    space.allocate(page, PAGE_SIZE, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, PageProtect::READWRITE)?;
    let mut peb = Peb32::xp(image_base);
    (peb.ansi_code_page_data, peb.oem_code_page_data, peb.unicode_case_table_data) = nls;
    peb.heap_segment_reserve = HEAP_SEGMENT_RESERVE;
    peb.heap_segment_commit = HEAP_SEGMENT_COMMIT;
    peb.heap_decommit_total_free_threshold = HEAP_DECOMMIT_TOTAL_FREE_THRESHOLD;
    peb.heap_decommit_free_block_threshold = HEAP_DECOMMIT_FREE_BLOCK_THRESHOLD;
    peb.critical_section_timeout = CRITICAL_SECTION_TIMEOUT;
    // The heap list follows the PEB, to the end of its page.
    let peb_size = core::mem::size_of::<Peb32>() as u32;
    peb.maximum_number_of_heaps = (PAGE_SIZE as u32 - peb_size) / 4;
    peb.process_heaps = PEB_VA + peb_size;
    peb.image_subsystem = u32::from(info.subsystem);
    peb.image_subsystem_major_version = u32::from(info.subsystem_version.0);
    peb.image_subsystem_minor_version = u32::from(info.subsystem_version.1);
    peb.session_id = session_id;
    space.write_bytes(page, peb.as_bytes())?;
    Ok(image_base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::process::MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION;

    const DISABLE: u32 = MEM_EXECUTE_OPTION_DISABLE;
    const ENABLE: u32 = MEM_EXECUTE_OPTION_ENABLE;
    const PERMANENT: u32 = MEM_EXECUTE_OPTION_PERMANENT;

    #[test]
    fn each_policy_gives_its_options() {
        assert_eq!(DEP_POLICY, DepPolicy::OptIn, "the XP SP2 default (ADR-020)");
        assert_eq!(DepPolicy::OptIn.initial_options(), ENABLE);
        assert_eq!(DepPolicy::OptOut.initial_options(), DISABLE);
        assert_eq!(DepPolicy::AlwaysOn.initial_options(), DISABLE | PERMANENT);
        assert_eq!(DepPolicy::AlwaysOff.initial_options(), ENABLE | PERMANENT);
    }

    #[test]
    fn each_policy_shows_in_shared_user_data() {
        assert_eq!(DepPolicy::OptIn.nx_support_policy(), 2, "NX_SUPPORT_POLICY_OPTIN");
        assert_eq!(DepPolicy::OptOut.nx_support_policy(), 3);
        assert_eq!(DepPolicy::AlwaysOn.nx_support_policy(), 1);
        assert_eq!(DepPolicy::AlwaysOff.nx_support_policy(), 0);
    }

    #[test]
    fn options_change_until_made_permanent() {
        assert_eq!(changed_execute_options(ENABLE, DISABLE), Ok(DISABLE));
        let thunks = DISABLE | MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION;
        assert_eq!(changed_execute_options(DISABLE, thunks), Ok(thunks));
        assert_eq!(changed_execute_options(ENABLE, DISABLE | PERMANENT), Ok(DISABLE | PERMANENT));
        assert_eq!(changed_execute_options(DISABLE | PERMANENT, ENABLE), Err(STATUS_ACCESS_DENIED));
        for policy in [DepPolicy::AlwaysOn, DepPolicy::AlwaysOff] {
            assert_eq!(changed_execute_options(policy.initial_options(), DISABLE), Err(STATUS_ACCESS_DENIED));
        }
    }

    #[test]
    fn options_say_whether_dep_is_on() {
        for bad in [0, DISABLE | ENABLE, PERMANENT, ENABLE | 0x10] {
            assert_eq!(changed_execute_options(ENABLE, bad), Err(STATUS_INVALID_PARAMETER), "{bad:#x}");
        }
    }
}
