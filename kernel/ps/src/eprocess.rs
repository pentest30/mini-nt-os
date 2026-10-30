//! EPROCESS — executive process object.
//!
//! Selected fields that matter for XP-era game compatibility, until the Ps
//! rewrite (M2) replaces this object with the real EPROCESS.

use alloc::string::String;
use alloc::sync::Arc;
use hal::sync::KSpinLock;
use mm::vad::VadTree;
use ob::{create_object, AccessMask, HandleTable, Object, ObjectType};

/// Process ID type (matches NT's CLIENT_ID.UniqueProcess).
pub type ProcessId = u64;

/// PROCESS_ALL_ACCESS as XP defines it.
pub const PROCESS_ALL_ACCESS: AccessMask = AccessMask(0x001F_0FFF);

/// The `Process` type, provisional until the Ps rewrite: every generic right
/// maps to full access.
pub static PROCESS_TYPE: ObjectType = ObjectType::new(
    "Process",
    PROCESS_ALL_ACCESS,
    ob::GenericMapping {
        read: PROCESS_ALL_ACCESS,
        write: PROCESS_ALL_ACCESS,
        execute: PROCESS_ALL_ACCESS,
        all: PROCESS_ALL_ACCESS,
    },
);

/// Executive Process object body.
pub struct EProcess {
    pub pid: ProcessId,
    pub image_name: String, // up to 15 chars in NT (EPROCESS.ImageFileName)
    pub handle_table: HandleTable,
    pub vad: KSpinLock<VadTree>,
    pub exit_code: KSpinLock<Option<i32>>,
}

impl EProcess {
    pub fn new(pid: ProcessId, image_name: &str) -> Arc<Object<Self>> {
        create_object(
            &PROCESS_TYPE,
            Self {
                pid,
                image_name: image_name.chars().take(15).collect(),
                handle_table: HandleTable::new(),
                vad: KSpinLock::new(VadTree::new()),
                exit_code: KSpinLock::new(None),
            },
        )
    }
}

static NEXT_PID: hal::sync::KSpinLock<ProcessId> = hal::sync::KSpinLock::new(4); // NT starts at PID 4

fn alloc_pid() -> ProcessId {
    let mut pid = NEXT_PID.lock();
    let p = *pid;
    *pid += 4;
    p
}

/// The System process (PID 4) — created at boot.
static SYSTEM_PROCESS: hal::sync::Once<Arc<Object<EProcess>>> = hal::sync::Once::new();

pub fn init_system_process() {
    SYSTEM_PROCESS.call_once(|| EProcess::new(4, "System"));
}

pub fn system_process() -> Arc<Object<EProcess>> {
    SYSTEM_PROCESS.get().expect("System process not initialised").clone()
}

/// Create a new user process (NtCreateProcess).
pub fn create(image_name: &str) -> Arc<Object<EProcess>> {
    EProcess::new(alloc_pid(), image_name)
}
