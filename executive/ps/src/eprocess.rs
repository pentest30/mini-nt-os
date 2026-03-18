//! EPROCESS — executive process object.
//!
//! Selected fields that matter for XP-era game compatibility.
//! Full NT EPROCESS is ~600 bytes on XP x86; we include what we need.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::Mutex;
use ob::handle::HandleTable;
use mm::vad::VadTree;
use ob::{ObjectHeader, ObjectType, KernelObject};

/// Process ID type (matches NT's CLIENT_ID.UniqueProcess).
pub type ProcessId = u64;

/// Executive Process object.
pub struct EProcess {
    pub header:      ObjectHeader,
    pub pid:         ProcessId,
    pub image_name:  String,          // up to 15 chars in NT (EPROCESS.ImageFileName)
    pub handle_table: Mutex<HandleTable>,
    pub vad:         Mutex<VadTree>,
    pub exit_code:   Mutex<Option<i32>>,
}

impl KernelObject for EProcess {
    fn header(&self) -> &ObjectHeader { &self.header }
}

impl EProcess {
    pub fn new(pid: ProcessId, image_name: &str) -> Arc<Self> {
        Arc::new(Self {
            header: ObjectHeader {
                name:     None,
                obj_type: ObjectType::Process,
            },
            pid,
            image_name: image_name.chars().take(15).collect(),
            handle_table: Mutex::new(HandleTable::new()),
            vad:          Mutex::new(VadTree::new()),
            exit_code:    Mutex::new(None),
        })
    }
}

static NEXT_PID: spin::Mutex<ProcessId> = spin::Mutex::new(4); // NT starts at PID 4

fn alloc_pid() -> ProcessId {
    let mut pid = NEXT_PID.lock();
    let p = *pid;
    *pid += 4;
    p
}

/// The System process (PID 4) — created at boot.
static SYSTEM_PROCESS: spin::Once<Arc<EProcess>> = spin::Once::new();

pub fn init_system_process() {
    SYSTEM_PROCESS.call_once(|| EProcess::new(4, "System"));
}

pub fn system_process() -> Arc<EProcess> {
    SYSTEM_PROCESS.get().expect("System process not initialised").clone()
}

/// Create a new user process (NtCreateProcess).
pub fn create(image_name: &str) -> Arc<EProcess> {
    EProcess::new(alloc_pid(), image_name)
}
