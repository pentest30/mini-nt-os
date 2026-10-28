//! ETHREAD / TEB stubs.

use alloc::sync::Arc;
use ob::{ObjectHeader, ObjectType, KernelObject};

pub type ThreadId = u64;

pub struct EThread {
    pub header: ObjectHeader,
    pub tid:    ThreadId,
}

impl KernelObject for EThread {
    fn header(&self) -> &ObjectHeader { &self.header }
}

impl EThread {
    pub fn new(tid: ThreadId) -> Arc<Self> {
        Arc::new(Self {
            header: ObjectHeader { name: None, obj_type: ObjectType::Thread },
            tid,
        })
    }
}
