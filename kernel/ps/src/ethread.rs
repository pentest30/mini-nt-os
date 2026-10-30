//! ETHREAD / TEB stubs, until the Ps rewrite (M2).

use alloc::sync::Arc;
use ob::{create_object, AccessMask, Object, ObjectType};

pub type ThreadId = u64;

/// THREAD_ALL_ACCESS as XP defines it.
pub const THREAD_ALL_ACCESS: AccessMask = AccessMask(0x001F_03FF);

/// The `Thread` type, provisional until the Ps rewrite: every generic right
/// maps to full access.
pub static THREAD_TYPE: ObjectType = ObjectType::new(
    "Thread",
    THREAD_ALL_ACCESS,
    ob::GenericMapping {
        read: THREAD_ALL_ACCESS,
        write: THREAD_ALL_ACCESS,
        execute: THREAD_ALL_ACCESS,
        all: THREAD_ALL_ACCESS,
    },
);

pub struct EThread {
    pub tid: ThreadId,
}

impl EThread {
    pub fn new(tid: ThreadId) -> Arc<Object<Self>> {
        create_object(&THREAD_TYPE, Self { tid })
    }
}
