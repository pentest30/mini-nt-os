//! Kernel object base types.
//!
//! Every NT object starts with an OBJECT_HEADER, followed by the body.
//! We model this with a trait + Arc<dyn KernelObject>.

use alloc::sync::Arc;
use alloc::string::String;

/// Object type tag — determines which operations are valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType {
    Process,
    Thread,
    Event,
    Semaphore,
    Mutex,
    File,
    Section,     // memory-mapped file
    Key,         // registry key
    Timer,
    IoCompletion,
}

/// Object header (OBJECT_HEADER in NT internals).
pub struct ObjectHeader {
    pub name:      Option<String>,
    pub obj_type:  ObjectType,
    // Reference count is managed by Arc<dyn KernelObject>.
}

/// Trait every kernel object body must implement.
pub trait KernelObject: Send + Sync {
    fn header(&self) -> &ObjectHeader;
    fn obj_type(&self) -> ObjectType { self.header().obj_type }
}

/// A reference-counted pointer to any kernel object.
pub type ObjectRef = Arc<dyn KernelObject>;
