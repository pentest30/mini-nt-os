//! Ob — Object Manager executive.
//!
//! NT's object manager provides:
//!   - A unified handle table per process (indices into a kernel object array)
//!   - Reference-counted kernel objects (OBJECT_HEADER + body)
//!   - A named object namespace (\\Device\\, \\Registry\\, \\BaseNamedObjects\\…)
//!   - Security descriptors (Phase 4 concern)
//!
//! Every kernel resource a game touches — files, events, mutexes, threads,
//! processes, sections — is an NT object managed here.

#![no_std]
extern crate alloc;

pub mod handle;
pub mod namespace;
pub mod object;

pub use handle::{Handle, HandleTable, INVALID_HANDLE};
pub use object::{KernelObject, ObjectType, ObjectHeader};

/// Initialise the object manager.
pub fn init() {
    namespace::init();
    log::info!("Ob: initialised");
}
