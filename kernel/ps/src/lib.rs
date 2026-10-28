//! Ps — Process manager executive.
//!
//! Manages:
//!   - EPROCESS (executive process object)
//!   - ETHREAD  (executive thread object)
//!   - PEB      (Process Environment Block — read by every Win32 app)
//!   - TEB      (Thread Environment Block  — one per thread, FS: in 32-bit)
//!
//! The PEB/TEB layout must be XP-compatible because games read them
//! directly (GetLastError, TlsGetValue, heap pointer, etc.).
//!
//! NT reference: ntoskrnl/ps/

#![no_std]
extern crate alloc;

pub mod eprocess;
pub mod ethread;
pub mod loader;
pub mod peb;
pub mod teb;

pub use eprocess::EProcess;
pub use ethread::EThread;

/// Initialise the process manager. Creates the initial System process.
pub fn init() {
    eprocess::init_system_process();
    log::info!("Ps: System process created");
}
