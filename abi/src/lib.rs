//! ABI crate (02 §10): `#[repr(C)]` layouts fixed by a contract that both
//! sides must honour, with no other definition anywhere (CLAUDE.md, rule 5).
//!
//! - [`bugcheck`]: the codes of the fatal error screen (`KeBugCheckEx`).
//! - [`context`]: the x86 `CONTEXT` of a thread.
//! - [`exception`]: the x86 `EXCEPTION_RECORD`.
//! - [`file`]: `IO_STATUS_BLOCK`, the values and information of the file
//!   services.
//! - [`fpu`]: the FXSAVE area of a thread's x87/SSE state (ADR-009).
//! - [`loader_block`]: loader → kernel handoff.
//! - [`ntstatus`]: `NtStatus` and the NTSTATUS values in use.
//! - [`object`]: access masks, generic mapping, object attributes.
//! - [`peb32`], [`teb32`]: the PEB and TEB of an i386 process, as on XP SP2.
//! - [`process`]: values about processes, such as their execute options.
//! - [`security`]: SIDs, ACLs, security descriptors and tokens (Se).
//! - [`service`], [`services`]: the system service tables, generated from the
//!   pinned ReactOS version by `tools/syscall-gen` (ADR-002).
//! - [`shared_data`]: `KUSER_SHARED_DATA`, as on XP SP2.
//!
//! `no_std`, without dependencies.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod bugcheck;
pub mod context;
pub mod exception;
pub mod file;
pub mod fpu;
pub mod loader_block;
pub mod lpc;
pub mod memory;
pub mod ntstatus;
pub mod object;
pub mod peb32;
pub mod process;
pub mod process_parameters;
pub mod registry;
pub mod security;
pub mod service;
pub mod services;
pub mod shared_data;
pub mod system_information;
pub mod teb32;

pub use loader_block::*;
