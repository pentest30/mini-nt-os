//! ABI crate (02 §10): `#[repr(C)]` layouts fixed by a contract that both
//! sides must honour, with no other definition anywhere (CLAUDE.md, rule 5).
//!
//! - [`fpu`]: the FXSAVE area of a thread's x87/SSE state (ADR-009).
//! - [`loader_block`]: loader → kernel handoff.
//! - [`ntstatus`]: `NtStatus` and the NTSTATUS values in use.
//!
//! The XP user-mode layouts (PEB, TEB, `KUSER_SHARED_DATA`, `CONTEXT`…) will
//! join it. `no_std`, without dependencies.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod fpu;
pub mod loader_block;
pub mod ntstatus;

pub use loader_block::*;
