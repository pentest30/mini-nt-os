//! ABI crate (02 §10): `#[repr(C)]` layouts fixed by a contract that both
//! sides must honour, with no other definition anywhere (CLAUDE.md, rule 5).
//!
//! - [`loader_block`]: loader → kernel handoff.
//!
//! The XP user-mode layouts (PEB, TEB, `KUSER_SHARED_DATA`, `CONTEXT`…) will
//! join it. `no_std`, without dependencies.

#![no_std]

pub mod loader_block;

pub use loader_block::*;
