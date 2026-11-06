//! The FAT32 on-disk format, shared by the host tools and the kernel
//! (ADR-022): the single source of truth of how Mino writes FAT32.
//! `no_std`, with `alloc`, on the pattern of `regf` (ADR-012).
//!
//! [`image`] builds a whole volume in memory; [`format`] formats an empty
//! volume sector by sector with constant memory. Both use the same FAT32
//! headers and geometry (512-byte sectors, one sector per cluster).
//!
//! The tests mount what [`image::build`] writes with the kernel's own FAT
//! reader (`io-manager`): what the tools write, the kernel reads back.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod format;
pub mod image;

pub use image::{build, path};
