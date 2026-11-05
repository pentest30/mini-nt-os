//! The FAT32 on-disk format, shared by the host tools and the kernel
//! (ADR-022): the single source of truth of how Mino writes FAT32.
//! `no_std`, with `alloc`, on the pattern of `regf` (ADR-012).
//!
//! Today [`image`] builds a whole volume in memory — what `tools/mkfat`
//! lays out on the boot disk, byte for byte the image it built before the
//! crate existed. The formatting of a mounted volume, sector by sector
//! (a `WriteSectors` trait, without a buffer the size of the disk), comes
//! with the installer's kernel side: it will live beside [`image`], sharing
//! this crate's geometry and directory entries.
//!
//! The tests mount what [`image::build`] writes with the kernel's own FAT
//! reader (`io-manager`): what the tools write, the kernel reads back.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod image;

pub use image::{build, path};
