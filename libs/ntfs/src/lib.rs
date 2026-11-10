//! Bounded, read-only NTFS format reader, independent of kernel and device drivers.
//!
//! The caller supplies a partition-bounded byte reader. No write operation is
//! exposed. All offsets are relative to that partition. Calls may perform I/O
//! and allocate: a future kernel adapter must call them at PASSIVE_LEVEL.
//! On-disk fields are decoded from bytes, never cast to native structures.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod attribute_list;
mod boot;
mod index;
mod information;
mod mft;
pub use information::Metadata;
mod namespace;
pub use index::{DirectoryEntry, FileReference};
mod record;
mod stream;
mod volume;
pub use volume::Volume;

#[cfg(test)]
mod extent_tests;
#[cfg(test)]
mod mft_tests;
#[cfg(test)]
mod path_tests;
#[cfg(test)]
mod tests;
pub use boot::Geometry;
pub use record::Record;

/// A malformed volume, unsupported feature, or failed device read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The requested bytes lie outside the supplied partition or structure.
    Bounds,
    /// On-disk metadata violates the supported NTFS format.
    Invalid(&'static str),
    /// The volume uses a feature deliberately excluded from this reader.
    Unsupported(&'static str),
    /// The backing device failed to provide the requested bytes.
    Io,
    /// A caller-specified file or attribute is absent.
    NotFound,
}

/// A partition-bounded read-only device. Implementations must fill the whole
/// destination or return an error. No operation may address a different partition.
///
/// # IRQL
/// Kernel implementations must be called at PASSIVE_LEVEL; reads may block.
pub trait ReadAt {
    /// Size of this partition in bytes; must remain stable while reading it.
    fn len(&self) -> u64;
    /// Whether the partition is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Read exactly `out.len()` bytes at a partition-relative offset.
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error>;
}

impl ReadAt for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        let start = usize::try_from(offset).map_err(|_| Error::Bounds)?;
        out.copy_from_slice(bytes(self, start, out.len())?);
        Ok(())
    }
}

pub(crate) fn bytes(data: &[u8], at: usize, len: usize) -> Result<&[u8], Error> {
    data.get(at..at.checked_add(len).ok_or(Error::Bounds)?).ok_or(Error::Bounds)
}
pub(crate) fn u16_at(data: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(bytes(data, at, 2)?.try_into().map_err(|_| Error::Bounds)?))
}
pub(crate) fn u64_at(data: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(bytes(data, at, 8)?.try_into().map_err(|_| Error::Bounds)?))
}

pub(crate) fn u32_at(data: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(bytes(data, at, 4)?.try_into().map_err(|_| Error::Bounds)?))
}
