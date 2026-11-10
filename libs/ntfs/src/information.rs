use crate::{u32_at, u64_at, Error, FileReference, ReadAt, Volume};
use alloc::{vec, vec::Vec};

/// Basic information from the current FILE and STANDARD_INFORMATION attribute.
#[derive(Clone, Copy, Debug)]
pub struct Metadata {
    /// Whether the record describes a directory.
    pub directory: bool,
    /// Unnamed DATA length, zero for a directory.
    pub size: u64,
    /// NT file attribute bits (not volume write protection).
    pub attributes: u32,
    /// Creation time in 100 ns units since 1601.
    pub creation_time: u64,
    /// Last modification time in NT units.
    pub last_write_time: u64,
    /// Last access time in NT units.
    pub last_access_time: u64,
}

impl<D: ReadAt> Volume<D> {
    /// Retrieve metadata after validating the supplied FILE sequence.
    pub fn metadata(&mut self, reference: FileReference) -> Result<Metadata, Error> {
        let directory = self.referenced_record(reference)?.is_directory();
        let stream = self.stream(reference.record, 0x10, &[])?.ok_or(Error::Invalid("STANDARD_INFORMATION missing"))?;
        if !stream.fully_initialized() || !matches!(stream.len(), 48 | 72) {
            return Err(Error::Invalid("STANDARD_INFORMATION size"));
        }
        let mut data = [0; 48];
        if stream.read(&mut self.device, 0, &mut data)? != data.len() {
            return Err(Error::Bounds);
        }
        Ok(Metadata {
            directory,
            size: if directory { 0 } else { self.file_size(reference.record)? },
            attributes: u32_at(&data, 32)?,
            creation_time: u64_at(&data, 0)?,
            last_write_time: u64_at(&data, 8)?,
            last_access_time: u64_at(&data, 24)?,
        })
    }

    /// Volume label from $Volume, preserving its UTF-16 encoding.
    pub fn volume_label(&mut self) -> Result<Vec<u16>, Error> {
        let Some(stream) = self.stream(3, 0x60, &[])? else { return Ok(Vec::new()) };
        if stream.len() > 512 || stream.len() % 2 != 0 || !stream.fully_initialized() {
            return Err(Error::Invalid("volume label"));
        }
        let mut data = vec![0; stream.len() as usize];
        if stream.read(&mut self.device, 0, &mut data)? != data.len() {
            return Err(Error::Bounds);
        }
        Ok(data.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect())
    }

    /// Count unallocated clusters from $Bitmap, excluding padding bits.
    pub fn free_clusters(&mut self) -> Result<u64, Error> {
        let clusters = self.geometry.volume_size / u64::from(self.geometry.cluster_size);
        let length = clusters.div_ceil(8);
        let stream = self.file_stream(6)?;
        if stream.len() < length || !stream.fully_initialized() {
            return Err(Error::Invalid("volume bitmap"));
        }
        let mut data = [0; 4096];
        let mut offset = 0;
        let mut used = 0;
        while offset < length {
            let take = (length - offset).min(data.len() as u64) as usize;
            if stream.read(&mut self.device, offset, &mut data[..take])? != take {
                return Err(Error::Bounds);
            }
            for (i, byte) in data[..take].iter().enumerate() {
                let bits = (clusters - (offset + i as u64) * 8).min(8);
                used += u64::from((byte & (0xff >> (8 - bits))).count_ones());
            }
            offset += take as u64;
        }
        Ok(clusters - used)
    }
}
