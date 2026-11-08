use crate::stream::Stream;
use crate::{Error, Geometry, ReadAt, Record};
use alloc::vec;

/// A read-only NTFS volume. Owns its partition reader and the validated $MFT
/// mapping. No namespace lookup or directory index traversal is provided yet:
/// files are addressed by their MFT record number.
pub struct Volume<D> {
    device: D,
    geometry: Geometry,
    mft: Stream,
}

impl<D: ReadAt> Volume<D> {
    /// Bootstrap $MFT from its first FILE record. The full mapping must reside
    /// in this record; attribute lists and mirror recovery are not supported.
    pub fn open(mut device: D) -> Result<Self, Error> {
        let geometry = Geometry::read(&mut device)?;
        let mut first = vec![0; geometry.record_size as usize];
        device.read_exact_at(geometry.mft_cluster * u64::from(geometry.cluster_size), &mut first)?;
        let record = Record::parse(first)?;
        let mft = data_stream(&record, geometry)?;
        if record.is_directory()
            || matches!(mft, Stream::Resident(_))
            || !mft.fully_initialized()
            || mft.len() < u64::from(geometry.record_size)
            || mft.len() % u64::from(geometry.record_size) != 0
        {
            return Err(Error::Invalid("MFT stream"));
        }
        let mut volume = Self { device, geometry, mft };
        // Require the mapping to point back to the very record used to bootstrap it.
        let mapped = volume.record(0)?;
        if mapped.raw() != record.raw() {
            return Err(Error::Invalid("MFT bootstrap mapping"));
        }
        Ok(volume)
    }

    /// Validated boot geometry.
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Number of record slots in the initialized MFT (including unused ones).
    pub fn record_count(&self) -> u64 {
        self.mft.len() / u64::from(self.geometry.record_size)
    }

    /// Read a base FILE record by number. Unused slots return NotFound.
    pub fn record(&mut self, number: u64) -> Result<Record, Error> {
        if number >= self.record_count() {
            return Err(Error::NotFound);
        }
        let mut data = vec![0; self.geometry.record_size as usize];
        let offset = number.checked_mul(u64::from(self.geometry.record_size)).ok_or(Error::Bounds)?;
        if self.mft.read(&mut self.device, offset, &mut data)? != data.len() {
            return Err(Error::Bounds);
        }
        Record::parse(data)
    }

    /// Size of the unnamed DATA stream of a regular file.
    pub fn file_size(&mut self, number: u64) -> Result<u64, Error> {
        Ok(self.file_stream(number)?.len())
    }

    /// Read a regular file's unnamed DATA stream at a byte offset. Returns the
    /// number copied, zero at EOF. Bytes beyond that count remain untouched.
    /// Errors may leave a partially filled buffer; callers must discard it.
    pub fn read_file(&mut self, number: u64, offset: u64, out: &mut [u8]) -> Result<usize, Error> {
        let stream = self.file_stream(number)?;
        stream.read(&mut self.device, offset, out)
    }

    /// Return the underlying device, without performing any writes.
    pub fn into_inner(self) -> D {
        self.device
    }

    fn file_stream(&mut self, number: u64) -> Result<Stream, Error> {
        let record = self.record(number)?;
        if record.is_directory() {
            return Err(Error::Unsupported("directory data"));
        }
        data_stream(&record, self.geometry)
    }
}

fn data_stream(record: &Record, geometry: Geometry) -> Result<Stream, Error> {
    let attributes = record.attributes()?;
    let mut found = None;
    for attr in &attributes {
        if attr.kind == 0x80 && attr.name.is_empty() {
            if found.is_some() {
                return Err(Error::Unsupported("multiple DATA extents"));
            }
            found = Some(Stream::parse(attr, geometry)?);
        }
    }
    found.ok_or(Error::NotFound)
}
