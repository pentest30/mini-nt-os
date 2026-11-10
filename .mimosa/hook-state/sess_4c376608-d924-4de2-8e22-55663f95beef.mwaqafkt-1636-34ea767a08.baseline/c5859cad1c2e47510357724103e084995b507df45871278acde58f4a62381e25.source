use crate::record::Attribute;
use crate::{bytes, u16_at, u32_at, u64_at, Error, Geometry, ReadAt};
use alloc::vec::Vec;

#[derive(Debug)]
pub(crate) struct Run {
    start: u64,
    length: u64,
    disk: u64,
}

/// An unnamed DATA stream. Reads are bounded and return zero for the valid
/// but not yet initialized tail. Compressed, encrypted and sparse streams
/// are explicitly unsupported. The stream is tied to its originating Volume.
#[derive(Debug)]
pub(crate) enum Stream {
    Resident(Vec<u8>),
    Runs { runs: Vec<Run>, size: u64, initialized: u64 },
}

impl Stream {
    pub fn parse(attr: &Attribute<'_>, g: Geometry) -> Result<Self, Error> {
        Self::assemble(&[attr], g)
    }

    /// Assemble a complete, ordered stream. Only the first extent defines the
    /// stream sizes; extension records' size fields are not authoritative.
    pub fn assemble(attrs: &[&Attribute<'_>], g: Geometry) -> Result<Self, Error> {
        Self::assemble_inner(attrs, g, true)
    }

    /// Bootstrap-only mapping with holes. Call `covers` before each read; this
    /// stream must never escape as a mounted volume's complete MFT mapping.
    pub(crate) fn assemble_partial(attrs: &[&Attribute<'_>], g: Geometry) -> Result<Self, Error> {
        Self::assemble_inner(attrs, g, false)
    }

    fn assemble_inner(attrs: &[&Attribute<'_>], g: Geometry, complete: bool) -> Result<Self, Error> {
        let first = attrs.first().ok_or(Error::NotFound)?;
        if u16_at(first.data, 12)? != 0 {
            return Err(Error::Unsupported("compressed, encrypted or sparse attribute"));
        }
        if !first.nonresident {
            if attrs.len() != 1 {
                return Err(Error::Invalid("multiple resident extents"));
            }
            return Ok(Self::Resident(
                bytes(first.data, first.payload_offset, u32_at(first.data, 16)? as usize)?.to_vec(),
            ));
        }
        let allocated = u64_at(first.data, 40)?;
        let size = u64_at(first.data, 48)?;
        let initialized = u64_at(first.data, 56)?;
        if initialized > size || size > allocated || allocated > g.volume_size {
            return Err(Error::Invalid("stream sizes"));
        }
        if u64_at(first.data, 16)? != 0 {
            return Err(Error::Invalid("first extent VCN"));
        }
        let mut runs = Vec::new();
        let mut next = 0;
        for attr in attrs {
            if !attr.nonresident {
                return Err(Error::Invalid("mixed resident and nonresident extents"));
            }
            let lowest = u64_at(attr.data, 16)?;
            if lowest < next || (complete && lowest != next) {
                return Err(Error::Invalid("extent gap or overlap"));
            }
            let part = Self::extent(attr, g)?;
            if runs.len() + part.len() > 4096 {
                return Err(Error::Unsupported("too many runs"));
            }
            runs.extend(part);
            next = u64_at(attr.data, 24)?.checked_add(1).ok_or(Error::Bounds)?;
        }
        let end = next.checked_mul(u64::from(g.cluster_size)).ok_or(Error::Bounds)?;
        if end > allocated || (complete && end != allocated) {
            return Err(Error::Invalid("mapping coverage"));
        }
        Ok(Self::Runs { runs, size, initialized })
    }

    /// Whether the entire byte range has initialized, known physical mappings.
    /// A partial bootstrap mapping must not issue I/O through an unknown hole.
    pub(crate) fn covers(&self, offset: u64, length: u64) -> bool {
        let Some(end) = offset.checked_add(length) else { return false };
        match self {
            Self::Resident(data) => end <= data.len() as u64,
            Self::Runs { runs, size, initialized } => {
                if end > *size || end > *initialized {
                    return false;
                }
                let mut at = offset;
                for run in runs {
                    if at == end {
                        return true;
                    }
                    if run.start > at {
                        return false;
                    }
                    if at < run.start + run.length {
                        at = end.min(run.start + run.length);
                    }
                }
                at == end
            }
        }
    }

    fn extent(attr: &Attribute<'_>, g: Geometry) -> Result<Vec<Run>, Error> {
        if u16_at(attr.data, 12)? != 0 {
            return Err(Error::Unsupported("compressed, encrypted or sparse attribute"));
        }
        if u16_at(attr.data, 34)? != 0 {
            return Err(Error::Unsupported("compression unit"));
        }
        let first_vcn = u64_at(attr.data, 16)?;
        let last_vcn = u64_at(attr.data, 24)?;
        let expected = last_vcn
            .checked_sub(first_vcn)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(u64::from(g.cluster_size)))
            .ok_or(Error::Bounds)?;
        let start = first_vcn.checked_mul(u64::from(g.cluster_size)).ok_or(Error::Bounds)?;
        let mapping = &attr.data[attr.payload_offset..];
        let mut runs = Vec::new();
        let mut at = 0;
        let mut total = 0u64;
        let mut lcn = 0i64;
        loop {
            let header = *mapping.get(at).ok_or(Error::Bounds)?;
            at += 1;
            if header == 0 {
                break;
            }
            let length_bytes = usize::from(header & 15);
            let offset_bytes = usize::from(header >> 4);
            if !(1..=8).contains(&length_bytes) || offset_bytes > 8 {
                return Err(Error::Invalid("mapping pair width"));
            }
            if offset_bytes == 0 {
                return Err(Error::Unsupported("sparse run"));
            }
            let mut length = [0; 8];
            length[..length_bytes].copy_from_slice(bytes(mapping, at, length_bytes)?);
            at += length_bytes;
            let delta = bytes(mapping, at, offset_bytes)?;
            let mut offset = if delta[offset_bytes - 1] & 0x80 != 0 { [0xff; 8] } else { [0; 8] };
            offset[..offset_bytes].copy_from_slice(delta);
            at += offset_bytes;
            let clusters = u64::from_le_bytes(length);
            if clusters == 0 {
                return Err(Error::Invalid("zero length run"));
            }
            lcn = lcn.checked_add(i64::from_le_bytes(offset)).ok_or(Error::Bounds)?;
            let disk = u64::try_from(lcn)
                .map_err(|_| Error::Bounds)?
                .checked_mul(u64::from(g.cluster_size))
                .ok_or(Error::Bounds)?;
            let length = clusters.checked_mul(u64::from(g.cluster_size)).ok_or(Error::Bounds)?;
            if disk.checked_add(length).ok_or(Error::Bounds)? > g.volume_size {
                return Err(Error::Bounds);
            }
            // Bound metadata memory even when the record contains tiny mapping pairs.
            if runs.len() == 4096 {
                return Err(Error::Unsupported("too many runs"));
            }
            runs.push(Run { start: start.checked_add(total).ok_or(Error::Bounds)?, length, disk });
            total = total.checked_add(length).ok_or(Error::Bounds)?;
        }
        if total != expected {
            return Err(Error::Invalid("mapping coverage"));
        }
        Ok(runs)
    }

    pub fn len(&self) -> u64 {
        match self {
            Self::Resident(data) => data.len() as u64,
            Self::Runs { size, .. } => *size,
        }
    }

    pub fn fully_initialized(&self) -> bool {
        match self {
            Self::Resident(_) => true,
            Self::Runs { size, initialized, .. } => size == initialized,
        }
    }

    pub fn read(&self, device: &mut impl ReadAt, offset: u64, out: &mut [u8]) -> Result<usize, Error> {
        if offset >= self.len() {
            return Ok(0);
        }
        let count = (self.len() - offset).min(out.len() as u64) as usize;
        match self {
            Self::Resident(data) => out[..count].copy_from_slice(bytes(data, offset as usize, count)?),
            Self::Runs { runs, initialized, .. } => {
                let valid = initialized.saturating_sub(offset).min(count as u64) as usize;
                let mut done = 0;
                for run in runs {
                    let position = offset + done as u64;
                    if done == valid {
                        break;
                    }
                    if position < run.start || position >= run.start + run.length {
                        continue;
                    }
                    let within = position - run.start;
                    let take = (run.length - within).min((valid - done) as u64) as usize;
                    let disk = run.disk + within;
                    if disk.checked_add(take as u64).ok_or(Error::Bounds)? > device.len() {
                        return Err(Error::Bounds);
                    }
                    device.read_exact_at(disk, &mut out[done..done + take])?;
                    done += take;
                }
                if done != valid {
                    return Err(Error::Invalid("mapping gap"));
                }
                out[valid..count].fill(0);
            }
        }
        Ok(count)
    }
}
