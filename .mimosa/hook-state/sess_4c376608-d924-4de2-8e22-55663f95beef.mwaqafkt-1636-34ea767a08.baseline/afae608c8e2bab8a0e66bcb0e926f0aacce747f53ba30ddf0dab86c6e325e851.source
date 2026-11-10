use crate::{bytes, u16_at, u64_at, Error, ReadAt};

/// Validated geometry of the supported NTFS volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Logical sector size (currently only 512 bytes).
    pub sector_size: u16,
    /// Bytes per cluster, at most 64 KiB.
    pub cluster_size: u32,
    /// Bytes per FILE record, at most 64 KiB.
    pub record_size: u32,
    /// Declared volume size in bytes, bounded by the supplied partition.
    pub volume_size: u64,
    /// First cluster of the master file table.
    pub mft_cluster: u64,
    /// First cluster of the master file table mirror.
    pub mirror_cluster: u64,
}

impl Geometry {
    /// Read and validate the volume boot sector without writing to the device.
    pub fn read(device: &mut impl ReadAt) -> Result<Self, Error> {
        let mut boot = [0; 512];
        if device.len() < boot.len() as u64 {
            return Err(Error::Bounds);
        }
        device.read_exact_at(0, &mut boot)?;
        Self::parse(&boot, device.len())
    }

    /// Validate an NTFS boot sector against the physical partition size.
    pub fn parse(boot: &[u8], partition_size: u64) -> Result<Self, Error> {
        if bytes(boot, 3, 8)? != b"NTFS    " || bytes(boot, 510, 2)? != [0x55, 0xaa] {
            return Err(Error::Invalid("boot signature"));
        }
        let sector_size = u16_at(boot, 11)?;
        if sector_size != 512 {
            return Err(Error::Unsupported("sector size"));
        }
        let sectors_per_cluster = boot[13];
        if !sectors_per_cluster.is_power_of_two() || sectors_per_cluster > 128 {
            return Err(Error::Unsupported("cluster size"));
        }
        if boot[14..21].iter().any(|b| *b != 0) || boot[22..24] != [0, 0] || boot[32..36] != [0; 4] {
            return Err(Error::Invalid("reserved BPB fields"));
        }
        let cluster_size = u32::from(sector_size) * u32::from(sectors_per_cluster);
        let sectors = u64_at(boot, 40)?;
        let volume_size = sectors.checked_mul(u64::from(sector_size)).ok_or(Error::Bounds)?;
        if volume_size == 0 || volume_size > partition_size {
            return Err(Error::Bounds);
        }
        let mft_cluster = u64_at(boot, 48)?;
        let mirror_cluster = u64_at(boot, 56)?;
        let encoding = boot[64] as i8;
        let record_size = if encoding < 0 {
            1u32.checked_shl(u32::from(encoding.unsigned_abs())).ok_or(Error::Bounds)?
        } else {
            u32::from(encoding as u8).checked_mul(cluster_size).ok_or(Error::Bounds)?
        };
        if !(512..=65536).contains(&record_size) || !record_size.is_power_of_two() {
            return Err(Error::Unsupported("FILE record size"));
        }
        for cluster in [mft_cluster, mirror_cluster] {
            let end = cluster
                .checked_mul(u64::from(cluster_size))
                .and_then(|offset| offset.checked_add(u64::from(record_size)))
                .ok_or(Error::Bounds)?;
            if cluster == 0 || end > volume_size {
                return Err(Error::Bounds);
            }
        }
        Ok(Self { sector_size, cluster_size, record_size, volume_size, mft_cluster, mirror_cluster })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> [u8; 512] {
        let mut b = [0; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 8;
        b[40..48].copy_from_slice(&2048u64.to_le_bytes());
        b[48..56].copy_from_slice(&4u64.to_le_bytes());
        b[56..64].copy_from_slice(&128u64.to_le_bytes());
        b[64] = (-10i8) as u8;
        b[510..512].copy_from_slice(&[0x55, 0xaa]);
        b
    }

    #[test]
    fn signed_record_size_and_partition_boundary() {
        let mut b = boot();
        let g = Geometry::parse(&b, 1048576).unwrap();
        assert_eq!((g.cluster_size, g.record_size), (4096, 1024));
        b[64] = 1;
        assert_eq!(Geometry::parse(&b, 1048576).unwrap().record_size, 4096);
        assert_eq!(Geometry::parse(&b, 1048575), Err(Error::Bounds));
    }

    #[test]
    fn rejects_truncation_overflow_and_unsupported_geometry() {
        let good = boot();
        for end in 0..512 {
            assert!(Geometry::parse(&good[..end], 1048576).is_err());
        }
        for (offset, value) in [(3, 0), (13, 0), (13, 3), (14, 1), (64, 0), (64, 128)] {
            let mut b = good;
            b[offset] = value;
            assert!(Geometry::parse(&b, 1048576).is_err());
        }
        let mut b = good;
        b[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(Geometry::parse(&b, u64::MAX), Err(Error::Bounds));
        b = good;
        b[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(Geometry::parse(&b, u64::MAX), Err(Error::Bounds));
    }
}
