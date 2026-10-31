use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatError {
    Io,
    InvalidBpb,
    NotFound,
    NotAFile,
    PathFormat,
    Unsupported,
    /// The device cannot be written.
    ReadOnly,
    /// No free cluster is left.
    Full,
    /// A chain or an entry contradicts the volume.
    Corrupt,
}

pub trait BlockDevice {
    fn sector_size(&self) -> u32;
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError>;
    /// Writes the sector `lba`; a device that cannot is read-only.
    fn write_sector(&self, _lba: u64, _data: &[u8]) -> Result<(), FatError> {
        Err(FatError::ReadOnly)
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for alloc::boxed::Box<D> {
    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        (**self).read_sector(lba, out)
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        (**self).write_sector(lba, data)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Fat32Bpb {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
}

/// A directory entry (8.3), with its dates and times as FAT keeps them:
/// local time, a date of 0 when unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirEntry {
    pub attr: u8,
    pub first_cluster: u32,
    pub file_size: u32,
    pub creation_date: u16,
    pub creation_time: u16,
    /// Tenths of a second (0 to 199) to add to `creation_time`.
    pub creation_tenths: u8,
    pub access_date: u16,
    pub write_date: u16,
    pub write_time: u16,
}

impl DirEntry {
    fn parse(ent: &[u8]) -> Self {
        let u16_at = |at: usize| u16::from_le_bytes([ent[at], ent[at + 1]]);
        let hi = u16_at(20) as u32;
        let lo = u16_at(26) as u32;
        Self {
            attr: ent[11],
            first_cluster: (hi << 16) | lo,
            file_size: u32::from_le_bytes([ent[28], ent[29], ent[30], ent[31]]),
            creation_tenths: ent[13],
            creation_time: u16_at(14),
            creation_date: u16_at(16),
            access_date: u16_at(18),
            write_time: u16_at(22),
            write_date: u16_at(24),
        }
    }
}

/// A FAT date and time (local time, 2 s steps, plus `tenths` of a second)
/// as an NT time, in 100 ns since 1601 ; 0 for a date of 0 or invalid.
pub fn nt_time(date: u16, time: u16, tenths: u8) -> u64 {
    let (year, month, day) = (1980 + i64::from(date >> 9), i64::from((date >> 5) & 0xF), i64::from(date & 0x1F));
    let (hour, minute, second) = (u64::from(time >> 11), u64::from((time >> 5) & 0x3F), u64::from(time & 0x1F) * 2);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return 0,
    };
    if date == 0 || day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 || tenths > 199 {
        return 0;
    }
    // Days from 1970-01-01 (H. Hinnant's days_from_civil), then from 1601.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe - 719_468 + 134_774) as u64;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    seconds * 10_000_000 + u64::from(tenths) * 100_000
}

#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub name: String,
    pub attr: u8,
    pub first_cluster: u32,
    pub file_size: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct FatFile {
    pub first_cluster: u32,
    pub file_size: u32,
    pub position: u32,
}

pub struct FatVolume<D: BlockDevice> {
    device: D,
    bpb: Fat32Bpb,
    fat_start_lba: u64,
    data_start_lba: u64,
    /// The data clusters, numbered from 2; 0 when the BPB does not say (the
    /// volume is then read only).
    clusters: u32,
}

impl<D: BlockDevice> FatVolume<D> {
    #[inline(always)]
    pub fn mount(device: D) -> Result<Self, FatError> {
        let bytes_per_sector = device.sector_size();
        if !(512..=4096).contains(&bytes_per_sector) || (bytes_per_sector & (bytes_per_sector - 1)) != 0 {
            return Err(FatError::Unsupported);
        }
        let mut sector = vec![0u8; bytes_per_sector as usize];
        device.read_sector(0, &mut sector)?;
        if sector.len() < 90 {
            return Err(FatError::InvalidBpb);
        }
        let bps = u16::from_le_bytes([sector[11], sector[12]]);
        let spc = sector[13];
        let rsvd = u16::from_le_bytes([sector[14], sector[15]]);
        let fats = sector[16];
        let root_entries = u16::from_le_bytes([sector[17], sector[18]]);
        let total16 = u16::from_le_bytes([sector[19], sector[20]]) as u32;
        let sectors_per_fat16 = u16::from_le_bytes([sector[22], sector[23]]) as u32;
        let total32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let sectors_per_fat32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        let mut bps = bps;
        let mut spc = spc;
        let mut rsvd = rsvd;
        let mut fats = fats;
        let mut sectors_per_fat32 = sectors_per_fat32;
        let mut root_cluster = root_cluster;
        let mut first_data_sector: u32 = 0;
        let total_sectors = if total16 != 0 { total16 } else { total32 };
        let bpb_ok = bps != 0
            && spc != 0
            && rsvd != 0
            && fats != 0
            && root_cluster >= 2
            && bps as u32 == bytes_per_sector
            && root_entries == 0
            && sectors_per_fat16 == 0
            && sectors_per_fat32 != 0
            && {
                let total_sectors = if total16 != 0 { total16 } else { total32 };
                total_sectors != 0 && {
                    let f = rsvd as u32 + (fats as u32 * sectors_per_fat32);
                    f < total_sectors
                }
            };
        if bpb_ok {
            first_data_sector = rsvd as u32 + (fats as u32 * sectors_per_fat32);
        }
        if !bpb_ok && bytes_per_sector == 512 {
            let mut fat = vec![0u8; 512];
            device.read_sector(1, &mut fat)?;
            let e0 = u32::from_le_bytes([fat[0], fat[1], fat[2], fat[3]]) & 0x0FFF_FFFF;
            let e1 = u32::from_le_bytes([fat[4], fat[5], fat[6], fat[7]]) & 0x0FFF_FFFF;
            if e0 < 0x0FFF_FFF8 || e1 != 0x0FFF_FFFF {
                return Err(FatError::InvalidBpb);
            }
            bps = 512;
            spc = 1;
            rsvd = 1;
            fats = 1;
            sectors_per_fat32 = 1;
            root_cluster = 2;
            first_data_sector = 2;
        } else if bpb_ok {
            // already handled above
        } else {
            return Err(FatError::InvalidBpb);
        }
        let vol = Self {
            device,
            bpb: Fat32Bpb {
                bytes_per_sector: bps,
                sectors_per_cluster: spc,
                reserved_sectors: rsvd,
                fat_count: fats,
                sectors_per_fat: sectors_per_fat32,
                root_cluster,
            },
            fat_start_lba: rsvd as u64,
            data_start_lba: first_data_sector as u64,
            clusters: if bpb_ok { (total_sectors - first_data_sector) / u32::from(spc) } else { 0 },
        };
        Ok(vol)
    }

    pub fn bpb(&self) -> Fat32Bpb {
        self.bpb
    }

    /// The device it is mounted on.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Mount and open a file in a single stack frame, avoiding cross-frame copy of FatVolume.
    #[inline(always)]
    pub fn mount_and_open(device: D, path: &str) -> Result<FatFile, FatError> {
        let vol = Self::mount(device)?;
        vol.open(path)
    }

    /// Mount and read a file in a single stack frame, avoiding cross-frame copy of FatVolume.
    #[inline(always)]
    pub fn mount_and_read(device: D, file: &mut FatFile, out: &mut [u8]) -> Result<usize, FatError> {
        let vol = Self::mount(device)?;
        vol.read(file, out)
    }

    pub fn open(&self, path: &str) -> Result<FatFile, FatError> {
        let bps = self.bpb.bytes_per_sector;
        let spc = self.bpb.sectors_per_cluster;
        if !(512..=4096).contains(&bps) || (bps & (bps - 1)) != 0 || spc == 0 {
            return Err(FatError::InvalidBpb);
        }
        let mut cluster = self.bpb.root_cluster;
        let mut parts = path.split('/').filter(|s| !s.is_empty());
        let first = parts.next().ok_or(FatError::PathFormat)?;
        let mut pending = Some(first);
        while let Some(name) = pending.take() {
            let entry = self.find_in_dir(cluster, name)?;
            if let Some(next) = parts.next() {
                if (entry.attr & 0x10) == 0 {
                    return Err(FatError::NotFound);
                }
                cluster = entry.first_cluster;
                pending = Some(next);
                continue;
            }
            if (entry.attr & 0x10) != 0 {
                return Err(FatError::NotAFile);
            }
            return Ok(FatFile { first_cluster: entry.first_cluster, file_size: entry.file_size, position: 0 });
        }
        Err(FatError::NotFound)
    }

    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntryInfo>, FatError> {
        let bps = self.bpb.bytes_per_sector;
        let spc = self.bpb.sectors_per_cluster;
        if !(512..=4096).contains(&bps) || (bps & (bps - 1)) != 0 || spc == 0 {
            return Err(FatError::InvalidBpb);
        }
        let mut cluster = self.bpb.root_cluster;
        if path != "/" && !path.is_empty() {
            let parts = path.split('/').filter(|s| !s.is_empty());
            for name in parts {
                let entry = self.find_in_dir(cluster, name)?;
                if (entry.attr & 0x10) == 0 {
                    return Err(FatError::NotFound);
                }
                cluster = entry.first_cluster;
            }
        }
        self.read_dir_entries(cluster)
    }

    pub fn read(&self, file: &mut FatFile, out: &mut [u8]) -> Result<usize, FatError> {
        if file.position >= file.file_size || out.is_empty() {
            return Ok(0);
        }
        let remaining = (file.file_size - file.position) as usize;
        let target = remaining.min(out.len());
        let bytes_per_sector = self.bpb.bytes_per_sector as usize;
        let sectors_per_cluster = self.bpb.sectors_per_cluster as usize;
        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return Err(FatError::InvalidBpb);
        }
        let bytes_per_cluster = bytes_per_sector * sectors_per_cluster;
        let mut cluster = file.first_cluster;
        let mut skip = file.position as usize / bytes_per_cluster;
        while skip > 0 {
            cluster = self.next_cluster(cluster)?;
            skip -= 1;
        }
        let mut cluster_offset = file.position as usize % bytes_per_cluster;
        let mut written = 0usize;
        let mut buf = vec![0u8; bytes_per_cluster];
        while written < target {
            self.read_cluster(cluster, &mut buf)?;
            let can_take = (bytes_per_cluster - cluster_offset).min(target - written);
            out[written..written + can_take].copy_from_slice(&buf[cluster_offset..cluster_offset + can_take]);
            written += can_take;
            cluster_offset = 0;
            if written < target {
                cluster = self.next_cluster(cluster)?;
            }
        }
        file.position = file.position.saturating_add(written as u32);
        Ok(written)
    }

    /// The cluster of the root directory.
    pub fn root_cluster(&self) -> u32 {
        self.bpb.root_cluster
    }

    /// The size of a cluster, in bytes.
    pub fn cluster_bytes(&self) -> u32 {
        u32::from(self.bpb.bytes_per_sector) * u32::from(self.bpb.sectors_per_cluster)
    }

    /// The entry `name` (8.3, any case) of the directory at `dir_cluster`;
    /// `NotFound` without it, `Unsupported` for a name 8.3 cannot hold.
    pub fn find_in_dir(&self, dir_cluster: u32, name: &str) -> Result<DirEntry, FatError> {
        self.find_entry(dir_cluster, name).map(|(entry, _)| entry)
    }

    /// [`find_in_dir`](Self::find_in_dir), with where the entry is.
    pub fn find_entry(&self, dir_cluster: u32, name: &str) -> Result<(DirEntry, EntryRef), FatError> {
        let target = short_name_11(name)?;
        let bps = self.bpb.bytes_per_sector as usize;
        let spc = self.bpb.sectors_per_cluster as usize;
        if !(512..=4096).contains(&bps) || spc == 0 {
            return Err(FatError::InvalidBpb);
        }
        let bytes_per_cluster = bps * spc;
        if bytes_per_cluster > 64 * 1024 {
            return Err(FatError::Unsupported);
        }
        let mut cluster = dir_cluster;
        let mut buf = vec![0u8; bytes_per_cluster];
        loop {
            self.read_cluster(cluster, &mut buf)?;
            let mut i = 0usize;
            while i + 32 <= buf.len() {
                let ent = &buf[i..i + 32];
                let first = ent[0];
                if first == 0x00 {
                    return Err(FatError::NotFound);
                }
                if first != 0xE5 {
                    // Neither a long-name part nor the volume label.
                    if ent[11] != 0x0F && ent[11] & 0x08 == 0 && ent[0..11] == target {
                        return Ok((DirEntry::parse(ent), EntryRef { cluster, index: (i / 32) as u32 }));
                    }
                }
                i += 32;
            }
            cluster = self.next_cluster(cluster)?;
        }
    }

    fn read_dir_entries(&self, dir_cluster: u32) -> Result<Vec<DirEntryInfo>, FatError> {
        let bps = self.bpb.bytes_per_sector as usize;
        let spc = self.bpb.sectors_per_cluster as usize;
        if !(512..=4096).contains(&bps) || spc == 0 {
            return Err(FatError::InvalidBpb);
        }
        let bytes_per_cluster = bps * spc;
        if bytes_per_cluster > 64 * 1024 {
            return Err(FatError::Unsupported);
        }
        let mut out = Vec::new();
        let mut cluster = dir_cluster;
        let mut buf = vec![0u8; bytes_per_cluster];
        loop {
            self.read_cluster(cluster, &mut buf)?;
            let mut i = 0usize;
            while i + 32 <= buf.len() {
                let ent = &buf[i..i + 32];
                let first = ent[0];
                if first == 0x00 {
                    return Ok(out);
                }
                if first != 0xE5 {
                    let attr = ent[11];
                    if attr != 0x0F {
                        let hi = u16::from_le_bytes([ent[20], ent[21]]) as u32;
                        let lo = u16::from_le_bytes([ent[26], ent[27]]) as u32;
                        let first_cluster = (hi << 16) | lo;
                        let file_size = u32::from_le_bytes([ent[28], ent[29], ent[30], ent[31]]);
                        let name = short_name_from_entry(ent);
                        out.push(DirEntryInfo { name, attr, first_cluster, file_size });
                    }
                }
                i += 32;
            }
            cluster = self.next_cluster(cluster)?;
        }
    }

    fn read_cluster(&self, cluster: u32, out: &mut [u8]) -> Result<(), FatError> {
        if cluster < 2 {
            return Err(FatError::InvalidBpb);
        }
        let bytes_per_sector = self.bpb.bytes_per_sector as usize;
        let sectors_per_cluster = self.bpb.sectors_per_cluster as usize;
        if out.len() != bytes_per_sector * sectors_per_cluster {
            return Err(FatError::InvalidBpb);
        }
        let first_lba = self.cluster_to_lba(cluster);
        let mut i = 0usize;
        while i < sectors_per_cluster {
            let start = i * bytes_per_sector;
            self.device.read_sector(first_lba + i as u64, &mut out[start..start + bytes_per_sector])?;
            i += 1;
        }
        Ok(())
    }

    fn cluster_to_lba(&self, cluster: u32) -> u64 {
        self.data_start_lba + ((cluster - 2) as u64 * self.bpb.sectors_per_cluster as u64)
    }

    fn next_cluster(&self, cluster: u32) -> Result<u32, FatError> {
        let bytes_per_sector = self.bpb.bytes_per_sector as usize;
        if bytes_per_sector == 0 {
            return Err(FatError::InvalidBpb);
        }
        let fat_offset = cluster as u64 * 4;
        let fat_sector = self.fat_start_lba + (fat_offset / bytes_per_sector as u64);
        let entry_offset = (fat_offset % bytes_per_sector as u64) as usize;
        let mut sec0 = vec![0u8; bytes_per_sector];
        self.device.read_sector(fat_sector, &mut sec0)?;
        let mut raw = [0u8; 4];
        if entry_offset <= bytes_per_sector - 4 {
            raw.copy_from_slice(&sec0[entry_offset..entry_offset + 4]);
        } else {
            let mut sec1 = vec![0u8; bytes_per_sector];
            self.device.read_sector(fat_sector + 1, &mut sec1)?;
            let left = bytes_per_sector - entry_offset;
            raw[..left].copy_from_slice(&sec0[entry_offset..]);
            raw[left..].copy_from_slice(&sec1[..4 - left]);
        }
        let next = u32::from_le_bytes(raw) & 0x0FFF_FFFF;
        if next >= 0x0FFF_FFF8 {
            return Err(FatError::NotFound);
        }
        if next < 2 {
            return Err(FatError::NotFound);
        }
        Ok(next)
    }
}

/// Where a directory entry is: the cluster of its directory that holds it,
/// and its index there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryRef {
    pub cluster: u32,
    pub index: u32,
}

/// The FAT value that ends a chain.
const END_OF_CHAIN: u32 = 0x0FFF_FFFF;
const ATTR_DIRECTORY: u8 = 0x10;

/// A directory entry for `name` (8.3, padded), without dates.
pub fn make_entry(name: &[u8; 11], attr: u8, first_cluster: u32, size: u32) -> [u8; 32] {
    let mut entry = [0u8; 32];
    entry[..11].copy_from_slice(name);
    entry[11] = attr;
    entry[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
    entry[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    entry
}

/// The 8.3 name of `name`, padded, in upper case; `Unsupported` if 8.3
/// cannot hold it.
pub fn short_name(name: &str) -> Result<[u8; 11], FatError> {
    short_name_11(name)
}

/// Writing (M4, ADR-017). The caller serialises the calls that write, and
/// the reads that may see them. Every FAT copy is written; the FSInfo
/// sector is left as it is (its free count stays "unknown"). New clusters
/// are zeroed. Dates are not written yet.
impl<D: BlockDevice> FatVolume<D> {
    fn bytes_per_sector(&self) -> usize {
        usize::from(self.bpb.bytes_per_sector)
    }

    fn check_cluster(&self, cluster: u32) -> Result<(), FatError> {
        if cluster < 2 || cluster >= self.clusters + 2 {
            return Err(FatError::Corrupt);
        }
        Ok(())
    }

    /// The FAT sector (in the first copy) and byte offset of `cluster`.
    fn fat_place(&self, cluster: u32) -> (u64, usize) {
        let offset = u64::from(cluster) * 4;
        let bps = self.bytes_per_sector() as u64;
        (self.fat_start_lba + offset / bps, (offset % bps) as usize)
    }

    /// The FAT entry of `cluster`: 0 free, [`END_OF_CHAIN`] (or above
    /// 0x0FFFFFF7) last, otherwise the next cluster.
    pub fn fat_entry(&self, cluster: u32) -> Result<u32, FatError> {
        let (lba, at) = self.fat_place(cluster);
        let mut sector = vec![0u8; self.bytes_per_sector()];
        self.device.read_sector(lba, &mut sector)?;
        Ok(u32::from_le_bytes([sector[at], sector[at + 1], sector[at + 2], sector[at + 3]]) & 0x0FFF_FFFF)
    }

    /// Sets the FAT entry of `cluster` in every copy, keeping its top four
    /// bits.
    fn set_fat_entry(&self, cluster: u32, value: u32) -> Result<(), FatError> {
        self.check_cluster(cluster)?;
        let (lba, at) = self.fat_place(cluster);
        let mut sector = vec![0u8; self.bytes_per_sector()];
        for copy in 0..u64::from(self.bpb.fat_count) {
            let lba = lba + copy * u64::from(self.bpb.sectors_per_fat);
            self.device.read_sector(lba, &mut sector)?;
            let old = u32::from_le_bytes([sector[at], sector[at + 1], sector[at + 2], sector[at + 3]]);
            let new = (old & 0xF000_0000) | (value & 0x0FFF_FFFF);
            sector[at..at + 4].copy_from_slice(&new.to_le_bytes());
            self.device.write_sector(lba, &sector)?;
        }
        Ok(())
    }

    fn zero_cluster(&self, cluster: u32) -> Result<(), FatError> {
        let zero = vec![0u8; self.bytes_per_sector()];
        let first = self.cluster_to_lba(cluster);
        for i in 0..u64::from(self.bpb.sectors_per_cluster) {
            self.device.write_sector(first + i, &zero)?;
        }
        Ok(())
    }

    /// A free cluster, from `hint` on, then from the start: zeroed, and the
    /// last of its chain. `Full` without one; `ReadOnly` for a volume whose
    /// size is unknown.
    pub fn allocate_cluster(&self, hint: u32) -> Result<u32, FatError> {
        if self.clusters == 0 {
            return Err(FatError::ReadOnly);
        }
        let end = self.clusters + 2;
        let start = if (2..end).contains(&hint) { hint } else { 2 };
        let per_sector = (self.bytes_per_sector() / 4) as u32;
        let mut sector = vec![0u8; self.bytes_per_sector()];
        let mut loaded = None;
        for cluster in (start..end).chain(2..start) {
            let (lba, at) = self.fat_place(cluster);
            if loaded != Some(lba) || cluster % per_sector == 0 {
                self.device.read_sector(lba, &mut sector)?;
                loaded = Some(lba);
            }
            if u32::from_le_bytes([sector[at], sector[at + 1], sector[at + 2], sector[at + 3]]) & 0x0FFF_FFFF == 0 {
                self.zero_cluster(cluster)?;
                self.set_fat_entry(cluster, END_OF_CHAIN)?;
                return Ok(cluster);
            }
        }
        Err(FatError::Full)
    }

    /// The clusters of the chain from `first`, in order; `Corrupt` for a
    /// chain that loops, leaves the volume or meets a free cluster.
    pub fn chain(&self, first: u32) -> Result<Vec<u32>, FatError> {
        let mut clusters = Vec::new();
        let mut cluster = first;
        loop {
            self.check_cluster(cluster)?;
            if clusters.len() > self.clusters as usize {
                return Err(FatError::Corrupt);
            }
            clusters.push(cluster);
            match self.fat_entry(cluster)? {
                next if next >= 0x0FFF_FFF8 => return Ok(clusters),
                0 | 1 => return Err(FatError::Corrupt),
                next => cluster = next,
            }
        }
    }

    /// Frees the chain from `first`.
    pub fn free_chain(&self, first: u32) -> Result<(), FatError> {
        for cluster in self.chain(first)? {
            self.set_fat_entry(cluster, 0)?;
        }
        Ok(())
    }

    /// Makes the chain from `*first` (0: none) `count` clusters long: frees
    /// the clusters past them, or adds zeroed ones, allocated from `hint`;
    /// `*first` becomes 0 for no cluster. Rends the chain.
    pub fn resize_chain(&self, first: &mut u32, count: usize, hint: u32) -> Result<Vec<u32>, FatError> {
        let mut clusters = if *first == 0 { Vec::new() } else { self.chain(*first)? };
        if count < clusters.len() {
            match count {
                0 => self.free_chain(clusters[0])?,
                _ => {
                    self.free_chain(clusters[count])?;
                    self.set_fat_entry(clusters[count - 1], END_OF_CHAIN)?;
                }
            }
            clusters.truncate(count);
        }
        let before = clusters.len();
        while clusters.len() < count {
            let hint = clusters.last().map_or(hint, |&last| last + 1);
            let new = match self.allocate_cluster(hint) {
                Ok(new) => new,
                Err(error) => {
                    // What was added goes back; shrinking allocates nothing.
                    let _ = self.resize_chain(first, before, hint);
                    return Err(error);
                }
            };
            match clusters.last() {
                Some(&last) => self.set_fat_entry(last, new)?,
                None => *first = new,
            }
            clusters.push(new);
        }
        if count == 0 {
            *first = 0;
        }
        Ok(clusters)
    }

    /// Writes `data` at the byte `offset` of the chain `clusters`.
    fn write_into(&self, clusters: &[u32], offset: u64, data: &[u8]) -> Result<(), FatError> {
        let bps = self.bytes_per_sector() as u64;
        let per_cluster = bps * u64::from(self.bpb.sectors_per_cluster);
        let mut sector = vec![0u8; bps as usize];
        let mut done = 0usize;
        while done < data.len() {
            let at = offset + done as u64;
            let cluster = *clusters.get((at / per_cluster) as usize).ok_or(FatError::Corrupt)?;
            let lba = self.cluster_to_lba(cluster) + (at % per_cluster) / bps;
            let within = (at % bps) as usize;
            let take = (bps as usize - within).min(data.len() - done);
            if take < bps as usize {
                self.device.read_sector(lba, &mut sector)?;
            }
            sector[within..within + take].copy_from_slice(&data[done..done + take]);
            self.device.write_sector(lba, &sector)?;
            done += take;
        }
        Ok(())
    }

    /// Writes `data` at `offset` in the file of first cluster `*first` and
    /// size `*size`, which grows to hold it (the gap between the old end and
    /// `offset` reads as zeros); both are updated. `Full` past 4 GiB or
    /// without room.
    pub fn write_file(
        &self,
        first: &mut u32,
        size: &mut u32,
        offset: u64,
        data: &[u8],
        hint: u32,
    ) -> Result<(), FatError> {
        let end =
            offset.checked_add(data.len() as u64).filter(|&end| end <= u64::from(u32::MAX)).ok_or(FatError::Full)?;
        let per_cluster = u64::from(self.cluster_bytes());
        let new_size = end.max(u64::from(*size));
        let clusters = self.resize_chain(first, new_size.div_ceil(per_cluster) as usize, hint)?;
        if offset > u64::from(*size) {
            // Bytes past the old end may hold what a truncation left there.
            let gap = vec![0u8; (offset - u64::from(*size)) as usize];
            self.write_into(&clusters, u64::from(*size), &gap)?;
        }
        self.write_into(&clusters, offset, data)?;
        *size = new_size as u32;
        Ok(())
    }

    /// Truncates (or extends with zeros) the file of first cluster `*first`
    /// and size `*size` to `new_size`; both are updated.
    pub fn set_file_size(&self, first: &mut u32, size: &mut u32, new_size: u32, hint: u32) -> Result<(), FatError> {
        if new_size > *size {
            let zeros = vec![0u8; (new_size - *size) as usize];
            let at = u64::from(*size);
            return self.write_file(first, size, at, &zeros, hint);
        }
        self.resize_chain(first, new_size.div_ceil(self.cluster_bytes()) as usize, hint)?;
        *size = new_size;
        Ok(())
    }

    /// The 32 bytes of the entry at `at`.
    pub fn read_entry(&self, at: EntryRef) -> Result<[u8; 32], FatError> {
        let (lba, within) = self.entry_place(at)?;
        let mut sector = vec![0u8; self.bytes_per_sector()];
        self.device.read_sector(lba, &mut sector)?;
        let mut entry = [0u8; 32];
        entry.copy_from_slice(&sector[within..within + 32]);
        Ok(entry)
    }

    /// Writes the entry at `at`.
    pub fn write_entry(&self, at: EntryRef, entry: &[u8; 32]) -> Result<(), FatError> {
        let (lba, within) = self.entry_place(at)?;
        let mut sector = vec![0u8; self.bytes_per_sector()];
        self.device.read_sector(lba, &mut sector)?;
        sector[within..within + 32].copy_from_slice(entry);
        self.device.write_sector(lba, &sector)
    }

    /// The first cluster and the size of the entry at `at`, rewritten.
    pub fn update_entry(&self, at: EntryRef, first_cluster: u32, size: u32) -> Result<(), FatError> {
        let mut entry = self.read_entry(at)?;
        entry[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
        entry[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        entry[28..32].copy_from_slice(&size.to_le_bytes());
        self.write_entry(at, &entry)
    }

    fn entry_place(&self, at: EntryRef) -> Result<(u64, usize), FatError> {
        self.check_cluster(at.cluster)?;
        let offset = at.index as usize * 32;
        if offset + 32 > self.cluster_bytes() as usize {
            return Err(FatError::Corrupt);
        }
        let bps = self.bytes_per_sector();
        Ok((self.cluster_to_lba(at.cluster) + (offset / bps) as u64, offset % bps))
    }

    /// Adds `entry` to the directory at `dir_cluster`, in its first free slot
    /// (deleted or past the end); a full directory grows by a zeroed cluster.
    pub fn add_entry(&self, dir_cluster: u32, entry: &[u8; 32], hint: u32) -> Result<EntryRef, FatError> {
        let per_cluster = self.cluster_bytes() as usize;
        let mut buffer = vec![0u8; per_cluster];
        let chain = self.chain(dir_cluster)?;
        for &cluster in &chain {
            self.read_cluster(cluster, &mut buffer)?;
            if let Some(index) = buffer.chunks_exact(32).position(|e| e[0] == 0x00 || e[0] == 0xE5) {
                let at = EntryRef { cluster, index: index as u32 };
                self.write_entry(at, entry)?;
                return Ok(at);
            }
        }
        let mut first = dir_cluster;
        let clusters = self.resize_chain(&mut first, chain.len() + 1, hint)?;
        let at = EntryRef { cluster: *clusters.last().expect("one more cluster"), index: 0 };
        self.write_entry(at, entry)?;
        Ok(at)
    }

    /// Creates the subdirectory `name` (8.3, padded) of the directory at
    /// `parent` (the root's `..` names cluster 0): a zeroed cluster with its
    /// `.` and `..`, and its entry. Rends its cluster and its entry.
    pub fn create_directory(&self, parent: u32, name: &[u8; 11], hint: u32) -> Result<(u32, EntryRef), FatError> {
        let cluster = self.allocate_cluster(hint)?;
        let dot_dot = if parent == self.bpb.root_cluster { 0 } else { parent };
        let made = self
            .write_entry(EntryRef { cluster, index: 0 }, &make_entry(b".          ", ATTR_DIRECTORY, cluster, 0))
            .and_then(|()| {
                self.write_entry(
                    EntryRef { cluster, index: 1 },
                    &make_entry(b"..         ", ATTR_DIRECTORY, dot_dot, 0),
                )
            })
            .and_then(|()| self.add_entry(parent, &make_entry(name, ATTR_DIRECTORY, cluster, 0), cluster + 1));
        match made {
            Ok(at) => Ok((cluster, at)),
            Err(error) => {
                let _ = self.free_chain(cluster);
                Err(error)
            }
        }
    }
}

fn short_name_11(name: &str) -> Result<[u8; 11], FatError> {
    if name.is_empty() {
        return Err(FatError::PathFormat);
    }
    let mut out = [b' '; 11];
    let mut split = name.split('.');
    let base = split.next().ok_or(FatError::PathFormat)?;
    let ext = split.next();
    if split.next().is_some() {
        return Err(FatError::Unsupported);
    }
    if base.is_empty() || base.len() > 8 {
        return Err(FatError::Unsupported);
    }
    if let Some(e) = ext {
        if e.len() > 3 {
            return Err(FatError::Unsupported);
        }
    }
    for (i, ch) in base.bytes().enumerate() {
        out[i] = upcase_fat_char(ch)?;
    }
    if let Some(e) = ext {
        for (i, ch) in e.bytes().enumerate() {
            out[8 + i] = upcase_fat_char(ch)?;
        }
    }
    Ok(out)
}

fn upcase_fat_char(ch: u8) -> Result<u8, FatError> {
    match ch {
        b'a'..=b'z' => Ok(ch - 32),
        b'A'..=b'Z'
        | b'0'..=b'9'
        | b'$'
        | b'%'
        | b'\''
        | b'-'
        | b'_'
        | b'@'
        | b'~'
        | b'`'
        | b'!'
        | b'('
        | b')'
        | b'{'
        | b'}'
        | b'^'
        | b'#'
        | b'&' => Ok(ch),
        _ => Err(FatError::Unsupported),
    }
}

fn short_name_from_entry(ent: &[u8]) -> String {
    let mut base_end = 8usize;
    while base_end > 0 && ent[base_end - 1] == b' ' {
        base_end -= 1;
    }
    let mut ext_end = 3usize;
    while ext_end > 0 && ent[8 + ext_end - 1] == b' ' {
        ext_end -= 1;
    }
    let mut out = String::new();
    let mut i = 0usize;
    while i < base_end {
        out.push(ent[i] as char);
        i += 1;
    }
    if ext_end > 0 {
        out.push('.');
        let mut j = 0usize;
        while j < ext_end {
            out.push(ent[8 + j] as char);
            j += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::RefCell;

    struct MemDisk {
        sector_size: u32,
        data: RefCell<alloc::vec::Vec<u8>>,
    }

    impl MemDisk {
        fn new(sector_size: u32, sectors: usize) -> Self {
            Self { sector_size, data: RefCell::new(vec![0u8; sector_size as usize * sectors]) }
        }

        fn write_sector(&self, lba: usize, src: &[u8]) {
            let s = self.sector_size as usize;
            let mut data = self.data.borrow_mut();
            data[lba * s..(lba + 1) * s].copy_from_slice(src);
        }
    }

    impl BlockDevice for MemDisk {
        fn sector_size(&self) -> u32 {
            self.sector_size
        }
        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
            let s = self.sector_size as usize;
            if out.len() != s {
                return Err(FatError::Io);
            }
            let l = lba as usize;
            let data = self.data.borrow();
            let end = (l + 1) * s;
            if end > data.len() {
                return Err(FatError::Io);
            }
            out.copy_from_slice(&data[l * s..end]);
            Ok(())
        }
    }

    fn make_test_disk() -> MemDisk {
        let d = MemDisk::new(512, 64);
        let mut boot = [0u8; 512];
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&1u16.to_le_bytes());
        boot[16] = 1;
        boot[17..19].copy_from_slice(&0u16.to_le_bytes());
        boot[19..21].copy_from_slice(&0u16.to_le_bytes());
        boot[32..36].copy_from_slice(&64u32.to_le_bytes());
        boot[36..40].copy_from_slice(&1u32.to_le_bytes());
        boot[44..48].copy_from_slice(&2u32.to_le_bytes());
        d.write_sector(0, &boot);

        let mut fat = [0u8; 512];
        fat[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
        fat[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        fat[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        fat[12..16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        d.write_sector(1, &fat);

        let mut root = [0u8; 512];
        root[0..11].copy_from_slice(b"KERNEL  BIN");
        root[11] = 0x20;
        root[20..22].copy_from_slice(&0u16.to_le_bytes());
        root[26..28].copy_from_slice(&3u16.to_le_bytes());
        root[28..32].copy_from_slice(&4u32.to_le_bytes());
        root[32] = 0x00;
        d.write_sector(2, &root);

        let mut file_sector = [0u8; 512];
        file_sector[0..4].copy_from_slice(b"ABCD");
        d.write_sector(3, &file_sector);
        d
    }

    #[test]
    fn mount_and_open_kernel_bin() {
        let disk = make_test_disk();
        let vol = FatVolume::mount(disk).expect("mount");
        let mut file = vol.open("/KERNEL.BIN").expect("open");
        let mut out = [0u8; 8];
        let n = vol.read(&mut file, &mut out).expect("read");
        assert_eq!(n, 4);
        assert_eq!(&out[..4], b"ABCD");
    }

    #[test]
    fn fat_dates_become_nt_times() {
        assert_eq!(nt_time(0x21, 0, 0), 119_600_064_000_000_000, "1980-01-01");
        assert_eq!(nt_time(12548, 25692, 50), 127_360_964_965_000_000, "2004-08-04 12:34:56.5");
        assert_eq!(nt_time(10333, 49021, 0), 125_963_423_980_000_000, "2000-02-29 23:59:58");
        assert_eq!(nt_time(0, 25692, 0), 0, "no date");
        assert_eq!(nt_time((21 << 9) | (2 << 5) | 29, 0, 0), 0, "2001-02-29");
        assert_eq!(nt_time(0x21, 24 << 11, 0), 0, "hour 24");
    }

    #[test]
    fn an_entry_gives_its_dates_and_volume_labels_are_skipped() {
        let disk = make_test_disk();
        let mut root = [0u8; 512];
        root[0..11].copy_from_slice(b"KERNEL  BIN");
        root[11] = 0x08; // a volume label of the same name, first
        root[32..43].copy_from_slice(b"KERNEL  BIN");
        root[43] = 0x21;
        root[32 + 22..32 + 24].copy_from_slice(&25692u16.to_le_bytes());
        root[32 + 24..32 + 26].copy_from_slice(&12548u16.to_le_bytes());
        root[32 + 26..32 + 28].copy_from_slice(&3u16.to_le_bytes());
        root[32 + 28..32 + 32].copy_from_slice(&4u32.to_le_bytes());
        disk.write_sector(2, &root);
        let vol = FatVolume::mount(disk).expect("mount");
        let entry = vol.find_in_dir(vol.root_cluster(), "kernel.bin").expect("found");
        assert_eq!((entry.attr, entry.first_cluster, entry.file_size), (0x21, 3, 4));
        assert_eq!((entry.write_date, entry.write_time), (12548, 25692));
        assert_eq!(vol.find_in_dir(vol.root_cluster(), "other.bin"), Err(FatError::NotFound));
        assert_eq!(vol.cluster_bytes(), 512);
    }

    #[test]
    fn short_name_encoding() {
        let got = short_name_11("bootx64.efi").expect("name");
        assert_eq!(&got, b"BOOTX64 EFI");
    }
}
