use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use hal::sync::KSpinLock;

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
    /// Makes what was written reach the medium; nothing to do for a device
    /// without a cache.
    fn flush(&self) -> Result<(), FatError> {
        Ok(())
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
    fn flush(&self) -> Result<(), FatError> {
        (**self).flush()
    }
}

impl<D: BlockDevice + ?Sized> BlockDevice for &mut D {
    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
        (**self).read_sector(lba, out)
    }
    fn write_sector(&self, lba: u64, data: &[u8]) -> Result<(), FatError> {
        (**self).write_sector(lba, data)
    }
    fn flush(&self) -> Result<(), FatError> {
        (**self).flush()
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
    /// BS_VolID: the serial number of the volume (0 without a BPB).
    pub volume_id: u32,
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
    /// The entry in the 32 bytes `ent`.
    pub fn parse(ent: &[u8]) -> Self {
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

/// A date and time as a FAT entry keeps them: local time (UTC here, without
/// a time zone), the time in 2 s steps, and tenths of a second (0 to 199)
/// for a creation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FatTime {
    pub date: u16,
    pub time: u16,
    pub tenths: u8,
}

/// The NT time `nt` (100 ns since 1601) as a FAT date and time, the inverse
/// of [`nt_time`]; `None` outside the years FAT can hold (1980 to 2107).
pub fn fat_time(nt: u64) -> Option<FatTime> {
    let seconds = nt / 10_000_000;
    // Days from 1970-01-01 (H. Hinnant's civil_from_days), from 1601.
    let days = i64::try_from(seconds / 86_400).ok()? - 134_774;
    let in_day = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1980..=2107).contains(&year) {
        return None;
    }
    let (hour, minute, second) = (in_day / 3600, in_day / 60 % 60, in_day % 60);
    Some(FatTime {
        date: (((year - 1980) as u16) << 9) | ((month as u16) << 5) | day as u16,
        time: ((hour as u16) << 11) | ((minute as u16) << 5) | (second / 2) as u16,
        tenths: ((second % 2) * 100 + nt % 10_000_000 / 100_000) as u8,
    })
}

/// The attributes of an entry that holds a part of a long name (VFAT).
const ATTR_LONG_NAME: u8 = 0x0F;
/// In the order byte of a long-name entry: the last part, which comes first.
const LONG_NAME_LAST: u8 = 0x40;
/// The UTF-16 units of a long name each of its entries holds.
const LONG_NAME_UNITS: usize = 13;
/// Where those units are in the entry: 5, then 6, then 2.
const LONG_NAME_SPANS: [(usize, usize); 3] = [(1, 5), (14, 6), (28, 2)];

/// The checksum of an 8.3 name, which each entry of its long name carries.
pub fn short_name_checksum(name: &[u8; 11]) -> u8 {
    name.iter().fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
}

/// The long name (VFAT) of the next 8.3 entry of a directory, gathered from
/// the long-name entries before it: the last part first (`LONG_NAME_LAST`
/// with the count of parts), then each part down to the first, all with the
/// checksum of the 8.3 name. A sequence that breaks these rules is no name.
#[derive(Default)]
struct LongName {
    units: Vec<u16>,
    /// The order of the part expected next; 0 once complete.
    next: u8,
    checksum: u8,
    broken: bool,
}

impl LongName {
    /// Takes in the long-name entry `ent`.
    fn take(&mut self, ent: &[u8]) {
        let order = ent[0] & !LONG_NAME_LAST;
        if ent[0] & LONG_NAME_LAST != 0 {
            *self = Self {
                units: vec![0; usize::from(order) * LONG_NAME_UNITS],
                next: order,
                checksum: ent[13],
                broken: order == 0 || order > 20,
            };
        } else if order != self.next || ent[13] != self.checksum || self.units.is_empty() {
            self.broken = true;
        }
        if self.broken {
            return;
        }
        let at = usize::from(order - 1) * LONG_NAME_UNITS;
        let mut units = LONG_NAME_SPANS.iter().flat_map(|&(start, count)| {
            (0..count).map(move |i| u16::from_le_bytes([ent[start + 2 * i], ent[start + 2 * i + 1]]))
        });
        for unit in &mut self.units[at..at + LONG_NAME_UNITS] {
            *unit = units.next().unwrap_or(0);
        }
        self.next = order - 1;
    }

    /// The long name of the 8.3 entry `ent`, if the entries before it make
    /// one for it; and forgets them.
    fn finish(&mut self, ent: &[u8]) -> Option<String> {
        let gathered = core::mem::take(self);
        let mut short = [0u8; 11];
        short.copy_from_slice(&ent[..11]);
        if gathered.broken
            || gathered.units.is_empty()
            || gathered.next != 0
            || gathered.checksum != short_name_checksum(&short)
        {
            return None;
        }
        let end = gathered.units.iter().position(|&unit| unit == 0).unwrap_or(gathered.units.len());
        char::decode_utf16(gathered.units[..end].iter().copied()).collect::<Result<String, _>>().ok()
    }
}

/// `long` and `name` are the same name, case aside.
fn same_name(long: &str, name: &str) -> bool {
    long.chars().flat_map(char::to_uppercase).eq(name.chars().flat_map(char::to_uppercase))
}

#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    /// Its long name if it has one, else its 8.3 name.
    pub name: String,
    pub attr: u8,
    pub first_cluster: u32,
    pub file_size: u32,
    /// Its 8.3 name, when it also has a long name.
    pub short_name: Option<String>,
    /// The 11 bytes of its 8.3 name as the entry holds them (a volume
    /// label's too).
    pub raw_name: [u8; 11],
    /// Where its (8.3) entry is in the directory, in bytes from its start.
    pub offset: u32,
    /// The entry, with its dates.
    pub entry: DirEntry,
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
    /// The first FAT copy, cached whole: the allocations and the chain walks
    /// read it in memory, the updates mark the dirty sectors and the flush
    /// writes them back to every copy (one device write per dirty sector
    /// instead of per entry).
    fat_cache: KSpinLock<FatCache>,
}

/// The cached first FAT copy and its per-sector dirty marks.
struct FatCache {
    bytes: Vec<u8>,
    dirty: Vec<bool>,
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
        // The first FAT copy, cached whole: the allocations and the chain
        // walks read it in memory (one device read per FAT sector here, at
        // mount), the updates mark the dirty sectors and the flush writes
        // them back to every copy.
        let fat_sectors = sectors_per_fat32 as usize;
        let mut fat_bytes = vec![0u8; fat_sectors * bytes_per_sector as usize];
        for i in 0..fat_sectors {
            device.read_sector(
                rsvd as u64 + i as u64,
                &mut fat_bytes[i * bytes_per_sector as usize..(i + 1) * bytes_per_sector as usize],
            )?;
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
                volume_id: if bpb_ok {
                    u32::from_le_bytes([sector[67], sector[68], sector[69], sector[70]])
                } else {
                    0
                },
            },
            fat_start_lba: rsvd as u64,
            data_start_lba: first_data_sector as u64,
            clusters: if bpb_ok { (total_sectors - first_data_sector) / u32::from(spc) } else { 0 },
            fat_cache: KSpinLock::new(FatCache { bytes: fat_bytes, dirty: vec![false; fat_sectors] }),
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

    /// Writes every dirty FAT sector back to each copy. Called by the flush
    /// and by the drop: a fresh mount must see the written chains.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (device I/O may wait actively).
    fn flush_fats(&self) -> Result<(), FatError> {
        let cache = self.fat_cache.lock();
        let bps = self.bytes_per_sector();
        let fat_count = u64::from(self.bpb.fat_count);
        let spf = u64::from(self.bpb.sectors_per_fat);
        for (index, dirty) in cache.dirty.iter().enumerate() {
            if *dirty {
                let sector = &cache.bytes[index * bps..(index + 1) * bps];
                for copy in 0..fat_count {
                    self.device.write_sector(self.fat_start_lba + index as u64 + copy * spf, sector)?;
                }
            }
        }
        Ok(())
    }

    /// Makes what was written reach the medium: the dirty FAT sectors to
    /// each copy, then the device flush.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (device I/O may wait actively).
    pub fn flush(&self) -> Result<(), FatError> {
        self.flush_fats()?;
        self.device.flush()
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
        self.dir_entries(cluster)
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

    /// The entry `name` (its 8.3 name or its long name, any case) of the
    /// directory at `dir_cluster`; `NotFound` without it.
    pub fn find_in_dir(&self, dir_cluster: u32, name: &str) -> Result<DirEntry, FatError> {
        self.find_entry(dir_cluster, name).map(|(entry, _)| entry)
    }

    /// [`find_in_dir`](Self::find_in_dir), with where the entry is.
    pub fn find_entry(&self, dir_cluster: u32, name: &str) -> Result<(DirEntry, EntryRef), FatError> {
        if name.is_empty() {
            return Err(FatError::PathFormat);
        }
        // A name 8.3 cannot hold may still be a long name.
        let target = short_name_11(name).ok();
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
        let mut long = LongName::default();
        loop {
            self.read_cluster(cluster, &mut buf)?;
            let mut i = 0usize;
            while i + 32 <= buf.len() {
                let ent = &buf[i..i + 32];
                match (ent[0], ent[11]) {
                    (0x00, _) => return Err(FatError::NotFound),
                    (0xE5, _) => long = LongName::default(),
                    (_, ATTR_LONG_NAME) => long.take(ent),
                    // The volume label.
                    (_, attr) if attr & 0x08 != 0 => long = LongName::default(),
                    _ => {
                        let long_name = long.finish(ent);
                        let short = target.is_some_and(|target| ent[0..11] == target);
                        if short || long_name.is_some_and(|long_name| same_name(&long_name, name)) {
                            return Ok((DirEntry::parse(ent), EntryRef { cluster, index: (i / 32) as u32 }));
                        }
                    }
                }
                i += 32;
            }
            cluster = self.next_cluster(cluster)?;
        }
    }

    /// The entries of the directory at `dir_cluster`, each with its long
    /// name if it has one, else its 8.3 name (`.` and `..` and the volume
    /// label among them).
    pub fn dir_entries(&self, dir_cluster: u32) -> Result<Vec<DirEntryInfo>, FatError> {
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
        let mut long = LongName::default();
        // Where this cluster begins in the directory.
        let mut base = 0u32;
        loop {
            self.read_cluster(cluster, &mut buf)?;
            let mut i = 0usize;
            while i + 32 <= buf.len() {
                let ent = &buf[i..i + 32];
                match (ent[0], ent[11]) {
                    (0x00, _) => return Ok(out),
                    (0xE5, _) => long = LongName::default(),
                    (_, ATTR_LONG_NAME) => long.take(ent),
                    (_, attr) => {
                        let entry = DirEntry::parse(ent);
                        let short = short_name_from_entry(ent);
                        let mut raw_name = [0u8; 11];
                        raw_name.copy_from_slice(&ent[..11]);
                        // Its long name if it has one.
                        let (name, short_name) = match long.finish(ent) {
                            Some(long_name) => (long_name, Some(short)),
                            None => (short, None),
                        };
                        out.push(DirEntryInfo {
                            name,
                            attr,
                            first_cluster: entry.first_cluster,
                            file_size: entry.file_size,
                            short_name,
                            raw_name,
                            offset: base + i as u32,
                            entry,
                        });
                    }
                }
                i += 32;
            }
            // A directory whose entries fill its last cluster has no end
            // marker: it ends with its chain.
            cluster = match self.next_cluster(cluster) {
                Ok(next) => next,
                Err(FatError::NotFound) => return Ok(out),
                Err(error) => return Err(error),
            };
            base += bytes_per_cluster as u32;
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
        // La FAT est dans le cache : les chaînes se lisent en mémoire.
        match self.fat_entry(cluster)? {
            next if next >= 0x0FFF_FFF8 => Err(FatError::NotFound),
            0 | 1 => Err(FatError::Corrupt),
            next => Ok(next),
        }
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

/// The 8.3 alias of the long name `long`, as other systems make it: its base
/// (before its last dot) and its extension in upper case, without spaces or
/// dots, other characters 8.3 cannot hold as `_`; then `~N` after at most 6
/// characters of the base, `N` the first that `taken` does not refuse.
fn alias_11(long: &str, taken: impl Fn(&[u8; 11]) -> bool) -> [u8; 11] {
    let clean = |part: &str| -> Vec<u8> {
        part.chars()
            .filter(|&c| c != ' ' && c != '.')
            .map(|c| {
                let c = c.to_ascii_uppercase();
                if c.is_ascii() && short_name(&c.to_string()).is_ok() {
                    c as u8
                } else {
                    b'_'
                }
            })
            .collect()
    };
    let (base, ext) = match long.rsplit_once('.') {
        Some((base, ext)) if !base.is_empty() => (clean(base), clean(ext)),
        _ => (clean(long), Vec::new()),
    };
    let basis = &base[..base.len().min(6)];
    for n in 1u32.. {
        let tail = alloc::format!("~{n}");
        let mut name = [b' '; 11];
        let kept = basis.len().min(8 - tail.len());
        name[..kept].copy_from_slice(&basis[..kept]);
        name[kept..kept + tail.len()].copy_from_slice(tail.as_bytes());
        name[8..8 + ext.len().min(3)].copy_from_slice(&ext[..ext.len().min(3)]);
        if !taken(&name) {
            return name;
        }
    }
    unreachable!("a free alias among 2^32")
}

/// The entries of the long name `long` of the 8.3 name `short`, in the order
/// a directory holds them: the last part first. A 0 unit ends a name that
/// does not fill its last part, 0xFFFF fills the rest.
pub(crate) fn long_name_entries(long: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let mut units: Vec<u16> = long.encode_utf16().collect();
    let parts = units.len().div_ceil(LONG_NAME_UNITS);
    if units.len() < parts * LONG_NAME_UNITS {
        units.push(0);
    }
    units.resize(parts * LONG_NAME_UNITS, 0xFFFF);
    (1..=parts)
        .rev()
        .map(|order| {
            let mut entry = [0u8; 32];
            entry[0] = order as u8 | if order == parts { LONG_NAME_LAST } else { 0 };
            entry[11] = ATTR_LONG_NAME;
            entry[13] = short_name_checksum(short);
            let mut part = units[(order - 1) * LONG_NAME_UNITS..order * LONG_NAME_UNITS].iter();
            for (start, count) in LONG_NAME_SPANS {
                for i in 0..count {
                    let at = start + 2 * i;
                    entry[at..at + 2].copy_from_slice(&part.next().expect("13 units").to_le_bytes());
                }
            }
            entry
        })
        .collect()
}

/// Writing (M4, ADR-017). The caller serialises the calls that write, and
/// the reads that may see them. Every FAT copy is written; the FSInfo
/// sector is left as it is (its free count stays "unknown"). New clusters
/// are zeroed. Dates are written by [`FatVolume::set_times`].
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

    /// The byte offset of the FAT entry of `cluster` in the cached copy.
    fn fat_offset(&self, cluster: u32) -> usize {
        let (lba, at) = self.fat_place(cluster);
        (lba - self.fat_start_lba) as usize * self.bytes_per_sector() + at
    }

    /// The FAT entry of `cluster`: 0 free, [`END_OF_CHAIN`] (or above
    /// 0x0FFFFFF7) last, otherwise the next cluster. Read from the cache.
    pub fn fat_entry(&self, cluster: u32) -> Result<u32, FatError> {
        self.check_cluster(cluster)?;
        let offset = self.fat_offset(cluster);
        let cache = self.fat_cache.lock();
        Ok(u32::from_le_bytes([
            cache.bytes[offset],
            cache.bytes[offset + 1],
            cache.bytes[offset + 2],
            cache.bytes[offset + 3],
        ]) & 0x0FFF_FFFF)
    }

    /// Sets the FAT entry of `cluster`, keeping its top four bits: in the
    /// cache, with its sector marked dirty — the flush writes every dirty
    /// sector to each copy.
    fn set_fat_entry(&self, cluster: u32, value: u32) -> Result<(), FatError> {
        self.check_cluster(cluster)?;
        let offset = self.fat_offset(cluster);
        let mut cache = self.fat_cache.lock();
        let old = u32::from_le_bytes([
            cache.bytes[offset],
            cache.bytes[offset + 1],
            cache.bytes[offset + 2],
            cache.bytes[offset + 3],
        ]);
        let new = (old & 0xF000_0000) | (value & 0x0FFF_FFFF);
        cache.bytes[offset..offset + 4].copy_from_slice(&new.to_le_bytes());
        let sector = offset / self.bytes_per_sector();
        cache.dirty[sector] = true;
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
        self.take_free_cluster(hint, true)
    }

    /// [`allocate_cluster`](Self::allocate_cluster), zeroing the cluster only
    /// when `zero`: a caller that writes the whole cluster at once skips a
    /// pass over its sectors.
    fn take_free_cluster(&self, hint: u32, zero: bool) -> Result<u32, FatError> {
        if self.clusters == 0 {
            return Err(FatError::ReadOnly);
        }
        let end = self.clusters + 2;
        let start = if (2..end).contains(&hint) { hint } else { 2 };
        // The scan reads the cached FAT; the found cluster's zeroing goes to
        // the device, its FAT entry through the cache (the lock is dropped
        // first: it is not reentrant).
        let free = {
            let cache = self.fat_cache.lock();
            (start..end).chain(2..start).find(|cluster| {
                let offset = self.fat_offset(*cluster);
                u32::from_le_bytes([
                    cache.bytes[offset],
                    cache.bytes[offset + 1],
                    cache.bytes[offset + 2],
                    cache.bytes[offset + 3],
                ]) & 0x0FFF_FFFF
                    == 0
            })
        };
        match free {
            Some(cluster) => {
                if zero {
                    self.zero_cluster(cluster)?;
                }
                self.set_fat_entry(cluster, END_OF_CHAIN)?;
                Ok(cluster)
            }
            None => Err(FatError::Full),
        }
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
        self.resize_chain_with(first, count, hint, true)
    }

    /// [`resize_chain`](Self::resize_chain), the added clusters zeroed only
    /// when `zero`.
    fn resize_chain_with(&self, first: &mut u32, count: usize, hint: u32, zero: bool) -> Result<Vec<u32>, FatError> {
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
            let new = match self.take_free_cluster(hint, zero) {
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
    ///
    /// The clusters it adds are not zeroed beforehand: each starts at or past
    /// the old end, which the gap and the data write over up to `end`; the
    /// rest of the last one, past `end`, is zeroed after. Each byte goes to
    /// the device once (copying a file onto a new volume wrote it twice). If
    /// a write fails, the chain gets back its old length: no cluster added
    /// stays with what it held before.
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
        let before = if *first == 0 { 0 } else { self.chain(*first)?.len() };
        let clusters = self.resize_chain_with(first, new_size.div_ceil(per_cluster) as usize, hint, false)?;
        let written = (|| {
            if offset > u64::from(*size) {
                // Bytes past the old end may hold what a truncation left there.
                let gap = vec![0u8; (offset - u64::from(*size)) as usize];
                self.write_into(&clusters, u64::from(*size), &gap)?;
            }
            self.write_into(&clusters, offset, data)?;
            let chain_end = clusters.len() as u64 * per_cluster;
            if clusters.len() > before && end < chain_end {
                // The rest of the last cluster added, as zeroing it first did.
                self.write_into(&clusters, end, &vec![0u8; (chain_end - end) as usize])?;
            }
            Ok(())
        })();
        if let Err(error) = written {
            let _ = self.resize_chain(first, before, hint);
            return Err(error);
        }
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

    /// Writes the dates of the entry at `at`: its creation (and then its
    /// last write and access too) if `created`, else its last write and
    /// access if `written`.
    pub fn set_times(&self, at: EntryRef, created: Option<FatTime>, written: Option<FatTime>) -> Result<(), FatError> {
        let Some(written) = written.or(created) else { return Ok(()) };
        let mut entry = self.read_entry(at)?;
        if let Some(created) = created {
            entry[13] = created.tenths;
            entry[14..16].copy_from_slice(&created.time.to_le_bytes());
            entry[16..18].copy_from_slice(&created.date.to_le_bytes());
        }
        entry[18..20].copy_from_slice(&written.date.to_le_bytes());
        entry[22..24].copy_from_slice(&written.time.to_le_bytes());
        entry[24..26].copy_from_slice(&written.date.to_le_bytes());
        self.write_entry(at, &entry)
    }

    /// Changes what NtSetInformationFile(FileBasicInformation) changes in
    /// the entry at `at`: its attributes (read-only, hidden, system,
    /// archive; the directory bit stays), its creation, last access (the
    /// date) and last write; `None` leaves one as it is.
    pub fn set_basic(
        &self,
        at: EntryRef,
        attributes: Option<u8>,
        created: Option<FatTime>,
        accessed: Option<FatTime>,
        written: Option<FatTime>,
    ) -> Result<(), FatError> {
        let mut entry = self.read_entry(at)?;
        if let Some(attributes) = attributes {
            entry[11] = (entry[11] & 0x10) | (attributes & 0x27);
        }
        if let Some(created) = created {
            entry[13] = created.tenths;
            entry[14..16].copy_from_slice(&created.time.to_le_bytes());
            entry[16..18].copy_from_slice(&created.date.to_le_bytes());
        }
        if let Some(accessed) = accessed {
            entry[18..20].copy_from_slice(&accessed.date.to_le_bytes());
        }
        if let Some(written) = written {
            entry[22..24].copy_from_slice(&written.time.to_le_bytes());
            entry[24..26].copy_from_slice(&written.date.to_le_bytes());
        }
        self.write_entry(at, &entry)
    }

    /// The number of data clusters.
    pub fn clusters(&self) -> u32 {
        self.clusters
    }

    /// The free clusters: those whose FAT entry is 0 (the FSInfo sector's
    /// count is not trusted). 0 for a volume whose size is unknown.
    pub fn free_clusters(&self) -> Result<u32, FatError> {
        // The cached FAT: the pending (unflushed) allocations count as used.
        let cache = self.fat_cache.lock();
        let mut free = 0;
        for cluster in 2..self.clusters + 2 {
            let offset = self.fat_offset(cluster);
            let entry = u32::from_le_bytes([
                cache.bytes[offset],
                cache.bytes[offset + 1],
                cache.bytes[offset + 2],
                cache.bytes[offset + 3],
            ]);
            if entry & 0x0FFF_FFFF == 0 {
                free += 1;
            }
        }
        Ok(free)
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

    /// Adds the entry of `long` to the directory at `dir_cluster`: the
    /// long-name (VFAT) entries of its 8.3 alias — the last part first, each
    /// carrying the checksum of the alias — then that alias's 8.3 entry,
    /// unique in the directory. A name 8.3 already holds gets a single
    /// entry. Every entry lands in the first free slot; a full directory
    /// grows by a zeroed cluster.
    pub fn add_entry_long(
        &self,
        dir_cluster: u32,
        long: &str,
        attributes: u8,
        hint: u32,
    ) -> Result<EntryRef, FatError> {
        if let Ok(short) = short_name(long) {
            return self.add_entry(dir_cluster, &make_entry(&short, attributes, 0, 0), hint);
        }
        // The alias must not collide with the 8.3 names the directory holds,
        // the aliases of its long names included.
        let taken: Vec<[u8; 11]> = self
            .dir_entries(dir_cluster)?
            .iter()
            .filter_map(|entry| short_name(entry.short_name.as_deref().unwrap_or(&entry.name)).ok())
            .collect();
        let alias = alias_11(long, |candidate| taken.contains(candidate));
        for part in long_name_entries(long, &alias) {
            self.add_entry(dir_cluster, &part, hint)?;
        }
        self.add_entry(dir_cluster, &make_entry(&alias, attributes, 0, 0), hint)
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

impl<D: BlockDevice> Drop for FatVolume<D> {
    fn drop(&mut self) {
        // The dirty FAT sectors reach the device even without an explicit
        // flush: a fresh mount over the same device must see the written
        // chains. Errors are swallowed (the drop cannot report them); the
        // explicit flush paths report theirs.
        let _ = self.flush_fats();
    }
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
    fn a_directory_that_fills_its_last_cluster_ends_with_its_chain() {
        // 16 entries fill the root's one cluster: no end marker follows
        // them, the end of the chain ends the directory (SYSTEM32 once
        // uxtheme and winmm joined it: STATUS_DISK_CORRUPT_ERROR).
        let disk = make_test_disk();
        let mut root = [0u8; 512];
        for (i, entry) in root.chunks_exact_mut(32).enumerate() {
            entry[..11].copy_from_slice(b"FILE00  TXT");
            entry[4] = b'0' + (i / 10) as u8;
            entry[5] = b'0' + (i % 10) as u8;
            entry[11] = 0x20;
        }
        disk.write_sector(2, &root);
        let vol = FatVolume::mount(disk).expect("mount");
        let entries = vol.dir_entries(2).expect("listed up to the end of its chain");
        assert_eq!(entries.len(), 16);
        assert_eq!(entries[15].name, "FILE15.TXT");
        assert!(vol.open("/FILE15.TXT").is_ok(), "the last one is found");
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
    fn fat_dates_round_trip_through_nt_time() {
        // (date, time, hundredths): 1980-01-01 00:00:00, 2004-08-04 12:00:00,
        // 2024-02-29 23:59:58.99, 2107-12-31 23:59:58.
        for (date, time, hundredths) in
            [(0x0021, 0, 0), (12548, 12 << 11, 0), (0x585D, 0xBF7D, 199), (0xFF9F, 0xBF7D, 0)]
        {
            let nt = nt_time(date, time, hundredths);
            assert_ne!(nt, 0);
            assert_eq!(fat_time(nt), Some(FatTime { date, time, tenths: hundredths }), "{date:#x} {time:#x}");
        }
        // Out of FAT's years.
        assert_eq!(fat_time(nt_time(0x0021, 0, 0) - 10_000_000), None, "1979-12-31 23:59:59");
        assert_eq!(fat_time(nt_time(0xFF9F, 0xBF7D, 199) + 10_000_000), None, "2108");
        assert_eq!(fat_time(0), None);
    }

    #[test]
    fn the_checksum_of_an_8_3_name() {
        // ((sum & 1) << 7) + (sum >> 1) + byte, for each byte of the name.
        assert_eq!(short_name_checksum(b"ADVAPI~1DLL"), 0x43);
        assert_eq!(short_name_checksum(b"           "), 0xF7);
    }

    #[test]
    fn a_file_is_found_by_its_long_name_too() {
        let disk = make_test_disk();
        let short = *b"ADVAPI~1DLL";
        let mut root = [0u8; 512];
        let entries = long_name_entries("advapi32_vista.dll", &short);
        assert_eq!(entries.len(), 2, "18 units: two parts");
        for (i, ent) in entries.iter().enumerate() {
            root[32 * i..32 * i + 32].copy_from_slice(ent);
        }
        root[64..96].copy_from_slice(&make_entry(&short, 0x20, 3, 4));
        // A long name whose checksum is another name's: not this entry's.
        let stale = long_name_entries("other_long_name.dll", b"OTHER~1 DLL");
        root[96..128].copy_from_slice(&stale[1]);
        root[128..160].copy_from_slice(&make_entry(b"KERNEL  BIN", 0x20, 3, 4));
        disk.write_sector(2, &root);
        let vol = FatVolume::mount(disk).expect("mount");
        let root_cluster = vol.root_cluster();
        for name in ["advapi32_vista.dll", "ADVAPI32_VISTA.DLL", "Advapi32_Vista.Dll", "advapi~1.dll"] {
            assert_eq!(vol.find_entry(root_cluster, name).map(|(e, at)| (e.file_size, at.index)), Ok((4, 2)), "{name}");
        }
        assert_eq!(vol.find_in_dir(root_cluster, "advapi32_vista.dl").err(), Some(FatError::NotFound));
        assert_eq!(vol.find_in_dir(root_cluster, "other_long_name.dll").err(), Some(FatError::NotFound));
        assert!(vol.find_in_dir(root_cluster, "kernel.bin").is_ok());
        let names: Vec<String> = vol.list_dir("/").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["advapi32_vista.dll", "KERNEL.BIN"], "the long name when there is one");
        // The 8.3 name too, and where each 8.3 entry is.
        let listed: Vec<(String, Option<String>, u32)> =
            vol.dir_entries(root_cluster).unwrap().into_iter().map(|e| (e.name, e.short_name, e.offset)).collect();
        assert_eq!(
            listed,
            [("advapi32_vista.dll".into(), Some("ADVAPI~1.DLL".into()), 64), ("KERNEL.BIN".into(), None, 128)]
        );
    }

    #[test]
    fn a_directory_across_two_clusters_counts_its_places_from_its_start() {
        let disk = make_test_disk();
        // The root: cluster 2, full, then cluster 4.
        let mut fat = [0u8; 512];
        for (i, next) in [0x0FFF_FFF8u32, 0xFFFF_FFFF, 4, 0x0FFF_FFFF, 0x0FFF_FFFF].iter().enumerate() {
            fat[4 * i..4 * i + 4].copy_from_slice(&next.to_le_bytes());
        }
        disk.write_sector(1, &fat);
        let mut first = [0u8; 512];
        for i in 0..16 {
            let mut name = *b"FILE00  TXT";
            name[4] = b'0' + (i / 10) as u8;
            name[5] = b'0' + (i % 10) as u8;
            first[32 * i..32 * i + 32].copy_from_slice(&make_entry(&name, 0x20, 0, 0));
        }
        disk.write_sector(2, &first);
        let mut second = [0u8; 512];
        second[32..64].copy_from_slice(&make_entry(b"LAST    TXT", 0x20, 0, 0));
        second[0] = 0xE5;
        disk.write_sector(4, &second);
        let vol = FatVolume::mount(disk).expect("mount");
        let listed = vol.dir_entries(vol.root_cluster()).unwrap();
        assert_eq!(listed.len(), 17);
        assert_eq!((listed[15].name.as_str(), listed[15].offset), ("FILE15.TXT", 15 * 32));
        assert_eq!((listed[16].name.as_str(), listed[16].offset), ("LAST.TXT", 512 + 32), "past a deleted entry");
    }

    #[test]
    fn a_broken_long_name_is_no_name() {
        let short = *b"ADVAPI~1DLL";
        let entries = long_name_entries("advapi32_vista.dll", &short);
        let find = |root: &[u8; 512]| {
            let disk = make_test_disk();
            disk.write_sector(2, root);
            let vol = FatVolume::mount(disk).expect("mount");
            vol.find_in_dir(vol.root_cluster(), "advapi32_vista.dll").map(|e| e.file_size)
        };
        let mut root = [0u8; 512];
        root[..32].copy_from_slice(&entries[0]);
        root[32..64].copy_from_slice(&entries[1]);
        root[64..96].copy_from_slice(&make_entry(&short, 0x20, 3, 4));
        assert_eq!(find(&root), Ok(4));
        let mut missing_part = root;
        missing_part[32..64].copy_from_slice(&entries[0]);
        assert_eq!(find(&missing_part), Err(FatError::NotFound), "the last part twice, the first never");
        let mut checksum = root;
        checksum[32 + 13] ^= 1;
        assert_eq!(find(&checksum), Err(FatError::NotFound), "a part of another name");
        let mut deleted = root;
        deleted[32] = 0xE5;
        assert_eq!(find(&deleted), Err(FatError::NotFound), "a deleted part");
        let mut other_short = root;
        other_short[64..75].copy_from_slice(b"ADVAPI~2DLL");
        assert_eq!(find(&other_short), Err(FatError::NotFound), "not the name of this 8.3 entry");
        let mut repeated = [0u8; 512];
        let mut again = entries[0];
        again[0] &= !LONG_NAME_LAST;
        for (i, ent) in [entries[0], again, entries[1], make_entry(&short, 0x20, 3, 4)].iter().enumerate() {
            repeated[32 * i..32 * i + 32].copy_from_slice(ent);
        }
        assert_eq!(find(&repeated), Err(FatError::NotFound), "part 2 twice, out of order");
        // Without its first part, an entry is listed by its 8.3 name.
        let mut incomplete = [0u8; 512];
        incomplete[..32].copy_from_slice(&entries[0]);
        incomplete[32..64].copy_from_slice(&make_entry(&short, 0x20, 3, 4));
        let disk = make_test_disk();
        disk.write_sector(2, &incomplete);
        let vol = FatVolume::mount(disk).expect("mount");
        let names: Vec<String> = vol.list_dir("/").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["ADVAPI~1.DLL"]);
    }

    #[test]
    fn short_name_encoding() {
        let got = short_name_11("bootx64.efi").expect("name");
        assert_eq!(&got, b"BOOTX64 EFI");
    }
}
