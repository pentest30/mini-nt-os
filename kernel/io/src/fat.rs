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
}

pub trait BlockDevice {
    fn sector_size(&self) -> u32;
    fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError>;
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

#[derive(Debug, Clone, Copy)]
pub struct DirEntry {
    pub attr: u8,
    pub first_cluster: u32,
    pub file_size: u32,
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
}

impl<D: BlockDevice> FatVolume<D> {
    #[inline(always)]
    pub fn mount(device: D) -> Result<Self, FatError> {
        let bytes_per_sector = device.sector_size();
        if bytes_per_sector < 512 || bytes_per_sector > 4096 || (bytes_per_sector & (bytes_per_sector - 1)) != 0 {
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
        let bpb_ok =
            bps != 0
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
        };
        Ok(vol)
    }

    pub fn bpb(&self) -> Fat32Bpb {
        self.bpb
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
        if bps < 512 || bps > 4096 || (bps & (bps - 1)) != 0 || spc == 0 {
            return Err(FatError::InvalidBpb);
        }
        let mut cluster = self.bpb.root_cluster;
        let mut parts = path.split('/').filter(|s| !s.is_empty());
        let first = parts.next().ok_or(FatError::PathFormat)?;
        let mut pending = Some(first);
        loop {
            let name = match pending.take() {
                Some(v) => v,
                None => break,
            };
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
        if bps < 512 || bps > 4096 || (bps & (bps - 1)) != 0 || spc == 0 {
            return Err(FatError::InvalidBpb);
        }
        let mut cluster = self.bpb.root_cluster;
        if path != "/" && !path.is_empty() {
            let mut parts = path.split('/').filter(|s| !s.is_empty());
            while let Some(name) = parts.next() {
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

    fn find_in_dir(&self, dir_cluster: u32, name: &str) -> Result<DirEntry, FatError> {
        let target = short_name_11(name)?;
        let bps = self.bpb.bytes_per_sector as usize;
        let spc = self.bpb.sectors_per_cluster as usize;
        if bps < 512 || bps > 4096 || spc == 0 {
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
                    let attr = ent[11];
                    if attr != 0x0F && ent[0..11] == target {
                        let hi = u16::from_le_bytes([ent[20], ent[21]]) as u32;
                        let lo = u16::from_le_bytes([ent[26], ent[27]]) as u32;
                        let first_cluster = (hi << 16) | lo;
                        let file_size = u32::from_le_bytes([ent[28], ent[29], ent[30], ent[31]]);
                        return Ok(DirEntry { attr, first_cluster, file_size });
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
        if bps < 512 || bps > 4096 || spc == 0 {
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
        b'A'..=b'Z' | b'0'..=b'9' | b'$' | b'%' | b'\'' | b'-' | b'_' | b'@' | b'~' | b'`' | b'!' | b'(' | b')' | b'{' | b'}' | b'^' | b'#' | b'&' => Ok(ch),
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
        fn sector_size(&self) -> u32 { self.sector_size }
        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
            let s = self.sector_size as usize;
            if out.len() != s { return Err(FatError::Io); }
            let l = lba as usize;
            let data = self.data.borrow();
            let end = (l + 1) * s;
            if end > data.len() { return Err(FatError::Io); }
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
    fn short_name_encoding() {
        let got = short_name_11("bootx64.efi").expect("name");
        assert_eq!(&got, b"BOOTX64 EFI");
    }
}
