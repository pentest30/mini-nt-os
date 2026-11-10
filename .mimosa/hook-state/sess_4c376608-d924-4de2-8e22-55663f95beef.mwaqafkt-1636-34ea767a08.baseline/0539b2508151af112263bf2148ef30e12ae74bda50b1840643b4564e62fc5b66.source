//! Independent FAT32 read, for the host to verify what an installation
//! wrote: the tree walked again, every file's chain followed to its end,
//! the signatures of the persisted files (MZ for the PE, regf for the
//! hives), and the free clusters. Deliberately small and on its own: it
//! shares nothing with the kernel's FAT driver, so a mistake of one shows
//! in the other.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

/// The attribute byte of a long-name entry.
const ATTR_LONG_NAME: u8 = 0x0F;
/// The UTF-16 units of a long name each of its entries holds.
const LONG_NAME_UNITS: usize = 13;
/// Where those units are in the entry: 5, then 6, then 2.
const LONG_NAME_SPANS: [(usize, usize); 3] = [(1, 5), (14, 6), (28, 2)];

/// A FAT32 volume, read whole into memory.
pub struct Fat32 {
    bytes: Vec<u8>,
    bps: usize,
    spc: usize,
    reserved: u32,
    fats: usize,
    fat_sectors: u32,
    clusters: u32,
    root_cluster: u32,
}

/// What a walk of the tree found, each file's chain followed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub files: u32,
    pub directories: u32,
    pub bytes: u64,
    pub free_clusters: u32,
    /// Every path seen, the long name when the entry carries one, the 8.3
    /// name otherwise.
    pub paths: Vec<String>,
    /// Every file by its path (upper case, as `paths`): its size and the
    /// FNV-1a hash of its bytes, to compare two trees.
    pub contents: BTreeMap<String, (u32, u64)>,
}

impl Fat32 {
    /// Reads `sectors` sectors of the volume at LBA `first` of `image`
    /// whole, and parses its BPB.
    pub fn read<R: Read + Seek>(image: &mut R, first: u64, sectors: u64) -> Result<Self, String> {
        let mut bytes = vec![0u8; usize::try_from(sectors * 512).map_err(|e| e.to_string())?];
        image.seek(SeekFrom::Start(first * 512)).map_err(|e| e.to_string())?;
        image.read_exact(&mut bytes).map_err(|e| e.to_string())?;
        Self::parse(bytes)
    }

    fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < 512 || bytes[510] != 0x55 || bytes[511] != 0xAA {
            return Err("no 55AA boot signature".into());
        }
        let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        let bps = usize::from(u16_at(11));
        let spc = usize::from(bytes[13]);
        let reserved = u32::from(u16_at(14));
        let fats = usize::from(bytes[16]);
        let fat_sectors = u32_at(36);
        let root_cluster = u32_at(44);
        let total = u64::from(u16_at(19)).max(u64::from(u32_at(32)));
        if !(512..=4096).contains(&bps) || !bps.is_power_of_two() {
            return Err(format!("implausible bytes per sector: {bps}"));
        }
        if spc == 0 || !spc.is_power_of_two() || spc > 128 {
            return Err(format!("implausible sectors per cluster: {spc}"));
        }
        if fats == 0 || fat_sectors == 0 || root_cluster < 2 {
            return Err(format!("not a FAT32 BPB: {fats} FATs, {fat_sectors} sectors each, root {root_cluster}"));
        }
        let data_start = reserved + fats as u32 * fat_sectors;
        let clusters = ((total.saturating_sub(u64::from(data_start)) / spc as u64) as u32).max(2);
        Ok(Self { bytes, bps, spc, reserved, fats, fat_sectors, clusters, root_cluster })
    }

    fn cluster_bytes(&self) -> usize {
        self.bps * self.spc
    }

    /// The FAT entry of `cluster`, from the first FAT copy.
    fn fat_entry(&self, cluster: u32) -> Result<u32, String> {
        if cluster < 2 || cluster >= self.clusters + 2 {
            return Err(format!("cluster {cluster} out of range"));
        }
        let at = self.reserved as usize * self.bps + cluster as usize * 4;
        Ok(u32::from_le_bytes([self.bytes[at], self.bytes[at + 1], self.bytes[at + 2], self.bytes[at + 3]])
            & 0x0FFF_FFFF)
    }

    fn cluster_slice(&self, cluster: u32) -> &[u8] {
        let at = (self.reserved + self.fats as u32 * self.fat_sectors) as usize * self.bps
            + (cluster as usize - 2) * self.cluster_bytes();
        &self.bytes[at..at + self.cluster_bytes()]
    }

    /// The chain from `first`, followed to the end; `Err` on a cycle, an
    /// early end, or a cluster out of range.
    fn chain(&self, first: u32, what: &str) -> Result<Vec<u32>, String> {
        let mut chain = Vec::new();
        let mut cluster = first;
        loop {
            if chain.len() > self.clusters as usize {
                return Err(format!("{what}: the chain does not end within the volume"));
            }
            chain.push(cluster);
            match self.fat_entry(cluster)? {
                next if next >= 0x0FFF_FFF8 => return Ok(chain),
                next @ (0 | 1) => return Err(format!("{what}: the chain ends on the FAT value {next}")),
                next => cluster = next,
            }
        }
    }

    /// Walks the whole tree from the root, following every directory and
    /// every file's chain, and counts the free clusters.
    pub fn walk(&self) -> Result<Stats, String> {
        let mut stats = Stats::default();
        let mut seen = HashSet::new();
        self.walk_dir(self.root_cluster, String::new(), &mut seen, &mut stats)?;
        let mut free = 0;
        for cluster in 2..self.clusters + 2 {
            free += u32::from(self.fat_entry(cluster)? == 0);
        }
        stats.free_clusters = free;
        Ok(stats)
    }

    fn walk_dir(
        &self,
        dir_cluster: u32,
        path: String,
        seen: &mut HashSet<u32>,
        stats: &mut Stats,
    ) -> Result<(), String> {
        if !seen.insert(dir_cluster) {
            return Err(format!("{}: a directory cycle at cluster {dir_cluster}", display(&path)));
        }
        // The long name being gathered: its units, the checksum of the 8.3
        // name they belong to, and the order expected next.
        let mut long: Vec<u16> = Vec::new();
        let mut checksum: u8 = 0;
        let mut next_order: u8 = 0;
        for cluster in self.chain(dir_cluster, display(&path))? {
            for entry in self.cluster_slice(cluster).chunks_exact(32) {
                match entry[0] {
                    // The end of the directory.
                    0x00 => return Ok(()),
                    // A deleted entry.
                    0xE5 => long.clear(),
                    _ if entry[11] == ATTR_LONG_NAME => {
                        let order = entry[0] & 0x3F;
                        if entry[0] & 0x40 != 0 {
                            long = vec![0; usize::from(order) * LONG_NAME_UNITS];
                            checksum = entry[13];
                            next_order = order;
                        }
                        if entry[13] != checksum || order != next_order || long.is_empty() {
                            long.clear();
                            continue;
                        }
                        let mut units = LONG_NAME_SPANS.iter().flat_map(|&(start, count)| {
                            (0..count)
                                .map(move |i| u16::from_le_bytes([entry[start + 2 * i], entry[start + 2 * i + 1]]))
                        });
                        let at = usize::from(order - 1) * LONG_NAME_UNITS;
                        for unit in &mut long[at..at + LONG_NAME_UNITS] {
                            *unit = units.next().unwrap_or(0);
                        }
                        next_order -= 1;
                    }
                    // The volume label.
                    _ if entry[11] & 0x08 != 0 => long.clear(),
                    _ => {
                        let raw: String =
                            entry[..11].iter().map(|&byte| byte as char).collect::<String>().trim_end().into();
                        let short = {
                            let (base, ext) = raw.split_at(8.min(raw.len()));
                            let ext = ext.trim_end();
                            if ext.is_empty() {
                                base.trim_end().to_string()
                            } else {
                                format!("{}.{}", base.trim_end(), ext)
                            }
                        };
                        // The long name, when the entries before it make one
                        // for this 8.3 entry.
                        let expected_checksum = {
                            let mut sum = 0u8;
                            for &byte in &entry[..11] {
                                sum = sum.rotate_right(1).wrapping_add(byte);
                            }
                            sum
                        };
                        let name = if !long.is_empty() && next_order == 0 && checksum == expected_checksum {
                            let end = long.iter().position(|&unit| unit == 0).unwrap_or(long.len());
                            String::from_utf16(&long[..end]).map_err(|_| "a long name is not UTF-16".to_string())?
                        } else {
                            short.clone()
                        };
                        long.clear();
                        if raw.starts_with('.') {
                            // `.` and `..` do not walk.
                            continue;
                        }
                        let child = if path.is_empty() { name.clone() } else { format!("{path}/{name}") };
                        if entry[11] & 0x10 != 0 {
                            stats.directories += 1;
                            let first = (u32::from(entry[27]) << 8 | u32::from(entry[26]))
                                | (u32::from(entry[20]) << 16 | u32::from(entry[21]) << 24);
                            if first < 2 {
                                return Err(format!("{}: a directory without a cluster", display(&child)));
                            }
                            self.walk_dir(first, child, seen, stats)?;
                        } else {
                            let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                            let first = (u32::from(entry[27]) << 8 | u32::from(entry[26]))
                                | (u32::from(entry[20]) << 16 | u32::from(entry[21]) << 24);
                            let hash = self.verify_file(first, size, &child, &short)?;
                            stats.files += 1;
                            stats.bytes += u64::from(size);
                            // The long names keep the case of their source;
                            // the verification matches without it.
                            stats.paths.push(child.to_ascii_uppercase());
                            stats.contents.insert(child.to_ascii_uppercase(), (size, hash));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Follows the file's chain to its end: exactly as many clusters as the
    /// size needs, no cycle; and the signatures the name promises — MZ for
    /// the PE (`.DLL`, `.EXE`, `.EFI`), regf for the hives of a CONFIG
    /// directory. Rends the FNV-1a hash of its bytes.
    fn verify_file(&self, first: u32, size: u32, path: &str, short: &str) -> Result<u64, String> {
        if size == 0 {
            // A file without bytes may hold no cluster.
            return Ok(FNV_OFFSET);
        }
        if first < 2 {
            return Err(format!("{}: no first cluster", display(path)));
        }
        let chain = self.chain(first, display(path))?;
        let expected = size.div_ceil(self.cluster_bytes() as u32);
        if chain.len() as u32 != expected.max(1) {
            return Err(format!(
                "{}: the size needs {expected} clusters, the chain holds {}",
                display(path),
                chain.len()
            ));
        }
        let head = &self.cluster_slice(chain[0])[..size.min(4) as usize];
        let extension = short.rsplit_once('.').map(|(_, ext)| ext.to_ascii_uppercase()).unwrap_or_default();
        if matches!(extension.as_str(), "DLL" | "EXE" | "EFI") && head[..size.min(2) as usize] != *b"MZ" {
            return Err(format!("{}: a PE without MZ", display(path)));
        }
        let in_config = path.rsplit_once('/').map(|(_, dir)| dir.eq_ignore_ascii_case("CONFIG")).unwrap_or(false);
        if in_config && extension != "LOG" && head[..size.min(4) as usize] != *b"regf" {
            return Err(format!("{}: a hive of CONFIG without regf", display(path)));
        }
        // FNV-1a over the bytes of the chain, as `fnv1a` over the file.
        let mut hash = FNV_OFFSET;
        let mut left = size as usize;
        for &cluster in &chain {
            let take = left.min(self.cluster_bytes());
            for &byte in &self.cluster_slice(cluster)[..take] {
                hash = (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
            }
            left -= take;
        }
        Ok(hash)
    }
}

/// The FNV-1a hash (64 bits) of `bytes`, as [`Stats::contents`] holds it for
/// each file.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET, |hash, &byte| (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME))
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// `""` shows as the root.
fn display(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader walks what the [`fatfs`] writer wrote: the 8.3 names, the
    /// long names with their checksums, the sizes, and the free clusters.
    #[test]
    fn the_reader_walks_what_the_writer_wrote() {
        // A DLL starts with MZ: the reader checks it.
        let mut payload: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
        payload[..2].copy_from_slice(b"MZ");
        let image = fatfs::build(&[
            (fatfs::path("KERNEL.BIN").unwrap(), b"ABCD".to_vec()),
            (fatfs::path("WINDOWS/SYSTEM32/NTDLL.DLL").unwrap(), payload.clone()),
            (fatfs::path("WINDOWS/SYSTEM32/KERNEL32_VISTA.DLL").unwrap(), payload.clone()),
            (fatfs::path("WINDOWS/SYSTEM32/CONFIG/SYSTEM").unwrap(), b"regf-hive-bytes".to_vec()),
            (fatfs::path("WINDOWS/FONTS/TAHOMA.TTF").unwrap(), vec![7u8; 100]),
        ])
        .unwrap();
        let mut file = std::io::Cursor::new(image.clone());
        let volume = Fat32::read(&mut file, 0, u64::from(image.len() as u32).div_ceil(512)).unwrap();
        let stats = volume.walk().unwrap();
        assert_eq!(stats.files, 5);
        assert_eq!(stats.directories, 4, "WINDOWS, SYSTEM32, CONFIG, FONTS");
        assert_eq!(stats.bytes, 4 + 2500 + 2500 + 15 + 100);
        // The hash of a file read through its chain is the hash of its bytes.
        assert_eq!(stats.contents.get("WINDOWS/SYSTEM32/NTDLL.DLL"), Some(&(2500, fnv1a(&payload))));
        assert_eq!(stats.contents.get("KERNEL.BIN"), Some(&(4, fnv1a(b"ABCD"))));
        assert!(stats.free_clusters > 0);
        let upcased: HashSet<&str> = stats.paths.iter().map(String::as_str).collect();
        for path in [
            "KERNEL.BIN",
            "WINDOWS/SYSTEM32/NTDLL.DLL",
            "WINDOWS/SYSTEM32/KERNEL32_VISTA.DLL",
            "WINDOWS/SYSTEM32/CONFIG/SYSTEM",
            "WINDOWS/FONTS/TAHOMA.TTF",
        ] {
            assert!(upcased.contains(path), "{path} not seen in {:?}", stats.paths);
        }
    }

    /// A truncated chain (a size larger than the chain holds) is refused.
    #[test]
    fn a_size_past_the_chain_is_refused() {
        let image = fatfs::build(&[(fatfs::path("X.BIN").unwrap(), vec![1u8; 1024])]).unwrap();
        let mut corrupted = image;
        let at = corrupted.windows(11).position(|window| window == b"X       BIN").expect("the entry is in the image");
        corrupted[at + 28..at + 32].copy_from_slice(&4096u32.to_le_bytes());
        let sectors = u64::from(corrupted.len() as u32).div_ceil(512);
        let mut file = std::io::Cursor::new(corrupted);
        let volume = Fat32::read(&mut file, 0, sectors).unwrap();
        let error = volume.walk().unwrap_err();
        assert!(error.contains("clusters"), "{error}");
    }
}
