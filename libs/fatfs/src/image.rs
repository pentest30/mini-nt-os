//! The FAT32 image: a tree of directories and files, as `fsck.vfat` and
//! the FAT32 specification want it.
//!
//! Each file is given by its path, a list of names; the directories on the
//! way are created. A name 8.3 can hold keeps its case as ReactOS's vfatfs
//! keeps it ([`case_flags`]): all in upper case, an 8.3 entry only; with a
//! base or an extension all in lower case, an 8.3 entry with the NT case
//! flags; with a base or an extension of mixed case (`Recent`), a long name
//! (VFAT) before its 8.3 entry, the name in upper case. Another name keeps
//! its case in a long name: the entries of its parts, the last first, before
//! an 8.3 entry whose name is a unique alias (`BASIS~N.EXT`), as other
//! systems make it. Directories, the root included, take as many
//! clusters as their entries need; a subdirectory starts with its `.` and
//! `..` entries. Every directory and file is one contiguous run of clusters,
//! in depth-first order from the root; an empty file has no cluster. The
//! clusters after them are free, for what the kernel writes: at least
//! [`FREE_CLUSTERS`], and enough for the [`MIN_CLUSTERS`] that make a FAT32
//! volume.
//!
//! Geometry:
//!   BytesPerSector   = 512
//!   SectorsPerClust  = 1
//!   ReservedSectors  = 32  (0: boot sector, 1: FSInfo, 6 and 7: their backups)
//!   NumberOfFATs     = 2   (the second mirrors the first)
//!   FAT sectors      = ceil((clusters + 2) × 4 / 512), each FAT
//!   RootCluster      = 2
//!   DataStartLBA     = ReservedSectors + 2 × FAT sectors
//!   lba(cluster)     = DataStartLBA + (cluster − 2)
//!
//! Directory entry (32 bytes): [0..11] name, [11] attributes, [12] the NT
//! case flags ([`CASE_LOWER_BASE`], [`CASE_LOWER_EXT`]), [14..18]
//! creation time and date, [18..20] last access date, [20..22] first
//! cluster (high), [22..26] last write time and date, [26..28] first
//! cluster (low), [28..32] size. Every entry carries the same date and
//! time ([`IMAGE_DATE`], [`IMAGE_TIME`]): two builds of an image are the
//! same.
//! Long-name entry (attributes 0x0F): [0] order (0x40 on the last part),
//! 13 UTF-16 units at [1..11], [14..26] and [28..32], [13] the checksum of
//! the 8.3 name.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};

/// An 8.3 name, padded with spaces: 8 bytes of base name, 3 of extension.
pub type ShortName = [u8; 11];

pub(crate) const SECTOR: usize = 512;
const ENTRY: usize = 32;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
pub(crate) const END_OF_CHAIN: u32 = 0x0FFF_FFFF;
pub(crate) const RESERVED_SECTORS: usize = 32;
pub(crate) const FAT_COUNT: usize = 2;
/// The fewest clusters of a FAT32 volume (below, it would be FAT16).
pub const MIN_CLUSTERS: usize = 65_525;
/// Free clusters left after the files, at least: 4 MiB.
pub const FREE_CLUSTERS: usize = 8192;
const DOT: ShortName = *b".          ";
const DOT_DOT: ShortName = *b"..         ";
const ATTR_LONG_NAME: u8 = 0x0F;
const LONG_NAME_LAST: u8 = 0x40;
/// The UTF-16 units of a long name each of its entries holds.
const LONG_NAME_UNITS: usize = 13;
/// A long name has at most this many UTF-16 units.
const LONG_NAME_MAX: usize = 255;

/// The NT case flags of an 8.3 entry, in its byte 12 (which DOS reserved):
/// the base of its name is in lower case…
pub const CASE_LOWER_BASE: u8 = 0x08;
/// … its extension is.
pub const CASE_LOWER_EXT: u8 = 0x10;

/// The case flags that keep the case of `name`, a name 8.3 holds
/// ([`short_name`]): a base or an extension all in lower case gets its flag,
/// one without letters none; `None` when one of them mixes cases, which only
/// a long name keeps. As ReactOS's vfatfs decides (FATAddEntry, its
/// `BaseAllLower` and `ExtensionAllLower`); the kernel's FAT writer
/// (`io::fat`) follows it too.
pub fn case_flags(name: &str) -> Option<u8> {
    let (base, extension) = name.split_once('.').unwrap_or((name, ""));
    let flag = |part: &str, lower: u8| {
        let has_lower = part.bytes().any(|byte| byte.is_ascii_lowercase());
        match (has_lower, part.bytes().any(|byte| byte.is_ascii_uppercase())) {
            (true, true) => None,
            (true, false) => Some(lower),
            (false, _) => Some(0),
        }
    };
    Some(flag(base, CASE_LOWER_BASE)? | flag(extension, CASE_LOWER_EXT)?)
}

/// The 8.3 name of `s`, as `FOO.BAR` or `FOOBAR`, in upper case.
pub fn short_name(s: &str) -> Result<ShortName, String> {
    let upper = s.to_ascii_uppercase();
    let (base, ext) = match upper.rsplit_once('.') {
        Some((base, ext)) => (base, ext),
        None => (upper.as_str(), ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return Err(format!("{s}: not an 8.3 name"));
    }
    let valid = |c: u8| c.is_ascii_alphanumeric() || b"$%'-_@~`!(){}^#&".contains(&c);
    if !base.bytes().chain(ext.bytes()).all(valid) {
        return Err(format!("{s}: a character an 8.3 name cannot hold"));
    }
    let mut name = [b' '; 11];
    name[..base.len()].copy_from_slice(base.as_bytes());
    name[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Ok(name)
}

/// The path `path` (components separated by `/` or `\`), each component
/// an 8.3 name or a long name ([`long_name_valid`]).
pub fn path(path: &str) -> Result<Vec<String>, String> {
    let names: Vec<String> = path.split(['/', '\\']).filter(|part| !part.is_empty()).map(String::from).collect();
    if names.is_empty() {
        return Err(format!("{path}: an empty path"));
    }
    match names.iter().find(|name| short_name(name).is_err() && !long_name_valid(name)) {
        Some(name) => Err(format!("{name}: not a FAT name")),
        None => Ok(names),
    }
}

/// `name` can be a long name: at most 255 UTF-16 units, no control
/// character, none of `"*/:<>?\|`, not `.` or `..`, not ending with a dot
/// or a space.
pub fn long_name_valid(name: &str) -> bool {
    let forbidden = |c: char| c.is_control() || "\"*/:<>?\\|".contains(c);
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.encode_utf16().count() <= LONG_NAME_MAX
        && !name.chars().any(forbidden)
        && !name.ends_with(['.', ' '])
}

/// The checksum of an 8.3 name, which each entry of its long name carries.
fn checksum(name: &ShortName) -> u8 {
    name.iter().fold(0u8, |sum, &byte| sum.rotate_right(1).wrapping_add(byte))
}

/// The 8.3 alias of the long name `long`, as other systems make it: its base
/// (before its last dot) and its extension in upper case, without spaces or
/// dots, other characters 8.3 cannot hold as `_`; then `~N` after at most 6
/// characters of the base, `N` the first that `taken` does not refuse.
fn alias(long: &str, taken: impl Fn(&ShortName) -> bool) -> ShortName {
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
        let tail = format!("~{n}");
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

/// The entries of the long name `long` of the 8.3 name `short`, in the
/// order a directory holds them: the last part first. A 0 unit ends a name
/// that does not fill its last part, 0xFFFF fills the rest.
fn long_entries(long: &str, short: &ShortName) -> Vec<[u8; ENTRY]> {
    let mut units: Vec<u16> = long.encode_utf16().collect();
    let parts = units.len().div_ceil(LONG_NAME_UNITS);
    if units.len() < parts * LONG_NAME_UNITS {
        units.push(0);
    }
    units.resize(parts * LONG_NAME_UNITS, 0xFFFF);
    (1..=parts)
        .rev()
        .map(|order| {
            let mut entry = [0u8; ENTRY];
            entry[0] = order as u8 | if order == parts { LONG_NAME_LAST } else { 0 };
            entry[11] = ATTR_LONG_NAME;
            entry[13] = checksum(short);
            let mut part = units[(order - 1) * LONG_NAME_UNITS..order * LONG_NAME_UNITS].iter();
            for (start, count) in [(1, 5), (14, 6), (28, 2)] {
                for i in 0..count {
                    let at = start + 2 * i;
                    entry[at..at + 2].copy_from_slice(&part.next().expect("13 units").to_le_bytes());
                }
            }
            entry
        })
        .collect()
}

/// A name in a directory: its 8.3 name, its long name when 8.3 cannot hold
/// it or its case, and the case flags of its 8.3 entry.
struct Name {
    short: ShortName,
    long: Option<String>,
    case: u8,
}

impl Name {
    /// `name` names this entry: its long name or its 8.3 name, any case.
    fn is(&self, name: &str) -> bool {
        self.long.as_ref().is_some_and(|long| long.to_uppercase() == name.to_uppercase())
            || short_name(name).is_ok_and(|short| short == self.short)
    }

    /// How many directory entries it takes.
    fn entries(&self) -> usize {
        1 + self.long.as_ref().map_or(0, |long| long.encode_utf16().count().div_ceil(LONG_NAME_UNITS))
    }
}

enum Node {
    File { data: usize, first: u32 },
    Dir(Dir),
}

#[derive(Default)]
struct Dir {
    entries: Vec<(Name, Node)>,
    first: u32,
    clusters: u32,
}

impl Dir {
    /// Adds the file `data` (an index into the file list) at `path` under
    /// this directory, creating the directories on the way.
    fn add(&mut self, path: &[String], data: usize) -> Result<(), String> {
        let (name, rest) = path.split_first().expect("a path is never empty");
        let existing = self.entries.iter_mut().find(|(entry, _)| entry.is(name)).map(|(_, node)| node);
        match (existing, rest.is_empty()) {
            (None, _) => {
                let entry = self.name(name)?;
                let node = if rest.is_empty() {
                    Node::File { data, first: 0 }
                } else {
                    let mut dir = Dir::default();
                    dir.add(rest, data)?;
                    Node::Dir(dir)
                };
                self.entries.push((entry, node));
            }
            (Some(Node::Dir(dir)), false) => dir.add(rest, data)?,
            (Some(_), _) => return Err(format!("{name}: given twice (or as an alias), or as a file and a directory")),
        }
        Ok(())
    }

    /// The name of a new entry `name`: its 8.3 name with its case flags, or,
    /// for a mixed case, its long name and its 8.3 name; else its long name
    /// and an alias no other entry has. (An 8.3 name that is an alias, or
    /// another entry's 8.3 name, already names that entry: [`Name::is`].)
    fn name(&self, name: &str) -> Result<Name, String> {
        let taken = |short: &ShortName| self.entries.iter().any(|(entry, _)| entry.short == *short);
        match short_name(name) {
            Ok(short) => Ok(match case_flags(name) {
                Some(case) => Name { short, long: None, case },
                None => Name { short, long: Some(name.to_string()), case: 0 },
            }),
            Err(_) if long_name_valid(name) => {
                Ok(Name { short: alias(name, taken), long: Some(name.to_string()), case: 0 })
            }
            Err(error) => Err(error),
        }
    }

    /// Gives this directory, then what it holds, their clusters from `next`.
    fn place(&mut self, root: bool, files: &[Vec<u8>], next: &mut u32) {
        let entries = self.entries.iter().map(|(name, _)| name.entries()).sum::<usize>() + if root { 0 } else { 2 };
        self.clusters = (entries * ENTRY).div_ceil(SECTOR).max(1) as u32;
        self.first = *next;
        *next += self.clusters;
        for (_, node) in &mut self.entries {
            match node {
                Node::File { data, first } => {
                    let clusters = files[*data].len().div_ceil(SECTOR) as u32;
                    *first = if clusters == 0 { 0 } else { *next };
                    *next += clusters;
                }
                Node::Dir(dir) => dir.place(false, files, next),
            }
        }
    }

    /// Writes its chain, its entries and what it holds into `image`.
    fn write(&self, parent: u32, files: &[Vec<u8>], image: &mut Image) {
        image.chain(self.first, self.clusters);
        let mut entries = Vec::new();
        if parent != u32::MAX {
            entries.push(entry(&DOT, ATTR_DIRECTORY, self.first, 0));
            entries.push(entry(&DOT_DOT, ATTR_DIRECTORY, parent, 0));
        }
        for (name, node) in &self.entries {
            if let Some(long) = &name.long {
                entries.extend(long_entries(long, &name.short));
            }
            let mut short = match node {
                Node::File { data, first } => entry(&name.short, ATTR_ARCHIVE, *first, files[*data].len() as u32),
                Node::Dir(dir) => entry(&name.short, ATTR_DIRECTORY, dir.first, 0),
            };
            short[12] = name.case;
            entries.push(short);
        }
        image.put(self.first, &entries.concat());
        // `..` of a directory under the root names cluster 0.
        let me = if parent == u32::MAX { 0 } else { self.first };
        for (_, node) in &self.entries {
            match node {
                Node::File { data, first } if *first != 0 => {
                    let data = &files[*data];
                    image.chain(*first, data.len().div_ceil(SECTOR) as u32);
                    image.put(*first, data);
                }
                Node::File { .. } => {}
                Node::Dir(dir) => dir.write(me, files, image),
            }
        }
    }
}

/// The date of every entry of the image, so that two builds of it are the
/// same: 2004-08-04 (XP SP2, ADR-003), FAT's packed date.
pub const IMAGE_DATE: u16 = ((2004 - 1980) << 9) | (8 << 5) | 4;
/// Its time: 12:00:00, FAT's packed time (2 s steps).
pub const IMAGE_TIME: u16 = 12 << 11;

fn entry(name: &ShortName, attributes: u8, first: u32, size: u32) -> [u8; ENTRY] {
    let mut entry = [0u8; ENTRY];
    entry[..11].copy_from_slice(name);
    entry[11] = attributes;
    // Created, last accessed and last written at the image's date.
    entry[14..16].copy_from_slice(&IMAGE_TIME.to_le_bytes());
    entry[16..18].copy_from_slice(&IMAGE_DATE.to_le_bytes());
    entry[18..20].copy_from_slice(&IMAGE_DATE.to_le_bytes());
    entry[22..24].copy_from_slice(&IMAGE_TIME.to_le_bytes());
    entry[24..26].copy_from_slice(&IMAGE_DATE.to_le_bytes());
    entry[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    entry[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    entry
}

struct Image {
    bytes: Vec<u8>,
    /// Where each FAT copy starts.
    fats: [usize; FAT_COUNT],
    data_start: usize,
}

impl Image {
    /// Chains the `count` clusters from `first`, the last one ending it.
    fn chain(&mut self, first: u32, count: u32) {
        for cluster in first..first + count {
            let next = if cluster + 1 == first + count { END_OF_CHAIN } else { cluster + 1 };
            for fat in self.fats {
                let at = fat + cluster as usize * 4;
                self.bytes[at..at + 4].copy_from_slice(&next.to_le_bytes());
            }
        }
    }

    /// Copies `data` from the start of cluster `first` on.
    fn put(&mut self, first: u32, data: &[u8]) {
        let at = self.data_start + (first as usize - 2) * SECTOR;
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }
}

/// The image holding `files`, each a path ([`path`]) and its bytes.
pub fn build(files: &[(Vec<String>, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut root = Dir::default();
    for (index, (path, _)) in files.iter().enumerate() {
        root.add(path, index)?;
    }
    let data: Vec<Vec<u8>> = files.iter().map(|(_, data)| data.clone()).collect();
    let mut next = 2;
    root.place(true, &data, &mut next);

    let clusters = (next as usize - 2 + FREE_CLUSTERS).max(MIN_CLUSTERS + 64);
    let fat_sectors = ((clusters + 2) * 4).div_ceil(SECTOR);
    let data_start_lba = RESERVED_SECTORS + FAT_COUNT * fat_sectors;
    let total_sectors = data_start_lba + clusters;
    let fat0 = RESERVED_SECTORS * SECTOR;
    let mut image = Image {
        bytes: vec![0u8; total_sectors * SECTOR],
        fats: [fat0, fat0 + fat_sectors * SECTOR],
        data_start: data_start_lba * SECTOR,
    };

    let boot = boot_sector(total_sectors as u32, fat_sectors as u32);
    let fs_info = fs_info_sector();
    for (lba, sector) in [(0, &boot), (1, &fs_info), (6, &boot), (7, &fs_info)] {
        image.bytes[lba * SECTOR..(lba + 1) * SECTOR].copy_from_slice(sector);
    }
    for fat in image.fats {
        image.bytes[fat..fat + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes()); // media descriptor F8
        image.bytes[fat + 4..fat + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        // clean, no error
    }
    root.write(u32::MAX, &data, &mut image);
    Ok(image.bytes)
}

/// The boot sector: a jump, the BPB of FAT32 and its extension, no label
/// ("NO NAME"), the signature.
pub(crate) fn boot_sector(total_sectors: u32, fat_sectors: u32) -> [u8; SECTOR] {
    let mut b = [0u8; SECTOR];
    b[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]); // jmp short, nop
    b[3..11].copy_from_slice(b"MINO    ");
    b[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes()); // BytesPerSector
    b[13] = 1; // SectorsPerCluster
    b[14..16].copy_from_slice(&(RESERVED_SECTORS as u16).to_le_bytes());
    b[16] = FAT_COUNT as u8;
    // RootEntryCount, TotalSectors16 and FATSz16 at 0: FAT32.
    b[21] = 0xF8; // media: fixed disk
    b[24..26].copy_from_slice(&63u16.to_le_bytes()); // sectors per track
    b[26..28].copy_from_slice(&255u16.to_le_bytes()); // heads
    b[32..36].copy_from_slice(&total_sectors.to_le_bytes());
    b[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
    // ExtFlags 0: every FAT mirrored; version 0.0.
    b[44..48].copy_from_slice(&2u32.to_le_bytes()); // RootCluster
    b[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
    b[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector
    b[64] = 0x80; // drive number
    b[66] = 0x29; // extended boot signature
    b[67..71].copy_from_slice(&0x4D49_4E4Fu32.to_le_bytes()); // volume serial number
    b[71..82].copy_from_slice(b"NO NAME    ");
    b[82..90].copy_from_slice(b"FAT32   ");
    b[510..512].copy_from_slice(&[0x55, 0xAA]);
    b
}

/// The FSInfo sector: its signatures, the free count and the next free
/// cluster unknown (0xFFFFFFFF), as the kernel does not keep them.
pub(crate) fn fs_info_sector() -> [u8; SECTOR] {
    let mut s = [0u8; SECTOR];
    s[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    s[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    s[488..492].copy_from_slice(&u32::MAX.to_le_bytes());
    s[492..496].copy_from_slice(&u32::MAX.to_le_bytes());
    s[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    s
}

/// `fsck.vfat -n` on `image`, in a file of the directory of the test
/// binary: `None` without `fsck.vfat`, its output when it fails.
#[cfg(test)]
pub fn fsck(image: &[u8]) -> Option<Result<(), String>> {
    use std::process::Command;
    let program = ["/usr/sbin/fsck.vfat", "/sbin/fsck.vfat", "fsck.vfat"]
        .into_iter()
        .find(|p| Command::new(p).arg("--help").output().is_ok())?;
    let path = std::env::temp_dir().join(format!("mkfat-{}-{:p}.img", std::process::id(), image.as_ptr()));
    std::fs::write(&path, image).expect("write the image");
    let output = Command::new(program).args(["-n", "-v"]).arg(&path).output().expect("run fsck.vfat");
    let _ = std::fs::remove_file(&path);
    Some(if output.status.success() {
        Ok(())
    } else {
        Err(format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use io_manager::{BlockDevice, FatError, FatVolume};

    struct Disk(Vec<u8>);

    impl BlockDevice for Disk {
        fn sector_size(&self) -> u32 {
            SECTOR as u32
        }
        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), FatError> {
            let at = lba as usize * SECTOR;
            out.copy_from_slice(self.0.get(at..at + SECTOR).ok_or(FatError::Io)?);
            Ok(())
        }
    }

    fn file(path: &str, data: &[u8]) -> (Vec<String>, Vec<u8>) {
        (super::path(path).unwrap(), data.to_vec())
    }

    fn read(volume: &FatVolume<Disk>, path: &str) -> Vec<u8> {
        let mut file = volume.open(path).unwrap_or_else(|e| panic!("{path}: {e:?}"));
        let mut data = vec![0u8; file.file_size as usize];
        assert_eq!(volume.read(&mut file, &mut data), Ok(data.len()));
        data
    }

    #[test]
    fn names_are_8_3_in_upper_case() {
        assert_eq!(&short_name("ntdll.dll").unwrap(), b"NTDLL   DLL");
        assert_eq!(&short_name("SYSTEM").unwrap(), b"SYSTEM     ");
        assert!(short_name("toolongname.dll").is_err());
        assert!(short_name("a.dlls").is_err());
        assert!(short_name("a b.dll").is_err());
        assert_eq!(path("WINDOWS\\system32/ntdll.dll").unwrap().len(), 3);
    }

    #[test]
    fn files_in_subdirectories_read_back() {
        let big: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let image = build(&[
            file("KERNEL.BIN", b"ABCD"),
            file("WINDOWS/SYSTEM32/NTDLL.DLL", &big),
            file("WINDOWS/SYSTEM32/CONFIG/SYSTEM", b"regf"),
            file("WINDOWS/WIN.INI", b""),
        ])
        .unwrap();
        let volume = FatVolume::mount(Disk(image)).unwrap();
        assert_eq!(read(&volume, "/KERNEL.BIN"), b"ABCD");
        assert_eq!(read(&volume, "/windows/system32/ntdll.dll"), big);
        assert_eq!(read(&volume, "/WINDOWS/SYSTEM32/CONFIG/SYSTEM"), b"regf");
        assert_eq!(read(&volume, "/WINDOWS/WIN.INI"), b"");
        let listed: Vec<String> = volume.list_dir("/WINDOWS/SYSTEM32").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(listed, [".", "..", "NTDLL.DLL", "CONFIG"]);
        assert_eq!(volume.open("/WINDOWS").err(), Some(FatError::NotAFile));
    }

    #[test]
    fn a_directory_spans_clusters() {
        let files: Vec<_> = (0..40).map(|i| file(&format!("DIR/F{i}.TXT"), format!("{i}").as_bytes())).collect();
        let mut root: Vec<_> = (0..20).map(|i| file(&format!("R{i}"), b"r")).collect();
        root.extend(files);
        let volume = FatVolume::mount(Disk(build(&root).unwrap())).unwrap();
        assert_eq!(read(&volume, "/R19"), b"r");
        assert_eq!(read(&volume, "/DIR/F39.TXT"), b"39");
        assert_eq!(volume.list_dir("/DIR").unwrap().len(), 42);
        assert_eq!(volume.list_dir("/").unwrap().len(), 21);
    }

    #[test]
    fn dot_entries_name_the_directory_and_its_parent() {
        let volume = FatVolume::mount(Disk(build(&[file("A/B/C", b"c")]).unwrap())).unwrap();
        let a = volume.list_dir("/A").unwrap();
        let b = volume.list_dir("/A/B").unwrap();
        let a_in_root = volume.list_dir("/").unwrap()[0].first_cluster;
        assert_eq!((a[0].first_cluster, a[1].first_cluster), (a_in_root, 0), "`..` under the root is cluster 0");
        assert_eq!(b[1].first_cluster, a_in_root);
        assert_eq!(b[0].first_cluster, a[2].first_cluster);
    }

    #[test]
    fn every_entry_carries_the_date_of_the_image() {
        let volume = FatVolume::mount(Disk(build(&[file("A/B.TXT", b"b"), file("C.TXT", b"c")]).unwrap())).unwrap();
        for directory in ["/", "/A"] {
            for listed in volume.list_dir(directory).unwrap() {
                let entry = listed.entry;
                assert_eq!((entry.creation_date, entry.creation_time), (IMAGE_DATE, IMAGE_TIME), "{}", listed.name);
                assert_eq!(
                    (entry.write_date, entry.write_time, entry.access_date),
                    (IMAGE_DATE, IMAGE_TIME, IMAGE_DATE)
                );
            }
        }
        assert_eq!((IMAGE_DATE, IMAGE_TIME), (12548, 24576), "2004-08-04 12:00:00");
    }

    #[test]
    fn the_image_is_a_clean_fat32_volume() {
        let big: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
        let image = build(&[
            file("KERNEL.BIN", b"ABCD"),
            file("WINDOWS/SYSTEM32/NTDLL.DLL", &big),
            file("WINDOWS/SYSTEM32/CONFIG/SYSTEM", b"regf"),
            file("EMPTY.TXT", b""),
        ])
        .unwrap();
        assert!(image.len() / SECTOR > MIN_CLUSTERS, "enough clusters for FAT32");
        assert_eq!(&image[510..512], &[0x55, 0xAA]);
        assert_eq!(&image[..SECTOR], &image[6 * SECTOR..7 * SECTOR], "the backup boot sector");
        let volume = FatVolume::mount(Disk(image.clone())).unwrap();
        assert_eq!(read(&volume, "/WINDOWS/SYSTEM32/NTDLL.DLL"), big);
        match fsck(&image) {
            None => std::eprintln!("fsck.vfat not found: the image is not checked (dosfstools)"),
            Some(result) => result.expect("fsck.vfat finds no error"),
        }
    }

    #[test]
    fn long_names_keep_their_case_beside_an_alias() {
        let three_parts = "a rather long file name, in three parts.bin";
        let image = build(&[
            file("WINDOWS/SYSTEM32/NTDLL.DLL", b"n"),
            file("WINDOWS/SYSTEM32/advapi32_vista.dll", b"a"),
            file("WINDOWS/SYSTEM32/ADVAPI32_VISTB.DLL", b"b"),
            file("WINDOWS/SYSTEM32/kernel32_vista.dll", b"k"),
            file(&format!("WINDOWS/{three_parts}"), b"3"),
            file("Program Files/x", b"x"),
        ])
        .unwrap();
        let volume = FatVolume::mount(Disk(image.clone())).unwrap();
        assert_eq!(read(&volume, "/WINDOWS/SYSTEM32/advapi32_vista.dll"), b"a");
        assert_eq!(read(&volume, "/windows/system32/ADVAPI32_VISTA.DLL"), b"a", "any case");
        assert_eq!(read(&volume, "/WINDOWS/SYSTEM32/ADVAPI~1.DLL"), b"a", "its alias");
        assert_eq!(read(&volume, "/WINDOWS/SYSTEM32/ADVAPI~2.DLL"), b"b", "the next alias");
        assert_eq!(read(&volume, "/WINDOWS/SYSTEM32/KERNEL~1.DLL"), b"k");
        assert_eq!(read(&volume, &format!("/WINDOWS/{three_parts}")), b"3");
        assert_eq!(read(&volume, "/PROGRA~1/x"), b"x", "a directory with a long name");
        let listed: Vec<String> = volume.list_dir("/WINDOWS/SYSTEM32").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(listed, [".", "..", "NTDLL.DLL", "advapi32_vista.dll", "ADVAPI32_VISTB.DLL", "kernel32_vista.dll"]);
        match fsck(&image) {
            None => std::eprintln!("fsck.vfat not found: the image is not checked (dosfstools)"),
            Some(result) => result.expect("fsck.vfat finds no error"),
        }
    }

    #[test]
    fn a_name_8_3_holds_keeps_its_case() {
        // As ReactOS's vfatfs (and the kernel's `io::fat`): all in upper case,
        // the 8.3 entry alone; a base or an extension all in lower case, the
        // NT case flags; mixed case, a long name before the 8.3 entry. They
        // all came out in upper case.
        let names = ["UPPER.DAT", "readme.txt", "lower.TXT", "UPCASE.txt", "123.dat", "Mixed.txt", "MIXEXT.Txt"];
        let files: Vec<_> = names.iter().map(|name| file(&format!("Recent/{name}"), name.as_bytes())).collect();
        let image = build(&files).unwrap();
        let volume = FatVolume::mount(Disk(image.clone())).unwrap();
        // The 8.3 entry of `name` in the directory at `dir`, and how many
        // long-name entries come right before it.
        let entry = |dir: u32, name: &str| {
            let (_, at) = volume.find_entry(dir, name).unwrap();
            let parts = (0..at.index)
                .rev()
                .map(|index| volume.read_entry(io_manager::fat::EntryRef { index, ..at }).unwrap())
                .take_while(|before| before[11] == ATTR_LONG_NAME)
                .count();
            (volume.read_entry(at).unwrap(), parts)
        };
        let (recent, parts) = entry(volume.root_cluster(), "RECENT");
        assert_eq!((&recent[..11], recent[12], parts), (&b"RECENT     "[..], 0, 1), "a long name before RECENT");
        let root: Vec<String> = volume.list_dir("/").unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(root, ["Recent"]);
        let dir = volume.find_in_dir(volume.root_cluster(), "recent").unwrap().first_cluster;
        let expected: [(&ShortName, u8, usize); 7] = [
            (b"UPPER   DAT", 0, 0),
            (b"README  TXT", CASE_LOWER_BASE | CASE_LOWER_EXT, 0),
            (b"LOWER   TXT", CASE_LOWER_BASE, 0),
            (b"UPCASE  TXT", CASE_LOWER_EXT, 0),
            (b"123     DAT", CASE_LOWER_EXT, 0),
            (b"MIXED   TXT", 0, 1),
            (b"MIXEXT  TXT", 0, 1),
        ];
        for (name, (short, case, long_parts)) in names.iter().zip(expected) {
            let (entry, parts) = entry(dir, name);
            assert_eq!((&entry[..11], entry[12], parts), (&short[..], case, long_parts), "{name}");
            assert_eq!(read(&volume, &format!("/RECENT/{}", name.to_uppercase())), name.as_bytes());
        }
        // The kernel reads each back in its case.
        let listed: Vec<String> = volume.list_dir("/Recent").unwrap().into_iter().skip(2).map(|e| e.name).collect();
        assert_eq!(listed, names);
        assert!(build(&[file("Recent", b"1"), file("RECENT", b"2")]).is_err(), "the same 8.3 name twice");
        match fsck(&image) {
            None => std::eprintln!("fsck.vfat not found: the image is not checked (dosfstools)"),
            Some(result) => result.expect("fsck.vfat finds no error"),
        }
    }

    #[test]
    fn long_names_count_in_the_size_of_their_directory() {
        // 20 names of two parts: 60 entries, 4 clusters; then another file.
        let mut files: Vec<_> =
            (0..20).map(|i| file(&format!("MANY/long_file_name_{i:02}.data"), format!("{i}").as_bytes())).collect();
        files.push(file("AFTER.BIN", b"after"));
        let image = build(&files).unwrap();
        let volume = FatVolume::mount(Disk(image.clone())).unwrap();
        assert_eq!(read(&volume, "/MANY/long_file_name_19.data"), b"19");
        assert_eq!(read(&volume, "/AFTER.BIN"), b"after");
        assert_eq!(volume.list_dir("/MANY").unwrap().len(), 22);
        if let Some(result) = fsck(&image) {
            result.expect("fsck.vfat finds no error");
        }
    }

    #[test]
    fn aliases_are_made_as_other_systems_make_them() {
        let none = |_: &ShortName| false;
        assert_eq!(&alias("advapi32_vista.dll", none), b"ADVAPI~1DLL");
        assert_eq!(&alias("ntdll_vista.dll", none), b"NTDLL_~1DLL");
        assert_eq!(&alias("a b.c.text", none), b"ABC~1   TEX", "spaces and dots out, the last extension");
        assert_eq!(&alias("x+y=z", none), b"X_Y_Z~1    ", "no extension");
        assert_eq!(&alias(".profile", none), b"PROFIL~1   ", "a leading dot is no extension");
        let first_nine = |name: &ShortName| name[..6] == *b"LONGNA" && name[7] <= b'9' && name[6] == b'~';
        assert_eq!(&alias("longname.txt", first_nine), b"LONGN~10TXT", "the base shortens for ~10");
    }

    #[test]
    fn a_long_name_cannot_hold_everything() {
        assert!(path("a:b").is_err());
        assert!(path("dir/a*b").is_err());
        assert!(path("ends with a dot.").is_err());
        assert!(path(&"x".repeat(256)).is_err());
        assert!(path(&"x".repeat(255)).is_ok());
        assert!(build(&[file("ADVAPI~1.DLL", b"1"), file("advapi32_vista.dll", b"2")]).is_ok(), "then ~2");
        assert!(build(&[file("advapi32_vista.dll", b"1"), file("ADVAPI~1.DLL", b"2")]).is_err(), "taken by the alias");
        assert!(build(&[file("advapi32_vista.dll", b"1"), file("ADVAPI32_VISTA.DLL", b"2")]).is_err(), "twice");
    }

    #[test]
    fn a_name_given_twice_is_refused() {
        assert!(build(&[file("A", b"1"), file("a", b"2")]).is_err());
        assert!(build(&[file("A", b"1"), file("A/B", b"2")]).is_err());
    }
}
