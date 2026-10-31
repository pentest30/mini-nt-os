//! The FAT32 image: a tree of directories and files, as `fsck.vfat` and
//! the FAT32 specification want it.
//!
//! Each file is given by its path, a list of 8.3 names; the directories on
//! the way are created. Directories, the root included, take as many
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
//! Directory entry (32 bytes): [0..11] name, [11] attributes,
//! [20..22] first cluster (high), [26..28] first cluster (low), [28..32] size.

/// An 8.3 name, padded with spaces: 8 bytes of base name, 3 of extension.
pub type ShortName = [u8; 11];

const SECTOR: usize = 512;
const ENTRY: usize = 32;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const END_OF_CHAIN: u32 = 0x0FFF_FFFF;
const RESERVED_SECTORS: usize = 32;
const FAT_COUNT: usize = 2;
/// The fewest clusters of a FAT32 volume (below, it would be FAT16).
pub const MIN_CLUSTERS: usize = 65_525;
/// Free clusters left after the files, at least: 4 MiB.
pub const FREE_CLUSTERS: usize = 8192;
const DOT: ShortName = *b".          ";
const DOT_DOT: ShortName = *b"..         ";

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

/// The path `path` (components separated by `/` or `\`), as 8.3 names.
pub fn short_path(path: &str) -> Result<Vec<ShortName>, String> {
    let names: Vec<ShortName> =
        path.split(['/', '\\']).filter(|part| !part.is_empty()).map(short_name).collect::<Result<_, _>>()?;
    if names.is_empty() {
        return Err(format!("{path}: an empty path"));
    }
    Ok(names)
}

/// `FOO.BAR` for an 8.3 name.
pub fn display(name: &ShortName) -> String {
    let base = String::from_utf8_lossy(&name[..8]).trim_end().to_string();
    let ext = String::from_utf8_lossy(&name[8..]).trim_end().to_string();
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

enum Node {
    File { data: usize, first: u32 },
    Dir(Dir),
}

#[derive(Default)]
struct Dir {
    entries: Vec<(ShortName, Node)>,
    first: u32,
    clusters: u32,
}

impl Dir {
    /// Adds the file `data` (an index into the file list) at `path` under
    /// this directory, creating the directories on the way.
    fn add(&mut self, path: &[ShortName], data: usize) -> Result<(), String> {
        let (name, rest) = path.split_first().expect("a path is never empty");
        let existing = self.entries.iter_mut().find(|(entry, _)| entry == name).map(|(_, node)| node);
        match (existing, rest.is_empty()) {
            (None, true) => self.entries.push((*name, Node::File { data, first: 0 })),
            (None, false) => {
                let mut dir = Dir::default();
                dir.add(rest, data)?;
                self.entries.push((*name, Node::Dir(dir)));
            }
            (Some(Node::Dir(dir)), false) => dir.add(rest, data)?,
            (Some(_), _) => return Err(format!("{}: given twice, or as a file and a directory", display(name))),
        }
        Ok(())
    }

    /// Gives this directory, then what it holds, their clusters from `next`.
    fn place(&mut self, root: bool, files: &[Vec<u8>], next: &mut u32) {
        let entries = self.entries.len() + if root { 0 } else { 2 };
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
            entries.push(match node {
                Node::File { data, first } => entry(name, ATTR_ARCHIVE, *first, files[*data].len() as u32),
                Node::Dir(dir) => entry(name, ATTR_DIRECTORY, dir.first, 0),
            });
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

fn entry(name: &ShortName, attributes: u8, first: u32, size: u32) -> [u8; ENTRY] {
    let mut entry = [0u8; ENTRY];
    entry[..11].copy_from_slice(name);
    entry[11] = attributes;
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

/// The image holding `files`, each a path and its bytes.
pub fn build(files: &[(Vec<ShortName>, Vec<u8>)]) -> Result<Vec<u8>, String> {
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
fn boot_sector(total_sectors: u32, fat_sectors: u32) -> [u8; SECTOR] {
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
fn fs_info_sector() -> [u8; SECTOR] {
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

    fn file(path: &str, data: &[u8]) -> (Vec<ShortName>, Vec<u8>) {
        (short_path(path).unwrap(), data.to_vec())
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
        assert_eq!(short_path("WINDOWS\\system32/ntdll.dll").unwrap().len(), 3);
        assert_eq!(display(b"KERNEL32DLL"), "KERNEL32.DLL");
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
    fn a_name_given_twice_is_refused() {
        assert!(build(&[file("A", b"1"), file("a", b"2")]).is_err());
        assert!(build(&[file("A", b"1"), file("A/B", b"2")]).is_err());
    }
}
