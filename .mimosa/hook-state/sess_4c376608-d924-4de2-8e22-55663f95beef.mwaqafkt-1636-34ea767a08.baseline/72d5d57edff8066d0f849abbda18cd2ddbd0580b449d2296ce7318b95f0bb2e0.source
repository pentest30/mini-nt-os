//! ISO 9660 (ECMA-119), to take the system tree out of the ReactOS CD image;
//! std only. The primary volume descriptor gives the root; names are taken
//! as recorded (ReactOS's `cdmake` keeps them as on its tree), without a
//! `;1` version or a trailing dot. No Joliet, no Rock Ridge, no multi-extent
//! file.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

const SECTOR: u64 = 2048;
/// Volume descriptors start at sector 16.
const FIRST_DESCRIPTOR: u64 = 16;
const PRIMARY: u8 = 1;
const TERMINATOR: u8 = 255;

/// A directory record.
#[derive(Clone, Debug, PartialEq)]
pub struct Dirent {
    pub name: String,
    pub sector: u32,
    pub size: u32,
    pub directory: bool,
}

/// An ISO 9660 image.
pub struct Iso<R> {
    reader: R,
    root: Dirent,
}

impl<R: Read + Seek> Iso<R> {
    /// The image in `reader`, from its primary volume descriptor.
    pub fn open(mut reader: R) -> Result<Self, String> {
        for n in FIRST_DESCRIPTOR.. {
            let mut descriptor = [0u8; SECTOR as usize];
            read_at(&mut reader, n * SECTOR, &mut descriptor)?;
            if &descriptor[1..6] != b"CD001" {
                return Err("iso9660: no volume descriptor".into());
            }
            match descriptor[0] {
                PRIMARY => {
                    let root = record(&descriptor[156..190]).ok_or("iso9660: bad root record")?;
                    return Ok(Self { reader, root: Dirent { name: String::new(), ..root } });
                }
                TERMINATOR => break,
                _ => {}
            }
        }
        Err("iso9660: no primary volume descriptor".into())
    }

    /// The records of `directory`, without `.` and `..`.
    pub fn read_dir(&mut self, directory: &Dirent) -> Result<Vec<Dirent>, String> {
        let mut data = vec![0u8; directory.size as usize];
        read_at(&mut self.reader, u64::from(directory.sector) * SECTOR, &mut data)?;
        let mut entries = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let length = usize::from(data[at]);
            if length == 0 {
                // Records do not cross sectors: the rest of this one is padding.
                at = (at / SECTOR as usize + 1) * SECTOR as usize;
                continue;
            }
            let rec = data.get(at..at + length).ok_or("iso9660: record past its directory")?;
            let entry = record(rec).ok_or("iso9660: bad directory record")?;
            if !entry.name.is_empty() {
                entries.push(entry);
            }
            at += length;
        }
        Ok(entries)
    }

    /// The record at `path` (`/`-separated, names compared without case).
    pub fn lookup(&mut self, path: &str) -> Result<Dirent, String> {
        let mut current = self.root.clone();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            current = self
                .read_dir(&current)?
                .into_iter()
                .find(|e| e.name.eq_ignore_ascii_case(part))
                .ok_or_else(|| format!("iso9660: no {path}"))?;
        }
        Ok(current)
    }

    /// Writes the content of the file `entry` to `sink`.
    pub fn copy<W: Write>(&mut self, entry: &Dirent, sink: &mut W) -> Result<(), String> {
        self.reader.seek(SeekFrom::Start(u64::from(entry.sector) * SECTOR)).map_err(io_error)?;
        let copied = io::copy(&mut (&mut self.reader).take(entry.size.into()), sink).map_err(io_error)?;
        if copied != u64::from(entry.size) {
            return Err(format!("iso9660: {} cut short", entry.name));
        }
        Ok(())
    }

    /// Copies the directory `entry` and everything below it into `dest`;
    /// returns the number of files and their bytes.
    pub fn extract_tree(&mut self, entry: &Dirent, dest: &Path) -> Result<(usize, u64), String> {
        fs::create_dir_all(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
        let (mut files, mut bytes) = (0, 0);
        for child in self.read_dir(entry)? {
            let path = dest.join(&child.name);
            if child.directory {
                let (f, b) = self.extract_tree(&child, &path)?;
                files += f;
                bytes += b;
            } else {
                let mut file =
                    io::BufWriter::new(fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?);
                self.copy(&child, &mut file)?;
                file.flush().map_err(|e| format!("{}: {e}", path.display()))?;
                files += 1;
                bytes += u64::from(child.size);
            }
        }
        Ok((files, bytes))
    }
}

/// A directory record; `.` and `..` get an empty name. `None` if malformed,
/// or if the name could escape its directory.
fn record(rec: &[u8]) -> Option<Dirent> {
    if rec.len() < 34 {
        return None;
    }
    let sector = u32::from_le_bytes(rec[2..6].try_into().ok()?);
    let size = u32::from_le_bytes(rec[10..14].try_into().ok()?);
    let directory = rec[25] & 0x02 != 0;
    let name_length = usize::from(rec[32]);
    let raw = rec.get(33..33 + name_length)?;
    let name = match raw {
        [0] | [1] => String::new(),
        _ => {
            let name = String::from_utf8_lossy(raw);
            let name = name.split(';').next().unwrap_or_default().trim_end_matches('.');
            if name.is_empty() || name == ".." || name.contains(['/', '\\', '\0']) {
                return None;
            }
            name.to_string()
        }
    };
    Some(Dirent { name, sector, size, directory })
}

fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, buffer: &mut [u8]) -> Result<(), String> {
    reader.seek(SeekFrom::Start(offset)).map_err(io_error)?;
    reader.read_exact(buffer).map_err(io_error)
}

fn io_error(e: io::Error) -> String {
    format!("iso9660: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A directory record for `name` at `sector`.
    fn rec(name: &[u8], sector: u32, size: u32, directory: bool) -> Vec<u8> {
        let length = 33 + name.len() + (name.len() + 1) % 2;
        let mut r = vec![0u8; length];
        r[0] = length as u8;
        r[2..6].copy_from_slice(&sector.to_le_bytes());
        r[6..10].copy_from_slice(&sector.to_be_bytes());
        r[10..14].copy_from_slice(&size.to_le_bytes());
        r[14..18].copy_from_slice(&size.to_be_bytes());
        r[25] = if directory { 2 } else { 0 };
        r[32] = name.len() as u8;
        r[33..33 + name.len()].copy_from_slice(name);
        r
    }

    /// An image: the root (sector 18) holds `reactos` (19) and `readme.txt;1`
    /// (20); `reactos` holds `system32` (21), which holds `ntdll.dll` (22).
    fn image() -> Vec<u8> {
        let mut iso = vec![0u8; 23 * SECTOR as usize];
        let sector = |iso: &mut Vec<u8>, n: usize, records: &[Vec<u8>]| {
            let mut at = n * SECTOR as usize;
            for r in records {
                iso[at..at + r.len()].copy_from_slice(r);
                at += r.len();
            }
        };
        let pvd = 16 * SECTOR as usize;
        iso[pvd] = PRIMARY;
        iso[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        let root = rec(&[0], 18, SECTOR as u32, true);
        iso[pvd + 156..pvd + 156 + root.len()].copy_from_slice(&root);
        iso[17 * SECTOR as usize] = TERMINATOR;
        iso[17 * SECTOR as usize + 1..17 * SECTOR as usize + 6].copy_from_slice(b"CD001");
        let dots = |me: u32, parent: u32| [rec(&[0], me, SECTOR as u32, true), rec(&[1], parent, SECTOR as u32, true)];
        let [a, b] = dots(18, 18);
        sector(&mut iso, 18, &[a, b, rec(b"reactos", 19, SECTOR as u32, true), rec(b"readme.txt;1", 20, 5, false)]);
        let [a, b] = dots(19, 18);
        sector(&mut iso, 19, &[a, b, rec(b"system32", 21, SECTOR as u32, true)]);
        iso[20 * SECTOR as usize..20 * SECTOR as usize + 5].copy_from_slice(b"hello");
        let [a, b] = dots(21, 19);
        sector(&mut iso, 21, &[a, b, rec(b"ntdll.dll", 22, 4, false)]);
        iso[22 * SECTOR as usize..22 * SECTOR as usize + 4].copy_from_slice(b"MZ\x90\x00");
        iso
    }

    #[test]
    fn paths_resolve_without_case_or_version() {
        let mut iso = Iso::open(Cursor::new(image())).expect("an image");
        let readme = iso.lookup("/README.TXT").expect("readme.txt;1");
        assert_eq!((readme.name.as_str(), readme.size, readme.directory), ("readme.txt", 5, false));
        let ntdll = iso.lookup("/reactos/System32/ntdll.dll").expect("ntdll.dll");
        let mut bytes = Vec::new();
        iso.copy(&ntdll, &mut bytes).unwrap();
        assert_eq!(bytes, b"MZ\x90\x00");
        assert!(iso.lookup("/reactos/missing").is_err());
    }

    #[test]
    fn a_tree_comes_out_with_its_directories() {
        let mut iso = Iso::open(Cursor::new(image())).unwrap();
        let reactos = iso.lookup("/reactos").unwrap();
        let dest = std::env::temp_dir().join(format!("mino-iso9660-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dest);
        assert_eq!(iso.extract_tree(&reactos, &dest).unwrap(), (1, 4));
        assert_eq!(fs::read(dest.join("system32").join("ntdll.dll")).unwrap(), b"MZ\x90\x00");
        fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn names_that_could_escape_are_refused() {
        assert!(record(&rec(b"..;1", 20, 1, false)).is_none());
        assert!(record(&rec(b"a/b", 20, 1, false)).is_none());
        assert!(record(&rec(b"a\\b", 20, 1, false)).is_none());
        assert_eq!(record(&rec(b"NOEXT.;1", 20, 1, false)).unwrap().name, "NOEXT");
        assert!(Iso::open(Cursor::new(vec![0u8; 20 * SECTOR as usize])).is_err(), "no descriptor");
    }
}
