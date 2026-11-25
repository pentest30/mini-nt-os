//! Tar archives (POSIX ustar, with pax and GNU long names), to unpack the
//! sources of the OpenGL ICD (`icd-build`, ADR-025); std only. The archive
//! is read as a stream (the output of `xz -dc`). Regular files and
//! directories are written; a link (symbolic or hard) becomes a copy of the
//! file it names, once the archive is read, which works on every host (no
//! privilege to create links under Windows). The archive is untrusted: a
//! name that is absolute, or that climbs with `..`, stops the extraction.

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use crate::Result;

const BLOCK: usize = 512;

/// What [`extract`] wrote.
#[derive(Debug, Default, PartialEq)]
pub struct Summary {
    pub files: usize,
    pub bytes: u64,
    /// Links copied from their target.
    pub links: usize,
    /// Links whose target is not a file of the archive (left out).
    pub dangling: Vec<String>,
}

/// Unpacks the archive read from `input` under `dest`.
pub fn extract(mut input: impl Read, dest: &Path) -> Result<Summary> {
    let mut summary = Summary::default();
    let mut links: Vec<(PathBuf, PathBuf, String)> = Vec::new();
    // The name and link target that a pax or GNU header gives the next entry.
    let (mut long_name, mut long_link): (Option<String>, Option<String>) = (None, None);
    let mut header = [0u8; BLOCK];
    loop {
        if !read_block(&mut input, &mut header)? {
            break; // an archive cut after its last entry
        }
        if header.iter().all(|&byte| byte == 0) {
            break;
        }
        check_sum(&header)?;
        let size = octal(&header[124..136])?;
        let kind = header[156];
        let data = |input: &mut dyn Read| -> Result<Vec<u8>> {
            let mut bytes = vec![0; usize::try_from(size).map_err(|_| "tar: entry too large")?];
            input.read_exact(&mut bytes).map_err(|e| format!("tar: {e}"))?;
            skip_padding(input, size)?;
            Ok(bytes)
        };
        match kind {
            b'x' => {
                let records = data(&mut input)?;
                for (key, value) in pax_records(&records)? {
                    match key.as_str() {
                        "path" => long_name = Some(value),
                        "linkpath" => long_link = Some(value),
                        _ => {}
                    }
                }
                continue;
            }
            b'g' => {
                data(&mut input)?; // global pax header: nothing we use
                continue;
            }
            b'L' | b'K' => {
                let bytes = data(&mut input)?;
                let text = c_string(&bytes);
                if kind == b'L' {
                    long_name = Some(text)
                } else {
                    long_link = Some(text)
                }
                continue;
            }
            _ => {}
        }
        let name = long_name.take().unwrap_or_else(|| ustar_name(&header));
        let link = long_link.take().unwrap_or_else(|| c_string(&header[157..257]));
        let path = dest.join(safe_relative(&name)?);
        match kind {
            b'0' | 0 | b'7' => {
                let bytes = data(&mut input)?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
                }
                fs::write(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
                summary.files += 1;
                summary.bytes += size;
            }
            b'5' => fs::create_dir_all(&path).map_err(|e| format!("{}: {e}", path.display()))?,
            b'1' => {
                // A hard link names its target from the archive's root.
                links.push((path, dest.join(safe_relative(&link)?), name));
                skip(&mut input, size)?;
            }
            b'2' => {
                // A symbolic link names its target from the link's directory.
                let base = Path::new(&name).parent().unwrap_or(Path::new(""));
                let target = safe_relative(&base.join(&link).to_string_lossy())?;
                links.push((path, dest.join(target), name));
                skip(&mut input, size)?;
            }
            // Devices, FIFOs and the like: nothing to write.
            _ => skip(&mut input, size)?,
        }
    }
    // A link may come before its target, or name another link: copy until
    // nothing changes.
    let mut pending = links;
    loop {
        let before = pending.len();
        pending.retain(|(path, target, _)| {
            if !target.is_file() {
                return true;
            }
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::copy(target, path).is_err()
        });
        summary.links += before - pending.len();
        if pending.is_empty() || pending.len() == before {
            break;
        }
    }
    summary.dangling = pending.into_iter().map(|(_, _, name)| name).collect();
    Ok(summary)
}

/// Reads one block; `false` at the end of the input before any byte of it.
fn read_block(input: &mut impl Read, block: &mut [u8; BLOCK]) -> Result<bool> {
    let mut filled = 0;
    while filled < BLOCK {
        match input.read(&mut block[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err("tar: archive cut in a header".into()),
            Ok(read) => filled += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("tar: {e}")),
        }
    }
    Ok(true)
}

fn skip(input: &mut dyn Read, size: u64) -> Result<()> {
    io::copy(&mut input.take(size), &mut io::sink()).map_err(|e| format!("tar: {e}"))?;
    skip_padding(input, size)
}

fn skip_padding(input: &mut dyn Read, size: u64) -> Result<()> {
    let padding = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
    io::copy(&mut input.take(padding), &mut io::sink()).map_err(|e| format!("tar: {e}"))?;
    Ok(())
}

/// The header's checksum: the sum of its bytes, its own field counted as
/// spaces.
fn check_sum(header: &[u8; BLOCK]) -> Result<()> {
    let stored = octal(&header[148..156])?;
    let sum: u64 =
        header.iter().enumerate().map(|(at, &byte)| if (148..156).contains(&at) { 32 } else { u64::from(byte) }).sum();
    if sum == stored {
        Ok(())
    } else {
        Err(format!("tar: bad header checksum ({sum}, stored {stored})"))
    }
}

/// An octal field, ended by a NUL or a space.
fn octal(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|&byte| byte & 0x80 != 0) {
        return Err("tar: base-256 sizes are not supported".into());
    }
    let digits = field.iter().copied().skip_while(|&byte| byte == b' ').take_while(|byte| (b'0'..=b'7').contains(byte));
    Ok(digits.fold(0, |value, digit| value * 8 + u64::from(digit - b'0')))
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A ustar name: its prefix (field at 345), a slash, its name.
fn ustar_name(header: &[u8; BLOCK]) -> String {
    let name = c_string(&header[0..100]);
    let prefix = if &header[257..262] == b"ustar" { c_string(&header[345..500]) } else { String::new() };
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

/// The records of a pax header: `LENGTH KEY=VALUE\n`, LENGTH counting the
/// whole record.
fn pax_records(bytes: &[u8]) -> Result<Vec<(String, String)>> {
    let mut records = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() && rest[0] != 0 {
        let space = rest.iter().position(|&byte| byte == b' ').ok_or("tar: bad pax record")?;
        let length: usize =
            std::str::from_utf8(&rest[..space]).ok().and_then(|text| text.parse().ok()).ok_or("tar: bad pax length")?;
        if length <= space + 1 || length > rest.len() || rest[length - 1] != b'\n' {
            return Err("tar: bad pax record".into());
        }
        let record = String::from_utf8_lossy(&rest[space + 1..length - 1]).into_owned();
        let (key, value) = record.split_once('=').ok_or("tar: pax record without `=`")?;
        records.push((key.to_string(), value.to_string()));
        rest = &rest[length..];
    }
    Ok(records)
}

/// `name` as a path under the destination: no root, no `..` that leaves
/// it (a `..` inside, as in a link's target, is folded).
fn safe_relative(name: &str) -> Result<PathBuf> {
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => parts.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(format!("tar: `{name}` leaves the destination"));
                }
            }
            Component::RootDir | Component::Prefix(_) => return Err(format!("tar: `{name}` is absolute")),
        }
    }
    if parts.is_empty() {
        return Err(format!("tar: empty name `{name}`"));
    }
    Ok(parts.iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar header for `name` of `kind`, `size` bytes, linked to `link`.
    fn header(name: &str, kind: u8, size: usize, link: &str) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..108].copy_from_slice(b"0000644\0");
        block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        block[156] = kind;
        block[157..157 + link.len()].copy_from_slice(link.as_bytes());
        block[257..263].copy_from_slice(b"ustar\0");
        block[148..156].copy_from_slice(b"        ");
        let sum: u32 = block.iter().map(|&byte| u32::from(byte)).sum();
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        block
    }

    fn entry(archive: &mut Vec<u8>, name: &str, kind: u8, data: &[u8], link: &str) {
        archive.extend(header(name, kind, data.len(), link));
        archive.extend(data);
        archive.resize(archive.len().next_multiple_of(BLOCK), 0);
    }

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mino-xtask-tar-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn files_directories_and_links_come_out() {
        let mut archive = Vec::new();
        entry(&mut archive, "src/", b'5', b"", "");
        // A link before its target, and a link to a link.
        entry(&mut archive, "src/alias.h", b'2', b"", "real.h");
        entry(&mut archive, "src/other/again.h", b'2', b"", "../alias.h");
        entry(&mut archive, "src/real.h", b'0', b"#define REAL 1\n", "");
        entry(&mut archive, "src/hard.h", b'1', b"", "src/real.h");
        entry(&mut archive, "src/broken.h", b'2', b"", "missing.h");
        let long = format!("src/{}.c", "n".repeat(120));
        entry(&mut archive, "././@LongLink", b'L', format!("{long}\0").as_bytes(), "");
        entry(&mut archive, "src/truncated", b'0', b"long", "");
        let pax_name = format!("src/{}.txt", "p".repeat(110));
        let record = format!("path={pax_name}\n");
        let pax = format!("{} {record}", record.len() + 4); // 3 digits and a space
        assert_eq!(pax.len(), record.len() + 4);
        entry(&mut archive, "PaxHeader", b'x', pax.as_bytes(), "");
        entry(&mut archive, "src/short", b'0', b"pax", "");
        archive.extend([0u8; 2 * BLOCK]);

        let dest = scratch("ok");
        let summary = extract(&archive[..], &dest).unwrap();
        assert_eq!(summary.files, 3);
        assert_eq!(summary.links, 3);
        assert_eq!(summary.dangling, ["src/broken.h"]);
        for name in ["src/real.h", "src/alias.h", "src/other/again.h", "src/hard.h"] {
            assert_eq!(fs::read(dest.join(name)).unwrap(), b"#define REAL 1\n", "{name}");
        }
        assert_eq!(fs::read(dest.join(&long)).unwrap(), b"long");
        assert_eq!(fs::read(dest.join(&pax_name)).unwrap(), b"pax");
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn a_name_that_leaves_the_destination_stops_the_extraction() {
        for name in ["../evil", "/etc/evil", "a/../../evil"] {
            let mut archive = Vec::new();
            entry(&mut archive, name, b'0', b"x", "");
            let dest = scratch("evil");
            assert!(extract(&archive[..], &dest).is_err(), "{name}");
            let _ = fs::remove_dir_all(&dest);
        }
        let mut archive = Vec::new();
        entry(&mut archive, "a", b'2', b"", "../../outside");
        assert!(extract(&archive[..], &scratch("evil-link")).is_err());
    }

    #[test]
    fn a_bad_checksum_is_refused() {
        let mut archive = Vec::new();
        entry(&mut archive, "a", b'0', b"x", "");
        archive[0] = b'b';
        assert!(extract(&archive[..], &scratch("sum")).unwrap_err().contains("checksum"));
    }
}
