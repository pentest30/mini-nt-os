//! ZIP archives (PKWARE APPNOTE), to unpack what `fetch-userland` downloads,
//! and to make the stored archives of the M7 routes ([`stored`]); std only.
//! The central directory lists the entries; an entry is stored or deflated,
//! and its size and CRC-32 check what comes out. No ZIP64, no encryption, no
//! archive split over several files.

use std::io::Write;

use crate::inflate::{inflate, Crc32};

/// An entry of the central directory.
#[derive(Debug, PartialEq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    method: u16,
    crc: u32,
    compressed: u64,
    /// Where its local header starts.
    local_header: usize,
}

const END_OF_CENTRAL_DIRECTORY: u32 = 0x0605_4b50;
const CENTRAL_DIRECTORY_HEADER: u32 = 0x0201_4b50;
const LOCAL_HEADER: u32 = 0x0403_4b50;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;

/// A ZIP archive of `files` (name, bytes), each stored (not compressed),
/// dated 2004-08-04 12:00 like the disks' files; the names in ASCII.
pub fn stored(files: &[(&str, &[u8])]) -> Vec<u8> {
    // MS-DOS time and date: 12:00:00, 2004-08-04.
    const TIME: u16 = 12 << 11;
    const DATE: u16 = ((2004 - 1980) << 9) | (8 << 5) | 4;
    let mut archive = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let mut crc = Crc32::new();
        crc.update(data);
        let (crc, size, at) = (crc.value(), data.len() as u32, archive.len() as u32);
        let common = |out: &mut Vec<u8>| {
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed: 2.0
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&STORED.to_le_bytes());
            out.extend_from_slice(&TIME.to_le_bytes());
            out.extend_from_slice(&DATE.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes()); // compressed
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra field
        };
        archive.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
        common(&mut archive);
        archive.extend_from_slice(name.as_bytes());
        archive.extend_from_slice(data);
        central.extend_from_slice(&CENTRAL_DIRECTORY_HEADER.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // made by: MS-DOS, 2.0
        common(&mut central);
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&0x20u32.to_le_bytes()); // external: archive
        central.extend_from_slice(&at.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let (start, length, count) = (archive.len() as u32, central.len() as u32, files.len() as u16);
    archive.extend_from_slice(&central);
    archive.extend_from_slice(&END_OF_CENTRAL_DIRECTORY.to_le_bytes());
    archive.extend_from_slice(&[0, 0, 0, 0]); // this disk, the directory's disk
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&length.to_le_bytes());
    archive.extend_from_slice(&start.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes()); // comment
    archive
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| "zip: truncated".to_string())
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "zip: truncated".to_string())
}

/// The entries of `archive`, in the order of its central directory.
pub fn entries(archive: &[u8]) -> Result<Vec<Entry>, String> {
    // The end record is in the last 22 bytes, then a comment of at most 64 KiB.
    let lowest = archive.len().saturating_sub(22 + 0xFFFF);
    let end = (lowest..=archive.len().saturating_sub(22))
        .rev()
        .find(|&at| u32_at(archive, at) == Ok(END_OF_CENTRAL_DIRECTORY))
        .ok_or("zip: no end of central directory")?;
    let count = u16_at(archive, end + 10)?;
    let mut at = u32_at(archive, end + 16)? as usize;
    if at == 0xFFFF_FFFF || count == 0xFFFF {
        return Err("zip: ZIP64 archives are not supported".into());
    }
    let mut entries = Vec::with_capacity(count.into());
    for _ in 0..count {
        if u32_at(archive, at)? != CENTRAL_DIRECTORY_HEADER {
            return Err("zip: bad central directory header".into());
        }
        let flags = u16_at(archive, at + 8)?;
        if flags & 1 != 0 {
            return Err("zip: encrypted entries are not supported".into());
        }
        let name_length = usize::from(u16_at(archive, at + 28)?);
        let skip = name_length + usize::from(u16_at(archive, at + 30)?) + usize::from(u16_at(archive, at + 32)?);
        let name = archive.get(at + 46..at + 46 + name_length).ok_or("zip: truncated")?;
        entries.push(Entry {
            name: String::from_utf8_lossy(name).into_owned(),
            method: u16_at(archive, at + 10)?,
            crc: u32_at(archive, at + 16)?,
            compressed: u32_at(archive, at + 20)?.into(),
            size: u32_at(archive, at + 24)?.into(),
            local_header: u32_at(archive, at + 42)? as usize,
        });
        at += 46 + skip;
    }
    Ok(entries)
}

/// Writes the content of `entry` to `sink`, checking its size and CRC-32.
pub fn extract<W: Write>(archive: &[u8], entry: &Entry, mut sink: W) -> Result<(), String> {
    let header = entry.local_header;
    if u32_at(archive, header)? != LOCAL_HEADER {
        return Err(format!("zip: {}: bad local header", entry.name));
    }
    let start = header + 30 + usize::from(u16_at(archive, header + 26)?) + usize::from(u16_at(archive, header + 28)?);
    let data = archive.get(start..start + entry.compressed as usize).ok_or("zip: entry past the archive")?;
    let (size, crc) = match entry.method {
        STORED => {
            let mut crc = Crc32::new();
            crc.update(data);
            sink.write_all(data).map_err(|e| format!("zip: write: {e}"))?;
            (data.len() as u64, crc.value())
        }
        DEFLATED => inflate(data, sink)?,
        method => return Err(format!("zip: {}: compression method {method} not supported", entry.name)),
    };
    if (size, crc) != (entry.size, entry.crc) {
        return Err(format!(
            "zip: {}: {size} bytes of CRC-32 {crc:#010x}, expected {} bytes of CRC-32 {:#010x}",
            entry.name, entry.size, entry.crc
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(lines: &[&str]) -> Vec<u8> {
        let hex: String = lines.concat();
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    /// Python's zipfile: `dir/a.txt` and `b.bin`, stored.
    const STORED_ARCHIVE: &[&str] = &[
        "504b0304140000000000e4545f5df5b6d4fe1d0000001d000000090000006469722f612e74787468656c6c6f207a6970",
        "2068656c6c6f207a69702068656c6c6f207a6970504b0304140000000000e4545f5d8cce0e1040000000400000000500",
        "0000622e62696e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728",
        "292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f504b01021403140000000000e4545f5df5b6d4fe1d0000001d",
        "0000000900000000000000000000008001000000006469722f612e747874504b01021403140000000000e4545f5d8cce",
        "0e104000000040000000050000000000000000000000800144000000622e62696e504b050600000000020002006a0000",
        "00a70000000000",
    ];

    /// The same, deflated.
    const DEFLATED_ARCHIVE: &[&str] = &[
        "504b0304140000000800e4545f5df5b6d4fe0f0000001d000000090000006469722f612e747874cb48cdc9c957a8ca2c",
        "50c8c0640100504b0304140000000800e4545f5d8cce0e10420000004000000005000000622e62696e63606462666165",
        "63e7e0e4e2e6e1e5e3171014121611151397909492969195935750545256515553d7d0d4d2d6d1d5d337303432363135",
        "33b7b0b4b2b6b1b5b30700504b01021403140000000800e4545f5df5b6d4fe0f0000001d000000090000000000000000",
        "0000008001000000006469722f612e747874504b01021403140000000800e4545f5d8cce0e1042000000400000000500",
        "00000000000000000000800136000000622e62696e504b050600000000020002006a0000009b0000000000",
    ];

    #[test]
    fn stored_and_deflated_entries_come_out_whole() {
        for archive in [unhex(STORED_ARCHIVE), unhex(DEFLATED_ARCHIVE)] {
            let entries = entries(&archive).expect("a valid archive");
            let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.size)).collect();
            assert_eq!(names, [("dir/a.txt", 29), ("b.bin", 64)]);
            let mut text = Vec::new();
            extract(&archive, &entries[0], &mut text).expect("dir/a.txt");
            assert_eq!(text, b"hello zip hello zip hello zip");
            let mut bytes = Vec::new();
            extract(&archive, &entries[1], &mut bytes).expect("b.bin");
            assert_eq!(bytes, (0..64).collect::<Vec<u8>>());
        }
    }

    #[test]
    fn a_stored_archive_reads_back() {
        let archive = stored(&[("ROUTE.TXT", b"PeaZip route\r\n"), ("b.bin", &[0, 1, 2, 255])]);
        let entries = entries(&archive).expect("a valid archive");
        let names: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.size, e.method)).collect();
        assert_eq!(names, [("ROUTE.TXT", 14, STORED), ("b.bin", 4, STORED)]);
        let mut text = Vec::new();
        extract(&archive, &entries[0], &mut text).expect("ROUTE.TXT, its CRC-32 checked");
        assert_eq!(text, b"PeaZip route\r\n");
        let mut bytes = Vec::new();
        extract(&archive, &entries[1], &mut bytes).expect("b.bin");
        assert_eq!(bytes, [0, 1, 2, 255]);
        // The local header of the first entry: its signature, version 2.0,
        // stored, then its date.
        assert_eq!(archive[..10], [0x50, 0x4B, 0x03, 0x04, 20, 0, 0, 0, 0, 0]);
        assert_eq!(u16_at(&archive, 12), Ok((24 << 9) | (8 << 5) | 4), "2004-08-04");
    }

    #[test]
    fn a_damaged_entry_fails_its_check() {
        let mut archive = unhex(STORED_ARCHIVE);
        let entries = entries(&archive).unwrap();
        // A byte of `dir/a.txt`, after its 39-byte local header.
        archive[39] ^= 0x20;
        assert!(extract(&archive, &entries[0], Vec::new()).unwrap_err().contains("CRC-32"));
        assert!(super::entries(&archive[..archive.len() - 30]).is_err(), "no end record");
    }
}
