//! Directory index decoding. Traversal and volume-relative bounds live in namespace.
use crate::{bytes, u16_at, u32_at, u64_at, Error};
use alloc::vec::Vec;

/// A record number and sequence, identifying one incarnation of a FILE record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileReference {
    /// Low 48 bits of the on-disk file reference.
    pub record: u64,
    /// Sequence checked against the referenced FILE before path traversal.
    pub sequence: u16,
}
impl FileReference {
    pub(crate) fn decode(value: u64) -> Self {
        Self { record: value & 0x0000_ffff_ffff_ffff, sequence: (value >> 48) as u16 }
    }
}

/// A directory's indexed name, including DOS aliases as separate entries.
/// UTF-16 is preserved verbatim; listing alone does not dereference the FILE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Target FILE reference; checked when resolving a path.
    pub reference: FileReference,
    /// On-disk UTF-16 name, without lossy conversion.
    pub name: Vec<u16>,
    /// NTFS name namespace: 0 POSIX, 1 Win32, 2 DOS, 3 Win32 and DOS.
    pub namespace: u8,
    /// Directory flag from the indexed FILE_NAME attributes.
    pub is_directory: bool,
}

pub(crate) struct Node {
    pub entries: Vec<DirectoryEntry>,
    pub children: Vec<u64>,
}

pub(crate) fn root(data: &[u8], parent: FileReference) -> Result<(u32, Node), Error> {
    if u32_at(data, 0)? != 0x30 || u32_at(data, 4)? != 1 {
        return Err(Error::Unsupported("directory index collation"));
    }
    let size = u32_at(data, 8)?;
    if !(512..=65536).contains(&size) || !size.is_power_of_two() {
        return Err(Error::Unsupported("index block size"));
    }
    Ok((size, node(data, 16, 16, parent)?))
}

pub(crate) fn block(data: &mut [u8], vcn: u64, parent: FileReference) -> Result<Node, Error> {
    if bytes(data, 0, 4)? != b"INDX" || !(512..=65536).contains(&data.len()) || !data.len().is_multiple_of(512) {
        return Err(Error::Invalid("INDX signature or size"));
    }
    if u64_at(data, 16)? != vcn {
        return Err(Error::Invalid("INDX VCN"));
    }
    let usa = usize::from(u16_at(data, 4)?);
    let count = usize::from(u16_at(data, 6)?);
    let first = u32_at(data, 24)? as usize;
    if usa < 40
        || usa % 2 != 0
        || count != data.len() / 512 + 1
        || usa + count * 2 > 510
        || usa + count * 2 > first.checked_add(24).ok_or(Error::Bounds)?
    {
        return Err(Error::Invalid("INDX update sequence array"));
    }
    let sequence = u16_at(data, usa)?;
    for sector in 1..count {
        if u16_at(data, sector * 512 - 2)? != sequence {
            return Err(Error::Invalid("INDX torn sector"));
        }
    }
    for sector in 1..count {
        let replacement = u16_at(data, usa + sector * 2)?.to_le_bytes();
        data[sector * 512 - 2..sector * 512].copy_from_slice(&replacement);
    }
    if u32_at(data, 32)? as usize != data.len() - 24 {
        return Err(Error::Invalid("INDX allocated size"));
    }
    node(data, 24, usa + count * 2 - 24, parent)
}

fn node(data: &[u8], header: usize, minimum: usize, parent: FileReference) -> Result<Node, Error> {
    let first = u32_at(data, header)? as usize;
    let used = u32_at(data, header + 4)? as usize;
    let allocated = u32_at(data, header + 8)? as usize;
    let flags = *bytes(data, header + 12, 1)?.first().ok_or(Error::Bounds)?;
    if first < minimum || first < 16 || !first.is_multiple_of(8) || used > allocated || first >= used || flags > 1 {
        return Err(Error::Invalid("index node header"));
    }
    bytes(data, header, allocated)?;
    let data = bytes(data, header, used)?;
    let mut at = first;
    let mut result = Node { entries: Vec::new(), children: Vec::new() };
    loop {
        let entry = bytes(data, at, 16)?;
        let len = usize::from(u16_at(entry, 8)?);
        let key_len = usize::from(u16_at(entry, 10)?);
        let entry_flags = u16_at(entry, 12)?;
        let child = entry_flags & 1 != 0;
        let end = entry_flags & 2 != 0;
        let trailer = if child { 8 } else { 0 };
        if len < 16 + trailer
            || len % 8 != 0
            || entry_flags > 3
            || child != (flags == 1)
            || key_len > len - 16 - trailer
        {
            return Err(Error::Invalid("index entry length or flags"));
        }
        let entry = bytes(data, at, len)?;
        if child {
            result.children.push(u64_at(entry, len - 8)?);
        }
        if end {
            if key_len != 0 || at + len != used {
                return Err(Error::Invalid("index end entry"));
            }
            return Ok(result);
        }
        let key = bytes(entry, 16, key_len)?;
        if key_len < 66 || FileReference::decode(u64_at(key, 0)?) != parent {
            return Err(Error::Invalid("indexed parent reference"));
        }
        let name_len = usize::from(key[64]);
        if name_len == 0 || key_len != 66 + name_len * 2 || key[65] > 3 {
            return Err(Error::Invalid("indexed file name"));
        }
        let name = key[66..].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        result.entries.push(DirectoryEntry {
            reference: FileReference::decode(u64_at(entry, 0)?),
            name,
            namespace: key[65],
            is_directory: u32_at(key, 56)? & 0x1000_0000 != 0,
        });
        at += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn p32(b: &mut [u8], at: usize, n: u32) {
        b[at..at + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn leaf() -> Vec<u8> {
        let mut b = vec![0; 144];
        p32(&mut b, 0, 0x30);
        p32(&mut b, 4, 1);
        p32(&mut b, 8, 4096);
        p32(&mut b, 16, 16);
        p32(&mut b, 20, 128);
        p32(&mut b, 24, 128);
        b[32] = 42;
        b[38] = 3;
        b[40] = 96;
        b[42] = 74;
        b[48] = 5;
        b[54] = 7;
        b[112] = 4;
        b[113] = 1;
        for (i, c) in "test".encode_utf16().enumerate() {
            b[114 + i * 2..116 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        b[136] = 16;
        b[140] = 2;
        b
    }
    #[test]
    fn root_names_references_and_truncation() {
        let good = leaf();
        let parent = FileReference { record: 5, sequence: 7 };
        let (_, node) = root(&good, parent).unwrap();
        assert_eq!(node.entries[0].reference, FileReference { record: 42, sequence: 3 });
        assert_eq!(node.entries[0].name, "test".encode_utf16().collect::<Vec<_>>());
        assert!(node.children.is_empty());
        for end in 0..good.len() {
            assert!(root(&good[..end], parent).is_err());
        }
        for offset in [16, 20, 24, 40, 42, 44, 48, 112, 113, 136, 140] {
            let mut bad = good.clone();
            bad[offset] = 255;
            assert!(root(&bad, parent).is_err(), "offset {offset}");
        }
    }
}
