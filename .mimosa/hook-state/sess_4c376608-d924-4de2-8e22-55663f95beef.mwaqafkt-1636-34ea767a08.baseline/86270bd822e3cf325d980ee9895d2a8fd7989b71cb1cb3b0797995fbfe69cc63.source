use crate::{bytes, u16_at, u32_at, u64_at, Error};
use alloc::vec::Vec;

/// A FILE record whose update sequence and attribute boundaries were checked.
/// Only base records in use are supported; attribute lists are refused.
#[derive(Debug)]
pub struct Record {
    data: Vec<u8>,
    first: usize,
    used: usize,
}

impl Record {
    pub(crate) fn parse(mut data: Vec<u8>) -> Result<Self, Error> {
        if bytes(&data, 0, 4)? != b"FILE" {
            return Err(Error::Invalid("FILE signature"));
        }
        if !(512..=65536).contains(&data.len()) || !data.len().is_multiple_of(512) {
            return Err(Error::Invalid("FILE size"));
        }
        let usa = usize::from(u16_at(&data, 4)?);
        let count = usize::from(u16_at(&data, 6)?);
        let first = usize::from(u16_at(&data, 20)?);
        let used = u32_at(&data, 24)? as usize;
        let allocated = u32_at(&data, 28)? as usize;
        if usa < 48
            || usa % 2 != 0
            || count != data.len() / 512 + 1
            || usa + count * 2 > first
            || usa + count * 2 > 510
            || first % 8 != 0
            || first < 48
            || first >= used
            || used > data.len()
            || allocated != data.len()
        {
            return Err(Error::Invalid("FILE header"));
        }
        let flags = u16_at(&data, 22)?;
        if flags & 1 == 0 {
            return Err(Error::NotFound);
        }
        if flags & !3 != 0 {
            return Err(Error::Unsupported("FILE flags"));
        }
        if u64_at(&data, 32)? != 0 {
            return Err(Error::Unsupported("extension FILE record"));
        }
        let sequence = u16_at(&data, usa)?;
        // Check every sector before replacing its trailer. No torn record is used.
        for sector in 1..count {
            if u16_at(&data, sector * 512 - 2)? != sequence {
                return Err(Error::Invalid("update sequence mismatch"));
            }
        }
        for sector in 1..count {
            let replacement = u16_at(&data, usa + sector * 2)?.to_le_bytes();
            data[sector * 512 - 2..sector * 512].copy_from_slice(&replacement);
        }
        let record = Self { data, first, used };
        record.attributes()?;
        Ok(record)
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.data
    }

    /// FILE sequence number, used to reject stale file references.
    pub fn sequence(&self) -> u16 {
        u16::from_le_bytes([self.data[16], self.data[17]])
    }
    /// Whether this record describes a directory.
    pub fn is_directory(&self) -> bool {
        self.data[22] & 2 != 0
    }

    pub(crate) fn attributes(&self) -> Result<Vec<Attribute<'_>>, Error> {
        let mut at = self.first;
        let mut result = Vec::new();
        loop {
            let kind = u32_at(&self.data[..self.used], at)?;
            if kind == u32::MAX {
                return Ok(result);
            }
            let size = u32_at(&self.data[..self.used], at + 4)? as usize;
            if size < 24 || !size.is_multiple_of(8) {
                return Err(Error::Invalid("attribute length"));
            }
            let data = bytes(&self.data[..self.used], at, size)?;
            let nonresident = match data[8] {
                0 => false,
                1 => true,
                _ => return Err(Error::Invalid("attribute form")),
            };
            let header = if nonresident { 64 } else { 24 };
            if size < header {
                return Err(Error::Invalid("attribute header"));
            }
            let name_len = usize::from(data[9]) * 2;
            let name_offset = usize::from(u16_at(data, 10)?);
            if name_len != 0 && name_offset < header {
                return Err(Error::Invalid("attribute name"));
            }
            let name = if name_len == 0 { &[][..] } else { bytes(data, name_offset, name_len)? };
            let payload_offset = usize::from(u16_at(data, if nonresident { 32 } else { 20 })?);
            if payload_offset < header
                || payload_offset > size
                || (name_len != 0 && name_offset + name_len > payload_offset)
            {
                return Err(Error::Invalid("attribute payload"));
            }
            if !nonresident {
                bytes(data, payload_offset, u32_at(data, 16)? as usize)?;
            }
            if kind == 0xc0 {
                return Err(Error::Unsupported("reparse point"));
            }
            if kind == 0x20 {
                return Err(Error::Unsupported("attribute list"));
            }
            result.push(Attribute { kind, data, name, nonresident, payload_offset });
            // size is nonzero, and bytes() checked at + size against used.
            at += size;
        }
    }
}

pub(crate) struct Attribute<'a> {
    pub kind: u32,
    pub data: &'a [u8],
    pub name: &'a [u8],
    pub nonresident: bool,
    pub payload_offset: usize,
}
