//! The `regf` hive format (ADR-012): the registry's on-disk format, shared by
//! the kernel (Cm) and the host tools (`tools/mkhive`). `no_std`, with
//! `alloc`.
//!
//! Written from the public descriptions of the format. A hive file is a
//! 4 KiB base block, then hive bins (`hbin`), each a multiple of 4 KiB, that
//! hold cells. A cell starts with its size, negative when allocated; cell
//! offsets count from the start of the first bin. The cells:
//!
//! - `nk`, a key: its name, its parent, its subkey list and its value list;
//! - `lf`, `lh`, `li`, `ri`, subkey lists: leaves of keys sorted by upcased
//!   name, or an index of leaves;
//! - the value list, an array of offsets of `vk` cells;
//! - `vk`, a value: its name, its type and its data, inline up to 4 bytes,
//!   else in a data cell, or in segments listed by a `db` cell (big data);
//! - `sk`, a security descriptor, shared by keys (not read here).
//!
//! [`Hive`] reads a hive in memory, without copying it; [`builder`] writes
//! one from a tree of keys (feature `builder`).

#![no_std]
extern crate alloc;

#[cfg(feature = "builder")]
pub mod builder;

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

/// The base block.
pub const BASE_BLOCK_SIZE: usize = 0x1000;
/// The size of an `hbin` header.
pub const HBIN_HEADER_SIZE: usize = 0x20;
/// No cell (an empty list, no class, no security).
pub const NO_CELL: u32 = 0xFFFF_FFFF;
/// The most data a single cell holds before a hive of version 1.4 or later
/// splits it into segments (`db`).
pub const BIG_DATA_SEGMENT: usize = 16344;

/// Key flags (`nk`).
pub const KEY_VOLATILE: u16 = 0x0001;
/// A mount point of another hive.
pub const KEY_HIVE_EXIT: u16 = 0x0002;
/// The root key of the hive.
pub const KEY_HIVE_ENTRY: u16 = 0x0004;
pub const KEY_NO_DELETE: u16 = 0x0008;
/// A symbolic link, whose `SymbolicLinkValue` names its target.
pub const KEY_SYM_LINK: u16 = 0x0010;
/// The name is stored in Latin-1, one byte per character.
pub const KEY_COMP_NAME: u16 = 0x0020;
/// Value flags (`vk`): the name is stored in Latin-1.
pub const VALUE_COMP_NAME: u16 = 0x0001;
/// In a `vk` data size: the data is in the data offset field itself.
const DATA_INLINE: u32 = 0x8000_0000;

/// What makes a hive unreadable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The file or a cell ends before its fields.
    Truncated,
    /// A structure does not carry its signature.
    BadSignature(&'static str),
    /// The base block's checksum does not match.
    BadChecksum,
    /// A cell offset that leads nowhere valid: past the bins, or to a free
    /// or misaligned cell.
    BadCell(u32),
    /// A valid structure that this reader does not handle.
    Unsupported(&'static str),
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, Error> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or(Error::Truncated)
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, Error> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or(Error::Truncated)
}

fn u64_at(data: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from(u32_at(data, at)?) | u64::from(u32_at(data, at + 4)?) << 32)
}

/// The checksum of a base block: the XOR of its first 127 words, with 0 and
/// `0xFFFFFFFF` replaced so that a checksum is never either.
pub fn checksum(base_block: &[u8]) -> u32 {
    let sum = base_block[..508].chunks_exact(4).fold(0u32, |sum, w| sum ^ u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
    match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        sum => sum,
    }
}

/// A UTF-16 unit in upper case, as the registry compares names: Latin-1
/// letters and the other characters with a single-unit upper case in the
/// Basic Multilingual Plane.
pub fn upcase(unit: u16) -> u16 {
    match unit {
        0x61..=0x7A => unit - 0x20,
        0x00..=0x7F => unit,
        _ => char::from_u32(u32::from(unit))
            .and_then(|c| {
                let mut upper = c.to_uppercase();
                match (upper.next(), upper.next()) {
                    (Some(u), None) if (u as u32) <= 0xFFFF => Some(u as u32 as u16),
                    _ => None,
                }
            })
            .unwrap_or(unit),
    }
}

/// A key or value name, as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name<'a> {
    /// One byte per character, Latin-1.
    Latin1(&'a [u8]),
    /// UTF-16, little-endian.
    Utf16(&'a [u8]),
}

impl Name<'_> {
    /// Its UTF-16 units.
    pub fn units(&self) -> impl Iterator<Item = u16> + '_ {
        let (latin1, utf16): (&[u8], &[u8]) = match *self {
            Name::Latin1(bytes) => (bytes, &[]),
            Name::Utf16(bytes) => (&[], bytes),
        };
        latin1.iter().map(|&b| u16::from(b)).chain(utf16.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
    }

    /// Its length in UTF-16 units.
    pub fn len(&self) -> usize {
        match *self {
            Name::Latin1(bytes) => bytes.len(),
            Name::Utf16(bytes) => bytes.len() / 2,
        }
    }

    /// Whether it is empty (the default value's name).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether it equals `other`, without case.
    pub fn eq_ignore_case(&self, other: impl IntoIterator<Item = u16>) -> bool {
        let mut other = other.into_iter();
        for unit in self.units() {
            match other.next() {
                Some(o) if upcase(o) == upcase(unit) => {}
                _ => return false,
            }
        }
        other.next().is_none()
    }

    /// It as a string (unpaired surrogates replaced).
    pub fn to_string_lossy(&self) -> String {
        char::decode_utf16(self.units()).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
    }
}

/// A hive in memory.
#[derive(Clone, Copy, Debug)]
pub struct Hive<'a> {
    /// The hive bins: cell offsets count from their start.
    bins: &'a [u8],
    root: u32,
    minor: u32,
}

impl<'a> Hive<'a> {
    /// The hive in `file`: its base block checked (signature, version 1,
    /// checksum), its bins taken as the base block gives their size.
    pub fn parse(file: &'a [u8]) -> Result<Self, Error> {
        let base = file.get(..BASE_BLOCK_SIZE).ok_or(Error::Truncated)?;
        if &base[..4] != b"regf" {
            return Err(Error::BadSignature("regf"));
        }
        if u32_at(base, 508)? != checksum(base) {
            return Err(Error::BadChecksum);
        }
        if u32_at(base, 20)? != 1 {
            return Err(Error::Unsupported("major version other than 1"));
        }
        let minor = u32_at(base, 24)?;
        let size = u32_at(base, 40)? as usize;
        let bins = file.get(BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + size).ok_or(Error::Truncated)?;
        if bins.get(..4) != Some(b"hbin") {
            return Err(Error::BadSignature("hbin"));
        }
        Ok(Self { bins, root: u32_at(base, 36)?, minor })
    }

    /// Its minor version (3 for XP's hives, 5 from XP SP2's tools on).
    pub fn minor_version(&self) -> u32 {
        self.minor
    }

    /// Its root key.
    pub fn root(&self) -> Result<Key<'a>, Error> {
        Key::at(*self, self.root)
    }

    /// The key at cell `offset`: a cell that holds a key node.
    pub fn key_at(&self, offset: u32) -> Result<Key<'a>, Error> {
        Key::at(*self, offset)
    }

    /// The payload of the allocated cell at `offset`, without its size.
    fn cell(&self, offset: u32) -> Result<&'a [u8], Error> {
        let at = offset as usize;
        if !offset.is_multiple_of(8) || at < HBIN_HEADER_SIZE {
            return Err(Error::BadCell(offset));
        }
        let size = u32_at(self.bins, at).map_err(|_| Error::BadCell(offset))? as i32;
        // Allocated cells have a negative size, header included.
        let length = size.checked_neg().filter(|&l| l >= 8).ok_or(Error::BadCell(offset))? as usize;
        self.bins.get(at + 4..at + length).ok_or(Error::BadCell(offset))
    }
}

/// A key of a hive.
#[derive(Clone, Copy, Debug)]
pub struct Key<'a> {
    hive: Hive<'a>,
    offset: u32,
    nk: &'a [u8],
}

impl<'a> Key<'a> {
    fn at(hive: Hive<'a>, offset: u32) -> Result<Self, Error> {
        let nk = hive.cell(offset)?;
        if nk.get(..2) != Some(b"nk") {
            return Err(Error::BadSignature("nk"));
        }
        let length = usize::from(u16_at(nk, 72)?);
        if nk.len() < 76 + length {
            return Err(Error::Truncated);
        }
        Ok(Self { hive, offset, nk })
    }

    /// Its cell offset.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Its flags (`KEY_*`).
    pub fn flags(&self) -> u16 {
        u16_at(self.nk, 2).unwrap_or(0)
    }

    /// When it was last written, as a FILETIME.
    pub fn last_written(&self) -> u64 {
        u64_at(self.nk, 4).unwrap_or(0)
    }

    /// Its name.
    pub fn name(&self) -> Name<'a> {
        let length = usize::from(u16_at(self.nk, 72).unwrap_or(0));
        let bytes = &self.nk[76..76 + length];
        if self.flags() & KEY_COMP_NAME != 0 {
            Name::Latin1(bytes)
        } else {
            Name::Utf16(bytes)
        }
    }

    /// Its class name, if any.
    pub fn class(&self) -> Result<Option<Name<'a>>, Error> {
        let offset = u32_at(self.nk, 48)?;
        let length = usize::from(u16_at(self.nk, 74)?);
        if offset == NO_CELL || length == 0 {
            return Ok(None);
        }
        let cell = self.hive.cell(offset)?;
        Ok(Some(Name::Utf16(cell.get(..length).ok_or(Error::Truncated)?)))
    }

    /// Its parent's cell offset.
    pub fn parent_offset(&self) -> u32 {
        u32_at(self.nk, 16).unwrap_or(NO_CELL)
    }

    /// How many subkeys it has (stable ones; volatile keys live in memory).
    pub fn subkey_count(&self) -> u32 {
        u32_at(self.nk, 20).unwrap_or(0)
    }

    /// How many values it has.
    pub fn value_count(&self) -> u32 {
        u32_at(self.nk, 36).unwrap_or(0)
    }

    /// The longest subkey name, class name and value name, in bytes of
    /// UTF-16, and the largest value data, as the hive records them.
    pub fn maxima(&self) -> (u32, u32, u32, u32) {
        let at = |o| u32_at(self.nk, o).unwrap_or(0);
        (at(52), at(56), at(60), at(64))
    }

    /// Its subkeys, in the order of their list (by upcased name).
    pub fn subkeys(&self) -> Result<Vec<Key<'a>>, Error> {
        let mut keys = Vec::new();
        if self.subkey_count() != 0 {
            self.collect_list(u32_at(self.nk, 28)?, &mut keys, 0)?;
        }
        Ok(keys)
    }

    /// The keys of the subkey list at `offset`, appended to `keys`.
    fn collect_list(&self, offset: u32, keys: &mut Vec<Key<'a>>, depth: u32) -> Result<(), Error> {
        if depth > 2 {
            return Err(Error::Unsupported("nested root indexes"));
        }
        let list = self.hive.cell(offset)?;
        let count = usize::from(u16_at(list, 2)?);
        let (stride, index) = match list.get(..2) {
            Some(b"lf" | b"lh") => (8, false),
            Some(b"li") => (4, false),
            Some(b"ri") => (4, true),
            _ => return Err(Error::BadSignature("subkey list")),
        };
        for i in 0..count {
            let entry = u32_at(list, 4 + stride * i)?;
            if index {
                self.collect_list(entry, keys, depth + 1)?;
            } else {
                keys.push(Key::at(self.hive, entry)?);
            }
        }
        Ok(())
    }

    /// Its subkey named `name` (UTF-16 units), without case.
    pub fn subkey_units(&self, name: &[u16]) -> Result<Option<Key<'a>>, Error> {
        Ok(self.subkeys()?.into_iter().find(|key| key.name().eq_ignore_case(name.iter().copied())))
    }

    /// Its subkey named `name`, without case.
    pub fn subkey(&self, name: &str) -> Result<Option<Key<'a>>, Error> {
        let units: Vec<u16> = name.encode_utf16().collect();
        self.subkey_units(&units)
    }

    /// The key at `path` below it, its components separated by `\`, without
    /// case; empty components are skipped.
    pub fn open(&self, path: &str) -> Result<Option<Key<'a>>, Error> {
        let mut key = *self;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            match key.subkey(part)? {
                Some(next) => key = next,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }

    /// Its values, in the order of its value list.
    pub fn values(&self) -> Result<Vec<Value<'a>>, Error> {
        let count = self.value_count() as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let list = self.hive.cell(u32_at(self.nk, 40)?)?;
        (0..count).map(|i| Value::at(self.hive, u32_at(list, 4 * i)?)).collect()
    }

    /// Its value named `name` (UTF-16 units; empty for the default value),
    /// without case.
    pub fn value_units(&self, name: &[u16]) -> Result<Option<Value<'a>>, Error> {
        Ok(self.values()?.into_iter().find(|value| value.name().eq_ignore_case(name.iter().copied())))
    }

    /// Its value named `name` (empty for the default value), without case.
    pub fn value(&self, name: &str) -> Result<Option<Value<'a>>, Error> {
        let units: Vec<u16> = name.encode_utf16().collect();
        self.value_units(&units)
    }
}

/// A value of a key.
#[derive(Clone, Copy, Debug)]
pub struct Value<'a> {
    hive: Hive<'a>,
    vk: &'a [u8],
}

impl<'a> Value<'a> {
    fn at(hive: Hive<'a>, offset: u32) -> Result<Self, Error> {
        let vk = hive.cell(offset)?;
        if vk.get(..2) != Some(b"vk") {
            return Err(Error::BadSignature("vk"));
        }
        if vk.len() < 20 + usize::from(u16_at(vk, 2)?) {
            return Err(Error::Truncated);
        }
        Ok(Self { hive, vk })
    }

    /// Its name; empty for the default value.
    pub fn name(&self) -> Name<'a> {
        let length = usize::from(u16_at(self.vk, 2).unwrap_or(0));
        let bytes = &self.vk[20..20 + length];
        if u16_at(self.vk, 16).unwrap_or(0) & VALUE_COMP_NAME != 0 {
            Name::Latin1(bytes)
        } else {
            Name::Utf16(bytes)
        }
    }

    /// Its type (`REG_*`).
    pub fn data_type(&self) -> u32 {
        u32_at(self.vk, 12).unwrap_or(0)
    }

    /// The size of its data.
    pub fn data_size(&self) -> u32 {
        u32_at(self.vk, 4).unwrap_or(0) & !DATA_INLINE
    }

    /// Its data: borrowed from the hive, or gathered from its segments.
    pub fn data(&self) -> Result<Cow<'a, [u8]>, Error> {
        let raw = u32_at(self.vk, 4)?;
        let size = (raw & !DATA_INLINE) as usize;
        if raw & DATA_INLINE != 0 {
            // At most 4 bytes, in the data offset field.
            return self.vk.get(8..8 + size.min(4)).map(Cow::Borrowed).ok_or(Error::Truncated);
        }
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let cell = self.hive.cell(u32_at(self.vk, 8)?)?;
        if size > BIG_DATA_SEGMENT && self.hive.minor >= 4 && cell.get(..2) == Some(b"db") {
            return self.big_data(cell, size).map(Cow::Owned);
        }
        cell.get(..size).map(Cow::Borrowed).ok_or(Error::Truncated)
    }

    /// Data split into segments (`db`).
    fn big_data(&self, db: &[u8], size: usize) -> Result<Vec<u8>, Error> {
        let count = usize::from(u16_at(db, 2)?);
        let list = self.hive.cell(u32_at(db, 4)?)?;
        let mut data = Vec::with_capacity(size);
        for i in 0..count {
            let segment = self.hive.cell(u32_at(list, 4 * i)?)?;
            let take = (size - data.len()).min(BIG_DATA_SEGMENT).min(segment.len());
            data.extend_from_slice(&segment[..take]);
        }
        if data.len() != size {
            return Err(Error::Truncated);
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::builder::{build, KeyNode};
    use super::*;
    use alloc::vec;

    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;
    const REG_BINARY: u32 = 3;

    fn sz(text: &str) -> Vec<u8> {
        text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    fn sample() -> Vec<u8> {
        let mut root = KeyNode::new("ROOT");
        let session = root.key_mut("ControlSet001\\Control\\Session Manager");
        session.set_value("GlobalFlag", REG_DWORD, vec![0x10, 0, 0, 0]);
        session.set_value("", REG_SZ, sz("default"));
        session.set_value("Sm", REG_BINARY, vec![1, 2, 3]);
        session.key_mut("Environment").set_value("Path", REG_SZ, sz("C:\\WINDOWS\\system32"));
        root.key_mut("Select").set_value("Current", REG_DWORD, vec![1, 0, 0, 0]);
        root.key_mut("Ünïcödé\\Ωμέγα").set_value("Ключ", REG_SZ, sz("значение"));
        build(&root, "\\SystemRoot\\System32\\Config\\SYSTEM")
    }

    #[test]
    fn a_built_hive_reads_back() {
        let file = sample();
        let hive = Hive::parse(&file).expect("a hive");
        assert_eq!(hive.minor_version(), 3);
        let root = hive.root().unwrap();
        assert_eq!(root.name().to_string_lossy(), "ROOT");
        assert_ne!(root.flags() & KEY_HIVE_ENTRY, 0);
        let names: Vec<_> = root.subkeys().unwrap().iter().map(|k| k.name().to_string_lossy()).collect();
        assert_eq!(names, ["ControlSet001", "Select", "Ünïcödé"], "sorted by upcased name");
        let session = root.open("controlset001\\CONTROL\\session manager").unwrap().expect("without case");
        assert_eq!((session.subkey_count(), session.value_count()), (1, 3));
        let flag = session.value("globalflag").unwrap().expect("GlobalFlag");
        assert_eq!((flag.data_type(), &*flag.data().unwrap()), (REG_DWORD, &[0x10u8, 0, 0, 0][..]));
        let small = session.value("SM").unwrap().expect("Sm");
        assert_eq!((small.data_size(), &*small.data().unwrap()), (3, &[1u8, 2, 3][..]), "inline, 3 bytes");
        assert_eq!(&*session.value("").unwrap().expect("default").data().unwrap(), &sz("default")[..]);
        let path = session.open("Environment").unwrap().unwrap().value("PATH").unwrap().unwrap();
        assert_eq!(&*path.data().unwrap(), &sz("C:\\WINDOWS\\system32")[..], "in a data cell");
        assert_eq!(session.parent_offset(), root.open("ControlSet001\\Control").unwrap().unwrap().offset());
        assert!(root.open("ControlSet001\\Missing").unwrap().is_none());
        // (largest subkey name, class, value name, value data), in bytes.
        assert_eq!(session.maxima(), (22, 0, 20, 16));
    }

    #[test]
    fn names_outside_latin1_are_utf16_and_match_without_case() {
        let file = sample();
        let root = Hive::parse(&file).unwrap().root().unwrap();
        let latin1 = root.subkey("ÜNÏCÖDÉ").unwrap().expect("Latin-1 upper case");
        assert!(matches!(latin1.name(), Name::Latin1(_)));
        let greek = latin1.subkey("ΩΜΈΓΑ").unwrap().expect("Greek upper case");
        assert!(matches!(greek.name(), Name::Utf16(_)));
        let value = greek.value("ключ").unwrap().expect("Cyrillic lower case");
        assert_eq!(&*value.data().unwrap(), &sz("значение")[..]);
        let units: Vec<u16> = "ωμέγα".encode_utf16().collect();
        assert!(latin1.subkey_units(&units).unwrap().is_some());
    }

    #[test]
    fn many_subkeys_and_large_data() {
        let mut root = KeyNode::new("R");
        for i in (0..300).rev() {
            root.key_mut(&alloc::format!("Key{i:03}"));
        }
        let big: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        root.set_value("Big", REG_BINARY, big.clone());
        let file = build(&root, "R");
        let root = Hive::parse(&file).unwrap().root().unwrap();
        let keys = root.subkeys().unwrap();
        assert_eq!(keys.len(), 300);
        assert_eq!(keys[0].name().to_string_lossy(), "Key000");
        assert_eq!(keys[299].name().to_string_lossy(), "Key299");
        assert!(root.subkey("key150").unwrap().is_some());
        assert_eq!(&*root.value("big").unwrap().unwrap().data().unwrap(), &big[..]);
    }

    #[test]
    fn damage_is_an_error_not_a_panic() {
        let file = sample();
        let mut bad = file.clone();
        bad[100] ^= 1;
        assert_eq!(Hive::parse(&bad).err(), Some(Error::BadChecksum));
        assert_eq!(Hive::parse(&file[..0x800]).err(), Some(Error::Truncated));
        assert_eq!(Hive::parse(&file[..0x1100]).err(), Some(Error::Truncated), "bins cut short");
        let mut unsigned = file.clone();
        unsigned[0] = b'R';
        assert_eq!(Hive::parse(&unsigned).err(), Some(Error::BadSignature("regf")));
        // A root offset that leads nowhere, with the checksum fixed.
        let mut lost = file.clone();
        lost[36..40].copy_from_slice(&0x7FFF_0008u32.to_le_bytes());
        let sum = checksum(&lost);
        lost[508..512].copy_from_slice(&sum.to_le_bytes());
        assert_eq!(Hive::parse(&lost).unwrap().root().err(), Some(Error::BadCell(0x7FFF_0008)));
        // Every byte of the bins flipped in turn: walking the tree never
        // panics.
        for at in BASE_BLOCK_SIZE..file.len().min(BASE_BLOCK_SIZE + 0x600) {
            let mut flipped = file.clone();
            flipped[at] ^= 0xFF;
            if let Ok(hive) = Hive::parse(&flipped) {
                let _ = walk(hive.root());
            }
        }
    }

    /// Reads every key and value below `key`.
    fn walk(key: Result<Key<'_>, Error>) -> Result<(), Error> {
        let key = key?;
        let _ = key.name().to_string_lossy();
        let _ = key.class();
        for value in key.values()? {
            let _ = value.name().to_string_lossy();
            let _ = value.data()?;
        }
        for subkey in key.subkeys()? {
            walk(Ok(subkey))?;
        }
        Ok(())
    }

    #[test]
    fn upcase_follows_the_registry() {
        assert_eq!(upcase(u16::from(b'a')), u16::from(b'A'));
        assert_eq!(upcase(u16::from(b'_')), u16::from(b'_'));
        assert_eq!(upcase(0xE9), 0xC9, "é");
        assert_eq!(upcase(0x3C9), 0x3A9, "ω");
        assert_eq!(upcase(0xDF), 0xDF, "ß has no single-unit upper case");
    }
}
