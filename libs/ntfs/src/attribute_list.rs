//! ATTRIBUTE_LIST resolution never recursively follows another list. Only the
//! base record's list is authoritative. Limits apply before allocating/reading.
use crate::record::Attribute;
use crate::stream::Stream;
use crate::{bytes, u16_at, u32_at, u64_at, Error, FileReference, Geometry, ReadAt, Record, Volume};
use alloc::{collections::BTreeSet, vec, vec::Vec};

const MAX_LIST_SIZE: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
pub(crate) const MAX_RECORDS: usize = 64;

pub(crate) struct Entry {
    pub(crate) kind: u32,
    pub(crate) name: Vec<u8>,
    pub(crate) lowest: u64,
    pub(crate) reference: FileReference,
    pub(crate) instance: u16,
}

fn parse(data: &[u8]) -> Result<Vec<Entry>, Error> {
    if data.is_empty() {
        return Err(Error::Invalid("empty attribute list"));
    }
    if data.len() as u64 > MAX_LIST_SIZE {
        return Err(Error::Unsupported("attribute list size"));
    }
    let mut at = 0;
    let mut entries = Vec::new();
    let mut instances = BTreeSet::new();
    while at < data.len() {
        let header = bytes(data, at, 26)?;
        let kind = u32_at(header, 0)?;
        if kind == 0xc0 {
            return Err(Error::Unsupported("reparse point"));
        }
        let length = usize::from(u16_at(header, 4)?);
        if kind == 0 || kind == u32::MAX || length < 32 || length % 8 != 0 {
            return Err(Error::Invalid("attribute list entry"));
        }
        let raw = bytes(data, at, length)?;
        let name_length = usize::from(raw[6]) * 2;
        let name_offset = usize::from(raw[7]);
        if name_length != 0 && (name_offset < 26 || name_offset % 2 != 0) {
            return Err(Error::Invalid("attribute list name"));
        }
        let name = if name_length == 0 { Vec::new() } else { bytes(raw, name_offset, name_length)?.to_vec() };
        let reference = FileReference::decode(u64_at(raw, 16)?);
        let instance = u16_at(raw, 24)?;
        if !instances.insert((reference.record, instance)) {
            return Err(Error::Invalid("duplicate attribute list reference"));
        }
        if entries.len() == MAX_ENTRIES {
            return Err(Error::Unsupported("attribute list entry limit"));
        }
        entries.push(Entry { kind, name, lowest: u64_at(raw, 8)?, reference, instance });
        at += length;
    }
    Ok(entries)
}

/// Read the complete list using mappings present in the base record only.
pub(crate) fn read_list(
    device: &mut impl ReadAt,
    attrs: &[Attribute<'_>],
    geometry: Geometry,
) -> Result<Option<Vec<Entry>>, Error> {
    let mut lists = attrs.iter().filter(|a| a.kind == 0x20);
    let Some(list) = lists.next() else { return Ok(None) };
    if lists.next().is_some() || !list.name.is_empty() {
        return Err(Error::Invalid("multiple or named attribute lists"));
    }
    let stream = Stream::parse(list, geometry)?;
    if stream.len() > MAX_LIST_SIZE {
        return Err(Error::Unsupported("attribute list size"));
    }
    if !stream.fully_initialized() {
        return Err(Error::Invalid("uninitialized attribute list"));
    }
    let mut data = vec![0; stream.len() as usize];
    if stream.read(device, 0, &mut data)? != data.len() {
        return Err(Error::Bounds);
    }
    parse(&data).map(Some)
}

pub(crate) fn select(
    entries: Vec<Entry>,
    attrs: &[Attribute<'_>],
    base: FileReference,
    kind: u32,
    name: &[u8],
) -> Result<Vec<Entry>, Error> {
    let mut entries: Vec<_> = entries.into_iter().filter(|e| e.kind == kind && e.name == name).collect();
    entries.sort_by_key(|e| e.lowest);
    for attr in attrs.iter().filter(|a| a.kind == kind && a.name == name) {
        let instance = u16_at(attr.data, 14)?;
        let lowest = if attr.nonresident { u64_at(attr.data, 16)? } else { 0 };
        if !entries.iter().any(|e| e.reference == base && e.instance == instance && e.lowest == lowest) {
            return Err(Error::Invalid("base attribute absent from list"));
        }
    }
    Ok(entries)
}

pub(crate) fn validate_extension(record: &Record, base: FileReference) -> Result<(), Error> {
    if FileReference::decode(record.base_reference()) != base || record.base_reference() == 0 {
        return Err(Error::Invalid("extension base reference"));
    }
    // File/directory semantics belong to the base, not the extension's flags.
    if record.attributes()?.iter().any(|a| a.kind == 0x20) {
        return Err(Error::Unsupported("nested attribute list"));
    }
    Ok(())
}

pub(crate) fn attribute<'a>(record: &'a Record, entry: &Entry) -> Result<Attribute<'a>, Error> {
    if record.sequence() != entry.reference.sequence {
        return Err(Error::Invalid("stale attribute list reference"));
    }
    let mut found = None;
    for attr in record.attributes()? {
        if u16_at(attr.data, 14)? != entry.instance {
            continue;
        }
        if found.is_some() {
            return Err(Error::Invalid("duplicate attribute instance"));
        }
        if attr.kind != entry.kind
            || attr.name != entry.name
            || (if attr.nonresident { u64_at(attr.data, 16)? } else { 0 }) != entry.lowest
        {
            return Err(Error::Invalid("attribute list identity"));
        }
        found = Some(attr);
    }
    found.ok_or(Error::Invalid("listed attribute missing"))
}

impl<D: ReadAt> Volume<D> {
    pub(crate) fn stream(&mut self, number: u64, kind: u32, name: &[u8]) -> Result<Option<Stream>, Error> {
        let base = self.record(number)?;
        let base_ref = FileReference { record: number, sequence: base.sequence() };
        let attrs = base.attributes()?;
        let Some(entries) = read_list(&mut self.device, &attrs, self.geometry)? else {
            let mut selected = attrs.iter().filter(|a| a.kind == kind && a.name == name);
            let first = selected.next();
            if selected.next().is_some() {
                return Err(Error::Unsupported(if kind == 0x80 {
                    "multiple DATA extents"
                } else {
                    "multiple index extents"
                }));
            }
            return first.map(|a| Stream::parse(a, self.geometry)).transpose();
        };
        let entries = select(entries, &attrs, base_ref, kind, name)?;
        if entries.is_empty() {
            return Ok(None);
        }
        let mut records = vec![(number, base)];
        for entry in &entries {
            if records.iter().any(|(n, _)| *n == entry.reference.record) {
                continue;
            }
            if records.len() == MAX_RECORDS {
                return Err(Error::Unsupported("attribute extension record limit"));
            }
            let record = self.raw_record(entry.reference.record)?;
            validate_extension(&record, base_ref)?;
            records.push((entry.reference.record, record));
        }
        let selected: Vec<_> = entries
            .iter()
            .map(|entry| {
                let record = &records.iter().find(|(n, _)| *n == entry.reference.record).ok_or(Error::NotFound)?.1;
                attribute(record, entry)
            })
            .collect::<Result<_, _>>()?;
        Stream::assemble(&selected.iter().collect::<Vec<_>>(), self.geometry).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{p16, p32};

    #[test]
    fn list_size_and_entry_count_are_bounded() {
        assert!(matches!(parse(&vec![0; MAX_LIST_SIZE as usize + 1]), Err(Error::Unsupported("attribute list size"))));
        let mut data = vec![0; (MAX_ENTRIES + 1) * 32];
        for (id, entry) in data.chunks_exact_mut(32).enumerate() {
            p32(entry, 0, 0x80);
            p16(entry, 4, 32);
            p16(entry, 24, id as u16);
        }
        assert_eq!(parse(&data[..MAX_ENTRIES * 32]).unwrap().len(), MAX_ENTRIES);
        assert!(matches!(parse(&data), Err(Error::Unsupported("attribute list entry limit"))));
    }

    #[test]
    fn list_names_and_truncated_entries_are_bounded() {
        let mut data = vec![0; 40];
        p32(&mut data, 0, 0x90);
        p16(&mut data, 4, 40);
        data[6] = 4;
        data[7] = 26;
        data[26..34].copy_from_slice(b"$\0I\x003\x000\0");
        assert_eq!(parse(&data).unwrap()[0].name, b"$\0I\x003\x000\0");
        for end in 0..data.len() {
            assert!(parse(&data[..end]).is_err(), "truncation at {end}");
        }
        for offset in [0, 24, 27, 34, 255] {
            data[7] = offset;
            assert!(parse(&data).is_err(), "name offset {offset}");
        }
    }
}
