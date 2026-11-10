//! ATTRIBUTE_LIST resolution never recursively follows another list. Only the
//! base record's list is authoritative. Limits apply before allocating/reading.
use crate::stream::Stream;
use crate::{bytes, u16_at, u32_at, u64_at, Error, FileReference, ReadAt, Volume};
use alloc::{collections::BTreeSet, vec, vec::Vec};

const MAX_LIST_SIZE: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_RECORDS: usize = 64;

struct Entry {
    kind: u32,
    name: Vec<u8>,
    lowest: u64,
    reference: FileReference,
    instance: u16,
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

impl<D: ReadAt> Volume<D> {
    pub(crate) fn stream(&mut self, number: u64, kind: u32, name: &[u8]) -> Result<Option<Stream>, Error> {
        let base = self.record(number)?;
        let base_ref = FileReference { record: number, sequence: base.sequence() };
        let attrs = base.attributes()?;
        let mut lists = attrs.iter().filter(|a| a.kind == 0x20);
        let Some(list) = lists.next() else {
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
        if lists.next().is_some() || !list.name.is_empty() {
            return Err(Error::Invalid("multiple or named attribute lists"));
        }
        // The list itself must be wholly described in the base record. This
        // supports a resident list or one complete nonresident mapping.
        let list_stream = Stream::parse(list, self.geometry)?;
        if list_stream.len() > MAX_LIST_SIZE {
            return Err(Error::Unsupported("attribute list size"));
        }
        if !list_stream.fully_initialized() {
            return Err(Error::Invalid("uninitialized attribute list"));
        }
        let mut data = vec![0; list_stream.len() as usize];
        if list_stream.read(&mut self.device, 0, &mut data)? != data.len() {
            return Err(Error::Bounds);
        }
        let mut entries: Vec<_> = parse(&data)?.into_iter().filter(|e| e.kind == kind && e.name == name).collect();
        entries.sort_by_key(|e| e.lowest);
        // Do not silently discard an attribute in the base when the list lies
        // about its membership or identity.
        for attr in attrs.iter().filter(|a| a.kind == kind && a.name == name) {
            let instance = u16_at(attr.data, 14)?;
            let lowest = if attr.nonresident { u64_at(attr.data, 16)? } else { 0 };
            if !entries.iter().any(|e| e.reference == base_ref && e.instance == instance && e.lowest == lowest) {
                return Err(Error::Invalid("base attribute absent from list"));
            }
        }
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
            if FileReference::decode(record.base_reference()) != base_ref || record.base_reference() == 0 {
                return Err(Error::Invalid("extension base reference"));
            }
            // File/directory semantics belong to the base record. An extension
            // only supplies attributes and is authenticated by its base link.
            if record.attributes()?.iter().any(|a| a.kind == 0x20) {
                return Err(Error::Unsupported("nested attribute list"));
            }
            records.push((entry.reference.record, record));
        }
        let mut selected = Vec::new();
        for entry in &entries {
            let record = &records.iter().find(|(n, _)| *n == entry.reference.record).ok_or(Error::NotFound)?.1;
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
                if attr.kind != kind
                    || attr.name != name
                    || (if attr.nonresident { u64_at(attr.data, 16)? } else { 0 }) != entry.lowest
                {
                    return Err(Error::Invalid("attribute list identity"));
                }
                found = Some(attr);
            }
            selected.push(found.ok_or(Error::Invalid("listed attribute missing"))?);
        }
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
