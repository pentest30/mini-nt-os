//! Resolve $MFT's own DATA extensions using only mappings already discovered.
//! Never guess a record's physical address or recurse through attribute lists.
use crate::attribute_list::{attribute, read_list, select, validate_extension, MAX_RECORDS};
use crate::stream::Stream;
use crate::{Error, FileReference, Geometry, ReadAt, Record};
use alloc::{vec, vec::Vec};

pub(crate) fn bootstrap(device: &mut impl ReadAt, base: &Record, g: Geometry) -> Result<Stream, Error> {
    let attrs = base.attributes()?;
    let Some(entries) = read_list(device, &attrs, g)? else {
        let mut data = attrs.iter().filter(|a| a.kind == 0x80 && a.name.is_empty());
        let first = data.next().ok_or(Error::NotFound)?;
        if data.next().is_some() {
            return Err(Error::Unsupported("multiple DATA extents"));
        }
        return Stream::parse(first, g);
    };
    let base_ref = FileReference { record: 0, sequence: base.sequence() };
    let entries = select(entries, &attrs, base_ref, 0x80, &[])?;
    if !entries.first().is_some_and(|e| e.reference == base_ref && e.lowest == 0) {
        return Err(Error::Invalid("MFT first extent missing from base"));
    }
    let mut records: Vec<(u64, Record)> = Vec::new();
    loop {
        // Entries are sorted by VCN, but records may become accessible in any
        // order. Known mappings can have holes until all dependencies resolve.
        let mut known = Vec::new();
        for entry in &entries {
            let record = if entry.reference.record == 0 {
                Some(base)
            } else {
                records.iter().find(|(n, _)| *n == entry.reference.record).map(|(_, r)| r)
            };
            if let Some(record) = record {
                known.push(attribute(record, entry)?);
            }
        }
        let refs: Vec<_> = known.iter().collect();
        let mapping = Stream::assemble_partial(&refs, g)?;
        if matches!(mapping, Stream::Resident(_))
            || !mapping.fully_initialized()
            || mapping.len() < u64::from(g.record_size)
            || mapping.len() % u64::from(g.record_size) != 0
        {
            return Err(Error::Invalid("MFT stream"));
        }
        if known.len() == entries.len() {
            // Publish only a complete, contiguous, validated mapping.
            return Stream::assemble(&refs, g);
        }
        if records.len() + 1 == MAX_RECORDS {
            return Err(Error::Unsupported("attribute extension record limit"));
        }
        let mut next = None;
        for entry in &entries {
            let number = entry.reference.record;
            if number == 0 || records.iter().any(|(n, _)| *n == number) {
                continue;
            }
            if number >= mapping.len() / u64::from(g.record_size) {
                return Err(Error::Invalid("MFT extension outside stream"));
            }
            let offset = number.checked_mul(u64::from(g.record_size)).ok_or(Error::Bounds)?;
            if mapping.covers(offset, u64::from(g.record_size)) {
                next = Some((number, offset));
                break;
            }
        }
        let (number, offset) = next.ok_or(Error::Unsupported("unreachable MFT extension"))?;
        let mut data = vec![0; g.record_size as usize];
        if mapping.read(device, offset, &mut data)? != data.len() {
            return Err(Error::Bounds);
        }
        let record = Record::parse(data)?;
        validate_extension(&record, base_ref)?;
        // Each iteration adds one distinct record, bounded by MAX_RECORDS.
        records.push((number, record));
    }
}
