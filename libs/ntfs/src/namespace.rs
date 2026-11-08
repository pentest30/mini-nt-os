use crate::index;
use crate::stream::Stream;
use crate::{DirectoryEntry, Error, FileReference, ReadAt, Volume};
use alloc::{collections::BTreeSet, vec, vec::Vec};

const I30: &[u8] = b"$\0I\x003\x000\0";
const MAX_BLOCKS: usize = 4096;
const MAX_ENTRIES: usize = 65536;

impl<D: ReadAt> Volume<D> {
    /// Enumerate a directory by MFT record number, including DOS aliases.
    /// Results are not sorted. References are validated during path lookup,
    /// not by this listing. Limits: 4096 INDX blocks and 65536 indexed names.
    pub fn read_directory(&mut self, number: u64) -> Result<Vec<DirectoryEntry>, Error> {
        let record = self.record(number)?;
        if !record.is_directory() {
            return Err(Error::Invalid("not a directory"));
        }
        let parent = FileReference { record: number, sequence: record.sequence() };
        let attrs = record.attributes()?;
        let mut root = None;
        let mut allocation = None;
        let mut bitmap = None;
        for attr in &attrs {
            if attr.name != I30 {
                continue;
            }
            let slot = match attr.kind {
                0x90 => &mut root,
                0xa0 => &mut allocation,
                0xb0 => &mut bitmap,
                _ => continue,
            };
            if slot.is_some() {
                return Err(Error::Unsupported("multiple index extents"));
            }
            *slot = Some(Stream::parse(attr, self.geometry)?);
        }
        let root = match root {
            Some(Stream::Resident(data)) => data,
            _ => return Err(Error::Invalid("resident INDEX_ROOT missing")),
        };
        let (block_size, node) = index::root(&root, parent)?;
        let mut entries = node.entries;
        let mut pending = node.children;
        if pending.is_empty() {
            return Ok(entries);
        }
        let allocation = allocation.ok_or(Error::Invalid("INDEX_ALLOCATION missing"))?;
        let bitmap = bitmap.ok_or(Error::Invalid("index BITMAP missing"))?;
        if matches!(allocation, Stream::Resident(_))
            || !allocation.fully_initialized()
            || !bitmap.fully_initialized()
            || !allocation.len().is_multiple_of(u64::from(block_size))
        {
            return Err(Error::Invalid("index allocation sizes"));
        }
        // NTFS uses sector units for VCNs when index blocks are smaller than a cluster.
        let unit = if block_size < self.geometry.cluster_size { 512 } else { self.geometry.cluster_size };
        let mut visited = BTreeSet::new();
        let mut data = vec![0; block_size as usize];
        while let Some(vcn) = pending.pop() {
            if visited.len() == MAX_BLOCKS {
                return Err(Error::Unsupported("directory block limit"));
            }
            if !visited.insert(vcn) {
                return Err(Error::Invalid("index cycle or shared child"));
            }
            let offset = vcn.checked_mul(u64::from(unit)).ok_or(Error::Bounds)?;
            if !offset.is_multiple_of(u64::from(block_size)) {
                return Err(Error::Invalid("index block alignment"));
            }
            let block_number = offset / u64::from(block_size);
            let mut bits = [0];
            if bitmap.read(&mut self.device, block_number / 8, &mut bits)? != 1
                || bits[0] & (1 << (block_number % 8)) == 0
            {
                return Err(Error::Invalid("unallocated index block"));
            }
            if allocation.read(&mut self.device, offset, &mut data)? != data.len() {
                return Err(Error::Bounds);
            }
            let node = index::block(&mut data, vcn, parent)?;
            if entries.len() + node.entries.len() > MAX_ENTRIES || pending.len() + node.children.len() > MAX_BLOCKS {
                return Err(Error::Unsupported("directory traversal limit"));
            }
            entries.extend(node.entries);
            pending.extend(node.children);
        }
        Ok(entries)
    }
}
