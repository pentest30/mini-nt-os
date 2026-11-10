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

impl<D: ReadAt> Volume<D> {
    /// Resolve a volume-root-relative UTF-8 path using the volume's $UpCase
    /// table (not the host's Unicode casing). `/` and `\` are separators;
    /// leading separators are optional. `.` and `..` are supported, but `..`
    /// cannot escape the root. A trailing separator requires a directory.
    /// Drive letters, ADS syntax and NUL are refused. At most 4096 UTF-16
    /// units and 64 nonempty components may be resolved in one call.
    /// Case-folded names referring to distinct files are explicitly ambiguous.
    pub fn lookup_path(&mut self, path: &str) -> Result<FileReference, Error> {
        if path.contains(['\0', ':']) {
            return Err(Error::Unsupported("path syntax"));
        }
        if path.encode_utf16().count() > 4096 {
            return Err(Error::Unsupported("path length"));
        }
        let root = self.record(5)?;
        if !root.is_directory() {
            return Err(Error::Invalid("root is not a directory"));
        }
        let mut stack = vec![FileReference { record: 5, sequence: root.sequence() }];
        let mut components = 0;
        for component in path.split(['/', '\\']).filter(|c| !c.is_empty()) {
            components += 1;
            if components > 64 {
                return Err(Error::Unsupported("path depth"));
            }
            let parent = *stack.last().ok_or(Error::Invalid("path stack"))?;
            if !self.referenced_record(parent)?.is_directory() {
                return Err(Error::Invalid("not a directory"));
            }
            if component == "." {
                continue;
            }
            if component == ".." {
                if stack.len() == 1 {
                    return Err(Error::Invalid("path escapes root"));
                }
                stack.pop();
                continue;
            }
            let name: Vec<u16> = component.encode_utf16().collect();
            if name.len() > 255 {
                return Err(Error::Unsupported("component length"));
            }
            self.load_upcase()?;
            let entries = self.read_directory(parent.record)?;
            let table = self.upcase.as_ref().ok_or(Error::Invalid("UpCase missing"))?;
            let mut found: Option<DirectoryEntry> = None;
            for entry in entries {
                if entry.name.len() != name.len()
                    || !entry.name.iter().zip(&name).all(|(&a, &b)| table[a as usize] == table[b as usize])
                {
                    continue;
                }
                if let Some(previous) = &found {
                    if previous.reference != entry.reference || previous.is_directory != entry.is_directory {
                        return Err(Error::Unsupported("ambiguous case-insensitive name"));
                    }
                }
                found = Some(entry);
            }
            let entry = found.ok_or(Error::NotFound)?;
            if self.referenced_record(entry.reference)?.is_directory() != entry.is_directory {
                return Err(Error::Invalid("indexed directory flag"));
            }
            stack.push(entry.reference);
        }
        let result = *stack.last().ok_or(Error::Invalid("path stack"))?;
        if path.ends_with(['/', '\\']) && !self.referenced_record(result)?.is_directory() {
            return Err(Error::Invalid("not a directory"));
        }
        Ok(result)
    }

    /// Read a file by path, with the same EOF and error semantics as read_file.
    /// This is a format reader, not an NT access-control check.
    pub fn read_path(&mut self, path: &str, offset: u64, out: &mut [u8]) -> Result<usize, Error> {
        let reference = self.lookup_path(path)?;
        self.read_file(reference.record, offset, out)
    }

    /// Read a FILE only if its sequence still matches the supplied reference.
    pub fn referenced_record(&mut self, reference: FileReference) -> Result<crate::Record, Error> {
        let record = self.record(reference.record)?;
        if reference.sequence != record.sequence() {
            return Err(Error::Invalid("stale file reference"));
        }
        Ok(record)
    }

    fn load_upcase(&mut self) -> Result<(), Error> {
        if self.upcase.is_some() {
            return Ok(());
        }
        // NTFS reserves FILE 10 for $UpCase: exactly 65536 little-endian u16s.
        let stream = self.file_stream(10)?;
        if stream.len() != 131072 || !stream.fully_initialized() {
            return Err(Error::Invalid("UpCase size"));
        }
        let mut data = vec![0; 131072];
        if stream.read(&mut self.device, 0, &mut data)? != data.len() {
            return Err(Error::Bounds);
        }
        let table: Vec<u16> = data.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        for &upper in &table {
            if table[upper as usize] != upper {
                return Err(Error::Invalid("UpCase not idempotent"));
            }
        }
        self.upcase = Some(table);
        Ok(())
    }
}
