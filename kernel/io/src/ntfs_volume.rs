//! Read-only NTFS adapter. Each operation owns a fresh reader, so no spinlock
//! spans filesystem allocation. ATA serializes each complete PIO command at
//! the channel, below this adapter. The mounted media must remain
//! stable; external writes/removal require unmounting (not yet implemented).
use crate::volume::{Listed, Node, SharedBlockDevice, Space, VolumeLabel};
use abi::{
    file::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL},
    ntstatus::*,
};
use alloc::vec::Vec;
use ntfs::{Error, FileReference, ReadAt};

pub(crate) struct NtfsMount {
    device: SharedBlockDevice,
    bytes: u64,
    cluster: u32,
    root: Node,
}

// No write or flush method is exposed to the NTFS format reader.
struct Reader<'a> {
    device: &'a SharedBlockDevice,
    bytes: u64,
}
impl ReadAt for Reader<'_> {
    fn len(&self) -> u64 {
        self.bytes
    }
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        if offset.checked_add(out.len() as u64).is_none_or(|end| end > self.bytes) {
            return Err(Error::Bounds);
        }
        let mut done = 0;
        let mut sector = [0; 512];
        while done < out.len() {
            let position = offset + done as u64;
            self.device.read_sector(position / 512, &mut sector).map_err(|_| Error::Io)?;
            let within = (position % 512) as usize;
            let take = (512 - within).min(out.len() - done);
            out[done..done + take].copy_from_slice(&sector[within..within + take]);
            done += take;
        }
        Ok(())
    }
}

fn status(error: Error) -> NtStatus {
    match error {
        Error::Io => STATUS_IO_DEVICE_ERROR,
        Error::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        Error::Unsupported(_) => STATUS_INVALID_DEVICE_REQUEST,
        Error::Bounds | Error::Invalid(_) => STATUS_FILE_CORRUPT_ERROR,
    }
}
fn node(v: &mut ntfs::Volume<Reader<'_>>, reference: FileReference) -> Result<Node, NtStatus> {
    let m = v.metadata(reference).map_err(status)?;
    let attributes = m.attributes | if m.directory { FILE_ATTRIBUTE_DIRECTORY } else { 0 };
    Ok(Node {
        directory: m.directory,
        size: m.size,
        attributes: if attributes == 0 { FILE_ATTRIBUTE_NORMAL } else { attributes },
        creation_time: m.creation_time,
        last_access_time: m.last_access_time,
        last_write_time: m.last_write_time,
        reference: Some(reference),
        ..Node::default()
    })
}
fn identity(node: &Node) -> Result<FileReference, NtStatus> {
    node.reference.ok_or(STATUS_INVALID_PARAMETER)
}
impl NtfsMount {
    pub(crate) fn mount(device: SharedBlockDevice, sectors: u64) -> Result<Self, NtStatus> {
        let bytes = sectors.checked_mul(512).ok_or(STATUS_UNRECOGNIZED_VOLUME)?;
        let mut v = ntfs::Volume::open(Reader { device: &device, bytes }).map_err(status)?;
        let root = v.lookup_path("/").map_err(status)?;
        let root = node(&mut v, root)?;
        let cluster = v.geometry().cluster_size;
        Ok(Self { device, bytes, cluster, root })
    }
    fn reader(&self) -> Result<ntfs::Volume<Reader<'_>>, NtStatus> {
        ntfs::Volume::open(Reader { device: &self.device, bytes: self.bytes }).map_err(status)
    }
    pub(crate) fn root(&self) -> Node {
        self.root
    }
    pub(crate) fn cluster_bytes(&self) -> u32 {
        self.cluster
    }
    pub(crate) fn current(&self, n: &Node) -> Result<Node, NtStatus> {
        node(&mut self.reader()?, identity(n)?)
    }
    pub(crate) fn lookup(&self, from: &Node, path: &str) -> Result<Node, NtStatus> {
        if path.encode_utf16().count() > 4096 {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let trailing = path.ends_with('\\');
        let path = path.strip_suffix('\\').unwrap_or(path);
        let mut v = self.reader()?;
        let mut reference = identity(from)?;
        let mut components = path.split('\\').peekable();
        let mut depth = 0;
        while let Some(name) = components.next() {
            depth += 1;
            if depth > 64
                || name.is_empty()
                || name == "."
                || name == ".."
                || name.encode_utf16().count() > 255
                || name.chars().any(|c| c < ' ' || matches!(c, '"' | '*' | '/' | ':' | '<' | '>' | '?' | '|'))
            {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            if !v.referenced_record(reference).map_err(status)?.is_directory() {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            }
            reference = v.lookup_child(reference, name).map_err(|e| match e {
                Error::NotFound if components.peek().is_some() => STATUS_OBJECT_PATH_NOT_FOUND,
                e => status(e),
            })?;
        }
        let found = node(&mut v, reference)?;
        if trailing && !found.directory {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        Ok(found)
    }
    pub(crate) fn read(&self, n: &Node, offset: u64, out: &mut [u8]) -> Result<usize, NtStatus> {
        let mut v = self.reader()?;
        if v.referenced_record(identity(n)?).map_err(status)?.is_directory() {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        v.read_file(identity(n)?.record, offset, out).map_err(status)
    }
    pub(crate) fn entries(&self, n: &Node) -> Result<Vec<Listed>, NtStatus> {
        let mut v = self.reader()?;
        let reference = identity(n)?;
        if !v.referenced_record(reference).map_err(status)?.is_directory() {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let entries = v.read_directory(reference.record).map_err(status)?;
        let mut listed = Vec::new();
        for (offset, e) in entries.iter().enumerate() {
            // NTFS reserves records 0..15 for filesystem metadata ($MFT,
            // $Secure, etc.), not ordinary user directory enumeration.
            if e.reference.record < 16 {
                continue;
            }
            // Combine the DOS alias with its Win32 entry, preserving hard links.
            if e.namespace == 2 && entries.iter().any(|o| o.reference == e.reference && o.namespace == 1) {
                continue;
            }
            let name = e.name.clone();
            if name == [b'.' as u16] || name == [b'.' as u16, b'.' as u16] {
                continue;
            }
            let short_name = if e.namespace == 1 {
                entries.iter().find(|o| o.reference == e.reference && o.namespace == 2).map(|o| o.name.clone())
            } else {
                None
            };
            let n = node(&mut v, e.reference)?;
            listed.push(Listed {
                name,
                short_name,
                offset: offset as u32,
                directory: n.directory,
                attributes: n.attributes,
                size: n.size,
                creation_time: n.creation_time,
                last_access_time: n.last_access_time,
                last_write_time: n.last_write_time,
            });
        }
        Ok(listed)
    }
    /// The serial number and `$VOLUME_NAME`, its UTF-16 as stored: NTFS
    /// accepts any 16-bit units, an unpaired surrogate too, which a
    /// conversion to `String` would refuse (as directory names are kept).
    pub(crate) fn label(&self) -> Result<VolumeLabel, NtStatus> {
        let mut v = self.reader()?;
        let label = v.volume_label().map_err(status)?;
        let mut boot = [0; 512];
        self.device.read_sector(0, &mut boot).map_err(|_| STATUS_IO_DEVICE_ERROR)?;
        Ok(VolumeLabel { label, serial: u32::from_le_bytes(boot[72..76].try_into().expect("boot sector")) })
    }
    pub(crate) fn space(&self) -> Result<Space, NtStatus> {
        let mut v = self.reader()?;
        let g = v.geometry();
        Ok(Space {
            total_clusters: g.volume_size / u64::from(g.cluster_size),
            free_clusters: v.free_clusters().map_err(status)?,
            sectors_per_cluster: g.cluster_size / 512,
            bytes_per_sector: 512,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, sync::Arc};
    use core::sync::atomic::{AtomicUsize, Ordering};
    struct Disk(Arc<AtomicUsize>);
    impl crate::fat::BlockDevice for Disk {
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), crate::fat::FatError> {
            assert!(lba < 2);
            self.0.fetch_add(1, Ordering::Relaxed);
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = ((lba * 512 + i as u64) % 251) as u8;
            }
            Ok(())
        }
    }
    /// A read-only disk image.
    struct Image(alloc::vec::Vec<u8>);
    impl crate::fat::BlockDevice for Image {
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_sector(&self, lba: u64, out: &mut [u8]) -> Result<(), crate::fat::FatError> {
            let at = usize::try_from(lba * 512).map_err(|_| crate::fat::FatError::Io)?;
            out.copy_from_slice(self.0.get(at..at + 512).ok_or(crate::fat::FatError::Io)?);
            Ok(())
        }
    }

    fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
        bytes[at..at + value.len()].copy_from_slice(value);
    }

    /// A FILE record of 1024 bytes, in use, holding `attribute`, with its
    /// update sequence (one number, then the saved end of each sector).
    fn file_record(attribute: &[u8]) -> alloc::vec::Vec<u8> {
        let mut b = alloc::vec![0; 1024];
        b[..4].copy_from_slice(b"FILE");
        put(&mut b, 4, &48u16.to_le_bytes());
        put(&mut b, 6, &3u16.to_le_bytes());
        put(&mut b, 16, &1u16.to_le_bytes());
        put(&mut b, 20, &56u16.to_le_bytes());
        put(&mut b, 22, &1u16.to_le_bytes());
        put(&mut b, 24, &((56 + attribute.len() + 8) as u32).to_le_bytes());
        put(&mut b, 28, &1024u32.to_le_bytes());
        put(&mut b, 56, attribute);
        put(&mut b, 56 + attribute.len(), &u32::MAX.to_le_bytes());
        put(&mut b, 48, &0x5A5Au16.to_le_bytes());
        for (end, slot) in [(510, 50), (1022, 52)] {
            let saved = [b[end], b[end + 1]];
            put(&mut b, slot, &saved);
            put(&mut b, end, &0x5A5Au16.to_le_bytes());
        }
        b
    }

    /// A 64-sector volume of 512-byte clusters: its boot sector (serial
    /// `serial`), an MFT of four records at cluster 4 (the first maps it),
    /// and `$Volume` (record 3) whose `$VOLUME_NAME` is `name`.
    fn volume_image(serial: u32, name: &[u16]) -> alloc::vec::Vec<u8> {
        let mut b = alloc::vec![0; 64 * 512];
        put(&mut b, 3, b"NTFS    ");
        put(&mut b, 11, &512u16.to_le_bytes());
        b[13] = 1;
        put(&mut b, 40, &64u64.to_le_bytes());
        put(&mut b, 48, &4u64.to_le_bytes());
        put(&mut b, 56, &20u64.to_le_bytes());
        b[64] = 0xF6; // FILE records of 2^10 bytes.
        put(&mut b, 72, &serial.to_le_bytes());
        put(&mut b, 510, &[0x55, 0xAA]);
        // $MFT's $DATA: non-resident, 8 clusters from cluster 4.
        let mut data = alloc::vec![0; 72];
        put(&mut data, 0, &0x80u32.to_le_bytes());
        put(&mut data, 4, &72u32.to_le_bytes());
        data[8] = 1;
        put(&mut data, 24, &7u64.to_le_bytes());
        put(&mut data, 32, &64u16.to_le_bytes());
        for at in [40, 48, 56] {
            put(&mut data, at, &4096u64.to_le_bytes());
        }
        put(&mut data, 64, &[0x11, 8, 4, 0]);
        put(&mut b, 4 * 512, &file_record(&data));
        // $VOLUME_NAME: resident.
        let value: alloc::vec::Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        let length = (24 + value.len() + 7) & !7;
        let mut attribute = alloc::vec![0; length];
        put(&mut attribute, 0, &0x60u32.to_le_bytes());
        put(&mut attribute, 4, &(length as u32).to_le_bytes());
        put(&mut attribute, 16, &(value.len() as u32).to_le_bytes());
        put(&mut attribute, 20, &24u16.to_le_bytes());
        put(&mut attribute, 24, &value);
        put(&mut b, 4 * 512 + 3 * 1024, &file_record(&attribute));
        b
    }

    #[test]
    fn the_volume_name_keeps_its_utf16_as_stored() {
        // An unpaired surrogate first: valid on NTFS, refused by
        // String::from_utf16.
        let name = [0xD800, u16::from(b'M'), u16::from(b'i'), u16::from(b'n'), u16::from(b'o')];
        let mount = NtfsMount {
            device: Box::new(Image(volume_image(0x4D49_4E4F, &name))),
            bytes: 64 * 512,
            cluster: 512,
            root: Node::default(),
        };
        assert_eq!(mount.label(), Ok(VolumeLabel { serial: 0x4D49_4E4F, label: name.to_vec() }));
        let plain: alloc::vec::Vec<u16> = "MinoData".encode_utf16().collect();
        let mount = NtfsMount { device: Box::new(Image(volume_image(7, &plain))), ..mount };
        assert_eq!(mount.label(), Ok(VolumeLabel { serial: 7, label: plain }));
    }

    #[test]
    fn byte_reader_handles_unaligned_reads_and_checks_bounds_before_io() {
        let calls = Arc::new(AtomicUsize::new(0));
        let disk: SharedBlockDevice = Box::new(Disk(calls.clone()));
        let mut reader = Reader { device: &disk, bytes: 1024 };
        let mut out = [0; 23];
        reader.read_exact_at(509, &mut out).unwrap();
        for (i, byte) in out.iter().enumerate() {
            assert_eq!(*byte, ((509 + i) % 251) as u8);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        for offset in [1002, 1024, u64::MAX] {
            assert_eq!(reader.read_exact_at(offset, &mut out), Err(Error::Bounds));
        }
        reader.read_exact_at(1024, &mut []).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2, "no out-of-partition I/O");
    }
}
