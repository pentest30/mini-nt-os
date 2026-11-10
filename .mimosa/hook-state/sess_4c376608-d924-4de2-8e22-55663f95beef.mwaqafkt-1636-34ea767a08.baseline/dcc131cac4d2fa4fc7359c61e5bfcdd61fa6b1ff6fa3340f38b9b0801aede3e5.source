//! GPT 1.0 on 512-byte logical sectors (UEFI specification, chapter 5).
//!
//! Reads both GPT copies, checking their CRCs and partition ranges; writes
//! canonical primary/backup tables and a protective MBR. No disk contents
//! are accessed through Rust layouts: fields are decoded explicitly.
//! Supports 128-byte entries, 128 through 4096 slots, without buffering the
//! whole table. Other entry sizes are rejected. Partition contents are never
//! modified. Writing requires exclusive access to an unmounted disk; errors
//! can leave a partial update, so this is not an atomic repartitioner.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;

/// The supported logical sector size.
pub const SECTOR_SIZE: usize = 512;
/// GUID bytes in the on-disk EFI encoding (first three fields little-endian).
pub type Guid = [u8; 16];
/// EFI System Partition type GUID.
pub const EFI_SYSTEM: Guid =
    [0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b];
/// Microsoft Basic Data type GUID (also used for FAT32 data volumes).
pub const BASIC_DATA: Guid =
    [0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7];

/// A disk whose capacity and logical sector size are known to the caller.
pub trait ReadSectors {
    /// The underlying device error.
    type Error;
    /// Reads one 512-byte sector at an absolute disk LBA.
    fn read_sector(&self, lba: u64, sector: &mut [u8; SECTOR_SIZE]) -> Result<(), Self::Error>;
}

/// Exclusive write access to that disk.
pub trait WriteSectors: ReadSectors {
    /// Writes one 512-byte sector at an absolute disk LBA.
    fn write_sector(&mut self, lba: u64, sector: &[u8; SECTOR_SIZE]) -> Result<(), Self::Error>;
    /// Makes completed writes reach the backing medium.
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// A malformed or unsupported disk layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Disk capacity or usable range cannot hold the metadata.
    Size,
    /// Invalid signature, revision, header size, reserved field, or LBA.
    Header,
    /// Header or partition-array checksum mismatch.
    Checksum,
    /// Unsupported entry layout, invalid GUID/range, duplicate or overlap.
    Entries,
    /// Missing protective MBR, or a hybrid MBR (not supported).
    ProtectiveMbr,
    /// Both copies are valid but disagree; neither is silently preferred.
    Conflict,
}

/// A GPT operation failed without discarding the underlying device error.
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    /// A read, write, or flush failed.
    Io(E),
    /// The metadata cannot be used.
    Invalid(Invalid),
}

/// One occupied slot in the partition array. LBAs are inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// One-based slot number, preserved even across unused slots.
    pub index: u32,
    /// Partition type GUID.
    pub kind: Guid,
    /// Nonzero GUID unique within this disk.
    pub id: Guid,
    /// First sector of the partition.
    pub first_lba: u64,
    /// Last sector of the partition, inclusive.
    pub last_lba: u64,
    /// GPT attribute bits, preserved without reinterpretation.
    pub attributes: u64,
    /// UTF-16 name units, as stored on disk.
    pub name: [u16; 36],
}

/// A validated GPT layout. Capacity includes all metadata and partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    sectors: u64,
    id: Guid,
    first: u64,
    last: u64,
    slots: u32,
    partitions: Vec<Partition>,
}

impl Layout {
    /// A new canonical layout with 128 slots and at least 16 KiB per table.
    /// GUIDs must be supplied by the caller; the library invents none.
    pub fn new(sectors: u64, id: Guid, mut partitions: Vec<Partition>) -> Result<Self, Invalid> {
        let last = sectors.checked_sub(34).ok_or(Invalid::Size)?;
        partitions.sort_by_key(|p| p.index);
        let layout = Self { sectors, id, first: 34, last, slots: 128, partitions };
        layout.validate()?;
        Ok(layout)
    }

    /// Disk capacity in 512-byte sectors.
    pub fn sectors(&self) -> u64 {
        self.sectors
    }
    /// Disk GUID in EFI byte order.
    pub fn id(&self) -> Guid {
        self.id
    }
    /// First and last usable LBAs, inclusive.
    pub fn usable_range(&self) -> (u64, u64) {
        (self.first, self.last)
    }
    /// Occupied slots, in their array order for layouts read from disk.
    pub fn partitions(&self) -> &[Partition] {
        &self.partitions
    }

    fn table_sectors(&self) -> u64 {
        u64::from(self.slots).div_ceil(4)
    }

    fn validate(&self) -> Result<(), Invalid> {
        if !(128..=4096).contains(&self.slots) {
            return Err(Invalid::Entries);
        }
        let table = self.table_sectors();
        if self.id == [0; 16]
            || self.first < 2 + table
            || self.first > self.last
            || self.sectors.checked_sub(2 + table).is_none_or(|last| self.last > last)
        {
            return Err(Invalid::Size);
        }
        for (i, p) in self.partitions.iter().enumerate() {
            if p.index == 0
                || p.index > self.slots
                || p.kind == [0; 16]
                || p.id == [0; 16]
                || p.first_lba < self.first
                || p.first_lba > p.last_lba
                || p.last_lba > self.last
            {
                return Err(Invalid::Entries);
            }
            if self.partitions[..i]
                .iter()
                .any(|q| q.index == p.index || q.id == p.id || (p.first_lba <= q.last_lba && q.first_lba <= p.last_lba))
            {
                return Err(Invalid::Entries);
            }
        }
        Ok(())
    }
}

/// Which valid copy supplied the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Both copies agree.
    Both,
    /// Only the primary copy is usable.
    Primary,
    /// Only the backup copy is usable; no automatic disk repair is done.
    Backup,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

fn crc_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

/// IEEE CRC-32, as used by GPT. Useful for independent metadata checks.
pub fn crc32(bytes: &[u8]) -> u32 {
    !crc_update(u32::MAX, bytes)
}

/// Whether sector 0 advertises a protective partition, including a damaged
/// or hybrid MBR. Callers use this to avoid treating a broken GPT as raw FAT.
pub fn has_protective_partition(mbr: &[u8; SECTOR_SIZE]) -> bool {
    (0..4).any(|i| mbr[446 + i * 16 + 4] == 0xee)
}

fn check_mbr(mbr: &[u8; SECTOR_SIZE], sectors: u64) -> Result<(), Invalid> {
    if mbr[510..] != [0x55, 0xaa] {
        return Err(Invalid::ProtectiveMbr);
    }
    let mut found = false;
    for i in 0..4 {
        let e = &mbr[446 + i * 16..462 + i * 16];
        if e.iter().all(|&b| b == 0) {
            continue;
        }
        if found
            || e[0] != 0
            || e[4] != 0xee
            || u32_at(e, 8) != 1
            || u32_at(e, 12) != (sectors - 1).min(u64::from(u32::MAX)) as u32
        {
            return Err(Invalid::ProtectiveMbr);
        }
        found = true;
    }
    if found {
        Ok(())
    } else {
        Err(Invalid::ProtectiveMbr)
    }
}

fn read_copy<D: ReadSectors>(disk: &D, sectors: u64, backup: bool) -> Result<(Layout, u32), Error<D::Error>> {
    let bad = Error::Invalid;
    let here = if backup { sectors - 1 } else { 1 };
    let other = if backup { 1 } else { sectors - 1 };
    let mut b = [0u8; SECTOR_SIZE];
    disk.read_sector(here, &mut b).map_err(Error::Io)?;
    let size = u32_at(&b, 12) as usize;
    if &b[..8] != b"EFI PART"
        || u32_at(&b, 8) != 0x0001_0000
        || !(92..=512).contains(&size)
        || u32_at(&b, 20) != 0
        || u64_at(&b, 24) != here
        || u64_at(&b, 32) != other
    {
        return Err(bad(Invalid::Header));
    }
    let crc = u32_at(&b, 16);
    put32(&mut b, 16, 0);
    if crc32(&b[..size]) != crc {
        return Err(bad(Invalid::Checksum));
    }
    if u32_at(&b, 84) != 128 {
        return Err(bad(Invalid::Entries));
    }
    let mut layout = Layout {
        sectors,
        id: b[56..72].try_into().unwrap(),
        first: u64_at(&b, 40),
        last: u64_at(&b, 48),
        slots: u32_at(&b, 80),
        partitions: Vec::new(),
    };
    layout.validate().map_err(bad)?;
    let start = u64_at(&b, 72);
    let end = start.checked_add(layout.table_sectors()).ok_or(bad(Invalid::Header))?;
    if (!backup && (start < 2 || end > layout.first)) || (backup && (start <= layout.last || end > sectors - 1)) {
        return Err(bad(Invalid::Header));
    }
    let expected = u32_at(&b, 88);
    let mut crc = u32::MAX;
    for sector in 0..layout.table_sectors() {
        disk.read_sector(start + sector, &mut b).map_err(Error::Io)?;
        let slots = (layout.slots - sector as u32 * 4).min(4) as usize;
        crc = crc_update(crc, &b[..slots * 128]);
        for i in 0..slots {
            let e = &b[i * 128..(i + 1) * 128];
            if e[..16] == [0; 16] {
                continue;
            }
            let mut name = [0; 36];
            for (j, unit) in name.iter_mut().enumerate() {
                *unit = u16::from_le_bytes([e[56 + 2 * j], e[57 + 2 * j]]);
            }
            layout.partitions.push(Partition {
                index: sector as u32 * 4 + i as u32 + 1,
                kind: e[..16].try_into().unwrap(),
                id: e[16..32].try_into().unwrap(),
                first_lba: u64_at(e, 32),
                last_lba: u64_at(e, 40),
                attributes: u64_at(e, 48),
                name,
            });
        }
    }
    if !crc != expected {
        return Err(bad(Invalid::Checksum));
    }
    layout.validate().map_err(bad)?;
    Ok((layout, expected))
}

/// Reads and validates the protective MBR and both copies. A valid copy can
/// recover an unreadable or corrupt peer; two differing valid copies fail.
pub fn read<D: ReadSectors>(disk: &D, sectors: u64) -> Result<(Layout, Source), Error<D::Error>> {
    if sectors < 68 {
        return Err(Error::Invalid(Invalid::Size));
    }
    let mut mbr = [0; SECTOR_SIZE];
    disk.read_sector(0, &mut mbr).map_err(Error::Io)?;
    check_mbr(&mbr, sectors).map_err(Error::Invalid)?;
    match (read_copy(disk, sectors, false), read_copy(disk, sectors, true)) {
        (Ok(a), Ok(b)) if a == b => Ok((a.0, Source::Both)),
        (Ok(_), Ok(_)) => Err(Error::Invalid(Invalid::Conflict)),
        (Ok(a), Err(_)) => Ok((a.0, Source::Primary)),
        (Err(_), Ok(b)) => Ok((b.0, Source::Backup)),
        (Err(e), Err(_)) => Err(e),
    }
}

fn table_sector(layout: &Layout, sector: u64) -> [u8; SECTOR_SIZE] {
    let mut b = [0; SECTOR_SIZE];
    for p in &layout.partitions {
        let slot = u64::from(p.index - 1);
        if slot / 4 != sector {
            continue;
        }
        let e = &mut b[(slot % 4) as usize * 128..(slot % 4 + 1) as usize * 128];
        e[..16].copy_from_slice(&p.kind);
        e[16..32].copy_from_slice(&p.id);
        put64(e, 32, p.first_lba);
        put64(e, 40, p.last_lba);
        put64(e, 48, p.attributes);
        for (j, unit) in p.name.iter().enumerate() {
            e[56 + 2 * j..58 + 2 * j].copy_from_slice(&unit.to_le_bytes());
        }
    }
    b
}

fn header(layout: &Layout, backup: bool, entries_crc: u32) -> [u8; SECTOR_SIZE] {
    let mut b = [0; SECTOR_SIZE];
    b[..8].copy_from_slice(b"EFI PART");
    put32(&mut b, 8, 0x0001_0000);
    put32(&mut b, 12, 92);
    put64(&mut b, 24, if backup { layout.sectors - 1 } else { 1 });
    put64(&mut b, 32, if backup { 1 } else { layout.sectors - 1 });
    put64(&mut b, 40, layout.first);
    put64(&mut b, 48, layout.last);
    b[56..72].copy_from_slice(&layout.id);
    put64(&mut b, 72, if backup { layout.sectors - 1 - layout.table_sectors() } else { 2 });
    put32(&mut b, 80, layout.slots);
    put32(&mut b, 84, 128);
    put32(&mut b, 88, entries_crc);
    let crc = crc32(&b[..92]);
    put32(&mut b, 16, crc);
    b
}

/// Writes both tables, backup first, with a flush between the copies, then
/// the protective MBR and a final flush. All ranges are checked before the
/// first write. Existing partition payload and free space are left intact.
/// The device must have exactly `layout.sectors()` sectors.
pub fn write<D: WriteSectors>(disk: &mut D, layout: &Layout) -> Result<(), Error<D::Error>> {
    layout.validate().map_err(Error::Invalid)?;
    let mut crc = u32::MAX;
    for i in 0..layout.table_sectors() {
        let slots = (layout.slots - i as u32 * 4).min(4) as usize;
        crc = crc_update(crc, &table_sector(layout, i)[..slots * 128]);
    }
    for backup in [true, false] {
        let start = if backup { layout.sectors - 1 - layout.table_sectors() } else { 2 };
        for i in 0..layout.table_sectors() {
            disk.write_sector(start + i, &table_sector(layout, i)).map_err(Error::Io)?;
        }
        disk.write_sector(if backup { layout.sectors - 1 } else { 1 }, &header(layout, backup, !crc))
            .map_err(Error::Io)?;
        disk.flush().map_err(Error::Io)?;
    }
    let mut mbr = [0; SECTOR_SIZE];
    mbr[447..450].copy_from_slice(&[0, 2, 0]);
    mbr[450] = 0xee;
    mbr[451..454].copy_from_slice(&[0xff; 3]);
    put32(&mut mbr, 454, 1);
    put32(&mut mbr, 458, (layout.sectors - 1).min(u64::from(u32::MAX)) as u32);
    mbr[510..].copy_from_slice(&[0x55, 0xaa]);
    disk.write_sector(0, &mbr).map_err(Error::Io)?;
    disk.flush().map_err(Error::Io)
}

#[cfg(test)]
mod tests;
