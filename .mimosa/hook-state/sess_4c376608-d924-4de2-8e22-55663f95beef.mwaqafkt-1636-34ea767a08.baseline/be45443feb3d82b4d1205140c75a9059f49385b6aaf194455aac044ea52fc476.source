use super::*;
use alloc::vec;

struct Disk {
    bytes: Vec<u8>,
    writes: usize,
    fail_write: Option<usize>,
    fail_flush: bool,
    flushes: usize,
}
impl Disk {
    fn new() -> Self {
        Self { bytes: vec![0xa5; 8192 * 512], writes: 0, fail_write: None, fail_flush: false, flushes: 0 }
    }
}
impl ReadSectors for Disk {
    type Error = &'static str;
    fn read_sector(&self, lba: u64, b: &mut [u8; 512]) -> Result<(), Self::Error> {
        let at = lba as usize * 512;
        b.copy_from_slice(self.bytes.get(at..at + 512).ok_or("bounds")?);
        Ok(())
    }
}
impl WriteSectors for Disk {
    fn write_sector(&mut self, lba: u64, b: &[u8; 512]) -> Result<(), Self::Error> {
        if self.fail_write == Some(self.writes) {
            return Err("write");
        }
        self.writes += 1;
        let at = lba as usize * 512;
        self.bytes[at..at + 512].copy_from_slice(b);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        if self.fail_flush {
            return Err("flush");
        }
        self.flushes += 1;
        Ok(())
    }
}
fn partition(index: u32, first: u64, last: u64) -> Partition {
    let mut name = [0; 36];
    name[..4].copy_from_slice(&[77, 105, 110, 111]);
    Partition {
        index,
        kind: BASIC_DATA,
        id: [index as u8; 16],
        first_lba: first,
        last_lba: last,
        attributes: 1 << 60,
        name,
    }
}
fn layout() -> Layout {
    Layout::new(8192, [0x42; 16], vec![partition(2, 2048, 4095), partition(128, 4096, 6000)]).unwrap()
}
fn repair_header(disk: &mut Disk, lba: usize) {
    let h = &mut disk.bytes[lba * 512..(lba + 1) * 512];
    put32(h, 16, 0);
    let crc = crc32(&h[..92]);
    put32(h, 16, crc);
}

#[test]
fn standard_crc_vector() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
}

#[test]
fn sixty_four_bit_lbas_and_saturated_protective_mbr_need_only_metadata_storage() {
    use alloc::collections::BTreeMap;
    #[derive(Default)]
    struct Sparse(BTreeMap<u64, [u8; 512]>);
    impl ReadSectors for Sparse {
        type Error = &'static str;
        fn read_sector(&self, lba: u64, out: &mut [u8; 512]) -> Result<(), Self::Error> {
            *out = *self.0.get(&lba).ok_or("not written")?;
            Ok(())
        }
    }
    impl WriteSectors for Sparse {
        fn write_sector(&mut self, lba: u64, b: &[u8; 512]) -> Result<(), Self::Error> {
            self.0.insert(lba, *b);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    let layout = Layout::new(u64::MAX, [0x42; 16], vec![]).unwrap();
    let mut disk = Sparse::default();
    write(&mut disk, &layout).unwrap();
    assert_eq!(disk.0.len(), 67);
    assert_eq!(u32_at(disk.0.get(&0).unwrap(), 458), u32::MAX);
    assert_eq!(read(&disk, u64::MAX), Ok((layout, Source::Both)));
}

#[test]
fn checked_crcs_do_not_make_bad_partition_ranges_or_guids_valid() {
    for (at, bytes) in [(32, 1u64.to_le_bytes().to_vec()), (40, 8191u64.to_le_bytes().to_vec()), (16, vec![0; 16])] {
        let mut disk = Disk::new();
        write(&mut disk, &layout()).unwrap();
        // Slot 2 is the first occupied entry.
        let offset = 2 * 512 + 128 + at;
        disk.bytes[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let crc = crc32(&disk.bytes[2 * 512..34 * 512]);
        put32(&mut disk.bytes[512..1024], 88, crc);
        repair_header(&mut disk, 1);
        disk.bytes[8191 * 512] ^= 1; // do not recover via the untouched peer
        assert_eq!(read(&disk, 8192), Err(Error::Invalid(Invalid::Entries)));
    }
}

#[test]
fn non_sector_multiple_entry_counts_and_high_slots_round_trip() {
    let mut layout = layout();
    layout.slots = 129;
    layout.first = 35;
    layout.last = 8192 - 35;
    layout.partitions[1].index = 129;
    let mut disk = Disk::new();
    write(&mut disk, &layout).unwrap();
    assert_eq!(read(&disk, 8192), Ok((layout, Source::Both)));
}

#[test]
fn an_unreadable_primary_can_recover_without_hiding_two_io_errors() {
    struct Faulty<'a>(&'a Disk, bool);
    impl ReadSectors for Faulty<'_> {
        type Error = &'static str;
        fn read_sector(&self, lba: u64, b: &mut [u8; 512]) -> Result<(), Self::Error> {
            if lba == 1 || (self.1 && lba == 8191) {
                return Err("read");
            }
            self.0.read_sector(lba, b)
        }
    }
    let mut disk = Disk::new();
    write(&mut disk, &layout()).unwrap();
    assert_eq!(read(&Faulty(&disk, false), 8192), Ok((layout(), Source::Backup)));
    assert_eq!(read(&Faulty(&disk, true), 8192), Err(Error::Io("read")));
}

#[test]
fn round_trip_preserves_slots_names_attributes_and_payload() {
    let mut disk = Disk::new();
    let layout = layout();
    write(&mut disk, &layout).unwrap();
    assert_eq!(read(&disk, 8192), Ok((layout, Source::Both)));
    assert_eq!(disk.flushes, 3);
    assert!(disk.bytes[34 * 512..(8192 - 33) * 512].iter().all(|&b| b == 0xa5));
    assert_eq!(&disk.bytes[2 * 512..34 * 512], &disk.bytes[(8192 - 33) * 512..(8192 - 1) * 512]);
    assert_eq!(u64_at(&disk.bytes[512..], 24), 1);
    assert_eq!(u64_at(&disk.bytes[(8192 - 1) * 512..], 24), 8191);
    assert_eq!(u32_at(&disk.bytes, 454), 1);
    assert_eq!(u32_at(&disk.bytes, 458), 8191);
}

#[test]
fn each_header_and_array_has_a_checked_crc_and_recovery_copy() {
    for offset in [512, 512 + 16, 512 + 40, 2 * 512 + 160] {
        let mut disk = Disk::new();
        write(&mut disk, &layout()).unwrap();
        disk.bytes[offset] ^= 1;
        assert_eq!(read(&disk, 8192), Ok((layout(), Source::Backup)));
        disk.bytes[(8192 - 1) * 512] ^= 1;
        assert!(read(&disk, 8192).is_err());
    }
    for offset in [(8192 - 1) * 512 + 16, (8192 - 33) * 512 + 160] {
        let mut disk = Disk::new();
        write(&mut disk, &layout()).unwrap();
        disk.bytes[offset] ^= 1;
        assert_eq!(read(&disk, 8192), Ok((layout(), Source::Primary)));
    }
}

#[test]
fn valid_but_conflicting_copies_are_refused() {
    let mut disk = Disk::new();
    write(&mut disk, &layout()).unwrap();
    disk.bytes[(8192 - 1) * 512 + 56] ^= 1;
    repair_header(&mut disk, 8191);
    assert_eq!(read(&disk, 8192), Err(Error::Invalid(Invalid::Conflict)));
}

#[test]
fn metadata_ranges_and_entry_counts_are_checked_before_reading_tables() {
    for (offset, value) in [(72, u64::MAX), (40, 2), (48, 8191), (32, 8000)] {
        let mut disk = Disk::new();
        write(&mut disk, &layout()).unwrap();
        put64(&mut disk.bytes[512..1024], offset, value);
        repair_header(&mut disk, 1);
        disk.bytes[8191 * 512] ^= 1;
        assert!(matches!(read(&disk, 8192), Err(Error::Invalid(_))));
    }
    for (offset, value) in [(80, 0), (80, u32::MAX), (84, 127), (12, 513)] {
        let mut disk = Disk::new();
        write(&mut disk, &layout()).unwrap();
        put32(&mut disk.bytes[512..1024], offset, value);
        repair_header(&mut disk, 1);
        disk.bytes[8191 * 512] ^= 1;
        assert!(matches!(read(&disk, 8192), Err(Error::Invalid(_))));
    }
}

#[test]
fn layout_rejects_overlaps_duplicate_ids_slots_and_reserved_lbas_without_writing() {
    for p in [
        partition(1, 33, 100),
        partition(1, 8190, 8191),
        partition(1, 3000, 2000),
        partition(0, 2048, 3000),
        partition(129, 2048, 3000),
    ] {
        assert!(Layout::new(8192, [1; 16], vec![p]).is_err());
    }
    for second in [partition(3, 3000, 5000), partition(3, 4095, 5000), partition(2, 6001, 6500)] {
        assert!(Layout::new(8192, [1; 16], vec![partition(2, 2048, 4095), second]).is_err());
    }
    let mut second = partition(3, 4096, 5000);
    second.id = [2; 16];
    assert!(Layout::new(8192, [1; 16], vec![partition(2, 2048, 4095), second]).is_err());
    assert!(Layout::new(67, [1; 16], vec![]).is_err());
    assert!(Layout::new(8192, [0; 16], vec![]).is_err());
    let mut bad = layout();
    bad.partitions[0].last_lba = 8191;
    let mut disk = Disk::new();
    assert!(write(&mut disk, &bad).is_err());
    assert_eq!(disk.writes, 0);
}

#[test]
fn protective_mbr_is_required_and_hybrid_mbr_is_rejected() {
    for at in [450, 454, 458, 510, 462 + 4] {
        let mut disk = Disk::new();
        write(&mut disk, &layout()).unwrap();
        disk.bytes[at] ^= 1;
        assert_eq!(read(&disk, 8192), Err(Error::Invalid(Invalid::ProtectiveMbr)));
    }
}

#[test]
fn io_errors_stop_writes_and_flush_errors_propagate() {
    for n in [0, 31, 32, 33, 64, 65, 66] {
        let mut disk = Disk::new();
        disk.fail_write = Some(n);
        assert_eq!(write(&mut disk, &layout()), Err(Error::Io("write")));
        assert_eq!(disk.writes, n);
    }
    let mut disk = Disk::new();
    disk.fail_flush = true;
    assert_eq!(write(&mut disk, &layout()), Err(Error::Io("flush")));
    assert_eq!(disk.writes, 33);
    assert_eq!(read(&disk, 1), Err(Error::Invalid(Invalid::Size)));
}
