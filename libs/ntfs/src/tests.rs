use crate::{Error, ReadAt, Record, Volume};
use alloc::{vec, vec::Vec};

fn p16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

fn resident(payload: &[u8]) -> Vec<u8> {
    let size = (24 + payload.len() + 7) & !7;
    let mut a = vec![0; size];
    p32(&mut a, 0, 0x80);
    p32(&mut a, 4, size as u32);
    p32(&mut a, 16, payload.len() as u32);
    p16(&mut a, 20, 24);
    a[24..24 + payload.len()].copy_from_slice(payload);
    a
}

fn nonresident(mapping: &[u8], clusters: u64, size: u64, initialized: u64) -> Vec<u8> {
    let len = (64 + mapping.len() + 7) & !7;
    let mut a = vec![0; len];
    p32(&mut a, 0, 0x80);
    p32(&mut a, 4, len as u32);
    a[8] = 1;
    p64(&mut a, 24, clusters - 1);
    p16(&mut a, 32, 64);
    p64(&mut a, 40, clusters * 512);
    p64(&mut a, 48, size);
    p64(&mut a, 56, initialized);
    a[64..64 + mapping.len()].copy_from_slice(mapping);
    a
}

fn record(attr: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..4].copy_from_slice(b"FILE");
    p16(&mut b, 4, 48);
    p16(&mut b, 6, 3);
    p16(&mut b, 16, 7);
    p16(&mut b, 20, 56);
    p16(&mut b, 22, 1);
    p32(&mut b, 24, (56 + attr.len() + 8) as u32);
    p32(&mut b, 28, 1024);
    b[56..56 + attr.len()].copy_from_slice(attr);
    p32(&mut b, 56 + attr.len(), u32::MAX);
    p16(&mut b, 48, 0xcafe);
    for (end, slot) in [(510, 50), (1022, 52)] {
        let value = [b[end], b[end + 1]];
        b[slot..slot + 2].copy_from_slice(&value);
        p16(&mut b, end, 0xcafe);
    }
    b
}

fn image() -> Vec<u8> {
    let mut b = vec![0; 128 * 512];
    b[3..11].copy_from_slice(b"NTFS    ");
    p16(&mut b, 11, 512);
    b[13] = 1;
    p64(&mut b, 40, 128);
    p64(&mut b, 48, 4);
    p64(&mut b, 56, 120);
    b[64] = 246;
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    // MFT is fragmented: four clusters at LCN 4, two more at LCN 20.
    let mft = record(&nonresident(&[0x11, 4, 4, 0x11, 2, 16, 0], 6, 3072, 3072));
    b[2048..3072].copy_from_slice(&mft);
    b[3072..4096].copy_from_slice(&record(&resident(b"hello NTFS")));
    // File 2 fragments go backwards on disk: 60, then 50 (signed delta -10).
    b[10240..11264].copy_from_slice(&record(&nonresident(&[0x11, 1, 60, 0x11, 1, 246, 0], 2, 900, 700)));
    b[60 * 512..61 * 512].fill(b'A');
    b[50 * 512..51 * 512].fill(b'B');
    b
}

#[test]
fn resident_and_fragmented_files_through_fragmented_mft() {
    let b = image();
    let mut v = Volume::open(b.as_slice()).unwrap();
    assert_eq!(v.record_count(), 3);
    assert_eq!(v.record(1).unwrap().sequence(), 7);
    assert_eq!(v.file_size(1), Ok(10));
    let mut out = [0xff; 16];
    assert_eq!(v.read_file(1, 6, &mut out), Ok(4));
    assert_eq!(&out[..4], b"NTFS");
    assert_eq!(&out[4..], &[0xff; 12]);
    assert_eq!(v.read_file(1, u64::MAX, &mut out), Ok(0));
    let mut out = [0xff; 500];
    assert_eq!(v.read_file(2, 500, &mut out), Ok(400));
    assert_eq!(&out[..12], &[b'A'; 12]);
    assert_eq!(&out[12..200], &[b'B'; 188]);
    assert_eq!(&out[200..400], &[0; 200]); // Never leak uninitialized disk contents.
    assert_eq!(&out[400..], &[0xff; 100]);
    assert_eq!(v.file_size(3), Err(Error::NotFound));
}

#[test]
fn sector_fixups_restore_resident_data_and_reject_torn_writes() {
    let payload: Vec<u8> = (0..800).map(|i| (i % 251) as u8).collect();
    let r = record(&resident(&payload));
    let parsed = Record::parse(r.clone()).unwrap();
    let attrs = parsed.attributes().unwrap();
    assert_eq!(&attrs[0].data[24..824], &payload);
    for offset in [510, 511, 1022, 1023] {
        let mut bad = r.clone();
        bad[offset] ^= 1;
        assert!(matches!(Record::parse(bad), Err(Error::Invalid("update sequence mismatch"))));
    }
}

#[test]
fn malformed_records_are_bounded_and_never_panic() {
    let good = record(&resident(b"hello"));
    for end in 0..good.len() {
        assert!(Record::parse(good[..end].to_vec()).is_err());
    }
    for offset in [4, 6, 20, 24, 28, 60, 64, 76] {
        let mut bad = good.clone();
        p32(&mut bad, offset, u32::MAX);
        assert!(Record::parse(bad).is_err(), "offset {offset}");
    }
    let mut bad = good.clone();
    p32(&mut bad, 56, 0x20);
    assert!(matches!(Record::parse(bad), Err(Error::Unsupported("attribute list"))));
    let mut bad = good;
    p16(&mut bad, 22, 0);
    assert!(matches!(Record::parse(bad), Err(Error::NotFound)));
}

#[test]
fn invalid_mapping_pairs_and_feature_flags_are_rejected() {
    for mapping in [
        &[0x11, 0, 60, 0][..],  // zero length
        &[0x19, 1, 60, 0][..],  // length width > 8
        &[0x91, 1, 60, 0][..],  // offset width > 8
        &[0x11, 2, 255, 0][..], // negative initial LCN
        &[0x11, 2, 127, 0][..], // beyond partition
        &[0x11, 1, 60, 0][..],  // insufficient coverage
        &[0x01, 2, 0][..],      // sparse run
    ] {
        let mut b = image();
        b[10240..11264].copy_from_slice(&record(&nonresident(mapping, 2, 900, 900)));
        let mut v = Volume::open(b.as_slice()).unwrap();
        assert!(v.file_size(2).is_err());
    }
    for flags in [1, 0x4000, 0x8000] {
        let mut a = resident(b"hidden");
        p16(&mut a, 12, flags);
        let mut b = image();
        b[3072..4096].copy_from_slice(&record(&a));
        assert!(matches!(Volume::open(b.as_slice()).unwrap().file_size(1), Err(Error::Unsupported(_))));
    }
}

struct Faulty<'a>(&'a [u8]);
impl ReadAt for Faulty<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        if offset >= 50 * 512 {
            return Err(Error::Io);
        }
        self.0.read_exact_at(offset, out)
    }
}

#[test]
fn io_errors_and_mft_bootstrap_corruption_are_not_hidden() {
    let b = image();
    let mut v = Volume::open(Faulty(&b)).unwrap();
    assert_eq!(v.read_file(2, 0, &mut [0; 2]), Err(Error::Io));
    let mut bad = b.clone();
    bad[2048] = 0;
    assert!(Volume::open(bad.as_slice()).is_err());
    let mut bad = b;
    bad[2048 + 56 + 64 + 2] = 8; // mapping no longer points to bootstrap record
    assert!(Volume::open(bad.as_slice()).is_err());
}
