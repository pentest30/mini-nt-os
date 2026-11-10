use crate::path_tests::{entry, image, named, put_record, reference, root};
use crate::tests::{nonresident, p16, p32, p64, record, resident};
use crate::{Error, Volume};
use alloc::{vec, vec::Vec};

pub(super) fn list_entry(kind: u32, name: &[u8], lowest: u64, number: u64, id: u16) -> Vec<u8> {
    let mut b = vec![0; (26 + name.len() + 7) & !7];
    let size = b.len();
    p32(&mut b, 0, kind);
    p16(&mut b, 4, size as u16);
    b[6] = (name.len() / 2) as u8;
    b[7] = 26;
    p64(&mut b, 8, lowest);
    p64(&mut b, 16, reference(number));
    p16(&mut b, 24, id);
    b[26..26 + name.len()].copy_from_slice(name);
    b
}
pub(super) fn list(data: &[u8]) -> Vec<u8> {
    let mut a = resident(data);
    p32(&mut a, 0, 0x20);
    p16(&mut a, 14, 9);
    a
}
fn extension(b: &mut [u8], number: usize, base: u64, attrs: &[u8], directory: bool) {
    let mut r = record(attrs);
    p64(&mut r, 32, reference(base));
    if directory {
        p16(&mut r, 22, 3);
    }
    b[2048 + number * 1024..2048 + (number + 1) * 1024].copy_from_slice(&r);
}
fn split_image(nonresident_list: bool) -> Vec<u8> {
    let mut b = image();
    let mut entries = list_entry(0x80, &[], 0, 7, 0);
    entries.extend(list_entry(0x80, &[], 1, 8, 1));
    let mut a = if nonresident_list {
        b[90 * 512..90 * 512 + entries.len()].copy_from_slice(&entries);
        let mut a = nonresident(&[0x11, 1, 90, 0], 1, entries.len() as u64, entries.len() as u64);
        p32(&mut a, 0, 0x20);
        p16(&mut a, 14, 9);
        a
    } else {
        list(&entries)
    };
    let mut first = nonresident(&[0x11, 1, 60, 0], 2, 900, 700);
    p64(&mut first, 24, 0);
    a.extend(first);
    put_record(&mut b, 7, &a, false);
    // The first LCN delta in each extent is absolute (starts at zero).
    let mut second = nonresident(&[0x11, 1, 50, 0], 2, 0, 0);
    p64(&mut second, 16, 1);
    p16(&mut second, 14, 1);
    p64(&mut second, 40, 0);
    extension(&mut b, 8, 7, &second, false);
    b[60 * 512..61 * 512].fill(b'A');
    b[50 * 512..51 * 512].fill(b'B');
    b
}

#[test]
fn reads_across_records_with_resident_and_nonresident_lists() {
    for b in [split_image(false), split_image(true)] {
        let mut v = Volume::open(b.as_slice()).unwrap();
        let mut out = [0xff; 500];
        assert_eq!(v.read_path("/folder/été.txt", 500, &mut out), Ok(400));
        assert_eq!(&out[..12], &[b'A'; 12]);
        assert_eq!(&out[12..200], &[b'B'; 188]);
        assert_eq!(&out[200..400], &[0; 200]);
        assert_eq!(&out[400..], &[0xff; 100]);
        assert!(matches!(v.record(8), Err(Error::Unsupported("extension FILE record"))));
    }
}

#[test]
fn resident_data_and_named_index_can_live_in_extensions() {
    let mut b = image();
    put_record(&mut b, 7, &list(&list_entry(0x80, &[], 0, 8, 0)), false);
    extension(&mut b, 8, 7, &resident(b"moved"), false);
    let mut v = Volume::open(b.as_slice()).unwrap();
    let mut out = [0; 5];
    assert_eq!(v.read_path("folder/été.txt", 0, &mut out), Ok(5));
    assert_eq!(&out, b"moved");
    let mut b = image();
    put_record(&mut b, 6, &list(&list_entry(0x90, b"$\0I\x003\x000\0", 0, 9, 0)), true);
    // The base determines that this is a directory, not the extension flag.
    extension(&mut b, 9, 6, &named(resident(&root(&[entry(6, 7, "Été.txt", false)], None)), 0x90), false);
    assert_eq!(Volume::open(b.as_slice()).unwrap().lookup_path("folder/été.txt").unwrap().record, 7);
}

#[test]
fn rejects_stale_foreign_deleted_and_recursive_extensions() {
    for (offset, value) in [(16, 8u64), (32, reference(6)), (32, 0), (22, 0)] {
        let mut b = split_image(false);
        if offset == 32 {
            p64(&mut b, 2048 + 8 * 1024 + offset, value);
        } else {
            p16(&mut b, 2048 + 8 * 1024 + offset, value as u16);
        }
        assert!(Volume::open(b.as_slice()).unwrap().file_size(7).is_err());
    }
    let mut b = split_image(false);
    extension(&mut b, 8, 7, &list(&list_entry(0x80, &[], 1, 7, 0)), false);
    assert_eq!(Volume::open(b.as_slice()).unwrap().file_size(7), Err(Error::Unsupported("nested attribute list")));
}

#[test]
fn rejects_extent_gaps_overlaps_and_identity_mismatches() {
    for (offset, value) in [(16, 0u64), (16, 2), (24, 2), (0, 0x90), (14, 2)] {
        let mut b = split_image(false);
        let start = 2048 + 8 * 1024 + 56;
        match offset {
            0 => p32(&mut b, start, value as u32),
            14 => p16(&mut b, start + 14, value as u16),
            _ => p64(&mut b, start + offset, value),
        };
        assert!(Volume::open(b.as_slice()).unwrap().file_size(7).is_err());
    }
    // List and actual attribute agree on a gap, but the complete stream must refuse it.
    let mut b = split_image(false);
    p64(&mut b, 2048 + 7 * 1024 + 56 + 24 + 32 + 8, 2);
    p64(&mut b, 2048 + 8 * 1024 + 56 + 16, 2);
    p64(&mut b, 2048 + 8 * 1024 + 56 + 24, 2);
    assert_eq!(Volume::open(b.as_slice()).unwrap().file_size(7), Err(Error::Invalid("extent gap or overlap")));
}

#[test]
fn malformed_duplicate_missing_and_uninitialized_lists_are_refused() {
    for offset in [0, 4, 6, 8, 16, 24] {
        let mut b = split_image(false);
        b[2048 + 7 * 1024 + 56 + 24 + offset] ^= 0xff;
        assert!(Volume::open(b.as_slice()).unwrap().file_size(7).is_err(), "offset {offset}");
    }
    let mut b = image();
    let one = list_entry(0x80, &[], 0, 7, 0);
    let mut entries = one.clone();
    entries.extend(one);
    let mut attrs = list(&entries);
    attrs.extend(resident(b"duplicate"));
    put_record(&mut b, 7, &attrs, false);
    assert_eq!(
        Volume::open(b.as_slice()).unwrap().file_size(7),
        Err(Error::Invalid("duplicate attribute list reference"))
    );
    let mut b = split_image(true);
    p64(&mut b, 2048 + 7 * 1024 + 56 + 56, 0);
    assert_eq!(Volume::open(b.as_slice()).unwrap().file_size(7), Err(Error::Invalid("uninitialized attribute list")));
    let mut b = image();
    put_record(&mut b, 7, &list(&[]), false);
    assert_eq!(Volume::open(b.as_slice()).unwrap().file_size(7), Err(Error::Invalid("empty attribute list")));
}

#[test]
fn index_allocation_and_bitmap_are_resolved_from_extensions() {
    let mut b = crate::path_tests::allocated_image();
    let record = Volume::open(b.as_slice()).unwrap().record(5).unwrap();
    let attrs = record.attributes().unwrap();
    let mut entries = list_entry(0x90, attrs[0].name, 0, 5, 0);
    entries.extend(list_entry(0xa0, attrs[1].name, 0, 8, 0));
    entries.extend(list_entry(0xb0, attrs[2].name, 0, 9, 0));
    let mut base = list(&entries);
    base.extend_from_slice(attrs[0].data);
    put_record(&mut b, 5, &base, true);
    extension(&mut b, 8, 5, attrs[1].data, true);
    extension(&mut b, 9, 5, attrs[2].data, true);
    assert_eq!(Volume::open(b.as_slice()).unwrap().lookup_path("/folder/été.txt").unwrap().record, 7);
}

#[test]
fn mft_with_a_list_and_all_data_in_base_is_supported() {
    let mut b = image();
    let mut attrs = list(&list_entry(0x80, &[], 0, 0, 0));
    attrs.extend(nonresident(&[0x11, 32, 4, 0], 32, 16384, 16384));
    put_record(&mut b, 0, &attrs, false);
    assert_eq!(Volume::open(b.as_slice()).unwrap().lookup_path("/folder/été.txt").unwrap().record, 7);
}
