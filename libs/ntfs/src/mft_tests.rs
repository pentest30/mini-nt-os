use crate::extent_tests::{list, list_entry};
use crate::path_tests::{entry, image, named, put_record, reference, root};
use crate::tests::{nonresident, p16, p64};
use crate::{Error, ReadAt, Volume};
use alloc::{vec, vec::Vec};

fn extent(lowest: u64, last: u64, lcn: u8, id: u16) -> Vec<u8> {
    let mut a = nonresident(&[0x11, (last - lowest + 1) as u8, lcn, 0], 32, 16384, 16384);
    p64(&mut a, 16, lowest);
    p64(&mut a, 24, last);
    p16(&mut a, 14, id);
    a
}

fn extension(b: &mut [u8], number: usize, attrs: &[u8]) {
    put_record(b, number, attrs, false);
    p64(b, 2048 + number * 1024 + 32, reference(0));
}

// Three extents at LCN 4, 80, 40. The original contiguous copy is erased:
// resolving records by boot_lcn + number * record_size cannot work.
fn relocate(b: &mut [u8], first_clusters: usize) {
    let logical = b[2048..2048 + 16384].to_vec();
    b[2048..2048 + 16384].fill(0);
    for (start, end, lcn) in [(0, first_clusters, 4), (first_clusters, 12, 80), (12, 32, 40)] {
        b[lcn * 512..(lcn + end - start) * 512].copy_from_slice(&logical[start * 512..end * 512]);
    }
}

fn split_mft(nonresident_list: bool, middle_owner: usize, last_owner: usize) -> Vec<u8> {
    let mut b = image();
    let mut entries = list_entry(0x80, &[], 0, 0, 0);
    entries.extend(list_entry(0x80, &[], 4, middle_owner as u64, 0));
    entries.extend(list_entry(0x80, &[], 12, last_owner as u64, 0));
    let mut attrs = if nonresident_list {
        b[100 * 512..100 * 512 + entries.len()].copy_from_slice(&entries);
        let mut a = nonresident(&[0x11, 1, 100, 0], 1, entries.len() as u64, entries.len() as u64);
        crate::tests::p32(&mut a, 0, 0x20);
        p16(&mut a, 14, 9);
        a
    } else {
        list(&entries)
    };
    attrs.extend(extent(0, 3, 4, 0));
    put_record(&mut b, 0, &attrs, false);
    extension(&mut b, middle_owner, &extent(4, 11, 80, 0));
    extension(&mut b, last_owner, &extent(12, 31, 40, 0));
    put_record(&mut b, 6, &named(crate::tests::resident(&root(&[entry(6, 8, "Été.txt", false)], None)), 0x90), true);
    relocate(&mut b, 4);
    b
}

#[test]
fn bootstraps_progressively_and_reads_paths_through_split_mft() {
    for nonresident_list in [false, true] {
        // Record 1 reveals record 3, which reveals the final MFT extent.
        let b = split_mft(nonresident_list, 1, 3);
        let mut v = Volume::open(b.as_slice()).unwrap();
        assert_eq!(v.record_count(), 16);
        let mut out = [0xff; 9];
        assert_eq!(v.read_path("/FOLDER/été.txt", 0, &mut out), Ok(6));
        assert_eq!(&out[..6], b"second");
        assert_eq!(&out[6..], &[0xff; 3]);
        assert_eq!(v.file_size(0), Ok(16384));
    }
}

#[test]
fn bootstrap_dependencies_can_be_resolved_out_of_vcn_order() {
    // Record 1 supplies the LAST extent; only that extent makes record 7
    // accessible, which in turn supplies the missing middle extent.
    let b = split_mft(false, 7, 1);
    let mut v = Volume::open(b.as_slice()).unwrap();
    assert_eq!(v.lookup_path("/folder/été.txt").unwrap().record, 8);
}

#[test]
fn reads_file_records_straddling_discontiguous_runs() {
    let mut b = image();
    let mut entries = list_entry(0x80, &[], 0, 0, 0);
    entries.extend(list_entry(0x80, &[], 3, 7, 0));
    entries.extend(list_entry(0x80, &[], 12, 0, 1));
    let mut attrs = list(&entries);
    attrs.extend(extent(0, 2, 4, 0));
    attrs.extend(extent(12, 31, 40, 1));
    put_record(&mut b, 0, &attrs, false);
    extension(&mut b, 7, &extent(3, 11, 80, 0));
    let expected: Vec<u8> = (0..800).map(|n| (n % 251) as u8).collect();
    put_record(&mut b, 1, &crate::tests::resident(&expected), false);
    relocate(&mut b, 3);
    let mut v = Volume::open(b.as_slice()).unwrap();
    let mut out = vec![0; expected.len()];
    assert_eq!(v.read_file(1, 0, &mut out), Ok(800));
    assert_eq!(out, expected);
}

#[test]
fn circular_dependencies_fail_without_guessing_disk_addresses() {
    struct BootstrapOnly<'a>(&'a [u8]);
    impl ReadAt for BootstrapOnly<'_> {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
            assert!(matches!((offset, out.len()), (0, 512) | (2048, 1024)), "unexpected I/O: {offset}");
            self.0.read_exact_at(offset, out)
        }
    }
    let b = split_mft(false, 3, 7);
    assert!(matches!(Volume::open(BootstrapOnly(&b)), Err(Error::Unsupported("unreachable MFT extension"))));
}

#[test]
fn rejects_stale_foreign_torn_and_out_of_range_mft_extensions() {
    for (offset, value) in [(16, 8), (32, reference(2)), (32, 0), (22, 0), (510, 0)] {
        let mut b = split_mft(false, 1, 3);
        if offset == 32 {
            p64(&mut b, 3072 + offset, value);
        } else {
            p16(&mut b, 3072 + offset, value as u16);
        }
        assert!(Volume::open(b.as_slice()).is_err(), "offset {offset}");
    }
    let mut b = split_mft(false, 1, 3);
    p64(&mut b, 2048 + 56 + 24 + 32 + 16, reference(16));
    assert!(matches!(Volume::open(b.as_slice()), Err(Error::Invalid("MFT extension outside stream"))));
}
