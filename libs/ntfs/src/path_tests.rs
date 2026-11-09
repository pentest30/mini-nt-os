use crate::tests::{nonresident, p16, p32, p64, record, resident};
use crate::{Error, FileReference, Volume};
use alloc::{vec, vec::Vec};

pub(super) fn reference(n: u64) -> u64 {
    n | (7 << 48)
}
pub(super) fn entry(parent: u64, target: u64, name: &str, directory: bool) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let key_len = 66 + units.len() * 2;
    let len = (16 + key_len + 7) & !7;
    let mut b = vec![0; len];
    p64(&mut b, 0, reference(target));
    p16(&mut b, 8, len as u16);
    p16(&mut b, 10, key_len as u16);
    p64(&mut b, 16, reference(parent));
    if directory {
        p32(&mut b, 72, 0x1000_0000);
    }
    b[80] = units.len() as u8;
    b[81] = 1;
    for (i, unit) in units.into_iter().enumerate() {
        p16(&mut b, 82 + i * 2, unit);
    }
    b
}
fn node(entries: &[Vec<u8>], child: Option<u64>) -> Vec<u8> {
    let mut b = vec![0; 16];
    p32(&mut b, 0, 16);
    for e in entries {
        b.extend_from_slice(e);
    }
    let mut end = vec![0; if child.is_some() { 24 } else { 16 }];
    let end_len = end.len();
    p16(&mut end, 8, end_len as u16);
    p16(&mut end, 12, if child.is_some() { 3 } else { 2 });
    if let Some(vcn) = child {
        p64(&mut end, 16, vcn);
        b[12] = 1;
    }
    b.extend_from_slice(&end);
    let len = b.len();
    p32(&mut b, 4, len as u32);
    p32(&mut b, 8, len as u32);
    b
}
pub(super) fn root(entries: &[Vec<u8>], child: Option<u64>) -> Vec<u8> {
    let mut b = vec![0; 16];
    p32(&mut b, 0, 0x30);
    p32(&mut b, 4, 1);
    p32(&mut b, 8, 512);
    b[12] = 1;
    b.extend_from_slice(&node(entries, child));
    b
}
pub(super) fn named(mut a: Vec<u8>, kind: u32) -> Vec<u8> {
    let offset = if a[8] == 0 { 20 } else { 32 };
    let header = if a[8] == 0 { 24 } else { 64 };
    a.splice(header..header, b"$\0I\x003\x000\0".iter().copied());
    let len = a.len();
    p32(&mut a, 0, kind);
    p32(&mut a, 4, len as u32);
    a[9] = 4;
    p16(&mut a, 10, header as u16);
    p16(&mut a, offset, (header + 8) as u16);
    a
}
pub(super) fn put_record(b: &mut [u8], number: usize, attr: &[u8], directory: bool) {
    let mut r = record(attr);
    if directory {
        p16(&mut r, 22, 3);
    }
    b[2048 + number * 1024..2048 + (number + 1) * 1024].copy_from_slice(&r);
}
pub(super) fn image() -> Vec<u8> {
    let mut b = vec![0; 512 * 512];
    b[3..11].copy_from_slice(b"NTFS    ");
    p16(&mut b, 11, 512);
    b[13] = 1;
    p64(&mut b, 40, 512);
    p64(&mut b, 48, 4);
    p64(&mut b, 56, 500);
    b[64] = 246;
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    put_record(&mut b, 0, &nonresident(&[0x11, 32, 4, 0], 32, 16384, 16384), false);
    put_record(&mut b, 5, &named(resident(&root(&[entry(5, 6, "Folder", true)], None)), 0x90), true);
    put_record(&mut b, 6, &named(resident(&root(&[entry(6, 7, "Été.txt", false)], None)), 0x90), true);
    put_record(&mut b, 7, &resident(b"content"), false);
    put_record(&mut b, 8, &resident(b"second"), false);
    put_record(&mut b, 10, &nonresident(&[0x22, 0, 1, 128, 0, 0], 256, 131072, 131072), false);
    for unit in 0..65536 {
        p16(&mut b, 128 * 512 + unit * 2, unit as u16);
    }
    for lower in b'a'..=b'z' {
        p16(&mut b, 128 * 512 + lower as usize * 2, u16::from(lower - 32));
    }
    p16(&mut b, 128 * 512 + 0xe9 * 2, 0xc9);
    b
}
fn indx(n: Vec<u8>) -> Vec<u8> {
    let mut b = vec![0; 512];
    b[..4].copy_from_slice(b"INDX");
    p16(&mut b, 4, 40);
    p16(&mut b, 6, 2);
    // Add eight bytes for USA between INDEX_HEADER and entries.
    b[24..40].copy_from_slice(&n[..16]);
    b[48..48 + n.len() - 16].copy_from_slice(&n[16..]);
    p32(&mut b, 24, 24);
    p32(&mut b, 28, (n.len() + 8) as u32);
    p32(&mut b, 32, 488);
    p16(&mut b, 40, 0xcafe);
    p16(&mut b, 510, 0xcafe);
    b
}
fn allocated_image() -> Vec<u8> {
    let mut b = image();
    let mut attrs = named(resident(&root(&[], Some(0))), 0x90);
    attrs.extend(named(nonresident(&[0x11, 1, 64, 0], 1, 512, 512), 0xa0));
    attrs.extend(named(resident(&[1]), 0xb0));
    put_record(&mut b, 5, &attrs, true);
    b[64 * 512..65 * 512].copy_from_slice(&indx(node(&[entry(5, 6, "Folder", true)], None)));
    b
}

#[test]
fn nested_paths_volume_upcase_and_normalization() {
    for b in [image(), allocated_image()] {
        let mut v = Volume::open(b.as_slice()).unwrap();
        assert_eq!(v.lookup_path("/folder/été.TXT").unwrap().record, 7);
        assert_eq!(v.lookup_path("\\FOLDER\\.\\ÉTÉ.txt").unwrap().record, 7);
        assert_eq!(v.lookup_path("/folder/../Folder/").unwrap().record, 6);
        assert_eq!(v.lookup_path("/").unwrap().record, 5);
        let mut out = [0; 7];
        assert_eq!(v.read_path("folder/été.txt", 0, &mut out), Ok(7));
        assert_eq!(&out, b"content");
        assert_eq!(v.lookup_path("missing"), Err(Error::NotFound));
        assert!(v.lookup_path("/folder/été.txt/").is_err());
        assert!(v.lookup_path("/folder/été.txt/..").is_err());
        assert!(v.lookup_path("/../folder").is_err());
        assert!(v.lookup_path("C:\\folder").is_err());
        assert!(v.lookup_path("/folder/a:stream").is_err());
        assert!(v.lookup_path("bad\0name").is_err());
        assert!(v.lookup_path(&"./".repeat(65)).is_err());
        assert!(v.lookup_path(&"a".repeat(4097)).is_err());
    }
}

#[test]
fn stale_references_wrong_parent_and_ambiguous_names() {
    let mut b = image();
    p16(&mut b, 2048 + 7 * 1024 + 16, 8);
    assert_eq!(
        Volume::open(b.as_slice()).unwrap().lookup_path("folder/été.txt"),
        Err(Error::Invalid("stale file reference"))
    );
    let mut b = image();
    put_record(&mut b, 6, &named(resident(&root(&[entry(5, 7, "wrong", false)], None)), 0x90), true);
    assert!(Volume::open(b.as_slice()).unwrap().read_directory(6).is_err());
    let mut b = image();
    put_record(
        &mut b,
        6,
        &named(resident(&root(&[entry(6, 7, "same", false), entry(6, 8, "SAME", false)], None)), 0x90),
        true,
    );
    assert_eq!(
        Volume::open(b.as_slice()).unwrap().lookup_path("folder/same"),
        Err(Error::Unsupported("ambiguous case-insensitive name"))
    );
    assert!(Volume::open(b.as_slice()).unwrap().referenced_record(FileReference { record: 7, sequence: 0 }).is_err());
}

#[test]
fn rejects_indx_corruption_and_cycles() {
    let good = allocated_image();
    for offset in [0, 4, 6, 16, 24, 28, 32, 40, 510, 511, 48 + 8, 48 + 10, 48 + 12, 48 + 16] {
        let mut b = good.clone();
        b[64 * 512 + offset] ^= 0xff;
        assert!(Volume::open(b.as_slice()).unwrap().read_directory(5).is_err(), "offset {offset}");
    }
    let mut b = good.clone();
    b[64 * 512..65 * 512].copy_from_slice(&indx(node(&[], Some(0))));
    assert_eq!(
        Volume::open(b.as_slice()).unwrap().read_directory(5),
        Err(Error::Invalid("index cycle or shared child"))
    );
    let mut b = good;
    let mut attrs = named(resident(&root(&[], Some(0))), 0x90);
    attrs.extend(named(nonresident(&[0x11, 1, 64, 0], 1, 512, 512), 0xa0));
    attrs.extend(named(resident(&[0]), 0xb0));
    put_record(&mut b, 5, &attrs, true);
    assert_eq!(Volume::open(b.as_slice()).unwrap().read_directory(5), Err(Error::Invalid("unallocated index block")));
}

#[test]
fn upcase_corruption_is_not_replaced_with_host_casing() {
    let mut b = image();
    // a -> b -> c violates idempotence.
    p16(&mut b, 128 * 512 + 97 * 2, 98);
    p16(&mut b, 128 * 512 + 98 * 2, 99);
    assert_eq!(Volume::open(b.as_slice()).unwrap().lookup_path("folder"), Err(Error::Invalid("UpCase not idempotent")));
    let mut b = image();
    put_record(&mut b, 10, &resident(b"bad"), false);
    assert_eq!(Volume::open(b.as_slice()).unwrap().lookup_path("folder"), Err(Error::Invalid("UpCase size")));
}

#[test]
fn dangling_children_missing_bitmap_and_duplicate_index_are_refused() {
    for child in [1, u64::MAX] {
        let mut b = allocated_image();
        let mut attrs = named(resident(&root(&[], Some(child))), 0x90);
        attrs.extend(named(nonresident(&[0x11, 1, 64, 0], 1, 512, 512), 0xa0));
        attrs.extend(named(resident(&[0xff]), 0xb0));
        put_record(&mut b, 5, &attrs, true);
        assert!(Volume::open(b.as_slice()).unwrap().read_directory(5).is_err());
    }
    let mut b = allocated_image();
    let mut attrs = named(resident(&root(&[], Some(0))), 0x90);
    attrs.extend(named(nonresident(&[0x11, 1, 64, 0], 1, 512, 512), 0xa0));
    put_record(&mut b, 5, &attrs, true);
    assert_eq!(Volume::open(b.as_slice()).unwrap().read_directory(5), Err(Error::Invalid("index BITMAP missing")));
    let mut attrs = named(resident(&root(&[], None)), 0x90);
    attrs.extend_from_slice(&attrs.clone());
    put_record(&mut b, 5, &attrs, true);
    assert_eq!(
        Volume::open(b.as_slice()).unwrap().read_directory(5),
        Err(Error::Unsupported("multiple index extents"))
    );
}

#[test]
fn empty_directory_and_deleted_target() {
    let mut b = image();
    put_record(&mut b, 6, &named(resident(&root(&[], None)), 0x90), true);
    let mut v = Volume::open(b.as_slice()).unwrap();
    assert!(v.read_directory(6).unwrap().is_empty());
    assert_eq!(v.lookup_path("folder/missing"), Err(Error::NotFound));
    assert_eq!(v.read_directory(7), Err(Error::Invalid("not a directory")));
    let mut b = image();
    p16(&mut b, 2048 + 7 * 1024 + 22, 0);
    assert_eq!(Volume::open(b.as_slice()).unwrap().lookup_path("folder/été.txt"), Err(Error::NotFound));
}

#[test]
fn indx_truncation_and_byte_mutations_never_panic() {
    let good = indx(node(&[entry(5, 6, "Folder", true)], None));
    let parent = FileReference { record: 5, sequence: 7 };
    for end in 0..good.len() {
        assert!(crate::index::block(&mut good[..end].to_vec(), 0, parent).is_err());
    }
    for offset in 0..good.len() {
        let mut bad = good.clone();
        bad[offset] ^= 0xff;
        let _ = crate::index::block(&mut bad, 0, parent);
    }
}
