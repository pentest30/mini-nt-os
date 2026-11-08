//! Cross-check against independently generated ntfs-3g images. No mount, root,
//! network or Microsoft resource is needed. Run explicitly with --ignored.
use ntfs::{Error, ReadAt, Volume};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::Command;

struct Device {
    file: File,
    size: u64,
}
impl ReadAt for Device {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        if offset.checked_add(out.len() as u64).ok_or(Error::Bounds)? > self.size {
            return Err(Error::Bounds);
        }
        self.file.seek(SeekFrom::Start(offset)).map_err(|_| Error::Io)?;
        self.file.read_exact(out).map_err(|_| Error::Io)
    }
}
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(tool: &str, args: &[&str]) -> Vec<u8> {
    let output = Command::new(tool).args(args).output().unwrap_or_else(|e| panic!("{tool}: {e}"));
    assert!(output.status.success(), "{tool}: {}", String::from_utf8_lossy(&output.stderr));
    output.stdout
}

#[test]
#[ignore = "requires mkntfs, ntfscp, ntfsls and ntfscat on PATH"]
fn ntfs3g_files_match_at_two_cluster_sizes() {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = Scratch(std::env::temp_dir().join(format!("mino-ntfs-{}-{stamp}", std::process::id())));
    fs::create_dir(&dir.0).unwrap();
    for cluster in ["512", "4096"] {
        let path = dir.0.join(format!("volume-{cluster}.img"));
        let image = File::create_new(&path).unwrap();
        image.set_len(32 * 1024 * 1024).unwrap();
        drop(image);
        let image_path = path.to_str().unwrap();
        run("mkntfs", &["-F", "-Q", "-s", "512", "-c", cluster, image_path]);
        let files = [
            ("small.txt", b"Mino NTFS read-only validation\n".to_vec()),
            ("large.bin", (0..131_195).map(|n| (n % 251) as u8).collect()),
        ];
        for (name, expected) in &files {
            let source = dir.0.join(name);
            fs::write(&source, expected).unwrap();
            run("ntfscp", &[image_path, source.to_str().unwrap(), &format!("/{name}")]);
        }
        let listing = String::from_utf8(run("ntfsls", &["-i", image_path])).unwrap();
        let file = File::open(&path).unwrap();
        let mut volume = Volume::open(Device { size: file.metadata().unwrap().len(), file }).unwrap();
        let entries = volume.read_directory(5).unwrap();
        for (name, expected) in files {
            let number: u64 = listing
                .lines()
                .find_map(|line| {
                    let mut parts = line.split_whitespace();
                    let number = parts.next()?;
                    (parts.next()? == name).then(|| number.parse().unwrap())
                })
                .unwrap_or_else(|| panic!("{name} not in listing: {listing}"));
            assert!(entries
                .iter()
                .any(|e| e.reference.record == number && e.name == name.encode_utf16().collect::<Vec<_>>()));
            assert_eq!(volume.file_size(number).unwrap(), expected.len() as u64);
            let mut got = vec![0xff; expected.len() + 11];
            assert_eq!(volume.read_file(number, 0, &mut got).unwrap(), expected.len());
            assert_eq!(&got[..expected.len()], &expected);
            assert_eq!(&got[expected.len()..], &[0xff; 11]);
            assert_eq!(run("ntfscat", &[image_path, &format!("/{name}")]), expected);
        }
    }
}
