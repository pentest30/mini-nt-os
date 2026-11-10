//! Independent NTFS fixtures for the read-only kernel scenario; disposable files only.
use crate::{sha256::Sha256, Result};
use std::{fs, io::Read, path::Path, process::Command};
pub fn missing_tool() -> Option<&'static str> {
    ["mkntfs", "ntfscp"].into_iter().find(|tool| Command::new(tool).arg("--help").output().is_err())
}
fn run(tool: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(tool).args(args).output().map_err(|e| format!("{tool}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{tool}: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}
pub fn create(dir: &Path, disk: &Path) -> Result<()> {
    let image = dir.join("ntfs-volume.img");
    let source = dir.join("ntfs-source.bin");
    let image_path = image.to_str().ok_or("NTFS fixture path is not UTF-8")?;
    let source_path = source.to_str().ok_or("NTFS fixture path is not UTF-8")?;
    fs::File::create(&image).and_then(|f| f.set_len(32 * 1024 * 1024)).map_err(|e| e.to_string())?;
    run("mkntfs", &["-F", "-Q", "-s", "512", "-c", "4096", "-L", "MinoData", image_path])?;
    fs::write(&source, b"Mino NTFS read-only\n").map_err(|e| e.to_string())?;
    for name in ["/readme.txt", "/Été.txt", "/\u{e000}-surrogate.txt"] {
        run("ntfscp", &[image_path, source_path, name])?;
    }
    fs::write(&source, (0..131195).map(|n| (n % 251) as u8).collect::<Vec<_>>()).map_err(|e| e.to_string())?;
    run("ntfscp", &[image_path, source_path, "/large.bin"])?;
    // Preserve raw UTF-16 in the fixture: ntfscp cannot accept an unpaired
    // surrogate. Replace only the leading unit in FILE_NAME and $I30; both
    // the placeholder and replacement sort after the other fixture names.
    let mut raw = fs::read(&image).map_err(|e| e.to_string())?;
    let placeholder: Vec<u8> = "\u{e000}-surrogate.txt".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let offsets: Vec<_> = raw
        .windows(placeholder.len())
        .enumerate()
        .filter_map(|(i, bytes)| (bytes == placeholder).then_some(i))
        .collect();
    if offsets.len() != 2 {
        return Err("expected FILE_NAME and root index placeholder".into());
    }
    for at in offsets {
        raw[at..at + 2].copy_from_slice(&0xd800u16.to_le_bytes());
    }
    fs::write(&image, raw).map_err(|e| e.to_string())?;
    crate::partition::create(&image, disk)?;
    fs::remove_file(image).map_err(|e| e.to_string())?;
    fs::remove_file(source).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn digest(path: &Path) -> Result<[u8; 32]> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash.finish())
}
