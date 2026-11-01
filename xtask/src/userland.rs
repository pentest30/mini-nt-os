//! `cargo xtask fetch-userland` (02 §9.2, ADR-002): the userland of the
//! pinned ReactOS version.
//!
//! The release archive of ReactOS 0.4.16, `ReactOS-0.4.16-i386.zip`, comes
//! from SourceForge, which publishes its SHA-256; `curl` downloads it (std
//! has no HTTPS client), then its digest is checked. It holds one ISO 9660
//! image, whose system tree (`/reactos`, the `C:\ReactOS` of the live system,
//! its binaries and its `.inf` files) goes to `third_party/reactos/0.4.16/`.
//! Git ignores that directory: the binaries are ReactOS's, under its licences
//! (GNU GPL version 2 and others), and none of them enters the repository.

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::iso9660::Iso;
use crate::sha256::{hex, Sha256};
use crate::{zip, Args, Result, Workspace};

pub const VERSION: &str = "0.4.16";
const ARCHIVE: &str = "ReactOS-0.4.16-i386.zip";
const URL: &str = "https://sourceforge.net/projects/reactos/files/ReactOS/0.4.16/ReactOS-0.4.16-i386.zip/download";
/// As SourceForge publishes it for the archive; the CI caches the archive
/// under it (.github/workflows/ci.yml).
const SHA256: &str = "e5851510cf5b79ef51a76b8155dd5ef7faca1155f44d0a1d41c35b77ece4ce2a";
/// The archive's one entry.
const IMAGE: &str = "ReactOS-0.4.16-i386.iso";
/// The tree taken out of the image, and where it goes.
const TREE: &str = "reactos";
/// Written last, with the archive's SHA-256: the userland is complete.
const STAMP: &str = ".fetched";

/// Where the userland goes.
pub fn dir(ws: &Workspace) -> PathBuf {
    ws.root.join("third_party").join("reactos").join(VERSION)
}

/// `ntdll.dll` of the fetched userland; `None` until `fetch-userland` ran.
pub fn ntdll(ws: &Workspace) -> Option<PathBuf> {
    system32_file(ws, "ntdll.dll")
}

/// The files of `system32` that every boot with the userland gets, with
/// their paths on the boot disk, under `WINDOWS/SYSTEM32` as on the system
/// volume (02 §9.1): ntdll, then the NLS tables (ANSI and OEM code pages,
/// Unicode case table) that each process maps, then `smss.exe`, which the
/// kernel starts with its `test-smss` feature (M4), the SYSTEM hive that
/// ReactOS generated, which the kernel mounts (until `tools/mkhive`,
/// ADR-012), the Win32 subsystem that `smss` starts (`csrss.exe` and its
/// server DLLs, M5), and the [`KNOWN_DLLS`]. `None` until `fetch-userland`
/// ran.
pub fn boot_files(ws: &Workspace) -> Option<Vec<(PathBuf, String)>> {
    [
        ("ntdll.dll", "NTDLL.DLL"),
        ("c_1252.nls", "C_1252.NLS"),
        ("c_437.nls", "C_437.NLS"),
        ("l_intl.nls", "L_INTL.NLS"),
        ("smss.exe", "SMSS.EXE"),
        ("config/system", "CONFIG/SYSTEM"),
        ("csrss.exe", "CSRSS.EXE"),
        ("csrsrv.dll", "CSRSRV.DLL"),
        ("basesrv.dll", "BASESRV.DLL"),
        ("winsrv.dll", "WINSRV.DLL"),
    ]
    .into_iter()
    .map(|(file, name)| (file.to_string(), name.to_ascii_uppercase()))
    .chain(KNOWN_DLLS.iter().map(|dll| (format!("{dll}.dll"), format!("{}.DLL", dll.to_ascii_uppercase()))))
    .map(|(file, name)| system32_file(ws, &file).map(|path| (path, format!("{SYSTEM32}/{name}"))))
    .collect()
}

/// The system directory on the boot disk.
const SYSTEM32: &str = "WINDOWS/SYSTEM32";

/// The `KnownDLLs` of the pinned SYSTEM hive (`Session Manager\KnownDLLs`),
/// without their `.dll`: `smss` opens each one in `DllDirectory`
/// (`%SystemRoot%\system32`) and makes a section of it in `\KnownDlls` (M4).
const KNOWN_DLLS: [&str; 21] = [
    "advapi32", "comdlg32", "gdi32", "imagehlp", "kernel32", "lz32", "msvcrt", "ole32", "oleaut32", "olecli32",
    "olesvr32", "olethk32", "rpcrt4", "setupapi", "shell32", "url", "urlmon", "user32", "version", "wininet",
    "wldap32",
];

/// The file `name` of the fetched `system32`; `None` until `fetch-userland`
/// ran, or without it.
fn system32_file(ws: &Workspace, name: &str) -> Option<PathBuf> {
    let dir = dir(ws);
    let complete = fs::read_to_string(dir.join(STAMP)).is_ok_and(|s| s.trim() == SHA256);
    let file = dir.join(TREE).join("system32").join(name);
    (complete && file.is_file()).then_some(file)
}

/// `fetch-userland [--archive FILE] [--force]`: downloads (or takes FILE),
/// checks and unpacks the pinned archive, unless already done.
pub fn fetch(ws: &Workspace, mut args: Args) -> Result<()> {
    let given = args.value("--archive")?.map(PathBuf::from);
    let force = args.flag("--force");
    args.finish()?;

    let dest = dir(ws);
    if !force && ntdll(ws).is_some() {
        println!("xtask: ReactOS {VERSION} userland already in {}", dest.display());
        return Ok(());
    }
    fs::create_dir_all(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    let _ = fs::remove_file(dest.join(STAMP));

    let archive_path = given.unwrap_or_else(|| dest.join(ARCHIVE));
    let started = Instant::now();
    let mut archive = fs::read(&archive_path).ok().filter(|a| digest(a) == SHA256);
    if archive.is_none() {
        if archive_path != dest.join(ARCHIVE) {
            return Err(format!("{}: missing, or not the pinned archive (SHA-256 {SHA256})", archive_path.display()));
        }
        download(URL, &archive_path)?;
        let downloaded = fs::read(&archive_path).map_err(|e| format!("{}: {e}", archive_path.display()))?;
        let got = digest(&downloaded);
        if got != SHA256 {
            let _ = fs::remove_file(&archive_path);
            return Err(format!("{ARCHIVE}: SHA-256 {got}, expected {SHA256}: download refused"));
        }
        archive = Some(downloaded);
    }
    let archive = archive.expect("checked above");
    println!("xtask: {ARCHIVE}: SHA-256 checked");

    let entries = zip::entries(&archive)?;
    let entry = entries.iter().find(|e| e.name == IMAGE).ok_or_else(|| format!("{ARCHIVE}: no {IMAGE}"))?;
    let image_path = dest.join(format!("{IMAGE}.part"));
    let image = fs::File::create(&image_path).map_err(|e| format!("{}: {e}", image_path.display()))?;
    let mut sink = BufWriter::new(image);
    zip::extract(&archive, entry, &mut sink)?;
    sink.flush().map_err(|e| format!("{}: {e}", image_path.display()))?;
    drop(sink);
    drop(archive);
    println!("xtask: {IMAGE}: {} bytes, CRC-32 checked", entry.size);

    let tree = dest.join(TREE);
    if tree.exists() {
        fs::remove_dir_all(&tree).map_err(|e| format!("{}: {e}", tree.display()))?;
    }
    let image = fs::File::open(&image_path).map_err(|e| format!("{}: {e}", image_path.display()))?;
    let mut iso = Iso::open(std::io::BufReader::new(image))?;
    let root = iso.lookup(TREE)?;
    let (files, bytes) = iso.extract_tree(&root, &tree)?;
    drop(iso);
    fs::remove_file(&image_path).map_err(|e| format!("{}: {e}", image_path.display()))?;

    let ntdll = tree.join("system32").join("ntdll.dll");
    if !ntdll.is_file() {
        return Err(format!("{IMAGE}: no /{TREE}/system32/ntdll.dll"));
    }
    fs::write(dest.join(STAMP), format!("{SHA256}\n")).map_err(|e| format!("{}: {e}", dest.display()))?;
    println!(
        "xtask: ReactOS {VERSION} userland in {}: {files} files, {} MiB, in {:.0} s",
        tree.display(),
        bytes >> 20,
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn digest(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finish())
}

/// Downloads `url` to `to` with curl, through a `.part` file.
fn download(url: &str, to: &Path) -> Result<()> {
    println!("xtask: downloading {url}");
    let part = to.with_extension("part");
    let status = Command::new("curl")
        .args(["--fail", "--location", "--retry", "3", "--proto", "=https", "--proto-redir", "=https", "--output"])
        .arg(&part)
        .arg(url)
        .status()
        .map_err(|e| format!("cannot run curl ({e}): download {url} yourself, then pass it with --archive FILE"))?;
    if !status.success() {
        let _ = fs::remove_file(&part);
        return Err(format!("curl failed ({status}) on {url}"));
    }
    fs::rename(&part, to).map_err(|e| format!("{}: {e}", to.display()))
}
