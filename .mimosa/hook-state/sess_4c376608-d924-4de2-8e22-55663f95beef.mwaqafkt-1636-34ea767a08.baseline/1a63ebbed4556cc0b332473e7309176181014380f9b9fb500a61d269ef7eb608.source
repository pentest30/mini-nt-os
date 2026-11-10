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
/// Unicode case table) that each process maps, and that of code page 20127
/// (US-ASCII), which the C locale of `msvcrt` asks for (`GetCPInfo`, through
/// the file the SYSTEM hive names in `Nls\CodePage`), then `smss.exe`, which the
/// kernel starts with its `test-smss` feature (M4), the SYSTEM hive that
/// ReactOS generated, which the kernel mounts (until `tools/mkhive`,
/// ADR-012), the Win32 subsystem that `smss` starts (`csrss.exe` and its
/// server DLLs, M5), the language pack that `gdi32` loads when it starts
/// (`lpk.dll`, GdiInitializeLanguagePack), the [`KNOWN_DLLS`], the [`FONTS`]
/// of win32k in `WINDOWS/FONTS`, and then every
/// DLL these programs
/// and DLLs import, directly or not ([`import_closure`]): the loader of ntdll
/// maps each import, and some of these have long names
/// (`advapi32_vista.dll`). `None` until `fetch-userland` ran.
pub fn boot_files(ws: &Workspace) -> Option<Vec<(PathBuf, String)>> {
    let mut files: Vec<String> = [
        "ntdll.dll",
        "c_1252.nls",
        "c_437.nls",
        "l_intl.nls",
        "c_20127.nls",
        "smss.exe",
        "config/system",
        "config/software",
        "csrss.exe",
        "csrsrv.dll",
        "basesrv.dll",
        "winsrv.dll",
        "lpk.dll",
        "winlogon.exe",
        "kbdus.dll",
        "cmd.exe",
        "taskmgr.exe",
        // comctl32's delay-loaded DLLs (OpenThemeData, PlaySound): GNU ld
        // leaves the PE's delay-import directory empty, so the closure
        // below cannot find them; without uxtheme, the delay-load helper
        // raises an exception in the WM_CREATE of the ListView, the
        // header, the tab control...
        "uxtheme.dll",
        "winmm.dll",
    ]
    .into_iter()
    .map(String::from)
    .chain(KNOWN_DLLS.iter().map(|dll| format!("{dll}.dll")))
    .collect();
    let (imported, missing) = import_closure(&files, |file| {
        let path = system32_file(ws, file)?;
        let bytes = fs::read(&path).ok()?;
        let pe = pe::Pe32::parse(&bytes).ok()?;
        Some(pe.imports().map(|import| import.dll_name().to_ascii_lowercase()).collect())
    });
    for dll in &missing {
        eprintln!("xtask: {dll}, imported on the boot disk, is not in the userland's system32");
    }
    files.extend(imported);
    let system32 = files
        .into_iter()
        .map(|file| system32_file(ws, &file).map(|path| (path, format!("{SYSTEM32}/{}", file.to_ascii_uppercase()))));
    let fonts = FONTS
        .iter()
        .map(|font| fonts_file(ws, font).map(|path| (path, format!("{FONTS_DIR}/{}", font.to_ascii_uppercase()))));
    system32.chain(fonts).collect()
}

/// The fonts directory on the boot disk (`\SystemRoot\Fonts`).
const FONTS_DIR: &str = "WINDOWS/FONTS";

/// The fonts of the boot disk, which win32k installs (ADR-013,
/// `win32k::font`): Tahoma and Tahoma Bold for the captions, Marlett for the
/// caption buttons; VGA (the default font of the console's code page 437),
/// Lucida Console (FontSubstitutes' Terminal) and Courier New (Courier) for
/// consrv.
const FONTS: [&str; 6] = ["tahoma.ttf", "tahomabd.ttf", "Marlett.ttf", "UniVGA16.ttf", "lucon.ttf", "cour.ttf"];

/// The font `name` of the fetched userland's `Fonts`; `None` until
/// `fetch-userland` ran, or without it.
fn fonts_file(ws: &Workspace, name: &str) -> Option<PathBuf> {
    let file = system32_file(ws, "ntdll.dll")?.parent()?.parent()?.join("Fonts").join(name);
    file.is_file().then_some(file)
}

/// The DLLs that the programs and DLLs among `files` (`.exe`, `.dll`)
/// import, directly or not, and that are not among them, in the order they
/// are found; then those of them `imports_of` cannot read (missing). Names
/// compare without case; `imports_of(name)` gives the imports of a file of
/// `system32`. Delay-load imports are not followed: the loader maps them
/// only when they are called (none is in this closure).
pub fn import_closure(
    files: &[String],
    imports_of: impl Fn(&str) -> Option<Vec<String>>,
) -> (Vec<String>, Vec<String>) {
    let is_image = |file: &str| file.ends_with(".exe") || file.ends_with(".dll");
    let mut known: std::collections::BTreeSet<String> = files.iter().map(|file| file.to_ascii_lowercase()).collect();
    let mut pending: Vec<String> = files.iter().filter(|file| is_image(file)).cloned().collect();
    let (mut added, mut missing) = (Vec::new(), Vec::new());
    let mut at = 0;
    while at < pending.len() {
        let file = pending[at].clone();
        at += 1;
        let Some(imports) = imports_of(&file) else {
            missing.push(file);
            continue;
        };
        for dll in imports {
            let dll = dll.to_ascii_lowercase();
            if known.insert(dll.clone()) {
                added.push(dll.clone());
                pending.push(dll);
            }
        }
    }
    added.retain(|dll| !missing.contains(dll));
    (added, missing)
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

#[cfg(test)]
mod closure_tests {
    use super::import_closure;

    fn imports(file: &str) -> Option<Vec<String>> {
        let list: &[&str] = match file {
            "csrss.exe" => &["ntdll.dll", "CSRSRV.dll"],
            "csrsrv.dll" => &["ntdll.dll"],
            "winsrv.dll" => &["user32.dll", "kernel32.dll"],
            "user32.dll" => &["advapi32.dll", "gdi32.dll"],
            "advapi32.dll" => &["rpcrt4.dll"],
            "rpcrt4.dll" => &["advapi32_vista.dll", "ws2_32.dll", "advapi32.dll"],
            "ws2_32.dll" => &["gone.dll"],
            "gone.dll" => return None,
            _ => &[],
        };
        Some(list.iter().map(|dll| dll.to_string()).collect())
    }

    #[test]
    fn the_closure_follows_imports_to_the_end() {
        let files: Vec<String> =
            ["ntdll.dll", "c_1252.nls", "csrss.exe", "csrsrv.dll", "winsrv.dll", "user32.dll", "kernel32.dll"]
                .iter()
                .map(|f| f.to_string())
                .collect();
        let (added, missing) = import_closure(&files, imports);
        assert_eq!(added, ["advapi32.dll", "gdi32.dll", "rpcrt4.dll", "advapi32_vista.dll", "ws2_32.dll"]);
        assert_eq!(missing, ["gone.dll"], "imported but not in system32");
    }

    #[test]
    fn a_file_without_imports_adds_nothing() {
        let (added, missing) = import_closure(&["config/system".to_string()], |_| panic!("not an image"));
        assert!(added.is_empty() && missing.is_empty());
    }
}
