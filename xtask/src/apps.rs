//! The applications of the M7 bench (`docs/compat/applications.md`, « La
//! liste du M7 ») : each installer is pinned by its official source, its
//! size and its SHA-256. `cargo xtask fetch-apps` downloads them into
//! `third_party/apps/<id>/` (not in Git) and checks them; a scenario with
//! `app = <id>` puts its installer on a larger system disk with the
//! command file of the bench's probe (`tests/native/appbench.c`), which runs
//! the installer silently, then the program it installed, and logs what it
//! sees. `cargo xtask image --apps` (or `--app ID`) puts the installers in
//! `C:\APPS` of an image with the real logon and `explorer`, where a person
//! starts them by hand.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{Args, Result, Workspace};

/// One application of the bench.
pub struct App {
    /// Its name in scenarios (`app = keepass`) and its directory.
    pub id: &'static str,
    /// What the probe prints.
    pub name: &'static str,
    /// The installer's file, as published.
    pub file: &'static str,
    /// Where it is published (followed with curl, HTTPS only).
    pub url: &'static str,
    pub size: u64,
    pub sha256: &'static str,
    /// How the installer is started on `C:` (its path is `C:\APPS\<file>`).
    pub kind: Kind,
    /// The program it installs, which the probe starts afterwards.
    pub program: &'static str,
    /// Free room on the system disk for the installation, in MiB.
    pub free_mib: u32,
    /// How long the installation may take, in seconds.
    pub install_seconds: u32,
    /// How long the probe lets the program run after its first window before
    /// it closes it, in seconds: GIMP queries its 150 plug-ins at its first
    /// start, each a process, behind its "GIMP Startup" window.
    pub program_seconds: u32,
    /// Guest memory, in MiB.
    pub memory_mb: u32,
}

/// The installer's silent mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A Windows Installer package: `msiexec /i … /qn`, with its verbose log.
    Msi,
    /// Nullsoft: `/S`.
    Nsis,
    /// Inno Setup: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, with its log.
    Inno,
    /// SumatraPDF's own installer: `/s`.
    Sumatra,
}

/// Where the installers are on the system disk.
pub const APPS_DIR: &str = "APPS";
/// The command file the probe reads (`C:\APPS\PROBE.TXT`).
pub const PROBE_FILE: &str = "PROBE.TXT";
/// The log the installer writes, when it writes one.
const INSTALL_LOG: &str = r"C:\APPS\INSTALL.LOG";

pub const APPS: [App; 10] = [
    App {
        id: "7zip",
        name: "7-Zip 9.20",
        file: "7z920.msi",
        url: "https://sourceforge.net/projects/sevenzip/files/7-Zip/9.20/7z920.msi/download",
        size: 1_122_816,
        sha256: "fe4807b4698ec89f82de7d85d32deaa4c772fc871537e31fb0fccf4473455cb8",
        kind: Kind::Msi,
        program: r"C:\Program Files\7-Zip\7zFM.exe",
        free_mib: 64,
        install_seconds: 300,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "notepadpp",
        name: "Notepad++ 7.9.2",
        file: "npp.7.9.2.Installer.exe",
        url: "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.9.2/npp.7.9.2.Installer.exe",
        size: 3_853_600,
        sha256: "a797da6e8cebe364becc30d3d5d540897166e7674a0fc8e386fd9593d0838f43",
        kind: Kind::Nsis,
        program: r"C:\Program Files\Notepad++\notepad++.exe",
        free_mib: 64,
        install_seconds: 300,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "keepass",
        name: "KeePass 1.18",
        file: "KeePass-1.18-Setup.exe",
        url: "https://sourceforge.net/projects/keepass/files/KeePass%201.x/1.18/KeePass-1.18-Setup.exe/download",
        size: 1_533_148,
        sha256: "10d63bb8185657893d5ac3cd31f12beb48a5457ac14bd8e93220f5ce21fa03f5",
        kind: Kind::Inno,
        program: r"C:\Program Files\KeePass Password Safe\KeePass.exe",
        free_mib: 64,
        install_seconds: 300,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "winmerge",
        name: "WinMerge 2.12.4",
        file: "WinMerge-2.12.4-Setup.exe",
        url: "https://sourceforge.net/projects/winmerge/files/stable/2.12.4/WinMerge-2.12.4-Setup.exe/download",
        size: 3_212_078,
        sha256: "155896d41247f4cb933d4b24bd67ee8fd02bf2268ca4db189dc8e56b88f263c4",
        kind: Kind::Inno,
        program: r"C:\Program Files\WinMerge\WinMergeU.exe",
        free_mib: 64,
        install_seconds: 300,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "sumatrapdf",
        name: "SumatraPDF 2.5.2",
        file: "SumatraPDF-2.5.2-install.exe",
        url: "https://files.sumatrapdfreader.org/software/sumatrapdf/rel/2.5.2/SumatraPDF-2.5.2-install.exe",
        size: 4_262_896,
        sha256: "d1effcab0de7c5a7d706c35f80cb042c1fbc9e5f64e0d0268a741862ad93dd1a",
        kind: Kind::Sumatra,
        program: r"C:\Program Files\SumatraPDF\SumatraPDF.exe",
        free_mib: 64,
        install_seconds: 300,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "abiword",
        name: "AbiWord 2.4.1",
        file: "abiword-setup-2.4.1.exe",
        url: "https://sourceforge.net/projects/abiword/files/OldFiles/abiword-setup-2.4.1.exe/download",
        size: 5_277_618,
        sha256: "9b7b2ee39dbfd01a72b094aec5574e762cc295f0b974a08df6c8e015d1b91fb5",
        kind: Kind::Nsis,
        program: r"C:\Program Files\AbiSuite2\AbiWord\bin\AbiWord.exe",
        free_mib: 96,
        install_seconds: 300,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "peazip",
        name: "PeaZip 3.9.1",
        file: "peazip-plain-3.9.1.WINDOWS.exe",
        url: "https://sourceforge.net/projects/peazip/files/3.9.1/peazip-plain-3.9.1.WINDOWS.exe/download",
        size: 5_679_767,
        sha256: "ee48b114ec1cd772937a0d1578540b526b99ea87ac16d9212f1f84824727a0a8",
        kind: Kind::Inno,
        program: r"C:\Program Files\PeaZip\peazip.exe",
        free_mib: 96,
        install_seconds: 300,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "devcpp",
        name: "Dev-C++ 4.9.9.2",
        file: "devcpp-4.9.9.2_setup.exe",
        url: "https://sourceforge.net/projects/dev-cpp/files/Binaries/Dev-C%2B%2B%204.9.9.2/devcpp-4.9.9.2_setup.exe/download",
        size: 9_326_468,
        sha256: "98ca778d39ce72d1d8dd8c362a19ff5c63d8b827cd02dfbf139d4d0fd6328c40",
        kind: Kind::Nsis,
        program: r"C:\Dev-Cpp\devcpp.exe",
        free_mib: 192,
        install_seconds: 600,
        program_seconds: 5,
        memory_mb: 256,
    },
    App {
        id: "gimp",
        name: "GIMP 2.6.12",
        file: "gimp-2.6.12-i686-setup-2.exe",
        url: "https://download.gimp.org/pub/gimp/v2.6/windows/gimp-2.6.12-i686-setup-2.exe",
        size: 21_221_232,
        sha256: "9df479d366fb1682800c776c0cdb4d9f69345374f47e226ed004508b92856327",
        kind: Kind::Inno,
        program: r"C:\Program Files\GIMP-2.0\bin\gimp-2.6.exe",
        free_mib: 320,
        install_seconds: 900,
        program_seconds: 600,
        memory_mb: 512,
    },
    App {
        id: "openoffice",
        name: "Apache OpenOffice 4.1.17",
        file: "Apache_OpenOffice_4.1.17_Win_x86_install_en-US.exe",
        url: "https://downloads.apache.org/openoffice/4.1.17/binaries/en-US/Apache_OpenOffice_4.1.17_Win_x86_install_en-US.exe",
        size: 143_243_640,
        sha256: "dd56646e4cb7183c9144b9ee1c9ae1f4d24edbb5a92b04f5d9573ac00f80a992",
        kind: Kind::Nsis,
        program: r"C:\Program Files\OpenOffice 4\program\soffice.exe",
        free_mib: 1024,
        install_seconds: 1500,
        program_seconds: 5,
        memory_mb: 768,
    },
];

/// The application `id` of the bench.
pub fn find(id: &str) -> Option<&'static App> {
    APPS.iter().find(|app| app.id == id)
}

/// The applications `ids` of the bench, in its order; all of them when
/// `ids` is empty. An id the bench does not have is an error.
pub fn select(ids: &[String]) -> Result<Vec<&'static App>> {
    for id in ids {
        find(id).ok_or_else(|| format!("--app {id}: not an application of the bench ({})", ids_list()))?;
    }
    Ok(APPS.iter().filter(|app| ids.is_empty() || ids.iter().any(|id| id == app.id)).collect())
}

/// Among `apps`, those whose installer `fetch-apps` checked, with its path;
/// each other one is reported and left out (`what` says where).
pub fn fetched(ws: &Workspace, apps: &[&'static App], what: &str) -> Vec<(&'static App, PathBuf)> {
    apps.iter()
        .filter_map(|app| match installer(ws, app) {
            Some(path) => Some((*app, path)),
            None => {
                println!(
                    "xtask: {what}: {} skipped, {} is not fetched (cargo xtask fetch-apps --app {})",
                    app.id, app.file, app.id
                );
                None
            }
        })
        .collect()
}

/// Where the installers are downloaded.
pub fn dir(ws: &Workspace) -> PathBuf {
    ws.root.join("third_party").join("apps")
}

/// The stamp `fetch-apps` writes beside an installer it checked: its
/// SHA-256, which spares hashing it again at each scenario.
fn stamp(path: &Path) -> PathBuf {
    let mut name = path.file_name().expect("an installer's file").to_os_string();
    name.push(".sha256");
    path.with_file_name(name)
}

/// The installer of `app`, once `fetch-apps` checked it; `None` before.
pub fn installer(ws: &Workspace, app: &App) -> Option<PathBuf> {
    let path = dir(ws).join(app.id).join(app.file);
    let size = fs::metadata(&path).ok()?.len();
    let stamped = fs::read_to_string(stamp(&path)).ok()?;
    (size == app.size && stamped.trim() == app.sha256).then_some(path)
}

/// Stamps the installer of `app` at `path` as checked.
pub(crate) fn mark_checked(app: &App, path: &Path) -> Result<()> {
    fs::write(stamp(path), format!("{}\n", app.sha256)).map_err(|e| format!("{}: {e}", path.display()))
}

/// Checks `bytes` against `app`: its size, then its SHA-256.
pub fn check(app: &App, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 != app.size {
        return Err(format!("{}: {} bytes, expected {}", app.file, bytes.len(), app.size));
    }
    let got = crate::userland::digest(bytes);
    if got != app.sha256 {
        return Err(format!("{}: SHA-256 {got}, expected {}", app.file, app.sha256));
    }
    Ok(())
}

/// `cargo xtask fetch-apps [--app ID]`: downloads each installer missing,
/// checks a file already there (one copied by hand counts once checked),
/// and stamps it.
pub fn fetch(ws: &Workspace, mut args: Args) -> Result<()> {
    let only = args.values("--app")?;
    args.finish()?;
    let mut failed = Vec::new();
    for app in select(&only)? {
        if installer(ws, app).is_some() {
            println!("xtask: {}: {} already checked", app.id, app.file);
            continue;
        }
        let folder = dir(ws).join(app.id);
        fs::create_dir_all(&folder).map_err(|e| format!("{}: {e}", folder.display()))?;
        let path = folder.join(app.file);
        let mut checked = fs::read(&path).ok().map(|bytes| check(app, &bytes));
        if !matches!(checked, Some(Ok(()))) {
            if let Some(Err(e)) = &checked {
                println!("xtask: {e}: downloading it again");
            }
            let _ = fs::remove_file(&path);
            checked = Some(crate::userland::download(app.url, &path).and_then(|()| {
                let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                check(app, &bytes)
            }));
        }
        match checked.expect("set above") {
            Ok(()) => {
                mark_checked(app, &path)?;
                println!("xtask: {}: {} checked (SHA-256)", app.id, app.file);
            }
            Err(e) => {
                let _ = fs::remove_file(&path);
                eprintln!("xtask: {}: {e}", app.id);
                failed.push(app.id);
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("not fetched: {}", failed.join(", ")))
    }
}

fn ids_list() -> String {
    APPS.iter().map(|app| app.id).collect::<Vec<_>>().join(", ")
}

/// The command file of the probe for `app`: one `key=value` per line, which
/// `tests/native/appbench.c` reads from `C:\APPS\PROBE.TXT`.
pub fn probe_commands(app: &App) -> String {
    let installer = format!(r"C:\{APPS_DIR}\{}", app.file);
    let (install, log) = match app.kind {
        Kind::Msi => (format!(r#""C:\WINDOWS\SYSTEM32\MSIEXEC.EXE" /i {installer} /qn /l*v {INSTALL_LOG}"#), true),
        Kind::Nsis => (format!(r#""{installer}" /S"#), false),
        Kind::Inno => (format!(r#""{installer}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="{INSTALL_LOG}""#), true),
        Kind::Sumatra => (format!(r#""{installer}" /s"#), false),
    };
    let mut text = format!("name={}\r\ninstall={install}\r\n", app.name);
    if log {
        text.push_str(&format!("log={INSTALL_LOG}\r\n"));
    }
    // A silent NSIS that fails says nothing: the probe runs it visible.
    if app.kind == Kind::Nsis {
        text.push_str(&format!("visible=\"{installer}\"\r\n"));
    }
    text.push_str(&format!(
        "timeout={}\r\nprogram={}\r\nsettle={}\r\n",
        app.install_seconds, app.program, app.program_seconds
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_application_is_pinned_once() {
        for (i, app) in APPS.iter().enumerate() {
            assert_eq!(app.sha256.len(), 64, "{}", app.id);
            assert!(app.sha256.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{}", app.id);
            assert!(app.url.starts_with("https://"), "{}: HTTPS only", app.id);
            assert!(app.program.starts_with(r"C:\"), "{}", app.id);
            assert!(app.size > 0 && app.free_mib > 0 && app.install_seconds > 0, "{}", app.id);
            assert!(APPS[i + 1..].iter().all(|other| other.id != app.id && other.sha256 != app.sha256), "{}", app.id);
        }
        assert_eq!(find("keepass").map(|app| app.file), Some("KeePass-1.18-Setup.exe"));
        assert!(find("KeePass").is_none(), "ids are exact");
    }

    #[test]
    fn the_applications_are_selected_by_id_in_the_order_of_the_bench() {
        let ids = |apps: Vec<&App>| apps.iter().map(|app| app.id).collect::<Vec<_>>();
        assert_eq!(select(&[]).unwrap().len(), APPS.len(), "all of them");
        let some = select(&["openoffice".into(), "7zip".into()]).unwrap();
        assert_eq!(ids(some), ["7zip", "openoffice"]);
        assert!(select(&["word".into()]).err().unwrap().contains("--app word: not an application of the bench"));
    }

    #[test]
    fn an_installer_is_checked_by_size_then_digest() {
        let app =
            App { size: 3, sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", ..APPS[0] };
        assert!(check(&app, b"abc").is_ok(), "the SHA-256 of `abc`");
        assert!(check(&app, b"abd").unwrap_err().contains("SHA-256"));
        assert!(check(&app, b"abcd").unwrap_err().contains("4 bytes, expected 3"));
    }

    #[test]
    fn the_probe_runs_each_kind_of_installer_silently() {
        let msi = probe_commands(find("7zip").unwrap());
        assert!(msi.contains(
            r#"install="C:\WINDOWS\SYSTEM32\MSIEXEC.EXE" /i C:\APPS\7z920.msi /qn /l*v C:\APPS\INSTALL.LOG"#
        ));
        assert!(msi.contains(r"log=C:\APPS\INSTALL.LOG"));
        let nsis = probe_commands(find("notepadpp").unwrap());
        assert!(nsis.contains(r#"install="C:\APPS\npp.7.9.2.Installer.exe" /S"#) && !nsis.contains("log="));
        assert!(nsis.contains("visible=\"C:\\APPS\\npp.7.9.2.Installer.exe\"\r\n"), "a failure shown");
        assert!(!msi.contains("visible="));
        let inno = probe_commands(find("keepass").unwrap());
        assert!(inno.contains(r#"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="C:\APPS\INSTALL.LOG""#));
        assert!(inno
            .contains("timeout=300\r\nprogram=C:\\Program Files\\KeePass Password Safe\\KeePass.exe\r\nsettle=5\r\n"));
        assert!(probe_commands(find("sumatrapdf").unwrap()).contains(r#"-install.exe" /s"#));
    }

    #[test]
    fn a_stamped_installer_of_the_right_size_is_ready() {
        let root = std::env::temp_dir().join(format!("mino-apps-{}", std::process::id()));
        let ws = Workspace { root: root.clone(), target: root.join("target") };
        let app = find("keepass").unwrap();
        let folder = dir(&ws).join(app.id);
        fs::create_dir_all(&folder).unwrap();
        let path = folder.join(app.file);
        fs::write(&path, vec![0u8; app.size as usize]).unwrap();
        assert!(installer(&ws, app).is_none(), "not checked yet");
        mark_checked(app, &path).unwrap();
        assert_eq!(installer(&ws, app), Some(path.clone()));
        fs::write(&path, b"short").unwrap();
        assert!(installer(&ws, app).is_none(), "the size changed");
        fs::remove_dir_all(&root).unwrap();
    }
}
