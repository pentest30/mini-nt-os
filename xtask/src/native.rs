//! The native test programs of `tests/native/` (spike S1, M3): C programs of
//! the NATIVE subsystem, compiled with MinGW (`i686-w64-mingw32-gcc`) and
//! linked to the pinned ReactOS's ntdll only, through an import library that
//! `dlltool` makes from `tests/native/ntdll.def`. They go to the boot disk of
//! the scenarios that `require = native`, where the kernel runs them
//! (`ntoskrnl::userland::run_boot_programs`).
//!
//! Without MinGW, nothing is built and those scenarios are skipped; the CI
//! installs it (`gcc-mingw-w64-i686`).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, Workspace};

const GCC: &str = "i686-w64-mingw32-gcc";
const DLLTOOL: &str = "i686-w64-mingw32-dlltool";

/// Each program: its source in `tests/native/`, and its name on the boot
/// disk, which the kernel looks for.
const PROGRAMS: &[(&str, &str)] = &[("s1hello.c", "S1HELLO.EXE")];

/// No C runtime, no stack protector, no unwind tables: ntdll and the code
/// itself, entered at `NtProcessStartup(PPEB)` (stdcall, 4 bytes).
const FLAGS: &[&str] = &[
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-ffreestanding",
    "-nostdlib",
    "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    "-s",
    "-Wl,--subsystem,native",
    "-Wl,-e,_NtProcessStartup@4",
];

/// Whether MinGW is installed.
pub fn available() -> bool {
    Command::new(GCC).arg("--version").output().is_ok_and(|o| o.status.success())
}

/// Builds the programs into `target/xtask/native/`; returns them for the
/// FAT ramdisk (`HOST:FAT_NAME`), or `None` without MinGW.
pub fn build(ws: &Workspace) -> Result<Option<Vec<String>>> {
    if !available() {
        return Ok(None);
    }
    let sources = ws.root.join("tests").join("native");
    let out = ws.target.join("xtask").join("native");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let library = out.join("libntdll.a");
    run(Command::new(DLLTOOL).arg("--kill-at").arg("-d").arg(sources.join("ntdll.def")).arg("-l").arg(&library))?;
    let mut files = Vec::new();
    for &(source, name) in PROGRAMS {
        let image = out.join(name);
        run(Command::new(GCC).args(FLAGS).arg("-o").arg(&image).arg(sources.join(source)).arg(&library))?;
        files.push(format!("{}:{name}", image.display()));
    }
    Ok(Some(files))
}

/// Runs `command`; its failure is an error.
fn run(command: &mut Command) -> Result<()> {
    let program = PathBuf::from(command.get_program());
    let status = command.status().map_err(|e| format!("{}: {e}", program.display()))?;
    if !status.success() {
        return Err(format!("{} failed ({status})", display(&program)));
    }
    Ok(())
}

fn display(program: &Path) -> String {
    program.file_name().map_or_else(|| program.display().to_string(), |n| n.to_string_lossy().into_owned())
}
