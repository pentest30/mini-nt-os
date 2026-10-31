//! The native test programs of `tests/native/` (spike S1, M3): C programs of
//! the NATIVE subsystem, linked to the pinned ReactOS's ntdll only, through an
//! import library made from `tests/native/ntdll.def`. They go to the boot
//! disk of the scenarios that `require = native`, where the kernel runs them
//! (`ntoskrnl::userland::run_boot_programs`).
//!
//! Two toolchains build them:
//! - MinGW (`i686-w64-mingw32-gcc`, its `dlltool`), the roadmap's;
//! - clang for `i686-pc-windows-msvc` with `lld-link` and `llvm-dlltool`, for
//!   the programs that use `__try`/`__except`/`__finally`, which GCC does not
//!   compile on i386; they link with `seh3.c`, the frame handler that clang's
//!   code calls, which ntdll does not export.
//!
//! Without one of the tools, nothing is built and those scenarios are
//! skipped; the CI installs them (`gcc-mingw-w64-i686`, `clang`, `lld`,
//! `llvm`).

use std::path::Path;
use std::process::Command;

use crate::{Result, Workspace};

/// The tools both toolchains need.
const TOOLS: &[&str] = &["i686-w64-mingw32-gcc", "i686-w64-mingw32-dlltool", "clang", "lld-link", "llvm-dlltool"];

#[derive(Clone, Copy)]
enum Toolchain {
    MinGw,
    ClangMsvc,
}

/// Each program: its sources in `tests/native/`, its name on the boot disk
/// (which the kernel looks for), and its toolchain.
const PROGRAMS: &[(&[&str], &str, Toolchain)] =
    &[(&["s1hello.c"], "S1HELLO.EXE", Toolchain::MinGw), (&["s1seh.c", "seh3.c"], "S1SEH.EXE", Toolchain::ClangMsvc)];

/// MinGW: no C runtime, no stack protector, no unwind tables; entered at
/// `NtProcessStartup(PPEB)` (stdcall, 4 bytes).
const GCC_FLAGS: &[&str] = &[
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

/// clang: frame-based SEH, a faulting instruction counting as an exception
/// in a `__try` block (`-fasync-exceptions`).
const CLANG_FLAGS: &[&str] = &[
    "--target=i686-pc-windows-msvc",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-ffreestanding",
    "-fno-builtin",
    "-fasync-exceptions",
    "-c",
];

/// lld-link: the NATIVE subsystem of XP (5.01), no default library; no
/// SafeSEH table, which only a load configuration would make the loader use.
const LINK_FLAGS: &[&str] =
    &["/nologo", "/subsystem:native,5.01", "/entry:NtProcessStartup", "/nodefaultlib", "/safeseh:no"];

/// The first tool missing, if any: one that cannot be started (their
/// `--version` does not always exit with success: `llvm-dlltool`'s does not).
pub fn missing_tool() -> Option<&'static str> {
    TOOLS.iter().copied().find(|tool| Command::new(tool).arg("--version").output().is_err())
}

/// Builds the programs into `target/xtask/native/`; returns them for the
/// FAT ramdisk (`HOST:FAT_NAME`), or `None` if a tool is missing.
pub fn build(ws: &Workspace) -> Result<Option<Vec<String>>> {
    if missing_tool().is_some() {
        return Ok(None);
    }
    let sources = ws.root.join("tests").join("native");
    let out = ws.target.join("xtask").join("native");
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let definitions = sources.join("ntdll.def");
    let gnu_library = out.join("libntdll.a");
    run(Command::new("i686-w64-mingw32-dlltool")
        .arg("--kill-at")
        .arg("-d")
        .arg(&definitions)
        .arg("-l")
        .arg(&gnu_library))?;
    let msvc_library = out.join("ntdll.lib");
    run(Command::new("llvm-dlltool").args(["-m", "i386", "-k", "-d"]).arg(&definitions).arg("-l").arg(&msvc_library))?;

    let mut files = Vec::new();
    for &(program_sources, name, toolchain) in PROGRAMS {
        let image = out.join(name);
        match toolchain {
            Toolchain::MinGw => {
                let mut gcc = Command::new("i686-w64-mingw32-gcc");
                gcc.args(GCC_FLAGS).arg("-o").arg(&image);
                gcc.args(program_sources.iter().map(|s| sources.join(s))).arg(&gnu_library);
                run(&mut gcc)?;
            }
            Toolchain::ClangMsvc => {
                let mut link = Command::new("lld-link");
                link.args(LINK_FLAGS).arg(format!("/out:{}", image.display()));
                for source in program_sources {
                    let object = out.join(Path::new(source).with_extension("obj"));
                    run(Command::new("clang").args(CLANG_FLAGS).arg("-o").arg(&object).arg(sources.join(source)))?;
                    link.arg(object);
                }
                run(link.arg(&msvc_library))?;
            }
        }
        files.push(format!("{}:{name}", image.display()));
    }
    Ok(Some(files))
}

/// Runs `command`; its failure is an error.
fn run(command: &mut Command) -> Result<()> {
    let program = command.get_program().to_string_lossy().into_owned();
    let status = command.status().map_err(|e| format!("{program}: {e}"))?;
    if !status.success() {
        return Err(format!("{program} failed ({status})"));
    }
    Ok(())
}
