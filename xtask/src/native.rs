//! The test programs of `tests/native/`, C programs linked to the pinned
//! ReactOS's DLLs through import libraries made from the `.def` files there.
//! They go to the boot disk of the scenarios that `require = native`:
//! - those of the NATIVE subsystem (spike S1, M3), linked to ntdll only,
//!   which the kernel runs (`ntoskrnl::userland::run_boot_programs`);
//! - those of the WINDOWS subsystem (M6), linked to ntdll, kernel32 and
//!   user32, which a scenario puts in the place of `winlogon.exe`
//!   (`initial-command`), for `smss` to start;
//! - those of the CONSOLE subsystem (M5), linked like them, which a program
//!   of the WINDOWS subsystem starts (CreateProcessW).
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
    /// MinGW, NATIVE subsystem.
    MinGw,
    /// MinGW, WINDOWS subsystem.
    MinGwWin32,
    /// MinGW, CONSOLE subsystem.
    MinGwConsole,
    ClangMsvc,
}

/// Each program: its sources in `tests/native/`, its name on the boot disk
/// (which the kernel or a scenario looks for), and its toolchain.
const PROGRAMS: &[(&[&str], &str, Toolchain)] = &[
    (&["s1hello.c"], "S1HELLO.EXE", Toolchain::MinGw),
    (&["s1seh.c", "seh3.c"], "S1SEH.EXE", Toolchain::ClangMsvc),
    (&["gui1.c"], "GUI1.EXE", Toolchain::MinGwWin32),
    (&["text1.c"], "TEXT1.EXE", Toolchain::MinGwWin32),
    (&["console1.c"], "CONSOLE1.EXE", Toolchain::MinGwWin32),
    (&["threads1.c"], "THREADS1.EXE", Toolchain::MinGwConsole),
];

/// The DLLs of the import libraries (`tests/native/NAME.def`): ntdll for
/// every program, kernel32, user32 and gdi32 for the Win32 ones.
const LIBRARIES: &[&str] = &["ntdll", "kernel32", "user32", "gdi32"];

/// MinGW: no C runtime, no stack protector, no unwind tables.
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
];

/// NATIVE subsystem: entered at `NtProcessStartup(PPEB)` (stdcall, 4 bytes).
const GCC_NATIVE_FLAGS: &[&str] = &["-Wl,--subsystem,native", "-Wl,-e,_NtProcessStartup@4"];

/// WINDOWS subsystem of XP (5.1): entered at `GuiStartup()` (stdcall, no
/// argument), which kernel32's BaseProcessStartup calls.
const GCC_WIN32_FLAGS: &[&str] = &["-Wl,--subsystem,windows:5.1", "-Wl,-e,_GuiStartup@0"];

/// CONSOLE subsystem of XP (5.1): entered at `ConsoleStartup()`, like
/// `GuiStartup`.
const GCC_CONSOLE_FLAGS: &[&str] = &["-Wl,--subsystem,console:5.1", "-Wl,-e,_ConsoleStartup@0"];

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
    let mut gnu_libraries = Vec::new();
    for library in LIBRARIES {
        let gnu_library = out.join(format!("lib{library}.a"));
        run(Command::new("i686-w64-mingw32-dlltool")
            .arg("--kill-at")
            .arg("-d")
            .arg(sources.join(format!("{library}.def")))
            .arg("-l")
            .arg(&gnu_library))?;
        gnu_libraries.push(gnu_library);
    }
    let msvc_library = out.join("ntdll.lib");
    run(Command::new("llvm-dlltool")
        .args(["-m", "i386", "-k", "-d"])
        .arg(sources.join("ntdll.def"))
        .arg("-l")
        .arg(&msvc_library))?;

    let mut files = Vec::new();
    for &(program_sources, name, toolchain) in PROGRAMS {
        let image = out.join(name);
        match toolchain {
            Toolchain::MinGw | Toolchain::MinGwWin32 | Toolchain::MinGwConsole => {
                let (subsystem, libraries) = match toolchain {
                    Toolchain::MinGw => (GCC_NATIVE_FLAGS, &gnu_libraries[..1]),
                    Toolchain::MinGwConsole => (GCC_CONSOLE_FLAGS, &gnu_libraries[..]),
                    _ => (GCC_WIN32_FLAGS, &gnu_libraries[..]),
                };
                let mut gcc = Command::new("i686-w64-mingw32-gcc");
                gcc.args(GCC_FLAGS).args(subsystem).arg("-o").arg(&image);
                gcc.args(program_sources.iter().map(|s| sources.join(s))).args(libraries);
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
