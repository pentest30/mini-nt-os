//! The OpenGL ICD of Direct3D (ADR-025): Mesa's Gallium llvmpipe, i386,
//! built for the XP loader from pinned sources. `cargo xtask icd-build`
//! downloads Mesa, LLVM and zlib (each checked against its size and
//! SHA-256), unpacks them in `third_party/mesa-icd/` (not in Git), patches
//! Mesa ([`PATCHES`]), builds LLVM's libraries, then Mesa, and refuses a
//! `mesaicd.dll` that the pinned loader would not load ([`check`]). The
//! checked DLL is stamped with its SHA-256 ([`dll`]).
//!
//! The build needs, beside `curl` and `xz`: a MinGW-w64 i686 GCC whose
//! `__thread` is emulated (`__emutls_get_address`, GCC 14 and older as
//! usually built; GCC 16 of MSYS2 has native TLS, which the XP loader does
//! not give a DLL loaded by LoadLibrary), CMake, Ninja, Meson, a Python with
//! Mako, bison and flex. `--toolchain DIR` (or `MINO_ICD_TOOLCHAIN`) gives
//! the GCC's `bin` directory, `MINO_ICD_PYTHON` the Python. For now the host
//! is a Windows one, where that GCC runs: a Linux host would build LLVM's
//! `llvm-config` and `tblgen` for itself first (cross build), not done yet.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::{tar, Args, Result, Workspace};

/// A pinned download.
struct Source {
    file: &'static str,
    url: &'static str,
    size: u64,
    sha256: &'static str,
    /// The directory the archive unpacks to; `None`: not unpacked (Meson
    /// takes it from its package cache).
    tree: Option<&'static str>,
}

/// Mesa 20.3.5: the last version with XP's condition variables (21.0 needs
/// the ones of later systems).
const MESA: Source = Source {
    file: "mesa-20.3.5.tar.xz",
    url: "https://archive.mesa3d.org/older-versions/20.x/mesa-20.3.5.tar.xz",
    size: 14_367_412,
    sha256: "909a72df63dfa3c0844ccf44a26ac028d148297ed333ab51560893923d7691ce",
    tree: Some("mesa-20.3.5"),
};

/// LLVM 11.1.0, which Mesa 20.3 supports (3.9 and later), libraries only.
const LLVM: Source = Source {
    file: "llvm-11.1.0.src.tar.xz",
    url: "https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/llvm-11.1.0.src.tar.xz",
    size: 38_915_280,
    sha256: "ce8508e318a01a63d4e8b3090ab2ded3c598a50258cc49e2625b9120d4c03ea5",
    tree: Some("llvm-11.1.0.src"),
};

/// zlib, which Mesa links: its wrap (`subprojects/zlib.wrap` of Mesa 20.3.5,
/// whose sums these are) built statically, from Meson's package cache.
const ZLIB: Source = Source {
    file: "zlib-1.2.11.tar.gz",
    url: "https://zlib.net/fossils/zlib-1.2.11.tar.gz",
    size: 607_698,
    sha256: "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
    tree: None,
};
const ZLIB_WRAP: Source = Source {
    file: "zlib-1.2.11-2-wrap.zip",
    url: "https://github.com/mesonbuild/zlib/releases/download/1.2.11-2/zlib.zip",
    size: 1_535,
    sha256: "aed811a48707be2a374a230c01e2efa17b385fe7e88f4ac0ee122093766aab2b",
    tree: None,
};

/// A change to a file of Mesa's tree: `from` found exactly `count` times,
/// each replaced by `to`. A source that moved stops the build.
pub struct Patch {
    file: &'static str,
    from: &'static str,
    to: &'static str,
    count: usize,
}

/// The `#if` that `gldrv.h` keeps the newer ICD types under: their
/// structures are compiled whatever `WINVER`, and `DrvSetCallbackProcs`
/// copies only the callbacks that `opengl32` gives.
const GLDRV_TYPES: &str = "#if 1 /* Mino: the types, whatever WINVER (built for XP) */";

/// Mesa's tree, made to build for XP.
pub const PATCHES: &[Patch] = &[
    // XP's headers: nothing newer is called directly (LLVM's calls go
    // through `xpcompat.c`).
    Patch {
        file: "meson.build",
        from: "'-D_WINDOWS', '-D_WIN32_WINNT=0x0A00', '-DWINVER=0x0A00',",
        to: "'-D_WINDOWS', '-D_WIN32_WINNT=0x0501', '-DWINVER=0x0501',",
        count: 1,
    },
    // A MinGW may have a libdl (dlfcn-win32) without <dlfcn.h>: Mesa then
    // compiles `dladdr` it cannot declare. Its Windows code needs neither.
    Patch {
        file: "meson.build",
        from: "if not cc.has_function('dlopen')",
        to: "if host_machine.system() != 'windows' and not cc.has_function('dlopen')",
        count: 1,
    },
    Patch {
        file: "meson.build",
        from: "if cc.has_function('dladdr', dependencies : dep_dl)",
        to: "if host_machine.system() != 'windows' and cc.has_function('dladdr', dependencies : dep_dl)",
        count: 1,
    },
    // Meson stops on the path of a `dumpbin` it did not find (MSVC's).
    Patch {
        file: "meson.build",
        from: "symbols_check_args = ['--dumpbin', prog_dumpbin.path()]",
        to: "symbols_check_args = prog_dumpbin.found() ? ['--dumpbin', prog_dumpbin.path()] : []",
        count: 1,
    },
    Patch { file: "src/gallium/frontends/wgl/gldrv.h", from: "#if WINVER >= 0x500", to: GLDRV_TYPES, count: 3 },
    Patch { file: "src/gallium/frontends/wgl/gldrv.h", from: "#if WINVER >= 0x600", to: GLDRV_TYPES, count: 3 },
    Patch { file: "src/gallium/frontends/wgl/gldrv.h", from: "#if WINVER >= 0xA00", to: GLDRV_TYPES, count: 2 },
];

/// The compiler definitions of every C and C++ file: XP's API.
const XP_DEFINES: [&str; 2] = ["-D_WIN32_WINNT=0x0501", "-DWINVER=0x0501"];

/// The linker options of the DLL: everything static (no `libgcc`,
/// `libstdc++` nor `libwinpthread` DLL beside it), and XP's versions in its
/// header.
const LINK_FLAGS: [&str; 7] = [
    "-static",
    "-static-libgcc",
    "-static-libstdc++",
    "-Wl,--major-subsystem-version,5",
    "-Wl,--minor-subsystem-version,1",
    "-Wl,--major-os-version,5",
    "-Wl,--minor-os-version,1",
];

/// Where it all goes.
pub fn dir(ws: &Workspace) -> PathBuf {
    ws.root.join("third_party").join("mesa-icd")
}

/// The ICD, once `icd-build` checked it; `None` before.
#[expect(dead_code, reason = "the disk of the d3d9-spike scenario takes it next (ADR-025, spike step 3)")]
pub fn dll(ws: &Workspace) -> Option<PathBuf> {
    let path = dir(ws).join("mesaicd.dll");
    let stamped = fs::read_to_string(stamp(&path)).ok()?;
    let bytes = fs::read(&path).ok()?;
    (crate::userland::digest(&bytes) == stamped.trim()).then_some(path)
}

fn stamp(path: &Path) -> PathBuf {
    let mut name = path.file_name().expect("a file").to_os_string();
    name.push(".sha256");
    path.with_file_name(name)
}

/// The i686 MinGW-w64 tools.
struct Toolchain {
    /// Prepended to the build's `PATH`, when given.
    bin: Option<PathBuf>,
    gcc: PathBuf,
    gxx: PathBuf,
    ar: PathBuf,
    strip: PathBuf,
}

impl Toolchain {
    /// In `bin` (prefixed names first, as Debian's, then plain ones, as a
    /// toolchain made for its own host); without it, on `PATH`, prefixed.
    fn find(bin: Option<PathBuf>) -> Result<Self> {
        let tool = |name: &str| -> Result<PathBuf> {
            let Some(dir) = &bin else { return Ok(PathBuf::from(format!("i686-w64-mingw32-{name}"))) };
            let exe = if cfg!(windows) { ".exe" } else { "" };
            [format!("i686-w64-mingw32-{name}{exe}"), format!("{name}{exe}")]
                .iter()
                .map(|file| dir.join(file))
                .find(|path| path.is_file())
                .ok_or_else(|| format!("no {name} in {}", dir.display()))
        };
        Ok(Self { gcc: tool("gcc")?, gxx: tool("g++")?, ar: tool("ar")?, strip: tool("strip")?, bin })
    }

    /// A command of the build: the toolchain's directory first in its `PATH`.
    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        if let Some(bin) = &self.bin {
            let path = std::env::var_os("PATH").unwrap_or_default();
            let joined = std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(&path)))
                .expect("PATH entries");
            command.env("PATH", joined);
        }
        command
    }

    /// Checks that it targets i686 and emulates `__thread`.
    fn check(&self, scratch: &Path) -> Result<()> {
        let machine = output(self.command(&self.gcc).arg("-dumpmachine"))?;
        if !machine.trim().starts_with("i686-w64-mingw32") {
            return Err(format!("{} targets {}, not i686-w64-mingw32", self.gcc.display(), machine.trim()));
        }
        let probe = scratch.join("tls-probe.c");
        fs::write(&probe, "__thread int counter;\nint *address(void) { return &counter; }\n")
            .map_err(|e| format!("{}: {e}", probe.display()))?;
        let assembly = output(self.command(&self.gcc).args(["-O2", "-S", "-o", "-"]).arg(&probe))?;
        match tls_model(&assembly) {
            TlsModel::Emulated => Ok(()),
            TlsModel::Native => Err(format!(
                "{} compiles `__thread` to native TLS, which the XP loader does not give a DLL loaded by \
                 LoadLibrary: take a MinGW-w64 GCC built without --enable-tls (GCC 14 and older as usually \
                 built), with --toolchain DIR",
                self.gcc.display()
            )),
            TlsModel::Unknown => Err(format!("{}: cannot tell how it compiles `__thread`", self.gcc.display())),
        }
    }
}

#[derive(Debug, PartialEq)]
enum TlsModel {
    Emulated,
    Native,
    Unknown,
}

/// How a GCC compiled the `__thread` probe, from its assembly.
fn tls_model(assembly: &str) -> TlsModel {
    if assembly.contains("__emutls_get_address") || assembly.contains("__emutls_v.") {
        TlsModel::Emulated
    } else if assembly.contains("__tls_index") || assembly.contains("%fs:44") || assembly.contains("@secrel32") {
        TlsModel::Native
    } else {
        TlsModel::Unknown
    }
}

/// The other programs of the build, each started once to see it is there.
const PROGRAMS: [(&str, &str); 6] = [
    ("cmake", "--version"),
    ("ninja", "--version"),
    ("meson", "--version"),
    ("xz", "--version"),
    ("curl", "--version"),
    ("bison", "--version"),
];

/// A Python with Mako: `MINO_ICD_PYTHON`, or the first of `python3` and
/// `python` that imports it.
fn python() -> Result<String> {
    let candidates: Vec<String> = match std::env::var("MINO_ICD_PYTHON") {
        Ok(python) => vec![python],
        Err(_) => vec!["python3".into(), "python".into()],
    };
    candidates
        .into_iter()
        .find(|python| Command::new(python).args(["-c", "import mako"]).output().is_ok_and(|out| out.status.success()))
        .ok_or_else(|| "no Python with Mako (pip install mako; MINO_ICD_PYTHON names one)".into())
}

/// `cargo xtask icd-build [--toolchain DIR]`.
pub fn build(ws: &Workspace, mut args: Args) -> Result<()> {
    let bin = args.value("--toolchain")?.or_else(|| std::env::var("MINO_ICD_TOOLCHAIN").ok()).map(PathBuf::from);
    args.finish()?;
    if !cfg!(windows) {
        return Err("icd-build runs on a Windows host for now (a Linux host needs a cross build of LLVM)".into());
    }
    let started = Instant::now();
    let root = dir(ws);
    let (downloads, sources, build) = (root.join("downloads"), root.join("src"), root.join("build"));
    for dir in [&downloads, &sources, &build] {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }

    // 1. The tools, all reported at once.
    let toolchain = Toolchain::find(bin)?;
    let mut missing: Vec<String> = PROGRAMS
        .iter()
        .filter(|(program, flag)| toolchain.command(program).arg(flag).output().is_err())
        .map(|(program, _)| program.to_string())
        .collect();
    if ["flex", "win_flex"].iter().all(|flex| toolchain.command(flex).arg("--version").output().is_err()) {
        missing.push("flex".into());
    }
    let python = python().map_err(|e| missing.push(e)).ok();
    if !missing.is_empty() {
        return Err(format!("icd-build needs {}", missing.join(", ")));
    }
    let python = python.expect("checked above");
    toolchain.check(&build)?;

    // 2. The sources.
    for source in [&MESA, &LLVM, &ZLIB, &ZLIB_WRAP] {
        fetch(source, &downloads)?;
    }
    let mesa = unpack(&MESA, &downloads, &sources, PATCHES)?;
    let llvm = unpack(&LLVM, &downloads, &sources, &[])?;
    let cache = mesa.join("subprojects").join("packagecache");
    fs::create_dir_all(&cache).map_err(|e| format!("{}: {e}", cache.display()))?;
    for source in [&ZLIB, &ZLIB_WRAP] {
        let to = cache.join(source.file);
        fs::copy(downloads.join(source.file), &to).map_err(|e| format!("{}: {e}", to.display()))?;
    }

    // 3. LLVM's libraries and llvm-config.
    let llvm_build = build.join("llvm");
    build_llvm(&toolchain, &llvm, &llvm_build)?;
    write_llvm_subproject(&toolchain, &llvm, &llvm_build, &mesa)?;

    // 4. The XP compatibility object, then Mesa.
    let xpcompat = build.join("xpcompat.o");
    run(toolchain
        .command(&toolchain.gcc)
        .args(["-O2", "-Wall", "-Wextra", "-c"])
        .args(XP_DEFINES)
        .arg(ws.root.join("xtask").join("icd-src").join("xpcompat.c"))
        .arg("-o")
        .arg(&xpcompat))?;
    let mesa_build = build.join("mesa");
    let native_file = build.join("native.ini");
    fs::write(&native_file, native_file_text(&toolchain, &python, &xpcompat))
        .map_err(|e| format!("{}: {e}", native_file.display()))?;
    build_mesa(&toolchain, &mesa, &mesa_build, &native_file)?;

    // 5. Stripped, checked, stamped, with its licences.
    let built = mesa_build.join("src").join("gallium").join("targets").join("libgl-gdi").join("opengl32.dll");
    let dll = root.join("mesaicd.dll");
    let _ = fs::remove_file(stamp(&dll));
    run(toolchain.command(&toolchain.strip).arg("-o").arg(&dll).arg(&built))?;
    let bytes = fs::read(&dll).map_err(|e| format!("{}: {e}", dll.display()))?;
    let report = check(&bytes, |name| crate::userland::system32_file(ws, name).and_then(|path| fs::read(path).ok()))?;
    copy_licences(&mesa, &llvm, &root)?;
    fs::write(stamp(&dll), format!("{}\n", crate::userland::digest(&bytes)))
        .map_err(|e| format!("{}: {e}", dll.display()))?;
    println!(
        "xtask: {} ({} MiB) checked: {report}; in {:.0} min",
        dll.display(),
        bytes.len() >> 20,
        started.elapsed().as_secs_f64() / 60.0
    );
    Ok(())
}

/// Downloads `source` unless a checked copy is there.
fn fetch(source: &Source, downloads: &Path) -> Result<()> {
    let path = downloads.join(source.file);
    let check = |path: &Path| -> Result<()> {
        let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if bytes.len() as u64 != source.size {
            return Err(format!("{}: {} bytes, expected {}", source.file, bytes.len(), source.size));
        }
        let digest = crate::userland::digest(&bytes);
        if digest != source.sha256 {
            return Err(format!("{}: SHA-256 {digest}, expected {}", source.file, source.sha256));
        }
        Ok(())
    };
    if path.is_file() && check(&path).is_ok() {
        return Ok(());
    }
    let _ = fs::remove_file(&path);
    crate::userland::download(source.url, &path)?;
    check(&path).inspect_err(|_| {
        let _ = fs::remove_file(&path);
    })
}

/// Unpacks `source` in `sources` and applies `patches`, unless its stamp
/// says it is done with these sums and patches.
fn unpack(source: &Source, downloads: &Path, sources: &Path, patches: &[Patch]) -> Result<PathBuf> {
    let tree = sources.join(source.tree.expect("an unpacked source"));
    let stamp = sources.join(format!("{}.stamp", source.tree.expect("an unpacked source")));
    let wanted = format!("{} {}\n", source.sha256, patches_digest(patches));
    if fs::read_to_string(&stamp).is_ok_and(|done| done == wanted) && tree.is_dir() {
        return Ok(tree);
    }
    let _ = fs::remove_file(&stamp);
    if tree.exists() {
        fs::remove_dir_all(&tree).map_err(|e| format!("{}: {e}", tree.display()))?;
    }
    println!("xtask: unpacking {}", source.file);
    // xz writes the archive to a file, read afterwards: a pipe from MSYS2's
    // xz to this process stalls under Windows.
    let archive = sources.join(format!("{}.tar", source.tree.expect("an unpacked source")));
    let file = fs::File::create(&archive).map_err(|e| format!("{}: {e}", archive.display()))?;
    let status = Command::new("xz")
        .arg("-dc")
        .arg(downloads.join(source.file))
        .stdout(file)
        .status()
        .map_err(|e| format!("xz: {e}"))?;
    if !status.success() {
        let _ = fs::remove_file(&archive);
        return Err(format!("xz failed ({status}) on {}", source.file));
    }
    let opened = fs::File::open(&archive).map_err(|e| format!("{}: {e}", archive.display()))?;
    let summary = tar::extract(std::io::BufReader::new(opened), sources);
    let _ = fs::remove_file(&archive);
    let summary = summary?;
    if !summary.dangling.is_empty() {
        println!("xtask: {}: links without a target, left out: {}", source.file, summary.dangling.join(", "));
    }
    for patch in patches {
        let path = tree.join(patch.file);
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let patched = apply(&text, patch).map_err(|e| format!("{}: {e}", path.display()))?;
        fs::write(&path, patched).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    fs::write(&stamp, wanted).map_err(|e| format!("{}: {e}", stamp.display()))?;
    Ok(tree)
}

/// `text` with `patch` applied; an error if `from` is not there `count` times.
pub fn apply(text: &str, patch: &Patch) -> Result<String> {
    let found = text.matches(patch.from).count();
    if found != patch.count {
        return Err(format!("`{}` found {found} times, expected {}", patch.from, patch.count));
    }
    Ok(text.replace(patch.from, patch.to))
}

/// A digest of the patches, in the stamp: changing one unpacks again.
fn patches_digest(patches: &[Patch]) -> String {
    let text: String = patches
        .iter()
        .map(|patch| format!("{}\0{}\0{}\0{}\n", patch.file, patch.from, patch.to, patch.count))
        .collect();
    crate::userland::digest(text.as_bytes())
}

/// LLVM, X86 only, static libraries: configured at each build (CMake keeps
/// its cache), then built (Ninja does nothing when it is up to date). Only
/// its libraries and llvm-config: its tools use functions newer than XP
/// (llvm-ar's CompareStringOrdinal).
fn build_llvm(toolchain: &Toolchain, llvm: &Path, out: &Path) -> Result<()> {
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    {
        let defines = XP_DEFINES.join(" ");
        run(toolchain
            .command("cmake")
            .current_dir(out)
            .args(["-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release"])
            .arg(format!("-DCMAKE_C_COMPILER={}", slashes(&toolchain.gcc)))
            .arg(format!("-DCMAKE_CXX_COMPILER={}", slashes(&toolchain.gxx)))
            .arg(format!("-DCMAKE_AR={}", slashes(&toolchain.ar)))
            .arg(format!("-DCMAKE_C_FLAGS={defines}"))
            // LLVM 11 leaves out includes that newer libstdc++ no longer
            // brings with others.
            .arg(format!("-DCMAKE_CXX_FLAGS={defines} -include cstdint -include limits"))
            .args([
                "-DLLVM_TARGETS_TO_BUILD=X86",
                "-DLLVM_ENABLE_ZLIB=OFF",
                "-DLLVM_ENABLE_TERMINFO=OFF",
                "-DLLVM_ENABLE_LIBXML2=OFF",
                "-DLLVM_INCLUDE_TESTS=OFF",
                "-DLLVM_INCLUDE_EXAMPLES=OFF",
                "-DLLVM_INCLUDE_BENCHMARKS=OFF",
                "-DLLVM_INCLUDE_DOCS=OFF",
                "-DLLVM_BUILD_TOOLS=OFF",
                "-DLLVM_ENABLE_BINDINGS=OFF",
                // Remarks.dll and LTO.dll, which Mesa does not use, link
                // with an unquoted path to their `.def` (a tree with a space).
                "-DLLVM_TOOL_REMARKS_SHLIB_BUILD=OFF",
                "-DLLVM_TOOL_LTO_BUILD=OFF",
                // LLVM 11 asks for an older CMake than CMake 4 accepts.
                "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
            ])
            .arg(llvm))?;
    }
    run(toolchain.command("ninja").current_dir(out).args(["llvm-libraries", "llvm-config"]))?;
    // llvm-config checks that each library of its component table is there,
    // and the table names the test libraries, which are not built.
    for library in ["libgtest.a", "libgtest_main.a", "libLLVMTestingSupport.a"] {
        let path = out.join("lib").join(library);
        if !path.is_file() {
            run(toolchain.command(&toolchain.ar).arg("rc").arg(&path))?;
        }
    }
    let config = out.join("bin").join("llvm-config.exe");
    output(toolchain.command(&config).arg("--shared-mode")).map(|_| ())
}

/// The LLVM components of llvmpipe (`llvm_modules` and
/// `llvm_optional_modules` of Mesa's `meson.build`, without the other
/// drivers' own).
const LLVM_MODULES: [&str; 10] = [
    "bitwriter",
    "engine",
    "mcdisassembler",
    "mcjit",
    "core",
    "executionengine",
    "scalaropts",
    "transformutils",
    "instcombine",
    "coroutines",
];

/// Gives LLVM to Mesa as a Meson subproject (`subprojects/llvm`, the way
/// Mesa's `docs/meson.rst` describes for Windows): Meson splits what
/// llvm-config prints at spaces, and the workspace's path may have one.
/// The libraries are named in llvm-config's order (dependencies last).
fn write_llvm_subproject(toolchain: &Toolchain, llvm: &Path, llvm_build: &Path, mesa: &Path) -> Result<()> {
    let config = llvm_build.join("bin").join("llvm-config.exe");
    let query = |args: &[&str]| output(toolchain.command(&config).args(args)).map(|text| text.trim().to_string());
    let version = query(&["--version"])?;
    let rtti = query(&["--has-rtti"])? == "YES";
    let mut args = vec!["--link-static", "--libnames"];
    args.extend(LLVM_MODULES);
    let libraries: Vec<String> = query(&args)?
        .split_whitespace()
        .map(|name| name.trim_start_matches("lib").trim_end_matches(".a").to_string())
        .collect();
    let system: Vec<String> =
        query(&["--link-static", "--system-libs"])?.split_whitespace().map(String::from).collect();
    let text = llvm_subproject_text(
        &version,
        rtti,
        &libraries,
        &system,
        &[llvm.join("include"), llvm_build.join("include")],
        &llvm_build.join("lib"),
    );
    let dir = mesa.join("subprojects").join("llvm");
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    fs::write(dir.join("meson.build"), text).map_err(|e| format!("{}: {e}", dir.display()))
}

/// The `meson.build` of the LLVM subproject: `dep_llvm` and `has_rtti`.
fn llvm_subproject_text(
    version: &str,
    rtti: bool,
    libraries: &[String],
    system: &[String],
    includes: &[PathBuf],
    lib_dir: &Path,
) -> String {
    let string = |text: &str| format!("'{}'", text.replace('\\', "/").replace('\'', "\\'"));
    let list = |items: Vec<String>| items.iter().map(|item| string(item)).collect::<Vec<_>>().join(", ");
    let includes = includes.iter().map(|path| path.to_string_lossy().into_owned()).collect();
    format!(
        "# Written by `cargo xtask icd-build` (xtask/src/icd.rs).\n\
         project('llvm', ['cpp'], version : '{version}')\n\
         cpp = meson.get_compiler('cpp')\n\
         _deps = []\n\
         foreach name : [{}]\n  _deps += cpp.find_library(name, dirs : {}, static : true)\nendforeach\n\
         dep_llvm = declare_dependency(\n  include_directories : include_directories({}),\n  \
         dependencies : _deps,\n  link_args : [{}],\n  version : '{version}',\n)\n\
         has_rtti = {rtti}\n",
        list(libraries.to_vec()),
        string(&lib_dir.to_string_lossy()),
        list(includes),
        list(system.to_vec()),
    )
}

/// The Meson native file of Mesa's build.
fn native_file_text(toolchain: &Toolchain, python: &str, xpcompat: &Path) -> String {
    let quote = |items: &[String]| items.iter().map(|item| format!("'{item}'")).collect::<Vec<_>>().join(", ");
    let defines: Vec<String> = XP_DEFINES.iter().map(|define| define.to_string()).collect();
    let mut cpp_args = defines.clone();
    cpp_args.extend(["-include".into(), "cstdint".into()]);
    let link = |cpp: bool| -> Vec<String> {
        std::iter::once(slashes(xpcompat))
            .chain(LINK_FLAGS.iter().filter(|flag| cpp || **flag != "-static-libstdc++").map(|flag| flag.to_string()))
            .collect()
    };
    format!(
        "[binaries]\nc = '{}'\ncpp = '{}'\nar = '{}'\nstrip = '{}'\npython = '{python}'\n\
         python3 = '{python}'\n\n[built-in options]\nc_args = [{}]\ncpp_args = [{}]\nc_link_args = [{}]\n\
         cpp_link_args = [{}]\n",
        slashes(&toolchain.gcc),
        slashes(&toolchain.gxx),
        slashes(&toolchain.ar),
        slashes(&toolchain.strip),
        quote(&defines),
        quote(&cpp_args),
        quote(&link(false)),
        quote(&link(true)),
    )
}

/// The options of Mesa's build: the Gallium swrast driver (llvmpipe), its
/// WGL front end (`libgl-gdi`), nothing else.
const MESA_OPTIONS: &[&str] = &[
    "--buildtype=release",
    "-Db_ndebug=true",
    "--wrap-mode=nodownload",
    "--force-fallback-for=zlib,llvm",
    "-Dzlib:default_library=static",
    "-Dplatforms=windows",
    "-Dgallium-drivers=swrast",
    "-Ddri-drivers=",
    "-Dvulkan-drivers=",
    "-Dllvm=enabled",
    "-Dshared-llvm=disabled",
    "-Dgles1=disabled",
    "-Dgles2=disabled",
    "-Degl=disabled",
    "-Dglx=disabled",
    "-Dgbm=disabled",
    "-Dosmesa=none",
    "-Dshared-glapi=disabled",
    "-Dzstd=disabled",
    "-Dvalgrind=disabled",
    "-Dlibunwind=disabled",
    "-Dlmsensors=disabled",
    "-Dgallium-vdpau=disabled",
    "-Dgallium-xvmc=disabled",
    "-Dgallium-omx=disabled",
    "-Dgallium-va=disabled",
    "-Dgallium-xa=disabled",
    "-Dshader-cache=disabled",
    "-Dbuild-tests=false",
];

fn build_mesa(toolchain: &Toolchain, mesa: &Path, out: &Path, native_file: &Path) -> Result<()> {
    let mut setup = toolchain.command("meson");
    setup.current_dir(mesa).arg("setup");
    if out.join("build.ninja").is_file() {
        setup.arg("--reconfigure");
    }
    run(setup.arg(out).arg("--native-file").arg(native_file).args(MESA_OPTIONS))?;
    run(toolchain.command("ninja").current_dir(out))
}

/// The licence notices that go with the DLL (ADR-025): Mesa's, LLVM's and
/// zlib's (in its README).
fn copy_licences(mesa: &Path, llvm: &Path, root: &Path) -> Result<()> {
    let licences = root.join("licences");
    fs::create_dir_all(&licences).map_err(|e| format!("{}: {e}", licences.display()))?;
    let zlib = mesa.join("subprojects").join("zlib-1.2.11").join("README");
    for (from, name) in [
        (mesa.join("docs").join("license.rst"), "MESA.TXT"),
        (llvm.join("LICENSE.TXT"), "LLVM.TXT"),
        (zlib, "ZLIB.TXT"),
    ] {
        fs::copy(&from, licences.join(name)).map_err(|e| format!("{}: {e}", from.display()))?;
    }
    Ok(())
}

/// Most a TLS template may hold: MinGW's CRT always has its markers
/// `_tls_start` and `_tls_end` (`tlssup.c`), which nothing reads by the
/// TLS index.
const CRT_TLS_TEMPLATE: u32 = 8;

/// Checks that the pinned loader would load `dll` (ADR-025): its subsystem
/// version at most 5.1, each import found among the exports of the DLL of
/// the same name (`system32(name)` gives its bytes), no implicit TLS (no
/// template past the CRT's markers, no code reading the TLS index). Returns
/// what it saw.
pub fn check(dll: &[u8], system32: impl Fn(&str) -> Option<Vec<u8>>) -> Result<String> {
    let pe = pe::Pe32::parse(dll).map_err(|e| format!("not a PE32 image: {e:?}"))?;
    let header = pe.optional_header();
    let (major, minor) = (header.major_subsystem_version, header.minor_subsystem_version);
    let mut problems = Vec::new();
    if (major, minor) > (5, 1) {
        problems.push(format!("subsystem version {major}.{minor}, past XP's 5.1"));
    }
    let mut imports = 0;
    for entry in pe.imports() {
        let dll_name = entry.dll_name().to_ascii_lowercase();
        let names = import_names(&pe, &entry)?;
        imports += names.len();
        let Some(bytes) = system32(&dll_name) else {
            problems.push(format!("imports {dll_name}, not in the pinned system32"));
            continue;
        };
        let exporter = pe::Pe32::parse(&bytes).map_err(|e| format!("{dll_name}: {e:?}"))?;
        let unresolved: Vec<String> = names
            .into_iter()
            .filter(|name| match name {
                Import::Name(name) => exporter.export(name).is_none(),
                Import::Ordinal(_) => true,
            })
            .map(|name| match name {
                Import::Name(name) => name,
                Import::Ordinal(ordinal) => format!("#{ordinal} (by ordinal, not checked)"),
            })
            .collect();
        if !unresolved.is_empty() {
            problems.push(format!("{dll_name} does not export {}", unresolved.join(", ")));
        }
    }
    let template = tls_template(&pe)?;
    if template > CRT_TLS_TEMPLATE {
        problems.push(format!("a TLS template of {template} bytes (implicit TLS)"));
    }
    let accesses = tls_index_reads(&pe);
    if accesses > 0 {
        problems.push(format!("{accesses} reads of the TLS array (fs:[2Ch]): implicit TLS"));
    }
    if problems.is_empty() {
        Ok(format!("subsystem {major}.{minor}, {imports} imports found, TLS template of {template} bytes"))
    } else {
        Err(format!("the ICD would not load under the XP loader: {}", problems.join("; ")))
    }
}

#[derive(Debug, PartialEq)]
enum Import {
    Name(String),
    Ordinal(u16),
}

/// The functions an import descriptor names: its lookup table (or its
/// address table, without one), up to the null entry.
fn import_names(pe: &pe::Pe32<'_>, entry: &pe::ImportEntry<'_>) -> Result<Vec<Import>> {
    let table = if entry.int_rva != 0 { entry.int_rva } else { entry.iat_rva };
    let mut names = Vec::new();
    for index in 0.. {
        let thunk = pe
            .read_rva(table + 4 * index, 4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
            .ok_or_else(|| format!("{}: import table out of the file", entry.dll_name()))?;
        if thunk == 0 {
            break;
        }
        if thunk & 0x8000_0000 != 0 {
            names.push(Import::Ordinal(thunk as u16));
            continue;
        }
        // IMAGE_IMPORT_BY_NAME: a hint, then the name.
        let mut name = Vec::new();
        while let Some(&[byte]) = pe.read_rva(thunk + 2 + name.len() as u32, 1) {
            if byte == 0 {
                break;
            }
            name.push(byte);
        }
        names.push(Import::Name(String::from_utf8_lossy(&name).into_owned()));
    }
    Ok(names)
}

/// The size of the TLS template (IMAGE_TLS_DIRECTORY32: raw data from
/// StartAddressOfRawData to EndAddressOfRawData, then SizeOfZeroFill); 0
/// without a TLS directory.
fn tls_template(pe: &pe::Pe32<'_>) -> Result<u32> {
    let header = pe.optional_header();
    let directories = header.data_directory;
    if header.number_of_rva_and_sizes <= 9 || directories[9].virtual_address == 0 {
        return Ok(0);
    }
    let bytes = pe.read_rva(directories[9].virtual_address, 24).ok_or("TLS directory out of the file")?;
    let field = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
    let (start, end, zero_fill) = (field(0), field(4), field(16));
    Ok(end.checked_sub(start).ok_or("TLS directory: end before start")? + zero_fill)
}

/// The reads of the TLS array pointer of the TEB (`fs:[2Ch]`) in the
/// executable sections: what a compiler emits for implicit TLS on i386
/// (`mov eax, fs:[2Ch]`, `mov reg, fs:[2Ch]`).
fn tls_index_reads(pe: &pe::Pe32<'_>) -> usize {
    pe.sections()
        .filter(|section| section.is_executable())
        .filter_map(|section| {
            let (rva, size) = (section.virtual_address, section.size_of_raw_data.min(section.virtual_size));
            pe.read_rva(rva, size as usize)
        })
        .map(count_tls_index_reads)
        .sum()
}

fn count_tls_index_reads(code: &[u8]) -> usize {
    const DISP: [u8; 4] = [0x2C, 0, 0, 0];
    (0..code.len())
        .filter(|&at| {
            let rest = &code[at..];
            match rest {
                // mov eax, fs:[disp32]
                [0x64, 0xA1, disp @ ..] if disp.starts_with(&DISP) => true,
                // mov reg, fs:[disp32]: ModR/M with mod 00, r/m 101
                [0x64, 0x8B, modrm, disp @ ..] if modrm & 0xC7 == 0x05 && disp.starts_with(&DISP) => true,
                _ => false,
            }
        })
        .count()
}

/// A path for CMake and Meson: forward slashes.
fn slashes(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn run(command: &mut Command) -> Result<()> {
    let status = command.status().map_err(|e| format!("{:?}: {e}", command.get_program()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{:?} failed ({status})", command.get_program()))
    }
}

fn output(command: &mut Command) -> Result<String> {
    let out = command.output().map_err(|e| format!("{:?}: {e}", command.get_program()))?;
    if !out.status.success() {
        let mut stderr = String::new();
        let _ = (&out.stderr[..]).read_to_string(&mut stderr);
        return Err(format!("{:?} failed ({}): {}", command.get_program(), out.status, stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_patch_applies_only_where_expected() {
        let patch = Patch { file: "f", from: "#if A", to: "#if 1", count: 2 };
        assert_eq!(apply("#if A\nx\n#if A\n", &patch).unwrap(), "#if 1\nx\n#if 1\n");
        assert!(apply("#if A\n", &patch).unwrap_err().contains("found 1 times, expected 2"));
        assert!(apply("", &patch).is_err(), "a source that moved stops the build");
    }

    #[test]
    fn the_patches_digest_follows_them() {
        assert_ne!(patches_digest(PATCHES), patches_digest(&PATCHES[1..]));
        assert_eq!(patches_digest(PATCHES), patches_digest(PATCHES));
    }

    #[test]
    fn the_tls_model_is_read_from_the_assembly() {
        // GCC 14 of winlibs, then GCC 16 of MSYS2 (--enable-tls).
        let emulated = "\tmovl\t$___emutls_v.counter, (%esp)\n\tcall\t___emutls_get_address\n";
        let native = "\tmovl\t__tls_index, %eax\n\tmovl\t%fs:44, %edx\n\tmovl\t(%edx,%eax,4), %eax\n";
        assert_eq!(tls_model(emulated), TlsModel::Emulated);
        assert_eq!(tls_model(native), TlsModel::Native);
        assert_eq!(tls_model("\tret\n"), TlsModel::Unknown);
    }

    #[test]
    fn reads_of_the_tls_array_are_counted() {
        let code = [
            0x64, 0xA1, 0x2C, 0, 0, 0, // mov eax, fs:[2Ch]
            0x64, 0x8B, 0x15, 0x2C, 0, 0, 0, // mov edx, fs:[2Ch]
            0x64, 0xA1, 0x18, 0, 0, 0, // mov eax, fs:[18h]: the TEB, not TLS
            0x64, 0x8B, 0x45, 0x2C, // mov eax, fs:[ebp+2Ch]: not disp32
            0x8B, 0x15, 0x2C, 0, 0, 0, // mov edx, [2Ch]: no fs
        ];
        assert_eq!(count_tls_index_reads(&code), 2);
        assert_eq!(count_tls_index_reads(&[0x64, 0xA1, 0x2C]), 0, "cut at the end");
    }

    /// A DLL importing `names` from kernel32.dll, its `.text` being `code`.
    fn importer(names: &[&'static str], code: &[u8]) -> Vec<u8> {
        use pe::builder::Pe32Builder;
        Pe32Builder::new(0x1000_0000)
            .section(".text", 0x1000, code.len() as u32, code, pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
            .imports("kernel32.dll", names)
            .build()
    }

    fn kernel32(name: &str) -> Option<Vec<u8>> {
        use pe::builder::Pe32Builder;
        (name == "kernel32.dll").then(|| {
            Pe32Builder::new(0x7C80_0000)
                .section(".text", 0x1000, 0x10, &[0xC3; 0x10], pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
                .exports("kernel32.dll", &[("CreateFileA", 0x1000), ("TlsAlloc", 0x1004)])
                .build()
        })
    }

    #[test]
    fn a_dll_the_xp_loader_takes_passes() {
        let report = check(&importer(&["CreateFileA", "TlsAlloc"], &[0xC3; 0x10]), kernel32).unwrap();
        assert!(report.contains("2 imports found"), "{report}");
    }

    #[test]
    fn an_import_newer_than_the_pinned_system_is_refused() {
        let error = check(&importer(&["CreateFileA", "GetFinalPathNameByHandleW"], &[0xC3; 0x10]), kernel32);
        assert!(error.unwrap_err().contains("kernel32.dll does not export GetFinalPathNameByHandleW"));
        let error = check(&importer(&["CreateFileA"], &[0xC3; 0x10]), |_| None).unwrap_err();
        assert!(error.contains("imports kernel32.dll, not in the pinned system32"), "{error}");
    }

    #[test]
    fn code_reading_the_tls_array_is_refused() {
        let code = [0x64, 0xA1, 0x2C, 0, 0, 0, 0xC3, 0xC3];
        let error = check(&importer(&["CreateFileA"], &code), kernel32).unwrap_err();
        assert!(error.contains("1 reads of the TLS array"), "{error}");
    }

    #[test]
    fn the_llvm_subproject_names_its_libraries_in_order() {
        let text = llvm_subproject_text(
            "11.1.0",
            false,
            &["LLVMMCJIT".into(), "LLVMSupport".into()],
            &["-lpsapi".into()],
            &[PathBuf::from("D:\\XP clone\\llvm\\include"), PathBuf::from("D:/b/include")],
            Path::new("D:\\XP clone\\b\\lib"),
        );
        assert!(text.contains("project('llvm', ['cpp'], version : '11.1.0')"));
        assert!(text.contains("foreach name : ['LLVMMCJIT', 'LLVMSupport']"));
        assert!(text.contains("dirs : 'D:/XP clone/b/lib'"), "{text}");
        assert!(text.contains("include_directories('D:/XP clone/llvm/include', 'D:/b/include')"));
        assert!(text.contains("link_args : ['-lpsapi']"));
        assert!(text.contains("has_rtti = false"));
    }

    #[test]
    fn the_native_file_links_xpcompat_first_and_everything_static() {
        let toolchain = Toolchain {
            bin: None,
            gcc: "C:\\tc\\gcc.exe".into(),
            gxx: "C:\\tc\\g++.exe".into(),
            ar: "C:\\tc\\ar.exe".into(),
            strip: "C:\\tc\\strip.exe".into(),
        };
        let text = native_file_text(&toolchain, "py", Path::new("C:\\b\\xpcompat.o"));
        assert!(text.contains("c = 'C:/tc/gcc.exe'\n"));
        assert!(!text.contains("llvm-config"), "LLVM comes from its subproject");
        assert!(text.contains("python3 = 'py'\n"));
        assert!(text.contains("c_link_args = ['C:/b/xpcompat.o', '-static', '-static-libgcc', '-Wl,"));
        assert!(text.contains("cpp_link_args = ['C:/b/xpcompat.o', '-static', '-static-libgcc', '-static-libstdc++'"));
        assert!(text.contains("'-Wl,--minor-subsystem-version,1'"));
    }
}
