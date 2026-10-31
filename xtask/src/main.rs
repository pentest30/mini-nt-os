//! `cargo xtask`: Mino's build and test driver (02 §9.2). Written in Rust so
//! that it behaves the same on Linux and Windows; std only.
//!
//! ```text
//! cargo xtask build [--features F]
//! cargo xtask lint
//! cargo xtask run   [--cpu CPU] [--features F] [--memory MB] [--gdb] [--headless]
//!                   [--add HOST_PATH:FAT_NAME]... [--data-dir DIR]
//! cargo xtask test  [--host] [--boot] [--scenario NAME]... [--cpu CPU] [--timeout S]
//! cargo xtask syscall-gen
//! cargo xtask fetch-userland [--archive FILE] [--force]
//! ```
//!
//! CPU is `default` (QEMU's CPU, AMD vendor: `int 2Eh`), `intel` (SYSENTER,
//! ADR-004) or any QEMU `-cpu` model. Boot scenarios live in
//! `tests/boot/<scenario>/scenario.txt`.
//!
//! The firmware and the emulator are found automatically, or given with
//! `--ovmf FILE` (combined image), `--ovmf-code FILE` and `--ovmf-vars FILE`
//! (pflash pair), `--qemu FILE`, or the `OVMF_PATH`, `OVMF_CODE`, `OVMF_VARS`
//! and `QEMU` environment variables.

mod inflate;
mod iso9660;
mod native;
mod qemu;
mod scenario;
mod sha256;
mod userland;
mod zip;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use qemu::{Cpu, Machine};

type Result<T> = std::result::Result<T, String>;

/// Cargo profile of the loader and kernel builds (root Cargo.toml).
const PROFILE: &str = "kernel";
const LOADER_TARGET: &str = "x86_64-unknown-uefi";
const KERNEL_TARGET: &str = "x86_64-unknown-none";

const USAGE: &str = "\
usage: cargo xtask <command> [options]

commands:
  build   build mino-loader and ntoskrnl
          --features F        ntoskrnl features (comma-separated)
  lint    rustfmt --check, the generated service tables up to date, then
          clippy -D warnings on the host and the bare-metal targets (06 §6)
  run     build, then boot in QEMU with the serial port on stdio
          --cpu CPU           default | intel | QEMU -cpu model
          --features F        ntoskrnl features
          --memory MB         guest memory (default 256)
          --gdb               wait for gdb on :1234 (QEMU -s -S)
          --headless          no display window
          --add PATH:NAME     add a host file to the FAT ramdisk (repeatable);
                              NTDLL.DLL comes with the fetched userland
          --data-dir DIR      expose DIR as a FAT disk on IDE secondary
  test    host tests, then the boot scenarios of tests/boot/
          --host              host tests (alone, unless --boot)
          --boot              boot scenarios (alone, unless --host)
          --scenario NAME     only this scenario (repeatable)
          --cpu CPU           only this CPU
          --timeout S         override the scenarios' timeout
  syscall-gen
          regenerate abi/src/services.rs from the pinned ReactOS service
          lists (tools/syscall-gen, ADR-002)
  fetch-userland
          download the pinned ReactOS release (curl), check its SHA-256 and
          unpack its system tree into third_party/reactos/<version>/
          --archive FILE      use this copy of the release archive
          --force             unpack again

firmware and emulator (run, test):
  --ovmf FILE | --ovmf-code FILE [--ovmf-vars FILE] | --qemu FILE
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(Args(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(mut args: Args) -> Result<()> {
    let ws = Workspace::locate();
    match args.command().as_deref() {
        Some("build") => {
            let features = args.value("--features")?;
            args.finish()?;
            let artifacts = build(&ws, features.as_deref())?;
            println!("mino-loader: {}", artifacts.loader.display());
            println!("ntoskrnl:    {}", artifacts.kernel.display());
            Ok(())
        }
        Some("lint") => {
            args.finish()?;
            lint(&ws)
        }
        Some("run") => run(&ws, args),
        Some("test") => test(&ws, args),
        Some("syscall-gen") => {
            args.finish()?;
            cargo(&ws, &["run", "--quiet", "-p", "syscall-gen"])
        }
        Some("fetch-userland") => userland::fetch(&ws, args),
        Some("help") | Some("-h") | Some("--help") | None => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Every ntoskrnl feature, checked together by `lint`.
const ALL_KERNEL_FEATURES: &str =
    "trace-syscalls,test-stack-overflow,test-ke-events,test-fpu,test-bugcheck,test-ke-starvation,\
     test-page-fault-irql,test-page-fault-access-violation,heartbeat";

/// `cargo fmt --check`, the service tables generated from the pinned ReactOS
/// lists up to date (`syscall-gen --check`), then clippy with warnings
/// denied: the host workspace,
/// and the kernel and loader on their own targets (cfg(target_os = "none")
/// code), the kernel with and without its features. `-D warnings` goes to
/// clippy, not RUSTFLAGS, which would replace the target flags of
/// .cargo/config.toml.
fn lint(ws: &Workspace) -> Result<()> {
    cargo(ws, &["fmt", "--all", "--check"])?;
    cargo(ws, &["run", "--quiet", "-p", "syscall-gen", "--", "--check"])?;
    cargo(ws, &["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])?;
    let bare_metal: [&[&str]; 3] = [
        &["-p", "ntoskrnl", "--target", KERNEL_TARGET],
        &["-p", "ntoskrnl", "--target", KERNEL_TARGET, "--features", ALL_KERNEL_FEATURES],
        &["-p", "mino-loader", "--target", LOADER_TARGET],
    ];
    for target_args in bare_metal {
        let mut args = vec!["clippy", "--profile", PROFILE];
        args.extend_from_slice(target_args);
        args.extend_from_slice(&["--", "-D", "warnings"]);
        cargo(ws, &args)?;
    }
    println!("xtask: lint clean");
    Ok(())
}

/// Builds, then boots interactively: serial on stdio, until QEMU exits.
fn run(ws: &Workspace, mut args: Args) -> Result<()> {
    let cpu = args.value("--cpu")?.map(|c| Cpu::parse(&c)).unwrap_or(Cpu::Default);
    let features = args.value("--features")?;
    let memory_mb = args.value("--memory")?.map(|m| parse_number(&m, "--memory")).transpose()?;
    let gdb = args.flag("--gdb");
    let headless = args.flag("--headless");
    let mut extra_files = args.values("--add")?;
    let data_dir = args.value("--data-dir")?.map(PathBuf::from);
    let options = qemu::Options::from_args(&mut args)?;
    args.finish()?;

    let artifacts = build(ws, features.as_deref())?;
    match userland_files(ws) {
        Some(files) => {
            extra_files.extend(files);
            // The native test programs, if MinGW can build them.
            extra_files.extend(native::build(ws)?.unwrap_or_default());
        }
        None => println!("xtask: no ReactOS userland (cargo xtask fetch-userland): the kernel boots without ntdll"),
    }
    let run_dir = ws.target.join("xtask").join("run");
    let esp = qemu::assemble_esp(ws, &run_dir, &artifacts, &extra_files)?;
    let machine = Machine {
        firmware: qemu::find_firmware(&options, &run_dir)?,
        esp,
        cpu,
        memory_mb: memory_mb.unwrap_or(qemu::DEFAULT_MEMORY_MB),
        data_dir,
    };
    if gdb {
        println!("xtask: QEMU waits for gdb: target remote :1234");
    }
    let status = machine
        .command(&options)?
        .args(["-serial", "stdio"])
        .args(if headless { &["-display", "none"][..] } else { &[] })
        .args(if gdb { &["-s", "-S"][..] } else { &[] })
        .status()
        .map_err(|e| format!("cannot start QEMU: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU exited with {status}"))
    }
}

/// Host tests, then each boot scenario on each of its CPUs.
fn test(ws: &Workspace, mut args: Args) -> Result<()> {
    // Neither flag: both parts.
    let (host, boot) = match (args.flag("--host"), args.flag("--boot")) {
        (false, false) => (true, true),
        flags => flags,
    };
    let names = args.values("--scenario")?;
    let cpu = args.value("--cpu")?.map(|c| Cpu::parse(&c));
    let timeout = args
        .value("--timeout")?
        .map(|t| parse_number(&t, "--timeout").map(|s| Duration::from_secs(s.into())))
        .transpose()?;
    let options = qemu::Options::from_args(&mut args)?;
    args.finish()?;

    if host {
        cargo(ws, &["test", "--workspace"])?;
    }
    if !boot {
        return Ok(());
    }

    let scenarios = scenario::load_all(&ws.root.join("tests").join("boot"), &names)?;
    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    let mut runs = 0;
    for sc in &scenarios {
        let mut extra_files = Vec::new();
        if sc.requires_userland {
            match userland_files(ws) {
                Some(files) => extra_files.extend(files),
                None => {
                    println!("xtask: SKIP {}: needs the ReactOS userland (cargo xtask fetch-userland)", sc.name);
                    skipped.push(sc.name.clone());
                    continue;
                }
            }
        }
        if sc.requires_native {
            match native::build(ws)? {
                Some(files) => extra_files.extend(files),
                None => {
                    println!("xtask: SKIP {}: needs MinGW (i686-w64-mingw32-gcc) for tests/native", sc.name);
                    skipped.push(sc.name.clone());
                    continue;
                }
            }
        }
        let cpus = match &cpu {
            Some(cpu) => vec![cpu.clone()],
            None => sc.cpus.clone(),
        };
        let artifacts = build(ws, Some(&sc.features.join(",")))?;
        for cpu in cpus {
            runs += 1;
            let label = format!("{} ({})", sc.name, cpu.name());
            println!("xtask: boot {label}");
            let run_dir = ws.target.join("xtask").join("boot").join(format!("{}-{}", sc.name, cpu.name()));
            let esp = qemu::assemble_esp(ws, &run_dir, &artifacts, &extra_files)?;
            let machine = Machine {
                firmware: qemu::find_firmware(&options, &run_dir)?,
                esp,
                cpu,
                memory_mb: qemu::DEFAULT_MEMORY_MB,
                data_dir: None,
            };
            let outcome = qemu::boot_and_watch(&machine, &options, sc, timeout.unwrap_or(sc.timeout), &run_dir)?;
            if outcome.passed {
                println!("xtask: PASS {label} in {:.1} s", outcome.elapsed.as_secs_f64());
            } else {
                println!("xtask: FAIL {label}: {}", outcome.reason);
                println!("--- serial log ({}) ---", outcome.serial_log.display());
                println!("{}", qemu::read_lossy(&outcome.serial_log));
                println!("--- end of serial log ---");
                failures.push(label);
            }
        }
    }
    if !skipped.is_empty() {
        println!("xtask: {} scenario(s) skipped: {}", skipped.len(), skipped.join(", "));
    }
    if failures.is_empty() {
        println!("xtask: {runs} boot run(s) passed");
        Ok(())
    } else {
        Err(format!("{} of {runs} boot run(s) failed: {}", failures.len(), failures.join(", ")))
    }
}

/// The files of the fetched userland for the FAT ramdisk (`HOST:FAT_NAME`):
/// `NTDLL.DLL`, which the kernel installs as the system DLL, and the NLS
/// tables each process maps (`userland::boot_files`); `None` until
/// `fetch-userland` ran.
fn userland_files(ws: &Workspace) -> Option<Vec<String>> {
    let files = userland::boot_files(ws)?;
    Some(files.into_iter().map(|(path, name)| format!("{}:{name}", path.display())).collect())
}

// ── Building ──────────────────────────────────────────────────────────────────

/// The two images a boot needs.
pub struct Artifacts {
    pub loader: PathBuf,
    pub kernel: PathBuf,
}

/// Builds `mino-loader` and `ntoskrnl` (with `features`, comma-separated).
fn build(ws: &Workspace, features: Option<&str>) -> Result<Artifacts> {
    cargo(ws, &["build", "-p", "mino-loader", "--target", LOADER_TARGET, "--profile", PROFILE])?;
    let mut kernel = vec!["build", "-p", "ntoskrnl", "--target", KERNEL_TARGET, "--profile", PROFILE];
    if let Some(f) = features.filter(|f| !f.is_empty()) {
        kernel.extend(["--features", f]);
    }
    cargo(ws, &kernel)?;
    Ok(Artifacts {
        loader: ws.target.join(LOADER_TARGET).join(PROFILE).join("mino-loader.efi"),
        kernel: ws.target.join(KERNEL_TARGET).join(PROFILE).join("ntoskrnl"),
    })
}

/// Runs cargo in the workspace root and fails if it fails.
pub fn cargo(ws: &Workspace, args: &[&str]) -> Result<()> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status =
        Command::new(&cargo).args(args).current_dir(&ws.root).status().map_err(|e| format!("cannot run cargo: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`cargo {}` failed ({status})", args.join(" ")))
    }
}

/// Repository root and Cargo target directory.
pub struct Workspace {
    pub root: PathBuf,
    pub target: PathBuf,
}

impl Workspace {
    fn locate() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask lives one level below the workspace root")
            .to_path_buf();
        let target = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| root.join("target"));
        Self { root, target }
    }
}

// ── Arguments ─────────────────────────────────────────────────────────────────

/// Remaining command-line arguments, consumed option by option.
pub struct Args(Vec<String>);

impl Args {
    fn command(&mut self) -> Option<String> {
        (!self.0.is_empty()).then(|| self.0.remove(0))
    }

    /// Removes `name` if present.
    pub fn flag(&mut self, name: &str) -> bool {
        let found = self.0.iter().any(|a| a == name);
        self.0.retain(|a| a != name);
        found
    }

    /// Removes `name VALUE` (or `name=VALUE`); the last occurrence wins.
    pub fn value(&mut self, name: &str) -> Result<Option<String>> {
        Ok(self.values(name)?.pop())
    }

    /// Removes every `name VALUE` (or `name=VALUE`), in order.
    pub fn values(&mut self, name: &str) -> Result<Vec<String>> {
        let mut found = Vec::new();
        let mut i = 0;
        while i < self.0.len() {
            if self.0[i] == name {
                if i + 1 >= self.0.len() {
                    return Err(format!("{name} needs a value"));
                }
                found.push(self.0.remove(i + 1));
                self.0.remove(i);
            } else if let Some(v) = self.0[i].strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                found.push(v.to_string());
                self.0.remove(i);
            } else {
                i += 1;
            }
        }
        Ok(found)
    }

    /// Fails on any argument no option consumed.
    fn finish(self) -> Result<()> {
        match self.0.first() {
            None => Ok(()),
            Some(a) => Err(format!("unexpected argument `{a}` (see `cargo xtask help`)")),
        }
    }
}

fn parse_number(s: &str, option: &str) -> Result<u32> {
    s.parse().map_err(|_| format!("{option}: `{s}` is not a number"))
}
