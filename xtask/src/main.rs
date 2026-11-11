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

mod fat32;
mod inflate;
mod install;
mod iso9660;
#[cfg(windows)]
mod job;
mod native;
mod ntfs_disk;
mod partition;
mod qemu;
mod rostests;
mod scenario;
mod screen;
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
  image   create one bootable GPT image (ESP + system volume)
          --output FILE       destination; must not exist (default target/mino.img)
          --features F        ntoskrnl features (default test-smss)
          --initial-command P  program booted as winlogon.exe (default BOOT1.EXE)
                              BOOT1 offers install or live desktop; `system`
                              keeps ReactOS winlogon.exe; native programs need MinGW
  lint    rustfmt --check, the generated service tables up to date, then
          clippy -D warnings on the host and the bare-metal targets (06 §6)
  run     build, then boot in QEMU with the serial port on stdio
          --image FILE        boot an existing image without rebuilding
          --cpu CPU           default | intel | QEMU -cpu model
          --features F        ntoskrnl features
          --memory MB         guest memory (default 256)
          --gdb               wait for gdb on :1234 (QEMU -s -S)
          --headless          no display window
          --add PATH:FATPATH  add a host file to the FAT ramdisk (repeatable),
                              as DIR/NAME.EXT (8.3); the fetched userland
                              goes under WINDOWS/SYSTEM32
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
  rostests-fetch
          sparse-clone the pinned ReactOS 0.4.16 tree (apitests, SDK
          headers, PSEH) into third_party/reactos-0.4.16/ with git
  rostests-build
          compile the ntdll and kernel32 apitests with MinGW into
          target/xtask/rostests/ (NTAPITST, K32APITST and their runners)

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
        Some("image") => install_image(&ws, args),
        Some("run") => run(&ws, args),
        Some("test") => test(&ws, args),
        Some("syscall-gen") => {
            args.finish()?;
            cargo(&ws, &["run", "--quiet", "-p", "syscall-gen"])
        }
        Some("fetch-userland") => userland::fetch(&ws, args),
        Some("rostests-fetch") => {
            args.finish()?;
            rostests::fetch(&ws)
        }
        Some("rostests-build") => {
            args.finish()?;
            match rostests::build(&ws)? {
                Some(_) => Ok(()),
                None => Err(format!("rostests needs {}", rostests::missing(&ws).unwrap_or_default())),
            }
        }
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
     test-page-fault-irql,test-page-fault-access-violation,test-critical-process,\
     test-critical-thread,heartbeat";

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

/// Build a development disk image, without touching a host disk.
fn install_image(ws: &Workspace, mut args: Args) -> Result<()> {
    let output = args.value("--output")?.map(PathBuf::from).unwrap_or_else(|| ws.target.join("mino.img"));
    // A person drives an image (VirtualBox): `interactive`, or the probe ends
    // its program 10 s after the last key, an installation mid-copy.
    let features = args.value("--features")?.unwrap_or_else(|| "test-smss,interactive".into());
    let initial_command = args.value("--initial-command")?.unwrap_or_else(|| "BOOT1.EXE".into());
    args.finish()?;
    if output.exists() {
        return Err(format!("{} already exists; choose another --output", output.display()));
    }
    let mut files = userland_files(ws)?.ok_or("fetch ReactOS first: cargo xtask fetch-userland")?;
    let artifacts = build(ws, Some(&features))?;
    if initial_command != "system" {
        // The startup choice (or an explicitly selected probe) boots as
        // winlogon.exe, smss's initial command.
        let native = native::build(ws)?.ok_or_else(|| {
            format!("initial-command: the native programs need {}", native::missing_tool().unwrap_or("a compiler"))
        })?;
        files.extend(native);
        put_initial_command(&mut files, &initial_command)?;
    }
    let run_dir = ws.target.join("xtask").join("image-source");
    let esp = qemu::assemble_esp(ws, &run_dir, &artifacts, &files)?;
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    install::create(&esp, &output)?;
    println!("Mino development image: {}", output.display());
    Ok(())
}

/// Builds, then boots interactively: serial on stdio, until QEMU exits.
fn run(ws: &Workspace, mut args: Args) -> Result<()> {
    let image = args.value("--image")?.map(PathBuf::from);
    let cpu = args.value("--cpu")?.map(|c| Cpu::parse(&c)).unwrap_or(Cpu::Default);
    let features = args.value("--features")?;
    let memory_mb = args.value("--memory")?.map(|m| parse_number(&m, "--memory")).transpose()?;
    let gdb = args.flag("--gdb");
    let headless = args.flag("--headless");
    let mut extra_files = args.values("--add")?;
    let data_dir = args.value("--data-dir")?.map(PathBuf::from);
    let options = qemu::Options::from_args(&mut args)?;
    args.finish()?;

    if let Some(image) = image {
        if features.is_some() || !extra_files.is_empty() || data_dir.is_some() {
            return Err("--image cannot be combined with --features, --add or --data-dir".into());
        }
        if !image.is_file() {
            return Err(format!("{} is not an image file", image.display()));
        }
        let run_dir = ws.target.join("xtask").join("run-image");
        std::fs::create_dir_all(&run_dir).map_err(|e| e.to_string())?;
        let machine = Machine {
            firmware: qemu::find_firmware(&options, &run_dir)?,
            esp: PathBuf::new(),
            cpu,
            memory_mb: memory_mb.unwrap_or(qemu::DEFAULT_MEMORY_MB),
            data_dir: None,
            system_disk: None,
            boot_disk: Some(image),
        };
        return run_machine(&machine, &options, headless, gdb);
    }

    let artifacts = build(ws, features.as_deref())?;
    match userland_files(ws)? {
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
        system_disk: None,
        boot_disk: None,
    };
    run_machine(&machine, &options, headless, gdb)
}

fn run_machine(machine: &Machine, options: &qemu::Options, headless: bool, gdb: bool) -> Result<()> {
    if gdb {
        println!("xtask: QEMU waits for gdb: target remote :1234");
    }
    let status = machine
        .command(options)?
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
        if sc.ntfs_disk {
            if let Some(tool) = ntfs_disk::missing_tool() {
                println!("xtask: SKIP {}: needs {tool} (ntfs-3g)", sc.name);
                skipped.push(sc.name.clone());
                continue;
            }
        }
        let mut extra_files = Vec::new();
        if sc.requires_userland {
            match userland_files(ws)? {
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
                    let tool = native::missing_tool().unwrap_or("a compiler");
                    println!("xtask: SKIP {}: tests/native needs {tool} (MinGW, clang, lld, llvm)", sc.name);
                    skipped.push(sc.name.clone());
                    continue;
                }
            }
        }
        if sc.requires_rostests {
            match rostests::build(ws)? {
                Some(files) => extra_files.extend(files),
                None => {
                    let what = rostests::missing(ws).unwrap_or_default();
                    println!("xtask: SKIP {}: rostests needs {what}", sc.name);
                    skipped.push(sc.name.clone());
                    continue;
                }
            }
        }
        if let Some(program) = &sc.initial_command {
            put_initial_command(&mut extra_files, program)?;
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
            // A system disk starts as the ramdisk (or an installed image). A
            // setup target is a distinct blank secondary ATA disk.
            let attached_disk = (sc.system_disk || sc.target_disk || sc.ntfs_disk).then(|| run_dir.join("c.img"));
            if let Some(image) = &attached_disk {
                if sc.ntfs_disk {
                    ntfs_disk::create(&run_dir, image)?;
                } else if sc.target_disk {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(image)
                        .map_err(|e| format!("{}: {e}", image.display()))?;
                    file.set_len(128 * 1024 * 1024).map_err(|e| format!("{}: {e}", image.display()))?;
                } else if sc.installed_disk {
                    install::create(&esp, image)?;
                } else if sc.gpt_disk {
                    partition::create(&esp.join("fat.img"), image)?;
                } else {
                    std::fs::copy(esp.join("fat.img"), image).map_err(|e| format!("{}: {e}", image.display()))?;
                }
            }
            // An installed image beside a target: the image is a file of its
            // own, the primary boot disk; the target stays the secondary
            // master (c.img).
            let boot_image = (sc.installed_disk && sc.target_disk).then(|| run_dir.join("boot.img"));
            if let Some(image) = &boot_image {
                install::create(&esp, image)?;
            }
            // The ramdisk image: the source the installer copies, which the
            // check of a setup target compares the copy with.
            let ramdisk_image = esp.join("fat.img");
            // `reboot = target`: the boots after the first start from the
            // target alone, the primary master, as a computer would once
            // installed.
            let installed_target = if sc.reboot_target {
                Some(Machine {
                    firmware: qemu::find_firmware(&options, &run_dir)?,
                    esp: esp.clone(),
                    cpu: cpu.clone(),
                    memory_mb: qemu::DEFAULT_MEMORY_MB,
                    data_dir: None,
                    boot_disk: attached_disk.clone(),
                    system_disk: None,
                })
            } else {
                None
            };
            let machine = Machine {
                firmware: qemu::find_firmware(&options, &run_dir)?,
                esp,
                cpu,
                memory_mb: qemu::DEFAULT_MEMORY_MB,
                data_dir: None,
                boot_disk: match &boot_image {
                    Some(image) => Some(image.clone()),
                    None if sc.installed_disk => attached_disk.clone(),
                    None => None,
                },
                system_disk: if sc.installed_disk && boot_image.is_none() { None } else { attached_disk.clone() },
            };
            let ntfs_hash =
                if sc.ntfs_disk { Some(ntfs_disk::digest(attached_disk.as_ref().expect("NTFS disk"))?) } else { None };
            let mut outcome = qemu::boot_and_watch(
                &machine,
                installed_target.as_ref(),
                &options,
                sc,
                timeout.unwrap_or(sc.timeout),
                &run_dir,
            )?;
            if let Some(before) = ntfs_hash {
                if ntfs_disk::digest(attached_disk.as_ref().expect("NTFS disk"))? != before {
                    outcome.passed = false;
                    outcome.reason = "NTFS disk changed during a read-only boot".into();
                } else {
                    println!("xtask: {label}: NTFS disk SHA-256 unchanged");
                }
            }
            if let (true, true, Some(image)) = (outcome.passed, sc.system_disk, &attached_disk) {
                let check_image = if sc.gpt_disk { Some(partition::extract(image)?) } else { None };
                match qemu::fsck(check_image.as_deref().unwrap_or(image)) {
                    None => println!(
                        "xtask: WARNING {label}: fsck.vfat not found, {} not checked (dosfstools)",
                        image.display()
                    ),
                    Some(Ok(())) => println!("xtask: {label}: fsck.vfat finds {} clean", image.display()),
                    Some(Err(report)) => {
                        outcome.passed = false;
                        outcome.reason = format!("fsck.vfat finds errors on {}:\n{report}", image.display());
                    }
                }
            }
            if let (true, true, Some(image)) = (outcome.passed, sc.target_disk, &attached_disk) {
                match partition::verify_setup_target(image, &ramdisk_image) {
                    Ok(()) => println!(
                        "xtask: {label}: both GPT copies, both FAT32 volumes and the copied tree are valid in {}",
                        image.display()
                    ),
                    Err(report) => {
                        outcome.passed = false;
                        outcome.reason = report;
                    }
                }
            }
            // Le critère du M5 : le bilan des apitests — [apitest] TOTALS:
            // tests=N failures=N skipped=N — comparé au plancher du scénario
            // et au seuil du jalon.
            if outcome.passed && sc.requires_rostests {
                let log = qemu::read_lossy(&outcome.serial_log);
                let parsed = log.lines().rev().find_map(rostests::parse_totals);
                let floor = sc.apitests_floor.unwrap_or(0);
                match parsed.map(|(tests, failures, _)| rostests::judge(tests, failures, floor)) {
                    Some(Ok(report)) => println!("xtask: {label}: {report}"),
                    Some(Err(report)) => {
                        outcome.passed = false;
                        outcome.reason = report;
                    }
                    None => {
                        outcome.passed = false;
                        outcome.reason = "apitests : le bilan [apitest] TOTALS n'est pas dans le journal".into();
                    }
                }
            }
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

/// The path of `winlogon.exe` on the ramdisk, which `smss` starts.
const INITIAL_COMMAND: &str = "WINDOWS/SYSTEM32/WINLOGON.EXE";
/// Where an installer medium keeps the real Winlogon while SETUP1.EXE is
/// the initial command. The installer restores it on the target volume.
const INSTALLED_WINLOGON: &str = "WINDOWS/SYSTEM32/WINLOGON.ORG";

/// Among the ramdisk's `files` (`HOST:FAT_PATH`), the test program
/// `program` (built from `tests/native/`) takes the place of `winlogon.exe`.
fn put_initial_command(files: &mut Vec<String>, program: &str) -> Result<()> {
    // L'entrée `HOST:FAT_PATH` dont le chemin FAT se termine par le
    // programme : à la racine du disque pour les sondes natives
    // (`TASKL.EXE`), dans `WINDOWS/SYSTEM32` pour les applications du
    // payload (`TASKMGR.EXE`). Le dernier `:` sépare le chemin du hôte de
    // son chemin FAT, qui n'en contient pas.
    let host = files
        .iter()
        .find_map(|file| {
            let (host, fat) = file.rsplit_once(':')?;
            (fat == program || fat.ends_with(&format!("/{program}"))).then(|| host.to_string())
        })
        .ok_or_else(|| format!("initial-command: no test program {program} on the boot disk"))?
        .to_string();
    let initial_suffix = format!(":{INITIAL_COMMAND}");
    let real = files
        .iter_mut()
        .find(|file| file.ends_with(&initial_suffix))
        .ok_or_else(|| format!("initial-command: the userland has no {INITIAL_COMMAND}"))?;
    let real_host = real.strip_suffix(&initial_suffix).expect("the matching suffix").to_string();
    *real = format!("{real_host}:{INSTALLED_WINLOGON}");
    files.push(format!("{host}:{INITIAL_COMMAND}"));
    Ok(())
}

/// The files of the fetched userland for the FAT ramdisk (`HOST:FAT_PATH`),
/// under `WINDOWS/SYSTEM32`: `NTDLL.DLL`, which the kernel installs as the
/// system DLL, the NLS tables each process maps, and the others of
/// `userland::boot_files`; `None` until `fetch-userland` ran.
fn userland_files(ws: &Workspace) -> Result<Option<Vec<String>>> {
    let Some(mut files) = userland::boot_files(ws) else { return Ok(None) };
    userland::layer_hives(ws, &mut files)?;
    Ok(Some(files.into_iter().map(|(path, name)| format!("{}:{name}", path.display())).collect()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_program_takes_the_place_of_winlogon() {
        let mut files = vec![
            "/u/winlogon.exe:WINDOWS/SYSTEM32/WINLOGON.EXE".to_string(),
            "/n/GUI1.EXE:GUI1.EXE".to_string(),
            "/u/user32.dll:WINDOWS/SYSTEM32/USER32.DLL".to_string(),
        ];
        put_initial_command(&mut files, "GUI1.EXE").unwrap();
        assert_eq!(
            files,
            [
                "/u/winlogon.exe:WINDOWS/SYSTEM32/WINLOGON.ORG",
                "/n/GUI1.EXE:GUI1.EXE",
                "/u/user32.dll:WINDOWS/SYSTEM32/USER32.DLL",
                "/n/GUI1.EXE:WINDOWS/SYSTEM32/WINLOGON.EXE"
            ]
        );
        assert!(put_initial_command(&mut files, "NONE.EXE").is_err());
    }
}
