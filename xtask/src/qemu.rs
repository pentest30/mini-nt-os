//! The QEMU side of `xtask`: ESP layout, firmware, emulator, and a headless
//! boot watched through its serial log.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::scenario::{Scenario, Verdict};
use crate::{cargo, Args, Artifacts, Result, Workspace};

pub const DEFAULT_MEMORY_MB: u32 = 256;

/// How often a watched boot rereads its serial log.
const POLL: Duration = Duration::from_millis(250);

/// QEMU CPU model.
#[derive(Clone)]
pub enum Cpu {
    /// QEMU's default CPU, AMD vendor: the `int 2Eh` path (ADR-004).
    Default,
    /// Intel vendor: the SYSENTER path.
    Intel,
    /// Any other QEMU `-cpu` model.
    Model(String),
}

impl Cpu {
    pub fn parse(s: &str) -> Self {
        match s {
            "default" => Cpu::Default,
            "intel" => Cpu::Intel,
            model => Cpu::Model(model.to_string()),
        }
    }

    /// Short name, for run directories and reports.
    pub fn name(&self) -> String {
        match self {
            Cpu::Default => "default".into(),
            Cpu::Intel => "intel".into(),
            Cpu::Model(m) => m.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect(),
        }
    }

    fn model(&self) -> Option<&str> {
        match self {
            Cpu::Default => None,
            Cpu::Intel => Some("qemu64,vendor=GenuineIntel"),
            Cpu::Model(m) => Some(m),
        }
    }
}

/// Firmware and emulator given on the command line or in the environment.
pub struct Options {
    ovmf: Option<PathBuf>,
    ovmf_code: Option<PathBuf>,
    ovmf_vars: Option<PathBuf>,
    qemu: Option<PathBuf>,
}

impl Options {
    pub fn from_args(args: &mut Args) -> Result<Self> {
        let pick = |arg: Option<String>, var: &str| {
            arg.map(PathBuf::from).or_else(|| std::env::var_os(var).map(PathBuf::from))
        };
        Ok(Self {
            ovmf: pick(args.value("--ovmf")?, "OVMF_PATH"),
            ovmf_code: pick(args.value("--ovmf-code")?, "OVMF_CODE"),
            ovmf_vars: pick(args.value("--ovmf-vars")?, "OVMF_VARS"),
            qemu: pick(args.value("--qemu")?, "QEMU"),
        })
    }
}

/// UEFI firmware for QEMU.
pub enum Firmware {
    /// Combined image, loaded with `-bios`.
    Bios(PathBuf),
    /// Read-only code, and a writable copy of the variable store, as pflash.
    Pflash { code: PathBuf, vars: PathBuf },
}

/// Split images (code, variable store template), preferred when present.
const PFLASH_CANDIDATES: &[(&str, &str)] = &[
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/qemu/edk2-x86_64-code.fd", "/usr/share/qemu/edk2-i386-vars.fd"),
    ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
    (r"C:\Program Files\qemu\share\edk2-x86_64-code.fd", r"C:\Program Files\qemu\share\edk2-i386-vars.fd"),
];

/// Combined images.
const BIOS_CANDIDATES: &[&str] = &[
    "/usr/share/ovmf/OVMF.fd",
    "/usr/share/edk2/ovmf/OVMF.fd",
    "/usr/local/share/qemu/OVMF.fd",
    "/usr/share/qemu/OVMF.fd",
];

/// Picks the firmware: what the options name, else a split image, else a
/// combined one. A pflash variable store is copied into `run_dir` (the
/// firmware writes to it); without a template, a zeroed one is created.
pub fn find_firmware(opts: &Options, run_dir: &Path) -> Result<Firmware> {
    if let Some(bios) = &opts.ovmf {
        return existing(bios).map(|p| Firmware::Bios(p.to_path_buf()));
    }
    let pflash = match &opts.ovmf_code {
        Some(code) => Some((existing(code)?.to_path_buf(), None)),
        None => PFLASH_CANDIDATES
            .iter()
            .map(|(code, vars)| (PathBuf::from(code), Some(PathBuf::from(vars))))
            .find(|(code, _)| code.is_file()),
    };
    if let Some((code, template)) = pflash {
        let template = match &opts.ovmf_vars {
            Some(vars) => Some(existing(vars)?.to_path_buf()),
            None => template.filter(|t| t.is_file()),
        };
        let vars = run_dir.join("ovmf-vars.fd");
        match template {
            Some(t) => fs::copy(&t, &vars).map(drop).map_err(io_error(&t))?,
            None => {
                let size = fs::metadata(&code).map_err(io_error(&code))?.len();
                fs::write(&vars, vec![0u8; size as usize]).map_err(io_error(&vars))?;
            }
        }
        return Ok(Firmware::Pflash { code, vars });
    }
    BIOS_CANDIDATES.iter().map(PathBuf::from).find(|p| p.is_file()).map(Firmware::Bios).ok_or_else(|| {
        "OVMF firmware not found: install it (Debian and Ubuntu: `ovmf`; on Windows QEMU \
             ships share\\edk2-x86_64-code.fd), or pass --ovmf or --ovmf-code"
            .into()
    })
}

fn qemu_binary(opts: &Options) -> Result<PathBuf> {
    if let Some(qemu) = &opts.qemu {
        return existing(qemu).map(Path::to_path_buf);
    }
    let exe = if cfg!(windows) { "qemu-system-x86_64.exe" } else { "qemu-system-x86_64" };
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join(exe))
        .chain([PathBuf::from(r"C:\Program Files\qemu\qemu-system-x86_64.exe")])
        .find(|p| p.is_file())
        .ok_or_else(|| "qemu-system-x86_64 not found: install QEMU, or pass --qemu".into())
}

/// A virtual machine booting the ESP.
pub struct Machine {
    pub firmware: Firmware,
    pub esp: PathBuf,
    pub cpu: Cpu,
    pub memory_mb: u32,
    /// Host directory exposed as a FAT disk on the secondary IDE channel.
    pub data_dir: Option<PathBuf>,
    /// The image of the system disk `C:`, master of the secondary IDE
    /// channel.
    pub system_disk: Option<PathBuf>,
}

impl Machine {
    /// The QEMU command, without the serial port and display options.
    pub fn command(&self, opts: &Options) -> Result<Command> {
        let mut cmd = Command::new(qemu_binary(opts)?);
        if let Some(model) = self.cpu.model() {
            cmd.args(["-cpu", model]);
        }
        match &self.firmware {
            Firmware::Bios(image) => {
                cmd.arg("-bios").arg(image);
            }
            Firmware::Pflash { code, vars } => {
                cmd.arg("-drive").arg(drive("if=pflash,format=raw,readonly=on", code, ""));
                cmd.arg("-drive").arg(drive("if=pflash,format=raw", vars, ""));
            }
        }
        // Virtual FAT disks, read-write: the firmware stores NvVars on the ESP.
        cmd.arg("-drive").arg(drive("format=raw", &self.esp, "fat:rw:"));
        match (&self.data_dir, &self.system_disk) {
            (Some(_), Some(_)) => {
                return Err("the data directory and the system disk both want the secondary IDE master".into())
            }
            (Some(dir), None) => {
                // Secondary IDE master: ports 0x170-0x177.
                cmd.arg("-drive").arg(drive("if=none,id=data,format=raw", dir, "fat:rw:"));
                cmd.args(["-device", "ide-hd,drive=data,bus=ide.1"]);
            }
            (None, Some(image)) => {
                cmd.arg("-drive").arg(drive("if=none,id=system,format=raw", image, ""));
                cmd.args(["-device", "ide-hd,drive=system,bus=ide.1"]);
            }
            (None, None) => {}
        }
        cmd.args(["-m", &format!("{}M", self.memory_mb), "-no-reboot"]);
        Ok(cmd)
    }
}

/// A `-drive` value; QEMU wants the commas of the file name doubled.
fn drive(options: &str, file: &Path, protocol: &str) -> String {
    format!("{options},file={protocol}{}", file.display().to_string().replace(',', ",,"))
}

/// Lays out a fresh ESP in `run_dir/esp`: the loader as the removable-media
/// boot file, the kernel, and the FAT ramdisk from mkfat, with `extra_files`
/// (`HOST_PATH:FAT_NAME`) added to it.
pub fn assemble_esp(ws: &Workspace, run_dir: &Path, artifacts: &Artifacts, extra_files: &[String]) -> Result<PathBuf> {
    if run_dir.exists() {
        fs::remove_dir_all(run_dir).map_err(io_error(run_dir))?;
    }
    let esp = run_dir.join("esp");
    let boot = esp.join("EFI").join("BOOT");
    fs::create_dir_all(&boot).map_err(io_error(&boot))?;
    copy(&artifacts.loader, &boot.join("BOOTX64.EFI"))?;
    // The loader reads \kernel.elf; \EFI\MINO\ntoskrnl.elf (02 §9.1) will
    // come with the system image.
    copy(&artifacts.kernel, &esp.join("kernel.elf"))?;

    let ramdisk = esp.join("fat.img");
    let ramdisk = ramdisk.to_str().ok_or_else(|| format!("non UTF-8 path: {}", ramdisk.display()))?;
    let mut mkfat = vec!["run", "--quiet", "-p", "mkfat", "--", ramdisk];
    mkfat.extend(extra_files.iter().map(String::as_str));
    cargo(ws, &mkfat)?;
    Ok(esp)
}

/// Result of a watched boot.
pub struct Outcome {
    pub passed: bool,
    pub reason: String,
    pub elapsed: Duration,
    pub serial_log: PathBuf,
}

/// Boots headless, with the serial port in `run_dir/serial.log`, and rereads
/// the log until the scenario passes or fails, QEMU exits, or `timeout`.
pub fn boot_and_watch(
    machine: &Machine,
    opts: &Options,
    scenario: &Scenario,
    timeout: Duration,
    run_dir: &Path,
) -> Result<Outcome> {
    let start = Instant::now();
    let mut earlier = String::new();
    for boot in 1..scenario.boots {
        let serial_log = run_dir.join(format!("serial-{boot}.log"));
        let outcome = boot_once(machine, opts, scenario, timeout, run_dir, &serial_log, &earlier, true)?;
        if !outcome.passed {
            return Ok(Outcome { reason: format!("boot {boot}: {}", outcome.reason), ..outcome });
        }
        earlier.push_str(&read_lossy(&serial_log));
    }
    let serial_log = run_dir.join("serial.log");
    let outcome = boot_once(machine, opts, scenario, timeout, run_dir, &serial_log, &earlier, false)?;
    Ok(Outcome { elapsed: start.elapsed(), ..outcome })
}

/// One boot. With `until_exit`, it passes when QEMU exits (the kernel reset
/// the machine) without a forbidden marker; otherwise when the scenario's
/// markers are all in `earlier` and this boot's serial log.
#[expect(clippy::too_many_arguments, reason = "the parts of one boot, used once")]
fn boot_once(
    machine: &Machine,
    opts: &Options,
    scenario: &Scenario,
    timeout: Duration,
    run_dir: &Path,
    serial_log: &Path,
    earlier: &str,
    until_exit: bool,
) -> Result<Outcome> {
    let qemu_log = run_dir.join("qemu.log");
    let stdout = fs::File::create(&qemu_log).map_err(io_error(&qemu_log))?;
    let stderr = stdout.try_clone().map_err(io_error(&qemu_log))?;
    let mut serial = OsString::from("file:");
    serial.push(serial_log);

    let mut child = machine
        .command(opts)?
        .arg("-serial")
        .arg(serial)
        .args(["-display", "none"])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| format!("cannot start QEMU: {e}"))?;

    let start = Instant::now();
    let (passed, mut reason) = loop {
        std::thread::sleep(POLL);
        // Read the log after checking for exit, so that it is complete.
        let exited = child.try_wait().map_err(|e| format!("QEMU: {e}"))?;
        let log = format!("{earlier}{}", read_lossy(serial_log));
        if until_exit {
            if let Some(why) = scenario.forbidden(&log) {
                break (false, why);
            }
            if exited.is_some() {
                break (true, String::new());
            }
            if start.elapsed() >= timeout {
                break (false, format!("timeout ({} s) before the machine reset", timeout.as_secs()));
            }
            continue;
        }
        match scenario.check(&log) {
            Verdict::Pass => break (true, String::new()),
            Verdict::Fail(why) => break (false, why),
            Verdict::Pending(missing) => {
                if let Some(status) = exited {
                    break (false, format!("QEMU exited ({status}); missing: {}", missing.join("; ")));
                }
                if start.elapsed() >= timeout {
                    break (false, format!("timeout ({} s); missing: {}", timeout.as_secs(), missing.join("; ")));
                }
            }
        }
    };
    let elapsed = start.elapsed();
    // Already exited, or no longer needed.
    let _ = child.kill();
    let _ = child.wait();

    let qemu_output = read_lossy(&qemu_log);
    if !passed && !qemu_output.trim().is_empty() {
        reason.push_str("\nQEMU output:\n");
        reason.push_str(qemu_output.trim_end());
    }
    Ok(Outcome { passed, reason, elapsed, serial_log: serial_log.to_path_buf() })
}

/// `fsck.vfat -n` on the disk image `image`: `None` without dosfstools,
/// otherwise `Err` with its report if it finds an error.
pub fn fsck(image: &Path) -> Option<std::result::Result<(), String>> {
    let program = ["/usr/sbin/fsck.vfat", "/sbin/fsck.vfat", "fsck.vfat"]
        .into_iter()
        .find(|p| Command::new(p).arg("--help").output().is_ok())?;
    let output = match Command::new(program).arg("-n").arg(image).output() {
        Ok(output) => output,
        Err(e) => return Some(Err(format!("cannot run {program}: {e}"))),
    };
    let report = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    Some(if output.status.success() { Ok(()) } else { Err(report) })
}

/// The file as text, invalid UTF-8 replaced; empty if it cannot be read.
pub fn read_lossy(path: &Path) -> String {
    fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

fn copy(from: &Path, to: &Path) -> Result<()> {
    fs::copy(from, to).map(drop).map_err(io_error(from))
}

fn existing(path: &Path) -> Result<&Path> {
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("{}: no such file", path.display()))
    }
}

fn io_error(path: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("{}: {e}", path.display())
}
