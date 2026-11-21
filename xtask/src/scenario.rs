//! Boot scenarios (ADR-018, 06 §6): one directory per scenario in
//! `tests/boot/`, whose `scenario.txt` names the kernel features, the CPUs to
//! boot on and the serial markers. The directory can later hold the
//! scenario's own files.
//!
//! ```text
//! # Whole-line comment.
//! features = test-stack-overflow
//! cpus     = default, intel
//! timeout  = 120
//! expect   = marker
//! expect   = marker A | marker B
//! forbid   = marker
//! forbid-line-start = prefix
//! requires = userland, native
//! disk     = system
//! boots    = 2
//! screen   = 640 400 3A6EA5
//! keys     = marker => shift-h i ret
//! ```
//!
//! - `features`: ntoskrnl features, comma-separated (default: none).
//! - `cpus`: `default`, `intel` or QEMU `-cpu` models (default: `default`).
//! - `timeout`: upper bound in seconds (default: 120); a run stops as soon
//!   as its verdict is known.
//! - `expect`: must appear in the serial log; with `|`, one of them.
//! - `forbid`: fails the run as soon as it appears anywhere.
//! - `forbid-line-start`: fails the run as soon as a line starts with it.
//! - `requires`, comma-separated; without one of them, the scenario is
//!   skipped:
//!   - `userland`: the ramdisk gets the fetched ReactOS userland (`NTDLL.DLL`
//!     and the NLS tables);
//!   - `native`: the ramdisk gets the native test programs of
//!     `tests/native/`, compiled with MinGW or clang (`xtask/src/native.rs`);
//!   - `rostests`: the ramdisk gets the ReactOS apitests (`NTAPITST.EXE`,
//!     `K32APITST.EXE` and their runners, `xtask/src/rostests.rs`), built
//!     from the tree that `cargo xtask rostests-fetch` clones.
//! - `apitests-floor = N` (with `requires = rostests`, and only then): at
//!   least N apitests must pass, the count of the last measurement; the
//!   share of passing tests is also compared to the M5 threshold, and only
//!   reported.
//! - `disk = installed`: a single GPT disk holds the real ESP and system
//!   partition, replacing the external virtual FAT boot disk.
//! - `disk = system-gpt`: wraps the FAT image in a GPT Basic Data partition;
//!   the two GPT copies are checked and the partition extracted for fsck.
//! - `disk = ntfs-data`: a disposable GPT/NTFS data disk on D:, generated with
//!   mkntfs/ntfscp. Its SHA-256 must remain unchanged after the boot.
//! - `disk = system`: the image of the ramdisk is also the system disk `C:`,
//!   a file attached as the master of the secondary IDE channel, which the
//!   boots share; after the last one, `fsck.vfat -n` must find it clean
//!   (skipped, with a warning, without dosfstools).
//! - `disk = target`: attaches a new, blank 128 MiB secondary ATA disk. It is
//!   never copied from the ramdisk and is not checked as a FAT volume; setup
//!   scenarios use it as a non-system installation candidate. With `disk =
//!   installed` too, the installed image is the primary boot disk and the
//!   target the secondary master.
//! - `reboot = target` (with `disk = installed`, `disk = target` and `boots`
//!   from 2): every boot after the first starts from the target disk alone,
//!   as the primary master: what the first boot installed there must boot.
//! - `boots`: how many times QEMU boots (default 1). Every boot but the last
//!   must end with QEMU (the kernel resets the machine, and `-no-reboot`
//!   makes QEMU exit); the `expect` markers are looked for in all the serial
//!   logs, the last boot's included.
//! - `power-cut = BOOT => MARKER => …` (BOOT before the last): that boot ends
//!   with a power cut instead of a reset: once the markers are in its serial
//!   log, in this order, QEMU is killed, and what the guest had not written
//!   to the disk is lost, as when the machine is switched off. The boot
//!   fails if QEMU exits before.
//! - `expect-last = MARKER => …`: the markers must appear in the serial log
//!   of the last boot itself, in this order (an `expect` marker may come
//!   from any boot).
//! - `screen = X Y RRGGBB`: once the markers are found, the screen of the
//!   last boot is dumped (`screen.ppm` in the run directory) and the pixel
//!   at column X, row Y must have this colour (`xtask/src/screen.rs`).
//! - `screen-wait = SECONDS` (with `screen`): the screen may take that long
//!   to show the pixels once the markers are found (what keys started is
//!   slow to appear): it is dumped again every second until it does.
//! - `screen-size = WIDTH HEIGHT` (with `screen`): the dumped screen must
//!   also have that size (a scenario that changes the display mode).
//! - `keys = MARKER => KEY…`: once MARKER is in the serial log of the boot,
//!   QEMU's monitor types the keys, one after the other (`sendkey`, with
//!   QEMU's key names: `a`, `shift-a`, `ret`, `spc`…), once
//!   (`xtask/src/screen.rs`). A KEY can be a quoted text, `"dir C:\"`: the
//!   keys that type its characters on a US keyboard. The `keys` lines fire
//!   in their order.
//! - `initial-command = PROGRAM.EXE`: this Win32 test program of
//!   `tests/native/` (or of the rostests) takes the place of `winlogon.exe` on the ramdisk, so
//!   that `smss` starts it as its initial command (with `requires =
//!   userland, native`).
//! - `session = PROGRAM.EXE` (with `requires = userland, native`, a system
//!   disk and `boots` from 2): the real `winlogon` sets the system up
//!   (minoinit, first boot), then logs Administrator on (autologon), and
//!   `userinit` starts this test program of `tests/native/` as the shell,
//!   with `/session` on its command line: it runs in the user's session,
//!   under the user's token, with `lsass` and the user's profile. The SOFTWARE
//!   hive of the disk names it (`Winlogon\Shell`).
//! - `shell = explorer` (with `requires = userland`): the boot disk also
//!   takes the shell, `explorer.exe` in `WINDOWS`, and the DLLs it imports
//!   that the other scenarios' disk does not have (`browseui`, `shdocvw`),
//!   which userinit starts after the logon.

use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::qemu::Cpu;
use crate::Result;

pub struct Scenario {
    pub name: String,
    pub features: Vec<String>,
    pub cpus: Vec<Cpu>,
    pub timeout: Duration,
    pub requires_userland: bool,
    pub requires_native: bool,
    /// Les apitests de ReactOS (rostests-build) au disque de démarrage.
    pub requires_rostests: bool,
    /// Les apitests qui doivent passer au moins (`apitests-floor`) : ceux
    /// qui passaient à la dernière mesure.
    pub apitests_floor: Option<u32>,
    /// The ramdisk image is also the system disk `C:`.
    pub system_disk: bool,
    /// Read-only NTFS data disk in a GPT partition, generated by ntfs-3g.
    pub ntfs_disk: bool,
    /// Wrap the system volume in GPT rather than using raw FAT.
    pub gpt_disk: bool,
    /// One real GPT image holds the ESP and system volume.
    pub installed_disk: bool,
    /// Un disque ATA secondaire vide, distinct du système courant.
    pub target_disk: bool,
    /// The boots after the first start from the target disk alone.
    pub reboot_target: bool,
    pub boots: u32,
    /// Guest memory in MiB (`memory`); the QEMU default without it.
    pub memory_mb: Option<u32>,
    /// Pixels the screen must show once the markers are found.
    pub screen: Vec<crate::screen::Pixel>,
    /// How long the screen may take to show them once the markers are found
    /// (`screen-wait`, in seconds): captured again until it does; 0, one
    /// capture.
    pub screen_wait: Duration,
    /// The size the dumped screen must have (`screen-size`), if given.
    pub screen_size: Option<(u32, u32)>,
    /// The test program that takes the place of `winlogon.exe`.
    pub initial_command: Option<String>,
    /// The boot disk takes the shell, `explorer.exe`, and its imports.
    pub shell: bool,
    /// The test program that userinit starts as the shell, in the session
    /// of the logged-on user (`session`).
    pub session: Option<String>,
    /// Keys to type once a marker is in the serial log, in order.
    pub keys: Vec<Keys>,
    /// An application of the M7 bench (`app = ID`, `xtask/src/apps.rs`):
    /// its installer and the probe's command file go to a larger system
    /// disk `C:`, which holds the whole ReactOS tree.
    pub app: Option<String>,
    /// The boot that ends with a power cut, and the markers after which it
    /// is cut.
    pub power_cut: Option<(u32, Sequence)>,
    /// Markers of the last boot's own serial log, each list in its order.
    expect_last: Vec<Sequence>,
    expect: Vec<Vec<String>>,
    forbid: Vec<String>,
    forbid_line_start: Vec<String>,
}

/// Markers that must appear in a serial log in this order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sequence(Vec<String>);

impl Sequence {
    /// `MARKER => MARKER…`.
    fn parse(value: &str) -> std::result::Result<Self, String> {
        let markers: Vec<String> = value.split("=>").map(|marker| marker.trim().to_string()).collect();
        if markers.iter().any(String::is_empty) {
            return Err("expected `MARKER => MARKER…`".into());
        }
        Ok(Self(markers))
    }

    /// The markers are in `log`, each after the end of the one before.
    pub fn found_in(&self, log: &str) -> bool {
        let mut rest = log;
        for marker in &self.0 {
            match rest.find(marker.as_str()) {
                Some(at) => rest = &rest[at + marker.len()..],
                None => return false,
            }
        }
        true
    }
}

impl std::fmt::Display for Sequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join(" => "))
    }
}

/// Keys that QEMU's monitor types once `after` is in the serial log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    pub after: String,
    pub keys: Vec<String>,
}

impl Keys {
    /// `MARKER => KEY…`, where a KEY can also be `"TEXT"`: the keys that type
    /// each character of TEXT on a US keyboard.
    fn parse(value: &str) -> std::result::Result<Self, String> {
        let (after, keys) = value.split_once("=>").ok_or("expected `MARKER => KEY…`")?;
        let (after, keys) = (after.trim(), key_names(keys)?);
        if after.is_empty() || keys.is_empty() {
            return Err("expected `MARKER => KEY…`".into());
        }
        Ok(Self { after: after.to_string(), keys })
    }
}

/// QEMU's key names in `text`: words separated by blanks, each one a key
/// name, or `"TEXT"`, which gives the keys of its characters
/// ([`key_of_char`]).
fn key_names(text: &str) -> std::result::Result<Vec<String>, String> {
    let mut keys = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        if let Some(quoted) = rest.strip_prefix('"') {
            let (inner, after) = quoted.split_once('"').ok_or("a `\"` without its end")?;
            for c in inner.chars() {
                keys.push(key_of_char(c).ok_or_else(|| format!("no key types `{c}`"))?);
            }
            rest = after.trim_start();
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            keys.push(rest[..end].to_string());
            rest = rest[end..].trim_start();
        }
    }
    Ok(keys)
}

/// The QEMU key name (`sendkey`) that types `c` on a US keyboard, with
/// `shift-` if it takes Shift; `None` for a character without a key (or
/// `"`, which ends a quoted text).
fn key_of_char(c: char) -> Option<String> {
    let plain = |name: &str| Some(name.to_string());
    let shifted = |name: &str| Some(format!("shift-{name}"));
    match c {
        'a'..='z' | '0'..='9' => Some(c.to_string()),
        'A'..='Z' => shifted(&c.to_ascii_lowercase().to_string()),
        ' ' => plain("spc"),
        '.' => plain("dot"),
        ',' => plain("comma"),
        '/' => plain("slash"),
        '\\' => plain("backslash"),
        ';' => plain("semicolon"),
        '\'' => plain("apostrophe"),
        '-' => plain("minus"),
        '=' => plain("equal"),
        '[' => plain("bracket_left"),
        ']' => plain("bracket_right"),
        '`' => plain("grave_accent"),
        ':' => shifted("semicolon"),
        '>' => shifted("dot"),
        '<' => shifted("comma"),
        '?' => shifted("slash"),
        '|' => shifted("backslash"),
        '_' => shifted("minus"),
        '+' => shifted("equal"),
        '{' => shifted("bracket_left"),
        '}' => shifted("bracket_right"),
        '~' => shifted("grave_accent"),
        '!' => shifted("1"),
        '@' => shifted("2"),
        '#' => shifted("3"),
        '$' => shifted("4"),
        '%' => shifted("5"),
        '^' => shifted("6"),
        '&' => shifted("7"),
        '*' => shifted("8"),
        '(' => shifted("9"),
        ')' => shifted("0"),
        _ => None,
    }
}

/// State of a boot, judged from its serial log so far.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Pass,
    Fail(String),
    /// Still missing these markers.
    Pending(Vec<String>),
}

impl Scenario {
    pub fn parse(name: &str, text: &str) -> Result<Self> {
        let mut sc = Scenario {
            name: name.to_string(),
            features: Vec::new(),
            cpus: vec![Cpu::Default],
            timeout: Duration::from_secs(120),
            requires_userland: false,
            requires_native: false,
            requires_rostests: false,
            apitests_floor: None,
            system_disk: false,
            ntfs_disk: false,
            gpt_disk: false,
            installed_disk: false,
            target_disk: false,
            reboot_target: false,
            boots: 1,
            memory_mb: None,
            screen: Vec::new(),
            screen_wait: Duration::ZERO,
            screen_size: None,
            initial_command: None,
            session: None,
            shell: false,
            keys: Vec::new(),
            app: None,
            power_cut: None,
            expect_last: Vec::new(),
            expect: Vec::new(),
            forbid: Vec::new(),
            forbid_line_start: Vec::new(),
        };
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = || format!("{name}/{SCENARIO_FILE}:{}", n + 1);
            let (key, value) = line
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| format!("{}: expected `key = value`", at()))?;
            let list = || value.split(',').map(str::trim).filter(|s| !s.is_empty());
            match key {
                "features" => sc.features = list().map(String::from).collect(),
                "cpus" => sc.cpus = list().map(Cpu::parse).collect(),
                "timeout" => {
                    let secs = value.parse().map_err(|_| format!("{}: timeout `{value}` is not a number", at()))?;
                    sc.timeout = Duration::from_secs(secs);
                }
                "expect" => sc.expect.push(value.split('|').map(|m| m.trim().to_string()).collect()),
                "expect-last" => sc.expect_last.push(Sequence::parse(value).map_err(|e| format!("{}: {e}", at()))?),
                "power-cut" => {
                    let (boot, after) = value
                        .split_once("=>")
                        .ok_or_else(|| format!("{}: expected `power-cut = BOOT => MARKER…`", at()))?;
                    let boot =
                        boot.trim().parse().ok().filter(|&boot| boot >= 1).ok_or_else(|| {
                            format!("{}: power-cut boot `{}` is not a number from 1", at(), boot.trim())
                        })?;
                    sc.power_cut = Some((boot, Sequence::parse(after).map_err(|e| format!("{}: {e}", at()))?));
                }
                "forbid" => sc.forbid.push(value.to_string()),
                "forbid-line-start" => sc.forbid_line_start.push(value.to_string()),
                "initial-command" => sc.initial_command = Some(value.to_string()),
                "session" => sc.session = Some(value.to_string()),
                "shell" => match value {
                    "explorer" => sc.shell = true,
                    _ => return Err(format!("{}: unknown shell `{value}`", at())),
                },
                "apitests-floor" => {
                    let floor =
                        value.parse().map_err(|_| format!("{}: apitests-floor `{value}` is not a number", at()))?;
                    sc.apitests_floor = Some(floor);
                }
                "screen" => sc.screen.push(crate::screen::Pixel::parse(value).map_err(|e| format!("{}: {e}", at()))?),
                "screen-size" => {
                    let size = value
                        .split_once(' ')
                        .and_then(|(width, height)| Some((width.trim().parse().ok()?, height.trim().parse().ok()?)));
                    sc.screen_size =
                        Some(size.ok_or_else(|| format!("{}: screen-size `{value}`: WIDTH HEIGHT", at()))?);
                }
                "screen-wait" => {
                    let secs = value.parse().map_err(|_| format!("{}: screen-wait `{value}` is not a number", at()))?;
                    sc.screen_wait = Duration::from_secs(secs);
                }
                "keys" => sc.keys.push(Keys::parse(value).map_err(|e| format!("{}: {e}", at()))?),
                "app" => {
                    crate::apps::find(value)
                        .ok_or_else(|| format!("{}: `{value}` is not an application of the bench", at()))?;
                    sc.app = Some(value.to_string());
                    sc.system_disk = true;
                }
                "disk" => match value {
                    "system" => sc.system_disk = true,
                    "ntfs-data" => sc.ntfs_disk = true,
                    "target" => sc.target_disk = true,
                    "installed" => {
                        sc.system_disk = true;
                        sc.gpt_disk = true;
                        sc.installed_disk = true;
                    }
                    "system-gpt" => {
                        sc.system_disk = true;
                        sc.gpt_disk = true;
                    }
                    _ => return Err(format!("{}: unknown disk `{value}`", at())),
                },
                "reboot" => match value {
                    "target" => sc.reboot_target = true,
                    _ => return Err(format!("{}: unknown reboot `{value}`", at())),
                },
                "boots" => {
                    sc.boots = value
                        .parse()
                        .ok()
                        .filter(|&boots| boots >= 1)
                        .ok_or_else(|| format!("{}: boots `{value}` is not a number from 1", at()))?;
                }
                "memory" => {
                    let mib = value
                        .parse()
                        .ok()
                        .filter(|&mib| mib >= 64)
                        .ok_or_else(|| format!("{}: memory `{value}` is not a number of MiB from 64", at()))?;
                    sc.memory_mb = Some(mib);
                }
                "requires" => {
                    for requirement in list() {
                        match requirement {
                            "userland" => sc.requires_userland = true,
                            "native" => sc.requires_native = true,
                            "rostests" => sc.requires_rostests = true,
                            _ => return Err(format!("{}: unknown requirement `{requirement}`", at())),
                        }
                    }
                }
                _ => return Err(format!("{}: unknown key `{key}`", at())),
            }
            if value.is_empty() && key != "features" {
                return Err(format!("{}: `{key}` needs a value", at()));
            }
        }
        if sc.expect.is_empty() {
            return Err(format!("{name}/{SCENARIO_FILE}: no `expect` marker"));
        }
        if sc.cpus.is_empty() {
            return Err(format!("{name}/{SCENARIO_FILE}: empty `cpus`"));
        }
        if sc.initial_command.is_some() && !(sc.requires_userland && sc.requires_native) {
            return Err(format!("{name}/{SCENARIO_FILE}: `initial-command` needs `requires = userland, native`"));
        }
        if let Some(program) = &sc.session {
            if !(sc.requires_userland && sc.requires_native) {
                return Err(format!("{name}/{SCENARIO_FILE}: `session` needs `requires = userland, native`"));
            }
            if sc.initial_command.is_some() {
                return Err(format!("{name}/{SCENARIO_FILE}: `session` keeps winlogon: no `initial-command`"));
            }
            if !sc.system_disk || sc.boots < 2 {
                return Err(format!(
                    "{name}/{SCENARIO_FILE}: `session = {program}` sets up then logs on: a system disk and `boots` from 2"
                ));
            }
        }
        if sc.screen_size.is_some() && sc.screen.is_empty() {
            return Err(format!("{name}/{SCENARIO_FILE}: `screen-size` without `screen` pixels"));
        }
        if !sc.screen_wait.is_zero() && sc.screen.is_empty() {
            return Err(format!("{name}/{SCENARIO_FILE}: `screen-wait` without `screen` pixels"));
        }
        if sc.shell && !sc.requires_userland {
            return Err(format!("{name}/{SCENARIO_FILE}: `shell` needs `requires = userland`"));
        }
        if sc.requires_rostests != sc.apitests_floor.is_some() {
            return Err(format!("{name}/{SCENARIO_FILE}: `requires = rostests` goes with `apitests-floor`"));
        }
        // An installed image is the primary boot disk: the target can be the
        // secondary master beside it, not beside a system disk there.
        if sc.ntfs_disk && (sc.system_disk || sc.target_disk) {
            return Err(format!("{name}/{SCENARIO_FILE}: NTFS data cannot also be system or target"));
        }
        if sc.system_disk && sc.target_disk && !sc.installed_disk {
            return Err(format!("{name}/{SCENARIO_FILE}: a disk cannot be both system and target"));
        }
        if sc.power_cut.as_ref().is_some_and(|(boot, _)| *boot >= sc.boots) {
            return Err(format!("{name}/{SCENARIO_FILE}: `power-cut` names a boot before the last one"));
        }
        if sc.reboot_target && !(sc.installed_disk && sc.target_disk && sc.boots >= 2) {
            return Err(format!(
                "{name}/{SCENARIO_FILE}: `reboot = target` needs `disk = installed`, `disk = target` and `boots` from 2"
            ));
        }
        Ok(sc)
    }

    /// A forbidden marker in `log`, during a boot that must end with QEMU.
    pub fn forbidden(&self, log: &str) -> Option<String> {
        match self.check(log) {
            Verdict::Fail(why) => Some(why),
            _ => None,
        }
    }

    /// The verdict of the last boot: [`check`](Self::check) on every serial
    /// log (`earlier`, then `this_boot`), and the `expect-last` markers in
    /// `this_boot` alone.
    pub fn check_last(&self, earlier: &str, this_boot: &str) -> Verdict {
        let missing_last = || {
            self.expect_last
                .iter()
                .filter(|sequence| !sequence.found_in(this_boot))
                .map(|sequence| format!("{sequence} (in the last boot)"))
        };
        match self.check(&format!("{earlier}{this_boot}")) {
            Verdict::Pass => match missing_last().collect::<Vec<_>>() {
                missing if missing.is_empty() => Verdict::Pass,
                missing => Verdict::Pending(missing),
            },
            Verdict::Pending(mut missing) => {
                missing.extend(missing_last());
                Verdict::Pending(missing)
            }
            failed => failed,
        }
    }

    pub fn check(&self, log: &str) -> Verdict {
        if let Some(m) = self.forbid.iter().find(|m| log.contains(m.as_str())) {
            return Verdict::Fail(format!("forbidden marker `{m}`"));
        }
        for prefix in &self.forbid_line_start {
            if let Some(line) = log.lines().find(|l| l.starts_with(prefix.as_str())) {
                return Verdict::Fail(format!("forbidden line `{}`", line.trim_end()));
            }
        }
        let missing: Vec<String> = self
            .expect
            .iter()
            .filter(|any| !any.iter().any(|m| log.contains(m.as_str())))
            .map(|any| any.join(" | "))
            .collect();
        if missing.is_empty() {
            Verdict::Pass
        } else {
            Verdict::Pending(missing)
        }
    }
}

/// File describing a scenario, in its directory.
const SCENARIO_FILE: &str = "scenario.txt";

/// The scenarios of `dir` (its subdirectories holding a `scenario.txt`),
/// sorted by name; only `names` if given.
pub fn load_all(dir: &Path, names: &[String]) -> Result<Vec<Scenario>> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths: Vec<_> =
        entries.filter_map(|e| e.ok().map(|e| e.path().join(SCENARIO_FILE))).filter(|p| p.is_file()).collect();
    paths.sort();
    let mut scenarios = Vec::new();
    for path in paths {
        let name = path.parent().and_then(Path::file_name).and_then(|s| s.to_str()).unwrap_or_default().to_string();
        if !names.is_empty() && !names.contains(&name) {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        scenarios.push(Scenario::parse(&name, &text)?);
    }
    if let Some(unknown) = names.iter().find(|n| !scenarios.iter().any(|s| &s.name == *n)) {
        return Err(format!("no scenario `{unknown}` in {}", dir.display()));
    }
    Ok(scenarios)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "
# comment
features = a, b
cpus = default, intel
timeout = 30
expect = ready
expect = hit | skipped
forbid = PANIC
forbid-line-start = [sys]
requires = userland
";

    #[test]
    fn parses_every_key() {
        let sc = Scenario::parse("sample", SAMPLE).unwrap();
        assert_eq!(sc.features, ["a", "b"]);
        assert_eq!(sc.cpus.iter().map(Cpu::name).collect::<Vec<_>>(), ["default", "intel"]);
        assert_eq!(sc.timeout, Duration::from_secs(30));
        assert_eq!(sc.expect, [vec!["ready"], vec!["hit", "skipped"]]);
        assert!(sc.requires_userland);
        assert!(!Scenario::parse("x", "expect = a").unwrap().requires_userland);
        let both = Scenario::parse("x", "expect = a\nrequires = userland, native").unwrap();
        assert!(both.requires_userland && both.requires_native);
        assert!(!sc.requires_native);
        assert!((!sc.system_disk, sc.boots) == (true, 1), "one boot on the ramdisk by default");
        let twice = Scenario::parse("x", "expect = a\ndisk = system\nboots = 2").unwrap();
        let ntfs = Scenario::parse("x", "expect = a\ndisk = ntfs-data").unwrap();
        assert!(ntfs.ntfs_disk && !ntfs.system_disk && !ntfs.target_disk);
        assert!(Scenario::parse("x", "expect = a\ndisk = ntfs-data\ndisk = target").is_err());
        assert!(twice.system_disk && twice.boots == 2);
        assert_eq!(sc.memory_mb, None, "QEMU's default memory");
        assert_eq!(Scenario::parse("x", "expect = a\nmemory = 8192").unwrap().memory_mb, Some(8192));
        assert!(Scenario::parse("x", "expect = a\nmemory = 8G").is_err());
        assert!(Scenario::parse("x", "expect = a\nmemory = 16").is_err(), "too little to boot");
        let gpt = Scenario::parse("x", "expect = a\ndisk = system-gpt").unwrap();
        assert!(gpt.system_disk && gpt.gpt_disk);
        let installed = Scenario::parse("x", "expect = a\ndisk = installed").unwrap();
        assert!(installed.system_disk && installed.gpt_disk && installed.installed_disk);
        let target = Scenario::parse("x", "expect = a\ndisk = target").unwrap();
        assert!(target.target_disk && !target.system_disk);
        let keys = Scenario::parse("x", "expect = a\nkeys = [x] ready => shift-h i ret\nkeys = b => a").unwrap();
        let first = Keys { after: "[x] ready".into(), keys: vec!["shift-h".into(), "i".into(), "ret".into()] };
        assert_eq!(keys.keys, [first, Keys { after: "b".into(), keys: vec!["a".into()] }]);
        let screen = Scenario::parse("x", "expect = a\nscreen = 1 2 3A6EA5").unwrap();
        assert_eq!(screen.screen, [crate::screen::Pixel { x: 1, y: 2, rgb: [0x3A, 0x6E, 0xA5] }]);
        assert!(sc.screen.is_empty());
        assert_eq!(screen.screen_wait, Duration::ZERO, "one capture by default");
        let waiting = Scenario::parse("x", "expect = a\nscreen = 1 2 3A6EA5\nscreen-wait = 60").unwrap();
        assert_eq!(waiting.screen_wait, Duration::from_secs(60));
        assert!(Scenario::parse("x", "expect = a\nscreen-wait = 60").is_err(), "a wait without pixels");
        let sized = Scenario::parse("x", "expect = a\nscreen = 1 2 3A6EA5\nscreen-size = 800 600").unwrap();
        assert_eq!((sized.screen_size, screen.screen_size), (Some((800, 600)), None));
        assert!(Scenario::parse("x", "expect = a\nscreen-size = 800 600").is_err(), "a size without pixels");
        assert!(Scenario::parse("x", "expect = a\nscreen = 1 2 3A6EA5\nscreen-size = 800").is_err());
        assert!(Scenario::parse("x", "expect = a\nscreen = 1 2 3A6EA5\nscreen-wait = soon").is_err());
        let gui = Scenario::parse("x", "expect = a\nrequires = userland, native\ninitial-command = GUI1.EXE").unwrap();
        assert_eq!(gui.initial_command.as_deref(), Some("GUI1.EXE"));
        assert_eq!(sc.initial_command, None);
        assert!(Scenario::parse("x", "expect = a\ninitial-command = GUI1.EXE").is_err(), "without the userland");
        let session = "expect = a\nrequires = userland, native\ndisk = system\nboots = 2\nsession = APPBENCH.EXE";
        assert_eq!(Scenario::parse("x", session).unwrap().session.as_deref(), Some("APPBENCH.EXE"));
        assert_eq!(sc.session, None);
        let without = |line: &str| session.replace(line, "");
        assert!(Scenario::parse("x", &without("\nboots = 2")).is_err(), "one boot: no logon");
        assert!(Scenario::parse("x", &without("\ndisk = system")).is_err(), "the setup's reboot needs a disk");
        assert!(Scenario::parse("x", &without(", native")).is_err(), "a test program needs native");
        assert!(Scenario::parse("x", &format!("{session}\ninitial-command = GUI1.EXE")).is_err(), "keeps winlogon");
        assert!(Scenario::parse("x", &session.replace("disk = system", "app = notepadpp")).is_ok(), "an app's disk");
        let shell = Scenario::parse("x", "expect = a\nrequires = userland\nshell = explorer").unwrap();
        assert!(shell.shell && !sc.shell);
        assert!(Scenario::parse("x", "expect = a\nshell = explorer").is_err(), "a shell without the userland");
        let bench = Scenario::parse("x", "expect = a\nrequires = rostests\napitests-floor = 12").unwrap();
        assert!(bench.requires_rostests && bench.apitests_floor == Some(12));
        assert_eq!(sc.apitests_floor, None);
        assert!(Scenario::parse("x", "expect = a\nrequires = rostests").is_err(), "a bench without its floor");
        assert!(Scenario::parse("x", "expect = a\napitests-floor = 3").is_err(), "a floor without its bench");
        assert!(Scenario::parse("x", "expect = a\nrequires = rostests\napitests-floor = many").is_err());
        let app = Scenario::parse("x", "expect = a\napp = keepass").unwrap();
        assert!(app.app.as_deref() == Some("keepass") && app.system_disk, "an application installs on C:");
        assert_eq!(sc.app, None);
        assert!(Scenario::parse("x", "expect = a\napp = word").is_err(), "not an application of the bench");
    }

    #[test]
    fn pending_until_every_expectation_is_met() {
        let sc = Scenario::parse("sample", SAMPLE).unwrap();
        assert_eq!(sc.check("boot"), Verdict::Pending(vec!["ready".into(), "hit | skipped".into()]));
        assert_eq!(sc.check("ready"), Verdict::Pending(vec!["hit | skipped".into()]));
        assert_eq!(sc.check("ready\nskipped"), Verdict::Pass);
    }

    #[test]
    fn forbidden_markers_fail_at_once() {
        let sc = Scenario::parse("sample", SAMPLE).unwrap();
        assert!(matches!(sc.check("KERNEL PANIC"), Verdict::Fail(_)));
        assert!(matches!(sc.check("ready\n[sys] NtWriteFile\nhit"), Verdict::Fail(_)));
        // Only at the start of a line.
        assert_eq!(sc.check("ready x [sys] hit"), Verdict::Pass);
    }

    #[test]
    fn a_boot_can_end_with_a_power_cut_and_the_last_one_show_its_own_markers() {
        let text = "expect = a\ndisk = system\nboots = 3\npower-cut = 2 => logged on => everything written\n\
                    expect-last = logged on => explorer";
        let sc = Scenario::parse("x", text).unwrap();
        let (boot, after) = sc.power_cut.clone().unwrap();
        assert_eq!((boot, after.to_string()), (2, "logged on => everything written".to_string()));
        assert!(!after.found_in("everything written\nlogged on"), "in this order");
        assert!(after.found_in("[lazy] everything written\nlogged on\n[lazy] more waits\n[lazy] everything written"));
        assert!(!after.found_in("logged on"));
        // The markers of earlier boots do not count for `expect-last`.
        let earlier = "a\nlogged on\nexplorer\n";
        assert_eq!(
            sc.check_last(earlier, "booting"),
            Verdict::Pending(vec!["logged on => explorer (in the last boot)".into()])
        );
        assert_eq!(
            sc.check_last(earlier, "explorer, then logged on"),
            Verdict::Pending(vec!["logged on => explorer (in the last boot)".into()])
        );
        assert_eq!(sc.check_last(earlier, "logged on\nexplorer"), Verdict::Pass);
        assert_eq!(
            sc.check_last("", "logged on\nexplorer"),
            Verdict::Pending(vec!["a".into()]),
            "`expect` still counts"
        );
        assert_eq!(Scenario::parse("x", "expect = a").unwrap().power_cut, None);
        let cut = |line: &str| Scenario::parse("x", &format!("expect = a\ndisk = system\nboots = 3\n{line}"));
        assert!(cut("power-cut = 3 => b").is_err(), "the last boot ends with its markers");
        assert!(cut("power-cut = 0 => b").is_err());
        assert!(cut("power-cut = two => b").is_err());
        assert!(cut("power-cut = 1").is_err(), "no marker");
        assert!(cut("power-cut = 1 => b =>").is_err(), "an empty marker");
        assert!(cut("expect-last = => b").is_err());
    }

    #[test]
    fn rejects_malformed_files() {
        assert!(Scenario::parse("x", "expect = a\nbogus = 1").is_err());
        assert!(Scenario::parse("x", "expect = a\ntimeout = soon").is_err());
        assert!(Scenario::parse("x", "expect = a\nno equals sign").is_err());
        assert!(Scenario::parse("x", "cpus = default").is_err(), "no expect");
        assert!(Scenario::parse("x", "expect =").is_err());
        assert!(Scenario::parse("x", "expect = a\nrequires = network").is_err());
        assert!(Scenario::parse("x", "expect = a\ndisk = floppy").is_err());
        assert!(Scenario::parse("x", "expect = a\nrequires = userland\nshell = progman").is_err());
        assert!(Scenario::parse("x", "expect = a\nboots = 0").is_err());
        assert!(Scenario::parse("x", "expect = a\nscreen = 1 2").is_err());
        assert!(Scenario::parse("x", "expect = a\nkeys = ready").is_err(), "no keys");
        assert!(Scenario::parse("x", "expect = a\nkeys = => a").is_err(), "no marker");
        assert!(Scenario::parse("x", "expect = a\nkeys = b => \"dir").is_err(), "an unended text");
        assert!(Scenario::parse("x", "expect = a\nkeys = b => \"é\"").is_err(), "a character without a key");
    }

    #[test]
    fn quoted_text_gives_the_keys_of_its_characters() {
        let sc = Scenario::parse("x", "expect = a\nkeys = [x] ready => \"set A=b> C:\\X\" ret \"\" esc").unwrap();
        let typed = [
            "s",
            "e",
            "t",
            "spc",
            "shift-a",
            "equal",
            "b",
            "shift-dot",
            "spc",
            "shift-c",
            "shift-semicolon",
            "backslash",
            "shift-x",
            "ret",
            "esc",
        ];
        assert_eq!(sc.keys, [Keys { after: "[x] ready".into(), keys: typed.map(String::from).to_vec() }]);
        assert_eq!(
            key_names("\"@echo %X%|*\"").unwrap(),
            ["shift-2", "e", "c", "h", "o", "spc", "shift-5", "shift-x", "shift-5", "shift-backslash", "shift-8"]
        );
    }
}
