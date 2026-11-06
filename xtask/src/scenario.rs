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
//!     `tests/native/`, compiled with MinGW or clang (`xtask/src/native.rs`).
//! - `disk = installed`: a single GPT disk holds the real ESP and system
//!   partition, replacing the external virtual FAT boot disk.
//! - `disk = system-gpt`: wraps the FAT image in a GPT Basic Data partition;
//!   the two GPT copies are checked and the partition extracted for fsck.
//! - `disk = system`: the image of the ramdisk is also the system disk `C:`,
//!   a file attached as the master of the secondary IDE channel, which the
//!   boots share; after the last one, `fsck.vfat -n` must find it clean
//!   (skipped, with a warning, without dosfstools).
//! - `boots`: how many times QEMU boots (default 1). Every boot but the last
//!   must end with QEMU (the kernel resets the machine, and `-no-reboot`
//!   makes QEMU exit); the `expect` markers are looked for in all the serial
//!   logs, the last boot's included.
//! - `screen = X Y RRGGBB`: once the markers are found, the screen of the
//!   last boot is dumped (`screen.ppm` in the run directory) and the pixel
//!   at column X, row Y must have this colour (`xtask/src/screen.rs`).
//! - `keys = MARKER => KEY…`: once MARKER is in the serial log of the boot,
//!   QEMU's monitor types the keys, one after the other (`sendkey`, with
//!   QEMU's key names: `a`, `shift-a`, `ret`, `spc`…), once
//!   (`xtask/src/screen.rs`). A KEY can be a quoted text, `"dir C:\"`: the
//!   keys that type its characters on a US keyboard. The `keys` lines fire
//!   in their order.
//! - `initial-command = PROGRAM.EXE`: this Win32 test program of
//!   `tests/native/` takes the place of `winlogon.exe` on the ramdisk, so
//!   that `smss` starts it as its initial command (with `requires =
//!   userland, native`).

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
    /// The ramdisk image is also the system disk `C:`.
    pub system_disk: bool,
    /// Wrap the system volume in GPT rather than using raw FAT.
    pub gpt_disk: bool,
    /// One real GPT image holds the ESP and system volume.
    pub installed_disk: bool,
    pub boots: u32,
    /// Pixels the screen must show once the markers are found.
    pub screen: Vec<crate::screen::Pixel>,
    /// The test program that takes the place of `winlogon.exe`.
    pub initial_command: Option<String>,
    /// Keys to type once a marker is in the serial log, in order.
    pub keys: Vec<Keys>,
    expect: Vec<Vec<String>>,
    forbid: Vec<String>,
    forbid_line_start: Vec<String>,
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
            system_disk: false,
            gpt_disk: false,
            installed_disk: false,
            boots: 1,
            screen: Vec::new(),
            initial_command: None,
            keys: Vec::new(),
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
                "forbid" => sc.forbid.push(value.to_string()),
                "forbid-line-start" => sc.forbid_line_start.push(value.to_string()),
                "initial-command" => sc.initial_command = Some(value.to_string()),
                "screen" => sc.screen.push(crate::screen::Pixel::parse(value).map_err(|e| format!("{}: {e}", at()))?),
                "keys" => sc.keys.push(Keys::parse(value).map_err(|e| format!("{}: {e}", at()))?),
                "disk" => match value {
                    "system" => sc.system_disk = true,
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
                "boots" => {
                    sc.boots = value
                        .parse()
                        .ok()
                        .filter(|&boots| boots >= 1)
                        .ok_or_else(|| format!("{}: boots `{value}` is not a number from 1", at()))?;
                }
                "requires" => {
                    for requirement in list() {
                        match requirement {
                            "userland" => sc.requires_userland = true,
                            "native" => sc.requires_native = true,
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
        Ok(sc)
    }

    /// A forbidden marker in `log`, during a boot that must end with QEMU.
    pub fn forbidden(&self, log: &str) -> Option<String> {
        match self.check(log) {
            Verdict::Fail(why) => Some(why),
            _ => None,
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
        assert!(twice.system_disk && twice.boots == 2);
        let gpt = Scenario::parse("x", "expect = a\ndisk = system-gpt").unwrap();
        assert!(gpt.system_disk && gpt.gpt_disk);
        let installed = Scenario::parse("x", "expect = a\ndisk = installed").unwrap();
        assert!(installed.system_disk && installed.gpt_disk && installed.installed_disk);
        let keys = Scenario::parse("x", "expect = a\nkeys = [x] ready => shift-h i ret\nkeys = b => a").unwrap();
        let first = Keys { after: "[x] ready".into(), keys: vec!["shift-h".into(), "i".into(), "ret".into()] };
        assert_eq!(keys.keys, [first, Keys { after: "b".into(), keys: vec!["a".into()] }]);
        let screen = Scenario::parse("x", "expect = a\nscreen = 1 2 3A6EA5").unwrap();
        assert_eq!(screen.screen, [crate::screen::Pixel { x: 1, y: 2, rgb: [0x3A, 0x6E, 0xA5] }]);
        assert!(sc.screen.is_empty());
        let gui = Scenario::parse("x", "expect = a\nrequires = userland, native\ninitial-command = GUI1.EXE").unwrap();
        assert_eq!(gui.initial_command.as_deref(), Some("GUI1.EXE"));
        assert_eq!(sc.initial_command, None);
        assert!(Scenario::parse("x", "expect = a\ninitial-command = GUI1.EXE").is_err(), "without the userland");
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
    fn rejects_malformed_files() {
        assert!(Scenario::parse("x", "expect = a\nbogus = 1").is_err());
        assert!(Scenario::parse("x", "expect = a\ntimeout = soon").is_err());
        assert!(Scenario::parse("x", "expect = a\nno equals sign").is_err());
        assert!(Scenario::parse("x", "cpus = default").is_err(), "no expect");
        assert!(Scenario::parse("x", "expect =").is_err());
        assert!(Scenario::parse("x", "expect = a\nrequires = network").is_err());
        assert!(Scenario::parse("x", "expect = a\ndisk = floppy").is_err());
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
