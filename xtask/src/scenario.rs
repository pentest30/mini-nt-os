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
//! requires = userland
//! ```
//!
//! - `features`: ntoskrnl features, comma-separated (default: none).
//! - `cpus`: `default`, `intel` or QEMU `-cpu` models (default: `default`).
//! - `timeout`: upper bound in seconds (default: 120); a run stops as soon
//!   as its verdict is known.
//! - `expect`: must appear in the serial log; with `|`, one of them.
//! - `forbid`: fails the run as soon as it appears anywhere.
//! - `forbid-line-start`: fails the run as soon as a line starts with it.
//! - `requires = userland`: the ramdisk gets the fetched ReactOS userland
//!   (`NTDLL.DLL`); without it, the scenario is skipped.

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
    expect: Vec<Vec<String>>,
    forbid: Vec<String>,
    forbid_line_start: Vec<String>,
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
                "requires" => match value {
                    "userland" => sc.requires_userland = true,
                    _ => return Err(format!("{}: unknown requirement `{value}`", at())),
                },
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
        Ok(sc)
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
    }
}
