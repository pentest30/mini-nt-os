//! `syscall-gen [--check]` : écrit `abi/src/services.rs` à partir des listes
//! de services de la version épinglée de ReactOS (`reactos/<version>/`), mis
//! en forme par rustfmt, et le rapport de couverture `docs/compat/syscalls.md`
//! d'après les handlers du dispatcher (`kernel/ntoskrnl/src/sys/mod.rs`).
//! Avec `--check`, échoue si l'un d'eux n'est pas à jour, sans rien écrire.
//! Lancé par `cargo xtask syscall-gen` et `cargo xtask lint`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use syscall_gen::{parse_implemented, parse_sysfuncs, parse_w32ksvc, render, render_coverage, validate, Pin};

/// La version épinglée de ReactOS (ADR-002) : `reactos/0.4.16/README.md`.
const PIN: Pin = Pin { version: "0.4.16", commit: "51bfc7037359b594876a349b46b992e363e79838" };

/// Les symboles définis pour `w32ksvc32.h` : i386, version de publication,
/// donc ni `DBG` ni `_WIN64`.
const DEFINED: &[&str] = &[];

const TABLES: &str = "abi/src/services.rs";
const DISPATCHER: &str = "kernel/ntoskrnl/src/sys/mod.rs";
const COVERAGE: &str = "docs/compat/syscalls.md";

fn main() -> ExitCode {
    let check = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => {
            eprintln!("usage: syscall-gen [--check]");
            return ExitCode::FAILURE;
        }
    };
    match generate(check) {
        Ok(message) => {
            println!("syscall-gen: {message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("syscall-gen: {error}");
            ExitCode::FAILURE
        }
    }
}

fn generate(check: bool) -> Result<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let lists = Path::new(env!("CARGO_MANIFEST_DIR")).join("reactos").join(PIN.version);
    let read = |path: &Path| std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()));
    let ntoskrnl = parse_sysfuncs(&read(&lists.join("sysfuncs.lst"))?).map_err(|e| format!("sysfuncs.lst: {e}"))?;
    let win32k = parse_w32ksvc(&read(&lists.join("w32ksvc32.h"))?, DEFINED).map_err(|e| format!("w32ksvc32.h: {e}"))?;
    validate(&ntoskrnl, &win32k)?;
    let implemented = parse_implemented(&read(&root.join(DISPATCHER))?).map_err(|e| format!("{DISPATCHER}: {e}"))?;
    let outputs = [
        (TABLES, rustfmt(&root, &render(&PIN, &ntoskrnl, &win32k))?),
        (COVERAGE, render_coverage(&PIN, &ntoskrnl, &win32k, &implemented)?),
    ];
    let mut written = Vec::new();
    for (path, text) in &outputs {
        let output: PathBuf = root.join(path);
        if std::fs::read_to_string(&output).unwrap_or_default() == *text {
            continue;
        }
        if check {
            return Err(format!("{path} is out of date: run `cargo xtask syscall-gen`"));
        }
        std::fs::write(&output, text).map_err(|e| format!("{}: {e}", output.display()))?;
        written.push(*path);
    }
    let summary =
        format!("{} ntoskrnl and {} win32k services, {} implemented", ntoskrnl.len(), win32k.len(), implemented.len());
    Ok(if written.is_empty() {
        format!("{TABLES} and {COVERAGE} are up to date ({summary})")
    } else {
        format!("wrote {} ({summary})", written.join(" and "))
    })
}

/// `text` mis en forme par rustfmt, avec la configuration du dépôt.
fn rustfmt(root: &Path, text: &str) -> Result<String, String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout", "--config-path"])
        .arg(root.join("rustfmt.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run rustfmt: {e}"))?;
    child.stdin.take().expect("piped stdin").write_all(text.as_bytes()).map_err(|e| format!("rustfmt: {e}"))?;
    let output = child.wait_with_output().map_err(|e| format!("rustfmt: {e}"))?;
    if !output.status.success() {
        return Err(format!("rustfmt failed with {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("rustfmt: {e}"))
}
