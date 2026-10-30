//! `syscall-gen` (ADR-002, 02 §6.2) : les tables des services système de
//! Mino, générées à partir des listes de la version épinglée de ReactOS.
//!
//! - [`parse_sysfuncs`] lit `ntoskrnl/sysfuncs.lst` ;
//! - [`parse_w32ksvc`] lit `win32ss/w32ksvc32.h`, avec ses blocs
//!   conditionnels ;
//! - [`render`] écrit `abi/src/services.rs` : le numéro de chaque service par
//!   son nom NT, et les deux tables (nom, octets d'arguments) ;
//! - [`parse_implemented`] lit la liste des handlers du dispatcher, et
//!   [`render_coverage`] écrit le rapport de couverture
//!   (`docs/compat/syscalls.md`).
//!
//! L'ordre d'une liste donne les numéros : 0x0000 et suivants pour
//! ntoskrnl, 0x1000 et suivants pour win32k.

use std::collections::BTreeSet;
use std::fmt::Write;

/// Un service d'une liste : son nom NT et son nombre d'arguments de 32 bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub argument_count: u32,
}

/// La version de ReactOS dont viennent les listes.
pub struct Pin<'a> {
    pub version: &'a str,
    pub commit: &'a str,
}

/// Au plus 0x1000 services par table : le numéro garde 12 bits pour l'index.
pub const MAX_SERVICES: usize = 0x1000;

/// Au plus 63 arguments : leur taille tient dans un octet, comme dans la
/// table des arguments d'XP.
pub const MAX_ARGUMENTS: u32 = 63;

/// Base des numéros de win32k.
pub const WIN32K_BASE: u32 = 0x1000;

fn entry(name: &str, count: &str, line: usize) -> Result<Entry, String> {
    let valid_name = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid_name {
        return Err(format!("line {line}: invalid service name `{name}`"));
    }
    let argument_count: u32 =
        count.trim().parse().map_err(|_| format!("line {line}: invalid argument count `{count}`"))?;
    if argument_count > MAX_ARGUMENTS {
        return Err(format!("line {line}: {name} has {argument_count} arguments (at most {MAX_ARGUMENTS})"));
    }
    Ok(Entry { name: name.to_owned(), argument_count })
}

/// `ntoskrnl/sysfuncs.lst` : une ligne `NtNom N` par service, dans l'ordre
/// des numéros ; les lignes vides sont ignorées.
pub fn parse_sysfuncs(text: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next(), fields.next()) {
            (Some(name), Some(count), None) => entries.push(entry(name, count, i + 1)?),
            _ => return Err(format!("line {}: expected `Name ArgumentCount`, found `{line}`", i + 1)),
        }
    }
    Ok(entries)
}

/// `win32ss/w32ksvc32.h` : `SVC_(Nom, N)` par service, qui s'appelle `NtNom`.
/// Les commentaires `//` et `/* … */` d'une ligne sont ignorés. Les blocs
/// `#if X`, `#ifdef X`, `#ifndef X`, `#else` et `#endif` s'évaluent avec les
/// symboles `defined` (définis à 1, les autres absents) ; toute autre
/// directive est une erreur.
pub fn parse_w32ksvc(text: &str, defined: &[&str]) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    // For each open block: whether its branch is taken, and whether `#else`
    // was seen.
    let mut blocks: Vec<(bool, bool)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = strip_comments(raw).trim().to_owned();
        if let Some(directive) = line.strip_prefix('#') {
            let mut words = directive.split_whitespace();
            let keyword = words.next().unwrap_or("");
            let symbol = words.next();
            if words.next().is_some() {
                return Err(format!("line {n}: unsupported directive `{line}`"));
            }
            let is_defined = |symbol: Option<&str>| match symbol {
                Some(symbol) if is_identifier(symbol) => Ok(defined.contains(&symbol)),
                Some(_) => Err(format!("line {n}: unsupported directive `{line}`")),
                None => Err(format!("line {n}: `#{keyword}` without a symbol")),
            };
            match keyword {
                "if" | "ifdef" => blocks.push((is_defined(symbol)?, false)),
                "ifndef" => blocks.push((!is_defined(symbol)?, false)),
                "else" if symbol.is_none() => match blocks.last_mut() {
                    Some((taken, seen_else @ false)) => {
                        *taken = !*taken;
                        *seen_else = true;
                    }
                    _ => return Err(format!("line {n}: `#else` without `#if`")),
                },
                "endif" if symbol.is_none() => {
                    blocks.pop().ok_or_else(|| format!("line {n}: `#endif` without `#if`"))?;
                }
                _ => return Err(format!("line {n}: unsupported directive `{line}`")),
            }
            continue;
        }
        if line.is_empty() || !blocks.iter().all(|&(taken, _)| taken) {
            continue;
        }
        let inner = line
            .strip_prefix("SVC_(")
            .and_then(|rest| rest.strip_suffix(')'))
            .ok_or_else(|| format!("line {n}: expected `SVC_(Name, ArgumentCount)`, found `{line}`"))?;
        let (name, count) =
            inner.split_once(',').ok_or_else(|| format!("line {n}: expected `SVC_(Name, ArgumentCount)`"))?;
        entries.push(entry(&format!("Nt{}", name.trim()), count, n)?);
    }
    if !blocks.is_empty() {
        return Err("`#if` without `#endif` at the end of the file".to_owned());
    }
    Ok(entries)
}

/// Un identifiant C : une lettre ou `_`, puis des lettres, chiffres ou `_`.
fn is_identifier(word: &str) -> bool {
    word.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `line` sans ses commentaires `//` et `/* … */` (sur la ligne).
fn strip_comments(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    loop {
        let line_comment = rest.find("//");
        let block_comment = rest.find("/*");
        match (line_comment, block_comment) {
            (Some(l), b) if b.is_none_or(|b| l < b) => {
                out.push_str(&rest[..l]);
                return out;
            }
            (_, Some(b)) => {
                out.push_str(&rest[..b]);
                match rest[b + 2..].find("*/") {
                    Some(end) => rest = &rest[b + 2 + end + 2..],
                    None => return out,
                }
            }
            _ => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

/// Vérifie les deux tables : pas trop de services, aucun nom en double, ni
/// dans une table ni entre les deux.
pub fn validate(ntoskrnl: &[Entry], win32k: &[Entry]) -> Result<(), String> {
    for (table, entries) in [("ntoskrnl", ntoskrnl), ("win32k", win32k)] {
        if entries.is_empty() || entries.len() > MAX_SERVICES {
            return Err(format!("{table}: {} services (1 to {MAX_SERVICES})", entries.len()));
        }
    }
    let mut names = BTreeSet::new();
    for entry in ntoskrnl.iter().chain(win32k) {
        if !names.insert(entry.name.as_str()) {
            return Err(format!("service `{}` listed twice", entry.name));
        }
    }
    Ok(())
}

/// Le texte de `abi/src/services.rs`, avant rustfmt.
pub fn render(pin: &Pin, ntoskrnl: &[Entry], win32k: &[Entry]) -> String {
    let mut out = String::new();
    let short = &pin.commit[..pin.commit.len().min(12)];
    let _ = writeln!(
        out,
        "//! System services of ReactOS {} (commit {short}), i386 free build, generated by\n\
         //! `tools/syscall-gen` from `ntoskrnl/sysfuncs.lst` ({} services) and\n\
         //! `win32ss/w32ksvc32.h` ({} services). Do not edit: `cargo xtask syscall-gen`.\n\
         #![expect(non_upper_case_globals, reason = \"the services' NT names\")]\n\
         \n\
         use crate::service::Service;\n",
        pin.version,
        ntoskrnl.len(),
        win32k.len()
    );
    for (base, entries) in [(0, ntoskrnl), (WIN32K_BASE, win32k)] {
        for (i, entry) in entries.iter().enumerate() {
            let _ = writeln!(out, "pub const {}: u32 = {:#06x};", entry.name, base + i as u32);
        }
        out.push('\n');
    }
    for (doc, name, entries) in [
        ("The ntoskrnl services (KiServiceTable), by number.", "NTOSKRNL", ntoskrnl),
        ("The win32k services (W32pServiceTable), by number less 0x1000.", "WIN32K", win32k),
    ] {
        let _ = writeln!(out, "/// {doc}\npub static {name}: [Service; {}] = [", entries.len());
        for entry in entries {
            let _ = writeln!(out, "    Service::new(\"{}\", {}),", entry.name, entry.argument_count);
        }
        out.push_str("];\n\n");
    }
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

/// Les services qui ont un handler : les entrées `(services::NtNom, …),` de
/// la liste `IMPLEMENTED` du dispatcher, une par ligne, jusqu'à `];`.
pub fn parse_implemented(source: &str) -> Result<Vec<String>, String> {
    let mut lines = source.lines().enumerate().skip_while(|(_, line)| !line.contains("pub const IMPLEMENTED"));
    lines.next().ok_or("no `pub const IMPLEMENTED` list")?;
    let mut names = Vec::new();
    for (i, raw) in lines {
        let line = raw.trim();
        if line == "];" {
            return Ok(names);
        }
        let name = line
            .strip_prefix("(services::")
            .and_then(|rest| rest.split_once(','))
            .map(|(name, _)| name)
            .filter(|name| is_identifier(name))
            .ok_or_else(|| format!("line {}: expected `(services::NtName, handler),`, found `{line}`", i + 1))?;
        names.push(name.to_owned());
    }
    Err("the `IMPLEMENTED` list has no `];`".to_owned())
}

/// Le rapport de couverture : le nombre de services implémentés par table,
/// puis chaque service avec son numéro, ses arguments et s'il a un handler.
/// Chaque nom de `implemented` doit être un service.
pub fn render_coverage(
    pin: &Pin,
    ntoskrnl: &[Entry],
    win32k: &[Entry],
    implemented: &[String],
) -> Result<String, String> {
    let known: BTreeSet<&str> = ntoskrnl.iter().chain(win32k).map(|e| e.name.as_str()).collect();
    if let Some(unknown) = implemented.iter().find(|name| !known.contains(name.as_str())) {
        return Err(format!("`{unknown}` is implemented but is not a service"));
    }
    let implemented: BTreeSet<&str> = implemented.iter().map(String::as_str).collect();
    let count = |entries: &[Entry]| entries.iter().filter(|e| implemented.contains(e.name.as_str())).count();
    let short = &pin.commit[..pin.commit.len().min(12)];
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Couverture des appels système\n\n\
         Généré par `tools/syscall-gen` (`cargo xtask syscall-gen`) : ne pas modifier.\n\n\
         Les services viennent de ReactOS {} (commit `{short}`), variante i386 de publication. Un service est\n\
         implémenté quand le dispatcher (`kernel/ntoskrnl/src/sys/mod.rs`) lui connaît un handler ; les autres\n\
         rendent `STATUS_NOT_IMPLEMENTED`.\n\n\
         | Table | Implémentés | Services |\n\
         |---|---:|---:|\n\
         | ntoskrnl | {} | {} |\n\
         | win32k | {} | {} |",
        pin.version,
        count(ntoskrnl),
        ntoskrnl.len(),
        count(win32k),
        win32k.len()
    );
    for (title, base, entries) in [("ntoskrnl", 0, ntoskrnl), ("win32k", WIN32K_BASE, win32k)] {
        let _ = writeln!(out, "\n## {title}\n\n| Numéro | Service | Arguments | Implémenté |\n|---|---|---:|:---:|");
        for (i, entry) in entries.iter().enumerate() {
            let mark = if implemented.contains(entry.name.as_str()) { "✅" } else { "" };
            let _ =
                writeln!(out, "| `{:#06x}` | `{}` | {} | {mark} |", base + i as u32, entry.name, entry.argument_count);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str, argument_count: u32) -> Entry {
        Entry { name: name.to_owned(), argument_count }
    }

    #[test]
    fn sysfuncs_gives_names_and_counts_in_order() {
        let entries = parse_sysfuncs("NtAcceptConnectPort 6\n\nNtClose 1\r\n").unwrap();
        assert_eq!(entries, [e("NtAcceptConnectPort", 6), e("NtClose", 1)]);
    }

    #[test]
    fn sysfuncs_rejects_what_it_does_not_know() {
        assert!(parse_sysfuncs("NtClose").unwrap_err().contains("line 1"));
        assert!(parse_sysfuncs("NtClose 1 2").is_err());
        assert!(parse_sysfuncs("NtClose one").unwrap_err().contains("argument count"));
        assert!(parse_sysfuncs("Nt-Close 1").unwrap_err().contains("name"));
        assert!(parse_sysfuncs("NtBig 64").unwrap_err().contains("at most 63"));
    }

    #[test]
    fn w32ksvc_prefixes_nt_and_skips_comments() {
        let text = "    // SVC_(<NAME>, <ARG_COUNT>)\n    SVC_(GdiAbortDoc, 1)\n\
                    SVC_(UserEnumDisplayMonitors, 5) /* FIXME: 4 on XP */\n  SVC_(GdiXLATEOBJ_iXlate,2)\n";
        let entries = parse_w32ksvc(text, &[]).unwrap();
        assert_eq!(entries, [e("NtGdiAbortDoc", 1), e("NtUserEnumDisplayMonitors", 5), e("NtGdiXLATEOBJ_iXlate", 2)]);
    }

    #[test]
    fn w32ksvc_takes_only_the_branches_of_its_symbols() {
        let text = "SVC_(A, 1)\n#ifdef _WIN64\nSVC_(B, 1)\n#endif // _WIN64\n#if DBG\nSVC_(C, 1)\n#else\nSVC_(D, 1)\n\
                    #ifndef DBG\nSVC_(E, 1)\n#endif\n#endif //DBG\nSVC_(F, 1)\n";
        let names = |defined: &[&str]| -> Vec<String> {
            parse_w32ksvc(text, defined).unwrap().into_iter().map(|e| e.name).collect()
        };
        assert_eq!(names(&[]), ["NtA", "NtD", "NtE", "NtF"]);
        assert_eq!(names(&["DBG"]), ["NtA", "NtC", "NtF"]);
        assert_eq!(names(&["DBG", "_WIN64"]), ["NtA", "NtB", "NtC", "NtF"]);
    }

    #[test]
    fn w32ksvc_rejects_unknown_directives_and_unbalanced_blocks() {
        assert!(parse_w32ksvc("#if defined(DBG)\n#endif\n", &[]).unwrap_err().contains("unsupported"));
        assert!(parse_w32ksvc("#define X 1\n", &[]).unwrap_err().contains("unsupported"));
        assert!(parse_w32ksvc("#endif\n", &[]).unwrap_err().contains("without `#if`"));
        assert!(parse_w32ksvc("#else\n", &[]).unwrap_err().contains("without `#if`"));
        assert!(parse_w32ksvc("#if X\n#else\n#else\n#endif\n", &[]).is_err(), "two #else");
        assert!(parse_w32ksvc("#ifdef X\n", &[]).unwrap_err().contains("without `#endif`"));
        assert!(parse_w32ksvc("SVC(GdiAbortDoc, 1)\n", &[]).unwrap_err().contains("line 1"));
    }

    #[test]
    fn the_pinned_lists_give_the_i386_free_build_tables() {
        let ntoskrnl = parse_sysfuncs(include_str!("../reactos/0.4.16/sysfuncs.lst")).unwrap();
        let win32k = parse_w32ksvc(include_str!("../reactos/0.4.16/w32ksvc32.h"), &[]).unwrap();
        validate(&ntoskrnl, &win32k).unwrap();
        assert_eq!((ntoskrnl.len(), win32k.len()), (296, 732), "738 SVC_ lines less 5 DBG and 1 _WIN64");
        let named = |entries: &[Entry], name: &str| entries.iter().any(|e| e.name == name);
        assert!(named(&ntoskrnl, "NtClose") && named(&win32k, "NtGdiAbortDoc"));
        assert!(!named(&win32k, "NtUserSetDbgTag"), "a checked build service");
        assert!(!named(&win32k, "NtUserSetWindowLongPtr"), "a 64-bit service");
    }

    #[test]
    fn the_implemented_list_is_read_line_by_line() {
        let source = "const A: u32 = 1;\npub const IMPLEMENTED: &[(u32, Handler)] = &[\n    \
                      (services::NtClose, object::nt_close),\n    (services::NtA, x::y),\n];\nfn f() {}\n";
        assert_eq!(parse_implemented(source).unwrap(), ["NtClose", "NtA"]);
        assert!(parse_implemented("fn f() {}").unwrap_err().contains("no `pub const IMPLEMENTED`"));
        let bad = "pub const IMPLEMENTED: &[(u32, Handler)] = &[\n    (services::NtA, a), (services::NtB, b),\n];";
        assert_eq!(parse_implemented(bad).unwrap(), ["NtA"], "one entry per line");
        let other = "pub const IMPLEMENTED: &[(u32, Handler)] = &[\n    (17, handler),\n];";
        assert!(parse_implemented(other).unwrap_err().contains("line 2"));
        assert!(parse_implemented("pub const IMPLEMENTED = &[\n").unwrap_err().contains("no `];`"));
    }

    #[test]
    fn coverage_counts_and_marks_the_implemented_services() {
        let pin = Pin { version: "0.4.16", commit: "51bfc7037359b594876a349b46b992e363e79838" };
        let ntoskrnl = [e("NtA", 1), e("NtClose", 1)];
        let report = render_coverage(&pin, &ntoskrnl, &[e("NtGdiC", 2)], &["NtClose".to_owned()]).unwrap();
        assert!(report.contains("| ntoskrnl | 1 | 2 |\n| win32k | 0 | 1 |"));
        assert!(report.contains("| `0x0000` | `NtA` | 1 |  |\n| `0x0001` | `NtClose` | 1 | ✅ |"));
        assert!(report.contains("| `0x1000` | `NtGdiC` | 2 |  |"));
        let unknown = render_coverage(&pin, &ntoskrnl, &[], &["NtNope".to_owned()]);
        assert!(unknown.unwrap_err().contains("not a service"));
    }

    #[test]
    fn names_are_unique_across_both_tables() {
        assert!(validate(&[e("NtA", 1)], &[e("NtB", 1)]).is_ok());
        assert!(validate(&[e("NtA", 1), e("NtA", 2)], &[e("NtB", 1)]).unwrap_err().contains("twice"));
        assert!(validate(&[e("NtA", 1)], &[e("NtA", 1)]).unwrap_err().contains("twice"));
        assert!(validate(&[], &[e("NtB", 1)]).is_err(), "an empty table");
    }

    #[test]
    fn numbers_follow_the_order_of_each_list() {
        let pin = Pin { version: "0.4.16", commit: "51bfc7037359b594876a349b46b992e363e79838" };
        let text = render(&pin, &[e("NtA", 1), e("NtB", 3)], &[e("NtGdiC", 0)]);
        assert!(text.contains("ReactOS 0.4.16 (commit 51bfc7037359)"));
        assert!(text.contains("pub const NtA: u32 = 0x0000;\npub const NtB: u32 = 0x0001;\n"));
        assert!(text.contains("pub const NtGdiC: u32 = 0x1000;\n"));
        assert!(text.contains("pub static NTOSKRNL: [Service; 2] = [\n    Service::new(\"NtA\", 1),\n"));
        assert!(text.contains("pub static WIN32K: [Service; 1] = [\n    Service::new(\"NtGdiC\", 0),\n];\n"));
        assert!(text.ends_with("];\n"));
    }
}
