//! L'énumération d'un répertoire (NtQueryDirectoryFile, 02 §5.6) : ce qu'un
//! pilote de système de fichiers fait d'IRP_MN_QUERY_DIRECTORY, sans l'IRP.
//!
//! [`is_name_in_expression`] dit si un nom répond à une expression, comme
//! FsRtlIsNameInExpression sans casse, d'après sa documentation publique :
//! `*` et `?`, et les jokers DOS que `kernel32` met à la place de certains
//! (FindFirstFileExW : `<` pour `*` devant un `.`, `>` pour `?`, `"` pour un
//! `.` devant `?` ou `*`). [`fill`] met des entrées dans un tampon de la
//! classe demandée, chacune à un multiple de 8 octets, la dernière avec un
//! `NextEntryOffset` de 0.
//!
//! Comme sur XP : la première entrée qui ne tient pas en entier est coupée
//! (`STATUS_BUFFER_OVERFLOW`, son nom tronqué, `FileNameLength` dit ce qui
//! est écrit) et comptée comme rendue ; une entrée suivante qui ne tient pas
//! attend la requête suivante.

use alloc::vec;
use alloc::vec::Vec;

use abi::file::{directory_entry_layout, DirectoryEntry, DIRECTORY_ENTRY_ALIGNMENT};

/// DOS_STAR : zéro caractère ou plus, jusqu'au dernier `.` du nom.
pub const DOS_STAR: u16 = b'<' as u16;
/// DOS_QM : un caractère, ou rien devant un `.` ou à la fin du nom (avec
/// ceux qui le suivent).
pub const DOS_QM: u16 = b'>' as u16;
/// DOS_DOT : un `.`, ou rien à la fin du nom.
pub const DOS_DOT: u16 = b'"' as u16;

const STAR: u16 = b'*' as u16;
const QUESTION: u16 = b'?' as u16;
const PERIOD: u16 = b'.' as u16;

/// L'unité UTF-16 `unit` en majuscule (RtlUpcaseUnicodeChar) : la majuscule
/// de son caractère quand elle en est une seule, du plan de base ; sinon
/// `unit` (une demi-paire de substitution aussi).
pub fn upcase_unit(unit: u16) -> u16 {
    let Some(c) = char::from_u32(u32::from(unit)) else { return unit };
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(up), None) => u16::try_from(u32::from(up)).unwrap_or(unit),
        _ => unit,
    }
}

/// `units` en majuscules.
pub fn upcase(units: &[u16]) -> Vec<u16> {
    units.iter().map(|&unit| upcase_unit(unit)).collect()
}

/// L'expression `expression` (déjà en majuscules) répond au nom `name`,
/// sans casse : FsRtlIsNameInExpression(IgnoreCase), avec `*`, `?`,
/// [`DOS_STAR`], [`DOS_QM`] et [`DOS_DOT`].
pub fn is_name_in_expression(expression: &[u16], name: &[u16]) -> bool {
    let name: Vec<u16> = upcase(name);
    let last_period = name.iter().rposition(|&unit| unit == PERIOD);
    let n = name.len();
    // `next[j]`: expression[e + 1..] matches name[j..]; `row[j]`: the same
    // for expression[e..]. The last row: the empty expression matches the
    // end of the name only.
    let mut next = vec![false; n + 1];
    next[n] = true;
    let mut row = vec![false; n + 1];
    for &c in expression.iter().rev() {
        for j in (0..=n).rev() {
            let here = name.get(j).copied();
            row[j] = match c {
                STAR => next[j] || (here.is_some() && row[j + 1]),
                DOS_STAR => next[j] || (here.is_some() && Some(j) != last_period && row[j + 1]),
                // At a period or the end, it (and the DOS_QMs after it)
                // matches nothing.
                DOS_QM => match here {
                    Some(unit) if unit != PERIOD => next[j + 1],
                    _ => next[j],
                },
                DOS_DOT => match here {
                    Some(PERIOD) => next[j + 1],
                    Some(_) => false,
                    None => next[j],
                },
                QUESTION => here.is_some() && next[j + 1],
                literal => here == Some(literal) && next[j + 1],
            };
        }
        core::mem::swap(&mut row, &mut next);
    }
    next[0]
}

/// Ce que [`fill`] a mis dans le tampon.
#[derive(Debug, PartialEq, Eq)]
pub struct Filled {
    /// Les octets à rendre (l'`Information` du bloc d'état) : jusqu'à la fin
    /// de la dernière entrée.
    pub bytes: Vec<u8>,
    /// Les entrées rendues (la première coupée comprise).
    pub count: usize,
    /// La première est coupée : `STATUS_BUFFER_OVERFLOW`.
    pub overflow: bool,
    /// D'où reprendre : la place, dans le répertoire, de la première entrée
    /// à considérer ensuite.
    pub resume: u32,
}

/// Met les entrées `entries` (chacune avec sa place dans le répertoire, en
/// ordre croissant) dans un tampon de `length` octets, de la classe `class`
/// ([`directory_entry_layout`]), une seule si `single`. `length` tient au
/// moins la partie fixe d'une entrée (le gestionnaire d'E/S l'a vérifié) ;
/// sans quoi, ou pour une autre classe, rien n'est rendu.
pub fn fill<'a>(
    class: u32,
    length: usize,
    single: bool,
    entries: impl IntoIterator<Item = (u32, DirectoryEntry<'a>)>,
    resume: u32,
) -> Filled {
    let mut filled = Filled { bytes: Vec::new(), count: 0, overflow: false, resume };
    let Some((name_at, _)) = directory_entry_layout(class).filter(|&(name_at, _)| length >= name_at) else {
        return filled;
    };
    let mut out = vec![0u8; length];
    let mut used = 0usize;
    let mut previous: Option<usize> = None;
    for (place, entry) in entries {
        let start = if previous.is_some() { used.next_multiple_of(DIRECTORY_ENTRY_ALIGNMENT) } else { 0 };
        let needed = name_at + entry.name.len() * 2;
        if start + needed > length {
            if previous.is_some() {
                // For the next query.
                filled.resume = place;
                break;
            }
            // The first one, cut.
            used = entry.encode(class, &mut out).unwrap_or(0);
            filled = Filled { bytes: Vec::new(), count: 1, overflow: true, resume: place + 1 };
            break;
        }
        if let Some(previous) = previous {
            let offset = (start - previous) as u32;
            out[previous..previous + 4].copy_from_slice(&offset.to_le_bytes());
        }
        used = start + entry.encode(class, &mut out[start..start + needed]).unwrap_or(0);
        previous = Some(start);
        filled.count += 1;
        filled.resume = place + 1;
        if single {
            break;
        }
    }
    out.truncate(used);
    filled.bytes = out;
    filled
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use abi::file::{FILE_BOTH_DIRECTORY_INFORMATION, FILE_NAMES_INFORMATION};
    use std::string::String;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// `pattern` as FindFirstFileExW gives it to the file system (`*.*`
    /// becomes `*`; `<`, `>` and `"` for the wildcards of DOS), upcased.
    fn expression(pattern: &str) -> Vec<u16> {
        upcase(&units(pattern))
    }

    fn matches(pattern: &str, name: &str) -> bool {
        is_name_in_expression(&expression(pattern), &units(name))
    }

    #[test]
    fn plain_names_match_without_case() {
        assert!(matches("OUT.TXT", "out.txt"));
        assert!(matches("out.txt", "OUT.TXT"), "the expression upcased");
        assert!(!matches("OUT.TXT", "OUT.TXTX"));
        assert!(!matches("OUT.TXT", "OUT.TX"));
        assert!(matches("é.TXT", "É.txt"), "beyond ASCII");
    }

    #[test]
    fn star_and_question_mark() {
        for name in ["", ".", "..", "OUT.TXT", "NO DOT"] {
            assert!(matches("*", name), "{name:?}");
        }
        assert!(matches("O*T", "OUT") && matches("O*T", "OT") && !matches("O*T", "OUTS"));
        assert!(matches("O?T", "OUT") && !matches("O?T", "OT") && !matches("O?T", "OUUT"));
        assert!(matches("*A*B*", "xxAyyBzz") && !matches("*A*B*", "xxByyAzz"));
    }

    #[test]
    fn the_wildcards_of_dos() {
        // `*.txt`: DOS_STAR up to the last period.
        assert!(matches("<.TXT", "OUT.TXT"));
        assert!(matches("<.TXT", ".TXT"));
        assert!(matches("<.GZ", "A.TAR.GZ"), "past a period that is not the last");
        assert!(!matches("<.TXT", "OUT.TXT.BAK"));
        assert!(!matches("<.TXT", "TXT"));
        assert!(matches("<X", "AX") && !matches("<X", "A.BX"), "never past the last period");
        // `a??.txt`: DOS_QM matches one character, or nothing at a period.
        for name in ["A.TXT", "AB.TXT", "ABC.TXT"] {
            assert!(matches("A>>.TXT", name), "{name}");
        }
        assert!(!matches("A>>.TXT", "ABCD.TXT"));
        assert!(matches("A>>", "A") && matches("A>>", "AB") && !matches("A>>", "ABCD"));
        // `a.*`: DOS_DOT, a period or the end of the name.
        assert!(matches("A\"*", "A") && matches("A\"*", "A.B") && !matches("A\"*", "AB"));
    }

    fn entry<'a>(name: &'a [u16], short: &'a [u16]) -> DirectoryEntry<'a> {
        DirectoryEntry { end_of_file: 5, file_attributes: 0x20, name, short_name: short, ..Default::default() }
    }

    /// The names of the FILE_NAMES_INFORMATION entries in `bytes`, by their
    /// `NextEntryOffset`, and where each one begins.
    fn walk(bytes: &[u8]) -> Vec<(usize, String)> {
        let mut found = Vec::new();
        let mut at = 0usize;
        loop {
            let word = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            let length = word(at + 8);
            let name: Vec<u16> =
                bytes[at + 12..at + 12 + length].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            found.push((at, String::from_utf16(&name).unwrap()));
            match word(at) {
                0 => return found,
                next => at += next,
            }
        }
    }

    #[test]
    fn entries_are_chained_at_multiples_of_eight() {
        let (a, bb, ccc) = (units("A"), units("BB"), units("CCC"));
        let entries = [(0u32, entry(&a, &[])), (32, entry(&bb, &[])), (64, entry(&ccc, &[]))];
        let filled = fill(FILE_NAMES_INFORMATION, 4096, false, entries, 0);
        assert_eq!((filled.count, filled.overflow, filled.resume), (3, false, 65));
        assert_eq!(walk(&filled.bytes), [(0, "A".into()), (16, "BB".into()), (32, "CCC".into())]);
        assert_eq!(filled.bytes.len(), 32 + 12 + 6, "up to the end of the last entry");

        let single = fill(FILE_NAMES_INFORMATION, 4096, true, entries, 0);
        assert_eq!((single.count, single.resume, walk(&single.bytes)), (1, 1, [(0, "A".into())].into()));
    }

    #[test]
    fn what_does_not_fit_waits_or_is_cut() {
        let (a, long) = (units("A"), units("A RATHER LONG NAME"));
        // A then the long name: 14 bytes, then 16 + 12 + 36; 40 bytes hold A.
        let entries = [(0u32, entry(&a, &[])), (32, entry(&long, &[]))];
        let filled = fill(FILE_NAMES_INFORMATION, 40, false, entries, 0);
        assert_eq!((filled.count, filled.overflow, filled.resume), (1, false, 32), "the long name waits");
        assert_eq!(walk(&filled.bytes), [(0, "A".into())]);

        // First, it is cut: what fits of its name.
        let cut = fill(FILE_NAMES_INFORMATION, 20, false, [(32, entry(&long, &[]))], 32);
        assert_eq!((cut.count, cut.overflow, cut.resume, cut.bytes.len()), (1, true, 33, 20));
        assert_eq!(walk(&cut.bytes), [(0, "A RA".into())]);

        // Nothing: not even the fixed part.
        let none = fill(FILE_BOTH_DIRECTORY_INFORMATION, 93, false, entries, 7);
        assert_eq!((none.count, none.bytes.len(), none.resume), (0, 0, 7));
        let nothing_left = fill(FILE_NAMES_INFORMATION, 4096, false, [], 7);
        assert_eq!((nothing_left.count, nothing_left.resume), (0, 7));
    }
}
