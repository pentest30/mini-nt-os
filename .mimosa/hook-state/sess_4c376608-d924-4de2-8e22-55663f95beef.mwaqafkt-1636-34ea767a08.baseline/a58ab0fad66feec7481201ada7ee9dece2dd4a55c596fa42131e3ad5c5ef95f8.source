//! The pattern matching of a directory enumeration
//! (`FsRtlIsNameInExpression`): which names a pattern keeps.
//!
//! `?` matches one character, `*` any number of them (none included),
//! without regard to case. The meta-characters of DOS, which the callers
//! send (`FindFirstFile` writes `<` for the star before an extension):
//! `<` matches any characters up to, but not including, the name's last
//! dot; `>` one character, or none at the last dot or the end. Two cases
//! of DOS, as `RtlIsNameInExpression` makes them: the pattern `*.*`
//! matches every name, dotted or not, and a pattern that ends in `*.`
//! matches only the names without an extension.

use alloc::vec::Vec;

/// Does `name` match the pattern `expression`?
pub fn is_name_in_expression(expression: &str, name: &str) -> bool {
    let up = |text: &str| text.chars().flat_map(char::to_uppercase).collect::<Vec<char>>();
    let expression = up(expression);
    let name = up(name);
    if expression == ['*'] || expression == ['*', '.', '*'] {
        return true;
    }
    // `W*.` (and its DOS writing `W<.`) names only what starts like `W*`
    // and has no extension.
    if expression.last() == Some(&'.') && matches!(expression[..expression.len() - 1].last(), Some('*' | '<')) {
        let without_dot = &expression[..expression.len() - 1];
        return !name.contains(&'.') && matches(without_dot, &name);
    }
    matches(&expression, &name)
}

/// Plain matching, `*` `?` and the DOS `<` `>`, of already up-cased
/// characters.
fn matches(expression: &[char], name: &[char]) -> bool {
    // Where the last dot of `name` is.
    let last_dot = || name.iter().rposition(|character| *character == '.');
    match expression.split_first() {
        None => name.is_empty(),
        Some(('*', rest)) => (0..=name.len()).any(|skip| matches(rest, &name[skip..])),
        // The star of DOS: any characters short of the last dot.
        Some(('<', rest)) => (0..=name.len()).any(|skip| {
            let crossed = last_dot().is_some_and(|at| skip > at);
            !crossed && matches(rest, &name[skip..])
        }),
        Some(('?', rest)) => name.split_first().is_some_and(|(_, rest_name)| matches(rest, rest_name)),
        // The question mark of DOS: one character, or none at the last dot
        // (or the end of the name).
        Some(('>', rest)) => match name.split_first() {
            Some((_, rest_name)) if last_dot() != Some(0) => matches(rest, rest_name),
            _ => matches(rest, name),
        },
        Some((&expected, rest)) => match name.split_first() {
            Some((&first, rest_name)) => expected == first && matches(rest, rest_name),
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_star_names_everything() {
        assert!(is_name_in_expression("*", "NTDLL.DLL"));
        assert!(is_name_in_expression("*.*", "NTDLL.DLL"), "the DOS case: dotted or not");
        assert!(is_name_in_expression("*.*", "README"));
    }

    #[test]
    fn a_star_before_a_dot_names_only_the_extension_less() {
        assert!(is_name_in_expression("*.", "README"));
        assert!(is_name_in_expression("W*.", "WINDOWS"));
        assert!(!is_name_in_expression("*.", "A.TXT"));
        assert!(!is_name_in_expression("W*.", "A.TXT"));
    }

    #[test]
    fn a_pattern_matches_without_case() {
        assert!(is_name_in_expression("nt*.dll", "NTDLL.DLL"));
        assert!(is_name_in_expression("*.DLL", "ntdll.dll"));
        assert!(!is_name_in_expression("*.DLL", "KERNEL.EXE"));
        assert!(is_name_in_expression("?.TXT", "A.TXT"));
        assert!(!is_name_in_expression("?.TXT", "AB.TXT"));
        assert!(is_name_in_expression("*A*", "BANANA"));
        assert!(!is_name_in_expression("NT*", "KERNEL.DLL"));
        assert!(is_name_in_expression("KERNEL", "kernel"));
    }

    #[test]
    fn the_meta_characters_of_dos_match_as_findfirstfile_sends_them() {
        // "*.EXE" as FindFirstFile writes it.
        assert!(is_name_in_expression("<.EXE", "TEST.EXE"));
        assert!(is_name_in_expression("<.EXE", "A.B.EXE"), "up to the last dot");
        assert!(!is_name_in_expression("<.EXE", "README"));
        assert!(!is_name_in_expression("<.EXE", "A.TXT"));
        // "<" alone stops at the last dot: "A.B" does not fully match.
        assert!(!is_name_in_expression("<", "A.B"));
        assert!(is_name_in_expression("<", "AB"));
        // ">" is "?" that gives way at the last dot.
        assert!(is_name_in_expression(">.TXT", "A.TXT"));
        assert!(!is_name_in_expression(">.TXT", "AB.TXT"));
        assert!(is_name_in_expression("A>B", "ACB"));
        // The extension-less case in its DOS writing.
        assert!(is_name_in_expression("<.", "README"));
        assert!(!is_name_in_expression("<.", "A.TXT"));
    }
}
