//! Démanglage des noms de symboles Rust, pour l'écran d'erreur fatale : le
//! schéma v0 (`_R…`, celui de notre chaîne) et l'ancien schéma (`_ZN…E`).
//!
//! Sans allocation : le texte va dans un `fmt::Write` (un tampon fixe à l'écran
//! d'erreur). Les empreintes de crate (`[0123abcd]`) sont omises. Un nom que ce
//! module ne sait pas lire est rendu tel quel par [`write_demangled`].
//!
//! Grammaire v0 : RFC 2603 (rust-lang/rfcs, `text/2603-rust-symbol-name-mangling-v0.md`).

use core::fmt::{self, Write};

/// Écrit `name` démanglé dans `out`, ou tel quel si ce n'est pas un nom Rust
/// lisible ; un suffixe (`.llvm.…`) est omis.
pub fn write_demangled(name: &str, out: &mut dyn Write) -> fmt::Result {
    if let Some(v0) = name.strip_prefix("_R") {
        // Le schéma v0 n'emploie pas `.` : un point commence le suffixe.
        let v0 = v0.split_once('.').map_or(v0, |(base, _)| base);
        if demangle_v0(v0.as_bytes(), &mut Discard).is_ok() {
            return demangle_v0(v0.as_bytes(), out).map_err(|_| fmt::Error);
        }
    } else if let Some(legacy) = name.strip_prefix("_ZN") {
        if demangle_legacy(legacy.as_bytes(), &mut Discard).is_ok() {
            return demangle_legacy(legacy.as_bytes(), out).map_err(|_| fmt::Error);
        }
    }
    out.write_str(name)
}

/// Un nom illisible, ou une sortie en erreur.
#[derive(Debug)]
struct Invalid;

impl From<fmt::Error> for Invalid {
    fn from(_: fmt::Error) -> Self {
        Invalid
    }
}

/// Sortie qui ne garde rien : pour valider un nom avant de l'écrire.
struct Discard;

impl Write for Discard {
    fn write_str(&mut self, _: &str) -> fmt::Result {
        Ok(())
    }
}

// ── Schéma v0 ────────────────────────────────────────────────────────────────

/// Profondeur maximale de récursion (chemins, types et renvois imbriqués).
const MAX_DEPTH: u32 = 64;

fn demangle_v0(sym: &[u8], out: &mut dyn Write) -> Result<(), Invalid> {
    // `_R` [<version>] <path> [<crate d'instanciation>] : une version (des
    // chiffres) n'est pas encore définie.
    if sym.first().is_some_and(u8::is_ascii_digit) {
        return Err(Invalid);
    }
    let mut p = V0 { sym, pos: 0, depth: 0, out, quiet: 0 };
    p.path(true)?;
    // Le reste, s'il y en a, est la crate d'instanciation : lue, non affichée.
    if p.pos < sym.len() {
        p.quiet += 1;
        p.path(false)?;
    }
    if p.pos == sym.len() {
        Ok(())
    } else {
        Err(Invalid)
    }
}

struct V0<'a, 'o> {
    /// Le nom, sans `_R` : les renvois (`B`) y sont des positions.
    sym: &'a [u8],
    pos: usize,
    depth: u32,
    out: &'o mut dyn Write,
    /// Non nul : on lit sans écrire (chemin d'un `impl`, crate d'instanciation).
    quiet: u32,
}

impl<'a> V0<'a, '_> {
    fn print(&mut self, s: &str) -> Result<(), Invalid> {
        if self.quiet == 0 {
            self.out.write_str(s)?;
        }
        Ok(())
    }

    fn print_u64(&mut self, v: u64) -> Result<(), Invalid> {
        if self.quiet == 0 {
            write!(self.out, "{v}")?;
        }
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.sym.get(self.pos).copied()
    }

    fn next(&mut self) -> Result<u8, Invalid> {
        let b = self.peek().ok_or(Invalid)?;
        self.pos += 1;
        Ok(b)
    }

    fn eat(&mut self, b: u8) -> bool {
        let found = self.peek() == Some(b);
        if found {
            self.pos += 1;
        }
        found
    }

    /// `<base-62-number>` : `_` vaut 0, `<chiffres>_` vaut leur valeur + 1.
    fn base62(&mut self) -> Result<u64, Invalid> {
        if self.eat(b'_') {
            return Ok(0);
        }
        let mut v: u64 = 0;
        loop {
            let d = match self.next()? {
                c @ b'0'..=b'9' => c - b'0',
                c @ b'a'..=b'z' => c - b'a' + 10,
                c @ b'A'..=b'Z' => c - b'A' + 36,
                b'_' => return v.checked_add(1).ok_or(Invalid),
                _ => return Err(Invalid),
            };
            v = v.checked_mul(62).and_then(|v| v.checked_add(u64::from(d))).ok_or(Invalid)?;
        }
    }

    /// `[s <base-62-number>]` : 0 sans désambiguïsateur, sinon sa valeur + 1.
    fn disambiguator(&mut self) -> Result<u64, Invalid> {
        if self.eat(b's') {
            self.base62()?.checked_add(1).ok_or(Invalid)
        } else {
            Ok(0)
        }
    }

    fn decimal(&mut self) -> Result<usize, Invalid> {
        let first = self.next()?;
        if !first.is_ascii_digit() {
            return Err(Invalid);
        }
        let mut v = usize::from(first - b'0');
        if v == 0 {
            return Ok(0);
        }
        while let Some(c @ b'0'..=b'9') = self.peek() {
            self.pos += 1;
            v = v.checked_mul(10).and_then(|v| v.checked_add(usize::from(c - b'0'))).ok_or(Invalid)?;
        }
        Ok(v)
    }

    /// `[<disambiguator>] ["u"] <decimal> ["_"] <octets>` : le nom (brut s'il est
    /// en punycode, `u`) et le désambiguïsateur.
    fn identifier(&mut self) -> Result<(&'a str, u64), Invalid> {
        let dis = self.disambiguator()?;
        let _punycode = self.eat(b'u');
        let len = self.decimal()?;
        self.eat(b'_');
        let sym: &'a [u8] = self.sym;
        let end = self.pos.checked_add(len).filter(|&e| e <= sym.len()).ok_or(Invalid)?;
        let name = core::str::from_utf8(&sym[self.pos..end]).map_err(|_| Invalid)?;
        self.pos = end;
        Ok((name, dis))
    }

    fn enter(&mut self) -> Result<(), Invalid> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(Invalid)
        } else {
            Ok(())
        }
    }

    /// Suit un renvoi `B <base-62-number>` : `f` lit ce qui se trouve à cette
    /// position (strictement avant le renvoi), puis la lecture reprend après.
    fn backref(&mut self, f: impl FnOnce(&mut Self) -> Result<(), Invalid>) -> Result<(), Invalid> {
        let at = self.pos - 1;
        let target = usize::try_from(self.base62()?).map_err(|_| Invalid)?;
        if target >= at {
            return Err(Invalid);
        }
        let resume = self.pos;
        self.pos = target;
        f(self)?;
        self.pos = resume;
        Ok(())
    }

    /// `<path>`. `in_value` : les arguments génériques s'écrivent `::<…>`.
    fn path(&mut self, in_value: bool) -> Result<(), Invalid> {
        self.enter()?;
        match self.next()? {
            b'C' => {
                let (name, _) = self.identifier()?;
                self.print(name)?;
            }
            b'N' => {
                let ns = self.next()?;
                if !ns.is_ascii_alphabetic() {
                    return Err(Invalid);
                }
                self.path(in_value)?;
                let (name, dis) = self.identifier()?;
                if ns.is_ascii_uppercase() {
                    // Espace de noms spécial : `{closure#0}`, `{shim:vtable#0}`…
                    self.print("::{")?;
                    self.print(match ns {
                        b'C' => "closure",
                        b'S' => "shim",
                        _ => "unknown",
                    })?;
                    if !name.is_empty() {
                        self.print(":")?;
                        self.print(name)?;
                    }
                    self.print("#")?;
                    self.print_u64(dis)?;
                    self.print("}")?;
                } else if !name.is_empty() {
                    self.print("::")?;
                    self.print(name)?;
                }
            }
            b'M' => {
                self.impl_path()?;
                self.print("<")?;
                self.ty()?;
                self.print(">")?;
            }
            b'X' => {
                self.impl_path()?;
                self.print("<")?;
                self.ty()?;
                self.print(" as ")?;
                self.path(false)?;
                self.print(">")?;
            }
            b'Y' => {
                self.print("<")?;
                self.ty()?;
                self.print(" as ")?;
                self.path(false)?;
                self.print(">")?;
            }
            b'I' => {
                self.path(in_value)?;
                if in_value {
                    self.print("::")?;
                }
                self.print("<")?;
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        self.print(", ")?;
                    }
                    first = false;
                    self.generic_arg()?;
                }
                self.print(">")?;
            }
            b'B' => self.backref(|p| p.path(in_value))?,
            _ => return Err(Invalid),
        }
        self.depth -= 1;
        Ok(())
    }

    /// `[<disambiguator>] <path>` d'un `impl` : lu, pas affiché.
    fn impl_path(&mut self) -> Result<(), Invalid> {
        self.disambiguator()?;
        self.quiet += 1;
        let r = self.path(false);
        self.quiet -= 1;
        r
    }

    fn generic_arg(&mut self) -> Result<(), Invalid> {
        if self.eat(b'L') {
            self.base62()?;
            self.print("'_")
        } else if self.eat(b'K') {
            self.konst()
        } else {
            self.ty()
        }
    }

    fn ty(&mut self) -> Result<(), Invalid> {
        self.enter()?;
        let c = self.next()?;
        if let Some(basic) = basic_type(c) {
            self.print(basic)?;
        } else {
            match c {
                b'R' | b'Q' => {
                    self.print("&")?;
                    if self.eat(b'L') {
                        self.base62()?;
                    }
                    if c == b'Q' {
                        self.print("mut ")?;
                    }
                    self.ty()?;
                }
                b'P' => {
                    self.print("*const ")?;
                    self.ty()?;
                }
                b'O' => {
                    self.print("*mut ")?;
                    self.ty()?;
                }
                b'A' => {
                    self.print("[")?;
                    self.ty()?;
                    self.print("; ")?;
                    self.konst()?;
                    self.print("]")?;
                }
                b'S' => {
                    self.print("[")?;
                    self.ty()?;
                    self.print("]")?;
                }
                b'T' => {
                    self.print("(")?;
                    let mut count = 0;
                    while !self.eat(b'E') {
                        if count > 0 {
                            self.print(", ")?;
                        }
                        self.ty()?;
                        count += 1;
                    }
                    if count == 1 {
                        self.print(",")?;
                    }
                    self.print(")")?;
                }
                b'F' => self.fn_sig()?,
                b'D' => self.dyn_bounds()?,
                b'B' => self.backref(|p| p.ty())?,
                _ => {
                    // Un chemin : on le relit depuis sa première lettre.
                    self.pos -= 1;
                    self.path(false)?;
                }
            }
        }
        self.depth -= 1;
        Ok(())
    }

    /// `[<binder>] ["U"] ["K" <abi>] {<type>} "E" <type>`
    fn fn_sig(&mut self) -> Result<(), Invalid> {
        if self.eat(b'G') {
            self.base62()?;
        }
        if self.eat(b'U') {
            self.print("unsafe ")?;
        }
        if self.eat(b'K') {
            self.print("extern \"")?;
            if self.eat(b'C') {
                self.print("C")?;
            } else {
                let len = self.decimal()?;
                self.eat(b'_');
                let end = self.pos.checked_add(len).filter(|&e| e <= self.sym.len()).ok_or(Invalid)?;
                let abi = core::str::from_utf8(&self.sym[self.pos..end]).map_err(|_| Invalid)?;
                self.pos = end;
                // L'ABI s'écrit avec `_` à la place de `-` (`system_unwind`).
                for part in abi.split('_').enumerate() {
                    if part.0 > 0 {
                        self.print("-")?;
                    }
                    self.print(part.1)?;
                }
            }
            self.print("\" ")?;
        }
        self.print("fn(")?;
        let mut first = true;
        while !self.eat(b'E') {
            if !first {
                self.print(", ")?;
            }
            first = false;
            self.ty()?;
        }
        self.print(")")?;
        if self.eat(b'u') {
            // Retour `()` : rien à écrire.
        } else {
            self.print(" -> ")?;
            self.ty()?;
        }
        Ok(())
    }

    /// `[<binder>] {<dyn-trait>} "E" <lifetime>`
    fn dyn_bounds(&mut self) -> Result<(), Invalid> {
        if self.eat(b'G') {
            self.base62()?;
        }
        self.print("dyn ")?;
        let mut first = true;
        while !self.eat(b'E') {
            if !first {
                self.print(" + ")?;
            }
            first = false;
            self.path(false)?;
            while self.eat(b'p') {
                // Lien de type associé (`Item = T`) : lu, pas affiché.
                self.quiet += 1;
                let r = self.identifier().map(|_| ()).and_then(|_| self.ty());
                self.quiet -= 1;
                r?;
            }
        }
        if !self.eat(b'L') {
            return Err(Invalid);
        }
        self.base62()?;
        Ok(())
    }

    /// `<const>` : `p` (`_`), un renvoi, ou un type de base suivi de sa valeur.
    fn konst(&mut self) -> Result<(), Invalid> {
        self.enter()?;
        match self.next()? {
            b'p' => self.print("_")?,
            b'B' => self.backref(|p| p.konst())?,
            ty => {
                let negative = self.eat(b'n');
                let mut v: u64 = 0;
                let mut digits = 0;
                loop {
                    let d = match self.next()? {
                        c @ b'0'..=b'9' => c - b'0',
                        c @ b'a'..=b'f' => c - b'a' + 10,
                        b'_' => break,
                        _ => return Err(Invalid),
                    };
                    digits += 1;
                    v = v.wrapping_shl(4) | u64::from(d);
                }
                match ty {
                    b'b' => self.print(if v == 0 { "false" } else { "true" })?,
                    b'c' => {
                        let ch = char::from_u32(u32::try_from(v).map_err(|_| Invalid)?).ok_or(Invalid)?;
                        let mut buf = [0u8; 4];
                        self.print("'")?;
                        self.print(ch.encode_utf8(&mut buf))?;
                        self.print("'")?;
                    }
                    _ if digits > 16 => self.print("{big}")?,
                    _ => {
                        if negative {
                            self.print("-")?;
                        }
                        self.print_u64(v)?;
                    }
                }
            }
        }
        self.depth -= 1;
        Ok(())
    }
}

fn basic_type(c: u8) -> Option<&'static str> {
    Some(match c {
        b'a' => "i8",
        b'b' => "bool",
        b'c' => "char",
        b'd' => "f64",
        b'e' => "str",
        b'f' => "f32",
        b'h' => "u8",
        b'i' => "isize",
        b'j' => "usize",
        b'l' => "i32",
        b'm' => "u32",
        b'n' => "i128",
        b'o' => "u128",
        b's' => "i16",
        b't' => "u16",
        b'u' => "()",
        b'v' => "...",
        b'x' => "i64",
        b'y' => "u64",
        b'z' => "!",
        b'p' => "_",
        _ => return None,
    })
}

// ── Ancien schéma ────────────────────────────────────────────────────────────

/// `_ZN` {<longueur><élément>} `E` [<suffixe `.…`>] : éléments joints par
/// `::`, l'empreinte finale (`h` + 16 chiffres hexadécimaux) omise,
/// échappements `$…$` décodés. (`..` y est un échappement, pas un suffixe.)
fn demangle_legacy(sym: &[u8], out: &mut dyn Write) -> Result<(), Invalid> {
    let mut pos = 0;
    let mut first = true;
    loop {
        match sym.get(pos) {
            Some(b'E') if !first && (pos + 1 == sym.len() || sym[pos + 1] == b'.') => return Ok(()),
            Some(c) if c.is_ascii_digit() => {}
            _ => return Err(Invalid),
        }
        let digits = sym[pos..].iter().take_while(|b| b.is_ascii_digit()).count();
        let len: usize =
            core::str::from_utf8(&sym[pos..pos + digits]).ok().and_then(|s| s.parse().ok()).ok_or(Invalid)?;
        pos += digits;
        let end = pos.checked_add(len).filter(|&e| e < sym.len()).ok_or(Invalid)?;
        let part = core::str::from_utf8(&sym[pos..end]).map_err(|_| Invalid)?;
        pos = end;
        let is_hash = sym[pos] == b'E' && part.len() == 17 && part.starts_with('h');
        if is_hash && part[1..].bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if !first {
            out.write_str("::")?;
        }
        first = false;
        legacy_part(part, out)?;
    }
}

fn legacy_part(mut part: &str, out: &mut dyn Write) -> Result<(), Invalid> {
    // `_` protège un élément qui commencerait par `$`.
    if part.starts_with("_$") {
        part = &part[1..];
    }
    while !part.is_empty() {
        if let Some(rest) = part.strip_prefix("..") {
            out.write_str("::")?;
            part = rest;
        } else if part.starts_with('$') {
            let end = part[1..].find('$').ok_or(Invalid)? + 1;
            let escape = &part[1..end];
            let ch = match escape {
                "SP" => '@',
                "BP" => '*',
                "RF" => '&',
                "LT" => '<',
                "GT" => '>',
                "LP" => '(',
                "RP" => ')',
                "C" => ',',
                _ => {
                    let hex = escape.strip_prefix('u').ok_or(Invalid)?;
                    char::from_u32(u32::from_str_radix(hex, 16).map_err(|_| Invalid)?).ok_or(Invalid)?
                }
            };
            out.write_char(ch)?;
            part = &part[end + 1..];
        } else {
            let end = part.find(['$', '.']).unwrap_or(part.len());
            let end = if end == 0 { 1 } else { end };
            out.write_str(&part[..end])?;
            part = &part[end..];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::String;

    fn demangled(name: &str) -> String {
        let mut s = String::new();
        write_demangled(name, &mut s).unwrap();
        s
    }

    /// Des noms du noyau, et leur forme démanglée par `c++filt` (binutils 2.42),
    /// empreintes de crate retirées. `c++filt` écrit `[u8; 2: usize]` : on écrit
    /// `[u8; 2]`, comme rustc-demangle.
    const KERNEL_SYMBOLS: &[(&str, &str)] = &[
        ("_RNvCs4ucKvTVXtXY_8ntoskrnl18kernel_main_phase1", "ntoskrnl::kernel_main_phase1"),
        ("_RNvNtCsixtykT6yiRY_3hal3idt9irq_timer", "hal::idt::irq_timer"),
        (
            "_RNvMNtCsf8j9dHhRaMZ_10io_manager3fatINtB2_9FatVolumeNtB4_14AtaBlockDeviceE11find_in_dirB4_",
            "<io_manager::fat::FatVolume<io_manager::AtaBlockDevice>>::find_in_dir",
        ),
        (
            "_RNvXs_NtNtCsdkwDDN9ROji_4core3ops5rangeINtB4_5RangejENtNtB8_3fmt5Debug3fmtB8_",
            "<core::ops::range::Range<usize> as core::fmt::Debug>::fmt",
        ),
        ("_RNCNvCs4ucKvTVXtXY_8ntoskrnl15check_kernel_wx0B3_", "ntoskrnl::check_kernel_wx::{closure#0}"),
        (
            "_RNvXsa_NtCsdkwDDN9ROji_4core5arrayAhj2_NtNtB7_3fmt5Debug3fmtCs4ucKvTVXtXY_8ntoskrnl",
            "<[u8; 2] as core::fmt::Debug>::fmt",
        ),
        (
            "_RNvMsn_NtCs4DdXuvLmbkN_5alloc4syncINtB5_3ArcDNtNtCsaWMVw1xWAcu_2ob6object12KernelObjectEL_E9drop_slowBL_",
            "<alloc::sync::Arc<dyn ob::object::KernelObject>>::drop_slow",
        ),
        (
            "_RNvXs1g_NtCsdkwDDN9ROji_4core3fmtRDNtB6_5DebugEL_Bx_3fmtB8_",
            "<&dyn core::fmt::Debug as core::fmt::Debug>::fmt",
        ),
        (
            "_RINvMNtCsdkwDDN9ROji_4core6optionINtB3_6OptionTyyEE7or_elseNCNvNtCsixtykT6yiRY_3hal3idt22exception_double_fault0EB11_",
            "<core::option::Option<(u64, u64)>>::or_else::<hal::idt::exception_double_fault::{closure#0}>",
        ),
        (
            "_RNvMNtCsdkwDDN9ROji_4core6optionINtB2_6OptionTFONtNtB4_3ffi6c_voidEuBJ_EE6expectCsa5Fbhf1336f_2ke",
            "<core::option::Option<(fn(*mut core::ffi::c_void), *mut core::ffi::c_void)>>::expect",
        ),
        (
            "_RNCNvNtNtCskZUXZrVLtBo_17compiler_builtins3mem5impls13compare_bytess1_0B7_.llvm.8785191241240594697",
            "compiler_builtins::mem::impls::compare_bytes::{closure#3}",
        ),
    ];

    #[test]
    fn kernel_symbols_read_like_cxxfilt_without_crate_hashes() {
        for &(mangled, expected) in KERNEL_SYMBOLS {
            assert_eq!(demangled(mangled), expected, "{mangled}");
        }
    }

    #[test]
    fn legacy_names_drop_their_hash_and_decode_escapes() {
        assert_eq!(demangled("_ZN4core3fmt5write17h0123456789abcdefE"), "core::fmt::write");
        assert_eq!(demangled("_ZN4core3fmt5write17h0123456789abcdefE.llvm.42"), "core::fmt::write");
        assert_eq!(
            demangled(
                "_ZN65_$LT$hal..sync..KSpinLock$LT$T$GT$$u20$as$u20$core..ops..Drop$GT$4drop17h0011223344556677E"
            ),
            "<hal::sync::KSpinLock<T> as core::ops::Drop>::drop"
        );
    }

    #[test]
    fn other_names_are_kept_as_they_are() {
        for name in ["kernel_main", "ke_context_switch", "_RNvC", "_R", "_RNvCs_3foo_trailing", "_ZN3foo", "_ZNE"] {
            assert_eq!(demangled(name), name, "{name}");
        }
    }

    #[test]
    fn a_backref_must_point_backwards() {
        // `B_` renvoie à la position 0 depuis la position 0 : refusé, nom brut.
        assert_eq!(demangled("_RB_"), "_RB_");
        let deep = std::format!("_R{}", "I".repeat(200));
        assert_eq!(demangled(&deep), deep, "too deep");
    }
}
