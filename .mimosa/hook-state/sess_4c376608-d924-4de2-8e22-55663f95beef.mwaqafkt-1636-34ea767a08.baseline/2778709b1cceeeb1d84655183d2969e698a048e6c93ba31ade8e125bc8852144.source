//! Écran d'erreur fatale (« STOP »), affiché sans prendre de verrou ni allouer.
//!
//! Il donne le code d'arrêt et ses quatre paramètres, le nom du code, la
//! raison, quelques valeurs étiquetées, l'IRQL, puis la pile d'appels noyau
//! symbolisée (`hal::symbols`). Ke y ajoute le thread courant
//! (`ke::bugcheck::ke_bug_check_ex`). La sortie va sur COM1 par accès direct
//! aux ports et, si son verrou est libre, sur la console du framebuffer.
//!
//! La pile se suit par la chaîne des RBP : le noyau est compilé avec les
//! pointeurs de cadre (`force-frame-pointers`, `.cargo/config.toml`). `core`
//! et `alloc`, précompilés, ne les gardent pas toujours : un cadre de ces
//! crates peut manquer, ou interrompre la chaîne. Chaque lecture est vérifiée
//! dans les tables de pages, pour que l'écran ne fasse pas lui-même de faute.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

pub use abi::bugcheck::BugCheckCode;

/// Où commence la pile d'appels de l'écran.
#[derive(Clone, Copy, Debug)]
pub enum StackStart {
    /// À l'appelant de [`stop`] : `KeBugCheckEx`, `panic!`.
    Caller,
    /// Au code qu'une trap a interrompu : l'instruction fautive et le RBP du
    /// code interrompu.
    Trap { rip: u64, rbp: u64 },
}

/// Cadres suivis au plus : une pile noyau de 24 Kio en tient une
/// cinquantaine de 512 octets.
const MAX_FRAMES: usize = 64;
/// Lignes de pile affichées au plus, pour que l'en-tête reste à l'écran.
const MAX_LINES: usize = 16;
/// Le noyau est lié dans les 2 Gio du haut (`code-model=kernel`, ADR-014) :
/// toute adresse de retour noyau est au-dessus.
const KERNEL_TEXT_MIN: u64 = 0xFFFF_FFFF_8000_0000;

/// L'écran est en cours : une faute pendant son affichage ne le relance pas.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// Affiche l'écran STOP et arrête ce processeur pour de bon.
///
/// `details` s'affichent un par ligne, `  <étiquette> 0x<valeur>`.
///
/// # IRQL
/// Tout niveau ; masque les interruptions. Ne prend aucun verrou et n'alloue pas.
#[inline(never)]
pub fn stop(
    code: BugCheckCode,
    params: [u64; 4],
    reason: Option<&dyn fmt::Display>,
    details: &[(&str, u64)],
    start: StackStart,
) -> ! {
    x86_64::instructions::interrupts::disable();
    if STOPPING.swap(true, Ordering::AcqRel) {
        out("\n*** STOP while printing the STOP screen\nSystem halted.\n");
        halt();
    }
    let here = frame_pointer();

    out("\n*** STOP: 0x");
    hex(u64::from(code.0), 8);
    out(" (");
    for (i, &p) in params.iter().enumerate() {
        if i > 0 {
            out(", ");
        }
        out("0x");
        hex(p, 16);
    }
    out(")\n");
    if let Some(name) = code.name() {
        out(name);
        out("\n");
    }
    if let Some(reason) = reason {
        // Une faute pendant le formatage finit sur la ligne de `STOPPING`.
        let _ = write!(Out, "{reason}");
        out("\n");
    }
    for &(label, value) in details {
        detail(label, value);
    }
    detail("IRQL         ", crate::irql::current() as u64);

    out("Call stack:\n");
    let rbp = match start {
        StackStart::Caller => here,
        StackStart::Trap { rip, rbp } => {
            // L'instruction fautive elle-même, pas une adresse de retour.
            frame_line(rip, rip);
            rbp
        }
    };
    let mut lines = 0;
    let mut cut = false;
    let mut emit = |line: Line| {
        if lines == MAX_LINES {
            cut = true;
            return;
        }
        lines += 1;
        match line {
            Line::Frame(ret) => frame_line(ret, ret - 1),
            Line::Repeated(times) => {
                let _ = writeln!(Out, "    (same frame {times} more times)");
            }
        }
    };
    let mut collapse = Collapse::default();
    let deeper = walk(rbp, read_stack_word, |ret| collapse.push(ret, &mut emit));
    collapse.flush(&mut emit);
    if deeper || cut {
        out("  ...\n");
    }
    out("System halted.\n");
    halt();
}

fn halt() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

/// Une ligne de la pile : `addr`, puis la fonction qui contient `inside` et
/// le décalage d'`addr` dans celle-ci. Pour une adresse de retour, `inside`
/// est l'octet d'avant, dans l'appel : une fonction qui finit par un appel
/// sans retour a pour adresse de retour le début de la suivante.
fn frame_line(addr: u64, inside: u64) {
    out("  ");
    hex(addr, 16);
    if let Some((name, offset)) = crate::symbols::lookup(inside) {
        out("  ");
        let _ = crate::symbols::write_demangled(name, &mut Out);
        let _ = write!(Out, "+{:#x}", offset + (addr - inside));
    }
    out("\n");
}

fn detail(label: &str, value: u64) {
    out("  ");
    out(label);
    out(" 0x");
    hex(value, 16);
    out("\n");
}

/// Suit la chaîne des RBP à partir de `rbp` : chaque cadre garde en `[rbp]`
/// le RBP de l'appelant et en `[rbp + 8]` l'adresse de retour, que reçoit
/// `visit`. S'arrête sur un RBP nul, mal aligné ou illisible, sur une adresse
/// de retour hors du noyau, ou quand la chaîne ne remonte plus la pile.
/// Renvoie `true` si elle continue au-delà de [`MAX_FRAMES`] cadres.
fn walk(mut rbp: u64, read: impl Fn(u64) -> Option<u64>, mut visit: impl FnMut(u64)) -> bool {
    let mut frames = 0;
    loop {
        if rbp == 0 || !rbp.is_multiple_of(8) {
            return false;
        }
        let (Some(next), Some(ret)) = (read(rbp), rbp.checked_add(8).and_then(&read)) else {
            return false;
        };
        if ret < KERNEL_TEXT_MIN {
            return false;
        }
        if frames == MAX_FRAMES {
            return true;
        }
        visit(ret);
        frames += 1;
        if next <= rbp {
            return false;
        }
        rbp = next;
    }
}

/// Une ligne de la pile d'appels.
#[derive(Debug, PartialEq)]
enum Line {
    /// Une adresse de retour.
    Frame(u64),
    /// La précédente revient encore autant de fois de suite : une récursion.
    Repeated(u32),
}

/// Résume en une ligne [`Line::Repeated`] les adresses de retour identiques
/// qui se suivent, pour qu'une récursion profonde ne cache pas le bas de la
/// pile.
#[derive(Default)]
struct Collapse {
    last: Option<u64>,
    repeats: u32,
}

impl Collapse {
    fn push(&mut self, ret: u64, emit: &mut impl FnMut(Line)) {
        if self.last == Some(ret) {
            self.repeats += 1;
            return;
        }
        self.flush(emit);
        emit(Line::Frame(ret));
        self.last = Some(ret);
    }

    /// Émet la répétition en cours.
    fn flush(&mut self, emit: &mut impl FnMut(Line)) {
        if self.repeats > 0 {
            emit(Line::Repeated(self.repeats));
            self.repeats = 0;
        }
    }
}

/// Le mot de 64 bits à `addr` (aligné sur 8), s'il est projeté.
fn read_stack_word(addr: u64) -> Option<u64> {
    if !mapped(addr) {
        return None;
    }
    // SAFETY: `addr` est aligné sur 8 et sa page est présente dans les tables
    // de pages actives ; lire ne modifie rien.
    Some(unsafe { core::ptr::read_volatile(addr as *const u64) })
}

/// `va` est projetée dans les tables de pages actives (CR3), lues par le HHDM.
fn mapped(va: u64) -> bool {
    const PRESENT: u64 = 1;
    const HUGE: u64 = 1 << 7;
    const FRAME: u64 = 0x000F_FFFF_FFFF_F000;

    let canonical = ((va as i64) << 16 >> 16) as u64 == va;
    if !canonical {
        return false;
    }
    // Nul avant `set_hhdm_offset`, quand le mapping identité est encore là.
    let hhdm = crate::HHDM_OFFSET.load(Ordering::Acquire);
    let mut table = x86_64::registers::control::Cr3::read_raw().0.start_address().as_u64();
    // Niveau 3 : PML4 ; 0 : table des pages.
    for level in (0..4).rev() {
        if table >= crate::HHDM_SIZE {
            return false;
        }
        let index = (va >> (12 + 9 * level)) & 0x1FF;
        // SAFETY: `table` est une table de pages sous 4 Gio, que le HHDM
        // projette ; lire une entrée ne modifie rien.
        let entry = unsafe { core::ptr::read_volatile((hhdm + table + index * 8) as *const u64) };
        if entry & PRESENT == 0 {
            return false;
        }
        if level == 0 || (level < 3 && entry & HUGE != 0) {
            return true;
        }
        table = entry & FRAME;
    }
    false
}

/// Le RBP de la fonction appelante (son cadre, pointeurs de cadre forcés).
#[inline(always)]
fn frame_pointer() -> u64 {
    let rbp: u64;
    // SAFETY: lire RBP n'a pas d'effet.
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags)) };
    rbp
}

/// Le RBP du code qu'une trap a interrompue. À appeler dans le gestionnaire
/// `x86-interrupt` lui-même : son prologue (`push rbp ; mov rbp, rsp`) a
/// sauvé ce RBP en `[rbp]`.
#[inline(always)]
pub(crate) fn interrupted_rbp() -> u64 {
    let rbp = frame_pointer();
    // SAFETY: `rbp` est le cadre du gestionnaire, sur la pile courante, dont
    // le premier mot est le RBP sauvé par son prologue.
    unsafe { core::ptr::read_volatile(rbp as *const u64) }
}

/// Écrit sur l'écran STOP.
struct Out;

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        out(s);
        Ok(())
    }
}

fn out(s: &str) {
    super::serial::write_str_unlocked(s);
    super::fb::write_str_fatal(s);
}

/// Écrit `value` en `digits` chiffres hexadécimaux minuscules, complétés par
/// des zéros.
fn hex(value: u64, digits: u32) {
    let mut buf = [0u8; 16];
    for (i, digit) in buf.iter_mut().take(digits as usize).enumerate() {
        let nibble = (value >> ((digits as usize - 1 - i) * 4)) & 0xF;
        *digit = b"0123456789abcdef"[nibble as usize];
    }
    // Le tampon ne contient que des chiffres hexadécimaux ASCII.
    out(core::str::from_utf8(&buf[..digits as usize]).unwrap_or("?"));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    const TEXT: u64 = KERNEL_TEXT_MIN + 0x1000;

    /// Une pile factice : adresse → mot.
    fn stack(words: &[(u64, u64)]) -> BTreeMap<u64, u64> {
        words.iter().copied().collect()
    }

    fn returns(start: u64, memory: &BTreeMap<u64, u64>) -> (Vec<u64>, bool) {
        let mut seen = Vec::new();
        let truncated = walk(start, |addr| memory.get(&addr).copied(), |ret| seen.push(ret));
        (seen, truncated)
    }

    #[test]
    fn follows_the_chain_up_to_the_end_of_the_stack() {
        let memory = stack(&[
            (0x1000, 0x1040),
            (0x1008, TEXT),
            (0x1040, 0x1100),
            (0x1048, TEXT + 1),
            (0x1100, 0),
            (0x1108, TEXT + 2),
        ]);
        assert_eq!(returns(0x1000, &memory), (std::vec![TEXT, TEXT + 1, TEXT + 2], false));
    }

    #[test]
    fn stops_where_the_chain_stops_climbing() {
        let memory = stack(&[(0x1000, 0x1040), (0x1008, TEXT), (0x1040, 0x1040), (0x1048, TEXT + 1)]);
        assert_eq!(returns(0x1000, &memory), (std::vec![TEXT, TEXT + 1], false), "a frame that points to itself");
        let memory = stack(&[(0x1000, 0x0800), (0x1008, TEXT), (0x0800, 0x2000), (0x0808, TEXT + 1)]);
        assert_eq!(returns(0x1000, &memory), (std::vec![TEXT], false), "a caller below its callee");
    }

    #[test]
    fn stops_on_a_bad_frame_pointer_or_return_address() {
        let memory = stack(&[(0x1000, 0x1044), (0x1008, TEXT)]);
        assert_eq!(returns(0x1000, &memory), (std::vec![TEXT], false), "unaligned RBP");
        let memory = stack(&[(0x1000, 0x2000), (0x1008, TEXT)]);
        assert_eq!(returns(0x1000, &memory), (std::vec![TEXT], false), "unreadable RBP");
        let memory = stack(&[(0x1000, 0x1040), (0x1008, 0x0040_1000), (0x1040, 0), (0x1048, TEXT)]);
        assert_eq!(returns(0x1000, &memory), (std::vec![], false), "user-mode return address");
        let memory = stack(&[(0x1000, 0x1040)]);
        assert_eq!(returns(0x1000, &memory), (std::vec![], false), "return address unreadable");
        assert_eq!(returns(0, &memory), (std::vec![], false), "null RBP");
    }

    #[test]
    fn repeated_frames_collapse_into_one_line() {
        let mut lines = Vec::new();
        let mut emit = |line| lines.push(line);
        let mut collapse = Collapse::default();
        for ret in [TEXT, TEXT + 1, TEXT + 1, TEXT + 1, TEXT + 2, TEXT, TEXT] {
            collapse.push(ret, &mut emit);
        }
        collapse.flush(&mut emit);
        assert_eq!(
            lines,
            [
                Line::Frame(TEXT),
                Line::Frame(TEXT + 1),
                Line::Repeated(2),
                Line::Frame(TEXT + 2),
                Line::Frame(TEXT),
                Line::Repeated(1),
            ]
        );
    }

    #[test]
    fn stops_after_the_maximum_number_of_frames() {
        let words: Vec<(u64, u64)> = (0..MAX_FRAMES as u64 + 10)
            .flat_map(|i| [(0x1000 + 16 * i, 0x1000 + 16 * (i + 1)), (0x1008 + 16 * i, TEXT + i)])
            .collect();
        let (seen, truncated) = returns(0x1000, &stack(&words));
        assert_eq!(seen, (0..MAX_FRAMES as u64).map(|i| TEXT + i).collect::<Vec<_>>());
        assert!(truncated);

        let exact: Vec<(u64, u64)> = words[..2 * MAX_FRAMES].to_vec();
        assert!(!returns(0x1000, &stack(&exact)).1, "exactly MAX_FRAMES frames is not truncated");
    }
}
