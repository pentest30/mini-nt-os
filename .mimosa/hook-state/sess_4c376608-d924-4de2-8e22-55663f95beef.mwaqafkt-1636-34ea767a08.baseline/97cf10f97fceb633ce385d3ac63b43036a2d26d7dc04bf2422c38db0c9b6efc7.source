//! Les tables d'une disposition de clavier (KBDTABLES, `kbd.h`) et ce qu'en
//! tire win32k (`keyboard.c` de ReactOS, comme spécification).
//!
//! [`Tables::parse`] les lit une fois dans l'image de la DLL de disposition
//! (ses pointeurs sont des adresses à sa base préférée), en limitant chaque
//! liste : une disposition mal formée est refusée, jamais suivie sans fin.
//! Puis :
//! - [`Tables::vsc_to_vk`] (IntVscToVk) : la touche virtuelle d'un scan code,
//!   préfixé `E0` ou `E1` ou non, avec ses drapeaux (`KBDEXT`, `KBDNUMPAD`) ;
//! - [`Tables::translate_char`] (IntTranslateChar) : le caractère d'une
//!   touche selon l'état du clavier (les modificateurs de la disposition,
//!   Caps Lock, AltGr), les touches mortes, et Ctrl + lettre ;
//! - [`to_unicode`] (IntToUnicodeEx) : ToUnicode, avec la touche morte en
//!   attente.
//!
//! L'état du clavier est celui que rend GetKeyboardState : un octet par
//! touche virtuelle, [`DOWN`] pour une touche enfoncée, [`LOCKED`] pour une
//! touche basculée (Caps Lock).
//!
//! Pas encore : les ligatures (`pLigature`), les noms des touches.

use alloc::vec::Vec;
use core::mem::size_of;

use abi::kbd::{
    DeadKey32, KbdTables32, Modifiers32, VkToWcharTable32, VscVk32, CAPLOK, CAPLOKALTGR, KBDALT, KBDCTRL, KBDSHIFT,
    KLLF_ALTGR, MODIFIERS_MOD_NUMBER, WCH_DEAD, WCH_LGTR, WCH_NONE,
};
use abi::user::vk::{VK_CAPITAL, VK_CONTROL, VK_MENU, VK_RMENU};

/// L'état du clavier : un octet par touche virtuelle.
pub type KeyState = [u8; 256];
/// La touche est enfoncée (KS_DOWN_BIT).
pub const DOWN: u8 = 0x80;
/// La touche est basculée (KS_LOCK_BIT).
pub const LOCKED: u8 = 0x01;

/// `vk` est enfoncée dans `state`.
pub fn is_down(state: &KeyState, vk: u8) -> bool {
    state[usize::from(vk)] & DOWN != 0
}

/// `vk` est basculée dans `state`.
pub fn is_locked(state: &KeyState, vk: u8) -> bool {
    state[usize::from(vk)] & LOCKED != 0
}

/// Les entrées au plus d'une liste des tables.
const MAX_ENTRIES: usize = 512;
/// Les tables de caractères au plus.
const MAX_WCHAR_TABLES: usize = 16;

/// Une ligne d'une table de caractères (VK_TO_WCHARS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub vk: u8,
    pub attributes: u8,
    /// Un caractère par modification.
    pub chars: Vec<u16>,
}

/// Une table de caractères (VK_TO_WCHAR_TABLE) : ses lignes, dans l'ordre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WcharTable {
    pub modifications: u8,
    pub rows: Vec<Row>,
}

/// Le caractère d'une touche.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translated {
    pub ch: u16,
    /// Une touche morte (WCH_DEAD) : `ch` est son caractère.
    pub dead: bool,
    /// Une ligature (WCH_LGTR).
    pub ligature: bool,
}

/// Les tables d'une disposition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tables {
    /// Les modificateurs (VK_TO_BIT) : une touche et ses bits.
    pub vk_to_bit: Vec<(u8, u8)>,
    pub max_mod_bits: u16,
    /// La colonne de chaque combinaison de bits (`ModNumber`).
    pub mod_number: Vec<u8>,
    pub wchar_tables: Vec<WcharTable>,
    pub dead_keys: Vec<DeadKey32>,
    pub vsc_to_vk: Vec<u16>,
    pub vsc_to_vk_e0: Vec<(u8, u16)>,
    pub vsc_to_vk_e1: Vec<(u8, u16)>,
    pub locale_flags: u32,
}

/// Lit `count` octets en `va` (une adresse à la base `base`) par `read`.
fn at<'a>(read: &dyn Fn(u32, usize) -> Option<&'a [u8]>, base: u32, va: u32, count: usize) -> Option<&'a [u8]> {
    read(va.checked_sub(base)?, count)
}

/// Les entrées de `size` octets en `va`, jusqu'à celle que `end` reconnaît
/// (exclue), au plus [`MAX_ENTRIES`] ; `None` si la liste n'a pas de fin ou
/// sort de l'image. Une adresse nulle : une liste vide.
fn list<'a, T>(
    read: &dyn Fn(u32, usize) -> Option<&'a [u8]>,
    base: u32,
    va: u32,
    size: usize,
    decode: impl Fn(&[u8]) -> Option<T>,
    end: impl Fn(&T) -> bool,
) -> Option<Vec<T>> {
    let mut entries = Vec::new();
    if va == 0 {
        return Some(entries);
    }
    for index in 0..MAX_ENTRIES {
        let entry = decode(at(read, base, va.checked_add((index * size) as u32)?, size)?)?;
        if end(&entry) {
            return Some(entries);
        }
        entries.push(entry);
    }
    None
}

impl Tables {
    /// Les tables en `tables` (une RVA) de l'image dont `read` lit les
    /// octets par RVA, à sa base préférée `base` ; `None` pour des tables
    /// incomplètes, mal formées ou trop longues.
    pub fn parse<'a>(read: &dyn Fn(u32, usize) -> Option<&'a [u8]>, base: u32, tables: u32) -> Option<Self> {
        let head = KbdTables32::from_bytes(read(tables, size_of::<KbdTables32>())?)?;
        let modifiers = Modifiers32::from_bytes(at(read, base, head.char_modifiers, MODIFIERS_MOD_NUMBER as usize)?)?;
        let vk_to_bit = list(read, base, modifiers.vk_to_bit, 2, |b| Some((b[0], b[1])), |&(vk, _)| vk == 0)?;
        let columns = usize::from(modifiers.max_mod_bits) + 1;
        if columns > 64 {
            return None;
        }
        let mod_number = at(read, base, head.char_modifiers + MODIFIERS_MOD_NUMBER, columns)?.to_vec();
        let heads = list(
            read,
            base,
            head.vk_to_wchar_table,
            size_of::<VkToWcharTable32>(),
            VkToWcharTable32::from_bytes,
            |table| table.vk_to_wchars == 0,
        )?;
        if heads.len() > MAX_WCHAR_TABLES {
            return None;
        }
        let mut wchar_tables = Vec::with_capacity(heads.len());
        for table in heads {
            let modifications = usize::from(table.modifications);
            if usize::from(table.size) < 2 + 2 * modifications {
                return None;
            }
            let decode = |b: &[u8]| {
                let chars = (0..modifications).map(|i| u16::from_le_bytes([b[2 + 2 * i], b[3 + 2 * i]])).collect();
                Some(Row { vk: b[0], attributes: b[1], chars })
            };
            let rows = list(read, base, table.vk_to_wchars, usize::from(table.size), decode, |row| row.vk == 0)?;
            wchar_tables.push(WcharTable { modifications: table.modifications, rows });
        }
        let dead_keys =
            list(read, base, head.dead_key, size_of::<DeadKey32>(), DeadKey32::from_bytes, |d| d.both == 0)?;
        let count = usize::from(head.max_vsc_to_vk);
        let vsc_to_vk = if count == 0 {
            Vec::new()
        } else {
            let bytes = at(read, base, head.vsc_to_vk, 2 * count)?;
            bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
        };
        let prefixed = |va| {
            list(read, base, va, size_of::<VscVk32>(), VscVk32::from_bytes, |e| e.vsc == 0)
                .map(|entries| entries.into_iter().map(|e| (e.vsc, e.vk)).collect::<Vec<_>>())
        };
        Some(Self {
            vk_to_bit,
            max_mod_bits: modifiers.max_mod_bits,
            mod_number,
            wchar_tables,
            dead_keys,
            vsc_to_vk,
            vsc_to_vk_e0: prefixed(head.vsc_to_vk_e0)?,
            vsc_to_vk_e1: prefixed(head.vsc_to_vk_e1)?,
            locale_flags: head.locale_flags,
        })
    }

    /// IntVscToVk : la touche virtuelle (avec ses drapeaux) du scan code
    /// `scan`, préfixé `0xE000` ou `0xE100` ; 0 sans touche.
    pub fn vsc_to_vk(&self, scan: u16) -> u16 {
        let code = (scan & 0xFF) as u8;
        let vk = match scan & 0xFF00 {
            0xE000 => self.vsc_to_vk_e0.iter().rev().find(|&&(vsc, _)| vsc == code).map_or(0, |&(_, vk)| vk),
            0xE100 => self.vsc_to_vk_e1.iter().rev().find(|&&(vsc, _)| vsc == code).map_or(0, |&(_, vk)| vk),
            _ => self.vsc_to_vk.get(usize::from(scan)).copied().unwrap_or(0),
        };
        // 0xFF and 0x00 are no key.
        if vk == 0xFF {
            0
        } else {
            vk
        }
    }

    /// IntGetModBits : les bits des modificateurs enfoncés dans `state`.
    pub fn mod_bits(&self, state: &KeyState) -> u8 {
        self.vk_to_bit.iter().filter(|&&(vk, _)| is_down(state, vk)).fold(0, |bits, &(_, mod_bits)| bits | mod_bits)
    }

    /// IntTranslateChar : le caractère de la touche `vk` dans l'état
    /// `state` (aucun : sans modificateur) ; `None` sans caractère.
    pub fn translate_char(&self, vk: u8, state: Option<&KeyState>) -> Option<Translated> {
        let mut bits = state.map_or(0, |state| self.mod_bits(state));
        let alt_gr = state.is_some_and(|state| self.locale_flags & KLLF_ALTGR != 0 && is_down(state, VK_RMENU));
        let caplok = if alt_gr { CAPLOKALTGR } else { CAPLOK };
        // Alt without Ctrl gives the character without Alt.
        if bits & (KBDALT | KBDCTRL) == KBDALT {
            bits &= !KBDALT;
        }
        if u16::from(bits) > self.max_mod_bits {
            return None;
        }
        for table in &self.wchar_tables {
            let Some(index) = table.rows.iter().position(|row| row.vk == vk) else { continue };
            let row = &table.rows[index];
            let mut row_bits = bits;
            if row.attributes & caplok != 0 && state.is_some_and(|state| is_locked(state, VK_CAPITAL)) {
                row_bits ^= KBDSHIFT;
            }
            let column = usize::from(*self.mod_number.get(usize::from(row_bits))?);
            let &ch = row.chars.get(column)?;
            if ch == WCH_NONE {
                return None;
            }
            if ch == WCH_DEAD {
                // The dead character is on the next row, of key 0xFF.
                let trailer = table.rows.get(index + 1).filter(|next| next.vk == 0xFF)?;
                return Some(Translated { ch: *trailer.chars.get(column)?, dead: true, ligature: false });
            }
            return Some(Translated { ch, dead: false, ligature: ch == WCH_LGTR });
        }
        // Ctrl + a letter: an ASCII control character, which no table has.
        let state = state?;
        if vk.is_ascii_uppercase() && is_down(state, VK_CONTROL) && !is_down(state, VK_MENU) {
            return Some(Translated { ch: u16::from(vk - b'A' + 1), dead: false, ligature: false });
        }
        None
    }
}

/// IntToUnicodeEx : les caractères de la touche `vk` dans l'état `state`,
/// dans `out` ; `dead` garde la touche morte d'un appel au suivant. Rend
/// leur nombre, négatif pour une touche morte, 0 sans caractère (ni
/// ligature).
pub fn to_unicode(tables: &Tables, vk: u8, state: &KeyState, dead: &mut u16, out: &mut [u16]) -> i32 {
    let Some(mut translated) = tables.translate_char(vk, Some(state)) else { return 0 };
    if translated.ligature {
        return 0;
    }
    let mut count = 0;
    let mut push = |ch: u16| {
        if let Some(slot) = out.get_mut(count) {
            *slot = ch;
            count += 1;
        }
    };
    if *dead != 0 {
        let composed =
            tables.dead_keys.iter().find(|key| key.both == (u32::from(*dead) << 16 | u32::from(translated.ch)));
        if let Some(key) = composed {
            translated = Translated { ch: key.composed, dead: false, ligature: false };
            *dead = 0;
        }
    }
    // A dead key without a composition: both characters as they are.
    if *dead != 0 {
        push(*dead);
        translated.dead = false;
    }
    push(translated.ch);
    *dead = if translated.dead { translated.ch } else { 0 };
    if translated.dead {
        -(count as i32)
    } else {
        count as i32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use abi::user::vk::{VK_LSHIFT, VK_SHIFT};

    /// A layout's image, flat (its RVAs are offsets), at base 0x1000_0000:
    /// a QWERTY subset with Shift, Ctrl and Alt, a dead key and AltGr.
    struct Image {
        bytes: Vec<u8>,
    }

    const BASE: u32 = 0x1000_0000;

    impl Image {
        fn new() -> Self {
            Self { bytes: alloc::vec![0; 0x100] }
        }

        /// Appends `bytes`, 4-aligned; returns their address.
        fn put(&mut self, bytes: &[u8]) -> u32 {
            while !self.bytes.len().is_multiple_of(4) {
                self.bytes.push(0);
            }
            let at = self.bytes.len() as u32;
            self.bytes.extend_from_slice(bytes);
            BASE + at
        }

        fn read<'a>(&'a self) -> impl Fn(u32, usize) -> Option<&'a [u8]> + 'a {
            move |rva, count| self.bytes.get(rva as usize..rva as usize + count)
        }
    }

    fn row(vk: u8, attributes: u8, chars: &[u16]) -> Vec<u8> {
        let mut bytes = alloc::vec![vk, attributes];
        chars.iter().for_each(|ch| bytes.extend_from_slice(&ch.to_le_bytes()));
        bytes
    }

    const ACUTE: u16 = 0x00B4;

    /// The tables: their RVA in the image.
    fn layout(image: &mut Image) -> u32 {
        // Shift, Ctrl, Alt; columns: none, Shift, Ctrl, (Shift+Ctrl invalid), Ctrl+Alt (AltGr).
        let bits = image.put(&[VK_SHIFT, KBDSHIFT, VK_CONTROL, KBDCTRL, VK_MENU, KBDALT, 0, 0]);
        let mut modifiers = bits.to_le_bytes().to_vec();
        modifiers.extend_from_slice(&6u16.to_le_bytes());
        modifiers.extend_from_slice(&[0, 1, 2, 0x0F, 0x0F, 0x0F, 3]);
        let modifiers = image.put(&modifiers);
        // Four columns, 2 + 8 bytes a row.
        let mut rows = Vec::new();
        rows.extend(row(b'A', CAPLOK, &[u16::from(b'a'), u16::from(b'A'), WCH_NONE, WCH_NONE]));
        rows.extend(row(b'1', 0, &[u16::from(b'1'), u16::from(b'!'), WCH_NONE, WCH_NONE]));
        rows.extend(row(b'E', CAPLOK, &[u16::from(b'e'), u16::from(b'E'), WCH_NONE, 0x20AC]));
        rows.extend(row(0xDE, 0, &[WCH_DEAD, u16::from(b'"'), WCH_NONE, WCH_NONE]));
        rows.extend(row(0xFF, 0, &[ACUTE, WCH_NONE, WCH_NONE, WCH_NONE]));
        rows.extend(row(0, 0, &[0, 0, 0, 0]));
        let rows = image.put(&rows);
        let mut tables = rows.to_le_bytes().to_vec();
        tables.extend_from_slice(&[4, 10, 0, 0]);
        tables.extend_from_slice(&[0; 8]);
        let wchar_tables = image.put(&tables);
        // ´ then e: é; the end.
        let mut dead = (u32::from(ACUTE) << 16 | u32::from(b'e')).to_le_bytes().to_vec();
        dead.extend_from_slice(&0x00E9u16.to_le_bytes());
        dead.extend_from_slice(&[0; 2 + 8]);
        let dead = image.put(&dead);
        // Scan codes 0..=0x12: 0x02 is '1', 0x12 'E', 0x10 an invalid 0xFF.
        let mut vsc = [0u16; 0x13];
        vsc[0x02] = u16::from(b'1');
        vsc[0x12] = u16::from(b'E');
        vsc[0x10] = 0xFF;
        vsc[0x2A % 0x13] = u16::from(VK_LSHIFT);
        let vsc: Vec<u8> = vsc.iter().flat_map(|vk| vk.to_le_bytes()).collect();
        let vsc = image.put(&vsc);
        // E0 1D: right Ctrl, extended.
        let e0 = image.put(&[0x1D, 0, 0xA3, 0x01, 0, 0, 0, 0]);
        let mut head = alloc::vec![0u8; 52];
        head[0..4].copy_from_slice(&modifiers.to_le_bytes());
        head[4..8].copy_from_slice(&wchar_tables.to_le_bytes());
        head[8..12].copy_from_slice(&dead.to_le_bytes());
        head[24..28].copy_from_slice(&vsc.to_le_bytes());
        head[28] = 0x13;
        head[32..36].copy_from_slice(&e0.to_le_bytes());
        head[40..44].copy_from_slice(&KLLF_ALTGR.to_le_bytes());
        image.put(&head) - BASE
    }

    #[expect(clippy::let_and_return, reason = "the reader borrows the image until the tables are built")]
    fn tables() -> Tables {
        let mut image = Image::new();
        let rva = layout(&mut image);
        let read = image.read();
        let tables = Tables::parse(&read, BASE, rva).expect("tables");
        tables
    }

    fn state(down: &[u8], locked: &[u8]) -> KeyState {
        let mut state = [0u8; 256];
        down.iter().for_each(|&vk| state[usize::from(vk)] |= DOWN);
        locked.iter().for_each(|&vk| state[usize::from(vk)] |= LOCKED);
        state
    }

    fn ch(tables: &Tables, vk: u8, state: &KeyState) -> Option<char> {
        tables.translate_char(vk, Some(state)).map(|t| char::from_u32(u32::from(t.ch)).unwrap())
    }

    #[test]
    fn the_tables_are_read_from_the_image() {
        let tables = tables();
        assert_eq!(tables.vk_to_bit, [(VK_SHIFT, KBDSHIFT), (VK_CONTROL, KBDCTRL), (VK_MENU, KBDALT)]);
        assert_eq!((tables.max_mod_bits, tables.mod_number.len()), (6, 7));
        assert_eq!((tables.wchar_tables.len(), tables.wchar_tables[0].rows.len()), (1, 5));
        assert_eq!(tables.dead_keys.len(), 1);
        assert_eq!((tables.vsc_to_vk.len(), tables.vsc_to_vk_e0.len(), tables.vsc_to_vk_e1.len()), (0x13, 1, 0));
    }

    #[test]
    fn a_scan_code_gives_its_virtual_key() {
        let tables = tables();
        assert_eq!(tables.vsc_to_vk(0x02), u16::from(b'1'));
        assert_eq!(tables.vsc_to_vk(0xE01D), 0x01A3, "right Ctrl, KBDEXT");
        assert_eq!(tables.vsc_to_vk(0x10), 0, "0xFF is no key");
        assert_eq!((tables.vsc_to_vk(0x40), tables.vsc_to_vk(0xE01E), tables.vsc_to_vk(0xE11D)), (0, 0, 0));
    }

    #[test]
    fn modifiers_choose_the_column() {
        let tables = tables();
        assert_eq!(ch(&tables, b'A', &state(&[], &[])), Some('a'));
        assert_eq!(ch(&tables, b'A', &state(&[VK_SHIFT], &[])), Some('A'));
        assert_eq!(ch(&tables, b'1', &state(&[VK_SHIFT], &[])), Some('!'));
        assert_eq!(ch(&tables, b'A', &state(&[VK_MENU], &[])), Some('a'), "Alt alone drops out");
        assert_eq!(ch(&tables, b'E', &state(&[VK_CONTROL, VK_MENU], &[])), Some('€'), "Ctrl+Alt: column 3");
        assert_eq!(ch(&tables, b'1', &state(&[VK_CONTROL, VK_MENU], &[])), None, "no character there");
        assert_eq!(tables.translate_char(b'A', None).map(|t| t.ch), Some(u16::from(b'a')), "no state");
        assert_eq!(ch(&tables, b'Z', &state(&[], &[])), None, "not in the layout");
    }

    #[test]
    fn caps_lock_shifts_the_keys_that_say_so() {
        let tables = tables();
        let caps = state(&[], &[VK_CAPITAL]);
        assert_eq!((ch(&tables, b'A', &caps), ch(&tables, b'1', &caps)), (Some('A'), Some('1')));
        assert_eq!(ch(&tables, b'A', &state(&[VK_SHIFT], &[VK_CAPITAL])), Some('a'), "Shift undoes it");
    }

    #[test]
    fn ctrl_and_a_letter_give_a_control_character() {
        let tables = tables();
        assert_eq!(tables.translate_char(b'C', Some(&state(&[VK_CONTROL], &[]))).map(|t| t.ch), Some(3));
        assert_eq!(tables.translate_char(b'C', Some(&state(&[VK_CONTROL, VK_MENU], &[]))), None);
    }

    #[test]
    fn a_dead_key_waits_for_the_next() {
        let tables = tables();
        let none = state(&[], &[]);
        let (mut dead, mut out) = (0, [0u16; 3]);
        assert_eq!(to_unicode(&tables, 0xDE, &none, &mut dead, &mut out), -1);
        assert_eq!((out[0], dead), (ACUTE, ACUTE));
        assert_eq!(to_unicode(&tables, b'E', &none, &mut dead, &mut out), 1);
        assert_eq!((out[0], dead), (0x00E9, 0), "´ then e: é");
        to_unicode(&tables, 0xDE, &none, &mut dead, &mut out);
        assert_eq!(to_unicode(&tables, b'A', &none, &mut dead, &mut out), 2, "no composition: both");
        assert_eq!((out[0], out[1], dead), (ACUTE, u16::from(b'a'), 0));
        assert_eq!(to_unicode(&tables, b'Z', &none, &mut dead, &mut out), 0);
        let mut short = [0u16; 1];
        to_unicode(&tables, 0xDE, &none, &mut dead, &mut short);
        assert_eq!(to_unicode(&tables, b'A', &none, &mut dead, &mut short), 1, "what the buffer holds");
    }

    #[test]
    fn malformed_tables_are_refused() {
        let mut image = Image::new();
        let rva = layout(&mut image);
        assert!(Tables::parse(&image.read(), BASE, rva + 0x10_0000).is_none(), "outside the image");
        // A dead-key list without its end.
        let mut endless = Image::new();
        let rva = layout(&mut endless);
        let dead = u32::from_le_bytes(endless.bytes[rva as usize + 8..rva as usize + 12].try_into().unwrap()) - BASE;
        endless.bytes.truncate(dead as usize + 8);
        let read = |at: u32, count: usize| {
            // Every entry past the first repeats it: no end.
            let at = if at > dead { dead } else { at };
            endless.bytes.get(at as usize..at as usize + count)
        };
        assert!(Tables::parse(&read, BASE, rva).is_none());
    }

    /// The pinned userland's US layout, when it is there.
    #[test]
    fn the_us_layout_of_reactos() {
        const KBDUS: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/reactos/0.4.16/reactos/system32/kbdus.dll");
        let Ok(image) = std::fs::read(KBDUS) else {
            std::eprintln!("skipped: no {KBDUS} (cargo xtask fetch-userland)");
            return;
        };
        let rva = crate::keyboard::layer_descriptor_tables(&image).expect("KbdLayerDescriptor");
        let pe = pe::Pe32::parse(&image).unwrap();
        let tables = Tables::parse(&|at, count| pe.read_rva(at, count), pe.optional_header().image_base, rva).unwrap();
        let none = state(&[], &[]);
        assert_eq!(tables.vsc_to_vk(0x1E), u16::from(b'A'));
        assert_eq!(tables.vsc_to_vk(0x1C), 0x0D, "Enter");
        assert_eq!(tables.vsc_to_vk(0x2A) & 0xFF, u16::from(VK_LSHIFT));
        assert_eq!(tables.vsc_to_vk(0xE01D), 0x01A3, "right Ctrl");
        assert_eq!((ch(&tables, b'A', &none), ch(&tables, b'A', &state(&[VK_SHIFT], &[]))), (Some('a'), Some('A')));
        assert_eq!(ch(&tables, b'1', &state(&[VK_SHIFT], &[])), Some('!'));
        assert_eq!(ch(&tables, 0x0D, &none), Some('\r'));
        assert_eq!(ch(&tables, 0x20, &none), Some(' '));
    }
}
