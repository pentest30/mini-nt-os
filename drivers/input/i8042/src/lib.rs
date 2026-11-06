//! Le clavier PS/2 du contrôleur 8042 (02 §8, `drivers/input/i8042` ;
//! `i8042prt` de ReactOS, `keyboard.c`, comme spécification).
//!
//! L'interruption du clavier (IRQ1, `hal::idt`) lit chaque octet du
//! contrôleur dans un anneau (`hal::ps2`) et prévient qui l'attend
//! (`hal::ps2::set_notify`). Ce pilote vide l'anneau ([`Keyboard::read`]) et
//! fait des octets du jeu de scan codes 1 des KEYBOARD_INPUT_DATA
//! ([`Decoder`], i8042KbdInterruptService) : un préfixe `E0` ou `E1` marque
//! le code qui le suit (`KEY_E0`, `KEY_E1`), le bit 7 d'un code dit une
//! touche relâchée (`KEY_BREAK`).
//!
//! Pas encore : les IRP (kbdclass, `\Device\KeyboardClass0` : win32k lit
//! le pilote directement), les voyants (IOCTL_KEYBOARD_SET_INDICATORS), la
//! souris, la réinitialisation du contrôleur, les touches de la combinaison
//! Ctrl + Alt + Suppr et de SysRq traitées à part.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use abi::kbd::{KeyboardInputData, KEY_BREAK, KEY_E0, KEY_E1};

/// Ce que le décodeur a vu avant l'octet suivant (KEYBOARD_SCAN_STATE).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ScanState {
    #[default]
    Normal,
    GotE0,
    GotE1,
}

/// Le décodeur des octets du clavier.
#[derive(Debug, Default)]
pub struct Decoder {
    state: ScanState,
}

impl Decoder {
    pub const fn new() -> Self {
        Self { state: ScanState::Normal }
    }

    /// L'octet `byte` : la touche qu'il achève, ou rien pour un préfixe.
    pub fn feed(&mut self, byte: u8) -> Option<KeyboardInputData> {
        if self.state == ScanState::Normal {
            match byte {
                0xE0 => {
                    self.state = ScanState::GotE0;
                    return None;
                }
                0xE1 => {
                    self.state = ScanState::GotE1;
                    return None;
                }
                _ => {}
            }
        }
        let mut flags = match self.state {
            ScanState::GotE0 => KEY_E0,
            ScanState::GotE1 => KEY_E1,
            ScanState::Normal => 0,
        };
        self.state = ScanState::Normal;
        if byte & 0x80 != 0 {
            flags |= KEY_BREAK;
        }
        Some(KeyboardInputData { make_code: u16::from(byte & 0x7F), flags, ..KeyboardInputData::default() })
    }
}

/// Le clavier : le décodeur, et l'anneau de `hal::ps2` qu'il vide.
#[derive(Debug, Default)]
pub struct Keyboard {
    decoder: Decoder,
}

impl Keyboard {
    pub const fn new() -> Self {
        Self { decoder: Decoder::new() }
    }

    /// La touche suivante, s'il y en a une dans l'anneau.
    ///
    /// # IRQL
    /// Tout niveau : l'anneau se lit sans verrou.
    pub fn read(&mut self) -> Option<KeyboardInputData> {
        while let Some(byte) = hal::ps2::pop_scancode() {
            if let Some(data) = self.decoder.feed(byte) {
                return Some(data);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> alloc_free::Keys {
        let mut decoder = Decoder::new();
        let mut keys = alloc_free::Keys::default();
        for &byte in bytes {
            if let Some(data) = decoder.feed(byte) {
                keys.push((data.make_code, data.flags));
            }
        }
        keys
    }

    /// A fixed list, without `alloc`.
    mod alloc_free {
        #[derive(Debug, Default, PartialEq, Eq)]
        pub struct Keys {
            pub keys: [(u16, u16); 8],
            pub count: usize,
        }

        impl Keys {
            pub fn push(&mut self, key: (u16, u16)) {
                self.keys[self.count] = key;
                self.count += 1;
            }

            pub fn as_slice(&self) -> &[(u16, u16)] {
                &self.keys[..self.count]
            }
        }
    }

    #[test]
    fn a_key_goes_down_then_up() {
        // A: 1E down, 9E up.
        assert_eq!(decode(&[0x1E, 0x9E]).as_slice(), [(0x1E, 0), (0x1E, KEY_BREAK)]);
    }

    #[test]
    fn a_prefix_marks_the_next_code_only() {
        // Right Ctrl: E0 1D, E0 9D; then A.
        let keys = decode(&[0xE0, 0x1D, 0xE0, 0x9D, 0x1E]);
        assert_eq!(keys.as_slice(), [(0x1D, KEY_E0), (0x1D, KEY_E0 | KEY_BREAK), (0x1E, 0)]);
    }

    #[test]
    fn pause_comes_after_e1() {
        // Pause: E1 1D 45 E1 9D C5, as i8042prt sees it.
        let keys = decode(&[0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5]);
        assert_eq!(keys.as_slice(), [(0x1D, KEY_E1), (0x45, 0), (0x1D, KEY_E1 | KEY_BREAK), (0x45, KEY_BREAK)]);
    }

    #[test]
    fn a_prefix_after_a_prefix_is_a_code() {
        // Only in the normal state is E0 a prefix.
        assert_eq!(decode(&[0xE0, 0xE0]).as_slice(), [(0x60, KEY_E0 | KEY_BREAK)]);
    }
}
