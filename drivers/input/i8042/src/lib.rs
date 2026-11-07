//! Le clavier et la souris PS/2 du contrôleur 8042 (02 §8,
//! `drivers/input/i8042` ; `i8042prt` de ReactOS, `keyboard.c` et `mouse.c`,
//! comme spécification).
//!
//! L'interruption du clavier (IRQ1, `hal::idt`) lit chaque octet du
//! contrôleur dans un anneau (`hal::ps2`) et prévient qui l'attend
//! (`hal::ps2::set_notify`). Ce pilote vide l'anneau ([`Keyboard::read`]) et
//! fait des octets du jeu de scan codes 1 des KEYBOARD_INPUT_DATA
//! ([`Decoder`], i8042KbdInterruptService) : un préfixe `E0` ou `E1` marque
//! le code qui le suit (`KEY_E0`, `KEY_E1`), le bit 7 d'un code dit une
//! touche relâchée (`KEY_BREAK`). La souris a son anneau (IRQ12) : ses
//! paquets de 3 octets, 4 avec la molette, deviennent des MOUSE_INPUT_DATA
//! ([`MouseDecoder`], [`Mouse::read`]).
//!
//! Pas encore : les IRP (kbdclass et mouclass, `\Device\KeyboardClass0` :
//! win32k lit le pilote directement), les voyants
//! (IOCTL_KEYBOARD_SET_INDICATORS), les boutons 4 et 5, la réinitialisation
//! du contrôleur, les touches de la combinaison Ctrl + Alt + Suppr et de
//! SysRq traitées à part.

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

/// Le décodeur des paquets de la souris PS/2 (i8042MouseInterruptService ;
/// le protocole d'IntelliMouse pour le quatrième octet) : un paquet de 3
/// octets — les boutons, les signes et les débordements, puis X, puis Y —,
/// de 4 avec la molette (son mouvement, signé sur 4 bits). Le premier octet
/// d'un paquet a toujours son bit 3 : un octet sans lui à cette place est
/// jeté (le décodeur se recale sur le paquet suivant).
#[derive(Debug)]
pub struct MouseDecoder {
    size: usize,
    packet: [u8; 4],
    filled: usize,
    /// Les boutons enfoncés au dernier paquet (bits 0 à 2 : gauche, droit,
    /// milieu).
    buttons: u8,
}

impl MouseDecoder {
    /// Des paquets de `size` octets (3, ou 4 avec une molette).
    pub const fn new(size: usize) -> Self {
        Self { size: if size == 4 { 4 } else { 3 }, packet: [0; 4], filled: 0, buttons: 0 }
    }

    /// L'octet `byte` : le mouvement qu'il achève, ou rien.
    pub fn feed(&mut self, byte: u8) -> Option<abi::mou::MouseInputData> {
        use abi::mou::*;
        if self.filled == 0 && byte & 0x08 == 0 {
            return None;
        }
        self.packet[self.filled] = byte;
        self.filled += 1;
        if self.filled < self.size {
            return None;
        }
        self.filled = 0;
        let [head, x, y, z] = self.packet;
        // Neuf bits signés ; un débordement rend le mouvement inutilisable.
        let axis = |value: u8, sign: bool, overflow: bool| -> i32 {
            match (overflow, sign) {
                (true, _) => 0,
                (false, true) => i32::from(value) - 256,
                (false, false) => i32::from(value),
            }
        };
        let dx = axis(x, head & 0x10 != 0, head & 0x40 != 0);
        let dy = -axis(y, head & 0x20 != 0, head & 0x80 != 0);
        let buttons = head & 0x07;
        let changed = buttons ^ self.buttons;
        self.buttons = buttons;
        let mut flags = 0;
        for (bit, down, up) in [
            (1, MOUSE_LEFT_BUTTON_DOWN, MOUSE_LEFT_BUTTON_UP),
            (2, MOUSE_RIGHT_BUTTON_DOWN, MOUSE_RIGHT_BUTTON_UP),
            (4, MOUSE_MIDDLE_BUTTON_DOWN, MOUSE_MIDDLE_BUTTON_UP),
        ] {
            if changed & bit != 0 {
                flags |= if buttons & bit != 0 { down } else { up };
            }
        }
        let mut data = MouseInputData {
            flags: MOUSE_MOVE_RELATIVE,
            button_flags: flags,
            raw_buttons: u32::from(buttons),
            last_x: dx,
            last_y: dy,
            ..MouseInputData::default()
        };
        if self.size == 4 {
            // 4 bits signés, positifs vers l'utilisateur ; WHEEL_DELTA par
            // cran, positif loin de l'utilisateur.
            let notches = i16::from(((z & 0x0F) << 4) as i8 >> 4);
            if notches != 0 {
                data.button_flags |= MOUSE_WHEEL;
                data.button_data = (-notches * WHEEL_DELTA) as u16;
            }
        }
        Some(data)
    }
}

/// La souris : le décodeur, et l'anneau de `hal::ps2` qu'il vide.
#[derive(Debug)]
pub struct Mouse {
    decoder: MouseDecoder,
}

impl Mouse {
    /// La souris du port auxiliaire, s'il y en a une (`hal::ps2`).
    pub fn new() -> Option<Self> {
        hal::ps2::mouse_packet_size().map(|size| Self { decoder: MouseDecoder::new(size) })
    }

    /// Le mouvement suivant, s'il y en a un dans l'anneau.
    ///
    /// # IRQL
    /// Tout niveau : l'anneau se lit sans verrou.
    pub fn read(&mut self) -> Option<abi::mou::MouseInputData> {
        while let Some(byte) = hal::ps2::pop_mouse() {
            if let Some(data) = self.decoder.feed(byte) {
                return Some(data);
            }
        }
        None
    }
}

#[cfg(test)]
mod mouse_tests {
    use super::*;
    use abi::mou::*;

    fn feed(decoder: &mut MouseDecoder, bytes: &[u8]) -> Option<MouseInputData> {
        let mut last = None;
        for &byte in bytes {
            if let Some(data) = decoder.feed(byte) {
                last = Some(data);
            }
        }
        last
    }

    #[test]
    fn a_move_right_and_up() {
        // QEMU's `mouse_move 12 -7`: X +12, Y up 7 (PS/2 Y is positive up).
        let data = feed(&mut MouseDecoder::new(3), &[0x08, 12, 7]).unwrap();
        assert_eq!((data.last_x, data.last_y, data.button_flags), (12, -7, 0));
    }

    #[test]
    fn negative_moves_use_the_sign_bits() {
        // X -3 (sign bit 4), Y down 5 (sign bit 5, 0xFB).
        let data = feed(&mut MouseDecoder::new(3), &[0x38, 0xFD, 0xFB]).unwrap();
        assert_eq!((data.last_x, data.last_y), (-3, 5));
    }

    #[test]
    fn an_overflow_drops_that_axis() {
        let data = feed(&mut MouseDecoder::new(3), &[0x48, 0xFF, 2]).unwrap();
        assert_eq!((data.last_x, data.last_y), (0, -2));
    }

    #[test]
    fn buttons_go_down_then_up() {
        let mut decoder = MouseDecoder::new(3);
        let down = feed(&mut decoder, &[0x09, 0, 0]).unwrap();
        assert_eq!(down.button_flags, MOUSE_LEFT_BUTTON_DOWN);
        let both = feed(&mut decoder, &[0x0B, 0, 0]).unwrap();
        assert_eq!(both.button_flags, MOUSE_RIGHT_BUTTON_DOWN, "only the change");
        let up = feed(&mut decoder, &[0x08, 0, 0]).unwrap();
        assert_eq!(up.button_flags, MOUSE_LEFT_BUTTON_UP | MOUSE_RIGHT_BUTTON_UP);
        let middle = feed(&mut decoder, &[0x0C, 0, 0]).unwrap();
        assert_eq!(middle.button_flags, MOUSE_MIDDLE_BUTTON_DOWN);
    }

    #[test]
    fn a_byte_without_bit_3_first_is_skipped() {
        // A stray byte, then a whole packet: the decoder finds its start.
        let data = feed(&mut MouseDecoder::new(3), &[0x05, 0x08, 4, 0]).unwrap();
        assert_eq!((data.last_x, data.last_y), (4, 0));
    }

    #[test]
    fn the_wheel_comes_in_the_fourth_byte() {
        let mut decoder = MouseDecoder::new(4);
        // One notch toward the user (z = +1): WHEEL_DELTA down, negative.
        let down = feed(&mut decoder, &[0x08, 0, 0, 0x01]).unwrap();
        assert_eq!((down.button_flags, down.button_data as i16), (MOUSE_WHEEL, -WHEEL_DELTA));
        // Two notches away (z = -2, 0x0E).
        let up = feed(&mut decoder, &[0x08, 0, 0, 0x0E]).unwrap();
        assert_eq!((up.button_flags, up.button_data as i16), (MOUSE_WHEEL, 2 * WHEEL_DELTA));
        // No wheel: no MOUSE_WHEEL.
        let still = feed(&mut decoder, &[0x08, 1, 0, 0]).unwrap();
        assert_eq!(still.button_flags, 0);
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
