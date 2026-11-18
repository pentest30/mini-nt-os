//! `bochs-dispi` (02 §7.2, §10) : le pilote d'affichage de l'interface Bochs
//! DISPI (`hal::bochs`), celle du VGA standard de QEMU (PCI 1234:1111) et du
//! VBoxVGA de VirtualBox (80EE:BEEF). Son framebuffer linéaire est la barre 0
//! du contrôleur, vue par la projection directe du noyau (HHDM) ; ses pixels
//! ont 32 bits (B, G, R, puis un octet inutilisé).
//!
//! Il part du mode que le micrologiciel a posé (celui du GOP) et sait en
//! changer à chaud ([`DisplayDriver::set_mode`]) : ses modes sont des
//! résolutions courantes ([`STANDARD`]) que le contrôleur tient — dans ses
//! limites (GETCAPS) et sa mémoire vidéo, à 32 bits par pixel — plus celle
//! du départ ([`mode_list`]). Comme le miniport `vbemp` de ReactOS, il
//! n'annonce qu'une fréquence (celle que `win32k` donne).
//!
//! Il implémente le pilote d'affichage de win32k
//! (`win32k::display::DisplayDriver`) : sa surface est le framebuffer, où le
//! moteur DIB dessine directement. Quand win32k prend l'écran, la console de
//! démarrage (`hal::fb`) cesse d'y écrire ; elle reprend l'écran pour un écran
//! d'arrêt (STOP), aux dimensions du dernier mode ([`hal::fb::set_geometry`]).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;

use hal::sync::KSpinLock;
use win32k::display::{DisplayDriver, Mode};
use win32k::gdi::dib::{Bitmap, PixelLayout};

/// Les contrôleurs à l'interface DISPI : fabricant, modèle PCI, description,
/// identifiant matériel.
const ADAPTERS: [(u16, u16, &str, &str); 2] = [
    (0x1234, 0x1111, "QEMU standard VGA (Bochs DISPI)", "PCI\\VEN_1234&DEV_1111"),
    (0x80EE, 0xBEEF, "VirtualBox VBoxVGA (Bochs DISPI)", "PCI\\VEN_80EE&DEV_BEEF"),
];

/// Les résolutions courantes (4:3, 5:4, 16:10, 16:9), en ordre croissant de
/// largeur puis de hauteur. Leurs largeurs sont des multiples de 8, ce que
/// l'interface exige (QEMU arrondit sinon : 1366 deviendrait 1360).
pub const STANDARD: [(u32, u32); 19] = [
    (640, 480),
    (800, 600),
    (1024, 768),
    (1152, 864),
    (1280, 720),
    (1280, 768),
    (1280, 800),
    (1280, 960),
    (1280, 1024),
    (1360, 768),
    (1400, 1050),
    (1440, 900),
    (1600, 900),
    (1600, 1200),
    (1680, 1050),
    (1920, 1080),
    (1920, 1200),
    (2560, 1440),
    (2560, 1600),
];

/// Les octets d'un pixel.
const BYTES_PER_PIXEL: usize = 4;

/// Les modes d'un contrôleur dont les plus grandes dimensions sont `max`, à
/// `memory` octets de mémoire vidéo, parti du mode `current` : les
/// résolutions [`STANDARD`] qui y tiennent, plus `current`, du plus petit au
/// plus grand (largeur, puis hauteur).
pub fn mode_list(max: (u32, u32), memory: usize, current: (u32, u32)) -> Vec<(u32, u32)> {
    let fits = |&(width, height): &(u32, u32)| {
        width <= max.0 && height <= max.1 && width as usize * height as usize * BYTES_PER_PIXEL <= memory
    };
    let mut modes: Vec<(u32, u32)> = STANDARD.iter().copied().filter(fits).collect();
    if !modes.contains(&current) {
        modes.push(current);
        modes.sort_unstable();
    }
    modes
}

/// Le pilote : le framebuffer, sa mémoire, ses modes, et le mode courant.
pub struct BochsDispi {
    /// L'adresse noyau du premier pixel du framebuffer.
    base: usize,
    /// La mémoire vidéo, en octets : aucun mode ne la dépasse.
    memory: usize,
    description: &'static str,
    hardware_id: &'static str,
    /// Les modes qu'il annonce ([`mode_list`]).
    modes: Vec<(u32, u32)>,
    /// Le mode courant, sous verrou : le changement de mode le réécrit, les
    /// dessins le lisent — un à la fois (le verrou de `win32k::display` tient
    /// les deux passages).
    state: KSpinLock<State>,
}

/// Les dimensions et le pas (en pixels) du mode courant.
#[derive(Clone, Copy)]
struct State {
    width: u32,
    height: u32,
    stride: u32,
}

impl BochsDispi {
    /// Le pilote du contrôleur DISPI de la machine, son framebuffer vu à
    /// `hhdm_offset` plus sa base physique ; `None` sans contrôleur connu,
    /// sans interface, si le micrologiciel n'a pas laissé un mode linéaire
    /// à 32 bits par pixel, ou si le framebuffer n'est pas sous 4 Gio.
    ///
    /// # Safety
    /// La projection directe couvre [0, 4 Gio) pour toute la vie du système,
    /// et seuls ce pilote et la console de démarrage écrivent dans le
    /// framebuffer.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, au démarrage (l'espace de configuration PCI).
    pub unsafe fn probe(hhdm_offset: u64) -> Option<Self> {
        let (function, description, hardware_id) = ADAPTERS
            .iter()
            .find_map(|&(vendor, device, text, id)| hal::pci::find(vendor, device).map(|f| (f, text, id)))?;
        let physical = hal::pci::memory_bar(function, 0)?;
        let current = hal::bochs::current()?;
        if !current.linear || current.bits_per_pixel != 32 || current.width == 0 || current.height == 0 {
            return None;
        }
        let stride = current.stride.max(current.width);
        let in_use = stride as usize * current.height as usize * BYTES_PER_PIXEL;
        // VirtualBox does not tell its memory by this register: only the
        // modes that fit where the firmware's does are offered then.
        let memory = hal::bochs::video_memory().filter(|&memory| memory >= in_use).unwrap_or(in_use);
        if physical.checked_add(memory as u64)? > 1 << 32 {
            return None;
        }
        let max = hal::bochs::capabilities().map_or((current.width, current.height), |(w, h, _)| (w, h));
        let base = usize::try_from(hhdm_offset.checked_add(physical)?).ok()?;
        Some(Self {
            base,
            memory,
            description,
            hardware_id,
            modes: mode_list(max, memory, (current.width, current.height)),
            state: KSpinLock::new(State { width: current.width, height: current.height, stride }),
        })
    }

    /// La mémoire vidéo du contrôleur, en octets.
    pub fn memory(&self) -> usize {
        self.memory
    }
}

impl DisplayDriver for BochsDispi {
    fn mode(&self) -> Mode {
        let state = *self.state.lock();
        Mode { width: state.width, height: state.height, layout: PixelLayout::Bgrx }
    }

    fn modes(&self) -> Vec<Mode> {
        self.modes.iter().map(|&(width, height)| Mode { width, height, layout: PixelLayout::Bgrx }).collect()
    }

    fn description(&self) -> &str {
        self.description
    }

    fn hardware_id(&self) -> &str {
        self.hardware_id
    }

    fn with_surface(&self, draw: &mut dyn FnMut(&mut Bitmap<'_>)) {
        let state = *self.state.lock();
        let length = state.stride as usize * state.height as usize;
        debug_assert!(length * BYTES_PER_PIXEL <= self.memory, "a mode within the video memory");
        // SAFETY: `probe`'s contract: the framebuffer's `memory` bytes are
        // mapped at `base` for good, and no mode goes past them (`set_mode`
        // keeps only those); win32k draws one at a time (`display::draw`),
        // and the boot console no longer writes once it has acquired the
        // screen.
        let pixels = unsafe { core::slice::from_raw_parts_mut(self.base as *mut u32, length) };
        let mut bitmap = Bitmap::new(pixels, state.width, state.height, state.stride, PixelLayout::Bgrx)
            .expect("the framebuffer holds its rows");
        draw(&mut bitmap);
    }

    fn acquire(&self) {
        hal::fb::set_exclusive(true);
    }

    fn set_mode(&self, width: u32, height: u32) -> bool {
        if !self.modes.contains(&(width, height)) {
            return false;
        }
        let (Ok(width16), Ok(height16)) = (u16::try_from(width), u16::try_from(height)) else { return false };
        let mut state = self.state.lock();
        let Some((read_width, read_height, stride)) = hal::bochs::set_mode(width16, height16) else { return false };
        let stride = stride.max(read_width);
        if stride as usize * read_height as usize * BYTES_PER_PIXEL > self.memory {
            // What the hardware kept does not fit what we may write: back to
            // the mode we had.
            let _ = hal::bochs::set_mode(state.width as u16, state.height as u16);
            return false;
        }
        *state = State { width: read_width, height: read_height, stride };
        if hal::fb::fb_ptr_addr() == self.base as u64 {
            hal::fb::set_geometry(read_width, read_height, stride);
        }
        (read_width, read_height) == (width, height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_standard_resolutions_are_sorted_and_eight_aligned() {
        assert!(STANDARD.windows(2).all(|pair| pair[0] < pair[1]), "by width, then height");
        assert!(STANDARD.iter().all(|&(width, _)| width % 8 == 0), "DISPI rounds widths down to 8");
    }

    #[test]
    fn modes_fit_the_limits_and_the_memory() {
        // QEMU's standard VGA: 16 MiB, limits far beyond.
        let qemu = mode_list((16000, 12000), 16 << 20, (1280, 800));
        assert_eq!(qemu.first(), Some(&(640, 480)));
        assert_eq!(qemu.last(), Some(&(2560, 1600)), "2560 × 1600 × 4 fits 16 MiB");
        assert_eq!(qemu.len(), STANDARD.len());
        // 8 MiB and a 1600-pixel limit.
        let small = mode_list((1600, 1200), 8 << 20, (1024, 768));
        assert_eq!(small.last(), Some(&(1600, 1200)), "7.3 MiB");
        assert!(!small.contains(&(1680, 1050)), "beyond the width limit");
        // The firmware's mode only (what VirtualBox gives).
        let fixed = mode_list((1024, 768), 1024 * 768 * 4, (1024, 768));
        assert_eq!(fixed, [(640, 480), (800, 600), (1024, 768)]);
    }

    #[test]
    fn the_firmware_mode_is_always_listed() {
        let modes = mode_list((2000, 2000), 32 << 20, (1288, 720));
        let at = modes.iter().position(|&mode| mode == (1288, 720)).expect("listed");
        assert_eq!(modes[at - 1], (1280, 1024), "in its place");
        assert_eq!(modes[at + 1], (1360, 768));
    }
}
