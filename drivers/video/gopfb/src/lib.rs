//! `gopfb` (02 §7.2, §10) : le pilote d'affichage du framebuffer UEFI (GOP),
//! que le chargeur trouve et décrit (`abi::FramebufferInfo`). Son mode de
//! départ est celui que le micrologiciel a choisi ; l'interface Bochs DISPI
//! du VGA le change ensuite à chaud ([`DisplayDriver::set_mode`]), la base
//! physique du framebuffer linéaire restant la même. Ses pixels ont 32
//! bits, dans l'ordre que GOP annonce.
//!
//! Il implémente le pilote d'affichage de win32k
//! (`win32k::display::DisplayDriver`) : sa surface est le framebuffer, où le
//! moteur DIB dessine directement. Quand win32k prend l'écran, la console de
//! démarrage (`hal::fb`) cesse d'y écrire ; elle reprend l'écran pour un écran
//! d'arrêt (STOP).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use abi::{FramebufferInfo, PixelFormat};
use hal::sync::KSpinLock;
use win32k::display::{DisplayDriver, Mode};
use win32k::gdi::dib::{Bitmap, PixelLayout};

/// Le framebuffer UEFI.
pub struct GopFramebuffer {
    /// L'adresse noyau de son premier pixel.
    base: usize,
    layout: PixelLayout,
    /// Les dimensions courantes et le pas, sous verrou : le changement de
    /// mode les réécrit, les dessins les lisent — un à la fois (le verrou de
    /// `win32k::display` tient les deux passages).
    mode: KSpinLock<ModeState>,
}

/// Les dimensions et le pas courants.
struct ModeState {
    width: u32,
    height: u32,
    stride: u32,
}

impl GopFramebuffer {
    /// Le pilote du framebuffer `info`, vu à `hhdm_offset + info.base` ;
    /// `None` sans framebuffer ou pour un format de pixel inconnu.
    ///
    /// # Safety
    /// L'espace physique du framebuffer (qui peut grandir à un changement de
    /// mode) est projeté à `hhdm_offset + info.base` pour toute la vie du
    /// système, et seuls ce pilote et la console de démarrage y écrivent.
    pub unsafe fn new(info: &FramebufferInfo, hhdm_offset: u64) -> Option<Self> {
        if !info.is_valid() || info.stride < info.width {
            return None;
        }
        let layout = match info.format {
            PixelFormat::Bgr => PixelLayout::Bgrx,
            PixelFormat::Rgb => PixelLayout::Rgbx,
            PixelFormat::Unknown => return None,
        };
        let base = usize::try_from(hhdm_offset.checked_add(info.base)?).ok()?;
        let mode = KSpinLock::new(ModeState { width: info.width, height: info.height, stride: info.stride });
        Some(Self { base, layout, mode })
    }
}

impl DisplayDriver for GopFramebuffer {
    fn mode(&self) -> Mode {
        let state = self.mode.lock();
        Mode { width: state.width, height: state.height, layout: self.layout }
    }

    fn with_surface(&self, draw: &mut dyn FnMut(&mut Bitmap<'_>)) {
        let state = self.mode.lock();
        let length = state.stride as usize * state.height as usize;
        // SAFETY: `new`'s contract: the framebuffer's pixels are mapped at
        // `base` for good, past the largest mode DISPI may set; win32k draws
        // one at a time (`display::draw`), and the boot console no longer
        // writes once it has acquired the screen.
        let pixels = unsafe { core::slice::from_raw_parts_mut(self.base as *mut u32, length) };
        let mut bitmap = Bitmap::new(pixels, state.width, state.height, state.stride, self.layout)
            .expect("the framebuffer holds its rows");
        draw(&mut bitmap);
    }

    fn acquire(&self) {
        hal::fb::set_exclusive(true);
    }

    fn set_mode(&self, width: u32, height: u32) -> bool {
        let (Some(width), Some(height)) = (u16::try_from(width).ok(), u16::try_from(height).ok()) else {
            return false;
        };
        let Some((read_width, read_height, stride)) = hal::bochs::set_mode(width, height) else {
            return false;
        };
        *self.mode.lock() = ModeState { width: read_width, height: read_height, stride };
        true
    }
}
