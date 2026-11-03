//! `gopfb` (02 §7.2, §10) : le pilote d'affichage du framebuffer UEFI (GOP),
//! que le chargeur trouve et décrit (`abi::FramebufferInfo`). Son mode est
//! celui que le micrologiciel a choisi, et ne change pas ; ses pixels ont 32
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
use win32k::display::{DisplayDriver, Mode};
use win32k::gdi::dib::{Bitmap, PixelLayout};

/// Le framebuffer UEFI.
pub struct GopFramebuffer {
    /// L'adresse noyau de son premier pixel.
    base: usize,
    width: u32,
    height: u32,
    /// Ses pixels par ligne.
    stride: u32,
    layout: PixelLayout,
}

impl GopFramebuffer {
    /// Le pilote du framebuffer `info`, vu à `hhdm_offset + info.base` ;
    /// `None` sans framebuffer ou pour un format de pixel inconnu.
    ///
    /// # Safety
    /// `stride × height` pixels de 32 bits sont projetés à
    /// `hhdm_offset + info.base` pour toute la vie du système, et seuls ce
    /// pilote et la console de démarrage y écrivent.
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
        Some(Self { base, width: info.width, height: info.height, stride: info.stride, layout })
    }
}

impl DisplayDriver for GopFramebuffer {
    fn mode(&self) -> Mode {
        Mode { width: self.width, height: self.height, layout: self.layout }
    }

    fn with_surface(&self, draw: &mut dyn FnMut(&mut Bitmap<'_>)) {
        let length = self.stride as usize * self.height as usize;
        // SAFETY: `new`'s contract: the framebuffer's pixels are mapped at
        // `base` for good; win32k draws one at a time (`display::draw`), and
        // the boot console no longer writes once it has acquired the screen.
        let pixels = unsafe { core::slice::from_raw_parts_mut(self.base as *mut u32, length) };
        let mut bitmap = Bitmap::new(pixels, self.width, self.height, self.stride, self.layout)
            .expect("the framebuffer holds its rows");
        draw(&mut bitmap);
    }

    fn acquire(&self) {
        hal::fb::set_exclusive(true);
    }
}
