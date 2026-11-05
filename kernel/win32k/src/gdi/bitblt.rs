//! BitBlt (NtGdiBitBlt, NtGdiMaskBlt de `bitblt.c` dans ReactOS, comme
//! spécification) : un rectangle d'un DC reçoit celui d'un autre (ou du
//! même), combiné à ce qu'il a et au pinceau du DC par un ROP3.
//!
//! La destination est coupée là où son DC peint ; la source est lue dans la
//! surface de son DC (l'écran ou son bitmap), sans sa région : ce qui tombe
//! hors d'elle n'est pas écrit (IntEngBitBlt). Une étendue négative retourne
//! le rectangle de la destination et recule le point de la source d'autant :
//! BitBlt ne retourne pas l'image. Un ROP sans source est un PatBlt.
//!
//! Deux surfaces : les bitmaps se prennent avant l'écran, et deux bitmaps
//! dans l'ordre de leurs adresses ; une même surface copie en place
//! ([`Bitmap::blt_within`]).
//!
//! Pas encore : StretchBlt (CAPTUREBLT y mène dans ReactOS : sans fenêtres
//! superposées, c'est le même BitBlt), MaskBlt avec un masque, les DC
//! transformés, les motifs autres que pleins, le défilement de l'écran à
//! travers plusieurs rectangles de la région (chacun copie en place, l'un
//! après l'autre).

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::gdi::rop::{CAPTUREBLT, NOMIRRORBITMAP};

use super::dc::{self, DcState};
use super::dib::{Bitmap, ColorRef, Rect};
use super::surface::Surface;

/// Une étape de BitBlt : un rectangle de la destination, sur sa surface, et
/// le pixel de la source qui répond à son coin.
pub type Part = (Rect, (i32, i32));

/// ROP3 qui se sert du motif (ROP4_USES_PATTERN) : le résultat dépend de
/// P.
pub const fn uses_pattern(rop: u32) -> bool {
    let rop3 = (rop >> 16) & 0xFF;
    (rop3 >> 4) & 0x0F != rop3 & 0x0F
}

/// NtGdiMaskBlt, sans masque : la destination (`x`, `y`, `width`,
/// `height`) depuis l'origine `origin` de son DC, sur sa surface et bien
/// ordonnée, et le point de la source (`x_src`, `y_src`), depuis l'origine
/// `src_origin` du sien, qui répond à son coin.
pub fn geometry(
    (x, y, width, height): (i32, i32, i32, i32),
    origin: (i32, i32),
    (x_src, y_src): (i32, i32),
    src_origin: (i32, i32),
) -> (Rect, (i32, i32)) {
    let left = x.saturating_add(origin.0);
    let top = y.saturating_add(origin.1);
    let (right, bottom) = (left.saturating_add(width), top.saturating_add(height));
    let mut from = (x_src.saturating_add(src_origin.0), y_src.saturating_add(src_origin.1));
    // A negative extent does not flip: the source point moves back with it.
    if width < 0 {
        from.0 = from.0.saturating_add(width);
    }
    if height < 0 {
        from.1 = from.1.saturating_add(height);
    }
    let rect = Rect::new(left.min(right), top.min(bottom), left.max(right), top.max(bottom));
    (rect, from)
}

/// Les étapes de BitBlt de `rect` (de source `from`) dans les rectangles
/// `clip` où peint la destination.
pub fn parts(rect: Rect, from: (i32, i32), clip: &[Rect]) -> Vec<Part> {
    clip.iter()
        .map(|visible| visible.intersect(&rect))
        .filter(|part| !part.is_empty())
        .map(|part| (part, (from.0 + part.left - rect.left, from.1 + part.top - rect.top)))
        .collect()
}

/// La surface d'un DC.
#[derive(Clone)]
enum Target {
    Display,
    Bitmap(Arc<Surface>),
}

impl Target {
    fn of(state: &DcState) -> Self {
        match &state.bitmap {
            None => Self::Display,
            Some(selected) => Self::Bitmap(selected.surface.clone()),
        }
    }
}

/// Fait les étapes `parts` de `source` vers `dest` par `rop3` avec le motif
/// `pattern`, les verrous pris dans l'ordre (voir le module).
fn blit(source: &Target, dest: &Target, parts: &[Part], rop3: u8, pattern: ColorRef) {
    let between = |dest: &mut Bitmap<'_>, source: &Bitmap<'_>| {
        for &(rect, from) in parts {
            dest.blt_from(rect, source, from, rop3, pattern);
        }
    };
    let within = |surface: &mut Bitmap<'_>| {
        for &(rect, from) in parts {
            surface.blt_within(rect, from, rop3, pattern);
        }
    };
    match (source, dest) {
        (Target::Display, Target::Display) => {
            crate::display::draw(within);
        }
        (Target::Bitmap(a), Target::Bitmap(b)) if Arc::ptr_eq(a, b) => {
            a.draw(within);
        }
        (Target::Bitmap(a), Target::Display) => {
            a.draw(|source| {
                crate::display::draw(|dest| between(dest, source));
            });
        }
        (Target::Display, Target::Bitmap(b)) => {
            b.draw(|dest| {
                crate::display::draw(|source| between(dest, source));
            });
        }
        (Target::Bitmap(a), Target::Bitmap(b)) => {
            if Arc::as_ptr(a) < Arc::as_ptr(b) {
                a.draw(|source| {
                    b.draw(|dest| between(dest, source));
                });
            } else {
                b.draw(|dest| {
                    a.draw(|source| between(dest, source));
                });
            }
        }
    }
}

/// NtGdiBitBlt : le rectangle (`x`, `y`, `width`, `height`) du DC `hdc`
/// reçoit celui du DC `hdc_src` à partir de (`x_src`, `y_src`), par le ROP
/// `rop`, avec le pinceau du DC s'il s'en sert. Un ROP sans source est un
/// PatBlt (sa source est ignorée). `Ok(false)` pour un DC qui n'est pas au
/// processus (comme ReactOS, sans erreur), ou sans pinceau quand il en
/// faut ; `Err` : l'erreur de Win32 de PatBlt.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn bit_blt(
    hdc: u32,
    (x, y, width, height): (i32, i32, i32, i32),
    hdc_src: u32,
    (x_src, y_src): (i32, i32),
    rop: u32,
) -> Result<bool, u32> {
    let rop = rop & !(NOMIRRORBITMAP | CAPTUREBLT);
    if !dc::uses_source(rop) {
        return dc::pat_blt(hdc, x, y, width, height, rop);
    }
    let (Some(dest), Some(source)) = (dc::lock(hdc), dc::lock(hdc_src)) else { return Ok(false) };
    let pattern = if uses_pattern(rop) {
        let Some((_, attr)) = dest.state().owner else { return Ok(false) };
        match dc::fill_brush(&dest, attr, None, false) {
            Ok(Some(brush)) if !brush.null => brush.color,
            _ => return Ok(false),
        }
    } else {
        ColorRef(0)
    };
    let (dest_state, source_state) = (dest.state(), source.state());
    let (rect, from) = geometry((x, y, width, height), dest_state.origin, (x_src, y_src), source_state.origin);
    let parts = parts(rect, from, dest_state.rao().rects());
    blit(&Target::of(&source_state), &Target::of(&dest_state), &parts, (rop >> 16) as u8, pattern);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::gdi::rop;

    #[test]
    fn which_rops_use_the_pattern() {
        assert!(uses_pattern(rop::PATCOPY) && uses_pattern(rop::PATINVERT));
        assert!(!uses_pattern(rop::SRCCOPY) && !uses_pattern(rop::DSTINVERT) && !uses_pattern(rop::BLACKNESS));
        assert!(uses_pattern(0x00C0_00CA), "MERGECOPY");
        assert!(!uses_pattern(0x0066_0046), "SRCINVERT");
    }

    #[test]
    fn the_destination_moves_with_its_origin_and_the_source_with_its_own() {
        let (rect, from) = geometry((10, 20, 30, 40), (100, 200), (1, 2), (5, 6));
        assert_eq!((rect, from), (Rect::new(110, 220, 140, 260), (6, 8)));
    }

    #[test]
    fn a_negative_extent_moves_the_source_back_without_flipping() {
        let (rect, from) = geometry((10, 20, -4, -6), (0, 0), (50, 60), (0, 0));
        assert_eq!(rect, Rect::new(6, 14, 10, 20), "well ordered");
        assert_eq!(from, (46, 54), "the source's corner moves back by the extents");
    }

    #[test]
    fn each_visible_rectangle_takes_its_part_of_the_source() {
        let clip = [Rect::new(0, 0, 15, 100), Rect::new(20, 0, 100, 12), Rect::new(200, 200, 300, 300)];
        let parts = parts(Rect::new(10, 10, 30, 30), (100, 200), &clip);
        assert_eq!(parts, [(Rect::new(10, 10, 15, 30), (100, 200)), (Rect::new(20, 10, 30, 12), (110, 200))]);
    }
}
