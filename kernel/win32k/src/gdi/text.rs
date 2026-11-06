//! ExtTextOut (GreExtTextOutW de `freetype.c` dans ReactOS, comme
//! spécification) : un texte en glyphes de la police du DC, de sa couleur de
//! texte, placé selon son alignement, sur un fond de sa couleur de fond si son
//! mode de fond est OPAQUE ou si l'appel le demande (ETO_OPAQUE), coupé au
//! rectangle donné (ETO_CLIPPED) et à la région où le DC peint.
//!
//! Les attributs viennent de ceux du DC (`DC_ATTR`, que `gdi32` change :
//! SetTextColor, SetBkColor, SetBkMode, SetTextAlign, SelectObject), lus au
//! moment du dessin, ou de ceux qu'un appel en lot a pris avec lui
//! (GdiBCTextOut).
//!
//! Pas encore : TA_UPDATECP (la position courante), les DC transformés,
//! le texte de droite à gauche (ETO_RTLREADING), ETO_GLYPH_INDEX (des
//! glyphes à la place des caractères), les décalages verticaux d'ETO_PDY,
//! le soulignement et le barré, un fond de mode OPAQUE autre que la cellule.

use alloc::vec::Vec;

use abi::gdi::{eto, ta, OPAQUE};

use super::dc::DcState;
use super::dib::{ColorRef, Rect};
use super::draw::{paint, Op};
use super::fontobj;

/// Les attributs de texte d'un DC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextAttrs {
    /// `hlfntNew` : la police.
    pub font: u32,
    /// `crForegroundClr` : la couleur du texte.
    pub color: ColorRef,
    /// `crBackgroundClr` : celle du fond.
    pub background: ColorRef,
    /// OPAQUE ou TRANSPARENT.
    pub bk_mode: i32,
    /// TA_*.
    pub align: u32,
}

/// Tout le plan : pas de coupure.
const EVERYWHERE: Rect = Rect { left: i32::MIN / 4, top: i32::MIN / 4, right: i32::MAX / 4, bottom: i32::MAX / 4 };

/// Les opérations d'un ExtTextOut de `text` en (`x`, `y`), avec les options
/// `options` (ETO_*) et le rectangle `rect`, les avances `dx` s'il y en a,
/// les attributs `attrs` et la police `logfont` (déjà résolue) : en
/// coordonnées du DC. `None` sans la police installée.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn text_ops(
    (x, y): (i32, i32),
    options: u32,
    rect: Option<Rect>,
    text: &[u16],
    dx: Option<&[i32]>,
    attrs: &TextAttrs,
    logfont: &abi::gdi::LogFontW32,
) -> Option<Vec<Op>> {
    let run = fontobj::text_run(logfont, text)?;
    let metrics = run.metrics;
    // With dx, the advances are the caller's.
    let offsets: Option<Vec<i32>> = dx.map(|dx| {
        let mut sum = 0;
        let mut offsets = Vec::with_capacity(dx.len() + 1);
        for &d in dx {
            offsets.push(sum);
            sum += d;
        }
        offsets.push(sum);
        offsets
    });
    let width = offsets.as_ref().and_then(|o| o.last().copied()).unwrap_or(run.width);
    let left = match attrs.align & ta::HORIZONTAL {
        ta::RIGHT => x - width,
        ta::CENTER => x - width / 2,
        _ => x,
    };
    let baseline = match attrs.align & ta::VERTICAL {
        ta::BASELINE => y,
        ta::BOTTOM => y - metrics.descent,
        _ => y + metrics.ascent,
    };
    let top = baseline - metrics.ascent;
    let clip = rect.filter(|_| options & eto::CLIPPED != 0);
    let mut ops = Vec::new();
    if let (true, Some(rect)) = (options & eto::OPAQUE != 0, rect) {
        ops.push(Op::Fill(rect, attrs.background));
    }
    if attrs.bk_mode == OPAQUE {
        let cell = Rect::new(left, top, left + width, top + metrics.height());
        ops.push(Op::Fill(clip.map_or(cell, |clip| cell.intersect(&clip)), attrs.background));
    }
    for glyph in run.glyphs {
        let pen = offsets.as_ref().and_then(|o| o.get(glyph.index).copied()).unwrap_or(glyph.x);
        let at = (left + pen + glyph.bitmap.left, baseline - glyph.bitmap.top);
        ops.push(Op::Glyph { at, bitmap: glyph.bitmap, color: attrs.color, clip: clip.unwrap_or(EVERYWHERE) });
    }
    Some(ops)
}

/// GreExtTextOutW sur le DC d'état `state`, au processus `pid` : rend vrai
/// si le texte a été dessiné (un texte vide avec ETO_OPAQUE ne fait que
/// remplir son rectangle). Faux sans la police installée.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
#[expect(clippy::too_many_arguments, reason = "what ExtTextOut takes, and the DC")]
pub fn ext_text_out(
    state: &DcState,
    pid: u32,
    at: (i32, i32),
    options: u32,
    rect: Option<Rect>,
    text: &[u16],
    dx: Option<&[i32]>,
    attrs: &TextAttrs,
) -> bool {
    let ops = if text.is_empty() {
        match (options & eto::OPAQUE != 0, rect) {
            (true, Some(rect)) => alloc::vec![Op::Fill(rect, attrs.background)],
            _ => return true,
        }
    } else {
        let logfont = fontobj::get_or_system(attrs.font, pid);
        match text_ops(at, options, rect, text, dx, attrs, &logfont) {
            Some(ops) => ops,
            None => return false,
        }
    };
    let rao = state.rao();
    state.draw(|surface| paint(surface, &ops, state.origin, &rao));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::{Bitmap, PixelLayout};
    use crate::gdi::region::Region;
    use abi::gdi::{LogFontW32, TRANSPARENT};

    const WHITE: ColorRef = ColorRef::rgb(255, 255, 255);
    const NAVY: ColorRef = ColorRef::rgb(0, 0, 128);
    const YELLOW: ColorRef = ColorRef::rgb(255, 255, 0);

    fn gui_font() -> LogFontW32 {
        fontobj::stock_fonts()[6].1
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// `ops` on a white 100 × 40 surface: the colour of each pixel.
    fn render(ops: &[Op]) -> impl Fn(i32, i32) -> ColorRef {
        let mut pixels = alloc::vec![PixelLayout::Rgbx.pixel(WHITE); 100 * 40];
        let mut surface = Bitmap::new(&mut pixels, 100, 40, 100, PixelLayout::Rgbx).unwrap();
        paint(&mut surface, ops, (0, 0), &Region::from_rect(Rect::new(0, 0, 100, 40)));
        move |x, y| PixelLayout::Rgbx.color(pixels[(y * 100 + x) as usize])
    }

    fn count(at: &impl Fn(i32, i32) -> ColorRef, area: Rect, color: ColorRef) -> usize {
        pixels(area).filter(|&(x, y)| at(x, y) == color).count()
    }

    /// The pixels of `area` that the text inked: neither white nor yellow
    /// (a thin stem is rarely covered whole).
    fn ink(at: &impl Fn(i32, i32) -> ColorRef, area: Rect) -> usize {
        pixels(area).filter(|&(x, y)| at(x, y) != WHITE && at(x, y) != YELLOW).count()
    }

    fn pixels(area: Rect) -> impl Iterator<Item = (i32, i32)> {
        (area.top..area.bottom).flat_map(move |y| (area.left..area.right).map(move |x| (x, y)))
    }

    fn attrs(bk_mode: i32, align: u32) -> TextAttrs {
        TextAttrs { font: 0, color: NAVY, background: YELLOW, bk_mode, align }
    }

    #[test]
    fn text_is_placed_by_its_alignment() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let text = units("Mino");
        let ops = text_ops((10, 5), 0, None, &text, None, &attrs(TRANSPARENT, 0), &gui_font()).unwrap();
        let at = render(&ops);
        // TA_TOP: the cell from y = 5, the baseline at 16, capitals from 8.
        assert!(ink(&at, Rect::new(10, 5, 40, 16)) > 10, "the text");
        // Without hinting, a stem of a pixel straddles two columns: dark
        // pixels toward navy, few of them covered whole.
        let dark = pixels(Rect::new(10, 5, 40, 16)).filter(|&(x, y)| at(x, y).components().0 < 128).count();
        assert!(dark > 4, "dark pixels toward navy");
        assert_eq!(ink(&at, Rect::new(0, 0, 100, 7)), 0, "nothing above its capitals");
        // A round letter overshoots its baseline by a fraction of a pixel.
        assert_eq!(ink(&at, Rect::new(0, 17, 100, 40)), 0, "nothing below its baseline");
        assert_eq!(ink(&at, Rect::new(0, 0, 10, 40)), 0, "nothing left of x");
        assert_eq!(count(&at, Rect::new(0, 0, 100, 40), YELLOW), 0, "transparent: no background");
        // TA_BASELINE | TA_RIGHT at (90, 30): the text ends at 90, on 30.
        let ops = text_ops((90, 30), 0, None, &text, None, &attrs(TRANSPARENT, ta::BASELINE | ta::RIGHT), &gui_font());
        let at = render(&ops.unwrap());
        assert_eq!(ink(&at, Rect::new(90, 0, 100, 40)), 0, "nothing right of x");
        assert_eq!(ink(&at, Rect::new(0, 31, 100, 40)), 0, "nothing below the baseline");
        assert!(ink(&at, Rect::new(60, 20, 90, 30)) > 10);
    }

    #[test]
    fn an_opaque_background_fills_the_cell_or_the_rectangle() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let text = units("Mino");
        let (width, _) = fontobj::text_extent(&gui_font(), &text).unwrap();
        let ops = text_ops((10, 5), 0, None, &text, None, &attrs(OPAQUE, 0), &gui_font()).unwrap();
        let at = render(&ops);
        assert_eq!(at(10, 5), YELLOW, "the cell's corner");
        assert_eq!(at(10 + width - 1, 5 + 12), YELLOW, "its other corner");
        assert_eq!((at(10 + width, 5), at(10, 5 + 13), at(9, 5)), (WHITE, WHITE, WHITE), "only the cell");
        // ETO_OPAQUE | ETO_CLIPPED in a rectangle narrower than the text.
        let rect = Rect::new(5, 20, 25, 35);
        let ops = text_ops(
            (7, 22),
            eto::OPAQUE | eto::CLIPPED,
            Some(rect),
            &units("Opaque text"),
            None,
            &attrs(TRANSPARENT, 0),
            &gui_font(),
        );
        let at = render(&ops.unwrap());
        assert_eq!((at(5, 20), at(24, 34)), (YELLOW, YELLOW), "the rectangle filled");
        assert_eq!(ink(&at, Rect::new(25, 0, 100, 40)), 0, "the text cut at its right");
        assert!(ink(&at, rect) > 4, "but drawn inside");
    }

    #[test]
    fn dx_gives_the_advances() {
        if !crate::font::tests::install_reactos_fonts() {
            return;
        }
        let text = units("ii");
        let attrs = attrs(TRANSPARENT, 0);
        let spaced = text_ops((0, 5), 0, None, &text, Some(&[40, 40]), &attrs, &gui_font()).unwrap();
        let at = render(&spaced);
        assert!(ink(&at, Rect::new(38, 0, 50, 40)) > 0, "the second i 40 pixels further");
        assert_eq!(ink(&at, Rect::new(8, 0, 38, 40)), 0, "nothing between");
    }
}
