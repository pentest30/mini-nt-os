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
//! ([`Bitmap::blt_within`]), un rectangle de la région après l'autre dans
//! le sens du décalage ([`overlap_order`]) : aucun n'écrase la source d'un
//! suivant (ScrollDC, ScrollWindowEx sur une région découpée par des
//! fenêtres filles).
//!
//! StretchBlt ([`stretch_blt`]) : aux mêmes tailles, BitBlt ; sinon chaque
//! pixel de la destination prend celui de la source qui lui répond, le plus
//! proche (STRETCH_DELETESCANS, comme StretchDIBits), la source lue d'abord
//! dans un tampon ([`read_area`]) : une même surface ne s'écrase pas.
//!
//! Pas encore : MaskBlt avec un masque, les DC transformés, les motifs
//! autres que pleins, StretchBlt d'une étendue négative (l'image retournée).
//! CAPTUREBLT est ignoré : sans fenêtres superposées, c'est le même BitBlt.

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::gdi::rop::{CAPTUREBLT, NOMIRRORBITMAP};

use core::sync::atomic::{AtomicBool, Ordering};

use abi::winerror::ERROR_CALL_NOT_IMPLEMENTED;

use super::dc::{self, DcState};
use super::dib::{Bitmap, ColorRef, PixelLayout, Rect, SRCCOPY};
use super::dibits::source_of;
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

/// Les étapes `parts` d'une copie dans une même surface, dans l'ordre où
/// aucune n'écrase la source d'une suivante : les bandes de la région
/// (rectangles de même haut) en partant du côté où va le décalage, et dans
/// une bande, les rectangles aussi. La source d'un rectangle est du côté
/// opposé au décalage : déjà lue quand on y écrit.
pub fn overlap_order(parts: &[Part]) -> Vec<Part> {
    let mut parts = parts.to_vec();
    let Some(&(rect, from)) = parts.first() else { return parts };
    let (dx, dy) = (rect.left - from.0, rect.top - from.1);
    parts.sort_by(|a, b| {
        let by_y = if dy > 0 { b.0.top.cmp(&a.0.top) } else { a.0.top.cmp(&b.0.top) };
        let by_x = if dx > 0 { b.0.left.cmp(&a.0.left) } else { a.0.left.cmp(&b.0.left) };
        by_y.then(by_x)
    });
    parts
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
        for (rect, from) in overlap_order(parts) {
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
    let (rect, from) = geometry(
        (x, y, width, height),
        dc::logical_origin(&dest_state, None),
        (x_src, y_src),
        dc::logical_origin(&source_state, None),
    );
    let parts = parts(rect, from, dest_state.rao().rects());
    blit(&Target::of(&source_state), &Target::of(&dest_state), &parts, (rop >> 16) as u8, pattern);
    Ok(true)
}

/// Les pixels de `area` sur la surface `target`, ligne par ligne (0 hors
/// d'elle), et l'ordre de leurs octets ; `None` pour un bitmap sans pixels.
fn read_area(target: &Target, area: Rect) -> Option<(Vec<u32>, PixelLayout)> {
    let mut read = None;
    let mut copy = |surface: &mut Bitmap<'_>| {
        let mut pixels = Vec::with_capacity(((area.right - area.left) * (area.bottom - area.top)) as usize);
        for y in area.top..area.bottom {
            for x in area.left..area.right {
                let inside = x >= 0 && y >= 0;
                pixels.push(if inside { surface.pixel(x as u32, y as u32).unwrap_or(0) } else { 0 });
            }
        }
        read = Some((pixels, surface.layout()));
    };
    match target {
        Target::Display => {
            crate::display::draw(&mut copy);
        }
        Target::Bitmap(surface) => {
            surface.draw(&mut copy);
        }
    }
    read
}

/// Une source de StretchBlt lue : ses pixels (`width` × `height`, la ligne du
/// haut d'abord) et l'ordre de leurs octets.
pub struct Stretched<'a> {
    pub pixels: &'a [u32],
    pub width: i32,
    pub height: i32,
    pub layout: PixelLayout,
}

/// La partie `part` du rectangle `rect` de `dest` reçoit `source`, étirée ou
/// réduite à `rect` (le pixel le plus proche), par le ROP3 `rop3` avec le
/// motif plein `pattern`. SRCCOPY garde l'octet haut d'une source du même
/// ordre d'octets, comme BitBlt.
pub fn stretch_part(
    dest: &mut Bitmap<'_>,
    part: Rect,
    rect: Rect,
    source: &Stretched<'_>,
    rop3: u8,
    pattern: ColorRef,
) {
    let part = part.intersect(&rect).intersect(&dest.bounds());
    let (width, height) = (rect.right - rect.left, rect.bottom - rect.top);
    let layout = dest.layout();
    let pattern = layout.pixel(pattern);
    for y in part.top..part.bottom {
        let sy = source_of(y - rect.top, height, 0, source.height);
        for x in part.left..part.right {
            let sx = source_of(x - rect.left, width, 0, source.width);
            let raw = source.pixels[(sy * source.width + sx) as usize];
            let pixel = if source.layout == layout { raw } else { layout.pixel(source.layout.color(raw)) };
            let value = if rop3 == SRCCOPY {
                pixel
            } else {
                let under = dest.pixel(x as u32, y as u32).unwrap_or(0);
                super::dib::rop3(rop3, pattern, pixel, under) & 0x00FF_FFFF
            };
            dest.set_pixel(x as u32, y as u32, value);
        }
    }
}

static NEGATIVE_STRETCH_REPORTED: AtomicBool = AtomicBool::new(false);

/// NtGdiStretchBlt (GreStretchBltMask sans masque) : le rectangle (`x`, `y`,
/// `width`, `height`) du DC `hdc` reçoit le rectangle (`x_src`, `y_src`,
/// `width_src`, `height_src`) du DC `hdc_src`, étiré ou réduit, par le ROP
/// `rop`, avec le pinceau du DC s'il s'en sert. Aux mêmes tailles, c'est
/// [`bit_blt`] ; un ROP sans source, PatBlt. `Ok(false)` comme BitBlt ; `Err`
/// : l'erreur de Win32, `ERROR_CALL_NOT_IMPLEMENTED` pour une étendue
/// négative (journalisé une fois).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn stretch_blt(
    hdc: u32,
    (x, y, width, height): (i32, i32, i32, i32),
    hdc_src: u32,
    (x_src, y_src, width_src, height_src): (i32, i32, i32, i32),
    rop: u32,
) -> Result<bool, u32> {
    let rop = rop & !(NOMIRRORBITMAP | CAPTUREBLT);
    if !dc::uses_source(rop) {
        return dc::pat_blt(hdc, x, y, width, height, rop);
    }
    if (width, height) == (width_src, height_src) {
        return bit_blt(hdc, (x, y, width, height), hdc_src, (x_src, y_src), rop);
    }
    if width < 0 || height < 0 || width_src < 0 || height_src < 0 {
        if !NEGATIVE_STRETCH_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: StretchBlt of a negative extent (a mirrored image): not yet");
        }
        return Err(ERROR_CALL_NOT_IMPLEMENTED);
    }
    let (Some(dest), Some(source)) = (dc::lock(hdc), dc::lock(hdc_src)) else { return Ok(false) };
    if width == 0 || height == 0 || width_src == 0 || height_src == 0 {
        return Ok(true);
    }
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
    let (ox, oy) = dc::logical_origin(&dest_state, None);
    let (sx, sy) = dc::logical_origin(&source_state, None);
    let (left, top) = (x.saturating_add(ox), y.saturating_add(oy));
    let rect = Rect::new(left, top, left.saturating_add(width), top.saturating_add(height));
    let (src_left, src_top) = (x_src.saturating_add(sx), y_src.saturating_add(sy));
    let area = Rect::new(src_left, src_top, src_left.saturating_add(width_src), src_top.saturating_add(height_src));
    let Some((pixels, layout)) = read_area(&Target::of(&source_state), area) else { return Ok(false) };
    let stretched = Stretched { pixels: &pixels, width: width_src, height: height_src, layout };
    let clip: Vec<Rect> = dest_state.rao().rects().to_vec();
    let draw = |surface: &mut Bitmap<'_>| {
        for &visible in &clip {
            stretch_part(surface, visible, rect, &stretched, (rop >> 16) as u8, pattern);
        }
    };
    match Target::of(&dest_state) {
        Target::Display => crate::display::draw(draw),
        Target::Bitmap(surface) => surface.draw(draw),
    };
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::gdi::rop;

    #[test]
    fn stretching_takes_the_nearest_pixel_where_the_destination_paints() {
        // A 2 x 1 source, red then blue, drawn at 4 x 2 from (1, 1) of a 6 x 3
        // surface, then shrunk back from a 4 x 2 source.
        let layout = PixelLayout::Bgrx;
        let (red, blue) = (layout.pixel(ColorRef::rgb(255, 0, 0)), layout.pixel(ColorRef::rgb(0, 0, 255)));
        let source = [red | 0x8000_0000, blue];
        let stretched = Stretched { pixels: &source, width: 2, height: 1, layout };
        let mut pixels = alloc::vec![0u32; 6 * 3];
        let mut surface = Bitmap::new(&mut pixels, 6, 3, 6, layout).unwrap();
        let rect = Rect::new(1, 1, 5, 3);
        stretch_part(&mut surface, Rect::new(0, 0, 4, 3), rect, &stretched, SRCCOPY, ColorRef(0));
        let at = |surface: &Bitmap<'_>, x, y| surface.pixel(x, y).unwrap();
        assert_eq!([at(&surface, 1, 1), at(&surface, 2, 2)], [red | 0x8000_0000, red | 0x8000_0000], "twice as big");
        assert_eq!(at(&surface, 3, 1), blue);
        assert_eq!(at(&surface, 4, 1), 0, "clipped at x 4");
        assert_eq!(at(&surface, 0, 1), 0, "outside the rectangle");
        // SRCAND with white keeps the destination, with black clears it.
        let white = layout.pixel(ColorRef::rgb(255, 255, 255));
        let mask = [white, 0];
        let and = Stretched { pixels: &mask, width: 2, height: 1, layout };
        stretch_part(&mut surface, rect, rect, &and, 0x88, ColorRef(0));
        assert_eq!([at(&surface, 1, 1), at(&surface, 3, 1)], [red, 0], "SRCAND; the high byte cleared");
        // Shrunk: a 4 x 1 source drawn at 2 x 1 takes every other pixel.
        let four = [1, 2, 3, 4];
        let shrunk = Stretched { pixels: &four, width: 4, height: 1, layout };
        stretch_part(&mut surface, rect, Rect::new(0, 0, 2, 1), &shrunk, SRCCOPY, ColorRef(0));
        assert_eq!([at(&surface, 0, 0), at(&surface, 1, 0)], [0, 0], "outside the part");
        stretch_part(&mut surface, Rect::new(0, 0, 6, 3), Rect::new(0, 0, 2, 1), &shrunk, SRCCOPY, ColorRef(0));
        assert_eq!([at(&surface, 0, 0), at(&surface, 1, 0)], [1, 3]);
        // Taller: a 1 x 2 source (5 over 6) drawn at 1 x 4 — rows apart from
        // columns, the extents not square.
        let column = [5, 6];
        let tall = Stretched { pixels: &column, width: 1, height: 2, layout };
        let mut pixels = alloc::vec![0u32; 4];
        let mut surface = Bitmap::new(&mut pixels, 1, 4, 1, layout).unwrap();
        stretch_part(&mut surface, Rect::new(0, 0, 1, 4), Rect::new(0, 0, 1, 4), &tall, SRCCOPY, ColorRef(0));
        assert_eq!((0..4).map(|y| at(&surface, 0, y)).collect::<Vec<_>>(), [5, 5, 6, 6], "each source row twice");
    }

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
    fn copies_in_one_surface_go_the_way_of_the_shift() {
        use super::super::dib::{PixelLayout, SRCCOPY};
        // A 10 x 10 surface, each pixel its own value; a region of two bands
        // (rows 0 to 5 in two rectangles, rows 5 to 10) scrolled down 3 and
        // right 2: each part copied in the other order would read pixels
        // already overwritten.
        let start: Vec<u32> = (0..100).collect();
        let clip = [Rect::new(0, 0, 4, 5), Rect::new(6, 0, 10, 5), Rect::new(0, 5, 10, 10)];
        let scrolled = parts(Rect::new(0, 0, 10, 10), (-2, -3), &clip);
        let ordered = overlap_order(&scrolled);
        assert_eq!(ordered[0].0, Rect::new(0, 5, 10, 10), "the band the shift goes to first");
        assert_eq!(ordered[1].0, Rect::new(6, 0, 10, 5), "then right to left");
        let mut pixels = start.clone();
        let mut surface = Bitmap::new(&mut pixels, 10, 10, 10, PixelLayout::Rgbx).unwrap();
        for (rect, from) in ordered {
            surface.blt_within(rect, from, SRCCOPY, ColorRef(0));
        }
        let value = |x: i32, y: i32| pixels[(y * 10 + x) as usize];
        let original = |x: i32, y: i32| start[(y * 10 + x) as usize];
        // Inside the region, each pixel holds what was 2 left and 3 up, if
        // that was on the surface.
        for &rect in &clip {
            for y in rect.top.max(3)..rect.bottom {
                for x in rect.left.max(2)..rect.right {
                    assert_eq!(value(x, y), original(x - 2, y - 3), "({x}, {y})");
                }
            }
        }
        let up = overlap_order(&parts(Rect::new(0, 0, 10, 10), (0, 3), &clip));
        assert_eq!(up[0].0, Rect::new(0, 0, 4, 5), "scrolled up: the top band first, left to right");
    }

    #[test]
    fn each_visible_rectangle_takes_its_part_of_the_source() {
        let clip = [Rect::new(0, 0, 15, 100), Rect::new(20, 0, 100, 12), Rect::new(200, 200, 300, 300)];
        let parts = parts(Rect::new(10, 10, 30, 30), (100, 200), &clip);
        assert_eq!(parts, [(Rect::new(10, 10, 15, 30), (100, 200)), (Rect::new(20, 10, 30, 12), (110, 200))]);
    }
}
