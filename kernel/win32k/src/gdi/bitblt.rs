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
//! Entre un bitmap monochrome et une surface en couleurs, les pixels se
//! convertissent comme EXLATEOBJ_vInitXlateFromDCs de ReactOS ([`Convert`]) :
//! d'une source monochrome, le noir donne la couleur du texte du DC de
//! destination et le blanc sa couleur de fond ; vers un bitmap monochrome, la
//! couleur de fond du DC source donne le blanc, toute autre le noir.
//! ImageList_AddMasked de `comctl32` en tire le masque d'une image (la
//! couleur de fond : celle que l'image tient pour transparente). Un ROP avec
//! une source porte sur les 32 bits d'un pixel, l'alpha compris.
//!
//! AlphaBlend ([`alpha_blend`], [`blend`]) : la source mélangée à la
//! destination par l'alpha constant et, avec AC_SRC_ALPHA, par celui de
//! chaque pixel, ses couleurs prémultipliées (DIB_32BPP_AlphaBlend) ; les
//! listes d'images de 32 bits de `comctl32` dessinent ainsi une image qui a
//! son alpha.
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

    /// Un bitmap monochrome (l'écran ne l'est jamais).
    fn is_monochrome(&self) -> bool {
        matches!(self, Self::Bitmap(surface) if surface.is_monochrome())
    }
}

/// La conversion des pixels d'un BitBlt entre un bitmap monochrome et une
/// surface en couleurs (EXLATEOBJ_vInitialize de ReactOS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Convert {
    /// D'une source monochrome vers la couleur : le noir (0) donne `zero`
    /// (la couleur du texte du DC de destination), le blanc (1) `one` (sa
    /// couleur de fond) ; un gris, le plus proche des deux.
    MonoToColor { zero: ColorRef, one: ColorRef },
    /// De la couleur vers un bitmap monochrome : `background` (la couleur de
    /// fond du DC source) donne le blanc, toute autre couleur le noir.
    ColorToMono { background: ColorRef },
}

impl Convert {
    /// Celle d'une source monochrome ou non vers une destination monochrome
    /// ou non ; `None` sans changement de profondeur.
    pub fn between(
        (source_mono, dest_mono): (bool, bool),
        source_background: ColorRef,
        (dest_text, dest_background): (ColorRef, ColorRef),
    ) -> Option<Self> {
        match (source_mono, dest_mono) {
            (true, false) => Some(Self::MonoToColor { zero: dest_text, one: dest_background }),
            (false, true) => Some(Self::ColorToMono { background: source_background }),
            _ => None,
        }
    }

    /// Ce que devient la couleur `color` de la source.
    pub fn color(self, color: ColorRef) -> ColorRef {
        let rgb = |color: ColorRef| color.0 & 0x00FF_FFFF;
        match self {
            // A monochrome bitmap holds black or white, but text smoothed
            // on it leaves grays: the nearest of the two decides.
            Self::MonoToColor { zero, one } => {
                if super::dibits::to_monochrome(color) == ColorRef::rgb(255, 255, 255) {
                    one
                } else {
                    zero
                }
            }
            Self::ColorToMono { background } => {
                if rgb(color) == rgb(background) {
                    ColorRef::rgb(255, 255, 255)
                } else {
                    ColorRef::rgb(0, 0, 0)
                }
            }
        }
    }
}

/// La conversion d'un BitBlt de la surface de `source` vers celle de `dest`,
/// d'après leurs couleurs de texte et de fond (le noir et le blanc pour un
/// DC sans attributs lisibles).
fn conversion(source: &dc::Dc, dest: &dc::Dc, source_target: &Target, dest_target: &Target) -> Option<Convert> {
    let monochrome = (source_target.is_monochrome(), dest_target.is_monochrome());
    if monochrome.0 == monochrome.1 {
        return None;
    }
    let (black, white) = (ColorRef::rgb(0, 0, 0), ColorRef::rgb(255, 255, 255));
    let source_background = dc::text_attrs(source).map_or(white, |attrs| attrs.background);
    let dest_colors = dc::text_attrs(dest).map_or((black, white), |attrs| (attrs.color, attrs.background));
    Convert::between(monochrome, source_background, dest_colors)
}

/// Les étapes `parts` de BitBlt de `source` vers `dest` par `rop3`, les
/// pixels de la source convertis par `convert` : chacune lue de la source,
/// convertie, puis écrite sur la destination (ce qui tombe hors de la source
/// n'est pas écrit).
fn blit_converted(source: &Target, dest: &Target, parts: &[Part], convert: Convert, rop3: u8, pattern: ColorRef) {
    for &(rect, from) in parts {
        let (width, height) = (rect.right - rect.left, rect.bottom - rect.top);
        let area = Rect::new(from.0, from.1, from.0 + width, from.1 + height);
        let Some((mut pixels, layout, bounds)) = read_area(source, area) else { continue };
        for pixel in pixels.iter_mut() {
            *pixel = PixelLayout::Bgrx.pixel(convert.color(layout.color(*pixel)));
        }
        // What of the source is on it, where it lands on the destination.
        let seen = area.intersect(&bounds);
        let (dx, dy) = (rect.left - from.0, rect.top - from.1);
        let target = Rect::new(seen.left + dx, seen.top + dy, seen.right + dx, seen.bottom + dy);
        let Some(converted) = Bitmap::new(&mut pixels, width as u32, height as u32, width as u32, PixelLayout::Bgrx)
        else {
            continue;
        };
        let corner = (target.left - rect.left, target.top - rect.top);
        let write = |surface: &mut Bitmap<'_>| surface.blt_from(target, &converted, corner, rop3, pattern);
        match dest {
            Target::Display => crate::display::draw(write),
            Target::Bitmap(surface) => surface.draw(write),
        };
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
    let (source_target, dest_target) = (Target::of(&source_state), Target::of(&dest_state));
    match conversion(&source, &dest, &source_target, &dest_target) {
        Some(convert) => blit_converted(&source_target, &dest_target, &parts, convert, (rop >> 16) as u8, pattern),
        None => blit(&source_target, &dest_target, &parts, (rop >> 16) as u8, pattern),
    }
    Ok(true)
}

/// Les pixels de `area` sur la surface `target`, ligne par ligne (0 hors
/// d'elle), l'ordre de leurs octets et les bornes de la surface ; `None` pour
/// un bitmap sans pixels.
fn read_area(target: &Target, area: Rect) -> Option<(Vec<u32>, PixelLayout, Rect)> {
    let mut read = None;
    let mut copy = |surface: &mut Bitmap<'_>| {
        let mut pixels = Vec::with_capacity(((area.right - area.left) * (area.bottom - area.top)) as usize);
        for y in area.top..area.bottom {
            for x in area.left..area.right {
                let inside = x >= 0 && y >= 0;
                pixels.push(if inside { surface.pixel(x as u32, y as u32).unwrap_or(0) } else { 0 });
            }
        }
        read = Some((pixels, surface.layout(), surface.bounds()));
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
                super::dib::rop3(rop3, pattern, pixel, under)
            };
            dest.set_pixel(x as u32, y as u32, value);
        }
    }
}

/// AC_SRC_OVER : la seule opération d'AlphaBlend.
pub const AC_SRC_OVER: u8 = 0;
/// AC_SRC_ALPHA : la source a l'alpha de chaque pixel, ses couleurs
/// prémultipliées.
pub const AC_SRC_ALPHA: u8 = 1;

/// DIB_32BPP_AlphaBlend, un pixel : la source (sa couleur, son alpha) sur la
/// destination (la sienne, son alpha), avec l'alpha constant `constant` et,
/// si `per_pixel` (AC_SRC_ALPHA), l'alpha de chaque pixel de la source, ses
/// couleurs prémultipliées : chaque composante de la source multipliée par
/// `constant`, puis ajoutée à celle de la destination multipliée par
/// 255 − l'alpha, plafonnée à 255.
pub fn blend(
    (source, source_alpha): (ColorRef, u8),
    (dest, dest_alpha): (ColorRef, u8),
    constant: u8,
    per_pixel: bool,
) -> (ColorRef, u8) {
    let scale = |value: u8| (u32::from(value) * u32::from(constant) / 255) as u8;
    let (sr, sg, sb) = source.components();
    let (sr, sg, sb, sa) = (scale(sr), scale(sg), scale(sb), scale(source_alpha));
    let alpha = if per_pixel { u32::from(sa) } else { u32::from(constant) };
    let over = |d: u8, s: u8| (u32::from(d) * (255 - alpha) / 255 + u32::from(s)).min(255) as u8;
    let (dr, dg, db) = dest.components();
    (ColorRef::rgb(over(dr, sr), over(dg, sg), over(db, sb)), over(dest_alpha, sa))
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
    let (source_target, dest_target) = (Target::of(&source_state), Target::of(&dest_state));
    let Some((mut pixels, mut layout, _)) = read_area(&source_target, area) else { return Ok(false) };
    if let Some(convert) = conversion(&source, &dest, &source_target, &dest_target) {
        for pixel in pixels.iter_mut() {
            *pixel = PixelLayout::Bgrx.pixel(convert.color(layout.color(*pixel)));
        }
        layout = PixelLayout::Bgrx;
    }
    let stretched = Stretched { pixels: &pixels, width: width_src, height: height_src, layout };
    let clip: Vec<Rect> = dest_state.rao().rects().to_vec();
    let draw = |surface: &mut Bitmap<'_>| {
        for &visible in &clip {
            stretch_part(surface, visible, rect, &stretched, (rop >> 16) as u8, pattern);
        }
    };
    match dest_target {
        Target::Display => crate::display::draw(draw),
        Target::Bitmap(surface) => surface.draw(draw),
    };
    Ok(true)
}

/// NtGdiAlphaBlend (IntEngAlphaBlend, DIB_32BPP_AlphaBlend) : le rectangle
/// (`x_src`, `y_src`, `width_src`, `height_src`) du DC `hdc_src`, étiré ou
/// réduit au pixel le plus proche, mélangé ([`blend`]) au rectangle (`x`,
/// `y`, `width`, `height`) du DC `hdc`, là où il peint. `blend_function` est
/// un BLENDFUNCTION : BlendOp, BlendFlags, SourceConstantAlpha, AlphaFormat,
/// octet par octet. `Ok(false)` pour un DC qui n'est pas au processus ;
/// `Err(ERROR_INVALID_PARAMETER)` pour une étendue négative, une opération
/// autre qu'AC_SRC_OVER, des drapeaux, AC_SRC_ALPHA d'une source qui n'est
/// pas de 32 bits, une source hors de son bitmap.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn alpha_blend(
    hdc: u32,
    (x, y, width, height): (i32, i32, i32, i32),
    hdc_src: u32,
    (x_src, y_src, width_src, height_src): (i32, i32, i32, i32),
    blend_function: u32,
) -> Result<bool, u32> {
    use abi::winerror::ERROR_INVALID_PARAMETER;
    let [op, flags, constant, format] = blend_function.to_le_bytes();
    if width < 0 || height < 0 || width_src < 0 || height_src < 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if op != AC_SRC_OVER || flags != 0 || format & !AC_SRC_ALPHA != 0 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let (Some(dest), Some(source)) = (dc::lock(hdc), dc::lock(hdc_src)) else { return Ok(false) };
    let (dest_state, source_state) = (dest.state(), source.state());
    let (source_target, dest_target) = (Target::of(&source_state), Target::of(&dest_state));
    let per_pixel = format & AC_SRC_ALPHA != 0;
    if per_pixel && matches!(&source_target, Target::Bitmap(surface) if surface.bit_count() != 32) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if width == 0 || height == 0 || width_src == 0 || height_src == 0 {
        return Ok(true);
    }
    let (ox, oy) = dc::logical_origin(&dest_state, None);
    let (sx, sy) = dc::logical_origin(&source_state, None);
    let (left, top) = (x.saturating_add(ox), y.saturating_add(oy));
    let rect = Rect::new(left, top, left.saturating_add(width), top.saturating_add(height));
    let (src_left, src_top) = (x_src.saturating_add(sx), y_src.saturating_add(sy));
    let area = Rect::new(src_left, src_top, src_left.saturating_add(width_src), src_top.saturating_add(height_src));
    let Some((pixels, layout, bounds)) = read_area(&source_target, area) else { return Ok(false) };
    if area.intersect(&bounds) != area {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let clip: Vec<Rect> = dest_state.rao().rects().to_vec();
    let draw = |surface: &mut Bitmap<'_>| {
        let dest_layout = surface.layout();
        for visible in &clip {
            let part = visible.intersect(&rect).intersect(&surface.bounds());
            for py in part.top..part.bottom {
                let row = source_of(py - top, height, 0, height_src);
                for px in part.left..part.right {
                    let column = source_of(px - left, width, 0, width_src);
                    let raw = pixels[(row * width_src + column) as usize];
                    let under = surface.pixel(px as u32, py as u32).unwrap_or(0);
                    let (color, alpha) = blend(
                        (layout.color(raw), (raw >> 24) as u8),
                        (dest_layout.color(under), (under >> 24) as u8),
                        constant,
                        per_pixel,
                    );
                    surface.set_pixel(px as u32, py as u32, dest_layout.pixel(color) | (u32::from(alpha) << 24));
                }
            }
        }
    };
    match dest_target {
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
    fn alpha_blending_adds_the_premultiplied_source() {
        let (white, black) = (ColorRef::rgb(255, 255, 255), ColorRef::rgb(0, 0, 0));
        let gray = ColorRef::rgb(128, 128, 128);
        // Per pixel: opaque replaces, transparent (black, 0) leaves.
        assert_eq!(blend((gray, 255), (white, 0), 255, true), (gray, 255));
        assert_eq!(blend((black, 0), (white, 0x40), 255, true), (white, 0x40));
        // Half transparent, premultiplied: 64 + 200 * 127 / 255.
        let (color, alpha) = blend((ColorRef::rgb(64, 64, 64), 128), (ColorRef::rgb(200, 200, 200), 0), 255, true);
        assert_eq!((color, alpha), (ColorRef::rgb(163, 163, 163), 128));
        // Constant alpha alone: the source scaled, the destination by 255 - it.
        let (color, _) = blend((white, 0), (black, 0), 128, false);
        assert_eq!(color, ColorRef::rgb(128, 128, 128));
        // Both: the constant scales the source and its alpha.
        let (color, alpha) = blend((white, 255), (black, 0), 128, true);
        assert_eq!((color, alpha), (ColorRef::rgb(128, 128, 128), 128));
        // Saturated: a source that is not premultiplied cannot pass 255.
        assert_eq!(blend((white, 64), (white, 255), 255, true).0, white);
    }

    #[test]
    fn monochrome_and_colours_convert_by_the_dcs_colours() {
        let (black, white) = (ColorRef::rgb(0, 0, 0), ColorRef::rgb(255, 255, 255));
        let (face, text, back) = (ColorRef::rgb(0xD4, 0xD0, 0xC8), ColorRef::rgb(1, 2, 3), ColorRef::rgb(4, 5, 6));
        assert_eq!(Convert::between((false, false), face, (text, back)), None, "colour to colour");
        assert_eq!(Convert::between((true, true), face, (text, back)), None, "monochrome to monochrome");
        let to_mono = Convert::between((false, true), face, (text, back)).unwrap();
        assert_eq!(to_mono.color(face), white, "the source's background: white");
        assert_eq!(to_mono.color(ColorRef(0x8000_0000 | face.0)), white, "whatever its high byte");
        assert_eq!([to_mono.color(black), to_mono.color(ColorRef::rgb(0xD4, 0xD0, 0xC9))], [black, black]);
        let to_colour = Convert::between((true, false), face, (text, back)).unwrap();
        assert_eq!([to_colour.color(black), to_colour.color(white)], [text, back], "0: text, 1: background");
        let (dark, light) = (ColorRef::rgb(0x40, 0x40, 0x40), ColorRef::rgb(0xC0, 0xC0, 0xC0));
        assert_eq!([to_colour.color(dark), to_colour.color(light)], [text, back], "smoothed text: the nearest");
    }

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
