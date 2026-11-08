//! Le moteur DIB : ce que fait la bibliothèque `Eng*` d'un pilote
//! d'affichage, sur une surface de 32 bits par pixel ([`Bitmap`]).
//!
//! Une surface range ses pixels ligne par ligne, `stride` pixels par ligne
//! (au moins sa largeur), dans l'ordre de ses octets ([`PixelLayout`]) : une
//! couleur ([`ColorRef`], `0x00BBGGRR`) y devient un pixel par
//! [`PixelLayout::pixel`].
//!
//! Les lignes d'une DIB dont `biHeight` est positif montent depuis celle du
//! bas ([`Bitmap::bottom_up`]) : la ligne `y` de la surface est la ligne
//! `height - 1 - y` en mémoire.
//!
//! BitBlt ([`Bitmap::blt_from`], [`Bitmap::blt_within`]) combine la source,
//! le motif d'un pinceau plein et la destination par un ROP3 quelconque
//! ([`rop3`]) ; une copie entre surfaces de même ordre d'octets passe ligne
//! par ligne.
//!
//! Pas encore : les autres profondeurs (1, 4, 8, 16, 24 bits), StretchBlt,
//! les motifs, l'alpha, les lignes.

/// COLORREF : une couleur, `0x00BBGGRR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColorRef(pub u32);

impl ColorRef {
    /// RGB(r, g, b).
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self(r as u32 | (g as u32) << 8 | (b as u32) << 16)
    }

    /// Ses composantes rouge, verte et bleue.
    pub const fn components(self) -> (u8, u8, u8) {
        (self.0 as u8, (self.0 >> 8) as u8, (self.0 >> 16) as u8)
    }
}

/// L'ordre des octets d'un pixel de 32 bits, le quatrième inutilisé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelLayout {
    /// Bleu, vert, rouge, puis l'octet inutilisé (GOP
    /// `PixelBlueGreenRedReserved8BitPerColor`, les DIB de 32 bits).
    Bgrx,
    /// Rouge, vert, bleu, puis l'octet inutilisé (GOP
    /// `PixelRedGreenBlueReserved8BitPerColor`).
    Rgbx,
}

impl PixelLayout {
    /// La couleur du pixel `pixel` : l'inverse de [`pixel`](Self::pixel).
    pub const fn color(self, pixel: u32) -> ColorRef {
        let (high, middle, low) = ((pixel >> 16) as u8, (pixel >> 8) as u8, pixel as u8);
        match self {
            PixelLayout::Bgrx => ColorRef::rgb(high, middle, low),
            PixelLayout::Rgbx => ColorRef::rgb(low, middle, high),
        }
    }

    /// Le pixel de `color`, tel qu'il s'écrit en mémoire (un mot petit-boutiste).
    pub const fn pixel(self, color: ColorRef) -> u32 {
        let (r, g, b) = color.components();
        match self {
            PixelLayout::Bgrx => (r as u32) << 16 | (g as u32) << 8 | b as u32,
            PixelLayout::Rgbx => (b as u32) << 16 | (g as u32) << 8 | r as u32,
        }
    }
}

/// Un rectangle : de (`left`, `top`) inclus à (`right`, `bottom`) exclus,
/// comme un RECT de GDI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub const fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Self { left, top, right, bottom }
    }

    /// Vide : sans largeur ou sans hauteur.
    pub const fn is_empty(&self) -> bool {
        self.right <= self.left || self.bottom <= self.top
    }

    /// Le plus petit rectangle qui tient les deux.
    pub fn union(&self, other: &Rect) -> Rect {
        Rect::new(
            self.left.min(other.left),
            self.top.min(other.top),
            self.right.max(other.right),
            self.bottom.max(other.bottom),
        )
    }

    /// Son intersection avec `other`, vide s'ils ne se touchent pas.
    pub fn intersect(&self, other: &Rect) -> Rect {
        Rect::new(
            self.left.max(other.left),
            self.top.max(other.top),
            self.right.min(other.right),
            self.bottom.min(other.bottom),
        )
    }
}

/// Un motif monochrome de 8 × 8 pixels posé sur une surface, pour
/// [`Bitmap::pat_blt_mono`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonoFill {
    /// Les lignes du motif, le bit 7 à gauche.
    pub rows: [u8; 8],
    /// La couleur des bits à 0 (celle du texte du DC).
    pub zero: ColorRef,
    /// La couleur des bits à 1 (celle de son fond).
    pub one: ColorRef,
    /// Le pixel de la surface où tombe le coin du motif (l'origine du
    /// pinceau : celle du DC, plus SetBrushOrgEx).
    pub origin: (i32, i32),
}

/// Une surface de 32 bits par pixel : `width` × `height` pixels, `stride`
/// par ligne, dans `pixels`.
pub struct Bitmap<'a> {
    pixels: &'a mut [u32],
    width: u32,
    height: u32,
    stride: u32,
    layout: PixelLayout,
    /// La ligne du haut est la dernière en mémoire.
    bottom_up: bool,
}

impl<'a> Bitmap<'a> {
    /// La surface de `pixels`. `None` si `stride` est plus petit que
    /// `width` ou si `pixels` ne tient pas `height` lignes.
    pub fn new(pixels: &'a mut [u32], width: u32, height: u32, stride: u32, layout: PixelLayout) -> Option<Self> {
        let needed = (stride as usize).checked_mul(height.saturating_sub(1) as usize)?.checked_add(width as usize)?;
        if stride < width || (height > 0 && pixels.len() < needed) {
            return None;
        }
        Some(Self { pixels, width, height, stride, layout, bottom_up: false })
    }

    /// La même surface, ses lignes montant depuis celle du bas (une DIB de
    /// `biHeight` positif).
    pub fn bottom_up(self) -> Self {
        Self { bottom_up: true, ..self }
    }

    /// L'indice, dans `pixels`, du premier pixel de la ligne `y` (sur la
    /// surface).
    fn row(&self, y: u32) -> usize {
        let line = if self.bottom_up { self.height - 1 - y } else { y };
        line as usize * self.stride as usize
    }

    /// Son rectangle entier.
    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width as i32, self.height as i32)
    }

    pub fn layout(&self) -> PixelLayout {
        self.layout
    }

    /// Le pixel en (`x`, `y`), s'il est sur la surface.
    pub fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        (x < self.width && y < self.height).then(|| self.pixels[self.row(y) + x as usize])
    }

    /// Le pixel en (`x`, `y`) prend la valeur `value` (dans le format de la
    /// surface), s'il est sur elle.
    pub fn set_pixel(&mut self, x: u32, y: u32, value: u32) {
        if x < self.width && y < self.height {
            let at = self.row(y) + x as usize;
            self.pixels[at] = value;
        }
    }

    /// PatBlt avec un pinceau plein (PATCOPY) : `rect`, coupé aux bords de
    /// la surface, prend la couleur `color`.
    pub fn fill_rect(&mut self, rect: Rect, color: ColorRef) {
        let rect = rect.intersect(&self.bounds());
        if rect.is_empty() {
            return;
        }
        let pixel = self.layout.pixel(color);
        for y in rect.top as u32..rect.bottom as u32 {
            let row = self.row(y);
            self.pixels[row + rect.left as usize..row + rect.right as usize].fill(pixel);
        }
    }

    /// Un masque de couverture de `width` colonnes (de 0, rien, à 255, tout)
    /// en `color`, son coin en (`x`, `y`) : chaque pixel va vers `color` à
    /// proportion de sa couverture, dans `clip` et les bords de la surface.
    pub fn blend_coverage(&mut self, (x, y): (i32, i32), width: usize, coverage: &[u8], color: ColorRef, clip: Rect) {
        if width == 0 {
            return;
        }
        let height = (coverage.len() / width) as i32;
        let area = Rect::new(x, y, x + width as i32, y + height).intersect(&clip).intersect(&self.bounds());
        if area.is_empty() {
            return;
        }
        let full = self.layout.pixel(color);
        let (r, g, b) = color.components();
        for py in area.top..area.bottom {
            let row = self.row(py as u32);
            let line = (py - y) as usize * width;
            for px in area.left..area.right {
                let alpha = u32::from(coverage[line + (px - x) as usize]);
                let pixel = &mut self.pixels[row + px as usize];
                *pixel = match alpha {
                    0 => continue,
                    255 => full,
                    _ => {
                        let (dr, dg, db) = self.layout.color(*pixel).components();
                        let mix =
                            |d: u8, s: u8| ((u32::from(d) * (255 - alpha) + u32::from(s) * alpha + 127) / 255) as u8;
                        self.layout.pixel(ColorRef::rgb(mix(dr, r), mix(dg, g), mix(db, b)))
                    }
                };
            }
        }
    }

    /// PatBlt avec un motif monochrome de 8 × 8 pixels ([`MonoFill`]) :
    /// `rect`, coupé aux bords de la surface, prend le pixel du motif qui y
    /// tombe par le ROP3 `rop3` ([`rop3_without_source`]).
    pub fn pat_blt_mono(&mut self, rect: Rect, fill: &MonoFill, rop3: u8) {
        let rect = rect.intersect(&self.bounds());
        if rect.is_empty() {
            return;
        }
        let colors = [self.layout.pixel(fill.zero), self.layout.pixel(fill.one)];
        for y in rect.top..rect.bottom {
            let bits = fill.rows[(y.wrapping_sub(fill.origin.1) & 7) as usize];
            let row = self.row(y as u32);
            for x in rect.left..rect.right {
                let bit = (bits >> (7 - (x.wrapping_sub(fill.origin.0) & 7))) & 1;
                let pixel = &mut self.pixels[row + x as usize];
                // The unused byte stays zero.
                *pixel = rop3_without_source(rop3, colors[usize::from(bit)], *pixel) & 0x00FF_FFFF;
            }
        }
    }

    /// PatBlt avec un pinceau plein : `rect`, coupé aux bords de la surface,
    /// prend `color` par le ROP3 `rop3` ([`rop3_without_source`]).
    pub fn pat_blt(&mut self, rect: Rect, color: ColorRef, rop3: u8) {
        if rop3 == PATCOPY {
            return self.fill_rect(rect, color);
        }
        let rect = rect.intersect(&self.bounds());
        if rect.is_empty() {
            return;
        }
        let pattern = self.layout.pixel(color);
        for y in rect.top as u32..rect.bottom as u32 {
            let row = self.row(y);
            for pixel in &mut self.pixels[row + rect.left as usize..row + rect.right as usize] {
                // The unused byte stays zero.
                *pixel = rop3_without_source(rop3, pattern, *pixel) & 0x00FF_FFFF;
            }
        }
    }
}

impl Bitmap<'_> {
    /// `rect` coupé à cette surface et à `source` dont le pixel `from`
    /// répond à son coin ; le décalage de `source` à cette surface.
    fn blt_area(&self, rect: Rect, source: Rect, from: (i32, i32)) -> (Rect, (i32, i32)) {
        let (dx, dy) = (from.0.saturating_sub(rect.left), from.1.saturating_sub(rect.top));
        let seen = Rect::new(
            source.left.saturating_sub(dx),
            source.top.saturating_sub(dy),
            source.right.saturating_sub(dx),
            source.bottom.saturating_sub(dy),
        );
        (rect.intersect(&self.bounds()).intersect(&seen), (dx, dy))
    }

    /// Le pixel `pixel` de l'ordre d'octets `from` dans celui de cette
    /// surface.
    fn converted(&self, pixel: u32, from: PixelLayout) -> u32 {
        if from == self.layout {
            pixel
        } else {
            self.layout.pixel(from.color(pixel))
        }
    }

    /// BitBlt d'une autre surface (EngBitBlt) : `rect` reçoit les pixels de
    /// `source` à partir de `from` (le pixel qui répond à son coin), par le
    /// ROP3 `rop3` avec le motif plein `pattern` ; coupé aux deux surfaces.
    pub fn blt_from(&mut self, rect: Rect, source: &Bitmap<'_>, from: (i32, i32), rop3: u8, pattern: ColorRef) {
        let (area, (dx, dy)) = self.blt_area(rect, source.bounds(), from);
        if area.is_empty() {
            return;
        }
        let pattern = self.layout.pixel(pattern);
        let (left, width) = (area.left as usize, (area.right - area.left) as usize);
        let source_left = (area.left + dx) as usize;
        for y in area.top..area.bottom {
            let (to, at) = (self.row(y as u32) + left, source.row((y + dy) as u32) + source_left);
            let from = &source.pixels[at..at + width];
            if rop3 == SRCCOPY && source.layout == self.layout {
                self.pixels[to..to + width].copy_from_slice(from);
                continue;
            }
            for (x, &pixel) in from.iter().enumerate() {
                let pixel = self.converted(pixel, source.layout);
                let dest = &mut self.pixels[to + x];
                // The unused byte stays zero.
                *dest = self::rop3(rop3, pattern, pixel, *dest) & 0x00FF_FFFF;
            }
        }
    }

    /// BitBlt dans la même surface (un défilement) : comme
    /// [`blt_from`](Self::blt_from), la source et la destination pouvant se
    /// chevaucher. Chaque pixel de la source est lu avant d'être écrit : les
    /// lignes vont vers la source, et les colonnes aussi sur une même ligne.
    pub fn blt_within(&mut self, rect: Rect, from: (i32, i32), rop3: u8, pattern: ColorRef) {
        let (area, (dx, dy)) = self.blt_area(rect, self.bounds(), from);
        if area.is_empty() {
            return;
        }
        let pattern = self.layout.pixel(pattern);
        let (left, width) = (area.left as usize, (area.right - area.left) as usize);
        let source_left = (area.left + dx) as usize;
        let rows: &mut dyn Iterator<Item = i32> =
            if dy > 0 { &mut (area.top..area.bottom) } else { &mut (area.top..area.bottom).rev() };
        for y in rows {
            let (to, at) = (self.row(y as u32) + left, self.row((y + dy) as u32) + source_left);
            if rop3 == SRCCOPY {
                self.pixels.copy_within(at..at + width, to);
                continue;
            }
            let columns: &mut dyn Iterator<Item = usize> = if dx > 0 { &mut (0..width) } else { &mut (0..width).rev() };
            for x in columns {
                let pixel = self.pixels[at + x];
                let dest = &mut self.pixels[to + x];
                *dest = self::rop3(rop3, pattern, pixel, *dest) & 0x00FF_FFFF;
            }
        }
    }
}

/// Le ROP3 de SRCCOPY : la source.
pub const SRCCOPY: u8 = 0xCC;

/// Le ROP3 `rop3`, bit à bit, du motif `pattern`, de la source `source` et
/// de la destination `dest` : chaque bit du résultat est le bit
/// `4 P + 2 S + D` de `rop3`.
pub const fn rop3(rop3: u8, pattern: u32, source: u32, dest: u32) -> u32 {
    let mut out = 0;
    let mut index = 0;
    while index < 8 {
        if rop3 & (1 << index) != 0 {
            let p = if index & 4 != 0 { pattern } else { !pattern };
            let s = if index & 2 != 0 { source } else { !source };
            let d = if index & 1 != 0 { dest } else { !dest };
            out |= p & s & d;
        }
        index += 1;
    }
    out
}

/// Le ROP3 de PATCOPY : le motif.
pub const PATCOPY: u8 = 0xF0;

/// Le ROP3 `rop3` sans source, bit à bit, du motif `pattern` et de la
/// destination `dest` : chaque bit du résultat est le bit `4 P + D` de
/// `rop3` (une source à 0 : `P·4 + S·2 + D`).
pub const fn rop3_without_source(rop3: u8, pattern: u32, dest: u32) -> u32 {
    let mut out = 0;
    if rop3 & 0x01 != 0 {
        out |= !pattern & !dest;
    }
    if rop3 & 0x02 != 0 {
        out |= !pattern & dest;
    }
    if rop3 & 0x10 != 0 {
        out |= pattern & !dest;
    }
    if rop3 & 0x20 != 0 {
        out |= pattern & dest;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_color_becomes_the_pixel_of_its_layout() {
        let blue = ColorRef::rgb(58, 110, 165);
        assert_eq!(blue, ColorRef(0x00A5_6E3A), "COLORREF is 0x00BBGGRR");
        assert_eq!(PixelLayout::Bgrx.pixel(blue), 0x003A_6EA5, "bytes A5 6E 3A: blue, green, red");
        assert_eq!(PixelLayout::Rgbx.pixel(blue), 0x00A5_6E3A, "bytes 3A 6E A5: red, green, blue");
    }

    #[test]
    fn a_pixel_gives_back_its_colour() {
        let color = ColorRef::rgb(1, 2, 3);
        for layout in [PixelLayout::Bgrx, PixelLayout::Rgbx] {
            assert_eq!(layout.color(layout.pixel(color)), color, "{layout:?}");
        }
    }

    #[test]
    fn coverage_blends_toward_its_colour_within_the_clip() {
        let mut pixels = [PixelLayout::Rgbx.pixel(ColorRef::rgb(0, 0, 0)); 4 * 2];
        let mut bitmap = Bitmap::new(&mut pixels, 4, 2, 4, PixelLayout::Rgbx).unwrap();
        let white = ColorRef::rgb(255, 255, 255);
        // A 3 × 2 mask at (1, 0), cut at x = 3.
        bitmap.blend_coverage((1, 0), 3, &[255, 128, 255, 0, 64, 255], white, Rect::new(0, 0, 3, 2));
        let at = |x: u32, y: u32| PixelLayout::Rgbx.color(bitmap.pixel(x, y).unwrap());
        assert_eq!(at(0, 0), ColorRef::rgb(0, 0, 0), "outside the mask");
        assert_eq!(at(1, 0), white, "covered");
        assert_eq!(at(2, 0), ColorRef::rgb(128, 128, 128), "half covered");
        assert_eq!(at(3, 0), ColorRef::rgb(0, 0, 0), "clipped");
        assert_eq!((at(1, 1), at(2, 1)), (ColorRef::rgb(0, 0, 0), ColorRef::rgb(64, 64, 64)));
    }

    #[test]
    fn a_rectangle_is_filled_within_the_surface() {
        let mut pixels = [0u32; 5 * 4];
        let mut bitmap = Bitmap::new(&mut pixels, 4, 4, 5, PixelLayout::Bgrx).unwrap();
        bitmap.fill_rect(Rect::new(2, 1, 9, 3), ColorRef::rgb(0xFF, 0, 0));
        let red = 0x00FF_0000;
        assert_eq!((bitmap.pixel(1, 1), bitmap.pixel(2, 1), bitmap.pixel(3, 2)), (Some(0), Some(red), Some(red)));
        assert_eq!((bitmap.pixel(2, 0), bitmap.pixel(2, 3), bitmap.pixel(4, 1)), (Some(0), Some(0), None));
        assert_eq!(pixels[5 + 4], 0, "the padding of a row past the width is left alone");
    }

    #[test]
    fn empty_or_outside_rectangles_draw_nothing() {
        let mut pixels = [0u32; 16];
        let mut bitmap = Bitmap::new(&mut pixels, 4, 4, 4, PixelLayout::Bgrx).unwrap();
        bitmap.fill_rect(Rect::new(3, 3, 3, 9), ColorRef::rgb(1, 2, 3));
        bitmap.fill_rect(Rect::new(-5, -5, 0, 2), ColorRef::rgb(1, 2, 3));
        bitmap.fill_rect(Rect::new(4, 0, 8, 4), ColorRef::rgb(1, 2, 3));
        assert!(pixels.iter().all(|&pixel| pixel == 0));
    }

    #[test]
    fn the_raster_operations_of_pat_blt() {
        let (p, d) = (0b1100, 0b1010);
        assert_eq!(rop3_without_source(0xF0, p, d) & 0xF, p, "PATCOPY");
        assert_eq!(rop3_without_source(0x5A, p, d) & 0xF, p ^ d, "PATINVERT");
        assert_eq!(rop3_without_source(0x55, p, d) & 0xF, !d & 0xF, "DSTINVERT");
        assert_eq!(rop3_without_source(0x00, p, d), 0, "BLACKNESS");
        assert_eq!(rop3_without_source(0xFF, p, d), u32::MAX, "WHITENESS");
        assert_eq!(rop3_without_source(0x0A, p, d) & 0xF, !p & d & 0xF, "PDna");
        assert_eq!(rop3_without_source(0xA0, p, d) & 0xF, p & d, "DPa");
    }

    #[test]
    fn pat_blt_combines_the_brush_with_the_screen() {
        let mut pixels = [0x0012_3456u32; 4];
        let mut bitmap = Bitmap::new(&mut pixels, 2, 2, 2, PixelLayout::Bgrx).unwrap();
        bitmap.pat_blt(Rect::new(1, 0, 5, 2), ColorRef::rgb(0xFF, 0, 0), 0x5A);
        assert_eq!(bitmap.pixel(0, 0), Some(0x0012_3456), "outside");
        assert_eq!(bitmap.pixel(1, 1), Some(0x00ED_3456), "PATINVERT: red flips 0x12");
        bitmap.pat_blt(Rect::new(0, 0, 1, 1), ColorRef(0), 0xFF);
        assert_eq!(bitmap.pixel(0, 0), Some(0x00FF_FFFF), "WHITENESS leaves the unused byte zero");
        bitmap.pat_blt(Rect::new(0, 1, 2, 2), ColorRef::rgb(0, 0, 0xFF), PATCOPY);
        assert_eq!((bitmap.pixel(0, 1), bitmap.pixel(1, 1)), (Some(0xFF), Some(0xFF)));
    }

    #[test]
    fn a_mono_pattern_repeats_from_the_brush_origin() {
        let mut pixels = [0x0012_3456u32; 10 * 3];
        let mut bitmap = Bitmap::new(&mut pixels, 10, 3, 10, PixelLayout::Bgrx).unwrap();
        let fill = MonoFill {
            rows: [0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA],
            zero: ColorRef::rgb(0, 0, 0),
            one: ColorRef::rgb(0xFF, 0xFF, 0xFF),
            origin: (1, 0),
        };
        bitmap.pat_blt_mono(Rect::new(0, 0, 12, 2), &fill, PATCOPY);
        let row =
            |bitmap: &Bitmap<'_>, y: u32| -> [u32; 10] { core::array::from_fn(|x| bitmap.pixel(x as u32, y).unwrap()) };
        let (black, white) = (0, 0x00FF_FFFF);
        assert_eq!(row(&bitmap, 0)[..4], [white, black, white, black], "0x55 from x = 1: x = 0 is its last bit");
        assert_eq!(row(&bitmap, 1)[..4], [black, white, black, white], "0xAA on the next row");
        assert_eq!(row(&bitmap, 0)[8..], [white, black], "it repeats every 8 pixels");
        assert_eq!(row(&bitmap, 2), [0x0012_3456; 10], "outside the rectangle");
        bitmap.pat_blt_mono(Rect::new(0, 2, 2, 3), &MonoFill { origin: (-7, -6), ..fill }, 0x5A);
        assert_eq!(row(&bitmap, 2)[..3], [0x00ED_CBA9, 0x0012_3456, 0x0012_3456], "PATINVERT; a negative origin");
    }

    #[test]
    fn the_rows_of_a_bottom_up_dib_go_up_from_the_last() {
        let mut pixels = [0u32; 3 * 2];
        let mut bitmap = Bitmap::new(&mut pixels, 3, 2, 3, PixelLayout::Bgrx).unwrap().bottom_up();
        bitmap.fill_rect(Rect::new(0, 0, 2, 1), ColorRef::rgb(0, 0, 0xFF));
        bitmap.pat_blt(Rect::new(2, 1, 3, 2), ColorRef::rgb(0, 0xFF, 0), PATCOPY);
        bitmap.blend_coverage((0, 1), 1, &[255], ColorRef::rgb(0xFF, 0, 0), Rect::new(0, 0, 3, 2));
        assert_eq!((bitmap.pixel(0, 0), bitmap.pixel(0, 1)), (Some(0xFF), Some(0x00FF_0000)));
        assert_eq!(pixels, [0x00FF_0000, 0, 0x0000_FF00, 0xFF, 0xFF, 0], "the top row is the last in memory");
    }

    #[test]
    fn the_raster_operations_with_a_source() {
        let (p, s, d) = (0b1111_0000, 0b1100_1100, 0b1010_1010);
        assert_eq!(rop3(0xCC, p, s, d) & 0xFF, s, "SRCCOPY");
        assert_eq!(rop3(0x66, p, s, d) & 0xFF, s ^ d, "SRCINVERT");
        assert_eq!(rop3(0x88, p, s, d) & 0xFF, s & d, "SRCAND");
        assert_eq!(rop3(0xEE, p, s, d) & 0xFF, s | d, "SRCPAINT");
        assert_eq!(rop3(0xC0, p, s, d) & 0xFF, p & s, "MERGECOPY");
        assert_eq!(rop3(0x33, p, s, d) & 0xFF, !s & 0xFF, "NOTSRCCOPY");
        for rop in 0..=255u8 {
            assert_eq!(rop3(rop, p, s, d) & 0xFF, u32::from(rop), "a ROP3 code is its result on 0xF0, 0xCC, 0xAA");
        }
        for rop in [0x00u8, 0x5A, 0xA0, 0xF0, 0xFF] {
            assert_eq!(rop3(rop, p, s, d), rop3_without_source(rop, p, d), "{rop:#x} does not use the source");
        }
    }

    #[test]
    fn blt_copies_from_another_surface_within_both() {
        let mut source = [0u32; 4 * 3];
        for (i, pixel) in source.iter_mut().enumerate() {
            *pixel = i as u32 + 1;
        }
        let source = Bitmap::new(&mut source, 4, 3, 4, PixelLayout::Bgrx).unwrap().bottom_up();
        let mut pixels = [0u32; 5 * 2];
        let mut dest = Bitmap::new(&mut pixels, 5, 2, 5, PixelLayout::Bgrx).unwrap();
        // The source's (2, 1) at (0, 0): two columns are left of the source,
        // past (4, y), cut.
        dest.blt_from(Rect::new(0, 0, 5, 2), &source, (2, 1), SRCCOPY, ColorRef(0));
        // Bottom-up: the source's row 1 is its second row in memory (5..8),
        // row 2 its first (1..4).
        assert_eq!(pixels, [7, 8, 0, 0, 0, 3, 4, 0, 0, 0]);
    }

    #[test]
    fn blt_converts_between_layouts_and_combines() {
        let red = ColorRef::rgb(0xFF, 0, 0);
        let mut source = [PixelLayout::Bgrx.pixel(red)];
        let source = Bitmap::new(&mut source, 1, 1, 1, PixelLayout::Bgrx).unwrap();
        let mut pixels = [PixelLayout::Rgbx.pixel(ColorRef::rgb(0, 0, 0xFF)); 2];
        let mut dest = Bitmap::new(&mut pixels, 2, 1, 2, PixelLayout::Rgbx).unwrap();
        dest.blt_from(Rect::new(0, 0, 1, 1), &source, (0, 0), SRCCOPY, ColorRef(0));
        assert_eq!(PixelLayout::Rgbx.color(pixels[0]), red, "converted");
        let mut dest = Bitmap::new(&mut pixels, 2, 1, 2, PixelLayout::Rgbx).unwrap();
        dest.blt_from(Rect::new(1, 0, 2, 1), &source, (0, 0), 0xEE, ColorRef(0));
        assert_eq!(PixelLayout::Rgbx.color(pixels[1]), ColorRef::rgb(0xFF, 0, 0xFF), "SRCPAINT");
    }

    #[test]
    fn blt_within_reads_each_pixel_before_writing_it() {
        let numbered = || core::array::from_fn::<u32, 16, _>(|i| i as u32);
        for (from, rop) in [((0, 1), SRCCOPY), ((0, 1), 0x66), ((1, 0), 0x66), ((0, 0), SRCCOPY)] {
            // Down by one row (a scroll up), left by one column, or onto itself.
            let mut pixels = numbered();
            let mut bitmap = Bitmap::new(&mut pixels, 4, 4, 4, PixelLayout::Bgrx).unwrap();
            bitmap.blt_within(Rect::new(0, 0, 4, 4), from, rop, ColorRef(0));
            let mut expected = numbered();
            for y in 0..4 {
                for x in 0..4 {
                    let (sx, sy) = (x + from.0 as usize, y + from.1 as usize);
                    if sx < 4 && sy < 4 {
                        let (s, d) = (numbered()[sy * 4 + sx], numbered()[y * 4 + x]);
                        expected[y * 4 + x] = rop3(rop, 0, s, d) & 0x00FF_FFFF;
                    }
                }
            }
            assert_eq!(pixels, expected, "from {from:?}, ROP {rop:#x}");
        }
        // Up by one row (a scroll down), right by one column.
        let mut pixels = numbered();
        let mut bitmap = Bitmap::new(&mut pixels, 4, 4, 4, PixelLayout::Bgrx).unwrap().bottom_up();
        bitmap.blt_within(Rect::new(1, 1, 4, 4), (0, 0), SRCCOPY, ColorRef(0));
        let at = |bitmap: &Bitmap<'_>, x, y| bitmap.pixel(x, y).unwrap();
        assert_eq!((at(&bitmap, 1, 1), at(&bitmap, 3, 3), at(&bitmap, 0, 3)), (12, 6, 0));
    }

    #[test]
    fn a_surface_must_hold_its_rows() {
        let mut pixels = [0u32; 10];
        assert!(Bitmap::new(&mut pixels, 4, 3, 4, PixelLayout::Bgrx).is_none(), "12 pixels needed");
        assert!(Bitmap::new(&mut pixels, 4, 2, 3, PixelLayout::Bgrx).is_none(), "a stride under the width");
        assert!(Bitmap::new(&mut pixels, 4, 2, 6, PixelLayout::Bgrx).is_some(), "the last row needs no padding");
    }
}
