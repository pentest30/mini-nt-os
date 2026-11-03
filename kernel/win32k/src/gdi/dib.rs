//! Le moteur DIB : ce que fait la bibliothèque `Eng*` d'un pilote
//! d'affichage, sur une surface de 32 bits par pixel ([`Bitmap`]).
//!
//! Une surface range ses pixels ligne par ligne, `stride` pixels par ligne
//! (au moins sa largeur), dans l'ordre de ses octets ([`PixelLayout`]) : une
//! couleur ([`ColorRef`], `0x00BBGGRR`) y devient un pixel par
//! [`PixelLayout::pixel`].
//!
//! Pas encore : les autres profondeurs (1, 4, 8, 16, 24 bits), BitBlt et
//! StretchBlt entre surfaces, les ROP, les motifs, l'alpha, les lignes.

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

/// Une surface de 32 bits par pixel : `width` × `height` pixels, `stride`
/// par ligne, dans `pixels`.
pub struct Bitmap<'a> {
    pixels: &'a mut [u32],
    width: u32,
    height: u32,
    stride: u32,
    layout: PixelLayout,
}

impl<'a> Bitmap<'a> {
    /// La surface de `pixels`. `None` si `stride` est plus petit que
    /// `width` ou si `pixels` ne tient pas `height` lignes.
    pub fn new(pixels: &'a mut [u32], width: u32, height: u32, stride: u32, layout: PixelLayout) -> Option<Self> {
        let needed = (stride as usize).checked_mul(height.saturating_sub(1) as usize)?.checked_add(width as usize)?;
        if stride < width || (height > 0 && pixels.len() < needed) {
            return None;
        }
        Some(Self { pixels, width, height, stride, layout })
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
        (x < self.width && y < self.height).then(|| self.pixels[(y * self.stride + x) as usize])
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
            let row = (y * self.stride) as usize;
            self.pixels[row + rect.left as usize..row + rect.right as usize].fill(pixel);
        }
    }
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
    fn a_surface_must_hold_its_rows() {
        let mut pixels = [0u32; 10];
        assert!(Bitmap::new(&mut pixels, 4, 3, 4, PixelLayout::Bgrx).is_none(), "12 pixels needed");
        assert!(Bitmap::new(&mut pixels, 4, 2, 3, PixelLayout::Bgrx).is_none(), "a stride under the width");
        assert!(Bitmap::new(&mut pixels, 4, 2, 6, PixelLayout::Bgrx).is_some(), "the last row needs no padding");
    }
}
