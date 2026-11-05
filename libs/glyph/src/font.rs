//! A TrueType or OpenType font, read by `ttf-parser` (0.21: later versions
//! need `core_maths` and `libm` without `std`, outside ADR-016): its metrics
//! at a size,
//! its glyphs and their advances, each glyph rendered to coverage by the
//! [`Rasterizer`].
//!
//! Sizes are em heights in pixels, 16.16 fixed point: what GDI derives from a
//! `LOGFONT` height (negative: the em height; positive: the cell height,
//! ascent plus descent). Metrics follow what GDI reads for TrueType fonts:
//! the Windows ascent and descent of the `OS/2` table, else those of `hhea`.
//! No hinting (ADR-013): outlines are scaled, then rendered with grayscale
//! antialiasing.

use alloc::vec::Vec;

use ttf_parser::cmap::Subtable;
use ttf_parser::name::PlatformId;
use ttf_parser::{Face, GlyphId, OutlineBuilder, Tag};

use crate::raster::{Point, Rasterizer, ONE};

/// Why a font was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a TrueType or OpenType font that `ttf-parser` reads.
    Malformed,
    /// An em of zero units.
    NoUnitsPerEm,
}

/// A parsed font, borrowing its file.
pub struct Font<'a> {
    face: Face<'a>,
    units_per_em: i64,
}

/// What GDI's TEXTMETRIC says of a font at a size, in whole pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    /// tmAscent: from the baseline up.
    pub ascent: i32,
    /// tmDescent: from the baseline down, positive.
    pub descent: i32,
    /// tmExternalLeading: the line gap above the cell.
    pub external_leading: i32,
    /// tmAveCharWidth: `OS/2` xAvgCharWidth, else the advance of `x`.
    pub average_width: i32,
}

impl Metrics {
    /// tmHeight: ascent plus descent.
    pub fn height(&self) -> i32 {
        self.ascent + self.descent
    }
}

/// The rest of what GDI's TEXTMETRIC says of a TrueType font at a size
/// (FillTM), as GDI computes it from the font's tables.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextMetrics {
    pub metrics: Metrics,
    /// tmInternalLeading: the cell above the em.
    pub internal_leading: i32,
    /// tmMaxCharWidth: `hhea` advanceWidthMax.
    pub max_width: i32,
    /// tmWeight: `OS/2` usWeightClass.
    pub weight: u16,
    /// tmFirstChar, tmLastChar, tmDefaultChar, tmBreakChar.
    pub first_char: u16,
    pub last_char: u16,
    pub default_char: u16,
    pub break_char: u16,
    /// tmPitchAndFamily: `TMPF_*` and `FF_*`.
    pub pitch_and_family: u8,
    /// A symbol font (its map is the symbol one): SYMBOL_CHARSET.
    pub symbol: bool,
}

/// TMPF_FIXED_PITCH: set for a font of variable pitch (the name is the
/// opposite of its meaning).
pub const TMPF_VARIABLE_PITCH: u8 = 0x01;
pub const TMPF_VECTOR: u8 = 0x02;
pub const TMPF_TRUETYPE: u8 = 0x04;
pub const FF_ROMAN: u8 = 0x10;
pub const FF_SWISS: u8 = 0x20;
pub const FF_MODERN: u8 = 0x30;
pub const FF_SCRIPT: u8 = 0x40;
pub const FF_DECORATIVE: u8 = 0x50;

/// A glyph rendered to coverage, placed against the pen: its top-left pixel
/// is `left` pixels right of the pen and `top` pixels above the baseline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bitmap {
    pub width: usize,
    pub height: usize,
    pub left: i32,
    pub top: i32,
    /// Row by row, 0 (uncovered) to 255 (covered).
    pub coverage: Vec<u8>,
}

impl<'a> Font<'a> {
    /// The font in `data` (the first of a collection).
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let face = Face::parse(data, 0).map_err(|_| Error::Malformed)?;
        let units_per_em = i64::from(face.units_per_em());
        if units_per_em == 0 {
            return Err(Error::NoUnitsPerEm);
        }
        Ok(Self { face, units_per_em })
    }

    /// unitsPerEm.
    pub fn units_per_em(&self) -> u16 {
        self.units_per_em as u16
    }

    /// The Windows ascent and descent (positive), in font units: those of
    /// `OS/2`, else `hhea`'s.
    pub fn windows_ascent_descent(&self) -> (i64, i64) {
        match self.face.tables().os2 {
            Some(os2) if os2.windows_ascender() != 0 || os2.windows_descender() != 0 => {
                (i64::from(os2.windows_ascender()), -i64::from(os2.windows_descender()))
            }
            _ => (i64::from(self.face.ascender()), -i64::from(self.face.descender())),
        }
    }

    /// The 16-bit big-endian word at `offset` of the table `tag`.
    fn table_u16(&self, tag: &[u8; 4], offset: usize) -> Option<u16> {
        let table = self.face.raw_face().table(Tag::from_bytes(tag))?;
        Some(u16::from_be_bytes([*table.get(offset)?, *table.get(offset + 1)?]))
    }

    /// xAvgCharWidth of the `OS/2` table, in font units: a 16-bit integer at
    /// offset 2.
    fn average_char_width(&self) -> Option<i64> {
        self.table_u16(b"OS/2", 2).map(|width| i64::from(width as i16))
    }

    /// The font has a symbol map (Windows, encoding 0): what FreeType calls
    /// a symbol charmap, which makes it a symbol font for GDI.
    fn is_symbol(&self) -> bool {
        let Some(cmap) = self.face.tables().cmap else { return false };
        cmap.subtables
            .into_iter()
            .any(|subtable| subtable.platform_id == PlatformId::Windows && subtable.encoding_id == 0)
    }

    /// FillTM: the TEXTMETRIC of the font at an em of `em` pixels (16.16).
    /// `OS/2`: usWeightClass (offset 4), the PANOSE family and serif style
    /// (32, 33), usFirstCharIndex and usLastCharIndex (64, 66); `hhea`:
    /// advanceWidthMax (10); `post`: isFixedPitch (12).
    pub fn text_metrics(&self, em: i64) -> TextMetrics {
        let metrics = self.metrics(em);
        let round = |v: i64| ((v + ONE / 2) >> 16) as i32;
        let (ascent, descent) = self.windows_ascent_descent();
        // (WinAscent + WinDescent - unitsPerEm), scaled: the cell above the em.
        let internal_leading = round(self.scale(ascent + descent - self.units_per_em, em)).max(0);
        let max_width = round(self.scale(i64::from(self.table_u16(b"hhea", 10).unwrap_or(0)), em));
        let weight = self.table_u16(b"OS/2", 4).unwrap_or(400);
        let symbol = self.is_symbol();
        let first = self.table_u16(b"OS/2", 64).unwrap_or(0x20);
        let last = self.table_u16(b"OS/2", 66).unwrap_or(0xFF);
        let (first_char, last_char, default_char, break_char) = if symbol || (0xF000..0xF100).contains(&first) {
            (0, 0xF0FF, 0x1F, 0x20)
        } else {
            let break_char = match first {
                0 | 1 => first + 2,
                0x100.. => 0x20,
                _ => first,
            };
            (first, last, break_char - 1, break_char)
        };
        let panose =
            |at: usize| self.face.raw_face().table(Tag::from_bytes(b"OS/2")).and_then(|t| t.get(32 + at).copied());
        let fixed = self
            .face
            .raw_face()
            .table(Tag::from_bytes(b"post"))
            .and_then(|t| t.get(12..16))
            .is_some_and(|b| b != [0; 4]);
        // PANOSE: proportion 9 is monospaced; family 2 is text (its serif
        // style says Swiss or Roman), 3 script, 4 decorative.
        let mut pitch_and_family = if fixed || panose(3) == Some(9) { 0 } else { TMPF_VARIABLE_PITCH };
        pitch_and_family |= match panose(0) {
            Some(3) => FF_SCRIPT,
            Some(4) => FF_DECORATIVE,
            _ if pitch_and_family == 0 => FF_MODERN,
            _ => match panose(1) {
                Some(11..=15) => FF_SWISS,
                _ => FF_ROMAN,
            },
        };
        TextMetrics {
            metrics,
            internal_leading,
            max_width,
            weight,
            first_char,
            last_char,
            default_char,
            break_char,
            pitch_and_family: pitch_and_family | TMPF_TRUETYPE | TMPF_VECTOR,
            symbol,
        }
    }

    /// The em height, 16.16, of a font whose cell (ascent plus descent) is
    /// `cell` pixels: a positive `LOGFONT` height.
    pub fn em_for_cell(&self, cell: u32) -> i64 {
        let (ascent, descent) = self.windows_ascent_descent();
        let units = (ascent + descent).max(1);
        i64::from(cell) * ONE * self.units_per_em / units
    }

    /// `units` font units at an em of `em` pixels (16.16), in 16.16 pixels.
    fn scale(&self, units: i64, em: i64) -> i64 {
        units * em / self.units_per_em
    }

    /// The metrics at an em of `em` pixels (16.16), rounded.
    pub fn metrics(&self, em: i64) -> Metrics {
        let (ascent, descent) = self.windows_ascent_descent();
        let round = |v: i64| ((v + ONE / 2) >> 16) as i32;
        let average = match self.average_char_width() {
            Some(width) if width > 0 => width,
            _ => self.glyph_index('x').and_then(|glyph| self.advance_units(glyph)).unwrap_or(0),
        };
        Metrics {
            ascent: round(self.scale(ascent, em)),
            descent: round(self.scale(descent, em)),
            external_leading: round(self.scale(i64::from(self.face.line_gap()).max(0), em)),
            average_width: round(self.scale(average, em)),
        }
    }

    /// The glyph of `c`, by the font's Unicode map, else by its symbol map
    /// (symbol fonts encode their glyphs in U+F000 to U+F0FF): `None`
    /// without one.
    pub fn glyph_index(&self, c: char) -> Option<u16> {
        if let Some(glyph) = self.face.glyph_index(c) {
            return Some(glyph.0);
        }
        let code = u32::from(c);
        let symbol = |subtable: &Subtable| subtable.platform_id == PlatformId::Windows && subtable.encoding_id == 0;
        let subtables = self.face.tables().cmap?.subtables;
        subtables
            .into_iter()
            .filter(symbol)
            .find_map(|subtable| subtable.glyph_index(code).or_else(|| subtable.glyph_index(0xF000 | (code & 0xFF))))
            .map(|glyph| glyph.0)
    }

    /// The advance of `glyph`, in font units.
    fn advance_units(&self, glyph: u16) -> Option<i64> {
        self.face.glyph_hor_advance(GlyphId(glyph)).map(i64::from)
    }

    /// The advance of `glyph` at an em of `em` pixels (16.16), in 16.16
    /// pixels; 0 for a glyph without one.
    pub fn advance(&self, glyph: u16, em: i64) -> i64 {
        self.advance_units(glyph).map_or(0, |units| self.scale(units, em))
    }

    /// `glyph` rendered at an em of `em` pixels (16.16): `None` for a glyph
    /// without an outline (a space).
    pub fn render(&self, glyph: u16, em: i64) -> Option<Bitmap> {
        let bounds = self.face.glyph_bounding_box(GlyphId(glyph))?;
        let scale = |units: i16| self.scale(i64::from(units), em);
        let left = (scale(bounds.x_min) >> 16) as i32;
        let right = ((scale(bounds.x_max) + ONE - 1) >> 16) as i32;
        let top = ((scale(bounds.y_max) + ONE - 1) >> 16) as i32;
        let bottom = (scale(bounds.y_min) >> 16) as i32;
        let (width, height) = ((right - left).max(1) as usize, (top - bottom).max(1) as usize);
        // Font units to bitmap pixels: scaled, from the bitmap's left and
        // its top, y downwards. The only float work: one factor per glyph.
        let factor = (em as f32) / (self.units_per_em as f32);
        let mut builder = Outline {
            raster: Rasterizer::new(width, height),
            factor,
            left: i64::from(left) * ONE,
            top: i64::from(top) * ONE,
        };
        self.face.outline_glyph(GlyphId(glyph), &mut builder)?;
        Some(Bitmap { width, height, left, top, coverage: builder.raster.coverage() })
    }
}

/// Feeds a glyph's outline, in font units, to the rasterizer.
struct Outline {
    raster: Rasterizer,
    /// 16.16 pixels per font unit.
    factor: f32,
    left: i64,
    top: i64,
}

impl Outline {
    fn point(&self, x: f32, y: f32) -> Point {
        Point::new((x * self.factor) as i64 - self.left, self.top - (y * self.factor) as i64)
    }
}

impl OutlineBuilder for Outline {
    fn move_to(&mut self, x: f32, y: f32) {
        let to = self.point(x, y);
        self.raster.move_to(to);
    }

    fn line_to(&mut self, x: f32, y: f32) {
        let to = self.point(x, y);
        self.raster.line_to(to);
    }

    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        let (control, to) = (self.point(x1, y1), self.point(x, y));
        self.raster.quad_to(control, to);
    }

    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let (control1, control2, to) = (self.point(x1, y1), self.point(x2, y2), self.point(x, y));
        self.raster.cubic_to(control1, control2, to);
    }

    fn close(&mut self) {
        self.raster.close();
    }
}
