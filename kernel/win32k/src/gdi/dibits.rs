//! StretchDIBits (NtGdiStretchDIBitsInternal ; `dibobj.c` de ReactOS, comme
//! spécification) : une DIB que l'appelant donne — son en-tête, sa table de
//! couleurs, ses lignes — peinte, étirée ou réduite, dans un rectangle d'un
//! DC. C'est ainsi que `user32` fait les bitmaps d'un curseur ou d'une
//! icône (CURSORICON_GetCursorDataFromBMI : la ressource dans un bitmap
//! compatible, son masque dans un bitmap monochrome).
//!
//! La DIB est lue en couleurs ([`Dib::decode`]) : un en-tête BITMAPINFOHEADER
//! (ou plus long : V4, V5) ou BITMAPCOREHEADER, 1, 4 ou 8 bits par pixel avec
//! leur table (RGBQUAD, ou RGBTRIPLE après un BITMAPCOREHEADER), 16 bits
//! (5-5-5), 24 ou 32 bits, sans compression ou, en 16 et 32 bits, avec les
//! masques de BI_BITFIELDS (derrière un BITMAPINFOHEADER, ou dans un en-tête
//! V4 ou V5 : les bitmaps de la barre d'outils de `comctl32`) ; les lignes
//! alignées sur 32 bits,
//! montant depuis celle du bas si la hauteur est positive. Chaque pixel de la
//! destination prend celui de la source qui lui répond (le plus proche, sans
//! moyenne : STRETCH_DELETESCANS). Sur un bitmap monochrome, une couleur
//! devient le noir ou le blanc le plus proche (la table de deux couleurs du
//! bitmap).
//!
//! Le point de la source se compte depuis le coin en haut à gauche de
//! l'image, quel que soit le sens de ses lignes.
//!
//! GetDIBits (NtGdiGetDIBitsInternal, GreGetDIBitsInternal) fait l'inverse :
//! des lignes d'un bitmap en DIB de 1 bit (noir 0, blanc 1, la table de deux
//! couleurs) ou de 32 bits (l'octet haut tel que le bitmap le garde : l'alpha
//! d'une DIB section), comptées depuis le bas du bitmap ([`scan_window`],
//! [`encode_lines`]). C'est ce que la liste d'images de `comctl32` lit des
//! copies des bitmaps d'une icône (ImageList_ReplaceIcon, add_with_alpha).
//!
//! Pas encore : les ROP autres que SRCCOPY, DIB_PAL_COLORS, les compressions
//! (RLE, JPEG, PNG), les étendues négatives (l'image retournée), les DC
//! transformés, l'alpha d'une DIB de 32 bits (perdu : les icônes de 32 bits
//! se dessinent par leurs masques) ; la conversion vers le monochrome se fait
//! couleur par couleur, sans la couleur de fond du DC.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::{BitmapInfoHeader32, BI_BITFIELDS, BI_RGB, DIB_RGB_COLORS};
use abi::winerror::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_PARAMETER};

use super::dc;
use super::dib::{ColorRef, Rect};

/// La taille d'un BITMAPCOREHEADER.
const CORE_HEADER_SIZE: u32 = 12;
/// Une DIB a au plus 16 384 pixels de côté.
const MAX_SIDE: u32 = 16_384;

/// Ce qu'est une DIB, tiré de son en-tête et de sa table de couleurs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DibFormat {
    pub width: u32,
    pub height: u32,
    /// Ses lignes montent depuis celle du bas (une hauteur positive).
    pub bottom_up: bool,
    pub bit_count: u16,
    /// Les couleurs de ses index (1, 4 et 8 bits).
    pub palette: Vec<ColorRef>,
    /// Les masques du rouge, du vert et du bleu de BI_BITFIELDS (16 et 32
    /// bits) ; sans eux, 5-5-5 et BGRX.
    pub masks: Option<[u32; 3]>,
}

/// Une composante de `pixel` sous `mask`, ramenée à 8 bits.
fn channel(pixel: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let max = mask >> shift;
    (u64::from((pixel & mask) >> shift) * 255 / u64::from(max)) as u8
}

impl DibFormat {
    /// DIB_GetBitmapInfo et la table de couleurs : la DIB de `info` (un
    /// BITMAPINFO, en-tête et table), pour `usage`. `Err` : l'erreur de Win32,
    /// `ERROR_INVALID_PARAMETER` pour un en-tête trop court ou invalide, une
    /// table qui ne tient pas ; `ERROR_CALL_NOT_IMPLEMENTED` pour ce que le
    /// moteur ne lit pas encore (une compression, DIB_PAL_COLORS), journalisé
    /// une fois.
    pub fn parse(info: &[u8], usage: u32) -> Result<Self, u32> {
        let size = read_u32(info, 0).ok_or(ERROR_INVALID_PARAMETER)?;
        let (width, height, planes, bit_count, compression, colors, entry) = if size == CORE_HEADER_SIZE {
            let half = |at| read_u16(info, at).ok_or(ERROR_INVALID_PARAMETER);
            let bit_count = half(10)?;
            (i32::from(half(4)?), i32::from(half(6)?), half(8)?, bit_count, BI_RGB, 0, 3usize)
        } else {
            let header = BitmapInfoHeader32::from_bytes(info).filter(|_| size >= 40).ok_or(ERROR_INVALID_PARAMETER)?;
            (header.width, header.height, header.planes, header.bit_count, header.compression, header.clr_used, 4)
        };
        if width <= 0 || height == 0 || height == i32::MIN || planes != 1 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let (width, abs_height) = (width as u32, height.unsigned_abs());
        if width > MAX_SIDE || abs_height > MAX_SIDE {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let bitfields = compression == BI_BITFIELDS && matches!(bit_count, 16 | 32) && size != CORE_HEADER_SIZE;
        if (compression != BI_RGB && !bitfields) || usage != DIB_RGB_COLORS {
            if !COMPRESSION_REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "win32k: StretchDIBits of a DIB of {bit_count} bits, compression {compression}, usage {usage}: not yet"
                );
            }
            return Err(ERROR_CALL_NOT_IMPLEMENTED);
        }
        // The masks follow a BITMAPINFOHEADER, and are where a V4 or V5
        // header has them: from byte 40 either way.
        let masks = if bitfields {
            let mask = |at| read_u32(info, at).ok_or(ERROR_INVALID_PARAMETER);
            Some([mask(40)?, mask(44)?, mask(48)?])
        } else {
            None
        };
        let palette_size = match bit_count {
            1 | 4 | 8 => {
                let full = 1u32 << bit_count;
                if colors == 0 || colors > full {
                    full
                } else {
                    colors
                }
            }
            16 | 24 | 32 => 0,
            _ => return Err(ERROR_INVALID_PARAMETER),
        };
        let start = size as usize;
        let mut palette = Vec::with_capacity(palette_size as usize);
        for index in 0..palette_size as usize {
            let at = start + index * entry;
            let bytes = info.get(at..at + entry).ok_or(ERROR_INVALID_PARAMETER)?;
            palette.push(ColorRef::rgb(bytes[2], bytes[1], bytes[0]));
        }
        Ok(Self { width, height: abs_height, bottom_up: height > 0, bit_count, palette, masks })
    }

    /// Les octets d'une de ses lignes, alignés sur 32 bits.
    pub fn stride(&self) -> usize {
        (self.width as usize * usize::from(self.bit_count)).div_ceil(32) * 4
    }

    /// Les octets de ses lignes, toutes.
    pub fn bits_size(&self) -> usize {
        self.stride() * self.height as usize
    }
}

/// Une DIB lue : ses pixels en couleurs, la ligne du haut d'abord.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dib {
    pub width: u32,
    pub height: u32,
    pixels: Vec<ColorRef>,
}

impl Dib {
    /// Les pixels de `format` dans `bits` ; `None` si `bits` ne tient pas
    /// ses lignes, ou qu'un index sort de sa table.
    pub fn decode(format: &DibFormat, bits: &[u8]) -> Option<Self> {
        let (width, height, stride) = (format.width as usize, format.height as usize, format.stride());
        if bits.len() < format.bits_size() {
            return None;
        }
        let mut pixels = Vec::with_capacity(width * height);
        for y in 0..height {
            let line = if format.bottom_up { height - 1 - y } else { y };
            let row = &bits[line * stride..line * stride + stride];
            for x in 0..width {
                let color = match format.bit_count {
                    1 | 4 | 8 => {
                        let depth = usize::from(format.bit_count);
                        let bit = x * depth;
                        let index = (row[bit / 8] >> (8 - depth - bit % 8)) & ((1u16 << depth) - 1) as u8;
                        *format.palette.get(usize::from(index))?
                    }
                    16 | 32 if format.masks.is_some() => {
                        let [red, green, blue] = format.masks.unwrap_or_default();
                        let pixel = if format.bit_count == 16 {
                            u32::from(u16::from_le_bytes([row[2 * x], row[2 * x + 1]]))
                        } else {
                            u32::from_le_bytes([row[4 * x], row[4 * x + 1], row[4 * x + 2], row[4 * x + 3]])
                        };
                        ColorRef::rgb(channel(pixel, red), channel(pixel, green), channel(pixel, blue))
                    }
                    16 => {
                        let word = u16::from_le_bytes([row[2 * x], row[2 * x + 1]]);
                        let five = |shift: u16| {
                            let value = ((word >> shift) & 0x1F) as u8;
                            (value << 3) | (value >> 2)
                        };
                        ColorRef::rgb(five(10), five(5), five(0))
                    }
                    24 => ColorRef::rgb(row[3 * x + 2], row[3 * x + 1], row[3 * x]),
                    _ => ColorRef::rgb(row[4 * x + 2], row[4 * x + 1], row[4 * x]),
                };
                pixels.push(color);
            }
        }
        Some(Self { width: format.width, height: format.height, pixels })
    }

    /// Le pixel en (`x`, `y`), depuis le coin en haut à gauche.
    pub fn pixel(&self, x: u32, y: u32) -> Option<ColorRef> {
        (x < self.width && y < self.height).then(|| self.pixels[y as usize * self.width as usize + x as usize])
    }
}

/// Le pixel de la source qui répond à la colonne (ou la ligne) `at` d'une
/// destination de `extent` pixels, d'une source de `source` pixels qui
/// commence à `start`.
pub fn source_of(at: i32, extent: i32, start: i32, source: i32) -> i32 {
    start + ((i64::from(at) * i64::from(source)) / i64::from(extent)) as i32
}

/// Le noir ou le blanc le plus proche de `color` (la table d'un bitmap
/// monochrome) : le blanc dès que la somme des composantes passe la moitié.
pub fn to_monochrome(color: ColorRef) -> ColorRef {
    let (r, g, b) = color.components();
    if u32::from(r) + u32::from(g) + u32::from(b) >= 3 * 128 {
        ColorRef::rgb(255, 255, 255)
    } else {
        ColorRef::rgb(0, 0, 0)
    }
}

static COMPRESSION_REPORTED: AtomicBool = AtomicBool::new(false);
static ROP_REPORTED: AtomicBool = AtomicBool::new(false);
static NEGATIVE_REPORTED: AtomicBool = AtomicBool::new(false);

fn not_yet(reported: &AtomicBool, what: &str) {
    if !reported.swap(true, Ordering::Relaxed) {
        log::warn!("win32k: StretchDIBits of {what}: not yet");
    }
}

/// NtGdiStretchDIBitsInternal : le rectangle `src` (`x`, `y`, largeur,
/// hauteur) de `dib` peint dans le rectangle `dst` du DC `hdc`, là où il
/// peint, par le ROP `rop`. Rend le nombre de lignes de la source ; `Ok(0)`
/// pour un DC qui n'est pas au processus (sans erreur, comme ReactOS).
/// `Err` : l'erreur de Win32, `ERROR_CALL_NOT_IMPLEMENTED` pour un ROP
/// autre que SRCCOPY ou une étendue négative (journalisé une fois).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn stretch_dibits(
    hdc: u32,
    (x, y, width, height): (i32, i32, i32, i32),
    (x_src, y_src, width_src, height_src): (i32, i32, i32, i32),
    dib: &Dib,
    rop: u32,
) -> Result<i32, u32> {
    if rop != abi::gdi::rop::SRCCOPY {
        not_yet(&ROP_REPORTED, "another ROP than SRCCOPY");
        return Err(ERROR_CALL_NOT_IMPLEMENTED);
    }
    if width < 0 || height < 0 || width_src < 0 || height_src < 0 {
        not_yet(&NEGATIVE_REPORTED, "a negative extent (a mirrored image)");
        return Err(ERROR_CALL_NOT_IMPLEMENTED);
    }
    let Some(dc) = dc::lock(hdc) else { return Ok(0) };
    if width == 0 || height == 0 || width_src == 0 || height_src == 0 {
        return Ok(0);
    }
    let state = dc.state();
    let monochrome = state.bitmap.as_ref().is_some_and(|selected| selected.surface.is_monochrome());
    let (ox, oy) = dc::logical_origin(&state, None);
    let left = x.saturating_add(ox);
    let top = y.saturating_add(oy);
    let rect = Rect::new(left, top, left.saturating_add(width), top.saturating_add(height));
    let clip: Vec<Rect> = state.rao().rects().iter().map(|visible| visible.intersect(&rect)).collect();
    state.draw(|surface| {
        let layout = surface.layout();
        for part in clip.iter().filter(|part| !part.is_empty()) {
            let part = part.intersect(&surface.bounds());
            for py in part.top..part.bottom {
                let sy = source_of(py - top, height, y_src, height_src);
                for px in part.left..part.right {
                    let sx = source_of(px - left, width, x_src, width_src);
                    let (Ok(sx), Ok(sy)) = (u32::try_from(sx), u32::try_from(sy)) else { continue };
                    let Some(color) = dib.pixel(sx, sy) else { continue };
                    let color = if monochrome { to_monochrome(color) } else { color };
                    surface.set_pixel(px as u32, py as u32, layout.pixel(color));
                }
            }
        }
    });
    Ok(height_src)
}

/// GetDIBits sait rendre une DIB de `bit_count` bits par pixel : 1 ou 32.
pub const fn encodes(bit_count: u16) -> bool {
    matches!(bit_count, 1 | 32)
}

/// Les octets d'une ligne de `width` pixels de `bit_count` bits, alignée
/// sur 32 bits (DIB_GetDIBWidthBytes).
pub fn dib_stride(width: u32, bit_count: u16) -> usize {
    (width as usize * usize::from(bit_count)).div_ceil(32) * 4
}

/// GreGetDIBitsInternal, les lignes copiées : pour un bitmap de
/// `bitmap_height` lignes et une DIB de `dib_height` lignes, les `lines`
/// lignes à partir de `start` (comptées depuis le bas de la DIB) ; rend la
/// ligne du bitmap (depuis le haut, négative au-dessus de lui) où commence
/// le bloc copié, et le nombre de lignes. `None` si `start` passe la DIB.
/// Une DIB moins haute que le bitmap en prend le haut : ReactOS ajoute à
/// `start` la différence des hauteurs.
pub fn scan_window(bitmap_height: u32, dib_height: u32, start: u32, lines: u32) -> Option<(i64, u32)> {
    if start >= dib_height {
        return None;
    }
    let lines = lines.min(dib_height - start);
    let start = if dib_height < bitmap_height { start + (bitmap_height - dib_height) } else { start };
    Some((i64::from(bitmap_height) - i64::from(start) - i64::from(lines), lines))
}

/// Les octets de `lines` lignes, à partir de la ligne `top` (depuis le haut)
/// d'un bitmap de `width` × `height` pixels de 32 bits (`pixels`, la ligne du
/// haut d'abord), en DIB de `dib_width` pixels de `bit_count` bits (1 ou 32 :
/// [`encodes`]), la ligne du bas d'abord sauf `top_down`. Hors du bitmap, des
/// zéros. En 1 bit, le blanc le plus proche (`to_monochrome`) donne 1.
pub fn encode_lines(
    pixels: &[u32],
    (width, height): (u32, u32),
    top: i64,
    lines: u32,
    dib_width: u32,
    bit_count: u16,
    top_down: bool,
) -> Vec<u8> {
    let stride = dib_stride(dib_width, bit_count);
    let mut bytes = alloc::vec![0u8; stride * lines as usize];
    let layout = super::dib::PixelLayout::Bgrx;
    for line in 0..lines as usize {
        let row = if top_down { line } else { lines as usize - 1 - line };
        let y = top + row as i64;
        if y < 0 || y >= i64::from(height) {
            continue;
        }
        let source = &pixels[y as usize * width as usize..][..width as usize];
        let out = &mut bytes[line * stride..][..stride];
        for (x, &raw) in source.iter().enumerate().take(dib_width as usize) {
            match bit_count {
                1 => {
                    if to_monochrome(layout.color(raw)) == ColorRef::rgb(255, 255, 255) {
                        out[x / 8] |= 0x80 >> (x % 8);
                    }
                }
                _ => out[4 * x..4 * x + 4].copy_from_slice(&raw.to_le_bytes()),
            }
        }
    }
    bytes
}

/// Ce que GetDIBits rend : le nombre de lignes, l'en-tête rempli, ce qui le
/// suit (la table de deux couleurs d'une DIB de 1 bit, les masques de
/// BI_BITFIELDS), et les lignes si l'appelant en veut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DibBits {
    pub lines: u32,
    pub header: BitmapInfoHeader32,
    pub after_header: Vec<u8>,
    pub bits: Option<Vec<u8>>,
}

static GET_DEPTH_REPORTED: AtomicBool = AtomicBool::new(false);

/// GreGetDIBitsInternal : les lignes `start..start + lines` (depuis le bas de
/// la DIB) du bitmap `hbm` (au processus courant ou public) dans la DIB que
/// décrit `header`, si `want_bits` ; le DC `hdc` doit être au processus. Un
/// en-tête de 0 bit par pixel ne demande que la description du bitmap (sa
/// taille, sa profondeur, BI_BITFIELDS en 32 bits ; la hauteur négative d'une
/// DIB section descendante) et rend sa hauteur. Sans `want_bits`, l'en-tête
/// et la table remplis, `lines` rendu tel quel, comme ReactOS. `Err` :
/// l'erreur de Win32 à poser, 0 pour aucune (un DC ou un bitmap qui n'est
/// pas au processus, un en-tête incohérent) ; `ERROR_CALL_NOT_IMPLEMENTED`
/// pour une autre profondeur que 1 ou 32 bits (journalisé une fois).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn get_dibits(
    hdc: u32,
    hbm: u32,
    mut header: BitmapInfoHeader32,
    start: u32,
    lines: u32,
    want_bits: bool,
) -> Result<DibBits, u32> {
    if dc::lock(hdc).is_none() {
        return Err(0);
    }
    let pid = dc::current_pid();
    let Some(surface) = super::surface::lock(hbm, pid) else { return Err(0) };
    if header.size < 40 {
        not_yet(&GET_DEPTH_REPORTED, "GetDIBits into a BITMAPCOREHEADER");
        return Err(ERROR_INVALID_PARAMETER);
    }
    if header.width < 0 || (header.bit_count == 0 && want_bits) {
        return Err(0);
    }
    let consistent = header.height != 0 && header.width != 0 && matches!(header.compression, BI_RGB | BI_BITFIELDS);
    if (want_bits || header.bit_count != 0) && !consistent {
        return Err(0);
    }
    let (width, height) = surface.size();
    let depth: u16 = if surface.is_monochrome() { 1 } else { 32 };
    header.clr_used = 0;
    header.clr_important = 0;
    if header.bit_count == 0 {
        let top_down = surface.user_bits(pid).is_some() && !surface.is_bottom_up();
        header.width = width as i32;
        header.height = if top_down { -(height as i32) } else { height as i32 };
        header.planes = 1;
        header.bit_count = depth;
        header.size_image = (dib_stride(width, depth) * height as usize) as u32;
        header.compression = if depth == 32 { BI_BITFIELDS } else { BI_RGB };
        header.x_pels_per_meter = 0;
        header.y_pels_per_meter = 0;
        if depth == 1 {
            header.clr_used = 2;
        }
        return Ok(DibBits { lines: height, header, after_header: Vec::new(), bits: None });
    }
    if !encodes(header.bit_count) {
        if !GET_DEPTH_REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!("win32k: GetDIBits of {} bits per pixel: not yet", header.bit_count);
        }
        return Err(ERROR_CALL_NOT_IMPLEMENTED);
    }
    let after_header = match (header.bit_count, header.compression) {
        (1, _) => alloc::vec![0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0],
        (32, BI_BITFIELDS) => {
            [0x00FF_0000u32, 0x0000_FF00, 0x0000_00FF].iter().flat_map(|mask| mask.to_le_bytes()).collect()
        }
        _ => Vec::new(),
    };
    let dib_height = header.height.unsigned_abs();
    header.size_image = (dib_stride(header.width as u32, header.bit_count) * dib_height as usize) as u32;
    if !want_bits || lines == 0 {
        return Ok(DibBits { lines, header, after_header, bits: None });
    }
    let Some((top, count)) = scan_window(height, dib_height, start, lines) else {
        // As ReactOS: a start past the DIB copies nothing and gives 1.
        return Ok(DibBits { lines: 1, header, after_header, bits: None });
    };
    let Some(pixels) = surface.raw_pixels() else { return Err(0) };
    let bits =
        encode_lines(&pixels, (width, height), top, count, header.width as u32, header.bit_count, header.height < 0);
    Ok(DibBits { lines: count, header, after_header, bits: Some(bits) })
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un BITMAPINFOHEADER de `width` × `height`, `bit_count` bits, suivi de
    /// la table `palette` (RGBQUAD).
    fn info(width: i32, height: i32, bit_count: u16, palette: &[ColorRef]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&40u32.to_le_bytes());
        bytes.extend_from_slice(&width.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&bit_count.to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&(palette.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        for color in palette {
            let (r, g, b) = color.components();
            bytes.extend_from_slice(&[b, g, r, 0]);
        }
        bytes
    }

    const BLACK: ColorRef = ColorRef::rgb(0, 0, 0);
    const WHITE: ColorRef = ColorRef::rgb(255, 255, 255);

    #[test]
    fn a_monochrome_dib_reads_from_the_bottom_line_up() {
        let format = DibFormat::parse(&info(3, 2, 1, &[BLACK, WHITE]), DIB_RGB_COLORS).expect("valid");
        assert_eq!((format.width, format.height, format.bottom_up, format.stride()), (3, 2, true, 4));
        // The bottom line first in memory: 1 0 1, then the top one: 0 1 0.
        let bits = [0b1010_0000, 0, 0, 0, 0b0100_0000, 0, 0, 0];
        let dib = Dib::decode(&format, &bits).expect("enough bits");
        assert_eq!([dib.pixel(0, 0), dib.pixel(1, 0), dib.pixel(2, 0)], [Some(BLACK), Some(WHITE), Some(BLACK)]);
        assert_eq!([dib.pixel(0, 1), dib.pixel(1, 1), dib.pixel(2, 1)], [Some(WHITE), Some(BLACK), Some(WHITE)]);
        assert_eq!(dib.pixel(3, 0), None);
        assert_eq!(Dib::decode(&format, &bits[..7]), None, "a line short");
    }

    #[test]
    fn palettes_and_direct_colors() {
        let red = ColorRef::rgb(255, 0, 0);
        let format = DibFormat::parse(&info(2, -1, 4, &[BLACK, red]), DIB_RGB_COLORS).expect("valid");
        assert!(!format.bottom_up);
        assert_eq!(Dib::decode(&format, &[0x10, 0, 0, 0]).and_then(|dib| dib.pixel(0, 0)), Some(red));
        let format = DibFormat::parse(&info(2, -1, 4, &[BLACK, red]), DIB_RGB_COLORS).expect("valid");
        assert_eq!(Dib::decode(&format, &[0x20, 0, 0, 0]), None, "an index past the table");
        let format = DibFormat::parse(&info(1, 1, 24, &[]), DIB_RGB_COLORS).expect("valid");
        assert_eq!(
            Dib::decode(&format, &[0x30, 0x20, 0x10, 0]).and_then(|dib| dib.pixel(0, 0)),
            Some(ColorRef::rgb(0x10, 0x20, 0x30))
        );
        let format = DibFormat::parse(&info(1, 1, 32, &[]), DIB_RGB_COLORS).expect("valid");
        assert_eq!(
            Dib::decode(&format, &[1, 2, 3, 0xFF]).and_then(|dib| dib.pixel(0, 0)),
            Some(ColorRef::rgb(3, 2, 1))
        );
        let format = DibFormat::parse(&info(1, 1, 16, &[]), DIB_RGB_COLORS).expect("valid");
        assert_eq!(Dib::decode(&format, &[0x00, 0x7C, 0, 0]).and_then(|dib| dib.pixel(0, 0)), Some(red), "5-5-5");
        let gray: Vec<ColorRef> = (0..=255).map(|level| ColorRef::rgb(level, level, level)).collect();
        let mut full = info(1, 1, 8, &gray);
        full[32..36].copy_from_slice(&0u32.to_le_bytes()); // biClrUsed 0: the full table.
        let format = DibFormat::parse(&full, DIB_RGB_COLORS).expect("a full table implied");
        assert_eq!((format.palette.len(), format.palette[200]), (256, ColorRef::rgb(200, 200, 200)));
        assert_eq!(DibFormat::parse(&info(1, 1, 8, &[]), DIB_RGB_COLORS), Err(ERROR_INVALID_PARAMETER), "no table");
    }

    #[test]
    fn a_core_header_has_triples() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0xFF, 0xFF, 0xFF]);
        let format = DibFormat::parse(&bytes, DIB_RGB_COLORS).expect("valid");
        assert_eq!(format.palette, [BLACK, WHITE]);
    }

    #[test]
    fn bitfields_give_their_masks() {
        // A V4 header (108 bytes), 32 bits, BI_BITFIELDS: the masks at 40.
        let mut v4 = info(1, 1, 32, &[]);
        v4[0..4].copy_from_slice(&108u32.to_le_bytes());
        v4[16..20].copy_from_slice(&BI_BITFIELDS.to_le_bytes());
        v4.resize(108, 0);
        for (at, mask) in [(40, 0x00FF_0000u32), (44, 0x0000_FF00), (48, 0x0000_00FF), (52, 0xFF00_0000)] {
            v4[at..at + 4].copy_from_slice(&mask.to_le_bytes());
        }
        let format = DibFormat::parse(&v4, DIB_RGB_COLORS).expect("a V4 header with its masks");
        assert_eq!(format.masks, Some([0x00FF_0000, 0x0000_FF00, 0x0000_00FF]));
        assert_eq!(
            Dib::decode(&format, &[0x30, 0x20, 0x10, 0x80]).and_then(|dib| dib.pixel(0, 0)),
            Some(ColorRef::rgb(0x10, 0x20, 0x30))
        );
        // A BITMAPINFOHEADER followed by 5-6-5 masks, 16 bits.
        let mut rgb565 = info(1, 1, 16, &[]);
        rgb565[16..20].copy_from_slice(&BI_BITFIELDS.to_le_bytes());
        for mask in [0xF800u32, 0x07E0, 0x001F] {
            rgb565.extend_from_slice(&mask.to_le_bytes());
        }
        let format = DibFormat::parse(&rgb565, DIB_RGB_COLORS).expect("three masks after the header");
        let green = Dib::decode(&format, &[0xE0, 0x07, 0, 0]).and_then(|dib| dib.pixel(0, 0));
        assert_eq!(green, Some(ColorRef::rgb(0, 255, 0)), "six bits of green");
        assert_eq!(DibFormat::parse(&rgb565[..48], DIB_RGB_COLORS), Err(ERROR_INVALID_PARAMETER), "a mask short");
        let mut indexed = info(1, 1, 8, &[BLACK]);
        indexed[16..20].copy_from_slice(&BI_BITFIELDS.to_le_bytes());
        assert_eq!(DibFormat::parse(&indexed, DIB_RGB_COLORS), Err(ERROR_CALL_NOT_IMPLEMENTED), "8 bits: no masks");
    }

    #[test]
    fn what_the_engine_refuses() {
        assert_eq!(DibFormat::parse(&info(0, 1, 32, &[]), DIB_RGB_COLORS), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(DibFormat::parse(&info(1, 1, 7, &[]), DIB_RGB_COLORS), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(DibFormat::parse(&info(1, 1, 32, &[])[..39], DIB_RGB_COLORS), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(DibFormat::parse(&info(1, 1, 1, &[BLACK]), DIB_RGB_COLORS).map(|f| f.palette.len()), Ok(1));
        let short = info(1, 1, 1, &[BLACK, WHITE]);
        let mut cut = short.clone();
        cut.truncate(short.len() - 1);
        assert_eq!(DibFormat::parse(&cut, DIB_RGB_COLORS), Err(ERROR_INVALID_PARAMETER), "the table does not fit");
        assert_eq!(DibFormat::parse(&info(1, 1, 32, &[]), abi::gdi::DIB_PAL_COLORS), Err(ERROR_CALL_NOT_IMPLEMENTED));
    }

    #[test]
    fn stretching_takes_the_nearest_source_pixel() {
        // Twice as wide: each source column twice.
        assert_eq!((0..4).map(|x| source_of(x, 4, 0, 2)).collect::<Vec<_>>(), [0, 0, 1, 1]);
        // Half as wide: every other column.
        assert_eq!((0..2).map(|x| source_of(x, 2, 10, 4)).collect::<Vec<_>>(), [10, 12]);
        assert_eq!(source_of(31, 32, 0, 32), 31, "the same size: the same pixel");
    }

    #[test]
    fn get_dibits_counts_its_lines_from_the_bottom() {
        assert_eq!(scan_window(16, 16, 0, 16), Some((0, 16)), "all of it");
        assert_eq!(scan_window(16, 16, 0, 100), Some((0, 16)), "no more lines than the DIB");
        assert_eq!(scan_window(16, 16, 4, 2), Some((10, 2)), "the 5th and 6th from the bottom");
        assert_eq!(scan_window(32, 16, 0, 16), Some((0, 16)), "a lower DIB: the bitmap's top half, as ReactOS");
        assert_eq!(scan_window(16, 16, 16, 1), None, "past the DIB");
    }

    #[test]
    fn get_dibits_encodes_one_and_thirty_two_bits() {
        // 2 x 2, top row white then red, bottom row black then gray; the high
        // byte of the red pixel is its alpha.
        let (white, red, black, gray) = (0x00FF_FFFF, 0x80FF_0000, 0, 0x0040_4040);
        let pixels = [white, red, black, gray];
        let bottom_up = encode_lines(&pixels, (2, 2), 0, 2, 2, 32, false);
        assert_eq!(bottom_up.len(), 16);
        assert_eq!(&bottom_up[..8], &[0, 0, 0, 0, 0x40, 0x40, 0x40, 0], "the bottom line first");
        assert_eq!(&bottom_up[8..], &[0xFF, 0xFF, 0xFF, 0, 0, 0, 0xFF, 0x80], "BGRA, the alpha kept");
        let top_down = encode_lines(&pixels, (2, 2), 0, 2, 2, 32, true);
        assert_eq!(&top_down[..8], &bottom_up[8..], "the top line first");
        let mono = encode_lines(&pixels, (2, 2), 0, 2, 2, 1, false);
        assert_eq!(mono, [0b0000_0000, 0, 0, 0, 0b1000_0000, 0, 0, 0], "white is 1; lines of 4 bytes");
        let wider = encode_lines(&pixels, (2, 2), 0, 1, 3, 32, true);
        assert_eq!(wider.len(), 12);
        assert_eq!(&wider[8..], &[0, 0, 0, 0], "past the bitmap's width: zeros");
        let above = encode_lines(&pixels, (2, 2), -1, 2, 2, 32, true);
        assert_eq!(&above[..8], &[0; 8], "above the bitmap: zeros");
        assert_eq!(&above[8..12], &[0xFF, 0xFF, 0xFF, 0]);
        assert!(encodes(1) && encodes(32) && !encodes(24) && !encodes(4));
        assert_eq!((dib_stride(16, 1), dib_stride(33, 1), dib_stride(3, 32)), (4, 8, 12));
    }

    #[test]
    fn colors_become_black_or_white_on_a_monochrome_bitmap() {
        assert_eq!(to_monochrome(ColorRef::rgb(200, 200, 200)), WHITE);
        assert_eq!(to_monochrome(ColorRef::rgb(0, 0, 255)), BLACK);
        assert_eq!(to_monochrome(ColorRef::rgb(128, 128, 128)), WHITE, "the middle goes to white");
    }
}
