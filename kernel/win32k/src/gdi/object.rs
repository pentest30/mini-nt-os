//! GreGetObject (NtGdiExtGetObjectW, GetObjectW) : ce qu'un objet GDI dit de
//! lui-même. Une police donne son LOGFONTW, suivi des noms et du vecteur de
//! dessin d'un ENUMLOGFONTEXDVW, à zéro (NtGdiHfontCreate ne garde que le
//! LOGFONTW, ce que CreateFontIndirectW de `gdi32` donne avec le reste à
//! zéro) ; un bitmap, son BITMAP, ou le DIBSECTION d'une DIB section qui a
//! la place. Sans tampon, la taille de la description (le LOGFONTW, le
//! BITMAP).
//!
//! Pas encore : pinceaux, stylos et palettes (0, journalisé une fois).

use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::{
    Bitmap32, BitmapInfoHeader32, DibSection32, LogFontW32, BI_RGB, ENUM_LOG_FONT_EX_DV_NO_AXES_SIZE,
    ENUM_LOG_FONT_EX_DV_SIZE,
};

use super::handles::{self, Object};
use super::surface::RGB_MASKS;

/// Le plus que NtGdiExtGetObjectW rend : la plus grande des descriptions,
/// un ENUMLOGFONTEXDVW.
pub const MAX_OBJECT_SIZE: u32 = ENUM_LOG_FONT_EX_DV_SIZE as u32;

/// GreGetObject : ce que l'objet `handle` (du processus `pid`, ou public) dit
/// de lui-même en `count` octets au plus. Rend la taille de sa description et,
/// si `data`, ses octets (autant que cette taille). 0 pour un handle inconnu,
/// un objet sans description ici, ou un bitmap sans la place d'un BITMAP.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get_object(handle: u32, pid: u32, count: u32, data: bool) -> (u32, Vec<u8>) {
    match handles::get(handle, pid) {
        Some(Object::Font(font)) => font_description(&font.logfont, count, data),
        Some(Object::Bitmap(surface)) => {
            // A DIB section is the bitmap whose pixels its process sees
            // (CreateBitmap's are in a section too, seen by the kernel only).
            let (width, height) = surface.size();
            let dib = surface.user_bits(pid);
            bitmap_description(width, height, surface.is_monochrome(), dib, count, data)
        }
        Some(_) => {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!("win32k: GetObject of a brush, a pen, a region or a DC: not yet");
            }
            (0, Vec::new())
        }
        None => (0, Vec::new()),
    }
}

/// FontGetObject : `logfont` en `count` octets au plus — le LOGFONTW, puis
/// le reste d'un ENUMLOGFONTEXDVW sans axes, à zéro ; sans `data`, la taille
/// d'un LOGFONTW.
pub fn font_description(logfont: &LogFontW32, count: u32, data: bool) -> (u32, Vec<u8>) {
    if !data {
        return (size_of::<LogFontW32>() as u32, Vec::new());
    }
    let mut bytes = logfont.as_bytes().to_vec();
    bytes.resize(ENUM_LOG_FONT_EX_DV_NO_AXES_SIZE, 0);
    bytes.truncate(count.min(ENUM_LOG_FONT_EX_DV_NO_AXES_SIZE as u32) as usize);
    (bytes.len() as u32, bytes)
}

/// BITMAP_GetObject : un bitmap de `width` × `height`, monochrome (un bit
/// par pixel) ou de 32 bits ; `dib`, pour une DIB section, l'adresse de ses
/// pixels chez l'appelant. Le BITMAP (ses lignes
/// alignées sur 16 bits, sur 32 pour une DIB section), ou le DIBSECTION
/// d'une DIB section si `count` le tient ; 0 si `count` ne tient pas un
/// BITMAP. Sans `data`, la taille d'un BITMAP.
pub fn bitmap_description(
    width: u32,
    height: u32,
    monochrome: bool,
    dib: Option<u32>,
    count: u32,
    data: bool,
) -> (u32, Vec<u8>) {
    if !data {
        return (size_of::<Bitmap32>() as u32, Vec::new());
    }
    if (count as usize) < size_of::<Bitmap32>() {
        return (0, Vec::new());
    }
    let bits_pixel: u16 = if monochrome { 1 } else { 32 };
    let row_bits = width * u32::from(bits_pixel);
    let width_bytes = if dib.is_some() { row_bits.div_ceil(32) * 4 } else { row_bits.div_ceil(16) * 2 };
    let bitmap = Bitmap32 {
        bm_type: 0,
        width: width as i32,
        height: height as i32,
        width_bytes: width_bytes as i32,
        planes: 1,
        bits_pixel,
        bits: dib.unwrap_or(0),
    };
    match dib {
        Some(_) if count as usize >= size_of::<DibSection32>() => {
            let section = DibSection32 {
                bitmap,
                header: BitmapInfoHeader32 {
                    size: size_of::<BitmapInfoHeader32>() as u32,
                    width: width as i32,
                    height: height as i32,
                    planes: 1,
                    bit_count: bits_pixel,
                    compression: BI_RGB,
                    size_image: width_bytes * height,
                    ..BitmapInfoHeader32::default()
                },
                bitfields: RGB_MASKS,
                section: 0,
                offset: 0,
            };
            (size_of::<DibSection32>() as u32, section.as_bytes().to_vec())
        }
        _ => (size_of::<Bitmap32>() as u32, bitmap.as_bytes().to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tahoma() -> LogFontW32 {
        let mut logfont = LogFontW32 { height: -11, weight: 700, char_set: 1, ..LogFontW32::default() };
        for (slot, unit) in logfont.face_name.iter_mut().zip("Tahoma".encode_utf16()) {
            *slot = unit;
        }
        logfont
    }

    #[test]
    fn a_font_gives_its_logfont_then_zeros() {
        let logfont = tahoma();
        assert_eq!(font_description(&logfont, 92, false), (92, Vec::new()), "no buffer: a LOGFONTW's size");
        let (size, bytes) = font_description(&logfont, 92, true);
        assert_eq!((size, &bytes[..]), (92, logfont.as_bytes()));
        let (size, bytes) = font_description(&logfont, MAX_OBJECT_SIZE, true);
        assert_eq!(size, 356, "an ENUMLOGFONTEXDVW without axes, not its 16 values");
        assert_eq!(&bytes[..92], logfont.as_bytes());
        assert!(bytes[92..].iter().all(|&b| b == 0), "the names and the design vector");
        assert_eq!(font_description(&logfont, 10, true), (10, logfont.as_bytes()[..10].to_vec()), "what fits");
    }

    #[test]
    fn a_bitmap_gives_its_bitmap_or_its_dibsection() {
        assert_eq!(bitmap_description(43, 13, true, None, 0, false).0, 24, "no buffer: a BITMAP's size");
        assert_eq!(bitmap_description(43, 13, true, None, 23, true), (0, Vec::new()), "no room for a BITMAP");
        // A monochrome DDB: rows of 16-bit words, no bits.
        let (size, bytes) = bitmap_description(43, 13, true, None, 84, true);
        let mono = Bitmap32 { width: 43, height: 13, width_bytes: 6, planes: 1, bits_pixel: 1, ..Bitmap32::default() };
        assert_eq!((size, &bytes[..]), (24, mono.as_bytes()));
        // A DIB section: rows of 32-bit words, its bits; the DIBSECTION with
        // room for it.
        let (size, bytes) = bitmap_description(3, 2, false, Some(0x0050_0000), 24, true);
        let bitmap =
            Bitmap32 { width: 3, height: 2, width_bytes: 12, planes: 1, bits_pixel: 32, bits: 0x0050_0000, bm_type: 0 };
        assert_eq!((size, &bytes[..]), (24, bitmap.as_bytes()), "a BITMAP when only it fits");
        let (size, bytes) = bitmap_description(3, 2, false, Some(0x0050_0000), MAX_OBJECT_SIZE, true);
        let header = BitmapInfoHeader32 {
            size: 40,
            width: 3,
            height: 2,
            planes: 1,
            bit_count: 32,
            size_image: 24,
            ..BitmapInfoHeader32::default()
        };
        let section = DibSection32 { bitmap, header, bitfields: RGB_MASKS, section: 0, offset: 0 };
        assert_eq!((size, &bytes[..]), (84, section.as_bytes()));
    }
}
