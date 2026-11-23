//! Les bitmaps (SURFACE ; `surface.c` d'`eng`, `dibobj.c`, `bitmaps.c`,
//! `dcobjs.c` de ReactOS, comme spécification).
//!
//! Le bitmap par défaut d'un DC en mémoire est un objet de stock :
//! 1 × 1, monochrome ; rien ne s'y dessine. Une DIB section
//! (CreateDIBSection, [`create_dib_section`]) range ses pixels dans une
//! section du fichier d'échange, que voient à la fois son processus, par une
//! vue dont l'adresse lui est rendue (`ppvBits`), et le noyau, par une vue
//! système (`mm::system_view`) : `gdi32` et l'application y lisent et y
//! écrivent ce que win32k y dessine, et inversement, sans copie. Ses lignes
//! montent depuis celle du bas si `biHeight` est positif.
//!
//! Une DIB section de 1, 4 ou 8 bits par pixel ([`Format::Indexed`]) garde
//! des index dans sa table de couleurs, comme son processus les lit et les
//! écrit : le moteur dessine sur ses pixels décodés en 32 bits
//! ([`decode_indexed`]), puis réécrit les pixels changés par l'index de la
//! couleur la plus proche ([`encode_indexed`], [`nearest_index`]). C'est le
//! format d'une liste d'images ILC_COLOR4 ou ILC_COLOR8 de `comctl32` (celle
//! du gestionnaire des tâches).
//!
//! Un bitmap de 24 bits par pixel ([`Format::Bgr`] : une DIB section, ou
//! CreateBitmap de 24 bits) garde ses pixels en BGR, trois octets, ses
//! lignes alignées sur 32 bits ; le moteur dessine de même sur ses pixels
//! décodés en 32 bits ([`decode_bgr`]), puis réécrit ceux qui ont changé
//! ([`encode_bgr`]). C'est la profondeur des images de la LCL de Lazarus
//! (PeaZip), qui n'avait sinon que des bitmaps nuls.
//!
//! Un bitmap n'est choisi que dans un DC à la fois (`hdc` du SURFACE) ; on
//! ne le supprime pas tant qu'il y est choisi (ce que dit la documentation
//! de DeleteObject ; ReactOS en diffère la suppression). Supprimé, une DIB
//! section quitte la mémoire de son processus.
//!
//! Un bitmap se copie (BITMAP_CopyBitmap : [`copy_bitmap`]) : GetIconInfo
//! donne ainsi les bitmaps d'une icône à son appelant ; GetDIBits les lit
//! (`super::dibits`).
//!
//! Pas encore : les DIB sections de 16 bits, les masques autres que ceux de
//! BI_RGB, la section d'une application (`hSection`), une table
//! DIB_PAL_COLORS, SetDIBits ; les bitmaps d'un processus rendus à sa fin.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use abi::gdi::{objt, BitmapInfoHeader32, BI_BITFIELDS, BI_RGB, LO_BITMAP_TYPE};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use abi::winerror::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_PARAMETER};
use hal::sync::KSpinLock;
use mm::section::Section;
use mm::system_view::{self, SystemView};
use mm::vad::PageProtect;

use super::dib::{Bitmap, ColorRef, PixelLayout};
use super::handles::{self, Object, OWNER_PUBLIC};

/// Les pixels d'un bitmap.
enum Pixels {
    /// Aucun : le bitmap par défaut d'un DC en mémoire.
    None,
    /// Ceux d'une DIB section : la vue du noyau, et celle de son processus
    /// (son PID et son adresse) tant qu'elle n'est pas défaite.
    Section { view: SystemView, user: KSpinLock<Option<(u32, u32)>> },
}

/// Le format des pixels d'un bitmap qui en a.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Format {
    /// 32 bits par pixel, BGRX ; l'octet haut tel que le processus l'écrit
    /// (l'alpha d'une icône).
    Bgrx,
    /// Des index de `bit_count` bits (1, 4 ou 8) dans `palette`, les lignes
    /// alignées sur 32 bits (les masques des images de la LCL : 1 bit).
    Indexed { bit_count: u16, palette: Vec<ColorRef> },
    /// 24 bits par pixel, BGR, les lignes alignées sur 32 bits.
    Bgr,
}

/// Les octets d'une ligne de `width` pixels de `bit_count` bits, alignée sur
/// 32 bits.
pub fn stride(width: u32, bit_count: u16) -> usize {
    (width as usize * usize::from(bit_count)).div_ceil(32) * 4
}

/// L'index de `palette` dont la couleur est `color`, sinon la plus proche
/// (la plus petite somme des carrés des écarts) ; le premier à égalité.
pub fn nearest_index(palette: &[ColorRef], color: ColorRef) -> u8 {
    let (r, g, b) = color.components();
    let distance = |entry: &ColorRef| {
        let (er, eg, eb) = entry.components();
        let d = |a: u8, b: u8| (i32::from(a) - i32::from(b)).pow(2);
        d(r, er) + d(g, eg) + d(b, eb)
    };
    let mut best = (0usize, i32::MAX);
    for (index, entry) in palette.iter().enumerate() {
        let gap = distance(entry);
        if gap < best.1 {
            best = (index, gap);
        }
    }
    best.0 as u8
}

/// Le décalage, dans sa ligne, du pixel `x` d'une DIB de `bit_count` bits :
/// son octet et le décalage de ses bits dans l'octet (le premier pixel dans
/// les bits hauts).
fn index_place(x: usize, bit_count: u16) -> (usize, u32) {
    let bit = x * usize::from(bit_count);
    (bit / 8, (8 - u32::from(bit_count)) - (bit % 8) as u32)
}

/// La ligne en mémoire de la ligne `y` (depuis le haut) d'une DIB de `height`
/// lignes.
fn memory_line(y: usize, height: usize, bottom_up: bool) -> usize {
    if bottom_up {
        height - 1 - y
    } else {
        y
    }
}

/// Les pixels BGRX, la ligne du haut d'abord, de la DIB indexée `bytes` de
/// `width` × `height` pixels de `bit_count` bits ; un index hors de `palette`
/// donne le noir.
pub fn decode_indexed(
    bytes: &[u8],
    (width, height): (u32, u32),
    bit_count: u16,
    palette: &[ColorRef],
    bottom_up: bool,
) -> Vec<u32> {
    let (w, h, line_bytes) = (width as usize, height as usize, stride(width, bit_count));
    let mask = (1u16 << bit_count) - 1;
    let mut pixels = Vec::with_capacity(w * h);
    for y in 0..h {
        let line = &bytes[memory_line(y, h, bottom_up) * line_bytes..][..line_bytes];
        for x in 0..w {
            let (at, shift) = index_place(x, bit_count);
            let index = (u16::from(line[at]) >> shift) & mask;
            let color = palette.get(usize::from(index)).copied().unwrap_or(ColorRef::rgb(0, 0, 0));
            pixels.push(PixelLayout::Bgrx.pixel(color));
        }
    }
    pixels
}

/// Réécrit dans la DIB indexée `bytes` les pixels de `after` (BGRX, la ligne
/// du haut d'abord) qui diffèrent de `before`, par l'index de leur couleur
/// la plus proche dans `palette` ; les autres gardent leur index.
pub fn encode_indexed(
    bytes: &mut [u8],
    (width, height): (u32, u32),
    (bit_count, palette): (u16, &[ColorRef]),
    bottom_up: bool,
    before: &[u32],
    after: &[u32],
) {
    let (w, h, line_bytes) = (width as usize, height as usize, stride(width, bit_count));
    let mask = ((1u16 << bit_count) - 1) as u8;
    for y in 0..h {
        let base = memory_line(y, h, bottom_up) * line_bytes;
        for x in 0..w {
            let at = y * w + x;
            if before[at] == after[at] {
                continue;
            }
            let index = nearest_index(palette, PixelLayout::Bgrx.color(after[at]));
            let (byte, shift) = index_place(x, bit_count);
            let cell = &mut bytes[base + byte];
            *cell = (*cell & !(mask << shift)) | ((index & mask) << shift);
        }
    }
}

/// Les pixels BGRX (l'octet haut à zéro), la ligne du haut d'abord, de la
/// DIB de 24 bits `bytes` de `width` × `height` pixels.
pub fn decode_bgr(bytes: &[u8], (width, height): (u32, u32), bottom_up: bool) -> Vec<u32> {
    let (w, h, line_bytes) = (width as usize, height as usize, stride(width, 24));
    let mut pixels = Vec::with_capacity(w * h);
    for y in 0..h {
        let line = &bytes[memory_line(y, h, bottom_up) * line_bytes..][..line_bytes];
        for x in 0..w {
            pixels.push(u32::from_le_bytes([line[3 * x], line[3 * x + 1], line[3 * x + 2], 0]));
        }
    }
    pixels
}

/// Réécrit dans la DIB de 24 bits `bytes` les pixels de `after` (BGRX, la
/// ligne du haut d'abord) qui diffèrent de `before` ; leur octet haut
/// n'a pas de place.
pub fn encode_bgr(bytes: &mut [u8], (width, height): (u32, u32), bottom_up: bool, before: &[u32], after: &[u32]) {
    let (w, h, line_bytes) = (width as usize, height as usize, stride(width, 24));
    for y in 0..h {
        let base = memory_line(y, h, bottom_up) * line_bytes;
        for x in 0..w {
            let at = y * w + x;
            if before[at] != after[at] {
                bytes[base + 3 * x..][..3].copy_from_slice(&after[at].to_le_bytes()[..3]);
            }
        }
    }
}

/// Le DC où un bitmap est choisi (`hdc` du SURFACE), 0 sinon.
#[derive(Debug, Default)]
struct Selection(AtomicU32);

impl Selection {
    /// Dans le DC `hdc`, s'il n'est dans aucun.
    fn select(&self, hdc: u32) -> bool {
        self.0.compare_exchange(0, hdc, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Hors du DC `hdc`, s'il y est.
    fn deselect(&self, hdc: u32) {
        let _ = self.0.compare_exchange(hdc, 0, Ordering::AcqRel, Ordering::Acquire);
    }

    fn is_selected(&self) -> bool {
        self.0.load(Ordering::Acquire) != 0
    }
}

/// Un bitmap.
pub struct Surface {
    width: u32,
    height: u32,
    /// La ligne du haut est la dernière en mémoire.
    bottom_up: bool,
    /// Un bitmap monochrome (CreateBitmap d'un bit par pixel) : ses pixels,
    /// de 32 bits comme les autres, ne sont que noirs ou blancs.
    monochrome: bool,
    format: Format,
    pixels: Pixels,
    selected: Selection,
    /// Un dessin à la fois.
    drawing: KSpinLock<()>,
}

impl core::fmt::Debug for Surface {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Surface({}x{})", self.width, self.height)
    }
}

impl Surface {
    /// Le bitmap par défaut d'un DC en mémoire.
    fn default_bitmap() -> Self {
        Self {
            width: 1,
            height: 1,
            bottom_up: false,
            monochrome: true,
            format: Format::Bgrx,
            pixels: Pixels::None,
            selected: Selection::default(),
            drawing: KSpinLock::new(()),
        }
    }

    /// Sa largeur et sa hauteur.
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Une DIB section dont les lignes montent depuis celle du bas.
    pub fn is_bottom_up(&self) -> bool {
        self.bottom_up
    }

    /// Le format de ses pixels.
    pub fn format(&self) -> &Format {
        &self.format
    }

    /// Ses bits par pixel : 1 (monochrome), 1, 4 ou 8 (une DIB section
    /// indexée), 24, 32.
    pub fn bit_count(&self) -> u16 {
        match &self.format {
            _ if self.monochrome => 1,
            Format::Indexed { bit_count, .. } => *bit_count,
            Format::Bgr => 24,
            Format::Bgrx => 32,
        }
    }

    /// Monochrome : le bitmap par défaut, ou celui de CreateBitmap d'un bit
    /// par pixel, CreateCompatibleBitmap d'un DC qui en a un.
    pub fn is_monochrome(&self) -> bool {
        self.monochrome
    }

    /// Ses pixels de 32 bits (BGRX, l'octet haut tel que le processus l'a
    /// écrit dans une DIB section : l'alpha d'une icône), de la ligne du haut
    /// à celle du bas ; `None` sans pixels (le bitmap par défaut).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn raw_pixels(&self) -> Option<alloc::vec::Vec<u32>> {
        let mut pixels = alloc::vec::Vec::with_capacity(self.width as usize * self.height as usize);
        let drawn = self.draw(|bitmap| {
            for y in 0..self.height {
                for x in 0..self.width {
                    pixels.push(bitmap.pixel(x, y).unwrap_or(0));
                }
            }
        });
        drawn.then_some(pixels)
    }

    /// Une DIB section (`hSecure`) : `gdi32` ne met pas en lot ce qui y
    /// dessine.
    pub fn is_dib_section(&self) -> bool {
        matches!(self.pixels, Pixels::Section { .. })
    }

    /// L'adresse de ses pixels chez le processus `pid` : la vue d'une DIB
    /// section qu'il a encore ; `None` sinon.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn user_bits(&self, pid: u32) -> Option<u32> {
        let Pixels::Section { user, .. } = &self.pixels else { return None };
        let view = *user.lock();
        view.filter(|&(owner, _)| owner == pid).map(|(_, at)| at)
    }

    /// Choisi dans un DC.
    pub fn is_selected(&self) -> bool {
        self.selected.is_selected()
    }

    /// Le choisit dans le DC `hdc` ; faux s'il l'est déjà dans un autre. Le
    /// bitmap par défaut va dans tous les DC.
    pub fn select(&self, hdc: u32) -> bool {
        matches!(self.pixels, Pixels::None) || self.selected.select(hdc)
    }

    /// Il quitte le DC `hdc`.
    pub fn deselect(&self, hdc: u32) {
        self.selected.deselect(hdc);
    }

    /// Appelle `draw` avec sa surface ; faux sans pixels (le bitmap par
    /// défaut).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL (`draw` y tourne).
    pub fn draw(&self, mut draw: impl FnMut(&mut Bitmap<'_>)) -> bool {
        let Pixels::Section { view, .. } = &self.pixels else { return false };
        let _one = self.drawing.lock();
        if let Format::Indexed { bit_count, palette } = &self.format {
            let size = stride(self.width, *bit_count) * self.height as usize;
            // SAFETY: the system view maps at least `size` bytes, the DIB's
            // lines (`create_dib_section`), resident while `self` lives;
            // `drawing` keeps the kernel to one slice at a time, as above.
            let bytes = unsafe { core::slice::from_raw_parts_mut(view.base() as *mut u8, size) };
            let size = (self.width, self.height);
            let mut pixels = decode_indexed(bytes, size, *bit_count, palette, self.bottom_up);
            let before = pixels.clone();
            {
                let Some(mut bitmap) = Bitmap::new(&mut pixels, self.width, self.height, self.width, PixelLayout::Bgrx)
                else {
                    return false;
                };
                draw(&mut bitmap);
            }
            encode_indexed(bytes, size, (*bit_count, palette), self.bottom_up, &before, &pixels);
            return true;
        }
        if self.format == Format::Bgr {
            let length = stride(self.width, 24) * self.height as usize;
            // SAFETY: as above, the system view maps at least the DIB's
            // `length` bytes (`create_dib_section`, `insert_kernel_bitmap`).
            let bytes = unsafe { core::slice::from_raw_parts_mut(view.base() as *mut u8, length) };
            let size = (self.width, self.height);
            let mut pixels = decode_bgr(bytes, size, self.bottom_up);
            let before = pixels.clone();
            {
                let Some(mut bitmap) = Bitmap::new(&mut pixels, self.width, self.height, self.width, PixelLayout::Bgrx)
                else {
                    return false;
                };
                draw(&mut bitmap);
            }
            encode_bgr(bytes, size, self.bottom_up, &before, &pixels);
            return true;
        }
        let count = self.width as usize * self.height as usize;
        // SAFETY: the system view maps `view.size()` bytes, at least
        // `count` pixels (`create_dib_section`), of pages resident while the
        // view lives, which is as long as `self`; `drawing` keeps the kernel
        // to one slice at a time. The process writes through its own view
        // only while the kernel does not run this thread at DISPATCH_LEVEL
        // (one processor): pixel by pixel, as GdiFlush leaves it.
        let pixels = unsafe { core::slice::from_raw_parts_mut(view.base() as *mut u32, count) };
        let Some(bitmap) = Bitmap::new(pixels, self.width, self.height, self.width, PixelLayout::Bgrx) else {
            return false;
        };
        draw(&mut if self.bottom_up { bitmap.bottom_up() } else { bitmap });
        true
    }

    /// Ses pixels quittent la mémoire du processus `pid`, s'il les y a
    /// encore et s'il est le processus courant (EngFreeUserMem).
    ///
    /// # IRQL
    /// <= APC_LEVEL.
    pub fn release_user_view(&self, pid: u32) {
        let Pixels::Section { user, .. } = &self.pixels else { return };
        let Some(thread) = ps::ethread::current_thread() else { return };
        if thread.pid() != pid {
            return;
        }
        let Some((owner, base)) = user.lock().take() else { return };
        if owner == pid {
            let _ = thread.process().with_space(|space| space.unmap_view(u64::from(base)));
        }
    }
}

/// Ce qu'est une DIB, tirée de son en-tête.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DibGeometry {
    pub width: u32,
    pub height: u32,
    /// `biHeight` positif : les lignes montent depuis celle du bas.
    pub bottom_up: bool,
    /// 1, 4, 8, 24 ou 32.
    pub bit_count: u16,
    /// Ses octets.
    pub size: u32,
}

/// Les octets au plus d'une DIB section (256 Mio).
pub const MAX_DIB_SIZE: u32 = 0x1000_0000;
/// Les masques de BI_BITFIELDS que prend une DIB de 32 bits : ceux de BI_RGB.
pub const RGB_MASKS: [u32; 3] = [0x00FF_0000, 0x0000_FF00, 0x0000_00FF];

/// DIB_CreateDIBSection, ses vérifications : la DIB de l'en-tête `header`
/// (ses masques `masks` pour BI_BITFIELDS). `Err` : l'erreur de Win32,
/// `ERROR_INVALID_PARAMETER` (un en-tête trop court, une compression RLE,
/// une taille nulle, négative ou trop grande, plus d'un plan) ou
/// `ERROR_CALL_NOT_IMPLEMENTED` (une autre profondeur que 1, 4, 8, 24 ou
/// 32 bits, BI_BITFIELDS hors de 32 bits, d'autres masques).
pub fn dib_geometry(header: &BitmapInfoHeader32, masks: Option<[u32; 3]>) -> Result<DibGeometry, u32> {
    let valid = header.size as usize >= core::mem::size_of::<BitmapInfoHeader32>()
        && header.width > 0
        && header.height != 0
        && header.height != i32::MIN
        && header.planes == 1;
    if !valid || !matches!(header.compression, BI_RGB | BI_BITFIELDS) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let supported = match header.bit_count {
        1 | 4 | 8 | 24 => header.compression == BI_RGB,
        32 => header.compression == BI_RGB || masks == Some(RGB_MASKS),
        _ => false,
    };
    if !supported {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            log::warn!(
                "win32k: a DIB section of {} bits per pixel, compression {}: not yet",
                header.bit_count,
                header.compression
            );
        }
        return Err(ERROR_CALL_NOT_IMPLEMENTED);
    }
    let (width, height) = (header.width as u32, header.height.unsigned_abs());
    // WIDTH_BYTES_ALIGN32.
    let line = u64::from(width) * u64::from(header.bit_count);
    let size = line.div_ceil(32) * 4 * u64::from(height);
    let size = u32::try_from(size).ok().filter(|&size| size <= MAX_DIB_SIZE).ok_or(ERROR_INVALID_PARAMETER)?;
    Ok(DibGeometry { width, height, bottom_up: header.height > 0, bit_count: header.bit_count, size })
}

/// DIB_CreateDIBSection, sans section d'application : une DIB section de
/// `geometry` (des pixels à zéro), au processus courant, sa table de
/// couleurs `palette` pour 1, 4 et 8 bits. Rend son handle et l'adresse de ses
/// pixels chez lui.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` hors d'un thread de Ps ; celles de la
/// section, des vues et de la table (rien ne reste alors).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn create_dib_section(geometry: DibGeometry, palette: Vec<ColorRef>) -> Result<(u32, u32), NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    let process = thread.process().clone();
    let size = u64::from(geometry.size).next_multiple_of(0x1000);
    let section = Section::create_pagefile(size, PageProtect::READWRITE)?;
    let view = system_view::map(&section, 0, size)?;
    let user = process.with_space(|space| space.map_view(&section, 0, 0, size, PageProtect::READWRITE))??;
    let pid = process.pid();
    let surface = Surface {
        width: geometry.width,
        height: geometry.height,
        bottom_up: geometry.bottom_up,
        monochrome: false,
        format: match geometry.bit_count {
            1 | 4 | 8 => Format::Indexed { bit_count: geometry.bit_count, palette },
            24 => Format::Bgr,
            _ => Format::Bgrx,
        },
        pixels: Pixels::Section { view, user: KSpinLock::new(Some((pid, user.base as u32))) },
        selected: Selection::default(),
        drawing: KSpinLock::new(()),
    };
    match handles::insert(Object::Bitmap(Arc::new(surface)), LO_BITMAP_TYPE, objt::SURF, pid) {
        Ok(handle) => Ok((handle, user.base as u32)),
        Err(status) => {
            let _ = process.with_space(|space| space.unmap_view(user.base));
            Err(status)
        }
    }
}

/// `CreateBitmap` : un bitmap de `width` × `height`, ses pixels convertis
/// de `bits` (le contenu que l'appelant donne pour `planes` × `bits_pixel`
/// bits par pixel, les lignes du haut vers le bas, alignées sur 16 bits,
/// 0 = noir et 1 = blanc pour la monochrome, BGR en 24 bits ; sans `bits`,
/// noirs), dans une section vue du noyau seul : en 24 bits pour 24 bits,
/// en 32 bits BGRA sinon. Un bitmap d'un bit par pixel est monochrome. Rend
/// son handle GDI, au processus courant.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` pour des dimensions ou une profondeur que le
/// moteur ne tient pas (la monochrome, 24 et 32 bits, pour l'instant), hors
/// d'un thread de Ps ; `STATUS_NO_MEMORY` sans place.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn create_from_bits(
    width: u32,
    height: u32,
    planes: u32,
    bits_pixel: u32,
    bits: Option<&[u8]>,
) -> Result<u32, NtStatus> {
    if width == 0 || height == 0 || width > 4096 || height > 4096 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let depth = planes * bits_pixel;
    let count = width as usize * height as usize;
    let mut pixels = alloc::vec![0u32; count];
    match (depth, bits) {
        (1 | 24 | 32, None) => {}
        (1, Some(bits)) => {
            let stride = (width as usize).div_ceil(16) * 2;
            if bits.len() < stride * height as usize {
                return Err(STATUS_INVALID_PARAMETER);
            }
            for y in 0..height as usize {
                for x in 0..width as usize {
                    let bit = bits[y * stride + x / 8] >> (7 - x % 8) & 1;
                    pixels[y * width as usize + x] = if bit == 0 { 0x0000_0000 } else { 0x00FF_FFFF };
                }
            }
        }
        (24, Some(bits)) => {
            let stride = (width as usize * 3).div_ceil(2) * 2;
            if bits.len() < stride * height as usize {
                return Err(STATUS_INVALID_PARAMETER);
            }
            for y in 0..height as usize {
                for x in 0..width as usize {
                    let at = y * stride + 3 * x;
                    pixels[y * width as usize + x] = u32::from_le_bytes([bits[at], bits[at + 1], bits[at + 2], 0]);
                }
            }
        }
        (32, Some(bits)) => {
            if bits.len() < count * 4 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            for (pixel, at) in pixels.iter_mut().zip((0..count).map(|i| i * 4)) {
                *pixel = u32::from_le_bytes([bits[at], bits[at + 1], bits[at + 2], 0]);
            }
        }
        _ => return Err(STATUS_INVALID_PARAMETER),
    }
    let format = if depth == 24 { Format::Bgr } else { Format::Bgrx };
    insert_kernel_bitmap(width, height, depth == 1, format, &pixels)
}

/// CreateCompatibleBitmap : un bitmap de `width` × `height`, noir,
/// monochrome si `monochrome` (celui d'un DC en mémoire qui en a un), de la
/// couleur de l'écran sinon. Rend son handle GDI, au processus courant.
///
/// # Errors
/// Celles de [`create_from_bits`].
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn create_compatible(width: u32, height: u32, monochrome: bool) -> Result<u32, NtStatus> {
    create_from_bits(width, height, 1, if monochrome { 1 } else { 32 }, None)
}

/// BITMAP_CopyBitmap : un bitmap neuf, au processus courant, de la taille, de
/// la profondeur et des pixels du bitmap `handle` (au processus courant, ou
/// public : ceux d'un curseur), l'octet haut compris (l'alpha d'une icône).
/// C'est un bitmap du noyau seul, comme ceux de CreateBitmap, même pour la
/// copie d'une DIB section (GreCreateBitmapEx ne lui donne pas de
/// `hSecure`). `None` pour un bitmap inconnu ou sans pixels (le bitmap par
/// défaut), ou sans place.
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn copy_bitmap(handle: u32) -> Option<u32> {
    let surface = lock(handle, super::dc::current_pid())?;
    let (width, height) = surface.size();
    let pixels = surface.raw_pixels()?;
    // A copy keeps 24 bits; the others become 32 bits.
    let format = if *surface.format() == Format::Bgr { Format::Bgr } else { Format::Bgrx };
    insert_kernel_bitmap(width, height, surface.is_monochrome(), format, &pixels).ok()
}

/// Un bitmap de `pixels` (32 bits, la ligne du haut d'abord) dans une section
/// vue du noyau seul, au processus courant, rangés en `format` (Bgrx, ou
/// Bgr : trois octets, les lignes alignées sur 32 bits).
fn insert_kernel_bitmap(
    width: u32,
    height: u32,
    monochrome: bool,
    format: Format,
    pixels: &[u32],
) -> Result<u32, NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    let process = thread.process().clone();
    let bytes: Vec<u8> = if format == Format::Bgr {
        let mut bytes = alloc::vec![0u8; stride(width, 24) * height as usize];
        let zeros = alloc::vec![0u32; pixels.len()];
        encode_bgr(&mut bytes, (width, height), false, &zeros, pixels);
        bytes
    } else {
        pixels.iter().flat_map(|pixel| pixel.to_le_bytes()).collect()
    };
    let size = (bytes.len() as u64).next_multiple_of(0x1000);
    let section = Section::create_pagefile(size, PageProtect::READWRITE)?;
    let view = system_view::map(&section, 0, size)?;
    for (at, byte) in bytes.iter().enumerate() {
        // SAFETY: la vue mappe `size` octets, `bytes` tient, à adresse fixe
        // tant que la vue vit.
        unsafe { (view.base() as *mut u8).add(at).write_volatile(*byte) };
    }
    let surface = Surface {
        width,
        height,
        bottom_up: false,
        monochrome,
        format,
        pixels: Pixels::Section { view, user: KSpinLock::new(None) },
        selected: Selection::default(),
        drawing: KSpinLock::new(()),
    };
    handles::insert(Object::Bitmap(Arc::new(surface)), LO_BITMAP_TYPE, objt::SURF, process.pid())
        .map_err(|_| STATUS_INVALID_PARAMETER)
}

/// Le bitmap par défaut, public ; rend son handle (pas encore de stock).
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, après la table des handles.
pub fn create_default_bitmap() -> Result<u32, NtStatus> {
    let object = Object::Bitmap(Arc::new(Surface::default_bitmap()));
    handles::insert(object, LO_BITMAP_TYPE, objt::SURF, OWNER_PUBLIC)
}

/// SURFACE_ShareLockSurface : le bitmap `handle`, s'il est au processus
/// `pid` ou public.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn lock(handle: u32, pid: u32) -> Option<Arc<Surface>> {
    match handles::get(handle, pid)? {
        Object::Bitmap(surface) => Some(surface),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(width: i32, height: i32, bit_count: u16, compression: u32) -> BitmapInfoHeader32 {
        BitmapInfoHeader32 { size: 40, width, height, planes: 1, bit_count, compression, ..Default::default() }
    }

    #[test]
    fn a_dib_of_32_bits_per_pixel() {
        let geometry = dib_geometry(&header(656, 400, 32, BI_RGB), None);
        let expected = DibGeometry { width: 656, height: 400, bottom_up: true, bit_count: 32, size: 656 * 400 * 4 };
        assert_eq!(geometry, Ok(expected));
        let top_down = dib_geometry(&header(3, -2, 32, BI_RGB), None).unwrap();
        assert_eq!((top_down.height, top_down.bottom_up, top_down.size), (2, false, 24));
        let masks = Some(RGB_MASKS);
        assert_eq!(dib_geometry(&header(1, 1, 32, BI_BITFIELDS), masks).map(|g| g.size), Ok(4));
        let largest = dib_geometry(&header(8192, -8192, 32, BI_RGB), None).map(|g| g.size);
        assert_eq!(largest, Ok(MAX_DIB_SIZE), "256 MiB, the most");
        let v5 = BitmapInfoHeader32 { size: 124, ..header(1, 1, 32, BI_RGB) };
        assert!(dib_geometry(&v5, None).is_ok(), "a longer header");
    }

    #[test]
    fn what_a_dib_section_refuses() {
        let refused = |header: BitmapInfoHeader32| dib_geometry(&header, None).err();
        assert_eq!(refused(BitmapInfoHeader32 { size: 12, ..header(1, 1, 32, BI_RGB) }), Some(ERROR_INVALID_PARAMETER));
        assert_eq!(refused(header(0, 1, 32, BI_RGB)), Some(ERROR_INVALID_PARAMETER), "no width");
        assert_eq!(refused(header(-1, 1, 32, BI_RGB)), Some(ERROR_INVALID_PARAMETER), "a negative width");
        assert_eq!(refused(header(1, 0, 32, BI_RGB)), Some(ERROR_INVALID_PARAMETER), "no height");
        assert_eq!(refused(header(1, i32::MIN, 32, BI_RGB)), Some(ERROR_INVALID_PARAMETER));
        assert_eq!(
            refused(BitmapInfoHeader32 { planes: 2, ..header(1, 1, 32, BI_RGB) }),
            Some(ERROR_INVALID_PARAMETER)
        );
        assert_eq!(refused(header(1, 1, 8, 1)), Some(ERROR_INVALID_PARAMETER), "BI_RLE8");
        assert_eq!(refused(header(65536, 65536, 32, BI_RGB)), Some(ERROR_INVALID_PARAMETER), "too big");
        assert_eq!(refused(header(8192, 8193, 32, BI_RGB)), Some(ERROR_INVALID_PARAMETER), "past 256 MiB");
        assert_eq!(refused(header(1, 1, 16, BI_RGB)), Some(ERROR_CALL_NOT_IMPLEMENTED), "16 bits: not yet");
        assert_eq!(refused(header(1, 1, 24, BI_BITFIELDS)), Some(ERROR_CALL_NOT_IMPLEMENTED), "masks of 24 bits");
        assert_eq!(refused(header(1, 1, 8, BI_BITFIELDS)), Some(ERROR_CALL_NOT_IMPLEMENTED), "masks of 8 bits");
        let other_masks = Some([0xFF, 0xFF00, 0x00FF_0000]);
        assert_eq!(dib_geometry(&header(1, 1, 32, BI_BITFIELDS), other_masks).err(), Some(ERROR_CALL_NOT_IMPLEMENTED));
    }

    #[test]
    fn dib_sections_of_one_four_and_eight_bits() {
        // A line of 33 pixels of 1 bit takes 5 bytes, aligned on 8.
        let one = dib_geometry(&header(33, 2, 1, BI_RGB), None).unwrap();
        assert_eq!((one.bit_count, one.size, one.bottom_up), (1, 16, true));
        // A line of 33 pixels of 4 bits takes 17 bytes, aligned on 20.
        let four = dib_geometry(&header(33, -2, 4, BI_RGB), None).unwrap();
        assert_eq!((four.bit_count, four.size, four.bottom_up), (4, 40, false));
        let eight = dib_geometry(&header(3, 2, 8, BI_RGB), None).unwrap();
        assert_eq!((eight.bit_count, eight.size), (8, 8));
    }

    #[test]
    fn dib_sections_of_twenty_four_bits() {
        // A line of 3 pixels takes 9 bytes, aligned on 12.
        let geometry = dib_geometry(&header(3, 2, 24, BI_RGB), None).unwrap();
        assert_eq!((geometry.bit_count, geometry.size, geometry.bottom_up), (24, 24, true));
        assert_eq!(stride(4, 24), 12, "4 pixels: 12 bytes, nothing to pad");
    }

    #[test]
    fn pixels_of_twenty_four_bits_decode_and_encode_back() {
        // 2 x 2, from the bottom line up: bottom (1,2,3) (4,5,6), top
        // (7,8,9) (10,11,12), each line padded from 6 to 8 bytes.
        let mut bytes = [1, 2, 3, 4, 5, 6, 0xEE, 0xEE, 7, 8, 9, 10, 11, 12, 0xEE, 0xEE];
        let pixels = decode_bgr(&bytes, (2, 2), true);
        assert_eq!(pixels, [0x0009_0807, 0x000C_0B0A, 0x0003_0201, 0x0006_0504], "the top line first, BGR");
        let mut after = pixels.clone();
        after[0] = 0xFF11_2233; // its high byte has no place
        after[3] = 0x0000_0000;
        encode_bgr(&mut bytes, (2, 2), true, &pixels, &after);
        assert_eq!(bytes, [1, 2, 3, 0, 0, 0, 0xEE, 0xEE, 0x33, 0x22, 0x11, 10, 11, 12, 0xEE, 0xEE], "the padding kept");
        // From the top line down.
        assert_eq!(decode_bgr(&[1, 2, 3, 0], (1, 1), false), [0x0003_0201]);
    }

    const BLACK: ColorRef = ColorRef::rgb(0, 0, 0);
    const RED: ColorRef = ColorRef::rgb(255, 0, 0);
    const GRAY: ColorRef = ColorRef::rgb(128, 128, 128);
    const WHITE: ColorRef = ColorRef::rgb(255, 255, 255);

    #[test]
    fn the_nearest_colour_of_a_table() {
        let palette = [BLACK, RED, GRAY, WHITE];
        assert_eq!(nearest_index(&palette, RED), 1, "exact");
        assert_eq!(nearest_index(&palette, ColorRef::rgb(200, 10, 10)), 1);
        assert_eq!(nearest_index(&palette, ColorRef::rgb(140, 120, 130)), 2);
        assert_eq!(nearest_index(&palette, ColorRef::rgb(250, 250, 240)), 3);
        assert_eq!(nearest_index(&[GRAY, GRAY], GRAY), 0, "the first of equals");
    }

    #[test]
    fn indexed_pixels_decode_and_encode_back() {
        let palette = [BLACK, RED, GRAY, WHITE];
        // 3 x 2 of 4 bits, from the bottom line up: bottom 3 2 1, top 1 0 3.
        let mut bytes = [0x32, 0x10, 0, 0, 0x10, 0x30, 0, 0];
        let pixels = decode_indexed(&bytes, (3, 2), 4, &palette, true);
        let bgrx = |c| PixelLayout::Bgrx.pixel(c);
        assert_eq!(pixels, [bgrx(RED), bgrx(BLACK), bgrx(WHITE), bgrx(WHITE), bgrx(GRAY), bgrx(RED)]);
        let mut after = pixels.clone();
        after[1] = bgrx(ColorRef::rgb(250, 5, 0)); // near red
        after[5] = bgrx(BLACK);
        encode_indexed(&mut bytes, (3, 2), (4, &palette), true, &pixels, &after);
        assert_eq!(bytes, [0x32, 0x00, 0, 0, 0x11, 0x30, 0, 0], "two pixels changed, the others kept");
        // 1 bit, from the top line down: the first pixel in the high bit.
        let mut one = [0b1010_0000, 0, 0, 0];
        let two = [BLACK, WHITE];
        let decoded = decode_indexed(&one, (3, 1), 1, &two, false);
        assert_eq!(decoded, [bgrx(WHITE), bgrx(BLACK), bgrx(WHITE)]);
        let mut changed = decoded.clone();
        changed[1] = bgrx(ColorRef::rgb(240, 240, 240)); // near white
        changed[2] = bgrx(ColorRef::rgb(100, 100, 100)); // nearer black than white (128 is nearer white)
        encode_indexed(&mut one, (3, 1), (1, &two), false, &decoded, &changed);
        assert_eq!(one, [0b1100_0000, 0, 0, 0], "the second pixel set, the third cleared");
        // 8 bits, from the top line down; an index past the table is black.
        let bytes = [3, 9, 0, 0];
        assert_eq!(decode_indexed(&bytes, (2, 1), 8, &palette, false), [bgrx(WHITE), bgrx(BLACK)]);
    }

    #[test]
    fn a_bitmap_is_selected_in_one_dc_at_a_time() {
        let selection = Selection::default();
        assert!(selection.select(0x10) && selection.is_selected());
        assert!(!selection.select(0x20), "already in another DC");
        selection.deselect(0x20);
        assert!(selection.is_selected(), "the other DC cannot take it out");
        selection.deselect(0x10);
        assert!(!selection.is_selected() && selection.select(0x20));
    }

    #[test]
    fn the_default_bitmap_goes_in_every_dc_and_draws_nothing() {
        let surface = Surface::default_bitmap();
        assert!(surface.select(0x10) && surface.select(0x20));
        assert!(!surface.is_selected() && !surface.is_dib_section());
        assert_eq!(surface.size(), (1, 1));
        assert!(!surface.draw(|_| panic!("drawn")), "nothing to draw on");
    }
}
