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
//! Un bitmap n'est choisi que dans un DC à la fois (`hdc` du SURFACE) ; on
//! ne le supprime pas tant qu'il y est choisi (ce que dit la documentation
//! de DeleteObject ; ReactOS en diffère la suppression). Supprimé, une DIB
//! section quitte la mémoire de son processus.
//!
//! Pas encore : les bitmaps compatibles (CreateBitmap,
//! CreateCompatibleBitmap), les profondeurs autres que 32 bits, les masques
//! autres que ceux de BI_RGB, la section d'une application (`hSection`),
//! les palettes, GetObject, GetDIBits et SetDIBits ; les bitmaps d'un
//! processus rendus à sa fin.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use abi::gdi::{objt, BitmapInfoHeader32, BI_BITFIELDS, BI_RGB, LO_BITMAP_TYPE};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use abi::winerror::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_PARAMETER};
use hal::sync::KSpinLock;
use mm::section::Section;
use mm::system_view::{self, SystemView};
use mm::vad::PageProtect;

use super::dib::{Bitmap, PixelLayout};
use super::handles::{self, Object, OWNER_PUBLIC};

/// Les pixels d'un bitmap.
enum Pixels {
    /// Aucun : le bitmap par défaut d'un DC en mémoire.
    None,
    /// Ceux d'une DIB section : la vue du noyau, et celle de son processus
    /// (son PID et son adresse) tant qu'elle n'est pas défaite.
    Section { view: SystemView, user: KSpinLock<Option<(u32, u32)>> },
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
            pixels: Pixels::None,
            selected: Selection::default(),
            drawing: KSpinLock::new(()),
        }
    }

    /// Sa largeur et sa hauteur.
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
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
/// `ERROR_CALL_NOT_IMPLEMENTED` (une autre profondeur que 32 bits, d'autres
/// masques).
pub fn dib_geometry(header: &BitmapInfoHeader32, masks: Option<[u32; 3]>) -> Result<DibGeometry, u32> {
    let valid = header.size as usize >= core::mem::size_of::<BitmapInfoHeader32>()
        && header.width > 0
        && header.height != 0
        && header.height != i32::MIN
        && header.planes == 1;
    if !valid || !matches!(header.compression, BI_RGB | BI_BITFIELDS) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    if header.bit_count != 32 || (header.compression == BI_BITFIELDS && masks != Some(RGB_MASKS)) {
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
    // WIDTH_BYTES_ALIGN32 of 32 bits per pixel: 4 bytes a pixel.
    let size = width.checked_mul(4).and_then(|stride| stride.checked_mul(height)).filter(|&size| size <= MAX_DIB_SIZE);
    let size = size.ok_or(ERROR_INVALID_PARAMETER)?;
    Ok(DibGeometry { width, height, bottom_up: header.height > 0, size })
}

/// DIB_CreateDIBSection, sans section d'application : une DIB section de
/// `geometry` (des pixels à zéro), au processus courant. Rend son handle et
/// l'adresse de ses pixels chez lui.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` hors d'un thread de Ps ; celles de la
/// section, des vues et de la table (rien ne reste alors).
///
/// # IRQL
/// PASSIVE_LEVEL, dans un service système, sans rien tenir.
pub fn create_dib_section(geometry: DibGeometry) -> Result<(u32, u32), NtStatus> {
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
/// bits par pixel, les lignes du haut vers le bas, celles de la monochrome
/// alignées sur 16 bits, 0 = noir et 1 = blanc ; sans `bits`, noirs) vers
/// 32 bits BGRA, dans une section vue du noyau seul. Un bitmap d'un bit par
/// pixel est monochrome. Rend son handle GDI, au processus courant.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` pour des dimensions ou une profondeur que le
/// moteur ne tient pas (la monochrome et le 32 bits, pour l'instant), hors
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
        (1 | 32, None) => {}
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
    insert_kernel_bitmap(width, height, depth == 1, &pixels)
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

/// Un bitmap de `pixels` (32 bits, la ligne du haut d'abord) dans une section
/// vue du noyau seul, au processus courant.
fn insert_kernel_bitmap(width: u32, height: u32, monochrome: bool, pixels: &[u32]) -> Result<u32, NtStatus> {
    let thread = ps::ethread::current_thread().ok_or(STATUS_INVALID_PARAMETER)?;
    let process = thread.process().clone();
    let size = u64::from(width * height * 4).next_multiple_of(0x1000);
    let section = Section::create_pagefile(size, PageProtect::READWRITE)?;
    let view = system_view::map(&section, 0, size)?;
    for (at, pixel) in pixels.iter().enumerate() {
        // SAFETY: la vue mappe `size` octets, les `count` pixels tiennent, à
        // adresse fixe tant que la vue vit.
        unsafe { (view.base() as *mut u32).add(at).write_volatile(*pixel) };
    }
    let surface = Surface {
        width,
        height,
        bottom_up: false,
        monochrome,
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
        assert_eq!(geometry, Ok(DibGeometry { width: 656, height: 400, bottom_up: true, size: 656 * 400 * 4 }));
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
        assert_eq!(refused(header(1, 1, 24, BI_RGB)), Some(ERROR_CALL_NOT_IMPLEMENTED), "24 bits: not yet");
        let other_masks = Some([0xFF, 0xFF00, 0x00FF_0000]);
        assert_eq!(dib_geometry(&header(1, 1, 32, BI_BITFIELDS), other_masks).err(), Some(ERROR_CALL_NOT_IMPLEMENTED));
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
