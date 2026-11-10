//! Le pilote d'affichage (02 §7.2) : un trait interne ([`DisplayDriver`]),
//! qu'implémente `drivers/video/gopfb` (le framebuffer UEFI, fixe), puis
//! d'autres (`bochs-dispi`) ; le noyau installe le sien au démarrage
//! ([`install`]).
//!
//! Le pilote donne sa surface (le framebuffer) au moteur DIB, comme un
//! pilote d'XP associe sa surface à GDI (EngAssociateSurface) : GDI y dessine
//! directement ([`draw`]). La première fois, le pilote prend l'écran à la
//! console de démarrage ([`DisplayDriver::acquire`]).
//!
//! Les dessins passent un à un, sous un `KSpinLock` : à DISPATCH_LEVEL, en
//! attendant un mutex du noyau à PASSIVE_LEVEL ; la surface est en mémoire
//! résidente (le framebuffer), sans faute de page.
//!
//! Pas encore : le changement de mode, plusieurs écrans, le curseur matériel,
//! la synchronisation avec le balayage.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use hal::sync::{KSpinLock, Once};

use crate::cursor::{Pixel, Shape};
use crate::gdi::dib::{Bitmap, PixelLayout};

/// Le mode d'un écran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub layout: PixelLayout,
}

/// Un pilote d'affichage.
pub trait DisplayDriver: Send + Sync {
    /// Son mode.
    fn mode(&self) -> Mode;

    /// Appelle `draw` avec sa surface, de la taille de son mode. win32k
    /// n'appelle qu'une fois à la fois ([`draw`]).
    fn with_surface(&self, draw: &mut dyn FnMut(&mut Bitmap<'_>));

    /// Prend l'écran : ce qui y écrivait avant (la console de démarrage)
    /// cesse de le faire.
    fn acquire(&self);

    /// Passe la surface à `width` × `height` ; `false` quand le pilote ne
    /// sait pas changer de mode. L'appelant redessine ensuite, une seule
    /// main à la fois ([`change_mode`]).
    fn set_mode(&self, width: u32, height: u32) -> bool {
        let _ = (width, height);
        false
    }
}

/// Le pilote installé.
static DRIVER: Once<Box<dyn DisplayDriver>> = Once::new();
/// Un dessin à la fois ; le curseur, que chacun retire puis remet.
static DRAWING: KSpinLock<Cursor> = KSpinLock::new(Cursor::new());

/// Ce que l'écran montre au pointeur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorImage {
    /// La flèche de win32k, avant les curseurs du système
    /// ([`crate::cursor::Shape::arrow`]).
    Arrow,
    /// La forme d'un curseur.
    Shape(Arc<Shape>),
    /// Rien : SetCursor(NULL).
    Hidden,
}

/// Le curseur logiciel (la « pointer exclusion » de GDI, réduite) : sa
/// place, s'il est montré, sa forme, et les pixels de l'écran qu'il couvre.
struct Cursor {
    x: i32,
    y: i32,
    visible: bool,
    /// Sa forme ; `None` : la flèche de win32k, faite au premier dessin.
    image: Option<CursorImage>,
    arrow: Option<Arc<Shape>>,
    /// Le coin de la forme dessinée et sa taille, quand elle l'est.
    drawn: Option<(i32, i32, u32, u32)>,
    saved: Vec<u32>,
}

impl Cursor {
    const fn new() -> Self {
        Self { x: 0, y: 0, visible: false, image: None, arrow: None, drawn: None, saved: Vec::new() }
    }

    /// La forme à dessiner ; `None` : rien.
    fn shape(&mut self) -> Option<Arc<Shape>> {
        match self.image.clone().unwrap_or(CursorImage::Arrow) {
            CursorImage::Hidden => None,
            CursorImage::Shape(shape) => Some(shape),
            CursorImage::Arrow => Some(self.arrow.get_or_insert_with(|| Arc::new(Shape::arrow())).clone()),
        }
    }

    /// Les pixels de l'écran d'une forme de `width` × `height` dessinée en
    /// (`left`, `top`), sur `surface` : leur rang dans la forme et leur place.
    fn cells(
        (left, top, width, height): (i32, i32, u32, u32),
        surface: &Bitmap<'_>,
    ) -> impl Iterator<Item = (usize, u32, u32)> {
        let bounds = surface.bounds();
        (0..height as usize).flat_map(move |row| {
            (0..width as usize).filter_map(move |column| {
                let (x, y) = (left + column as i32, top + row as i32);
                (x >= bounds.left && x < bounds.right && y >= bounds.top && y < bounds.bottom).then_some((
                    row * width as usize + column,
                    x as u32,
                    y as u32,
                ))
            })
        })
    }

    /// Rend à l'écran les pixels que le curseur couvrait.
    fn hide(&mut self, surface: &mut Bitmap<'_>) {
        let Some(place) = self.drawn.take() else { return };
        let cells: Vec<_> = Self::cells(place, surface).collect();
        for (index, x, y) in cells {
            surface.set_pixel(x, y, self.saved[index]);
        }
    }

    /// Garde les pixels de l'écran sous le curseur, puis le dessine.
    fn show(&mut self, surface: &mut Bitmap<'_>) {
        if !self.visible || self.drawn.is_some() {
            return;
        }
        let Some(shape) = self.shape() else { return };
        let place = (self.x - shape.hotspot.0, self.y - shape.hotspot.1, shape.width, shape.height);
        let layout = surface.layout();
        self.saved.clear();
        self.saved.resize(shape.pixels.len(), 0);
        let cells: Vec<_> = Self::cells(place, surface).collect();
        for (index, x, y) in cells {
            let screen = surface.pixel(x, y).unwrap_or(0);
            self.saved[index] = screen;
            let pixel = shape.pixels[index];
            if pixel != Pixel::Transparent {
                surface.set_pixel(x, y, layout.pixel(pixel.over(layout.color(screen))));
            }
        }
        self.drawn = Some(place);
    }
}

/// Montre le curseur, son point chaud en (`x`, `y`) de l'écran ; rien avant
/// que win32k ait pris l'écran.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_cursor(x: i32, y: i32) {
    let Some(driver) = DRIVER.get() else { return };
    if !acquired() {
        return;
    }
    let mut cursor = DRAWING.lock();
    driver.with_surface(&mut |surface| {
        cursor.hide(surface);
        (cursor.x, cursor.y, cursor.visible) = (x, y, true);
        cursor.show(surface);
    });
}

/// L'écran montre `image` au pointeur, à sa place ; il la gardera quand il
/// se montrera.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_cursor_image(image: CursorImage) {
    let mut cursor = DRAWING.lock();
    if cursor.image.as_ref() == Some(&image) {
        return;
    }
    let redraw = DRIVER.get().filter(|_| acquired() && cursor.visible);
    match redraw {
        Some(driver) => driver.with_surface(&mut |surface| {
            cursor.hide(surface);
            cursor.image = Some(image.clone());
            cursor.show(surface);
        }),
        None => cursor.image = Some(image),
    }
}

/// Le pilote a pris l'écran.
static ACQUIRED: AtomicBool = AtomicBool::new(false);

/// Installe le pilote d'affichage ; ses capacités vont dans la table des
/// handles GDI (`crate::gdi::devcaps`).
///
/// # Panics
/// Au second appel.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn install(driver: Box<dyn DisplayDriver>) {
    assert!(DRIVER.get().is_none(), "a display driver installed twice");
    let mode = driver.mode();
    DRIVER.call_once(|| driver);
    log::info!("win32k: display {}x{} ({:?})", mode.width, mode.height, mode.layout);
    if let Err(status) = crate::gdi::devcaps::publish(&mode) {
        log::warn!("win32k: the display's capabilities not published: {status:?}");
    }
}

/// Le mode de l'écran ; `None` sans pilote.
///
/// # IRQL
/// Tout niveau.
pub fn mode() -> Option<Mode> {
    DRIVER.get().map(|driver| driver.mode())
}

/// Le pilote a pris l'écran : win32k y a dessiné.
///
/// # IRQL
/// Tout niveau.
pub fn acquired() -> bool {
    ACQUIRED.load(Ordering::Acquire)
}

/// Appelle `draw` avec la surface de l'écran, le pilote ayant pris l'écran ;
/// `false` sans pilote.
///
/// # IRQL
/// <= DISPATCH_LEVEL (`draw` y tourne).
pub fn draw(mut draw: impl FnMut(&mut Bitmap<'_>)) -> bool {
    let Some(driver) = DRIVER.get() else { return false };
    let mut cursor = DRAWING.lock();
    if !ACQUIRED.swap(true, Ordering::AcqRel) {
        // Le premier dessin de win32k prend l'écran : le rideau de démarrage
        // se lève ici, avant que la surface ne soit touchée.
        hal::splash::hide();
        driver.acquire();
    }
    // GDI draws, and reads back, the screen without the cursor.
    driver.with_surface(&mut |surface| {
        cursor.hide(surface);
        draw(surface);
        cursor.show(surface);
    });
    true
}

/// Change le mode de l'écran pour `width` × `height` ; `false` sans pilote
/// ou quand le matériel ne suit pas. La surface est réécrite à la nouvelle
/// taille (son contenu est perdu) : l'appelant redessine ensuite, par
/// [`draw`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn change_mode(width: u32, height: u32) -> bool {
    let Some(driver) = DRIVER.get() else { return false };
    let _one = DRAWING.lock();
    if !driver.set_mode(width, height) {
        return false;
    }
    let mode = driver.mode();
    log::info!("win32k: display mode changed to {}x{}", mode.width, mode.height);
    true
}
