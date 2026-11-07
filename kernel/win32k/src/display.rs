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
use core::sync::atomic::{AtomicBool, Ordering};

use hal::sync::{KSpinLock, Once};

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
/// Un dessin à la fois.
static DRAWING: KSpinLock<()> = KSpinLock::new(());
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
    let _one = DRAWING.lock();
    if !ACQUIRED.swap(true, Ordering::AcqRel) {
        // Le premier dessin de win32k prend l'écran : le rideau de démarrage
        // se lève ici, avant que la surface ne soit touchée.
        hal::splash::hide();
        driver.acquire();
    }
    driver.with_surface(&mut draw);
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
