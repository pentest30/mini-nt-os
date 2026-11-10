//! GDI (02 §7.2) : le moteur DIB en Rust ([`dib`]), qui dessine sur une
//! surface de 32 bits par pixel, celle de l'écran ([`crate::display`]) ou
//! une bitmap en mémoire ; les régions ([`region`]) ; les dessins de USER
//! dans le noyau, bords en relief et dégradés ([`draw`]) ; les couleurs
//! système ([`syscolor`]) ; la table des handles GDI que voient les clients
//! ([`handles`]) et les capacités de l'écran ([`devcaps`]), les pinceaux
//! ([`brush`]), les régions d'un client ([`rgnobj`]), les polices
//! ([`fontobj`]), les bitmaps ([`surface`] : DIB sections), les contextes de
//! périphérique de l'écran et en mémoire ([`dc`]), BitBlt ([`bitblt`]), le
//! texte ([`text`], ADR-013) et les appels qu'un client met en lot
//! ([`batch`]).
//!
//! Pas encore : stylos et palettes comme objets GDI, transformations, lignes
//! et courbes, StretchBlt.

pub mod batch;
pub mod bitblt;
pub mod brush;
pub mod dc;
pub mod devcaps;
pub mod dib;
pub mod draw;
pub mod fontobj;
pub mod handles;
pub mod pen;
pub mod region;
pub mod rgnobj;
pub mod surface;
pub mod syscolor;
pub mod text;

use dc::{current_pid, free_attr, AttrKind};
use handles::Object;

/// GreDeleteObject : l'objet `handle` du processus courant (ni de stock, ni
/// public, ni un DC, ni un bitmap choisi dans un DC) quitte la table ; une
/// région ou un pinceau rend ses attributs, une DIB section quitte la
/// mémoire du processus. `false` si rien n'a été supprimé.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn delete_object(handle: u32) -> bool {
    let pid = current_pid();
    let deletable = |object: &Object| match object {
        Object::Dc(_) => false,
        Object::Bitmap(surface) => !surface.is_selected(),
        _ => true,
    };
    let Some((object, attr)) = handles::delete(handle, pid, deletable) else { return false };
    match object {
        Object::Region(_) if attr != 0 => free_attr(AttrKind::Region, attr),
        Object::Brush(_) if attr != 0 => free_attr(AttrKind::Brush, attr),
        Object::Bitmap(surface) => surface.release_user_view(pid),
        _ => {}
    }
    true
}
