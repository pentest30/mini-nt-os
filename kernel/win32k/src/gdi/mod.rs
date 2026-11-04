//! GDI (02 §7.2) : le moteur DIB en Rust ([`dib`]), qui dessine sur une
//! surface de 32 bits par pixel, celle de l'écran ([`crate::display`]) ou
//! une bitmap en mémoire ; les régions ([`region`]) ; les dessins de USER
//! dans le noyau, bords en relief et dégradés ([`draw`]) ; les couleurs
//! système ([`syscolor`]) ; la table des handles GDI que voient les clients
//! ([`handles`]), les pinceaux ([`brush`]), les contextes de périphérique
//! de l'écran ([`dc`]) et les appels qu'un client met en lot ([`batch`]).
//!
//! Pas encore : DC en mémoire, stylos, régions, palettes et polices comme
//! objets GDI, transformations, texte (ADR-013), lignes et courbes, BitBlt.

pub mod batch;
pub mod brush;
pub mod dc;
pub mod dib;
pub mod draw;
pub mod handles;
pub mod region;
pub mod syscolor;
