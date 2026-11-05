//! GDI (02 §7.2) : le moteur DIB en Rust ([`dib`]), qui dessine sur une
//! surface de 32 bits par pixel, celle de l'écran ([`crate::display`]) ou
//! une bitmap en mémoire ; les régions ([`region`]) ; les dessins de USER
//! dans le noyau, bords en relief et dégradés ([`draw`]) ; les couleurs
//! système ([`syscolor`]) ; la table des handles GDI que voient les clients
//! ([`handles`]), les pinceaux ([`brush`]), les régions d'un client
//! ([`rgnobj`]), les polices ([`fontobj`]), les contextes de périphérique de
//! l'écran ([`dc`]), le texte ([`text`], ADR-013) et les appels qu'un client
//! met en lot ([`batch`]).
//!
//! Pas encore : DC en mémoire, stylos et palettes comme objets GDI,
//! transformations, lignes et courbes, BitBlt.

pub mod batch;
pub mod brush;
pub mod dc;
pub mod dib;
pub mod draw;
pub mod fontobj;
pub mod handles;
pub mod region;
pub mod rgnobj;
pub mod syscolor;
pub mod text;
