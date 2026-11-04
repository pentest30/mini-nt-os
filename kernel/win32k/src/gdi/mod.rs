//! GDI (02 §7.2) : le moteur DIB en Rust ([`dib`]), qui dessine sur une
//! surface de 32 bits par pixel, celle de l'écran ([`crate::display`]) ou
//! une bitmap en mémoire ; les régions ([`region`]) ; les dessins de USER
//! dans le noyau, bords en relief et dégradés ([`draw`]) ; les couleurs
//! système ([`syscolor`]).
//!
//! Pas encore : contextes de périphérique, objets GDI (pinceaux, stylos,
//! régions, palettes, polices) et leur table de handles partagée,
//! transformations, texte (ADR-013), lignes et courbes, ROP autres que la
//! copie d'un motif plein.

pub mod dib;
pub mod draw;
pub mod region;
pub mod syscolor;
