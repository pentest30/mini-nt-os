//! Les stylos (`pen.cpp` de ReactOS, comme spécification) : la ligne que
//! LineTo trace. Un stylo d'application (CreatePen) vit dans la table des
//! handles GDI, au processus qui l'a créé ; le DC sans stylo en a un
//! implicit, noir d'un pixel (BLACK_PEN de stock).
//!
//! Les styles pointillés (PS_DASH, PS_DOT…) se dessinent en sautant un
//! pixel sur deux le long du trait — une approximation des motifs de XP,
//! qui suffisent aux axes des graphes ; PS_NULL ne dessine rien. Une
//! largeur au-delà d'un pixel épaissit le trait perpendiculairement.

use alloc::sync::Arc;

use abi::gdi::{objt, LO_PEN_TYPE};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};

use super::dib::ColorRef;
use super::handles::{self, Object};

/// PS_SOLID.
pub const PS_SOLID: u32 = 0;
/// PS_NULL : le stylo ne dessine rien.
pub const PS_NULL: u32 = 5;
/// PS_TYPE_MASK et PS_STYLE_MASK (les quatre bits du style), et son type
/// cosmétique (le géométrique : le bit 0x10).
pub const PS_TYPE_MASK: u32 = 0x000F_0000;
pub const PS_STYLE_MASK: u32 = 0x0000_000F;
pub const PS_COSMETIC: u32 = 0;
/// Les styles de pinceau de ExtCreatePen : plein, rien, hachuré, à motif.
pub const BS_SOLID: u32 = 0;
pub const BS_NULL: u32 = 1;
pub const BS_HATCHED: u32 = 2;
pub const BS_PATTERN: u32 = 3;

/// Un stylo : son style (`PS_*`), sa largeur en pixels (0 et 1 : un pixel),
/// sa couleur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pen {
    pub style: u32,
    pub width: i32,
    pub color: ColorRef,
}

impl Pen {
    /// Le stylo implicite d'un DC : noir, d'un pixel.
    pub const BLACK: Self = Self { style: PS_SOLID, width: 1, color: ColorRef(0) };

    /// `CreatePen` : un stylo au processus courant ; rend son handle GDI.
    /// Les styles que Mino ne tient pas encore (cosmétiques, INSIDEFRAME…)
    /// se dessinent pleins.
    ///
    /// # Errors
    /// `STATUS_NO_MEMORY` sans place dans la table.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, dans un service système.
    pub fn create(style: u32, width: i32, color: u32) -> Result<u32, NtStatus> {
        let pen = Self { style, width: width.max(1), color: ColorRef(color & 0x00FF_FFFF) };
        let pid = super::dc::current_pid();
        handles::insert(Object::Pen(Arc::new(pen)), LO_PEN_TYPE, objt::PEN, pid)
    }

    /// NtGdiExtCreatePen (IntGdiExtCreatePen de ReactOS, comme spécification)
    /// : un stylo au processus courant, d'un style étendu. `PS_NULL` et
    /// `BS_NULL` rendent le stylo nul ; un stylo cosmétique d'un pinceau qui
    /// n'est pas plein, et un style de pinceau inconnu, sont refusés
    /// (`STATUS_INVALID_PARAMETER`). Les longs de style d'utilisateur sont
    /// lus puis jetés par l'appelant : les pointillés se dessinent en
    /// approximations, comme ceux de `CreatePen` ; `BS_HATCHED` et
    /// `BS_PATTERN` se dessinent pleins.
    ///
    /// # Errors
    /// `STATUS_INVALID_PARAMETER` pour un style ou un pinceau refusé ;
    /// `STATUS_NO_MEMORY` sans place dans la table.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, dans un service système.
    pub fn ext_create(style: u32, width: i32, brush_style: u32, color: u32) -> Result<u32, NtStatus> {
        let pen = Self::extended(style, width, brush_style, color)?;
        let pid = super::dc::current_pid();
        handles::insert(Object::Pen(Arc::new(pen)), LO_PEN_TYPE, objt::PEN, pid)
    }

    /// Le stylo d'un style étendu, avant la table des handles : `PS_NULL`
    /// et `BS_NULL` rendent le stylo nul ; un stylo cosmétique d'un pinceau
    /// qui n'est pas plein, et un style de pinceau inconnu, sont refusés.
    /// Le style stocké ne garde que ses quatre bits : les bits du type
    /// (PS_GEOMETRIC) et ceux des embouts et des jointures ne disent pas
    /// comment la ligne se dessine, et le dessin compare le style à
    /// PS_SOLID et PS_NULL (dib.rs) — PS_GEOMETRIC | PS_SOLID s'y dessinait
    /// pointillé.
    ///
    /// # Errors
    /// `STATUS_INVALID_PARAMETER` pour un style ou un pinceau refusé.
    fn extended(style: u32, width: i32, brush_style: u32, color: u32) -> Result<Self, NtStatus> {
        if (style & PS_TYPE_MASK) == PS_COSMETIC && brush_style != BS_SOLID {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if (style & PS_STYLE_MASK) == PS_NULL || brush_style == BS_NULL {
            return Ok(Self { style: PS_NULL, width: 1, color: ColorRef(0) });
        }
        if brush_style != BS_SOLID && brush_style != BS_HATCHED && brush_style != BS_PATTERN {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self { style: style & PS_STYLE_MASK, width: width.max(1), color: ColorRef(color & 0x00FF_FFFF) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_extended_style_keeps_only_its_base_style() {
        // PS_GEOMETRIC | PS_SOLID (0x10000) : plein, pas pointillé — le
        // dessin compare le style stocké à PS_SOLID.
        let pen = Pen::extended(0x0001_0000, 2, BS_SOLID, 0xFF0000).unwrap();
        assert_eq!((pen.style, pen.width, pen.color), (PS_SOLID, 2, ColorRef(0xFF0000)));
        // Les embouts et les jointures partent avec le type.
        let pen = Pen::extended(0x0001_0300 | 2, 1, BS_SOLID, 0).unwrap();
        assert_eq!(pen.style, 2, "PS_DOT, without its caps and joins");

        // Un cosmétique d'un pinceau non plein est refusé (BS_NULL avec,
        // comme IntGdiExtCreatePen) ; PS_NULL et le pinceau nul d'un
        // géométrique rendent le stylo nul.
        assert_eq!(Pen::extended(PS_COSMETIC, 1, BS_HATCHED, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(Pen::extended(PS_COSMETIC, 1, BS_NULL, 0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(Pen::extended(0x0001_0000 | 5, 3, BS_SOLID, 0).unwrap().style, PS_NULL);
        assert_eq!(Pen::extended(0x0001_0000, 3, BS_NULL, 0).unwrap().style, PS_NULL);
    }
}
