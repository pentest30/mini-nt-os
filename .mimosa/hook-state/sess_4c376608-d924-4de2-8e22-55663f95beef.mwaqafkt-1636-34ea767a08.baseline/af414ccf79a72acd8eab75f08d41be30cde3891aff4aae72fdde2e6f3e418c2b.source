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
use abi::ntstatus::NtStatus;

use super::dib::ColorRef;
use super::handles::{self, Object};

/// PS_SOLID.
pub const PS_SOLID: u32 = 0;
/// PS_NULL : le stylo ne dessine rien.
pub const PS_NULL: u32 = 5;

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
}
