//! Les pinceaux (`brush.cpp`, `stockobj.c` de ReactOS, comme
//! spécification) : pleins ou nuls. Les pinceaux de stock (GetStockObject)
//! et ceux des couleurs du système (GetSysColorBrush, `ahbrSystem` du
//! `SERVERINFO`, où `user32` les lit) sont créés au démarrage, publics.
//!
//! Les polices de stock sont créées avec eux (`super::fontobj`).
//!
//! Le bitmap par défaut des DC en mémoire (DEFAULT_BITMAP, `super::surface`)
//! est créé avec eux.
//!
//! Un client crée ses pinceaux pleins (CreateSolidBrush, [`create_solid`]) :
//! à lui, avec leurs attributs (`BRUSH_ATTR`) chez lui ; `gdi32` met alors
//! leur suppression en lot.
//!
//! Pas encore : les pinceaux hachurés et à motif, le pinceau du DC
//! (`DC_BRUSH`), le cache de pinceaux du PEB, les autres objets de stock
//! (stylos, palette), un changement des couleurs du système (SetSysColors).

use alloc::sync::Arc;
use core::mem::offset_of;

use abi::gdi::{objt, stock, BrushAttr32, LO_BRUSH_TYPE};
use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL};
use abi::user::{ServerInfo32, NUM_SYSCOLORS};
use hal::sync::Once;

use super::dib::ColorRef;
use super::handles::{self, Object, OWNER_PUBLIC};

/// Un pinceau : plein, d'une couleur, ou nul (il ne peint rien).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Brush {
    pub color: ColorRef,
    /// BS_NULL (`BR_IS_NULL`).
    pub null: bool,
    /// BS_PATTERN : le handle du bitmap dont le motif vient ; 0 pour un
    /// pinceau sans motif. Le dessin du motif à venir : sa couleur de repli
    /// (`color`) sert en attendant.
    pub pattern: u32,
}

impl Brush {
    /// Un pinceau plein de `color`.
    pub const fn solid(color: ColorRef) -> Self {
        Self { color, null: false, pattern: 0 }
    }

    /// Un pinceau à motif, du bitmap GDI `bitmap`.
    pub const fn pattern(bitmap: u32) -> Self {
        Self { color: ColorRef(0), null: false, pattern: bitmap }
    }
}

/// Les pinceaux de stock, de WHITE_BRUSH à NULL_BRUSH (CreateStockObjects).
pub const STOCK_BRUSHES: [Brush; stock::NULL_BRUSH + 1] = [
    Brush::solid(ColorRef::rgb(255, 255, 255)),
    Brush::solid(ColorRef::rgb(192, 192, 192)),
    Brush::solid(ColorRef::rgb(128, 128, 128)),
    Brush::solid(ColorRef::rgb(64, 64, 64)),
    Brush::solid(ColorRef::rgb(0, 0, 0)),
    Brush { color: ColorRef(0), null: true, pattern: 0 },
];

/// Les handles des objets de stock (0 : pas encore créé).
static STOCK: Once<[u32; stock::COUNT]> = Once::new();

/// Le handle de l'objet de stock `index` ; 0 avant [`init`] ou pour un
/// objet pas encore créé.
///
/// # IRQL
/// Tout niveau.
pub fn stock_object(index: usize) -> u32 {
    STOCK.get().and_then(|objects| objects.get(index).copied()).unwrap_or(0)
}

/// Un pinceau de stock, public.
fn create_stock(brush: Brush) -> Result<u32, NtStatus> {
    let handle = handles::insert(Object::Brush(Arc::new(brush)), LO_BRUSH_TYPE, objt::BRUSH, OWNER_PUBLIC)?;
    handles::make_stock(handle)
}

/// CreateStockObjects puis CreateSysColorObjects : les pinceaux de stock,
/// puis ceux des couleurs du système (`colors`), écrits dans `ahbrSystem`.
///
/// # Panics
/// Au second appel.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage, après la table des handles et la section
/// partagée de USER.
pub fn init(colors: &[u32; NUM_SYSCOLORS]) -> Result<(), NtStatus> {
    assert!(STOCK.get().is_none(), "the stock objects created twice");
    let mut objects = [0; stock::COUNT];
    for (slot, brush) in objects.iter_mut().zip(STOCK_BRUSHES) {
        *slot = create_stock(brush)?;
    }
    for (index, logfont) in super::fontobj::stock_fonts() {
        objects[index] = super::fontobj::create_stock(logfont)?;
    }
    objects[stock::DEFAULT_BITMAP] = handles::make_stock(super::surface::create_default_bitmap()?)?;
    STOCK.call_once(|| objects);
    let mut system = [0u8; NUM_SYSCOLORS * 4];
    for (slot, &color) in system.chunks_exact_mut(4).zip(colors) {
        slot.copy_from_slice(&create_stock(Brush::solid(ColorRef(color)))?.to_le_bytes());
    }
    let section = crate::shared::section().ok_or(STATUS_UNSUCCESSFUL)?;
    let at = u64::from(crate::shared::SERVER_INFO) + offset_of!(ServerInfo32, ahbr_system) as u64;
    section.write_kernel(at, &system)
}

/// IntGdiCreateSolidBrush (CreateBrushInternal) : un pinceau plein de
/// `color`, au processus courant, avec ses attributs chez lui ; rend son
/// handle.
///
/// # Errors
/// Celles de l'allocation et de l'écriture des attributs, de la table.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn create_solid(color: u32) -> Result<u32, NtStatus> {
    use super::dc::{allocate_attr, free_attr, AttrKind};
    let (pid, attr) = allocate_attr(AttrKind::Brush)?;
    let attrs = BrushAttr32 { attr_flags: 0, color };
    let brush = Object::Brush(Arc::new(Brush::solid(ColorRef(color & 0x00FF_FFFF))));
    let inserted = ke::usermem::copy_to_user(u64::from(attr), attrs.as_bytes())
        .and_then(|()| handles::insert_with_user_data(brush, LO_BRUSH_TYPE, objt::BRUSH, pid, attr));
    if inserted.is_err() {
        free_attr(AttrKind::Brush, attr);
    }
    inserted
}

/// `CreatePatternBrush` : un pinceau à motif, du bitmap GDI `hbmp` ; rend
/// son handle GDI, au processus courant. Le motif se peint quand la tranche
/// dessin l'écrit ; le pinceau, lui, existe et se choisit.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` sans bitmap ; `STATUS_NO_MEMORY` sans place
/// pour ses attributs.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn create_pattern(hbmp: u32) -> Result<u32, NtStatus> {
    use super::dc::{allocate_attr, free_attr, AttrKind};
    if hbmp == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (pid, attr) = allocate_attr(AttrKind::Brush)?;
    let attrs = BrushAttr32 { attr_flags: 0, color: 0 };
    let brush = Object::Brush(Arc::new(Brush::pattern(hbmp)));
    let inserted = ke::usermem::copy_to_user(u64::from(attr), attrs.as_bytes())
        .and_then(|()| handles::insert_with_user_data(brush, LO_BRUSH_TYPE, objt::BRUSH, pid, attr));
    if inserted.is_err() {
        free_attr(AttrKind::Brush, attr);
    }
    inserted
}
