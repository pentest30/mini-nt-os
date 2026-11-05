//! Les pinceaux (`brush.cpp`, `stockobj.c` de ReactOS, comme
//! spécification) : pleins ou nuls. Les pinceaux de stock (GetStockObject)
//! et ceux des couleurs du système (GetSysColorBrush, `ahbrSystem` du
//! `SERVERINFO`, où `user32` les lit) sont créés au démarrage, publics.
//!
//! Les polices de stock sont créées avec eux (`super::fontobj`).
//!
//! Pas encore : les pinceaux d'un client (CreateSolidBrush, leur
//! `BRUSH_ATTR`), hachurés et à motif, le pinceau du DC (`DC_BRUSH`), les
//! autres objets de stock (stylos, palette), un changement des couleurs du
//! système (SetSysColors).

use alloc::sync::Arc;
use core::mem::offset_of;

use abi::gdi::{objt, stock, LO_BRUSH_TYPE};
use abi::ntstatus::{NtStatus, STATUS_UNSUCCESSFUL};
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
}

impl Brush {
    /// Un pinceau plein de `color`.
    pub const fn solid(color: ColorRef) -> Self {
        Self { color, null: false }
    }
}

/// Les pinceaux de stock, de WHITE_BRUSH à NULL_BRUSH (CreateStockObjects).
pub const STOCK_BRUSHES: [Brush; stock::NULL_BRUSH + 1] = [
    Brush::solid(ColorRef::rgb(255, 255, 255)),
    Brush::solid(ColorRef::rgb(192, 192, 192)),
    Brush::solid(ColorRef::rgb(128, 128, 128)),
    Brush::solid(ColorRef::rgb(64, 64, 64)),
    Brush::solid(ColorRef::rgb(0, 0, 0)),
    Brush { color: ColorRef(0), null: true },
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
    STOCK.call_once(|| objects);
    let mut system = [0u8; NUM_SYSCOLORS * 4];
    for (slot, &color) in system.chunks_exact_mut(4).zip(colors) {
        slot.copy_from_slice(&create_stock(Brush::solid(ColorRef(color)))?.to_le_bytes());
    }
    let section = crate::shared::section().ok_or(STATUS_UNSUCCESSFUL)?;
    let at = u64::from(crate::shared::SERVER_INFO) + offset_of!(ServerInfo32, ahbr_system) as u64;
    section.write_kernel(at, &system)
}
