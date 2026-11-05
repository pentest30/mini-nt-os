//! Les régions de GDI (`region.c` de ReactOS, comme spécification) : un
//! objet de la table des handles ([`super::handles`]) qui tient une
//! [`Region`], au processus qui l'a créée (NtGdiCreateRectRgn), avec ses
//! attributs (`RGN_ATTR`) dans la mémoire de ce processus. `gdi32` y lit la
//! complexité de la région et le rectangle qui la tient (GetRgnBox), et y
//! change lui-même une région vide ou rectangulaire (SetRectRgn,
//! CombineRgn) en la marquant `ATTR_RGN_DIRTY`. Le noyau reprend ces
//! attributs avant de se servir de la région (REGION_vSyncRegion :
//! [`synced`]), puis les réécrit (REGION_UnlockRgn : [`attributes`]).
//!
//! Deux threads d'un processus qui changent ensemble la même région n'ont
//! pas de verrou entre la lecture de ses attributs et leur écriture (ReactOS
//! verrouille l'objet) : l'un des changements peut se perdre, sans danger
//! pour le noyau.
//!
//! Pas encore : les autres formes (ellipses, polygones, ExtCreateRegion),
//! OffsetRgn, EqualRgn, PtInRegion, RectInRegion, GetRegionData, les
//! régions d'un processus rendues à sa fin.

use alloc::sync::Arc;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::gdi::{objt, RgnAttr32, ATTR_RGN_DIRTY, ATTR_RGN_VALID, LO_REGION_TYPE, NULLREGION, SIMPLEREGION};
use abi::ntstatus::NtStatus;
use abi::user::Rect32;
use hal::sync::KSpinLock;
use ke::usermem::{copy_from_user, copy_to_user};

use super::dc::{allocate_attr, current_pid, free_attr, AttrKind};
use super::handles::{self, Object};
use super::region::Region;

/// Une région de GDI.
pub struct RegionObject {
    region: KSpinLock<Region>,
    /// L'adresse de ses attributs chez son propriétaire.
    attr: u32,
}

/// REGION_vSyncRegion : `region` telle que la disent ses attributs `attr`
/// quand `gdi32` les a changés (vide, ou un rectangle) ; des attributs qui
/// disent une région complexe sont ignorés (journalisé une fois).
pub fn synced(region: Region, attr: &RgnAttr32) -> Region {
    if attr.attr_flags & ATTR_RGN_DIRTY == 0 {
        return region;
    }
    let rect = attr.rect;
    match attr.complexity as i32 {
        NULLREGION => Region::default(),
        SIMPLEREGION => Region::from_corners(rect.left, rect.top, rect.right, rect.bottom),
        _ => {
            static REPORTED: AtomicBool = AtomicBool::new(false);
            if !REPORTED.swap(true, Ordering::Relaxed) {
                log::warn!("win32k: region attributes changed to a complex region: ignored");
            }
            region
        }
    }
}

/// REGION_UnlockRgn : les attributs de `region`, à partir des drapeaux
/// `flags` qu'ils avaient : sa complexité, le rectangle qui la tient,
/// `ATTR_RGN_VALID` (et plus `ATTR_RGN_DIRTY`).
pub fn attributes(region: &Region, flags: u32) -> RgnAttr32 {
    let bounds = region.bounds();
    RgnAttr32 {
        attr_flags: flags & !(ATTR_RGN_DIRTY | ATTR_RGN_VALID) | ATTR_RGN_VALID,
        complexity: region.complexity() as u32,
        rect: Rect32 { left: bounds.left, top: bounds.top, right: bounds.right, bottom: bounds.bottom },
    }
}

impl RegionObject {
    /// Ses attributs, chez le processus courant.
    fn read_attr(&self) -> Option<RgnAttr32> {
        let mut bytes = [0u8; size_of::<RgnAttr32>()];
        copy_from_user(&mut bytes, u64::from(self.attr)).ok()?;
        RgnAttr32::from_bytes(&bytes)
    }

    /// REGION_LockRgn, `change`, REGION_UnlockRgn : la région, avec ce que
    /// `gdi32` a changé dans ses attributs, passe par `change`, puis ses
    /// attributs sont réécrits.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, dans le processus propriétaire, sans rien tenir.
    pub fn update<R>(&self, change: impl FnOnce(&mut Region) -> R) -> R {
        let attr = self.read_attr();
        let mut region = self.region.lock().clone();
        if let Some(attr) = &attr {
            region = synced(region, attr);
        }
        let result = change(&mut region);
        let written = attributes(&region, attr.map_or(0, |attr| attr.attr_flags));
        *self.region.lock() = region;
        let _ = copy_to_user(u64::from(self.attr), written.as_bytes());
        result
    }

    /// La région, avec ce que `gdi32` a changé dans ses attributs.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, dans le processus propriétaire, sans rien tenir.
    pub fn get(&self) -> Region {
        self.update(|region| region.clone())
    }

    /// La région devient `region`.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, dans le processus propriétaire, sans rien tenir.
    pub fn set(&self, region: Region) {
        self.update(|current| *current = region);
    }
}

/// NtGdiCreateRectRgn : une région du rectangle de ces coins, au processus
/// courant, avec ses attributs chez lui ; rend son handle.
///
/// # Errors
/// Ceux de l'allocation des attributs, de leur écriture, de la table.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn create_rect(x1: i32, y1: i32, x2: i32, y2: i32) -> Result<u32, NtStatus> {
    let (pid, attr) = allocate_attr(AttrKind::Region)?;
    let region = Region::from_corners(x1, y1, x2, y2);
    let written = attributes(&region, 0);
    let object = Object::Region(Arc::new(RegionObject { region: KSpinLock::new(region), attr }));
    let created = copy_to_user(u64::from(attr), written.as_bytes())
        .and_then(|()| handles::insert_with_user_data(object, LO_REGION_TYPE, objt::RGN, pid, attr));
    if created.is_err() {
        free_attr(AttrKind::Region, attr);
    }
    created
}

/// REGION_LockRgn : la région de `hrgn`, si elle est au processus courant.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn lock(hrgn: u32) -> Option<Arc<RegionObject>> {
    match handles::get(hrgn, current_pid())? {
        Object::Region(region) => Some(region),
        _ => None,
    }
}

/// GreDeleteObject : l'objet `handle` du processus courant (ni de stock, ni
/// public, ni un DC) quitte la table ; une région rend ses attributs.
/// `false` si rien n'a été supprimé.
///
/// # IRQL
/// PASSIVE_LEVEL, sans rien tenir.
pub fn delete_object(handle: u32) -> bool {
    let deletable = |object: &Object| !matches!(object, Object::Dc(_));
    let Some((object, user_data)) = handles::delete(handle, current_pid(), deletable) else { return false };
    if matches!(object, Object::Region(_)) && user_data != 0 {
        free_attr(AttrKind::Region, user_data);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::Rect;
    use abi::gdi::COMPLEXREGION;

    fn attr(flags: u32, complexity: i32, rect: Rect32) -> RgnAttr32 {
        RgnAttr32 { attr_flags: flags, complexity: complexity as u32, rect }
    }

    const RECT: Rect32 = Rect32 { left: 30, top: 40, right: 10, bottom: 20 };

    #[test]
    fn what_gdi32_changed_comes_back() {
        let old = Region::from_rect(Rect::new(0, 0, 5, 5));
        let rect = synced(old.clone(), &attr(ATTR_RGN_VALID | ATTR_RGN_DIRTY, SIMPLEREGION, RECT));
        assert_eq!(rect.rects(), [Rect::new(10, 20, 30, 40)], "corners in any order");
        assert!(synced(old.clone(), &attr(ATTR_RGN_DIRTY, NULLREGION, RECT)).is_empty());
        assert_eq!(synced(old.clone(), &attr(ATTR_RGN_VALID, NULLREGION, RECT)), old, "not changed");
        assert_eq!(synced(old.clone(), &attr(ATTR_RGN_DIRTY, COMPLEXREGION, RECT)), old, "corrupted: ignored");
    }

    #[test]
    fn the_attributes_say_the_region_and_that_it_is_valid() {
        let mut region = Region::from_rect(Rect::new(0, 0, 10, 10));
        let written = attributes(&region, ATTR_RGN_DIRTY | 0x4);
        assert_eq!(written.attr_flags, ATTR_RGN_VALID | 0x4, "no longer dirty");
        assert_eq!(
            (written.complexity, written.rect),
            (SIMPLEREGION as u32, Rect32 { left: 0, top: 0, right: 10, bottom: 10 })
        );
        region.subtract_rect(Rect::new(5, 5, 10, 10));
        assert_eq!(attributes(&region, 0).complexity, COMPLEXREGION as u32);
        let empty = attributes(&Region::default(), ATTR_RGN_VALID);
        assert_eq!(
            (empty.attr_flags, empty.complexity, empty.rect),
            (ATTR_RGN_VALID, NULLREGION as u32, Rect32::default())
        );
    }
}
