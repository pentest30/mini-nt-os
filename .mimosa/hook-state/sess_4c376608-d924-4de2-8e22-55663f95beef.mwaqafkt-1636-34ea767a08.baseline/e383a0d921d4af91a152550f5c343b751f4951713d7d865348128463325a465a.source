//! La table des handles GDI (`gdiobj.c` de ReactOS, comme spécification) :
//! ses entrées sont dans une section que chaque processus GUI voit en
//! lecture seule (`PEB.GdiSharedHandleTable`, [`map_into`]), où `gdi32`
//! vérifie un handle avant de s'en servir (GdiValidateHandle) et trouve les
//! attributs d'un DC (GdiGetHandleUserData) ; le noyau garde les objets.
//!
//! Le handle de l'entrée `i` est `FullUnique << 16 | i` : le type du handle,
//! le bit des objets de stock et un compte de reprises
//! (ENTRY_hInsertObject). Les dix premières entrées ne servent pas
//! (`RESERVE_ENTRIES_COUNT`). Un objet est à un processus (son PID), public
//! (0 : les objets de stock) ou à personne ([`OWNER_NONE`] : un DC du cache
//! au repos) ; seul son propriétaire, ou tout processus pour un objet
//! public, s'en sert ([`get`]).
//!
//! L'entrée d'un client nomme l'objet du noyau (`KernelData`) par une
//! adresse du serveur fictive ([`kernel_data`]), qu'il ne suit jamais : un
//! objet du noyau 64 bits n'a pas d'adresse sur 32 bits.
//!
//! Une entrée rendue ([`delete`], ENTRY_vPushFreeEntry) perd son type, son
//! propriétaire et ses attributs, et compte une reprise de plus : ses
//! anciens handles ne trouvent plus rien. Les entrées rendues sont reprises
//! les premières, la dernière rendue d'abord.
//!
//! Pas encore : les objets d'un processus rendus à sa fin ; les verrous
//! partagés et exclusifs ; le cache de handles du PEB (`GdiHandleBuffer`) ;
//! les polices publiques (`cfPublic`, hors de la vue : `gdi32` ne les lit
//! pas). Les capacités de l'écran (`DevCaps`) suivent les entrées
//! ([`set_device_caps`], `super::devcaps`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use abi::gdi::{
    gdi_entry_offset, DevCaps32, GdiSharedTail32, GdiTableEntry32, GDI_ENTRY_REUSE_INCREMENT, GDI_ENTRY_STOCK_MASK,
    GDI_HANDLE_COUNT, GDI_HANDLE_INDEX_MASK, GDI_HANDLE_STOCK_MASK, GDI_HANDLE_TYPE_MASK, GDI_SHARED_TAIL,
    RESERVE_ENTRIES_COUNT,
};
use abi::ntstatus::{NtStatus, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_UNSUCCESSFUL};
use hal::sync::{KSpinLock, Once};
use mm::address_space::AddressSpace;
use mm::address_space::ViewOptions;
use mm::section::Section;
use mm::vad::PageProtect;

use super::brush::Brush;
use super::dc::Dc;
use super::rgnobj::RegionObject;

/// GDI_OBJ_HMGR_PUBLIC : un objet de tous (les objets de stock).
pub const OWNER_PUBLIC: u32 = 0;
/// GDI_OBJ_HMGR_NONE : un objet de personne, dont aucun processus ne se
/// sert (un DC du cache entre deux GetDC).
pub const OWNER_NONE: u32 = 0x8000_0012;

/// La taille de la vue d'un client : les entrées, puis les capacités de
/// l'écran jusqu'à `pvLangPack`, en pages entières.
pub const VIEW_SIZE: u32 = (GDI_SHARED_TAIL + size_of::<GdiSharedTail32>() as u32).next_multiple_of(0x1000);

/// L'adresse du serveur, fictive, de l'objet de l'entrée `index`.
pub const fn kernel_data(index: u32) -> u32 {
    0xBE00_0000 + (index << 8)
}

/// Un objet de GDI.
#[derive(Clone)]
pub enum Object {
    Dc(Arc<Dc>),
    Brush(Arc<Brush>),
    Pen(Arc<super::pen::Pen>),
    Region(Arc<RegionObject>),
    Font(Arc<super::fontobj::FontObject>),
    Bitmap(Arc<super::surface::Surface>),
}

/// Une entrée prise ou rendue : l'objet (aucun pour une entrée rendue),
/// l'entrée telle que la voit un client.
struct Slot {
    object: Option<Object>,
    entry: GdiTableEntry32,
}

/// Les entrées déjà prises, à partir de `RESERVE_ENTRIES_COUNT`, et celles
/// d'entre elles qui sont rendues.
#[derive(Default)]
pub struct Table {
    slots: Vec<Slot>,
    free: Vec<u32>,
}

impl Table {
    /// GDIOBJ_hInsertObject : `object`, d'un handle de type `handle_type`
    /// (`GDILoObjType`) et du type de base `objt`, entre à `owner` dans la
    /// dernière entrée rendue, sinon dans la première jamais prise. Rend son
    /// handle et l'entrée du client ; `None` si la table est pleine.
    pub fn insert(&mut self, object: Object, handle_type: u32, objt: u8, owner: u32) -> Option<(u32, GdiTableEntry32)> {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                let index = RESERVE_ENTRIES_COUNT + self.slots.len() as u32;
                if index >= GDI_HANDLE_COUNT {
                    return None;
                }
                self.slots.push(Slot { object: None, entry: GdiTableEntry32::default() });
                index
            }
        };
        let slot = &mut self.slots[(index - RESERVE_ENTRIES_COUNT) as usize];
        let reuse = slot.entry.full_unique & 0xFF00;
        slot.entry = GdiTableEntry32 {
            kernel_data: kernel_data(index),
            process_id: owner,
            full_unique: reuse | ((handle_type & GDI_HANDLE_TYPE_MASK) >> 16) as u16,
            object_type: objt & 0x1F,
            flags: 0,
            user_data: 0,
        };
        slot.object = Some(object);
        Some((handle_of(index, &slot.entry), slot.entry))
    }

    /// L'entrée de `handle`, si elle a un objet et a son type, son bit de
    /// stock et son compte de reprises.
    fn slot(&self, handle: u32) -> Option<&Slot> {
        let index = (handle & GDI_HANDLE_INDEX_MASK).checked_sub(RESERVE_ENTRIES_COUNT)?;
        self.slots
            .get(index as usize)
            .filter(|slot| slot.object.is_some() && u32::from(slot.entry.full_unique) == handle >> 16)
    }

    fn slot_mut(&mut self, handle: u32) -> Option<&mut Slot> {
        let index = (handle & GDI_HANDLE_INDEX_MASK).checked_sub(RESERVE_ENTRIES_COUNT)?;
        self.slots
            .get_mut(index as usize)
            .filter(|slot| slot.object.is_some() && u32::from(slot.entry.full_unique) == handle >> 16)
    }

    /// Les handles des objets du processus `pid`, dans l'ordre des entrées.
    pub fn owned_by(&self, pid: u32) -> Vec<u32> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.object.is_some() && slot.entry.process_id == pid && pid != OWNER_PUBLIC)
            .map(|(index, slot)| handle_of(RESERVE_ENTRIES_COUNT + index as u32, &slot.entry))
            .collect()
    }

    /// L'objet de `handle` et son propriétaire.
    pub fn get(&self, handle: u32) -> Option<(Object, u32)> {
        let slot = self.slot(handle)?;
        Some((slot.object.clone()?, slot.entry.process_id))
    }

    /// ENTRY_vPushFreeEntry : l'entrée de `handle` est rendue ; rend son
    /// objet et l'entrée du client, sans type ni propriétaire, une reprise
    /// de plus.
    pub fn remove(&mut self, handle: u32) -> Option<(Object, GdiTableEntry32)> {
        let slot = self.slot_mut(handle)?;
        let object = slot.object.take()?;
        let reuse = (slot.entry.full_unique & 0xFF00).wrapping_add(GDI_ENTRY_REUSE_INCREMENT);
        slot.entry = GdiTableEntry32 { full_unique: reuse, ..GdiTableEntry32::default() };
        let entry = slot.entry;
        self.free.push(handle & GDI_HANDLE_INDEX_MASK);
        Some((object, entry))
    }

    /// L'objet de `handle`, s'il est au processus `pid` ou public
    /// (GDIOBJ_ReferenceObjectByHandle).
    pub fn get_for(&self, handle: u32, pid: u32) -> Option<Object> {
        let (object, owner) = self.get(handle)?;
        (owner == pid || owner == OWNER_PUBLIC).then_some(object)
    }

    /// GDIOBJ_vSetObjectOwner : `handle` est désormais à `owner`. Rend
    /// l'entrée du client.
    pub fn set_owner(&mut self, handle: u32, owner: u32) -> Option<GdiTableEntry32> {
        let slot = self.slot_mut(handle)?;
        slot.entry.process_id = owner;
        Some(slot.entry)
    }

    /// GDIOBJ_vSetObjectAttr : les attributs de `handle` sont en `user_data`
    /// chez son propriétaire (0 : aucun). Rend l'entrée du client.
    pub fn set_user_data(&mut self, handle: u32, user_data: u32) -> Option<GdiTableEntry32> {
        let slot = self.slot_mut(handle)?;
        slot.entry.user_data = user_data;
        Some(slot.entry)
    }

    /// GDIOBJ_ConvertToStockObj : `handle` devient un objet de stock, public.
    /// Rend son nouveau handle (avec le bit de stock) et l'entrée du client.
    pub fn make_stock(&mut self, handle: u32) -> Option<(u32, GdiTableEntry32)> {
        let slot = self.slot_mut(handle)?;
        slot.entry.full_unique |= GDI_ENTRY_STOCK_MASK;
        slot.entry.process_id = OWNER_PUBLIC;
        Some((handle | GDI_HANDLE_STOCK_MASK, slot.entry))
    }
}

/// Le handle de l'entrée `index`, telle que `entry` la décrit.
fn handle_of(index: u32, entry: &GdiTableEntry32) -> u32 {
    u32::from(entry.full_unique) << 16 | index
}

/// La table.
static TABLE: KSpinLock<Table> = KSpinLock::new(Table { slots: Vec::new(), free: Vec::new() });

/// La section des entrées, une fois créée.
static SECTION: Once<Arc<Section>> = Once::new();

/// Crée la section de la table (des pages du fichier d'échange, à zéro,
/// prises à la première écriture).
///
/// # Panics
/// Au second appel.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn init() -> Result<(), NtStatus> {
    assert!(SECTION.get().is_none(), "the GDI handle table created twice");
    let section = Section::create_pagefile(u64::from(VIEW_SIZE), PageProtect::READWRITE)?;
    SECTION.call_once(|| section);
    Ok(())
}

/// GDI_MapHandleTable : projette la table en lecture seule
/// (`SEC_NO_CHANGE`) dans `space` ; rend l'adresse de la vue.
/// `STATUS_UNSUCCESSFUL` avant [`init`].
///
/// # IRQL
/// <= APC_LEVEL.
pub fn map_into(space: &AddressSpace) -> Result<u32, NtStatus> {
    let section = SECTION.get().ok_or(STATUS_UNSUCCESSFUL)?;
    let options = ViewOptions { top_down: true, no_change: true };
    let view = space.map_view_with(section, 0, 0, u64::from(VIEW_SIZE), PageProtect::READONLY, options)?;
    Ok(view.base as u32)
}

/// Écrit `caps`, les capacités de l'écran, après les entrées de la section.
/// `STATUS_UNSUCCESSFUL` avant [`init`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_device_caps(caps: &DevCaps32) -> Result<(), NtStatus> {
    let section = SECTION.get().ok_or(STATUS_UNSUCCESSFUL)?;
    let tail = GdiSharedTail32 { dev_caps: *caps, ..GdiSharedTail32::default() };
    section.write_kernel(u64::from(GDI_SHARED_TAIL), &tail.as_bytes()[..size_of::<DevCaps32>()])
}

/// Écrit l'entrée `entry` du handle `handle` dans la section, si elle
/// existe (pas dans les tests de l'hôte).
fn publish(handle: u32, entry: &GdiTableEntry32) -> Result<(), NtStatus> {
    match SECTION.get() {
        Some(section) => {
            section.write_kernel(u64::from(gdi_entry_offset(handle & GDI_HANDLE_INDEX_MASK)), entry.as_bytes())
        }
        None => Ok(()),
    }
}

/// Une entrée de plus : `object`, à `owner` ; rend son handle.
///
/// # Errors
/// `STATUS_INSUFFICIENT_RESOURCES` pour une table pleine ; celles de
/// l'écriture de la section.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
/// Le nombre d'objets GDI du processus `pid` (GetGuiResources,
/// GR_GDIOBJECTS) ; les objets de stock ne comptent pas (owner public).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn count_of(pid: u32) -> u32 {
    TABLE.lock().slots.iter().filter(|slot| slot.object.is_some() && slot.entry.process_id == pid).count() as u32
}

/// Les handles des objets du processus `pid` (GDI_CleanupForProcess).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn owned_by(pid: u32) -> Vec<u32> {
    TABLE.lock().owned_by(pid)
}

pub fn insert(object: Object, handle_type: u32, objt: u8, owner: u32) -> Result<u32, NtStatus> {
    let mut table = TABLE.lock();
    let (handle, entry) = table.insert(object, handle_type, objt, owner).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    publish(handle, &entry)?;
    Ok(handle)
}

/// Une entrée de plus : `object`, à `owner`, ses attributs en `user_data`
/// chez lui (GDIOBJ_vSetObjectAttr) ; rend son handle.
///
/// # Errors
/// Comme [`insert`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn insert_with_user_data(
    object: Object,
    handle_type: u32,
    objt: u8,
    owner: u32,
    user_data: u32,
) -> Result<u32, NtStatus> {
    let mut table = TABLE.lock();
    let (handle, _) = table.insert(object, handle_type, objt, owner).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let entry = table.set_user_data(handle, user_data).ok_or(STATUS_INVALID_HANDLE)?;
    if let Err(status) = publish(handle, &entry) {
        if let Some((_, entry)) = table.remove(handle) {
            let _ = publish(handle, &entry);
        }
        return Err(status);
    }
    Ok(handle)
}

/// L'objet de `handle`, s'il est au processus `pid` ou public
/// (GDIOBJ_ReferenceObjectByHandle).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get(handle: u32, pid: u32) -> Option<Object> {
    TABLE.lock().get_for(handle, pid)
}

/// Le pinceau de `handle`, s'il est au processus `pid` ou public.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn brush(handle: u32, pid: u32) -> Option<Arc<Brush>> {
    match get(handle, pid)? {
        Object::Brush(brush) => Some(brush),
        _ => None,
    }
}

/// L'objet de `handle` et son propriétaire, quel qu'il soit
/// (GreGetObjectOwner).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn get_with_owner(handle: u32) -> Option<(Object, u32)> {
    TABLE.lock().get(handle)
}

/// GreDeleteObject : l'objet de `handle`, au processus `pid` (ni de stock,
/// ni public), quitte la table, si `deletable` l'accepte ; rend l'objet et
/// les attributs qu'il avait chez `pid`.
///
/// # Errors
/// Celles de l'écriture de la section (l'objet a quand même quitté la
/// table).
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn delete(handle: u32, pid: u32, deletable: impl FnOnce(&Object) -> bool) -> Option<(Object, u32)> {
    if handle & GDI_HANDLE_STOCK_MASK != 0 {
        return None;
    }
    let mut table = TABLE.lock();
    let slot = table.slot(handle)?;
    if slot.entry.process_id != pid || pid == OWNER_PUBLIC || !deletable(slot.object.as_ref()?) {
        return None;
    }
    let user_data = slot.entry.user_data;
    let (object, entry) = table.remove(handle)?;
    let _ = publish(handle, &entry);
    Some((object, user_data))
}

/// `handle` est désormais à `owner`, ses attributs en `user_data` chez lui.
///
/// # Errors
/// `STATUS_INVALID_HANDLE` pour un handle sans objet ; celles de l'écriture
/// de la section.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn set_owner(handle: u32, owner: u32, user_data: u32) -> Result<(), NtStatus> {
    let mut table = TABLE.lock();
    table.set_owner(handle, owner).ok_or(STATUS_INVALID_HANDLE)?;
    let entry = table.set_user_data(handle, user_data).ok_or(STATUS_INVALID_HANDLE)?;
    publish(handle, &entry)
}

/// `handle` devient un objet de stock ; rend son nouveau handle.
///
/// # Errors
/// Comme [`set_owner`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn make_stock(handle: u32) -> Result<u32, NtStatus> {
    let mut table = TABLE.lock();
    let (stock, entry) = table.make_stock(handle).ok_or(STATUS_INVALID_HANDLE)?;
    publish(stock, &entry)?;
    Ok(stock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdi::dib::ColorRef;
    use abi::gdi::{objt, GDI_HANDLE_BASETYPE_MASK, LO_BRUSH_TYPE, LO_DC_TYPE};

    fn brush() -> Object {
        Object::Brush(Arc::new(Brush::solid(ColorRef(0x123456))))
    }

    /// GdiValidateHandle of the pinned gdi32: the entry's base type is not
    /// zero, its FullUnique carries the handle's type, its owner (lock bit
    /// aside) is none or `pid`.
    fn gdi32_validates(entry: &GdiTableEntry32, handle: u32, pid: u32) -> bool {
        let type_ = u32::from(entry.full_unique) | u32::from(entry.object_type) << 16 | u32::from(entry.flags) << 24;
        type_ & GDI_HANDLE_BASETYPE_MASK != 0
            && (type_ << 16) & GDI_HANDLE_TYPE_MASK == handle & GDI_HANDLE_TYPE_MASK
            && (entry.process_id & !1 == 0 || entry.process_id & !1 == pid)
    }

    #[test]
    fn handles_carry_their_type_after_the_reserved_entries() {
        let mut table = Table::default();
        let (first, entry) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        assert_eq!(first, 0x0010_000A);
        assert_eq!((entry.full_unique, entry.object_type, entry.process_id), (0x10, 0x10, 0x44));
        assert_eq!(entry.kernel_data, 0xBE00_0A00);
        let (second, _) = table.insert(brush(), LO_DC_TYPE, objt::DC, 0x44).unwrap();
        assert_eq!(second, 0x0001_000B);
        assert!(gdi32_validates(&entry, first, 0x44));
        assert!(!gdi32_validates(&entry, first, 0x48), "another process");
        assert!(!gdi32_validates(&entry, first & !GDI_HANDLE_TYPE_MASK | LO_DC_TYPE, 0x44), "another type");
    }

    #[test]
    fn a_handle_finds_its_object_only_with_its_upper_half() {
        let mut table = Table::default();
        let (handle, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        assert!(table.get(handle).is_some());
        assert!(table.get(handle | GDI_HANDLE_STOCK_MASK).is_none(), "the stock bit");
        assert!(table.get(handle + 0x0100_0000).is_none(), "another reuse");
        assert!(table.get(handle & !GDI_HANDLE_TYPE_MASK | LO_DC_TYPE).is_none(), "another type");
        assert!(table.get(handle + 1).is_none(), "an entry not taken");
        assert!(table.get(5).is_none(), "a reserved entry");
    }

    #[test]
    fn a_stock_object_is_public_with_the_stock_bit() {
        let mut table = Table::default();
        let (handle, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        let (stock, entry) = table.make_stock(handle).unwrap();
        assert_eq!(stock, 0x0090_000A);
        assert_eq!((entry.full_unique, entry.process_id), (0x90, OWNER_PUBLIC));
        assert!(gdi32_validates(&entry, stock, 0x1234), "any process");
        assert!(table.get(handle).is_none(), "the old handle");
        assert_eq!(table.get(stock).map(|(_, owner)| owner), Some(OWNER_PUBLIC));
    }

    #[test]
    fn owners_and_attributes_change() {
        let mut table = Table::default();
        let (handle, _) = table.insert(brush(), LO_DC_TYPE, objt::DC, OWNER_NONE).unwrap();
        let entry = table.set_owner(handle, 0x44).unwrap();
        assert_eq!(entry.process_id, 0x44);
        let entry = table.set_user_data(handle, 0x0034_0000).unwrap();
        assert_eq!((entry.process_id, entry.user_data), (0x44, 0x0034_0000));
        let entry = table.set_owner(handle, OWNER_NONE).unwrap();
        assert!(!gdi32_validates(&entry, handle, 0x44), "a DC of nobody");
        assert!(table.set_owner(handle + 1, 0x44).is_none());
        assert!(table.set_owner(handle | GDI_HANDLE_STOCK_MASK, 0x44).is_none(), "another upper half");
        assert!(table.set_user_data(handle + 0x0100_0000, 0).is_none(), "another reuse");
        assert!(table.make_stock(handle & !GDI_HANDLE_TYPE_MASK | LO_BRUSH_TYPE).is_none(), "another type");
        assert_eq!(table.get(handle).map(|(_, owner)| owner), Some(OWNER_NONE), "unchanged");
    }

    #[test]
    fn only_the_owner_uses_an_object_unless_it_is_public() {
        let mut table = Table::default();
        let (handle, _) = table.insert(brush(), LO_DC_TYPE, objt::DC, OWNER_NONE).unwrap();
        assert!(table.get_for(handle, 0x44).is_none(), "a DC of nobody");
        table.set_owner(handle, 0x44);
        assert!(table.get_for(handle, 0x44).is_some());
        assert!(table.get_for(handle, 0x48).is_none(), "another process");
        let (brush_handle, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x48).unwrap();
        let (stock, _) = table.make_stock(brush_handle).unwrap();
        assert!(table.get_for(stock, 0x44).is_some() && table.get_for(stock, 0x48).is_some(), "public");
    }

    #[test]
    fn a_removed_entry_comes_back_once_more_reused() {
        let mut table = Table::default();
        let (first, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        let (second, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        let (_, entry) = table.remove(first).expect("taken");
        assert_eq!(
            (entry.full_unique, entry.object_type, entry.process_id, entry.user_data, entry.kernel_data),
            (0x0100, 0, 0, 0, 0)
        );
        assert!(!gdi32_validates(&entry, first, 0), "no type any more");
        assert!(table.get(first).is_none() && table.remove(first).is_none(), "gone");
        assert!(table.get(second).is_some(), "the other stays");
        let (again, entry) = table.insert(brush(), LO_DC_TYPE, objt::DC, 0x48).unwrap();
        assert_eq!(again, 0x0101_000A, "the entry given back, with its reuse count");
        assert_eq!((entry.full_unique, entry.object_type), (0x0101, objt::DC));
        assert!(table.get(first).is_none(), "the old handle finds nothing");
        table.remove(second);
        table.remove(again);
        let (last_given_back, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        assert_eq!(last_given_back & GDI_HANDLE_INDEX_MASK, 0xA, "the last given back first");
        let (stock, _) = table.make_stock(last_given_back).unwrap();
        table.remove(stock);
        let (after_stock, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        assert_eq!(after_stock, 0x0310_000A, "the stock bit does not stay");
    }

    #[test]
    fn the_table_fills_up_at_its_last_entry() {
        let mut table = Table::default();
        for _ in RESERVE_ENTRIES_COUNT..GDI_HANDLE_COUNT - 1 {
            table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        }
        let (last, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        assert_eq!(last, 0x0010_FFFF);
        assert!(table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).is_none(), "full");
    }

    #[test]
    fn a_process_s_objects_are_found_for_its_end() {
        let mut table = Table::default();
        let (brush_44, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x48).unwrap();
        let (dc_44, _) = table.insert(brush(), LO_DC_TYPE, objt::DC, 0x44).unwrap();
        table.insert(brush(), LO_DC_TYPE, objt::DC, OWNER_NONE).unwrap();
        let (stock, _) = table.insert(brush(), LO_BRUSH_TYPE, objt::BRUSH, 0x44).unwrap();
        let (stock, _) = table.make_stock(stock).unwrap();
        assert_eq!(table.owned_by(0x44), [brush_44, dc_44], "not the stock object, nobody's DC, 0x48's");
        table.remove(brush_44);
        assert_eq!(table.owned_by(0x44), [dc_44]);
        assert!(table.owned_by(OWNER_PUBLIC).is_empty(), "the stock objects are nobody's to clean up");
        assert!(table.get(stock).is_some());
    }

    #[test]
    fn the_view_holds_the_entries_and_the_capabilities() {
        assert_eq!(VIEW_SIZE, 0x10_1000);
    }
}
