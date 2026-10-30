//! Tables de handles (02 §5.4) : une par processus.
//!
//! Un handle est un multiple de 4 : l'entrée `i` de la table est le handle
//! `4 × (i + 1)`, et les deux bits du bas, que NT laisse aux appelants, sont
//! ignorés. Une entrée tient l'objet (une référence), les droits accordés et
//! les attributs du handle (héritable, protégé contre la fermeture). Une
//! entrée libérée est la première reprise, comme sur XP.
//!
//! Le verrou de la table ne couvre que ses entrées : un handle qui se ferme
//! lâche son objet, et appelle la procédure de fermeture de son type, après.
//!
//! Pas encore : handles noyau (`OBJ_KERNEL_HANDLE`, avec Ps et la table du
//! processus System), contrôle d'accès par Se (ADR-011 : tout est accordé),
//! audit.

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_HANDLE_NOT_CLOSABLE, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use abi::object::{AccessMask, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DUPLICATE_SAME_ATTRIBUTES};
use core::any::Any;
use hal::sync::KSpinLock;

use crate::object::{downcast, handle_closed, Object, ObjectRef, ObjectType};

/// Le nombre de handles d'une table, au plus (16 Mi, comme XP).
pub const MAX_HANDLES: usize = 1 << 24;

/// Un handle (`HANDLE`), tel que le voit le mode utilisateur i386.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handle(pub u32);

impl Handle {
    pub const NULL: Handle = Handle(0);
    /// `NtCurrentProcess()` : Ps le résout, la table ne le connaît pas.
    pub const CURRENT_PROCESS: Handle = Handle(0xFFFF_FFFF);
    /// `NtCurrentThread()`.
    pub const CURRENT_THREAD: Handle = Handle(0xFFFF_FFFE);

    fn from_slot(slot: usize) -> Self {
        Handle(((slot as u32) + 1) << 2)
    }

    /// L'entrée qu'il désigne, sans ses deux bits du bas.
    fn slot(self) -> Option<usize> {
        let slot = (self.0 >> 2).checked_sub(1)? as usize;
        (slot < MAX_HANDLES).then_some(slot)
    }
}

/// Les attributs d'un handle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandleAttributes {
    /// Un processus fils le reçoit (`OBJ_INHERIT`).
    pub inherit: bool,
    /// NtClose le refuse (`HANDLE_FLAG_PROTECT_FROM_CLOSE`).
    pub protect_from_close: bool,
}

struct Entry {
    object: ObjectRef,
    access: AccessMask,
    attributes: HandleAttributes,
}

struct Slots {
    entries: Vec<Option<Entry>>,
    /// Les entrées libres, la dernière libérée en haut.
    free: Vec<usize>,
    count: usize,
}

/// La table de handles d'un processus.
pub struct HandleTable {
    slots: KSpinLock<Slots>,
    /// Le nombre d'entrées au plus : [`MAX_HANDLES`], moins dans les tests.
    limit: usize,
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleTable {
    /// Une table vide.
    pub const fn new() -> Self {
        Self::with_limit(MAX_HANDLES)
    }

    /// Une table vide d'au plus `limit` entrées.
    pub(crate) const fn with_limit(limit: usize) -> Self {
        Self { slots: KSpinLock::new(Slots { entries: Vec::new(), free: Vec::new(), count: 0 }), limit }
    }

    /// Le nombre de handles ouverts.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn count(&self) -> usize {
        self.slots.lock().count
    }

    /// Un handle sur `object`, avec les droits que son type accorde pour
    /// `desired` (`ObjectType::granted_access`) ; `STATUS_INSUFFICIENT_RESOURCES`
    /// quand la table est pleine.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn insert(
        &self,
        object: ObjectRef,
        desired: AccessMask,
        attributes: HandleAttributes,
    ) -> Result<Handle, NtStatus> {
        let access = object.object_type().granted_access(desired);
        self.insert_granted(object, access, attributes)
    }

    fn insert_granted(
        &self,
        object: ObjectRef,
        access: AccessMask,
        attributes: HandleAttributes,
    ) -> Result<Handle, NtStatus> {
        let mut slots = self.slots.lock();
        let slot = match slots.free.pop() {
            Some(slot) => slot,
            None if slots.entries.len() < self.limit => {
                slots.entries.push(None);
                slots.entries.len() - 1
            }
            None => return Err(STATUS_INSUFFICIENT_RESOURCES),
        };
        object.header().add_handle();
        slots.entries[slot] = Some(Entry { object, access, attributes });
        slots.count += 1;
        Ok(Handle::from_slot(slot))
    }

    /// ObReferenceObjectByHandle : l'objet de `handle`, du type `expected`
    /// s'il est donné (`STATUS_OBJECT_TYPE_MISMATCH`), si le handle a les
    /// droits `desired`, génériques traduits (`STATUS_ACCESS_DENIED`) ;
    /// `STATUS_INVALID_HANDLE` sans entrée.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn reference(
        &self,
        handle: Handle,
        expected: Option<&ObjectType>,
        desired: AccessMask,
    ) -> Result<ObjectRef, NtStatus> {
        let (object, granted) = {
            let slots = self.slots.lock();
            let entry =
                handle.slot().and_then(|slot| slots.entries.get(slot)?.as_ref()).ok_or(STATUS_INVALID_HANDLE)?;
            (entry.object.clone(), entry.access)
        };
        if expected.is_some_and(|ty| !object.is_type(ty)) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if !granted.contains(object.object_type().generic_mapping.map(desired)) {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(object)
    }

    /// [`reference`](Self::reference) d'un objet du type `ty`, de corps `T`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn reference_as<T: Any + Send + Sync>(
        &self,
        handle: Handle,
        ty: &ObjectType,
        desired: AccessMask,
    ) -> Result<Arc<Object<T>>, NtStatus> {
        downcast(&self.reference(handle, Some(ty), desired)?).ok_or(STATUS_OBJECT_TYPE_MISMATCH)
    }

    /// Les droits et les attributs de `handle`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn query(&self, handle: Handle) -> Result<(AccessMask, HandleAttributes), NtStatus> {
        let slots = self.slots.lock();
        let entry = handle.slot().and_then(|slot| slots.entries.get(slot)?.as_ref()).ok_or(STATUS_INVALID_HANDLE)?;
        Ok((entry.access, entry.attributes))
    }

    /// NtSetInformationObject (`ObjectHandleFlagInformation`) : les attributs
    /// de `handle`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set_attributes(&self, handle: Handle, attributes: HandleAttributes) -> Result<(), NtStatus> {
        let mut slots = self.slots.lock();
        let entry =
            handle.slot().and_then(|slot| slots.entries.get_mut(slot)?.as_mut()).ok_or(STATUS_INVALID_HANDLE)?;
        entry.attributes = attributes;
        Ok(())
    }

    /// NtClose : `STATUS_INVALID_HANDLE` sans entrée,
    /// `STATUS_HANDLE_NOT_CLOSABLE` pour un handle protégé.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn close(&self, handle: Handle) -> Result<(), NtStatus> {
        let entry = {
            let mut slots = self.slots.lock();
            let slot = handle.slot().ok_or(STATUS_INVALID_HANDLE)?;
            match slots.entries.get(slot) {
                Some(Some(entry)) if entry.attributes.protect_from_close => return Err(STATUS_HANDLE_NOT_CLOSABLE),
                Some(Some(_)) => {}
                _ => return Err(STATUS_INVALID_HANDLE),
            }
            slots.free.push(slot);
            slots.count -= 1;
            slots.entries[slot].take().expect("checked above")
        };
        handle_closed(&entry.object);
        Ok(())
    }

    /// ObDuplicateHandleTable : la table d'un processus fils, avec les handles
    /// héritables de celle-ci, aux mêmes valeurs.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn inherit(&self) -> HandleTable {
        let slots = self.slots.lock();
        let entries: Vec<Option<Entry>> = slots
            .entries
            .iter()
            .map(|entry| {
                let entry = entry.as_ref().filter(|entry| entry.attributes.inherit)?;
                entry.object.header().add_handle();
                Some(Entry { object: entry.object.clone(), access: entry.access, attributes: entry.attributes })
            })
            .collect();
        let free = (0..entries.len()).rev().filter(|&slot| entries[slot].is_none()).collect();
        let count = entries.iter().filter(|entry| entry.is_some()).count();
        HandleTable { slots: KSpinLock::new(Slots { entries, free, count }), limit: self.limit }
    }

    /// ObKillProcess : ferme tous les handles, protégés ou non.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn rundown(&self) {
        let entries = {
            let mut slots = self.slots.lock();
            slots.free.clear();
            slots.count = 0;
            core::mem::take(&mut slots.entries)
        };
        for entry in entries.into_iter().flatten() {
            handle_closed(&entry.object);
        }
    }
}

impl Drop for HandleTable {
    fn drop(&mut self) {
        self.rundown();
    }
}

/// NtDuplicateObject : un handle dans `target` sur l'objet de `handle` dans
/// `source`. Avec `DUPLICATE_SAME_ACCESS`, les droits du handle source, sinon
/// ceux que le type accorde pour `desired` ; avec `DUPLICATE_SAME_ATTRIBUTES`,
/// ses attributs, sinon `attributes`. Avec `DUPLICATE_CLOSE_SOURCE`, le handle
/// source se ferme, que la copie réussisse ou non.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn duplicate(
    source: &HandleTable,
    handle: Handle,
    target: &HandleTable,
    desired: AccessMask,
    attributes: HandleAttributes,
    options: u32,
) -> Result<Handle, NtStatus> {
    let copied = (|| {
        let (granted, source_attributes) = source.query(handle)?;
        let object = source.reference(handle, None, AccessMask::NONE)?;
        let attributes = if options & DUPLICATE_SAME_ATTRIBUTES != 0 { source_attributes } else { attributes };
        if options & DUPLICATE_SAME_ACCESS != 0 {
            target.insert_granted(object, granted, attributes)
        } else {
            target.insert(object, desired, attributes)
        }
    })();
    if options & DUPLICATE_CLOSE_SOURCE != 0 {
        // The source goes whatever happened; a protected one stays.
        let _ = source.close(handle);
    }
    copied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::create_object;
    use abi::object::GenericMapping;

    const MAPPING: GenericMapping = GenericMapping {
        read: AccessMask(0x0002_0001),
        write: AccessMask(0x0002_0002),
        execute: AccessMask(0x0002_0004),
        all: AccessMask(0x000F_0007),
    };
    static EVENT: ObjectType = ObjectType::new("Event", AccessMask(0x000F_0007), MAPPING);
    static MUTANT: ObjectType = ObjectType::new("Mutant", AccessMask(0x000F_0007), MAPPING);

    fn event() -> ObjectRef {
        create_object(&EVENT, 0u32)
    }

    const NONE: HandleAttributes = HandleAttributes { inherit: false, protect_from_close: false };
    const ALL: AccessMask = AccessMask::GENERIC_ALL;

    #[test]
    fn handles_are_multiples_of_four_and_the_last_freed_comes_back_first() {
        let table = HandleTable::new();
        let handles: Vec<_> = (0..3).map(|_| table.insert(event(), ALL, NONE).unwrap()).collect();
        assert_eq!(handles, [Handle(4), Handle(8), Handle(12)]);
        table.close(Handle(4)).unwrap();
        table.close(Handle(8)).unwrap();
        assert_eq!(table.insert(event(), ALL, NONE), Ok(Handle(8)));
        assert_eq!(table.insert(event(), ALL, NONE), Ok(Handle(4)));
        assert_eq!(table.insert(event(), ALL, NONE), Ok(Handle(16)));
        assert_eq!(table.count(), 4);
    }

    #[test]
    fn the_low_bits_of_a_handle_are_ignored() {
        let table = HandleTable::new();
        let object = event();
        let handle = table.insert(object.clone(), ALL, NONE).unwrap();
        let tagged = Handle(handle.0 | 3);
        assert!(Arc::ptr_eq(&table.reference(tagged, None, AccessMask::NONE).unwrap(), &object));
    }

    #[test]
    fn bad_handles_are_invalid() {
        let table = HandleTable::new();
        for handle in [Handle::NULL, Handle(4), Handle::CURRENT_PROCESS, Handle::CURRENT_THREAD, Handle(3)] {
            assert_eq!(
                table.reference(handle, None, AccessMask::NONE).err(),
                Some(STATUS_INVALID_HANDLE),
                "{handle:?}"
            );
            assert_eq!(table.close(handle), Err(STATUS_INVALID_HANDLE));
        }
        let handle = table.insert(event(), ALL, NONE).unwrap();
        table.close(handle).unwrap();
        assert_eq!(table.close(handle), Err(STATUS_INVALID_HANDLE), "closed twice");
    }

    #[test]
    fn reference_checks_the_type_and_the_access() {
        let table = HandleTable::new();
        let read_only = table.insert(event(), AccessMask::GENERIC_READ, NONE).unwrap();
        assert_eq!(table.query(read_only).map(|(access, _)| access), Ok(AccessMask(0x0002_0001)));
        assert!(table.reference(read_only, Some(&EVENT), AccessMask::GENERIC_READ).is_ok());
        assert_eq!(table.reference(read_only, Some(&EVENT), AccessMask(2)).err(), Some(STATUS_ACCESS_DENIED));
        assert_eq!(
            table.reference(read_only, Some(&EVENT), AccessMask::GENERIC_WRITE).err(),
            Some(STATUS_ACCESS_DENIED),
            "generic rights are mapped before the check"
        );
        assert_eq!(
            table.reference(read_only, Some(&MUTANT), AccessMask::NONE).err(),
            Some(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(table.reference_as::<u32>(read_only, &EVENT, AccessMask::NONE).map(|e| **e), Ok(0));
        assert_eq!(
            table.reference_as::<u64>(read_only, &EVENT, AccessMask::NONE).err(),
            Some(STATUS_OBJECT_TYPE_MISMATCH)
        );
    }

    #[test]
    fn handles_are_counted_on_the_object_and_its_type() {
        static COUNTED: ObjectType = ObjectType::new("Counted", AccessMask(0x000F_0007), MAPPING);
        let table = HandleTable::new();
        let object: ObjectRef = create_object(&COUNTED, ());
        let (a, b) =
            (table.insert(object.clone(), ALL, NONE).unwrap(), table.insert(object.clone(), ALL, NONE).unwrap());
        assert_eq!((object.handle_count(), COUNTED.handle_count(), Arc::strong_count(&object)), (2, 2, 3));
        table.close(a).unwrap();
        table.close(b).unwrap();
        assert_eq!((object.handle_count(), COUNTED.handle_count(), Arc::strong_count(&object)), (0, 0, 1));
    }

    #[test]
    fn a_protected_handle_does_not_close() {
        let table = HandleTable::new();
        let protected = HandleAttributes { inherit: false, protect_from_close: true };
        let handle = table.insert(event(), ALL, protected).unwrap();
        assert_eq!(table.close(handle), Err(STATUS_HANDLE_NOT_CLOSABLE));
        table.set_attributes(handle, NONE).unwrap();
        assert_eq!(table.close(handle), Ok(()));
    }

    #[test]
    fn a_child_inherits_the_inheritable_handles_at_the_same_values() {
        let parent = HandleTable::new();
        let inherit = HandleAttributes { inherit: true, protect_from_close: false };
        let (kept, shared) = (event(), event());
        let private = parent.insert(kept, ALL, NONE).unwrap();
        let inherited = parent.insert(shared.clone(), AccessMask::GENERIC_READ, inherit).unwrap();
        let child = parent.inherit();
        assert_eq!(child.count(), 1);
        assert_eq!(child.reference(private, None, AccessMask::NONE).err(), Some(STATUS_INVALID_HANDLE));
        assert!(Arc::ptr_eq(&child.reference(inherited, None, AccessMask::NONE).unwrap(), &shared));
        assert_eq!(child.query(inherited), parent.query(inherited), "same access and attributes");
        assert_eq!(shared.handle_count(), 2);
        assert_eq!(child.insert(event(), ALL, NONE), Ok(private), "the hole is free in the child");
    }

    #[test]
    fn duplicate_copies_access_attributes_and_may_close_the_source() {
        let (source, target) = (HandleTable::new(), HandleTable::new());
        let object = event();
        let inherit = HandleAttributes { inherit: true, protect_from_close: false };
        let handle = source.insert(object.clone(), AccessMask::GENERIC_READ, inherit).unwrap();
        let same = duplicate(
            &source,
            handle,
            &target,
            AccessMask::NONE,
            NONE,
            DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES,
        );
        assert_eq!(target.query(same.unwrap()), source.query(handle));
        let narrower = duplicate(&source, handle, &target, AccessMask(1), NONE, 0).unwrap();
        assert_eq!(target.query(narrower), Ok((AccessMask(1), NONE)));
        let moved =
            duplicate(&source, handle, &target, AccessMask::NONE, NONE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
        assert!(moved.is_ok());
        assert_eq!(source.count(), 0, "the source closed");
        assert_eq!(object.handle_count(), 3);
        let failed = duplicate(&source, handle, &target, ALL, NONE, DUPLICATE_CLOSE_SOURCE);
        assert_eq!(failed, Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn duplicate_closes_the_source_even_when_the_copy_fails() {
        let source = HandleTable::new();
        let handle = source.insert(event(), ALL, NONE).unwrap();
        let full = HandleTable::with_limit(0);
        let result = duplicate(&source, handle, &full, ALL, NONE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
        assert_eq!(result, Err(STATUS_INSUFFICIENT_RESOURCES));
        assert_eq!(source.count(), 0);
    }

    #[test]
    fn a_full_table_refuses_a_handle() {
        let table = HandleTable::with_limit(2);
        let (a, _) = (table.insert(event(), ALL, NONE).unwrap(), table.insert(event(), ALL, NONE).unwrap());
        assert_eq!(table.insert(event(), ALL, NONE), Err(STATUS_INSUFFICIENT_RESOURCES));
        table.close(a).unwrap();
        assert_eq!(table.insert(event(), ALL, NONE), Ok(a), "a freed entry is enough");
    }

    #[test]
    fn rundown_closes_everything_even_protected_handles() {
        static RUN: ObjectType = ObjectType::new("Run", AccessMask(0x000F_0007), MAPPING);
        let table = HandleTable::new();
        let protected = HandleAttributes { inherit: false, protect_from_close: true };
        let objects: Vec<ObjectRef> = (0..3).map(|_| create_object(&RUN, ()) as ObjectRef).collect();
        for object in &objects {
            table.insert(object.clone(), ALL, protected).unwrap();
        }
        table.rundown();
        assert_eq!((table.count(), RUN.handle_count()), (0, 0));
        assert!(objects.iter().all(|o| Arc::strong_count(o) == 1), "the table let the objects go");
        assert_eq!(table.insert(event(), ALL, NONE), Ok(Handle(4)), "an empty table again");
    }

    #[test]
    fn dropping_a_table_closes_its_handles() {
        static DROPPED: ObjectType = ObjectType::new("Dropped", AccessMask(0x000F_0007), MAPPING);
        let object: ObjectRef = create_object(&DROPPED, ());
        let table = HandleTable::new();
        table.insert(object.clone(), ALL, NONE).unwrap();
        drop(table);
        assert_eq!((object.handle_count(), DROPPED.handle_count()), (0, 0));
    }
}
