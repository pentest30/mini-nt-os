//! Ob — gestionnaire d'objets (02 §5.4).
//!
//! - [`object`] : en-tête, corps, types, références (`Arc`), comptes de
//!   handles ; un objet nommé temporaire perd son nom avec son dernier
//!   handle.
//! - [`directory`], [`symlink`] : répertoires et liens symboliques.
//! - [`namespace`] : l'espace de noms d'XP, la recherche d'un nom
//!   (*parse*, liens, `\??`), l'insertion d'un nom.
//! - [`handle`] : les tables de handles, une par processus.
//!
//! [`insert_object`] et [`open_object_by_name`] assemblent nom et handle,
//! comme ObInsertObject et ObOpenObjectByName ; les appels système viendront
//! au M3.
//!
//! WI7e Ch.8 §Object Manager

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod directory;
pub mod handle;
pub mod namespace;
pub mod object;
pub mod symlink;

pub use abi::object::{AccessMask, GenericMapping};
pub use directory::{Directory, DIRECTORY_TYPE};
pub use handle::{duplicate, Handle, HandleAttributes, HandleTable};
pub use namespace::{Lookup, Namespace};
pub use object::{create_object, downcast, make_temporary, Object, ObjectRef, ObjectType, Parsed, TYPE_TYPE};
pub use symlink::{SymbolicLink, SYMBOLIC_LINK_TYPE};

use abi::ntstatus::{NtStatus, STATUS_OBJECT_NAME_EXISTS, STATUS_SUCCESS};
use abi::object::OBJ_INHERIT;
use hal::sync::Once;

static NAMESPACE: Once<Namespace> = Once::new();

/// Crée l'espace de noms du système et y range les types d'Ob.
///
/// # IRQL
/// PASSIVE_LEVEL, au démarrage.
pub fn init() {
    let namespace = NAMESPACE.call_once(Namespace::new);
    for ty in [&TYPE_TYPE, &DIRECTORY_TYPE, &SYMBOLIC_LINK_TYPE] {
        namespace.register_type(ty).expect("a type registered twice");
    }
    log::info!("Ob: namespace ready ({} entries under the root)", namespace.root().len());
}

/// L'espace de noms du système.
///
/// # Panics
/// Avant [`init`].
///
/// # IRQL
/// Tout niveau.
pub fn namespace() -> &'static Namespace {
    NAMESPACE.get().expect("Ob not initialised")
}

/// ObInsertObject : nomme `object` si `name` est donné (absolu, ou relatif
/// au répertoire `root`), puis donne à `table` un handle sur lui, avec les
/// droits accordés pour `desired`, héritable avec `OBJ_INHERIT`. Avec
/// `OBJ_OPENIF` et un nom pris par un objet du même type, le handle est sur
/// celui-là et le statut rendu `STATUS_OBJECT_NAME_EXISTS`. Si le handle ne
/// peut être créé, le nom donné est repris.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn insert_object(
    namespace: &Namespace,
    object: ObjectRef,
    name: Option<&str>,
    root: Option<&ObjectRef>,
    attributes: u32,
    table: &HandleTable,
    desired: AccessMask,
) -> Result<(Handle, NtStatus), NtStatus> {
    let (target, status) = match name {
        None => (object, STATUS_SUCCESS),
        Some(name) => match namespace.insert(&object, name, root, attributes)? {
            Some(existing) => (existing, STATUS_OBJECT_NAME_EXISTS),
            None => (object, STATUS_SUCCESS),
        },
    };
    let handle_attributes = HandleAttributes { inherit: attributes & OBJ_INHERIT != 0, protect_from_close: false };
    match table.insert(target.clone(), desired, handle_attributes) {
        Ok(handle) => Ok((handle, status)),
        Err(error) => {
            if name.is_some() && status == STATUS_SUCCESS && !target.is_permanent() {
                object::remove_name(&target);
            }
            Err(error)
        }
    }
}

/// ObOpenObjectByName : un handle dans `table` sur l'objet que désigne
/// `name`, du type `expected` s'il est donné.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn open_object_by_name(
    namespace: &Namespace,
    name: &str,
    root: Option<&ObjectRef>,
    expected: Option<&ObjectType>,
    attributes: u32,
    table: &HandleTable,
    desired: AccessMask,
) -> Result<Handle, NtStatus> {
    let object = namespace.open(name, root, expected, attributes)?;
    let handle_attributes = HandleAttributes { inherit: attributes & OBJ_INHERIT != 0, protect_from_close: false };
    table.insert(object, desired, handle_attributes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::ntstatus::{STATUS_INSUFFICIENT_RESOURCES, STATUS_OBJECT_NAME_NOT_FOUND};
    use abi::object::{GenericMapping, OBJ_OPENIF, OBJ_PERMANENT};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    const MAPPING: GenericMapping =
        GenericMapping { read: AccessMask(1), write: AccessMask(2), execute: AccessMask(4), all: AccessMask(7) };
    static EVENT: ObjectType = ObjectType::new("Event", AccessMask(7), MAPPING);
    const ALL: AccessMask = AccessMask::GENERIC_ALL;
    const BNO: &str = "\\BaseNamedObjects";

    fn event() -> ObjectRef {
        create_object(&EVENT, ())
    }

    #[test]
    fn a_named_object_leaves_the_namespace_with_its_last_handle() {
        let ns = Namespace::new();
        let table = HandleTable::new();
        let (first, status) =
            insert_object(&ns, event(), Some("\\BaseNamedObjects\\Temp"), None, 0, &table, ALL).unwrap();
        assert_eq!(status, STATUS_SUCCESS);
        let second = open_object_by_name(&ns, "\\BaseNamedObjects\\temp", None, Some(&EVENT), 0, &table, ALL).unwrap();
        table.close(first).unwrap();
        assert!(ns.open("\\BaseNamedObjects\\Temp", None, None, 0).is_ok(), "one handle left");
        let object = table.reference(second, None, AccessMask::NONE).unwrap();
        table.close(second).unwrap();
        assert_eq!(ns.open("\\BaseNamedObjects\\Temp", None, None, 0).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(object.name(), None);
        assert_eq!(Arc::strong_count(&object), 1, "the directory let it go");
    }

    #[test]
    fn a_permanent_object_keeps_its_name_until_made_temporary() {
        let ns = Namespace::new();
        let table = HandleTable::new();
        let object = event();
        let (handle, _) =
            insert_object(&ns, object.clone(), Some("\\BaseNamedObjects\\Kept"), None, OBJ_PERMANENT, &table, ALL)
                .unwrap();
        table.close(handle).unwrap();
        assert!(ns.open("\\BaseNamedObjects\\Kept", None, None, 0).is_ok());
        make_temporary(&object);
        assert_eq!(ns.open("\\BaseNamedObjects\\Kept", None, None, 0).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
    }

    #[test]
    fn open_if_gives_a_handle_to_the_object_there() {
        let ns = Namespace::new();
        let table = HandleTable::new();
        let first = event();
        insert_object(&ns, first.clone(), Some("\\BaseNamedObjects\\Shared"), None, 0, &table, ALL).unwrap();
        let (handle, status) =
            insert_object(&ns, event(), Some("\\BaseNamedObjects\\Shared"), None, OBJ_OPENIF, &table, ALL).unwrap();
        assert_eq!(status, STATUS_OBJECT_NAME_EXISTS);
        assert!(Arc::ptr_eq(&table.reference(handle, None, AccessMask::NONE).unwrap(), &first));
        assert_eq!(first.handle_count(), 2);
    }

    #[test]
    fn a_failed_handle_takes_the_name_back() {
        let ns = Namespace::new();
        let full = HandleTable::with_limit(0);
        let object = event();
        let result = insert_object(&ns, object.clone(), Some("\\BaseNamedObjects\\Lost"), None, 0, &full, ALL);
        assert_eq!(result.err(), Some(STATUS_INSUFFICIENT_RESOURCES));
        assert_eq!(ns.open("\\BaseNamedObjects\\Lost", None, None, 0).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(object.name(), None);
    }

    #[test]
    fn the_close_procedure_sees_each_close() {
        static CLOSES: AtomicU32 = AtomicU32::new(0);
        static LEFT: AtomicU32 = AtomicU32::new(u32::MAX);
        fn on_close(_object: &ObjectRef, left: u32) {
            CLOSES.fetch_add(1, Ordering::Relaxed);
            LEFT.store(left, Ordering::Relaxed);
        }
        static WATCHED: ObjectType = ObjectType::new("Watched", AccessMask(7), MAPPING).with_close(on_close);
        let table = HandleTable::new();
        let object: ObjectRef = create_object(&WATCHED, ());
        let (a, b) = (
            table.insert(object.clone(), ALL, Default::default()).unwrap(),
            table.insert(object, ALL, Default::default()).unwrap(),
        );
        table.close(a).unwrap();
        assert_eq!((CLOSES.load(Ordering::Relaxed), LEFT.load(Ordering::Relaxed)), (1, 1));
        table.close(b).unwrap();
        assert_eq!((CLOSES.load(Ordering::Relaxed), LEFT.load(Ordering::Relaxed)), (2, 0));
    }

    #[test]
    fn a_handle_inherits_with_obj_inherit() {
        let ns = Namespace::new();
        let table = HandleTable::new();
        let (handle, _) = insert_object(&ns, event(), None, None, OBJ_INHERIT, &table, ALL).unwrap();
        assert!(table.query(handle).unwrap().1.inherit);
        let named = open_object_by_name(&ns, BNO, None, Some(&DIRECTORY_TYPE), OBJ_INHERIT, &table, ALL).unwrap();
        assert!(table.query(named).unwrap().1.inherit);
    }
}
