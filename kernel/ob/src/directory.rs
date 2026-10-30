//! Répertoires d'objets (`Directory`) : des noms vers des objets.
//!
//! Un répertoire tient les objets qu'il nomme. Les noms se comparent sans la
//! casse, comme sur XP où `ObCaseInsensitive` vaut 1 : deux noms qui ne
//! diffèrent que par la casse désignent le même objet. Chaque caractère se
//! met en majuscule un pour un, comme `RtlUpcaseUnicodeChar`.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID};
use abi::object::{AccessMask, GenericMapping};
use hal::sync::KSpinLock;

use crate::object::{create_object, Object, ObjectRef, ObjectType};

pub const DIRECTORY_QUERY: AccessMask = AccessMask(0x0001);
pub const DIRECTORY_TRAVERSE: AccessMask = AccessMask(0x0002);
pub const DIRECTORY_CREATE_OBJECT: AccessMask = AccessMask(0x0004);
pub const DIRECTORY_CREATE_SUBDIRECTORY: AccessMask = AccessMask(0x0008);
pub const DIRECTORY_ALL_ACCESS: AccessMask = AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | 0xF);

/// Le type `Directory`.
pub static DIRECTORY_TYPE: ObjectType = ObjectType::new(
    "Directory",
    DIRECTORY_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | DIRECTORY_QUERY.0 | DIRECTORY_TRAVERSE.0),
        write: AccessMask(
            AccessMask::STANDARD_RIGHTS_WRITE.0 | DIRECTORY_CREATE_OBJECT.0 | DIRECTORY_CREATE_SUBDIRECTORY.0,
        ),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | DIRECTORY_QUERY.0 | DIRECTORY_TRAVERSE.0),
        all: DIRECTORY_ALL_ACCESS,
    },
);

struct Entry {
    /// Le nom tel qu'il a été donné.
    name: String,
    object: ObjectRef,
}

/// Un répertoire : ses entrées, par nom mis en majuscules.
pub struct Directory {
    entries: KSpinLock<BTreeMap<String, Entry>>,
}

/// `name` en majuscules, caractère pour caractère.
pub fn fold(name: &str) -> String {
    name.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

/// Un nom d'entrée : non vide, sans `\`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('\\')
}

impl Directory {
    /// Un répertoire vide, objet sans nom.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create() -> Arc<Object<Directory>> {
        create_object(&DIRECTORY_TYPE, Directory { entries: KSpinLock::new(BTreeMap::new()) })
    }

    /// L'objet qui porte le nom `name`, sans regarder la casse.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn lookup(&self, name: &str) -> Option<ObjectRef> {
        self.entries.lock().get(&fold(name)).map(|entry| entry.object.clone())
    }

    /// Le nombre d'entrées.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Il est vide.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// NtQueryDirectoryObject : le nom et le nom du type de chaque entrée,
    /// par ordre de nom.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn entries(&self) -> Vec<(String, &'static str)> {
        self.entries.lock().values().map(|e| (e.name.clone(), e.object.object_type().name)).collect()
    }

    /// Ajoute `object` sous le nom `name` ; `STATUS_OBJECT_NAME_COLLISION` si
    /// le nom est pris.
    pub(crate) fn insert(&self, name: &str, object: ObjectRef) -> Result<(), NtStatus> {
        if !valid_name(name) {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let mut entries = self.entries.lock();
        let key = fold(name);
        if entries.contains_key(&key) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        entries.insert(key, Entry { name: String::from(name), object });
        Ok(())
    }

    /// Retire l'entrée `name` si elle désigne `object`, et la rend.
    pub(crate) fn remove(&self, name: &str, object: &ObjectRef) -> Option<ObjectRef> {
        let mut entries = self.entries.lock();
        let key = fold(name);
        match entries.get(&key) {
            Some(entry) if Arc::ptr_eq(&entry.object, object) => entries.remove(&key).map(|entry| entry.object),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> ObjectRef {
        Directory::create()
    }

    #[test]
    fn names_compare_without_case() {
        let dir = Directory::create();
        let event = object();
        dir.insert("MyEvent", event.clone()).unwrap();
        assert!(Arc::ptr_eq(&dir.lookup("myevent").unwrap(), &event));
        assert!(Arc::ptr_eq(&dir.lookup("MYEVENT").unwrap(), &event));
        assert_eq!(dir.insert("MYEVENT", object()), Err(STATUS_OBJECT_NAME_COLLISION));
        assert_eq!(dir.entries(), [(String::from("MyEvent"), "Directory")], "the name as given");
    }

    #[test]
    fn folding_is_one_character_for_one() {
        assert_eq!(fold("Éa ß"), "ÉA ß", "ß has no one-letter capital");
        assert_eq!(fold("C:"), "C:");
    }

    #[test]
    fn a_name_is_not_empty_and_has_no_separator() {
        let dir = Directory::create();
        assert_eq!(dir.insert("", object()), Err(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(dir.insert("a\\b", object()), Err(STATUS_OBJECT_NAME_INVALID));
        assert!(dir.is_empty());
    }

    #[test]
    fn remove_takes_only_the_object_named() {
        let dir = Directory::create();
        let (first, second) = (object(), object());
        dir.insert("x", first.clone()).unwrap();
        assert!(dir.remove("X", &second).is_none(), "another object");
        assert!(Arc::ptr_eq(&dir.remove("X", &first).unwrap(), &first));
        assert!(dir.lookup("x").is_none());
    }

    #[test]
    fn entries_come_by_name() {
        let dir = Directory::create();
        for name in ["b", "a", "c"] {
            dir.insert(name, object()).unwrap();
        }
        let names: Vec<_> = dir.entries().into_iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["a", "b", "c"]);
    }
}
