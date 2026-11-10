//! L'espace de noms (02 §5.4) : un arbre de répertoires depuis `\`.
//!
//! [`Namespace::lookup`] suit un nom composant par composant
//! (ObpLookupObjectName). Un objet dont le type a une procédure *parse* reçoit
//! la suite du nom : un lien symbolique la fait reprendre depuis la racine,
//! [`MAX_REPARSE`] fois au plus ; un périphérique ou une clé la résoudront
//! (Io, Cm). `\??` désigne le répertoire des lettres de lecteur, `\GLOBAL??`
//! (le DeviceMap de chaque session viendra avec les sessions), et
//! `\DosDevices` est un lien vers `\??`.
//!
//! Un objet nommé temporaire quitte son répertoire avec son dernier handle ;
//! un objet permanent (`OBJ_PERMANENT`) y reste (`object::handle_closed`).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_OBJECT_PATH_SYNTAX_BAD, STATUS_OBJECT_TYPE_MISMATCH,
};
use abi::object::{OBJ_OPENIF, OBJ_OPENLINK, OBJ_PERMANENT};

use crate::directory::Directory;
use crate::object::{create_object, downcast, NameInfo, Object, ObjectRef, ObjectType, Parsed, TYPE_TYPE};
use crate::symlink::{SymbolicLink, SYMBOLIC_LINK_TYPE};

/// Le nombre de liens qu'une recherche suit au plus.
pub const MAX_REPARSE: usize = 32;

/// Les répertoires que crée [`Namespace::new`], sous la racine.
pub const STANDARD_DIRECTORIES: [&str; 12] = [
    "ObjectTypes",
    "GLOBAL??",
    "Device",
    "Driver",
    "FileSystem",
    "BaseNamedObjects",
    "KnownDlls",
    "Windows",
    "Sessions",
    "RPC Control",
    "KernelObjects",
    "Callback",
];

/// Ce que trouve une recherche.
pub enum Lookup {
    /// L'objet que désigne le nom.
    Found(ObjectRef),
    /// Le dernier composant n'existe pas : `name` dans `directory`, où un
    /// objet peut le prendre.
    Missing { directory: Arc<Object<Directory>>, name: String },
}

/// Où en est une recherche après un passage.
enum Step {
    Done(Lookup),
    Reparse(String),
}

/// Un espace de noms : sa racine et le répertoire des lettres de lecteur.
pub struct Namespace {
    root: Arc<Object<Directory>>,
    dos_devices: Arc<Object<Directory>>,
}

/// Ajoute `object` sous `name` dans `directory`, nommé et permanent.
fn add_permanent(directory: &Arc<Object<Directory>>, name: &str, object: ObjectRef) {
    directory.insert(name, object.clone()).expect("a fresh directory");
    *object.header().name.lock() = Some(NameInfo { name: String::from(name), directory: Arc::downgrade(directory) });
    object.header().set_permanent(true);
}

impl Namespace {
    /// Un espace de noms avec les répertoires d'XP ([`STANDARD_DIRECTORIES`])
    /// et le lien `\DosDevices` vers `\??`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new() -> Self {
        let root = Directory::create();
        let mut dos_devices = None;
        for name in STANDARD_DIRECTORIES {
            let directory = Directory::create();
            add_permanent(&root, name, directory.clone());
            if name == "GLOBAL??" {
                dos_devices = Some(directory);
            }
        }
        add_permanent(&root, "DosDevices", SymbolicLink::create("\\??"));
        Self { root, dos_devices: dos_devices.expect("GLOBAL?? is a standard directory") }
    }

    /// Le répertoire racine, `\`.
    pub fn root(&self) -> &Arc<Object<Directory>> {
        &self.root
    }

    /// ObpLookupObjectName : ce que désigne `name`, absolu (`\…`), ou relatif
    /// à `root` : un répertoire, ou un objet dont le type a une procédure
    /// *parse*, qui reçoit alors le nom (une clé du registre, un
    /// périphérique). Avec `open_link`, un lien en dernier composant est
    /// rendu lui-même au lieu d'être suivi (`OBJ_OPENLINK`).
    ///
    /// Erreurs : nom absolu sans `\` ou relatif avec
    /// (`STATUS_OBJECT_PATH_SYNTAX_BAD`), composant vide
    /// (`STATUS_OBJECT_NAME_INVALID`), composant intermédiaire absent
    /// (`STATUS_OBJECT_PATH_NOT_FOUND`), ni répertoire ni procédure *parse*
    /// sur le chemin (`STATUS_OBJECT_TYPE_MISMATCH`), plus de [`MAX_REPARSE`]
    /// liens (`STATUS_OBJECT_NAME_NOT_FOUND`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn lookup(&self, name: &str, root: Option<&ObjectRef>, open_link: bool) -> Result<Lookup, NtStatus> {
        let mut step = self.walk(name, root, open_link)?;
        for _ in 0..MAX_REPARSE {
            match step {
                Step::Done(lookup) => return Ok(lookup),
                Step::Reparse(name) => step = self.walk(&name, None, open_link)?,
            }
        }
        match step {
            Step::Done(lookup) => Ok(lookup),
            Step::Reparse(_) => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    /// Un passage de recherche, jusqu'au bout du nom ou jusqu'à un lien.
    fn walk(&self, name: &str, root: Option<&ObjectRef>, open_link: bool) -> Result<Step, NtStatus> {
        let (mut current, mut rest): (ObjectRef, &str) = match root {
            Some(_) if name.starts_with('\\') => return Err(STATUS_OBJECT_PATH_SYNTAX_BAD),
            Some(root) if name.is_empty() => return Ok(Step::Done(Lookup::Found(root.clone()))),
            Some(root) => match root.object_type().parse {
                // Not a directory: its parse procedure takes the name.
                Some(parse) if downcast::<Directory>(root).is_none() => {
                    return match parse(root, &alloc::format!("\\{name}"))? {
                        Parsed::Object(object) => Ok(Step::Done(Lookup::Found(object))),
                        Parsed::Reparse(name) => Ok(Step::Reparse(name)),
                    };
                }
                _ => (root.clone(), name),
            },
            None => {
                let rest = name.strip_prefix('\\').ok_or(STATUS_OBJECT_PATH_SYNTAX_BAD)?;
                match rest.split_once('\\') {
                    _ if rest.is_empty() => return Ok(Step::Done(Lookup::Found(self.root.clone()))),
                    _ if rest == "??" => return Ok(Step::Done(Lookup::Found(self.dos_devices.clone()))),
                    Some(("??", tail)) => (self.dos_devices.clone(), tail),
                    _ => (self.root.clone(), rest),
                }
            }
        };
        loop {
            let (component, tail) = match rest.split_once('\\') {
                Some((component, tail)) => (component, Some(tail)),
                None => (rest, None),
            };
            if component.is_empty() {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            let directory = downcast::<Directory>(&current).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
            let Some(child) = directory.lookup(component) else {
                return match tail {
                    None => Ok(Step::Done(Lookup::Missing { directory, name: String::from(component) })),
                    Some(_) => Err(STATUS_OBJECT_PATH_NOT_FOUND),
                };
            };
            if let Some(parse) = child.object_type().parse {
                let link_itself = tail.is_none() && open_link && child.is_type(&SYMBOLIC_LINK_TYPE);
                if !link_itself {
                    // The rest of the name, from its separator on.
                    let remaining = &rest[component.len()..];
                    return match parse(&child, remaining)? {
                        Parsed::Object(object) => Ok(Step::Done(Lookup::Found(object))),
                        Parsed::Reparse(name) => Ok(Step::Reparse(name)),
                    };
                }
            }
            match tail {
                None => return Ok(Step::Done(Lookup::Found(child))),
                Some(tail) => (current, rest) = (child, tail),
            }
        }
    }

    /// Donne à `object` le nom `name` (absolu, ou relatif au répertoire
    /// `root`) ; permanent avec `OBJ_PERMANENT`. Si le nom est pris :
    /// `STATUS_OBJECT_NAME_COLLISION`, ou avec `OBJ_OPENIF` l'objet qui le
    /// porte, s'il est du même type (`STATUS_OBJECT_TYPE_MISMATCH` sinon).
    ///
    /// # Panics
    /// Si `object` a déjà un nom.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn insert(
        &self,
        object: &ObjectRef,
        name: &str,
        root: Option<&ObjectRef>,
        attributes: u32,
    ) -> Result<Option<ObjectRef>, NtStatus> {
        assert!(object.name().is_none(), "object inserted twice");
        match self.lookup(name, root, attributes & OBJ_OPENLINK != 0)? {
            Lookup::Found(existing) if attributes & OBJ_OPENIF != 0 => {
                if !existing.is_type(object.object_type()) {
                    return Err(STATUS_OBJECT_TYPE_MISMATCH);
                }
                Ok(Some(existing))
            }
            Lookup::Found(_) => Err(STATUS_OBJECT_NAME_COLLISION),
            Lookup::Missing { directory, name } => {
                directory.insert(&name, object.clone())?;
                *object.header().name.lock() = Some(NameInfo { name, directory: Arc::downgrade(&directory) });
                object.header().set_permanent(attributes & OBJ_PERMANENT != 0);
                Ok(None)
            }
        }
    }

    /// L'objet que désigne `name`, du type `expected` s'il est donné
    /// (`STATUS_OBJECT_TYPE_MISMATCH`) ; `STATUS_OBJECT_NAME_NOT_FOUND` s'il
    /// n'existe pas.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn open(
        &self,
        name: &str,
        root: Option<&ObjectRef>,
        expected: Option<&ObjectType>,
        attributes: u32,
    ) -> Result<ObjectRef, NtStatus> {
        match self.lookup(name, root, attributes & OBJ_OPENLINK != 0)? {
            Lookup::Found(object) if expected.is_some_and(|ty| !object.is_type(ty)) => Err(STATUS_OBJECT_TYPE_MISMATCH),
            Lookup::Found(object) => Ok(object),
            Lookup::Missing { .. } => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    /// Le nom complet de `object` (NtQueryObject, `ObjectNameInformation`) ;
    /// `None` s'il n'est pas dans cet espace de noms.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn full_name(&self, object: &ObjectRef) -> Option<String> {
        let root: ObjectRef = self.root.clone();
        if Arc::ptr_eq(object, &root) {
            return Some(String::from("\\"));
        }
        let parent = |object: &ObjectRef| {
            let info = object.header().name.lock();
            let info = info.as_ref()?;
            let directory: ObjectRef = info.directory.upgrade()?;
            Some((info.name.clone(), directory))
        };
        let mut names = Vec::new();
        let mut current = object.clone();
        while !Arc::ptr_eq(&current, &root) {
            let (name, directory) = parent(&current)?;
            names.push(name);
            current = directory;
        }
        names.reverse();
        Some(format!("\\{}", names.join("\\")))
    }

    /// Range le type `ty` dans `\ObjectTypes`, comme objet `Type` permanent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn register_type(&self, ty: &'static ObjectType) -> Result<(), NtStatus> {
        let object: ObjectRef = create_object(&TYPE_TYPE, ty);
        self.insert(&object, &format!("\\ObjectTypes\\{}", ty.name), None, OBJ_PERMANENT).map(|_| ())
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::DIRECTORY_TYPE;
    use abi::object::{AccessMask, GenericMapping};

    const MAPPING: GenericMapping =
        GenericMapping { read: AccessMask(1), write: AccessMask(2), execute: AccessMask(4), all: AccessMask(7) };
    static EVENT: ObjectType = ObjectType::new("Event", AccessMask(7), MAPPING);
    /// A device: its parse procedure opens a "file" named by the rest.
    static DEVICE: ObjectType = ObjectType::new("Device", AccessMask(7), MAPPING).with_parse(open_file);
    static FILE: ObjectType = ObjectType::new("File", AccessMask(7), MAPPING);

    fn open_file(_device: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
        Ok(Parsed::Object(create_object(&FILE, String::from(remaining))))
    }

    fn event() -> ObjectRef {
        create_object(&EVENT, ())
    }

    fn found(lookup: Result<Lookup, NtStatus>) -> ObjectRef {
        match lookup {
            Ok(Lookup::Found(object)) => object,
            Ok(Lookup::Missing { name, .. }) => panic!("{name} missing"),
            Err(status) => panic!("{status:?}"),
        }
    }

    #[test]
    fn a_new_namespace_has_the_xp_directories() {
        let ns = Namespace::new();
        let names: Vec<_> = ns.root().entries().into_iter().map(|(name, _)| name).collect();
        assert_eq!(names.len(), STANDARD_DIRECTORIES.len() + 1);
        for name in ["\\BaseNamedObjects", "\\Device", "\\GLOBAL??", "\\ObjectTypes", "\\RPC Control", "\\KnownDlls"] {
            assert!(found(ns.lookup(name, None, false)).is_type(&DIRECTORY_TYPE), "{name}");
        }
        let link = found(ns.lookup("\\DosDevices", None, true));
        assert_eq!(downcast::<SymbolicLink>(&link).unwrap().target(), "\\??");
        assert!(Arc::ptr_eq(&found(ns.lookup("\\", None, false)), &(ns.root().clone() as ObjectRef)));
    }

    #[test]
    fn names_are_found_whatever_their_case() {
        let ns = Namespace::new();
        let e = event();
        assert_eq!(ns.insert(&e, "\\BaseNamedObjects\\Ready", None, 0).map(|o| o.is_none()), Ok(true));
        assert!(Arc::ptr_eq(&found(ns.lookup("\\basenamedobjects\\READY", None, false)), &e));
        assert_eq!(ns.full_name(&e).as_deref(), Some("\\BaseNamedObjects\\Ready"));
        assert_eq!(e.name().as_deref(), Some("Ready"));
    }

    #[test]
    fn a_missing_name_gives_where_to_create_it() {
        let ns = Namespace::new();
        let Ok(Lookup::Missing { directory, name }) = ns.lookup("\\BaseNamedObjects\\New", None, false) else {
            panic!("not missing");
        };
        assert_eq!(name, "New");
        let bno = found(ns.lookup("\\BaseNamedObjects", None, false));
        assert!(Arc::ptr_eq(&(directory as ObjectRef), &bno));
    }

    #[test]
    fn bad_names_say_why() {
        let ns = Namespace::new();
        ns.insert(&event(), "\\BaseNamedObjects\\E", None, 0).unwrap();
        let status = |name| ns.lookup(name, None, false).err();
        assert_eq!(status("BaseNamedObjects"), Some(STATUS_OBJECT_PATH_SYNTAX_BAD), "relative without a root");
        assert_eq!(status("\\Nowhere\\X"), Some(STATUS_OBJECT_PATH_NOT_FOUND));
        assert_eq!(status("\\BaseNamedObjects\\\\X"), Some(STATUS_OBJECT_NAME_INVALID), "empty component");
        assert_eq!(status("\\BaseNamedObjects\\E\\X"), Some(STATUS_OBJECT_TYPE_MISMATCH), "an event has no children");
        assert_eq!(ns.open("\\BaseNamedObjects\\Nope", None, None, 0).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(ns.open("\\BaseNamedObjects\\E", None, Some(&FILE), 0).err(), Some(STATUS_OBJECT_TYPE_MISMATCH));
    }

    #[test]
    fn a_name_relative_to_a_directory() {
        let ns = Namespace::new();
        let bno = found(ns.lookup("\\BaseNamedObjects", None, false));
        let e = event();
        ns.insert(&e, "Relative", Some(&bno), 0).unwrap();
        assert!(Arc::ptr_eq(&found(ns.lookup("\\BaseNamedObjects\\Relative", None, false)), &e));
        assert!(Arc::ptr_eq(&found(ns.lookup("", Some(&bno), false)), &bno), "empty name: the root itself");
        assert_eq!(ns.lookup("\\Relative", Some(&bno), false).err(), Some(STATUS_OBJECT_PATH_SYNTAX_BAD));
        assert_eq!(ns.lookup("X", Some(&e), false).err(), Some(STATUS_OBJECT_TYPE_MISMATCH), "root not a directory");
    }

    #[test]
    fn insert_collides_or_opens_if_asked() {
        let ns = Namespace::new();
        let first = event();
        ns.insert(&first, "\\BaseNamedObjects\\Once", None, 0).unwrap();
        assert_eq!(ns.insert(&event(), "\\BaseNamedObjects\\ONCE", None, 0).err(), Some(STATUS_OBJECT_NAME_COLLISION));
        let existing = ns.insert(&event(), "\\BaseNamedObjects\\Once", None, OBJ_OPENIF).unwrap();
        assert!(Arc::ptr_eq(&existing.unwrap(), &first), "OBJ_OPENIF gives the object there");
        let other: ObjectRef = create_object(&FILE, String::new());
        assert_eq!(
            ns.insert(&other, "\\BaseNamedObjects\\Once", None, OBJ_OPENIF).err(),
            Some(STATUS_OBJECT_TYPE_MISMATCH)
        );
    }

    #[test]
    fn links_are_followed_unless_opened_themselves() {
        let ns = Namespace::new();
        let e = event();
        ns.insert(&e, "\\BaseNamedObjects\\Target", None, 0).unwrap();
        let link: ObjectRef = SymbolicLink::create("\\BaseNamedObjects");
        ns.insert(&link, "\\Shortcut", None, 0).unwrap();
        assert!(Arc::ptr_eq(&found(ns.lookup("\\Shortcut\\Target", None, false)), &e), "link in the middle");
        let to_event: ObjectRef = SymbolicLink::create("\\BaseNamedObjects\\Target");
        ns.insert(&to_event, "\\Alias", None, 0).unwrap();
        assert!(Arc::ptr_eq(&found(ns.lookup("\\Alias", None, false)), &e), "link at the end");
        assert!(Arc::ptr_eq(&found(ns.lookup("\\Alias", None, true)), &to_event), "OBJ_OPENLINK");
        assert!(Arc::ptr_eq(&found(ns.lookup("\\Shortcut\\Target", None, true)), &e), "only the last component");
    }

    #[test]
    fn question_marks_name_the_dos_devices() {
        let ns = Namespace::new();
        let drive: ObjectRef = SymbolicLink::create("\\Device\\HarddiskVolume1");
        ns.insert(&drive, "\\??\\C:", None, 0).unwrap();
        assert_eq!(ns.full_name(&drive).as_deref(), Some("\\GLOBAL??\\C:"));
        let global = found(ns.lookup("\\GLOBAL??", None, false));
        assert!(Arc::ptr_eq(&found(ns.lookup("\\??", None, false)), &global));
        assert!(Arc::ptr_eq(&found(ns.lookup("\\DosDevices\\c:", None, true)), &drive), "\\DosDevices → \\??");
    }

    #[test]
    fn a_parse_procedure_takes_the_rest_of_the_name() {
        let ns = Namespace::new();
        let disk: ObjectRef = create_object(&DEVICE, ());
        ns.insert(&disk, "\\Device\\HarddiskVolume1", None, 0).unwrap();
        let drive: ObjectRef = SymbolicLink::create("\\Device\\HarddiskVolume1");
        ns.insert(&drive, "\\??\\C:", None, 0).unwrap();
        let file = found(ns.lookup("\\??\\C:\\Windows\\win.ini", None, false));
        assert!(file.is_type(&FILE));
        assert_eq!(downcast::<String>(&file).unwrap().as_str(), "\\Windows\\win.ini");
        let volume = found(ns.lookup("\\Device\\HarddiskVolume1", None, false));
        assert_eq!(downcast::<String>(&volume).unwrap().as_str(), "", "opening the device itself");
    }

    #[test]
    fn a_name_relative_to_an_object_with_a_parse_procedure_goes_to_it() {
        let ns = Namespace::new();
        let disk: ObjectRef = create_object(&DEVICE, ());
        let file = found(ns.lookup("Windows\\win.ini", Some(&disk), false));
        assert_eq!(downcast::<String>(&file).unwrap().as_str(), "\\Windows\\win.ini");
        assert!(Arc::ptr_eq(&found(ns.lookup("", Some(&disk), false)), &disk), "an empty name: the root itself");
        assert_eq!(ns.lookup("\\A", Some(&disk), false).err(), Some(STATUS_OBJECT_PATH_SYNTAX_BAD));
        let plain = event();
        assert_eq!(ns.lookup("x", Some(&plain), false).err(), Some(STATUS_OBJECT_TYPE_MISMATCH), "no parse procedure");
    }

    #[test]
    fn a_link_loop_stops() {
        let ns = Namespace::new();
        let a: ObjectRef = SymbolicLink::create("\\B");
        let b: ObjectRef = SymbolicLink::create("\\A");
        ns.insert(&a, "\\A", None, 0).unwrap();
        ns.insert(&b, "\\B", None, 0).unwrap();
        assert_eq!(ns.lookup("\\A", None, false).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
        // A chain of exactly MAX_REPARSE links still resolves.
        let e = event();
        ns.insert(&e, "\\End", None, 0).unwrap();
        for i in 0..MAX_REPARSE {
            let target = if i == 0 { String::from("\\End") } else { format!("\\L{}", i - 1) };
            ns.insert(&(SymbolicLink::create(&target) as ObjectRef), &format!("\\L{i}"), None, 0).unwrap();
        }
        let last = format!("\\L{}", MAX_REPARSE - 1);
        assert!(Arc::ptr_eq(&found(ns.lookup(&last, None, false)), &e));
        let one_more: ObjectRef = SymbolicLink::create(&last);
        ns.insert(&one_more, "\\TooFar", None, 0).unwrap();
        assert_eq!(ns.lookup("\\TooFar", None, false).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
    }

    #[test]
    fn types_are_registered_in_object_types() {
        let ns = Namespace::new();
        ns.register_type(&EVENT).unwrap();
        let ty = found(ns.lookup("\\ObjectTypes\\event", None, false));
        assert!(ty.is_type(&TYPE_TYPE));
        let body = downcast::<&'static ObjectType>(&ty).unwrap();
        assert!(core::ptr::eq(**body, &EVENT), "the object stands for the type");
        assert_eq!(ns.register_type(&EVENT), Err(STATUS_OBJECT_NAME_COLLISION));
    }
}
