//! Cm — le registre (02 §5.7, ADR-012), en lecture pour l'instant.
//!
//! `\REGISTRY` est un objet `Key` de l'espace de noms d'Ob, dont la
//! procédure *parse* résout la suite du nom : chaque clé ouverte est un objet
//! `Key` qui désigne un nœud, une clé virtuelle (`\REGISTRY`,
//! `\REGISTRY\MACHINE`, `\REGISTRY\USER`) ou une cellule d'une ruche montée
//! (`regf`). Une ruche est gardée en mémoire telle que le fichier, sans copie
//! de ses cellules ; une clé de sa racine peut être un lien
//! (`CurrentControlSet`), que la recherche suit en reprenant depuis la racine
//! de l'espace de noms.
//!
//! Les noms se comparent sans casse. Pas encore : l'écriture (création de
//! clés, valeurs), les clés volatiles, les notifications, la sécurité des
//! clés (ADR-011), l'écriture des ruches sur disque.
//!
//! [`info`] encode les classes d'information des services.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod info;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_OBJECT_TYPE_MISMATCH, STATUS_REGISTRY_CORRUPT,
};
use abi::registry::{KEY_ALL_ACCESS, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_QUERY_VALUE};
use hal::sync::{KSpinLock, Once};
use ob::{create_object, downcast, AccessMask, GenericMapping, Object, ObjectRef, ObjectType, Parsed};
use regf::Hive;

use info::{KeyFacts, ValueFacts};

const STANDARD_RIGHTS_READ: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
/// KEY_READ.
const KEY_READ: u32 = (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) & !SYNCHRONIZE;

/// Le type `Key`.
pub static KEY_TYPE: ObjectType = ObjectType::new(
    "Key",
    AccessMask(KEY_ALL_ACCESS),
    GenericMapping {
        read: AccessMask(KEY_READ),
        write: AccessMask(0x0002_0006),
        execute: AccessMask(KEY_READ),
        all: AccessMask(KEY_ALL_ACCESS),
    },
)
.with_parse(parse_key);

/// Une ruche montée : le fichier en mémoire, et les liens de sa racine.
pub struct HiveFile {
    data: Arc<[u8]>,
    /// (nom, chemin absolu de la cible) : des clés de sa racine qui sont des
    /// liens, comme `CurrentControlSet`.
    links: Vec<(String, String)>,
}

impl HiveFile {
    /// La ruche du fichier `data`, sans lien ; `STATUS_REGISTRY_CORRUPT` si
    /// elle ne se lit pas.
    pub fn new(data: Arc<[u8]>) -> Result<Self, NtStatus> {
        Hive::parse(&data).and_then(|hive| hive.root()).map_err(|_| STATUS_REGISTRY_CORRUPT)?;
        Ok(Self { data, links: Vec::new() })
    }

    /// Fait de `name`, à sa racine, un lien vers la clé `target` (chemin
    /// absolu).
    pub fn with_link(mut self, name: &str, target: &str) -> Self {
        self.links.push((name.into(), target.into()));
        self
    }

    /// La ruche, vérifiée à la création.
    fn hive(&self) -> Hive<'_> {
        Hive::parse(&self.data).expect("a hive checked when created")
    }

    /// La clé à la cellule `cell`, atteinte par ses parents.
    fn key(&self, cell: u32) -> Result<regf::Key<'_>, NtStatus> {
        self.hive().key_at(cell).map_err(corrupt)
    }

    fn root_cell(&self) -> u32 {
        self.hive().root().map(|root| root.offset()).unwrap_or(0)
    }

    /// Le lien `name` de sa racine.
    fn link(&self, name: &str) -> Option<&str> {
        self.links.iter().find(|(link, _)| eq_ignore_case(link, name)).map(|(_, target)| target.as_str())
    }
}

fn corrupt(_: regf::Error) -> NtStatus {
    STATUS_REGISTRY_CORRUPT
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.encode_utf16().map(regf::upcase).eq(b.encode_utf16().map(regf::upcase))
}

/// Une clé hors des ruches : `\REGISTRY` et ses sous-clés.
pub struct VirtualKey {
    children: KSpinLock<Vec<(String, Child)>>,
}

#[derive(Clone)]
enum Child {
    Virtual(Arc<VirtualKey>),
    /// La racine d'une ruche montée.
    Hive(Arc<HiveFile>),
}

impl VirtualKey {
    fn new() -> Self {
        Self { children: KSpinLock::new(Vec::new()) }
    }

    fn child(&self, name: &str) -> Option<(String, Child)> {
        self.children.lock().iter().find(|(child, _)| eq_ignore_case(child, name)).cloned()
    }
}

/// Ce que désigne une clé ouverte.
#[derive(Clone)]
pub enum Node {
    Virtual(Arc<VirtualKey>),
    Hive { file: Arc<HiveFile>, cell: u32 },
}

/// Le corps d'un objet `Key`.
pub struct Key {
    node: Node,
    /// Son nom, le dernier composant de son chemin.
    name: String,
}

/// Le pas d'une recherche.
enum Step {
    Key(Node, String),
    /// Un lien : la suite du nom reprend depuis cette cible.
    Link(String),
}

impl Key {
    /// Son nom de clé, le dernier composant de son chemin (l'objet, lui,
    /// n'est nommé dans l'espace d'Ob que pour `\REGISTRY`).
    pub fn key_name(&self) -> &str {
        &self.name
    }

    /// Sa sous-clé `name`, ou le lien de ce nom ; `None` sans elle.
    fn step(&self, name: &str) -> Result<Option<Step>, NtStatus> {
        match &self.node {
            Node::Virtual(key) => Ok(key.child(name).map(|(stored, child)| match child {
                Child::Virtual(child) => Step::Key(Node::Virtual(child), stored),
                Child::Hive(file) => {
                    let cell = file.root_cell();
                    Step::Key(Node::Hive { file, cell }, stored)
                }
            })),
            Node::Hive { file, cell } => {
                if *cell == file.root_cell() {
                    if let Some(target) = file.link(name) {
                        return Ok(Some(Step::Link(target.into())));
                    }
                }
                let subkey = file.key(*cell)?.subkey(name).map_err(corrupt)?;
                Ok(subkey.map(|key| {
                    Step::Key(Node::Hive { file: file.clone(), cell: key.offset() }, key.name().to_string_lossy())
                }))
            }
        }
    }

    /// Ce qu'en disent les classes d'information.
    pub fn facts(&self) -> Result<KeyFacts, NtStatus> {
        let name: Vec<u16> = self.name.encode_utf16().collect();
        match &self.node {
            Node::Virtual(key) => {
                let children = key.children.lock();
                let max_name = children.iter().map(|(n, _)| n.encode_utf16().count() * 2).max().unwrap_or(0);
                Ok(KeyFacts { name, subkeys: children.len() as u32, max_name: max_name as u32, ..KeyFacts::default() })
            }
            Node::Hive { file, cell } => {
                let key = file.key(*cell)?;
                let (max_name, max_class, max_value_name, max_value_data) = key.maxima();
                let class = key.class().map_err(corrupt)?.map(|c| c.units().collect()).unwrap_or_default();
                Ok(KeyFacts {
                    name,
                    class,
                    last_written: key.last_written(),
                    subkeys: key.subkey_count(),
                    max_name,
                    max_class,
                    values: key.value_count(),
                    max_value_name,
                    max_value_data,
                })
            }
        }
    }

    /// Sa sous-clé numéro `index`, dans l'ordre de l'énumération ; `None`
    /// au-delà.
    pub fn subkey_at(&self, index: u32) -> Result<Option<Key>, NtStatus> {
        match &self.node {
            Node::Virtual(key) => {
                let children = key.children.lock();
                Ok(children.get(index as usize).map(|(name, child)| {
                    let node = match child {
                        Child::Virtual(child) => Node::Virtual(child.clone()),
                        Child::Hive(file) => Node::Hive { file: file.clone(), cell: file.root_cell() },
                    };
                    Key { node, name: name.clone() }
                }))
            }
            Node::Hive { file, cell } => {
                let subkeys = file.key(*cell)?.subkeys().map_err(corrupt)?;
                Ok(subkeys.get(index as usize).map(|key| Key {
                    node: Node::Hive { file: file.clone(), cell: key.offset() },
                    name: key.name().to_string_lossy(),
                }))
            }
        }
    }

    /// Ses valeurs, dans l'ordre de l'énumération.
    pub fn values(&self) -> Result<Vec<ValueFacts>, NtStatus> {
        match &self.node {
            Node::Virtual(_) => Ok(Vec::new()),
            Node::Hive { file, cell } => {
                let values = file.key(*cell)?.values().map_err(corrupt)?;
                values
                    .iter()
                    .map(|value| {
                        Ok(ValueFacts {
                            name: value.name().units().collect(),
                            data_type: value.data_type(),
                            data: value.data().map_err(corrupt)?.into_owned(),
                        })
                    })
                    .collect()
            }
        }
    }

    /// Sa valeur `name` (vide pour la valeur par défaut), sans casse.
    pub fn value(&self, name: &[u16]) -> Result<Option<ValueFacts>, NtStatus> {
        match &self.node {
            Node::Virtual(_) => Ok(None),
            Node::Hive { file, cell } => {
                let value = file.key(*cell)?.value_units(name).map_err(corrupt)?;
                value
                    .map(|value| {
                        Ok(ValueFacts {
                            name: value.name().units().collect(),
                            data_type: value.data_type(),
                            data: value.data().map_err(corrupt)?.into_owned(),
                        })
                    })
                    .transpose()
            }
        }
    }
}

/// La procédure *parse* des clés : la clé que désigne la suite du nom.
fn parse_key(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
    let key = downcast::<Key>(object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    if remaining.is_empty() {
        return Ok(Parsed::Object(object.clone()));
    }
    let rest = remaining.strip_prefix('\\').ok_or(STATUS_OBJECT_NAME_INVALID)?;
    let mut current = Key { node: key.node.clone(), name: key.name.clone() };
    let mut parts = rest.split('\\');
    while let Some(part) = parts.next() {
        if part.is_empty() {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        match current.step(part)? {
            Some(Step::Key(node, name)) => current = Key { node, name },
            Some(Step::Link(target)) => {
                let tail: Vec<&str> = parts.collect();
                return Ok(Parsed::Reparse(if tail.is_empty() {
                    target
                } else {
                    format!("{target}\\{}", tail.join("\\"))
                }));
            }
            None => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }
    Ok(Parsed::Object(create_object(&KEY_TYPE, current)))
}

/// La racine d'un registre neuf : `REGISTRY`, avec `MACHINE` et `USER`,
/// sans ruche.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn new_registry() -> Arc<Object<Key>> {
    let root = VirtualKey::new();
    for name in ["MACHINE", "USER"] {
        root.children.lock().push((name.into(), Child::Virtual(Arc::new(VirtualKey::new()))));
    }
    create_object(&KEY_TYPE, Key { node: Node::Virtual(Arc::new(root)), name: "REGISTRY".into() })
}

/// Monte `file` sous la clé virtuelle `parent` (un chemin sous la racine
/// `registry`, comme `MACHINE`), au nom `name`.
/// `STATUS_OBJECT_PATH_NOT_FOUND` sans clé virtuelle `parent` ;
/// `STATUS_OBJECT_NAME_COLLISION` si le nom est pris.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn mount(registry: &Key, parent: &str, name: &str, file: HiveFile) -> Result<(), NtStatus> {
    let parent = virtual_key(registry, parent)?;
    let mut children = parent.children.lock();
    if children.iter().any(|(child, _)| eq_ignore_case(child, name)) {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    children.push((name.into(), Child::Hive(Arc::new(file))));
    Ok(())
}

/// Démonte la ruche `name` de la clé virtuelle `parent` ; les clés déjà
/// ouvertes la gardent. `STATUS_OBJECT_NAME_NOT_FOUND` sans elle.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn unmount(registry: &Key, parent: &str, name: &str) -> Result<(), NtStatus> {
    let parent = virtual_key(registry, parent)?;
    let mut children = parent.children.lock();
    let index = children
        .iter()
        .position(|(child, node)| eq_ignore_case(child, name) && matches!(node, Child::Hive(_)))
        .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    children.remove(index);
    Ok(())
}

/// La clé virtuelle au chemin `path` sous `registry`.
fn virtual_key(registry: &Key, path: &str) -> Result<Arc<VirtualKey>, NtStatus> {
    let Node::Virtual(mut key) = registry.node.clone() else { return Err(STATUS_OBJECT_PATH_NOT_FOUND) };
    for part in path.split('\\').filter(|p| !p.is_empty()) {
        match key.child(part) {
            Some((_, Child::Virtual(child))) => key = child,
            _ => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
        }
    }
    Ok(key)
}

/// Le registre du système, `\REGISTRY`.
static REGISTRY: Once<Arc<Object<Key>>> = Once::new();

/// Crée `\REGISTRY` dans l'espace de noms d'Ob.
///
/// # IRQL
/// PASSIVE_LEVEL, une fois, après `ob::init` et l'enregistrement du type
/// `Key`.
pub fn init() {
    let registry = REGISTRY.call_once(new_registry);
    let object: ObjectRef = registry.clone();
    ob::namespace()
        .insert(&object, "\\REGISTRY", None, abi::object::OBJ_PERMANENT)
        .expect("\\REGISTRY taken before Cm");
}

/// Le registre du système ; `None` avant [`init`].
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn registry() -> Option<Arc<Object<Key>>> {
    REGISTRY.get().cloned()
}

/// Monte la ruche SYSTEM du fichier `data` en `\REGISTRY\MACHINE\SYSTEM`,
/// avec le lien `CurrentControlSet` vers le jeu de contrôle que désigne
/// `Select\Current` (1 sans lui). Rend ce numéro.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub fn mount_system_hive(data: Arc<[u8]>) -> Result<u32, NtStatus> {
    let registry = registry().expect("Cm not initialised");
    let current = {
        let hive = Hive::parse(&data).map_err(corrupt)?;
        let select = hive.root().and_then(|root| root.open("Select")).map_err(corrupt)?;
        let value = select.and_then(|key| key.value("Current").ok().flatten());
        value
            .and_then(|v| v.data().ok().map(|d| d.into_owned()))
            .and_then(|d| d.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
            .unwrap_or(1)
    };
    let target = format!("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet{current:03}");
    mount(&registry, "MACHINE", "SYSTEM", HiveFile::new(data)?.with_link("CurrentControlSet", &target))?;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::registry::REG_SZ;
    use alloc::vec;
    use ob::namespace::{Lookup, Namespace};
    use regf::builder::{build, KeyNode};

    fn sz(text: &str) -> Vec<u8> {
        text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    /// A namespace with a registry, the SYSTEM hive mounted.
    fn registry() -> (Namespace, Arc<Object<Key>>) {
        let mut root = KeyNode::new("$$$PROTO.HIV");
        root.key_mut("Select").set_value("Current", 4, vec![1, 0, 0, 0]);
        let session = root.key_mut("ControlSet001\\Control\\Session Manager");
        session.set_value("ObjectDirectories", 7, sz("\\Windows"));
        session.key_mut("KnownDLLs").set_value("kernel32", REG_SZ, sz("kernel32.dll"));
        root.key_mut("ControlSet001\\Services");
        let data: Arc<[u8]> = Arc::from(build(&root, "SYSTEM"));
        let ns = Namespace::new();
        let registry = new_registry();
        let object: ObjectRef = registry.clone();
        ns.insert(&object, "\\REGISTRY", None, 0).unwrap();
        let file =
            HiveFile::new(data).unwrap().with_link("CurrentControlSet", "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001");
        mount(&registry, "MACHINE", "SYSTEM", file).unwrap();
        (ns, registry)
    }

    fn open(ns: &Namespace, name: &str) -> Result<Arc<Object<Key>>, NtStatus> {
        match ns.lookup(name, None, false)? {
            Lookup::Found(object) => downcast::<Key>(&object).ok_or(STATUS_OBJECT_TYPE_MISMATCH),
            Lookup::Missing { .. } => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        }
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn keys_open_by_name_through_the_hive_without_case() {
        let (ns, _) = registry();
        let session = open(&ns, "\\Registry\\Machine\\system\\ControlSet001\\Control\\SESSION MANAGER").unwrap();
        assert_eq!(session.key_name(), "Session Manager", "the stored name");
        let directories = session.value(&units("objectdirectories")).unwrap().expect("ObjectDirectories");
        assert_eq!((directories.data_type, directories.data), (7, sz("\\Windows")));
        assert!(session.value(&units("Missing")).unwrap().is_none());
        assert_eq!(open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\Missing").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\\\Select").err(), Some(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(open(&ns, "\\REGISTRY\\MACHINE\\SOFTWARE").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND), "not mounted");
    }

    #[test]
    fn current_control_set_leads_to_the_selected_set() {
        let (ns, _) = registry();
        let known =
            open(&ns, "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs").unwrap();
        assert_eq!(known.value(&units("KERNEL32")).unwrap().unwrap().data, sz("kernel32.dll"));
        let set = open(&ns, "\\Registry\\Machine\\System\\CurrentControlSet").unwrap();
        assert_eq!(set.key_name(), "ControlSet001");
    }

    #[test]
    fn names_relative_to_a_key_go_through_its_parse_procedure() {
        let (ns, _) = registry();
        let control: ObjectRef = open(&ns, "\\Registry\\Machine\\System\\ControlSet001\\Control").unwrap();
        let found = match ns.lookup("Session Manager\\KnownDLLs", Some(&control), false).unwrap() {
            Lookup::Found(object) => downcast::<Key>(&object).unwrap(),
            Lookup::Missing { .. } => panic!("missing"),
        };
        assert_eq!(found.key_name(), "KnownDLLs");
    }

    #[test]
    fn virtual_keys_and_hive_keys_enumerate() {
        let (ns, registry) = registry();
        let machine = open(&ns, "\\REGISTRY\\MACHINE").unwrap();
        assert_eq!(machine.subkey_at(0).unwrap().unwrap().key_name(), "SYSTEM");
        assert!(machine.subkey_at(1).unwrap().is_none());
        let facts = registry.facts().unwrap();
        assert_eq!((facts.subkeys, facts.values, facts.max_name), (2, 0, 14), "MACHINE and USER");
        let set = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001").unwrap();
        let names: Vec<_> =
            (0..).map_while(|i| set.subkey_at(i).unwrap()).map(|k| String::from(k.key_name())).collect();
        assert_eq!(names, ["Control", "Services"]);
        let session = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager").unwrap();
        let facts = session.facts().unwrap();
        assert_eq!((facts.subkeys, facts.values, facts.max_name, facts.max_value_name), (1, 1, 18, 34));
        assert_eq!(session.values().unwrap()[0].data_type, 7);
    }

    #[test]
    fn mounting_twice_or_under_nothing_is_refused_and_unmounting_hides_the_hive() {
        let (ns, registry) = registry();
        let again = HiveFile::new(Arc::from(build(&KeyNode::new("X"), "X"))).unwrap();
        assert_eq!(mount(&registry, "MACHINE", "system", again).err(), Some(STATUS_OBJECT_NAME_COLLISION));
        let other = HiveFile::new(Arc::from(build(&KeyNode::new("X"), "X"))).unwrap();
        assert_eq!(mount(&registry, "NOWHERE", "X", other).err(), Some(STATUS_OBJECT_PATH_NOT_FOUND));
        let kept = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\Select").unwrap();
        unmount(&registry, "MACHINE", "SYSTEM").unwrap();
        assert_eq!(open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM").err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
        assert!(kept.value(&units("Current")).unwrap().is_some(), "an open key keeps its hive");
        assert_eq!(HiveFile::new(Arc::from(&b"regf"[..])).err(), Some(STATUS_REGISTRY_CORRUPT));
    }
}
