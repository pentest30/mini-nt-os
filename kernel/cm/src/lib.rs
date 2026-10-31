//! Cm — le registre (02 §5.7, ADR-012).
//!
//! `\REGISTRY` est un objet `Key` de l'espace de noms d'Ob, dont la
//! procédure *parse* résout la suite du nom : chaque clé ouverte est un objet
//! `Key` qui désigne un nœud, une clé virtuelle (`\REGISTRY`,
//! `\REGISTRY\MACHINE`, `\REGISTRY\USER`) ou une clé d'une ruche montée.
//!
//! Une ruche montée est un arbre de clés en mémoire ([`HiveKey`]), lu du
//! fichier `regf` à son montage : ses valeurs s'écrivent et s'effacent, des
//! clés s'y créent ([`Key::set_value`], [`Key::delete_value`],
//! [`Key::create_subkey`]), chacune sous son verrou. Les sous-clés restent
//! triées par nom en majuscules, comme dans les listes d'un fichier `regf`.
//! Une clé de sa racine peut être un lien (`CurrentControlSet`), que la
//! recherche suit en reprenant depuis la racine de l'espace de noms.
//!
//! Les noms se comparent sans casse. Pas encore : l'écriture des ruches sur
//! disque (par `regf::builder`, la ruche entière), la suppression de clés,
//! les clés liens, les notifications, la sécurité des clés (ADR-011 : tout
//! est accordé).
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
    NtStatus, STATUS_ACCESS_DENIED, STATUS_CHILD_MUST_BE_VOLATILE, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
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

/// La profondeur d'une ruche, au plus : 512 niveaux, comme XP.
pub const MAX_DEPTH: usize = 512;
/// La longueur d'un nom de clé, au plus, en caractères.
pub const MAX_KEY_NAME: usize = 255;

/// Une clé d'une ruche montée.
pub struct HiveKey {
    /// Son nom, en UTF-16.
    name: Vec<u16>,
    /// Créée volatile (`REG_OPTION_VOLATILE`) : elle n'ira pas sur disque.
    volatile: bool,
    /// Son niveau dans la ruche, la racine au niveau 1.
    depth: usize,
    state: KSpinLock<HiveKeyState>,
}

struct HiveKeyState {
    class: Vec<u16>,
    /// FILETIME de sa dernière écriture.
    last_written: u64,
    /// Dans l'ordre de l'énumération : celui du fichier, puis de l'écriture.
    values: Vec<ValueFacts>,
    /// Triées par nom en majuscules.
    subkeys: Vec<Arc<HiveKey>>,
}

fn upcased(units: &[u16]) -> impl Iterator<Item = u16> + '_ {
    units.iter().map(|&u| regf::upcase(u))
}

fn units_eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && upcased(a).eq(upcased(b))
}

impl HiveKey {
    fn new(name: Vec<u16>, class: Vec<u16>, last_written: u64, volatile: bool, depth: usize) -> Arc<Self> {
        Arc::new(Self {
            name,
            volatile,
            depth,
            state: KSpinLock::new(HiveKeyState { class, last_written, values: Vec::new(), subkeys: Vec::new() }),
        })
    }

    fn name_string(&self) -> String {
        String::from_utf16_lossy(&self.name)
    }

    /// Sa sous-clé `name`, sans casse.
    fn child(&self, name: &[u16]) -> Option<Arc<HiveKey>> {
        self.state.lock().subkeys.iter().find(|key| units_eq_ignore_case(&key.name, name)).cloned()
    }

    /// Range `child` parmi ses sous-clés, à sa place dans l'ordre des noms.
    fn insert_sorted(subkeys: &mut Vec<Arc<HiveKey>>, child: Arc<HiveKey>) {
        let at = subkeys.partition_point(|key| upcased(&key.name).lt(upcased(&child.name)));
        subkeys.insert(at, child);
    }
}

/// Une ruche montée : l'arbre de ses clés, et les liens de sa racine.
pub struct HiveFile {
    root: Arc<HiveKey>,
    /// (nom, chemin absolu de la cible) : des clés de sa racine qui sont des
    /// liens, comme `CurrentControlSet`.
    links: Vec<(String, String)>,
}

impl HiveFile {
    /// La ruche du fichier `data`, lue en entier, sans lien ;
    /// `STATUS_REGISTRY_CORRUPT` si elle ne se lit pas, ou dépasse
    /// [`MAX_DEPTH`] niveaux (une boucle de cellules aussi).
    pub fn new(data: Arc<[u8]>) -> Result<Self, NtStatus> {
        let hive = Hive::parse(&data).map_err(corrupt)?;
        Ok(Self { root: load(&hive).map_err(corrupt)?, links: Vec::new() })
    }

    /// Fait de `name`, à sa racine, un lien vers la clé `target` (chemin
    /// absolu).
    pub fn with_link(mut self, name: &str, target: &str) -> Self {
        self.links.push((name.into(), target.into()));
        self
    }

    /// Le lien `name` de sa racine.
    fn link(&self, name: &str) -> Option<&str> {
        self.links.iter().find(|(link, _)| eq_ignore_case(link, name)).map(|(_, target)| target.as_str())
    }
}

/// L'arbre des clés de `hive`, parcouru sans récursion.
fn load(hive: &Hive<'_>) -> Result<Arc<HiveKey>, regf::Error> {
    let read = |key: &regf::Key<'_>, depth: usize| -> Result<Arc<HiveKey>, regf::Error> {
        let class = key.class()?.map(|c| c.units().collect()).unwrap_or_default();
        let node = HiveKey::new(key.name().units().collect(), class, key.last_written(), false, depth);
        let values = key
            .values()?
            .iter()
            .map(|value| {
                Ok(ValueFacts {
                    name: value.name().units().collect(),
                    data_type: value.data_type(),
                    data: value.data()?.into_owned(),
                })
            })
            .collect::<Result<Vec<_>, regf::Error>>()?;
        node.state.lock().values = values;
        Ok(node)
    };
    let root_cell = hive.root()?;
    let root = read(&root_cell, 1)?;
    let mut pending: Vec<(regf::Key<'_>, Arc<HiveKey>)> = alloc::vec![(root_cell, root.clone())];
    while let Some((cell, node)) = pending.pop() {
        let subkeys = cell.subkeys()?;
        if !subkeys.is_empty() && node.depth >= MAX_DEPTH {
            return Err(regf::Error::Unsupported("a hive deeper than 512 levels"));
        }
        for subkey in subkeys {
            let child = read(&subkey, node.depth + 1)?;
            HiveKey::insert_sorted(&mut node.state.lock().subkeys, child.clone());
            pending.push((subkey, child));
        }
    }
    Ok(root)
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
    Hive { file: Arc<HiveFile>, key: Arc<HiveKey> },
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

/// Le temps système, en FILETIME, pour la date d'écriture d'une clé.
fn now() -> u64 {
    hal::timer::interrupt_time()
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
                    let key = file.root.clone();
                    Step::Key(Node::Hive { file, key }, stored)
                }
            })),
            Node::Hive { file, key } => {
                if Arc::ptr_eq(key, &file.root) {
                    if let Some(target) = file.link(name) {
                        return Ok(Some(Step::Link(target.into())));
                    }
                }
                let units: Vec<u16> = name.encode_utf16().collect();
                Ok(key.child(&units).map(|child| {
                    let name = child.name_string();
                    Step::Key(Node::Hive { file: file.clone(), key: child }, name)
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
            Node::Hive { key, .. } => {
                let state = key.state.lock();
                let bytes = |units: usize| (units * 2) as u32;
                let max_name = state.subkeys.iter().map(|k| bytes(k.name.len())).max().unwrap_or(0);
                let max_class = state.subkeys.iter().map(|k| bytes(k.state.lock().class.len())).max().unwrap_or(0);
                let max_value_name = state.values.iter().map(|v| bytes(v.name.len())).max().unwrap_or(0);
                let max_value_data = state.values.iter().map(|v| v.data.len() as u32).max().unwrap_or(0);
                Ok(KeyFacts {
                    name,
                    class: state.class.clone(),
                    last_written: state.last_written,
                    subkeys: state.subkeys.len() as u32,
                    max_name,
                    max_class,
                    values: state.values.len() as u32,
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
                        Child::Hive(file) => Node::Hive { file: file.clone(), key: file.root.clone() },
                    };
                    Key { node, name: name.clone() }
                }))
            }
            Node::Hive { file, key } => {
                let child = key.state.lock().subkeys.get(index as usize).cloned();
                Ok(child.map(|child| {
                    let name = child.name_string();
                    Key { node: Node::Hive { file: file.clone(), key: child }, name }
                }))
            }
        }
    }

    /// Ses valeurs, dans l'ordre de l'énumération.
    pub fn values(&self) -> Result<Vec<ValueFacts>, NtStatus> {
        match &self.node {
            Node::Virtual(_) => Ok(Vec::new()),
            Node::Hive { key, .. } => Ok(key.state.lock().values.clone()),
        }
    }

    /// Sa valeur `name` (vide pour la valeur par défaut), sans casse.
    pub fn value(&self, name: &[u16]) -> Result<Option<ValueFacts>, NtStatus> {
        match &self.node {
            Node::Virtual(_) => Ok(None),
            Node::Hive { key, .. } => {
                Ok(key.state.lock().values.iter().find(|v| units_eq_ignore_case(&v.name, name)).cloned())
            }
        }
    }

    /// La clé d'une ruche qu'il désigne ; `STATUS_ACCESS_DENIED` pour une clé
    /// virtuelle, que rien n'écrit.
    fn hive_key(&self) -> Result<(&Arc<HiveFile>, &Arc<HiveKey>), NtStatus> {
        match &self.node {
            Node::Hive { file, key } => Ok((file, key)),
            Node::Virtual(_) => Err(STATUS_ACCESS_DENIED),
        }
    }

    /// NtSetValueKey : donne à sa valeur `name` (vide pour la valeur par
    /// défaut) le type `data_type` et les données `data`, la crée sinon (à la
    /// fin de l'énumération) ; la clé prend la date de l'écriture.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set_value(&self, name: &[u16], data_type: u32, data: Vec<u8>) -> Result<(), NtStatus> {
        let (_, key) = self.hive_key()?;
        let mut state = key.state.lock();
        match state.values.iter_mut().find(|v| units_eq_ignore_case(&v.name, name)) {
            Some(value) => {
                value.data_type = data_type;
                value.data = data;
            }
            None => state.values.push(ValueFacts { name: name.to_vec(), data_type, data }),
        }
        state.last_written = now();
        Ok(())
    }

    /// NtDeleteValueKey : efface sa valeur `name` ;
    /// `STATUS_OBJECT_NAME_NOT_FOUND` sans elle.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn delete_value(&self, name: &[u16]) -> Result<(), NtStatus> {
        let (_, key) = self.hive_key()?;
        let mut state = key.state.lock();
        let index = state
            .values
            .iter()
            .position(|v| units_eq_ignore_case(&v.name, name))
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        state.values.remove(index);
        state.last_written = now();
        Ok(())
    }

    /// NtCreateKey, une fois le parent trouvé : sa sous-clé `name`, créée de
    /// la classe `class` (volatile avec `volatile`) si elle n'existe pas.
    /// Rend la clé, et si elle vient d'être créée. Erreurs : nom vide ou avec
    /// `\\` (`STATUS_OBJECT_NAME_INVALID`), de plus de [`MAX_KEY_NAME`]
    /// caractères (`STATUS_INVALID_PARAMETER`), un lien de la racine de la
    /// ruche (`STATUS_OBJECT_NAME_COLLISION`), une clé durable sous une clé
    /// volatile (`STATUS_CHILD_MUST_BE_VOLATILE`), une clé virtuelle
    /// (`STATUS_ACCESS_DENIED`), au-delà de [`MAX_DEPTH`] niveaux
    /// (`STATUS_INVALID_PARAMETER`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_subkey(&self, name: &str, class: &[u16], volatile: bool) -> Result<(Key, bool), NtStatus> {
        let (file, key) = self.hive_key()?;
        let units: Vec<u16> = name.encode_utf16().collect();
        if units.is_empty() || name.contains('\\') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if units.len() > MAX_KEY_NAME {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if Arc::ptr_eq(key, &file.root) && file.link(name).is_some() {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let opened = |child: Arc<HiveKey>| {
            let name = child.name_string();
            Key { node: Node::Hive { file: file.clone(), key: child }, name }
        };
        let mut state = key.state.lock();
        if let Some(child) = state.subkeys.iter().find(|k| units_eq_ignore_case(&k.name, &units)) {
            return Ok((opened(child.clone()), false));
        }
        if key.volatile && !volatile {
            return Err(STATUS_CHILD_MUST_BE_VOLATILE);
        }
        if key.depth >= MAX_DEPTH {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let time = now();
        let child = HiveKey::new(units, class.to_vec(), time, volatile, key.depth + 1);
        HiveKey::insert_sorted(&mut state.subkeys, child.clone());
        state.last_written = time;
        Ok((opened(child), true))
    }

    /// La clé est volatile.
    pub fn is_volatile(&self) -> bool {
        matches!(&self.node, Node::Hive { key, .. } if key.volatile)
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

    #[test]
    fn values_are_set_replaced_and_deleted() {
        let (ns, _) = registry();
        let select = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\Select").unwrap();
        select.set_value(&units("Text"), REG_SZ, sz("one")).unwrap();
        select.set_value(&units(""), 4, vec![7, 0, 0, 0]).unwrap();
        select.set_value(&units("CURRENT"), 4, vec![2, 0, 0, 0]).unwrap();
        let names: Vec<_> =
            select.values().unwrap().into_iter().map(|v| String::from_utf16(&v.name).unwrap()).collect();
        assert_eq!(names, ["Current", "Text", ""], "replaced in place, new ones at the end");
        assert_eq!(select.value(&units("current")).unwrap().unwrap().data, vec![2, 0, 0, 0]);
        let again = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\Select").unwrap();
        assert_eq!(again.value(&units("text")).unwrap().unwrap().data, sz("one"), "seen through another open");
        assert_eq!(again.facts().unwrap().values, 3);
        select.delete_value(&units("TEXT")).unwrap();
        assert_eq!(select.delete_value(&units("Text")).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));
        assert!(again.value(&units("Text")).unwrap().is_none());
        assert_eq!(again.facts().unwrap().max_value_data, 4);
    }

    #[test]
    fn subkeys_are_created_once_and_stay_sorted() {
        let (ns, _) = registry();
        let set = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001").unwrap();
        let (zeta, created) = set.create_subkey("Zeta", &units("Cls"), false).unwrap();
        assert!(created);
        assert_eq!(zeta.facts().unwrap().class, units("Cls"));
        let (alpha, _) = set.create_subkey("alpha", &[], false).unwrap();
        alpha.set_value(&units("V"), 4, vec![1, 0, 0, 0]).unwrap();
        let (same, created) = set.create_subkey("ALPHA", &units("ignored"), false).unwrap();
        assert!(!created, "an existing key opens");
        assert_eq!((same.key_name(), same.values().unwrap().len()), ("alpha", 1));
        let names: Vec<_> =
            (0..).map_while(|i| set.subkey_at(i).unwrap()).map(|k| String::from(k.key_name())).collect();
        assert_eq!(names, ["alpha", "Control", "Services", "Zeta"]);
        let found = open(&ns, "\\Registry\\Machine\\System\\CurrentControlSet\\ZETA").unwrap();
        assert_eq!(found.key_name(), "Zeta", "reached by name, through the link");
        assert_eq!(set.facts().unwrap().max_class, 6);
    }

    #[test]
    fn what_cannot_be_created() {
        let (ns, registry) = registry();
        let machine = open(&ns, "\\REGISTRY\\MACHINE").unwrap();
        assert_eq!(machine.create_subkey("New", &[], false).err(), Some(STATUS_ACCESS_DENIED), "a virtual key");
        assert_eq!(registry.set_value(&units("V"), 4, vec![0; 4]).err(), Some(STATUS_ACCESS_DENIED));
        let system = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM").unwrap();
        assert_eq!(system.create_subkey("currentcontrolset", &[], false).err(), Some(STATUS_OBJECT_NAME_COLLISION));
        assert_eq!(system.create_subkey("", &[], false).err(), Some(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(system.create_subkey("a\\b", &[], false).err(), Some(STATUS_OBJECT_NAME_INVALID));
        let long = "k".repeat(MAX_KEY_NAME + 1);
        assert_eq!(system.create_subkey(&long, &[], false).err(), Some(STATUS_INVALID_PARAMETER));
        assert!(system.create_subkey(&long[1..], &[], false).is_ok(), "255 characters");
    }

    #[test]
    fn a_volatile_key_holds_only_volatile_keys() {
        let (ns, _) = registry();
        let system = open(&ns, "\\REGISTRY\\MACHINE\\SYSTEM").unwrap();
        let (volatile, _) = system.create_subkey("Volatile", &[], true).unwrap();
        assert!(volatile.is_volatile() && !system.is_volatile());
        assert_eq!(volatile.create_subkey("Durable", &[], false).err(), Some(STATUS_CHILD_MUST_BE_VOLATILE));
        assert!(volatile.create_subkey("Also", &[], true).unwrap().0.is_volatile());
    }

    #[test]
    fn a_hive_holds_512_levels() {
        let path = |levels: usize| (1..levels).map(|i| format!("K{i}")).collect::<Vec<_>>().join("\\");
        let mut deep = KeyNode::new("ROOT");
        deep.key_mut(&path(MAX_DEPTH));
        let file = HiveFile::new(Arc::from(build(&deep, "DEEP"))).expect("512 levels load");
        let ns = Namespace::new();
        let registry = new_registry();
        let object: ObjectRef = registry.clone();
        ns.insert(&object, "\\REGISTRY", None, 0).unwrap();
        mount(&registry, "MACHINE", "DEEP", file).unwrap();
        let bottom = open(&ns, &format!("\\REGISTRY\\MACHINE\\DEEP\\{}", path(MAX_DEPTH))).unwrap();
        assert_eq!(bottom.create_subkey("Deeper", &[], false).err(), Some(STATUS_INVALID_PARAMETER));
        let mut deeper = KeyNode::new("ROOT");
        deeper.key_mut(&path(MAX_DEPTH + 1));
        assert_eq!(HiveFile::new(Arc::from(build(&deeper, "DEEP"))).err(), Some(STATUS_REGISTRY_CORRUPT));
    }
}
