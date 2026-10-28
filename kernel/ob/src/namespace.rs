//! NT object namespace — the global named object tree.
//!
//! NT's namespace looks like a file system:
//!   \\                        root directory
//!   \\Device\\                device objects
//!   \\Device\\HarddiskVolume1 a volume
//!   \\BaseNamedObjects\\      user-visible named objects (events, mutexes…)
//!   \\Registry\\              registry hive root
//!   \\KernelObjects\\         system events (LowMemoryCondition, etc.)
//!
//! Games use named objects via kernel32's CreateEvent/OpenEvent etc.,
//! which prepend "\\BaseNamedObjects\\" before calling Nt APIs.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;
use super::object::ObjectRef;

struct Directory {
    children: BTreeMap<String, NamespaceEntry>,
}

enum NamespaceEntry {
    Object(ObjectRef),
    Directory(Directory),
}

static ROOT: Mutex<Directory> = Mutex::new(Directory {
    children: BTreeMap::new(),
});

/// Initialise the root namespace with required directories.
pub fn init() {
    let mut root = ROOT.lock();
    for name in &["Device", "BaseNamedObjects", "Registry", "KernelObjects"] {
        root.children.insert(
            name.to_string(),
            NamespaceEntry::Directory(Directory { children: BTreeMap::new() }),
        );
    }
    log::info!("Ob namespace: root directories created");
}

/// Insert a named object at an absolute NT path (e.g. "\\BaseNamedObjects\\MyEvent").
pub fn insert(path: &str, object: ObjectRef) -> Result<(), &'static str> {
    let parts: Vec<&str> = path.trim_matches('\\').split('\\').collect();
    if parts.is_empty() { return Err("empty path"); }

    let mut root = ROOT.lock();
    let mut dir  = &mut root.children;

    for &component in &parts[..parts.len() - 1] {
        match dir.get_mut(component) {
            Some(NamespaceEntry::Directory(d)) => dir = &mut d.children,
            _ => return Err("path component not found or not a directory"),
        }
    }

    let name = parts[parts.len() - 1];
    if dir.contains_key(name) { return Err("object already exists"); }
    dir.insert(name.to_string(), NamespaceEntry::Object(object));
    Ok(())
}

/// Look up a named object.
pub fn lookup(path: &str) -> Option<ObjectRef> {
    let parts: Vec<&str> = path.trim_matches('\\').split('\\').collect();
    let root = ROOT.lock();
    let mut dir = &root.children;

    for (i, &component) in parts.iter().enumerate() {
        match dir.get(component)? {
            NamespaceEntry::Object(obj) if i == parts.len() - 1 => {
                return Some(obj.clone());
            }
            NamespaceEntry::Directory(d) => dir = &d.children,
            _ => return None,
        }
    }
    None
}
