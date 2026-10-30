//! Objects (02 §5.4) : un en-tête, puis le corps.
//!
//! Un objet est un [`Object<T>`] dans un `Arc` : le compte de pointeurs de NT
//! (`ObReferenceObject`, `ObDereferenceObject`) est celui de l'`Arc`, et le
//! corps se détruit (son `Drop`) quand la dernière référence part. L'en-tête
//! tient le type, le compte de handles, le nom et le drapeau permanent. Le
//! code qui ne connaît pas le corps manipule un [`ObjectRef`], et retrouve le
//! corps par [`downcast`].
//!
//! Un type ([`ObjectType`]) est une `static` du composant qui le définit : ses
//! droits valides, sa correspondance générique, ses procédures (*parse*,
//! fermeture) et ses compteurs.
//!
//! Pas encore : descripteur de sécurité (avec Se ; ADR-011 : accès accordés),
//! quotas, objets exclusifs (`OBJ_EXCLUSIVE`).

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use abi::ntstatus::NtStatus;
use abi::object::{AccessMask, GenericMapping};
use hal::sync::KSpinLock;

use crate::directory::Directory;

/// Ce que décide la procédure *parse* d'un type pour la suite d'un nom.
pub enum Parsed {
    /// L'objet que désigne le nom entier.
    Object(ObjectRef),
    /// Reprendre la recherche depuis la racine avec ce nom (lien symbolique).
    Reparse(String),
}

/// La procédure *parse* d'un type : l'objet `object` atteint par une
/// recherche, et la suite du nom (vide, ou qui commence par `\`).
pub type ParseProcedure = fn(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus>;

/// La procédure de fermeture d'un type : après la fermeture de chaque handle,
/// avec le nombre de handles qui restent sur l'objet.
pub type CloseProcedure = fn(object: &ObjectRef, handles_left: u32);

/// Un type d'objet (OBJECT_TYPE).
pub struct ObjectType {
    pub name: &'static str,
    /// Les droits qu'un handle peut avoir sur un objet du type.
    pub valid_access: AccessMask,
    pub generic_mapping: GenericMapping,
    pub parse: Option<ParseProcedure>,
    pub close: Option<CloseProcedure>,
    objects: AtomicU32,
    handles: AtomicU32,
}

impl ObjectType {
    /// Un type sans procédures.
    pub const fn new(name: &'static str, valid_access: AccessMask, generic_mapping: GenericMapping) -> Self {
        Self {
            name,
            valid_access,
            generic_mapping,
            parse: None,
            close: None,
            objects: AtomicU32::new(0),
            handles: AtomicU32::new(0),
        }
    }

    /// Ce type avec la procédure *parse* `parse`.
    pub const fn with_parse(self, parse: ParseProcedure) -> Self {
        Self { parse: Some(parse), ..self }
    }

    /// Ce type avec la procédure de fermeture `close`.
    pub const fn with_close(self, close: CloseProcedure) -> Self {
        Self { close: Some(close), ..self }
    }

    /// Le nombre d'objets du type qui existent.
    pub fn object_count(&self) -> u32 {
        self.objects.load(Ordering::Relaxed)
    }

    /// Le nombre de handles ouverts sur des objets du type.
    pub fn handle_count(&self) -> u32 {
        self.handles.load(Ordering::Relaxed)
    }

    /// Les droits qu'un handle reçoit quand on demande `desired` : droits
    /// génériques traduits, `MAXIMUM_ALLOWED` pour tous les droits du type,
    /// dans la limite des droits valides. Tout est accordé tant que Se
    /// n'existe pas (ADR-011).
    pub fn granted_access(&self, desired: AccessMask) -> AccessMask {
        let mut granted = self.generic_mapping.map(desired);
        if desired.contains(AccessMask::MAXIMUM_ALLOWED) {
            granted = granted | self.generic_mapping.all;
        }
        granted & self.valid_access
    }
}

pub const OBJECT_TYPE_CREATE: AccessMask = AccessMask(0x0001);
pub const OBJECT_TYPE_ALL_ACCESS: AccessMask = AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | 0x1);

/// Le type `Type` : celui des objets qui représentent les types dans
/// `\ObjectTypes` (`Namespace::register_type`).
pub static TYPE_TYPE: ObjectType = ObjectType::new(
    "Type",
    OBJECT_TYPE_ALL_ACCESS,
    GenericMapping {
        read: AccessMask::STANDARD_RIGHTS_READ,
        write: AccessMask::STANDARD_RIGHTS_WRITE,
        execute: AccessMask::STANDARD_RIGHTS_EXECUTE,
        all: OBJECT_TYPE_ALL_ACCESS,
    },
);

/// Le nom d'un objet inséré dans un répertoire.
pub(crate) struct NameInfo {
    pub(crate) name: String,
    /// Le répertoire, qui tient l'objet ; faible, sinon un cycle.
    pub(crate) directory: Weak<Object<Directory>>,
}

/// L'en-tête d'un objet (OBJECT_HEADER).
pub struct ObjectHeader {
    ty: &'static ObjectType,
    handles: AtomicU32,
    permanent: AtomicBool,
    pub(crate) name: KSpinLock<Option<NameInfo>>,
}

/// Un objet : son en-tête, puis son corps, auquel il donne accès (`Deref`).
pub struct Object<T: ?Sized> {
    header: ObjectHeader,
    body: T,
}

/// Une référence à un objet de type quelconque.
pub type ObjectRef = Arc<Object<dyn Any + Send + Sync>>;

/// ObCreateObject : un objet du type `ty` de corps `body`, sans nom ni handle.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn create_object<T: Any + Send + Sync>(ty: &'static ObjectType, body: T) -> Arc<Object<T>> {
    ty.objects.fetch_add(1, Ordering::Relaxed);
    let header =
        ObjectHeader { ty, handles: AtomicU32::new(0), permanent: AtomicBool::new(false), name: KSpinLock::new(None) };
    Arc::new(Object { header, body })
}

/// L'objet `object` vu comme un `T`, s'il en est un.
///
/// # IRQL
/// Tout niveau.
pub fn downcast<T: Any + Send + Sync>(object: &ObjectRef) -> Option<Arc<Object<T>>> {
    let body: &(dyn Any + Send + Sync) = &object.body;
    if !body.is::<T>() {
        return None;
    }
    let raw = Arc::into_raw(object.clone());
    // SAFETY: the allocation holds an Object<T> (its body is a T), created by
    // `create_object` as an Arc<Object<T>>; dropping the vtable keeps the
    // address, and the reference taken by `clone` passes to the result.
    Some(unsafe { Arc::from_raw(raw.cast::<Object<T>>()) })
}

impl<T: ?Sized> Object<T> {
    /// Son type.
    pub fn object_type(&self) -> &'static ObjectType {
        self.header.ty
    }

    /// Il est du type `ty`.
    pub fn is_type(&self, ty: &ObjectType) -> bool {
        core::ptr::eq(self.header.ty, ty)
    }

    /// Le nombre de handles ouverts sur lui.
    pub fn handle_count(&self) -> u32 {
        self.header.handles.load(Ordering::Acquire)
    }

    /// Il garde son nom sans handle (`OBJ_PERMANENT`).
    pub fn is_permanent(&self) -> bool {
        self.header.permanent.load(Ordering::Acquire)
    }

    /// Son nom dans son répertoire, s'il en a un.
    pub fn name(&self) -> Option<String> {
        self.header.name.lock().as_ref().map(|info| info.name.clone())
    }

    pub(crate) fn header(&self) -> &ObjectHeader {
        &self.header
    }
}

impl ObjectHeader {
    pub(crate) fn set_permanent(&self, permanent: bool) {
        self.permanent.store(permanent, Ordering::Release);
    }

    /// Compte un handle de plus.
    pub(crate) fn add_handle(&self) {
        self.handles.fetch_add(1, Ordering::AcqRel);
        self.ty.handles.fetch_add(1, Ordering::Relaxed);
    }
}

impl<T: ?Sized> Deref for Object<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.body
    }
}

impl<T: ?Sized> Drop for Object<T> {
    fn drop(&mut self) {
        self.header.ty.objects.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Après la fermeture d'un handle sur `object` : la procédure de fermeture
/// de son type, puis, au dernier handle d'un objet nommé temporaire, son nom
/// quitte l'espace de noms.
pub(crate) fn handle_closed(object: &ObjectRef) {
    let left = object.header.handles.fetch_sub(1, Ordering::AcqRel) - 1;
    object.header.ty.handles.fetch_sub(1, Ordering::Relaxed);
    if let Some(close) = object.header.ty.close {
        close(object, left);
    }
    if left == 0 && !object.is_permanent() {
        remove_name(object);
    }
}

/// Retire `object` de son répertoire (ObpDeleteNameCheck) : il n'a plus de
/// nom, et le répertoire ne le tient plus.
pub(crate) fn remove_name(object: &ObjectRef) {
    let info = object.header.name.lock().take();
    if let Some(directory) = info.as_ref().and_then(|info| info.directory.upgrade()) {
        // Dropped after the directory's lock: it may be the last reference.
        let removed = directory.remove(&info.as_ref().unwrap().name, object);
        drop(removed);
    }
}

/// NtMakeTemporaryObject : `object` perd son nom avec son dernier handle,
/// tout de suite s'il n'en a plus.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn make_temporary(object: &ObjectRef) {
    object.header.set_permanent(false);
    if object.handle_count() == 0 {
        remove_name(object);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPPING: GenericMapping = GenericMapping {
        read: AccessMask(0x0002_0001),
        write: AccessMask(0x0002_0002),
        execute: AccessMask(0x0002_0004),
        all: AccessMask(0x000F_000F),
    };

    static THING: ObjectType = ObjectType::new("Thing", AccessMask(0x000F_000F), MAPPING);
    static OTHER: ObjectType = ObjectType::new("Other", AccessMask(0x000F_000F), MAPPING);

    struct Thing(u32);

    #[test]
    fn an_object_gives_its_body_and_its_type() {
        let thing = create_object(&THING, Thing(7));
        assert_eq!(thing.0, 7);
        assert!(thing.is_type(&THING) && !thing.is_type(&OTHER));
        assert_eq!(thing.object_type().name, "Thing");
        assert_eq!((thing.handle_count(), thing.is_permanent(), thing.name()), (0, false, None));
    }

    #[test]
    fn downcast_finds_the_body_again() {
        let object: ObjectRef = create_object(&THING, Thing(42));
        let thing = downcast::<Thing>(&object).expect("a Thing");
        assert_eq!(thing.0, 42);
        assert_eq!(Arc::strong_count(&object), 2, "the downcast is a reference");
        assert!(downcast::<u32>(&object).is_none());
    }

    #[test]
    fn the_type_counts_its_objects() {
        static COUNTED: ObjectType = ObjectType::new("Counted", AccessMask(1), MAPPING);
        let objects: alloc::vec::Vec<_> = (0..3).map(|i| create_object(&COUNTED, i)).collect();
        assert_eq!(COUNTED.object_count(), 3);
        drop(objects);
        assert_eq!(COUNTED.object_count(), 0);
    }

    #[test]
    fn granted_access_maps_generic_rights_within_the_valid_ones() {
        static NARROW: ObjectType = ObjectType::new("Narrow", AccessMask(0x0002_0003), MAPPING);
        assert_eq!(NARROW.granted_access(AccessMask::GENERIC_READ), AccessMask(0x0002_0001));
        assert_eq!(NARROW.granted_access(AccessMask::GENERIC_ALL), AccessMask(0x0002_0003), "valid rights only");
        assert_eq!(NARROW.granted_access(AccessMask::MAXIMUM_ALLOWED), AccessMask(0x0002_0003));
        assert_eq!(NARROW.granted_access(AccessMask(0x4)), AccessMask::NONE);
    }
}
