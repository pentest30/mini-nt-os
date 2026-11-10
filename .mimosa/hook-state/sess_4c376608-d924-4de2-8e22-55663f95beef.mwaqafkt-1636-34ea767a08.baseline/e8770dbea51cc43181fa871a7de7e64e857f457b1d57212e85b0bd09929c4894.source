//! Liens symboliques (`SymbolicLink`) : un nom qui en remplace un autre.
//!
//! La procédure *parse* du type remplace la partie du nom déjà lue par la
//! cible du lien, et la recherche reprend depuis la racine
//! (`Namespace::lookup`).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use abi::ntstatus::{NtStatus, STATUS_OBJECT_TYPE_MISMATCH};
use abi::object::{AccessMask, GenericMapping};

use crate::object::{create_object, downcast, Object, ObjectRef, ObjectType, Parsed};

pub const SYMBOLIC_LINK_QUERY: AccessMask = AccessMask(0x0001);
pub const SYMBOLIC_LINK_ALL_ACCESS: AccessMask = AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | 0x1);

/// Le type `SymbolicLink`.
pub static SYMBOLIC_LINK_TYPE: ObjectType = ObjectType::new(
    "SymbolicLink",
    SYMBOLIC_LINK_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | SYMBOLIC_LINK_QUERY.0),
        write: AccessMask::STANDARD_RIGHTS_WRITE,
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | SYMBOLIC_LINK_QUERY.0),
        all: SYMBOLIC_LINK_ALL_ACCESS,
    },
)
.with_parse(parse);

/// Un lien symbolique : le nom complet qu'il désigne.
pub struct SymbolicLink {
    target: String,
}

impl SymbolicLink {
    /// Un lien vers `target`, objet sans nom.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create(target: &str) -> Arc<Object<SymbolicLink>> {
        create_object(&SYMBOLIC_LINK_TYPE, SymbolicLink { target: String::from(target) })
    }

    /// NtQuerySymbolicLinkObject : la cible.
    pub fn target(&self) -> &str {
        &self.target
    }
}

/// La cible, suivie de la suite du nom.
fn parse(object: &ObjectRef, remaining: &str) -> Result<Parsed, NtStatus> {
    let link = downcast::<SymbolicLink>(object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?;
    Ok(Parsed::Reparse(format!("{}{remaining}", link.target)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_reparses_to_its_target_and_the_rest() {
        let link: ObjectRef = SymbolicLink::create("\\Device\\Harddisk0\\Partition1");
        let Ok(Parsed::Reparse(name)) = parse(&link, "\\Windows") else { panic!("no reparse") };
        assert_eq!(name, "\\Device\\Harddisk0\\Partition1\\Windows");
        let Ok(Parsed::Reparse(name)) = parse(&link, "") else { panic!("no reparse") };
        assert_eq!(name, "\\Device\\Harddisk0\\Partition1");
    }

    #[test]
    fn parse_only_takes_links() {
        let directory: ObjectRef = crate::directory::Directory::create();
        assert!(matches!(parse(&directory, ""), Err(STATUS_OBJECT_TYPE_MISMATCH)));
    }
}
