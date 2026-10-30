//! Objects (CLAUDE.md, rule 5): access masks, the generic mapping and the
//! object attributes, values of the XP SDK headers.

/// An access mask (`ACCESS_MASK`): specific rights in the low 16 bits, then
/// standard rights, then generic rights.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AccessMask(pub u32);

impl AccessMask {
    pub const NONE: Self = Self(0);
    pub const DELETE: Self = Self(0x0001_0000);
    pub const READ_CONTROL: Self = Self(0x0002_0000);
    pub const WRITE_DAC: Self = Self(0x0004_0000);
    pub const WRITE_OWNER: Self = Self(0x0008_0000);
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);
    /// DELETE, READ_CONTROL, WRITE_DAC and WRITE_OWNER.
    pub const STANDARD_RIGHTS_REQUIRED: Self = Self(0x000F_0000);
    pub const STANDARD_RIGHTS_READ: Self = Self::READ_CONTROL;
    pub const STANDARD_RIGHTS_WRITE: Self = Self::READ_CONTROL;
    pub const STANDARD_RIGHTS_EXECUTE: Self = Self::READ_CONTROL;
    pub const ACCESS_SYSTEM_SECURITY: Self = Self(0x0100_0000);
    pub const MAXIMUM_ALLOWED: Self = Self(0x0200_0000);
    pub const GENERIC_ALL: Self = Self(0x1000_0000);
    pub const GENERIC_EXECUTE: Self = Self(0x2000_0000);
    pub const GENERIC_WRITE: Self = Self(0x4000_0000);
    pub const GENERIC_READ: Self = Self(0x8000_0000);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Every right of `other` is in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Some right of `other` is in `self`.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// The rights of `self` without those of `other`.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl core::ops::BitOr for AccessMask {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl core::ops::BitAnd for AccessMask {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// `GENERIC_MAPPING`: the specific rights each generic right stands for, for
/// one object type.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericMapping {
    pub read: AccessMask,
    pub write: AccessMask,
    pub execute: AccessMask,
    pub all: AccessMask,
}

impl GenericMapping {
    /// `RtlMapGenericMask`: replaces the generic rights of `mask` with the
    /// specific rights they stand for.
    pub const fn map(&self, mask: AccessMask) -> AccessMask {
        let mut mapped = mask.0 & 0x0FFF_FFFF;
        if mask.0 & AccessMask::GENERIC_READ.0 != 0 {
            mapped |= self.read.0;
        }
        if mask.0 & AccessMask::GENERIC_WRITE.0 != 0 {
            mapped |= self.write.0;
        }
        if mask.0 & AccessMask::GENERIC_EXECUTE.0 != 0 {
            mapped |= self.execute.0;
        }
        if mask.0 & AccessMask::GENERIC_ALL.0 != 0 {
            mapped |= self.all.0;
        }
        AccessMask(mapped)
    }
}

const _: () = assert!(core::mem::size_of::<GenericMapping>() == 16);
const _: () = assert!(core::mem::offset_of!(GenericMapping, all) == 12);

// `OBJECT_ATTRIBUTES.Attributes`.
pub const OBJ_INHERIT: u32 = 0x0000_0002;
pub const OBJ_PERMANENT: u32 = 0x0000_0010;
pub const OBJ_EXCLUSIVE: u32 = 0x0000_0020;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
pub const OBJ_OPENIF: u32 = 0x0000_0080;
pub const OBJ_OPENLINK: u32 = 0x0000_0100;
pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

// `NtDuplicateObject` options.
pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;
pub const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
pub const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x0000_0004;

#[cfg(test)]
mod tests {
    use super::*;

    const MAPPING: GenericMapping = GenericMapping {
        read: AccessMask(0x0002_0001),
        write: AccessMask(0x0002_0002),
        execute: AccessMask(0x0002_0004),
        all: AccessMask(0x000F_000F),
    };

    #[test]
    fn generic_rights_map_to_specific_ones() {
        assert_eq!(MAPPING.map(AccessMask::GENERIC_READ), AccessMask(0x0002_0001));
        assert_eq!(MAPPING.map(AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE), AccessMask(0x0002_0003));
        assert_eq!(MAPPING.map(AccessMask::GENERIC_EXECUTE | AccessMask(0x10)), AccessMask(0x0002_0014));
        assert_eq!(MAPPING.map(AccessMask::GENERIC_ALL), AccessMask(0x000F_000F));
        assert_eq!(MAPPING.map(AccessMask::MAXIMUM_ALLOWED), AccessMask::MAXIMUM_ALLOWED, "not a generic right");
    }

    #[test]
    fn set_operations() {
        let rw = AccessMask(3);
        assert!(rw.contains(AccessMask(1)) && !rw.contains(AccessMask(5)));
        assert!(rw.intersects(AccessMask(5)) && !rw.intersects(AccessMask(4)));
        assert_eq!(rw.without(AccessMask(1)), AccessMask(2));
    }
}
