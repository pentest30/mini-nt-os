//! Les descripteurs de sécurité : propriétaire, groupe principal, SACL et
//! DACL, et leurs drapeaux.
//!
//! Un [`SecurityDescriptor`] se capture du mode utilisateur, sous sa forme
//! absolue (des pointeurs) ou relative (des décalages) :
//! [`capture`](SecurityDescriptor::capture), sur une fonction qui lit la
//! mémoire de l'appelant (`ke::usermem` dans le noyau, un tableau dans les
//! tests). Un objet garde le sien sous la forme relative
//! ([`to_self_relative`](SecurityDescriptor::to_self_relative)) : SACL, DACL,
//! propriétaire puis groupe après l'en-tête, comme RtlMakeSelfRelativeSD.
//!
//! [`select`](SecurityDescriptor::select) rend les parties qu'une requête
//! demande (SeQuerySecurityDescriptorInfo), [`merge`](SecurityDescriptor::merge)
//! remplace celles qu'un appelant donne (SeSetSecurityDescriptorInfo).

use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_INVALID_ACL, STATUS_INVALID_OWNER, STATUS_INVALID_PRIMARY_GROUP, STATUS_INVALID_SECURITY_DESCR,
    STATUS_UNKNOWN_REVISION,
};
use abi::security::{
    SecurityDescriptor32, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION,
    SECURITY_DESCRIPTOR_MIN_LENGTH, SECURITY_DESCRIPTOR_REVISION, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED,
    SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_DEFAULTED, SE_SACL_PRESENT, SE_SACL_PROTECTED,
    SE_SELF_RELATIVE, SID_HEADER_SIZE, UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
};

use crate::acl::Acl;
use crate::sid::Sid;

/// Les drapeaux qui suivent la DACL, hors `SE_DACL_PRESENT`.
const DACL_FLAGS: u16 = SE_DACL_DEFAULTED | SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED;
/// Les drapeaux qui suivent la SACL, hors `SE_SACL_PRESENT`.
const SACL_FLAGS: u16 = SE_SACL_DEFAULTED | SE_SACL_AUTO_INHERIT_REQ | SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED;

/// Un descripteur de sécurité.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct SecurityDescriptor {
    /// Ses drapeaux, sans `SE_SELF_RELATIVE` ni ceux de présence, que
    /// donnent `dacl` et `sacl`.
    pub flags: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    /// `None` : pas de SACL ; `Some(None)` : une SACL nulle.
    pub sacl: Option<Option<Acl>>,
    /// `None` : pas de DACL ; `Some(None)` : une DACL nulle, qui accorde
    /// tout.
    pub dacl: Option<Option<Acl>>,
}

impl SecurityDescriptor {
    /// SECURITY_DESCRIPTOR_CONTROL, sans `SE_SELF_RELATIVE`.
    pub fn control(&self) -> u16 {
        let mut control = self.flags & !(SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT);
        if self.dacl.is_some() {
            control |= SE_DACL_PRESENT;
        }
        if self.sacl.is_some() {
            control |= SE_SACL_PRESENT;
        }
        control
    }

    /// SeCaptureSecurityDescriptor : le descripteur en `address`, sous sa
    /// forme absolue ou relative, lu par `read(adresse, tampon)`.
    ///
    /// # Errors
    /// `STATUS_UNKNOWN_REVISION` pour une autre révision que 1 ;
    /// `STATUS_INVALID_SID`, `STATUS_INVALID_ACL` pour une partie qui n'est
    /// pas valide ; `STATUS_INVALID_SECURITY_DESCR` pour un décalage qui
    /// déborde ; celles de `read`.
    pub fn capture(
        address: u32,
        read: &mut impl FnMut(u32, &mut [u8]) -> Result<(), NtStatus>,
    ) -> Result<Self, NtStatus> {
        let mut bytes = [0u8; SECURITY_DESCRIPTOR_MIN_LENGTH];
        read(address, &mut bytes)?;
        if bytes[0] != SECURITY_DESCRIPTOR_REVISION {
            return Err(STATUS_UNKNOWN_REVISION);
        }
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        let field = |index: usize| {
            let at = 4 + 4 * index;
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let header = SecurityDescriptor32 {
            revision: bytes[0],
            sbz1: bytes[1],
            control,
            owner: field(0),
            group: field(1),
            sacl: field(2),
            dacl: field(3),
        };
        // A part is a pointer, or an offset from the header; 0 for none.
        let locate = |value: u32| -> Result<Option<u32>, NtStatus> {
            match value {
                0 => Ok(None),
                _ if control & SE_SELF_RELATIVE != 0 => {
                    address.checked_add(value).map(Some).ok_or(STATUS_INVALID_SECURITY_DESCR)
                }
                _ => Ok(Some(value)),
            }
        };
        let owner = locate(header.owner)?.map(|at| capture_sid(at, read)).transpose()?;
        let group = locate(header.group)?.map(|at| capture_sid(at, read)).transpose()?;
        let sacl = match control & SE_SACL_PRESENT {
            0 => None,
            _ => Some(locate(header.sacl)?.map(|at| capture_acl(at, read)).transpose()?),
        };
        let dacl = match control & SE_DACL_PRESENT {
            0 => None,
            _ => Some(locate(header.dacl)?.map(|at| capture_acl(at, read)).transpose()?),
        };
        Ok(Self { flags: control & !(SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT), owner, group, sacl, dacl })
    }

    /// Le descripteur relatif `bytes` ; `STATUS_INVALID_SECURITY_DESCR` s'il
    /// n'est pas relatif ou qu'une partie déborde.
    pub fn from_self_relative(bytes: &[u8]) -> Result<Self, NtStatus> {
        let control = bytes.get(2..4).map(|control| u16::from_le_bytes([control[0], control[1]]));
        if control.is_none_or(|control| control & SE_SELF_RELATIVE == 0) {
            return Err(STATUS_INVALID_SECURITY_DESCR);
        }
        Self::capture(0, &mut |at, buffer| {
            let at = at as usize;
            let part = bytes.get(at..at + buffer.len()).ok_or(STATUS_INVALID_SECURITY_DESCR)?;
            buffer.copy_from_slice(part);
            Ok(())
        })
    }

    /// RtlLengthSecurityDescriptor : la taille de sa forme relative.
    pub fn length(&self) -> usize {
        let acl = |part: &Option<Option<Acl>>| part.as_ref().and_then(Option::as_ref).map_or(0, Acl::len);
        SECURITY_DESCRIPTOR_MIN_LENGTH
            + acl(&self.sacl)
            + acl(&self.dacl)
            + self.owner.as_ref().map_or(0, Sid::length)
            + self.group.as_ref().map_or(0, Sid::length)
    }

    /// Sa forme relative : l'en-tête, puis SACL, DACL, propriétaire et
    /// groupe.
    pub fn to_self_relative(&self) -> Vec<u8> {
        let mut header = SecurityDescriptor32 {
            revision: SECURITY_DESCRIPTOR_REVISION,
            control: self.control() | SE_SELF_RELATIVE,
            ..Default::default()
        };
        let mut parts = Vec::with_capacity(self.length() - SECURITY_DESCRIPTOR_MIN_LENGTH);
        let offset = |parts: &Vec<u8>| (SECURITY_DESCRIPTOR_MIN_LENGTH + parts.len()) as u32;
        if let Some(Some(sacl)) = &self.sacl {
            header.sacl = offset(&parts);
            parts.extend_from_slice(sacl.bytes());
        }
        if let Some(Some(dacl)) = &self.dacl {
            header.dacl = offset(&parts);
            parts.extend_from_slice(dacl.bytes());
        }
        if let Some(owner) = &self.owner {
            header.owner = offset(&parts);
            owner.write_to(&mut parts);
        }
        if let Some(group) = &self.group {
            header.group = offset(&parts);
            group.write_to(&mut parts);
        }
        let mut bytes = Vec::with_capacity(self.length());
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(&parts);
        bytes
    }

    /// SeQuerySecurityDescriptorInfo : les parties que demande
    /// `information` (`*_SECURITY_INFORMATION`), avec leurs drapeaux.
    pub fn select(&self, information: u32) -> Self {
        let mut selected = Self::default();
        if information & OWNER_SECURITY_INFORMATION != 0 {
            selected.owner = self.owner;
            selected.flags |= self.flags & SE_OWNER_DEFAULTED;
        }
        if information & GROUP_SECURITY_INFORMATION != 0 {
            selected.group = self.group;
            selected.flags |= self.flags & SE_GROUP_DEFAULTED;
        }
        if information & DACL_SECURITY_INFORMATION != 0 {
            selected.dacl = self.dacl.clone();
            selected.flags |= self.flags & DACL_FLAGS;
        }
        if information & SACL_SECURITY_INFORMATION != 0 {
            selected.sacl = self.sacl.clone();
            selected.flags |= self.flags & SACL_FLAGS;
        }
        selected
    }

    /// SeSetSecurityDescriptorInfo : ce descripteur, dont les parties que
    /// désigne `information` viennent de `new`, avec leurs drapeaux ;
    /// `PROTECTED_*` et `UNPROTECTED_*` posent et ôtent la protection de la
    /// DACL et de la SACL contre l'héritage.
    ///
    /// # Errors
    /// `STATUS_INVALID_OWNER` ou `STATUS_INVALID_PRIMARY_GROUP` quand `new`
    /// n'a pas le propriétaire ou le groupe demandé.
    pub fn merge(&self, information: u32, new: &Self) -> Result<Self, NtStatus> {
        let mut merged = self.clone();
        if information & OWNER_SECURITY_INFORMATION != 0 {
            merged.owner = Some(new.owner.ok_or(STATUS_INVALID_OWNER)?);
            merged.flags = (merged.flags & !SE_OWNER_DEFAULTED) | (new.flags & SE_OWNER_DEFAULTED);
        }
        if information & GROUP_SECURITY_INFORMATION != 0 {
            merged.group = Some(new.group.ok_or(STATUS_INVALID_PRIMARY_GROUP)?);
            merged.flags = (merged.flags & !SE_GROUP_DEFAULTED) | (new.flags & SE_GROUP_DEFAULTED);
        }
        if information & DACL_SECURITY_INFORMATION != 0 {
            merged.dacl = new.dacl.clone();
            merged.flags = (merged.flags & !DACL_FLAGS) | (new.flags & DACL_FLAGS);
        }
        if information & SACL_SECURITY_INFORMATION != 0 {
            merged.sacl = new.sacl.clone();
            merged.flags = (merged.flags & !SACL_FLAGS) | (new.flags & SACL_FLAGS);
        }
        if information & PROTECTED_DACL_SECURITY_INFORMATION != 0 {
            merged.flags |= SE_DACL_PROTECTED;
        } else if information & UNPROTECTED_DACL_SECURITY_INFORMATION != 0 {
            merged.flags &= !SE_DACL_PROTECTED;
        }
        if information & PROTECTED_SACL_SECURITY_INFORMATION != 0 {
            merged.flags |= SE_SACL_PROTECTED;
        } else if information & UNPROTECTED_SACL_SECURITY_INFORMATION != 0 {
            merged.flags &= !SE_SACL_PROTECTED;
        }
        Ok(merged)
    }
}

/// Le SID en `at`, lu par `read` : son en-tête, puis le reste.
fn capture_sid(at: u32, read: &mut impl FnMut(u32, &mut [u8]) -> Result<(), NtStatus>) -> Result<Sid, NtStatus> {
    let mut header = [0u8; SID_HEADER_SIZE];
    read(at, &mut header)?;
    let count = Sid::check_header(&header)?;
    let mut bytes = [0u8; Sid::length_required(abi::security::SID_MAX_SUB_AUTHORITIES)];
    let bytes = &mut bytes[..Sid::length_required(count)];
    read(at, bytes)?;
    Sid::parse(bytes)
}

/// L'ACL en `at`, lue par `read` : son en-tête, puis le reste.
fn capture_acl(at: u32, read: &mut impl FnMut(u32, &mut [u8]) -> Result<(), NtStatus>) -> Result<Acl, NtStatus> {
    let mut header = [0u8; 8];
    read(at, &mut header)?;
    let size = Acl::size_from_header(&header)?;
    if size < header.len() {
        return Err(STATUS_INVALID_ACL);
    }
    let mut bytes = alloc::vec![0u8; size];
    read(at, &mut bytes)?;
    Acl::parse(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::ntstatus::{STATUS_ACCESS_VIOLATION, STATUS_INVALID_SID};
    use alloc::collections::BTreeMap;

    /// Une mémoire de l'appelant : des octets à des adresses.
    struct Memory(BTreeMap<u32, Vec<u8>>);

    impl Memory {
        fn read(&self, at: u32, buffer: &mut [u8]) -> Result<(), NtStatus> {
            let (base, bytes) = self.0.range(..=at).next_back().ok_or(STATUS_ACCESS_VIOLATION)?;
            let start = (at - base) as usize;
            let part = bytes.get(start..start + buffer.len()).ok_or(STATUS_ACCESS_VIOLATION)?;
            buffer.copy_from_slice(part);
            Ok(())
        }
    }

    fn header(control: u16, owner: u32, group: u32, sacl: u32, dacl: u32) -> Vec<u8> {
        SecurityDescriptor32 { revision: 1, sbz1: 0, control, owner, group, sacl, dacl }.as_bytes().to_vec()
    }

    #[test]
    fn an_absolute_descriptor_is_captured_from_its_pointers() {
        // As csrss builds it (CsrSetProcessSecurity): a DACL with one ACE for
        // its user, with room left, in an absolute descriptor.
        let dacl = Acl::allowing(&[(0x0002_0F3B, Sid::LOCAL_SYSTEM)]);
        let mut memory = Memory(BTreeMap::new());
        memory.0.insert(0x1000, header(SE_DACL_PRESENT, 0, 0, 0, 0x2000));
        memory.0.insert(0x2000, dacl.bytes().to_vec());
        memory.0.insert(0x3000, Sid::ADMINISTRATORS.to_bytes());
        let captured = SecurityDescriptor::capture(0x1000, &mut |at, buffer| memory.read(at, buffer));
        let expected = SecurityDescriptor { dacl: Some(Some(dacl.clone())), ..Default::default() };
        assert_eq!(captured, Ok(expected));
        memory.0.insert(0x1000, header(SE_DACL_PRESENT | SE_OWNER_DEFAULTED, 0x3000, 0, 0x2000, 0));
        let captured = SecurityDescriptor::capture(0x1000, &mut |at, buffer| memory.read(at, buffer)).unwrap();
        assert_eq!(captured.owner, Some(Sid::ADMINISTRATORS));
        assert_eq!(captured.dacl, Some(None), "a null DACL");
        assert_eq!(captured.sacl, None, "a SACL pointer without SE_SACL_PRESENT is ignored");
        assert_eq!(captured.control(), SE_DACL_PRESENT | SE_OWNER_DEFAULTED);
    }

    #[test]
    fn a_relative_descriptor_goes_to_bytes_and_back() {
        let audit =
            Acl::build(abi::security::ACL_REVISION, &[(abi::security::SYSTEM_AUDIT_ACE_TYPE, 0x40, 1, Sid::EVERYONE)]);
        let mut descriptor = SecurityDescriptor {
            flags: SE_DACL_PROTECTED | SE_GROUP_DEFAULTED,
            owner: Some(Sid::ADMINISTRATORS),
            group: Some(Sid::LOCAL_SYSTEM),
            sacl: Some(Some(audit)),
            dacl: Some(Some(Acl::allowing(&[(0x1000_0000, Sid::LOCAL_SYSTEM), (0xA002_0000, Sid::ADMINISTRATORS)]))),
        };
        let bytes = descriptor.to_self_relative();
        assert_eq!(bytes.len(), descriptor.length());
        assert_eq!(bytes.len(), 20 + 28 + 52 + 16 + 12);
        let control = SE_SELF_RELATIVE | SE_DACL_PROTECTED | SE_GROUP_DEFAULTED | SE_DACL_PRESENT | SE_SACL_PRESENT;
        assert_eq!(bytes[..20], header(control, 100, 116, 20, 48)[..], "SACL, DACL, owner, then group");
        assert_eq!(SecurityDescriptor::from_self_relative(&bytes), Ok(descriptor.clone()));
        descriptor.sacl = Some(None);
        let bytes = descriptor.to_self_relative();
        assert_eq!(bytes[..20], header(control, 72, 88, 0, 20)[..], "a null SACL takes no room");
        assert_eq!(SecurityDescriptor::from_self_relative(&bytes), Ok(descriptor));
        let empty = SecurityDescriptor::default().to_self_relative();
        assert_eq!(empty, header(SE_SELF_RELATIVE, 0, 0, 0, 0));
    }

    #[test]
    fn bad_descriptors_are_refused() {
        let good = SecurityDescriptor { owner: Some(Sid::EVERYONE), ..Default::default() }.to_self_relative();
        let mut revision = good.clone();
        revision[0] = 2;
        assert_eq!(SecurityDescriptor::from_self_relative(&revision), Err(STATUS_UNKNOWN_REVISION));
        let mut sid = good.clone();
        sid[20] = 3;
        assert_eq!(SecurityDescriptor::from_self_relative(&sid), Err(STATUS_INVALID_SID));
        assert_eq!(SecurityDescriptor::from_self_relative(&good[..24]), Err(STATUS_INVALID_SECURITY_DESCR));
        let mut absolute = good.clone();
        absolute[3] = 0;
        assert_eq!(SecurityDescriptor::from_self_relative(&absolute), Err(STATUS_INVALID_SECURITY_DESCR));
        let mut acl = header(SE_SELF_RELATIVE | SE_DACL_PRESENT, 0, 0, 0, 20);
        acl.extend_from_slice(&[2, 0, 4, 0, 0, 0, 0, 0]);
        assert_eq!(SecurityDescriptor::from_self_relative(&acl), Err(STATUS_INVALID_ACL), "a DACL of 4 bytes");
    }

    #[test]
    fn a_query_selects_its_parts() {
        let dacl = Some(Some(Acl::allowing(&[(1, Sid::EVERYONE)])));
        let descriptor = SecurityDescriptor {
            flags: SE_OWNER_DEFAULTED | SE_DACL_DEFAULTED | SE_SACL_PROTECTED,
            owner: Some(Sid::ADMINISTRATORS),
            group: Some(Sid::LOCAL_SYSTEM),
            sacl: Some(None),
            dacl: dacl.clone(),
        };
        let selected = descriptor.select(DACL_SECURITY_INFORMATION);
        assert_eq!(selected, SecurityDescriptor { flags: SE_DACL_DEFAULTED, dacl, ..Default::default() });
        let selected = descriptor.select(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION);
        assert_eq!((selected.owner, selected.group, selected.control()), (descriptor.owner, descriptor.group, 1));
        assert_eq!(descriptor.select(0), SecurityDescriptor::default());
    }

    #[test]
    fn a_change_replaces_only_its_parts() {
        let old = SecurityDescriptor {
            flags: SE_DACL_PROTECTED,
            owner: Some(Sid::ADMINISTRATORS),
            group: Some(Sid::LOCAL_SYSTEM),
            sacl: None,
            dacl: Some(None),
        };
        let dacl = Some(Some(Acl::allowing(&[(0x0002_0F3B, Sid::LOCAL_SYSTEM)])));
        let new = SecurityDescriptor { flags: SE_DACL_DEFAULTED, dacl: dacl.clone(), ..Default::default() };
        let merged = old.merge(DACL_SECURITY_INFORMATION, &new).unwrap();
        assert_eq!(merged, SecurityDescriptor { flags: SE_DACL_DEFAULTED, dacl: dacl.clone(), ..old.clone() });
        assert_eq!(old.merge(OWNER_SECURITY_INFORMATION, &new), Err(STATUS_INVALID_OWNER));
        assert_eq!(old.merge(GROUP_SECURITY_INFORMATION, &new), Err(STATUS_INVALID_PRIMARY_GROUP));
        let protected = old.merge(DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, &new).unwrap();
        assert_eq!(protected.flags, SE_DACL_DEFAULTED | SE_DACL_PROTECTED);
        let unprotected = old.merge(UNPROTECTED_DACL_SECURITY_INFORMATION, &new).unwrap();
        assert_eq!((unprotected.flags, unprotected.dacl), (0, Some(None)), "the DACL stays");
        let owner = SecurityDescriptor { owner: Some(Sid::EVERYONE), ..Default::default() };
        let merged = SecurityDescriptor::default().merge(OWNER_SECURITY_INFORMATION, &owner).unwrap();
        assert_eq!(merged, owner, "an object without a descriptor gets the parts given");
    }
}
