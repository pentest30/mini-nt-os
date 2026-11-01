//! Les ACL : un en-tête (`abi::security::Acl`), puis les ACE.
//!
//! Une [`Acl`] tient les octets d'une liste vérifiée comme le fait
//! RtlValidAcl : révision 2 à 4, taille paire d'au moins 8 octets, chaque
//! ACE dans la liste, de taille paire et d'au moins un en-tête ; une ACE des
//! quatre premiers types (autorisé, refusé, audit, alarme) a une taille
//! multiple de 4 et tient son SID. Les autres types (ACE d'objet, de rappel)
//! ne sont vérifiés que par leur taille ; `SeAccessCheck` les lira.

use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_INVALID_ACL};
use abi::security::{
    AceHeader, Acl as AclHeader, ACCESS_ALLOWED_ACE_TYPE, ACCESS_MAX_MS_V2_ACE_TYPE, KNOWN_ACE_SID_START,
    MAX_ACL_REVISION, MIN_ACL_REVISION,
};

use crate::sid::Sid;

const HEADER: usize = core::mem::size_of::<AclHeader>();
const ACE_HEADER: usize = core::mem::size_of::<AceHeader>();

/// Une ACL vérifiée : ses `AclSize` octets.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Acl(Vec<u8>);

/// Une ACE d'une ACL.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    /// Le masque d'accès ; 0 pour un type au-delà des quatre premiers.
    pub mask: u32,
    /// Le SID d'une ACE des quatre premiers types.
    pub sid: Option<Sid>,
}

impl Acl {
    /// Lit l'en-tête d'une ACL (ses 8 premiers octets) et rend sa taille
    /// (`AclSize`) : de quoi lire la suite. `STATUS_INVALID_ACL` pour un
    /// en-tête trop court.
    pub fn size_from_header(header: &[u8]) -> Result<usize, NtStatus> {
        match header {
            [_, _, low, high, ..] => Ok(usize::from(u16::from_le_bytes([*low, *high]))),
            _ => Err(STATUS_INVALID_ACL),
        }
    }

    /// L'ACL au début de `bytes`, vérifiée (RtlValidAcl) ;
    /// `STATUS_INVALID_ACL` sinon.
    pub fn parse(bytes: &[u8]) -> Result<Self, NtStatus> {
        let size = Self::size_from_header(bytes)?;
        if size < HEADER || size % 2 != 0 {
            return Err(STATUS_INVALID_ACL);
        }
        let bytes = bytes.get(..size).ok_or(STATUS_INVALID_ACL)?;
        if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&bytes[0]) {
            return Err(STATUS_INVALID_ACL);
        }
        let count = u16::from_le_bytes([bytes[4], bytes[5]]);
        let mut at = HEADER;
        for _ in 0..count {
            // The header of an ACE ends before the end of the list.
            if at + ACE_HEADER >= size {
                return Err(STATUS_INVALID_ACL);
            }
            let (ace_type, ace_size) = (bytes[at], usize::from(u16::from_le_bytes([bytes[at + 2], bytes[at + 3]])));
            if ace_size < ACE_HEADER || ace_size % 2 != 0 || at + ace_size > size {
                return Err(STATUS_INVALID_ACL);
            }
            if ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE {
                let ace = &bytes[at..at + ace_size];
                if ace_size % 4 != 0 || ace_size < KNOWN_ACE_SID_START {
                    return Err(STATUS_INVALID_ACL);
                }
                // The SID within the ACE: its slice ends with it.
                Sid::parse(&ace[KNOWN_ACE_SID_START..]).map_err(|_| STATUS_INVALID_ACL)?;
            }
            at += ace_size;
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Une ACL de révision `revision` faite des ACE `(type, drapeaux, masque,
    /// SID)` des quatre premiers types, dans cet ordre, sans place libre.
    ///
    /// # Panics
    /// Pour un autre type d'ACE, ou au-delà de 64 Kio.
    pub fn build(revision: u8, aces: &[(u8, u8, u32, Sid)]) -> Self {
        let size = HEADER + aces.iter().map(|(_, _, _, sid)| KNOWN_ACE_SID_START + sid.length()).sum::<usize>();
        let size = u16::try_from(size).expect("an ACL of at most 64 KiB");
        let header =
            AclHeader { acl_revision: revision, sbz1: 0, acl_size: size, ace_count: aces.len() as u16, sbz2: 0 };
        let mut bytes = Vec::with_capacity(usize::from(size));
        bytes.extend_from_slice(header.as_bytes());
        for (ace_type, flags, mask, sid) in aces {
            assert!(*ace_type <= ACCESS_MAX_MS_V2_ACE_TYPE, "only ACEs of the first four types");
            let ace_size = (KNOWN_ACE_SID_START + sid.length()) as u16;
            bytes.extend_from_slice(AceHeader { ace_type: *ace_type, ace_flags: *flags, ace_size }.as_bytes());
            bytes.extend_from_slice(&mask.to_le_bytes());
            sid.write_to(&mut bytes);
        }
        Self(bytes)
    }

    /// Une ACL qui autorise `(masque, SID)`, dans cet ordre
    /// (`ACL_REVISION`).
    pub fn allowing(aces: &[(u32, Sid)]) -> Self {
        let aces: Vec<(u8, u8, u32, Sid)> =
            aces.iter().map(|&(mask, sid)| (ACCESS_ALLOWED_ACE_TYPE, 0, mask, sid)).collect();
        Self::build(abi::security::ACL_REVISION, &aces)
    }

    /// Ses octets.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// Sa taille (`AclSize`).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Une ACL a toujours son en-tête.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Sa révision.
    pub fn revision(&self) -> u8 {
        self.0[0]
    }

    /// Ses ACE, dans l'ordre.
    pub fn aces(&self) -> impl Iterator<Item = Ace> + '_ {
        let count = u16::from_le_bytes([self.0[4], self.0[5]]);
        let mut at = HEADER;
        (0..count).map(move |_| {
            let ace = &self.0[at..];
            let size = usize::from(u16::from_le_bytes([ace[2], ace[3]]));
            at += size;
            let known = ace[0] <= ACCESS_MAX_MS_V2_ACE_TYPE;
            Ace {
                ace_type: ace[0],
                flags: ace[1],
                mask: if known { u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]) } else { 0 },
                // Checked by `parse` and made by `build`.
                sid: known.then(|| Sid::parse(&ace[KNOWN_ACE_SID_START..size]).expect("a checked ACE")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::security::{ACCESS_DENIED_ACE_TYPE, ACL_REVISION};

    #[test]
    fn an_acl_built_reads_back() {
        let acl = Acl::build(
            ACL_REVISION,
            &[
                (ACCESS_DENIED_ACE_TYPE, 2, 0x10, Sid::EVERYONE),
                (ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F_0FFF, Sid::LOCAL_SYSTEM),
            ],
        );
        assert_eq!(acl.len(), 8 + 20 + 20);
        assert_eq!(Acl::parse(acl.bytes()), Ok(acl.clone()));
        let aces: Vec<Ace> = acl.aces().collect();
        assert_eq!(
            aces,
            [
                Ace { ace_type: ACCESS_DENIED_ACE_TYPE, flags: 2, mask: 0x10, sid: Some(Sid::EVERYONE) },
                Ace { ace_type: ACCESS_ALLOWED_ACE_TYPE, flags: 0, mask: 0x1F_0FFF, sid: Some(Sid::LOCAL_SYSTEM) },
            ]
        );
    }

    #[test]
    fn free_space_after_the_aces_is_kept() {
        // As RtlCreateAcl and RtlAddAccessAllowedAce leave it: room for more.
        let mut bytes = Acl::allowing(&[(1, Sid::LOCAL_SYSTEM)]).bytes().to_vec();
        bytes.extend_from_slice(&[0; 12]);
        let size = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&size.to_le_bytes());
        let acl = Acl::parse(&bytes).expect("a valid ACL with free space");
        assert_eq!((acl.len(), acl.aces().count()), (40, 1));
        let empty = [ACL_REVISION, 0, 8, 0, 0, 0, 0, 0];
        assert_eq!(Acl::parse(&empty).map(|acl| acl.aces().count()), Ok(0), "no ACE");
    }

    #[test]
    fn bad_acls_are_refused() {
        let good = Acl::allowing(&[(1, Sid::ADMINISTRATORS)]).bytes().to_vec();
        // The same, with 8 free bytes at the end.
        let mut roomy = good.clone();
        roomy.extend_from_slice(&[0; 8]);
        roomy[2] = 40;
        assert!(Acl::parse(&roomy).is_ok());
        let broken = |acl: &[u8], offset: usize, value: u8| {
            let mut bytes = acl.to_vec();
            bytes[offset] = value;
            Acl::parse(&bytes)
        };
        assert_eq!(broken(&good, 0, 1), Err(STATUS_INVALID_ACL), "revision 1");
        assert_eq!(broken(&good, 0, 5), Err(STATUS_INVALID_ACL), "revision 5");
        assert_eq!(broken(&roomy, 2, 39), Err(STATUS_INVALID_ACL), "an odd size");
        assert_eq!(broken(&good, 2, 6), Err(STATUS_INVALID_ACL), "smaller than its header");
        assert_eq!(broken(&good, 4, 2), Err(STATUS_INVALID_ACL), "a second ACE past the end");
        assert_eq!(broken(&good, 10, 26), Err(STATUS_INVALID_ACL), "an ACE past the end");
        assert_eq!(broken(&good, 10, 0), Err(STATUS_INVALID_ACL), "an ACE without a header");
        assert_eq!(broken(&roomy, 10, 26), Err(STATUS_INVALID_ACL), "an allowed ACE whose size is not a multiple of 4");
        assert_eq!(broken(&good, 10, 20), Err(STATUS_INVALID_ACL), "a SID that does not fit its ACE");
        assert_eq!(broken(&good, 16, 9), Err(STATUS_INVALID_ACL), "a bad SID");
        assert_eq!(Acl::parse(&good[..20]), Err(STATUS_INVALID_ACL), "fewer bytes than its size");
        let unknown = broken(&good, 8, 0x11);
        assert!(unknown.is_ok(), "another type of ACE: only its size is checked");
        // A second ACE, of another type, reduced to its header: it may not
        // end the list.
        let mut header_only = roomy.clone();
        header_only[4] = 2;
        header_only[32..36].copy_from_slice(&[0x11, 0, 4, 0]);
        assert!(Acl::parse(&header_only).is_ok(), "four bytes after it");
        assert_eq!(broken(&header_only, 2, 36), Err(STATUS_INVALID_ACL), "the header ends the list");
    }
}
