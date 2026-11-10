//! Les SID : une autorité et jusqu'à 15 sous-autorités.
//!
//! Format binaire (`abi::security`) : révision (1), nombre de
//! sous-autorités, autorité sur 6 octets gros-boutistes, puis les
//! sous-autorités, 32 bits petits-boutistes chacune.

use alloc::vec::Vec;
use core::fmt;

use abi::ntstatus::{NtStatus, STATUS_INVALID_SID};
use abi::security::{
    DOMAIN_ALIAS_RID_ADMINS, SECURITY_AUTHENTICATED_USER_RID, SECURITY_BUILTIN_DOMAIN_RID, SECURITY_LOCAL_SYSTEM_RID,
    SECURITY_NT_AUTHORITY, SECURITY_WORLD_RID, SECURITY_WORLD_SID_AUTHORITY, SID_HEADER_SIZE, SID_MAX_SUB_AUTHORITIES,
    SID_REVISION,
};

const MAX: usize = SID_MAX_SUB_AUTHORITIES as usize;

/// Un SID. Les sous-autorités au-delà de `count` valent 0 : deux SID égaux
/// sont égaux champ par champ.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sid {
    authority: [u8; 6],
    count: u8,
    sub_authorities: [u32; MAX],
}

impl Sid {
    /// S-1-5-18 : LocalSystem.
    pub const LOCAL_SYSTEM: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[SECURITY_LOCAL_SYSTEM_RID]);
    /// S-1-5-32-544 : Administrators.
    pub const ADMINISTRATORS: Sid =
        Sid::new(SECURITY_NT_AUTHORITY, &[SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS]);
    /// S-1-1-0 : Everyone.
    pub const EVERYONE: Sid = Sid::new(SECURITY_WORLD_SID_AUTHORITY, &[SECURITY_WORLD_RID]);
    /// S-1-5-11 : Authenticated Users.
    pub const AUTHENTICATED_USERS: Sid = Sid::new(SECURITY_NT_AUTHORITY, &[SECURITY_AUTHENTICATED_USER_RID]);

    /// Le SID d'autorité `authority` et de sous-autorités `sub_authorities`.
    ///
    /// # Panics
    /// Au-delà de 15 sous-autorités.
    pub const fn new(authority: [u8; 6], sub_authorities: &[u32]) -> Self {
        assert!(sub_authorities.len() <= MAX, "a SID has at most 15 sub-authorities");
        let mut sid = Self { authority, count: sub_authorities.len() as u8, sub_authorities: [0; MAX] };
        let mut i = 0;
        while i < sub_authorities.len() {
            sid.sub_authorities[i] = sub_authorities[i];
            i += 1;
        }
        sid
    }

    /// RtlLengthRequiredSid : la taille d'un SID de `count` sous-autorités.
    pub const fn length_required(count: u8) -> usize {
        SID_HEADER_SIZE + 4 * count as usize
    }

    /// Le SID au début de `bytes` (RtlValidSid) ; `STATUS_INVALID_SID` pour
    /// une autre révision, plus de 15 sous-autorités, ou des octets qui
    /// manquent.
    pub fn parse(bytes: &[u8]) -> Result<Self, NtStatus> {
        let header = bytes.get(..SID_HEADER_SIZE).ok_or(STATUS_INVALID_SID)?;
        let count = Self::check_header(header)?;
        let body = bytes.get(SID_HEADER_SIZE..Self::length_required(count)).ok_or(STATUS_INVALID_SID)?;
        let mut sid = Self { authority: [0; 6], count, sub_authorities: [0; MAX] };
        sid.authority.copy_from_slice(&header[2..8]);
        for (sub, word) in sid.sub_authorities.iter_mut().zip(body.chunks_exact(4)) {
            *sub = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        Ok(sid)
    }

    /// Vérifie l'en-tête d'un SID (ses 8 premiers octets) et rend son nombre
    /// de sous-autorités : de quoi lire la suite.
    pub fn check_header(header: &[u8]) -> Result<u8, NtStatus> {
        match header {
            [SID_REVISION, count, ..] if header.len() >= SID_HEADER_SIZE && *count <= SID_MAX_SUB_AUTHORITIES => {
                Ok(*count)
            }
            _ => Err(STATUS_INVALID_SID),
        }
    }

    /// RtlLengthSid : sa taille en octets.
    pub const fn length(&self) -> usize {
        Self::length_required(self.count)
    }

    /// Ses sous-autorités.
    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authorities[..usize::from(self.count)]
    }

    /// Son autorité.
    pub const fn authority(&self) -> [u8; 6] {
        self.authority
    }

    /// Ajoute ses octets à `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[SID_REVISION, self.count]);
        out.extend_from_slice(&self.authority);
        for sub in self.sub_authorities() {
            out.extend_from_slice(&sub.to_le_bytes());
        }
    }

    /// Ses octets.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.length());
        self.write_to(&mut bytes);
        bytes
    }
}

/// `S-1-5-32-544` : l'autorité en décimal sous 2^32, en hexadécimal
/// au-delà, comme RtlConvertSidToUnicodeString.
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.authority;
        if a == 0 && b == 0 {
            write!(f, "S-1-{}", u32::from_be_bytes([c, d, e, g]))?;
        } else {
            write!(f, "S-1-0x{a:02X}{b:02X}{c:02X}{d:02X}{e:02X}{g:02X}")?;
        }
        for sub in self.sub_authorities() {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn well_known_sids_read_as_xp_writes_them() {
        assert_eq!(format!("{}", Sid::LOCAL_SYSTEM), "S-1-5-18");
        assert_eq!(format!("{}", Sid::ADMINISTRATORS), "S-1-5-32-544");
        assert_eq!(format!("{}", Sid::EVERYONE), "S-1-1-0");
        assert_eq!(format!("{}", Sid::AUTHENTICATED_USERS), "S-1-5-11");
        let odd = Sid::new([1, 2, 3, 4, 5, 6], &[7]);
        assert_eq!(format!("{odd}"), "S-1-0x010203040506-7");
    }

    #[test]
    fn a_sid_goes_to_bytes_and_back() {
        let bytes = Sid::ADMINISTRATORS.to_bytes();
        assert_eq!(bytes, [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]);
        assert_eq!(Sid::ADMINISTRATORS.length(), 16);
        let mut longer = bytes.clone();
        longer.extend_from_slice(&[0xAA; 4]);
        assert_eq!(Sid::parse(&longer), Ok(Sid::ADMINISTRATORS), "only its own bytes");
    }

    #[test]
    fn bad_sids_are_refused() {
        let bytes = Sid::LOCAL_SYSTEM.to_bytes();
        assert_eq!(Sid::parse(&bytes[..11]), Err(STATUS_INVALID_SID), "a missing sub-authority");
        let mut revision = bytes.clone();
        revision[0] = 2;
        assert_eq!(Sid::parse(&revision), Err(STATUS_INVALID_SID), "revision 2");
        let mut many = alloc::vec![1u8, 16, 0, 0, 0, 0, 0, 5];
        many.extend_from_slice(&[0; 64]);
        assert_eq!(Sid::parse(&many), Err(STATUS_INVALID_SID), "16 sub-authorities");
        assert_eq!(Sid::parse(&[1, 0, 0, 0, 0, 0, 0, 5]).map(|sid| sid.length()), Ok(8), "none is fine");
    }
}
