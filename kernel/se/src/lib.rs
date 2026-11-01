//! Se — la sécurité (02 §5.8, ADR-011).
//!
//! - [`sid`] : les SID et les SID connus (LocalSystem, Administrators…).
//! - [`acl`] : les ACL, vérifiées comme le fait RtlValidAcl.
//! - [`descriptor`] : les descripteurs de sécurité ; capture du mode
//!   utilisateur, forme relative, requête et changement de leurs parties.
//! - [`token`] : les jetons (type `Token`), le jeton de System, sa copie pour
//!   un processus créé, leurs privilèges et leurs classes d'information.
//!
//! Les LUID viennent de [`allocate_luid`] (ExAllocateLocallyUniqueId).
//!
//! Pas encore : SeAccessCheck et le mode permissif qui journalise les refus
//! (ADR-011) ; jusque-là, Ob accorde tout ce qui est demandé.
//!
//! WI7e Ch.6 §Security

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
extern crate alloc;

pub mod acl;
pub mod descriptor;
pub mod sid;
pub mod token;

pub use acl::{Ace, Acl};
pub use descriptor::SecurityDescriptor;
pub use sid::Sid;
pub use token::{Adjusted, Privilege, PrivilegeChange, SidAndAttributes, Token, TOKEN_OBJECT_TYPE};

use core::sync::atomic::{AtomicU64, Ordering};

use abi::security::Luid32;

/// Une LUID : une valeur unique tant que le système tourne.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Luid(pub u64);

impl Luid {
    /// Telle que le mode utilisateur la voit.
    pub const fn to_abi(self) -> Luid32 {
        Luid32 { low_part: self.0 as u32, high_part: (self.0 >> 32) as i32 }
    }

    /// Celle que le mode utilisateur donne.
    pub const fn from_abi(luid: Luid32) -> Self {
        Self((luid.high_part as u32 as u64) << 32 | luid.low_part as u64)
    }
}

/// La prochaine LUID : après celles des sessions d'ouverture connues
/// (`SYSTEM_LUID`, 0x3E7, et celles qui la précèdent).
static NEXT_LUID: AtomicU64 = AtomicU64::new(0x3E9);

/// ExAllocateLocallyUniqueId : une LUID neuve.
///
/// # IRQL
/// Tout niveau.
pub fn allocate_luid() -> Luid {
    Luid(NEXT_LUID.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luids_are_new_and_cross_the_abi() {
        let (first, second) = (allocate_luid(), allocate_luid());
        assert!(second > first && first.0 >= 0x3E9);
        let luid = Luid(0x1_0000_0002);
        assert_eq!(luid.to_abi(), Luid32 { low_part: 2, high_part: 1 });
        assert_eq!(Luid::from_abi(luid.to_abi()), luid);
    }
}
