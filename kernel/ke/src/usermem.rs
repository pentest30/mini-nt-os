//! La mémoire utilisateur (02 §6.4) : le noyau ne l'atteint que par ces
//! primitives.
//!
//! Une plage utilisateur est d'abord sondée ([`probe_for_read`],
//! [`probe_for_write`]) : sous [`USER_PROBE_ADDRESS`], sans débordement,
//! alignée comme demandé. Elle est ensuite copiée par `hal::usermem`. Une
//! faute que Mm résout (page à zéro, copie sur écriture, garde de la pile du
//! thread) est transparente ; une autre rend `STATUS_ACCESS_VIOLATION`, au
//! lieu d'arrêter le système.

use core::marker::PhantomData;
use core::mem::{size_of, MaybeUninit};

use abi::ntstatus::{NtStatus, STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT};

/// MmUserProbeAddress d'XP : la première adresse qu'une sonde refuse ; les
/// 64 Kio du haut de la moitié utilisateur ne sont jamais projetés.
pub const USER_PROBE_ADDRESS: u64 = 0x7FFF_0000;

/// ProbeForRead : `[addr, addr + len)` est une plage utilisateur, alignée sur
/// `alignment` (une puissance de 2). Une longueur nulle est toujours valide.
/// `STATUS_DATATYPE_MISALIGNMENT` si l'adresse n'est pas alignée,
/// `STATUS_ACCESS_VIOLATION` si la plage déborde ou sort de la moitié
/// utilisateur.
///
/// # IRQL
/// Tout niveau.
pub fn probe_for_read(addr: u64, len: usize, alignment: usize) -> Result<(), NtStatus> {
    debug_assert!(alignment.is_power_of_two());
    if len == 0 {
        return Ok(());
    }
    if addr & (alignment as u64 - 1) != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    match addr.checked_add(len as u64) {
        Some(end) if end <= USER_PROBE_ADDRESS => Ok(()),
        _ => Err(STATUS_ACCESS_VIOLATION),
    }
}

/// ProbeForWrite : comme [`probe_for_read`]. Les pages ne sont pas touchées
/// d'avance : la copie qui suit fait les fautes, et rend leur erreur.
///
/// # IRQL
/// Tout niveau.
pub fn probe_for_write(addr: u64, len: usize, alignment: usize) -> Result<(), NtStatus> {
    probe_for_read(addr, len, alignment)
}

/// Copie `dst.len()` octets depuis l'adresse utilisateur `src`.
///
/// # IRQL
/// < DISPATCH_LEVEL. Peut faire des fautes de page.
pub fn copy_from_user(dst: &mut [u8], src: u64) -> Result<(), NtStatus> {
    probe_for_read(src, dst.len(), 1)?;
    // SAFETY: `dst` is kernel memory; `src` is a probed user range, a fault
    // in which ends the copy.
    if unsafe { hal::usermem::copy(dst.as_mut_ptr(), src as *const u8, dst.len()) } {
        Ok(())
    } else {
        Err(STATUS_ACCESS_VIOLATION)
    }
}

/// Copie `src` vers l'adresse utilisateur `dst`.
///
/// # IRQL
/// < DISPATCH_LEVEL. Peut faire des fautes de page.
pub fn copy_to_user(dst: u64, src: &[u8]) -> Result<(), NtStatus> {
    probe_for_write(dst, src.len(), 1)?;
    // SAFETY: `src` is kernel memory; `dst` is a probed user range, a fault
    // in which ends the copy.
    if unsafe { hal::usermem::copy(dst as *mut u8, src.as_ptr(), src.len()) } {
        Ok(())
    } else {
        Err(STATUS_ACCESS_VIOLATION)
    }
}

/// Un type qui se lit en mémoire utilisateur, avec son alignement i386.
///
/// # Safety
/// Toute suite de `size_of::<Self>()` octets en est une valeur valide, et il
/// n'a pas d'octets de remplissage.
pub unsafe trait UserValue: Copy {
    /// L'alignement que demande sa sonde dans un processus i386.
    const ALIGNMENT: usize;
}

macro_rules! user_value {
    ($($t:ty => $alignment:expr),* $(,)?) => {
        $(
            // SAFETY: an integer: every bit pattern is a value, no padding.
            unsafe impl UserValue for $t {
                const ALIGNMENT: usize = $alignment;
            }
        )*
    };
}

// i386 aligns 64-bit integers on 4 bytes, like LARGE_INTEGER in a probe.
user_value!(u8 => 1, i8 => 1, u16 => 2, i16 => 2, u32 => 4, i32 => 4, u64 => 4, i64 => 4);

// SAFETY: an array of values valid for any bit pattern, without padding,
// is one too.
unsafe impl<T: UserValue, const N: usize> UserValue for [T; N] {
    const ALIGNMENT: usize = T::ALIGNMENT;
}

/// Un pointeur utilisateur vers un `T`, sur 32 bits comme dans un processus
/// i386.
#[derive(Debug, PartialEq, Eq)]
pub struct UserPtr<T> {
    addr: u32,
    _target: PhantomData<fn() -> T>,
}

impl<T> Clone for UserPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for UserPtr<T> {}

impl<T: UserValue> UserPtr<T> {
    pub const fn new(addr: u32) -> Self {
        Self { addr, _target: PhantomData }
    }

    pub const fn addr(self) -> u32 {
        self.addr
    }

    pub const fn is_null(self) -> bool {
        self.addr == 0
    }

    /// Sonde (alignement de `T`) puis lit la valeur.
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL. Peut faire des fautes de page.
    pub fn read(self) -> Result<T, NtStatus> {
        probe_for_read(u64::from(self.addr), size_of::<T>(), T::ALIGNMENT)?;
        let mut value = MaybeUninit::<T>::uninit();
        // SAFETY: the `size_of::<T>()` bytes of `value`, which `copy` fills
        // entirely when it succeeds.
        let bytes = unsafe { core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>()) };
        copy_from_user(bytes, u64::from(self.addr))?;
        // SAFETY: every byte was copied, and any bytes are a `T` (`UserValue`).
        Ok(unsafe { value.assume_init() })
    }

    /// Sonde (alignement de `T`) puis écrit `value`.
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL. Peut faire des fautes de page.
    pub fn write(self, value: &T) -> Result<(), NtStatus> {
        probe_for_write(u64::from(self.addr), size_of::<T>(), T::ALIGNMENT)?;
        // SAFETY: a `UserValue` has no padding: all its bytes are initialised.
        let bytes = unsafe { core::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) };
        copy_to_user(u64::from(self.addr), bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_stays_in_the_user_half() {
        assert_eq!(probe_for_read(0x1_0000, 0x1000, 4), Ok(()));
        assert_eq!(probe_for_read(USER_PROBE_ADDRESS - 4, 4, 4), Ok(()), "up to the probe address");
        assert_eq!(probe_for_read(USER_PROBE_ADDRESS - 4, 5, 1), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(probe_for_read(u64::MAX - 1, 4, 1), Err(STATUS_ACCESS_VIOLATION), "wraps around");
        assert_eq!(probe_for_write(0xFFFF_8000_0000_0000, 1, 1), Err(STATUS_ACCESS_VIOLATION), "kernel half");
    }

    #[test]
    fn a_probe_checks_alignment_but_not_an_empty_range() {
        assert_eq!(probe_for_read(0x1_0002, 4, 4), Err(STATUS_DATATYPE_MISALIGNMENT));
        assert_eq!(probe_for_read(0x1_0002, 2, 2), Ok(()));
        assert_eq!(probe_for_read(0xFFFF_FFFF_0000_0001, 0, 4), Ok(()), "nothing to read");
    }

    #[test]
    fn user_pointers_probe_with_i386_alignment() {
        // Above the probe address: refused before any copy.
        assert_eq!(UserPtr::<u32>::new(0x8000_0000).read(), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(UserPtr::<u32>::new(0x1_0001).write(&1), Err(STATUS_DATATYPE_MISALIGNMENT));
        assert_eq!(<u64 as UserValue>::ALIGNMENT, 4, "LARGE_INTEGER aligns on 4 on i386");
        assert_eq!(<[u16; 3] as UserValue>::ALIGNMENT, 2);
        assert!(UserPtr::<u8>::new(0).is_null());
    }
}
