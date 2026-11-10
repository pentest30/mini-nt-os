//! La table des handles USER (02 §7.2) : dans la section partagée de USER
//! ([`crate::shared`]), où `user32` la lit (ValidateHandle). L'entrée `i` a
//! le handle `FIRST_USER_HANDLE + 2 i`, sa génération dans le mot haut ;
//! une entrée neuve a la génération 2, une entrée reprise la suivante
//! (UserAllocHandle de ReactOS). La tête de la table dit combien d'entrées
//! ont servi (`nb_handles`, la borne des index pour `user32`), le
//! `SERVERINFO` combien sont prises (`cHandleEntries`).
//!
//! Pas encore : les verrous d'objet (`cLockObj`), la destruction différée
//! (`HANDLEENTRY_DESTROY`), les objets d'un processus ou d'un thread rendus
//! à sa fin.

use alloc::vec::Vec;
use core::mem::{offset_of, size_of};

use abi::ntstatus::{NtStatus, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_UNSUCCESSFUL};
use abi::user::{ServerInfoHead32, UserHandleEntry32, UserHandleTable32, FIRST_USER_HANDLE};
use hal::sync::KSpinLock;

use crate::shared;

/// Le handle de l'entrée `index` à la génération `generation`.
pub const fn handle(index: u32, generation: u16) -> u32 {
    (index << 1) + FIRST_USER_HANDLE + ((generation as u32) << 16)
}

/// L'index de l'entrée d'un handle, s'il en a la forme.
pub const fn index(handle: u32) -> Option<u32> {
    let low = handle & 0xFFFF;
    if low < FIRST_USER_HANDLE || !(low - FIRST_USER_HANDLE).is_multiple_of(2) {
        return None;
    }
    Some((low - FIRST_USER_HANDLE) >> 1)
}

/// Les entrées : la génération de chacune de celles qui ont servi, les
/// libres, et combien la table en tient.
#[derive(Debug)]
pub struct Slots {
    generations: Vec<u16>,
    free: Vec<u32>,
    capacity: u32,
}

impl Slots {
    pub fn new(capacity: u32) -> Self {
        Self { generations: Vec::new(), free: Vec::new(), capacity }
    }

    /// Prend une entrée : une libre (sa génération suivante, 1 après
    /// 0xFFFE), sinon une neuve (génération 2) ; `None` si la table est
    /// pleine. Rend son index et sa génération.
    pub fn alloc(&mut self) -> Option<(u32, u16)> {
        let index = match self.free.pop() {
            Some(index) => index,
            None if (self.generations.len() as u32) < self.capacity => {
                self.generations.push(1);
                self.generations.len() as u32 - 1
            }
            None => return None,
        };
        let generation = &mut self.generations[index as usize];
        *generation = if *generation >= 0xFFFE { 1 } else { *generation + 1 };
        Some((index, *generation))
    }

    /// Rend l'entrée du handle `handle`, si elle est prise à sa génération ;
    /// rend son index.
    pub fn free(&mut self, handle: u32) -> Option<u32> {
        let index = index(handle)?;
        let generation = *self.generations.get(index as usize)?;
        if generation != (handle >> 16) as u16 || self.free.contains(&index) {
            return None;
        }
        self.free.push(index);
        Some(index)
    }

    /// Combien d'entrées ont servi (`nb_handles`).
    pub fn used(&self) -> u32 {
        self.generations.len() as u32
    }

    /// Combien sont prises (`cHandleEntries`).
    pub fn taken(&self) -> u32 {
        self.used() - self.free.len() as u32
    }
}

/// Les entrées de la table, une fois USER initialisé.
static SLOTS: KSpinLock<Option<Slots>> = KSpinLock::new(None);

/// Écrit l'entrée `index`, puis le compte des entrées dans la tête de la
/// table et dans le `SERVERINFO`.
fn write(index: u32, entry: &UserHandleEntry32, slots: &Slots) -> Result<(), NtStatus> {
    let section = shared::section().ok_or(STATUS_UNSUCCESSFUL)?;
    let at = shared::HANDLE_ENTRIES + index * size_of::<UserHandleEntry32>() as u32;
    section.write_kernel(u64::from(at), entry.as_bytes())?;
    let head = u64::from(shared::HANDLE_TABLE) + offset_of!(UserHandleTable32, nb_handles) as u64;
    section.write_kernel(head, &slots.used().to_le_bytes())?;
    let counted = u64::from(shared::SERVER_INFO) + offset_of!(ServerInfoHead32, handle_entries) as u64;
    section.write_kernel(counted, &slots.taken().to_le_bytes())
}

/// UserAllocHandle : un handle pour l'objet `object` (son adresse du
/// serveur) de type `kind` (`TYPE_*`), à `owner` (un `THREADINFO` ou un
/// `PROCESSINFO`, son adresse du serveur, ou 0).
///
/// # Errors
/// `STATUS_INSUFFICIENT_RESOURCES` si la table est pleine ;
/// `STATUS_UNSUCCESSFUL` avant l'initialisation de USER.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn alloc(object: u32, owner: u32, kind: u8) -> Result<u32, NtStatus> {
    let mut slots = SLOTS.lock();
    let slots = slots.get_or_insert_with(|| Slots::new(shared::HANDLE_COUNT));
    let (index, generation) = slots.alloc().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let entry = UserHandleEntry32 { ptr: object, owner, kind, flags: 0, generation };
    if let Err(status) = write(index, &entry, slots) {
        slots.free(handle(index, generation));
        return Err(status);
    }
    Ok(handle(index, generation))
}

/// Rend le handle `handle` : son entrée devient libre (sa génération
/// reste, jusqu'à sa reprise).
///
/// # Errors
/// `STATUS_INVALID_HANDLE` pour un handle qui n'est pas pris.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn free(handle: u32) -> Result<(), NtStatus> {
    let mut slots = SLOTS.lock();
    let slots = slots.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    let index = slots.free(handle).ok_or(STATUS_INVALID_HANDLE)?;
    let entry = UserHandleEntry32 { generation: (handle >> 16) as u16, ..UserHandleEntry32::default() };
    write(index, &entry, slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_is_its_index_and_its_generation() {
        assert_eq!(handle(0, 2), 0x0002_0020, "the first window handle of ReactOS");
        assert_eq!(handle(5, 3), 0x0003_002A);
        assert_eq!((index(0x0002_0020), index(0x0003_002A)), (Some(0), Some(5)));
        assert_eq!((index(0x1F), index(0x21)), (None, None), "below the first, or odd");
    }

    #[test]
    fn entries_are_new_then_taken_again_one_generation_later() {
        let mut slots = Slots::new(2);
        let first = slots.alloc().unwrap();
        let second = slots.alloc().unwrap();
        assert_eq!((first, second), ((0, 2), (1, 2)));
        assert_eq!(slots.alloc(), None, "full");
        assert_eq!((slots.used(), slots.taken()), (2, 2));
        assert_eq!(slots.free(handle(0, 2)), Some(0));
        assert_eq!(slots.free(handle(0, 2)), None, "not twice");
        assert_eq!(slots.free(handle(1, 3)), None, "another generation");
        assert_eq!((slots.used(), slots.taken()), (2, 1));
        assert_eq!(slots.alloc(), Some((0, 3)), "taken again, the next generation");
    }

    #[test]
    fn the_generation_wraps_to_one() {
        let mut slots = Slots::new(1);
        slots.alloc();
        slots.generations[0] = 0xFFFE;
        slots.free(handle(0, 0xFFFE));
        assert_eq!(slots.alloc(), Some((0, 1)));
    }
}
