//! La souris absolue de VirtualBox (02 §8, pilotes). Sans elle, VirtualBox ne
//! donne à Mino que les déplacements de la souris PS/2 : le curseur de Mino
//! et le pointeur de l'hôte se décalent, et le curseur bute avant les bords
//! de l'écran quand le pointeur de l'hôte sort de la fenêtre. Avec elle, le
//! pilote annonce à VMMDev (`abi::vmmdev`) qu'il lit des positions
//! absolues ; tant que l'intégration de la souris de l'hôte est active, il
//! remplace le déplacement de chaque paquet PS/2 par la position du
//! pointeur de l'hôte (`MOUSE_MOVE_ABSOLUTE`, 0 à 0xFFFF sur chaque axe).
//! L'hôte signale une nouvelle position par un paquet PS/2 vide ; les
//! boutons et la molette restent ceux du paquet.
//!
//! Le pilote ne dessine pas le pointeur (pas de `SetPointerShape`) : c'est
//! le curseur logiciel de win32k qui se voit, l'hôte cache le sien.
//!
//! Hors de VirtualBox (QEMU, une vraie machine), pas de VMMDev : le pilote
//! ne se crée pas, la souris PS/2 reste relative.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::size_of;

use abi::mou::{MouseInputData, MOUSE_MOVE_ABSOLUTE};
use abi::vmmdev::{
    GuestInfo, MouseStatus, MOUSE_GUEST_CAN_ABSOLUTE, MOUSE_HOST_WANTS_ABSOLUTE, MOUSE_RANGE_MAX,
    REQUEST_GET_MOUSE_STATUS, REQUEST_SET_MOUSE_STATUS,
};

/// La page où le pilote écrit ses requêtes : son adresse physique, sous
/// 4 Gio, et son adresse dans le noyau.
#[derive(Debug)]
pub struct RequestPage {
    pub physical: u64,
    pub virt: *mut u8,
}

/// Pourquoi la souris absolue n'est pas là.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// Pas de VMMDev sur le bus PCI : ce n'est pas VirtualBox.
    NoDevice,
    /// La page de requêtes est au-dessus de 4 Gio.
    PageAbove4GiB,
    /// VMMDev a refusé une requête : son type, son statut.
    Refused { request_type: u32, rc: i32 },
}

/// La souris absolue de VirtualBox.
#[derive(Debug)]
pub struct VBoxMouse {
    port: u16,
    page: RequestPage,
}

impl VBoxMouse {
    /// Trouve VMMDev, s'annonce (sans cela, VMMDev refuse toute autre
    /// requête) et lui dit que Mino lit des positions absolues.
    ///
    /// # Errors
    /// [`Unavailable`].
    ///
    /// # Safety
    /// `page` est une page de 4 Kio du noyau, projetée en `page.virt`, que le
    /// pilote garde pour lui seul tant qu'il vit.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL, au démarrage (`hal::pci`).
    pub unsafe fn new(page: RequestPage) -> Result<Self, Unavailable> {
        let port = hal::vmmdev::find().ok_or(Unavailable::NoDevice)?;
        if page.physical >= 1 << 32 {
            return Err(Unavailable::PageAbove4GiB);
        }
        let mut mouse = Self { port, page };
        let info = mouse.call(GuestInfo::new());
        check(info.header.request_type, info.header.rc)?;
        let set = mouse.call(MouseStatus::new(REQUEST_SET_MOUSE_STATUS, MOUSE_GUEST_CAN_ABSOLUTE));
        check(set.header.request_type, set.header.rc)?;
        Ok(mouse)
    }

    /// Remet `request` à VMMDev par la page de requêtes ; rend la requête
    /// telle que VMMDev l'a laissée.
    fn call<T: Copy>(&mut self, request: T) -> T {
        const { assert!(size_of::<T>() <= 4096) };
        let slot = self.page.virt.cast::<T>();
        // SAFETY: la page est au pilote seul et assez grande (`new`, et
        // l'assertion ci-dessus) ; alignée sur 4 Kio, donc pour `T`.
        unsafe { slot.write_volatile(request) };
        // SAFETY: le port de VMMDev, l'adresse physique de la page (sous
        // 4 Gio, vérifié par `new`) qui porte une requête complète.
        unsafe { hal::vmmdev::submit(self.port, self.page.physical as u32) };
        // SAFETY: comme l'écriture.
        unsafe { slot.read_volatile() }
    }

    /// La position du pointeur de l'hôte, si l'hôte en envoie (son
    /// intégration de la souris est active).
    ///
    /// # IRQL
    /// Tout niveau (une écriture de port).
    pub fn position(&mut self) -> Option<(i32, i32)> {
        absolute(&self.call(MouseStatus::new(REQUEST_GET_MOUSE_STATUS, 0)))
    }

    /// Fait d'un paquet de la souris PS/2 un déplacement à la position du
    /// pointeur de l'hôte, s'il en envoie une ; rend vrai alors.
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn apply(&mut self, data: &mut MouseInputData) -> bool {
        let Some((x, y)) = self.position() else { return false };
        data.flags = MOUSE_MOVE_ABSOLUTE;
        data.last_x = x;
        data.last_y = y;
        true
    }
}

/// Le statut `rc` d'une requête de type `request_type` : une erreur s'il est
/// négatif.
fn check(request_type: u32, rc: i32) -> Result<(), Unavailable> {
    if rc < 0 {
        return Err(Unavailable::Refused { request_type, rc });
    }
    Ok(())
}

/// La position absolue que dit un état de la souris rendu par VMMDev, bornée
/// à 0..=0xFFFF, si la requête a réussi et que l'hôte envoie des positions.
pub fn absolute(status: &MouseStatus) -> Option<(i32, i32)> {
    (status.header.rc >= 0 && status.features & MOUSE_HOST_WANTS_ABSOLUTE != 0)
        .then(|| (status.x.clamp(0, MOUSE_RANGE_MAX), status.y.clamp(0, MOUSE_RANGE_MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::vmmdev::MOUSE_GUEST_NEEDS_HOST_CURSOR;

    fn status(rc: i32, features: u32, x: i32, y: i32) -> MouseStatus {
        let mut status = MouseStatus::new(REQUEST_GET_MOUSE_STATUS, 0);
        status.header.rc = rc;
        (status.features, status.x, status.y) = (features, x, y);
        status
    }

    #[test]
    fn the_host_position_counts_only_when_the_host_sends_it() {
        let both = MOUSE_GUEST_CAN_ABSOLUTE | MOUSE_HOST_WANTS_ABSOLUTE;
        assert_eq!(absolute(&status(0, both, 0x8000, 0x4000)), Some((0x8000, 0x4000)));
        // Intégration de l'hôte coupée : la souris PS/2 reste relative.
        assert_eq!(absolute(&status(0, MOUSE_GUEST_CAN_ABSOLUTE, 0x8000, 0x4000)), None);
        // Requête refusée.
        assert_eq!(absolute(&status(-1, both, 0x8000, 0x4000)), None);
        assert_eq!(absolute(&status(0, both | MOUSE_GUEST_NEEDS_HOST_CURSOR, 0x1_0000, -3)), Some((0xFFFF, 0)));
    }

    #[test]
    fn a_negative_status_is_a_refusal() {
        assert_eq!(check(50, 0), Ok(()));
        assert_eq!(check(50, 1), Ok(()));
        assert_eq!(check(2, -37), Err(Unavailable::Refused { request_type: 2, rc: -37 }));
    }

    #[test]
    fn without_vmmdev_there_is_no_absolute_mouse() {
        let mut page = [0u8; 64];
        // SAFETY: sur l'hôte, `hal::vmmdev::find` ne trouve rien : la page
        // n'est jamais touchée.
        let mouse = unsafe { VBoxMouse::new(RequestPage { physical: 0x1000, virt: page.as_mut_ptr() }) };
        assert_eq!(mouse.err(), Some(Unavailable::NoDevice));
    }
}
