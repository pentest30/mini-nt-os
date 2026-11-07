//! Bochs DISPI : l'interface d'affichage étendue du VGA standard (QEMU,
//! VirtualBox), aux ports 0x1CE (l'index) et 0x1CF (la donnée). Elle décrit
//! le même framebuffer linéaire que le GOP du chargeur — la base physique ne
//! bouge pas — et permet d'en changer la résolution à chaud.
//!
//! La séquence de changement : désactiver, poser la profondeur puis les
//! dimensions (réelles et virtuelles, le pas suit la largeur virtuelle),
//! réactiver avec le framebuffer linéaire. La relecture des registres rend
//! ce que le matériel a retenu.
//!
//! # IRQL
//! Les ports se lisent et s'écrivent à tout niveau ; le changement complet
//! ([`set_mode`]) s'appelle à PASSIVE_LEVEL, une seule main à la fois.

/// Le port d'index (écrit en 16 bits).
const INDEX: u16 = 0x1CE;
/// Le port de données.
const DATA: u16 = 0x1CF;

const ID: u16 = 0x0;
const XRES: u16 = 0x1;
const YRES: u16 = 0x2;
const BPP: u16 = 0x3;
const ENABLE: u16 = 0x4;
const VIRT_W: u16 = 0x6;
const VIRT_H: u16 = 0x7;
const X_OFFSET: u16 = 0x8;
const Y_OFFSET: u16 = 0x9;
const ENABLED: u16 = 0x01;
const LINEAR_FRAMEBUFFER: u16 = 0x40;
/// Le plus petit identifiant que l'interface annonce (`B0C2` chez QEMU).
const ID_MIN: u16 = 0xB0C0;
const ID_MAX: u16 = 0xB0C5;
/// La profondeur du framebuffer linéaire, en bits par pixel.
const BITS_PER_PIXEL: u16 = 32;

/// Le mot de 16 bits `value` vers le port `port` (out dx, ax).
///
/// # Safety
/// Le appelant connaît le port : l'index 0x1CE ou la donnée 0x1CF de
/// l'interface VGA, sans effet de bord au-delà du registre visé.
#[cfg(target_os = "none")]
#[inline]
unsafe fn port_out(port: u16, value: u16) {
    // SAFETY: contrat ci-dessus.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nostack)) };
}

/// Le mot de 16 bits du port `port` (in ax, dx).
///
/// # Safety
/// Le appelant connaît le port : 0x1CE ou 0x1CF de l'interface VGA.
#[cfg(target_os = "none")]
#[inline]
unsafe fn port_in(port: u16) -> u16 {
    let value: u16;
    // SAFETY: contrat ci-dessus.
    unsafe { core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nostack)) };
    value
}

/// Écrit `index` au port d'index, puis la donnée : le registre `index`.
#[cfg(target_os = "none")]
fn put_register(index: u16, value: u16) {
    // SAFETY: les ports fixes de l'interface VGA (le module le documente).
    unsafe {
        port_out(INDEX, index);
        port_out(DATA, value);
    }
}

/// Le contenu du registre `index`.
#[cfg(target_os = "none")]
fn get_register(index: u16) -> u16 {
    // SAFETY: les ports fixes de l'interface VGA (le module le documente).
    unsafe {
        port_out(INDEX, index);
        port_in(DATA)
    }
}

/// L'interface DISPI est-elle là ? Son identifiant se lit et vaut au moins
/// `B0C0`. Sans VGA (l'hôte, un autre contrôleur) : `false`.
///
/// # IRQL
/// Tout niveau.
pub fn identify() -> bool {
    #[cfg(target_os = "none")]
    {
        (ID_MIN..=ID_MAX).contains(&get_register(ID))
    }
    #[cfg(not(target_os = "none"))]
    {
        false
    }
}

/// Passe le framebuffer linéaire à `width` × `height`, 32 bits par pixel ;
/// rend les dimensions et le pas (en pixels) que le matériel retient, ou
/// `None` sans interface.
///
/// # IRQL
/// PASSIVE_LEVEL ; un seul appelant à la fois (l'écran est le sien pendant
/// le changement).
pub fn set_mode(width: u16, height: u16) -> Option<(u32, u32, u32)> {
    #[cfg(target_os = "none")]
    {
        if !identify() || width == 0 || height == 0 {
            return None;
        }
        put_register(ENABLE, 0);
        put_register(BPP, BITS_PER_PIXEL);
        put_register(X_OFFSET, 0);
        put_register(Y_OFFSET, 0);
        // Le pas suit la largeur virtuelle : elle égale la réelle. La hauteur
        // virtuelle, QEMU la recalcule lui-même (le fixup la force à la
        // capacité) : la relecture n'est pas la valeur posée.
        put_register(VIRT_W, width);
        put_register(VIRT_H, height);
        put_register(XRES, width);
        put_register(YRES, height);
        put_register(ENABLE, ENABLED | LINEAR_FRAMEBUFFER);
        let (read_width, read_height) = (get_register(XRES), get_register(YRES));
        Some((u32::from(read_width), u32::from(read_height), u32::from(read_width)))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (width, height);
        None
    }
}
