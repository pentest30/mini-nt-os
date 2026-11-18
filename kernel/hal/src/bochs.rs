//! Bochs DISPI : l'interface d'affichage étendue du VGA standard (QEMU,
//! VirtualBox), aux ports 0x1CE (l'index) et 0x1CF (la donnée). Elle décrit
//! le framebuffer linéaire de la barre 0 du contrôleur — celui que le GOP du
//! chargeur décrit aussi, la base physique ne bouge pas — et permet d'en
//! changer la résolution à chaud. Le pilote `drivers/video/bochs-dispi` s'en
//! sert.
//!
//! La séquence de changement : désactiver, poser la profondeur puis les
//! dimensions (réelles et virtuelles, le pas suit la largeur virtuelle),
//! réactiver avec le framebuffer linéaire. La relecture des registres rend
//! ce que le matériel a retenu.
//!
//! Les limites de l'interface (GETCAPS) se lisent sans la désactiver : le bit
//! `GETCAPS` posé avec `ENABLED` déjà présent ne change pas de mode, les
//! registres de dimensions rendent alors leurs maximums ; on remet ensuite
//! `ENABLE` tel qu'il était.
//!
//! # IRQL
//! Les ports se lisent et s'écrivent à tout niveau, mais l'index et la
//! donnée forment une paire : un seul appelant à la fois. Le pilote les
//! appelle sous son verrou, ou au démarrage avant que win32k ne dessine.

/// Les ports et les registres de l'interface, que seul le code bare-metal
/// atteint : sur l'hôte, l'interface est absente ([`identify`] rend `false`,
/// le reste `None`).
#[cfg(target_os = "none")]
mod dispi {
    /// Le port d'index (écrit en 16 bits).
    pub const INDEX: u16 = 0x1CE;
    /// Le port de données.
    pub const DATA: u16 = 0x1CF;

    pub const ID: u16 = 0x0;
    pub const XRES: u16 = 0x1;
    pub const YRES: u16 = 0x2;
    pub const BPP: u16 = 0x3;
    pub const ENABLE: u16 = 0x4;
    pub const VIRT_W: u16 = 0x6;
    pub const VIRT_H: u16 = 0x7;
    pub const X_OFFSET: u16 = 0x8;
    pub const Y_OFFSET: u16 = 0x9;
    /// La mémoire vidéo, en blocs de 64 Kio (à partir de l'identifiant
    /// `B0C5` chez QEMU ; 0 avant).
    pub const VIDEO_MEMORY_64K: u16 = 0xA;
    pub const ENABLED: u16 = 0x01;
    pub const GETCAPS: u16 = 0x02;
    pub const LINEAR_FRAMEBUFFER: u16 = 0x40;
    /// Le plus petit identifiant que l'interface annonce (`B0C5` chez QEMU).
    pub const ID_MIN: u16 = 0xB0C0;
    pub const ID_MAX: u16 = 0xB0C5;
    /// La profondeur du framebuffer linéaire, en bits par pixel.
    pub const BITS_PER_PIXEL: u16 = 32;
}
#[cfg(target_os = "none")]
use dispi::*;

/// Le mot de 16 bits `value` vers le port `port` (out dx, ax).
///
/// # Safety
/// L'appelant connaît le port : l'index 0x1CE ou la donnée 0x1CF de
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
/// L'appelant connaît le port : 0x1CE ou 0x1CF de l'interface VGA.
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
/// Tout niveau (voir le module).
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

/// Un mode de l'interface, tel que ses registres le disent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispiMode {
    pub width: u32,
    pub height: u32,
    pub bits_per_pixel: u32,
    /// Le pas d'une ligne, en pixels (la largeur virtuelle).
    pub stride: u32,
    /// Le framebuffer linéaire est actif.
    pub linear: bool,
}

/// Le mode en vigueur ; `None` sans interface.
///
/// # IRQL
/// Tout niveau (voir le module).
pub fn current() -> Option<DispiMode> {
    #[cfg(target_os = "none")]
    {
        if !identify() {
            return None;
        }
        let enable = get_register(ENABLE);
        Some(DispiMode {
            width: u32::from(get_register(XRES)),
            height: u32::from(get_register(YRES)),
            bits_per_pixel: u32::from(get_register(BPP)),
            stride: u32::from(get_register(VIRT_W)),
            linear: enable & (ENABLED | LINEAR_FRAMEBUFFER) == ENABLED | LINEAR_FRAMEBUFFER,
        })
    }
    #[cfg(not(target_os = "none"))]
    {
        None
    }
}

/// La mémoire vidéo que l'interface annonce, en octets ; `None` sans
/// interface ou quand elle ne la dit pas (identifiant avant `B0C5`).
///
/// # IRQL
/// Tout niveau (voir le module).
pub fn video_memory() -> Option<usize> {
    #[cfg(target_os = "none")]
    {
        if !identify() {
            return None;
        }
        let blocks = usize::from(get_register(VIDEO_MEMORY_64K));
        (blocks != 0).then_some(blocks * 64 * 1024)
    }
    #[cfg(not(target_os = "none"))]
    {
        None
    }
}

/// Les plus grandes largeur, hauteur et profondeur que l'interface accepte
/// (GETCAPS) ; `None` sans interface ou si elle ne répond pas. Le mode en
/// vigueur n'est pas touché.
///
/// # IRQL
/// Tout niveau (voir le module).
pub fn capabilities() -> Option<(u32, u32, u32)> {
    #[cfg(target_os = "none")]
    {
        if !identify() {
            return None;
        }
        let enable = get_register(ENABLE);
        // With ENABLED already set, GETCAPS does not switch modes: the
        // dimension registers read as their maximums.
        put_register(ENABLE, enable | GETCAPS);
        let caps = (get_register(XRES), get_register(YRES), get_register(BPP));
        put_register(ENABLE, enable);
        let (width, height, bits) = (u32::from(caps.0), u32::from(caps.1), u32::from(caps.2));
        (width != 0 && height != 0).then_some((width, height, bits))
    }
    #[cfg(not(target_os = "none"))]
    {
        None
    }
}

/// Passe le framebuffer linéaire à `width` × `height`, 32 bits par pixel ;
/// rend les dimensions et le pas (en pixels) que le matériel retient, ou
/// `None` sans interface.
///
/// # IRQL
/// Tout niveau ; un seul appelant à la fois (l'écran est le sien pendant le
/// changement).
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
        let stride = get_register(VIRT_W);
        Some((u32::from(read_width), u32::from(read_height), u32::from(stride)))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (width, height);
        None
    }
}
