//! VMMDev, le périphérique d'intégration de VirtualBox (`abi::vmmdev`) : le
//! trouver sur le bus PCI et lui remettre une requête. Le protocole (quelle
//! requête, quand) est dans le pilote `vboxmouse`.
//!
//! # IRQL
//! [`find`] : celui de `hal::pci`. [`submit`] : tout niveau, l'écriture du
//! port est traitée par l'hyperviseur avant de rendre la main.

use abi::vmmdev::{DEVICE_ID, VENDOR_ID};

/// Le port de requêtes de VMMDev (sa barre 0, d'entrées-sorties), s'il est
/// là.
///
/// # IRQL
/// Voir `hal::pci`.
pub fn find() -> Option<u16> {
    let function = crate::pci::find(VENDOR_ID, DEVICE_ID)?;
    crate::pci::io_bar(function, 0)
}

/// Remet à VMMDev la requête dont l'adresse physique est `request` : le
/// périphérique la traite pendant l'écriture, et laisse son statut dans la
/// requête.
///
/// # Safety
/// `port` est le port rendu par [`find`] ; `request` est l'adresse physique
/// d'une requête complète (`abi::vmmdev`, son en-tête dit sa taille), que
/// rien d'autre ne touche pendant l'appel et dont la mémoire peut être
/// écrite par le périphérique.
pub unsafe fn submit(port: u16, request: u32) {
    #[cfg(target_os = "none")]
    {
        // Sans `nomem` (au contraire de `Port::write`) : le périphérique lit
        // et écrit la requête en mémoire pendant le `out`, qui est donc une
        // barrière pour le compilateur.
        // SAFETY: contrat ci-dessus.
        unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") request, options(nostack, preserves_flags)) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (port, request);
    }
}
