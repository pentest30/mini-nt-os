//! La ruche HARDWARE (02 §5.7) : volatile, bâtie au démarrage, comme XP la
//! tire de la détection du matériel, montée en `\REGISTRY\MACHINE\HARDWARE`.
//! Elle ne va jamais sur disque.
//!
//! `DESCRIPTION\System` (`AT/AT COMPATIBLE`), et pour le processeur
//! `CentralProcessor\0` et `FloatingPointProcessor\0` : `Identifier`
//! (`x86 Family 6 Model 15 Stepping 11`, de `SystemProcessorInformation`),
//! `VendorIdentifier`, `ProcessorNameString` (la marque de CPUID, sans ses
//! espaces de tête), `FeatureSet` (KeFeatureBits). `DEVICEMAP` et
//! `RESOURCEMAP`, vides, attendent les pilotes.
//!
//! Pas encore : `~MHz` (sans mesure de la fréquence), `Configuration Data`,
//! les bus et les périphériques.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::NtStatus;
use abi::registry::{REG_DWORD, REG_SZ};
use regf::builder::{build, KeyNode};

/// Un REG_SZ : le texte et son NUL, en UTF-16.
fn sz(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// L'identifiant du processeur, comme XP l'écrit.
pub fn processor_identifier() -> String {
    let info = crate::sys::processor_information();
    alloc::format!(
        "x86 Family {} Model {} Stepping {}",
        info.processor_level,
        info.processor_revision >> 8,
        info.processor_revision & 0xFF
    )
}

/// L'arbre de la ruche.
fn tree() -> KeyNode {
    let info = crate::sys::processor_information();
    let identifier = processor_identifier();
    let vendor = String::from_utf8_lossy(&hal::cpuid::vendor()).into_owned();
    let brand = hal::cpuid::brand().map(|brand| {
        let end = brand.iter().position(|&b| b == 0).unwrap_or(brand.len());
        String::from(String::from_utf8_lossy(&brand[..end]).trim_start())
    });
    let mut root = KeyNode::new("HARDWARE");
    root.key_mut("DESCRIPTION\\System").set_value("Identifier", REG_SZ, sz("AT/AT COMPATIBLE"));
    let cpu = root.key_mut("DESCRIPTION\\System\\CentralProcessor\\0");
    cpu.set_value("Identifier", REG_SZ, sz(&identifier));
    cpu.set_value("VendorIdentifier", REG_SZ, sz(&vendor));
    if let Some(brand) = brand {
        cpu.set_value("ProcessorNameString", REG_SZ, sz(&brand));
    }
    cpu.set_value("FeatureSet", REG_DWORD, info.processor_feature_bits.to_le_bytes().to_vec());
    root.key_mut("DESCRIPTION\\System\\FloatingPointProcessor\\0").set_value("Identifier", REG_SZ, sz(&identifier));
    root.key_mut("DEVICEMAP");
    root.key_mut("RESOURCEMAP");
    root
}

/// Bâtit la ruche HARDWARE et la monte en `\REGISTRY\MACHINE\HARDWARE` ;
/// rend l'identifiant du processeur.
///
/// # IRQL
/// PASSIVE_LEVEL, une fois, après `cm::init`.
pub fn mount_hardware_hive() -> Result<String, NtStatus> {
    let registry = cm::registry().expect("Cm initialised");
    let file = cm::HiveFile::new(Arc::from(build(&tree(), "HARDWARE")))?;
    cm::mount(&registry, "MACHINE", "HARDWARE", file)?;
    Ok(processor_identifier())
}
