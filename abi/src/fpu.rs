//! Zone FXSAVE : l'état x87, MMX et SSE d'un thread (ADR-009). Format 64 bits
//! (`FXSAVE64`), imposé par le processeur (Intel SDM vol. 1, §10.5.1).
//!
//! Le `CONTEXT` x86 en porte une copie au format 32 bits (`ExtendedRegisters`)
//! ; la conversion viendra avec `NtGetContextThread`.

/// Mot de contrôle x87 initial d'un thread : exceptions masquées, arrondi au
/// plus proche, précision 53 bits (double). C'est le mot de contrôle par défaut
/// documenté du runtime C d'XP (`_CW_DEFAULT`).
pub const INITIAL_FCW: u16 = 0x027F;

/// MXCSR initial d'un thread : exceptions masquées, arrondi au plus proche.
pub const INITIAL_MXCSR: u32 = 0x1F80;

/// Zone de `FXSAVE64`/`FXRSTOR64` : 512 octets alignés sur 16.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FxSaveArea {
    /// Mot de contrôle x87 (FCW).
    pub fcw: u16,
    /// Mot d'état x87 (FSW).
    pub fsw: u16,
    /// Mot d'étiquettes abrégé (un bit par registre, 1 = occupé).
    pub ftw: u8,
    reserved1: u8,
    /// Code de la dernière instruction x87 en faute.
    pub fop: u16,
    /// Adresse de la dernière instruction x87.
    pub fip: u64,
    /// Adresse du dernier opérande x87.
    pub fdp: u64,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    /// ST0 à ST7 (ou MM0 à MM7), 80 bits dans 16 octets.
    pub st: [[u8; 16]; 8],
    /// XMM0 à XMM15.
    pub xmm: [[u8; 16]; 16],
    reserved2: [u8; 96],
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<FxSaveArea>() == 512);
    assert!(align_of::<FxSaveArea>() == 16);
    assert!(offset_of!(FxSaveArea, fcw) == 0);
    assert!(offset_of!(FxSaveArea, fsw) == 2);
    assert!(offset_of!(FxSaveArea, ftw) == 4);
    assert!(offset_of!(FxSaveArea, fop) == 6);
    assert!(offset_of!(FxSaveArea, fip) == 8);
    assert!(offset_of!(FxSaveArea, fdp) == 16);
    assert!(offset_of!(FxSaveArea, mxcsr) == 24);
    assert!(offset_of!(FxSaveArea, mxcsr_mask) == 28);
    assert!(offset_of!(FxSaveArea, st) == 32);
    assert!(offset_of!(FxSaveArea, xmm) == 160);
};

impl FxSaveArea {
    /// État d'un thread neuf : pile x87 vide, registres à zéro, FCW et MXCSR
    /// initiaux.
    pub const fn initial() -> Self {
        Self {
            fcw: INITIAL_FCW,
            fsw: 0,
            ftw: 0,
            reserved1: 0,
            fop: 0,
            fip: 0,
            fdp: 0,
            mxcsr: INITIAL_MXCSR,
            mxcsr_mask: 0,
            st: [[0; 16]; 8],
            xmm: [[0; 16]; 16],
            reserved2: [0; 96],
        }
    }
}

impl Default for FxSaveArea {
    fn default() -> Self {
        Self::initial()
    }
}
