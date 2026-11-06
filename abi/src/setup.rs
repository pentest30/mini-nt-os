//! ABI privée entre l'installateur Mino et son moteur noyau.
//!
//! Le premier contrôle est volontairement en lecture seule : il rend une
//! cible sûre et le plan GPT calculé, sans exposer encore de commande
//! d'écriture. Tous les champs sont des mots de 32 bits afin que le layout
//! soit identique dans le noyau 64 bits et le programme Win32.

/// CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS).
pub const IOCTL_MINO_SETUP_QUERY: u32 = 0x8000_6000;

/// Version du contrat [`SetupPreview`].
pub const SETUP_ABI_VERSION: u32 = 1;

/// Un plan prêt à être présenté.
pub const SETUP_READY: u32 = 0;
/// Aucun disque non protégé n'est présent.
pub const SETUP_NO_TARGET: u32 = 1;
/// Le disque présent est trop petit pour deux volumes FAT32.
pub const SETUP_TOO_SMALL: u32 = 2;

/// La cible peut être sélectionnée par l'installateur.
pub const SETUP_DISK_CANDIDATE: u32 = 1 << 0;
/// Le disque porte le système courant et ne doit jamais être ciblé.
pub const SETUP_DISK_SYSTEM: u32 = 1 << 1;
/// Le disque contient le média qui a démarré Mino et reste protégé.
pub const SETUP_DISK_BOOT: u32 = 1 << 2;

/// Nombre de mots de 32 bits dans [`SetupPreview`].
pub const SETUP_PREVIEW_WORDS: usize = 17;
/// Taille encodée de [`SetupPreview`].
pub const SETUP_PREVIEW_SIZE: usize = SETUP_PREVIEW_WORDS * 4;

/// Aperçu immuable rendu avant toute écriture.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetupPreview {
    pub version: u32,
    pub state: u32,
    /// 0 : aucun ; 1 : maître primaire ; 2 : maître secondaire.
    pub disk_number: u32,
    pub disk_flags: u32,
    pub sector_size: u32,
    pub total_sectors: u64,
    /// Empreinte des champs du plan, à redonner au futur appel d'exécution.
    pub plan_token: u64,
    pub esp_first: u64,
    pub esp_sectors: u64,
    pub system_first: u64,
    pub system_sectors: u64,
}

impl SetupPreview {
    /// Encodage explicite, indépendant de l'alignement de Rust ou de C.
    pub fn to_bytes(self) -> [u8; SETUP_PREVIEW_SIZE] {
        let split = |value: u64| [value as u32, (value >> 32) as u32];
        let total = split(self.total_sectors);
        let token = split(self.plan_token);
        let esp_first = split(self.esp_first);
        let esp_sectors = split(self.esp_sectors);
        let system_first = split(self.system_first);
        let system_sectors = split(self.system_sectors);
        let words = [
            self.version,
            self.state,
            self.disk_number,
            self.disk_flags,
            self.sector_size,
            total[0],
            total[1],
            token[0],
            token[1],
            esp_first[0],
            esp_first[1],
            esp_sectors[0],
            esp_sectors[1],
            system_first[0],
            system_first[1],
            system_sectors[0],
            system_sectors[1],
        ];
        let mut bytes = [0; SETUP_PREVIEW_SIZE];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_layout_is_stable_for_win32() {
        let preview = SetupPreview {
            version: 1,
            state: 2,
            disk_number: 3,
            disk_flags: 4,
            sector_size: 512,
            total_sectors: 0x1122_3344_5566_7788,
            plan_token: 0x99aa_bbcc_ddee_ff00,
            esp_first: 0x1234,
            esp_sectors: 0x2345,
            system_first: 0x3456,
            system_sectors: 0x4567,
        };
        let bytes = preview.to_bytes();
        assert_eq!(bytes.len(), 68);
        assert_eq!(&bytes[20..28], &preview.total_sectors.to_le_bytes());
        assert_eq!(&bytes[28..36], &preview.plan_token.to_le_bytes());
        assert_eq!(&bytes[60..68], &preview.system_sectors.to_le_bytes());
    }
}
