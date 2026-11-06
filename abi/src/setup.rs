//! ABI privée entre l'installateur Mino et son moteur noyau.
//!
//! Le premier contrôle est volontairement en lecture seule : il rend une
//! cible sûre et le plan GPT calculé, sans exposer encore de commande
//! d'écriture. Tous les champs sont des mots de 32 bits afin que le layout
//! soit identique dans le noyau 64 bits et le programme Win32.

/// CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS).
pub const IOCTL_MINO_SETUP_QUERY: u32 = 0x8000_6000;

/// CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS).
///
/// La préparation écrit les tables GPT du plan sur le disque choisi, puis
/// les relit pour les vérifier. Elle exige le jeton de l'aperçu ; elle ne
/// formate pas et ne copie rien.
pub const IOCTL_MINO_SETUP_PREPARE: u32 = 0x8000_A004;

/// CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS).
///
/// Le formatage formate les deux volumes du plan (ESP et système) en FAT32,
/// après la préparation — ses tables GPT doivent être là. Même demande et
/// même jeton que la préparation ; il ne copie rien.
pub const IOCTL_MINO_SETUP_FORMAT: u32 = 0x8000_A008;

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

/// Nombre de mots de 32 bits de [`SetupPrepare`].
pub const SETUP_PREPARE_WORDS: usize = 4;
/// Taille encodée de [`SetupPrepare`].
pub const SETUP_PREPARE_SIZE: usize = SETUP_PREPARE_WORDS * 4;

/// La demande de préparation : le disque de l'aperçu et son jeton. Le noyau
/// recalcule le plan du disque et refuse tout jeton qui ne le décrit plus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupPrepare {
    pub version: u32,
    /// Le numéro du disque que l'aperçu a rendu.
    pub disk_number: u32,
    /// Le `plan_token` de l'aperçu, tel quel.
    pub plan_token: u64,
}

impl SetupPrepare {
    /// Encodage explicite, symétrique de [`SetupPreview::to_bytes`].
    pub fn to_bytes(self) -> [u8; SETUP_PREPARE_SIZE] {
        let token = [self.plan_token as u32, (self.plan_token >> 32) as u32];
        let mut bytes = [0; SETUP_PREPARE_SIZE];
        for (index, word) in [self.version, self.disk_number, token[0], token[1]].iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// Décode la demande ; `None` pour une version du contrat qui n'est pas
    /// la sienne.
    pub fn from_bytes(bytes: [u8; SETUP_PREPARE_SIZE]) -> Option<Self> {
        let word = |at: usize| {
            let mut buffer = [0u8; 4];
            buffer.copy_from_slice(&bytes[at * 4..at * 4 + 4]);
            u32::from_le_bytes(buffer)
        };
        let version = word(0);
        (version == SETUP_ABI_VERSION).then(|| Self {
            version,
            disk_number: word(1),
            plan_token: u64::from(word(2)) | (u64::from(word(3)) << 32),
        })
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

    #[test]
    fn prepare_request_round_trips_and_refuses_other_versions() {
        let request = SetupPrepare { version: SETUP_ABI_VERSION, disk_number: 2, plan_token: 0x99aa_bbcc_ddee_ff00 };
        let decoded = SetupPrepare::from_bytes(request.to_bytes()).unwrap();
        assert_eq!(decoded, request);
        let mut other = request.to_bytes();
        other[..4].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(SetupPrepare::from_bytes(other), None);
    }
}
