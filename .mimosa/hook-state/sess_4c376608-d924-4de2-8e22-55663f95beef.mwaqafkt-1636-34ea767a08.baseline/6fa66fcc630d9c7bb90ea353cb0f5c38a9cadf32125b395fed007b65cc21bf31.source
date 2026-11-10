//! Les tables NLS : la page de code ANSI, la page de code OEM et la table de
//! casse Unicode, que `ntdll` lit dans le PEB (`AnsiCodePageData`,
//! `OemCodePageData`, `UnicodeCaseTableData`) dès le début de
//! l'initialisation du processus (`RtlInitNlsTables`), sans quoi aucune
//! chaîne ANSI ne se convertit. Comme sous XP, une seule section les tient,
//! chacune alignée sur une page ; chaque processus la projette en lecture
//! seule ([`crate::eprocess::create_process`]).
//!
//! Les fichiers viennent de `system32` (`C_1252.NLS`, `C_437.NLS`,
//! `L_INTL.NLS`) ; le noyau les installe au démarrage ([`install`]).

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{NtStatus, STATUS_INVALID_PARAMETER};
use hal::sync::KSpinLock;
use mm::section::Section;
use mm::vad::PageProtect;
use mm::virtual_alloc::PAGE_SIZE;

/// La taille, en mots, de l'en-tête d'un fichier de page de code
/// (CPTABLEINFO) : son premier mot.
const CODE_PAGE_HEADER_WORDS: u16 = 0x0D;

/// Les trois tables, dans leur section.
pub struct NlsTables {
    section: Arc<Section>,
    /// Les pages de code ANSI et OEM, d'après leurs en-têtes.
    pub ansi_code_page: u16,
    pub oem_code_page: u16,
    /// Les décalages des tables OEM et de casse dans la section ; l'ANSI est
    /// au début.
    oem_offset: u32,
    case_offset: u32,
}

/// Les tables installées.
static NLS_TABLES: KSpinLock<Option<Arc<NlsTables>>> = KSpinLock::new(None);

/// La page de code d'un fichier de page de code, d'après son en-tête ;
/// `STATUS_INVALID_PARAMETER` s'il n'en a pas.
fn code_page(file: &[u8]) -> Result<u16, NtStatus> {
    match file {
        [size_low, size_high, page_low, page_high, ..]
            if u16::from_le_bytes([*size_low, *size_high]) == CODE_PAGE_HEADER_WORDS =>
        {
            Ok(u16::from_le_bytes([*page_low, *page_high]))
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Les décalages des tables OEM et de casse, chaque table alignée sur une
/// page à la suite de la précédente.
fn layout(ansi: usize, oem: usize) -> (u32, u32) {
    let page = PAGE_SIZE as usize;
    let oem_offset = ansi.next_multiple_of(page);
    let case_offset = oem_offset + oem.next_multiple_of(page);
    (oem_offset as u32, case_offset as u32)
}

impl NlsTables {
    /// Les tables `ansi`, `oem` et `case` dans une section de données en
    /// lecture seule. `STATUS_INVALID_PARAMETER` si `ansi` ou `oem` n'est pas
    /// un fichier de page de code, ou si `case` est vide.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub fn new(ansi: &[u8], oem: &[u8], case: &[u8]) -> Result<Self, NtStatus> {
        let (ansi_code_page, oem_code_page) = (code_page(ansi)?, code_page(oem)?);
        if case.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let (oem_offset, case_offset) = layout(ansi.len(), oem.len());
        let mut bytes = Vec::with_capacity(case_offset as usize + case.len());
        bytes.extend_from_slice(ansi);
        bytes.resize(oem_offset as usize, 0);
        bytes.extend_from_slice(oem);
        bytes.resize(case_offset as usize, 0);
        bytes.extend_from_slice(case);
        let section = Section::create_data_file(Arc::from(bytes), 0, PageProtect::READONLY)?;
        Ok(Self { section, ansi_code_page, oem_code_page, oem_offset, case_offset })
    }

    /// Leur section, que chaque processus projette.
    pub fn section(&self) -> &Arc<Section> {
        &self.section
    }

    /// Les adresses des tables ANSI, OEM et de casse dans une vue de la
    /// section en `base`.
    pub fn addresses(&self, base: u32) -> (u32, u32, u32) {
        (base, base + self.oem_offset, base + self.case_offset)
    }
}

/// Installe les tables, ou les retire (`None`) : les processus créés ensuite
/// les projettent.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn install(tables: Option<NlsTables>) {
    *NLS_TABLES.lock() = tables.map(Arc::new);
}

/// Les tables installées.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn current() -> Option<Arc<NlsTables>> {
    NLS_TABLES.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_page_file(page: u16, size: usize) -> Vec<u8> {
        let mut file = alloc::vec![0u8; size];
        file[..4].copy_from_slice(&[0x0D, 0, page as u8, (page >> 8) as u8]);
        file
    }

    #[test]
    fn each_table_starts_on_its_own_page() {
        assert_eq!(layout(66082, 66594), (0x11000, 0x22000), "c_1252.nls, then c_437.nls");
        assert_eq!(layout(0x1000, 0x1000), (0x1000, 0x2000), "already page-sized");
    }

    #[test]
    fn code_pages_come_from_their_headers() {
        assert_eq!(code_page(&code_page_file(1252, 0x40)), Ok(1252));
        assert_eq!(code_page(&code_page_file(437, 0x40)), Ok(437));
        assert_eq!(code_page(&[0x01, 0x00, 0x01, 0x05]), Err(STATUS_INVALID_PARAMETER), "l_intl.nls is not one");
        assert_eq!(code_page(&[0x0D, 0x00]), Err(STATUS_INVALID_PARAMETER), "too short");
    }

    #[test]
    fn the_tables_share_one_read_only_section() {
        let (ansi, oem) = (code_page_file(1252, 0x1800), code_page_file(437, 0x10));
        let tables = NlsTables::new(&ansi, &oem, &[1, 2, 3]).expect("three tables");
        assert_eq!((tables.ansi_code_page, tables.oem_code_page), (1252, 437));
        assert_eq!(tables.addresses(0x1_0000), (0x1_0000, 0x1_2000, 0x1_3000));
        assert_eq!(tables.section().size(), 0x3003);
        assert_eq!(tables.section().protect(), PageProtect::READONLY);
        assert_eq!(NlsTables::new(&[1, 0, 1, 5], &oem, &[1]).err(), Some(STATUS_INVALID_PARAMETER), "not ANSI");
        assert_eq!(NlsTables::new(&ansi, &oem, &[]).err(), Some(STATUS_INVALID_PARAMETER), "no case table");
    }
}
