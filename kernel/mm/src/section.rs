//! Sections (02 §5.3) : la mémoire que partagent des vues.
//!
//! Une section (NtCreateSection) tient des pages que toutes ses vues
//! (NtMapViewOfSection, `AddressSpace::map_view`) partagent :
//!
//! - adossée au fichier d'échange : des pages à zéro ; sans fichier d'échange
//!   (ADR-010), elles restent en mémoire ;
//! - de fichier de données : les octets d'un fichier ;
//! - d'image : un PE32 (`libs/pe`) disposé comme en mémoire, en-têtes et
//!   sections à leur RVA, chaque page avec la protection de sa section
//!   ([`ImageLayout`]).
//!
//! Une page de la section naît à la première faute d'une vue qui la touche
//! (page prototype), puis toutes les vues projettent la même page physique
//! (`PageUsage::Section`, entrée marquée `paging::PTE_SHARED`). Une page en
//! copie sur écriture (`WRITECOPY` : sections d'image inscriptibles, vues
//! `PAGE_WRITECOPY`) est copiée dans une page privée de la vue à sa première
//! écriture (`mm::fault`). La section rend ses pages quand disparaît sa
//! dernière référence : son créateur et chacune de ses vues en tiennent une.
//!
//! Comme sur XP, Mm ne reloge pas une image projetée ailleurs qu'à sa base :
//! la vue rend `STATUS_IMAGE_NOT_AT_BASE`, et `ntdll` applique les relocations
//! sur des pages qui se copient à l'écriture.
//!
//! Le fichier est une copie de ses octets en mémoire, en attendant les objets
//! fichier d'Io : les écritures dans une vue partagée d'une section de fichier
//! n'y retournent pas.
//!
//! L'objet section d'Ob ([`SECTION_TYPE`], [`create_section_object`]) tient
//! la section ; une vue la tient aussi, et survit donc à la fermeture du
//! dernier handle de l'objet, comme sur XP.
//!
//! Pas encore : appels système (NtCreateSection, M3), `SEC_RESERVE`,
//! NtExtendSection, vues dans l'espace système, retour au fichier.
//!
//! WI7e Ch.5 §Section Objects

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::ntstatus::{
    NtStatus, STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER,
    STATUS_MAPPED_FILE_SIZE_ZERO, STATUS_NO_MEMORY, STATUS_SECTION_PROTECTION, STATUS_SECTION_TOO_BIG,
};
use hal::sync::KSpinLock;
use ob::{AccessMask, GenericMapping, Object, ObjectType};

use crate::pfn::{self, PageUsage};
use crate::vad::PageProtect;
use crate::Pfn;

const PAGE: u64 = 4096;

pub const SECTION_QUERY: AccessMask = AccessMask(0x0001);
pub const SECTION_MAP_WRITE: AccessMask = AccessMask(0x0002);
pub const SECTION_MAP_READ: AccessMask = AccessMask(0x0004);
pub const SECTION_MAP_EXECUTE: AccessMask = AccessMask(0x0008);
pub const SECTION_EXTEND_SIZE: AccessMask = AccessMask(0x0010);
pub const SECTION_ALL_ACCESS: AccessMask = AccessMask(AccessMask::STANDARD_RIGHTS_REQUIRED.0 | 0x1F);

/// Le type `Section` : son corps est la section (`Arc<Section>`).
pub static SECTION_TYPE: ObjectType = ObjectType::new(
    "Section",
    SECTION_ALL_ACCESS,
    GenericMapping {
        read: AccessMask(AccessMask::STANDARD_RIGHTS_READ.0 | SECTION_QUERY.0 | SECTION_MAP_READ.0),
        write: AccessMask(AccessMask::STANDARD_RIGHTS_WRITE.0 | SECTION_MAP_WRITE.0),
        execute: AccessMask(AccessMask::STANDARD_RIGHTS_EXECUTE.0 | SECTION_MAP_EXECUTE.0),
        all: SECTION_ALL_ACCESS,
    },
);

/// L'objet section de `section` (ObCreateObject), sans nom ni handle.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn create_section_object(section: Arc<Section>) -> Arc<Object<Arc<Section>>> {
    ob::create_object(&SECTION_TYPE, section)
}

/// Ce que contient une section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    /// Adossée au fichier d'échange : de la mémoire partagée.
    Pagefile,
    /// Les octets d'un fichier de données.
    DataFile,
    /// Une image PE.
    Image,
}

/// Ce qu'une section d'image sait de son PE (NtQuerySection,
/// `SectionImageInformation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageInfo {
    pub image_base: u64,
    /// RVA du point d'entrée.
    pub entry_point: u64,
    /// Taille en mémoire, arrondie à la page.
    pub size_of_image: u64,
    /// IMAGE_FILE_RELOCS_STRIPPED : l'image ne quitte pas sa base.
    pub relocs_stripped: bool,
}

/// La disposition d'une image en mémoire, tirée de son PE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageLayout {
    pub info: ImageInfo,
    /// La protection des pages de l'image, en suites (nombre de pages,
    /// protection) qui la couvrent dans l'ordre.
    pub protects: Vec<(u64, PageProtect)>,
    /// Ce qui vient du fichier : (RVA, décalage dans le fichier, longueur).
    copies: Vec<(u64, u64, u64)>,
}

impl ImageLayout {
    /// Lit la disposition de l'image `file` ; `STATUS_INVALID_IMAGE_FORMAT`
    /// si ce n'est pas un PE32 i386 cohérent : en-têtes ou données de section
    /// hors du fichier, sections hors de l'image, pas dans l'ordre ou pas
    /// alignées sur la page.
    ///
    /// Les en-têtes sont en lecture seule, jusqu'à la première section ;
    /// chaque section garde sa protection ([`image_protection`]) jusqu'à la
    /// suivante, ou la fin de l'image. Une image alignée sous la page
    /// (section et fichier alignés pareil) est tout entière
    /// `EXECUTE_WRITECOPY`, comme sur XP.
    pub fn new(file: &[u8]) -> Result<Self, NtStatus> {
        let invalid = |_| STATUS_INVALID_IMAGE_FORMAT;
        let pe = pe::Pe32::parse(file).map_err(invalid)?;
        let (header, opt) = (pe.file_header(), pe.optional_header());
        let size_of_image = u64::from(opt.size_of_image).next_multiple_of(PAGE);
        let size_of_headers = u64::from(opt.size_of_headers);
        let section_alignment = u64::from(opt.section_alignment);
        if size_of_image == 0 || size_of_headers > file.len() as u64 || size_of_headers > size_of_image {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        let info = ImageInfo {
            image_base: u64::from(opt.image_base),
            entry_point: u64::from(opt.address_of_entry_point),
            size_of_image,
            relocs_stripped: header.characteristics & pe::FILE_RELOCS_STRIPPED != 0,
        };
        let pages = size_of_image / PAGE;
        let mut copies = alloc::vec![(0, 0, size_of_headers)];
        let mut protects: Vec<(u64, PageProtect)> = Vec::new();
        // (first page, protection) of each region, from the headers on.
        let mut starts = alloc::vec![(0, PageProtect::READONLY)];
        let mut end_of_previous = size_of_headers;
        for section in pe.sections() {
            let (va, virtual_size) = (u64::from(section.virtual_address), u64::from(section.virtual_size));
            let (raw_offset, raw_size) = (u64::from(section.pointer_to_raw_data), u64::from(section.size_of_raw_data));
            let size = if virtual_size == 0 { raw_size } else { virtual_size };
            let copied = raw_size.min(size);
            if va < end_of_previous
                || va + size > size_of_image
                || (copied != 0 && raw_offset + copied > file.len() as u64)
            {
                return Err(STATUS_INVALID_IMAGE_FORMAT);
            }
            if section_alignment >= PAGE && !va.is_multiple_of(PAGE) {
                return Err(STATUS_INVALID_IMAGE_FORMAT);
            }
            if copied != 0 {
                copies.push((va, raw_offset, copied));
            }
            starts.push((va / PAGE, image_protection(section.characteristics)));
            end_of_previous = va + size;
        }
        if section_alignment < PAGE {
            protects.push((pages, PageProtect::EXECUTE_WRITECOPY));
        } else {
            for (i, &(first, protect)) in starts.iter().enumerate() {
                let next = starts.get(i + 1).map_or(pages, |&(next, _)| next);
                if next > first {
                    protects.push((next - first, protect));
                }
            }
        }
        Ok(Self { info, protects, copies })
    }

    /// Remplit `page`, la page `index` de l'image, depuis `file` : les octets
    /// des en-têtes et des sections qui y tombent, des zéros ailleurs.
    pub fn fill(&self, file: &[u8], index: u64, page: &mut [u8]) {
        page.fill(0);
        let (start, end) = (index * PAGE, (index + 1) * PAGE);
        for &(rva, offset, len) in &self.copies {
            let (from, to) = (rva.max(start), (rva + len).min(end));
            if from < to {
                let source = (offset + from - rva) as usize;
                page[(from - start) as usize..(to - start) as usize]
                    .copy_from_slice(&file[source..source + (to - from) as usize]);
            }
        }
    }
}

/// La protection des pages d'une section d'image, d'après ses
/// caractéristiques (`SCN_MEM_*`) : une section inscriptible se copie à
/// l'écriture, sauf si elle est partagée (`SCN_MEM_SHARED`).
pub fn image_protection(characteristics: u32) -> PageProtect {
    let has = |flag| characteristics & flag != 0;
    let (execute, read, write, shared) =
        (has(pe::SCN_MEM_EXECUTE), has(pe::SCN_MEM_READ), has(pe::SCN_MEM_WRITE), has(pe::SCN_MEM_SHARED));
    match (execute, write, shared) {
        (true, true, true) => PageProtect::EXECUTE_READWRITE,
        (true, true, false) => PageProtect::EXECUTE_WRITECOPY,
        (true, false, _) if read => PageProtect::EXECUTE_READ,
        (true, false, _) => PageProtect::EXECUTE,
        (false, true, true) => PageProtect::READWRITE,
        (false, true, false) => PageProtect::WRITECOPY,
        (false, false, _) if read => PageProtect::READONLY,
        (false, false, _) => PageProtect::NOACCESS,
    }
}

/// Une vue avec la protection `view` est permise sur une section créée avec
/// `section` : pas d'exécution sans une section exécutable, pas d'écriture
/// partagée sans une section inscriptible ; la copie sur écriture et la
/// lecture vont avec toute section.
pub fn view_protection_allowed(section: PageProtect, view: PageProtect) -> bool {
    let writes_shared = |p: PageProtect| p.writable() && !p.copy_on_write();
    (!view.executable() || section.executable()) && (!writes_shared(view) || writes_shared(section))
}

/// D'où viennent les pages d'une section.
enum Source {
    Zero,
    File(Arc<[u8]>),
    Image { file: Arc<[u8]>, layout: ImageLayout },
}

impl Source {
    /// Remplit `page`, la page `index` de la section.
    fn fill(&self, index: u64, page: &mut [u8]) {
        match self {
            Source::Zero => page.fill(0),
            Source::File(file) => {
                page.fill(0);
                let start = (index * PAGE).min(file.len() as u64) as usize;
                let end = ((index + 1) * PAGE).min(file.len() as u64) as usize;
                page[..end - start].copy_from_slice(&file[start..end]);
            }
            Source::Image { file, layout } => layout.fill(file, index, page),
        }
    }
}

/// Une section : sa taille, sa protection, la source de ses pages et celles
/// qui existent déjà.
pub struct Section {
    kind: SectionKind,
    size: u64,
    protect: PageProtect,
    source: Source,
    /// Les pages créées, par indice ; un verrou tournant, pris sous celui de
    /// la VAD par la faute de page.
    pages: KSpinLock<BTreeMap<u64, Pfn>>,
}

impl Section {
    fn new(kind: SectionKind, size: u64, protect: PageProtect, source: Source) -> Arc<Self> {
        Arc::new(Self { kind, size, protect, source, pages: KSpinLock::new(BTreeMap::new()) })
    }

    /// Une section de `size` octets adossée au fichier d'échange : des pages
    /// à zéro, partagées.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_pagefile(size: u64, protect: PageProtect) -> Result<Arc<Self>, NtStatus> {
        check_protection(protect)?;
        if size == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self::new(SectionKind::Pagefile, size, protect, Source::Zero))
    }

    /// Une section du fichier de données `file`, de `size` octets (0 : tout
    /// le fichier, qui ne peut être vide) ; `STATUS_SECTION_TOO_BIG` au-delà
    /// du fichier.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_data_file(file: Arc<[u8]>, size: u64, protect: PageProtect) -> Result<Arc<Self>, NtStatus> {
        check_protection(protect)?;
        let length = file.len() as u64;
        if length == 0 {
            return Err(STATUS_MAPPED_FILE_SIZE_ZERO);
        }
        if size > length {
            return Err(STATUS_SECTION_TOO_BIG);
        }
        let size = if size == 0 { length } else { size };
        Ok(Self::new(SectionKind::DataFile, size, protect, Source::File(file)))
    }

    /// Une section de l'image PE32 `file` ([`ImageLayout`]).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_image(file: Arc<[u8]>) -> Result<Arc<Self>, NtStatus> {
        let layout = ImageLayout::new(&file)?;
        let size = layout.info.size_of_image;
        Ok(Self::new(SectionKind::Image, size, PageProtect::EXECUTE_WRITECOPY, Source::Image { file, layout }))
    }

    pub fn kind(&self) -> SectionKind {
        self.kind
    }

    /// Sa taille en octets ; celle de l'image en mémoire pour une image.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// La protection donnée à sa création ; `EXECUTE_WRITECOPY` pour une
    /// image.
    pub fn protect(&self) -> PageProtect {
        self.protect
    }

    /// La disposition de l'image, pour une section d'image.
    pub fn image(&self) -> Option<&ImageLayout> {
        match &self.source {
            Source::Image { layout, .. } => Some(layout),
            _ => None,
        }
    }

    /// Le nombre de pages créées.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn resident_pages(&self) -> usize {
        self.pages.lock().len()
    }

    /// La page `index`, créée et remplie au premier besoin ;
    /// `STATUS_NO_MEMORY` sans page libre.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub(crate) fn page(&self, index: u64) -> Result<Pfn, NtStatus> {
        let mut pages = self.pages.lock();
        if let Some(&page) = pages.get(&index) {
            return Ok(page);
        }
        let page = pfn::allocate_page(PageUsage::Section).ok_or(STATUS_NO_MEMORY)?;
        let hhdm = crate::HHDM_OFFSET.load(core::sync::atomic::Ordering::Acquire);
        // SAFETY: a page just allocated, reached through the HHDM, that
        // nothing else uses yet.
        let bytes = unsafe { core::slice::from_raw_parts_mut((hhdm + page.to_phys()) as *mut u8, PAGE as usize) };
        self.source.fill(index, bytes);
        pages.insert(index, page);
        Ok(page)
    }
}

/// Une protection de section : valide, sans garde.
fn check_protection(protect: PageProtect) -> Result<(), NtStatus> {
    if !protect.is_valid() || protect.contains(PageProtect::GUARD) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    Ok(())
}

/// Une vue de `section` avec la protection `view`, à sa création ou à un
/// changement : `STATUS_SECTION_PROTECTION` si la section ne la permet pas
/// ([`view_protection_allowed`]). Une image se copie à l'écriture : y écrire
/// devient `WRITECOPY` ([`PageProtect::with_copy`]).
pub fn view_protection(section: &Section, view: PageProtect) -> Result<PageProtect, NtStatus> {
    let view = if section.kind == SectionKind::Image { view.with_copy() } else { view };
    if view_protection_allowed(section.protect, view) {
        Ok(view)
    } else {
        Err(STATUS_SECTION_PROTECTION)
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        // No view is left (each holds a reference): no page table maps these
        // pages any more.
        for &page in self.pages.lock().values() {
            pfn::free_page(page);
        }
    }
}

/// Une section n'est égale qu'à elle-même.
impl PartialEq for Section {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
}

impl Eq for Section {}

impl core::fmt::Debug for Section {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Section({:?}, {:#x} bytes, {:?})", self.kind, self.size, self.protect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pe::builder::Pe32Builder;
    use pe::{SCN_MEM_EXECUTE as X, SCN_MEM_READ as R, SCN_MEM_SHARED as S, SCN_MEM_WRITE as W};

    const RO: PageProtect = PageProtect::READONLY;
    const RW: PageProtect = PageProtect::READWRITE;
    const RX: PageProtect = PageProtect::EXECUTE_READ;
    const WC: PageProtect = PageProtect::WRITECOPY;
    const ERW: PageProtect = PageProtect::EXECUTE_READWRITE;
    const EWC: PageProtect = PageProtect::EXECUTE_WRITECOPY;

    fn image() -> Vec<u8> {
        Pe32Builder::new(0x40_0000)
            .entry_point(0x1010)
            .section(".text", 0x1000, 0x1800, &[0xC3; 0x300], X | R)
            .section(".data", 0x3000, 0x100, b"data", R | W)
            .section(".bss", 0x4000, 0x2000, &[], R | W)
            .build()
    }

    #[test]
    fn image_pages_take_the_protection_of_their_section() {
        let layout = ImageLayout::new(&image()).unwrap();
        let info =
            ImageInfo { image_base: 0x40_0000, entry_point: 0x1010, size_of_image: 0x6000, relocs_stripped: false };
        assert_eq!(layout.info, info);
        // Headers, .text (two pages, up to .data), .data, .bss (two pages).
        assert_eq!(layout.protects, [(1, RO), (2, RX), (1, WC), (2, WC)]);
    }

    #[test]
    fn image_pages_hold_the_file_bytes_and_zeros_elsewhere() {
        let file = image();
        let layout = ImageLayout::new(&file).unwrap();
        let mut page = [0xAAu8; PAGE as usize];
        layout.fill(&file, 0, &mut page);
        assert_eq!(&page[..2], b"MZ");
        assert_eq!(&page[0x200..], &[0; 0xE00], "after SizeOfHeaders");
        layout.fill(&file, 1, &mut page);
        assert_eq!(&page[..0x300], &[0xC3; 0x300]);
        assert!(page[0x300..].iter().all(|&b| b == 0), "raw data padded with zeros");
        layout.fill(&file, 3, &mut page);
        assert_eq!(&page[..4], b"data");
        assert_eq!(&page[4..0x100], &[0; 0xFC], "VirtualSize 0x100 caps the raw data (0x200)");
        layout.fill(&file, 4, &mut page);
        assert!(page.iter().all(|&b| b == 0), ".bss");
    }

    #[test]
    fn raw_data_past_the_virtual_size_is_not_mapped() {
        let file = Pe32Builder::new(0x40_0000).section(".data", 0x1000, 0x10, &[0x77; 0x200], R).build();
        let layout = ImageLayout::new(&file).unwrap();
        let mut page = [0xAAu8; PAGE as usize];
        layout.fill(&file, 1, &mut page);
        assert_eq!(&page[..0x10], &[0x77; 0x10]);
        assert!(page[0x10..].iter().all(|&b| b == 0), "raw data beyond VirtualSize");
    }

    #[test]
    fn an_image_aligned_below_the_page_is_all_execute_writecopy() {
        let file = Pe32Builder::new(0x40_0000)
            .alignments(0x200, 0x200)
            .section(".text", 0x200, 0x200, &[0x90; 0x200], X | R)
            .section(".data", 0x400, 0x200, &[0x55; 0x200], R | W)
            .build();
        let layout = ImageLayout::new(&file).unwrap();
        assert_eq!(layout.protects, [(1, EWC)]);
        let mut page = [0u8; PAGE as usize];
        layout.fill(&file, 0, &mut page);
        assert_eq!((&page[..2], page[0x200], page[0x400]), (&b"MZ"[..], 0x90, 0x55));
    }

    #[test]
    fn a_broken_image_is_an_invalid_image_format() {
        assert_eq!(ImageLayout::new(b"MZ not a PE"), Err(STATUS_INVALID_IMAGE_FORMAT));
        let truncated = image();
        assert_eq!(ImageLayout::new(&truncated[..0x300]), Err(STATUS_INVALID_IMAGE_FORMAT), ".text raw data cut");
        let overlap = Pe32Builder::new(0x40_0000)
            .section(".a", 0x1000, 0x2000, &[], R)
            .section(".b", 0x2000, 0x1000, &[], R)
            .build();
        assert_eq!(ImageLayout::new(&overlap), Err(STATUS_INVALID_IMAGE_FORMAT), "sections overlap");
        let unaligned = Pe32Builder::new(0x40_0000).section(".a", 0x1800, 0x100, &[], R).build();
        assert_eq!(ImageLayout::new(&unaligned), Err(STATUS_INVALID_IMAGE_FORMAT));
        let mut beyond = image();
        beyond[0x40 + 4 + 20 + 56..][..4].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        assert_eq!(ImageLayout::new(&beyond), Err(STATUS_INVALID_IMAGE_FORMAT), "section past SizeOfImage");
    }

    #[test]
    fn section_characteristics_give_the_page_protection() {
        let cases = [
            (X | R, RX),
            (X, PageProtect::EXECUTE),
            (X | R | W, EWC),
            (X | R | W | S, ERW),
            (R, RO),
            (R | W, WC),
            (R | W | S, RW),
            (0, PageProtect::NOACCESS),
        ];
        for (characteristics, protect) in cases {
            assert_eq!(image_protection(characteristics), protect, "{characteristics:#x}");
        }
        let stripped = Pe32Builder::new(0x40_0000).relocs_stripped().section(".a", 0x1000, 1, &[], R).build();
        assert!(ImageLayout::new(&stripped).unwrap().info.relocs_stripped);
    }

    #[test]
    fn a_view_asks_no_more_than_its_section() {
        assert!(view_protection_allowed(RW, RW));
        assert!(view_protection_allowed(RW, RO));
        assert!(view_protection_allowed(RO, WC), "copy-on-write of a read-only section");
        assert!(view_protection_allowed(WC, WC));
        assert!(view_protection_allowed(ERW, RX));
        assert!(view_protection_allowed(RO, PageProtect::NOACCESS));
        assert!(!view_protection_allowed(RO, RW), "shared write");
        assert!(!view_protection_allowed(WC, RW));
        assert!(!view_protection_allowed(RW, RX), "execution");
        assert!(!view_protection_allowed(RX, ERW));
    }

    #[test]
    fn writing_to_an_image_view_becomes_copy_on_write() {
        let image = Section::create_image(Arc::from(image())).unwrap();
        assert_eq!(view_protection(&image, RW), Ok(WC));
        assert_eq!(view_protection(&image, ERW), Ok(EWC));
        assert_eq!(view_protection(&image, RX), Ok(RX));
        let shared = Section::create_pagefile(PAGE, RO).unwrap();
        assert_eq!(view_protection(&shared, RW), Err(STATUS_SECTION_PROTECTION), "no conversion for data");
        assert_eq!(view_protection(&shared, WC), Ok(WC));
    }

    #[test]
    fn section_creation_checks_its_arguments() {
        assert_eq!(Section::create_pagefile(0, RW).err(), Some(STATUS_INVALID_PARAMETER));
        assert_eq!(Section::create_pagefile(PAGE, RW | RO).err(), Some(STATUS_INVALID_PAGE_PROTECTION));
        assert_eq!(Section::create_pagefile(PAGE, RW | PageProtect::GUARD).err(), Some(STATUS_INVALID_PAGE_PROTECTION));
        let file: Arc<[u8]> = Arc::from(&b"0123456789"[..]);
        assert_eq!(Section::create_data_file(Arc::from(&[][..]), 0, RO).err(), Some(STATUS_MAPPED_FILE_SIZE_ZERO));
        assert_eq!(Section::create_data_file(file.clone(), 11, RO).err(), Some(STATUS_SECTION_TOO_BIG));
        assert_eq!(Section::create_data_file(file.clone(), 0, RO).map(|s| s.size()), Ok(10));
        assert_eq!(Section::create_data_file(file, 4, RO).map(|s| s.size()), Ok(4));
        assert_eq!(Section::create_image(Arc::from(&b"MZ"[..])).err(), Some(STATUS_INVALID_IMAGE_FORMAT));
        let image = Section::create_image(Arc::from(image())).unwrap();
        assert_eq!((image.kind(), image.size(), image.protect()), (SectionKind::Image, 0x6000, EWC));
    }

    #[test]
    fn a_section_object_holds_the_section_and_maps_its_rights() {
        let section = Section::create_pagefile(PAGE, RW).unwrap();
        let object = create_section_object(section.clone());
        assert!(Arc::ptr_eq(&**object, &section), "its body is the section");
        assert_eq!(Arc::strong_count(&section), 2);
        let read = SECTION_TYPE.granted_access(AccessMask::GENERIC_READ);
        assert_eq!(read, AccessMask(0x0002_0005), "READ_CONTROL, query, map for reading");
        assert_eq!(SECTION_TYPE.granted_access(AccessMask::GENERIC_ALL), AccessMask(0x000F_001F));
        drop(object);
        assert_eq!(Arc::strong_count(&section), 1, "a view would keep it, not the object");
    }

    #[test]
    fn a_data_file_page_ends_with_zeros_past_the_file() {
        let bytes: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let source = Source::File(Arc::from(bytes.clone()));
        let mut page = [0xAAu8; PAGE as usize];
        source.fill(1, &mut page);
        assert_eq!(&page[..5000 - 4096], &bytes[4096..]);
        assert!(page[5000 - 4096..].iter().all(|&b| b == 0));
        source.fill(2, &mut page);
        assert!(page.iter().all(|&b| b == 0), "past the end of the file");
    }
}
