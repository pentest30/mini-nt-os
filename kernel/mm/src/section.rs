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
//! Une section de données d'un fichier ouvert (NtCreateSection,
//! `sys::section`) ne lit rien à sa création (ADR-024, proposée) : ses pages
//! sont celles d'un [`FileSegment`], le segment du fichier que partagent
//! toutes ses sections de données tant que le fichier ne change pas (le
//! `DataSectionObject` des SECTION_OBJECT_POINTERS de NT ; Io le retrouve,
//! `io::section_cache`). La première faute sur une page d'une vue la fait
//! lire du fichier ([`FileSegment::read_in`], par un [`FileReader`] d'Io),
//! verrou de la VAD relâché, à l'IRQL de la faute (sous DISPATCH_LEVEL),
//! avec les pages absentes de ses 64 Kio alignés (MmMakeSegmentResident de
//! ReactOS) ; puis la faute reprend (STATUS_MM_RESTART_OPERATION de
//! ReactOS). Les écritures dans une vue partagée vont aux pages du segment,
//! que voient les autres vues et sections du fichier, mais pas au fichier.
//!
//! Une section d'image d'un fichier ouvert ne lit à sa création que ses
//! en-têtes ([`Section::create_paged_image`]) : une page de l'image se
//! remplit à sa première faute des pages du fichier qu'elle demande
//! ([`ImageLayout::file_pages`]), lues dans le segment du fichier comme pour
//! une section de données, verrou de la VAD relâché. Io refuse d'écrire ou
//! d'effacer le fichier tant qu'une section d'image le tient (le jeton que
//! garde la section, `io::section_cache::IMAGES`), comme MmFlushImageSection
//! de NT : une DLL chargée ne change pas sous ses vues. Les sections créées
//! par le noyau d'octets déjà en mémoire (NLS, ntdll, tests) gardent ces
//! octets ([`Section::create_image`], [`Section::create_data_file`]).
//!
//! L'objet section d'Ob ([`SECTION_TYPE`], [`create_section_object`]) tient
//! la section ; une vue la tient aussi, et survit donc à la fermeture du
//! dernier handle de l'objet, comme sur XP.
//!
//! Une section du fichier d'échange peut naître réservée (`SEC_RESERVE`) :
//! ses pages ne sont utilisables qu'une fois commitées, par
//! NtAllocateVirtualMemory(`MEM_COMMIT`) dans l'une de ses vues. L'engagement
//! est celui de la section ([`Section::commit`]) : une page commitée dans une
//! vue l'est dans toutes, dans chaque processus, comme les pages prototypes
//! d'XP. Elle peut aussi être basée (`SEC_BASED`) : sa création lui donne une
//! adresse, la même dans chaque processus, cherchée du haut vers le bas sous
//! [`HIGH_SECTION_BASE`] parmi celles des autres sections basées ; une vue
//! sans adresse demandée y va. La section partagée de `csrss` (1 Mio) tombe
//! ainsi en `0x7F6F0000`, comme sur XP.
//!
//! Les appels système (NtCreateSection, NtOpenSection, NtMapViewOfSection,
//! NtUnmapViewOfSection) sont dans `ntoskrnl::sys::section`.
//!
//! Pas encore : le décommit des pages d'une section, `SEC_BASED` pour un
//! fichier, NtExtendSection, vues dans l'espace système d'une section de
//! fichier, retour au fichier (pages modifiées), cohérence avec les
//! écritures du fichier (une page déjà lue garde ce qu'elle avait, une page
//! lue après l'écriture voit le fichier écrit), pages d'image à la faute.
//!
//! WI7e Ch.5 §Section Objects

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER,
    STATUS_IN_PAGE_ERROR, STATUS_MAPPED_FILE_SIZE_ZERO, STATUS_NO_MEMORY, STATUS_SECTION_PROTECTION,
    STATUS_SECTION_TOO_BIG,
};
use hal::sync::KSpinLock;
use ob::{AccessMask, GenericMapping, Object, ObjectType};

use crate::pfn::{self, PageUsage};
use crate::vad::{PageProtect, USER_VA_END};
use crate::virtual_alloc::{ALLOC_GRANULARITY, USER_VA_START};
use crate::Pfn;

const PAGE: u64 = 4096;

/// MmHighSectionBase : les sections basées vont sous cette adresse
/// (exclue), 8 Mio sous le haut du mode utilisateur.
pub const HIGH_SECTION_BASE: u64 = USER_VA_END - 0x80_0000;

/// Les plages des sections basées (début → fin exclue), de tous les
/// processus.
static BASED_SECTIONS: KSpinLock<BTreeMap<u64, u64>> = KSpinLock::new(BTreeMap::new());

/// MiFindEmptyAddressRangeDownBasedTree : la plus haute plage libre de
/// `size` octets parmi `taken`, alignée sur 64 Kio, sous
/// [`HIGH_SECTION_BASE`] et au-dessus du bas du mode utilisateur.
fn find_based_range(taken: &BTreeMap<u64, u64>, size: u64) -> Option<u64> {
    let mut top = HIGH_SECTION_BASE;
    // From the highest range down: each gap is tried above it.
    for (&start, &end) in taken.range(..HIGH_SECTION_BASE).rev().chain(core::iter::once((&0, &0))) {
        if let Some(candidate) = top.checked_sub(size).map(|at| at & !(ALLOC_GRANULARITY - 1)) {
            if candidate >= end.max(USER_VA_START) {
                return Some(candidate);
            }
        }
        top = top.min(start);
    }
    None
}

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
    /// Sous-système (`IMAGE_SUBSYSTEM_*`) et sa version, pour le PEB.
    pub subsystem: u16,
    pub subsystem_version: (u16, u16),
    /// Pile de ses threads : taille réservée, taille commitée.
    pub stack_reserve: u64,
    pub stack_commit: u64,
    /// `IMAGE_FILE_MACHINE_*`, et les `IMAGE_FILE_*` de l'en-tête du fichier.
    pub machine: u16,
    pub characteristics: u16,
    /// `IMAGE_DLLCHARACTERISTICS_*` et `LoaderFlags` de l'en-tête optionnel.
    pub dll_characteristics: u16,
    pub loader_flags: u32,
    /// Elle a du code : `SizeOfCode`, ou un point d'entrée.
    pub contains_code: bool,
    /// La taille de son fichier.
    pub file_size: u64,
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
        Self::parse(file, file.len() as u64)
    }

    /// Comme [`new`](Self::new), d'après `bytes`, le début d'un fichier de
    /// `file_size` octets qui tient ses en-têtes et les données de ses
    /// sections ; ce qui manque à `bytes` est `STATUS_INVALID_IMAGE_FORMAT`.
    pub fn parse(bytes: &[u8], file_size: u64) -> Result<Self, NtStatus> {
        Self::parse_within(bytes, file_size, file_size.min(bytes.len() as u64))
    }

    /// Comme [`parse`](Self::parse), d'après `head`, le début d'un fichier
    /// de `file_size` octets qui tient au moins ses en-têtes PE (sa table des
    /// sections) : les données des sections sont à lire du fichier
    /// ([`file_pages`](Self::file_pages)), dans sa taille.
    pub fn parse_head(head: &[u8], file_size: u64) -> Result<Self, NtStatus> {
        Self::parse_within(head, file_size, file_size)
    }

    /// [`parse`](Self::parse) : les en-têtes et les données des sections
    /// doivent tenir dans les `available` premiers octets du fichier.
    fn parse_within(bytes: &[u8], file_size: u64, available: u64) -> Result<Self, NtStatus> {
        let invalid = |_| STATUS_INVALID_IMAGE_FORMAT;
        // Pe32 reads its optional header and section table without checking
        // they are there: a short file is refused before.
        headers_end(bytes).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
        let pe = pe::Pe32::parse(bytes).map_err(invalid)?;
        let (header, opt) = (pe.file_header(), pe.optional_header());
        let size_of_image = u64::from(opt.size_of_image).next_multiple_of(PAGE);
        let size_of_headers = u64::from(opt.size_of_headers);
        let section_alignment = u64::from(opt.section_alignment);
        if size_of_image == 0 || size_of_headers > available || size_of_headers > size_of_image {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        let info = ImageInfo {
            image_base: u64::from(opt.image_base),
            entry_point: u64::from(opt.address_of_entry_point),
            size_of_image,
            relocs_stripped: header.characteristics & pe::FILE_RELOCS_STRIPPED != 0,
            subsystem: opt.subsystem,
            subsystem_version: (opt.major_subsystem_version, opt.minor_subsystem_version),
            stack_reserve: u64::from(opt.size_of_stack_reserve),
            stack_commit: u64::from(opt.size_of_stack_commit),
            machine: header.machine,
            characteristics: header.characteristics,
            dll_characteristics: opt.dll_characteristics,
            loader_flags: opt.loader_flags,
            contains_code: opt.size_of_code != 0 || opt.address_of_entry_point != 0,
            file_size,
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
            if va < end_of_previous || va + size > size_of_image || (copied != 0 && raw_offset + copied > available) {
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
        self.fill_from(index, page, |offset, out| {
            let offset = offset as usize;
            out.copy_from_slice(&file[offset..offset + out.len()]);
        });
    }

    /// Comme [`fill`](Self::fill), `read` copiant les octets du fichier à
    /// partir d'une place dans un morceau de la page.
    fn fill_from(&self, index: u64, page: &mut [u8], mut read: impl FnMut(u64, &mut [u8])) {
        page.fill(0);
        let (start, end) = (index * PAGE, (index + 1) * PAGE);
        for &(rva, offset, len) in &self.copies {
            let (from, to) = (rva.max(start), (rva + len).min(end));
            if from < to {
                read(offset + from - rva, &mut page[(from - start) as usize..(to - start) as usize]);
            }
        }
    }

    /// Les pages du fichier dont la page `index` de l'image prend des octets
    /// (une page peut revenir : les en-têtes et une section dans la même).
    pub fn file_pages(&self, index: u64) -> impl Iterator<Item = u64> + '_ {
        let (start, end) = (index * PAGE, (index + 1) * PAGE);
        self.copies.iter().flat_map(move |&(rva, offset, len)| {
            let (from, to) = (rva.max(start), (rva + len).min(end));
            // `from` is at or past `rva`: the bytes of the file it takes.
            if from < to {
                (offset + from - rva) / PAGE..(offset + to - rva).div_ceil(PAGE)
            } else {
                0..0
            }
        })
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

/// La fin des en-têtes d'un PE32 au début de `head` : en-tête optionnel et
/// table des sections compris ; `None` si `head` ne les tient pas.
fn headers_end(head: &[u8]) -> Option<usize> {
    let u16_at = |at: usize| head.get(at..at.checked_add(2)?).map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])));
    let u32_at =
        |at: usize| head.get(at..at.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let optional_header = u32_at(0x3C)?.checked_add(4 + core::mem::size_of::<pe::ImageFileHeader>())?;
    let file_header = optional_header - core::mem::size_of::<pe::ImageFileHeader>();
    let sections = u16_at(file_header + 2)?;
    let optional_size = u16_at(file_header + 16)?;
    let table = optional_header.checked_add(optional_size)?;
    let end = table
        .checked_add(sections * core::mem::size_of::<pe::ImageSectionHeader>())?
        .max(optional_header.checked_add(core::mem::size_of::<pe::ImageOptionalHeader32>())?);
    (end <= head.len()).then_some(end)
}

/// Ce qui lit un fichier pour le segment de ses sections de données : Io,
/// par `ntoskrnl::sys::section`.
pub trait FileReader: Send + Sync {
    /// Lit les octets du fichier à partir de `offset` dans `buffer` (de la
    /// mémoire du noyau) ; rend combien, moins à la fin du fichier.
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL, sans verrou tournant tenu : l'IRQL d'une faute de
    /// page. Peut bloquer.
    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, NtStatus>;
}

/// Les pages qu'une faute fait lire ensemble : 64 Kio, alignés
/// (MmMakeSegmentResident de ReactOS pour un fichier de données).
pub const READ_CLUSTER_PAGES: u64 = 16;

/// Les pages lues des fichiers pour leurs segments, depuis le démarrage.
static FILE_PAGES_READ: AtomicU64 = AtomicU64::new(0);

/// Les pages lues des fichiers pour leurs segments depuis le démarrage.
///
/// # IRQL
/// Tout niveau.
pub fn file_pages_read() -> u64 {
    FILE_PAGES_READ.load(Ordering::Relaxed)
}

/// Le segment d'un fichier : ses pages lues, que partagent toutes ses
/// sections de données (le `DataSectionObject` de NT). Il ne lit rien à sa
/// création ; [`read_in`](Self::read_in) lit une page à sa première faute.
/// Ses pages restent jusqu'à sa disparition, avec sa dernière section.
pub struct FileSegment {
    reader: Box<dyn FileReader>,
    /// La taille du fichier à la création du segment.
    size: u64,
    /// Les pages lues, par indice dans le fichier.
    pages: KSpinLock<BTreeMap<u64, Pfn>>,
}

impl FileSegment {
    /// Le segment d'un fichier de `size` octets, que `reader` lit.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new(reader: Box<dyn FileReader>, size: u64) -> Arc<Self> {
        Arc::new(Self { reader, size, pages: KSpinLock::new(BTreeMap::new()) })
    }

    /// La taille du fichier à sa création.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Le nombre de pages lues.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn resident_pages(&self) -> usize {
        self.pages.lock().len()
    }

    /// La page `index`, si elle est lue.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn resident(&self, index: u64) -> Option<Pfn> {
        self.pages.lock().get(&index).copied()
    }

    /// Copie dans `out` les octets du fichier à partir de `offset`, de ses
    /// pages lues ; `false` (`out` en partie rempli) si l'une ne l'est pas.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    fn copy_resident(&self, offset: u64, out: &mut [u8]) -> bool {
        let pages = self.pages.lock();
        let hhdm = crate::HHDM_OFFSET.load(Ordering::Acquire);
        let mut done = 0;
        while done < out.len() {
            let at = offset + done as u64;
            let Some(frame) = pages.get(&(at / PAGE)) else { return false };
            let within = (at % PAGE) as usize;
            let count = (PAGE as usize - within).min(out.len() - done);
            // SAFETY: a page of the segment, kept until it is dropped (the
            // lock is held), read through the HHDM; `out` is kernel memory.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    ((hhdm + frame.to_phys()) as *const u8).add(within),
                    out[done..].as_mut_ptr(),
                    count,
                );
            }
            done += count;
        }
        true
    }

    /// MmMakeSegmentResident : lit la page `index` du fichier, avec celles
    /// qui manquent autour d'elle dans ses 64 Kio alignés
    /// ([`READ_CLUSTER_PAGES`], [`missing_run`]), par une seule lecture ; des
    /// zéros après la fin du fichier. Rien à faire si elle est déjà lue ; une
    /// page lue entre-temps par une autre faute garde la sienne.
    ///
    /// # Errors
    /// `STATUS_IN_PAGE_ERROR` si la lecture échoue (rien n'est gardé),
    /// `STATUS_NO_MEMORY` sans page libre.
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL, sans verrou tournant tenu (le lecteur peut
    /// bloquer). Peut bloquer.
    pub fn read_in(&self, index: u64) -> Result<(), NtStatus> {
        let pages = self.size.div_ceil(PAGE).max(index + 1);
        let (first, end) = {
            let resident = self.pages.lock();
            if resident.contains_key(&index) {
                return Ok(());
            }
            missing_run(index, pages, |page| resident.contains_key(&page))
        };
        let mut buffer = alloc::vec![0u8; ((end - first) * PAGE) as usize];
        let from = first * PAGE;
        let wanted = (end * PAGE).min(self.size.max(from)) - from;
        if wanted != 0 {
            // Fewer bytes than asked (the file got shorter): zeros after.
            self.reader.read(from, &mut buffer[..wanted as usize]).map_err(|_| STATUS_IN_PAGE_ERROR)?;
        }
        let hhdm = crate::HHDM_OFFSET.load(Ordering::Acquire);
        let mut frames = Vec::with_capacity((end - first) as usize);
        for (page, bytes) in (first..end).zip(buffer.chunks_exact(PAGE as usize)) {
            let Some(frame) = pfn::allocate_page(PageUsage::Section) else {
                frames.into_iter().for_each(|(_, frame)| pfn::free_page(frame));
                return Err(STATUS_NO_MEMORY);
            };
            // SAFETY: a page just allocated, reached through the HHDM, that
            // nothing else uses yet.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), (hhdm + frame.to_phys()) as *mut u8, bytes.len()) };
            frames.push((page, frame));
        }
        let mut resident = self.pages.lock();
        let mut inserted = 0;
        for (page, frame) in frames {
            match resident.entry(page) {
                alloc::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(frame);
                    inserted += 1;
                }
                // Read meanwhile by another fault: its page may be mapped.
                alloc::collections::btree_map::Entry::Occupied(_) => pfn::free_page(frame),
            }
        }
        FILE_PAGES_READ.fetch_add(inserted, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for FileSegment {
    fn drop(&mut self) {
        // Its last section is gone, and every view held one: no page table
        // maps these pages any more.
        for &page in self.pages.lock().values() {
            pfn::free_page(page);
        }
    }
}

impl core::fmt::Debug for FileSegment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FileSegment({:#x} bytes, {} pages read)", self.size, self.resident_pages())
    }
}

/// Les pages à lire pour la page `index` d'un fichier de `pages` pages :
/// la suite des pages non lues (`resident` dit celles qui le sont) qui la
/// contient, dans ses [`READ_CLUSTER_PAGES`] alignées. Rend (première,
/// fin exclue).
pub fn missing_run(index: u64, pages: u64, resident: impl Fn(u64) -> bool) -> (u64, u64) {
    let cluster = index - index % READ_CLUSTER_PAGES;
    let limit = (cluster + READ_CLUSTER_PAGES).min(pages);
    let mut first = index;
    while first > cluster && !resident(first - 1) {
        first -= 1;
    }
    let mut end = index + 1;
    while end < limit && !resident(end) {
        end += 1;
    }
    (first, end)
}

/// D'où viennent les pages d'une section.
enum Source {
    Zero,
    File(Arc<[u8]>),
    Image {
        file: Arc<[u8]>,
        layout: ImageLayout,
    },
    /// Le segment d'un fichier : ses pages se lisent à la faute.
    Segment(Arc<FileSegment>),
    /// Une image dont les octets se lisent du segment de son fichier à la
    /// faute ; `_held` retient ce qui empêche d'écrire le fichier (Io).
    PagedImage {
        segment: Arc<FileSegment>,
        layout: ImageLayout,
        _held: Option<Arc<dyn Any + Send + Sync>>,
    },
}

impl Source {
    /// Remplit `page`, la page `index` de la section, pour une source en
    /// mémoire.
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
            Source::Segment(_) | Source::PagedImage { .. } => {
                unreachable!("a file's pages are read in, not filled")
            }
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
    /// `SEC_RESERVE` : un bit par page commitée. `None` : toutes le sont.
    committed: Option<KSpinLock<Vec<u64>>>,
    /// `SEC_BASED` : son adresse dans chaque processus.
    based: Option<u64>,
    /// Le chemin du fichier d'une image, s'il est connu : le nom du processus
    /// qu'on en crée.
    file_name: Option<String>,
    /// Les pages créées, par indice ; un verrou tournant, pris sous celui de
    /// la VAD par la faute de page.
    pages: KSpinLock<BTreeMap<u64, Pfn>>,
}

impl Section {
    fn new(kind: SectionKind, size: u64, protect: PageProtect, source: Source) -> Arc<Self> {
        Self::named(kind, size, protect, source, None)
    }

    fn named(
        kind: SectionKind,
        size: u64,
        protect: PageProtect,
        source: Source,
        file_name: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            kind,
            size,
            protect,
            source,
            committed: None,
            based: None,
            file_name,
            pages: KSpinLock::new(BTreeMap::new()),
        })
    }

    /// Une section de `size` octets adossée au fichier d'échange : des pages
    /// à zéro, partagées.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_pagefile(size: u64, protect: PageProtect) -> Result<Arc<Self>, NtStatus> {
        Self::create_shared(size, protect, false, false)
    }

    /// Une section de `size` octets adossée au fichier d'échange, ses pages
    /// réservées avec `reserve` (`SEC_RESERVE`, voir [`commit`](Self::commit))
    /// et basée avec `based` (`SEC_BASED`) : son adresse, prise parmi celles
    /// des sections basées (`STATUS_NO_MEMORY` sans place), lui reste jusqu'à
    /// sa destruction.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_shared(size: u64, protect: PageProtect, reserve: bool, based: bool) -> Result<Arc<Self>, NtStatus> {
        check_protection(protect)?;
        if size == 0 || size > USER_VA_END {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let pages = size.div_ceil(PAGE);
        let committed = reserve.then(|| KSpinLock::new(alloc::vec![0u64; pages.div_ceil(64) as usize]));
        let based = match based {
            false => None,
            true => {
                let span = pages * PAGE;
                let mut taken = BASED_SECTIONS.lock();
                let start = find_based_range(&taken, span).ok_or(STATUS_NO_MEMORY)?;
                taken.insert(start, start + span);
                Some(start)
            }
        };
        Ok(Arc::new(Self {
            kind: SectionKind::Pagefile,
            size,
            protect,
            source: Source::Zero,
            committed,
            based,
            file_name: None,
            pages: KSpinLock::new(BTreeMap::new()),
        }))
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

    /// Une section de données du fichier dont `segment` tient les pages, de
    /// `size` octets (0 : tout le fichier, qui ne peut être vide) ;
    /// `STATUS_SECTION_TOO_BIG` au-delà du fichier. Rien n'est lu : ses pages
    /// sont celles du segment, lues à leur première faute.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_paged_data_file(
        segment: Arc<FileSegment>,
        size: u64,
        protect: PageProtect,
    ) -> Result<Arc<Self>, NtStatus> {
        check_protection(protect)?;
        let length = segment.size();
        if length == 0 {
            return Err(STATUS_MAPPED_FILE_SIZE_ZERO);
        }
        if size > length {
            return Err(STATUS_SECTION_TOO_BIG);
        }
        let size = if size == 0 { length } else { size };
        Ok(Self::new(SectionKind::DataFile, size, protect, Source::Segment(segment)))
    }

    /// Le segment du fichier d'une section de données créée par
    /// [`create_paged_data_file`](Self::create_paged_data_file).
    pub fn file_segment(&self) -> Option<&Arc<FileSegment>> {
        match &self.source {
            Source::Segment(segment) => Some(segment),
            _ => None,
        }
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

    /// Comme [`create_image`](Self::create_image), pour l'image du fichier
    /// `file_name` (NtCreateSection), qui nommera le processus qu'on en crée.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_image_of(file: Arc<[u8]>, file_name: &str) -> Result<Arc<Self>, NtStatus> {
        let size = file.len() as u64;
        Self::create_image_from(file, size, file_name)
    }

    /// Comme [`create_image_of`](Self::create_image_of), d'après `bytes`, le
    /// début d'un fichier de `file_size` octets qui tient ses en-têtes et les
    /// données de ses sections.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_image_from(bytes: Arc<[u8]>, file_size: u64, file_name: &str) -> Result<Arc<Self>, NtStatus> {
        let layout = ImageLayout::parse(&bytes, file_size)?;
        let size = layout.info.size_of_image;
        let source = Source::Image { file: bytes, layout };
        Ok(Self::named(SectionKind::Image, size, PageProtect::EXECUTE_WRITECOPY, source, Some(file_name.into())))
    }

    /// La section d'image du fichier `file_name` (NtCreateSection), dont
    /// `head`, son début, tient les en-têtes et dont `segment` lit les pages
    /// à la faute ; elle garde `held` (le jeton d'Io qui interdit d'écrire
    /// le fichier tant qu'elle vit). Rien d'autre n'est lu.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn create_paged_image(
        head: &[u8],
        segment: Arc<FileSegment>,
        file_name: &str,
        held: Option<Arc<dyn Any + Send + Sync>>,
    ) -> Result<Arc<Self>, NtStatus> {
        let layout = ImageLayout::parse_head(head, segment.size())?;
        let size = layout.info.size_of_image;
        let source = Source::PagedImage { segment, layout, _held: held };
        Ok(Self::named(SectionKind::Image, size, PageProtect::EXECUTE_WRITECOPY, source, Some(file_name.into())))
    }

    /// Le chemin du fichier de l'image, s'il est connu.
    pub fn file_name(&self) -> Option<&str> {
        self.file_name.as_deref()
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

    /// `SEC_RESERVE` : ses pages ne sont utilisables qu'une fois commitées.
    pub fn is_reserve(&self) -> bool {
        self.committed.is_some()
    }

    /// `SEC_BASED` : son adresse dans chaque processus.
    pub fn based_address(&self) -> Option<u64> {
        self.based
    }

    /// La page `index` est commitée : toujours, sauf dans une section
    /// `SEC_RESERVE` qui ne l'a pas encore commitée.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn is_committed(&self, index: u64) -> bool {
        self.committed_run(index, 1).0
    }

    /// L'état de la page `index` (commitée ou non), et combien de pages, `limit`
    /// au plus, le partagent à partir d'elle.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn committed_run(&self, index: u64, limit: u64) -> (bool, u64) {
        let Some(bits) = &self.committed else { return (true, limit) };
        let bits = bits.lock();
        let at = |page: u64| bits.get((page / 64) as usize).is_some_and(|word| word >> (page % 64) & 1 != 0);
        let state = at(index);
        let pages = self.size.div_ceil(PAGE);
        let count = (index..(index + limit).min(pages)).take_while(|&page| at(page) == state).count() as u64;
        (state, count.max(1))
    }

    /// Commite `count` pages de la section à partir de la page `first`
    /// (NtAllocateVirtualMemory dans une vue) ; celles qui l'étaient le
    /// restent. Rien à faire hors d'une section `SEC_RESERVE`, dont les pages
    /// sont toutes commitées.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn commit(&self, first: u64, count: u64) {
        let Some(bits) = &self.committed else { return };
        let mut bits = bits.lock();
        let pages = self.size.div_ceil(PAGE);
        for page in first..(first + count).min(pages) {
            bits[(page / 64) as usize] |= 1 << (page % 64);
        }
    }

    /// La disposition de l'image, pour une section d'image.
    pub fn image(&self) -> Option<&ImageLayout> {
        match &self.source {
            Source::Image { layout, .. } | Source::PagedImage { layout, .. } => Some(layout),
            _ => None,
        }
    }

    /// Le nombre de pages créées ; celles de son segment pour une section
    /// de données d'un fichier, que partagent ses autres sections.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn resident_pages(&self) -> usize {
        match &self.source {
            Source::Segment(segment) => segment.resident_pages(),
            _ => self.pages.lock().len(),
        }
    }

    /// Écrit `data` dans la section en `offset`, par l'alias du noyau de ses
    /// pages (le HHDM), allouées s'il le faut : toutes ses vues le voient
    /// aussitôt. Pour une section du fichier d'échange que le noyau tient à
    /// jour et que des processus lisent par une vue en lecture seule (la
    /// section partagée de USER, `win32k`).
    ///
    /// # Errors
    /// `STATUS_INVALID_PARAMETER` pour une autre section que du fichier
    /// d'échange, ou au-delà de sa taille ; `STATUS_NO_MEMORY` sans page
    /// libre.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn write_kernel(&self, offset: u64, data: &[u8]) -> Result<(), NtStatus> {
        self.each_kernel_run(offset, data.len(), |page, at, done| {
            let run = &data[done..][..(PAGE as usize - at).min(data.len() - done)];
            // SAFETY: `page` is a page of the section, alive while it is, and
            // `at + run.len()` stays in it; views in user mode may read it
            // meanwhile, as they read KUSER_SHARED_DATA.
            unsafe { core::ptr::copy_nonoverlapping(run.as_ptr(), page.add(at), run.len()) };
            run.len()
        })
    }

    /// Lit `buffer.len()` octets de la section en `offset`, par l'alias du
    /// noyau de ses pages ; voir [`write_kernel`](Self::write_kernel).
    ///
    /// # Errors
    /// Celles de [`write_kernel`](Self::write_kernel).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn read_kernel(&self, offset: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
        let length = buffer.len();
        self.each_kernel_run(offset, length, |page, at, done| {
            let run = (PAGE as usize - at).min(length - done);
            // SAFETY: as in `write_kernel`; `buffer[done..]` holds `run` bytes.
            unsafe { core::ptr::copy_nonoverlapping(page.add(at), buffer[done..].as_mut_ptr(), run) };
            run
        })
    }

    /// Parcourt les `length` octets de la section en `offset`, page par page :
    /// `f` reçoit le début de la page (par le HHDM), l'octet où commencer
    /// dans la page et ce qui est déjà fait ; il rend ce qu'il a fait, jusqu'à
    /// la fin de la page.
    fn each_kernel_run(
        &self,
        offset: u64,
        length: usize,
        mut f: impl FnMut(*mut u8, usize, usize) -> usize,
    ) -> Result<(), NtStatus> {
        let end = offset.checked_add(length as u64).ok_or(STATUS_INVALID_PARAMETER)?;
        if self.kind != SectionKind::Pagefile || end > self.size {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let hhdm = crate::HHDM_OFFSET.load(core::sync::atomic::Ordering::Acquire);
        let mut done = 0;
        while done < length {
            let at = offset + done as u64;
            // A section of the paging file: never a page to read in.
            let page = self.page(at / PAGE)?.ok_or(STATUS_INVALID_PARAMETER)?;
            done += f((hhdm + page.to_phys()) as *mut u8, (at % PAGE) as usize, done);
        }
        Ok(())
    }

    /// La page `index`, créée et remplie au premier besoin ;
    /// `STATUS_NO_MEMORY` sans page libre. `None` pour une page du segment
    /// d'un fichier qui n'est pas encore lue : [`read_in`](Self::read_in)
    /// la lira, sans verrou tournant tenu.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub(crate) fn page(&self, index: u64) -> Result<Option<Pfn>, NtStatus> {
        if let Source::Segment(segment) = &self.source {
            return Ok(segment.resident(index));
        }
        let mut pages = self.pages.lock();
        if let Some(&page) = pages.get(&index) {
            return Ok(Some(page));
        }
        if let Source::PagedImage { segment, layout, .. } = &self.source {
            // The file pages it takes bytes from, read first (`read_in`);
            // once read, they stay with the segment.
            if layout.file_pages(index).any(|page| segment.resident(page).is_none()) {
                return Ok(None);
            }
            let page = pfn::allocate_page(PageUsage::Section).ok_or(STATUS_NO_MEMORY)?;
            let hhdm = crate::HHDM_OFFSET.load(core::sync::atomic::Ordering::Acquire);
            // SAFETY: a page just allocated, reached through the HHDM, that
            // nothing else uses yet.
            let bytes = unsafe { core::slice::from_raw_parts_mut((hhdm + page.to_phys()) as *mut u8, PAGE as usize) };
            layout.fill_from(index, bytes, |offset, out| {
                let read = segment.copy_resident(offset, out);
                debug_assert!(read, "a file page of the image gone from its segment");
            });
            pages.insert(index, page);
            return Ok(Some(page));
        }
        let page = pfn::allocate_page(PageUsage::Section).ok_or(STATUS_NO_MEMORY)?;
        let hhdm = crate::HHDM_OFFSET.load(core::sync::atomic::Ordering::Acquire);
        // SAFETY: a page just allocated, reached through the HHDM, that
        // nothing else uses yet.
        let bytes = unsafe { core::slice::from_raw_parts_mut((hhdm + page.to_phys()) as *mut u8, PAGE as usize) };
        self.source.fill(index, bytes);
        pages.insert(index, page);
        Ok(Some(page))
    }

    /// Lit la page `index` d'une section de données d'un fichier (et ses
    /// voisines, [`FileSegment::read_in`]), ou les pages du fichier dont
    /// prend la page `index` d'une image lue à la faute ; rien pour une autre
    /// section, dont les pages se remplissent en mémoire.
    ///
    /// # Errors
    /// Celles de [`FileSegment::read_in`].
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL, sans verrou tournant tenu. Peut bloquer.
    pub fn read_in(&self, index: u64) -> Result<(), NtStatus> {
        match &self.source {
            Source::Segment(segment) => segment.read_in(index),
            Source::PagedImage { segment, layout, .. } => {
                layout.file_pages(index).try_for_each(|page| segment.read_in(page))
            }
            _ => Ok(()),
        }
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
        // pages any more. A segment's pages go with the segment.
        for &page in self.pages.lock().values() {
            pfn::free_page(page);
        }
        if let Some(start) = self.based {
            BASED_SECTIONS.lock().remove(&start);
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
        let info = ImageInfo {
            image_base: 0x40_0000,
            entry_point: 0x1010,
            size_of_image: 0x6000,
            relocs_stripped: false,
            subsystem: 3,
            subsystem_version: (4, 0),
            stack_reserve: 0x10_0000,
            stack_commit: 0x1000,
            machine: 0x14C,
            characteristics: layout.info.characteristics,
            dll_characteristics: 0,
            loader_flags: 0,
            contains_code: true,
            file_size: image().len() as u64,
        };
        assert_eq!(layout.info, info);
        assert_ne!(info.characteristics & 0x0002, 0, "an executable image");
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
    fn based_sections_go_top_down_under_the_high_section_base() {
        let mut taken = BTreeMap::new();
        // csrss's shared section, 1 MiB, lands where XP puts it.
        assert_eq!(HIGH_SECTION_BASE, 0x7F7F_0000);
        assert_eq!(find_based_range(&taken, 0x10_0000), Some(0x7F6F_0000));
        taken.insert(0x7F6F_0000, 0x7F7F_0000);
        assert_eq!(find_based_range(&taken, 0x1000), Some(0x7F6E_0000), "below it, aligned on 64 KiB");
        taken.insert(0x7F00_0000, 0x7F60_0000);
        assert_eq!(find_based_range(&taken, 0x8_0000), Some(0x7F67_0000), "the top of the gap between two");
        assert_eq!(find_based_range(&taken, 0x10_0000), Some(0x7EF0_0000), "the gap too small: below both");
        assert_eq!(find_based_range(&taken, HIGH_SECTION_BASE), None, "no room");
        let low = BTreeMap::from([(USER_VA_START, HIGH_SECTION_BASE)]);
        assert_eq!(find_based_range(&low, 0x1000), None, "everything taken");
    }

    #[test]
    fn a_reserved_section_commits_its_pages_one_range_at_a_time() {
        let section = Section::create_shared(70 * PAGE, RW, true, false).unwrap();
        assert!(section.is_reserve() && section.based_address().is_none());
        assert_eq!(section.committed_run(0, 70), (false, 70), "nothing committed");
        section.commit(1, 2);
        section.commit(64, 10);
        assert_eq!(section.committed_run(0, 70), (false, 1));
        assert_eq!(section.committed_run(1, 70), (true, 2));
        assert_eq!(section.committed_run(3, 70), (false, 61), "across the first word");
        assert_eq!(section.committed_run(64, 70), (true, 6), "up to the end of the section");
        assert_eq!(section.committed_run(3, 5), (false, 5), "within the limit");
        assert!(section.is_committed(65) && !section.is_committed(63));
        let committed = Section::create_pagefile(PAGE, RW).unwrap();
        assert!(!committed.is_reserve() && committed.is_committed(0));
        assert_eq!(committed.committed_run(0, 9), (true, 9));
        committed.commit(0, 1);
        assert_eq!(Section::create_shared(0, RW, true, false).err(), Some(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn a_based_section_keeps_its_address_until_it_goes() {
        // The only test that makes based sections: the table is shared.
        let first = Section::create_shared(0x10_0000, RW, true, true).unwrap();
        let second = Section::create_shared(0x2000, RW, false, true).unwrap();
        assert_eq!(first.based_address(), Some(0x7F6F_0000));
        assert_eq!(second.based_address(), Some(0x7F6E_0000));
        drop(first);
        let third = Section::create_shared(0x8_0000, RW, false, true).unwrap();
        assert_eq!(third.based_address(), Some(0x7F77_0000), "the first one's range is free again");
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

    extern crate std;
    use std::sync::Mutex;

    /// A file in memory that counts its reads: (offset, length) of each.
    struct CountingReader {
        bytes: Vec<u8>,
        reads: Arc<Mutex<Vec<(u64, usize)>>>,
        fail: Arc<Mutex<bool>>,
        /// Called once, during the first read (a fault on another thread).
        during: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl FileReader for CountingReader {
        fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, NtStatus> {
            let during = self.during.lock().unwrap().take();
            if let Some(during) = during {
                during();
            }
            if *self.fail.lock().unwrap() {
                return Err(abi::ntstatus::STATUS_IO_DEVICE_ERROR);
            }
            self.reads.lock().unwrap().push((offset, buffer.len()));
            let start = (offset as usize).min(self.bytes.len());
            let count = buffer.len().min(self.bytes.len() - start);
            buffer[..count].copy_from_slice(&self.bytes[start..start + count]);
            Ok(count)
        }
    }

    type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

    /// A segment over `len` bytes of a pattern, its reads and its failure
    /// switch.
    fn segment(len: usize) -> (Arc<FileSegment>, Vec<u8>, Reads, Arc<Mutex<bool>>) {
        crate::pfn::init_for_host_tests();
        let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + i / 4096) as u8).collect();
        let reads = Arc::new(Mutex::new(Vec::new()));
        let fail = Arc::new(Mutex::new(false));
        let reader =
            CountingReader { bytes: bytes.clone(), reads: reads.clone(), fail: fail.clone(), during: Mutex::new(None) };
        (FileSegment::new(Box::new(reader), len as u64), bytes, reads, fail)
    }

    /// A segment over `bytes`, and its reads.
    fn segment_of(bytes: &[u8]) -> (Arc<FileSegment>, Reads) {
        crate::pfn::init_for_host_tests();
        let reads = Arc::new(Mutex::new(Vec::new()));
        let fail = Arc::new(Mutex::new(false));
        let reader = CountingReader { bytes: bytes.to_vec(), reads: reads.clone(), fail, during: Mutex::new(None) };
        (FileSegment::new(Box::new(reader), bytes.len() as u64), reads)
    }

    /// The bytes of a page of the host's PFN database.
    fn bytes_of(frame: Pfn) -> &'static [u8] {
        let hhdm = crate::HHDM_OFFSET.load(Ordering::Acquire);
        // SAFETY: a page of the host buffer (`init_for_host_tests`), alive
        // while its segment is, which the caller holds.
        unsafe { core::slice::from_raw_parts((hhdm + frame.to_phys()) as *const u8, PAGE as usize) }
    }

    #[test]
    fn a_data_section_of_a_file_reads_nothing_until_a_fault_reads_its_page_in() {
        let (segment, bytes, reads, _) = segment(300 * 1024);
        let section = Section::create_paged_data_file(segment.clone(), 0, RO).unwrap();
        assert_eq!((section.kind(), section.size()), (SectionKind::DataFile, 300 * 1024));
        assert!(reads.lock().unwrap().is_empty(), "nothing read at its creation");
        assert_eq!(section.page(20), Ok(None), "not read yet: the fault reads it in, its lock released");
        section.read_in(20).unwrap();
        assert_eq!(*reads.lock().unwrap(), [(16 * PAGE, 16 * PAGE as usize)], "its 64 KiB, in one read");
        let frame = section.page(20).unwrap().expect("read in");
        assert_eq!(bytes_of(frame), &bytes[20 * PAGE as usize..21 * PAGE as usize]);
        assert_eq!(section.page(15), Ok(None), "another cluster");
        assert_eq!(section.resident_pages(), 16);
        section.read_in(20).unwrap();
        section.read_in(31).unwrap();
        assert_eq!(reads.lock().unwrap().len(), 1, "read once");
        assert!(file_pages_read() >= 16);
    }

    #[test]
    fn the_sections_of_a_file_share_the_pages_of_its_segment() {
        let (segment, _, reads, _) = segment(5 * PAGE as usize);
        let first = Section::create_paged_data_file(segment.clone(), 0, RO).unwrap();
        let second = Section::create_paged_data_file(segment.clone(), 2 * PAGE, PageProtect::READWRITE).unwrap();
        first.read_in(1).unwrap();
        assert_eq!(first.page(1).unwrap(), second.page(1).unwrap(), "the same page, not a copy");
        assert!(second.page(1).unwrap().is_some());
        second.read_in(0).unwrap();
        assert_eq!(reads.lock().unwrap().len(), 1, "the second section reads nothing more");
        assert_eq!(second.size(), 2 * PAGE);
        assert!(core::ptr::eq(&**first.file_segment().unwrap(), &**second.file_segment().unwrap()));
        drop(first);
        assert_eq!(second.resident_pages(), 5, "the pages stay with the segment");
    }

    #[test]
    fn a_file_that_ends_inside_a_page_reads_zeros_after_its_end() {
        let (segment, bytes, reads, _) = segment(5000);
        let section = Section::create_paged_data_file(segment, 0, RO).unwrap();
        section.read_in(1).unwrap();
        assert_eq!(*reads.lock().unwrap(), [(0, 5000)], "both pages, no more than the file");
        let last = bytes_of(section.page(1).unwrap().unwrap());
        assert_eq!(&last[..5000 - 4096], &bytes[4096..]);
        assert!(last[5000 - 4096..].iter().all(|&b| b == 0), "zeros past the end of the file");
        assert_eq!(bytes_of(section.page(0).unwrap().unwrap()), &bytes[..4096]);
    }

    #[test]
    fn a_page_past_the_end_of_a_shorter_file_is_zeros() {
        // The file got shorter after its segment was made: fewer bytes.
        let (segment, _, reads, _) = segment(3 * PAGE as usize);
        segment.read_in(7).unwrap();
        assert_eq!(*reads.lock().unwrap(), [(0, 3 * PAGE as usize)], "no more than the file, in its cluster");
        assert!(bytes_of(segment.resident(7).unwrap()).iter().all(|&b| b == 0));
    }

    #[test]
    fn a_failed_read_keeps_nothing_and_the_next_fault_reads_again() {
        let (segment, bytes, reads, fail) = segment(2 * PAGE as usize);
        *fail.lock().unwrap() = true;
        assert_eq!(segment.read_in(0), Err(STATUS_IN_PAGE_ERROR));
        assert_eq!(segment.resident_pages(), 0);
        *fail.lock().unwrap() = false;
        segment.read_in(0).unwrap();
        assert_eq!(reads.lock().unwrap().len(), 1);
        assert_eq!(bytes_of(segment.resident(1).unwrap()), &bytes[4096..]);
    }

    #[test]
    fn a_page_read_by_another_fault_meanwhile_keeps_its_frame() {
        crate::pfn::init_for_host_tests();
        let bytes = alloc::vec![0x5Au8; 2 * PAGE as usize];
        let holder: Arc<Mutex<Option<Arc<FileSegment>>>> = Arc::new(Mutex::new(None));
        let other: Arc<Mutex<Option<Pfn>>> = Arc::new(Mutex::new(None));
        let (inner, seen) = (holder.clone(), other.clone());
        let reads = Arc::new(Mutex::new(Vec::new()));
        let reader = CountingReader {
            bytes,
            reads: reads.clone(),
            fail: Arc::new(Mutex::new(false)),
            // While the first fault reads, a second one reads page 1 in.
            during: Mutex::new(Some(Box::new(move || {
                let segment = inner.lock().unwrap().clone().unwrap();
                segment.read_in(1).unwrap();
                *seen.lock().unwrap() = segment.resident(1);
            }))),
        };
        let segment = FileSegment::new(Box::new(reader), 2 * PAGE);
        *holder.lock().unwrap() = Some(segment.clone());
        segment.read_in(0).unwrap();
        assert_eq!(reads.lock().unwrap().len(), 2, "both faults read");
        let theirs = other.lock().unwrap().expect("the other fault's page");
        assert_eq!(segment.resident(1), Some(theirs), "the page of the other fault, which a view may map");
        assert_eq!(segment.resident_pages(), 2);
        *holder.lock().unwrap() = None;
    }

    #[test]
    fn a_fault_reads_the_missing_pages_of_its_aligned_cluster() {
        let none = |_| false;
        assert_eq!(missing_run(20, 100, none), (16, 32));
        assert_eq!(missing_run(0, 3, none), (0, 3), "the end of the file");
        let some = |page: u64| page == 18 || page == 25;
        assert_eq!(missing_run(20, 100, some), (19, 25), "between two pages already read");
        assert_eq!(missing_run(17, 100, some), (16, 18));
        assert_eq!(missing_run(33, 34, none), (32, 34));
    }

    #[test]
    fn a_paged_data_section_checks_its_arguments() {
        let (segment, ..) = segment(10);
        assert_eq!(Section::create_paged_data_file(segment.clone(), 11, RO).err(), Some(STATUS_SECTION_TOO_BIG));
        assert_eq!(Section::create_paged_data_file(segment.clone(), 4, RO).map(|s| s.size()), Ok(4));
        assert_eq!(
            Section::create_paged_data_file(segment, 0, RW | PageProtect::GUARD).err(),
            Some(STATUS_INVALID_PAGE_PROTECTION)
        );
        let (empty, ..) = self::segment(0);
        assert_eq!(Section::create_paged_data_file(empty, 0, RO).err(), Some(STATUS_MAPPED_FILE_SIZE_ZERO));
    }

    #[test]
    fn an_image_reads_its_headers_and_sections_not_what_follows() {
        let mut file = image();
        file.extend_from_slice(&[0xEE; 0x50000]); // an installer's payload
        let (segment, reads) = segment_of(&file);
        let section = Section::create_paged_image(&file[..0x400], segment, "\\SETUP.EXE", None).unwrap();
        let layout = section.image().unwrap();
        assert_eq!(layout.info.file_size, file.len() as u64, "the size of the whole file");
        assert_eq!(*layout, ImageLayout::new(&file).unwrap(), "the same image as from the whole file");
        for index in 0..section.size() / PAGE {
            section.read_in(index).unwrap();
        }
        let reads = reads.lock().unwrap();
        assert!(reads.iter().all(|&(at, len)| at + len as u64 <= READ_CLUSTER_PAGES * PAGE), "{reads:?}");
    }

    #[test]
    fn a_file_cut_in_its_headers_is_not_an_image() {
        let file = image();
        for cut in [0x40, 0x80, 0xB0, 0x150] {
            assert_eq!(ImageLayout::new(&file[..cut]), Err(STATUS_INVALID_IMAGE_FORMAT), "cut at {cut:#x}");
        }
        let prefix = &file[..0x200];
        assert_eq!(
            ImageLayout::parse(prefix, file.len() as u64),
            Err(STATUS_INVALID_IMAGE_FORMAT),
            "the raw data of .text beyond the bytes given"
        );
    }

    /// An image whose sections lie far into its file, past 64 KiB.
    fn far_image() -> Vec<u8> {
        Pe32Builder::new(0x40_0000)
            .entry_point(0x1010)
            .section(".text", 0x1000, 0x1800, &[0xC3; 0x300], X | R)
            .section(".pad", 0x3000, 0x20000, &[0x11; 0x20000], R)
            .section(".data", 0x23000, 0x100, b"data", R | W)
            .build()
    }

    #[test]
    fn an_image_section_of_a_file_reads_only_the_file_pages_a_fault_needs() {
        let file = far_image();
        let (segment, reads) = segment_of(&file);
        let head = &file[..0x1000];
        let section = Section::create_paged_image(head, segment, "\\far.exe", None).unwrap();
        let layout = ImageLayout::new(&file).unwrap();
        assert_eq!(section.image(), Some(&layout), "the layout of the whole file, from its headers");
        assert!(reads.lock().unwrap().is_empty(), "nothing read at its creation");
        let data_page = 0x23;
        assert_eq!(section.page(data_page), Ok(None), "its file pages to read first");
        section.read_in(data_page).unwrap();
        let read = reads.lock().unwrap().clone();
        assert_eq!(read.len(), 1, "one read");
        let data_at = u64::from(pe::Pe32::parse(&file).unwrap().sections().nth(2).unwrap().pointer_to_raw_data);
        assert!(read[0].0 <= data_at && data_at < read[0].0 + read[0].1 as u64, "around .data's raw data");
        assert!((read[0].1 as u64) <= READ_CLUSTER_PAGES * PAGE, "64 KiB at most, not the file");
        let mut expected = [0u8; PAGE as usize];
        layout.fill(&file, data_page, &mut expected);
        assert_eq!(bytes_of(section.page(data_page).unwrap().unwrap()), &expected[..]);
        for index in 0..section.size() / PAGE {
            section.read_in(index).unwrap();
            layout.fill(&file, index, &mut expected);
            assert_eq!(bytes_of(section.page(index).unwrap().unwrap()), &expected[..], "page {index}");
        }
    }

    #[test]
    fn an_image_page_is_made_once_from_its_file_pages() {
        let file = image();
        let (segment, reads) = segment_of(&file);
        let section = Section::create_paged_image(&file, segment, "\\a.exe", None).unwrap();
        section.read_in(1).unwrap();
        let first = section.page(1).unwrap().unwrap();
        assert_eq!(section.page(1).unwrap(), Some(first), "the same page");
        section.read_in(3).unwrap();
        assert_eq!(reads.lock().unwrap().len(), 1, "the file is small: one cluster for both");
        assert_eq!(&bytes_of(section.page(3).unwrap().unwrap())[..4], b"data");
        assert_eq!(section.page(4).unwrap().map(|page| bytes_of(page).iter().all(|&b| b == 0)), Some(true), ".bss");
    }

    #[test]
    fn a_paged_image_with_section_data_past_the_end_of_its_file_is_refused() {
        let file = far_image();
        let (segment, _) = segment_of(&file[..file.len() - 0x200]);
        let refused = Section::create_paged_image(&file[..0x1000], segment, "\\cut.exe", None);
        assert_eq!(refused.err(), Some(STATUS_INVALID_IMAGE_FORMAT));
    }

    #[test]
    fn a_paged_image_keeps_what_it_holds_until_it_goes() {
        let file = image();
        let (segment, _) = segment_of(&file);
        let held: Arc<dyn Any + Send + Sync> = Arc::new(());
        let section = Section::create_paged_image(&file, segment, "\\a.exe", Some(held.clone())).unwrap();
        assert_eq!(Arc::strong_count(&held), 2);
        drop(section);
        assert_eq!(Arc::strong_count(&held), 1, "let go with the section");
    }
}
