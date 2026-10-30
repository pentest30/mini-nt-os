//! Espaces d'adresses (02 §4.2, §5.3) : une PML4 par processus.
//!
//! La moitié haute (entrées 256 à 511) est celle du système. [`init`] la
//! complète au démarrage, une PDPT par entrée, et chaque nouvelle PML4 la
//! recopie : le noyau y est le même dans tous les espaces, et ce qu'il projette
//! ensuite (pools, piles) se place sous ces PDPT partagées, sans jamais
//! toucher une PML4. La moitié basse est propre à chaque espace : ses tables et
//! ses pages lui appartiennent, et [`AddressSpace::destroy`] les rend à la base
//! PFN.
//!
//! Le registre CR3 d'un thread (sa base de répertoire, `directory table
//! base`) est chargé par Ke à chaque commutation (`ke::sched`).
//!
//! Chaque espace tient sa VAD. [`AddressSpace::allocate`] et la suite y
//! réservent et commitent sans rien projeter : la première faute sur une page
//! commitée lui donne une page à zéro ([`AddressSpace::access_fault`],
//! `mm::fault`). Un espace vivant est enregistré par sa base de répertoire,
//! pour que la faute trouve celui du CR3 courant.
//!
//! Une vue de section ([`AddressSpace::map_view`]) est un nœud de la VAD qui
//! tient la section : ses pages projettent celles de la section, marquées
//! `PTE_SHARED`, que ni [`AddressSpace::unmap_view`] ni la destruction de
//! l'espace ne rendent ; ses copies privées (copie sur écriture), si.
//!
//! Pas encore : hyperspace.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use abi::ntstatus::{
    NtStatus, STATUS_ACCESS_VIOLATION, STATUS_CONFLICTING_ADDRESSES, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_IMAGE_NOT_AT_BASE, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER, STATUS_INVALID_VIEW_SIZE,
    STATUS_MAPPED_ALIGNMENT, STATUS_NOT_MAPPED_VIEW, STATUS_NO_MEMORY, STATUS_STACK_OVERFLOW, STATUS_SUCCESS,
};
use abi::teb32::{NtTib32, Teb32};
use hal::sync::KSpinLock;
use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::{PhysAddr, VirtAddr};

use crate::fault::{self, Access, Backing, PteState, Resolution};
use crate::paging::{MmPageTables, PTE_RETAINED, PTE_SHARED};
use crate::pfn::{self, PageUsage};
use crate::section::{view_protection, Section};
use crate::vad::{PageProtect, PageState, VadKind, VadNode, VadTree, USER_VA_END};
use crate::virtual_alloc::{self, AllocType, FreeType, PageMapper, RegionInfo, ALLOC_GRANULARITY, USER_VA_START};
use crate::Pfn;

/// Première entrée de la moitié haute de la PML4.
const KERNEL_HALF: usize = 256;
/// Fin (exclue) de la moitié basse : 0x0000_8000_0000_0000.
pub const USER_HALF_END: u64 = 1 << 47;

/// La PML4 du système : celle du démarrage.
static SYSTEM_DIRECTORY: AtomicU64 = AtomicU64::new(0);
/// La moitié haute de la PML4 du système est complète.
static KERNEL_HALF_FILLED: AtomicBool = AtomicBool::new(false);
/// Les espaces vivants, par base de répertoire : la faute de page y trouve
/// celui du CR3 courant ([`AddressSpace::current`]).
static SPACES: KSpinLock<BTreeMap<u64, Arc<AddressSpace>>> = KSpinLock::new(BTreeMap::new());

const PAGE: u64 = 4096;

fn hhdm() -> u64 {
    crate::HHDM_OFFSET.load(Ordering::Acquire)
}

/// La table de pages à l'adresse physique `phys`, par le HHDM.
///
/// # Safety
/// `phys` est une table de pages vivante, que rien d'autre ne modifie pendant
/// l'emprunt.
unsafe fn table(phys: u64) -> &'static mut PageTable {
    // SAFETY: garanti par l'appelant ; le HHDM projette toute la mémoire gérée.
    unsafe { &mut *((hhdm() + phys) as *mut PageTable) }
}

/// Une page de table neuve, à zéro.
fn new_table() -> u64 {
    let pfn = pfn::allocate_page(PageUsage::PageTable).expect("out of physical memory for a page table");
    // SAFETY: une page qui vient d'être allouée, projetée par le HHDM.
    unsafe { table(pfn.to_phys()).zero() };
    pfn.to_phys()
}

/// Retient la PML4 active comme celle du système et complète sa moitié haute.
///
/// # Safety
/// Une fois, à la fin de `mm::init`, avant toute PML4 de processus ; la PML4
/// active est celle du démarrage.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub(crate) unsafe fn init() {
    let (frame, _) = x86_64::registers::control::Cr3::read();
    let directory = frame.start_address().as_u64();
    SYSTEM_DIRECTORY.store(directory, Ordering::Release);
    // SAFETY: la PML4 active, que seul ce démarrage modifie.
    let l4 = unsafe { table(directory) };
    let mut filled = 0;
    for entry in l4.iter_mut().skip(KERNEL_HALF) {
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            entry.set_addr(PhysAddr::new(new_table()), PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
            filled += 1;
        }
    }
    KERNEL_HALF_FILLED.store(true, Ordering::Release);
    x86_64::instructions::tlb::flush_all();
    log::info!("Mm: kernel half of the PML4 filled at boot ({filled} PDPTs), shared by every address space");
}

/// La moitié haute de la PML4 du système est complète : aucune entrée n'y
/// change plus.
pub fn kernel_half_filled() -> bool {
    KERNEL_HALF_FILLED.load(Ordering::Acquire)
}

/// La base de répertoire (CR3) de l'espace du système.
///
/// # IRQL
/// Tout niveau.
pub fn system_directory_table_base() -> u64 {
    SYSTEM_DIRECTORY.load(Ordering::Acquire)
}

/// Ce que rend NtMapViewOfSection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedView {
    pub base: u64,
    pub size: u64,
    /// `STATUS_SUCCESS`, ou `STATUS_IMAGE_NOT_AT_BASE` pour une image
    /// projetée ailleurs qu'à sa base.
    pub status: NtStatus,
}

/// L'espace d'adresses d'un processus : sa PML4 et sa VAD.
pub struct AddressSpace {
    pml4: Pfn,
    /// Un verrou tournant : la faute de page la consulte, sous DISPATCH_LEVEL.
    vad: KSpinLock<VadTree>,
    /// DEP coupé (ADR-020) : toute page lisible s'exécute. Changé sous le
    /// verrou de la VAD.
    execute_enabled: AtomicBool,
}

impl AddressSpace {
    /// Un espace neuf, enregistré : la moitié haute du système, une moitié
    /// basse vide ; `None` si la mémoire manque.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new() -> Option<Arc<Self>> {
        assert!(kernel_half_filled(), "address space created before mm::init");
        let pml4 = pfn::allocate_page(PageUsage::PageTable)?;
        // SAFETY: la page vient d'être allouée ; la PML4 du système est
        // vivante, et sa moitié haute ne change plus.
        unsafe {
            let l4 = table(pml4.to_phys());
            let system = table(system_directory_table_base());
            for i in 0..512 {
                l4[i] = if i < KERNEL_HALF { Default::default() } else { system[i].clone() };
            }
        }
        let space =
            Arc::new(Self { pml4, vad: KSpinLock::new(VadTree::new()), execute_enabled: AtomicBool::new(false) });
        SPACES.lock().insert(space.directory_table_base(), space.clone());
        Some(space)
    }

    /// L'espace actif sur ce processeur (CR3) ; `None` dans celui du système.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn current() -> Option<Arc<Self>> {
        let (frame, _) = x86_64::registers::control::Cr3::read();
        SPACES.lock().get(&frame.start_address().as_u64()).cloned()
    }

    /// Sa base de répertoire : la valeur de CR3 qui l'active.
    pub fn directory_table_base(&self) -> u64 {
        self.pml4.to_phys()
    }

    /// Projette la page physique `phys` en `virt`, dans la moitié basse, avec
    /// `flags`. L'espace possède ensuite cette page : [`destroy`](Self::destroy)
    /// la rendra à la base PFN.
    ///
    /// # Safety
    /// `virt` n'est pas encore projetée dans cet espace ; `phys` est une page
    /// allouée à la base PFN (ordre 0), que rien d'autre ne possède.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub unsafe fn map_page(&self, virt: u64, phys: u64, flags: PageTableFlags) {
        assert!(virt < USER_HALF_END, "{virt:#x} is not in the user half");
        // SAFETY: cette PML4 vit autant que `self` ; le reste est garanti par
        // l'appelant.
        unsafe {
            MmPageTables::for_directory(hhdm(), self.directory_table_base()).map_page(
                VirtAddr::new(virt),
                PhysAddr::new(phys),
                flags,
            )
        };
    }

    /// DEP est coupé : toute page lisible s'exécute (ADR-020). Un espace
    /// neuf a DEP actif ; Ps le règle d'après la politique du système.
    ///
    /// # IRQL
    /// Tout niveau.
    pub fn execute_enabled(&self) -> bool {
        self.execute_enabled.load(Ordering::Acquire)
    }

    /// Coupe DEP (`true`) ou l'active : les pages déjà présentes prennent
    /// aussitôt leurs nouveaux droits. La VAD garde les protections
    /// demandées ; seuls les droits des pages changent.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn set_execute_enabled(&self, enabled: bool) {
        let vad = self.vad.lock();
        self.execute_enabled.store(enabled, Ordering::Release);
        let mut tables = self.tables();
        for node in vad.nodes() {
            let mut at = node.start;
            for run in node.runs() {
                let end = at + run.pages * PAGE;
                if run.state == PageState::Committed {
                    for page in (at..end).step_by(PAGE as usize) {
                        set_rights(&mut tables, page, self.effective(run.protect));
                    }
                }
                at = end;
            }
        }
    }

    /// La protection qui donne les droits d'une page : celle de la VAD, qui
    /// s'exécute aussi si DEP est coupé.
    fn effective(&self, protect: PageProtect) -> PageProtect {
        if self.execute_enabled() {
            protect.with_execute()
        } else {
            protect
        }
    }

    /// Le `PageMapper` des opérations sur la VAD.
    fn mapper(&self) -> DemandMapper {
        DemandMapper { tables: self.tables(), execute_enabled: self.execute_enabled() }
    }

    /// Ses tables de pages.
    fn tables(&self) -> MmPageTables {
        // SAFETY: la PML4 vit autant que `self`.
        unsafe { MmPageTables::for_directory(hhdm(), self.directory_table_base()) }
    }

    /// NtAllocateVirtualMemory dans cet espace (`virtual_alloc::allocate`),
    /// sans rien projeter.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn allocate(&self, base: u64, size: u64, alloc_type: AllocType, protect: PageProtect) -> Result<u64, NtStatus> {
        let mut mapper = self.mapper();
        virtual_alloc::allocate(&mut self.vad.lock(), Some(&mut mapper), base, size, alloc_type, protect)
    }

    /// NtFreeVirtualMemory dans cet espace (`virtual_alloc::free`) : les pages
    /// décommitées rendent leur page physique.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn free(&self, base: u64, size: u64, free_type: FreeType) -> Result<(u64, u64), NtStatus> {
        let mut mapper = self.mapper();
        virtual_alloc::free(&mut self.vad.lock(), Some(&mut mapper), base, size, free_type)
    }

    /// NtProtectVirtualMemory dans cet espace (`virtual_alloc::protect`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn protect(&self, base: u64, size: u64, protect: PageProtect) -> Result<PageProtect, NtStatus> {
        let mut mapper = self.mapper();
        virtual_alloc::protect(&mut self.vad.lock(), Some(&mut mapper), base, size, protect)
    }

    /// NtQueryVirtualMemory dans cet espace (`virtual_alloc::query`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn query(&self, addr: u64) -> Result<RegionInfo, NtStatus> {
        virtual_alloc::query(&self.vad.lock(), addr)
    }

    /// NtMapViewOfSection : projette `size` octets de `section` à partir de
    /// `offset` (`size` 0 : jusqu'au bout), en `base` (0 : là où il y a la
    /// place), avec `protect`. Rien n'est projeté avant la première faute.
    ///
    /// - Fichier de données et mémoire partagée : `offset` aligné sur 64 Kio
    ///   (`STATUS_MAPPED_ALIGNMENT`), la vue dans la section
    ///   (`STATUS_INVALID_VIEW_SIZE`), `protect` permise par la section
    ///   (`STATUS_SECTION_PROTECTION`).
    /// - Image : toute l'image, chaque page avec la protection de sa section ;
    ///   en `base` 0, à sa base préférée si la place est libre. Ailleurs, la
    ///   vue rend `STATUS_IMAGE_NOT_AT_BASE`, et c'est `ntdll` qui reloge ; une
    ///   image sans relocations ne quitte pas sa base
    ///   (`STATUS_CONFLICTING_ADDRESSES`).
    /// - `base` explicite : alignée sur 64 Kio (`STATUS_MAPPED_ALIGNMENT`),
    ///   la plage libre (`STATUS_CONFLICTING_ADDRESSES`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn map_view(
        &self,
        section: &Arc<Section>,
        base: u64,
        offset: u64,
        size: u64,
        protect: PageProtect,
    ) -> Result<MappedView, NtStatus> {
        if !protect.is_valid() {
            return Err(STATUS_INVALID_PAGE_PROTECTION);
        }
        let (size, protects, image) = match section.image() {
            Some(layout) => {
                if offset != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if size != 0 && size.next_multiple_of(PAGE) != section.size() {
                    return Err(STATUS_INVALID_VIEW_SIZE);
                }
                (section.size(), layout.protects.clone(), Some(layout.info))
            }
            None => {
                if !offset.is_multiple_of(ALLOC_GRANULARITY) {
                    return Err(STATUS_MAPPED_ALIGNMENT);
                }
                let end = if size == 0 { section.size() } else { offset.saturating_add(size) };
                if offset >= section.size() || end > section.size() {
                    return Err(STATUS_INVALID_VIEW_SIZE);
                }
                let size = (end - offset).next_multiple_of(PAGE);
                (size, alloc::vec![(size / PAGE, view_protection(section, protect)?)], None)
            }
        };
        let mut vad = self.vad.lock();
        let fits = |vad: &VadTree, at: u64| {
            at >= USER_VA_START
                && at.checked_add(size).is_some_and(|end| end <= USER_VA_END)
                && !vad.overlaps(at, at + size)
        };
        let base = if base != 0 {
            if !base.is_multiple_of(ALLOC_GRANULARITY) {
                return Err(STATUS_MAPPED_ALIGNMENT);
            }
            if !fits(&vad, base) {
                return Err(STATUS_CONFLICTING_ADDRESSES);
            }
            base
        } else {
            let preferred = image.map(|info| info.image_base).filter(|&at| at.is_multiple_of(ALLOC_GRANULARITY));
            match preferred.filter(|&at| fits(&vad, at)) {
                Some(at) => at,
                None => vad.find_free_gap(USER_VA_START, size, ALLOC_GRANULARITY).ok_or(STATUS_NO_MEMORY)?,
            }
        };
        let status = match image {
            Some(info) if base != info.image_base && info.relocs_stripped => return Err(STATUS_CONFLICTING_ADDRESSES),
            Some(info) if base != info.image_base => STATUS_IMAGE_NOT_AT_BASE,
            _ => STATUS_SUCCESS,
        };
        let protect = if image.is_some() { section.protect() } else { protects[0].1 };
        let kind = VadKind::View { section: section.clone(), offset };
        vad.insert(VadNode::view(base, base + size, protect, kind, &protects)).expect("a free range");
        Ok(MappedView { base, size, status })
    }

    /// NtUnmapViewOfSection : retire la vue qui contient `addr`
    /// (`STATUS_NOT_MAPPED_VIEW` hors d'une vue). Ses copies privées sont
    /// rendues ; les pages de la section restent à la section.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn unmap_view(&self, addr: u64) -> Result<(), NtStatus> {
        let mut vad = self.vad.lock();
        let (start, end) = match vad.find(addr) {
            Some(node) if matches!(node.kind, VadKind::View { .. }) => (node.start, node.end),
            _ => return Err(STATUS_NOT_MAPPED_VIEW),
        };
        let mut tables = self.tables();
        for page in (start..end).step_by(PAGE as usize) {
            release_page(&mut tables, page);
        }
        // Dropping the node may drop the section, and its pages with it.
        vad.remove(start);
        Ok(())
    }

    /// Écrit `data` en `addr` comme le ferait le processus, sans s'attacher à
    /// lui (MmCopyVirtualMemory) : chaque page est d'abord résolue comme par
    /// une faute d'écriture (page à zéro, copie sur écriture) ; l'erreur de
    /// cette faute sinon (`STATUS_ACCESS_VIOLATION` pour une page réservée ou
    /// en lecture seule).
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL.
    pub fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<(), NtStatus> {
        self.copy(addr, data.len(), Access::Write, |page, done, len| {
            // SAFETY: `page` is `len` bytes of a page of this space, mapped
            // writable and held by the VAD lock while this runs.
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), page, len) }
        })
    }

    /// Lit `buffer.len()` octets en `addr` comme le ferait le processus
    /// (MmCopyVirtualMemory) ; voir [`write_bytes`](Self::write_bytes).
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL.
    pub fn read_bytes(&self, addr: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
        self.copy(addr, buffer.len(), Access::Read, |page, done, len| {
            // SAFETY: `page` is `len` readable bytes of a page of this space,
            // held by the VAD lock while this runs.
            unsafe { core::ptr::copy_nonoverlapping(page, buffer[done..].as_mut_ptr(), len) }
        })
    }

    /// Passe sur `[addr, addr + len)` page par page : `copy(page, done, len)`
    /// reçoit l'adresse, par le HHDM, des `len` octets de la page qui suivent
    /// les `done` premiers, une fois la page présente avec le droit `access`.
    fn copy(
        &self,
        addr: u64,
        len: usize,
        access: Access,
        mut copy: impl FnMut(*mut u8, usize, usize),
    ) -> Result<(), NtStatus> {
        let mut done = 0;
        while done < len {
            let va = addr.checked_add(done as u64).ok_or(STATUS_ACCESS_VIOLATION)?;
            let (page, offset) = (va & !(PAGE - 1), (va & (PAGE - 1)) as usize);
            let chunk = (len - done).min(PAGE as usize - offset);
            let mut faulted = false;
            loop {
                {
                    let _vad = self.vad.lock();
                    let mut tables = self.tables();
                    if let Some(entry) = tables.leaf_entry(VirtAddr::new(page)) {
                        let flags = entry.flags();
                        let usable = flags.contains(PageTableFlags::PRESENT)
                            && (access != Access::Write || flags.contains(PageTableFlags::WRITABLE));
                        if usable {
                            copy((hhdm() + entry.addr().as_u64() + offset as u64) as *mut u8, done, chunk);
                            break;
                        }
                    }
                }
                // Once resolved, the page must be usable: a second fault would
                // mean the tables disagree with the VAD.
                if faulted {
                    return Err(STATUS_ACCESS_VIOLATION);
                }
                let status = self.access_fault(page, access);
                if status != STATUS_SUCCESS {
                    return Err(status);
                }
                faulted = true;
            }
            done += chunk;
        }
        Ok(())
    }

    /// Résout une faute de page à `addr`, dans la moitié basse, d'après la
    /// VAD (`fault::resolve`) : `STATUS_SUCCESS` si l'accès peut reprendre,
    /// sinon l'exception qu'il lève (`STATUS_NO_MEMORY` sans page libre).
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL.
    pub fn access_fault(&self, addr: u64, access: Access) -> NtStatus {
        let page = addr & !(PAGE - 1);
        let mut vad = self.vad.lock();
        let mut tables = self.tables();
        let node = vad.find(page);
        // Faults go by the rights of the page: those of the VAD's protection,
        // with execute if DEP is off.
        let state = node.and_then(|node| node.run_at(page)).map(|(_, run)| (run.state, self.effective(run.protect)));
        let backing =
            if node.and_then(|node| node.section_page(page)).is_some() { Backing::Section } else { Backing::Private };
        match fault::resolve(state, backing, pte_state(&mut tables, page), access) {
            Resolution::DemandZero(protect) => {
                let Some(frame) = pfn::allocate_page(PageUsage::UserPrivate) else {
                    return STATUS_NO_MEMORY;
                };
                // SAFETY: a page just allocated, reached through the HHDM.
                unsafe { core::ptr::write_bytes((hhdm() + frame.to_phys()) as *mut u8, 0, PAGE as usize) };
                let flags = MmPageTables::leaf_flags(protect.writable(), protect.executable(), true);
                // SAFETY: the page has no physical page in this space (resolve
                // said so); the frame belongs to the space from now on.
                if let Err(status) =
                    unsafe { tables.try_map_page(VirtAddr::new(page), PhysAddr::new(frame.to_phys()), flags) }
                {
                    pfn::free_page(frame);
                    return status;
                }
                fault::count_demand_zero();
                STATUS_SUCCESS
            }
            Resolution::MapShared(protect) => {
                let (section, index) = vad.find(page).and_then(|node| node.section_page(page)).expect("a view page");
                let frame = match section.page(index) {
                    Ok(frame) => frame,
                    Err(status) => return status,
                };
                let (writable, executable) = fault::page_rights(protect, true);
                let flags = MmPageTables::leaf_flags(writable, executable, true) | PTE_SHARED;
                // SAFETY: the page has no physical page in this space (resolve
                // said so); the frame stays the section's.
                match unsafe { tables.try_map_page(VirtAddr::new(page), PhysAddr::new(frame.to_phys()), flags) } {
                    Ok(()) => STATUS_SUCCESS,
                    Err(status) => status,
                }
            }
            Resolution::CopyOnWrite(protect) => {
                let node = vad.find_mut(page).expect("a committed page has its VAD");
                let (section, index) = node.section_page(page).map(|(s, i)| (s.clone(), i)).expect("a view page");
                let shared = match section.page(index) {
                    Ok(frame) => frame,
                    Err(status) => return status,
                };
                let Some(copy) = pfn::allocate_page(PageUsage::UserPrivate) else {
                    return STATUS_NO_MEMORY;
                };
                // SAFETY: two distinct pages reached through the HHDM: the
                // section's, read, and a page just allocated.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (hhdm() + shared.to_phys()) as *const u8,
                        (hhdm() + copy.to_phys()) as *mut u8,
                        PAGE as usize,
                    )
                };
                let private = protect.without_copy();
                let (writable, executable) = fault::page_rights(private, false);
                let flags = MmPageTables::leaf_flags(writable, executable, true);
                match tables.leaf_entry(VirtAddr::new(page)) {
                    Some(entry) if entry.flags().contains(PageTableFlags::PRESENT) => {
                        entry.set_addr(PhysAddr::new(copy.to_phys()), flags);
                        x86_64::instructions::tlb::flush(VirtAddr::new(page));
                    }
                    // SAFETY: the page has no physical page in this space; the
                    // copy belongs to the space from now on.
                    _ => {
                        if let Err(status) =
                            unsafe { tables.try_map_page(VirtAddr::new(page), PhysAddr::new(copy.to_phys()), flags) }
                        {
                            pfn::free_page(copy);
                            return status;
                        }
                    }
                }
                // The VAD keeps the protection asked for, without the copy.
                let (_, run) = node.run_at(page).expect("a page of its VAD");
                node.protect(page, page + PAGE, run.protect.without_copy());
                STATUS_SUCCESS
            }
            Resolution::Remap(protect) => {
                set_rights(&mut tables, page, protect);
                STATUS_SUCCESS
            }
            Resolution::Guard => {
                let node = vad.find_mut(page).expect("a committed page has its VAD");
                let (_, run) = node.run_at(page).expect("a page of its VAD");
                node.protect(page, page + PAGE, run.protect - PageProtect::GUARD);
                STATUS_GUARD_PAGE_VIOLATION
            }
            Resolution::AccessViolation => STATUS_ACCESS_VIOLATION,
        }
    }

    /// MiCheckForUserStackOverflow : la faute en `addr` vient de lever une
    /// page de garde, dans le thread dont le TEB est en `teb`. Si elle est
    /// dans sa pile, la garde descend d'une page, `StackLimit` suit, et
    /// l'accès reprend (`STATUS_SUCCESS`) ; sinon l'exception que donne
    /// [`fault::stack_extension`].
    ///
    /// # IRQL
    /// < DISPATCH_LEVEL.
    pub fn extend_user_stack(&self, addr: u64, teb: u32) -> NtStatus {
        let tib = u64::from(teb) + offset_of!(Teb32, nt_tib) as u64;
        let field = |at: u64| {
            let mut bytes = [0u8; 4];
            self.read_bytes(at, &mut bytes).map(|()| u64::from(u32::from_le_bytes(bytes)))
        };
        let (Ok(base), Ok(bottom)) = (
            field(tib + offset_of!(NtTib32, stack_base) as u64),
            field(u64::from(teb) + offset_of!(Teb32, deallocation_stack) as u64),
        ) else {
            return STATUS_GUARD_PAGE_VIOLATION;
        };
        let (guard, limit) = match fault::stack_extension(addr, bottom, base) {
            Ok(extension) => extension,
            Err(status) => return status,
        };
        if self.allocate(guard, PAGE, AllocType::MEM_COMMIT, PageProtect::READWRITE | PageProtect::GUARD).is_err() {
            return STATUS_STACK_OVERFLOW;
        }
        match self.write_bytes(tib + offset_of!(NtTib32, stack_limit) as u64, &(limit as u32).to_le_bytes()) {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        }
    }

    /// Retire l'espace du registre et rend à la base PFN tout ce qu'il
    /// possède : les pages de sa moitié basse, ses tables, puis sa PML4 ;
    /// enfin sa VAD lâche les sections de ses vues.
    ///
    /// # Panics
    /// S'il est actif sur ce processeur, ou encore tenu ailleurs.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL. Aucun thread ne doit plus l'utiliser.
    pub fn destroy(self: Arc<Self>) {
        let (frame, _) = x86_64::registers::control::Cr3::read();
        let directory = self.directory_table_base();
        assert_ne!(frame.start_address().as_u64(), directory, "destroying the active address space");
        SPACES.lock().remove(&directory);
        let space = Arc::try_unwrap(self).unwrap_or_else(|_| panic!("address space {directory:#x} still in use"));
        // SAFETY: cette PML4 et ses tables appartiennent à l'espace, que plus
        // rien n'utilise ; leurs pages ne sont libérées qu'une fois.
        unsafe { free_tables(space.directory_table_base(), 4, KERNEL_HALF) };
    }
}

/// Le `PageMapper` d'un espace : un commit ne projette rien (la faute le
/// fera) ; un décommit et un changement de protection ne touchent que les
/// pages qui ont déjà une page physique.
struct DemandMapper {
    tables: MmPageTables,
    /// DEP coupé dans l'espace : les droits ajoutent l'exécution.
    execute_enabled: bool,
}

impl PageMapper for DemandMapper {
    fn commit_page(&mut self, _virt: u64, _writable: bool, _executable: bool, _user: bool) -> Result<(), NtStatus> {
        Ok(())
    }

    fn decommit_page(&mut self, virt: u64) {
        release_page(&mut self.tables, virt);
    }

    fn protect_page(&mut self, virt: u64, protect: PageProtect) {
        let protect = if self.execute_enabled { protect.with_execute() } else { protect };
        set_rights(&mut self.tables, virt, protect);
    }
}

/// Retire de la table la page physique de `virt`, s'il y en a une, et la
/// rend à la base PFN, sauf celle d'une section.
fn release_page(tables: &mut MmPageTables, virt: u64) {
    let Some(entry) = tables.leaf_entry(VirtAddr::new(virt)) else {
        return;
    };
    let flags = entry.flags();
    if flags.intersects(PageTableFlags::PRESENT | PTE_RETAINED) {
        let phys = entry.addr().as_u64();
        entry.set_unused();
        // Only meaningful if the space is active: switching CR3 flushes its
        // user pages, never global.
        x86_64::instructions::tlb::flush(VirtAddr::new(virt));
        if !flags.contains(PTE_SHARED) {
            pfn::free_page(Pfn(phys / PAGE));
        }
    }
}

/// Ce que la table tient pour la page `virt`.
fn pte_state(tables: &mut MmPageTables, virt: u64) -> PteState {
    match tables.leaf_entry(VirtAddr::new(virt)) {
        Some(entry) if entry.flags().contains(PageTableFlags::PRESENT) => PteState::Present {
            writable: entry.flags().contains(PageTableFlags::WRITABLE),
            executable: !entry.flags().contains(PageTableFlags::NO_EXECUTE),
            shared: entry.flags().contains(PTE_SHARED),
        },
        Some(entry) if entry.flags().contains(PTE_RETAINED) => PteState::Retained,
        _ => PteState::Absent,
    }
}

/// Donne `protect` à la page `virt` si elle a une page physique : présente
/// avec ses droits si la protection permet un accès, tenue non présente
/// sinon ; une page de section le reste.
fn set_rights(tables: &mut MmPageTables, virt: u64, protect: PageProtect) {
    let Some(entry) = tables.leaf_entry(VirtAddr::new(virt)) else {
        return;
    };
    if !entry.flags().intersects(PageTableFlags::PRESENT | PTE_RETAINED) {
        return;
    }
    let shared = entry.flags() & PTE_SHARED;
    let flags = if protect.accessible() {
        let (writable, executable) = fault::page_rights(protect, !shared.is_empty());
        MmPageTables::leaf_flags(writable, executable, true)
    } else {
        PTE_RETAINED
    };
    entry.set_addr(entry.addr(), flags | shared);
    x86_64::instructions::tlb::flush(VirtAddr::new(virt));
}

/// Libère les `entries` premières entrées de la table `phys` de niveau
/// `level` (4 : PML4, 1 : table des pages), récursivement, puis la table.
///
/// # Safety
/// La table et tout ce qu'elle désigne dans ces entrées appartiennent à
/// l'appelant et ne servent plus.
unsafe fn free_tables(phys: u64, level: u8, entries: usize) {
    // SAFETY: garanti par l'appelant.
    let t = unsafe { table(phys) };
    for entry in t.iter().take(entries) {
        let held = if level == 1 { PageTableFlags::PRESENT | PTE_RETAINED } else { PageTableFlags::PRESENT };
        if !entry.flags().intersects(held) {
            continue;
        }
        assert!(!entry.flags().contains(PageTableFlags::HUGE_PAGE), "huge page in a user half");
        let next = entry.addr().as_u64();
        if level == 1 {
            // A section's page stays the section's, which the VAD holds.
            if !entry.flags().contains(PTE_SHARED) {
                pfn::free_page(Pfn(next / PAGE));
            }
        } else {
            // SAFETY: une table de l'espace, désignée par cette entrée.
            unsafe { free_tables(next, level - 1, 512) };
        }
    }
    pfn::free_page(Pfn(phys / PAGE));
}
