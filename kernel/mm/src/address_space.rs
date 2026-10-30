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
//! Pas encore : pages partagées entre espaces (sections), hyperspace.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use abi::ntstatus::{NtStatus, STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION, STATUS_NO_MEMORY, STATUS_SUCCESS};
use hal::sync::KSpinLock;
use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::{PhysAddr, VirtAddr};

use crate::fault::{self, Access, PteState, Resolution};
use crate::paging::{MmPageTables, PTE_RETAINED};
use crate::pfn::{self, PageUsage};
use crate::vad::{PageProtect, VadTree};
use crate::virtual_alloc::{self, AllocType, FreeType, PageMapper, RegionInfo};
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

/// L'espace d'adresses d'un processus : sa PML4 et sa VAD.
pub struct AddressSpace {
    pml4: Pfn,
    /// Un verrou tournant : la faute de page la consulte, sous DISPATCH_LEVEL.
    vad: KSpinLock<VadTree>,
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
        let space = Arc::new(Self { pml4, vad: KSpinLock::new(VadTree::new()) });
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
        let mut mapper = DemandMapper { tables: self.tables() };
        virtual_alloc::allocate(&mut self.vad.lock(), Some(&mut mapper), base, size, alloc_type, protect)
    }

    /// NtFreeVirtualMemory dans cet espace (`virtual_alloc::free`) : les pages
    /// décommitées rendent leur page physique.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn free(&self, base: u64, size: u64, free_type: FreeType) -> Result<(u64, u64), NtStatus> {
        let mut mapper = DemandMapper { tables: self.tables() };
        virtual_alloc::free(&mut self.vad.lock(), Some(&mut mapper), base, size, free_type)
    }

    /// NtProtectVirtualMemory dans cet espace (`virtual_alloc::protect`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn protect(&self, base: u64, size: u64, protect: PageProtect) -> Result<PageProtect, NtStatus> {
        let mut mapper = DemandMapper { tables: self.tables() };
        virtual_alloc::protect(&mut self.vad.lock(), Some(&mut mapper), base, size, protect)
    }

    /// NtQueryVirtualMemory dans cet espace (`virtual_alloc::query`).
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn query(&self, addr: u64) -> Result<RegionInfo, NtStatus> {
        virtual_alloc::query(&self.vad.lock(), addr)
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
        let state = vad.find(page).and_then(|node| node.run_at(page)).map(|(_, run)| (run.state, run.protect));
        match fault::resolve(state, pte_state(&mut tables, page), access) {
            Resolution::DemandZero(protect) => {
                let Some(frame) = pfn::allocate_page(PageUsage::UserPrivate) else {
                    return STATUS_NO_MEMORY;
                };
                // SAFETY: a page just allocated, reached through the HHDM.
                unsafe { core::ptr::write_bytes((hhdm() + frame.to_phys()) as *mut u8, 0, PAGE as usize) };
                let flags = MmPageTables::leaf_flags(protect.writable(), protect.executable(), true);
                // SAFETY: the page has no physical page in this space (resolve
                // said so); the frame belongs to the space from now on.
                unsafe { tables.map_page(VirtAddr::new(page), PhysAddr::new(frame.to_phys()), flags) };
                fault::count_demand_zero();
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

    /// Retire l'espace du registre et rend à la base PFN tout ce qu'il
    /// possède : les pages de sa moitié basse, ses tables, puis sa PML4.
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
}

impl PageMapper for DemandMapper {
    fn commit_page(&mut self, _virt: u64, _writable: bool, _executable: bool, _user: bool) -> Result<(), NtStatus> {
        Ok(())
    }

    fn decommit_page(&mut self, virt: u64) {
        let Some(entry) = self.tables.leaf_entry(VirtAddr::new(virt)) else {
            return;
        };
        if entry.flags().intersects(PageTableFlags::PRESENT | PTE_RETAINED) {
            let phys = entry.addr().as_u64();
            entry.set_unused();
            // Only meaningful if the space is active: switching CR3 flushes
            // its user pages, never global.
            x86_64::instructions::tlb::flush(VirtAddr::new(virt));
            pfn::free_page(Pfn(phys / PAGE));
        }
    }

    fn protect_page(&mut self, virt: u64, protect: PageProtect) {
        set_rights(&mut self.tables, virt, protect);
    }
}

/// Ce que la table tient pour la page `virt`.
fn pte_state(tables: &mut MmPageTables, virt: u64) -> PteState {
    match tables.leaf_entry(VirtAddr::new(virt)) {
        Some(entry) if entry.flags().contains(PageTableFlags::PRESENT) => PteState::Present {
            writable: entry.flags().contains(PageTableFlags::WRITABLE),
            executable: !entry.flags().contains(PageTableFlags::NO_EXECUTE),
        },
        Some(entry) if entry.flags().contains(PTE_RETAINED) => PteState::Retained,
        _ => PteState::Absent,
    }
}

/// Donne `protect` à la page `virt` si elle a une page physique : présente
/// avec ses droits si la protection permet un accès, tenue non présente sinon.
fn set_rights(tables: &mut MmPageTables, virt: u64, protect: PageProtect) {
    let Some(entry) = tables.leaf_entry(VirtAddr::new(virt)) else {
        return;
    };
    if !entry.flags().intersects(PageTableFlags::PRESENT | PTE_RETAINED) {
        return;
    }
    let flags = if protect.accessible() {
        MmPageTables::leaf_flags(protect.writable(), protect.executable(), true)
    } else {
        PTE_RETAINED
    };
    entry.set_addr(entry.addr(), flags);
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
            pfn::free_page(Pfn(next / PAGE));
        } else {
            // SAFETY: une table de l'espace, désignée par cette entrée.
            unsafe { free_tables(next, level - 1, 512) };
        }
    }
    pfn::free_page(Pfn(phys / PAGE));
}
