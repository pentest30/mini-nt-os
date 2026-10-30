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
//! Pas encore : pages partagées entre espaces (sections), hyperspace.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::{PhysAddr, VirtAddr};

use crate::paging::MmPageTables;
use crate::pfn::{self, PageUsage};
use crate::Pfn;

/// Première entrée de la moitié haute de la PML4.
const KERNEL_HALF: usize = 256;
/// Fin (exclue) de la moitié basse : 0x0000_8000_0000_0000.
pub const USER_HALF_END: u64 = 1 << 47;

/// La PML4 du système : celle du démarrage.
static SYSTEM_DIRECTORY: AtomicU64 = AtomicU64::new(0);
/// La moitié haute de la PML4 du système est complète.
static KERNEL_HALF_FILLED: AtomicBool = AtomicBool::new(false);

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

/// L'espace d'adresses d'un processus : sa PML4.
pub struct AddressSpace {
    pml4: Pfn,
}

impl AddressSpace {
    /// Un espace neuf : la moitié haute du système, une moitié basse vide ;
    /// `None` si la mémoire manque.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn new() -> Option<Self> {
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
        Some(Self { pml4 })
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

    /// Rend à la base PFN tout ce que possède l'espace : les pages projetées
    /// dans sa moitié basse, ses tables, puis sa PML4.
    ///
    /// # Panics
    /// S'il est actif sur ce processeur.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL. Aucun thread ne doit plus l'utiliser.
    pub fn destroy(self) {
        let (frame, _) = x86_64::registers::control::Cr3::read();
        assert_ne!(frame.start_address().as_u64(), self.directory_table_base(), "destroying the active address space");
        // SAFETY: cette PML4 et ses tables appartiennent à l'espace, que plus
        // rien n'utilise ; leurs pages ne sont libérées qu'une fois.
        unsafe { free_tables(self.directory_table_base(), 4, KERNEL_HALF) };
    }
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
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        assert!(!entry.flags().contains(PageTableFlags::HUGE_PAGE), "huge page in a user half");
        let next = entry.addr().as_u64();
        if level == 1 {
            pfn::free_page(Pfn(next / 4096));
        } else {
            // SAFETY: une table de l'espace, désignée par cette entrée.
            unsafe { free_tables(next, level - 1, 512) };
        }
    }
    pfn::free_page(Pfn(phys / 4096));
}
