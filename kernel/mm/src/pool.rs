//! Pools du noyau (02 §5.3) : le pool non paginé, qui sert aussi d'allocateur
//! global de Rust, et le pool paginé.
//!
//! - Les blocs jusqu'à 2 Kio viennent de listes par classe de taille
//!   (puissances de deux, de 16 o à 2 Kio), remplies une page (une dalle) à la
//!   fois.
//! - Les blocs plus grands prennent des pages entières dans une liste de
//!   suites de pages libres, triée par adresse, qui fusionne les voisines.
//!
//! Chaque bloc est aligné sur sa classe (ou sur la page pour les suites de
//! pages) : la disposition passée à `dealloc` suffit à retrouver sa classe,
//! sans en-tête.
//!
//! Chaque pool réserve une plage d'adresses (02 §4.2) et n'en projette que ce
//! qu'il utilise : il grandit d'au moins [`GROW_PAGES`] pages quand rien ne
//! convient, en prenant des pages à la base PFN ([`Backing`]), et rend à la
//! base les pages libres au sommet de sa plage au-delà d'une réserve de
//! [`GROW_PAGES`] pages. Les dalles restent à leur classe.
//!
//! [`ex_allocate_pool_with_tag`] et [`ex_free_pool_with_tag`] (en attendant la
//! crate `ex`, 02 §5.10) ajoutent un en-tête qui porte la taille et
//! l'étiquette du bloc ; chaque pool compte les blocs vivants et leurs octets
//! par étiquette ([`Pool::tag_stats`]), les allocations de Rust (`Box`, `Vec`…)
//! sous [`TAG_RUST`]. Un processus terminé doit les ramener à leur valeur
//! initiale (critère de sortie de M2).
//!
//! Rien n'est paginé (ADR-010) : le pool paginé reste en mémoire, mais ne se
//! prend qu'à APC_LEVEL au plus ; le non paginé, jusqu'à DISPATCH_LEVEL.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use hal::irql::Irql;

use crate::pfn::PageUsage;

const PAGE: usize = 4096;
/// Smallest block: room for the free-list link, and 16-byte alignment.
const MIN_BLOCK: usize = 16;
/// Largest size served by a size class; larger requests take whole pages.
const MAX_BLOCK: usize = 2048;
const NUM_CLASSES: usize = 8; // 16, 32, 64, 128, 256, 512, 1024, 2048

/// Pages projetées au moins à chaque croissance ; et pages libres gardées au
/// sommet de la plage quand elle rend des pages.
pub const GROW_PAGES: usize = 64;

/// Étiquettes suivies au plus par pool ; les suivantes comptent sous
/// [`TAG_OVERFLOW`].
const MAX_TAGS: usize = 64;

/// Une étiquette de pool : quatre caractères, le premier dans l'octet de poids
/// faible (`tag(b"Proc")`).
pub type PoolTag = u32;

/// L'étiquette de ces quatre caractères.
pub const fn tag(name: &[u8; 4]) -> PoolTag {
    u32::from_le_bytes(*name)
}

/// Les allocations de Rust (`Box`, `Vec`…), par l'allocateur global.
pub const TAG_RUST: PoolTag = tag(b"Rust");
/// Les étiquettes au-delà des [`MAX_TAGS`] premières.
pub const TAG_OVERFLOW: PoolTag = tag(b"Ovfl");

/// Le pool d'une allocation (POOL_TYPE).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolType {
    /// Utilisable jusqu'à DISPATCH_LEVEL.
    NonPaged = 0,
    /// Utilisable jusqu'à APC_LEVEL.
    Paged = 1,
}

impl PoolType {
    /// IRQL le plus haut où ce pool se prend et se rend.
    pub const fn max_irql(self) -> Irql {
        match self {
            PoolType::NonPaged => Irql::Dispatch,
            PoolType::Paged => Irql::Apc,
        }
    }
}

/// Où un pool prend et rend ses pages.
pub trait Backing {
    /// Projette `pages` pages neuves en `addr`, accessibles en écriture ;
    /// `false` si la mémoire manque, rien n'étant alors projeté.
    fn map(&self, addr: usize, pages: usize) -> bool;
    /// Rend les `pages` pages que [`map`](Self::map) a projetées en `addr`.
    fn unmap(&self, addr: usize, pages: usize);
}

/// Blocs vivants d'une étiquette.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TagStats {
    /// Blocs alloués et pas encore libérés.
    pub allocations: usize,
    /// Leurs octets demandés.
    pub bytes: usize,
}

#[derive(Clone, Copy)]
struct TagEntry {
    tag: PoolTag,
    stats: TagStats,
}

/// État d'un pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStats {
    /// Octets projetés.
    pub mapped: usize,
    /// Octets remis (arrondis au bloc ou à la page, en-têtes compris).
    pub used: usize,
}

/// Free block of a size class; the link lives in the free memory itself.
struct FreeBlock {
    next: *mut FreeBlock,
}

/// Free run of whole pages; the header lives in its first page.
struct FreeRun {
    pages: usize,
    next: *mut FreeRun,
}

struct Inner {
    classes: [*mut FreeBlock; NUM_CLASSES],
    /// Free page runs, sorted by address, never adjacent (merged on free).
    runs: *mut FreeRun,
    /// Début de la plage.
    start: usize,
    /// Fin de ce qui est projeté.
    end: usize,
    /// En dessous, la plage reste projetée.
    floor: usize,
    /// Fin de la plage réservée.
    limit: usize,
    used: usize,
    tags: [TagEntry; MAX_TAGS],
}

/// Un pool du noyau. Créé par [`Pool::new`], il reçoit sa plage par
/// [`Pool::init`] ; le pool non paginé sert d'allocateur global
/// ([`GlobalPool`]).
pub struct Pool<B> {
    kind: PoolType,
    backing: B,
    locked: AtomicBool,
    inner: UnsafeCell<Inner>,
}

// SAFETY: `inner` is only reached through `with_lock`, which serialises access.
unsafe impl<B: Sync> Sync for Pool<B> {}

/// En-tête des blocs de [`ex_allocate_pool_with_tag`], devant le bloc rendu.
#[repr(C, align(16))]
struct PoolHeader {
    size: usize,
    tag: PoolTag,
    magic: u32,
}

/// Marque un en-tête vivant ; effacée à la libération.
const HEADER_MAGIC: u32 = tag(b"Pool");
const HEADER: usize = core::mem::size_of::<PoolHeader>();
const _: () = assert!(HEADER == 16);

impl<B: Backing> Pool<B> {
    /// Un pool vide : toute allocation échoue jusqu'à [`Pool::init`].
    pub const fn new(kind: PoolType, backing: B) -> Self {
        Self {
            kind,
            backing,
            locked: AtomicBool::new(false),
            inner: UnsafeCell::new(Inner {
                classes: [ptr::null_mut(); NUM_CLASSES],
                runs: ptr::null_mut(),
                start: 0,
                end: 0,
                floor: 0,
                limit: 0,
                used: 0,
                tags: [TagEntry { tag: 0, stats: TagStats { allocations: 0, bytes: 0 } }; MAX_TAGS],
            }),
        }
    }

    /// Donne au pool la plage `[start, start + reserved * PAGE)` et y projette
    /// ses `initial` premières pages, qui le restent ; `false` si la mémoire
    /// manque pour elles.
    ///
    /// # Safety
    /// `start` est aligné sur la page ; la plage n'est utilisée par rien
    /// d'autre et ne l'est que par ce pool, pour toute sa vie. Une fois, avant
    /// toute allocation.
    ///
    /// # IRQL
    /// PASSIVE_LEVEL.
    pub unsafe fn init(&self, start: usize, initial: usize, reserved: usize) -> bool {
        assert!(start.is_multiple_of(PAGE) && initial <= reserved);
        self.with_lock(|inner| {
            inner.start = start;
            inner.end = start;
            inner.floor = start + initial * PAGE;
            inner.limit = start + reserved * PAGE;
            // SAFETY: forwarded.
            initial == 0 || unsafe { inner.grow(&self.backing, initial) }
        })
    }

    /// Bytes currently handed out (rounded up to the block or page size).
    pub fn used(&self) -> usize {
        self.with_lock(|inner| inner.used)
    }

    /// Bytes mapped but not handed out, including blocks cached in the size
    /// classes.
    pub fn free(&self) -> usize {
        self.with_lock(|inner| (inner.end - inner.start) - inner.used)
    }

    /// Bytes mapped.
    pub fn capacity(&self) -> usize {
        self.with_lock(|inner| inner.end - inner.start)
    }

    /// L'état du pool.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn stats(&self) -> PoolStats {
        self.with_lock(|inner| PoolStats { mapped: inner.end - inner.start, used: inner.used })
    }

    /// Les blocs vivants de l'étiquette `tag`.
    ///
    /// # IRQL
    /// <= DISPATCH_LEVEL.
    pub fn tag_stats(&self, tag: PoolTag) -> TagStats {
        self.with_lock(|inner| inner.tags.iter().find(|e| e.tag == tag).map(|e| e.stats).unwrap_or_default())
    }

    /// Alloue `size` octets étiquetés `tag`, alignés sur 16 ; nul si la
    /// mémoire manque.
    ///
    /// # Panics
    /// Au-dessus de l'IRQL du pool ([`PoolType::max_irql`]).
    pub fn allocate_with_tag(&self, size: usize, tag: PoolTag) -> *mut u8 {
        self.check_irql();
        let Some(total) = size.checked_add(HEADER) else {
            return ptr::null_mut();
        };
        let Ok(layout) = Layout::from_size_align(total, HEADER) else {
            return ptr::null_mut();
        };
        self.with_lock(|inner| {
            // SAFETY: the pool's invariants hold under the lock.
            let header = unsafe { inner.alloc(&self.backing, layout) }.cast::<PoolHeader>();
            if header.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: a fresh block of `total` bytes, aligned on 16.
            unsafe { header.write(PoolHeader { size, tag, magic: HEADER_MAGIC }) };
            inner.account(tag, size, true);
            // SAFETY: inside the block, just after its header.
            unsafe { header.cast::<u8>().add(HEADER) }
        })
    }

    /// Libère un bloc de [`allocate_with_tag`](Self::allocate_with_tag).
    ///
    /// # Safety
    /// `block` vient de `allocate_with_tag` sur ce pool et n'est plus utilisé.
    ///
    /// # Panics
    /// Si `block` n'est pas un bloc vivant (en-tête invalide, déjà libéré), ou
    /// si son étiquette n'est pas `tag`.
    pub unsafe fn free_with_tag(&self, block: *mut u8, tag: PoolTag) {
        self.check_irql();
        // SAFETY: the header sits just before a block of `allocate_with_tag`
        // (contract), inside its allocation.
        let header = unsafe { block.sub(HEADER) }.cast::<PoolHeader>();
        // SAFETY: as above.
        let PoolHeader { size, tag: owner, magic } = unsafe { header.read() };
        assert_eq!(magic, HEADER_MAGIC, "freeing {block:p}, which is not a live pool block");
        assert_eq!(owner, tag, "freeing a pool block of tag {owner:#010x} as tag {tag:#010x}");
        // SAFETY: as above; marks the block dead against a second free.
        unsafe { (*header).magic = 0 };
        let layout = Layout::from_size_align(size + HEADER, HEADER).unwrap_or(Layout::new::<PoolHeader>());
        self.with_lock(|inner| {
            inner.account(tag, size, false);
            // SAFETY: the block was handed out for this layout.
            unsafe { inner.dealloc(&self.backing, header.cast(), layout) };
        });
    }

    fn check_irql(&self) {
        let irql = hal::irql::current();
        assert!(irql <= self.kind.max_irql(), "{:?} pool used at IRQL {irql:?}", self.kind);
    }

    /// Runs `f` with the pool locked. On the bare-metal target, interrupts are
    /// off while the lock is held, so an interrupt can never spin on it.
    fn with_lock<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let irq = irq_save();
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held, so this is the only live reference to inner.
        let result = f(unsafe { &mut *self.inner.get() });
        self.locked.store(false, Ordering::Release);
        irq_restore(irq);
        result
    }
}

// SAFETY: blocks come from the pool's range, never overlap while live (each
// is on no free list until freed), and honour the layout's alignment (class
// blocks are aligned to their power-of-two size, page runs to the page or
// more).
unsafe impl<B: Backing> GlobalAlloc for Pool<B> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with_lock(|inner| {
            // SAFETY: the pool's invariants hold under the lock.
            let block = unsafe { inner.alloc(&self.backing, layout) };
            if !block.is_null() {
                inner.account(TAG_RUST, layout.size(), true);
            }
            block
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.with_lock(|inner| {
            inner.account(TAG_RUST, layout.size(), false);
            // SAFETY: the caller returns a block this pool handed out for `layout`.
            unsafe { inner.dealloc(&self.backing, ptr, layout) }
        })
    }
}

impl Inner {
    /// # Safety
    /// Pool invariants hold.
    unsafe fn alloc(&mut self, backing: &impl Backing, layout: Layout) -> *mut u8 {
        match class_of(layout) {
            // SAFETY: forwarded.
            Some(class) => unsafe { self.alloc_block(backing, class) },
            // SAFETY: forwarded.
            None => unsafe { self.alloc_pages(backing, pages_for(layout.size()), layout.align()) },
        }
    }

    /// # Safety
    /// `ptr` is a live block handed out by `alloc` for `layout`.
    unsafe fn dealloc(&mut self, backing: &impl Backing, ptr: *mut u8, layout: Layout) {
        match class_of(layout) {
            // SAFETY: forwarded.
            Some(class) => unsafe { self.free_block(ptr as usize, class) },
            None => {
                let pages = pages_for(layout.size());
                self.used -= pages * PAGE;
                // SAFETY: these pages were taken by alloc_pages.
                unsafe {
                    self.give_pages(ptr as usize, pages);
                    self.trim(backing);
                }
            }
        }
    }

    /// Ajoute `delta` octets (en plus ou en moins) aux blocs vivants de `tag`.
    fn account(&mut self, tag: PoolTag, bytes: usize, allocated: bool) {
        let slot = match self.tags.iter().position(|e| e.tag == tag) {
            Some(i) => i,
            None => match self.tags.iter().position(|e| e.tag == 0) {
                Some(i) if i < MAX_TAGS - 1 => {
                    self.tags[i].tag = tag;
                    i
                }
                _ => {
                    self.tags[MAX_TAGS - 1].tag = TAG_OVERFLOW;
                    MAX_TAGS - 1
                }
            },
        };
        let stats = &mut self.tags[slot].stats;
        if allocated {
            stats.allocations += 1;
            stats.bytes += bytes;
        } else {
            stats.allocations -= 1;
            stats.bytes -= bytes;
        }
    }

    /// Projette `pages` pages de plus au sommet de la plage et les ajoute aux
    /// suites libres ; `false` si la plage ou la mémoire manque.
    ///
    /// # Safety
    /// Pool invariants hold.
    unsafe fn grow(&mut self, backing: &impl Backing, pages: usize) -> bool {
        let room = (self.limit - self.end) / PAGE;
        let pages = pages.min(room);
        if pages == 0 || !backing.map(self.end, pages) {
            return false;
        }
        let at = self.end;
        self.end += pages * PAGE;
        // SAFETY: just mapped, writable, and in no run.
        unsafe { self.give_pages(at, pages) };
        true
    }

    /// Rend à la base PFN les pages libres au sommet de la plage, au-delà de
    /// [`GROW_PAGES`], sans descendre sous `floor`.
    ///
    /// # Safety
    /// Pool invariants hold.
    unsafe fn trim(&mut self, backing: &impl Backing) {
        // SAFETY: every run reached from self.runs is a free run in the range.
        unsafe {
            let mut last = self.runs;
            while !last.is_null() && !(*last).next.is_null() {
                last = (*last).next;
            }
            if last.is_null() || last as usize + (*last).pages * PAGE != self.end {
                return;
            }
            let keep_from = (last as usize + GROW_PAGES * PAGE).max(self.floor);
            if keep_from >= self.end || (self.end - keep_from) / PAGE < GROW_PAGES {
                return;
            }
            let release = (self.end - keep_from) / PAGE;
            (*last).pages -= release;
            self.end = keep_from;
            backing.unmap(keep_from, release);
        }
    }

    /// # Safety
    /// Pool invariants: the free lists and runs describe free memory in the range.
    unsafe fn alloc_block(&mut self, backing: &impl Backing, class: usize) -> *mut u8 {
        if self.classes[class].is_null() {
            // SAFETY: forwarded.
            let page = unsafe { self.take_or_grow(backing, 1, PAGE) };
            if page == 0 {
                return ptr::null_mut();
            }
            let size = class_size(class);
            // Thread the new page's blocks onto the class list, lowest first.
            for offset in (0..PAGE).step_by(size).rev() {
                let block = (page + offset) as *mut FreeBlock;
                // SAFETY: the page was just taken from the runs; block is inside it.
                unsafe { block.write(FreeBlock { next: self.classes[class] }) };
                self.classes[class] = block;
            }
        }
        let block = self.classes[class];
        // SAFETY: block heads the class list, so it is a free block of this class.
        self.classes[class] = unsafe { (*block).next };
        self.used += class_size(class);
        block as *mut u8
    }

    /// # Safety
    /// `addr` must be a live block of `class` handed out by `alloc_block`.
    unsafe fn free_block(&mut self, addr: usize, class: usize) {
        let block = addr as *mut FreeBlock;
        // SAFETY: the block is ours again and at least MIN_BLOCK bytes.
        unsafe { block.write(FreeBlock { next: self.classes[class] }) };
        self.classes[class] = block;
        self.used -= class_size(class);
    }

    /// # Safety
    /// Pool invariants hold.
    unsafe fn alloc_pages(&mut self, backing: &impl Backing, pages: usize, align: usize) -> *mut u8 {
        // SAFETY: forwarded.
        let addr = unsafe { self.take_or_grow(backing, pages, align) };
        if addr == 0 {
            return ptr::null_mut();
        }
        self.used += pages * PAGE;
        addr as *mut u8
    }

    /// [`take_pages`](Self::take_pages), après avoir grandi s'il le faut :
    /// d'au moins [`GROW_PAGES`], ou, si la mémoire manque pour cela, de juste
    /// assez pour la demande et son alignement.
    ///
    /// # Safety
    /// Pool invariants hold.
    unsafe fn take_or_grow(&mut self, backing: &impl Backing, pages: usize, align: usize) -> usize {
        // SAFETY: forwarded.
        unsafe {
            let addr = self.take_pages(pages, align);
            if addr != 0 {
                return addr;
            }
            let needed = pages + align.max(PAGE) / PAGE - 1;
            if !self.grow(backing, needed.max(GROW_PAGES)) && !self.grow(backing, needed) {
                return 0;
            }
            self.take_pages(pages, align)
        }
    }
    /// Takes `pages` pages aligned to `align` (at least a page) from the first
    /// run that fits, splitting it. Returns 0 when nothing fits.
    ///
    /// # Safety
    /// Pool invariants hold.
    unsafe fn take_pages(&mut self, pages: usize, align: usize) -> usize {
        let align = align.max(PAGE);
        let mut link: *mut *mut FreeRun = &mut self.runs;
        // SAFETY: every run reached from self.runs is a free run in the range.
        unsafe {
            while !(*link).is_null() {
                let run = *link;
                let run_start = run as usize;
                let run_end = run_start + (*run).pages * PAGE;
                let start = align_up(run_start, align);
                let end = start + pages * PAGE;
                if end <= run_end {
                    let next = (*run).next;
                    // Unlink the run, then give back what is left on both sides.
                    *link = next;
                    if start > run_start {
                        self.give_pages(run_start, (start - run_start) / PAGE);
                    }
                    if run_end > end {
                        self.give_pages(end, (run_end - end) / PAGE);
                    }
                    return start;
                }
                link = &mut (*run).next;
            }
        }
        0
    }

    /// Inserts `[addr, addr + pages * PAGE)` into the runs, merging neighbours.
    ///
    /// # Safety
    /// The pages must be free, mapped, page-aligned, inside the range and not
    /// already in a run.
    unsafe fn give_pages(&mut self, addr: usize, pages: usize) {
        if pages == 0 {
            return;
        }
        let mut prev: *mut FreeRun = ptr::null_mut();
        let mut next = self.runs;
        // SAFETY: runs reached from self.runs are free runs in the region; the
        // new pages are free and ours to write.
        unsafe {
            while !next.is_null() && (next as usize) < addr {
                prev = next;
                next = (*next).next;
            }
            let run = addr as *mut FreeRun;
            run.write(FreeRun { pages, next });
            if !next.is_null() && addr + pages * PAGE == next as usize {
                (*run).pages += (*next).pages;
                (*run).next = (*next).next;
            }
            if prev.is_null() {
                self.runs = run;
            } else if prev as usize + (*prev).pages * PAGE == addr {
                (*prev).pages += (*run).pages;
                (*prev).next = (*run).next;
            } else {
                (*prev).next = run;
            }
        }
    }
}

/// Size class for `layout`, or `None` when it needs whole pages.
fn class_of(layout: Layout) -> Option<usize> {
    let size = layout.size().max(layout.align()).max(MIN_BLOCK).next_power_of_two();
    if size > MAX_BLOCK {
        return None;
    }
    Some((size.trailing_zeros() - MIN_BLOCK.trailing_zeros()) as usize)
}

const fn class_size(class: usize) -> usize {
    MIN_BLOCK << class
}

fn pages_for(size: usize) -> usize {
    size.max(1).div_ceil(PAGE)
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(target_os = "none")]
fn irq_save() -> bool {
    let enabled = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();
    enabled
}

#[cfg(target_os = "none")]
fn irq_restore(enabled: bool) {
    if enabled {
        x86_64::instructions::interrupts::enable();
    }
}

// Host tests run in user mode, where cli/sti fault: the lock alone serialises.
#[cfg(not(target_os = "none"))]
fn irq_save() -> bool {
    false
}

#[cfg(not(target_os = "none"))]
fn irq_restore(_enabled: bool) {}

/// Le pool non paginé : allocateur global de Rust et `PoolType::NonPaged`.
pub static NONPAGED_POOL: Pool<KernelBacking> =
    Pool::new(PoolType::NonPaged, KernelBacking { usage: PageUsage::NonPagedPool });

/// Le pool paginé (`PoolType::Paged`), jamais paginé encore (ADR-010).
pub static PAGED_POOL: Pool<KernelBacking> = Pool::new(PoolType::Paged, KernelBacking { usage: PageUsage::PagedPool });

/// Début de la plage du pool non paginé (02 §4.2).
pub const NONPAGED_POOL_START: usize = 0xFFFF_8800_0000_0000;
/// Début de la plage du pool paginé, après celle du non paginé.
pub const PAGED_POOL_START: usize = 0xFFFF_8C00_0000_0000;
/// Pages réservées à chaque pool : 16 Gio d'adresses.
const POOL_RESERVED_PAGES: usize = (16 << 30) / PAGE;
/// Pages projetées dès le départ, qui le restent : la table de pages du haut de
/// chaque plage existe ainsi avant la première PML4 de processus, qui recopie
/// la moitié haute de celle du système (02 §4.2).
const NONPAGED_INITIAL_PAGES: usize = 256;
const PAGED_INITIAL_PAGES: usize = 16;

/// Donne leurs plages aux deux pools du noyau.
///
/// # Safety
/// Une fois, après `mm::init`, avant toute allocation.
///
/// # IRQL
/// PASSIVE_LEVEL.
pub unsafe fn init() {
    // SAFETY: les plages de 02 §4.2 ne servent qu'aux pools ; une fois.
    let ready = unsafe {
        NONPAGED_POOL.init(NONPAGED_POOL_START, NONPAGED_INITIAL_PAGES, POOL_RESERVED_PAGES)
            && PAGED_POOL.init(PAGED_POOL_START, PAGED_INITIAL_PAGES, POOL_RESERVED_PAGES)
    };
    assert!(ready, "out of physical memory for the kernel pools");
}

/// ExAllocatePoolWithTag : `size` octets du pool `pool`, étiquetés `tag`,
/// alignés sur 16 ; nul si la mémoire manque.
///
/// # IRQL
/// <= DISPATCH_LEVEL pour le pool non paginé, <= APC_LEVEL pour le paginé.
pub fn ex_allocate_pool_with_tag(pool: PoolType, size: usize, tag: PoolTag) -> *mut u8 {
    kernel_pool(pool).allocate_with_tag(size, tag)
}

/// ExFreePoolWithTag : libère un bloc de [`ex_allocate_pool_with_tag`].
///
/// # Safety
/// `block` vient de `ex_allocate_pool_with_tag` sur le pool `pool` et n'est
/// plus utilisé.
///
/// # IRQL
/// Comme [`ex_allocate_pool_with_tag`].
pub unsafe fn ex_free_pool_with_tag(pool: PoolType, block: *mut u8, tag: PoolTag) {
    // SAFETY: forwarded.
    unsafe { kernel_pool(pool).free_with_tag(block, tag) };
}

/// Le pool du noyau de ce type.
pub fn kernel_pool(pool: PoolType) -> &'static Pool<KernelBacking> {
    match pool {
        PoolType::NonPaged => &NONPAGED_POOL,
        PoolType::Paged => &PAGED_POOL,
    }
}

/// Les pages des pools du noyau : prises à la base PFN pour leur usage, et
/// projetées dans les tables de pages du noyau (RW, NX).
pub struct KernelBacking {
    usage: PageUsage,
}

impl Backing for KernelBacking {
    fn map(&self, addr: usize, pages: usize) -> bool {
        use x86_64::structures::paging::PageTableFlags as F;
        // SAFETY: HHDM_OFFSET is the bootloader's offset, recorded by mm::init,
        // and the active CR3 shares the kernel half.
        let mut pt = unsafe { crate::MmPageTables::new(crate::HHDM_OFFSET.load(Ordering::Acquire)) };
        for i in 0..pages {
            let Some(pfn) = crate::pfn::allocate_page(self.usage) else {
                self.unmap(addr, i);
                return false;
            };
            let virt = x86_64::VirtAddr::new((addr + i * PAGE) as u64);
            // SAFETY: the pool hands over an unmapped page of its range; `pfn`
            // is a page just allocated.
            unsafe {
                pt.map_page(virt, x86_64::PhysAddr::new(pfn.to_phys()), F::PRESENT | F::WRITABLE | F::NO_EXECUTE)
            };
        }
        true
    }

    fn unmap(&self, addr: usize, pages: usize) {
        // SAFETY: as in `map`.
        let mut pt = unsafe { crate::MmPageTables::new(crate::HHDM_OFFSET.load(Ordering::Acquire)) };
        for i in 0..pages {
            // SAFETY: `map` projected these pages; the pool no longer uses them.
            let frame = unsafe { pt.unmap_page(x86_64::VirtAddr::new((addr + i * PAGE) as u64)) };
            crate::pfn::free_page(crate::Pfn(frame.start_address().as_u64() / PAGE as u64));
        }
    }
}

/// L'allocateur global de Rust : le pool non paginé, sous [`TAG_RUST`]. Le
/// noyau le déclare `#[global_allocator]`.
pub struct GlobalPool;

// SAFETY: forwards to `NONPAGED_POOL`, a `GlobalAlloc`.
unsafe impl GlobalAlloc for GlobalPool {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded.
        unsafe { NONPAGED_POOL.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded.
        unsafe { NONPAGED_POOL.dealloc(ptr, layout) }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::Cell;

    /// Les pages d'un pool de test : un tampon de l'hôte, déjà là. `map` suit
    /// ce qui est projeté, et refuse au-delà de `budget` pages, comme une
    /// mémoire physique épuisée.
    struct HostBacking {
        mapped: Cell<usize>,
        budget: Cell<usize>,
    }

    impl Backing for HostBacking {
        fn map(&self, _: usize, pages: usize) -> bool {
            let fits = self.mapped.get() + pages <= self.budget.get();
            if fits {
                self.mapped.set(self.mapped.get() + pages);
            }
            fits
        }

        fn unmap(&self, _: usize, pages: usize) {
            self.mapped.set(self.mapped.get() - pages);
        }
    }

    /// A pool over a fresh page-aligned host buffer, freed on drop.
    struct TestPool {
        pool: Pool<HostBacking>,
        base: *mut u8,
        layout: Layout,
    }

    impl TestPool {
        /// Un pool de `size` octets, tous projetés d'avance : il ne grandit ni
        /// ne rétrécit.
        fn new(size: usize) -> Self {
            Self::growable(size / PAGE, size / PAGE, size / PAGE)
        }

        /// Un pool de `reserved` pages, dont `initial` projetées d'avance, qui
        /// peut en projeter `budget` au total.
        fn growable(initial: usize, reserved: usize, budget: usize) -> Self {
            let layout = Layout::from_size_align(reserved * PAGE, PAGE).unwrap();
            // SAFETY: non-zero size.
            let base = unsafe { std::alloc::alloc(layout) };
            assert!(!base.is_null());
            let backing = HostBacking { mapped: Cell::new(0), budget: Cell::new(budget) };
            let pool = Pool::new(PoolType::NonPaged, backing);
            // SAFETY: the buffer is ours, page-aligned, writable, and outlives the pool.
            assert!(unsafe { pool.init(base as usize, initial, reserved) });
            Self { pool, base, layout }
        }

        fn mapped_pages(&self) -> usize {
            self.pool.backing.mapped.get()
        }

        fn alloc(&self, size: usize, align: usize) -> *mut u8 {
            // SAFETY: valid layout with non-zero size.
            unsafe { self.pool.alloc(Layout::from_size_align(size, align).unwrap()) }
        }

        fn dealloc(&self, ptr: *mut u8, size: usize, align: usize) {
            // SAFETY: ptr came from alloc with the same layout.
            unsafe { self.pool.dealloc(ptr, Layout::from_size_align(size, align).unwrap()) }
        }

        fn contains(&self, ptr: *mut u8, size: usize) -> bool {
            let (p, b) = (ptr as usize, self.base as usize);
            p >= b && p + size <= b + self.layout.size()
        }
    }

    impl Drop for TestPool {
        fn drop(&mut self) {
            // SAFETY: allocated in new() with this layout.
            unsafe { std::alloc::dealloc(self.base, self.layout) };
        }
    }

    // ── Ported from bump-alloc ────────────────────────────────────────────────

    #[test]
    fn alloc_single_byte_returns_non_null() {
        let t = TestPool::new(64 * 1024);
        assert!(!t.alloc(1, 1).is_null());
    }

    #[test]
    fn alloc_returns_different_pointers() {
        let t = TestPool::new(64 * 1024);
        assert_ne!(t.alloc(8, 8), t.alloc(8, 8));
    }

    #[test]
    fn alloc_non_overlapping_ranges() {
        let t = TestPool::new(64 * 1024);
        let a = t.alloc(100, 8) as usize;
        let b = t.alloc(100, 8) as usize;
        assert!(a + 100 <= b || b + 100 <= a);
    }

    #[test]
    fn alloc_respects_alignment() {
        let t = TestPool::new(256 * 1024);
        for align in [1, 2, 8, 16, 64, 256, 4096, 8192] {
            let p = t.alloc(24, align);
            assert!(!p.is_null());
            assert_eq!(p as usize % align, 0, "align {align}");
        }
    }

    #[test]
    fn alloc_returns_null_on_oom() {
        let t = TestPool::new(16 * 1024);
        assert!(t.alloc(64 * 1024, 8).is_null());
    }

    #[test]
    fn alloc_exactly_fills_heap() {
        let t = TestPool::new(16 * 1024);
        let p = t.alloc(16 * 1024, 8);
        assert!(!p.is_null() && t.contains(p, 16 * 1024));
        assert!(t.alloc(1, 1).is_null(), "heap is full");
    }

    #[test]
    fn capacity_reflects_init_size() {
        let t = TestPool::new(64 * 1024);
        assert_eq!(t.pool.capacity(), 64 * 1024);
    }

    #[test]
    fn used_and_free_track_allocations() {
        let t = TestPool::new(64 * 1024);
        assert_eq!(t.pool.used(), 0);
        let p = t.alloc(100, 8); // 128-byte class
        assert_eq!(t.pool.used(), 128);
        assert_eq!(t.pool.free(), 64 * 1024 - 128);
        t.dealloc(p, 100, 8);
        assert_eq!(t.pool.used(), 0);
    }

    #[test]
    fn mixed_small_then_large_alloc_succeeds() {
        let t = TestPool::new(256 * 1024);
        for _ in 0..50 {
            assert!(!t.alloc(48, 8).is_null());
        }
        let big = t.alloc(12 * 1024, 16);
        assert!(!big.is_null() && t.contains(big, 12 * 1024));
    }

    #[test]
    fn hundred_varied_allocs_then_large() {
        let t = TestPool::new(1024 * 1024);
        for i in 1..=100 {
            assert!(!t.alloc(i * 7, 8).is_null());
        }
        assert!(!t.alloc(64 * 1024, 4096).is_null());
    }

    // ── Real freeing ──────────────────────────────────────────────────────────

    #[test]
    fn freed_block_is_reused() {
        let t = TestPool::new(64 * 1024);
        let a = t.alloc(200, 8);
        t.dealloc(a, 200, 8);
        assert_eq!(t.alloc(200, 8), a);
    }

    #[test]
    fn freed_pages_merge_back_into_one_run() {
        let t = TestPool::new(24 * 1024);
        let a = t.alloc(8 * 1024, 8);
        let b = t.alloc(8 * 1024, 8);
        let c = t.alloc(8 * 1024, 8);
        assert!(t.alloc(4096, 8).is_null(), "full");
        // Free in an order that needs both forward and backward merges.
        t.dealloc(a, 8 * 1024, 8);
        t.dealloc(c, 8 * 1024, 8);
        t.dealloc(b, 8 * 1024, 8);
        let all = t.alloc(24 * 1024, 8);
        assert_eq!(all, t.base, "the three runs merged into the whole region");
    }

    #[test]
    fn oom_recovers_after_free() {
        let t = TestPool::new(16 * 1024);
        let p = t.alloc(16 * 1024, 8);
        assert!(t.alloc(4096, 8).is_null());
        t.dealloc(p, 16 * 1024, 8);
        assert!(!t.alloc(4096, 8).is_null());
    }

    /// The pattern that made `linked_list_allocator` "corrupt" (bump-alloc
    /// notes): B-tree-node-sized blocks mixed with ~12 KiB blocks, here with
    /// frees and content checks.
    #[test]
    fn btree_nodes_mixed_with_12k_blocks_keep_their_contents() {
        let t = TestPool::new(2 * 1024 * 1024);
        let mut live: Vec<(*mut u8, usize, u8)> = Vec::new();
        for round in 0..400usize {
            let size = if round % 5 == 4 { 12 * 1024 } else { 128 + (round * 37) % 160 };
            let p = t.alloc(size, 8);
            assert!(!p.is_null() && t.contains(p, size), "round {round}");
            let tag = round as u8;
            // SAFETY: p is a live block of `size` bytes.
            unsafe { ptr::write_bytes(p, tag, size) };
            live.push((p, size, tag));
            if round % 3 == 2 {
                let (q, qs, qt) = live.remove(round % live.len());
                // SAFETY: q is live with qs bytes.
                assert!(unsafe { core::slice::from_raw_parts(q, qs) }.iter().all(|&b| b == qt));
                t.dealloc(q, qs, 8);
            }
        }
        for (p, size, tag) in live {
            // SAFETY: p is live with size bytes.
            assert!(unsafe { core::slice::from_raw_parts(p, size) }.iter().all(|&b| b == tag));
        }
    }

    /// Random sizes and alignments, random frees, content checked on every free.
    #[test]
    fn random_workload_never_overlaps() {
        let t = TestPool::new(4 * 1024 * 1024);
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut live: BTreeMap<usize, (usize, usize, u8)> = BTreeMap::new();
        for i in 0..5000u32 {
            if live.is_empty() || rand() % 3 != 0 {
                let size = match rand() % 10 {
                    0 => 4096 + (rand() % 20_000) as usize,
                    _ => 1 + (rand() % 2500) as usize,
                };
                let align = 1usize << (rand() % 7);
                let p = t.alloc(size, align);
                if p.is_null() {
                    continue;
                }
                let addr = p as usize;
                assert_eq!(addr % align, 0);
                assert!(t.contains(p, size));
                if let Some((&a, &(s, _, _))) = live.range(..=addr).next_back() {
                    assert!(a + s <= addr, "overlaps the block below");
                }
                if let Some((&a, _)) = live.range(addr..).next() {
                    assert!(addr + size <= a, "overlaps the block above");
                }
                let tag = i as u8;
                // SAFETY: p is a live block of `size` bytes.
                unsafe { ptr::write_bytes(p, tag, size) };
                live.insert(addr, (size, align, tag));
            } else {
                let key = *live.keys().nth((rand() as usize) % live.len()).unwrap();
                let (size, align, tag) = live.remove(&key).unwrap();
                // SAFETY: key is a live block of `size` bytes.
                let bytes = unsafe { core::slice::from_raw_parts(key as *const u8, size) };
                assert!(bytes.iter().all(|&b| b == tag), "block at {key:#x} was overwritten");
                t.dealloc(key as *mut u8, size, align);
            }
        }
        for (addr, (size, align, _)) in core::mem::take(&mut live) {
            t.dealloc(addr as *mut u8, size, align);
        }
        assert_eq!(t.pool.used(), 0);
    }

    // ── Croissance et restitution ────────────────────────────────────────────

    #[test]
    fn a_pool_grows_on_demand_by_at_least_a_chunk() {
        let t = TestPool::growable(1, 1024, 1024);
        assert_eq!(t.mapped_pages(), 1);
        let p = t.alloc(3 * PAGE, 8);
        assert!(!p.is_null() && t.contains(p, 3 * PAGE));
        assert_eq!(t.mapped_pages(), 1 + GROW_PAGES, "one chunk, not three pages");
        assert_eq!(t.pool.capacity(), (1 + GROW_PAGES) * PAGE);
        for _ in 0..100 {
            assert!(!t.alloc(2000, 8).is_null(), "slabs grow the pool too");
        }
    }

    #[test]
    fn a_pool_gives_back_its_free_pages_at_the_top_beyond_a_chunk() {
        let t = TestPool::growable(1, 2048, 2048);
        let big = t.alloc(200 * PAGE, 8);
        assert!(!big.is_null());
        assert_eq!(t.mapped_pages(), 201);
        t.dealloc(big, 200 * PAGE, 8);
        assert_eq!(t.mapped_pages(), GROW_PAGES, "a chunk kept for the next allocations");
        assert_eq!(t.pool.used(), 0);
        let again = t.alloc(200 * PAGE, 8);
        assert!(!again.is_null(), "it grows again");
        t.dealloc(again, 200 * PAGE, 8);
    }

    #[test]
    fn a_pool_never_gives_back_its_initial_pages() {
        let t = TestPool::growable(300, 2048, 2048);
        let big = t.alloc(250 * PAGE, 8);
        t.dealloc(big, 250 * PAGE, 8);
        assert_eq!(t.mapped_pages(), 300);
    }

    #[test]
    fn growth_stops_at_the_end_of_the_range() {
        let t = TestPool::growable(1, 16, 1024);
        assert!(t.alloc(32 * PAGE, 8).is_null());
        assert!(!t.alloc(15 * PAGE, 8).is_null(), "what is left of the range");
    }

    #[test]
    fn short_of_memory_a_pool_grows_by_just_enough_then_fails_cleanly() {
        let t = TestPool::growable(1, 1024, 8);
        assert!(!t.alloc(4 * PAGE, 8).is_null(), "a chunk would not fit: four pages do");
        assert_eq!(t.mapped_pages(), 5);
        assert!(t.alloc(16 * PAGE, 8).is_null());
        assert_eq!(t.mapped_pages(), 5, "nothing taken by the failure");
    }

    #[test]
    fn aligned_requests_grow_enough_for_their_alignment() {
        let t = TestPool::growable(1, 4096, 4096);
        for (pages, align) in [(16, 64 * 1024), (64, 256 * 1024)] {
            let p = t.alloc(pages * PAGE, align);
            assert!(!p.is_null() && (p as usize).is_multiple_of(align));
        }
    }

    // ── Étiquettes ───────────────────────────────────────────────────────────

    const T1: PoolTag = tag(b"Tst1");
    const T2: PoolTag = tag(b"Tst2");

    #[test]
    fn tagged_blocks_are_counted_per_tag_until_freed() {
        let t = TestPool::new(64 * 1024);
        let a = t.pool.allocate_with_tag(100, T1);
        let b = t.pool.allocate_with_tag(5000, T1);
        let c = t.pool.allocate_with_tag(40, T2);
        for (p, size) in [(a, 100), (b, 5000), (c, 40)] {
            assert!(!p.is_null() && (p as usize).is_multiple_of(16));
            // SAFETY: a live block of `size` bytes.
            unsafe { ptr::write_bytes(p, 0xA5, size) };
        }
        assert_eq!(t.pool.tag_stats(T1), TagStats { allocations: 2, bytes: 5100 });
        assert_eq!(t.pool.tag_stats(T2), TagStats { allocations: 1, bytes: 40 });
        // SAFETY: live blocks of this pool, with their tags.
        unsafe {
            t.pool.free_with_tag(b, T1);
            t.pool.free_with_tag(a, T1);
            t.pool.free_with_tag(c, T2);
        }
        assert_eq!(t.pool.tag_stats(T1), TagStats::default());
        assert_eq!(t.pool.tag_stats(T2), TagStats::default());
        assert_eq!(t.pool.used(), 0);
    }

    #[test]
    #[should_panic(expected = "as tag")]
    fn freeing_with_another_tag_stops() {
        let t = TestPool::new(64 * 1024);
        let a = t.pool.allocate_with_tag(100, T1);
        // SAFETY: a live block of this pool (wrong tag on purpose).
        unsafe { t.pool.free_with_tag(a, T2) };
    }

    #[test]
    #[should_panic(expected = "not a live pool block")]
    fn freeing_twice_stops() {
        let t = TestPool::new(64 * 1024);
        let a = t.pool.allocate_with_tag(100, T1);
        // SAFETY: freed once, then again on purpose; the memory stays mapped.
        unsafe {
            t.pool.free_with_tag(a, T1);
            t.pool.free_with_tag(a, T1);
        }
    }

    #[test]
    fn tags_beyond_the_table_count_together() {
        let t = TestPool::new(256 * 1024);
        let tags: Vec<PoolTag> = (0..MAX_TAGS as u32 + 5).map(|i| 0x4000_0000 + i).collect();
        let blocks: Vec<*mut u8> = tags.iter().map(|&tag| t.pool.allocate_with_tag(8, tag)).collect();
        assert_eq!(t.pool.tag_stats(TAG_OVERFLOW).allocations, tags.len() - (MAX_TAGS - 1));
        for (&block, &tag) in blocks.iter().zip(&tags) {
            // SAFETY: live blocks of this pool, with their tags.
            unsafe { t.pool.free_with_tag(block, tag) };
        }
        assert_eq!(t.pool.tag_stats(TAG_OVERFLOW), TagStats::default());
    }

    #[test]
    fn rust_allocations_count_under_their_tag() {
        let t = TestPool::new(64 * 1024);
        let p = t.alloc(100, 8);
        let q = t.alloc(9000, 8);
        assert_eq!(t.pool.tag_stats(TAG_RUST), TagStats { allocations: 2, bytes: 9100 });
        t.dealloc(p, 100, 8);
        t.dealloc(q, 9000, 8);
        assert_eq!(t.pool.tag_stats(TAG_RUST), TagStats::default());
    }

    #[test]
    fn each_pool_type_has_its_irql_limit() {
        assert_eq!(PoolType::NonPaged.max_irql(), Irql::Dispatch);
        assert_eq!(PoolType::Paged.max_irql(), Irql::Apc);
    }

    #[test]
    fn class_of_maps_layouts_to_classes() {
        let l = |s, a| Layout::from_size_align(s, a).unwrap();
        assert_eq!(class_of(l(1, 1)), Some(0));
        assert_eq!(class_of(l(16, 8)), Some(0));
        assert_eq!(class_of(l(17, 8)), Some(1));
        assert_eq!(class_of(l(8, 64)), Some(2), "alignment raises the class");
        assert_eq!(class_of(l(2048, 8)), Some(7));
        assert_eq!(class_of(l(2049, 8)), None);
        assert_eq!(class_of(l(8, 4096)), None, "page alignment needs whole pages");
    }
}
