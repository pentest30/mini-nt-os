//! Kernel stacks, each above an unmapped reserve (02 §4.2).
//!
//! Stacks live in their own kernel region, one fixed-size slot per stack:
//!
//! ```text
//!   slot n:  [ guard page | reserve (unmapped) | 24 KiB stack (RW, NX) ]
//!            ^ base(n)                         ^ bottom(n)             ^ top(n) = base(n + 1)
//! ```
//!
//! A stack starts with [`KERNEL_STACK_SIZE`] bytes; [`grow`] maps pages of
//! the reserve below it, in place, up to [`KERNEL_LARGE_STACK_SIZE`]
//! (MmGrowKernelStack: a thread that calls back into user mode needs more,
//! `ps::callback`). Nothing moves, so nothing that points into the stack
//! needs fixing. The guard page stays unmapped for good: an overflow runs
//! into the reserve or the guard page and an underflow into the next slot's,
//! so the CPU faults instead of silently corrupting a neighbour;
//! [`guard_hit`] lets the fault handlers name the stack involved.
//!
//! [`free`] gives a stack's pages back and its slot to the next
//! [`allocate`]. The region sits under a PML4 entry of the kernel half, filled
//! at boot and shared by every address space (`mm::address_space`).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hal::sync::KSpinLock;

use abi::ntstatus::{NtStatus, STATUS_NO_MEMORY, STATUS_STACK_OVERFLOW};
use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};

use crate::paging::MmPageTables;
use crate::pfn::PageUsage;

/// Size of every kernel stack from [`allocate`].
pub const KERNEL_STACK_SIZE: u64 = 24 * 1024;
/// Most a stack reaches by [`grow`] (KERNEL_LARGE_STACK_SIZE of a 64-bit
/// NT kernel).
pub const KERNEL_LARGE_STACK_SIZE: u64 = 72 * 1024;
/// Unmapped page below every stack's reserve.
pub const GUARD_SIZE: u64 = 4096;
/// Start of the kernel stack region (02 §4.2).
pub const REGION_BASE: u64 = 0xFFFF_B000_0000_0000;
/// Number of slots in the region.
pub const MAX_STACKS: u64 = 4096;

const SLOT_SIZE: u64 = GUARD_SIZE + KERNEL_LARGE_STACK_SIZE;
const PAGES: usize = (KERNEL_STACK_SIZE / 4096) as usize;
const STACK_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits() | PageTableFlags::NO_EXECUTE.bits(),
);

/// Number of slots handed out so far: the high-water mark of the region.
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
/// Slots below the high-water mark that [`free`] gave back.
static FREE_SLOTS: KSpinLock<Vec<u64>> = KSpinLock::new(Vec::new());

/// A mapped kernel stack: `[bottom, top)`, growing down from `top`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelStack {
    /// Lowest mapped address; the unmapped reserve, or the guard page, ends
    /// here.
    pub bottom: u64,
    /// One past the highest mapped address; the initial stack pointer.
    pub top: u64,
}

impl KernelStack {
    /// Lowest address the stack may reach by [`grow`]: its guard page ends
    /// here.
    pub const fn limit(&self) -> u64 {
        self.top - KERNEL_LARGE_STACK_SIZE
    }
}

const fn slot_base(slot: u64) -> u64 {
    REGION_BASE + slot * SLOT_SIZE
}

/// The stack of `slot` as [`allocate`] gives it.
const fn stack_of_slot(slot: u64) -> KernelStack {
    let top = slot_base(slot + 1);
    KernelStack { bottom: top - KERNEL_STACK_SIZE, top }
}

/// The slot of a stack, from its top.
fn slot_of(stack: &KernelStack) -> u64 {
    (stack.top - REGION_BASE) / SLOT_SIZE - 1
}

/// Allocates a kernel stack: 24 KiB of fresh, zeroed frames under an unmapped
/// guard page. Returns `None` when the region or physical memory is exhausted.
///
/// # IRQL
/// PASSIVE_LEVEL. Allocates pages (`mm::pfn`) and edits the kernel page tables.
pub fn allocate() -> Option<KernelStack> {
    let freed = FREE_SLOTS.lock().pop();
    let slot = match freed {
        Some(slot) => slot,
        None => {
            ALLOCATED.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_STACKS).then_some(n + 1)).ok()?
        }
    };
    let stack = stack_of_slot(slot);

    let mut frames = [0u64; PAGES];
    for i in 0..PAGES {
        let Some(pfn) = crate::pfn::allocate_page(PageUsage::KernelStack) else {
            frames[..i].iter().for_each(|&phys| crate::pfn::free_page(crate::Pfn(phys / 4096)));
            FREE_SLOTS.lock().push(slot);
            return None;
        };
        frames[i] = pfn.to_phys();
    }

    // SAFETY: HHDM_OFFSET is the bootloader's offset, recorded by mm::init, and
    // the active CR3 holds the kernel page tables.
    let mut pt = unsafe { MmPageTables::new(crate::HHDM_OFFSET.load(Ordering::Acquire)) };
    for (i, &phys) in frames.iter().enumerate() {
        let virt = VirtAddr::new(stack.bottom + (i as u64) * 4096);
        // SAFETY: this slot was handed out once above, so its pages are not
        // mapped yet; `phys` is a frame just allocated.
        unsafe { pt.map_page(virt, PhysAddr::new(phys), STACK_FLAGS) };
    }
    // SAFETY: [bottom, top) was mapped writable just above.
    unsafe { core::ptr::write_bytes(stack.bottom as *mut u8, 0, KERNEL_STACK_SIZE as usize) };
    Some(stack)
}

/// Gives back a stack from [`allocate`]: its pages go back to the PFN
/// database and its slot to the next [`allocate`].
///
/// # Safety
/// `stack` came from [`allocate`], is freed once, and nothing runs on it or
/// points into it any more.
///
/// # IRQL
/// PASSIVE_LEVEL. Edits the kernel page tables.
pub unsafe fn free(stack: KernelStack) {
    let slot = slot_of(&stack);
    assert!(
        stack.top == stack_of_slot(slot).top
            && stack.bottom >= stack.limit()
            && stack.bottom <= stack_of_slot(slot).bottom
            && stack.bottom.is_multiple_of(4096),
        "not a kernel stack: {stack:x?}"
    );
    // SAFETY: as in `allocate`.
    let mut pt = unsafe { MmPageTables::new(crate::HHDM_OFFSET.load(Ordering::Acquire)) };
    for page in (stack.bottom..stack.top).step_by(4096) {
        // SAFETY: `allocate` and `grow` mapped every page of the stack, and
        // nothing uses them any more (contract).
        let frame = unsafe { pt.unmap_page(VirtAddr::new(page)) };
        crate::pfn::free_page(crate::Pfn(frame.start_address().as_u64() / 4096));
    }
    FREE_SLOTS.lock().push(slot);
}

/// MmGrowKernelStack: maps zeroed pages of the reserve under `stack`, in
/// place, so that it reaches down to `bottom` (rounded down to a page). A
/// stack that already reaches it is left as it is.
///
/// # Errors
/// `STATUS_STACK_OVERFLOW` if `bottom` is under the stack's
/// [`limit`](KernelStack::limit); `STATUS_NO_MEMORY` without the frames
/// (the stack is then left as it was).
///
/// # IRQL
/// PASSIVE_LEVEL. Allocates pages (`mm::pfn`) and edits the kernel page
/// tables.
pub fn grow(stack: &mut KernelStack, bottom: u64) -> Result<(), NtStatus> {
    let bottom = bottom & !0xFFF;
    let new = grown_range(stack, bottom)?;
    if new.is_empty() {
        return Ok(());
    }
    // SAFETY: as in `allocate`.
    let mut pt = unsafe { MmPageTables::new(crate::HHDM_OFFSET.load(Ordering::Acquire)) };
    // From the top down: a failure leaves the pages mapped so far contiguous.
    let mut page = new.end;
    while page > new.start {
        page -= 4096;
        let Some(pfn) = crate::pfn::allocate_page(PageUsage::KernelStack) else {
            for mapped in (page + 4096..new.end).step_by(4096) {
                // SAFETY: mapped just below, by this call; not in use yet.
                let frame = unsafe { pt.unmap_page(VirtAddr::new(mapped)) };
                crate::pfn::free_page(crate::Pfn(frame.start_address().as_u64() / 4096));
            }
            return Err(STATUS_NO_MEMORY);
        };
        // SAFETY: a page of the slot's reserve, which no one maps but its
        // stack's owner, under the stack's bottom; `pfn` was just allocated.
        unsafe {
            pt.map_page(VirtAddr::new(page), PhysAddr::new(pfn.to_phys()), STACK_FLAGS);
            core::ptr::write_bytes(page as *mut u8, 0, 4096);
        }
    }
    stack.bottom = bottom;
    Ok(())
}

/// The pages [`grow`] maps for `stack` to reach `bottom`, page aligned:
/// none (an empty range) if it reaches it already.
fn grown_range(stack: &KernelStack, bottom: u64) -> Result<core::ops::Range<u64>, NtStatus> {
    if bottom < stack.limit() {
        return Err(STATUS_STACK_OVERFLOW);
    }
    Ok(bottom..stack.bottom)
}

/// If `addr` lies under the stack of its slot as [`allocate`] gives it (in
/// the reserve or the guard page), returns that stack (overflow); in the
/// guard page just past the region in use, returns the last stack
/// (underflow). The fault handlers ask only for addresses that faulted:
/// a stack that [`grow`] extended does not fault in its new pages.
///
/// # IRQL
/// Any level. Lock-free, for use from fault handlers.
pub fn guard_hit(addr: u64) -> Option<KernelStack> {
    guard_hit_in(addr, ALLOCATED.load(Ordering::Acquire))
}

fn guard_hit_in(addr: u64, allocated: u64) -> Option<KernelStack> {
    let offset = addr.checked_sub(REGION_BASE)?;
    let slot = offset / SLOT_SIZE;
    let below = if slot < allocated { SLOT_SIZE - KERNEL_STACK_SIZE } else { GUARD_SIZE };
    if allocated == 0 || slot > allocated || offset % SLOT_SIZE >= below {
        return None;
    }
    Some(stack_of_slot(slot.min(allocated - 1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_contiguous_and_aligned() {
        let s0 = stack_of_slot(0);
        let s1 = stack_of_slot(1);
        assert_eq!(s0.limit(), REGION_BASE + GUARD_SIZE, "the guard page is under the reserve");
        assert_eq!(s0.top - s0.bottom, KERNEL_STACK_SIZE);
        assert_eq!(s0.top, slot_base(1), "a stack's top is the next slot's guard page");
        assert_eq!(s1.limit() - s0.top, GUARD_SIZE);
        assert_eq!(s1.top - s1.limit(), KERNEL_LARGE_STACK_SIZE);
        assert_eq!(s0.top % 16, 0, "initial stack pointer must be 16-byte aligned");
        assert_eq!((slot_of(&s0), slot_of(&s1)), (0, 1));
    }

    #[test]
    fn a_stack_grows_in_place_down_to_its_limit() {
        let stack = stack_of_slot(3);
        assert_eq!(grown_range(&stack, stack.bottom - 8192), Ok(stack.bottom - 8192..stack.bottom));
        assert_eq!(grown_range(&stack, stack.limit()), Ok(stack.limit()..stack.bottom), "down to the guard page");
        assert_eq!(grown_range(&stack, stack.limit() - 4096), Err(STATUS_STACK_OVERFLOW), "never into it");
        assert!(grown_range(&stack, stack.bottom).unwrap().is_empty(), "already there");
        assert!(grown_range(&stack, stack.bottom + 4096).unwrap().is_empty(), "never shrinks");
    }

    #[test]
    fn region_fits_below_the_next_kernel_area() {
        // 02 §4.2: system views start at 0xFFFF_C000_0000_0000.
        assert!(slot_base(MAX_STACKS) <= 0xFFFF_C000_0000_0000);
    }

    #[test]
    fn guard_page_of_an_allocated_stack_is_an_overflow() {
        assert_eq!(guard_hit_in(slot_base(0), 2), Some(stack_of_slot(0)));
        assert_eq!(guard_hit_in(slot_base(1) + GUARD_SIZE - 1, 2), Some(stack_of_slot(1)));
        assert_eq!(guard_hit_in(slot_base(1) + GUARD_SIZE, 2), Some(stack_of_slot(1)), "the reserve");
        assert_eq!(guard_hit_in(stack_of_slot(1).bottom - 1, 2), Some(stack_of_slot(1)));
    }

    #[test]
    fn guard_page_past_the_last_stack_is_an_underflow() {
        assert_eq!(guard_hit_in(slot_base(2) + 8, 2), Some(stack_of_slot(1)));
        assert_eq!(guard_hit_in(slot_base(2) + GUARD_SIZE, 2), None, "only its guard page");
    }

    #[test]
    fn stack_memory_and_foreign_addresses_are_not_guards() {
        assert_eq!(guard_hit_in(stack_of_slot(0).bottom, 2), None);
        assert_eq!(guard_hit_in(stack_of_slot(1).top - 8, 2), None);
        assert_eq!(guard_hit_in(slot_base(3), 2), None, "slot beyond the region in use");
        assert_eq!(guard_hit_in(REGION_BASE - 1, 2), None);
        assert_eq!(guard_hit_in(0x0040_0000, 2), None);
        assert_eq!(guard_hit_in(slot_base(0), 0), None, "no stack allocated yet");
    }
}
