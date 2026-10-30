//! Kernel stacks, each preceded by an unmapped guard page (02 §4.2).
//!
//! Stacks live in their own kernel region, one fixed-size slot per stack:
//!
//! ```text
//!   slot n:  [ guard page (unmapped) | 24 KiB stack (RW, NX) ]
//!            ^ base(n)               ^ bottom(n)             ^ top(n) = base(n + 1)
//! ```
//!
//! An overflow runs into the slot's own guard page and an underflow into the
//! next slot's, so the CPU faults instead of silently corrupting a neighbour;
//! [`guard_hit`] lets the fault handlers name the stack involved.
//!
//! Not done yet: stacks are never freed (threads are not reaped). The region
//! sits under a PML4 entry of the kernel half, filled at boot and shared by
//! every address space (`mm::address_space`).

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::structures::paging::PageTableFlags;
use x86_64::{PhysAddr, VirtAddr};

use crate::paging::MmPageTables;
use crate::pfn::PageUsage;

/// Usable size of every kernel stack.
pub const KERNEL_STACK_SIZE: u64 = 24 * 1024;
/// Unmapped page below every stack.
pub const GUARD_SIZE: u64 = 4096;
/// Start of the kernel stack region (02 §4.2).
pub const REGION_BASE: u64 = 0xFFFF_B000_0000_0000;
/// Number of slots in the region.
pub const MAX_STACKS: u64 = 4096;

const SLOT_SIZE: u64 = GUARD_SIZE + KERNEL_STACK_SIZE;
const PAGES: usize = (KERNEL_STACK_SIZE / 4096) as usize;
const STACK_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits() | PageTableFlags::NO_EXECUTE.bits(),
);

/// Number of slots handed out so far.
static ALLOCATED: AtomicU64 = AtomicU64::new(0);

/// A mapped kernel stack: `[bottom, top)`, growing down from `top`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelStack {
    /// Lowest mapped address; the guard page ends here.
    pub bottom: u64,
    /// One past the highest mapped address; the initial stack pointer.
    pub top: u64,
}

const fn slot_base(slot: u64) -> u64 {
    REGION_BASE + slot * SLOT_SIZE
}

const fn stack_of_slot(slot: u64) -> KernelStack {
    let bottom = slot_base(slot) + GUARD_SIZE;
    KernelStack { bottom, top: bottom + KERNEL_STACK_SIZE }
}

/// Allocates a kernel stack: 24 KiB of fresh, zeroed frames under an unmapped
/// guard page. Returns `None` when the region or physical memory is exhausted.
///
/// # IRQL
/// PASSIVE_LEVEL. Allocates pages (`mm::pfn`) and edits the kernel page tables.
pub fn allocate() -> Option<KernelStack> {
    let slot =
        ALLOCATED.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_STACKS).then_some(n + 1)).ok()?;
    let stack = stack_of_slot(slot);

    let mut frames = [0u64; PAGES];
    for i in 0..PAGES {
        let Some(pfn) = crate::pfn::allocate_page(PageUsage::KernelStack) else {
            frames[..i].iter().for_each(|&phys| crate::pfn::free_page(crate::Pfn(phys / 4096)));
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

/// If `addr` lies in a guard page of the region, returns the stack it belongs
/// to: the stack above it (overflow), or the last stack for the guard just
/// past the region in use (underflow).
///
/// # IRQL
/// Any level. Lock-free, for use from fault handlers.
pub fn guard_hit(addr: u64) -> Option<KernelStack> {
    guard_hit_in(addr, ALLOCATED.load(Ordering::Acquire))
}

fn guard_hit_in(addr: u64, allocated: u64) -> Option<KernelStack> {
    let offset = addr.checked_sub(REGION_BASE)?;
    let slot = offset / SLOT_SIZE;
    if allocated == 0 || slot > allocated || offset % SLOT_SIZE >= GUARD_SIZE {
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
        assert_eq!(s0.bottom, REGION_BASE + GUARD_SIZE);
        assert_eq!(s0.top - s0.bottom, KERNEL_STACK_SIZE);
        assert_eq!(s0.top, slot_base(1), "a stack's top is the next slot's guard page");
        assert_eq!(s1.bottom - s0.top, GUARD_SIZE);
        assert_eq!(s0.top % 16, 0, "initial stack pointer must be 16-byte aligned");
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
    }

    #[test]
    fn guard_page_past_the_last_stack_is_an_underflow() {
        assert_eq!(guard_hit_in(slot_base(2) + 8, 2), Some(stack_of_slot(1)));
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
