//! Global Descriptor Table (GDT)
//!
//! NT kernel runs entirely in ring 0. We set up the minimal GDT required:
//!   - Null descriptor
//!   - 64-bit kernel code segment  (CS)
//!   - 64-bit kernel data segment  (SS/DS/ES)
//!   - 64-bit user code segment    (CS ring 3)  — needed for Win32 (Phase 2)
//!   - 64-bit user data segment    (DS ring 3)  — needed for Win32 (Phase 2)
//!   - Task State Segment (TSS)    — RSP0 for ring-3→ring-0 entry + IST slots
//!
//! # IST (Interrupt Stack Table)
//! The TSS holds 7 IST pointers. We populate IST[0] with a dedicated
//! double-fault stack so a kernel stack overflow cannot cause a triple fault.
//! The IDT wires the double-fault handler to use this slot.
//!
//! WI7e Ch.3 "Trap Dispatching"

use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;
use spin::Once;
use core::sync::atomic::{AtomicU64, Ordering};

// Virtual address of TSS.privilege_stack_table[0] in static memory.
// Written once inside init(); used by set_kernel_stack_top() at runtime.
static TSS_RSP0_VA: AtomicU64 = AtomicU64::new(0);

// ── Static stacks ────────────────────────────────────────────────────────────

/// RSP0 — loaded by the CPU on ring-3 → ring-0 interrupt/syscall entry.
/// 16 KiB matches NT's kernel interrupt stack size on x64.
static mut KERNEL_STACK: [u8; 16 * 1024] = [0u8; 16 * 1024];

/// IST slot 0 — dedicated double-fault stack.
///
/// Separate from KERNEL_STACK: a stack overflow causing a double fault
/// switches to this clean stack rather than triple-faulting the machine.
/// 4 KiB is enough for the double-fault handler to log and halt.
static mut DOUBLE_FAULT_STACK: [u8; 4 * 1024] = [0u8; 4 * 1024];

// ── Exported constants ────────────────────────────────────────────────────────

/// IST slot index used for the double-fault handler.
/// Referenced by `idt::init` when registering the double-fault entry.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

// ── Static storage ────────────────────────────────────────────────────────────

static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();
static TSS: Once<TaskStateSegment>                   = Once::new();

struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    tss:         SegmentSelector,
    /// 32-bit ring-3 code segment (L=0, D=1, DPL=3, base=0, limit=4GB).
    user_code32: SegmentSelector,
    /// 32-bit ring-3 data segment (DPL=3, base=0, limit=4GB).
    user_data32: SegmentSelector,
    /// 32-bit ring-3 FS segment covering the TEB page at 0x7FFD_F000.
    user_teb_fs: SegmentSelector,
}

// ── Public init ──────────────────────────────────────────────────────────────

/// Initialise and load the GDT.
///
/// Builds a TSS with:
/// - `privilege_stack_table[0]` (RSP0) — kernel stack for ring-3→ring-0 entry.
/// - `interrupt_stack_table[DOUBLE_FAULT_IST_INDEX]` — double-fault stack.
///
/// # Safety
/// Must be called exactly once, in ring 0, with interrupts disabled.
pub unsafe fn init() {
    let tss = TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();

        // RSP0: kernel stack for privilege-level transitions.
        tss.privilege_stack_table[0] = {
            let top = unsafe {
                (core::ptr::addr_of_mut!(KERNEL_STACK) as *mut u8).add(16 * 1024)
            };
            VirtAddr::new(top as u64)
        };

        // IST[0]: double-fault stack — survives kernel stack overflow.
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let top = unsafe {
                (core::ptr::addr_of_mut!(DOUBLE_FAULT_STACK) as *mut u8).add(4 * 1024)
            };
            VirtAddr::new(top as u64)
        };

        tss
    });

    // Record the address of privilege_stack_table[0] so set_kernel_stack_top()
    // can update RSP0 at runtime without going through the Once cell.
    // Use addr_of! instead of a reference because TaskStateSegment is packed
    // (4-byte aligned) and creating a reference to a VirtAddr field inside it
    // would be undefined behaviour (misaligned reference).
    // SAFETY: tss is in 'static Once storage — the address is stable forever.
    TSS_RSP0_VA.store(
        core::ptr::addr_of!(tss.privilege_stack_table[0]) as u64,
        Ordering::Relaxed,
    );

    let (gdt, sel) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_code32 = gdt.append(Descriptor::UserSegment(0x00CF_FA00_0000_FFFF));
        let user_data32 = gdt.append(Descriptor::UserSegment(0x00CF_F200_0000_FFFF));
        let user_teb_fs = gdt.append(Descriptor::UserSegment(0x7F40_F2FD_F000_0FFF));
        let tss_sel = gdt.append(Descriptor::tss_segment(tss));

        (gdt, Selectors { kernel_code, kernel_data, tss: tss_sel,
                          user_code32, user_data32, user_teb_fs })
    });

    gdt.load();

    // SAFETY: all selectors belong to the GDT we just loaded above.
    unsafe {
        use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
        use x86_64::instructions::tables::load_tss;
        CS::set_reg(sel.kernel_code);
        SS::set_reg(sel.kernel_data);
        DS::set_reg(sel.kernel_data);
        ES::set_reg(sel.kernel_data);
        // Load TSS so the CPU can read RSP0 and IST entries on interrupts.
        load_tss(sel.tss);
    }

    log::trace!("HAL GDT: loaded (kernel CS/DS + TSS [RSP0=16K, IST0=4K] + user32 segments)");
}

// ── Selector accessors ────────────────────────────────────────────────────────

/// Raw selector value for the 32-bit ring-3 code segment.
///
/// # Panics
/// Panics if called before `gdt::init()`.
pub fn user_code32_selector() -> u16 {
    GDT.get().expect("gdt::init not called").1.user_code32.0
}

/// Raw selector value for the 32-bit ring-3 data segment.
pub fn user_data32_selector() -> u16 {
    GDT.get().expect("gdt::init not called").1.user_data32.0
}

/// Raw selector value for the 32-bit TEB/FS segment (base = TEB32_VA).
pub fn user_teb_fs_selector() -> u16 {
    GDT.get().expect("gdt::init not called").1.user_teb_fs.0
}

pub fn kernel_code_selector() -> u16 {
    GDT.get().expect("gdt::init not called").1.kernel_code.0
}

pub fn kernel_data_selector() -> u16 {
    GDT.get().expect("gdt::init not called").1.kernel_data.0
}

pub fn kernel_stack_top() -> u64 {
    TSS.get().expect("gdt::init not called").privilege_stack_table[0].as_u64()
}

/// Update TSS.RSP0 — the kernel stack pointer loaded on ring-3 → ring-0 transitions.
///
/// Must be called before switching to a new user-mode thread so that interrupts
/// fired while that thread executes in ring-3 push their saved frame onto its
/// dedicated kernel stack rather than the shared boot-time stack.
///
/// # Safety
/// - `init()` must have been called before this function.
/// - Caller is responsible for ensuring `rsp0` points to valid, mapped memory
///   with at least 512 bytes below it for the CPU interrupt frame.
/// - On single-CPU Phase 2.5 this is called at DISPATCH_LEVEL (timer ISR)
///   with IF=0, so no concurrent access to the TSS is possible.
///
/// # IRQL: DISPATCH_LEVEL
pub unsafe fn set_kernel_stack_top(rsp0: u64) {
    let ptr = TSS_RSP0_VA.load(Ordering::Relaxed);
    if ptr != 0 {
        // SAFETY: ptr was stored by init() and points to TSS.privilege_stack_table[0]
        // which lives in 'static Once<TaskStateSegment> storage.
        // VirtAddr is repr(transparent) over u64 in x86_64 0.15 — writing u64 is safe.
        unsafe { (ptr as *mut u64).write_volatile(rsp0) };
    }
}
