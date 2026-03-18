//! Interrupt Descriptor Table (IDT)
//!
//! Registers handlers for:
//!   - CPU exceptions (vectors 0x00–0x1F)
//!   - APIC timer     (vector 0x20) — drives the scheduler clock
//!   - Syscall gate   (vector 0x2E / INT 2Eh) — NT native syscall ABI
//!
//! # Double-fault stack
//! The double-fault handler is configured to use IST slot 0 (see `gdt.rs`).
//! This guarantees a valid stack even if the fault was triggered by a kernel
//! stack overflow, preventing a triple fault and machine reset.
//!
//! # Syscall ABI
//! XP games use INT 0x2E (pre-SP1) or SYSENTER (SP1+).
//! INT 0x2E is supported here for maximum compatibility.
//! TODO Phase 2: add SYSENTER handler.
//!
//! WI7e Ch.3 "Trap Dispatching", Ch.2 "System Service Dispatching"

use core::arch::global_asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::instructions::port::Port;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::VirtAddr;
use spin::Once;

use super::gdt::DOUBLE_FAULT_IST_INDEX;

static IDT: Once<InterruptDescriptorTable> = Once::new();
static SYSCALL_HOOK: AtomicUsize = AtomicUsize::new(0);

// ── Init ─────────────────────────────────────────────────────────────────────

/// Initialise and load the IDT.
///
/// # Safety
/// Must run after [`super::gdt::init`] — the TSS (with IST entries) must be
/// loaded before the double-fault handler can reference IST[0].
/// Interrupts must be disabled.
pub unsafe fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        // ── CPU exceptions ──────────────────────────────────────────────────
        idt.divide_error.set_handler_fn(exception_divide_error);
        idt.invalid_opcode.set_handler_fn(exception_invalid_opcode);
        idt.breakpoint.set_handler_fn(exception_breakpoint);
        idt.page_fault.set_handler_fn(exception_page_fault);
        idt.general_protection_fault.set_handler_fn(exception_gpf);
        idt.stack_segment_fault.set_handler_fn(exception_stack_segment);
        idt.segment_not_present.set_handler_fn(exception_segment_not_present);

        // Double fault must use IST[0] to survive kernel stack overflow.
        // SAFETY: DOUBLE_FAULT_IST_INDEX (0) is valid; gdt::init() populated
        // interrupt_stack_table[0] with a live 4 KiB stack before this runs.
        unsafe {
            idt.double_fault
                .set_handler_fn(exception_double_fault)
                .set_stack_index(DOUBLE_FAULT_IST_INDEX);
        }

        // ── APIC timer (IRQ0 → vector 0x20) ────────────────────────────────
        // SAFETY: vector 0x20 does not overlap any CPU exception (0x00–0x1F).
        unsafe { idt[0x20].set_handler_fn(irq_timer); }

        // ── PS/2 keyboard (IRQ1 → vector 0x21) ──────────────────────────────
        // SAFETY: vector 0x21 does not overlap CPU exceptions or the timer.
        unsafe { idt[0x21].set_handler_fn(irq_keyboard); }

        // ── NT syscall gate (INT 0x2E) ───────────────────────────────────────
        // DPL=3 so user-mode code (games) can invoke it directly.
        // Uses a naked global_asm! handler (hal_int2e_entry) so we can write
        // the dispatch return value directly into EAX before IRETQ.
        // `extern "x86-interrupt"` cannot do this — its epilogue restores EAX
        // from the saved value, discarding any write we make inside the handler.
        // SAFETY: vector 0x2E does not overlap CPU exceptions; hal_int2e_entry
        // is a valid 64-bit function pointer with the correct interrupt-gate ABI.
        unsafe {
            extern "C" { fn hal_int2e_entry(); }
            idt[0x2E]
                .set_handler_addr(VirtAddr::new(hal_int2e_entry as *const () as u64))
                .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        }

        idt
    });

    // SAFETY: `idt` has 'static lifetime via `Once`; safe to load here.
    unsafe { idt.load(); }

    log::trace!("HAL IDT: loaded (exceptions + APIC timer 0x20 + NT syscall 0x2E)");
}

// ── Exception handlers ───────────────────────────────────────────────────────

extern "x86-interrupt" fn exception_divide_error(frame: InterruptStackFrame) {
    panic!("EXCEPTION: #DE Divide Error\n{:#?}", frame);
}

extern "x86-interrupt" fn exception_invalid_opcode(frame: InterruptStackFrame) {
    panic!(
        "EXCEPTION: #UD Invalid Opcode at {:#x}\n{:#?}",
        frame.instruction_pointer, frame
    );
}

extern "x86-interrupt" fn exception_breakpoint(frame: InterruptStackFrame) {
    // Non-fatal — log and resume execution (used by debuggers).
    log::warn!(
        "EXCEPTION: #BP Breakpoint at {:#x}",
        frame.instruction_pointer
    );
}

extern "x86-interrupt" fn exception_double_fault(
    frame: InterruptStackFrame,
    error: u64,
) -> ! {
    // Running on IST[0] — the regular kernel stack may be corrupt.
    // Only use async-safe operations: serial write via `log`, no heap.
    panic!(
        "EXCEPTION: #DF Double Fault (error={:#x})\n{:#?}",
        error, frame
    );
}

extern "x86-interrupt" fn exception_page_fault(
    frame: InterruptStackFrame,
    error: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    use core::sync::atomic::Ordering;

    // SAFETY: reading CR2 is always safe inside a page-fault handler.
    let faulting_addr = unsafe { Cr2::read() };
    // Extract raw u64 from the possibly-invalid VirtAddr Result.
    let cr2_raw: u64 = match faulting_addr {
        Ok(v)  => v.as_u64(),
        Err(e) => e.0,  // VirtAddrNotValid wraps the raw u64
    };
    let hhdm = crate::HHDM_OFFSET.load(Ordering::Acquire);

    // Walk page tables for the faulting address and the instruction pointer.
    if hhdm != 0 {
        let rip = frame.instruction_pointer.as_u64();
        log::error!(
            "[#PF diag] CR2={:#x}  RIP={:#x}  err={:#?}",
            cr2_raw, rip, error
        );
        pf_dump_pte(hhdm, cr2_raw, "CR2");
        pf_dump_pte(hhdm, rip,     "RIP");
        // Also dump nearby user addresses to see what's mapped
        for va in [0x2001000u64, 0x7FFF0000u64, 0x10000000u64] {
            pf_dump_pte(hhdm, va, "    ");
        }
    }

    panic!(
        "EXCEPTION: #PF Page Fault\n  Address : {:#x}\n  Flags   : {:#?}\n{:#?}",
        cr2_raw, error, frame
    );
}

/// Walk the x86_64 page-table hierarchy for `va` and log the leaf PTE flags.
/// Uses the supplied `hhdm` offset to convert physical addresses to virtual.
/// No heap allocation — safe to call from a fault handler.
fn pf_dump_pte(hhdm: u64, va: u64, label: &str) {
    use x86_64::{registers::control::Cr3, structures::paging::{PageTable, PageTableFlags}, VirtAddr};

    // SAFETY: HHDM maps every physical frame; CR3 points to the live PML4.
    let (l4f, _) = unsafe { Cr3::read() };
    let l4 = unsafe { &*((hhdm + l4f.start_address().as_u64()) as *const PageTable) };

    let virt = VirtAddr::new_truncate(va);
    let e4 = &l4[virt.p4_index()];
    if !e4.flags().contains(PageTableFlags::PRESENT) {
        log::error!("  {} {:#x}: L4 NOT PRESENT", label, va);
        return;
    }
    let user4 = e4.flags().contains(PageTableFlags::USER_ACCESSIBLE);
    log::error!("  {} {:#x}: L4 phys={:#x} user={} flags={:?}", label, va, e4.addr().as_u64(), user4, e4.flags());

    let l3 = unsafe { &*((hhdm + e4.addr().as_u64()) as *const PageTable) };
    let e3 = &l3[virt.p3_index()];
    if !e3.flags().contains(PageTableFlags::PRESENT) {
        log::error!("  {} {:#x}: L3 NOT PRESENT", label, va);
        return;
    }
    let user3 = e3.flags().contains(PageTableFlags::USER_ACCESSIBLE);
    if e3.flags().contains(PageTableFlags::HUGE_PAGE) {
        log::error!("  {} {:#x}: L3 1GB HUGE phys={:#x} user={} flags={:?}", label, va, e3.addr().as_u64(), user3, e3.flags());
        return;
    }
    log::error!("  {} {:#x}: L3 phys={:#x} user={} flags={:?}", label, va, e3.addr().as_u64(), user3, e3.flags());

    let l2 = unsafe { &*((hhdm + e3.addr().as_u64()) as *const PageTable) };
    let e2 = &l2[virt.p2_index()];
    if !e2.flags().contains(PageTableFlags::PRESENT) {
        log::error!("  {} {:#x}: L2 NOT PRESENT", label, va);
        return;
    }
    let user2 = e2.flags().contains(PageTableFlags::USER_ACCESSIBLE);
    if e2.flags().contains(PageTableFlags::HUGE_PAGE) {
        log::error!("  {} {:#x}: L2 2MB HUGE phys={:#x} user={} flags={:?}", label, va, e2.addr().as_u64(), user2, e2.flags());
        return;
    }
    log::error!("  {} {:#x}: L2 phys={:#x} user={} flags={:?}", label, va, e2.addr().as_u64(), user2, e2.flags());

    let l1 = unsafe { &*((hhdm + e2.addr().as_u64()) as *const PageTable) };
    let e1 = &l1[virt.p1_index()];
    if !e1.flags().contains(PageTableFlags::PRESENT) {
        log::error!("  {} {:#x}: L1 NOT PRESENT", label, va);
        return;
    }
    let user1 = e1.flags().contains(PageTableFlags::USER_ACCESSIBLE);
    log::error!("  {} {:#x}: L1 phys={:#x} user={} flags={:?}", label, va, e1.addr().as_u64(), user1, e1.flags());
}

extern "x86-interrupt" fn exception_gpf(
    frame: InterruptStackFrame,
    error: u64,
) {
    panic!(
        "EXCEPTION: #GP General Protection Fault (selector={:#x})\n{:#?}",
        error, frame
    );
}

extern "x86-interrupt" fn exception_stack_segment(
    frame: InterruptStackFrame,
    error: u64,
) {
    panic!(
        "EXCEPTION: #SS Stack Segment Fault (error={:#x})\n{:#?}",
        error, frame
    );
}

extern "x86-interrupt" fn exception_segment_not_present(
    frame: InterruptStackFrame,
    error: u64,
) {
    panic!(
        "EXCEPTION: #NP Segment Not Present (selector={:#x})\n{:#?}",
        error, frame
    );
}

// ── IRQ handlers ─────────────────────────────────────────────────────────────

extern "x86-interrupt" fn irq_timer(_frame: InterruptStackFrame) {
    // ── 1. Tick counter ──────────────────────────────────────────────────────
    super::timer::tick();

    // ── 2. Heartbeat log (ISR-safe, no heap) ─────────────────────────────────
    // Log "[alive] tick=N\n" every 1000 ms using the ISR-safe serial writer.
    // We cannot use log::info! here (heap alloc forbidden at IRQL >= DISPATCH).
    let ms = super::timer::get_tick_count();
    if ms % 1000 == 0 {
        super::serial::write_str_isr("[alive] tick=");
        let mut buf = [0u8; 20];
        let mut n = ms;
        if n == 0 {
            super::serial::write_str_isr("0\n");
        } else {
            let mut i = buf.len();
            while n > 0 {
                i -= 1;
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            // SAFETY: buf[i..] contains only ASCII digits written above.
            let s = unsafe { core::str::from_utf8_unchecked(&buf[i..]) };
            super::serial::write_str_isr(s);
            super::serial::write_str_isr("\n");
        }
    }

    // ── 3. EOI — MUST happen before context switch ────────────────────────────
    // Acknowledge the interrupt at the APIC so the next periodic tick can be
    // delivered.  If we switch stacks before sending EOI, the idle thread
    // would `hlt` waiting for a timer interrupt that never comes (the APIC
    // holds off new interrupts until EOI is received).
    //
    // SAFETY: inside the APIC timer ISR (vector 0x20); EOI is required.
    unsafe { apic_eoi() };

    // ── 4. Preemptive scheduler tick ─────────────────────────────────────────
    // Called after EOI so the APIC is free to fire the next tick while we
    // are executing on the new thread's stack.  The hook (if set) calls
    // `ke::scheduler::schedule()` which saves the current context and
    // restores the next runnable thread.
    super::timer::call_schedule_hook();
}

/// C-ABI trampoline called by the naked `hal_int2e_entry` handler.
///
/// # IRQL
/// Called at IRQL = DISPATCH_LEVEL (inside interrupt handler).
/// No heap allocation. No page faults.
#[unsafe(no_mangle)]
extern "sysv64" fn hal_int2e_dispatch(number: u32, args_ptr: u32) -> u32 {
    dispatch_syscall(number, args_ptr)
}

#[inline]
pub(crate) fn dispatch_syscall(number: u32, args_ptr: u32) -> u32 {
    let hook = SYSCALL_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return 0xC000_0002;
    }
    let f: fn(u32, u32) -> u32 = unsafe { core::mem::transmute(hook) };
    f(number, args_ptr)
}

pub fn set_syscall_hook(hook: Option<fn(u32, u32) -> u32>) {
    let addr = hook.map_or(0usize, |f| f as usize);
    SYSCALL_HOOK.store(addr, Ordering::Release);
}

// ── INT 0x2E naked syscall gate ───────────────────────────────────────────────
//
// Why global_asm! instead of extern "x86-interrupt":
//   `extern "x86-interrupt"` has LLVM save ALL used registers at function entry
//   and restore them before IRETQ.  Any write to EAX inside the handler body is
//   silently undone by the epilogue — the user sees the original EAX (syscall
//   number), never the return value.
//
//   This naked handler manually controls the save/restore: after calling
//   hal_int2e_dispatch it overwrites the saved-EAX slot on the stack with the
//   return value so that `pop rax` before IRETQ delivers the result to user mode.
//
// Stack layout after the 9 pushes below (RSP = lowest address):
//   [RSP+ 0]  R8   (last  pushed)
//   [RSP+ 8]  R9
//   [RSP+16]  R10
//   [RSP+24]  R11
//   [RSP+32]  RDI
//   [RSP+40]  RSI
//   [RSP+48]  RCX
//   [RSP+56]  RDX  (args_ptr)
//   [RSP+64]  RAX  (syscall number — overwritten with return value)
//   --- interrupt frame (CPU-pushed, 5 × 8 = 40 bytes) ---
//   [RSP+72]  RIP
//   [RSP+80]  CS
//   [RSP+88]  RFLAGS
//   [RSP+96]  RSP_user
//   [RSP+104] SS   (== user flat data selector — used to restore DS/ES)

#[cfg(target_os = "none")]
global_asm!(
    r#"
    .intel_syntax noprefix
    .global hal_int2e_entry
hal_int2e_entry:
    cld
    push rax
    push rdx
    push rcx
    push rsi
    push rdi
    push r11
    push r10
    push r9
    push r8

    // Switch to kernel data segments.
    // kernel_data selector = kernel_code selector + 8
    // (GDT layout: null | kernel_code | kernel_data | ...)
    mov ax, cs
    add ax, 8
    mov ds, ax
    mov es, ax

    // SysV64: arg1=RDI=syscall_number, arg2=RSI=args_ptr
    mov edi, dword ptr [rsp + 64]
    mov esi, dword ptr [rsp + 56]
    call hal_int2e_dispatch

    // Overwrite saved-RAX slot with dispatch return value so pop rax
    // below delivers EAX=return_value to user mode (not the syscall number).
    mov dword ptr [rsp + 64], eax

    // Restore user data segments from SS in the interrupt frame.
    // For 32-bit compat user mode, SS == DS == ES (flat data segment).
    mov ax, word ptr [rsp + 104]
    mov ds, ax
    mov es, ax

    pop r8
    pop r9
    pop r10
    pop r11
    pop rdi
    pop rsi
    pop rcx
    pop rdx
    pop rax     // EAX = dispatch return value

    iretq
    "#
);

#[cfg(not(target_os = "none"))]
#[allow(dead_code)]
extern "C" fn hal_int2e_entry_stub() {}

// ── PS/2 keyboard IRQ1 handler ────────────────────────────────────────────

extern "x86-interrupt" fn irq_keyboard(_frame: InterruptStackFrame) {
    // Read the scancode from port 0x60 (must read to acknowledge the 8042).
    // SAFETY: port 0x60 is the PS/2 data register; always safe at CPL 0.
    let scancode: u8 = unsafe { Port::<u8>::new(0x60).read() };

    // Push into the lock-free ring buffer (ISR-safe, no heap).
    super::ps2::isr_push_scancode(scancode);

    // Send EOI to the master PIC (IRQ1 is on the master 8259).
    // SAFETY: port 0x20 is the master PIC command register.
    unsafe { Port::<u8>::new(0x20).write(0x20); }
}

// ── APIC helpers ─────────────────────────────────────────────────────────────

/// Send End-Of-Interrupt to the local APIC.
///
/// Writes 0 to the APIC EOI register at the architectural default base
/// address (0xFEE0_0000 + 0x0B0). The bootloader identity-maps this range
/// so the write is valid in Phase 1.
///
/// # Safety
/// Must be called only from an APIC-sourced interrupt handler.
/// The APIC MMIO range must be identity-mapped (guaranteed by bootloader).
#[inline]
unsafe fn apic_eoi() {
    // SAFETY: 0xFEE0_00B0 is the APIC EOI MMIO register.
    // Identity-mapped by the bootloader for Phase 1.
    // Writing 0 acknowledges the current interrupt.
    unsafe {
        core::ptr::write_volatile(0xFEE0_00B0usize as *mut u32, 0);
    }
}
