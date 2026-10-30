//! Interrupt Descriptor Table (IDT)
//!
//! Registers handlers for:
//!   - CPU exceptions (vectors 0x00–0x1F)
//!   - APIC timer     (vector 0xD0, CLOCK_LEVEL) — drives the scheduler clock
//!   - User-mode gates (vectors 0x2A–0x2E, `trap`): tick count, callback
//!     return, assertion, debug service, system service
//!
//! # Double-fault stack
//! The double-fault handler is configured to use IST slot 0 (see `gdt.rs`).
//! This guarantees a valid stack even if the fault was triggered by a kernel
//! stack overflow, preventing a triple fault and machine reset.
//!
//! # Syscall ABI
//! System calls come through INT 0x2E or SYSENTER (on Intel, ADR-004), both
//! with a full KTRAP_FRAME (`trap`).
//!
//! WI7e Ch.3 "Trap Dispatching", Ch.2 "System Service Dispatching"

use crate::sync::Once;
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::instructions::port::Port;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::VirtAddr;

use abi::ntstatus::{NtStatus, STATUS_ACCESS_VIOLATION, STATUS_SUCCESS};

use super::bugcheck::{self, interrupted_rbp, BugCheckCode, StackStart};
use super::gdt::DOUBLE_FAULT_IST_INDEX;

static IDT: Once<InterruptDescriptorTable> = Once::new();
static USER_FAULT_HOOK: AtomicUsize = AtomicUsize::new(0);
/// `fn(u64) -> Option<(u64, u64)>`: guard-page lookup for kernel stacks, see
/// [`set_stack_guard_hook`].
static STACK_GUARD_HOOK: AtomicUsize = AtomicUsize::new(0);
/// [`PageFaultHook`]: the memory manager's page faults, see
/// [`set_page_fault_hook`].
static PAGE_FAULT_HOOK: AtomicUsize = AtomicUsize::new(0);
/// End (exclusive) of the user half of an address space.
const USER_HALF_END: u64 = 1 << 47;
static IN_PF_OUTER: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

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
        idt.device_not_available.set_handler_fn(exception_device_not_available);
        idt.x87_floating_point.set_handler_fn(exception_x87_floating_point);
        idt.simd_floating_point.set_handler_fn(exception_simd_floating_point);

        // The user exceptions (`trap`): a stub sends user mode to a trap
        // frame, kernel mode to the handler above. #BP is DPL 3, so that
        // user mode may execute `int 3`.
        #[cfg(target_os = "none")]
        {
            type Handler = extern "x86-interrupt" fn(InterruptStackFrame);
            type ErrorHandler = extern "x86-interrupt" fn(InterruptStackFrame, u64);
            let stub = |vector, handler: u64| VirtAddr::new(super::trap::exception_stub(vector, handler));
            // SAFETY: each stub is an interrupt-gate entry: it returns with
            // IRETQ, or jumps to the vector's handler with the stack as the
            // CPU left it.
            unsafe {
                idt.divide_error.set_handler_addr(stub(0x00, exception_divide_error as Handler as *const () as u64));
                idt.breakpoint
                    .set_handler_addr(stub(0x03, exception_breakpoint as Handler as *const () as u64))
                    .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
                idt.invalid_opcode
                    .set_handler_addr(stub(0x06, exception_invalid_opcode as Handler as *const () as u64));
                idt.general_protection_fault
                    .set_handler_addr(stub(0x0D, exception_gpf as ErrorHandler as *const () as u64));
                let page_fault =
                    exception_page_fault as extern "x86-interrupt" fn(InterruptStackFrame, PageFaultErrorCode);
                idt.page_fault.set_handler_addr(stub(0x0E, page_fault as *const () as u64));
            }
        }

        // Double fault must use IST[0] to survive kernel stack overflow.
        // SAFETY: DOUBLE_FAULT_IST_INDEX (0) is valid; gdt::init() populated
        // interrupt_stack_table[0] with a live 16 KiB stack before this runs.
        unsafe {
            idt.double_fault.set_handler_fn(exception_double_fault).set_stack_index(DOUBLE_FAULT_IST_INDEX);
        }

        // ── Interrupts: the vector's class is the ISR's IRQL (hal::irql) ─────
        // APIC timer at CLOCK_LEVEL, above DISPATCH_LEVEL.
        idt[super::timer::CLOCK_VECTOR].set_handler_fn(irq_timer);
        // PS/2 keyboard (8259 IRQ1) at DEVICE_LEVEL.
        idt[super::timer::PIC_VECTOR_BASE + 1].set_handler_fn(irq_keyboard);
        // Spurious interrupts: the APIC's (SVR), which a raise of the TPR can
        // produce for an interrupt it has just masked, and the master 8259's
        // IRQ7. Neither takes an EOI.
        idt[0xFF].set_handler_fn(irq_spurious);
        idt[super::timer::PIC_VECTOR_BASE + 7].set_handler_fn(irq_spurious);

        // ── User-mode gates (INT 0x2A to 0x2E, `trap`) ───────────────────────
        // DPL=3 so user mode can invoke them; their stubs push a KTRAP_FRAME
        // and return from it.
        #[cfg(target_os = "none")]
        for (vector, stub) in super::trap::gates() {
            // SAFETY: the vectors do not overlap CPU exceptions; each stub is
            // an interrupt-gate entry that returns with IRETQ.
            unsafe {
                idt[vector].set_handler_addr(VirtAddr::new(stub)).set_privilege_level(x86_64::PrivilegeLevel::Ring3);
            }
        }

        idt
    });

    // `idt` has 'static lifetime via `Once`, as `load` requires.
    idt.load();

    log::trace!("HAL IDT: loaded (exceptions, clock 0xD0, 8259 0x30, user gates 0x2A-0x2E)");
}

// ── Exception handlers ───────────────────────────────────────────────────────

// Each handler reads the interrupted code's RBP first, from the frame its
// prologue built, so the STOP screen's call stack starts at the trap.

extern "x86-interrupt" fn exception_divide_error(frame: InterruptStackFrame) {
    let rbp = interrupted_rbp();
    stop_on_trap(0, 0, &frame, 0, None, "divide error (#DE)", rbp);
}

extern "x86-interrupt" fn exception_invalid_opcode(frame: InterruptStackFrame) {
    let rbp = interrupted_rbp();
    stop_on_trap(6, 0, &frame, 0, None, "invalid opcode (#UD)", rbp);
}

extern "x86-interrupt" fn exception_device_not_available(frame: InterruptStackFrame) {
    let rbp = interrupted_rbp();
    floating_point_trap(7, &frame, "device not available (#NM): CR0.TS is never set", rbp);
}

extern "x86-interrupt" fn exception_x87_floating_point(frame: InterruptStackFrame) {
    let rbp = interrupted_rbp();
    floating_point_trap(16, &frame, "x87 floating-point exception (#MF)", rbp);
}

extern "x86-interrupt" fn exception_simd_floating_point(frame: InterruptStackFrame) {
    let rbp = interrupted_rbp();
    floating_point_trap(19, &frame, "SIMD floating-point exception (#XM)", rbp);
}

/// A floating-point trap. In user mode, it goes to the user fault hook, with
/// `STATUS_ACCESS_VIOLATION`, until it becomes an exception: the
/// `STATUS_FLOAT_*` code needs the FPU status decoded. In kernel mode, where the
/// FPU is only used under `ke::fpu::with_floating_point` with every exception
/// masked, it is a STOP.
fn floating_point_trap(trap: u64, frame: &InterruptStackFrame, what: &str, rbp: u64) -> ! {
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        super::serial::write_str("[FPU] user-mode floating-point fault\n");
        user_fault(STATUS_ACCESS_VIOLATION);
    }
    stop_on_trap(trap, 0, frame, 0, None, what, rbp)
}

/// A user-mode exception nothing resolved: to the user fault hook, which does
/// not come back (the thread ends).
fn user_fault(exception: NtStatus) -> ! {
    let hook = USER_FAULT_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: `hook` was stored by `set_user_fault_hook` from a valid
        // `fn(NtStatus)`.
        let hook: fn(NtStatus) = unsafe { core::mem::transmute(hook) };
        hook(exception);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn exception_breakpoint(_frame: InterruptStackFrame) {
    // Silently skip INT3 at unimplemented stubs.
    // DXVK's DllMain calls CRT functions that hit INT3 padding.
    // Returning from #BP advances RIP past the INT3 byte automatically.
}

extern "x86-interrupt" fn exception_double_fault(frame: InterruptStackFrame, error: u64) -> ! {
    let rbp = interrupted_rbp();
    // Running on IST[0] (16 KiB): the interrupted stack may be exhausted. The
    // STOP screen takes no lock and does not allocate; its deepest recursion,
    // demangling, is bounded (`symbols::demangle`). A kernel stack overflow
    // usually lands here: the #PF on the guard page cannot push its frame onto
    // the same stack.
    let cr2 = x86_64::registers::control::Cr2::read_raw();
    let rsp = frame.stack_pointer.as_u64();
    let guard = stack_guard_hit(cr2).or_else(|| stack_guard_hit(rsp));
    stop_on_trap(8, error, &frame, cr2, guard, "double fault", rbp);
}

/// STOP screen for a trap the kernel cannot handle, naming a kernel stack
/// overflow when the fault hit a guard page. `rbp` is the interrupted code's
/// ([`interrupted_rbp`]).
fn stop_on_trap(
    trap: u64,
    error: u64,
    frame: &InterruptStackFrame,
    cr2: u64,
    guard: Option<(u64, u64)>,
    what: &str,
    rbp: u64,
) -> ! {
    let rip = frame.instruction_pointer.as_u64();
    let rsp = frame.stack_pointer.as_u64();
    let params = [trap, error, rip, cr2];
    let start = StackStart::Trap { rip, rbp };
    match guard {
        Some((bottom, top)) => bugcheck::stop(
            BugCheckCode::UNEXPECTED_KERNEL_MODE_TRAP,
            params,
            Some(&"KERNEL STACK OVERFLOW: guard page hit"),
            &[
                ("fault address", cr2),
                ("RIP          ", rip),
                ("RSP          ", rsp),
                ("stack bottom ", bottom),
                ("stack top    ", top),
            ],
            start,
        ),
        None => bugcheck::stop(
            BugCheckCode::UNEXPECTED_KERNEL_MODE_TRAP,
            params,
            Some(&what),
            &[("CR2          ", cr2), ("RIP          ", rip), ("RSP          ", rsp)],
            start,
        ),
    }
}

/// Asks the kernel whether `addr` is in a kernel stack guard page; returns
/// that stack's `(bottom, top)`.
fn stack_guard_hit(addr: u64) -> Option<(u64, u64)> {
    let hook = STACK_GUARD_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return None;
    }
    // SAFETY: only `set_stack_guard_hook` stores into STACK_GUARD_HOOK, always
    // a `fn(u64) -> Option<(u64, u64)>`.
    let f: fn(u64) -> Option<(u64, u64)> = unsafe { core::mem::transmute(hook) };
    f(addr)
}

extern "x86-interrupt" fn exception_page_fault(mut frame: InterruptStackFrame, error: PageFaultErrorCode) {
    let rbp = interrupted_rbp();
    if IN_PF_OUTER.swap(true, core::sync::atomic::Ordering::SeqCst) {
        // Nested page fault — log minimal info then halt.
        let cr2 = x86_64::registers::control::Cr2::read_raw();
        super::serial::write_str("\n[NESTED #PF] CR2=0x");
        serial_hex64(cr2);
        super::serial::write_str(" RIP=0x");
        serial_hex64(frame.instruction_pointer.as_u64());
        super::serial::write_str("\n");
        loop {
            x86_64::instructions::hlt();
        }
    }
    if let Some(fixup) = exception_page_fault_inner(&frame, error, rbp) {
        // SAFETY: `fixup` is the fixup of the faulting instruction, in the
        // same routine (`usermem`): it returns its error with the stack as it
        // was at the fault.
        unsafe { frame.as_mut().update(|frame| frame.instruction_pointer = VirtAddr::new(fixup)) };
    }
}

/// A fault on user memory in an instruction of the exception table
/// (`usermem`): where it resumes.
fn recover(rip: u64) -> Option<u64> {
    let fixup = super::usermem::fixup(rip)?;
    IN_PF_OUTER.store(false, Ordering::SeqCst);
    Some(fixup)
}

/// The page fault: `None` once resolved, the fixup where the kernel resumes
/// after a fault on user memory it copies; otherwise it does not return.
fn exception_page_fault_inner(frame: &InterruptStackFrame, error: PageFaultErrorCode, rbp: u64) -> Option<u64> {
    use x86_64::registers::control::Cr2;

    let faulting_addr = Cr2::read();
    let cr2_raw: u64 = match faulting_addr {
        Ok(v) => v.as_u64(),
        Err(e) => e.0,
    };
    let rip = frame.instruction_pointer.as_u64();

    // User-mode faults go through a trap frame (`trap`): only the kernel's
    // reach this handler. A user address is the memory manager's (demand-zero and guard pages,
    // `mm::fault`); it takes locks, so not at DISPATCH_LEVEL or above.
    if cr2_raw < USER_HALF_END {
        // P3 of IRQL_NOT_LESS_OR_EQUAL and of an access violation: 1 for a
        // write, 8 for an instruction fetch.
        let access = if error.contains(PageFaultErrorCode::INSTRUCTION_FETCH) {
            8
        } else {
            u64::from(error.contains(PageFaultErrorCode::CAUSED_BY_WRITE))
        };
        let irql = super::irql::current();
        if irql >= super::irql::Irql::Dispatch {
            bugcheck::stop(
                BugCheckCode::IRQL_NOT_LESS_OR_EQUAL,
                [cr2_raw, u64::from(irql.as_u8()), access, rip],
                Some(&"page fault on a user address at DISPATCH_LEVEL or above"),
                &[("address      ", cr2_raw), ("IRQL         ", u64::from(irql.as_u8())), ("RIP          ", rip)],
                StackStart::Trap { rip, rbp },
            );
        }
        match page_fault_hook(cr2_raw, error) {
            Some(STATUS_SUCCESS) => {
                // Resolved: the faulting instruction runs again.
                IN_PF_OUTER.store(false, Ordering::SeqCst);
                return None;
            }
            Some(status) => {
                if let Some(fixup) = recover(rip) {
                    return Some(fixup);
                }
                // The kernel touched user memory outside the user memory
                // primitives: XP stops the same way.
                bugcheck::stop(
                    BugCheckCode::KMODE_EXCEPTION_NOT_HANDLED,
                    [u64::from(status.0), rip, access, cr2_raw],
                    Some(&"exception on a user address in kernel mode"),
                    &[
                        ("address      ", cr2_raw),
                        ("RIP          ", rip),
                        ("RSP          ", frame.stack_pointer.as_u64()),
                    ],
                    StackStart::Trap { rip, rbp },
                );
            }
            None => {
                if let Some(fixup) = recover(rip) {
                    return Some(fixup);
                }
            }
        }
    }

    // ISR-safe output only — no heap allocation, no log::* macros.
    super::serial::write_str("\n[#PF] CR2=0x");
    serial_hex64(cr2_raw);
    super::serial::write_str(" RIP=0x");
    serial_hex64(rip);
    super::serial::write_str(" err=0x");
    serial_hex64(error.bits());
    super::serial::write_str(" RSP=0x");
    serial_hex64(frame.stack_pointer.as_u64());
    super::serial::write_str("\n");

    // Kernel-mode fault in a guard page: a stack overflow whose #PF frame still
    // fitted above the guard (otherwise it would have been a double fault).
    if let Some(guard) = stack_guard_hit(cr2_raw) {
        stop_on_trap(0xE, error.bits(), frame, cr2_raw, Some(guard), "page fault", rbp);
    }

    // Any other kernel-mode fault: a reference to an invalid address.
    let write = error.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
    bugcheck::stop(
        BugCheckCode::PAGE_FAULT_IN_NONPAGED_AREA,
        [cr2_raw, u64::from(write), rip, 0],
        Some(&"page fault in kernel mode"),
        &[
            ("CR2          ", cr2_raw),
            ("RIP          ", rip),
            ("RSP          ", frame.stack_pointer.as_u64()),
            ("error code   ", error.bits()),
        ],
        StackStart::Trap { rip, rbp },
    );
}

/// Walk the x86_64 page-table hierarchy for `va` and log the leaf PTE flags.
/// Uses the supplied `hhdm` offset to convert physical addresses to virtual.
/// No heap allocation — safe to call from a fault handler.
#[expect(dead_code, reason = "page-fault diagnostic kept for M0 (audit §3.1)")]
fn pf_dump_pte(hhdm: u64, va: u64, label: &str) {
    use x86_64::{
        registers::control::Cr3,
        structures::paging::{PageTable, PageTableFlags},
        VirtAddr,
    };

    let (l4f, _) = Cr3::read();
    // SAFETY: HHDM maps every physical frame; CR3 points to the live PML4.
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
        log::error!(
            "  {} {:#x}: L3 1GB HUGE phys={:#x} user={} flags={:?}",
            label,
            va,
            e3.addr().as_u64(),
            user3,
            e3.flags()
        );
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
        log::error!(
            "  {} {:#x}: L2 2MB HUGE phys={:#x} user={} flags={:?}",
            label,
            va,
            e2.addr().as_u64(),
            user2,
            e2.flags()
        );
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

extern "x86-interrupt" fn exception_gpf(frame: InterruptStackFrame, error: u64) {
    let rbp = interrupted_rbp();
    let rip = frame.instruction_pointer.as_u64();
    // Dump bytes at the faulting instruction (ISR-safe, no heap).
    super::serial::write_str("[#GP] RIP=0x");
    serial_hex64(rip);
    super::serial::write_str(" err=0x");
    serial_hex64(error);
    super::serial::write_str(" bytes:");
    for off in 0u64..16 {
        super::serial::write_str(" ");
        let addr = rip.wrapping_add(off);
        // Only read if address looks plausible
        if !(0x8000_0000_0000_0000..0xFFFF_8000_0000_0000).contains(&addr) {
            let b = unsafe { core::ptr::read_volatile(addr as *const u8) };
            serial_hex8(b);
        } else {
            super::serial::write_str("??");
        }
    }
    // Dump segment registers
    let (fs, gs, ds, es): (u16, u16, u16, u16);
    unsafe {
        core::arch::asm!("mov {0:x}, fs", out(reg) fs);
        core::arch::asm!("mov {0:x}, gs", out(reg) gs);
        core::arch::asm!("mov {0:x}, ds", out(reg) ds);
        core::arch::asm!("mov {0:x}, es", out(reg) es);
    }
    super::serial::write_str("\n[#GP] FS=0x");
    serial_hex16(fs);
    super::serial::write_str(" GS=0x");
    serial_hex16(gs);
    super::serial::write_str(" DS=0x");
    serial_hex16(ds);
    super::serial::write_str(" ES=0x");
    serial_hex16(es);
    super::serial::write_str("\n");
    stop_on_trap(13, error, &frame, 0, None, "general protection fault (#GP)", rbp);
}

fn serial_hex8(b: u8) {
    let hex = b"0123456789abcdef";
    super::serial::write_byte(hex[(b >> 4) as usize]);
    super::serial::write_byte(hex[(b & 0xF) as usize]);
}
fn serial_hex16(v: u16) {
    serial_hex8((v >> 8) as u8);
    serial_hex8(v as u8);
}
fn serial_hex64(v: u64) {
    let mut started = false;
    for i in (0..16).rev() {
        let nib = ((v >> (i * 4)) & 0xF) as u8;
        if nib != 0 || started || i == 0 {
            super::serial::write_byte(b"0123456789abcdef"[nib as usize]);
            started = true;
        }
    }
}

extern "x86-interrupt" fn exception_stack_segment(frame: InterruptStackFrame, error: u64) {
    let rbp = interrupted_rbp();
    stop_on_trap(12, error, &frame, 0, None, "stack segment fault (#SS)", rbp);
}

extern "x86-interrupt" fn exception_segment_not_present(frame: InterruptStackFrame, error: u64) {
    let rbp = interrupted_rbp();
    stop_on_trap(11, error, &frame, 0, None, "segment not present (#NP)", rbp);
}

// ── IRQ handlers ─────────────────────────────────────────────────────────────

extern "x86-interrupt" fn irq_timer(_frame: InterruptStackFrame) {
    // ── 0. CLOCK_LEVEL for the ISR (the APIC already masks up to it) ─────────
    let interrupted = super::irql::enter_interrupt(super::irql::Irql::Clock);

    // ── 1. Interrupt time, then Ke's clock work (quantum end, which requests
    // the DISPATCH interrupt run in step 4) ─────────────────────────────────
    super::timer::tick();
    super::timer::call_clock_hook();

    // ── 2. Heartbeat log (ISR-safe, no heap) ─────────────────────────────────
    // Log "[alive] tick=N\n" every 1000 ms using the ISR-safe serial writer.
    // We cannot use log::info! here (heap alloc forbidden at IRQL >= DISPATCH).
    // Debugging only (feature `heartbeat`): unconditional logging in an ISR
    // is not allowed (06 §5), and its lines would split the serial markers of
    // the boot scenarios.
    let ms = super::timer::get_tick_count();
    if cfg!(feature = "heartbeat") && ms.is_multiple_of(1000) {
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
    // SAFETY: inside the APIC timer ISR (CLOCK_VECTOR); EOI is required.
    unsafe { apic_eoi() };

    // ── 4. Back to the interrupted IRQL, then the DISPATCH interrupt ──────────
    // After EOI, so the APIC is free to fire the next tick while we run on the
    // next thread's stack. The DISPATCH interrupt (DPCs, thread switch) runs
    // now only if the interrupted code was below DISPATCH_LEVEL; otherwise it
    // waits for the IRQL to drop (a KSpinLock holder is never preempted).
    super::irql::exit_interrupt(interrupted);
}

/// Kernel-stack guard lookup: the `(bottom, top)` of the stack whose guard
/// page holds the address, if any.
pub type StackGuardHook = fn(u64) -> Option<(u64, u64)>;

/// Register the kernel-stack guard-page lookup used by the #DF and #PF
/// handlers to recognise a stack overflow. Returns the overflowed stack's
/// `(bottom, top)` when the address is in a guard page.
///
/// The hook runs inside fault handlers: it must not lock, allocate or fault.
///
/// # IRQL
/// Any level.
pub fn set_stack_guard_hook(hook: Option<StackGuardHook>) {
    let addr = hook.map_or(0usize, |f| f as usize);
    STACK_GUARD_HOOK.store(addr, Ordering::Release);
}

/// The memory manager's page fault handler (MmAccessFault): given the fault
/// address, in the user half, and the error code, `None` if the address is
/// none of its business, `Some(STATUS_SUCCESS)` when the access can run
/// again, or the exception the access raises.
pub type PageFaultHook = fn(u64, PageFaultErrorCode) -> Option<NtStatus>;

/// Registers the memory manager's page fault handler, called for faults on
/// user addresses below DISPATCH_LEVEL, interrupts disabled (a fault on a user
/// address at DISPATCH_LEVEL or above is IRQL_NOT_LESS_OR_EQUAL).
///
/// # IRQL
/// Any level.
pub fn set_page_fault_hook(hook: Option<PageFaultHook>) {
    PAGE_FAULT_HOOK.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Asks the memory manager about a fault on a user address.
fn page_fault_hook(addr: u64, error: PageFaultErrorCode) -> Option<NtStatus> {
    let hook = PAGE_FAULT_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return None;
    }
    // SAFETY: only `set_page_fault_hook` stores into PAGE_FAULT_HOOK, always a
    // `PageFaultHook`.
    let f: PageFaultHook = unsafe { core::mem::transmute(hook) };
    f(addr, error)
}

/// Registers the function called with the exception of a user-mode
/// floating-point trap; it must not come back. The kernel ends the thread's
/// process there, until the trap becomes an exception (the other user-mode
/// exceptions go through `trap`).
pub fn set_user_fault_hook(hook: Option<fn(NtStatus)>) {
    let addr = hook.map_or(0usize, |f| f as usize);
    USER_FAULT_HOOK.store(addr, Ordering::Release);
}

// ── PS/2 keyboard IRQ1 handler ────────────────────────────────────────────

extern "x86-interrupt" fn irq_keyboard(_frame: InterruptStackFrame) {
    let interrupted = super::irql::enter_interrupt(super::irql::Irql::Device);

    // Read the scancode from port 0x60 (must read to acknowledge the 8042).
    // SAFETY: port 0x60 is the PS/2 data register; always safe at CPL 0.
    let scancode: u8 = unsafe { Port::<u8>::new(0x60).read() };

    // Push into the lock-free ring buffer (ISR-safe, no heap).
    super::ps2::isr_push_scancode(scancode);

    // Send EOI to the master PIC (IRQ1 is on the master 8259).
    // SAFETY: port 0x20 is the master PIC command register.
    unsafe {
        Port::<u8>::new(0x20).write(0x20);
    }
    super::irql::exit_interrupt(interrupted);
}

/// A spurious interrupt: nothing to do, and no EOI.
extern "x86-interrupt" fn irq_spurious(_frame: InterruptStackFrame) {}

// ── APIC helpers ─────────────────────────────────────────────────────────────

/// Send End-Of-Interrupt to the local APIC.
///
/// Writes 0 to the APIC EOI register (offset 0x0B0), reached like every APIC
/// register through `timer::apic_reg` (HHDM once set).
///
/// # Safety
/// Must be called only from an APIC-sourced interrupt handler.
#[inline]
unsafe fn apic_eoi() {
    // SAFETY: apic_reg(0xB0) is the mapped APIC EOI register; writing 0
    // acknowledges the current interrupt.
    unsafe {
        core::ptr::write_volatile(super::timer::apic_reg(0xB0) as *mut u32, 0);
    }
}
