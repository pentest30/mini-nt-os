//! Ring-3 (user-mode) transition via IRETQ.
//!
//! On XP x86, the kernel switches to user mode by pushing an IRET frame and
//! executing IRETQ. When the target CS is a 32-bit code segment (L=0, D=1),
//! the CPU enters IA-32e compatibility mode and begins executing 32-bit
//! instructions at EIP. DS/ES/SS are loaded from the supplied selector.
//! FS is pre-loaded before IRETQ so TEB self-pointer works from the first
//! instruction.
//!
//! WI7e Ch.3 "Trap Dispatching" §Kernel-to-User Mode Transition
//! WI7e Ch.6 §User-Mode Stack and Entry Point

/// Switch from ring-0 (64-bit) to ring-3 (32-bit IA-32e compatibility mode).
///
/// Builds a 5-entry IRETQ stack frame on the current kernel stack:
///
/// ```text
///   [RSP+32]  SS     = user_data32 | 3   (ring-3 RPL)
///   [RSP+24]  RSP    = stack_top (zero-extended to 64 bits)
///   [RSP+16]  RFLAGS = IF=1, IOPL=3, reserved bit 1
///   [RSP+ 8]  CS     = user_code32 | 3
///   [RSP+ 0]  RIP    = entry_point (zero-extended to 64 bits)
/// ```
///
/// Before IRETQ, FS is loaded with `user_teb_fs` so that `FS:[0x18]`
/// resolves to the TEB's `NtTib.self_ptr` field immediately in ring-3.
///
/// # Safety
/// - `user_code32` must be a GDT descriptor with L=0, D=1, DPL=3.
/// - `user_data32` must be a GDT descriptor with DPL=3.
/// - `user_teb_fs`  must be a GDT descriptor with base = TEB32_VA, DPL=3.
/// - `entry_point` must point to mapped, executable user-mode memory.
/// - `stack_top` must point to mapped, writable user-mode stack (at least 4 KiB below).
/// - PEB, TEB, and all image pages must have `USER_ACCESSIBLE` set in the page tables.
///
// ── ring3_iretq_trampoline ────────────────────────────────────────────────────
//
// Called via `ret` from `ke_context_switch` when the scheduler first switches
// to a new user-mode thread.
//
// Stack layout on entry — RSP points to slot after trampoline addr was popped:
//   [RSP+ 0]  FS selector (u64) — TEB segment descriptor
//   [RSP+ 8]  RIP (u64) — ring-3 entry point (32-bit EIP)
//   [RSP+16]  CS  (u64) — ring-3 code32 selector | RPL=3
//   [RSP+24]  RFLAGS (u64)
//   [RSP+32]  RSP (u64) — ring-3 stack top
//   [RSP+40]  SS  (u64) — ring-3 data32 selector | RPL=3
//
// Execution:
//   1. `pop rax` — FS selector → rax; RSP advances to RIP slot
//   2. `mov fs, ax` — load TEB segment into FS
//   3. `iretq` — pops RIP/CS/RFLAGS/RSP/SS → enters ring-3
//
// # IRQL: DISPATCH_LEVEL on entry (from ke_context_switch inside timer ISR).
// After IRETQ the CPU restores RFLAGS (IF=1) and switches to ring-3.
core::arch::global_asm!(
    ".intel_syntax noprefix",
    ".global ring3_iretq_trampoline",
    "ring3_iretq_trampoline:",
    "   pop rax",          // rax = FS selector; RSP → RIP slot
    "   mov fs, ax",       // load TEB segment (DPL=3, base=TEB32_VA)
    "   iretq",            // → ring-3: pops RIP/CS/RFLAGS/RSP/SS
);

/// Exported symbol from the `ring3_iretq_trampoline` global_asm above.
///
/// Used by `ke::scheduler::spawn_user_thread` as the initial `ret` target
/// in a new user-mode thread's kernel stack frame.
///
/// # IRQL: DISPATCH_LEVEL (invoked by the scheduler context-switch path).
pub fn ring3_iretq_trampoline_fn() -> u64 {
    // SAFETY: the symbol is defined by the global_asm! above and is always valid.
    unsafe extern "C" { fn ring3_iretq_trampoline(); }
    ring3_iretq_trampoline as u64
}

/// # IRQL: PASSIVE_LEVEL
/// Must be called with interrupts enabled (RFLAGS.IF=1) so the APIC timer
/// continues to fire after the transition.
pub unsafe fn jump_to_ring3_32(
    user_code32: u16,
    user_data32: u16,
    user_teb_fs: u16,
    entry_point: u32,
    stack_top:   u32,
) -> ! {
    // RFLAGS value for ring-3:
    //   IF   = 1  (bit  9) — enable hardware interrupts
    //   IOPL = 3  (bits 13:12) — allow I/O port access (Phase 3: restrict to 0)
    //   bit 1    = 1  (always-set reserved bit)
    const RFLAGS: u64 = (1u64 << 9)   // IF
                      | (3u64 << 12)  // IOPL = 3
                      | (1u64 << 1);  // reserved

    let cs:   u64 = (user_code32 as u64) | 3;  // RPL = 3
    let ss:   u64 = (user_data32 as u64) | 3;  // RPL = 3
    let rip:  u64 = entry_point as u64;
    let rsp:  u64 = stack_top   as u64;

    // SAFETY: see function-level safety contract.
    unsafe {
        core::arch::asm!(
            // Load FS with the TEB descriptor before switching privilege level.
            // `:x` gives the 16-bit alias of the allocated GP register (e.g. ax).
            // Loading a DPL=3 segment from CPL=0 is legal: max(CPL=0,RPL=0) <= DPL=3.
            "mov fs, {teb_sel:x}",
            // Push IRETQ frame (5 × 8 bytes) on the kernel stack.
            "push {ss}",        // [+32] SS
            "push {rsp_user}",  // [+24] RSP (user stack)
            "push {rflags}",    // [+16] RFLAGS
            "push {cs}",        // [+ 8] CS
            "push {rip}",       // [+ 0] RIP (= EIP in 32-bit mode)
            // IRETQ pops RIP, CS, RFLAGS, RSP, SS — switches to ring-3.
            "iretq",
            teb_sel  = in(reg) user_teb_fs as u64,
            ss       = in(reg) ss,
            rsp_user = in(reg) rsp,
            rflags   = in(reg) RFLAGS,
            cs       = in(reg) cs,
            rip      = in(reg) rip,
            options(noreturn),
        );
    }
}
