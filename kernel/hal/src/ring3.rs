//! Ring-3 (user-mode) transition via IRETQ.
//!
//! On XP x86, the kernel switches to user mode by pushing an IRET frame and
//! executing IRETQ. When the target CS is a 32-bit code segment (L=0, D=1),
//! the CPU enters IA-32e compatibility mode and begins executing 32-bit
//! instructions at EIP. DS/ES/SS are loaded from the supplied selector.
//! FS is pre-loaded before IRETQ so TEB self-pointer works from the first
//! instruction; GS is swapped to the user's base (SWAPGS, `trap`) and null.
//!
//! WI7e Ch.3 "Trap Dispatching" §Kernel-to-User Mode Transition
//! WI7e Ch.6 §User-Mode Stack and Entry Point

/// RFLAGS loaded on every entry to ring 3: IF=1, reserved bit 1, IOPL=0.
///
/// IOPL=0 makes `in`/`out`, `cli` and `sti` fault (#GP) in user mode, as on XP.
/// The scheduler's initial thread frame uses it.
pub const USER_RFLAGS: u64 = (1u64 << 9)   // IF
                           | (1u64 << 1); // reserved, always 1
const _: () = assert!(USER_RFLAGS & (3 << 12) == 0, "user mode must run with IOPL=0");

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
//   3. `swapgs`, then a null GS — the user's GS base, the KPCR's back in
//      IA32_KERNEL_GS_BASE
//   4. `iretq` — pops RIP/CS/RFLAGS/RSP/SS → enters ring-3
//
// # IRQL: DISPATCH_LEVEL on entry (from ke_context_switch inside timer ISR).
// After IRETQ the CPU restores RFLAGS (IF=1) and switches to ring-3.
core::arch::global_asm!(
    ".global ring3_iretq_trampoline",
    "ring3_iretq_trampoline:",
    // User mode runs at PASSIVE_LEVEL: drop the DISPATCH_LEVEL left by the
    // dispatch that switched to this new thread (hal::irql: CR8).
    "   xor eax, eax",
    "   mov cr8, rax",
    "   pop rax",      // rax = FS selector; RSP → RIP slot
    "   mov fs, ax",   // load TEB segment (DPL=3, base=this thread's TEB)
    "   swapgs",       // the user's GS base; the KPCR's in IA32_KERNEL_GS_BASE
    "   xor eax, eax", // a null GS for user mode
    "   mov gs, eax",
    "   iretq", // → ring-3: pops RIP/CS/RFLAGS/RSP/SS
);

/// Exported symbol from the `ring3_iretq_trampoline` global_asm above.
///
/// Used by `ke::sched::create_user_thread` as the initial `ret` target
/// in a new user-mode thread's kernel stack frame.
///
/// # IRQL: DISPATCH_LEVEL (invoked by the scheduler context-switch path).
pub fn ring3_iretq_trampoline_fn() -> u64 {
    // SAFETY: the symbol is defined by the global_asm! above and is always valid.
    unsafe extern "C" {
        fn ring3_iretq_trampoline();
    }
    ring3_iretq_trampoline as *const () as u64
}
