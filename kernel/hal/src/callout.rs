//! The switch of a thread to user mode for a callback, and its way back
//! (KiCallUserMode, KiCallbackReturn). `ke::callout` keeps the state.
//!
//! [`enter`] keeps its caller's callee-saved registers on the kernel stack
//! and notes the stack pointer in `resume`. Everything above it stays live:
//! the entries from user mode during the callback must push their trap frame
//! under it. `on_switch` receives that new initial stack (16-byte aligned,
//! under every live frame) and makes it the thread's (TSS.RSP0,
//! SYSENTER_ESP); the trap frame for user mode is copied just under it, and
//! the thread leaves by the gates' way back (`hal_trap_exit`, with the frame
//! of a system service). Interrupts stay masked from the call to the IRETQ,
//! so nothing enters from user mode before the new initial stack is in place.
//!
//! [`resume`] — later, on the same thread, on the initial stack of another
//! entry, interrupts masked — goes back to the stack pointer `enter` noted:
//! `enter` returns `value` to its caller, with the registers it had.

use core::ffi::c_void;

use crate::trap::KTrapFrame;

/// Told the new initial stack of the thread, interrupts masked, by
/// [`enter`]; `context` is the one `enter` was given.
pub type OnSwitch = extern "sysv64" fn(context: *mut c_void, initial_stack: u64);

/// KiCallUserMode: goes to user mode with `frame`, until [`resume`] comes
/// back here with the stack pointer `enter` writes into `*resume`; returns
/// the value `resume` gives.
///
/// # Safety
/// Interrupts masked; `frame` takes the thread to user mode (RPL 3 in its
/// CS) and lives in its caller's frame; `on_switch` makes the initial stack
/// it receives the current thread's for the entries from user mode, without
/// enabling interrupts; `resume` is written before `on_switch` runs and
/// stays valid until `resume` uses it, on this thread.
#[cfg(target_os = "none")]
pub unsafe fn enter(frame: &KTrapFrame, resume: *mut u64, on_switch: OnSwitch, context: *mut c_void) -> u64 {
    unsafe extern "sysv64" {
        fn hal_callout_enter(
            frame: *const KTrapFrame,
            resume: *mut u64,
            on_switch: OnSwitch,
            context: *mut c_void,
        ) -> u64;
    }
    // SAFETY: guaranteed by the caller.
    unsafe { hal_callout_enter(frame, resume, on_switch, context) }
}

/// Host build: no user mode.
///
/// # Safety
/// None; it panics.
#[cfg(not(target_os = "none"))]
pub unsafe fn enter(_frame: &KTrapFrame, _resume: *mut u64, _on_switch: OnSwitch, _context: *mut c_void) -> u64 {
    panic!("no user mode on the host")
}

/// KiCallbackReturn: goes back to the [`enter`] that noted `stack`, which
/// returns `value`. The frames under `stack` are dropped: nothing they own
/// is released.
///
/// # Safety
/// Interrupts masked, on the thread that called `enter`, which noted
/// `stack` and has not come back yet; the frames above `stack` were left
/// as they were, and nothing on the current stack needs to outlive it.
#[cfg(target_os = "none")]
pub unsafe fn resume(stack: u64, value: u64) -> ! {
    unsafe extern "sysv64" {
        fn hal_callout_resume(stack: u64, value: u64) -> !;
    }
    // SAFETY: guaranteed by the caller.
    unsafe { hal_callout_resume(stack, value) }
}

/// Host build: no user mode.
///
/// # Safety
/// None; it panics.
#[cfg(not(target_os = "none"))]
pub unsafe fn resume(_stack: u64, _value: u64) -> ! {
    panic!("no user mode on the host")
}

// `hal_callout_enter`: at the entry, RSP is 8 past a multiple of 16; after
// the six pushes still, hence the 8 bytes before the call to `on_switch`,
// where RSP is then the new initial stack. The trap frame goes under it, the
// way the gates push theirs, and leaves through their way back.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global hal_callout_enter",
    "hal_callout_enter:",
    "   push rbp",
    "   push rbx",
    "   push r12",
    "   push r13",
    "   push r14",
    "   push r15",
    "   mov [rsi], rsp",
    "   mov rbx, rdi",
    "   mov r12, rsp",
    "   and r12, -16",
    "   mov rdi, rcx",
    "   mov rsi, r12",
    "   sub rsp, 8",
    "   call rdx",
    "   lea rsp, [r12 - {frame}]",
    "   mov rdi, rsp",
    "   mov rsi, rbx",
    "   mov ecx, {words}",
    "   rep movsq",
    "   jmp hal_trap_exit",
    ".global hal_callout_resume",
    "hal_callout_resume:",
    "   mov rsp, rdi",
    "   mov rax, rsi",
    "   pop r15",
    "   pop r14",
    "   pop r13",
    "   pop r12",
    "   pop rbx",
    "   pop rbp",
    "   ret",
    frame = const core::mem::size_of::<KTrapFrame>(),
    words = const core::mem::size_of::<KTrapFrame>() / 8,
);
