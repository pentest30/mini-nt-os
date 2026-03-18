//! KTHREAD — kernel thread object.
//!
//! Each thread has:
//!   - A kernel stack
//!   - Saved non-volatile context for context switching
//!   - Priority (0-31, 31 = highest)
//!   - Execution state
//!
//! Phase 2: this file provides the first real context-switch primitive.

use alloc::boxed::Box;
use core::arch::global_asm;

/// Thread priority — 0 (idle) to 31 (real-time).
pub type Priority = u8;

/// Thread execution state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Initialized,
    Ready,
    Running,
    Waiting,
    Terminated,
}

/// Saved register context for context switching.
/// We save the non-volatile registers (common to SysV AMD64 and MS x64).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KContext {
    pub rsp: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

/// Kernel thread object (KTHREAD in NT internals).
pub struct KThread {
    pub context: KContext,
    pub state: ThreadState,
    pub priority: Priority,
    pub stack: Box<[u8]>,
}

/// Default kernel stack size: 12 KiB (XP uses ~12-16 KiB).
const KERNEL_STACK_SIZE: usize = 12 * 1024;

impl KThread {
    /// Allocate a new kernel thread with the given entry point and priority.
    pub fn new(entry: fn() -> !, priority: Priority) -> Self {
        let mut stack = alloc::vec![0u8; KERNEL_STACK_SIZE].into_boxed_slice();

        // Set up an initial stack frame so the first context switch returns into `entry`.
        let stack_top = stack.as_mut_ptr() as usize + KERNEL_STACK_SIZE;
        let rsp = (stack_top - 8) & !0xF;
        unsafe {
            // SAFETY: rsp points at the top of our stack buffer and reserves
            // one 8-byte return slot used by the switch stub.
            *(rsp as *mut u64) = entry as u64;
        }

        Self {
            context: KContext {
                rsp: rsp as u64,
                rbx: 0,
                rbp: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: entry as u64,
            },
            state: ThreadState::Initialized,
            priority,
            stack,
        }
    }

    /// Create the bootstrap thread object representing the currently running
    /// kernel execution context.
    pub fn bootstrap_current(priority: Priority) -> Self {
        Self {
            context: KContext {
                rsp: 0,
                rbx: 0,
                rbp: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
            },
            state: ThreadState::Running,
            priority,
            stack: alloc::vec![].into_boxed_slice(),
        }
    }
}

unsafe extern "C" {
    fn ke_context_switch(old_ctx: *mut KContext, new_ctx: *const KContext);
}

/// Low-level context switch between two kernel threads.
///
/// # Safety
/// - `current` and `next` must be valid, distinct `KThread` instances.
/// - Their contexts/stacks must remain alive across the switch.
/// - Caller must ensure correct scheduler invariants and IRQL discipline.
pub unsafe fn switch_to(current: &mut KThread, next: &mut KThread) {
    // SAFETY: the caller guarantees both contexts are valid and live.
    unsafe { ke_context_switch(&mut current.context as *mut _, &next.context as *const _) };
}

/// Direct context switch on raw KContext pointers.
///
/// Used by the scheduler which stores KContext inline in a static table and
/// must release the scheduler lock before switching (to avoid lock-across-
/// context-switch deadlocks).
///
/// # Safety
/// - `old_ctx` and `new_ctx` must be valid, distinct, non-null pointers.
/// - Both contexts must remain live for the duration of the switch.
/// - Called at IRQL >= DISPATCH (interrupts disabled on single-CPU Phase 2).
/// - IRQL: DISPATCH_LEVEL (timer ISR context, IF=0).
#[inline(always)]
pub unsafe fn context_switch_raw(old_ctx: *mut KContext, new_ctx: *const KContext) {
    // SAFETY: forwarded from caller's guarantee above.
    unsafe { ke_context_switch(old_ctx, new_ctx) };
}

global_asm!(
    r#"
    .intel_syntax noprefix
    .global ke_context_switch
ke_context_switch:
    # rdi = old_ctx, rsi = new_ctx
    mov [rdi + 0x00], rsp
    mov [rdi + 0x08], rbx
    mov [rdi + 0x10], rbp
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], r13
    mov [rdi + 0x28], r14
    mov [rdi + 0x30], r15
    mov rax, [rsp]
    mov [rdi + 0x38], rax

    mov rsp, [rsi + 0x00]
    mov rbx, [rsi + 0x08]
    mov rbp, [rsi + 0x10]
    mov r12, [rsi + 0x18]
    mov r13, [rsi + 0x20]
    mov r14, [rsi + 0x28]
    mov r15, [rsi + 0x30]
    mov rax, [rsi + 0x38]
    mov [rsp], rax
    ret
    "#
);

// ── Tests ────────────────────────────────────────────────────────────────────
// Run with: cargo test -p ke
//
// These tests run on the host (std provides the allocator).
// They verify:
//   1. KContext field offsets match the asm offsets in ke_context_switch.
//   2. KThread::new sets up the initial stack frame so the entry address
//      sits at the top of the aligned stack, ready for `ret` to land there.

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    // ── T1-1a: KContext field offsets must match the asm ─────────────────────
    // ke_context_switch uses hard-coded byte offsets.
    // If KContext layout changes these tests catch it before the asm breaks.

    #[test]
    fn kcontext_rsp_at_offset_0x00() {
        assert_eq!(offset_of!(KContext, rsp), 0x00);
    }

    #[test]
    fn kcontext_rbx_at_offset_0x08() {
        assert_eq!(offset_of!(KContext, rbx), 0x08);
    }

    #[test]
    fn kcontext_rbp_at_offset_0x10() {
        assert_eq!(offset_of!(KContext, rbp), 0x10);
    }

    #[test]
    fn kcontext_r12_at_offset_0x18() {
        assert_eq!(offset_of!(KContext, r12), 0x18);
    }

    #[test]
    fn kcontext_r13_at_offset_0x20() {
        assert_eq!(offset_of!(KContext, r13), 0x20);
    }

    #[test]
    fn kcontext_r14_at_offset_0x28() {
        assert_eq!(offset_of!(KContext, r14), 0x28);
    }

    #[test]
    fn kcontext_r15_at_offset_0x30() {
        assert_eq!(offset_of!(KContext, r15), 0x30);
    }

    #[test]
    fn kcontext_rip_at_offset_0x38() {
        assert_eq!(offset_of!(KContext, rip), 0x38);
    }

    #[test]
    fn kcontext_total_size_is_64_bytes() {
        assert_eq!(core::mem::size_of::<KContext>(), 64);
    }

    // ── T1-1b: KThread::new stack frame setup ────────────────────────────────
    // The initial RSP must be 16-byte aligned and the word at [rsp] must be
    // the entry function address (for `ret` to land there on first switch).

    #[test]
    fn new_thread_rsp_is_16_byte_aligned() {
        fn dummy_entry() -> ! { loop {} }
        let t = KThread::new(dummy_entry, 8);
        assert_eq!(t.context.rsp % 16, 0, "initial RSP must be 16-byte aligned");
    }

    #[test]
    fn new_thread_entry_on_stack_top() {
        fn dummy_entry() -> ! { loop {} }
        let t = KThread::new(dummy_entry, 8);
        // SAFETY: rsp is a valid pointer into our owned stack buffer.
        let word_at_rsp = unsafe { *(t.context.rsp as *const u64) };
        assert_eq!(
            word_at_rsp,
            dummy_entry as *const () as u64,
            "[rsp] must hold the entry address so ret jumps there"
        );
    }

    #[test]
    fn new_thread_rsp_inside_stack_buffer() {
        fn dummy_entry() -> ! { loop {} }
        let t = KThread::new(dummy_entry, 8);
        let stack_start = t.stack.as_ptr() as u64;
        let stack_end = stack_start + t.stack.len() as u64;
        assert!(
            t.context.rsp >= stack_start && t.context.rsp < stack_end,
            "initial RSP {:#x} must be inside stack [{:#x}, {:#x})",
            t.context.rsp,
            stack_start,
            stack_end
        );
    }

    #[test]
    fn new_thread_callee_regs_zeroed() {
        fn dummy_entry() -> ! { loop {} }
        let t = KThread::new(dummy_entry, 8);
        assert_eq!(t.context.rbx, 0);
        assert_eq!(t.context.rbp, 0);
        assert_eq!(t.context.r12, 0);
        assert_eq!(t.context.r13, 0);
        assert_eq!(t.context.r14, 0);
        assert_eq!(t.context.r15, 0);
    }

    #[test]
    fn new_thread_state_is_initialized() {
        fn dummy_entry() -> ! { loop {} }
        let t = KThread::new(dummy_entry, 8);
        assert_eq!(t.state, ThreadState::Initialized);
    }

    #[test]
    fn bootstrap_current_state_is_running() {
        let t = KThread::bootstrap_current(8);
        assert_eq!(t.state, ThreadState::Running);
    }

    #[test]
    fn bootstrap_current_stack_is_empty() {
        let t = KThread::bootstrap_current(8);
        assert_eq!(t.stack.len(), 0);
    }
}
