//! The trap frame (`KTRAP_FRAME`, 02 §6.3) and the user-mode gates
//! `int 2Ah` to `int 2Eh` (02 §6.1).
//!
//! Each gate pushes the same frame: the CPU's IRETQ frame, an error code (0)
//! and the vector, the general registers, then the DS, ES, FS and GS
//! selectors. The kernel's hook for the vector ([`set_trap_hook`]) receives
//! it and may change it (EAX, EIP…); the gate then returns to user mode with
//! what the frame holds. The kernel converts it to and from an x86 `CONTEXT`
//! (`ke::context`).
//!
//! GS is saved but not reloaded on the way out: in the kernel, its base is
//! the KPCR, which loading a selector would lose (no SWAPGS before M3's
//! entry rework).

use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};

/// KTRAP_FRAME, Mino's internal 64-bit format: lowest address first, as the
/// gates push it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KTrapFrame {
    pub gs: u64,
    pub fs: u64,
    pub es: u64,
    pub ds: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    /// The gate's vector.
    pub vector: u64,
    /// 0 for the software gates.
    pub error_code: u64,
    // Pushed by the CPU.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// The CPU aligns RSP on 16 bytes before pushing its frame: a frame of a
// multiple of 16 bytes leaves RSP aligned for the call to the hook.
const _: () = assert!(size_of::<KTrapFrame>() == 26 * 8 && size_of::<KTrapFrame>().is_multiple_of(16));

/// The first and last user-mode gates.
pub const FIRST_GATE: u8 = 0x2A;
pub const LAST_GATE: u8 = 0x2E;

/// What the kernel does with a gate's frame.
pub type TrapHook = fn(&mut KTrapFrame);

static HOOKS: [AtomicUsize; (LAST_GATE - FIRST_GATE + 1) as usize] =
    [const { AtomicUsize::new(0) }; (LAST_GATE - FIRST_GATE + 1) as usize];

/// Plugs `hook` into the gate `vector` (`FIRST_GATE..=LAST_GATE`).
///
/// # Panics
/// For another vector.
///
/// # IRQL
/// Any level.
pub fn set_trap_hook(vector: u8, hook: Option<TrapHook>) {
    assert!((FIRST_GATE..=LAST_GATE).contains(&vector), "no user-mode gate {vector:#x}");
    HOOKS[(vector - FIRST_GATE) as usize].store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Called by the gates with their frame, interrupts masked, at the IRQL of
/// the interrupted user code (PASSIVE_LEVEL). Without a hook, EAX gets
/// `STATUS_NOT_IMPLEMENTED`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
#[cfg_attr(
    all(not(target_os = "none"), not(test)),
    expect(dead_code, reason = "called by the gates' assembly, which the host does not build")
)]
extern "sysv64" fn hal_trap_dispatch(frame: &mut KTrapFrame) {
    let index = (frame.vector as u8).wrapping_sub(FIRST_GATE) as usize;
    match HOOKS.get(index).map(|hook| hook.load(Ordering::Acquire)) {
        Some(hook) if hook != 0 => {
            // SAFETY: only `set_trap_hook` stores into HOOKS, always a
            // `TrapHook`.
            let hook: TrapHook = unsafe { core::mem::transmute(hook) };
            hook(frame);
        }
        _ => frame.rax = u64::from(abi::ntstatus::STATUS_NOT_IMPLEMENTED.0),
    }
}

/// The entry stub of each gate, `FIRST_GATE` first.
#[cfg(target_os = "none")]
pub(crate) fn gates() -> [(u8, u64); (LAST_GATE - FIRST_GATE + 1) as usize] {
    unsafe extern "C" {
        fn hal_trap_2a();
        fn hal_trap_2b();
        fn hal_trap_2c();
        fn hal_trap_2d();
        fn hal_trap_2e();
    }
    [
        (0x2A, hal_trap_2a as *const () as u64),
        (0x2B, hal_trap_2b as *const () as u64),
        (0x2C, hal_trap_2c as *const () as u64),
        (0x2D, hal_trap_2d as *const () as u64),
        (0x2E, hal_trap_2e as *const () as u64),
    ]
}

// Each stub pushes the error code and its vector, then joins the common
// part, which pushes the rest of the frame (see `KTrapFrame`), switches DS
// and ES to the kernel's data segment (kernel code selector + 8), calls the
// hook, and returns to user mode from the frame.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".macro HAL_TRAP_GATE vector",
    ".global hal_trap_\\vector",
    "hal_trap_\\vector:",
    "   push 0",
    "   push 0x\\vector",
    "   jmp hal_trap_common",
    ".endm",
    "HAL_TRAP_GATE 2a",
    "HAL_TRAP_GATE 2b",
    "HAL_TRAP_GATE 2c",
    "HAL_TRAP_GATE 2d",
    "HAL_TRAP_GATE 2e",
    "hal_trap_common:",
    "   cld",
    "   push rax",
    "   push rbx",
    "   push rcx",
    "   push rdx",
    "   push rsi",
    "   push rdi",
    "   push rbp",
    "   push r8",
    "   push r9",
    "   push r10",
    "   push r11",
    "   push r12",
    "   push r13",
    "   push r14",
    "   push r15",
    "   mov eax, ds",
    "   push rax",
    "   mov eax, es",
    "   push rax",
    "   mov eax, fs",
    "   push rax",
    "   mov eax, gs",
    "   push rax",
    "   mov eax, cs",
    "   add eax, 8",
    "   mov ds, eax",
    "   mov es, eax",
    "   mov rdi, rsp",
    "   call hal_trap_dispatch",
    // GS keeps the KPCR's base.
    "   add rsp, 8",
    "   pop rax",
    "   mov fs, eax",
    "   pop rax",
    "   mov es, eax",
    "   pop rax",
    "   mov ds, eax",
    "   pop r15",
    "   pop r14",
    "   pop r13",
    "   pop r12",
    "   pop r11",
    "   pop r10",
    "   pop r9",
    "   pop r8",
    "   pop rbp",
    "   pop rdi",
    "   pop rsi",
    "   pop rdx",
    "   pop rcx",
    "   pop rbx",
    "   pop rax",
    // The vector and the error code.
    "   add rsp, 16",
    "   iretq",
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn the_frame_is_laid_out_as_the_gates_push_it() {
        assert_eq!(offset_of!(KTrapFrame, gs), 0);
        assert_eq!(offset_of!(KTrapFrame, ds), 3 * 8);
        assert_eq!(offset_of!(KTrapFrame, r15), 4 * 8);
        assert_eq!(offset_of!(KTrapFrame, rax), 18 * 8);
        assert_eq!(offset_of!(KTrapFrame, vector), 19 * 8);
        assert_eq!(offset_of!(KTrapFrame, rip), 21 * 8, "the CPU's frame follows the error code");
        assert_eq!(offset_of!(KTrapFrame, ss), 25 * 8);
    }

    #[test]
    fn a_gate_without_hook_answers_not_implemented() {
        let mut frame = KTrapFrame { vector: 0x2C, ..KTrapFrame::default() };
        set_trap_hook(0x2C, None);
        hal_trap_dispatch(&mut frame);
        assert_eq!(frame.rax, 0xC000_0002);
    }

    #[test]
    #[should_panic(expected = "no user-mode gate")]
    fn only_the_user_gates_take_a_hook() {
        set_trap_hook(0x80, None);
    }
}
