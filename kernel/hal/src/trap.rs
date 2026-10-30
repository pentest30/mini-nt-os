//! The trap frame (`KTRAP_FRAME`, 02 §6.3), the user-mode gates `int 2Ah` to
//! `int 2Eh` (02 §6.1), and the CPU exceptions of user mode.
//!
//! Each gate pushes the same frame: the CPU's IRETQ frame, an error code (0)
//! and the vector, the general registers, then the DS, ES, FS and GS
//! selectors. The kernel's hook for the vector ([`set_trap_hook`]) receives
//! it and may change it (EAX, EIP…); the gate then returns to user mode with
//! what the frame holds. The kernel converts it to and from an x86 `CONTEXT`
//! (`ke::context`).
//!
//! The exceptions of [`USER_EXCEPTIONS`] (#DE, #BP, #UD, #GP, #PF) enter by
//! stubs that look at where they come from: from user mode, they push the
//! same frame (with the CPU's error code for #GP and #PF) and go to the
//! vector's hook, which must exist; from kernel mode, they jump to the
//! kernel's handler (`idt`), as if the stub were not there.
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

/// The CPU exceptions that user mode takes through a trap frame: #DE, #BP,
/// #UD, #GP and #PF.
pub const USER_EXCEPTIONS: [u8; 5] = [0x00, 0x03, 0x06, 0x0D, 0x0E];

/// What the kernel does with a trap frame.
pub type TrapHook = fn(&mut KTrapFrame);

const GATES: usize = (LAST_GATE - FIRST_GATE + 1) as usize;

static HOOKS: [AtomicUsize; GATES + USER_EXCEPTIONS.len()] =
    [const { AtomicUsize::new(0) }; GATES + USER_EXCEPTIONS.len()];

/// The hook slot of `vector`: a gate, then a user exception.
fn slot(vector: u8) -> Option<usize> {
    if (FIRST_GATE..=LAST_GATE).contains(&vector) {
        return Some((vector - FIRST_GATE) as usize);
    }
    USER_EXCEPTIONS.iter().position(|&v| v == vector).map(|i| GATES + i)
}

/// Plugs `hook` into the gate or the user exception `vector`.
///
/// # Panics
/// For another vector.
///
/// # IRQL
/// Any level.
pub fn set_trap_hook(vector: u8, hook: Option<TrapHook>) {
    let slot = slot(vector).unwrap_or_else(|| panic!("no user-mode gate or exception {vector:#x}"));
    HOOKS[slot].store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Called by the gates and the user exception stubs with their frame,
/// interrupts masked, at the IRQL of the interrupted user code
/// (PASSIVE_LEVEL). A gate without a hook gives EAX
/// `STATUS_NOT_IMPLEMENTED`; an exception without a hook is a kernel bug.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
#[cfg_attr(
    all(not(target_os = "none"), not(test)),
    expect(dead_code, reason = "called by the gates' assembly, which the host does not build")
)]
extern "sysv64" fn hal_trap_dispatch(frame: &mut KTrapFrame) {
    dispatch(frame);
}

/// The vector's hook, or what [`hal_trap_dispatch`] does without one.
fn dispatch(frame: &mut KTrapFrame) {
    let vector = frame.vector as u8;
    match slot(vector).map(|slot| HOOKS[slot].load(Ordering::Acquire)) {
        Some(hook) if hook != 0 => {
            // SAFETY: only `set_trap_hook` stores into HOOKS, always a
            // `TrapHook`.
            let hook: TrapHook = unsafe { core::mem::transmute(hook) };
            hook(frame);
        }
        _ if (FIRST_GATE..=LAST_GATE).contains(&vector) => {
            frame.rax = u64::from(abi::ntstatus::STATUS_NOT_IMPLEMENTED.0)
        }
        _ => panic!("user-mode exception {vector:#x} without a handler"),
    }
}

/// The kernel-mode handler of each user exception, where its stub jumps
/// from kernel mode (`idt` sets them).
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
static HAL_KERNEL_EXCEPTION_HANDLERS: [core::sync::atomic::AtomicU64; USER_EXCEPTIONS.len()] =
    [const { core::sync::atomic::AtomicU64::new(0) }; USER_EXCEPTIONS.len()];

/// Records `handler`, the kernel-mode handler of the user exception
/// `vector`; returns the stub for its IDT entry.
///
/// # Panics
/// For a vector outside [`USER_EXCEPTIONS`].
#[cfg(target_os = "none")]
pub(crate) fn exception_stub(vector: u8, handler: u64) -> u64 {
    unsafe extern "C" {
        fn hal_exception_00();
        fn hal_exception_03();
        fn hal_exception_06();
        fn hal_exception_0d();
        fn hal_exception_0e();
    }
    let stubs = [
        hal_exception_00 as *const () as u64,
        hal_exception_03 as *const () as u64,
        hal_exception_06 as *const () as u64,
        hal_exception_0d as *const () as u64,
        hal_exception_0e as *const () as u64,
    ];
    let index = USER_EXCEPTIONS.iter().position(|&v| v == vector).expect("not a user exception");
    HAL_KERNEL_EXCEPTION_HANDLERS[index].store(handler, Ordering::Release);
    stubs[index]
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
    // A user exception: from user mode (RPL 3 in the saved CS), the frame,
    // after the CPU's error code or a 0; from kernel mode, the kernel's
    // handler, the stack untouched.
    ".macro HAL_EXCEPTION vector, index, error",
    ".global hal_exception_\\vector",
    "hal_exception_\\vector:",
    "   .if \\error",
    "   test byte ptr [rsp + 16], 3",
    "   .else",
    "   test byte ptr [rsp + 8], 3",
    "   .endif",
    "   jz 1f",
    "   .if \\error == 0",
    "   push 0",
    "   .endif",
    "   push 0x\\vector",
    "   jmp hal_trap_common",
    "1: jmp qword ptr [rip + HAL_KERNEL_EXCEPTION_HANDLERS + 8 * \\index]",
    ".endm",
    "HAL_EXCEPTION 00, 0, 0",
    "HAL_EXCEPTION 03, 1, 0",
    "HAL_EXCEPTION 06, 2, 0",
    "HAL_EXCEPTION 0d, 3, 1",
    "HAL_EXCEPTION 0e, 4, 1",
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
    #[should_panic(expected = "no user-mode gate or exception")]
    fn only_the_user_gates_and_exceptions_take_a_hook() {
        set_trap_hook(0x80, None);
    }

    #[test]
    fn each_gate_and_user_exception_has_its_slot() {
        assert_eq!((slot(0x2A), slot(0x2E)), (Some(0), Some(4)));
        assert_eq!((slot(0x00), slot(0x0E)), (Some(5), Some(9)));
        assert_eq!((slot(0x0F), slot(0x29), slot(0x2F)), (None, None, None));
    }

    #[test]
    #[should_panic(expected = "without a handler")]
    fn an_exception_needs_its_hook() {
        let mut frame = KTrapFrame { vector: 0x06, ..KTrapFrame::default() };
        // `dispatch`: a panic does not unwind out of `extern "sysv64"`.
        dispatch(&mut frame);
    }
}
