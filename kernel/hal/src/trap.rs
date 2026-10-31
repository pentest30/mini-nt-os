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
//! SYSENTER (`sysenter`, on Intel, ADR-004) pushes the same frame under the
//! pseudo-vector [`SYSENTER`]: SS and CS of user mode, ESP from EDX, the
//! user's EFLAGS (which SYSENTER keeps, but for IF), and an EIP of 0 that the
//! hook sets, since SYSENTER loses it.
//!
//! On the way back to user mode, after the vector's hook, the frame goes to
//! the return hook ([`set_user_return_hook`]), where the kernel delivers the
//! thread's user APCs.
//!
//! GS (02 §6.3): in the kernel, its base is the KPCR (`pcr`); in user mode,
//! the user's, while IA32_KERNEL_GS_BASE holds the KPCR's. Every entry from
//! user mode (RPL 3 in the saved CS) swaps them (SWAPGS), and so does every
//! way back: [`hal_trap_dispatch`]'s frames, the stubs of the interrupts and
//! exceptions that `idt` handles ([`entry_stub`]), and the first entry of a
//! thread (`ring3`). On the way back, the user's GS selector is loaded again
//! after the swap: the base belongs to the processor, not to the thread, and
//! another thread may have run since the entry.

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

/// The frame's vector for SYSENTER, which no IDT vector reaches.
pub const SYSENTER: u64 = 0x100;

/// What the kernel does with a trap frame.
pub type TrapHook = fn(&mut KTrapFrame);

const GATES: usize = (LAST_GATE - FIRST_GATE + 1) as usize;

/// The hooks: the gates, the user exceptions, then SYSENTER.
static HOOKS: [AtomicUsize; GATES + USER_EXCEPTIONS.len() + 1] =
    [const { AtomicUsize::new(0) }; GATES + USER_EXCEPTIONS.len() + 1];

/// The return hook: a `TrapHook`, or 0.
static USER_RETURN_HOOK: AtomicUsize = AtomicUsize::new(0);

/// The vector is a gate.
fn is_gate(vector: u64) -> bool {
    (u64::from(FIRST_GATE)..=u64::from(LAST_GATE)).contains(&vector)
}

/// The hook slot of `vector`: a gate, a user exception, then SYSENTER.
fn slot(vector: u64) -> Option<usize> {
    if is_gate(vector) {
        return Some((vector - u64::from(FIRST_GATE)) as usize);
    }
    if vector == SYSENTER {
        return Some(GATES + USER_EXCEPTIONS.len());
    }
    USER_EXCEPTIONS.iter().position(|&v| u64::from(v) == vector).map(|i| GATES + i)
}

/// Plugs `hook` into the gate, the user exception or SYSENTER, `vector`.
///
/// # Panics
/// For another vector.
///
/// # IRQL
/// Any level.
pub fn set_trap_hook(vector: u64, hook: Option<TrapHook>) {
    let slot = slot(vector).unwrap_or_else(|| panic!("no user-mode gate or exception {vector:#x}"));
    HOOKS[slot].store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Plugs `hook` into the way back to user mode: every gate and user
/// exception gives it the frame after the vector's hook.
///
/// # IRQL
/// Any level.
pub fn set_user_return_hook(hook: Option<TrapHook>) {
    USER_RETURN_HOOK.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

/// Called by the gates, the user exception stubs and SYSENTER with their
/// frame, interrupts masked, at the IRQL of the interrupted user code
/// (PASSIVE_LEVEL). A gate without a hook gives EAX
/// `STATUS_NOT_IMPLEMENTED`; an exception or SYSENTER without a hook is a
/// kernel bug.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
#[cfg_attr(
    all(not(target_os = "none"), not(test)),
    expect(dead_code, reason = "called by the gates' assembly, which the host does not build")
)]
extern "sysv64" fn hal_trap_dispatch(frame: &mut KTrapFrame) {
    dispatch(frame);
    let hook = USER_RETURN_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `set_user_return_hook` stores into USER_RETURN_HOOK,
        // always a `TrapHook`.
        let hook: TrapHook = unsafe { core::mem::transmute(hook) };
        hook(frame);
    }
}

/// The vector's hook, or what [`hal_trap_dispatch`] does without one.
fn dispatch(frame: &mut KTrapFrame) {
    let vector = frame.vector;
    match slot(vector).map(|slot| HOOKS[slot].load(Ordering::Acquire)) {
        Some(hook) if hook != 0 => {
            // SAFETY: only `set_trap_hook` stores into HOOKS, always a
            // `TrapHook`.
            let hook: TrapHook = unsafe { core::mem::transmute(hook) };
            hook(frame);
        }
        _ if is_gate(vector) => frame.rax = u64::from(abi::ntstatus::STATUS_NOT_IMPLEMENTED.0),
        _ => panic!("user-mode exception or SYSENTER {vector:#x} without a handler"),
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

/// The handlers of `idt` that user mode reaches without a trap frame, in
/// the order of their stubs: the interrupts, which come back, then the
/// exceptions that stop the system or end the thread, without, then with,
/// an error code.
#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
pub(crate) enum Entry {
    Clock,
    Keyboard,
    Spurious,
    DeviceNotAvailable,
    X87FloatingPoint,
    SimdFloatingPoint,
    SegmentNotPresent,
    StackSegment,
    DoubleFault,
}

/// The `idt` handler of each [`Entry`], where its stub goes.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
static HAL_ENTRY_HANDLERS: [core::sync::atomic::AtomicU64; 9] = [const { core::sync::atomic::AtomicU64::new(0) }; 9];

/// Records `handler`, the `idt` handler of `entry`; returns the stub for its
/// IDT entry. From kernel mode, the stub jumps to the handler, the stack as
/// the CPU left it. From user mode, it swaps GS first; for an interrupt, it
/// also keeps the user's GS selector and gives the handler a kernel-mode
/// frame, whose IRETQ comes back to the stub: it swaps GS again, loads the
/// selector and returns with the CPU's frame.
#[cfg(target_os = "none")]
pub(crate) fn entry_stub(entry: Entry, handler: u64) -> u64 {
    unsafe extern "C" {
        fn hal_entry_0();
        fn hal_entry_1();
        fn hal_entry_2();
        fn hal_entry_3();
        fn hal_entry_4();
        fn hal_entry_5();
        fn hal_entry_6();
        fn hal_entry_7();
        fn hal_entry_8();
    }
    let stubs = [
        hal_entry_0 as *const () as u64,
        hal_entry_1 as *const () as u64,
        hal_entry_2 as *const () as u64,
        hal_entry_3 as *const () as u64,
        hal_entry_4 as *const () as u64,
        hal_entry_5 as *const () as u64,
        hal_entry_6 as *const () as u64,
        hal_entry_7 as *const () as u64,
        hal_entry_8 as *const () as u64,
    ];
    HAL_ENTRY_HANDLERS[entry as usize].store(handler, Ordering::Release);
    stubs[entry as usize]
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
// part, which swaps GS (from user mode), pushes the rest of the frame (see
// `KTrapFrame`), switches DS and ES to the kernel's data segment (kernel
// code selector + 8), calls the hook, and returns to user mode from the
// frame, GS swapped back and its selector loaded.
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
    // SYSENTER: on the thread's kernel stack (SYSENTER_ESP), interrupts
    // masked. The user's ESP is in EDX (zero-extended: the upper halves of
    // the registers are undefined after compatibility mode); EFLAGS are the
    // user's but for IF, which goes back on.
    ".global hal_sysenter_entry",
    "hal_sysenter_entry:",
    "   push qword ptr [rip + HAL_SYSENTER_USER_SS]",
    "   mov r11d, edx",
    "   push r11",
    "   pushfq",
    "   or qword ptr [rsp], 0x200",
    "   push qword ptr [rip + HAL_SYSENTER_USER_CS]",
    "   push 0",
    "   push 0",
    "   push 0x100",
    "   jmp hal_trap_common",
    // The CPU's frame is under the vector and the error code: CS at +24.
    "hal_trap_common:",
    "   test byte ptr [rsp + 24], 3",
    "   jz 1f",
    "   swapgs",
    "1: cld",
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
    // Back to user mode (CS at +176): the user's GS base, from its selector.
    "   test byte ptr [rsp + 176], 3",
    "   jz 2f",
    "   pop rax",
    "   swapgs",
    "   mov gs, eax",
    "   jmp 3f",
    "2: add rsp, 8",
    "3: pop rax",
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
    // An interrupt that comes back (`entry_stub`). From user mode, the
    // user's GS selector goes in a slot over the CPU's frame, then a
    // kernel-mode frame (SS null, RSP on the slot, RFLAGS, CS, RIP after the
    // call) goes to the handler.
    ".macro HAL_INTERRUPT index",
    ".global hal_entry_\\index",
    "hal_entry_\\index:",
    "   test byte ptr [rsp + 8], 3",
    "   jz 3f",
    "   swapgs",
    "   push rax",
    "   mov eax, gs",
    "   xchg rax, [rsp]",
    "   push 0",
    "   push rsp",
    "   add qword ptr [rsp], 8",
    "   pushfq",
    "   push rax",
    "   mov eax, cs",
    "   xchg rax, [rsp]",
    "   call 3f",
    "   xchg rax, [rsp]",
    "   swapgs",
    "   mov gs, eax",
    "   pop rax",
    "   iretq",
    "3: jmp qword ptr [rip + HAL_ENTRY_HANDLERS + 8 * \\index]",
    ".endm",
    // An exception whose handler does not come back.
    ".macro HAL_FATAL index, error",
    ".global hal_entry_\\index",
    "hal_entry_\\index:",
    "   .if \\error",
    "   test byte ptr [rsp + 16], 3",
    "   .else",
    "   test byte ptr [rsp + 8], 3",
    "   .endif",
    "   jz 1f",
    "   swapgs",
    "1: jmp qword ptr [rip + HAL_ENTRY_HANDLERS + 8 * \\index]",
    ".endm",
    "HAL_INTERRUPT 0",
    "HAL_INTERRUPT 1",
    "HAL_INTERRUPT 2",
    "HAL_FATAL 3, 0",
    "HAL_FATAL 4, 0",
    "HAL_FATAL 5, 0",
    "HAL_FATAL 6, 1",
    "HAL_FATAL 7, 1",
    "HAL_FATAL 8, 1",
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
    fn each_gate_user_exception_and_sysenter_has_its_slot() {
        assert_eq!((slot(0x2A), slot(0x2E)), (Some(0), Some(4)));
        assert_eq!((slot(0x00), slot(0x0E)), (Some(5), Some(9)));
        assert_eq!(slot(SYSENTER), Some(10));
        assert_eq!((slot(0x0F), slot(0x29), slot(0x2F), slot(0x12A)), (None, None, None, None));
    }

    #[test]
    #[should_panic(expected = "without a handler")]
    fn sysenter_needs_its_hook() {
        let mut frame = KTrapFrame { vector: SYSENTER, ..KTrapFrame::default() };
        // `dispatch`: a panic does not unwind out of `extern "sysv64"`.
        dispatch(&mut frame);
    }

    #[test]
    #[should_panic(expected = "without a handler")]
    fn an_exception_needs_its_hook() {
        let mut frame = KTrapFrame { vector: 0x06, ..KTrapFrame::default() };
        // `dispatch`: a panic does not unwind out of `extern "sysv64"`.
        dispatch(&mut frame);
    }
}
