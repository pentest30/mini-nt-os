#[cfg(target_os = "none")]
use core::arch::global_asm;

#[cfg(target_os = "none")]
use crate::gdt;
#[cfg(target_os = "none")]
use crate::idt;
#[cfg(target_os = "none")]
use crate::msr::{self, IA32_SYSENTER_CS, IA32_SYSENTER_EIP, IA32_SYSENTER_ESP};

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn hal_sysenter_entry();
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
extern "sysv64" fn hal_sysenter_dispatch(number: u32, args_ptr: u32) -> u32 {
    idt::dispatch_syscall(number, args_ptr)
}

#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
static mut HAL_SYSENTER_USER_CS: u64 = 0;
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
static mut HAL_SYSENTER_USER_SS: u64 = 0;

/// Programs the SYSENTER MSRs: kernel CS, entry stack, and `hal_sysenter_entry`.
///
/// # Safety
/// The GDT (kernel and 32-bit user selectors) and the kernel stack must be set
/// up, and the CPU must support SYSENTER; called once, from `hal::init`.
///
/// # IRQL
/// Any level; interrupts disabled during HAL initialisation.
#[cfg(target_os = "none")]
pub unsafe fn init() {
    let cs = gdt::kernel_code_selector() as u64;
    let sp = gdt::kernel_stack_top();
    let ep = hal_sysenter_entry as *const () as usize as u64;
    unsafe {
        HAL_SYSENTER_USER_CS = (gdt::user_code32_selector() | 3) as u64;
        HAL_SYSENTER_USER_SS = (gdt::user_data32_selector() | 3) as u64;
    }
    unsafe {
        msr::wrmsr(IA32_SYSENTER_CS, cs);
        msr::wrmsr(IA32_SYSENTER_ESP, sp);
        msr::wrmsr(IA32_SYSENTER_EIP, ep);
    }
}

/// Host build (tests, `cargo check`): no SYSENTER to set up.
///
/// # Safety
/// None: does nothing.
#[cfg(not(target_os = "none"))]
pub unsafe fn init() {}

/// Point SYSENTER_ESP at `top`: the kernel stack SYSENTER switches to.
///
/// # Safety
/// `top` must be the 16-byte aligned top of a mapped, writable kernel stack
/// that stays valid for as long as it is installed.
///
/// # IRQL
/// Any level.
#[cfg(target_os = "none")]
pub unsafe fn set_entry_stack(top: u64) {
    // SAFETY: writing IA32_SYSENTER_ESP only changes where the next SYSENTER
    // lands; the caller guarantees `top` is a valid stack.
    unsafe { msr::wrmsr(IA32_SYSENTER_ESP, top) };
}

/// Host build (tests, `cargo check`): no SYSENTER to set up.
///
/// # Safety
/// None: does nothing.
#[cfg(not(target_os = "none"))]
pub unsafe fn set_entry_stack(_top: u64) {}

#[cfg(target_os = "none")]
global_asm!(
    r#"
    .global hal_sysenter_entry
hal_sysenter_entry:
    cld
    mov  r10w, cs
    add  r10w, 8
    mov  ds, r10w
    mov  es, r10w
    // XP SP2 SYSENTER ABI (matches real ntdll.dll KiFastSystemCall stub):
    //   EAX = service number
    //   EDX = user ESP at the time of SYSENTER
    //         [EDX+0] = return address (to KiFastSystemCallRet)
    //         [EDX+4] = arg[0], [EDX+8] = arg[1], ...
    //
    // Return path: IRETQ to SharedUserData+0x300 (0x7FFE_0300) with RSP=EDX.
    //   The `ret` byte there pops [EDX+0] = caller's return address and jumps.
    //
    // Save user ESP in r12 (callee-saved in sysv64 — preserved across the call).
    // r9 is caller-saved and would be clobbered by hal_sysenter_dispatch.
    mov  r12d, edx
    // sysv64 calling convention: arg1=RDI=number, arg2=RSI=args_ptr.
    // args_ptr = EDX+4 (skip the return address at [EDX+0]).
    mov  edi, eax
    lea  esi, [edx + 4]
    call hal_sysenter_dispatch
    mov  r10w, word ptr [rip + HAL_SYSENTER_USER_SS]
    mov  ds, r10w
    mov  es, r10w
    // Return to 32-bit compat user mode via IRETQ.
    // RIP  = 0x7FFE_0300 (KiFastSystemCallRet: `ret` byte in SharedUserData).
    // RSP  = original user ESP (r12d); [RSP+0] = user return address.
    push qword ptr [rip + HAL_SYSENTER_USER_SS]
    push r12                   // new RSP = user ESP (r12 preserved by callee)
    mov  r11d, {user_rflags}   // RFLAGS: IF=1, IOPL=0, reserved bit set
    push r11
    push qword ptr [rip + HAL_SYSENTER_USER_CS]
    mov  r8d, 0x7FFE0300       // SharedUserData KiFastSystemCallRet
    push r8
    iretq
    "#,
    user_rflags = const crate::ring3::USER_RFLAGS,
);
