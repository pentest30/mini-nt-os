use core::arch::global_asm;

use crate::gdt;
use crate::idt;
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

#[cfg(not(target_os = "none"))]
pub unsafe fn init() {}

#[cfg(target_os = "none")]
global_asm!(
    r#"
    .intel_syntax noprefix
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
    mov  r11d, 0x3202          // RFLAGS: IF=1, IOPL=0, reserved bit set
    push r11
    push qword ptr [rip + HAL_SYSENTER_USER_CS]
    mov  r8d, 0x7FFE0300       // SharedUserData KiFastSystemCallRet
    push r8
    iretq
    "#
);
