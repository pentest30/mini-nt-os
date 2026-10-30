//! SYSENTER (02 §6.1, ADR-004): the MSRs that send it to its entry, which
//! pushes the trap frame (`trap`, `hal_sysenter_entry`), on the thread's
//! kernel stack (SYSENTER_ESP follows the running thread).

#[cfg(target_os = "none")]
use crate::gdt;
#[cfg(target_os = "none")]
use crate::msr::{self, IA32_SYSENTER_CS, IA32_SYSENTER_EIP, IA32_SYSENTER_ESP};

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn hal_sysenter_entry();
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
