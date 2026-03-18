//! Hardware Abstraction Layer (HAL)
//!
//! Mirrors the Windows NT HAL concept: abstracts x86_64 hardware details
//! (interrupts, timers, SMP) from the kernel executive above.
//!
//! All items here must compile in a `no_std` bare-metal environment.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(abi_x86_interrupt)]

pub mod fb;
pub mod gdt;
pub mod idt;
pub mod irql;
pub mod msr;
pub mod ps2;
pub mod ring3;
pub mod serial;
pub mod sysenter;
pub mod timer;

use core::sync::atomic::{AtomicU64, Ordering};

/// HHDM offset stored by the kernel after boot for use by fault handlers.
pub static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Store the HHDM offset so the page-fault handler can walk page tables.
pub fn set_hhdm_offset(v: u64) {
    HHDM_OFFSET.store(v, Ordering::Release);
}

/// Initialise the HAL. Called once by the kernel immediately after boot.
///
/// # Safety
/// Must be called exactly once, before any other HAL function, with
/// interrupts disabled.
pub unsafe fn init() {
    // SAFETY: caller guarantees single-call, interrupts disabled.
    unsafe {
        serial::init();         // first — UART must be open before logger_init
        serial::logger_init();  // register SerialLogger as the global log backend
        gdt::init();     // TSS with RSP0 + IST[0] double-fault stack
        sysenter::init();
        idt::init();     // exception + timer + syscall handlers (needs GDT/TSS)
        irql::init();    // set IRQL = PASSIVE, program APIC TPR
        timer::init();   // APIC timer calibration + periodic tick (needs IDT)
        ps2::init();     // flush PS/2 output buffer left by UEFI firmware
    }
    log::info!("HAL initialised");
}
