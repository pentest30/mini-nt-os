//! Bootloader — UEFI entry point.
//!
//! Boot sequence:
//!   B3 — Load `kernel.elf` from the ESP: segments into one physical block.
//!   B1 — Collect UEFI memory map; classify and merge regions.
//!   B2 — Build 4-level page tables (identity [0, 4 GiB) + HHDM + kernel W^X,
//!        and the framebuffer in the HHDM wherever it lies).
//!   B4 — Fill `BootInfo`, exit UEFI boot services, switch CR3, jump.
//!
//! The kernel only gets HHDM addresses (BootInfo, boot stack): the identity
//! map serves the bootloader's last instructions and is removed by the
//! kernel after its phase 0 (ADR-014).
//!
//! Everything the kernel reaches through the HHDM is allocated below 4 GiB
//! (`memory::allocate_low`): on a machine with more RAM, the firmware would
//! otherwise hand out pages above it. The firmware may also load this image
//! above 4 GiB (at its preferred base, 0x1_4000_0000, when RAM is there), out
//! of the identity map: CR3 is therefore switched by a trampoline copied below
//! 4 GiB ([`TRAMPOLINE`]).
//!
//! Build target: x86_64-unknown-uefi
//! uefi crate 0.26: helpers module does not exist; use allocator::init +
//! logger::Logger directly.

#![no_std]
#![no_main]

mod loader;
mod memory;
mod paging;

use abi::{BootInfo, FramebufferInfo, PixelFormat};
use core::arch::asm;
use paging::HHDM_OFFSET;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopFmt};
use uefi::table::boot::{MemoryType, OpenProtocolAttributes, OpenProtocolParams};
use uefi::{
    entry,
    table::{Boot, SystemTable},
    Handle, Status,
};
use x86_64::registers::{
    control::{Cr0, Cr0Flags},
    model_specific::{Efer, EferFlags, Msr},
};

/// UEFI logger — writes to the firmware text console.
/// Must be disabled before ExitBootServices.
static LOGGER: uefi::logger::Logger = uefi::logger::Logger::new();

/// BootInfo written before ExitBootServices and passed to `kernel_main`.
///
/// Lives in bootloader BSS (zeroed); `BootInfo::new()` pre-fills the magic
/// and `hhdm_offset` fields so the kernel can validate them immediately.
static mut BOOT_INFO: BootInfo = BootInfo::new();

/// The last instructions before the kernel, copied to a page below 4 GiB:
/// mapped by the firmware's tables and by ours, it survives the CR3 switch
/// wherever the firmware loaded this image. Position-independent; takes the
/// PML4 in RAX, the kernel's stack in RSI, its entry in RCX, and leaves the
/// `BootInfo` pointer in RDI (SysV first argument).
const TRAMPOLINE: [u8; 12] = [
    0x0F, 0x22, 0xD8, // mov cr3, rax
    0x48, 0x89, 0xF4, // mov rsp, rsi
    0x48, 0x83, 0xE4, 0xF0, // and rsp, -16
    0xFF, 0xE1, // jmp rcx
];

/// IA32_APIC_BASE: the local APIC's base, enable (bit 11) and x2APIC (bit 10).
const IA32_APIC_BASE: u32 = 0x1B;

/// UEFI application entry point.
#[entry]
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    // ── Initialise UEFI pool allocator (needed by find_handles etc.) ──────────
    // SAFETY: we pass a valid, live SystemTable; exit_boot_services() will
    //         notify the allocator before boot services are torn down.
    unsafe { uefi::allocator::init(&mut st) };

    // ── Initialise UEFI console logger ────────────────────────────────────────
    // SAFETY: st.stdout() returns a &mut Output valid for the boot-services
    //         lifetime; we disable the logger before ExitBootServices.
    unsafe { LOGGER.set_output(st.stdout() as *mut _) };
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);

    // Where the firmware loaded this image: at its preferred base
    // (0x1_4000_0000) when RAM is there, beyond the identity map.
    let here = query_gop as *const () as u64;
    log::info!(
        "micro-nt-os bootloader starting at {:#x}{}",
        here,
        if here >= paging::HHDM_SIZE { ", above 4 GiB: the trampoline switches CR3" } else { "" }
    );

    // ── Locate ACPI RSDP via UEFI config tables ───────────────────────────────
    // Config table borrow is released immediately (rsdp_phys is a plain u64).
    let rsdp_phys = st
        .config_table()
        .iter()
        .find(|t| t.guid == uefi::table::cfg::ACPI2_GUID || t.guid == uefi::table::cfg::ACPI_GUID)
        .map(|t| t.address as usize as u64)
        .unwrap_or(0);
    log::info!("bootloader: RSDP at {:#x}", rsdp_phys);
    log_local_apic();

    // ── B3 / B2 / B1 inside a block so `bt` borrow ends before exit_boot_services ──
    let (
        kernel_phys,
        kernel_size,
        kernel_entry,
        kernel_symbols,
        ramdisk_phys,
        ramdisk_size,
        regions,
        region_count,
        pml4_phys,
        boot_info_phys,
        boot_stack_top,
        trampoline,
        fb_info,
    ) = {
        let bt = st.boot_services();

        // B3: Load the kernel ELF from the ESP into physical memory.
        let kernel = loader::load_kernel(bt);
        let (kp, ks, ke, ksym) = (kernel.phys_base, kernel.size, kernel.entry, kernel.symbols);
        let (rdp, rds) = loader::load_optional_ramdisk(bt).unwrap_or((0, 0));

        // B0: Query GOP framebuffer (before memory::collect so the FB physical
        //     address is known; does not allocate any UEFI pages).
        let fb = query_gop(bt, image);

        // B2: Build 4-level page tables (identity + HHDM).
        // Must happen BEFORE memory::collect so that the page-table frames are
        // already marked LOADER_DATA in the UEFI map when we snapshot it;
        // otherwise mm::init feeds those frames to the buddy as Usable and the
        // kernel corrupts the PML4 when mapping its heap.
        // SAFETY: single-threaded UEFI boot services context; identity map active.
        let pml4 = unsafe { paging::build(bt) };
        // SAFETY: as above; `kernel` was just laid out by the loader.
        unsafe { paging::map_kernel(bt, pml4, &kernel) };
        // SAFETY: as above; `fb` comes from the firmware's GOP.
        unsafe { paging::map_framebuffer(bt, pml4, &fb) };
        log::info!("bootloader: PML4 at {:#x}", pml4.as_u64());

        let boot_info_pages = core::mem::size_of::<BootInfo>().div_ceil(4096);
        let bi_phys = memory::allocate_low(bt, MemoryType::LOADER_DATA, boot_info_pages)
            .expect("bootloader: failed to allocate BootInfo pages");
        let boot_stack_pages = 16usize;
        let boot_stack_phys = memory::allocate_low(bt, MemoryType::LOADER_DATA, boot_stack_pages)
            .expect("bootloader: failed to allocate boot stack pages");
        let stack_top = boot_stack_phys + (boot_stack_pages as u64) * 4096;
        let trampoline = memory::allocate_low(bt, MemoryType::LOADER_CODE, 1)
            .expect("bootloader: failed to allocate the trampoline page");
        // SAFETY: the page was just allocated below 4 GiB, identity-mapped by
        // the firmware; the copy stays inside it.
        unsafe { core::ptr::copy_nonoverlapping(TRAMPOLINE.as_ptr(), trampoline as *mut u8, TRAMPOLINE.len()) };

        // B1: Collect UEFI physical memory map; mark kernel pages KernelImage.
        // Called after all UEFI allocations so the snapshot reflects everything.
        let (mut rgns, count) = memory::collect(bt);
        memory::mark_kernel(&mut rgns, count, kp / 4096, ks.div_ceil(4096));

        (kp, ks, ke, ksym, rdp, rds, rgns, count, pml4, bi_phys, stack_top, trampoline, fb)
        // `bt` borrow released here
    };

    // ── Populate BootInfo ─────────────────────────────────────────────────────
    // SAFETY: single-threaded; BOOT_INFO written only here; no concurrent access.
    unsafe {
        BOOT_INFO.kernel_phys_base = kernel_phys;
        BOOT_INFO.kernel_size = kernel_size;
        BOOT_INFO.symbols = kernel_symbols;
        BOOT_INFO.rsdp_phys = rsdp_phys;
        BOOT_INFO.ramdisk_phys_base = ramdisk_phys;
        BOOT_INFO.ramdisk_size = ramdisk_size;
        BOOT_INFO.framebuffer = fb_info;
        BOOT_INFO.memory_map_len = region_count as u32;
        BOOT_INFO.memory_map = regions;
    }

    log::info!(
        "bootloader: BootInfo ready — {} regions, kernel {:#x}+{}B, entry {:#x}",
        region_count,
        kernel_phys,
        kernel_size,
        kernel_entry,
    );
    log::info!("bootloader: leaving boot services; the kernel paints the screen next");

    // ── Disable logger and allocator BEFORE ExitBootServices ─────────────────
    // After EBS the UEFI console and pool allocator are no longer valid.
    LOGGER.disable();
    uefi::allocator::exit_boot_services();

    // ── B4: Exit UEFI boot services ───────────────────────────────────────────
    // uefi 0.26: exit_boot_services is a safe fn (takes self by value).
    let (_runtime, _mmap) = st.exit_boot_services(MemoryType::LOADER_DATA);

    // ── Hand BootInfo over ────────────────────────────────────────────────────
    // Copied while the firmware's tables still map this image, wherever it
    // lies; the kernel gets it at its HHDM address (below 4 GiB, so inside
    // the HHDM), like the boot stack.
    let boot_info_dst = boot_info_phys as *mut BootInfo;
    // SAFETY: boot_info_phys is a LOADER_DATA block sized for one BootInfo,
    // identity-mapped by the firmware; BOOT_INFO is no longer written.
    unsafe { core::ptr::copy_nonoverlapping(core::ptr::addr_of!(BOOT_INFO), boot_info_dst, 1) };

    // ── Enforce the kernel's W^X ──────────────────────────────────────────────
    // EFER.NXE before loading CR3: the new tables set NX bits, which are
    // reserved (and fault) without it. CR0.WP makes ring 0 honour read-only
    // pages too, so the kernel's .text and .rodata are really read-only.
    // SAFETY: every x86-64 CPU we target supports NX; nothing below writes
    // to a read-only page (only the trampoline runs, and it writes nothing).
    unsafe {
        Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
        Cr0::update(|flags| flags.insert(Cr0Flags::WRITE_PROTECT));
    }

    // ── Switch CR3 and jump to kernel_main, from the trampoline ───────────────
    // SAFETY: the trampoline page lies below 4 GiB, executable in the
    //         firmware's tables (LOADER_CODE) and in ours (the identity map
    //         sets no NX); pml4_phys is a valid, fully-built PML4.
    //         kernel_entry is inside the kernel's text segment, mapped RX;
    //         the stack and BootInfo are reached at their HHDM addresses.
    //         The kernel (x86_64-unknown-none) uses the SysV AMD64 ABI where
    //         the first argument is in rdi. kernel_entry never returns (-> !).
    unsafe {
        asm!(
            "jmp rdx",
            in("rdx") trampoline,
            in("rax") pml4_phys.as_u64(),
            in("rsi") HHDM_OFFSET + boot_stack_top,
            in("rcx") kernel_entry,
            in("rdi") HHDM_OFFSET + boot_info_dst as u64,
            options(noreturn),
        );
    }
}

/// Logs the local APIC's base and mode: the kernel drives it by MMIO
/// (xAPIC) or by MSRs (x2APIC), as the firmware leaves it.
fn log_local_apic() {
    // SAFETY: IA32_APIC_BASE exists on every x86-64 CPU; reading it changes nothing.
    let value = unsafe { Msr::new(IA32_APIC_BASE).read() };
    let mode = match (value & (1 << 11) != 0, value & (1 << 10) != 0) {
        (false, _) => "disabled",
        (true, false) => "xAPIC",
        (true, true) => "x2APIC",
    };
    log::info!("bootloader: local APIC at {:#x}, {}", value & 0x000F_FFFF_FFFF_F000, mode);
}

/// Query the UEFI GOP protocol and return framebuffer geometry.
///
/// Returns `FramebufferInfo::zeroed()` if GOP is unavailable (headless mode).
/// Must be called while UEFI boot services are active. The protocol is not
/// opened exclusively: that would disconnect the firmware's text console,
/// and the loader's journal would stop showing on screen.
fn query_gop(bt: &uefi::table::boot::BootServices, image: Handle) -> FramebufferInfo {
    let handle = match bt.get_handle_for_protocol::<GraphicsOutput>() {
        Ok(h) => h,
        Err(_) => {
            log::warn!("bootloader: GOP not available — framebuffer disabled");
            return FramebufferInfo::zeroed();
        }
    };

    // SAFETY: the GOP handle stays valid until ExitBootServices, and the
    // protocol is dropped (closed) before this function returns.
    let opened = unsafe {
        bt.open_protocol::<GraphicsOutput>(
            OpenProtocolParams { handle, agent: image, controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    let mut gop = match opened {
        Ok(g) => g,
        Err(e) => {
            log::warn!("bootloader: GOP open failed ({:?}) — framebuffer disabled", e.status());
            return FramebufferInfo::zeroed();
        }
    };

    let mode = gop.current_mode_info();
    let (w, h) = mode.resolution();
    let stride = mode.stride();
    let format = match mode.pixel_format() {
        GopFmt::Bgr => PixelFormat::Bgr,
        GopFmt::Rgb => PixelFormat::Rgb,
        _ => PixelFormat::Unknown,
    };
    // SAFETY: GOP framebuffer pointer is valid for the lifetime of boot services.
    let base = gop.frame_buffer().as_mut_ptr() as u64;

    log::info!("bootloader: GOP {}×{} stride={} fmt={:?} base={:#x}", w, h, stride, format, base);

    FramebufferInfo { base, width: w as u32, height: h as u32, stride: stride as u32, format }
}

/// Shows the message on the firmware console while boot services last (the
/// logger is a no-op once disabled): on real hardware, the screen is the
/// only journal.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("bootloader: {}", info);
    loop {
        x86_64::instructions::hlt();
    }
}
