//! Bootloader — UEFI entry point.
//!
//! Boot sequence:
//!   B3 — Load `kernel.elf` from the ESP: segments into one physical block.
//!   B1 — Collect UEFI memory map; classify and merge regions.
//!   B2 — Build 4-level page tables (identity [0, 4 GiB) + HHDM + kernel W^X).
//!   B4 — Fill `BootInfo`, exit UEFI boot services, switch CR3, jump.
//!
//! The kernel only gets HHDM addresses (BootInfo, boot stack): the identity
//! map serves the bootloader's last instructions and is removed by the
//! kernel after its phase 0 (ADR-014).
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
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::{
    entry,
    table::{Boot, SystemTable},
    Handle, Status,
};
use x86_64::{
    registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags},
    registers::model_specific::{Efer, EferFlags},
    structures::paging::PhysFrame,
};

/// UEFI logger — writes to the firmware text console.
/// Must be disabled before ExitBootServices.
static LOGGER: uefi::logger::Logger = uefi::logger::Logger::new();

/// BootInfo written before ExitBootServices and passed to `kernel_main`.
///
/// Lives in bootloader BSS (zeroed); `BootInfo::new()` pre-fills the magic
/// and `hhdm_offset` fields so the kernel can validate them immediately.
static mut BOOT_INFO: BootInfo = BootInfo::new();

/// UEFI application entry point.
#[entry]
fn efi_main(_image: Handle, mut st: SystemTable<Boot>) -> Status {
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

    log::info!("micro-nt-os bootloader starting");

    // ── Locate ACPI RSDP via UEFI config tables ───────────────────────────────
    // Config table borrow is released immediately (rsdp_phys is a plain u64).
    let rsdp_phys = st
        .config_table()
        .iter()
        .find(|t| t.guid == uefi::table::cfg::ACPI2_GUID || t.guid == uefi::table::cfg::ACPI_GUID)
        .map(|t| t.address as usize as u64)
        .unwrap_or(0);
    log::info!("bootloader: RSDP at {:#x}", rsdp_phys);

    // ── B3 / B2 / B1 inside a block so `bt` borrow ends before exit_boot_services ──
    let (
        kernel_phys,
        kernel_size,
        kernel_entry,
        ramdisk_phys,
        ramdisk_size,
        regions,
        region_count,
        pml4_phys,
        boot_info_phys,
        boot_stack_top,
        fb_info,
    ) = {
        let bt = st.boot_services();

        // B3: Load the kernel ELF from the ESP into physical memory.
        let kernel = loader::load_kernel(bt);
        let (kp, ks, ke) = (kernel.phys_base, kernel.size, kernel.entry);
        let (rdp, rds) = loader::load_optional_ramdisk(bt).unwrap_or((0, 0));

        // B2: Build 4-level page tables (identity + HHDM).
        // Must happen BEFORE memory::collect so that the page-table frames are
        // already marked LOADER_DATA in the UEFI map when we snapshot it;
        // otherwise mm::init feeds those frames to the buddy as Usable and the
        // kernel corrupts the PML4 when mapping its heap.
        // SAFETY: single-threaded UEFI boot services context; identity map active.
        let pml4 = unsafe { paging::build(bt) };
        // SAFETY: as above; `kernel` was just laid out by the loader.
        unsafe { paging::map_kernel(bt, pml4, &kernel) };
        log::info!("bootloader: PML4 at {:#x}", pml4.as_u64());

        // B0: Query GOP framebuffer (before memory::collect so the FB physical
        //     address is known; does not allocate any UEFI pages).
        let fb = query_gop(bt);

        let boot_info_pages = (core::mem::size_of::<BootInfo>() + 4095) / 4096;
        let bi_phys = bt
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, boot_info_pages)
            .expect("bootloader: failed to allocate BootInfo pages") as u64;
        let boot_stack_pages = 16usize;
        let boot_stack_phys = bt
            .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, boot_stack_pages)
            .expect("bootloader: failed to allocate boot stack pages") as u64;
        let stack_top = boot_stack_phys + (boot_stack_pages as u64) * 4096;

        // B1: Collect UEFI physical memory map; mark kernel pages KernelImage.
        // Called after all UEFI allocations so the snapshot reflects everything.
        let (mut rgns, count) = memory::collect(bt);
        memory::mark_kernel(&mut rgns, count, kp / 4096, (ks + 4095) / 4096);

        (kp, ks, ke, rdp, rds, rgns, count, pml4, bi_phys, stack_top, fb)
        // `bt` borrow released here
    };

    // ── Populate BootInfo ─────────────────────────────────────────────────────
    // SAFETY: single-threaded; BOOT_INFO written only here; no concurrent access.
    unsafe {
        BOOT_INFO.kernel_phys_base = kernel_phys;
        BOOT_INFO.kernel_size = kernel_size;
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

    // ── Disable logger and allocator BEFORE ExitBootServices ─────────────────
    // After EBS the UEFI console and pool allocator are no longer valid.
    LOGGER.disable();
    uefi::allocator::exit_boot_services();

    // ── B4: Exit UEFI boot services ───────────────────────────────────────────
    // uefi 0.26: exit_boot_services is a safe fn (takes self by value).
    let (_runtime, _mmap) = st.exit_boot_services(MemoryType::LOADER_DATA);

    // ── Enforce the kernel's W^X ──────────────────────────────────────────────
    // EFER.NXE before loading CR3: the new tables set NX bits, which are
    // reserved (and fault) without it. CR0.WP makes ring 0 honour read-only
    // pages too, so the kernel's .text and .rodata are really read-only.
    // SAFETY: every x86-64 CPU we target supports NX; the bootloader's own
    // code and data live in writable, executable identity-mapped pages.
    unsafe {
        Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
        Cr0::update(|flags| flags.insert(Cr0Flags::WRITE_PROTECT));
    }

    // ── Activate our page tables ──────────────────────────────────────────────
    // SAFETY: pml4_phys is a valid, fully-built PML4.
    //         The current IP is in the identity-mapped [0, 4 GiB) region,
    //         so execution continues uninterrupted after the CR3 write.
    unsafe {
        let frame = PhysFrame::containing_address(pml4_phys);
        Cr3::write(frame, Cr3Flags::empty());
    }

    // ── Jump to kernel_main ───────────────────────────────────────────────────
    // SAFETY: kernel_entry is inside the kernel's text segment, mapped RX.
    //         BootInfo is copied to its LOADER_DATA pages through the identity
    //         map, then handed over at its HHDM address, like the boot stack
    //         (both below 4 GiB, so inside the HHDM). kernel_entry never
    //         returns (-> !).
    unsafe {
        // The kernel (x86_64-unknown-none) uses the SysV AMD64 ABI where the
        // first argument is in rdi. The bootloader (x86_64-unknown-uefi) uses
        // the Microsoft ABI where "C" puts the first arg in rcx. We must
        // explicitly request "sysv64" so the bootloader emits code that passes
        // the BootInfo pointer in rdi, matching what kernel_main reads.
        let boot_info_dst = boot_info_phys as *mut BootInfo;
        core::ptr::copy_nonoverlapping(core::ptr::addr_of!(BOOT_INFO), boot_info_dst, 1);
        asm!(
            "mov rsp, {stack}",
            "and rsp, -16",
            "mov rdi, {boot_info}",
            "jmp {entry}",
            stack = in(reg) HHDM_OFFSET + boot_stack_top,
            boot_info = in(reg) HHDM_OFFSET + boot_info_dst as u64,
            entry = in(reg) kernel_entry,
            options(noreturn),
        );
    }
}

/// Query the UEFI GOP protocol and return framebuffer geometry.
///
/// Returns `FramebufferInfo::zeroed()` if GOP is unavailable (headless mode).
/// Must be called while UEFI boot services are active.
fn query_gop(bt: &uefi::table::boot::BootServices) -> FramebufferInfo {
    let handle = match bt.get_handle_for_protocol::<GraphicsOutput>() {
        Ok(h) => h,
        Err(_) => {
            log::warn!("bootloader: GOP not available — framebuffer disabled");
            return FramebufferInfo::zeroed();
        }
    };

    let mut gop = match bt.open_protocol_exclusive::<GraphicsOutput>(handle) {
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
