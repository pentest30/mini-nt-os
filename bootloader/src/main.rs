//! Bootloader — UEFI entry point.
//!
//! Boot sequence:
//!   B3 — Load `kernel.bin` from the ESP into physical 0x0010_0000.
//!   B1 — Collect UEFI memory map; classify and merge regions.
//!   B2 — Build 4-level page tables (identity [0, 4 GiB) + HHDM).
//!   B4 — Fill `BootInfo`, exit UEFI boot services, switch CR3, jump.
//!
//! Build target: x86_64-unknown-uefi
//! uefi crate 0.26: helpers module does not exist; use allocator::init +
//! logger::Logger directly.

#![no_std]
#![no_main]

mod loader;
mod memory;
mod paging;

use boot_info::{BootInfo, FramebufferInfo, PixelFormat};
use core::arch::asm;
use loader::KERNEL_PHYS_BASE;
use paging::HHDM_OFFSET;
use uefi::{entry, Handle, Status, table::{Boot, SystemTable}};
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopFmt};
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::PhysFrame,
};

/// Virtual entry address: HHDM base + kernel physical load address.
/// The kernel binary is a flat binary; `kernel_main` is at its first byte.
const KERNEL_VIRT_ENTRY: u64 = HHDM_OFFSET + KERNEL_PHYS_BASE;

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
        .find(|t| {
            t.guid == uefi::table::cfg::ACPI2_GUID
                || t.guid == uefi::table::cfg::ACPI_GUID
        })
        .map(|t| t.address as usize as u64)
        .unwrap_or(0);
    log::info!("bootloader: RSDP at {:#x}", rsdp_phys);

    // ── B3 / B2 / B1 inside a block so `bt` borrow ends before exit_boot_services ──
    let (kernel_phys, kernel_size, ramdisk_phys, ramdisk_size, regions, region_count, pml4_phys, boot_info_phys, boot_stack_top, fb_info) = {
        let bt = st.boot_services();

        // B3: Load kernel binary from ESP into physical memory.
        let (kp, ks) = loader::load(bt);
        let (rdp, rds) = loader::load_optional_ramdisk(bt).unwrap_or((0, 0));

        // B2: Build 4-level page tables (identity + HHDM).
        // Must happen BEFORE memory::collect so that the page-table frames are
        // already marked LOADER_DATA in the UEFI map when we snapshot it;
        // otherwise mm::init feeds those frames to the buddy as Usable and the
        // kernel corrupts the PML4 when mapping its heap.
        // SAFETY: single-threaded UEFI boot services context; identity map active.
        let pml4 = unsafe { paging::build(bt) };
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

        (kp, ks, rdp, rds, rgns, count, pml4, bi_phys, stack_top, fb)
        // `bt` borrow released here
    };

    // ── Populate BootInfo ─────────────────────────────────────────────────────
    // SAFETY: single-threaded; BOOT_INFO written only here; no concurrent access.
    unsafe {
        BOOT_INFO.kernel_phys_base = kernel_phys;
        BOOT_INFO.kernel_size      = kernel_size;
        BOOT_INFO.rsdp_phys        = rsdp_phys;
        BOOT_INFO.ramdisk_phys_base = ramdisk_phys;
        BOOT_INFO.ramdisk_size      = ramdisk_size;
        BOOT_INFO.framebuffer      = fb_info;
        BOOT_INFO.memory_map_len   = region_count as u32;
        BOOT_INFO.memory_map       = regions;
    }

    log::info!(
        "bootloader: BootInfo ready — {} regions, kernel {:#x}+{}B, entry {:#x}",
        region_count, kernel_phys, kernel_size, KERNEL_VIRT_ENTRY,
    );

    // ── Disable logger and allocator BEFORE ExitBootServices ─────────────────
    // After EBS the UEFI console and pool allocator are no longer valid.
    LOGGER.disable();
    uefi::allocator::exit_boot_services();

    // ── B4: Exit UEFI boot services ───────────────────────────────────────────
    // uefi 0.26: exit_boot_services is a safe fn (takes self by value).
    let (_runtime, _mmap) = st.exit_boot_services(MemoryType::LOADER_DATA);

    // ── Activate our page tables ──────────────────────────────────────────────
    // SAFETY: pml4_phys is a valid, fully-built PML4.
    //         The current IP is in the identity-mapped [0, 4 GiB) region,
    //         so execution continues uninterrupted after the CR3 write.
    unsafe {
        let frame = PhysFrame::containing_address(pml4_phys);
        Cr3::write(frame, Cr3Flags::empty());
    }

    // ── Jump to kernel_main ───────────────────────────────────────────────────
    // SAFETY: KERNEL_VIRT_ENTRY is mapped (HHDM covers [0, 4 GiB)).
    //         BOOT_INFO lives at its physical address, identity-mapped by the
    //         bootloader; the kernel can reach it via the HHDM too.
    //         kernel_entry never returns (-> !).
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
            stack = in(reg) boot_stack_top,
            boot_info = in(reg) boot_info_dst as u64,
            entry = in(reg) KERNEL_VIRT_ENTRY,
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
        Ok(h)  => h,
        Err(_) => {
            log::warn!("bootloader: GOP not available — framebuffer disabled");
            return FramebufferInfo::zeroed();
        }
    };

    let mut gop = match bt.open_protocol_exclusive::<GraphicsOutput>(handle) {
        Ok(g)  => g,
        Err(e) => {
            log::warn!("bootloader: GOP open failed ({:?}) — framebuffer disabled", e.status());
            return FramebufferInfo::zeroed();
        }
    };

    let mode   = gop.current_mode_info();
    let (w, h) = mode.resolution();
    let stride = mode.stride();
    let format = match mode.pixel_format() {
        GopFmt::Bgr => PixelFormat::Bgr,
        GopFmt::Rgb => PixelFormat::Rgb,
        _           => PixelFormat::Unknown,
    };
    // SAFETY: GOP framebuffer pointer is valid for the lifetime of boot services.
    let base = gop.frame_buffer().as_mut_ptr() as u64;

    log::info!(
        "bootloader: GOP {}×{} stride={} fmt={:?} base={:#x}",
        w, h, stride, format, base
    );

    FramebufferInfo { base, width: w as u32, height: h as u32, stride: stride as u32, format }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
