//! Kernel entry point — called by the bootloader after ExitBootServices().
//!
//! Initialisation order (mirrors NT startup sequence):
//!   1. HAL        — GDT, IDT, serial, IRQL, APIC timer (enables interrupts)
//!   2. Mm         — feed BootInfo memory map to buddy allocator
//!   3. Heap (E1)  — map 256 × 4 KiB pages at HEAP_START via MmPageTables;
//!                   init LockedHeap there
//!   4. Executive  — Ke, Ob, Ps, Io stubs (Phase 2)
//!
//! Heap virtual address: 0xFFFF_8800_0000_0000 (above the kernel image HHDM
//! range, below UEFI runtime services).

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
mod launcher;
mod syscall;

use boot_info::BootInfo;
use core::arch::asm;
use x86_64::{
    instructions::segmentation::{DS, ES, SS, Segment},
    PhysAddr, VirtAddr,
    structures::gdt::SegmentSelector,
    structures::paging::PageTableFlags,
};

/// Kernel heap — backed by a bump allocator.
///
/// `BumpAllocator` never fails due to fragmentation (zero fragmentation),
/// which is critical because `linked_list_allocator` was found to corrupt
/// its free-list when BTreeMap/Arc small allocs preceded a large alloc.
///
/// # Phase 3 upgrade
/// When we need real dealloc (per-process heaps), swap for a slab allocator.
/// The `GlobalAlloc` interface is unchanged.
#[global_allocator]
static ALLOCATOR: bump_alloc::BumpAllocator = bump_alloc::BumpAllocator::new();

/// First virtual address of the kernel heap region.
/// Chosen above the kernel HHDM image region and below UEFI runtime services.
const HEAP_START: u64   = 0xFFFF_8800_0000_0000;

/// Kernel heap size: 4 MiB = 1024 × 4 KiB pages.
const HEAP_SIZE:  usize = 4 * 1024 * 1024;

/// Number of 4 KiB pages to map for the heap.
const HEAP_PAGES: usize = HEAP_SIZE / 4096;

/// Page flags for the heap: present, writable, NX.
const HEAP_FLAGS: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits()
        | PageTableFlags::WRITABLE.bits()
        | PageTableFlags::NO_EXECUTE.bits(),
);

// ── KernelPageMapper ─────────────────────────────────────────────────────────
//
// Implements `mm::PageMapper` using the buddy allocator + the kernel's
// active page tables (OffsetPageTable).  Passed to `mm::virtual_alloc::allocate`
// and `free` so user-mode allocations get real physical backing.
//
// # IRQL: PASSIVE_LEVEL only.
// Both the buddy lock and OffsetPageTable::map_to are spinlock-protected.

struct KernelPageMapper {
    pt: mm::MmPageTables,
}

impl mm::virtual_alloc::PageMapper for KernelPageMapper {
    fn commit_page(
        &mut self,
        virt_addr:  u64,
        writable:   bool,
        executable: bool,
        user:       bool,
    ) -> Result<(), &'static str> {
        // Check if the VA is already mapped as a USER_ACCESSIBLE 4 KiB page.
        // If so, just zero the page (for BSS sections / VirtualAlloc guarantees)
        // but don't allocate a new frame.
        if let Some((_p, f)) = self.pt.translate_flags(VirtAddr::new(virt_addr)) {
            use x86_64::structures::paging::PageTableFlags as F;
            if f.contains(F::USER_ACCESSIBLE) && !f.contains(F::HUGE_PAGE) {
                // Zero the page — process reuse requires clean state.
                unsafe { core::ptr::write_bytes(virt_addr as *mut u8, 0, 4096); }
                return Ok(());
            }
        }

        let pfn = mm::buddy::BUDDY
            .lock()
            .as_mut()
            .ok_or("commit_page: buddy not initialised")?
            .alloc(0)
            .ok_or("commit_page: out of physical memory")?;

        let phys = PhysAddr::new(pfn.to_phys());
        let virt = VirtAddr::new(virt_addr);

        let mut flags = PageTableFlags::PRESENT;
        if writable    { flags |= PageTableFlags::WRITABLE; }
        if !executable { flags |= PageTableFlags::NO_EXECUTE; }
        if user        { flags |= PageTableFlags::USER_ACCESSIBLE; }

        // SAFETY: virt is a freshly claimed user-mode address; phys is a
        //         fresh page-aligned frame from the buddy.
        unsafe { self.pt.map_page(virt, phys, flags) };

        // Zero the page — Windows guarantees MEM_COMMIT pages are zeroed.
        // Without this, .bss sections contain stale data from recycled frames.
        // SAFETY: the page was just mapped at `virt`; writing 4096 zeros is valid.
        unsafe {
            core::ptr::write_bytes(virt_addr as *mut u8, 0, 4096);
        }
        Ok(())
    }

    fn decommit_page(&mut self, virt_addr: u64) -> Result<(), &'static str> {
        let virt  = VirtAddr::new(virt_addr);
        // SAFETY: virt_addr was previously mapped by commit_page; single-CPU
        //         Phase 2 — no concurrent unmap possible.
        let frame = unsafe { self.pt.unmap_page(virt) };  // also flushes TLB
        // Return frame to buddy.
        let pfn = mm::Pfn(frame.start_address().as_u64() / 4096);
        if let Some(b) = mm::buddy::BUDDY.lock().as_mut() {
            b.free(pfn, 0);
        }
        Ok(())
    }
}


/// Kernel entry point.
///
/// # Safety
/// - Called exactly once by the bootloader.
/// - CPU is in 64-bit long mode, interrupts disabled on entry.
/// - `boot_info_ptr` points to a valid, static `BootInfo` in identity-mapped
///   physical memory.
/// - The bootloader's identity map [0, 4 GiB) and HHDM are active.
///
/// # IRQL: HIGH on entry; drops to PASSIVE after `hal::init()`.
///
/// Placed in `.text.entry` so the linker script can guarantee it sits at
/// the very first byte of the kernel flat binary (physical 0x0010_0000).
#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn kernel_main(boot_info_ptr: *const BootInfo) -> ! {
    extern "C" {
        static __bss_start: u8;
        static __bss_end: u8;
    }
    unsafe {
        let start = core::ptr::addr_of!(__bss_start) as usize;
        let end = core::ptr::addr_of!(__bss_end) as usize;
        if end > start {
            core::ptr::write_bytes(start as *mut u8, 0, end - start);
        }
    }

    // ── 1. HAL: GDT, IDT, serial, IRQL, APIC timer ──────────────────────────
    // SAFETY: first call; CPU in clean state with interrupts disabled.
    // hal::init() registers the serial logger, then enables interrupts.
    unsafe { hal::init() };
    set_kernel_segments();

    // ── Validate BootInfo ────────────────────────────────────────────────────
    // SAFETY: boot_info_ptr provided by the bootloader in identity-mapped memory.
    let boot_info: &'static BootInfo = unsafe {
        assert!(!boot_info_ptr.is_null(), "null BootInfo pointer");
        let bi = &*boot_info_ptr;
        assert!(bi.is_valid(), "invalid BootInfo magic: {:#x}", bi.magic);
        bi
    };

    // Store HHDM offset for the page-fault handler's page-table walk.
    hal::set_hhdm_offset(boot_info.hhdm_offset);

    // ── 1.5. Framebuffer console ─────────────────────────────────────────────
    // Init before the first log::info! so kernel messages appear on screen.
    // SAFETY: HHDM is active; bootloader identity-maps [0, 4 GiB) so the
    //         GOP framebuffer (always below 4 GiB on QEMU/VBox) is reachable
    //         at hhdm_offset + framebuffer.base.
    unsafe { hal::fb::init(&boot_info.framebuffer, boot_info.hhdm_offset) };
    hal::fb::write_str("[fb] boot banner enabled\n");

    log::info!("micro-nt-os kernel_main — Phase 1");
    log::info!(
        "BootInfo: kernel={:#x}+{}B  HHDM={:#x}  regions={}",
        boot_info.kernel_phys_base,
        boot_info.kernel_size,
        boot_info.hhdm_offset,
        boot_info.memory_map_len,
    );

    // ── 2. Mm: feed buddy allocator from BootInfo memory map ─────────────────
    // Pass the true kernel physical end (including BSS) so the buddy never
    // hands out BSS frames as page-table pages, which would alias statics.
    //
    // SAFETY: __bss_end is a linker symbol; taking its address is valid.
    let bss_end_phys = unsafe { &__bss_end as *const u8 as u64 };
    mm::init(boot_info, bss_end_phys);

    // ── 3. Heap (E1): pre-allocate all frames, then map them ─────────────────
    //
    // We MUST NOT hold the buddy lock while calling map_page — map_page calls
    // BuddyFrameAllocator internally which tries to acquire the same lock,
    // causing a spin-mutex self-deadlock.
    //
    // Solution: pre-allocate all HEAP_PAGES frames into a stack array while
    // holding the lock once, then release the lock, then do all mappings.
    {
        x86_64::instructions::interrupts::disable();

        let kernel_start_pfn = boot_info.kernel_phys_base / 4096;
        // Use the same BSS-inclusive end we passed to mm::init() so the heap
        // frame skip covers the full kernel footprint (code + data + BSS).
        let kernel_end_pfn = (bss_end_phys + 4095) / 4096;

        // Ramdisk frame range — must not be handed to the heap allocator.
        // UEFI LOADER_DATA is BootloaderReclaimable (not Usable) so the buddy
        // normally never sees these frames; but if UEFI coalesces or
        // mis-categorises regions we could corrupt the ramdisk before Io reads it.
        let ramdisk_start_pfn = boot_info.ramdisk_phys_base / 4096;
        let ramdisk_end_pfn   = if boot_info.ramdisk_size > 0 {
            (boot_info.ramdisk_phys_base + boot_info.ramdisk_size + 4095) / 4096
        } else {
            0
        };

        // Phase 1 — allocate all frames (buddy lock held, no map_page calls).
        let mut heap_frames = [mm::Pfn(0u64); HEAP_PAGES];
        {
            let mut guard = mm::buddy::BUDDY.lock();
            let buddy = guard.as_mut().expect("mm not initialised");
            for slot in heap_frames.iter_mut() {
                let mut candidate = buddy
                    .alloc(0)
                    .expect("out of physical memory mapping heap");
                while (candidate.0 >= kernel_start_pfn && candidate.0 < kernel_end_pfn)
                    || (ramdisk_end_pfn > 0
                        && candidate.0 >= ramdisk_start_pfn
                        && candidate.0 < ramdisk_end_pfn)
                {
                    candidate = buddy
                        .alloc(0)
                        .expect("out of memory skipping kernel/ramdisk frames");
                }
                *slot = candidate;
            }
            // buddy lock released here — guard drops at end of this block
        }

        // Phase 2 — map all pre-allocated frames (no buddy lock held).
        // map_page may internally allocate intermediate page-table frames via
        // BuddyFrameAllocator; the lock is free so no deadlock.
        // SAFETY: bootloader page tables are active; hhdm_offset is correct.
        let mut pt = unsafe { mm::MmPageTables::new(boot_info.hhdm_offset) };
        for (i, pfn) in heap_frames.iter().enumerate() {
            let virt = VirtAddr::new(HEAP_START + (i * 4096) as u64);
            let phys = PhysAddr::new(pfn.to_phys());
            // SAFETY: virt is in the unmapped heap range; phys is a fresh frame.
            unsafe { pt.map_page(virt, phys, HEAP_FLAGS) };
        }

        // Phase 3 — initialise the bump allocator.
        // SAFETY: HEAP_START..+HEAP_SIZE is now fully mapped RW+NX;
        //         this is the one and only call to init().
        unsafe { ALLOCATOR.init(HEAP_START as *mut u8, HEAP_SIZE) };

        x86_64::instructions::interrupts::enable();

        log::info!(
            "heap: {:#x}..{:#x} ({} KiB, {} pages mapped)",
            HEAP_START,
            HEAP_START + HEAP_SIZE as u64,
            HEAP_SIZE / 1024,
            HEAP_PAGES,
        );
    }

    // Smoke-test: Box allocation forces a real heap use.
    {
        let _probe = alloc::boxed::Box::new(0xDEAD_BEEF_u64);
        log::info!("heap: Box allocation probe OK");
    }

    // ── 4. Executive initialisation ───────────────────────────────────────────
    // With the bump allocator (T5-1) there is no free-list fragmentation, so
    // ob/ps/io can safely run before or after loader_demo without corrupting
    // subsequent large allocations.
    x86_64::instructions::interrupts::disable();
    set_kernel_segments();
    ke::init();
    ob::init();
    ps::init();
    io_manager::init(
        boot_info.ramdisk_phys_base,
        boot_info.ramdisk_size,
        boot_info.hhdm_offset,
    );
    fat_smoke_probe();

    // Wire preemptive round-robin: timer ISR calls schedule() after each EOI.
    // Must be registered after ke::init() (scheduler table is ready) and before
    // interrupts re-enable (avoid a timer ISR firing with a half-initialised hook).
    hal::timer::set_tick_hook(Some(ke::scheduler::schedule));
    hal::idt::set_syscall_hook(Some(syscall::dispatch));
    hal::idt::set_user_fault_hook(Some(ke::scheduler::terminate_current_thread));

    x86_64::instructions::interrupts::enable();

    // ── 5a. Phase 3: auto-run HELLO.EXE from FAT if present ──────────────────
    // Silently skipped if HELLO.EXE is not on the ramdisk.
    // Emits "[smoke] HELLO.EXE ran ok" on success — checked by qemu-run.sh.
    try_run_hello_exe(boot_info.hhdm_offset);

    // ── 5a2. Phase 3: DXVK DLL chain load test ────────────────────────────────
    // Attempts to load D3D8.DLL from the FAT ramdisk (triggers d3d9.dll dep).
    // Both resolve imports against vulkan-1.dll / kernel32.dll stub modules.
    try_load_dxvk_chain();

    // ── 5b. Phase 2: PE loader smoke test + process setup ─────────────────────
    log::info!(
        "heap before loader_demo: used={} free={}",
        ALLOCATOR.used(), ALLOCATOR.free(),
    );
    let ring3_ctx = loader_demo(boot_info.hhdm_offset);

    // ── Ready ─────────────────────────────────────────────────────────────────
    let free_pages = mm::buddy::BUDDY
        .lock()
        .as_ref()
        .map(|b| b.free_pages())
        .unwrap_or(0);

    log::info!(
        "kernel_main ready — ticks: {}, free_pages: {}",
        hal::timer::get_tick_count(),
        free_pages,
    );
    // ── Phase 2.5: scheduler-based ring-3 launch ─────────────────────────────
    //
    // Register the initial user-mode process as a scheduler thread.  The timer
    // ISR will switch to it the next time schedule() runs pick_next() and finds
    // this thread in the Ready queue.
    //
    // We no longer call jump_to_ring3_32() directly here; instead the scheduler
    // handles the ring-0→ring-3 transition via ring3_iretq_trampoline when it
    // first context-switches to this thread.  This allows the boot thread to
    // re-run (e.g. as a kernel shell) after the user-mode process exits via
    // NtTerminateProcess → ke::scheduler::terminate_current_thread().
    let (entry_point, stack_top) = ring3_ctx;

    log::info!(
        "kernel_main: spawning user thread  entry={:#010x}  usp={:#010x}",
        entry_point, stack_top,
    );

    let user_tid = ke::scheduler::spawn_user_thread(
        entry_point,
        stack_top,
        hal::gdt::user_code32_selector(),
        hal::gdt::user_data32_selector(),
        hal::gdt::user_teb_fs_selector(),
    ).expect("kernel_main: scheduler full — cannot spawn initial user thread");

    log::info!("kernel_main: user thread TID={} spawned — launching Mino UI", user_tid);

    // Show the game launcher immediately. CMD.EXE (user thread) continues
    // running in the background; its framebuffer output is suppressed by
    // EXCLUSIVE=true inside launcher::run(). When the user presses D we
    // drop to the kernel debug shell.
    loop {
        launcher::run();
        // Kill all user-mode threads (CMD.EXE etc.) so the kernel shell has
        // exclusive console input — no thread races for serial/PS2 keystrokes.
        ke::scheduler::terminate_user_threads();
        // kernel_shell returns when ESC is pressed → back to launcher.
        kernel_shell(boot_info.hhdm_offset);
    }
}

fn set_kernel_segments() {
    unsafe {
        asm!("cld");
        let kd = SegmentSelector(hal::gdt::kernel_data_selector());
        DS::set_reg(kd);
        ES::set_reg(kd);
        SS::set_reg(kd);
    }
}

// ── loader_from_fat ───────────────────────────────────────────────────────────
//
// Tries to open /CMD.EXE from the FAT32 ramdisk, load it as a PE32 image into
// user-mode VA space, and return (entry_point, stack_top) for the IRETQ trampoline.
//
// Returns None if the file is missing or any step fails (caller falls back to
// build_test_pe32 in loader_demo).
//
// Side-effects (on success):
//   • Emits "[smoke] FAT read probe hit" to the kernel log.
//   • Installs a fresh SYSCALL_CTX (VAD + hhdm_offset) for ring-3 syscalls.
//   • Sets SharedUserData address for GetTickCount stub.
//
// # IRQL: PASSIVE — interrupts are disabled by the caller (loader_demo).

fn loader_from_fat(hhdm_offset: u64) -> Option<(u32, u32)> {
    let mut file = match io_manager::open_fat_file("/CMD.EXE") {
        Ok(f) => f,
        Err(e) => {
            log::warn!("loader_from_fat: open failed: {:?}", e);
            return None;
        }
    };
    let size = file.file_size as usize;
    if size == 0 || size > 256 * 1024 {
        log::warn!("loader_from_fat: invalid file size {}", size);
        return None;
    }
    let mut pe_bytes = alloc::vec![0u8; size];
    let n = match io_manager::read_fat_file(&mut file, &mut pe_bytes) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("loader_from_fat: read failed: {:?}", e);
            return None;
        }
    };
    if n < 64 {
        log::warn!("loader_from_fat: short read {}", n);
        return None;
    }
    pe_bytes.truncate(n);
    log::info!("[smoke] FAT read probe hit");

    let mut vad = mm::vad::VadTree::new();
    let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    let mut mapper = KernelPageMapper { pt };
    let mut img = ps::loader::LoadedImage { image_base: 0, entry_point: 0, image_size: 0 };
    ps::loader::load_image(&pe_bytes, &mut img, &mut vad, &mut mapper, None).ok()?;
    let ctx = ps::loader::setup_process(&img, &mut vad, &mut mapper, 4, 1).ok()?;
    hal::timer::set_shared_user_data_addr(Some(ps::loader::SHARED_USER_DATA32_VA as u64));
    syscall::install(vad, hhdm_offset);
    Some((img.entry_point as u32, ctx.stack_top))
}

// ── loader_demo ───────────────────────────────────────────────────────────────
//
// Entry point for Phase 2.5 user-mode bootstrap:
//   1. Try to load CMD.EXE from the FAT ramdisk (loader_from_fat).
//   2. Fall back to an inline-built PE32 in kernel heap memory.
//
// Returns (entry_point, stack_top) for the IRETQ trampoline in kernel_main.

// ── try_run_hello_exe ─────────────────────────────────────────────────────────
//
// Phase 3 smoke test: if HELLO.EXE is present on the FAT ramdisk, load it as a
// real MSVC-compiled PE32, run it as a ring-3 user thread, wait for it to exit,
// and emit "[smoke] HELLO.EXE ran ok".  Silently skipped if not found.
//
// Must be called before loader_demo() so its VAD doesn't conflict with CMD.EXE.
// # IRQL: PASSIVE_LEVEL (interrupts disabled across load, enabled while waiting)
fn try_run_hello_exe(hhdm_offset: u64) {
    // Probe: is HELLO.EXE on the ramdisk?
    if io_manager::open_fat_file("/HELLO.EXE").is_err() {
        return; // not present — skip silently
    }
    log::info!("[phase3] found HELLO.EXE on FAT — loading");

    x86_64::instructions::interrupts::disable();
    set_kernel_segments();
    let tid = shell_load_and_spawn("/HELLO.EXE", hhdm_offset);
    x86_64::instructions::interrupts::enable();

    match tid {
        Some(t) => {
            // Wait for the process to exit via NtTerminateProcess.
            while ke::scheduler::is_thread_running(t) {
                x86_64::instructions::hlt();
            }
            log::info!("[smoke] HELLO.EXE ran ok");
        }
        None => {
            log::warn!("[phase3] HELLO.EXE load failed");
        }
    }
}

/// Phase 3 smoke test: attempt to load the DXVK d3d8→d3d9→vulkan-1 DLL chain.
/// Exercises: FAT read of real PE32 DLLs, recursive dependency loading,
/// relocation, and import resolution against stub modules.
/// Silently skipped if D3D8.DLL is not on the ramdisk.
fn try_load_dxvk_chain() {
    if io_manager::open_fat_file("/D3D8.DLL").is_err() {
        return; // DXVK DLLs not present — skip
    }
    log::info!("[phase3] DXVK DLLs found — testing load chain");

    // Use the syscall LoadLibraryA path which handles recursive deps.
    // We call the kernel-internal load_dll_from_fat directly (same code path).
    let base = syscall::load_dll_from_fat_pub("d3d8.dll");
    if base != 0 {
        log::info!("[smoke] DXVK d3d8.dll loaded at {:#x}", base);
        // Verify vulkan-1.dll is resolvable (stub module)
        if let Some(vk_base) = ps::loader::resolve_stub_module_base("vulkan-1.dll") {
            log::info!("[smoke] vulkan-1.dll stub at {:#x}", vk_base);
        }
    } else {
        log::warn!("[phase3] DXVK d3d8.dll load failed");
    }

    // Test loading real DXVK d3d9.dll (4.3 MB) — uses buddy-backed buffer.
    let d3d9_base = syscall::load_dll_from_fat_pub("d3d9.dll");
    if d3d9_base != 0 {
        log::info!("[smoke] DXVK d3d9.dll loaded at {:#x}", d3d9_base);
    } else {
        log::warn!("[phase3] DXVK d3d9.dll load failed");
    }
}

fn loader_demo(hhdm_offset: u64) -> (u32, u32) {
    // IRQs must stay disabled while we use the bump allocator and page tables.
    x86_64::instructions::interrupts::disable();
    set_kernel_segments();

    // ── Fast path: load real binary from FAT ramdisk ──────────────────────────
    if let Some(ctx) = loader_from_fat(hhdm_offset) {
        x86_64::instructions::interrupts::enable();
        return ctx;
    }

    log::info!("loader_demo: step 1 — heap used={} free={}", ALLOCATOR.used(), ALLOCATOR.free());

    // Build a tiny but valid PE32 in heap memory.
    let pe_bytes = build_test_pe32(
        0x0200_0000,  // preferred image base (32 MiB, safe above heap frame range)
        0x1000,       // AddressOfEntryPoint RVA
    );

    let mut vad = mm::vad::VadTree::new();

    // SAFETY: bootloader page tables active; hhdm_offset is correct.
    let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    let mut mapper = KernelPageMapper { pt };

    let mut img = ps::loader::LoadedImage { image_base: 0, entry_point: 0, image_size: 0 };
    ps::loader::load_image(&pe_bytes, &mut img, &mut vad, &mut mapper, None)
        .expect("loader_demo: load_image failed");

    log::info!(
        "loader_demo: PE loaded — base={:#x}  entry={:#x}  size={} B",
        img.image_base, img.entry_point, img.image_size,
    );

    let ctx = ps::loader::setup_process(&img, &mut vad, &mut mapper, 4, 1)
        .expect("loader_demo: setup_process failed");
    hal::timer::set_shared_user_data_addr(Some(ps::loader::SHARED_USER_DATA32_VA as u64));

    log::info!("loader_demo: VAD has {} entry(ies)", vad.len());
    syscall::install(vad, hhdm_offset);
    log::info!("loader_demo: PASS");

    x86_64::instructions::interrupts::enable();

    // Truncate to u32 — these are 32-bit user-mode addresses (<4 GiB).
    (img.entry_point as u32, ctx.stack_top)
}

#[allow(dead_code)]
fn fat_smoke_probe() {
    match io_manager::smoke_probe_mz() {
        Ok(out) if out == *b"MZ" => {
            log::info!("[smoke] FAT read probe hit");
        }
        Ok(out) => {
            log::warn!("fat_smoke: unexpected signature={:02x?}", out);
        }
        Err(e) => {
            log::warn!("fat_smoke: probe failed: {:?}", e);
        }
    }
}

/// Build a minimal valid PE32 binary as a heap-allocated byte vector.
/// Used only by `loader_demo`.
fn build_test_pe32(image_base: u32, entry_rva: u32) -> alloc::vec::Vec<u8> {
    // NOTE: image_base must be at a VA that is NOT used by the heap's physical
    // frames in the identity map.  Safe choices: > 32 MiB (0x200_0000) on
    // a 128 MiB QEMU machine where heap frames start at ~1 MiB and span ~4 MiB.
    use ps::loader::*;

    log::info!("build_test_pe32: before alloc heap used={} free={}", ALLOCATOR.used(), ALLOCATOR.free());
    let mut buf = alloc::vec![0u8; 0x3000]; // 12 KiB — enough for headers + one section
    log::info!("build_test_pe32: after alloc ptr={:#x} heap used={} free={}", buf.as_ptr() as usize, ALLOCATOR.used(), ALLOCATOR.free());

    // ── DOS header ────────────────────────────────────────────────────────────
    buf[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
    let nt_off: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&nt_off.to_le_bytes());

    // ── NT signature ──────────────────────────────────────────────────────────
    buf[0x40..0x44].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

    let fh_off  = 0x44usize;
    let opt_sz  = core::mem::size_of::<ImageOptionalHeader32>() as u16;
    let nsec: u16 = 2;

    // ── FILE_HEADER ───────────────────────────────────────────────────────────
    buf[fh_off..fh_off+2].copy_from_slice(&MACHINE_I386.to_le_bytes());
    buf[fh_off+2..fh_off+4].copy_from_slice(&nsec.to_le_bytes());
    buf[fh_off+16..fh_off+18].copy_from_slice(&opt_sz.to_le_bytes());

    // ── OPTIONAL_HEADER32 ─────────────────────────────────────────────────────
    let opt_off = fh_off + core::mem::size_of::<ImageFileHeader>();
    // magic
    buf[opt_off..opt_off+2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
    // entry point RVA at offset 16
    buf[opt_off+16..opt_off+20].copy_from_slice(&entry_rva.to_le_bytes());
    // image base at offset 28
    buf[opt_off+28..opt_off+32].copy_from_slice(&image_base.to_le_bytes());
    // SizeOfImage at offset 56 (covers .text at 0x1000 and .data at 0x2000)
    let size_of_image: u32 = 0x3000;
    buf[opt_off+56..opt_off+60].copy_from_slice(&size_of_image.to_le_bytes());
    // SizeOfHeaders at offset 60
    let size_of_headers: u32 = 0x400;
    buf[opt_off+60..opt_off+64].copy_from_slice(&size_of_headers.to_le_bytes());
    // number of data directories at offset 92
    let n_dirs: u32 = 16;
    buf[opt_off+92..opt_off+96].copy_from_slice(&n_dirs.to_le_bytes());

    // ── Section headers (.text, .data) ───────────────────────────────────────
    let sh_off = opt_off + opt_sz as usize;
    let text_rva: u32 = 0x1000;
    let text_raw: u32 = 0x600;
    let text_off = size_of_headers as usize;
    buf[sh_off..sh_off+5].copy_from_slice(b".text");
    buf[sh_off+8..sh_off+12].copy_from_slice(&(text_raw).to_le_bytes());
    buf[sh_off+12..sh_off+16].copy_from_slice(&text_rva.to_le_bytes());
    buf[sh_off+16..sh_off+20].copy_from_slice(&text_raw.to_le_bytes());
    buf[sh_off+20..sh_off+24].copy_from_slice(&size_of_headers.to_le_bytes());
    let text_chars: u32 = SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_CNT_CODE;
    buf[sh_off+36..sh_off+40].copy_from_slice(&text_chars.to_le_bytes());

    let sh2 = sh_off + 40;
    let data_rva: u32 = 0x2000;
    let data_raw: u32 = 0x600;
    let data_off = (size_of_headers + text_raw) as usize;
    buf[sh2..sh2+5].copy_from_slice(b".data");
    buf[sh2+8..sh2+12].copy_from_slice(&(data_raw).to_le_bytes());
    buf[sh2+12..sh2+16].copy_from_slice(&data_rva.to_le_bytes());
    buf[sh2+16..sh2+20].copy_from_slice(&data_raw.to_le_bytes());
    buf[sh2+20..sh2+24].copy_from_slice(&(size_of_headers + text_raw).to_le_bytes());
    let data_chars: u32 = SCN_MEM_READ | SCN_MEM_WRITE | SCN_CNT_INITIALIZED_DATA;
    buf[sh2+36..sh2+40].copy_from_slice(&data_chars.to_le_bytes());

    fn emit_u32(dst: &mut alloc::vec::Vec<u8>, v: u32) {
        dst.extend_from_slice(&v.to_le_bytes());
    }
    fn emit_push_u32(dst: &mut alloc::vec::Vec<u8>, v: u32) {
        dst.push(0x68);
        dst.extend_from_slice(&v.to_le_bytes());
    }

    let args_write_va = image_base.wrapping_add(data_rva + 0x00);
    let args_alloc_va = image_base.wrapping_add(data_rva + 0x20);
    let iat_iosb_va = image_base.wrapping_add(data_rva + 0x130);
    let iat_msg_va = image_base.wrapping_add(data_rva + 0x138);
    let args_iat_proof_va = image_base.wrapping_add(data_rva + 0x148);
    let iat_proof_msg_va = image_base.wrapping_add(data_rva + 0x160);
    let import_desc_rva: u32 = data_rva + 0x1A0;
    let import_int_rva: u32 = data_rva + 0x1C0;
    let import_iat_rva: u32 = data_rva + 0x1D0;
    let import_ibn_rva: u32 = data_rva + 0x1E0;
    let import_dll_rva: u32 = data_rva + 0x1F0;
    let import_iat_va    = image_base.wrapping_add(import_iat_rva);
    let sysenter_iosb_va = image_base.wrapping_add(data_rva + 0xD0);
    let sysenter_msg_va  = image_base.wrapping_add(data_rva + 0xD8);
    let args_create_proc_va = image_base.wrapping_add(data_rva + 0x80);
    let out_proc_handle_va = image_base.wrapping_add(data_rva + 0x90);
    let args_create_thread_va = image_base.wrapping_add(data_rva + 0xA0);
    let out_thread_handle_va = image_base.wrapping_add(data_rva + 0xB8);
    let out_client_id_va = image_base.wrapping_add(data_rva + 0xC0);
    let out_base_va = image_base.wrapping_add(data_rva + 0x40);
    let out_size_va = image_base.wrapping_add(data_rva + 0x44);
    let args_term_va = image_base.wrapping_add(data_rva + 0x48);
    let msg_va = image_base.wrapping_add(data_rva + 0x60);
    let msg = b"[smoke] int2e write+alloc+term\n";
    let iat_msg = b"[iat] NtWriteFile via IAT\n";
    let iat_proof_msg = b"IATOK";
    let sysenter_msg  = b"[smoke] SYSENTER path hit\n";

    let mut code = alloc::vec::Vec::<u8>::new();
    code.extend_from_slice(&[0x66, 0xB8, 0x23, 0x00]);
    code.extend_from_slice(&[0x8E, 0xD8]);
    code.extend_from_slice(&[0x8E, 0xC0]);
    code.push(0xBA); emit_u32(&mut code, args_write_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.push(0xBA); emit_u32(&mut code, 0);
    code.extend_from_slice(&[0xB8, 0x50, 0x20, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.push(0xBA); emit_u32(&mut code, args_create_proc_va);
    code.extend_from_slice(&[0xB8, 0x1B, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xA1]); emit_u32(&mut code, out_proc_handle_va);
    code.extend_from_slice(&[0xA3]); emit_u32(&mut code, args_create_thread_va + 12);
    code.push(0xBA); emit_u32(&mut code, args_create_thread_va);
    code.extend_from_slice(&[0xB8, 0x35, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    emit_push_u32(&mut code, 0);
    emit_push_u32(&mut code, 0);
    emit_push_u32(&mut code, iat_msg.len() as u32);
    emit_push_u32(&mut code, iat_msg_va);
    emit_push_u32(&mut code, iat_iosb_va);
    emit_push_u32(&mut code, 0);
    emit_push_u32(&mut code, 0);
    emit_push_u32(&mut code, 0);
    emit_push_u32(&mut code, 0);
    code.extend_from_slice(&[0xFF, 0x15]); emit_u32(&mut code, import_iat_va);
    code.push(0xBA); emit_u32(&mut code, args_iat_proof_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.push(0xBA); emit_u32(&mut code, args_alloc_va);
    code.extend_from_slice(&[0xB8, 0x11, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0x8B, 0x1D]); emit_u32(&mut code, out_base_va);
    code.extend_from_slice(&[0xC7, 0x03]); emit_u32(&mut code, 0x1234_5678);

    // NtWriteFile via SYSENTER (XP SP2 ABI).
    // Stack layout at SYSENTER: [EDX+0]=ret_addr  [EDX+4..]=args[0..8].
    // Push in reverse: Key → ... → FileHandle → then call/pop trick for ret_addr.
    code.extend_from_slice(&[0x6A, 0x00]);                    // push 0  (Key)
    code.extend_from_slice(&[0x6A, 0x00]);                    // push 0  (ByteOffset)
    emit_push_u32(&mut code, sysenter_msg.len() as u32);      // push Length
    emit_push_u32(&mut code, sysenter_msg_va);                // push Buffer
    emit_push_u32(&mut code, sysenter_iosb_va);               // push IoStatusBlock
    code.extend_from_slice(&[0x6A, 0x00]);                    // push 0  (ApcContext)
    code.extend_from_slice(&[0x6A, 0x00]);                    // push 0  (ApcRoutine)
    code.extend_from_slice(&[0x6A, 0x00]);                    // push 0  (Event)
    code.extend_from_slice(&[0x6A, 0xFF]);                    // push -1 (FileHandle = serial)
    // call/pop trick: push address of `pop eax`, add 16 → .after_sysenter.
    // delta = 1(pop)+5(add)+1(push)+2(mov edx,esp)+5(mov eax,imm)+2(sysenter) = 16
    code.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call .se_eip
    code.push(0x58);                                          // pop eax  (.se_eip)
    code.extend_from_slice(&[0x05, 16, 0, 0, 0]);            // add eax, 16
    code.push(0x50);                                          // push eax (ret addr)
    code.extend_from_slice(&[0x89, 0xE2]);                    // mov edx, esp
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]); // mov eax, NtWriteFile
    code.extend_from_slice(&[0x0F, 0x34]);                    // sysenter
    // .after_sysenter: ret@SharedUserData+0x300 popped ret_addr; 9 args remain.
    code.extend_from_slice(&[0x83, 0xC4, 0x24]);              // add esp, 36

    code.push(0xBA); emit_u32(&mut code, args_term_va);
    code.extend_from_slice(&[0xB8, 0xC2, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E, 0xEB, 0xFE]);
    let code_end = text_off + code.len();
    buf[text_off..code_end].copy_from_slice(&code);

    let args_write_off = data_off;
    let args_alloc_off = data_off + 0x20;
    let sysenter_iosb_off = data_off + 0xD0;
    let sysenter_msg_off  = data_off + 0xD8;
    let iat_iosb_off = data_off + 0x130;
    let iat_msg_off = data_off + 0x138;
    let args_iat_proof_off = data_off + 0x148;
    let iat_proof_msg_off = data_off + 0x160;
    let import_desc_off = data_off + 0x1A0;
    let import_int_off = data_off + 0x1C0;
    let import_iat_off = data_off + 0x1D0;
    let import_ibn_off = data_off + 0x1E0;
    let import_dll_off = data_off + 0x1F0;
    let args_create_proc_off = data_off + 0x80;
    let out_proc_handle_off = data_off + 0x90;
    let args_create_thread_off = data_off + 0xA0;
    let out_thread_handle_off = data_off + 0xB8;
    let out_client_id_off = data_off + 0xC0;
    let out_base_off = data_off + 0x40;
    let out_size_off = data_off + 0x44;
    let args_term_off = data_off + 0x48;
    let msg_off = data_off + 0x60;

    buf[args_write_off + 16..args_write_off + 20].copy_from_slice(&0u32.to_le_bytes());
    buf[args_write_off + 20..args_write_off + 24].copy_from_slice(&msg_va.to_le_bytes());
    buf[args_write_off + 24..args_write_off + 28].copy_from_slice(&(msg.len() as u32).to_le_bytes());
    buf[args_iat_proof_off + 16..args_iat_proof_off + 20].copy_from_slice(&0u32.to_le_bytes());
    buf[args_iat_proof_off + 20..args_iat_proof_off + 24].copy_from_slice(&iat_proof_msg_va.to_le_bytes());
    buf[args_iat_proof_off + 24..args_iat_proof_off + 28].copy_from_slice(&(iat_proof_msg.len() as u32).to_le_bytes());

    buf[opt_off + 104..opt_off + 108].copy_from_slice(&import_desc_rva.to_le_bytes());
    buf[opt_off + 108..opt_off + 112].copy_from_slice(&(40u32).to_le_bytes());
    buf[import_desc_off..import_desc_off + 4].copy_from_slice(&import_int_rva.to_le_bytes());
    buf[import_desc_off + 12..import_desc_off + 16].copy_from_slice(&import_dll_rva.to_le_bytes());
    buf[import_desc_off + 16..import_desc_off + 20].copy_from_slice(&import_iat_rva.to_le_bytes());
    buf[import_int_off..import_int_off + 4].copy_from_slice(&import_ibn_rva.to_le_bytes());
    buf[import_iat_off..import_iat_off + 4].copy_from_slice(&0x1000_1000u32.to_le_bytes());
    buf[import_ibn_off..import_ibn_off + 2].copy_from_slice(&0u16.to_le_bytes());
    buf[import_ibn_off + 2..import_ibn_off + 14].copy_from_slice(b"NtWriteFile\0");
    buf[import_dll_off..import_dll_off + 10].copy_from_slice(b"ntdll.dll\0");

    buf[args_alloc_off + 4..args_alloc_off + 8].copy_from_slice(&out_base_va.to_le_bytes());
    buf[args_alloc_off + 8..args_alloc_off + 12].copy_from_slice(&0u32.to_le_bytes());
    buf[args_alloc_off + 12..args_alloc_off + 16].copy_from_slice(&out_size_va.to_le_bytes());
    buf[args_alloc_off + 16..args_alloc_off + 20].copy_from_slice(&0x3000u32.to_le_bytes());
    buf[args_alloc_off + 20..args_alloc_off + 24].copy_from_slice(&0x4u32.to_le_bytes());

    buf[args_create_proc_off..args_create_proc_off + 4].copy_from_slice(&out_proc_handle_va.to_le_bytes());
    buf[out_proc_handle_off..out_proc_handle_off + 4].copy_from_slice(&0u32.to_le_bytes());

    buf[args_create_thread_off..args_create_thread_off + 4].copy_from_slice(&out_thread_handle_va.to_le_bytes());
    buf[args_create_thread_off + 12..args_create_thread_off + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf[args_create_thread_off + 16..args_create_thread_off + 20].copy_from_slice(&out_client_id_va.to_le_bytes());
    buf[out_thread_handle_off..out_thread_handle_off + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[out_client_id_off..out_client_id_off + 8].copy_from_slice(&0u64.to_le_bytes());
    buf[iat_iosb_off..iat_iosb_off + 8].copy_from_slice(&0u64.to_le_bytes());
    buf[iat_msg_off..iat_msg_off + iat_msg.len()].copy_from_slice(iat_msg);
    buf[iat_proof_msg_off..iat_proof_msg_off + iat_proof_msg.len()].copy_from_slice(iat_proof_msg);


    buf[out_base_off..out_base_off + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[out_size_off..out_size_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[args_term_off + 4..args_term_off + 8].copy_from_slice(&0u32.to_le_bytes());
    buf[msg_off..msg_off + msg.len()].copy_from_slice(msg);

    // SYSENTER data (iosb zeroed, msg copied)
    buf[sysenter_iosb_off..sysenter_iosb_off + 8].copy_from_slice(&0u64.to_le_bytes());
    buf[sysenter_msg_off..sysenter_msg_off + sysenter_msg.len()].copy_from_slice(sysenter_msg);

    buf
}

// ── Kernel shell ──────────────────────────────────────────────────────────────
//
// A minimal ring-0 interactive shell over serial.
// Commands: ls [path], cat <file>, run <file>, help.
//
// The shell runs as the boot thread (TID 0) after the initial user process
// exits.  Interrupts must stay enabled so the APIC timer can preempt child
// processes while the shell is waiting for them.

/// Write to both serial (COM1) and the framebuffer console.
fn shell_write(s: &str) {
    hal::serial::write_str(s);
    hal::fb::write_str(s);
}

fn kernel_shell(hhdm_offset: u64) {
    // Clear the framebuffer and enter text-console mode.
    let (w, h) = hal::fb::screen_dims();
    hal::fb::draw_rect(0, 0, w, h, 0x00_00_00_00);

    shell_write("\n  Mino NT Shell  --  type 'help'  (ESC = back to launcher)\n\n");
    let mut line_buf = [0u8; 128];
    loop {
        shell_write("$ ");
        let n = shell_read_line(&mut line_buf);
        // ESC pressed during read → return to launcher
        if n == 1 && line_buf[0] == 0x1B { return; }
        let cmd = core::str::from_utf8(&line_buf[..n]).unwrap_or("").trim();
        if cmd.is_empty() { continue; }

        if cmd == "help" {
            shell_write("  ls [path]   list directory\n");
            shell_write("  cat <file>  print file contents\n");
            shell_write("  run <file>  load and exec PE32 image\n");
            shell_write("  help        this message\n");
            shell_write("  ESC         back to launcher\n");
        } else if cmd == "ls" || cmd.starts_with("ls ") {
            let path = if cmd.len() > 3 { cmd[3..].trim() } else { "/" };
            shell_ls(path);
        } else if cmd.starts_with("cat ") {
            shell_cat(cmd[4..].trim());
        } else if cmd.starts_with("run ") {
            shell_run(cmd[4..].trim(), hhdm_offset);
        } else {
            shell_write("Unknown command. Type 'help'.\n");
        }
    }
}

/// Read one line from serial (echo back, handle backspace).
/// Returns byte count (without the newline).
fn shell_read_line(buf: &mut [u8]) -> usize {
    let max = buf.len().saturating_sub(1);
    let mut n = 0usize;
    loop {
        // HLT-based read so timer interrupts can run while we wait.
        // Poll both COM1 and PS/2 keyboard so the shell works via QEMU keyboard.
        let b = loop {
            if let Some(byte) = hal::serial::try_read_byte() { break byte; }
            // PS/2: read from IRQ1 ring buffer, convert scancode to ASCII.
            if let Some(sc) = hal::ps2::pop_scancode() {
                if let Some(ascii) = hal::ps2::scancode_to_ascii_pub(sc) {
                    break ascii;
                }
                continue; // key release or unmapped — try again
            }
            x86_64::instructions::hlt();
        };
        match b {
            0x1B => {
                // ESC — return immediately so caller can go back to launcher
                buf[0] = 0x1B;
                return 1;
            }
            b'\r' | b'\n' => {
                hal::serial::write_byte(b'\r');
                hal::serial::write_byte(b'\n');
                hal::fb::write_byte(b'\n');
                break;
            }
            0x08 | 0x7F => {
                if n > 0 {
                    n -= 1;
                    hal::serial::write_byte(0x08);
                    hal::serial::write_byte(b' ');
                    hal::serial::write_byte(0x08);
                    hal::fb::write_byte(0x08); // backspace on screen
                }
            }
            b if b >= 0x20 && n < max => {
                buf[n] = b;
                n += 1;
                hal::serial::write_byte(b);
                hal::fb::write_byte(b); // echo to screen
            }
            _ => {}
        }
    }
    n
}

/// `ls [path]` — list a FAT32 directory.
fn shell_ls(path: &str) {
    let norm = shell_norm_path(path);
    match io_manager::list_fat_dir(&norm) {
        Ok(entries) => {
            for e in &entries {
                if e.attr & 0x10 != 0 {
                    shell_write("[DIR] ");
                } else {
                    shell_write("      ");
                }
                shell_write(&e.name);
                if e.attr & 0x10 == 0 {
                    shell_write("  ");
                    serial_write_u32(e.file_size);
                    shell_write(" B");
                }
                shell_write("\n");
            }
            shell_write("  (");
            serial_write_u32(entries.len() as u32);
            shell_write(" entries)\n");
        }
        Err(e) => {
            hal::serial::write_fmt(core::format_args!("ls: {:?}\n", e));
            hal::fb::write_str("ls: error\n");
        }
    }
}

/// `cat <file>` — dump a FAT32 file to serial + framebuffer.
fn shell_cat(path: &str) {
    let norm = shell_norm_path(path);
    let mut file = match io_manager::open_fat_file(&norm) {
        Ok(f) => f,
        Err(e) => {
            hal::serial::write_fmt(core::format_args!("cat: {:?}\n", e));
            hal::fb::write_str("cat: not found\n");
            return;
        }
    };
    let size = file.file_size as usize;
    if size == 0 || size > 512 * 1024 {
        shell_write("cat: file empty or > 512 KiB\n");
        return;
    }
    let mut buf = alloc::vec![0u8; size];
    match io_manager::read_fat_file(&mut file, &mut buf) {
        Ok(n) => {
            for &b in &buf[..n] {
                hal::serial::write_byte(b);
                if b == b'\n' || b >= 0x20 { hal::fb::write_byte(b); }
            }
            shell_write("\n");
        }
        Err(e) => {
            hal::serial::write_fmt(core::format_args!("cat: {:?}\n", e));
            hal::fb::write_str("cat: read error\n");
        }
    }
}

/// `run <file>` — load a PE32 image and wait for it to exit.
fn shell_run(path: &str, hhdm_offset: u64) {
    let norm = shell_norm_path(path);
    shell_write("[shell] loading ");
    shell_write(&norm);
    shell_write("\n");

    x86_64::instructions::interrupts::disable();
    set_kernel_segments();
    let tid = shell_load_and_spawn(&norm, hhdm_offset);
    x86_64::instructions::interrupts::enable();

    match tid {
        Some(t) => {
            shell_write("[shell] running...\n");
            while ke::scheduler::is_thread_running(t) {
                x86_64::instructions::hlt();
            }
            shell_write("[shell] process exited\n");
        }
        None => {
            shell_write("[shell] failed to load image\n");
        }
    }
}

/// Load a PE32 from FAT32, set up PEB/TEB, spawn as a scheduler user thread.
/// Returns the scheduler TID, or None on any failure.
///
/// # IRQL: PASSIVE_LEVEL (interrupts disabled by caller for page-table safety)
fn shell_load_and_spawn(fat_path: &str, hhdm_offset: u64) -> Option<usize> {
    let mut file = io_manager::open_fat_file(fat_path).ok()?;
    let size = file.file_size as usize;
    if size < 64 || size > 512 * 1024 {
        log::warn!("shell_load_and_spawn: bad size {}", size);
        return None;
    }
    let mut bytes = alloc::vec![0u8; size];
    let n = io_manager::read_fat_file(&mut file, &mut bytes).ok()?;
    bytes.truncate(n);

    let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    let mut mapper = KernelPageMapper { pt };
    let mut vad = mm::vad::VadTree::new();
    let mut img = ps::loader::LoadedImage { image_base: 0, entry_point: 0, image_size: 0 };

    ps::loader::load_image(&bytes, &mut img, &mut vad, &mut mapper, None).ok()?;

    // Use a fresh PID for each spawned process (start at 8 to avoid colliding
    // with the initial smoke-test process which used PID=4).
    static SHELL_NEXT_PID: spin::Mutex<u32> = spin::Mutex::new(8);
    let pid = {
        let mut p = SHELL_NEXT_PID.lock();
        let out = *p;
        *p = p.wrapping_add(4);
        out
    };

    let ctx = ps::loader::setup_process(&img, &mut vad, &mut mapper, pid, 2).ok()?;

    // Re-install syscall context so NtAllocateVirtualMemory uses the new VAD.
    syscall::install(vad, hhdm_offset);

    hal::timer::set_shared_user_data_addr(Some(ps::loader::SHARED_USER_DATA32_VA as u64));

    ke::scheduler::spawn_user_thread(
        img.entry_point as u32,
        ctx.stack_top,
        hal::gdt::user_code32_selector(),
        hal::gdt::user_data32_selector(),
        hal::gdt::user_teb_fs_selector(),
    )
}

/// Normalise a shell path argument → FAT-style "/NAME.EXT" uppercase.
fn shell_norm_path(s: &str) -> alloc::string::String {
    let s = s.trim();
    if s.is_empty() || s == "/" {
        return alloc::string::String::from("/");
    }
    let mut out = alloc::string::String::new();
    if !s.starts_with('/') { out.push('/'); }
    for ch in s.chars() {
        if ch == '\\' { out.push('/'); }
        else { out.push(ch.to_ascii_uppercase()); }
    }
    out
}

/// Write a u32 to serial in decimal (no heap allocation).
fn serial_write_u32(mut n: u32) {
    if n == 0 { hal::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 10];
    let mut i = 10usize;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    // SAFETY: buf[i..] contains only ASCII digits.
    unsafe { hal::serial::write_str(core::str::from_utf8_unchecked(&buf[i..])) };
}

/// Panic handler — write message to serial and halt.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    hal::serial::write_str("\n\n*** KERNEL PANIC ***\n");
    // Print the panic message (e.g. "memory allocation of N bytes failed").
    hal::serial::write_fmt(core::format_args!("msg: {}\n", info.message()));
    if let Some(loc) = info.location() {
        hal::serial::write_str(loc.file());
        hal::serial::write_str(":");
        // Write line number without heap/alloc.
        let mut n = loc.line();
        if n == 0 {
            hal::serial::write_str("0");
        } else {
            let mut buf = [0u8; 10];
            let mut i = 10usize;
            while n > 0 {
                i -= 1;
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            // SAFETY: buf[i..] contains only ASCII digits.
            hal::serial::write_str(unsafe { core::str::from_utf8_unchecked(&buf[i..]) });
        }
        hal::serial::write_str("\n");
    }
    hal::serial::write_str("System halted.\n");
    loop {
        x86_64::instructions::hlt();
    }
}
