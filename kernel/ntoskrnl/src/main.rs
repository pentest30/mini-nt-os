//! Kernel entry point — called by the bootloader after ExitBootServices().
//!
//! Initialisation order (mirrors NT startup sequence):
//!   1. HAL        — GDT, IDT, serial, IRQL, APIC timer (enables interrupts)
//!   2. Mm         — PFN database from the BootInfo memory map (`mm::pfn`)
//!   3. Pools      — nonpaged and paged pools (`mm::pool`), which grow on
//!      demand; the nonpaged pool is Rust's global allocator
//!   4. Executive  — Ke, Ob, Ps, Io stubs (Phase 2)

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
mod launcher;
mod shared_data;
mod sys;
mod syscall;
mod userland;

use abi::BootInfo;
use core::arch::asm;
use x86_64::{
    instructions::segmentation::{Segment, DS, ES, SS},
    structures::gdt::SegmentSelector,
    structures::paging::PageTableFlags,
    PhysAddr, VirtAddr,
};

/// Kernel heap — the nonpaged pool (`mm::pool`): size classes for small
/// blocks, merged page runs for large ones, growing on demand and giving
/// pages back. `heap_self_test` and `pool_self_test` check it at every boot.
#[global_allocator]
static ALLOCATOR: mm::pool::GlobalPool = mm::pool::GlobalPool;

/// The pool behind the global allocator.
const HEAP: &mm::pool::Pool<mm::pool::KernelBacking> = &mm::pool::NONPAGED_POOL;

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
        virt_addr: u64,
        writable: bool,
        executable: bool,
        user: bool,
    ) -> Result<(), abi::ntstatus::NtStatus> {
        // Idempotent: skip if the VA is already mapped as a USER_ACCESSIBLE 4 KiB page.
        // DO NOT zero — the page may contain live data (e.g., game stack being reused).
        // Fresh pages are zeroed below instead.
        if let Some((_p, f)) = self.pt.translate_flags(VirtAddr::new(virt_addr)) {
            use x86_64::structures::paging::PageTableFlags as F;
            if f.contains(F::USER_ACCESSIBLE) && !f.contains(F::HUGE_PAGE) {
                return Ok(());
            }
        }

        let pfn = mm::pfn::allocate_page(mm::pfn::PageUsage::UserPrivate).ok_or(abi::ntstatus::STATUS_NO_MEMORY)?;

        let phys = PhysAddr::new(pfn.to_phys());
        let virt = VirtAddr::new(virt_addr);

        let mut flags = PageTableFlags::PRESENT;
        if writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !executable {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        if user {
            flags |= PageTableFlags::USER_ACCESSIBLE;
        }

        // SAFETY: virt is a freshly claimed user-mode address; phys is a
        //         fresh page-aligned frame.
        unsafe { self.pt.map_page(virt, phys, flags) };

        // Zero the page — Windows guarantees MEM_COMMIT pages are zeroed.
        // Without this, .bss sections contain stale data from recycled frames.
        // SAFETY: the page was just mapped at `virt`; writing 4096 zeros is valid.
        unsafe {
            core::ptr::write_bytes(virt_addr as *mut u8, 0, 4096);
        }
        Ok(())
    }

    fn decommit_page(&mut self, virt_addr: u64) {
        let virt = VirtAddr::new(virt_addr);
        // SAFETY: virt_addr was previously mapped by commit_page; single-CPU
        //         Phase 2 — no concurrent unmap possible.
        let frame = unsafe { self.pt.unmap_page(virt) }; // also flushes TLB
        mm::pfn::free_page(mm::Pfn(frame.start_address().as_u64() / 4096));
    }

    fn protect_page(&mut self, virt_addr: u64, protect: mm::vad::PageProtect) {
        let flags = mm::MmPageTables::leaf_flags(protect.writable(), protect.executable(), true);
        // SAFETY: virt_addr was previously mapped by commit_page; the VAD has
        //         just given the page these rights.
        unsafe { self.pt.update_flags(VirtAddr::new(virt_addr), flags) };
    }
}

/// Kernel entry point.
///
/// # Safety
/// - Called exactly once by the bootloader.
/// - CPU is in 64-bit long mode, interrupts disabled on entry.
/// - `boot_info_ptr` points to a valid, static `BootInfo` in the HHDM, and
///   the stack is in the HHDM too.
/// - The bootloader's identity map [0, 4 GiB) and HHDM are active; the
///   identity map is removed at the start of phase 1.
///
/// # IRQL: HIGH on entry; drops to PASSIVE after `hal::init()`.
///
/// Placed in `.text.entry`, first in the text segment. The bootloader jumps
/// here through the ELF entry point, at the kernel's link address.
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
    // SAFETY: boot_info_ptr provided by the bootloader, in the HHDM.
    let boot_info: &'static BootInfo = unsafe {
        assert!(!boot_info_ptr.is_null(), "null BootInfo pointer");
        let bi = &*boot_info_ptr;
        assert!(bi.is_valid(), "invalid BootInfo magic: {:#x}", bi.magic);
        bi
    };

    // Store HHDM offset for the page-fault handler's page-table walk and for
    // APIC MMIO, which stops using the identity map from here on.
    hal::set_hhdm_offset(boot_info.hhdm_offset);

    // ── 1.5. Framebuffer console ─────────────────────────────────────────────
    // Init before the first log::info! so kernel messages appear on screen.
    // The GOP framebuffer (always below 4 GiB on QEMU/VBox) is reachable at
    // hhdm_offset + framebuffer.base.
    hal::fb::init(&boot_info.framebuffer, boot_info.hhdm_offset);
    hal::fb::write_str("[fb] boot banner enabled\n");

    log::info!("micro-nt-os kernel_main — Phase 1");
    log::info!(
        "BootInfo: kernel={:#x}+{}B  HHDM={:#x}  regions={}",
        boot_info.kernel_phys_base,
        boot_info.kernel_size,
        boot_info.hhdm_offset,
        boot_info.memory_map_len,
    );
    // Before anything that can stop the system, so the STOP screen names the
    // functions on the stack.
    register_symbols(boot_info);

    // ── 2. Mm: feed buddy allocator from BootInfo memory map ─────────────────
    // Pass the true kernel physical end (including BSS) so the buddy never
    // hands out BSS frames as page-table pages, which would alias statics.
    // The bootloader laid the whole ELF image, BSS included, out in one block.
    let kernel_end_phys = boot_info.kernel_phys_base + boot_info.kernel_size;
    mm::init(boot_info, kernel_end_phys);
    check_kernel_wx(boot_info.hhdm_offset);

    // ── 3. Pools: their address ranges, and a first chunk mapped ─────────────
    // SAFETY: once, right after mm::init, before the first allocation.
    unsafe { mm::pool::init() };
    log::info!(
        "pools: nonpaged at {:#x} ({} KiB mapped), paged at {:#x} ({} KiB mapped), growing on demand",
        mm::pool::NONPAGED_POOL_START,
        mm::pool::NONPAGED_POOL.capacity() / 1024,
        mm::pool::PAGED_POOL_START,
        mm::pool::PAGED_POOL.capacity() / 1024,
    );

    // Smoke-test: Box allocation forces a real heap use.
    {
        let _probe = alloc::boxed::Box::new(0xDEAD_BEEF_u64);
        log::info!("heap: Box allocation probe OK");
    }

    // ── 3b. Guarded kernel stacks (M0, 02 §4.2) ──────────────────────────────
    // From here on every kernel stack comes from mm::kstack, with an unmapped
    // guard page below it: an overflow faults, and the #DF/#PF handlers print
    // a STOP screen naming it instead of corrupting memory or triple-faulting.
    hal::idt::set_stack_guard_hook(Some(kstack_guard_hit));
    // Faults on user addresses go to Mm first: demand-zero and guard pages of
    // the address spaces (mm::fault).
    hal::idt::set_page_fault_hook(Some(mm::fault::page_fault_hook));

    // Ring-3 → ring-0 entry: RSP0 until a user thread installs its own, and
    // SYSENTER_ESP (shared by all threads until the trap rework of M3).
    let entry_stack = mm::kstack::allocate().expect("no kernel stack for syscall entry");
    // SAFETY: entry_stack is reserved for ring-3 entry for the life of the system.
    unsafe {
        hal::gdt::set_kernel_stack_top(entry_stack.top);
        hal::sysenter::set_entry_stack(entry_stack.top);
    }

    // The boot thread leaves the bootloader's unguarded stack for good.
    let boot_stack = mm::kstack::allocate().expect("no kernel stack for the boot thread");
    log::info!(
        "kstack: boot thread on guarded stack {:#x}..{:#x}, syscall entry {:#x}..{:#x}",
        boot_stack.bottom,
        boot_stack.top,
        entry_stack.bottom,
        entry_stack.top,
    );
    // SAFETY: boot_stack is a fresh 16-byte aligned stack owned by the boot
    // thread for the life of the system. kernel_main_phase1 never returns, so
    // nothing on the bootloader stack is used again.
    unsafe {
        asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "call {phase1}",
            "ud2",
            top = in(reg) boot_stack.top,
            phase1 = sym kernel_main_phase1,
            in("rdi") boot_info_ptr,
            options(noreturn),
        );
    }
}

/// Rest of the boot sequence, on the boot thread's guarded kernel stack.
///
/// # IRQL
/// PASSIVE_LEVEL.
extern "C" fn kernel_main_phase1(boot_info_ptr: *const BootInfo) -> ! {
    // SAFETY: kernel_main validated this pointer before switching stacks.
    let boot_info: &'static BootInfo = unsafe { &*boot_info_ptr };

    remove_identity_map(boot_info.hhdm_offset);

    if cfg!(feature = "test-stack-overflow") {
        provoke_stack_overflow();
    }

    heap_self_test();
    pfn_self_test();
    pool_self_test();
    symbols_self_test();

    // ── 4. Executive initialisation ───────────────────────────────────────────
    x86_64::instructions::interrupts::disable();
    set_kernel_segments();
    let idle_stack = mm::kstack::allocate().expect("no kernel stack for the idle thread");
    // SAFETY: idle_stack is reserved for the idle thread for the life of the system.
    unsafe { ke::init(idle_stack.top) };
    ob::init();
    for ty in [
        &mm::section::SECTION_TYPE,
        &ps::eprocess::PROCESS_TYPE,
        &ps::ethread::THREAD_TYPE,
        &io_manager::FILE_TYPE,
        &io_manager::DEVICE_TYPE,
        &cm::KEY_TYPE,
    ] {
        ob::namespace().register_type(ty).expect("an object type registered twice");
    }
    cm::init();
    ps::init();
    io_manager::init(boot_info.ramdisk_phys_base, boot_info.ramdisk_size, boot_info.hhdm_offset);
    mount_boot_volume();
    fat_smoke_probe();

    // Wire preemptive round-robin: each clock tick ends the quantum, and the
    // DISPATCH interrupt (timer ISR below DISPATCH_LEVEL, or IRQL drop) drains
    // the DPC queue, then runs schedule(); the APC interrupt delivers the
    // current thread's kernel APCs. Registered after ke::init() (scheduler
    // table ready) and before interrupts re-enable.
    hal::irql::set_dispatch_hook(Some(ke::dpc::ki_dispatch_interrupt));
    hal::irql::set_apc_hook(Some(ke::apc::ki_apc_interrupt));
    hal::timer::set_clock_hook(Some(ke::clock::ki_clock_interrupt));
    sys::gates::install();
    sys::exceptions::install();
    sys::apc::install();
    shared_data::init();
    hal::idt::set_user_fault_hook(Some(user_fault));

    x86_64::instructions::interrupts::enable();
    // Raises starved threads every second (ke::sched).
    spawn_kernel_thread(
        ke::balance::BALANCE_SET_MANAGER_PRIORITY,
        ke::balance::ke_balance_set_manager,
        core::ptr::null_mut(),
    );
    tpr_self_test();
    deferred_preemption_self_test();
    dpc_self_test();
    ke_self_test();
    boost_self_test();
    apc_self_test();
    address_space_self_test();
    vad_self_test();
    demand_paging_self_test();
    kernel_stack_self_test();
    out_of_page_tables_self_test();
    section_self_test();
    object_manager_self_test();
    process_self_test();
    system_service_self_test();
    early_exit_self_test();
    loader_services_self_test();
    registry_self_test();
    object_directory_self_test();
    trap_gate_self_test();
    exception_self_test();
    user_apc_self_test();
    system_dll_self_test();
    fatal_entry_self_test();
    fpu_self_test();
    if cfg!(feature = "test-ke-events") {
        event_ping_pong_test(ke::sched::NORMAL_PRIORITY, "equal priorities");
        event_ping_pong_test(ke::sched::NORMAL_PRIORITY + 1, "pinger above ponger");
    }
    if cfg!(feature = "test-fpu") {
        fpu_parallel_test();
    }
    if cfg!(feature = "test-ke-starvation") {
        starvation_test();
    }
    if cfg!(feature = "test-bugcheck") {
        bugcheck_test_outer();
    }
    if cfg!(feature = "test-page-fault-irql") {
        page_fault_irql_test();
    }
    if cfg!(feature = "test-page-fault-access-violation") {
        page_fault_access_violation_test();
    }

    // ReactOS's ntdll, if the boot disk has it: the system DLL from now on,
    // and a native program under it (spike S1).
    userland::install_system_dll();
    userland::install_nls_tables();
    userland::mount_system_hive();
    userland::run_native_probe();
    userland::run_boot_programs();
    if cfg!(feature = "test-smss") {
        userland::run_smss_probe();
    }

    // ── 5a. Phase 3: auto-run HELLO.EXE from FAT if present ──────────────────
    // Silently skipped if HELLO.EXE is not on the ramdisk.
    // Emits "[smoke] HELLO.EXE ran ok" on success (not required by tests/boot/).
    try_run_hello_exe(boot_info.hhdm_offset);

    // ── 5a2. Phase 3: DXVK DLL chain load test ────────────────────────────────
    // Attempts to load D3D8.DLL from the FAT ramdisk (triggers d3d9.dll dep).
    // Both resolve imports against vulkan-1.dll / kernel32.dll stub modules.
    try_load_dxvk_chain();

    // ── 5b. Phase 2: PE loader smoke test + process setup ─────────────────────
    log::info!("heap before loader_demo: used={} free={}", HEAP.used(), HEAP.free(),);
    let ring3_ctx = loader_demo(boot_info.hhdm_offset);

    // ── Ready ─────────────────────────────────────────────────────────────────
    // Every page allocated and freed so far, by the loader and the ring-3
    // programs too, went through the PFN database.
    if let Err(why) = mm::pfn::check() {
        panic!("PFN database out of step with the free lists: {why}");
    }
    let pages = mm::pfn::stats();
    log::info!("[smoke] Mm: PFN database consistent at the end of phase 1: {pages}");

    // End of phase 1: the boot scenarios (tests/boot/) wait for this line.
    log::info!("kernel: phase 1 done — ticks: {}, free_pages: {}", hal::timer::get_tick_count(), pages.free);
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
    // NtTerminateProcess → ke::sched::terminate_current_thread().
    let (entry_point, stack_top) = ring3_ctx;

    log::info!("kernel_main: spawning user thread  entry={:#010x}  usp={:#010x}", entry_point, stack_top,);

    let user_tid = spawn_user_thread(entry_point, stack_top)
        .expect("kernel_main: scheduler full — cannot spawn initial user thread");

    log::info!("kernel_main: user thread TID={} spawned — launching Mino UI", user_tid);

    // Show the game launcher immediately. CMD.EXE (user thread) continues
    // running in the background; its framebuffer output is suppressed by
    // EXCLUSIVE=true inside launcher::run(). When the user presses D we
    // drop to the kernel debug shell.
    loop {
        launcher::run();
        // Kill all user-mode threads (CMD.EXE etc.) so the kernel shell has
        // exclusive console input — no thread races for serial/PS2 keystrokes.
        ke::sched::terminate_user_threads();
        // kernel_shell returns when ESC is pressed → back to launcher.
        kernel_shell(boot_info.hhdm_offset);
    }
}

/// A user-mode floating-point trap (`hal::idt`, interrupts masked): until it
/// becomes an exception (`sys::exceptions`), the process of a Ps thread ends
/// with the code, as an unhandled exception would end it; a thread of the
/// legacy loader just ends.
///
/// # IRQL
/// PASSIVE_LEVEL, from user mode.
fn user_fault(exception: abi::ntstatus::NtStatus) {
    // Ps runs the process down with interrupts enabled, as from a system call.
    x86_64::instructions::interrupts::enable();
    ps::terminate_current_process(exception);
}

/// Spawns a ring-3 thread on a fresh guarded kernel stack (`mm::kstack`).
///
/// # IRQL
/// PASSIVE_LEVEL.
pub(crate) fn spawn_user_thread(entry32: u32, stack32: u32) -> Option<usize> {
    let kstack = mm::kstack::allocate()?;
    let start = ke::sched::UserThreadStart {
        directory_table_base: mm::address_space::system_directory_table_base(),
        kernel_stack_top: kstack.top,
        entry: entry32,
        stack: stack32,
        teb: ps::loader::TEB32_VA,
        owner: core::ptr::null(),
        tid: core::ptr::null(),
    };
    // SAFETY: kstack was just allocated for this thread alone and is never
    // freed; the system address space lives forever.
    unsafe { ke::sched::create_user_thread(&start) }
}

/// Churns the pool with the pattern blamed for the old heap "corruption"
/// (B-tree nodes mixed with ~12 KiB blocks, audit §4.2), checking every value
/// and every block, then checks that freeing gave all the memory back.
/// Prints `[smoke] heap self-test ok`, which the smoke test requires.
///
/// # IRQL
/// PASSIVE_LEVEL, before any other thread exists (exact `used()` accounting).
fn heap_self_test() {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    const ROUNDS: u32 = 2000;
    let used_before = HEAP.used();
    let mut peak = used_before;
    {
        let mut map: BTreeMap<u32, u64> = BTreeMap::new();
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for round in 0..ROUNDS {
            map.insert(round, u64::from(round) * 3);
            if round % 4 == 3 {
                map.remove(&(round - 2));
            }
            if round % 50 == 0 {
                blocks.push(alloc::vec![round as u8; 12 * 1024]);
                if blocks.len() > 8 {
                    let old = blocks.remove(0);
                    assert!(old.iter().all(|&b| b == old[0]), "heap self-test: 12 KiB block overwritten");
                }
            }
            peak = peak.max(HEAP.used());
        }
        for (key, value) in &map {
            assert_eq!(*value, u64::from(*key) * 3, "heap self-test: BTreeMap value overwritten");
        }
        for block in &blocks {
            assert!(block.iter().all(|&b| b == block[0]), "heap self-test: 12 KiB block overwritten");
        }
    }
    assert_eq!(HEAP.used(), used_before, "heap self-test: memory not given back");
    log::info!(
        "[smoke] heap self-test ok: {} rounds, peak {} KiB, back to {} bytes used",
        ROUNDS,
        (peak - used_before) / 1024,
        used_before,
    );
}

/// Checks that the kernel image is W^X as the bootloader mapped it (ADR-014):
/// every page of .text is RX, of .rodata R, of .data/.bss RW + NX, and the CPU
/// enforces it (CR0.WP, EFER.NXE). Prints `[smoke] kernel W^X ok`, which the
/// smoke test requires.
///
/// # IRQL
/// PASSIVE_LEVEL.
fn check_kernel_wx(hhdm_offset: u64) {
    use x86_64::registers::control::{Cr0, Cr0Flags};
    use x86_64::registers::model_specific::{Efer, EferFlags};
    use x86_64::structures::paging::PageTableFlags as F;

    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
        static __rodata_start: u8;
        static __rodata_end: u8;
        static __data_start: u8;
        static __data_end: u8;
    }

    assert!(Cr0::read().contains(Cr0Flags::WRITE_PROTECT), "W^X: CR0.WP is off");
    assert!(Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE), "W^X: EFER.NXE is off");

    // SAFETY: hhdm_offset is the bootloader's HHDM; CR3 holds the kernel tables.
    let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    let check = |name: &str, start: *const u8, end: *const u8, writable: bool, executable: bool| {
        let (start, end) = (start as u64, end as u64);
        for va in (start..end).step_by(4096) {
            let (_, flags) = pt
                .translate_flags(VirtAddr::new(va))
                .unwrap_or_else(|| panic!("W^X: {} page {:#x} is not mapped", name, va));
            assert_eq!(flags.contains(F::WRITABLE), writable, "W^X: {} page {:#x} writable", name, va);
            assert_eq!(!flags.contains(F::NO_EXECUTE), executable, "W^X: {} page {:#x} executable", name, va);
        }
        (end - start) / 4096
    };
    // Only the addresses of the linker symbols are taken, never their contents.
    let text = check(".text", core::ptr::addr_of!(__text_start), core::ptr::addr_of!(__text_end), false, true);
    let rodata = check(".rodata", core::ptr::addr_of!(__rodata_start), core::ptr::addr_of!(__rodata_end), false, false);
    let data = check(".data/.bss", core::ptr::addr_of!(__data_start), core::ptr::addr_of!(__data_end), true, false);
    log::info!(
        "[smoke] kernel W^X ok: .text {} pages RX, .rodata {} pages R, .data/.bss {} pages RW+NX at {:#x}",
        text,
        rodata,
        data,
        kernel_main as *const () as u64,
    );
}

/// Ends the bootloader's identity map (ADR-014, 02 §4.1) and checks that the
/// user half is empty while the HHDM still reaches the same memory.
///
/// # IRQL
/// PASSIVE_LEVEL. Called once, at the start of phase 1.
fn remove_identity_map(hhdm_offset: u64) {
    // SAFETY: from phase 1 on, the kernel runs on its image, a guarded kernel
    // stack and HHDM addresses only (BootInfo, frames, APIC); no process has
    // been created, so PML4[0] holds nothing but the identity map.
    let mut pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    // SAFETY: as above.
    unsafe { pt.remove_identity_map() };

    const APIC_PHYS: u64 = 0xFEE0_0000;
    for va in [0x1000, 0x10_0000, APIC_PHYS] {
        assert!(pt.translate(VirtAddr::new(va)).is_none(), "identity map still maps {:#x}", va);
    }
    assert_eq!(
        pt.translate(VirtAddr::new(hhdm_offset + APIC_PHYS)),
        Some(PhysAddr::new(APIC_PHYS)),
        "HHDM no longer maps the APIC",
    );
    log::info!("[smoke] identity map removed: user half empty, APIC at {:#x}", hhdm_offset + APIC_PHYS);
}

/// Checks the DPC queue (M1, `ke::dpc`): a DPC queued below DISPATCH_LEVEL runs
/// at once, at DISPATCH_LEVEL with interrupts enabled; one queued under a
/// KSpinLock runs on release, once however often it was queued; one removed
/// before that never runs.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled, DISPATCH interrupt hook registered.
fn dpc_self_test() {
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use ke::dpc::{ke_insert_queue_dpc, ke_remove_queue_dpc, KDpc};

    static RUNS: AtomicUsize = AtomicUsize::new(0);
    static WRONG_CONTEXT: AtomicBool = AtomicBool::new(false);
    fn count(_: *const KDpc, _: *mut c_void, arg1: *mut c_void, _: *mut c_void) {
        let at_dispatch = hal::irql::current() == hal::irql::Irql::Dispatch;
        if !at_dispatch || !x86_64::instructions::interrupts::are_enabled() {
            WRONG_CONTEXT.store(true, Ordering::Relaxed);
        }
        RUNS.fetch_add(arg1 as usize, Ordering::Relaxed);
    }
    static DPC: KDpc = KDpc::new(count, core::ptr::null_mut());
    static LOCK: hal::sync::KSpinLock<()> = hal::sync::KSpinLock::new(());
    let one = core::ptr::without_provenance_mut::<c_void>(1);
    let null = core::ptr::null_mut();

    // SAFETY: `DPC` is a static: valid, at a fixed address.
    unsafe {
        assert!(ke_insert_queue_dpc(&DPC, one, null));
        assert_eq!(RUNS.load(Ordering::Relaxed), 1, "DPC queued at PASSIVE_LEVEL did not run at once");
        {
            let _guard = LOCK.lock();
            assert!(ke_insert_queue_dpc(&DPC, one, null));
            assert!(!ke_insert_queue_dpc(&DPC, one, null), "DPC queued twice");
            assert_eq!(RUNS.load(Ordering::Relaxed), 1, "DPC ran at DISPATCH_LEVEL");
        }
        assert_eq!(RUNS.load(Ordering::Relaxed), 2, "pending DPC not run on IRQL drop");
        {
            let _guard = LOCK.lock();
            assert!(ke_insert_queue_dpc(&DPC, one, null));
            assert!(ke_remove_queue_dpc(&DPC));
        }
    }
    assert_eq!(RUNS.load(Ordering::Relaxed), 2, "removed DPC ran");
    assert!(!WRONG_CONTEXT.load(Ordering::Relaxed), "DPC routine not at DISPATCH_LEVEL with interrupts enabled");
    log::info!("[smoke] DPC: run at once, deferred under a KSpinLock, removable");
}

/// Checks that the IRQL is the APIC task priority (M1, `hal::irql`): with
/// interrupts enabled, the clock (CLOCK_LEVEL) keeps ticking at
/// DISPATCH_LEVEL, is masked by the APIC alone at HIGH_LEVEL, and is
/// delivered as soon as the IRQL drops.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled, timer running.
/// Registers the kernel's ELF symbol table, which the bootloader copied below
/// 4 GiB (`BootInfo::symbols`), so inside the HHDM.
///
/// # IRQL
/// HIGH_LEVEL, once, during phase 0.
fn register_symbols(boot_info: &BootInfo) {
    let symbols = boot_info.symbols;
    if !symbols.is_present() {
        log::warn!("no kernel symbol table: the STOP screen will show bare addresses");
        return;
    }
    let end = symbols.phys.checked_add(symbols.symtab_size).and_then(|e| e.checked_add(symbols.strtab_size));
    assert!(end.is_some_and(|end| end <= hal::HHDM_SIZE), "kernel symbol table outside the HHDM");
    let base = (boot_info.hhdm_offset + symbols.phys) as *const u8;
    // SAFETY: the bootloader copied both tables to [phys, end), a LOADER_DATA
    // block that the buddy never receives (`BootloaderReclaimable`) and the
    // HHDM maps (checked above); nothing writes to it after the handoff.
    let (symtab, strtab) = unsafe {
        (
            core::slice::from_raw_parts(base, symbols.symtab_size as usize),
            core::slice::from_raw_parts(base.add(symbols.symtab_size as usize), symbols.strtab_size as usize),
        )
    };
    let table = hal::symbols::SymbolTable::new(symtab, strtab);
    hal::symbols::init(table);
    log::info!("kernel symbols: {} functions", table.function_count());
}

/// Checks the PFN database (M2, `mm::pfn`): it agrees with the free lists
/// after the boot's allocations (heap, page tables, kernel stacks), and a
/// block allocated then freed leaves every count as it was.
///
/// # IRQL
/// PASSIVE_LEVEL.
fn pfn_self_test() {
    use mm::pfn::{self, PageState, PageUsage};

    if let Err(why) = pfn::check() {
        panic!("PFN database out of step with the free lists: {why}");
    }
    let before = pfn::stats();
    assert!(before.active(PageUsage::PageTable) > 0 && before.active(PageUsage::KernelStack) > 0);
    let block = pfn::allocate_pages(2, PageUsage::Buffer).expect("no 4 free pages");
    let during = pfn::stats();
    assert_eq!(
        (during.free, during.active(PageUsage::Buffer)),
        (before.free - 4, before.active(PageUsage::Buffer) + 4)
    );
    let state = pfn::PAGE_FRAMES.lock().entry(block).map(|e| e.state);
    assert_eq!(state, Some(PageState::Active));
    pfn::free_pages(block, 2);
    assert_eq!(pfn::stats(), before, "a block allocated then freed changed the counts");
    log::info!("[smoke] Mm: PFN round trip ok, {before}");
}

/// Checks the kernel pools (M2, `mm::pool`): the nonpaged pool grows past what
/// it has mapped, and gives the pages back to the PFN database once the
/// blocks are freed; tagged blocks of both pools are counted until freed; the
/// PFN database's pool pages follow exactly what the nonpaged pool maps.
///
/// # IRQL
/// PASSIVE_LEVEL.
fn pool_self_test() {
    use mm::pfn::{self, PageUsage};
    use mm::pool::{self, PoolType, TagStats, NONPAGED_POOL, PAGED_POOL};

    const TAG: pool::PoolTag = pool::tag(b"Test");
    const BLOCK: usize = 256 * 1024;
    const BLOCKS: usize = 8;
    const PAGED: usize = 64 * 1024;
    let pool_pages = |pool: &pool::Pool<pool::KernelBacking>| pool.capacity() as u64 / 4096;
    let (mapped_before, pages_before) = (pool_pages(&NONPAGED_POOL), pfn::stats().active(PageUsage::NonPagedPool));
    assert_eq!(pages_before, mapped_before, "nonpaged pool pages outside the pool");

    let mut blocks = [core::ptr::null_mut(); BLOCKS];
    for block in &mut blocks {
        *block = pool::ex_allocate_pool_with_tag(PoolType::NonPaged, BLOCK, TAG);
        assert!(!block.is_null(), "nonpaged pool exhausted");
        // SAFETY: a live block of BLOCK bytes.
        unsafe { core::ptr::write_bytes(*block, 0x5A, BLOCK) };
    }
    let paged = pool::ex_allocate_pool_with_tag(PoolType::Paged, PAGED, TAG);
    assert!(!paged.is_null(), "paged pool exhausted");
    let peak = pool_pages(&NONPAGED_POOL);
    assert!(peak >= mapped_before + (BLOCKS * BLOCK / 4096 / 2) as u64, "the nonpaged pool did not grow");
    assert_eq!(pfn::stats().active(PageUsage::NonPagedPool), peak, "the PFN database does not follow the pool");
    assert_eq!(NONPAGED_POOL.tag_stats(TAG), TagStats { allocations: BLOCKS, bytes: BLOCKS * BLOCK });
    assert_eq!(PAGED_POOL.tag_stats(TAG), TagStats { allocations: 1, bytes: PAGED });

    for block in blocks {
        // SAFETY: a live block of the nonpaged pool, with its tag.
        unsafe { pool::ex_free_pool_with_tag(PoolType::NonPaged, block, TAG) };
    }
    // SAFETY: a live block of the paged pool, with its tag.
    unsafe { pool::ex_free_pool_with_tag(PoolType::Paged, paged, TAG) };
    assert_eq!(NONPAGED_POOL.tag_stats(TAG), TagStats::default());
    assert_eq!(PAGED_POOL.tag_stats(TAG), TagStats::default());
    let after = pool_pages(&NONPAGED_POOL);
    assert!(
        after <= mapped_before + pool::GROW_PAGES as u64,
        "the nonpaged pool kept {after} pages, {mapped_before} before"
    );
    assert_eq!(pfn::stats().active(PageUsage::NonPagedPool), after);
    log::info!(
        "[smoke] Mm: pools grow ({} KiB mapped at the peak) and give pages back ({} KiB after), tags counted",
        peak * 4,
        after * 4
    );
}

/// Finds this very function, and a code address inside it, through the
/// registered symbol table.
fn symbols_self_test() {
    let here = symbols_self_test as fn() as usize as u64;
    fn demangled(addr: u64, buf: &mut [u8]) -> Option<(&str, u64)> {
        let (name, offset) = hal::symbols::lookup(addr)?;
        let mut out = hal::symbols::FixedBuf::new(buf);
        hal::symbols::write_demangled(name, &mut out).ok()?;
        Some((out.into_str(), offset))
    }
    let (mut a, mut b) = ([0u8; 128], [0u8; 128]);
    assert_eq!(demangled(here, &mut a), Some(("ntoskrnl::symbols_self_test", 0)), "kernel symbol lookup");
    assert_eq!(demangled(here + 1, &mut b), Some(("ntoskrnl::symbols_self_test", 1)));
    assert_eq!(hal::symbols::lookup(0x1000), None, "a user address has no kernel symbol");
    log::info!("[smoke] symbols: kernel functions found by address");
}

fn tpr_self_test() {
    use hal::irql::{Irql, IrqlGuard};

    const PERIODS: u32 = 3;
    assert!(x86_64::instructions::interrupts::are_enabled());
    {
        let _dispatch = IrqlGuard::raise(Irql::Dispatch);
        let start = hal::timer::interrupt_time();
        hal::timer::spin_periods(PERIODS);
        assert!(hal::timer::interrupt_time() > start, "no clock interrupt at DISPATCH_LEVEL");
    }
    let masked_at;
    {
        let _high = IrqlGuard::raise(Irql::High);
        masked_at = hal::timer::interrupt_time();
        hal::timer::spin_periods(PERIODS);
        assert_eq!(hal::timer::interrupt_time(), masked_at, "clock interrupt delivered at HIGH_LEVEL");
    }
    assert!(hal::timer::interrupt_time() > masked_at, "pending clock interrupt not delivered on IRQL drop");
    log::info!("[smoke] TPR: clock ticks at DISPATCH_LEVEL, masked at HIGH_LEVEL, delivered on drop");
}

/// Starts a kernel thread on a fresh guarded kernel stack (`mm::kstack`);
/// returns its TID.
///
/// # IRQL
/// PASSIVE_LEVEL.
fn spawn_kernel_thread(priority: u8, routine: ke::sched::ThreadRoutine, context: *mut core::ffi::c_void) -> usize {
    // SAFETY: the system address space lives for good.
    unsafe { spawn_kernel_thread_in(mm::address_space::system_directory_table_base(), priority, routine, context) }
}

/// Like [`spawn_kernel_thread`], in the address space of directory table base
/// `directory_table_base`.
///
/// # Safety
/// The address space stays live while the thread runs.
///
/// # IRQL
/// PASSIVE_LEVEL.
unsafe fn spawn_kernel_thread_in(
    directory_table_base: u64,
    priority: u8,
    routine: ke::sched::ThreadRoutine,
    context: *mut core::ffi::c_void,
) -> usize {
    let stack = mm::kstack::allocate().expect("no kernel stack for a kernel thread");
    // SAFETY: the stack was just allocated for this thread alone and is never
    // freed; callers keep `context` valid for the thread's life, and the
    // address space live (contract).
    unsafe { ke::sched::create_kernel_thread_in(directory_table_base, stack.top, priority, routine, context) }
        .expect("thread table full")
}

/// Checks that DISPATCH_LEVEL defers preemption (M1, `hal::irql`): with a
/// kernel thread of the same priority ready, the boot thread holds a KSpinLock
/// for more than a quantum without being switched out, then the switch asked
/// for by the quantum end runs on release.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled, scheduler and dispatch hook ready.
fn deferred_preemption_self_test() {
    use core::sync::atomic::{AtomicBool, Ordering};

    const TICKS: u64 = 5;
    static LOCK: hal::sync::KSpinLock<()> = hal::sync::KSpinLock::new(());
    static RELEASED: AtomicBool = AtomicBool::new(false);
    fn peer(_: *mut core::ffi::c_void) {
        while !RELEASED.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    spawn_kernel_thread(ke::sched::NORMAL_PRIORITY, peer, core::ptr::null_mut());

    let tick_ms = hal::timer::TICK_INTERVAL_MS;
    let switches;
    {
        let _guard = LOCK.lock();
        // Counted once the lock is held: a tick just before may switch freely
        // (the peer then spins until its own quantum ends).
        switches = ke::sched::context_switches();
        let start = hal::timer::get_tick_count();
        while hal::timer::get_tick_count() < start + TICKS * tick_ms {
            core::hint::spin_loop();
        }
        assert_eq!(ke::sched::context_switches(), switches, "preempted while holding a KSpinLock");
        RELEASED.store(true, Ordering::Release);
    }
    // The dispatch requested by those ticks ran when the guard lowered the IRQL.
    assert!(ke::sched::context_switches() > switches, "pending dispatch not run on IRQL drop");
    log::info!("[smoke] dispatch deferred: {} ticks under a KSpinLock without preemption, run on release", TICKS);
}

/// Checks the scheduler and the dispatcher on real threads (M1, `ke::sched`): a
/// kernel thread of higher priority runs before its creation returns; after a
/// 20 ms delay it wakes the boot thread through an event, then ends, which
/// signals its thread object; a wait on an event nobody sets times out.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn ke_self_test() {
    use abi::ntstatus::{STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_WAIT_0};
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicBool, Ordering};
    use ke::dispatcher::{
        ke_delay_execution_thread, ke_initialize_event, ke_set_event, ke_wait_for_single_object, DispatcherHeader,
        KEvent, ObjectType, ProcessorMode, EVENT_INCREMENT,
    };
    use ke::sched::KePlatform;

    const MS: i64 = 10_000;
    static STARTED: AtomicBool = AtomicBool::new(false);
    fn signaler(event: *mut c_void) {
        STARTED.store(true, Ordering::Relaxed);
        // SAFETY: on a scheduler thread; the event is never freed.
        unsafe {
            let delay = ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -20 * MS);
            assert_eq!(delay, STATUS_SUCCESS);
            ke_set_event::<KePlatform>(event.cast(), EVENT_INCREMENT);
        }
    }
    let wait = |object: *mut DispatcherHeader, timeout_ms: i64| {
        // SAFETY: on the boot thread; the objects waited on are never freed.
        unsafe { ke_wait_for_single_object::<KePlatform>(object, ProcessorMode::Kernel, false, Some(-timeout_ms * MS)) }
    };

    let event = alloc::boxed::Box::into_raw(alloc::boxed::Box::<KEvent>::new_uninit()).cast::<KEvent>();
    // SAFETY: fresh memory at a fixed address, never freed.
    let header = unsafe {
        ke_initialize_event(event, ObjectType::SynchronizationEvent, false);
        core::ptr::addr_of_mut!((*event).header)
    };
    let start = hal::timer::interrupt_time();
    // Above the boot thread, boost included.
    let tid = spawn_kernel_thread(ke::sched::current_priority() + 1, signaler, event.cast());
    assert!(STARTED.load(Ordering::Relaxed), "a higher-priority thread did not preempt its creator");
    assert_eq!(wait(header, 1000), STATUS_WAIT_0, "event not set");
    let waited = hal::timer::interrupt_time() - start;
    assert!(waited >= 20 * MS as u64, "20 ms delay over after {waited} x 100 ns");
    let thread = ke::sched::thread_object(tid).expect("thread object");
    assert_eq!(wait(thread, 1000), STATUS_WAIT_0, "thread end not signaled");

    let start = hal::timer::interrupt_time();
    assert_eq!(wait(header, 30), STATUS_TIMEOUT);
    assert!(hal::timer::interrupt_time() - start >= 30 * MS as u64, "timed out too early");
    log::info!("[smoke] Ke: priority preemption, event wait, delay, thread end and timeout ok");
}

/// Checks wait boosts (M1, `ke::sched`): a thread of base priority 7, woken
/// through an event with the increment that lifts it one level above the boot
/// thread (itself at 8, or above while a boost of its own lasts), preempts it
/// before `ke_set_event` returns; one quantum later, its boost has decayed by
/// one level, to the boot thread's priority, and the boot thread gets the
/// processor back while the woken thread still spins.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn boost_self_test() {
    use abi::ntstatus::{STATUS_SUCCESS, STATUS_WAIT_0};
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use ke::dispatcher::{
        ke_delay_execution_thread, ke_initialize_event, ke_set_event, ke_wait_for_single_object, KEvent, ObjectType,
        ProcessorMode,
    };
    use ke::sched::{KePlatform, LOW_REALTIME_PRIORITY, NORMAL_PRIORITY};

    const MS: i64 = 10_000;
    static WOKEN_AT: AtomicU8 = AtomicU8::new(0);
    static RELEASE: AtomicBool = AtomicBool::new(false);
    fn sleeper(event: *mut c_void) {
        let event = event.cast::<KEvent>();
        // SAFETY: on a scheduler thread; the event is never freed.
        let status = unsafe {
            ke_wait_for_single_object::<KePlatform>(
                core::ptr::addr_of_mut!((*event).header),
                ProcessorMode::Kernel,
                false,
                None,
            )
        };
        assert_eq!(status, STATUS_WAIT_0);
        WOKEN_AT.store(ke::sched::current_priority(), Ordering::Relaxed);
        while !RELEASE.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    let event = alloc::boxed::Box::into_raw(alloc::boxed::Box::<KEvent>::new_uninit()).cast::<KEvent>();
    // SAFETY: fresh memory at a fixed address, never freed.
    unsafe { ke_initialize_event(event, ObjectType::SynchronizationEvent, false) };
    let tid = spawn_kernel_thread(NORMAL_PRIORITY - 1, sleeper, event.cast());
    // Below the boot thread, the sleeper runs, and starts waiting, only while
    // the boot thread waits.
    // SAFETY: on the boot thread.
    let delay = unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
    assert_eq!(delay, STATUS_SUCCESS);
    assert_eq!(WOKEN_AT.load(Ordering::Relaxed), 0, "the sleeper did not wait");
    let waker = ke::sched::current_priority();
    assert!((NORMAL_PRIORITY..LOW_REALTIME_PRIORITY - 1).contains(&waker), "boot thread at {waker}");
    // SAFETY: the event is initialised and never freed.
    unsafe { ke_set_event::<KePlatform>(event, waker + 1 - (NORMAL_PRIORITY - 1)) };
    assert_eq!(
        WOKEN_AT.load(Ordering::Relaxed),
        waker + 1,
        "the woken thread did not run boosted before its waker resumed"
    );
    assert_eq!(
        ke::sched::thread_priority(tid),
        Some(waker),
        "the boost did not decay by one level at the end of the quantum"
    );
    RELEASE.store(true, Ordering::Release);
    let thread = ke::sched::thread_object(tid).expect("thread object");
    // SAFETY: on the boot thread; the thread object is never freed.
    let end =
        unsafe { ke_wait_for_single_object::<KePlatform>(thread, ProcessorMode::Kernel, false, Some(-1000 * MS)) };
    assert_eq!(end, STATUS_WAIT_0, "the woken thread did not end");
    log::info!("[smoke] Ke: wait boost preempts the waker, then decays one level per quantum");
}

/// Checks kernel APCs on real threads (M1, `ke::apc`): a special APC queued to
/// the running thread runs at APC_LEVEL before the call returns; one queued
/// by a DPC runs as soon as the DPC has; a normal APC queued to a thread
/// waiting at PASSIVE_LEVEL runs in that thread, its kernel routine at
/// APC_LEVEL and its normal routine at PASSIVE_LEVEL, and the wait goes on
/// after it.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn apc_self_test() {
    use abi::ntstatus::STATUS_WAIT_0;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering};
    use hal::irql::Irql;
    use ke::apc::{ke_insert_queue_apc, KApc, NormalRoutine};
    use ke::dispatcher::{
        ke_initialize_event, ke_set_event, ke_wait_for_single_object, KEvent, KThread, ObjectType, Platform,
        ProcessorMode, EVENT_INCREMENT, IO_NO_INCREMENT,
    };
    use ke::dpc::{ke_insert_queue_dpc, KDpc};
    use ke::sched::KePlatform;

    const NOT_RUN: u8 = u8::MAX;
    static SELF_APC: AtomicU8 = AtomicU8::new(NOT_RUN);
    static DPC_APC: AtomicU8 = AtomicU8::new(NOT_RUN);
    static KERNEL_ROUTINE: AtomicU8 = AtomicU8::new(NOT_RUN);
    static NORMAL_ROUTINE: AtomicU8 = AtomicU8::new(NOT_RUN);
    static NORMAL_IN: AtomicPtr<KThread> = AtomicPtr::new(core::ptr::null_mut());
    static WOKEN: AtomicBool = AtomicBool::new(false);

    /// Records the IRQL in the `AtomicU8` that `argument1` points to.
    fn record(
        _: *mut KApc,
        _: &mut Option<NormalRoutine>,
        _: &mut *mut c_void,
        at: &mut *mut c_void,
        _: &mut *mut c_void,
    ) {
        // SAFETY: every APC of this test passes one of the statics above.
        unsafe { (*at.cast::<AtomicU8>()).store(hal::irql::current() as u8, Ordering::Relaxed) };
    }
    /// Records the IRQL in the `AtomicU8` that `argument2` points to.
    fn normal(_: *mut c_void, _: *mut c_void, at: *mut c_void) {
        // SAFETY: as above.
        unsafe { (*at.cast::<AtomicU8>()).store(hal::irql::current() as u8, Ordering::Relaxed) };
        NORMAL_IN.store(KePlatform::current_thread(), Ordering::Relaxed);
    }
    fn queue_from_dpc(_: *const KDpc, apc: *mut c_void, _: *mut c_void, _: *mut c_void) {
        // SAFETY: the APC is leaked, initialised for the boot thread.
        let queued = unsafe {
            ke_insert_queue_apc::<KePlatform>(
                apc.cast(),
                (&raw const DPC_APC).cast_mut().cast(),
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(queued && DPC_APC.load(Ordering::Relaxed) == NOT_RUN, "an APC ran at DISPATCH_LEVEL");
    }
    fn sleeper(event: *mut c_void) {
        let event = event.cast::<KEvent>();
        // SAFETY: on a scheduler thread; the event is never freed.
        let status = unsafe {
            ke_wait_for_single_object::<KePlatform>(&raw mut (*event).header, ProcessorMode::Kernel, false, None)
        };
        assert_eq!(status, STATUS_WAIT_0);
        WOKEN.store(true, Ordering::Release);
    }
    let leak = |apc: KApc| alloc::boxed::Box::leak(alloc::boxed::Box::new(apc)) as *mut KApc;
    let arg = |at: &'static AtomicU8| core::ptr::from_ref(at).cast_mut().cast::<c_void>();
    let me = KePlatform::current_thread();

    // SAFETY: each APC is leaked: valid, at a fixed address, for good.
    let queued = unsafe {
        ke_insert_queue_apc::<KePlatform>(
            leak(KApc::new(me, record, None, None, ProcessorMode::Kernel, core::ptr::null_mut())),
            arg(&SELF_APC),
            core::ptr::null_mut(),
            IO_NO_INCREMENT,
        )
    };
    assert!(queued);
    assert_eq!(SELF_APC.load(Ordering::Relaxed), Irql::Apc as u8, "special APC to the running thread");

    let from_dpc = leak(KApc::new(me, record, None, None, ProcessorMode::Kernel, core::ptr::null_mut()));
    let dpc = alloc::boxed::Box::leak(alloc::boxed::Box::new(KDpc::new(queue_from_dpc, from_dpc.cast())));
    // SAFETY: the DPC is leaked: valid, at a fixed address, for good.
    assert!(unsafe { ke_insert_queue_dpc(dpc, core::ptr::null_mut(), core::ptr::null_mut()) });
    assert_eq!(DPC_APC.load(Ordering::Relaxed), Irql::Apc as u8, "APC queued by a DPC, run after it");

    let event = alloc::boxed::Box::into_raw(alloc::boxed::Box::<KEvent>::new_uninit()).cast::<KEvent>();
    // SAFETY: fresh memory at a fixed address, never freed.
    unsafe { ke_initialize_event(event, ObjectType::SynchronizationEvent, false) };
    // Above the boot thread: it runs, and starts waiting, before this returns.
    let tid = spawn_kernel_thread(ke::sched::current_priority() + 1, sleeper, event.cast());
    let waiter = ke::sched::thread_object(tid).expect("thread object").cast::<KThread>();
    let to_waiter = leak(KApc::new(
        waiter,
        record,
        None,
        Some(NormalRoutine::Kernel(normal)),
        ProcessorMode::Kernel,
        core::ptr::null_mut(),
    ));
    // SAFETY: as above; the waiter is a registered thread, never freed.
    unsafe {
        ke_insert_queue_apc::<KePlatform>(to_waiter, arg(&KERNEL_ROUTINE), arg(&NORMAL_ROUTINE), IO_NO_INCREMENT)
    };
    assert_eq!(KERNEL_ROUTINE.load(Ordering::Relaxed), Irql::Apc as u8, "kernel routine");
    assert_eq!(NORMAL_ROUTINE.load(Ordering::Relaxed), Irql::Passive as u8, "normal routine");
    assert_eq!(NORMAL_IN.load(Ordering::Relaxed), waiter, "the APC ran in another thread's context");
    assert!(!WOKEN.load(Ordering::Acquire), "the wait did not resume after the APC");
    // SAFETY: the event is initialised and never freed.
    unsafe { ke_set_event::<KePlatform>(event, EVENT_INCREMENT) };
    // SAFETY: on the boot thread; the thread object is never freed.
    let end = unsafe {
        ke_wait_for_single_object::<KePlatform>(waiter.cast(), ProcessorMode::Kernel, false, Some(-1000 * 10_000))
    };
    assert_eq!(end, STATUS_WAIT_0);
    assert!(WOKEN.load(Ordering::Acquire));
    log::info!("[smoke] Ke: kernel APCs run at APC_LEVEL, normal routines at PASSIVE_LEVEL, a wait resumes after them");
}

/// Checks per-process address spaces (M2, `mm::address_space`): the same user
/// address holds a different page in each of two address spaces, seen by the
/// boot thread through an attach, and by two kernel threads, one in each
/// space, that preempt each other; the system address space sees neither.
/// Destroying the spaces gives back every page they took.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn address_space_self_test() {
    use abi::ntstatus::STATUS_WAIT_0;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicU64, Ordering};
    use ke::dispatcher::{ke_wait_for_multiple_objects, ProcessorMode, WaitBlock, WaitType};
    use ke::sched::KePlatform;
    use mm::address_space::AddressSpace;
    use mm::pfn::{self, PageUsage};
    use x86_64::structures::paging::PageTableFlags as F;

    const VA: u64 = 0x40_0000;
    const MARKERS: [u64; 2] = [0x5350_4143_4500_0001, 0x5350_4143_4500_0002];
    const SPIN_MS: u64 = 60;
    static READS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static WRONG: AtomicU64 = AtomicU64::new(0);

    fn read_va() -> u64 {
        // SAFETY: VA holds a page in the address space this is called in (the
        // callers make sure), mapped for the kernel.
        unsafe { core::ptr::read_volatile(VA as *const u64) }
    }
    /// Reads VA for SPIN_MS, preempted by the other reader on quantum ends.
    fn reader(index: *mut c_void) {
        let i = index.addr();
        let end = hal::timer::interrupt_time() + SPIN_MS * 10_000;
        while hal::timer::interrupt_time() < end {
            if read_va() != MARKERS[i] {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
            READS[i].fetch_add(1, Ordering::Relaxed);
        }
    }
    let counts = || {
        let s = pfn::stats();
        (s.active(PageUsage::PageTable), s.active(PageUsage::UserPrivate))
    };
    let hhdm = hal::HHDM_OFFSET.load(Ordering::Acquire);

    let before = counts();
    let spaces = [AddressSpace::new().expect("no PML4"), AddressSpace::new().expect("no PML4")];
    for (space, marker) in spaces.iter().zip(MARKERS) {
        let page = pfn::allocate_page(PageUsage::UserPrivate).expect("no page");
        // SAFETY: a page just allocated, reached through the HHDM.
        unsafe { ((hhdm + page.to_phys()) as *mut u64).write(marker) };
        // SAFETY: VA is free in this new space; the page belongs to the space
        // from now on.
        unsafe { space.map_page(VA, page.to_phys(), F::PRESENT | F::NO_EXECUTE) };
    }
    let created = counts();
    // SAFETY: CR3 holds the system's tables.
    let system = unsafe { mm::MmPageTables::new(hhdm) };
    assert!(system.translate(x86_64::VirtAddr::new(VA)).is_none(), "the system address space sees a process page");
    for (space, marker) in spaces.iter().zip(MARKERS) {
        // SAFETY: the space lives until the end of this test.
        let attached = unsafe { ke::sched::ke_stack_attach(space.directory_table_base()) };
        assert_eq!(read_va(), marker, "attached to a space, the boot thread does not see its page");
        ke::sched::ke_unstack_detach(attached);
    }

    let switches = ke::sched::context_switches();
    let threads = [0usize, 1].map(|i| {
        // SAFETY: the spaces live until both threads have ended (waited for below).
        let tid = unsafe {
            spawn_kernel_thread_in(
                spaces[i].directory_table_base(),
                ke::sched::NORMAL_PRIORITY,
                reader,
                core::ptr::without_provenance_mut(i),
            )
        };
        ke::sched::thread_object(tid).expect("thread object")
    });
    let mut blocks = [const { WaitBlock::new() }; 2];
    // SAFETY: on the boot thread; the thread objects are never freed.
    let status = unsafe {
        ke_wait_for_multiple_objects::<KePlatform>(
            &threads,
            WaitType::WaitAll,
            ProcessorMode::Kernel,
            false,
            Some(-2000 * 10_000),
            Some(&mut blocks),
        )
    };
    assert_eq!(status, STATUS_WAIT_0, "the readers did not end");
    let reads = READS.each_ref().map(|r| r.load(Ordering::Relaxed));
    assert_eq!(WRONG.load(Ordering::Relaxed), 0, "a thread saw another address space's page");
    assert!(reads.iter().all(|&r| r > 0));
    let switched = ke::sched::context_switches() - switches;
    assert!(switched >= 4, "the readers did not take turns ({switched} switches)");

    let in_use = counts();
    for space in spaces {
        space.destroy();
    }
    let after = counts();
    assert_eq!(
        (in_use.0 - after.0, in_use.1 - after.1),
        (created.0 - before.0, created.1 - before.1),
        "destroying the spaces did not give back every page they took"
    );
    log::info!(
        "[smoke] Mm: address spaces: the same address holds its own page in each, across {switched} switches; \
         destroyed without a leak ({} page tables, {} pages)",
        created.0 - before.0,
        created.1 - before.1
    );
}

/// The VAD with the real mapper (`mm::virtual_alloc`): in a new address space,
/// reserve 16 pages, commit two inside the reservation, protect one, decommit
/// it, then release everything; the page tables and the PFN database follow.
fn vad_self_test() {
    use core::sync::atomic::Ordering;
    use mm::address_space::AddressSpace;
    use mm::pfn::{self, PageUsage};
    use mm::vad::{PageProtect, VadTree};
    use mm::virtual_alloc::{self, AllocType, FreeType, MemState, PAGE_SIZE};
    use x86_64::structures::paging::PageTableFlags as F;

    const BASE: u64 = 0x40_0000;
    const COMMIT: u64 = BASE + 4 * PAGE_SIZE;
    const MARKER: u64 = 0x5641_4400_0000_0001;
    let rw = PageProtect::READWRITE;
    let user_pages = || pfn::stats().active(PageUsage::UserPrivate);
    let flags = |mapper: &KernelPageMapper, va| mapper.pt.translate_flags(VirtAddr::new(va)).map(|(_, f)| f);

    let space = AddressSpace::new().expect("no PML4");
    // SAFETY: the space lives until the end of this test, detached before it
    // is destroyed.
    let attached = unsafe { ke::sched::ke_stack_attach(space.directory_table_base()) };
    // SAFETY: CR3 holds the attached space's tables.
    let mut mapper =
        KernelPageMapper { pt: unsafe { mm::MmPageTables::new(hal::HHDM_OFFSET.load(Ordering::Acquire)) } };
    let mut vad = VadTree::new();
    let before = user_pages();

    let reserved =
        virtual_alloc::allocate(&mut vad, Some(&mut mapper), BASE, 16 * PAGE_SIZE, AllocType::MEM_RESERVE, rw);
    assert_eq!(reserved, Ok(BASE));
    assert_eq!(user_pages(), before, "a reservation took physical pages");
    let committed =
        virtual_alloc::allocate(&mut vad, Some(&mut mapper), COMMIT, 2 * PAGE_SIZE, AllocType::MEM_COMMIT, rw);
    assert_eq!(committed, Ok(COMMIT), "commit inside the reservation");
    assert_eq!(user_pages(), before + 2);
    let f = flags(&mapper, COMMIT).expect("a committed page is not mapped");
    assert!(f.contains(F::WRITABLE | F::USER_ACCESSIBLE | F::NO_EXECUTE), "{f:?}");
    assert!(flags(&mapper, BASE).is_none(), "a reserved page is mapped");
    // SAFETY: the page was just committed read-write in the attached space.
    unsafe { core::ptr::write_volatile(COMMIT as *mut u64, MARKER) };

    let old = virtual_alloc::protect(&mut vad, Some(&mut mapper), COMMIT, PAGE_SIZE, PageProtect::EXECUTE_READ);
    assert_eq!(old, Ok(rw));
    let f = flags(&mapper, COMMIT).unwrap();
    assert!(!f.intersects(F::WRITABLE | F::NO_EXECUTE), "the protection did not reach the page tables: {f:?}");
    // SAFETY: still mapped, now read-only.
    assert_eq!(unsafe { core::ptr::read_volatile(COMMIT as *const u64) }, MARKER, "protecting lost the data");

    let decommitted = virtual_alloc::free(&mut vad, Some(&mut mapper), COMMIT, PAGE_SIZE, FreeType::MEM_DECOMMIT);
    assert_eq!(decommitted, Ok((COMMIT, PAGE_SIZE)));
    assert!(flags(&mapper, COMMIT).is_none(), "a decommitted page is still mapped");
    assert_eq!(user_pages(), before + 1);
    assert_eq!(virtual_alloc::query(&vad, COMMIT).map(|r| r.state), Ok(MemState::Reserve));
    let released = virtual_alloc::free(&mut vad, Some(&mut mapper), BASE, 0, FreeType::MEM_RELEASE);
    assert_eq!(released, Ok((BASE, 16 * PAGE_SIZE)));
    assert_eq!(user_pages(), before, "releasing did not give back the committed page");
    assert!(vad.is_empty());
    ke::sched::ke_unstack_detach(attached);
    space.destroy();
    log::info!(
        "[smoke] Mm: VAD reserve, commit, protect, decommit and release reach the page tables and the PFN database"
    );
}

/// Demand paging (`mm::fault`): in a new address space, reserve 256 MiB,
/// commit 64 pages one by one and touch every other one: only those take a
/// page, one fault each. A `PAGE_NOACCESS` page keeps its data out of reach, a
/// guard page fires once, and releasing then destroying the space gives back
/// every page.
fn demand_paging_self_test() {
    use abi::ntstatus::{STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION};
    use core::sync::atomic::Ordering;
    use mm::address_space::AddressSpace;
    use mm::fault::{self, Access};
    use mm::pfn::{self, PageUsage};
    use mm::vad::PageProtect;
    use mm::virtual_alloc::{AllocType, FreeType, MemState, PAGE_SIZE};
    use x86_64::structures::paging::PageTableFlags as F;

    const RESERVED: u64 = 256 << 20;
    const COMMITTED: u64 = 64;
    const MARKER: u64 = 0x4445_4D41_4E44_0000;
    let (rw, ro, guard) = (PageProtect::READWRITE, PageProtect::READONLY, PageProtect::READWRITE | PageProtect::GUARD);
    let counts = || {
        let s = pfn::stats();
        (s.active(PageUsage::PageTable), s.active(PageUsage::UserPrivate))
    };
    let hhdm = hal::HHDM_OFFSET.load(Ordering::Acquire);
    // SAFETY (the three closures): called while attached to the space below,
    // whose page tables CR3 holds; the addresses are committed pages of it.
    let flags = |va| unsafe { mm::MmPageTables::new(hhdm) }.translate_flags(VirtAddr::new(va)).map(|(_, f)| f);
    let read = |va: u64| unsafe { core::ptr::read_volatile(va as *const u64) };
    let write = |va: u64, value: u64| unsafe { core::ptr::write_volatile(va as *mut u64, value) };

    let before = counts();
    let space = AddressSpace::new().expect("no PML4");
    // SAFETY: the space lives until the end of this test, detached before it
    // is destroyed.
    let attached = unsafe { ke::sched::ke_stack_attach(space.directory_table_base()) };
    let base = space.allocate(0, RESERVED, AllocType::MEM_RESERVE, PageProtect::NOACCESS).expect("reserve 256 MiB");
    let page = |i: u64| base + i * PAGE_SIZE;
    for i in 0..COMMITTED {
        assert_eq!(space.allocate(page(i), PAGE_SIZE, AllocType::MEM_COMMIT, rw), Ok(page(i)));
    }
    assert_eq!(counts().1, before.1, "committing took physical pages");
    let faults = fault::demand_zero_faults();
    for i in (0..COMMITTED).step_by(2) {
        assert_eq!(read(page(i)), 0, "a demand-zero page is not zeroed");
        write(page(i), MARKER + i);
    }
    let touched = counts();
    assert_eq!(touched.1 - before.1, COMMITTED / 2, "untouched pages took physical memory");
    assert_eq!(fault::demand_zero_faults() - faults, COMMITTED / 2, "not one fault per touched page");
    assert!(flags(page(1)).is_none(), "an untouched page is mapped");
    let f = flags(page(0)).expect("a touched page is not mapped");
    assert!(f.contains(F::WRITABLE | F::USER_ACCESSIBLE | F::NO_EXECUTE), "{f:?}");

    // PAGE_NOACCESS: out of reach, its data kept for a later protection.
    assert_eq!(space.protect(page(2), PAGE_SIZE, PageProtect::NOACCESS), Ok(rw));
    assert!(flags(page(2)).is_none(), "a PAGE_NOACCESS page is mapped");
    assert_eq!(space.access_fault(page(2), Access::Read), STATUS_ACCESS_VIOLATION);
    assert_eq!(counts().1, touched.1, "PAGE_NOACCESS gave its page away");
    assert_eq!(space.protect(page(2), PAGE_SIZE, ro), Ok(PageProtect::NOACCESS));
    assert_eq!(read(page(2)), MARKER + 2, "the data did not survive PAGE_NOACCESS");
    assert!(!flags(page(2)).unwrap().contains(F::WRITABLE));
    assert_eq!(space.access_fault(page(2), Access::Write), STATUS_ACCESS_VIOLATION, "write to a read-only page");

    // Guard pages fire once, untouched or touched before, then work as committed.
    let fresh = page(COMMITTED);
    assert_eq!(space.allocate(fresh, PAGE_SIZE, AllocType::MEM_COMMIT, guard), Ok(fresh));
    assert_eq!(space.protect(page(4), PAGE_SIZE, guard), Ok(rw));
    for va in [fresh, page(4)] {
        assert_eq!(space.access_fault(va, Access::Write), STATUS_GUARD_PAGE_VIOLATION);
        assert_eq!(space.query(va).map(|r| r.protect), Ok(rw), "the guard is still up");
    }
    write(fresh, MARKER);
    assert_eq!(read(page(4)), MARKER + 4, "the data did not survive the guard");

    // Copies from outside the space, as the process would read and write.
    let straddle = page(9) - 8;
    let mut back = [0u8; 16];
    space.read_bytes(straddle, &mut back).expect("read across two pages");
    assert_eq!(back, [0; 16], "untouched committed pages read as zeros");
    space.write_bytes(straddle, b"across two pages").expect("write across two pages");
    space.read_bytes(straddle, &mut back).expect("read back");
    assert_eq!(&back, b"across two pages");
    assert_eq!(read(straddle).to_le_bytes(), *b"across t", "the first half at the end of one page");
    assert_eq!(read(page(9)).to_le_bytes(), *b"wo pages", "the second half at the start of the next");
    let mut byte = [0u8];
    assert_eq!(space.read_bytes(page(COMMITTED + 1), &mut byte), Err(STATUS_ACCESS_VIOLATION), "reserved page");
    assert_eq!(space.access_fault(page(COMMITTED + 1), Access::Read), STATUS_ACCESS_VIOLATION, "reserved page");
    assert_eq!(space.access_fault(base + RESERVED, Access::Read), STATUS_ACCESS_VIOLATION, "free page");

    let mapped = counts().1;
    assert_eq!(space.free(page(0), PAGE_SIZE, FreeType::MEM_DECOMMIT), Ok((page(0), PAGE_SIZE)));
    assert_eq!(counts().1, mapped - 1, "decommitting kept the page");
    assert!(flags(page(0)).is_none(), "a decommitted page is still mapped");
    assert_eq!(space.query(page(0)).map(|r| r.state), Ok(MemState::Reserve));
    assert_eq!(space.free(base, 0, FreeType::MEM_RELEASE), Ok((base, RESERVED)));
    assert_eq!(counts().1, before.1, "releasing did not give back every touched page");

    // A page kept out of reach goes with the space.
    let last = space.allocate(0, PAGE_SIZE, AllocType::MEM_RESERVE | AllocType::MEM_COMMIT, rw).expect("commit");
    write(last, MARKER);
    assert_eq!(space.protect(last, PAGE_SIZE, PageProtect::NOACCESS), Ok(rw));
    let tables = counts().0 - before.0;
    ke::sched::ke_unstack_detach(attached);
    space.destroy();
    assert_eq!(counts(), before, "destroying the space did not give back every page");
    log::info!(
        "[smoke] Mm: demand paging: 256 MiB reserved, {COMMITTED} pages committed, {} touched for as many \
         pages and faults; PAGE_NOACCESS and guard pages; all back on release and destroy ({tables} page tables)",
        COMMITTED / 2
    );
}

/// Kernel stacks go back (`mm::kstack::free`): their pages to the PFN database,
/// their slots to the next allocation.
fn kernel_stack_self_test() {
    use mm::pfn::{self, PageUsage};
    let stack_pages = || pfn::stats().active(PageUsage::KernelStack);
    let before = stack_pages();
    let stacks = [(); 3].map(|_| mm::kstack::allocate().expect("a kernel stack"));
    let per_stack = (stack_pages() - before) / 3;
    for stack in stacks {
        // SAFETY: allocated just above, never used.
        unsafe { mm::kstack::free(stack) };
    }
    assert_eq!(stack_pages(), before, "freed stacks kept their pages");
    let again = mm::kstack::allocate().expect("a kernel stack");
    assert_eq!(again, stacks[2], "the last slot freed comes back first");
    // SAFETY: allocated just above, never used.
    unsafe { mm::kstack::free(again) };
    log::info!("[smoke] Mm: kernel stacks freed and their slots reused ({per_stack} pages each)");
}

/// A demand-zero fault that gets its page but no page table returns
/// `STATUS_NO_MEMORY` and gives the page back, instead of stopping the system:
/// every free page but one is taken, and the first page of a new address
/// space needs three tables.
fn out_of_page_tables_self_test() {
    use abi::ntstatus::{STATUS_NO_MEMORY, STATUS_SUCCESS};
    use core::sync::atomic::Ordering;
    use mm::address_space::AddressSpace;
    use mm::buddy::MAX_ORDER;
    use mm::fault::Access;
    use mm::pfn::{self, PageUsage};
    use mm::vad::PageProtect;
    use mm::virtual_alloc::{AllocType, PAGE_SIZE};

    let space = AddressSpace::new().expect("no PML4");
    let commit = AllocType::MEM_RESERVE | AllocType::MEM_COMMIT;
    let va = space.allocate(0, PAGE_SIZE, commit, PageProtect::READWRITE).expect("commit");
    let user_pages = || pfn::stats().active(PageUsage::UserPrivate);
    let before = user_pages();
    let hhdm = hal::HHDM_OFFSET.load(Ordering::Acquire);
    // The first page of each block taken holds the previous block and its
    // order (the PFN plus one, 0 at the end): no pool, no stack.
    let link = |block: mm::Pfn| (hhdm + block.to_phys()) as *mut [u64; 2];
    // At DISPATCH_LEVEL, no thread allocates while the pages are taken (ISRs
    // and DPCs never do).
    let irql = hal::irql::raise(hal::irql::Irql::Dispatch);
    let (mut last, mut count) = ([0u64; 2], 0);
    loop {
        let free = pfn::stats().free;
        let largest = (0..MAX_ORDER).rev().filter(|&order| 1 << order < free);
        let Some((block, order)) =
            largest.into_iter().find_map(|order| pfn::allocate_pages(order, PageUsage::Buffer).map(|b| (b, order)))
        else {
            break;
        };
        // SAFETY: the first page of a block just allocated, through the HHDM.
        unsafe { link(block).write(last) };
        last = [block.0 + 1, order as u64];
        count += 1;
    }
    let left = pfn::stats().free;
    let status = space.access_fault(va, Access::Write);
    while last[0] != 0 {
        let block = mm::Pfn(last[0] - 1);
        // SAFETY: a block taken above, still allocated.
        let previous = unsafe { link(block).read() };
        pfn::free_pages(block, last[1] as usize);
        last = previous;
    }
    hal::irql::lower(irql);
    assert_eq!(left, 1, "not one free page left");
    assert_eq!(status, STATUS_NO_MEMORY);
    assert_eq!(user_pages(), before, "the fault kept its page");
    assert_eq!(space.access_fault(va, Access::Write), STATUS_SUCCESS, "memory back, the fault works");
    space.destroy();
    log::info!("[smoke] Mm: a fault without a page table returns STATUS_NO_MEMORY ({count} blocks taken)");
}

/// Sections (`mm::section`): a shared-memory section mapped in two address
/// spaces shares its pages; each space maps a different image at 0x400000,
/// with its protections and copy-on-write; a data file reads back. Unmapping,
/// destroying the spaces and dropping the sections give back every page.
fn section_self_test() {
    use abi::ntstatus::{
        STATUS_ACCESS_VIOLATION, STATUS_IMAGE_NOT_AT_BASE, STATUS_NOT_MAPPED_VIEW, STATUS_SECTION_PROTECTION,
        STATUS_SUCCESS,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use mm::address_space::AddressSpace;
    use mm::fault::Access;
    use mm::pfn::{self, PageUsage};
    use mm::section::Section;
    use mm::vad::PageProtect;
    use mm::virtual_alloc::{MemType, PAGE_SIZE as P};
    use pe::builder::Pe32Builder;
    use x86_64::structures::paging::PageTableFlags as F;

    const IMAGE_BASE: u64 = 0x40_0000;
    const MARKER: u64 = 0x5345_4354_494F_4E00;
    let (ro, rw) = (PageProtect::READONLY, PageProtect::READWRITE);
    let counts = || {
        let s = pfn::stats();
        (s.active(PageUsage::PageTable), s.active(PageUsage::UserPrivate), s.active(PageUsage::Section))
    };
    let hhdm = hal::HHDM_OFFSET.load(Ordering::Acquire);
    // SAFETY (the three closures): called through `in_space`, attached to a
    // space whose page tables CR3 holds; the addresses are pages of its views.
    let flags = |va| unsafe { mm::MmPageTables::new(hhdm) }.translate_flags(VirtAddr::new(va)).map(|(_, f)| f);
    let read = |va: u64| unsafe { core::ptr::read_volatile(va as *const u64) };
    let write = |va: u64, value: u64| unsafe { core::ptr::write_volatile(va as *mut u64, value) };
    let before = counts();
    let (a, b) = (AddressSpace::new().expect("no PML4"), AddressSpace::new().expect("no PML4"));

    // Shared memory: one page, whoever writes it.
    let shared = Section::create_pagefile(4 * P, rw).expect("pagefile section");
    let (va, vb) = (a.map_view(&shared, 0, 0, 0, rw).expect("map"), b.map_view(&shared, 0, 0, 0, rw).expect("map"));
    assert_eq!((va.size, va.status), (4 * P, STATUS_SUCCESS));
    in_space(&a, || write(va.base + P, MARKER));
    in_space(&b, || {
        assert_eq!(read(vb.base + P), MARKER, "a view does not see the other's write");
        write(vb.base + 2 * P, MARKER + 1);
    });
    assert_eq!(in_space(&a, || read(va.base + 2 * P)), MARKER + 1);
    assert_eq!((shared.resident_pages(), counts().2 - before.2), (2, 2), "not one section page per page touched");
    assert_eq!(counts().1, before.1, "a shared write took a private page");
    // Protected copy-on-write, a shared page is no longer written in place.
    assert_eq!(a.protect(va.base + P, P, PageProtect::WRITECOPY), Ok(rw));
    in_space(&a, || {
        assert!(!flags(va.base + P).unwrap().contains(F::WRITABLE), "a copy-on-write page mapped writable");
        write(va.base + P, MARKER + 2);
    });
    assert_eq!(in_space(&b, || read(vb.base + P)), MARKER, "a copy went to the other space");
    assert_eq!(counts().1 - before.1, 1, "copy-on-write did not take one private page");

    // Two images at 0x400000, one per space.
    let image = |code: u8, data: &[u8]| {
        let file = Pe32Builder::new(IMAGE_BASE as u32)
            .entry_point(0x1000)
            .section(".text", 0x1000, 0x100, &[code; 0x100], pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
            .section(".data", 0x2000, 0x100, data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
            .build();
        Section::create_image(Arc::from(file)).expect("image section")
    };
    let (one, two) = (image(0x90, b"data one"), image(0xCC, b"data two"));
    for (space, section) in [(&a, &one), (&b, &two)] {
        let view = space.map_view(section, 0, 0, 0, ro).expect("map an image");
        assert_eq!((view.base, view.size, view.status), (IMAGE_BASE, 3 * P, STATUS_SUCCESS));
    }
    in_space(&a, || {
        assert_eq!(read(IMAGE_BASE) as u16, 0x5A4D, "no MZ at the image base");
        assert_eq!(read(IMAGE_BASE + 0x1000), 0x9090_9090_9090_9090);
        let code = flags(IMAGE_BASE + 0x1000).unwrap();
        assert!(!code.intersects(F::WRITABLE | F::NO_EXECUTE), "code page: {code:?}");
        assert_eq!(read(IMAGE_BASE + 0x2000).to_le_bytes(), *b"data one");
        assert!(!flags(IMAGE_BASE + 0x2000).unwrap().contains(F::WRITABLE), "copy-on-write page mapped writable");
        write(IMAGE_BASE + 0x2000, MARKER);
        assert_eq!(read(IMAGE_BASE + 0x2000), MARKER);
    });
    assert_eq!(counts().1 - before.1, 2, "copy-on-write did not take one private page");
    assert_eq!(a.query(IMAGE_BASE + 0x2000).map(|r| r.protect), Ok(rw), "a copied page is read-write");
    assert_eq!(a.query(IMAGE_BASE).map(|r| r.kind), Ok(Some(MemType::Image)));
    in_space(&b, || {
        assert_eq!(read(IMAGE_BASE + 0x1000), 0xCCCC_CCCC_CCCC_CCCC, "each space has its own image at 0x400000");
        assert_eq!(read(IMAGE_BASE + 0x2000).to_le_bytes(), *b"data two");
    });
    let again = b.map_view(&one, 0, 0, 0, ro).expect("map an image twice");
    assert_eq!(again.status, STATUS_IMAGE_NOT_AT_BASE);
    assert_eq!(in_space(&b, || read(again.base + 0x2000)).to_le_bytes(), *b"data one", "a copy went to the section");
    assert_eq!(one.resident_pages(), 3, "headers, code, data");

    // A data file, read-only.
    let bytes: alloc::vec::Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let file = Section::create_data_file(Arc::from(bytes.clone()), 0, ro).expect("data file section");
    assert_eq!(a.map_view(&file, 0, 0, 0, rw).err(), Some(STATUS_SECTION_PROTECTION));
    let view = a.map_view(&file, 0, 0, 0, ro).expect("map a data file");
    assert_eq!(view.size, 2 * P);
    in_space(&a, || {
        // SAFETY: two readable pages of a view in the attached space.
        let mapped = unsafe { core::slice::from_raw_parts(view.base as *const u8, 2 * P as usize) };
        assert_eq!(&mapped[..5000], &bytes[..], "the view does not hold the file");
        assert!(mapped[5000..].iter().all(|&b| b == 0), "past the end of the file");
    });
    assert_eq!(a.access_fault(view.base, Access::Write), STATUS_ACCESS_VIOLATION, "write to a read-only view");

    let mapped = counts();
    assert_eq!(a.unmap_view(IMAGE_BASE + 0x1234), Ok(()));
    assert_eq!((counts().1, counts().2), (mapped.1 - 1, mapped.2), "unmapping: the copy goes, the section's stay");
    assert_eq!(a.unmap_view(va.base), Ok(()));
    assert_eq!(counts().1, before.1, "unmapping kept a copy");
    assert_eq!(a.unmap_view(IMAGE_BASE), Err(STATUS_NOT_MAPPED_VIEW));
    let resident = [&shared, &one, &two, &file].iter().map(|s| s.resident_pages() as u64).sum::<u64>();
    assert_eq!(counts().2 - before.2, resident);
    // Views still mapped in both spaces: their pages stay the sections'.
    a.destroy();
    b.destroy();
    assert_eq!(counts().2 - before.2, resident, "destroying a space freed section pages");
    drop((shared, one, two, file));
    assert_eq!(counts(), before, "the sections or the spaces kept pages");
    log::info!(
        "[smoke] Mm: sections: shared memory seen by two spaces, a different image at 0x400000 in each, \
         copy-on-write, a data file; {resident} section pages, all back"
    );
}

/// Runs `f` attached to `space`.
fn in_space<R>(space: &mm::address_space::AddressSpace, f: impl FnOnce() -> R) -> R {
    // SAFETY: the space outlives the attachment, which ends here.
    let attached = unsafe { ke::sched::ke_stack_attach(space.directory_table_base()) };
    let result = f();
    ke::sched::ke_unstack_detach(attached);
    result
}

/// i386 machine code for the self-tests, one instruction at a time.
struct Code(alloc::vec::Vec<u8>);

impl Code {
    fn new() -> Self {
        Self(alloc::vec::Vec::new())
    }

    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    fn word(&mut self, opcode: &[u8], value: u32) -> &mut Self {
        self.bytes(opcode).bytes(&value.to_le_bytes())
    }

    /// `int 2Eh` with EAX = `number` and EDX = `arguments`.
    fn int2e_at(&mut self, number: u32, arguments: u32) -> &mut Self {
        self.word(&[0xBA], arguments).word(&[0xB8], number).bytes(&[0xCD, 0x2E])
    }

    /// Pushes `arguments` (stdcall: the first lowest), then `int 2Eh` with
    /// EAX = `number` and EDX = ESP, then pops them.
    fn call(&mut self, number: u32, arguments: &[u32]) -> &mut Self {
        for &argument in arguments.iter().rev() {
            self.word(&[0x68], argument);
        }
        self.bytes(&[0x89, 0xE2]).word(&[0xB8], number).bytes(&[0xCD, 0x2E]);
        if !arguments.is_empty() {
            self.bytes(&[0x83, 0xC4, (arguments.len() * 4) as u8]);
        }
        self
    }

    /// `mov [addr], eax`.
    fn store_eax(&mut self, addr: u32) -> &mut Self {
        self.word(&[0xA3], addr)
    }

    /// Like [`call`](Self::call), with arguments that are values or words
    /// read from memory at run time (a handle returned earlier).
    fn call_args(&mut self, number: u32, arguments: &[Arg]) -> &mut Self {
        for argument in arguments.iter().rev() {
            match *argument {
                Arg::Value(value) => self.word(&[0x68], value),      // push value
                Arg::Memory(addr) => self.word(&[0xFF, 0x35], addr), // push dword [addr]
            };
        }
        self.bytes(&[0x89, 0xE2]).word(&[0xB8], number).bytes(&[0xCD, 0x2E]);
        if !arguments.is_empty() {
            self.bytes(&[0x83, 0xC4, (arguments.len() * 4) as u8]);
        }
        self
    }
}

/// An argument of [`Code::call_args`].
#[derive(Clone, Copy)]
enum Arg {
    Value(u32),
    Memory(u32),
}

/// KiSystemService (`sys`, M3): a Ps process calls system services through
/// `int 2Eh`, each number taken from the generated tables (`abi::services`):
/// memory allocated, written, read back and freed; a bad handle, an invalid
/// number, a service without a handler; arguments at an unmapped address or
/// in the kernel half, an out pointer that faults, and one in the guard page
/// of the stack, which the kernel grows; the other thread ended by
/// NtTerminateProcess(NULL), then the process by NtTerminateProcess on
/// itself.
fn system_service_self_test() {
    use abi::ntstatus::{
        NtStatus, STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_INVALID_SYSTEM_SERVICE,
        STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS, STATUS_WAIT_0,
    };
    use abi::process::NT_CURRENT_PROCESS;
    use abi::services::{self, NTOSKRNL};
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    // In and out values.
    const BASE: u32 = DATA;
    const SIZE: u32 = DATA + 0x04;
    const FREE_BASE: u32 = DATA + 0x08;
    const FREE_SIZE: u32 = DATA + 0x0C;
    // Statuses and results.
    const ALLOCATED: u32 = DATA + 0x10;
    const READ_BACK: u32 = DATA + 0x14;
    const FREED: u32 = DATA + 0x18;
    const CLOSED: u32 = DATA + 0x1C;
    const INVALID: u32 = DATA + 0x20;
    const UNIMPLEMENTED: u32 = DATA + 0x24;
    const UNMAPPED_ARGUMENTS: u32 = DATA + 0x28;
    const KERNEL_ARGUMENTS: u32 = DATA + 0x2C;
    const UNMAPPED_OUT: u32 = DATA + 0x30;
    const GUARD_OUT: u32 = DATA + 0x34;
    const OTHERS: u32 = DATA + 0x38;
    const AFTER_EXIT: u32 = DATA + 0x3C;
    // Handshake with the kernel.
    const DONE: u32 = DATA + 0x40;
    const GO: u32 = DATA + 0x44;
    const COMMIT_RESERVE: u32 = 0x3000;
    const READWRITE: u32 = 0x04;
    const RELEASE: u32 = 0x8000;
    const GUARD_OFFSET: u32 = 0x1F00;

    // A service without a handler and without arguments, so that EDX = ESP
    // at the top of the stack is enough.
    let unimplemented = (0..NTOSKRNL.len() as u32)
        .find(|&n| NTOSKRNL[n as usize].argument_bytes == 0 && !sys::is_implemented(n))
        .expect("every service without arguments is implemented");
    let mut code = Code::new();
    code.bytes(&[0x89, 0xE3]) // mov ebx, esp: the top of the stack
        .call(services::NtAllocateVirtualMemory, &[NT_CURRENT_PROCESS, BASE, 0, SIZE, COMMIT_RESERVE, READWRITE])
        .store_eax(ALLOCATED)
        .word(&[0x8B, 0x0D], BASE) // mov ecx, [BASE]
        .word(&[0xC7, 0x01], 0x1234_5678) // mov dword [ecx], 0x12345678
        .bytes(&[0x8B, 0x01]) // mov eax, [ecx]
        .store_eax(READ_BACK)
        .word(&[0xA1], BASE) // mov eax, [BASE]
        .store_eax(FREE_BASE)
        .call(services::NtFreeVirtualMemory, &[NT_CURRENT_PROCESS, FREE_BASE, FREE_SIZE, RELEASE])
        .store_eax(FREED)
        .call(services::NtClose, &[0x1234])
        .store_eax(CLOSED)
        .bytes(&[0x89, 0xE2]) // mov edx, esp
        .word(&[0xB8], NTOSKRNL.len() as u32)
        .bytes(&[0xCD, 0x2E])
        .store_eax(INVALID)
        .bytes(&[0x89, 0xE2])
        .word(&[0xB8], unimplemented)
        .bytes(&[0xCD, 0x2E])
        .store_eax(UNIMPLEMENTED)
        .int2e_at(services::NtClose, 0x10)
        .store_eax(UNMAPPED_ARGUMENTS)
        .int2e_at(services::NtClose, 0x8000_0000)
        .store_eax(KERNEL_ARGUMENTS)
        .call(services::NtAllocateVirtualMemory, &[NT_CURRENT_PROCESS, 0x20, 0, SIZE, COMMIT_RESERVE, READWRITE])
        .store_eax(UNMAPPED_OUT)
        // NtAllocateVirtualMemory(-1, ebx - GUARD_OFFSET, 0, SIZE, ...): the
        // base pointer is in the guard page under the committed top.
        .word(&[0x68], READWRITE)
        .word(&[0x68], COMMIT_RESERVE)
        .word(&[0x68], SIZE)
        .word(&[0x68], 0)
        .word(&[0x8D, 0x83], GUARD_OFFSET.wrapping_neg()) // lea eax, [ebx - GUARD_OFFSET]
        .bytes(&[0x50]) // push eax
        .word(&[0x68], NT_CURRENT_PROCESS)
        .bytes(&[0x89, 0xE2])
        .word(&[0xB8], services::NtAllocateVirtualMemory)
        .bytes(&[0xCD, 0x2E, 0x83, 0xC4, 24])
        .store_eax(GUARD_OUT)
        .call(services::NtTerminateProcess, &[0, 0xB0B])
        .store_eax(OTHERS)
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .word(&[0x83, 0x3D], GO) // cmp dword [GO], 0
        .bytes(&[0x00, 0x74, 0xF7]) // je back to the cmp
        .call(services::NtTerminateProcess, &[NT_CURRENT_PROCESS, 0x600D])
        .store_eax(AFTER_EXIT)
        .bytes(&[0xEB, 0xFE]);
    let main = code.0;
    assert!(main.len() <= 0x200, "the test program outgrew its slot");
    let mut text = [0xCC; 0x210];
    text[..main.len()].copy_from_slice(&main);
    text[0x200..0x202].copy_from_slice(&[0xEB, 0xFE]); // the other thread: jmp $
    let mut data = [0u8; 0x48];
    data[0x04..0x08].copy_from_slice(&0x2000u32.to_le_bytes());
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x210, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x48, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "services.exe", false).expect("a process");
    let thread = |start: u32| {
        let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
        (ps::create_thread(&process, start, &stack).expect("a thread"), stack)
    };
    let (other, _) = thread(IMAGE_BASE + 0x1200);
    let (main, stack) = thread(IMAGE_BASE + 0x1000);

    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    let status = |addr: u32| NtStatus(read(addr));
    let mut waited = 0;
    while read(DONE) == 0 {
        assert!(waited < 300, "the test program did not finish");
        // SAFETY: the boot thread, at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
        waited += 1;
    }
    let base = read(BASE);
    assert_eq!(status(ALLOCATED), STATUS_SUCCESS, "NtAllocateVirtualMemory");
    assert!(base != 0 && base % 0x1_0000 == 0, "base {base:#x}");
    assert_eq!((read(SIZE), read(READ_BACK)), (0x2000, 0x1234_5678));
    assert_eq!(
        (status(FREED), read(FREE_BASE), read(FREE_SIZE)),
        (STATUS_SUCCESS, base, 0x2000),
        "NtFreeVirtualMemory"
    );
    assert_eq!(status(CLOSED), STATUS_INVALID_HANDLE, "NtClose of a bad handle");
    assert_eq!(status(INVALID), STATUS_INVALID_SYSTEM_SERVICE, "a number past the table");
    assert_eq!(status(UNIMPLEMENTED), STATUS_NOT_IMPLEMENTED, "{}", NTOSKRNL[unimplemented as usize].name);
    assert_eq!(status(UNMAPPED_ARGUMENTS), STATUS_ACCESS_VIOLATION, "arguments at an unmapped address");
    assert_eq!(status(KERNEL_ARGUMENTS), STATUS_ACCESS_VIOLATION, "arguments in the kernel half");
    assert_eq!(status(UNMAPPED_OUT), STATUS_ACCESS_VIOLATION, "an out pointer at an unmapped address");
    assert_eq!(status(GUARD_OUT), STATUS_SUCCESS, "an out pointer in the stack guard page");
    // The lowest free range: the one released above, so it is free again.
    assert_eq!(read(stack.stack_base - GUARD_OFFSET), base, "the freed range was not reused");
    let limit = read(main.teb() + 8);
    assert_eq!(limit, stack.stack_base - 0x2000, "the kernel's fault did not grow the stack");
    assert_eq!(status(OTHERS), STATUS_SUCCESS, "NtTerminateProcess(NULL)");
    let object = other.dispatcher_object().expect("a started thread");
    // SAFETY: the object of a thread held here.
    let ended =
        unsafe { ke_wait_for_single_object::<KePlatform>(object, ProcessorMode::Kernel, false, Some(-3000 * MS)) };
    assert_eq!((ended, other.exit_status()), (STATUS_WAIT_0, NtStatus(0xB0B)), "the other thread did not end");
    assert_eq!(process.active_threads(), 1, "NtTerminateProcess(NULL) ended the caller");

    process.write_memory(u64::from(GO), &1u32.to_le_bytes()).expect("let the program go on");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!((ended, process.exit_status()), (STATUS_WAIT_0, NtStatus(0x600D)), "NtTerminateProcess on itself");
    assert_eq!(main.exit_status(), NtStatus(0x600D));
    ps::wait_for_reaper();
    log::info!(
        "[smoke] sys: system services from user mode: {} of {} ntoskrnl services, the rest STATUS_NOT_IMPLEMENTED",
        sys::IMPLEMENTED.len(),
        NTOSKRNL.len()
    );
}

/// Ps: a thread that runs, and ends, before `create_thread` returns to its
/// creator. A kernel thread below `NORMAL_PRIORITY` creates a process whose
/// thread, at `NORMAL_PRIORITY`, preempts it as soon as it is ready and ends
/// its process at once (NtTerminateProcess on itself); the reaper then takes
/// a thread whose creator has not resumed. Its Ke thread must be known by
/// then (it once was published only after `create_user_thread` returned).
fn early_exit_self_test() {
    use abi::ntstatus::{NtStatus, STATUS_WAIT_0};
    use abi::process::NT_CURRENT_PROCESS;
    use abi::services;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_wait_for_single_object, ProcessorMode};
    use ke::sched::{KePlatform, NORMAL_PRIORITY};
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;

    /// What the creator gets and gives back.
    struct Creation {
        section: Arc<Section>,
        process: Option<Arc<ob::Object<ps::EProcess>>>,
        /// The creator's priority while it creates the thread.
        priority: u8,
    }

    fn creator(context: *mut core::ffi::c_void) {
        // SAFETY: the boot thread keeps the `Creation` until this thread ends.
        let creation = unsafe { &mut *context.cast::<Creation>() };
        creation.priority = ke::sched::current_priority();
        let info = creation.section.image().expect("an image").info;
        let process =
            ps::create_process(&ps::system_process(), &creation.section, "early.exe", false).expect("a process");
        let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
        ps::create_thread(&process, IMAGE_BASE + 0x1000, &stack).expect("a thread");
        creation.process = Some(process);
    }

    let mut code = Code::new();
    code.call(services::NtTerminateProcess, &[NT_CURRENT_PROCESS, 0x600D]).bytes(&[0xEB, 0xFE]);
    let mut text = [0xCC; 0x40];
    text[..code.0.len()].copy_from_slice(&code.0);
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x40, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let mut creation = Creation { section, process: None, priority: 0 };
    let context = core::ptr::addr_of_mut!(creation).cast();
    // `creation` outlives the thread, which this thread waits for.
    let tid = spawn_kernel_thread(NORMAL_PRIORITY - 1, creator, context);
    let object = ke::sched::thread_object(tid).expect("the creator's object");
    // SAFETY: a thread object lives as long as its thread's slot.
    let ended =
        unsafe { ke_wait_for_single_object::<KePlatform>(object, ProcessorMode::Kernel, false, Some(-3000 * MS)) };
    assert_eq!(ended, STATUS_WAIT_0, "the creator did not finish");
    assert!(creation.priority < NORMAL_PRIORITY, "the creator does not run below its thread");
    let process = creation.process.take().expect("the creator made a process");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!((ended, process.exit_status()), (STATUS_WAIT_0, NtStatus(0x600D)), "the process did not end");
    drop(process);
    ps::wait_for_reaper();
    log::info!("[smoke] Ps: a thread that ends before its creator resumes is reaped");
}

/// The services ntdll's loader calls (spike S1, `sys`): from a Ps process,
/// NtQuerySystemInformation(SystemBasicInformation) with its exact size,
/// then with a size one byte short and one too large
/// (`STATUS_INFO_LENGTH_MISMATCH`, the size still returned), an unmapped and
/// a misaligned buffer, and a class without a handler; NtProtectVirtualMemory
/// on part of a page (the whole page changes, the range comes back rounded,
/// with the old protection), on two pages, on a reserved page
/// (`STATUS_NOT_COMMITTED`) and with an invalid protection;
/// NtQueryVirtualMemory on those pages, the reserved page, the image, a free
/// range, with a short buffer and on a kernel address.
fn loader_services_self_test() {
    use abi::ntstatus::{
        NtStatus, STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
        STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER, STATUS_NOT_COMMITTED, STATUS_NOT_IMPLEMENTED,
        STATUS_SUCCESS, STATUS_WAIT_0,
    };
    use abi::process::NT_CURRENT_PROCESS;
    use abi::services;
    use abi::system_information::SYSTEM_BASIC_INFORMATION;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    // SYSTEM_BASIC_INFORMATION, and the length returned with it.
    const BASIC: u32 = DATA;
    const BASIC_LENGTH: u32 = DATA + 0x30;
    // Statuses, and the length returned on a mismatch.
    const QUERIED: u32 = DATA + 0x40;
    const SHORT: u32 = DATA + 0x44;
    const SHORT_LENGTH: u32 = DATA + 0x48;
    const UNMAPPED: u32 = DATA + 0x4C;
    const MISALIGNED: u32 = DATA + 0x50;
    const UNKNOWN_CLASS: u32 = DATA + 0x54;
    const LONG: u32 = DATA + 0x58;
    // NtProtectVirtualMemory: two committed pages and a reserved one, the
    // ranges passed and returned, the old protections and the statuses.
    const PAGES: u32 = DATA + 0x60;
    const PAGES_SIZE: u32 = DATA + 0x64;
    const RESERVED: u32 = DATA + 0x68;
    const RESERVED_SIZE: u32 = DATA + 0x6C;
    const PART: u32 = DATA + 0x70;
    const PART_SIZE: u32 = DATA + 0x74;
    const PART_OLD: u32 = DATA + 0x78;
    const PART_STATUS: u32 = DATA + 0x7C;
    const BOTH: u32 = DATA + 0x80;
    const BOTH_SIZE: u32 = DATA + 0x84;
    const BOTH_OLD: u32 = DATA + 0x88;
    const BOTH_STATUS: u32 = DATA + 0x8C;
    const RESERVED_STATUS: u32 = DATA + 0x90;
    const INVALID_STATUS: u32 = DATA + 0x94;
    const OLD: u32 = DATA + 0x98;
    const DONE: u32 = DATA + 0x9C;
    // NtQueryVirtualMemory: statuses, the length returned, and four
    // MEMORY_BASIC_INFORMATION.
    const QUERIES: u32 = DATA + 0xA0; // committed, reserved, image, free
    const SHORT_QUERY: u32 = DATA + 0xB0;
    const KERNEL_QUERY: u32 = DATA + 0xB4;
    const QUERY_LENGTH: u32 = DATA + 0xB8;
    const MBI: [u32; 4] = [DATA + 0x120, DATA + 0x140, DATA + 0x160, DATA + 0x180];
    const COMMIT_RESERVE: u32 = 0x3000;
    const RESERVE: u32 = 0x2000;
    const READONLY: u32 = 0x02;
    const READWRITE: u32 = 0x04;
    // SystemProcessInformation: not implemented.
    const PROCESS_INFORMATION: u32 = 5;
    const SCRATCH: u32 = DATA + 0x100;

    let query = services::NtQuerySystemInformation;
    let mut code = Code::new();
    code.call(query, &[SYSTEM_BASIC_INFORMATION, BASIC, 0x2C, BASIC_LENGTH])
        .store_eax(QUERIED)
        .call(query, &[SYSTEM_BASIC_INFORMATION, SCRATCH, 0x2B, SHORT_LENGTH])
        .store_eax(SHORT)
        .call(query, &[SYSTEM_BASIC_INFORMATION, SCRATCH, 0x30, 0])
        .store_eax(LONG)
        .call(query, &[SYSTEM_BASIC_INFORMATION, 0x10, 0x2C, 0])
        .store_eax(UNMAPPED)
        .call(query, &[SYSTEM_BASIC_INFORMATION, SCRATCH + 2, 0x2C, 0])
        .store_eax(MISALIGNED)
        .call(query, &[PROCESS_INFORMATION, SCRATCH, 0x100, 0])
        .store_eax(UNKNOWN_CLASS);
    let set = |code: &mut Code, at: u32, value: u32| {
        code.word(&[0xC7, 0x05], at).bytes(&value.to_le_bytes());
    };
    let allocate = services::NtAllocateVirtualMemory;
    let protect = services::NtProtectVirtualMemory;
    set(&mut code, PAGES_SIZE, 0x2000);
    set(&mut code, RESERVED_SIZE, 0x1000);
    code.call(allocate, &[NT_CURRENT_PROCESS, PAGES, 0, PAGES_SIZE, COMMIT_RESERVE, READWRITE])
        .call(allocate, &[NT_CURRENT_PROCESS, RESERVED, 0, RESERVED_SIZE, RESERVE, READWRITE])
        // 16 bytes in the first page, then both pages.
        .word(&[0xA1], PAGES) // mov eax, [PAGES]
        .store_eax(BOTH)
        .bytes(&[0x83, 0xC0, 0x10]) // add eax, 0x10
        .store_eax(PART);
    set(&mut code, PART_SIZE, 0x10);
    set(&mut code, BOTH_SIZE, 0x2000);
    code.call(protect, &[NT_CURRENT_PROCESS, PART, PART_SIZE, READONLY, PART_OLD])
        .store_eax(PART_STATUS)
        .call(protect, &[NT_CURRENT_PROCESS, BOTH, BOTH_SIZE, READWRITE, BOTH_OLD])
        .store_eax(BOTH_STATUS)
        .call(protect, &[NT_CURRENT_PROCESS, RESERVED, RESERVED_SIZE, READONLY, OLD])
        .store_eax(RESERVED_STATUS)
        .call(protect, &[NT_CURRENT_PROCESS, BOTH, BOTH_SIZE, 0x03, OLD])
        .store_eax(INVALID_STATUS);
    let query_vm = services::NtQueryVirtualMemory;
    // The committed pages and the reserved one: their address from memory.
    for (i, at) in [PAGES, RESERVED].into_iter().enumerate() {
        code.word(&[0x68], QUERY_LENGTH)
            .word(&[0x68], 0x1C)
            .word(&[0x68], MBI[i])
            .word(&[0x68], 0)
            .word(&[0xFF, 0x35], at) // push dword [at]
            .word(&[0x68], NT_CURRENT_PROCESS)
            .bytes(&[0x89, 0xE2]) // mov edx, esp
            .word(&[0xB8], query_vm)
            .bytes(&[0xCD, 0x2E, 0x83, 0xC4, 24])
            .store_eax(QUERIES + 4 * i as u32);
    }
    code.call(query_vm, &[NT_CURRENT_PROCESS, IMAGE_BASE + 0x10, 0, MBI[2], 0x1C, 0])
        .store_eax(QUERIES + 8)
        .call(query_vm, &[NT_CURRENT_PROCESS, 0x7000_0000, 0, MBI[3], 0x1C, 0])
        .store_eax(QUERIES + 12)
        .call(query_vm, &[NT_CURRENT_PROCESS, IMAGE_BASE, 0, SCRATCH, 0x1B, 0])
        .store_eax(SHORT_QUERY)
        .call(query_vm, &[NT_CURRENT_PROCESS, 0x8000_0000, 0, SCRATCH, 0x1C, 0])
        .store_eax(KERNEL_QUERY)
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .bytes(&[0xEB, 0xFE]); // jmp $
    let mut text = [0xCC; 0x400];
    assert!(code.0.len() <= text.len(), "the test program outgrew its slot");
    text[..code.0.len()].copy_from_slice(&code.0);
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x400, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x200, &[], pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "loader.exe", false).expect("a process");
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    ps::create_thread(&process, IMAGE_BASE + 0x1000, &stack).expect("a thread");
    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    let status = |addr: u32| NtStatus(read(addr));
    for waited in 0.. {
        if read(DONE) != 0 {
            break;
        }
        assert!(waited < 300, "the test program did not finish");
        // SAFETY: the boot thread, at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
    }

    assert_eq!((status(QUERIED), read(BASIC_LENGTH)), (STATUS_SUCCESS, 0x2C), "SystemBasicInformation");
    let basic: [u32; 11] = core::array::from_fn(|i| read(BASIC + 4 * i as u32));
    assert_eq!(basic[1], hal::timer::MAXIMUM_INCREMENT, "TimerResolution");
    assert_eq!((basic[2], basic[6]), (0x1000, 0x1_0000), "PageSize, AllocationGranularity");
    let pages = mm::pfn::stats();
    assert!(basic[3] > 0 && u64::from(basic[3]) <= pages.tracked, "NumberOfPhysicalPages {}", basic[3]);
    assert_eq!((basic[4], u64::from(basic[5])), (1, pages.tracked - 1), "lowest and highest physical pages");
    assert_eq!((basic[7], basic[8]), (0x1_0000, 0x7FFE_FFFF), "the user-mode address range");
    assert_eq!((basic[9], basic[10] & 0xFF), (1, 1), "one processor");
    assert_eq!(
        (status(SHORT), read(SHORT_LENGTH), read(SCRATCH)),
        (STATUS_INFO_LENGTH_MISMATCH, 0x2C, 0),
        "a short buffer gets nothing but the size"
    );
    assert_eq!((status(LONG), read(SCRATCH)), (STATUS_INFO_LENGTH_MISMATCH, 0), "the size must be exact");
    assert_eq!(status(UNMAPPED), STATUS_ACCESS_VIOLATION, "an unmapped buffer");
    assert_eq!(status(MISALIGNED), STATUS_DATATYPE_MISALIGNMENT, "a misaligned buffer");
    assert_eq!(status(UNKNOWN_CLASS), STATUS_NOT_IMPLEMENTED, "SystemProcessInformation");
    let pages = read(PAGES);
    assert_ne!(pages, 0, "NtAllocateVirtualMemory");
    assert_eq!(
        (status(PART_STATUS), read(PART), read(PART_SIZE), read(PART_OLD)),
        (STATUS_SUCCESS, pages, 0x1000, READWRITE),
        "NtProtectVirtualMemory on 16 bytes: the whole page, rounded"
    );
    assert_eq!(
        (status(BOTH_STATUS), read(BOTH), read(BOTH_SIZE), read(BOTH_OLD)),
        (STATUS_SUCCESS, pages, 0x2000, READONLY),
        "NtProtectVirtualMemory on both pages: the first one's old protection"
    );
    assert_eq!(status(RESERVED_STATUS), STATUS_NOT_COMMITTED, "a reserved page");
    assert_eq!(status(INVALID_STATUS), STATUS_INVALID_PAGE_PROTECTION, "PAGE_READONLY | PAGE_NOACCESS");
    let protection = process.with_space(|space| space.query(u64::from(pages))).expect("the space").expect("a range");
    assert_eq!((protection.protect.bits(), protection.region_size), (READWRITE, 0x2000), "the VAD after both");
    let statuses: [NtStatus; 4] = core::array::from_fn(|i| status(QUERIES + 4 * i as u32));
    assert_eq!(statuses, [STATUS_SUCCESS; 4], "NtQueryVirtualMemory");
    assert_eq!(read(QUERY_LENGTH), 0x1C, "the length returned");
    // BaseAddress, AllocationBase, AllocationProtect, RegionSize, State,
    // Protect, Type.
    let mbi = |i: usize| -> [u32; 7] { core::array::from_fn(|f| read(MBI[i] + 4 * f as u32)) };
    let reserved = read(RESERVED);
    assert_eq!(mbi(0), [pages, pages, READWRITE, 0x2000, 0x1000, READWRITE, 0x2_0000], "two committed pages");
    assert_eq!(mbi(1), [reserved, reserved, READWRITE, 0x1000, 0x2000, 0, 0x2_0000], "a reserved page");
    let image = mbi(2);
    assert_eq!((image[0], image[1], image[6]), (IMAGE_BASE, IMAGE_BASE, 0x100_0000), "the image's headers");
    let free = mbi(3);
    assert_eq!((free[0], free[1], free[4], free[5], free[6]), (0x7000_0000, 0, 0x1_0000, 0x01, 0), "a free range");
    assert_eq!(status(SHORT_QUERY), STATUS_INFO_LENGTH_MISMATCH, "a short buffer");
    assert_eq!(status(KERNEL_QUERY), STATUS_INVALID_PARAMETER, "a kernel address");

    ps::terminate_process(process.clone(), NtStatus(0x600D)).expect("end the test program");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!(ended, STATUS_WAIT_0, "the test program did not end");
    drop(process);
    ps::wait_for_reaper();
    log::info!(
        "[smoke] sys: the loader's services: NtQuerySystemInformation(SystemBasicInformation), NtProtectVirtualMemory, \
         NtQueryVirtualMemory"
    );
}

/// The registry services (`cm`, `sys::registry`, M4): a hive built here is
/// mounted at `\REGISTRY\MACHINE\MinoTest`; from a Ps process, NtOpenKey by
/// absolute name, relative to an open key, and on a missing key (its handle
/// zeroed); NtQueryValueKey in its partial and full classes, with a buffer
/// that only holds the fixed part (`STATUS_BUFFER_OVERFLOW`) and one that
/// does not (`STATUS_BUFFER_TOO_SMALL`), on a missing value, a bad handle and
/// a handle without `KEY_QUERY_VALUE`; NtEnumerateKey, NtQueryKey and
/// NtEnumerateValueKey, to their end.
fn registry_self_test() {
    use abi::ntstatus::{
        NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_HANDLE,
        STATUS_NO_MORE_ENTRIES, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS, STATUS_WAIT_0,
    };
    use abi::registry::{
        KEY_BASIC_INFORMATION, KEY_FULL_INFORMATION, KEY_SET_VALUE, KEY_VALUE_BASIC_INFORMATION,
        KEY_VALUE_FULL_INFORMATION, KEY_VALUE_PARTIAL_INFORMATION, REG_DWORD, REG_SZ,
    };
    use abi::services;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;
    use regf::builder::{build, KeyNode};

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    const KEY_READ: u32 = 0x0002_0019;
    // Statuses, handles, result lengths.
    const STATUS: u32 = DATA;
    const H1: u32 = DATA + 0x40;
    const H2: u32 = DATA + 0x44;
    const H3: u32 = DATA + 0x48;
    const H4: u32 = DATA + 0x4C;
    const LENGTH: u32 = DATA + 0x50;
    // OBJECT_ATTRIBUTES, UNICODE_STRING, buffers, the strings.
    const OA_SUB: u32 = DATA + 0x80;
    const OA_DEEP: u32 = DATA + 0x98;
    const OA_MISSING: u32 = DATA + 0xB0;
    const US_SUB: usize = 0xC8;
    const US_TEXT: usize = 0xD0;
    const US_DWORD: usize = 0xD8;
    const US_MISSING: usize = 0xE0;
    const US_DEEP: usize = 0xE8;
    const US_NOPE: usize = 0xF0;
    const BUFFER: u32 = DATA + 0x100; // nine of 0x40 bytes
    const DONE: u32 = DATA + 0x3FC;
    const TEXT: &str = "hello registry";

    // The hive.
    let mut root = KeyNode::new("MINOTEST");
    let sub = root.key_mut("Sub");
    let text: alloc::vec::Vec<u8> = TEXT.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    sub.set_value("Text", REG_SZ, text.clone());
    sub.set_value("Dword", REG_DWORD, 0x1234_5678u32.to_le_bytes().to_vec());
    sub.set_value("", REG_SZ, "def\0".encode_utf16().flat_map(u16::to_le_bytes).collect());
    sub.key_mut("Deep");
    let registry = cm::registry().expect("Cm initialised");
    let hive = cm::HiveFile::new(Arc::from(build(&root, "MINOTEST"))).expect("a hive");
    cm::mount(&registry, "MACHINE", "MinoTest", hive).expect("mount the test hive");

    // The program's data: strings and their UNICODE_STRING, the attributes.
    let mut data = alloc::vec![0u8; 0x600];
    let mut strings = 0x400usize;
    let mut unicode = |data: &mut alloc::vec::Vec<u8>, at: usize, text: &str| {
        let units: alloc::vec::Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        data[strings..strings + units.len()].copy_from_slice(&units);
        let length = units.len() as u16;
        data[at..at + 2].copy_from_slice(&length.to_le_bytes());
        data[at + 2..at + 4].copy_from_slice(&length.to_le_bytes());
        data[at + 4..at + 8].copy_from_slice(&(DATA + strings as u32).to_le_bytes());
        strings += units.len().next_multiple_of(4);
    };
    unicode(&mut data, US_SUB, "\\Registry\\Machine\\MinoTest\\Sub");
    unicode(&mut data, US_TEXT, "Text");
    unicode(&mut data, US_DWORD, "dword");
    unicode(&mut data, US_MISSING, "Missing");
    unicode(&mut data, US_DEEP, "deep");
    unicode(&mut data, US_NOPE, "\\Registry\\Machine\\MinoTest\\Nope");
    for (oa, name) in [(OA_SUB, US_SUB), (OA_DEEP, US_DEEP), (OA_MISSING, US_NOPE)] {
        let at = (oa - DATA) as usize;
        data[at..at + 4].copy_from_slice(&24u32.to_le_bytes());
        data[at + 8..at + 12].copy_from_slice(&(DATA + name as u32).to_le_bytes());
    }
    // H3 starts non-zero: a failed open must zero it.
    data[0x48..0x4C].copy_from_slice(&u32::MAX.to_le_bytes());
    let us = |at: usize| Arg::Value(DATA + at as u32);
    let buffer = |i: u32| Arg::Value(BUFFER + 0x40 * i);
    let length = |i: u32| Arg::Value(LENGTH + 4 * i);
    let status = |i: u32| STATUS + 4 * i;
    let (open, query_value) = (services::NtOpenKey, services::NtQueryValueKey);
    let v = Arg::Value;

    let mut code = Code::new();
    code.call_args(open, &[v(H1), v(KEY_READ), v(OA_SUB)])
        .store_eax(status(0))
        .call_args(
            query_value,
            &[Arg::Memory(H1), us(US_TEXT), v(KEY_VALUE_PARTIAL_INFORMATION), buffer(0), v(0x40), length(0)],
        )
        .store_eax(status(1))
        .call_args(
            query_value,
            &[Arg::Memory(H1), us(US_DWORD), v(KEY_VALUE_FULL_INFORMATION), buffer(1), v(0x40), length(1)],
        )
        .store_eax(status(2))
        .call_args(
            query_value,
            &[Arg::Memory(H1), us(US_TEXT), v(KEY_VALUE_PARTIAL_INFORMATION), buffer(2), v(16), length(2)],
        )
        .store_eax(status(3))
        .call_args(
            query_value,
            &[Arg::Memory(H1), us(US_TEXT), v(KEY_VALUE_PARTIAL_INFORMATION), buffer(3), v(8), length(3)],
        )
        .store_eax(status(4))
        .call_args(
            query_value,
            &[Arg::Memory(H1), us(US_MISSING), v(KEY_VALUE_PARTIAL_INFORMATION), buffer(8), v(0x40), length(4)],
        )
        .store_eax(status(5))
        // OA_DEEP.RootDirectory = H1, then "deep" relative to it.
        .word(&[0xA1], H1)
        .store_eax(OA_DEEP + 4)
        .call_args(open, &[v(H2), v(KEY_READ), v(OA_DEEP)])
        .store_eax(status(6))
        .call_args(
            services::NtEnumerateKey,
            &[Arg::Memory(H1), v(0), v(KEY_BASIC_INFORMATION), buffer(4), v(0x40), length(5)],
        )
        .store_eax(status(7))
        .call_args(
            services::NtEnumerateKey,
            &[Arg::Memory(H1), v(1), v(KEY_BASIC_INFORMATION), buffer(8), v(0x40), length(6)],
        )
        .store_eax(status(8))
        .call_args(services::NtQueryKey, &[Arg::Memory(H1), v(KEY_FULL_INFORMATION), buffer(5), v(0x40), length(7)])
        .store_eax(status(9))
        .call_args(
            services::NtEnumerateValueKey,
            &[Arg::Memory(H1), v(0), v(KEY_VALUE_BASIC_INFORMATION), buffer(6), v(0x40), length(8)],
        )
        .store_eax(status(10))
        .call_args(
            services::NtEnumerateValueKey,
            &[Arg::Memory(H1), v(3), v(KEY_VALUE_BASIC_INFORMATION), buffer(8), v(0x40), length(9)],
        )
        .store_eax(status(11))
        .call_args(open, &[v(H3), v(KEY_READ), v(OA_MISSING)])
        .store_eax(status(12))
        .call_args(
            query_value,
            &[v(0x1234), us(US_TEXT), v(KEY_VALUE_PARTIAL_INFORMATION), buffer(8), v(0x40), length(10)],
        )
        .store_eax(status(13))
        .call_args(open, &[v(H4), v(KEY_SET_VALUE), v(OA_SUB)])
        .store_eax(status(14))
        .call_args(
            query_value,
            &[Arg::Memory(H4), us(US_TEXT), v(KEY_VALUE_PARTIAL_INFORMATION), buffer(8), v(0x40), length(11)],
        )
        .store_eax(status(15))
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .bytes(&[0xEB, 0xFE]); // jmp $
    let mut image_text = [0xCC; 0x800];
    assert!(code.0.len() <= image_text.len(), "the test program outgrew its slot");
    image_text[..code.0.len()].copy_from_slice(&code.0);
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x800, &image_text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x600, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "registry.exe", false).expect("a process");
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    ps::create_thread(&process, IMAGE_BASE + 0x1000, &stack).expect("a thread");
    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    let bytes = |addr: u32, n: usize| {
        let mut bytes = alloc::vec![0u8; n];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        bytes
    };
    for waited in 0.. {
        if read(DONE) != 0 {
            break;
        }
        assert!(waited < 300, "the registry test program did not finish");
        // SAFETY: the boot thread, at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
    }
    let statuses: alloc::vec::Vec<NtStatus> = (0..16).map(|i| NtStatus(read(status(i)))).collect();
    let buf = |i: u32| BUFFER + 0x40 * i;
    let len = |i: u32| read(LENGTH + 4 * i);
    assert_eq!(statuses[0], STATUS_SUCCESS, "NtOpenKey by absolute name");
    assert_ne!(read(H1), 0);
    assert_eq!(statuses[1], STATUS_SUCCESS, "NtQueryValueKey, partial");
    assert_eq!((read(buf(0) + 4), read(buf(0) + 8), len(0)), (REG_SZ, 30, 42), "type, data length, result length");
    assert_eq!(bytes(buf(0) + 12, 30), text, "the string");
    assert_eq!(statuses[2], STATUS_SUCCESS, "NtQueryValueKey, full, without case");
    // Full: title, type, data offset, data length, name length; the name
    // "Dword" (10 bytes) after 20, the data aligned at 32.
    let full: [u32; 5] = core::array::from_fn(|i| read(buf(1) + 4 * i as u32));
    assert_eq!(full, [0, REG_DWORD, 32, 4, 10]);
    assert_eq!((read(buf(1) + 32), len(1)), (0x1234_5678, 36));
    assert_eq!((statuses[3], len(2), read(buf(2) + 8)), (STATUS_BUFFER_OVERFLOW, 42, 30), "the fixed part only fits");
    assert_eq!(read(buf(2) + 16), 0, "nothing past the 16 bytes asked for");
    assert_eq!((statuses[4], len(3), read(buf(3))), (STATUS_BUFFER_TOO_SMALL, 42, 0), "under the fixed part");
    assert_eq!(statuses[5], STATUS_OBJECT_NAME_NOT_FOUND, "a missing value");
    assert_eq!(statuses[6], STATUS_SUCCESS, "NtOpenKey relative to an open key");
    assert_ne!(read(H2), 0);
    assert_eq!((statuses[7], read(buf(4) + 12)), (STATUS_SUCCESS, 8), "NtEnumerateKey 0: Deep");
    assert_eq!(
        bytes(buf(4) + 16, 8),
        "Deep".encode_utf16().flat_map(u16::to_le_bytes).collect::<alloc::vec::Vec<u8>>()
    );
    assert_eq!(statuses[8], STATUS_NO_MORE_ENTRIES, "NtEnumerateKey past the end");
    assert_eq!(
        (statuses[9], read(buf(5) + 20), read(buf(5) + 32)),
        (STATUS_SUCCESS, 1, 3),
        "NtQueryKey: 1 subkey, 3 values"
    );
    assert_eq!(statuses[10], STATUS_SUCCESS, "NtEnumerateValueKey 0");
    assert_eq!(statuses[11], STATUS_NO_MORE_ENTRIES, "NtEnumerateValueKey past the end");
    assert_eq!((statuses[12], read(H3)), (STATUS_OBJECT_NAME_NOT_FOUND, 0), "a missing key, its handle zeroed");
    assert_eq!(statuses[13], STATUS_INVALID_HANDLE, "a bad handle");
    assert_eq!((statuses[14], statuses[15]), (STATUS_SUCCESS, STATUS_ACCESS_DENIED), "KEY_SET_VALUE does not read");

    ps::terminate_process(process.clone(), NtStatus(0x600D)).expect("end the test program");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!(ended, STATUS_WAIT_0, "the test program did not end");
    drop(process);
    ps::wait_for_reaper();
    cm::unmount(&registry, "MACHINE", "MinoTest").expect("unmount the test hive");
    log::info!(
        "[smoke] Cm: a mounted hive read from user mode: NtOpenKey, NtQueryValueKey, NtEnumerateKey, NtQueryKey, \
         NtEnumerateValueKey"
    );
}

/// The object directory services (`sys::object`, M4): from a Ps process,
/// NtCreateDirectoryObject (then `OBJ_OPENIF`: `STATUS_OBJECT_NAME_EXISTS`;
/// without it: `STATUS_OBJECT_NAME_COLLISION`), NtCreateSymbolicLinkObject
/// relative to the directory, NtOpenSymbolicLinkObject (the link itself),
/// NtOpenDirectoryObject through the link, on a missing name (its handle
/// zeroed) and on a key (`STATUS_OBJECT_TYPE_MISMATCH`). The directory's name
/// goes with its last handle.
fn object_directory_self_test() {
    use abi::ntstatus::{
        NtStatus, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_EXISTS, STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS, STATUS_WAIT_0,
    };
    use abi::object::OBJ_OPENIF;
    use abi::services;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    const STATUS: u32 = DATA; // 8 statuses
    const HANDLE: u32 = DATA + 0x20; // 8 handles
    const OA: u32 = DATA + 0x40; // 6 OBJECT_ATTRIBUTES of 24 bytes
    const US: usize = 0xD0; // 6 UNICODE_STRING
    const DONE: u32 = DATA + 0x1FC;
    const ALL_DIRECTORY: u32 = 0x000F_000F;
    const ALL_LINK: u32 = 0x000F_0001;
    const QUERY: u32 = 0x0001;

    let mut data = alloc::vec![0u8; 0x400];
    let mut strings = 0x200usize;
    let names = ["\\MinoDir", "Link", "\\MinoDir\\Link", "\\MinoDir\\Missing", "\\REGISTRY"];
    for (i, text) in names.iter().enumerate() {
        let units: alloc::vec::Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        data[strings..strings + units.len()].copy_from_slice(&units);
        let at = US + 8 * i;
        let length = units.len() as u16;
        data[at..at + 2].copy_from_slice(&length.to_le_bytes());
        data[at + 2..at + 4].copy_from_slice(&length.to_le_bytes());
        data[at + 4..at + 8].copy_from_slice(&(DATA + strings as u32).to_le_bytes());
        strings += units.len().next_multiple_of(4);
    }
    let us = |i: usize| DATA + (US + 8 * i) as u32;
    // OA 0: \MinoDir; 1: \MinoDir with OBJ_OPENIF; 2: Link (root set at run
    // time); 3: \MinoDir\Link; 4: \MinoDir\Missing; 5: \REGISTRY.
    for (i, (name, attributes)) in [(0, 0), (0, OBJ_OPENIF), (1, 0), (2, 0), (3, 0), (4, 0)].into_iter().enumerate() {
        let at = (OA - DATA) as usize + 24 * i;
        data[at..at + 4].copy_from_slice(&24u32.to_le_bytes());
        data[at + 8..at + 12].copy_from_slice(&us(name).to_le_bytes());
        data[at + 12..at + 16].copy_from_slice(&attributes.to_le_bytes());
    }
    // Handle 6 starts non-zero: a failed open must zero it.
    data[0x38..0x3C].copy_from_slice(&u32::MAX.to_le_bytes());
    let oa = |i: u32| Arg::Value(OA + 24 * i);
    let handle = |i: u32| Arg::Value(HANDLE + 4 * i);
    let status = |i: u32| STATUS + 4 * i;
    let v = Arg::Value;
    let (create_dir, open_dir) = (services::NtCreateDirectoryObject, services::NtOpenDirectoryObject);
    let mut code = Code::new();
    code.call_args(create_dir, &[handle(0), v(ALL_DIRECTORY), oa(0)])
        .store_eax(status(0))
        .call_args(create_dir, &[handle(1), v(ALL_DIRECTORY), oa(1)])
        .store_eax(status(1))
        .call_args(create_dir, &[handle(2), v(ALL_DIRECTORY), oa(0)])
        .store_eax(status(2))
        .word(&[0xA1], HANDLE) // mov eax, [handle 0]
        .store_eax(OA + 24 * 2 + 4) // OA 2's RootDirectory
        .call_args(services::NtCreateSymbolicLinkObject, &[handle(3), v(ALL_LINK), oa(2), v(us(0))])
        .store_eax(status(3))
        .call_args(services::NtOpenSymbolicLinkObject, &[handle(4), v(ALL_LINK), oa(3)])
        .store_eax(status(4))
        .call_args(open_dir, &[handle(5), v(QUERY), oa(3)])
        .store_eax(status(5))
        .call_args(open_dir, &[handle(6), v(QUERY), oa(4)])
        .store_eax(status(6))
        .call_args(open_dir, &[handle(7), v(QUERY), oa(5)])
        .store_eax(status(7))
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .bytes(&[0xEB, 0xFE]);
    let mut text = [0xCC; 0x400];
    assert!(code.0.len() <= text.len(), "the test program outgrew its slot");
    text[..code.0.len()].copy_from_slice(&code.0);
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x400, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x400, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "obdir.exe", false).expect("a process");
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    ps::create_thread(&process, IMAGE_BASE + 0x1000, &stack).expect("a thread");
    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    for waited in 0.. {
        if read(DONE) != 0 {
            break;
        }
        assert!(waited < 300, "the object directory test program did not finish");
        // SAFETY: the boot thread, at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
    }
    let statuses: alloc::vec::Vec<NtStatus> = (0..8).map(|i| NtStatus(read(status(i)))).collect();
    assert_eq!(
        &statuses[..3],
        &[STATUS_SUCCESS, STATUS_OBJECT_NAME_EXISTS, STATUS_OBJECT_NAME_COLLISION],
        "NtCreateDirectoryObject, again with OBJ_OPENIF, again without"
    );
    assert_eq!(statuses[3], STATUS_SUCCESS, "NtCreateSymbolicLinkObject relative to the directory");
    assert_eq!(statuses[4], STATUS_SUCCESS, "NtOpenSymbolicLinkObject");
    assert_eq!(statuses[5], STATUS_SUCCESS, "NtOpenDirectoryObject through the link");
    assert_eq!(
        (statuses[6], read(HANDLE + 24)),
        (STATUS_OBJECT_NAME_NOT_FOUND, 0),
        "a missing name, its handle zeroed"
    );
    assert_eq!(statuses[7], STATUS_OBJECT_TYPE_MISMATCH, "a key is not a directory");
    let ns = ob::namespace();
    let link =
        ns.open("\\MinoDir\\Link", None, Some(&ob::SYMBOLIC_LINK_TYPE), abi::object::OBJ_OPENLINK).expect("the link");
    assert_eq!(ob::downcast::<ob::SymbolicLink>(&link).expect("a link").target(), "\\MinoDir");
    drop(link);

    ps::terminate_process(process.clone(), NtStatus(0x600D)).expect("end the test program");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!(ended, STATUS_WAIT_0, "the test program did not end");
    drop(process);
    ps::wait_for_reaper();
    assert!(ns.open("\\MinoDir", None, None, 0).is_err(), "a temporary directory's name goes with its last handle");
    log::info!(
        "[smoke] Ob: object directories and links from user mode: NtCreateDirectoryObject, NtOpenDirectoryObject, \
         NtCreateSymbolicLinkObject, NtOpenSymbolicLinkObject"
    );
}

/// The user-mode gates (`sys::gates`, `hal::trap`, M3): from a Ps process,
/// `int 2Ah` gives the tick count, `int 2Eh` keeps EBX, ESI, EDI, EBP and FS
/// across a system service, `int 2Dh` prints through DbgPrint and skips the
/// byte after it (the `int 3` of ntdll), `int 2Bh` has no callback to return
/// from, and `int 2Ch`, without an exception dispatcher, ends the process
/// with `STATUS_ASSERTION_FAILURE`.
fn trap_gate_self_test() {
    use abi::ntstatus::{
        NtStatus, STATUS_ASSERTION_FAILURE, STATUS_INVALID_HANDLE, STATUS_NO_CALLBACK_ACTIVE, STATUS_WAIT_0,
    };
    use abi::services;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    const TICKS: u32 = DATA;
    const CLOSED: u32 = DATA + 0x04;
    const KEPT: u32 = DATA + 0x08; // EBX, ESI, EDI, EBP
    const TEB_SELF: u32 = DATA + 0x18;
    const PRINTED: u32 = DATA + 0x1C;
    const CALLBACK: u32 = DATA + 0x20;
    const DONE: u32 = DATA + 0x24;
    const GO: u32 = DATA + 0x28;
    const AFTER_ASSERTION: u32 = DATA + 0x2C;
    // DbgPrompt: the length of the answer, the answer, the prompt.
    const PROMPTED: u32 = DATA + 0x30;
    const ANSWER: u32 = DATA + 0x34;
    const MESSAGE: u32 = DATA + 0x40;
    const TEXT: &[u8] = b"hello from Mino user mode\n";
    const PROMPT: u32 = DATA + 0x60;
    const QUESTION: &[u8] = b"(boipt)? ";
    const KEPT_VALUES: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];

    let mut code = Code::new();
    code.bytes(&[0xCD, 0x2A])
        .store_eax(TICKS)
        // Across exactly one gate, so that two faults cannot cancel out.
        .word(&[0xBB], KEPT_VALUES[0]) // mov ebx, …
        .word(&[0xBE], KEPT_VALUES[1]) // mov esi, …
        .word(&[0xBF], KEPT_VALUES[2]) // mov edi, …
        .word(&[0xBD], KEPT_VALUES[3]) // mov ebp, …
        .call(services::NtClose, &[0x1234])
        .store_eax(CLOSED)
        .word(&[0x89, 0x1D], KEPT) // mov [KEPT], ebx
        .word(&[0x89, 0x35], KEPT + 4) // mov [KEPT + 4], esi
        .word(&[0x89, 0x3D], KEPT + 8) // mov [KEPT + 8], edi
        .word(&[0x89, 0x2D], KEPT + 12) // mov [KEPT + 12], ebp
        .bytes(&[0x64, 0xA1, 0x18, 0, 0, 0]) // mov eax, fs:[0x18]
        .store_eax(TEB_SELF)
        // DebugService(BREAKPOINT_PRINT, MESSAGE, length), then `inc eax`
        // where ntdll has its `int 3`: skipped, EAX stays the status.
        .word(&[0xB8], 1)
        .word(&[0xB9], MESSAGE)
        .word(&[0xBA], TEXT.len() as u32)
        .bytes(&[0xCD, 0x2D, 0x40])
        .store_eax(PRINTED)
        // DebugService(BREAKPOINT_PROMPT, PROMPT, length, ANSWER, 4): the
        // length of the answer in EAX.
        .word(&[0xB8], 2)
        .word(&[0xB9], PROMPT)
        .word(&[0xBA], QUESTION.len() as u32)
        .word(&[0xBB], ANSWER)
        .word(&[0xBF], 4)
        .bytes(&[0xCD, 0x2D, 0x40])
        .store_eax(PROMPTED)
        .bytes(&[0xCD, 0x2B])
        .store_eax(CALLBACK)
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .word(&[0x83, 0x3D], GO)
        .bytes(&[0x00, 0x74, 0xF7]) // until [GO] != 0
        .bytes(&[0xCD, 0x2C])
        .store_eax(AFTER_ASSERTION)
        .bytes(&[0xEB, 0xFE]);
    let mut text = [0xCC; 0x100];
    text[..code.0.len()].copy_from_slice(&code.0);
    let mut data = [0u8; 0x80];
    data[0x40..0x40 + TEXT.len()].copy_from_slice(TEXT);
    data[0x60..0x60 + QUESTION.len()].copy_from_slice(QUESTION);
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x100, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x80, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "gates.exe", false).expect("a process");
    let before = hal::timer::get_tick_count() as u32;
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    let thread = ps::create_thread(&process, IMAGE_BASE + 0x1000, &stack).expect("a thread");
    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    for waited in 0.. {
        if read(DONE) != 0 {
            break;
        }
        assert!(waited < 300, "the gate test program did not finish");
        // SAFETY: the boot thread, at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
    }
    let after = hal::timer::get_tick_count() as u32;
    let ticks = read(TICKS);
    assert!((before..=after).contains(&ticks), "int 2Ah gave {ticks}, not in [{before}, {after}]");
    assert_eq!(NtStatus(read(CLOSED)), STATUS_INVALID_HANDLE, "int 2Eh");
    let kept = [read(KEPT), read(KEPT + 4), read(KEPT + 8), read(KEPT + 12)];
    assert_eq!(kept, KEPT_VALUES, "a gate lost EBX, ESI, EDI or EBP");
    assert_eq!(read(TEB_SELF), thread.teb(), "a gate lost FS");
    assert_eq!(read(PRINTED), 0, "int 2Dh did not skip the byte after it");
    assert_eq!((read(PROMPTED), read(ANSWER)), (1, u32::from(b'i')), "DbgPrompt: no debugger answers `i`");
    assert_eq!(NtStatus(read(CALLBACK)), STATUS_NO_CALLBACK_ACTIVE, "int 2Bh");

    process.write_memory(u64::from(GO), &1u32.to_le_bytes()).expect("let the program go on");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!((ended, process.exit_status()), (STATUS_WAIT_0, STATUS_ASSERTION_FAILURE), "int 2Ch");
    ps::wait_for_reaper();
    log::info!("[smoke] gates: int 2Ah to 2Eh from user mode, registers kept across them, DbgPrompt answered");
}

/// The user-mode exceptions (`sys::exceptions`, `ke::exception`, M3): a Ps
/// process whose exception dispatcher stands in for ntdll's takes a write to
/// address 0, `int 3`, `ud2`, a division by zero, `hlt`, a selector past the
/// GDT and `int 2Ch` with FS null, each with its code, address and
/// parameters, FS on the TEB, and a CONTEXT that NtContinue resumes past the
/// instruction; NtRaiseException raises an exception from a context and
/// refuses 16 parameters, NtContinue a context it cannot read; a second
/// chance ends the process with the code.
fn exception_self_test() {
    use abi::context::{CONTEXT_CONTROL, CONTEXT_INTEGER};
    use abi::exception::{ExceptionRecord32, BREAKPOINT_BREAK, EXCEPTION_READ_FAULT, EXCEPTION_WRITE_FAULT};
    use abi::ntstatus::{
        NtStatus, STATUS_ACCESS_VIOLATION, STATUS_ASSERTION_FAILURE, STATUS_BREAKPOINT, STATUS_ILLEGAL_INSTRUCTION,
        STATUS_INTEGER_DIVIDE_BY_ZERO, STATUS_INVALID_PARAMETER, STATUS_PRIVILEGED_INSTRUCTION, STATUS_WAIT_0,
    };
    use abi::services;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const TEXT: u32 = IMAGE_BASE + 0x1000;
    const DISPATCHER: u32 = TEXT + 0x200;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    // The dispatcher's: its next slot, the bytes it skips, whether it gives
    // up (second chance), and what its system service returned.
    const SLOT: u32 = DATA;
    const SKIP: u32 = DATA + 0x04;
    const SECOND: u32 = DATA + 0x08;
    const FAILED: u32 = DATA + 0x0C;
    // Handshake with the kernel.
    const DONE: u32 = DATA + 0x10;
    const GO: u32 = DATA + 0x14;
    // ESP before the faults; EBX and ESP after them; EBX, ESP and EAX after
    // NtRaiseException, then what it returned; the two refusals.
    const ESP_BEFORE: u32 = DATA + 0x18;
    const KEPT: u32 = DATA + 0x1C;
    const RAISED: u32 = DATA + 0x24;
    const TOO_MANY: u32 = DATA + 0x34;
    const BAD_CONTEXT: u32 = DATA + 0x38;
    const RECORD: u32 = DATA + 0x40;
    const BAD_RECORD: u32 = DATA + 0x90;
    // One slot per exception: code, address, parameter count, two
    // parameters, EIP, EBX and ESP of the context, then the TEB through FS.
    const SLOTS: u32 = DATA + 0x100;
    const SLOT_SIZE: u32 = 0x40;
    const CONTEXT: u32 = DATA + 0x400;
    const MAGIC: u32 = 0x5EB0_0001;
    const RAISED_EBX: u32 = 0x5EB0_0002;
    const RAISED_EAX: u32 = 0x5EB0_0003;
    const RAISED_CODE: u32 = 0xE000_1234;
    const RAISED_AT: u32 = 0x1122_3344;

    /// `mov dword [SKIP], length`, then the faulting instruction: its
    /// address.
    fn fault(code: &mut Code, instruction: &[u8]) -> u32 {
        code.word(&[0xC7, 0x05], SKIP).bytes(&(instruction.len() as u32).to_le_bytes());
        let at = TEXT + code.0.len() as u32;
        code.bytes(instruction);
        at
    }

    let mut code = Code::new();
    code.word(&[0x89, 0x25], ESP_BEFORE) // mov [ESP_BEFORE], esp
        .word(&[0xBB], MAGIC); // mov ebx, MAGIC
    let write = fault(&mut code, &[0xA3, 0, 0, 0, 0]); // mov [0], eax
    let int3 = fault(&mut code, &[0xCC]);
    let ud2 = fault(&mut code, &[0x0F, 0x0B]);
    code.bytes(&[0x31, 0xC9]); // xor ecx, ecx
    let divide = fault(&mut code, &[0xF7, 0xF1]); // div ecx
    let hlt = fault(&mut code, &[0xF4]);
    code.word(&[0xB8], 0xFFFB); // mov eax, a selector past the GDT
    let selector = fault(&mut code, &[0x8E, 0xD8]); // mov ds, eax
    code.bytes(&[0x31, 0xC0, 0x8E, 0xE0]); // xor eax, eax; mov fs, eax
    let assertion = fault(&mut code, &[0xCD, 0x2C]);
    code.word(&[0x89, 0x1D], KEPT) // mov [KEPT], ebx
        .word(&[0x89, 0x25], KEPT + 4) // mov [KEPT + 4], esp
        .word(&[0xC7, 0x05], SKIP)
        .bytes(&0u32.to_le_bytes())
        .word(&[0x89, 0x25], CONTEXT + 0xC4) // the context's Esp
        .call(services::NtRaiseException, &[RECORD, CONTEXT, 1])
        .store_eax(RAISED + 12);
    // Where the context of NtRaiseException resumes.
    let resume = TEXT + code.0.len() as u32;
    code.store_eax(RAISED + 8)
        .word(&[0x89, 0x1D], RAISED) // mov [RAISED], ebx
        .word(&[0x89, 0x25], RAISED + 4) // mov [RAISED + 4], esp
        .call(services::NtRaiseException, &[BAD_RECORD, CONTEXT, 1])
        .store_eax(TOO_MANY)
        .call(services::NtContinue, &[0x10, 0])
        .store_eax(BAD_CONTEXT)
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .word(&[0x83, 0x3D], GO) // cmp dword [GO], 0
        .bytes(&[0x00, 0x74, 0xF7]) // je back to the cmp
        .word(&[0xC7, 0x05], SECOND)
        .bytes(&1u32.to_le_bytes());
    // A code of its own: an exception at the wrong place cannot end the
    // process with it.
    fault(&mut code, &[0x0F, 0x0B]);
    code.bytes(&[0xEB, 0xFE]);
    let main = code.0;
    assert!(main.len() <= 0x200, "the test program outgrew its slot");

    // The dispatcher, entered with ESP on the addresses of the record and
    // the context: it fills its slot, then NtContinue(context + skip, FALSE),
    // or NtRaiseException(record, context, FALSE) in second chance.
    let mut resume_code = Code::new();
    resume_code
        .bytes(&[0x6A, 0x00, 0x56, 0x89, 0xE2]) // push 0; push esi; mov edx, esp
        .word(&[0xB8], services::NtContinue)
        .bytes(&[0xCD, 0x2E])
        .store_eax(FAILED)
        .bytes(&[0xEB, 0xFE]);
    let mut dispatcher = Code::new();
    dispatcher
        .bytes(&[0x8B, 0x1C, 0x24]) // mov ebx, [esp]: the record
        .bytes(&[0x8B, 0x74, 0x24, 0x04]) // mov esi, [esp + 4]: the context
        .word(&[0x8B, 0x3D], SLOT); // mov edi, [SLOT]
                                    // The record's code, address, parameter count and two parameters:
                                    // mov eax, [ebx + offset]; mov [edi + 4i], eax.
    for (i, offset) in [0x00u8, 0x0C, 0x10, 0x14, 0x18].into_iter().enumerate() {
        dispatcher.bytes(&[0x8B, 0x43, offset, 0x89, 0x47, 4 * i as u8]);
    }
    // The context's Eip, Ebx and Esp: mov eax, [esi + offset]; mov [edi + 4i], eax.
    for (i, offset) in [0xB8u32, 0xA4, 0xC4].into_iter().enumerate() {
        dispatcher.word(&[0x8B, 0x86], offset).bytes(&[0x89, 0x47, 4 * (5 + i) as u8]);
    }
    dispatcher
        .bytes(&[0x64, 0xA1, 0x18, 0, 0, 0]) // mov eax, fs:[0x18]
        .bytes(&[0x89, 0x47, 0x20]) // mov [edi + 0x20], eax
        .word(&[0x83, 0x05], SLOT) // add dword [SLOT], SLOT_SIZE
        .bytes(&[SLOT_SIZE as u8])
        .word(&[0xA1], SKIP) // mov eax, [SKIP]
        .word(&[0x01, 0x86], 0xB8) // add [esi + Eip], eax
        .word(&[0x83, 0x3D], SECOND) // cmp dword [SECOND], 0
        .bytes(&[0x00, 0x75, resume_code.0.len() as u8]) // jne past NtContinue
        .bytes(&resume_code.0)
        .bytes(&[0x6A, 0x00, 0x56, 0x53, 0x89, 0xE2]) // push 0; push esi; push ebx; mov edx, esp
        .word(&[0xB8], services::NtRaiseException)
        .bytes(&[0xCD, 0x2E])
        .store_eax(FAILED)
        .bytes(&[0xEB, 0xFE]);
    assert!(dispatcher.0.len() <= 0x100, "the dispatcher outgrew its slot");

    let mut text = [0xCC; 0x300];
    text[..main.len()].copy_from_slice(&main);
    text[0x200..0x200 + dispatcher.0.len()].copy_from_slice(&dispatcher.0);
    let mut data = [0u8; 0x700];
    let mut put = |addr: u32, value: u32| {
        let at = (addr - DATA) as usize;
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    put(SLOT, SLOTS);
    // The context of NtRaiseException: it resumes after the call, with its
    // own EBX.
    put(CONTEXT, CONTEXT_CONTROL | CONTEXT_INTEGER);
    put(CONTEXT + 0xA4, RAISED_EBX);
    put(CONTEXT + 0xB0, RAISED_EAX);
    put(CONTEXT + 0xB8, resume);
    put(CONTEXT + 0xC0, 0x202);
    put(BAD_RECORD + 0x10, 16);
    let record = ExceptionRecord32::new(RAISED_CODE, RAISED_AT, &[0xAAAA, 0xBBBB]);
    let at = (RECORD - DATA) as usize;
    data[at..at + 0x50].copy_from_slice(record.as_bytes());
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x300, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x700, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "seh.exe", false).expect("a process");
    // ntdll's KiUserExceptionDispatcher, for every process, while it runs.
    ke::exception::set_user_exception_dispatcher(DISPATCHER);
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    let thread = ps::create_thread(&process, TEXT, &stack).expect("a thread");
    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    for waited in 0.. {
        if read(DONE) != 0 {
            break;
        }
        assert!(waited < 300, "the exception test program did not finish");
        // SAFETY: the boot thread, at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
    }
    assert_eq!(read(FAILED), 0, "NtContinue failed in the dispatcher");
    let slot = |i: u32| core::array::from_fn::<u32, 9, _>(|j| read(SLOTS + SLOT_SIZE * i + 4 * j as u32));
    let esp = read(ESP_BEFORE);
    let teb = thread.teb();
    let faults: [(NtStatus, u32, &[u32], &str); 7] = [
        (STATUS_ACCESS_VIOLATION, write, &[EXCEPTION_WRITE_FAULT, 0], "a write to address 0"),
        (STATUS_BREAKPOINT, int3, &[BREAKPOINT_BREAK], "int 3"),
        (STATUS_ILLEGAL_INSTRUCTION, ud2, &[], "ud2"),
        (STATUS_INTEGER_DIVIDE_BY_ZERO, divide, &[], "a division by zero"),
        (STATUS_PRIVILEGED_INSTRUCTION, hlt, &[], "hlt"),
        (STATUS_ACCESS_VIOLATION, selector, &[EXCEPTION_READ_FAULT, u32::MAX], "a selector past the GDT"),
        (STATUS_ASSERTION_FAILURE, assertion, &[], "int 2Ch with FS null"),
    ];
    for (i, &(code, at, parameters, what)) in faults.iter().enumerate() {
        let [got, address, count, first, second, eip, ebx, context_esp, fs_teb] = slot(i as u32);
        assert_eq!((NtStatus(got), address, eip), (code, at, at), "{what}: code, address, context EIP");
        assert_eq!(count as usize, parameters.len(), "{what}: parameter count");
        assert_eq!(&[first, second][..parameters.len()], parameters, "{what}: parameters");
        assert_eq!((ebx, context_esp), (MAGIC, esp), "{what}: context EBX and ESP");
        assert_eq!(fs_teb, teb, "{what}: the dispatcher's FS is not on the TEB");
    }
    assert_eq!((read(KEPT), read(KEPT + 4)), (MAGIC, esp), "NtContinue did not restore EBX and ESP");
    assert_eq!(
        slot(faults.len() as u32),
        [RAISED_CODE, RAISED_AT, 2, 0xAAAA, 0xBBBB, resume, RAISED_EBX, esp, teb],
        "the record and context of NtRaiseException"
    );
    assert_eq!(
        (read(RAISED), read(RAISED + 4), read(RAISED + 8), read(RAISED + 12)),
        (RAISED_EBX, esp, RAISED_EAX, 0),
        "the thread did not resume from the context of NtRaiseException"
    );
    assert_eq!(NtStatus(read(TOO_MANY)), STATUS_INVALID_PARAMETER, "NtRaiseException with 16 parameters");
    assert_eq!(NtStatus(read(BAD_CONTEXT)), STATUS_ACCESS_VIOLATION, "NtContinue of an unreadable context");

    process.write_memory(u64::from(GO), &1u32.to_le_bytes()).expect("let the program go on");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!((ended, process.exit_status()), (STATUS_WAIT_0, STATUS_ILLEGAL_INSTRUCTION), "the second chance");
    ke::exception::set_user_exception_dispatcher(0);
    ps::wait_for_reaper();
    log::info!(
        "[smoke] exceptions: faults, int 3 and NtRaiseException reach a user-mode dispatcher, NtContinue resumes"
    );
}

/// User APCs (`ke::apc`, `sys::apc`, M3): a Ps process whose APC dispatcher
/// stands in for ReactOS ntdll's (its SEH record between the CONTEXT and the
/// interrupted ESP) queues two APCs to itself, which a non-alertable wait
/// leaves queued and an alertable one runs in order, then returns
/// STATUS_USER_APC with its registers and its stack back; NtTestAlert runs a
/// third; an APC
/// that the kernel queues ends an alertable wait already blocked; a fifth
/// stays queued through a non-alertable wait, and is run down with the
/// process. A bad handle is refused.
fn user_apc_self_test() {
    use abi::ntstatus::{NtStatus, STATUS_INVALID_HANDLE, STATUS_SUCCESS, STATUS_USER_APC, STATUS_WAIT_0};
    use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
    use abi::services;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const TEXT: u32 = IMAGE_BASE + 0x1000;
    const DISPATCHER: u32 = TEXT + 0x200;
    const ROUTINE: u32 = TEXT + 0x280;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    // The routine's next log entry; what NtContinue returned to the
    // dispatcher.
    const LOG: u32 = DATA;
    const FAILED: u32 = DATA + 0x04;
    // Handshake with the kernel.
    const DONE: u32 = DATA + 0x08;
    const GO: u32 = DATA + 0x0C;
    const WAITING: u32 = DATA + 0x10;
    // Statuses, and the log pointer at two points.
    const QUEUED: u32 = DATA + 0x14; // two, then the bad handle
    const NON_ALERTABLE: u32 = DATA + 0x20;
    const NOT_YET: u32 = DATA + 0x24;
    const DELAYED: u32 = DATA + 0x28;
    const KEPT: u32 = DATA + 0x2C; // EBX, ESP
    const ESP_BEFORE: u32 = DATA + 0x34;
    const TESTED: u32 = DATA + 0x38; // NtQueueApcThread, NtTestAlert
    const WOKEN: u32 = DATA + 0x40;
    const STILL: u32 = DATA + 0x44; // NtQueueApcThread, NtDelayExecution
    const AFTER: u32 = DATA + 0x4C;
    // The arguments of the alertable wait, read back after its APCs.
    const ARGUMENTS: u32 = DATA + 0x60;
    // LARGE_INTEGER intervals: 10 ms and 5 s, relative.
    const SHORT: u32 = DATA + 0x50;
    const LONG: u32 = DATA + 0x58;
    // One entry per APC run: its context and two arguments.
    const LOG_START: u32 = DATA + 0x100;
    const MAGIC: u32 = 0xA9C0_0001;

    let queue = |code: &mut Code, first: u32| {
        code.call(services::NtQueueApcThread, &[NT_CURRENT_THREAD, ROUTINE, first, first + 1, first + 2]);
    };
    let mut code = Code::new();
    code.word(&[0x89, 0x25], ESP_BEFORE) // mov [ESP_BEFORE], esp
        .word(&[0xBB], MAGIC); // mov ebx, MAGIC
    queue(&mut code, 0x11);
    code.store_eax(QUEUED);
    queue(&mut code, 0x21);
    code.store_eax(QUEUED + 4)
        .call(services::NtQueueApcThread, &[0x1234, ROUTINE, 0, 0, 0])
        .store_eax(QUEUED + 8)
        .call(services::NtDelayExecution, &[0, SHORT])
        .store_eax(NON_ALERTABLE)
        .word(&[0xA1], LOG) // mov eax, [LOG]
        .store_eax(NOT_YET)
        // NtDelayExecution(TRUE, LONG), its arguments left on the stack
        // through the APCs, then read back.
        .word(&[0x68], LONG)
        .bytes(&[0x6A, 0x01, 0x89, 0xE2]) // push 1; mov edx, esp
        .word(&[0xB8], services::NtDelayExecution)
        .bytes(&[0xCD, 0x2E])
        .store_eax(DELAYED)
        .bytes(&[0x8B, 0x0C, 0x24]) // mov ecx, [esp]
        .word(&[0x89, 0x0D], ARGUMENTS) // mov [ARGUMENTS], ecx
        .bytes(&[0x8B, 0x4C, 0x24, 0x04]) // mov ecx, [esp + 4]
        .word(&[0x89, 0x0D], ARGUMENTS + 4)
        .bytes(&[0x83, 0xC4, 0x08]) // add esp, 8
        .word(&[0x89, 0x1D], KEPT) // mov [KEPT], ebx
        .word(&[0x89, 0x25], KEPT + 4); // mov [KEPT + 4], esp
    queue(&mut code, 0x31);
    code.store_eax(TESTED)
        .call(services::NtTestAlert, &[])
        .store_eax(TESTED + 4)
        .word(&[0xC7, 0x05], WAITING)
        .bytes(&1u32.to_le_bytes())
        .call(services::NtDelayExecution, &[1, LONG])
        .store_eax(WOKEN);
    queue(&mut code, 0x51);
    code.store_eax(STILL)
        .call(services::NtDelayExecution, &[0, SHORT])
        .store_eax(STILL + 4)
        .word(&[0xA1], LOG)
        .store_eax(AFTER)
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .word(&[0x83, 0x3D], GO) // cmp dword [GO], 0
        .bytes(&[0x00, 0x74, 0xF7]) // je back to the cmp
        .call(services::NtTerminateProcess, &[NT_CURRENT_PROCESS, 0x600D])
        .bytes(&[0xEB, 0xFE]);
    let main = code.0;
    assert!(main.len() <= 0x200, "the test program outgrew its slot");

    // The dispatcher, entered with ESP on the routine, its context, its two
    // arguments, then the CONTEXT: like ReactOS's, it writes its SEH record
    // past the CONTEXT, calls the routine, then NtContinue(context, TRUE).
    let mut dispatcher = Code::new();
    dispatcher
        .word(&[0x8D, 0x84, 0x24], 16 + 0x2CC) // lea eax, [esp + 16 + CONTEXT]
        .word(&[0xC7, 0x00], 0x5E5E_5E5E) // mov dword [eax], …
        .bytes(&[0xC7, 0x40, 0x04])
        .bytes(&0x5E5E_5E5Eu32.to_le_bytes()) // mov dword [eax + 4], …
        .bytes(&[0x58, 0xFF, 0xD0]) // pop eax; call eax
        .bytes(&[0x89, 0xE1, 0x6A, 0x01, 0x51, 0x89, 0xE2]) // mov ecx, esp; push 1; push ecx; mov edx, esp
        .word(&[0xB8], services::NtContinue)
        .bytes(&[0xCD, 0x2E])
        .store_eax(FAILED)
        .bytes(&[0xEB, 0xFE]);
    // The routine, stdcall (context, argument1, argument2): logs them.
    let mut routine = Code::new();
    routine.word(&[0x8B, 0x3D], LOG); // mov edi, [LOG]
    for i in 0..3u8 {
        routine.bytes(&[0x8B, 0x44, 0x24, 4 + 4 * i, 0x89, 0x47, 4 * i]); // mov eax, [esp + 4 + 4i]; mov [edi + 4i], eax
    }
    routine
        .word(&[0x83, 0x05], LOG) // add dword [LOG], 12
        .bytes(&[12, 0xC2, 12, 0]); // ret 12

    let mut text = [0xCC; 0x300];
    text[..main.len()].copy_from_slice(&main);
    text[0x200..0x200 + dispatcher.0.len()].copy_from_slice(&dispatcher.0);
    text[0x280..0x280 + routine.0.len()].copy_from_slice(&routine.0);
    let mut data = [0u8; 0x200];
    data[0..4].copy_from_slice(&LOG_START.to_le_bytes());
    data[0x50..0x58].copy_from_slice(&(-10 * MS).to_le_bytes());
    data[0x58..0x60].copy_from_slice(&(-5000 * MS).to_le_bytes());
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x300, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x200, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "apc.exe", false).expect("a process");
    // ntdll's KiUserApcDispatcher, for every process, while it runs.
    ke::apc::set_user_apc_dispatcher(DISPATCHER);
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    let thread = ps::create_thread(&process, TEXT, &stack).expect("a thread");
    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    let wait_for = |addr: u32, what: &str| {
        for waited in 0.. {
            if read(addr) != 0 {
                break;
            }
            assert!(waited < 300, "the APC test program did not reach {what}");
            // SAFETY: the boot thread, at PASSIVE_LEVEL.
            unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
        }
    };
    wait_for(WAITING, "its alertable wait");
    // Into its 5 s wait, then an APC from here ends it.
    // SAFETY: as above.
    unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -50 * MS) };
    thread.queue_user_apc(ROUTINE, 0x41, 0x42, 0x43).expect("an APC for a live thread");
    wait_for(DONE, "its end");

    let status = |addr: u32| NtStatus(read(addr));
    assert_eq!(read(FAILED), 0, "NtContinue failed in the dispatcher");
    assert_eq!((status(QUEUED), status(QUEUED + 4)), (STATUS_SUCCESS, STATUS_SUCCESS), "NtQueueApcThread");
    assert_eq!(status(QUEUED + 8), STATUS_INVALID_HANDLE, "NtQueueApcThread on a bad handle");
    assert_eq!(status(NON_ALERTABLE), STATUS_SUCCESS, "a non-alertable NtDelayExecution");
    assert_eq!(read(NOT_YET), LOG_START, "an APC ran before an alertable wait");
    assert_eq!(status(DELAYED), STATUS_USER_APC, "the alertable NtDelayExecution, back from its APCs");
    assert_eq!((read(ARGUMENTS), read(ARGUMENTS + 4)), (1, LONG), "the APC dispatcher wrote over the stack");
    let entry = |i: u32| [read(LOG_START + 12 * i), read(LOG_START + 12 * i + 4), read(LOG_START + 12 * i + 8)];
    assert_eq!([entry(0), entry(1)], [[0x11, 0x12, 0x13], [0x21, 0x22, 0x23]], "the queued APCs, in order");
    assert_eq!((read(KEPT), read(KEPT + 4)), (MAGIC, read(ESP_BEFORE)), "EBX or ESP lost across the APCs");
    assert_eq!((status(TESTED), status(TESTED + 4)), (STATUS_SUCCESS, STATUS_SUCCESS), "NtTestAlert");
    assert_eq!(entry(2), [0x31, 0x32, 0x33], "the APC of NtTestAlert");
    assert_eq!(status(WOKEN), STATUS_USER_APC, "the kernel's APC did not end the wait");
    assert_eq!(entry(3), [0x41, 0x42, 0x43], "the kernel's APC");
    assert_eq!((status(STILL), status(STILL + 4)), (STATUS_SUCCESS, STATUS_SUCCESS), "the last APC, then a wait");
    assert_eq!(read(AFTER), LOG_START + 4 * 12, "an APC ran in a non-alertable wait");

    process.write_memory(u64::from(GO), &1u32.to_le_bytes()).expect("let the program go on");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!((ended, process.exit_status()), (STATUS_WAIT_0, NtStatus(0x600D)), "the process did not end");
    ke::apc::set_user_apc_dispatcher(0);
    ps::wait_for_reaper();
    log::info!("[smoke] user APCs: queued, then run by alertable waits and NtTestAlert in a user-mode dispatcher");
}

/// The system DLL (`ps::system_dll`) and KUSER_SHARED_DATA (`mm::shared_data`,
/// M3): with a synthetic ntdll installed, a new process maps it at its base,
/// and its first thread enters LdrInitializeThunk through the APC dispatcher,
/// with ntdll's base and the CONTEXT where ReactOS's stub looks for it, then
/// reaches its entry point. With GS on its TEB, it takes clock interrupts,
/// system services and a sleep while a second thread, with GS of its own,
/// goes through the kernel, and keeps GS (SWAPGS). It reads XP SP2's
/// KUSER_SHARED_DATA at
/// 0x7FFE0000 (version 5.1, system root, DEP policy, a running tick count,
/// SystemCall on KiFastSystemCall on Intel, KiIntSystemCall elsewhere),
/// cannot write to it (the exception reaches ntdll's dispatcher), and goes
/// through SystemCall as ntdll's stubs do: a system service keeps EFLAGS
/// (DF, IF), an APC queued to itself runs in an alertable wait and the wait
/// returns STATUS_USER_APC with EBX and ESP kept, and ntdll's dispatchers
/// resume with NtContinue. On Intel, all of these go through SYSENTER.
fn system_dll_self_test() {
    use abi::ntstatus::{
        NtStatus, STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_SUCCESS, STATUS_USER_APC, STATUS_WAIT_0,
    };
    use abi::process::{NT_CURRENT_PROCESS, NT_CURRENT_THREAD};
    use abi::services;
    use abi::shared_data::KUSER_SHARED_DATA_VA;
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const NTDLL: u32 = 0x7C90_0000;
    const N_TEXT: u32 = NTDLL + 0x1000;
    const N_DATA: u32 = NTDLL + 0x2000;
    // ntdll's: what its NtContinue returned; LdrInitializeThunk's three
    // arguments, then EIP and ESP of the CONTEXT above them; the exception's
    // code and two parameters.
    const N_FAILED: u32 = N_DATA;
    const N_LDR: u32 = N_DATA + 0x04;
    const N_EXCEPTION: u32 = N_DATA + 0x20;
    // Its entry points, by offset in .text.
    const APC: u32 = 0x000;
    const LDR: u32 = 0x040;
    const EXCEPTION: u32 = 0x0A0;
    const INT_SYSTEM_CALL: u32 = 0x100;
    const FAST_SYSTEM_CALL: u32 = 0x110;
    const FAST_SYSTEM_CALL_RET: u32 = 0x114;
    const RAISE: u32 = 0x118;
    const CALLBACK: u32 = 0x11C;
    const ZW_CONTINUE: u32 = 0x120;
    const IMAGE_BASE: u32 = 0x40_0000;
    const TEXT: u32 = IMAGE_BASE + 0x1000;
    // The program's stubs, and its APC routine.
    const ZW_CLOSE: u32 = TEXT + 0x180;
    const ZW_QUEUE_APC_THREAD: u32 = TEXT + 0x190;
    const ZW_DELAY_EXECUTION: u32 = TEXT + 0x1A0;
    const ROUTINE: u32 = TEXT + 0x1C0;
    // A second thread, GS on the flat data selector (base 0), which sleeps
    // through SystemCall in a loop.
    const SLEEPER: u32 = TEXT + 0x1E0;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    // The program's: eight KUSER_SHARED_DATA fields, then the write.
    const SHARED: u32 = DATA; // major, minor, SystemCall, SystemCallReturn, root, multiplier, NX policy, ticks
    const AFTER_WRITE: u32 = DATA + 0x20;
    const CLOSED: u32 = DATA + 0x24;
    const DONE: u32 = DATA + 0x28;
    const GO: u32 = DATA + 0x2C;
    // EFLAGS after a service with DF set; the APC queued, the alertable
    // wait, ESP before it, EBX and ESP after it, what the routine received.
    const FLAGS: u32 = DATA + 0x30;
    const QUEUED: u32 = DATA + 0x34;
    const DELAYED: u32 = DATA + 0x38;
    const ESP_BEFORE: u32 = DATA + 0x3C;
    const KEPT: u32 = DATA + 0x40;
    const APC_LOG: u32 = DATA + 0x48;
    // A LARGE_INTEGER: 5 s, relative.
    const LONG: u32 = DATA + 0x58;
    // GS loaded with the TEB selector: gs:[0x18] at once, then GS and
    // gs:[0x18] after clock interrupts and a system service.
    const GS_KEPT: u32 = DATA + 0x60;
    // LARGE_INTEGERs: 1 ms and 20 ms, relative.
    const ONE_MS: u32 = DATA + 0x70;
    const TWENTY_MS: u32 = DATA + 0x78;
    const MAGIC: u32 = 0x5C5C_0001;
    let shared = |offset: u32| KUSER_SHARED_DATA_VA + offset;

    /// `call target`, from code that starts at `origin`.
    fn call_to(code: &mut Code, origin: u32, target: u32) {
        let at = origin + code.0.len() as u32;
        code.word(&[0xE8], target.wrapping_sub(at + 5));
    }
    /// An ntdll stub: the service in EAX, a call through
    /// SharedUserData->SystemCall, then `ret` past its arguments.
    fn stub(service: u32, arguments: u16) -> Code {
        let mut code = Code::new();
        code.word(&[0xB8], service)
            .word(&[0xBA], KUSER_SHARED_DATA_VA + 0x300) // mov edx, &SystemCall
            .bytes(&[0xFF, 0x12, 0xC2]) // call [edx]; ret …
            .bytes(&(4 * arguments).to_le_bytes());
        code
    }

    // ── ntdll ──
    let mut text = [0xCC; 0x200];
    let mut put = |at: u32, code: &Code| text[at as usize..at as usize + code.0.len()].copy_from_slice(&code.0);
    // Like ReactOS's, it writes its SEH record past the CONTEXT first.
    let mut apc = Code::new();
    apc.word(&[0x8D, 0x84, 0x24], 16 + 0x2CC) // lea eax, [esp + 16 + CONTEXT]
        .word(&[0xC7, 0x00], 0x5E5E_5E5E) // mov dword [eax], …
        .bytes(&[0xC7, 0x40, 0x04])
        .bytes(&0x5E5E_5E5Eu32.to_le_bytes()) // mov dword [eax + 4], …
        .bytes(&[0x58, 0xFF, 0xD0]) // pop eax; call eax
        .bytes(&[0x89, 0xE1, 0x6A, 0x01, 0x51]); // mov ecx, esp; push 1; push ecx
    call_to(&mut apc, N_TEXT + APC, N_TEXT + ZW_CONTINUE);
    apc.store_eax(N_FAILED).bytes(&[0xEB, 0xFE]);
    put(APC, &apc);
    // mov eax, [esp + offset]; mov [N_LDR + 4i], eax: its arguments, then
    // the CONTEXT's Eip and Esp, 16 bytes above the return address; for the
    // first thread only (CONTEXT's Eip on TEXT).
    let mut record = Code::new();
    for (i, offset) in [4u32, 8, 12, 16 + 0xB8, 16 + 0xC4].into_iter().enumerate() {
        record.word(&[0x8B, 0x84, 0x24], offset).word(&[0xA3], N_LDR + 4 * i as u32);
    }
    let mut ldr = Code::new();
    ldr.word(&[0x81, 0xBC, 0x24], 16 + 0xB8) // cmp dword [esp + 16 + Eip], TEXT
        .bytes(&TEXT.to_le_bytes())
        .bytes(&[0x75, record.0.len() as u8]) // jne past the record
        .bytes(&record.0)
        .bytes(&[0xC2, 12, 0]); // ret 12
    put(LDR, &ldr);
    let mut exception = Code::new();
    exception
        .bytes(&[0x8B, 0x1C, 0x24, 0x8B, 0x74, 0x24, 0x04]) // mov ebx, [esp]; mov esi, [esp + 4]
        .bytes(&[0x8B, 0x03]) // mov eax, [ebx]: the code
        .store_eax(N_EXCEPTION)
        .bytes(&[0x8B, 0x43, 0x14]) // mov eax, [ebx + 0x14]
        .store_eax(N_EXCEPTION + 4)
        .bytes(&[0x8B, 0x43, 0x18]) // mov eax, [ebx + 0x18]
        .store_eax(N_EXCEPTION + 8)
        .word(&[0x83, 0x86], 0xB8) // add dword [esi + Eip], 5: past the write
        .bytes(&[5])
        .bytes(&[0x6A, 0x00, 0x56]); // push 0; push esi
    call_to(&mut exception, N_TEXT + EXCEPTION, N_TEXT + ZW_CONTINUE);
    exception.store_eax(N_FAILED).bytes(&[0xEB, 0xFE]);
    put(EXCEPTION, &exception);
    put(ZW_CONTINUE, &stub(services::NtContinue, 2));
    let mut int_system_call = Code::new();
    int_system_call.bytes(&[0x8D, 0x54, 0x24, 0x08, 0xCD, 0x2E, 0xC3]); // lea edx, [esp + 8]; int 2Eh; ret
    put(INT_SYSTEM_CALL, &int_system_call);
    let mut fast_system_call = Code::new();
    fast_system_call.bytes(&[0x89, 0xE2, 0x0F, 0x34]); // mov edx, esp; sysenter
    put(FAST_SYSTEM_CALL, &fast_system_call);
    let mut ret = Code::new();
    ret.bytes(&[0xC3]);
    put(FAST_SYSTEM_CALL_RET, &ret);
    let at = |offset: u32| N_TEXT - NTDLL + offset;
    let ntdll = Pe32Builder::new(NTDLL)
        .section(".text", 0x1000, 0x200, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x40, &[0u8; 0x40], pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .exports(
            "ntdll.dll",
            &[
                ("KiUserApcDispatcher", at(APC)),
                ("LdrInitializeThunk", at(LDR)),
                ("KiUserExceptionDispatcher", at(EXCEPTION)),
                ("KiIntSystemCall", at(INT_SYSTEM_CALL)),
                ("KiFastSystemCall", at(FAST_SYSTEM_CALL)),
                ("KiFastSystemCallRet", at(FAST_SYSTEM_CALL_RET)),
                ("KiRaiseUserExceptionDispatcher", at(RAISE)),
                ("KiUserCallbackDispatcher", at(CALLBACK)),
            ],
        )
        .build();
    let dll = ps::system_dll::SystemDll::new(Arc::from(ntdll)).expect("the synthetic ntdll");
    assert_eq!(dll.int_system_call, N_TEXT + INT_SYSTEM_CALL);
    ps::system_dll::install(Some(dll));

    // ── the program ──
    let mut code = Code::new();
    for (i, offset) in [0x26C, 0x270, 0x300, 0x304, 0x030, 0x004].into_iter().enumerate() {
        code.word(&[0xA1], shared(offset)).store_eax(SHARED + 4 * i as u32); // mov eax, [0x7FFExxxx]
    }
    code.word(&[0x0F, 0xB6, 0x05], shared(0x2D5)) // movzx eax, byte [NXSupportPolicy]
        .store_eax(SHARED + 0x18)
        .word(&[0xA1], shared(0x320)) // TickCount
        .store_eax(SHARED + 0x1C)
        // GS on the TEB, as user mode may load it.
        .word(&[0xB8], u32::from(ke::context::UserSelectors::current().teb)) // mov eax, TEB selector
        .bytes(&[0x8E, 0xE8]) // mov gs, eax
        .bytes(&[0x65, 0xA1, 0x18, 0, 0, 0]) // mov eax, gs:[0x18]
        .store_eax(GS_KEPT)
        // 50 ms of clock interrupts in user mode: until TickCount moves on.
        .word(&[0x8B, 0x1D], shared(0x320)) // mov ebx, [TickCount]
        .bytes(&[0x83, 0xC3, 50]) // add ebx, 50
        .word(&[0xA1], shared(0x320)) // mov eax, [TickCount]
        .bytes(&[0x39, 0xD8, 0x72, 0xF7]) // cmp eax, ebx; jb back to the mov
        .word(&[0x68], 0x1234);
    // NtClose(0x1234) through SystemCall.
    call_to(&mut code, TEXT, ZW_CLOSE);
    // NtDelayExecution(FALSE, 20 ms): the sleeper goes through the kernel
    // meanwhile, with its own GS.
    code.word(&[0x68], TWENTY_MS).bytes(&[0x6A, 0x00]);
    call_to(&mut code, TEXT, ZW_DELAY_EXECUTION);
    code.bytes(&[0x8C, 0xE8]) // mov eax, gs
        .store_eax(GS_KEPT + 4)
        .bytes(&[0x65, 0xA1, 0x18, 0, 0, 0]) // mov eax, gs:[0x18]
        .store_eax(GS_KEPT + 8)
        .word(&[0xA3], KUSER_SHARED_DATA_VA) // mov [0x7FFE0000], eax: read-only
        .word(&[0xC7, 0x05], AFTER_WRITE)
        .bytes(&1u32.to_le_bytes())
        // NtClose(0x1234) with DF set, then EFLAGS.
        .bytes(&[0xFD]) // std
        .word(&[0x68], 0x1234);
    call_to(&mut code, TEXT, ZW_CLOSE);
    code.store_eax(CLOSED)
        .bytes(&[0x9C, 0x58, 0xFC]) // pushfd; pop eax; cld
        .store_eax(FLAGS)
        .word(&[0xBB], MAGIC); // mov ebx, MAGIC
                               // NtQueueApcThread(NtCurrentThread(), ROUTINE, 0x11, 0x22, 0x33).
    for argument in [0x33, 0x22, 0x11, ROUTINE, NT_CURRENT_THREAD] {
        code.word(&[0x68], argument);
    }
    call_to(&mut code, TEXT, ZW_QUEUE_APC_THREAD);
    code.store_eax(QUEUED)
        .word(&[0x89, 0x25], ESP_BEFORE) // mov [ESP_BEFORE], esp
        .word(&[0x68], LONG)
        .bytes(&[0x6A, 0x01]); // NtDelayExecution(TRUE, LONG)
    call_to(&mut code, TEXT, ZW_DELAY_EXECUTION);
    code.store_eax(DELAYED)
        .word(&[0x89, 0x1D], KEPT) // mov [KEPT], ebx
        .word(&[0x89, 0x25], KEPT + 4) // mov [KEPT + 4], esp
        .word(&[0xC7, 0x05], DONE)
        .bytes(&1u32.to_le_bytes())
        .word(&[0x83, 0x3D], GO) // cmp dword [GO], 0
        .bytes(&[0x00, 0x74, 0xF7]) // je back to the cmp
        .call(services::NtTerminateProcess, &[NT_CURRENT_PROCESS, 0x600D])
        .bytes(&[0xEB, 0xFE]);
    assert!(code.0.len() <= 0x180, "the test program outgrew its slot");
    // The routine, stdcall (context, argument1, argument2): logs them.
    let mut routine = Code::new();
    for i in 0..3u8 {
        routine.bytes(&[0x8B, 0x44, 0x24, 4 + 4 * i]).store_eax(APC_LOG + 4 * u32::from(i));
        // mov eax, [esp + 4 + 4i]
    }
    routine.bytes(&[0xC2, 12, 0]); // ret 12
    let mut text = [0xCC; 0x200];
    let mut put = |at: u32, code: &Code| {
        let at = (at - TEXT) as usize;
        text[at..at + code.0.len()].copy_from_slice(&code.0);
    };
    put(TEXT, &code);
    put(ZW_CLOSE, &stub(services::NtClose, 1));
    put(ZW_QUEUE_APC_THREAD, &stub(services::NtQueueApcThread, 5));
    put(ZW_DELAY_EXECUTION, &stub(services::NtDelayExecution, 2));
    put(ROUTINE, &routine);
    // The sleeper: GS on the data selector, then NtDelayExecution(FALSE,
    // 1 ms), again and again.
    let mut sleeper = Code::new();
    sleeper
        .word(&[0xB8], u32::from(ke::context::UserSelectors::current().data)) // mov eax, data selector
        .bytes(&[0x8E, 0xE8]) // mov gs, eax
        .word(&[0x68], ONE_MS)
        .bytes(&[0x6A, 0x00]);
    call_to(&mut sleeper, SLEEPER, ZW_DELAY_EXECUTION);
    let back = sleeper.0.len() as u8 + 2;
    sleeper.bytes(&[0xEB, back.wrapping_neg()]); // jmp to the top
    put(SLEEPER, &sleeper);
    let mut data = [0u8; 0x80];
    data[0x58..0x60].copy_from_slice(&(-5000 * MS).to_le_bytes());
    data[0x70..0x78].copy_from_slice(&(-MS).to_le_bytes());
    data[0x78..0x80].copy_from_slice(&(-20 * MS).to_le_bytes());
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x200, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x80, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "native.exe", false).expect("a process");
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    let thread = ps::create_thread(&process, TEXT, &stack).expect("a thread");
    let sleeper_stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    let _sleeper = ps::create_thread(&process, SLEEPER, &sleeper_stack).expect("a second thread");
    let read = |addr: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(addr), &mut bytes).expect("read the process");
        u32::from_le_bytes(bytes)
    };
    for waited in 0.. {
        if read(DONE) != 0 {
            break;
        }
        assert!(waited < 300, "the native program did not finish");
        // SAFETY: the boot thread, at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -10 * MS) };
    }

    assert_eq!(read(N_FAILED), 0, "NtContinue failed in ntdll");
    let ldr: [u32; 5] = core::array::from_fn(|i| read(N_LDR + 4 * i as u32));
    assert_eq!(ldr, [0, NTDLL, 0, TEXT, stack.stack_base], "LdrInitializeThunk's arguments and CONTEXT");
    let fields: [u32; 8] = core::array::from_fn(|i| read(SHARED + 4 * i as u32));
    assert_eq!(&fields[..2], &[5, 1], "NtMajorVersion, NtMinorVersion");
    // ADR-004: SYSENTER on Intel, int 2Eh elsewhere.
    let system_call = if hal::cpuid::is_intel() { FAST_SYSTEM_CALL } else { INT_SYSTEM_CALL };
    assert_eq!(
        (fields[2], fields[3]),
        (N_TEXT + system_call, N_TEXT + FAST_SYSTEM_CALL_RET),
        "SystemCall, SystemCallReturn"
    );
    assert_eq!(fields[4], u32::from(b'C') | u32::from(b':') << 16, "NtSystemRoot");
    assert_eq!((fields[5], fields[6]), (1 << 24, 2), "TickCountMultiplier, NXSupportPolicy (OptIn)");
    assert_ne!(fields[7], 0, "the clock does not update TickCount");
    let exception: [u32; 3] = core::array::from_fn(|i| read(N_EXCEPTION + 4 * i as u32));
    assert_eq!(exception, [STATUS_ACCESS_VIOLATION.0, 1, KUSER_SHARED_DATA_VA], "a write to KUSER_SHARED_DATA");
    assert_eq!(read(AFTER_WRITE), 1, "ntdll's dispatcher did not resume the program");
    let teb_selector = u32::from(ke::context::UserSelectors::current().teb);
    assert_eq!(read(GS_KEPT), thread.teb(), "GS does not reach the TEB");
    assert_eq!(
        (read(GS_KEPT + 4) & 0xFFFF, read(GS_KEPT + 8)),
        (teb_selector, thread.teb()),
        "GS lost across clock interrupts and a system service"
    );
    assert_eq!(NtStatus(read(CLOSED)), STATUS_INVALID_HANDLE, "NtClose through SystemCall");
    assert_eq!(read(FLAGS) & 0x600, 0x600, "a system service lost DF, or came back with interrupts masked");
    assert_eq!(NtStatus(read(QUEUED)), STATUS_SUCCESS, "NtQueueApcThread through SystemCall");
    let log: [u32; 3] = core::array::from_fn(|i| read(APC_LOG + 4 * i as u32));
    assert_eq!(log, [0x11, 0x22, 0x33], "the APC did not run with its arguments");
    assert_eq!(NtStatus(read(DELAYED)), STATUS_USER_APC, "the alertable wait, back from its APC");
    assert_eq!((read(KEPT), read(KEPT + 4)), (MAGIC, read(ESP_BEFORE)), "EBX or ESP lost across the APC");

    process.write_memory(u64::from(GO), &1u32.to_le_bytes()).expect("let the program go on");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!((ended, process.exit_status()), (STATUS_WAIT_0, NtStatus(0x600D)), "the process did not end");
    ps::system_dll::install(None);
    ps::wait_for_reaper();
    log::info!(
        "[smoke] ntdll: mapped at its base, threads start in LdrInitializeThunk, KUSER_SHARED_DATA read-only, \
         system calls through SystemCall ({})",
        if hal::cpuid::is_intel() { "SYSENTER" } else { "int 2Eh" }
    );
}

/// SWAPGS on the exceptions that do not come back (`hal::trap::entry_stub`,
/// M3): a Ps process loads GS with its TEB selector, then takes an x87
/// division by zero (#MF); the kernel's user fault path, which reaches the
/// KPCR through GS, ends the process with `STATUS_ACCESS_VIOLATION`.
fn fatal_entry_self_test() {
    use abi::ntstatus::{STATUS_ACCESS_VIOLATION, STATUS_WAIT_0};
    use alloc::sync::Arc;
    use ke::dispatcher::{ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::section::Section;
    use pe::builder::Pe32Builder;

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const CONTROL_WORD: u32 = IMAGE_BASE + 0x2000;

    let mut code = Code::new();
    code.word(&[0xB8], u32::from(ke::context::UserSelectors::current().teb)) // mov eax, TEB selector
        .bytes(&[0x8E, 0xE8]) // mov gs, eax
        .bytes(&[0xDB, 0xE3]) // fninit
        .word(&[0xD9, 0x2D], CONTROL_WORD) // fldcw [CONTROL_WORD]: division by zero unmasked
        .bytes(&[0xD9, 0xE8, 0xD9, 0xEE, 0xDE, 0xF9]) // fld1; fldz; fdivp
        .bytes(&[0x9B]) // fwait: #MF
        .bytes(&[0xEB, 0xFE]);
    let mut text = [0xCC; 0x40];
    text[..code.0.len()].copy_from_slice(&code.0);
    // XP's control word, 0x027F, but for ZM.
    let mut data = [0u8; 0x10];
    data[..2].copy_from_slice(&0x027Bu16.to_le_bytes());
    let file = Pe32Builder::new(IMAGE_BASE)
        .entry_point(0x1000)
        .section(".text", 0x1000, 0x40, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
        .section(".data", 0x2000, 0x10, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
        .build();
    let section = Section::create_image(Arc::from(file)).expect("image section");
    let info = section.image().expect("an image").info;
    let process = ps::create_process(&ps::system_process(), &section, "x87.exe", false).expect("a process");
    let stack = ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
    let _thread = ps::create_thread(&process, IMAGE_BASE + 0x1000, &stack).expect("a thread");
    // SAFETY: the object of a process held here.
    let ended = unsafe {
        ke_wait_for_single_object::<KePlatform>(
            process.dispatcher_object(),
            ProcessorMode::Kernel,
            false,
            Some(-3000 * MS),
        )
    };
    assert_eq!((ended, process.exit_status()), (STATUS_WAIT_0, STATUS_ACCESS_VIOLATION), "the #MF with GS loaded");
    ps::wait_for_reaper();
    log::info!(
        "[smoke] SWAPGS: user GS kept across interrupts, services and switches; #MF with GS loaded ends the process"
    );
}

/// Ps, and the M2 exit criteria 1 and 3 (05): see [`process_round`]. The
/// round runs twice: the first sizes the global tables (IDs, free kernel stack
/// slots, the reaper's list); after the second, every page and every pool
/// byte the processes took is back.
fn process_self_test() {
    use mm::pfn::{self, PageUsage};

    let counts = || {
        let s = pfn::stats();
        let pages = [PageUsage::PageTable, PageUsage::KernelStack, PageUsage::UserPrivate, PageUsage::Section];
        (pages.map(|usage| s.active(usage)), HEAP.used(), mm::pool::PAGED_POOL.used())
    };
    process_round();
    let before = counts();
    let (one, two) = process_round();
    assert_eq!(counts(), before, "pages or pool kept after the end of the processes");
    log::info!(
        "[smoke] Ps: two processes ran at once, each with its own image at 0x400000 (counters {one:?} and {two:?}), each thread on its own TEB"
    );
    log::info!(
        "[smoke] Ps: a process reserved 256 MiB and committed it page by page; only the pages written took memory"
    );
    log::info!(
        "[smoke] Ps: user stacks grow by their guard page, up to STATUS_STACK_OVERFLOW; a guard elsewhere faults"
    );
    log::info!("[smoke] Ps: DEP OptIn: code runs from a read-write page until its process turns DEP on");
    log::info!(
        "[smoke] Ps: processes ended on request, on a fault and before their first run; pages, pool, handles, kernel stacks and IDs given back"
    );
}

/// Processes on images built here, all at 0x400000:
///
/// - `one` and `two` run at once: each thread stores the TID its TEB holds
///   (`fs:[0x24]`, so the TEB descriptor must follow each switch) and bumps
///   its counter, by 1 in `one`, by 2 in `two`; a thread of `one` is
///   terminated, which frees its TEB; then both processes are;
/// - in `faulty`, the first thread writes to address 0: the process ends with
///   `STATUS_ACCESS_VIOLATION`, the other thread by its exit APC;
/// - `early`, with a single thread, is terminated before the thread ever ran:
///   it ends at its first tick;
/// - while they run, `two` reserves 256 MiB and commits it page by page:
///   only the pages written take memory (M2 exit criterion 2);
/// - the stack of `grows` grows by its guard page as its thread pushes
///   32 KiB, `TEB.StackLimit` following; `overflow` pushes until
///   `STATUS_STACK_OVERFLOW` ends it; `guarded` touches a guard page outside
///   its stack and ends with `STATUS_GUARD_PAGE_VIOLATION`;
/// - under the OptIn DEP policy (ADR-020), `dep-off` runs code from a
///   read-write page; `dep-on`, which turns DEP on after its code page was
///   mapped, faults on it with `STATUS_ACCESS_VIOLATION`.
///
/// Then each process has its exit status, its handles closed, its address
/// space gone; with the last reference, its IDs are free. Returns the
/// counters of `one` and `two`.
fn process_round() -> ([u32; 2], [u32; 2]) {
    use abi::ntstatus::{
        NtStatus, STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION, STATUS_INVALID_CID,
        STATUS_PENDING, STATUS_PROCESS_IS_TERMINATING, STATUS_STACK_OVERFLOW, STATUS_THREAD_IS_TERMINATING,
        STATUS_WAIT_0,
    };
    use abi::peb32::Peb32;
    use abi::process::{MEM_EXECUTE_OPTION_DISABLE, MEM_EXECUTE_OPTION_ENABLE, MEM_EXECUTE_OPTION_PERMANENT};
    use abi::teb32::{NtTib32, Teb32};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::mem::offset_of;
    use ke::dispatcher::{ke_delay_execution_thread, ke_wait_for_single_object, DispatcherHeader, ProcessorMode};
    use ke::sched::KePlatform;
    use mm::pfn::{self, PageUsage};
    use mm::section::Section;
    use mm::vad::PageProtect;
    use mm::virtual_alloc::{AllocType, MemState, PAGE_SIZE};
    use ob::{AccessMask, Object};
    use pe::builder::Pe32Builder;
    use ps::{EProcess, EThread};

    const MS: i64 = 10_000;
    const IMAGE_BASE: u32 = 0x40_0000;
    const DATA: u32 = IMAGE_BASE + 0x2000;
    /// `mov dword [0], 1` then `jmp $`.
    const FAULT: [u8; 12] = [0xC7, 0x05, 0, 0, 0, 0, 1, 0, 0, 0, 0xEB, 0xFE];
    /// `push eax` then `jmp` back to it.
    const OVERFLOW: [u8; 3] = [0x50, 0xEB, 0xFD];
    /// A guard page outside any stack, in `guarded`.
    const GUARD_VA: u32 = 0x50_0000;
    // mov ecx, 0x2000; push eax; dec ecx; jnz push: 32 KiB pushed; then
    // mov dword [DATA+8], 1; jmp $.
    let mut grow = [0u8; 21];
    grow[..9].copy_from_slice(&[0xB9, 0x00, 0x20, 0x00, 0x00, 0x50, 0x49, 0x75, 0xFC]);
    grow[9..11].copy_from_slice(&[0xC7, 0x05]);
    grow[11..15].copy_from_slice(&(DATA + 8).to_le_bytes());
    grow[15..].copy_from_slice(&[1, 0, 0, 0, 0xEB, 0xFE]);
    // mov eax, [GUARD_VA]; jmp $.
    let mut guarded = [0xA1, 0, 0, 0, 0, 0xEB, 0xFE];
    guarded[1..5].copy_from_slice(&GUARD_VA.to_le_bytes());

    // Thread `slot`: mov eax, fs:[0x24]; mov [DATA+0x10+4*slot], eax;
    // add dword [DATA+4*slot], step; jmp back.
    let spinner = |slot: u32, step: u8| {
        let mut code = [0u8; 20];
        code[..6].copy_from_slice(&[0x64, 0xA1, 0x24, 0, 0, 0]);
        code[6] = 0xA3;
        code[7..11].copy_from_slice(&(DATA + 0x10 + 4 * slot).to_le_bytes());
        code[11..13].copy_from_slice(&[0x83, 0x05]);
        code[13..17].copy_from_slice(&(DATA + 4 * slot).to_le_bytes());
        code[17] = step;
        code[18..].copy_from_slice(&[0xEB, 0xEC]);
        code
    };
    // Thread `i`'s code at RVA 0x1000 + 0x20 * i.
    let image = |codes: &[&[u8]], marker: &[u8; 8]| {
        let mut text = [0xCC; 0x60];
        for (i, code) in codes.iter().enumerate() {
            text[0x20 * i..0x20 * i + code.len()].copy_from_slice(code);
        }
        let mut data = [0; 0x28];
        data[0x20..].copy_from_slice(marker);
        let file = Pe32Builder::new(IMAGE_BASE)
            .entry_point(0x1000)
            .section(".text", 0x1000, 0x60, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
            .section(".data", 0x2000, 0x28, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
            .build();
        Section::create_image(Arc::from(file)).expect("image section")
    };
    let system = ps::system_process();
    // A thread at `start`, on a stack sized by the image.
    let thread = |process: &Arc<Object<EProcess>>, section: &Arc<Section>, start: u32| {
        let info = section.image().expect("an image").info;
        let stack = ps::create_user_stack(process, info.stack_reserve, info.stack_commit).expect("a user stack");
        ps::create_thread(process, start, &stack).expect("create a thread")
    };
    // A process, with a thread at each RVA.
    let start = |section: &Arc<Section>, name: &str, rvas: &[u32]| {
        let process = ps::create_process(&system, section, name, false).expect("create a process");
        let threads: Vec<Arc<Object<EThread>>> =
            rvas.iter().map(|&rva| thread(&process, section, IMAGE_BASE + rva)).collect();
        (process, threads)
    };
    // Counters, TIDs seen through FS, marker.
    let state = |process: &EProcess| {
        let mut bytes = [0u8; 0x28];
        process.read_memory(u64::from(DATA), &mut bytes).expect("read the image's data");
        let word = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        ([word(0), word(4)], [word(0x10), word(0x14)], [&bytes[0x20..]].concat())
    };
    let delay = |ms: i64| {
        // SAFETY: a kernel thread at PASSIVE_LEVEL.
        unsafe { ke_delay_execution_thread::<KePlatform>(ProcessorMode::Kernel, false, -ms * MS) }
    };
    let wait_until = |what: &str, done: &dyn Fn() -> bool| {
        for _ in 0..300 {
            if done() {
                return;
            }
            delay(10);
        }
        panic!("Ps self-test: {what}");
    };
    let wait = |object: *mut DispatcherHeader, ms: i64| {
        // SAFETY: the object of a process or a thread held by the caller.
        unsafe { ke_wait_for_single_object::<KePlatform>(object, ProcessorMode::Kernel, false, Some(-ms * MS)) }
    };
    let read_u32 = |process: &EProcess, va: u32| {
        let mut bytes = [0u8; 4];
        process.read_memory(u64::from(va), &mut bytes).expect("read a process");
        u32::from_le_bytes(bytes)
    };

    let (one, two, faulty) = (
        image(&[&spinner(0, 1), &spinner(1, 1)], b"image 1\0"),
        image(&[&spinner(0, 2), &spinner(1, 2)], b"image 2\0"),
        image(&[&FAULT, &spinner(1, 1)], b"faulty\0\0"),
    );
    let (a, ta) = start(&one, "one.exe", &[0x1000, 0x1020]);
    let (b, tb) = start(&two, "two.exe", &[0x1000, 0x1020]);
    assert_eq!((a.image_base(), b.image_base()), (IMAGE_BASE, IMAGE_BASE));
    // A handle in A's table, which its end must close.
    let section_object = mm::section::create_section_object(one.clone());
    a.handle_table.insert(section_object.clone(), AccessMask::GENERIC_ALL, Default::default()).expect("a handle");

    // The PEB, and each TEB under it.
    let peb = ps::eprocess::PEB_VA;
    assert_eq!(read_u32(&a, peb + offset_of!(Peb32, image_base_address) as u32), IMAGE_BASE);
    assert_eq!(read_u32(&a, peb + offset_of!(Peb32, os_major_version) as u32), 5);
    assert_eq!(read_u32(&a, peb + offset_of!(Peb32, os_build_number) as u32) & 0xFFFF, 2600);
    assert_eq!((ta[0].teb(), ta[1].teb()), (0x7FFD_E000, 0x7FFD_D000), "TEBs go down from under the PEB");
    for t in &ta {
        let field = |offset: usize| read_u32(&a, t.teb() + offset as u32);
        assert_eq!(field(0x18), t.teb(), "NtTib.Self");
        assert_eq!((field(offset_of!(Teb32, client_id)), field(offset_of!(Teb32, client_id) + 4)), (a.pid(), t.tid()));
        assert_eq!(field(offset_of!(Teb32, process_environment_block)), peb);
    }

    // Both run at once.
    wait_until("a thread never ran", &|| [&a, &b].iter().all(|p| state(p).0.iter().all(|&count| count > 0)));
    let (first_a, first_b) = (state(&a).0, state(&b).0);
    wait_until("a thread stopped while the others ran", &|| {
        let (now_a, now_b) = (state(&a).0, state(&b).0);
        (0..2).all(|i| now_a[i] > first_a[i] && now_b[i] > first_b[i])
    });
    let (sa, sb) = (state(&a), state(&b));
    assert_eq!((&sa.2[..], &sb.2[..]), (&b"image 1\0"[..], &b"image 2\0"[..]), "each process has its own image");
    assert!(sb.0.iter().all(|count| count % 2 == 0), "image two adds 2: {:?}", sb.0);
    // Copied on write without DEP, the data page is read-write, not executable.
    let copied = a.with_space(|space| space.query(u64::from(DATA)).map(|region| region.protect));
    assert_eq!(copied, Ok(Ok(PageProtect::READWRITE)), "a copied page took the rights of DEP");
    assert_eq!(sa.1, [ta[0].tid(), ta[1].tid()], "a thread of one did not see its own TEB through FS");
    assert_eq!(sb.1, [tb[0].tid(), tb[1].tid()], "a thread of two did not see its own TEB through FS");

    // 256 MiB reserved, every page committed one by one, a few written.
    const RESERVED: u64 = 256 << 20;
    const WRITTEN: u64 = 16;
    let private = || pfn::stats().active(PageUsage::UserPrivate);
    let before = private();
    let base = b
        .with_space(|space| {
            let base = space.allocate(0, RESERVED, AllocType::MEM_RESERVE, PageProtect::READWRITE)?;
            for page in (base..base + RESERVED).step_by(PAGE_SIZE as usize) {
                space.allocate(page, PAGE_SIZE, AllocType::MEM_COMMIT, PageProtect::READWRITE)?;
            }
            Ok::<u64, NtStatus>(base)
        })
        .expect("a process")
        .expect("reserve and commit 256 MiB");
    assert_eq!(private(), before, "a commit took a page");
    for i in 0..WRITTEN {
        b.write_memory(base + i * (RESERVED / WRITTEN), &[0x5A]).expect("write a committed page");
    }
    assert_eq!(private() - before, WRITTEN, "not one page per page written");
    // One thread ends, its process lives on.
    ps::terminate_thread(ta[1].clone(), NtStatus(0x1111)).expect("terminate a thread");
    let object = ta[1].dispatcher_object().expect("a started thread");
    assert_eq!(wait(object, 3000), STATUS_WAIT_0, "a terminated thread did not end");
    assert_eq!((ta[1].exit_status(), a.exit_status(), a.active_threads()), (NtStatus(0x1111), STATUS_PENDING, 1));
    let teb = a.with_space(|space| space.query(u64::from(ta[1].teb())).map(|region| region.state));
    assert_eq!(teb, Ok(Ok(MemState::Free)), "the TEB of an ended thread was not freed");
    assert_eq!(ps::terminate_thread(ta[1].clone(), NtStatus(1)), Err(STATUS_THREAD_IS_TERMINATING));
    ps::terminate_process(a.clone(), NtStatus(0xA0A0)).expect("terminate one");
    ps::terminate_process(b.clone(), NtStatus(0xB0B0)).expect("terminate two");
    for process in [&a, &b] {
        assert_eq!(wait(process.dispatcher_object(), 3000), STATUS_WAIT_0, "{} did not end", process.image_file_name());
    }

    let (c, tc) = start(&faulty, "faulty.exe", &[0x1000, 0x1020]);
    assert_eq!(wait(c.dispatcher_object(), 3000), STATUS_WAIT_0, "a faulting process did not end");
    // Created and terminated at once: at the boot thread's priority, its
    // thread has not run yet. Alone, nothing but its exit APC stops it.
    let (d, td) = start(&one, "early.exe", &[0x1000]);
    ps::terminate_process(d.clone(), NtStatus(0xD0D0)).expect("terminate early");
    assert_eq!(wait(d.dispatcher_object(), 100), STATUS_WAIT_0, "a thread ended before its first run lingered");

    // The stack grows by its guard page, down to its overflow.
    let stacks = image(&[&grow, &OVERFLOW, &guarded], b"stacks\0\0");
    let (e, te) = start(&stacks, "grows.exe", &[0x1000]);
    wait_until("a thread did not push 32 KiB", &|| read_u32(&e, DATA + 8) == 1);
    let tib = offset_of!(Teb32, nt_tib) as u32;
    let base = read_u32(&e, te[0].teb() + tib + offset_of!(NtTib32, stack_base) as u32);
    let limit = read_u32(&e, te[0].teb() + tib + offset_of!(NtTib32, stack_limit) as u32);
    assert_eq!(limit, base - 0x8000, "TEB.StackLimit did not follow the stack");
    let region = |va: u32| e.with_space(|space| space.query(u64::from(va))).expect("a space").expect("a region");
    assert!(region(limit - 0x1000).protect.contains(PageProtect::GUARD), "the guard did not move down");
    assert_eq!(region(limit - 0x2000).state, MemState::Reserve, "more stack committed than needed");
    ps::terminate_process(e.clone(), NtStatus(0xE0E0)).expect("terminate grows");
    let (f, tf) = start(&stacks, "overflow.exe", &[0x1020]);
    let (g, _) = start(&stacks, "guarded.exe", &[]);
    let commit = AllocType::MEM_RESERVE | AllocType::MEM_COMMIT;
    let guard = g.with_space(|space| {
        space.allocate(u64::from(GUARD_VA), PAGE_SIZE, commit, PageProtect::READWRITE | PageProtect::GUARD)
    });
    guard.expect("a space").expect("a guard page");
    let tg = alloc::vec![thread(&g, &stacks, IMAGE_BASE + 0x1040)];
    for process in [&e, &f, &g] {
        assert_eq!(wait(process.dispatcher_object(), 3000), STATUS_WAIT_0, "{} did not end", process.image_file_name());
    }

    // DEP (ADR-020): under OptIn, code runs from a read-write page; a process
    // that turns DEP on cannot run it, though the page is already mapped
    // executable.
    const CODE_VA: u32 = 0x60_0000;
    // mov dword [CODE_VA + 0x100], 1; jmp $.
    let mut data_code = [0xC7, 0x05, 0, 0, 0, 0, 1, 0, 0, 0, 0xEB, 0xFE];
    data_code[2..6].copy_from_slice(&(CODE_VA + 0x100).to_le_bytes());
    // The code page is present and executes.
    let hhdm = hal::HHDM_OFFSET.load(core::sync::atomic::Ordering::Acquire);
    let executes = |process: &EProcess| {
        let flags = process.with_space(|space| {
            in_space(space, || {
                // SAFETY: attached to the space, whose page tables CR3 holds.
                unsafe { mm::MmPageTables::new(hhdm) }.translate_flags(VirtAddr::new(u64::from(CODE_VA)))
            })
        });
        flags.expect("a space").map(|(_, flags)| !flags.contains(PageTableFlags::NO_EXECUTE))
    };
    let with_code = |name: &str| {
        let (process, _) = start(&one, name, &[]);
        let page =
            process.with_space(|space| space.allocate(u64::from(CODE_VA), PAGE_SIZE, commit, PageProtect::READWRITE));
        page.expect("a space").expect("a read-write page");
        process.write_memory(u64::from(CODE_VA), &data_code).expect("write the code");
        assert_eq!(executes(&process), Some(true), "a page mapped by a fault without DEP does not execute");
        let again = process.with_space(|space| space.protect(u64::from(CODE_VA), PAGE_SIZE, PageProtect::READWRITE));
        assert_eq!(again, Ok(Ok(PageProtect::READWRITE)));
        assert_eq!(executes(&process), Some(true), "a page protected again without DEP does not execute");
        process
    };
    let h = with_code("dep-off.exe");
    assert_eq!(h.execute_options(), MEM_EXECUTE_OPTION_ENABLE, "OptIn starts without DEP");
    let th = alloc::vec![thread(&h, &one, CODE_VA)];
    wait_until("no code ran from a read-write page without DEP", &|| read_u32(&h, CODE_VA + 0x100) == 1);
    let asked = h.with_space(|space| space.query(u64::from(CODE_VA)).map(|region| region.protect));
    assert_eq!(asked, Ok(Ok(PageProtect::READWRITE)), "the VAD lost the protection asked for");
    ps::terminate_process(h.clone(), NtStatus(0xDE0F)).expect("terminate dep-off");
    let i = with_code("dep-on.exe");
    let on = MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_PERMANENT;
    i.set_execute_options(on).expect("turn DEP on");
    assert_eq!(executes(&i), Some(false), "a present page still executes under DEP");
    assert_eq!(
        i.set_execute_options(MEM_EXECUTE_OPTION_ENABLE),
        Err(STATUS_ACCESS_DENIED),
        "a permanent choice changed"
    );
    let ti = alloc::vec![thread(&i, &one, CODE_VA)];
    for process in [&h, &i] {
        assert_eq!(wait(process.dispatcher_object(), 3000), STATUS_WAIT_0, "{} did not end", process.image_file_name());
    }
    ps::wait_for_reaper();

    let ended = [
        (&a, &ta, NtStatus(0xA0A0)),
        (&b, &tb, NtStatus(0xB0B0)),
        (&c, &tc, STATUS_ACCESS_VIOLATION),
        (&d, &td, NtStatus(0xD0D0)),
        (&e, &te, NtStatus(0xE0E0)),
        (&f, &tf, STATUS_STACK_OVERFLOW),
        (&g, &tg, STATUS_GUARD_PAGE_VIOLATION),
        (&h, &th, NtStatus(0xDE0F)),
        (&i, &ti, STATUS_ACCESS_VIOLATION),
    ];
    for (process, threads, status) in ended {
        assert_eq!((process.exit_status(), process.active_threads()), (status, 0), "{}", process.image_file_name());
        let survivors = if core::ptr::eq(process, &a) { &threads[..1] } else { &threads[..] };
        assert!(
            survivors.iter().all(|t| t.exit_status() == status),
            "{}: thread exit status",
            process.image_file_name()
        );
    }
    assert_eq!(
        a.read_memory(u64::from(DATA), &mut [0; 4]),
        Err(STATUS_PROCESS_IS_TERMINATING),
        "space outlived its end"
    );
    assert_eq!(ps::terminate_process(a.clone(), NtStatus(1)), Err(STATUS_PROCESS_IS_TERMINATING));
    let stack = ps::InitialTeb { stack_base: 0x10_0000, stack_limit: 0xF_F000, stack_allocation_base: 0x1_0000 };
    assert!(ps::create_thread(&a, IMAGE_BASE, &stack).is_err(), "a thread in an ended process");
    assert_eq!(section_object.handle_count(), 0, "the handle table was not run down");

    let ids: Vec<u32> = [&a, &b, &c, &d, &e, &f, &g, &h, &i]
        .iter()
        .map(|p| p.pid())
        .chain([&ta, &tb, &tc, &td, &te, &tf, &tg, &th, &ti].iter().flat_map(|threads| threads.iter().map(|t| t.tid())))
        .collect();
    drop((a, b, c, d, e, f, g, h, i, ta, tb, tc, td, te, tf, tg, th, ti));
    drop((section_object, one, two, faulty, stacks, system));
    for id in ids {
        assert_eq!(ps::lookup_process(id).err(), Some(STATUS_INVALID_CID), "process {id} outlived its references");
        assert_eq!(ps::lookup_thread(id).err(), Some(STATUS_INVALID_CID), "thread {id} outlived its references");
    }
    (sa.0, sb.0)
}

/// The object manager (`ob`): the XP namespace and the object types; a named
/// section shared by two handle tables, as two processes would, each mapping
/// it through its handle; its name goes with its last handle while the views
/// keep it; links through `\DosDevices` and `\??`; a thousand handles run
/// down with the pool back where it was.
fn object_manager_self_test() {
    use abi::ntstatus::{STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS};
    use abi::object::OBJ_PERMANENT;
    use alloc::sync::Arc;
    use mm::address_space::AddressSpace;
    use mm::section::{
        create_section_object, Section, SECTION_ALL_ACCESS, SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_TYPE,
    };
    use mm::vad::PageProtect;
    use mm::virtual_alloc::PAGE_SIZE;
    use ob::{AccessMask, HandleTable, ObjectRef};

    const NAME: &str = "\\BaseNamedObjects\\MinoSelfTest";
    const MARKER: u64 = 0x4F42_4A45_4354_0000;
    let rw = PageProtect::READWRITE;
    let ns = ob::namespace();
    let types = ob::downcast::<ob::Directory>(&ns.open("\\ObjectTypes", None, None, 0).expect("\\ObjectTypes"))
        .expect("a directory")
        .entries();
    let names: alloc::vec::Vec<_> = types.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["Device", "Directory", "File", "Key", "Process", "Section", "SymbolicLink", "Thread", "Type"]);

    // A named section, two handle tables.
    let (first, second) = (HandleTable::new(), HandleTable::new());
    let section: ObjectRef = create_section_object(Section::create_pagefile(4 * PAGE_SIZE, rw).expect("section"));
    let (h1, status) = ob::insert_object(ns, section, Some(NAME), None, 0, &first, SECTION_ALL_ACCESS).expect("insert");
    assert_eq!(status, STATUS_SUCCESS);
    let map_rights = SECTION_MAP_READ | SECTION_MAP_WRITE;
    let open = |name, access| ob::open_object_by_name(ns, name, None, Some(&SECTION_TYPE), 0, &second, access);
    let h2 = open("\\basenamedobjects\\MINOSELFTEST", map_rights).expect("open by name, any case");
    let read_only = open(NAME, SECTION_MAP_READ).expect("open for reading");
    assert_eq!(second.reference(read_only, Some(&SECTION_TYPE), SECTION_MAP_WRITE).err(), Some(STATUS_ACCESS_DENIED));

    let (a, b) = (AddressSpace::new().expect("no PML4"), AddressSpace::new().expect("no PML4"));
    let map = |table: &HandleTable, handle, space: &AddressSpace| {
        let section = table.reference_as::<Arc<Section>>(handle, &SECTION_TYPE, SECTION_MAP_WRITE).expect("reference");
        space.map_view(&section, 0, 0, 0, rw).expect("map").base
    };
    let (va, vb) = (map(&first, h1, &a), map(&second, h2, &b));
    // SAFETY (both accesses): a read-write view of the attached space.
    in_space(&a, || unsafe { core::ptr::write_volatile(va as *mut u64, MARKER) });
    let read =
        |space: &AddressSpace, va: u64| in_space(space, || unsafe { core::ptr::read_volatile(va as *const u64) });
    assert_eq!(read(&b, vb), MARKER, "the named section is not shared");
    for (table, handle) in [(&first, h1), (&second, h2), (&second, read_only)] {
        table.close(handle).expect("close");
    }
    assert_eq!(ns.open(NAME, None, None, 0).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND), "name kept without handles");
    assert_eq!(read(&b, vb), MARKER, "the views no longer hold the section");
    for (space, va) in [(&a, va), (&b, vb)] {
        space.unmap_view(va).expect("unmap");
    }
    a.destroy();
    b.destroy();

    // \DosDevices → \?? → a link of ours → \BaseNamedObjects.
    let link: ObjectRef = ob::SymbolicLink::create("\\BaseNamedObjects");
    ns.insert(&link, "\\??\\MinoSelfTest:", None, OBJ_PERMANENT).expect("link");
    let through = ns.open("\\DosDevices\\MinoSelfTest:", None, None, 0).expect("follow the links");
    assert!(Arc::ptr_eq(&through, &ns.open("\\BaseNamedObjects", None, None, 0).unwrap()));
    ob::make_temporary(&link);
    assert_eq!(ns.open("\\??\\MinoSelfTest:", None, None, 0).err(), Some(STATUS_OBJECT_NAME_NOT_FOUND));

    // A thousand handles, run down: objects, sections and table all go.
    let pool = HEAP.used();
    let table = HandleTable::new();
    for _ in 0..1000 {
        let object = create_section_object(Section::create_pagefile(PAGE_SIZE, rw).expect("section"));
        table.insert(object, AccessMask::GENERIC_ALL, Default::default()).expect("handle");
    }
    let used = HEAP.used() - pool;
    table.rundown();
    drop(table);
    assert_eq!(HEAP.used(), pool, "the pool did not come back after the rundown");
    assert_eq!(SECTION_TYPE.object_count(), 0, "section objects left");
    log::info!(
        "[smoke] Ob: XP namespace and {} types; a named section shared by two handle tables, its name gone with \
         its last handle, its views kept; links through \\DosDevices; 1000 handles ({} KiB) run down, pool back",
        names.len(),
        used / 1024
    );
}

/// An address space where `alloc` has reserved, maybe committed, the page at
/// `0x400000`, attached for good: for the tests that end on a STOP screen.
fn attach_stop_test_space(alloc: mm::virtual_alloc::AllocType) -> u64 {
    const VA: u64 = 0x40_0000;
    let space = mm::address_space::AddressSpace::new().expect("no PML4");
    let rw = mm::vad::PageProtect::READWRITE;
    assert_eq!(space.allocate(VA, mm::virtual_alloc::PAGE_SIZE, alloc, rw), Ok(VA));
    // SAFETY: the space is never destroyed (the registry keeps it), and the
    // boot thread never detaches.
    let _attached_for_good = unsafe { ke::sched::ke_stack_attach(space.directory_table_base()) };
    VA
}

/// A fault on a user page at DISPATCH_LEVEL must stop the system with
/// IRQL_NOT_LESS_OR_EQUAL (feature `test-page-fault-irql`).
#[inline(never)]
fn page_fault_irql_test() {
    let va =
        attach_stop_test_space(mm::virtual_alloc::AllocType::MEM_RESERVE | mm::virtual_alloc::AllocType::MEM_COMMIT);
    log::info!("[smoke] touching a committed user page at DISPATCH_LEVEL on purpose (test-page-fault-irql)");
    let _irql = hal::irql::raise(hal::irql::Irql::Dispatch);
    // SAFETY: none; the fault this read takes must stop the system.
    let value = unsafe { core::ptr::read_volatile(va as *const u64) };
    panic!("a page fault at DISPATCH_LEVEL was resolved (read {value:#x})");
}

/// A kernel-mode read of a reserved user page must stop the system with
/// KMODE_EXCEPTION_NOT_HANDLED and STATUS_ACCESS_VIOLATION (feature
/// `test-page-fault-access-violation`).
#[inline(never)]
fn page_fault_access_violation_test() {
    let va = attach_stop_test_space(mm::virtual_alloc::AllocType::MEM_RESERVE);
    log::info!("[smoke] reading a reserved user page on purpose (test-page-fault-access-violation)");
    // SAFETY: none; the fault this read takes must stop the system.
    let value = unsafe { core::ptr::read_volatile(va as *const u64) };
    panic!("a read of a reserved page succeeded (read {value:#x})");
}

/// Checks that the FPU state follows each thread (ADR-009): the boot thread's
/// control words survive a switch to a new thread, which starts with the
/// initial ones whatever its creator had loaded.
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn fpu_self_test() {
    use abi::fpu::{INITIAL_FCW, INITIAL_MXCSR};
    use core::sync::atomic::{AtomicU64, Ordering};

    const FCW: u16 = 0x0F7F; // round toward zero, 64-bit precision
    const MXCSR: u32 = 0x7F80; // round toward zero
    static SEEN: AtomicU64 = AtomicU64::new(0);
    fn probe(_: *mut core::ffi::c_void) {
        let (fcw, mxcsr) = hal::fpu::control_words();
        SEEN.store(u64::from(fcw) << 32 | u64::from(mxcsr), Ordering::Relaxed);
    }
    let kept = ke::fpu::with_floating_point(|| {
        hal::fpu::set_control_words(FCW, MXCSR);
        // Above the boot thread, boost included: it runs, and ends, before
        // this returns.
        spawn_kernel_thread(ke::sched::current_priority() + 1, probe, core::ptr::null_mut());
        hal::fpu::control_words()
    });
    assert_eq!(kept, (FCW, MXCSR), "the boot thread's FPU state was lost across a switch");
    let seen = SEEN.load(Ordering::Relaxed);
    assert_eq!(
        seen,
        u64::from(INITIAL_FCW) << 32 | u64::from(INITIAL_MXCSR),
        "a new thread did not start with the initial FPU state"
    );
    log::info!(
        "[smoke] FPU: state kept across switches, new thread starts with FCW {:#06x} MXCSR {:#06x}",
        INITIAL_FCW,
        INITIAL_MXCSR
    );
}

/// M1 exit criterion (05): two kernel threads exchange 10 000 round trips
/// through two synchronization events, without a loss or a hang. The ponger
/// runs at normal priority, the pinger at `pinger_priority`. Each wake carries
/// `EVENT_INCREMENT`: a woken thread whose boosted priority exceeds its
/// waker's preempts it. A lost wake-up leaves both threads waiting, which the
/// boot thread's timeout reports. Called only with the `test-ke-events`
/// feature (scenario `tests/boot/ke-events`).
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn event_ping_pong_test(pinger_priority: u8, label: &str) {
    use abi::ntstatus::STATUS_WAIT_0;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicU32, Ordering};
    use ke::dispatcher::{
        ke_initialize_event, ke_set_event, ke_wait_for_multiple_objects, ke_wait_for_single_object, KEvent, ObjectType,
        ProcessorMode, WaitBlock, WaitType, EVENT_INCREMENT,
    };
    use ke::sched::KePlatform;

    const ROUND_TRIPS: u32 = 10_000;
    struct PingPong {
        ping: KEvent,
        pong: KEvent,
        pings: AtomicU32,
        pongs: AtomicU32,
    }
    /// Waits on `event`, then sets `answer`, `ROUND_TRIPS` times (or the other
    /// way round), counting in `count`.
    ///
    /// # Safety
    /// On a scheduler thread; both events are initialised and never freed.
    unsafe fn exchange(wait_first: bool, event: *mut KEvent, answer: *mut KEvent, count: &AtomicU32) {
        for _ in 0..ROUND_TRIPS {
            // SAFETY: guaranteed by the caller.
            unsafe {
                if !wait_first {
                    ke_set_event::<KePlatform>(answer, EVENT_INCREMENT);
                }
                let header = core::ptr::addr_of_mut!((*event).header);
                let status = ke_wait_for_single_object::<KePlatform>(header, ProcessorMode::Kernel, false, None);
                assert_eq!(status, STATUS_WAIT_0);
                count.fetch_add(1, Ordering::Relaxed);
                if wait_first {
                    ke_set_event::<KePlatform>(answer, EVENT_INCREMENT);
                }
            }
        }
    }
    fn ponger(pp: *mut c_void) {
        let pp = pp.cast::<PingPong>();
        // SAFETY: on its own thread; `pp` is never freed.
        unsafe {
            exchange(true, core::ptr::addr_of_mut!((*pp).ping), core::ptr::addr_of_mut!((*pp).pong), &(*pp).pongs)
        };
    }
    fn pinger(pp: *mut c_void) {
        let pp = pp.cast::<PingPong>();
        // SAFETY: as above.
        unsafe {
            exchange(false, core::ptr::addr_of_mut!((*pp).pong), core::ptr::addr_of_mut!((*pp).ping), &(*pp).pings)
        };
    }

    let pp = alloc::boxed::Box::into_raw(alloc::boxed::Box::<PingPong>::new_uninit()).cast::<PingPong>();
    // SAFETY: fresh memory at a fixed address, never freed; each field is
    // written in place.
    unsafe {
        ke_initialize_event(core::ptr::addr_of_mut!((*pp).ping), ObjectType::SynchronizationEvent, false);
        ke_initialize_event(core::ptr::addr_of_mut!((*pp).pong), ObjectType::SynchronizationEvent, false);
        core::ptr::addr_of_mut!((*pp).pings).write(AtomicU32::new(0));
        core::ptr::addr_of_mut!((*pp).pongs).write(AtomicU32::new(0));
    }
    let switches = ke::sched::context_switches();
    let start = hal::timer::interrupt_time();
    let ponger = spawn_kernel_thread(ke::sched::NORMAL_PRIORITY, ponger, pp.cast());
    let pinger = spawn_kernel_thread(pinger_priority, pinger, pp.cast());
    let threads = [ponger, pinger].map(|tid| ke::sched::thread_object(tid).expect("thread object"));
    let mut blocks = [const { WaitBlock::new() }; 2];
    // SAFETY: on the boot thread; the thread objects are never freed.
    let status = unsafe {
        ke_wait_for_multiple_objects::<KePlatform>(
            &threads,
            WaitType::WaitAll,
            ProcessorMode::Kernel,
            false,
            Some(-30 * 1000 * 10_000),
            Some(&mut blocks),
        )
    };
    // SAFETY: `pp` is never freed.
    let (pings, pongs) = unsafe { ((*pp).pings.load(Ordering::Relaxed), (*pp).pongs.load(Ordering::Relaxed)) };
    assert_eq!(status, STATUS_WAIT_0, "ping-pong hung ({label}): {pings} pings, {pongs} pongs answered");
    assert_eq!((pings, pongs), (ROUND_TRIPS, ROUND_TRIPS));
    log::info!(
        "[ke-events] {}: {} round trips in {} ms, {} context switches",
        label,
        ROUND_TRIPS,
        (hal::timer::interrupt_time() - start) / 10_000,
        ke::sched::context_switches() - switches,
    );
}

/// Starvation (M1, boosts): a thread of priority 4 is ready while one of
/// priority 9 spins. The balance set manager raises the starved thread to 15
/// once it has been ready for 4 s, at its next pass (one per second); the
/// starved thread then runs, and the spinning thread, which watches for it,
/// stops. Without that raise, the starved thread runs only once the other
/// gives up, 10 s later, after the boot thread has seen it had not run.
/// Called only with the `test-ke-starvation` feature (scenario
/// `tests/boot/ke-starvation`).
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn starvation_test() {
    use abi::ntstatus::STATUS_WAIT_0;
    use core::sync::atomic::{AtomicU64, Ordering};
    use ke::dispatcher::{ke_wait_for_single_object, ProcessorMode};
    use ke::sched::KePlatform;

    const MS: u64 = 10_000;
    static START: AtomicU64 = AtomicU64::new(0);
    static RAN_AT: AtomicU64 = AtomicU64::new(0);
    fn starved(_: *mut core::ffi::c_void) {
        RAN_AT.store(hal::timer::interrupt_time(), Ordering::Release);
    }
    fn hog(_: *mut core::ffi::c_void) {
        let give_up = START.load(Ordering::Relaxed) + 10_000 * MS;
        while RAN_AT.load(Ordering::Acquire) == 0 && hal::timer::interrupt_time() < give_up {
            core::hint::spin_loop();
        }
    }

    log::info!("[ke-starvation] a priority-9 thread spins while a priority-4 one is ready");
    START.store(hal::timer::interrupt_time(), Ordering::Relaxed);
    spawn_kernel_thread(4, starved, core::ptr::null_mut());
    let hog = spawn_kernel_thread(9, hog, core::ptr::null_mut());
    let hog = ke::sched::thread_object(hog).expect("thread object");
    // SAFETY: on the boot thread; the thread object is never freed.
    let status = unsafe {
        ke_wait_for_single_object::<KePlatform>(hog, ProcessorMode::Kernel, false, Some(-20_000 * MS as i64))
    };
    assert_eq!(status, STATUS_WAIT_0, "the spinning thread did not end");
    let ran_at = RAN_AT.load(Ordering::Acquire);
    assert_ne!(ran_at, 0, "the starved thread never ran while the other spun");
    let after_ms = (ran_at - START.load(Ordering::Relaxed)) / MS;
    assert!((4000..6000).contains(&after_ms), "the starved thread ran after {after_ms} ms, not after 4 to 5 s");
    log::info!("[ke-starvation] the starved thread ran after {} ms, raised by the balance set manager", after_ms);
}

/// M1 exit criterion (05): four kernel threads compute in floating point at
/// the same time (SSE and x87, each with its own rounding modes), preempted in
/// the middle of their computations, and get the host's results
/// (`ke::fpu::workload`). Called only with the `test-fpu` feature (scenario
/// `tests/boot/fpu`).
///
/// # IRQL
/// PASSIVE_LEVEL, interrupts enabled.
fn fpu_parallel_test() {
    use abi::ntstatus::STATUS_WAIT_0;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use ke::dispatcher::{ke_wait_for_multiple_objects, ProcessorMode, WaitBlock, WaitType};
    use ke::fpu::workload::{run, EXPECTED, WORKLOADS};
    use ke::sched::KePlatform;

    /// Switches the four threads go through before they stop: about ten
    /// quanta each, most of them in the middle of a computation.
    const MIN_SWITCHES: u64 = 40;
    static START: AtomicU64 = AtomicU64::new(0);
    static ROUNDS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
    static MISMATCHES: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
    fn worker(index: *mut c_void) {
        let i = index.addr();
        ke::fpu::with_floating_point(|| loop {
            if run(&WORKLOADS[i]) != EXPECTED[i] {
                MISMATCHES[i].fetch_add(1, Ordering::Relaxed);
            }
            let rounds = ROUNDS[i].fetch_add(1, Ordering::Relaxed) + 1;
            if rounds >= 2 && ke::sched::context_switches() - START.load(Ordering::Relaxed) >= MIN_SWITCHES {
                break;
            }
        });
    }

    START.store(ke::sched::context_switches(), Ordering::Relaxed);
    let start = hal::timer::interrupt_time();
    let threads = [0, 1, 2, 3].map(|i| {
        let tid = spawn_kernel_thread(ke::sched::NORMAL_PRIORITY, worker, core::ptr::without_provenance_mut(i));
        ke::sched::thread_object(tid).expect("thread object")
    });
    let mut blocks = [const { WaitBlock::new() }; 4];
    // SAFETY: on the boot thread; the thread objects are never freed.
    let status = unsafe {
        ke_wait_for_multiple_objects::<KePlatform>(
            &threads,
            WaitType::WaitAll,
            ProcessorMode::Kernel,
            false,
            Some(-90 * 1000 * 10_000),
            Some(&mut blocks),
        )
    };
    let rounds = ROUNDS.each_ref().map(|r| r.load(Ordering::Relaxed));
    let mismatches = MISMATCHES.each_ref().map(|m| m.load(Ordering::Relaxed));
    assert_eq!(status, STATUS_WAIT_0, "floating-point threads did not end: {rounds:?} rounds");
    assert_eq!(mismatches, [0; 4], "results differ from the host's in {mismatches:?} of {rounds:?} rounds");
    log::info!(
        "[fpu] 4 threads: results identical to the host ({:?} rounds, {} context switches, {} ms)",
        rounds,
        ke::sched::context_switches() - START.load(Ordering::Relaxed),
        (hal::timer::interrupt_time() - start) / 10_000,
    );
}

/// Kernel-stack guard-page lookup for the fault handlers (`hal::idt`).
fn kstack_guard_hit(addr: u64) -> Option<(u64, u64)> {
    mm::kstack::guard_hit(addr).map(|s| (s.bottom, s.top))
}

/// Recurses until the boot thread's kernel stack runs into its guard page.
/// Expected outcome: the STOP screen naming a kernel stack overflow.
/// Called only with the `test-stack-overflow` feature.
fn provoke_stack_overflow() -> ! {
    log::info!("[smoke] provoking a kernel stack overflow (test-stack-overflow)");
    let depth = recurse(0);
    panic!("stack overflow test: recursion returned at depth {}", depth);
}

/// Fails an assertion two calls deep: the STOP screen of a `panic!`, through
/// `KeBugCheckEx`, must name both functions (feature `test-bugcheck`).
#[inline(never)]
fn bugcheck_test_outer() {
    // Used after the call, so that the call is not a tail call: this frame
    // stays on the stack.
    core::hint::black_box(bugcheck_test_inner(core::hint::black_box(1)));
}

#[inline(never)]
fn bugcheck_test_inner(depth: u32) -> u32 {
    log::info!("[smoke] failing an assertion on purpose (test-bugcheck)");
    assert!(depth == 0, "deliberate bugcheck (test-bugcheck)");
    depth
}

#[inline(never)]
fn recurse(depth: u64) -> u64 {
    // 512 bytes per frame, live across the call so frames cannot be merged.
    let frame = core::hint::black_box([depth; 64]);
    if core::hint::black_box(depth) == u64::MAX {
        return frame[0];
    }
    recurse(depth + 1) + frame[63]
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
    let img = ps::loader::load_image(&pe_bytes, &mut vad, &mut mapper, None).ok()?;
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
            while ke::sched::is_thread_running(t) {
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
    // IRQs must stay disabled while we edit the page tables.
    x86_64::instructions::interrupts::disable();
    set_kernel_segments();

    // ── Fast path: load real binary from FAT ramdisk ──────────────────────────
    if let Some(ctx) = loader_from_fat(hhdm_offset) {
        x86_64::instructions::interrupts::enable();
        return ctx;
    }

    log::info!("loader_demo: step 1 — heap used={} free={}", HEAP.used(), HEAP.free());

    // Build a tiny but valid PE32 in heap memory.
    let pe_bytes = build_test_pe32(
        0x0200_0000, // preferred image base, as in tools/mkfat's TEST.EXE
        0x1000,      // AddressOfEntryPoint RVA
    );

    let mut vad = mm::vad::VadTree::new();

    // SAFETY: bootloader page tables active; hhdm_offset is correct.
    let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    let mut mapper = KernelPageMapper { pt };

    let img = ps::loader::load_image(&pe_bytes, &mut vad, &mut mapper, None).expect("loader_demo: load_image failed");

    log::info!(
        "loader_demo: PE loaded — base={:#x}  entry={:#x}  size={} B",
        img.image_base,
        img.entry_point,
        img.image_size,
    );

    let ctx = ps::loader::setup_process(&img, &mut vad, &mut mapper, 4, 1).expect("loader_demo: setup_process failed");
    hal::timer::set_shared_user_data_addr(Some(ps::loader::SHARED_USER_DATA32_VA as u64));

    log::info!("loader_demo: VAD has {} entry(ies)", vad.len());
    syscall::install(vad, hhdm_offset);
    log::info!("loader_demo: PASS");

    x86_64::instructions::interrupts::enable();

    // Truncate to u32 — these are 32-bit user-mode addresses (<4 GiB).
    (img.entry_point as u32, ctx.stack_top)
}

#[allow(dead_code)]
/// The boot RAM disk as the system volume (`io_manager::mount_boot_volume`):
/// `\Device\Ramdisk0`, with `\??\C:` and `\SystemRoot` leading to it.
fn mount_boot_volume() {
    match io_manager::mount_boot_volume() {
        Ok(Some(size)) => log::info!(
            "[boot] Io: boot volume {} (FAT32, {size} bytes), {}",
            io_manager::BOOT_VOLUME,
            io_manager::BOOT_LINKS.map(|(name, target)| alloc::format!("{name} -> {target}")).join(", ")
        ),
        Ok(None) => log::info!("[boot] Io: no boot RAM disk, no system volume"),
        Err(status) => log::error!("[boot] Io: the boot volume refused: {status}"),
    }
}

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
#[expect(clippy::identity_op, reason = "data section offsets are listed uniformly, 0x00 included")]
fn build_test_pe32(image_base: u32, entry_rva: u32) -> alloc::vec::Vec<u8> {
    // Same layout as tools/mkfat's TEST.EXE: the import directory (data +
    // 0x1A0) holds one descriptor and its all-zero terminator, then the INT.
    use ps::loader::*;

    log::info!("build_test_pe32: before alloc heap used={} free={}", HEAP.used(), HEAP.free());
    let mut buf = alloc::vec![0u8; 0x3000]; // 12 KiB — enough for headers + one section
    log::info!(
        "build_test_pe32: after alloc ptr={:#x} heap used={} free={}",
        buf.as_ptr() as usize,
        HEAP.used(),
        HEAP.free()
    );

    // ── DOS header ────────────────────────────────────────────────────────────
    buf[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
    let nt_off: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&nt_off.to_le_bytes());

    // ── NT signature ──────────────────────────────────────────────────────────
    buf[0x40..0x44].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

    let fh_off = 0x44usize;
    let opt_sz = core::mem::size_of::<ImageOptionalHeader32>() as u16;
    let nsec: u16 = 2;

    // ── FILE_HEADER ───────────────────────────────────────────────────────────
    buf[fh_off..fh_off + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
    buf[fh_off + 2..fh_off + 4].copy_from_slice(&nsec.to_le_bytes());
    buf[fh_off + 16..fh_off + 18].copy_from_slice(&opt_sz.to_le_bytes());

    // ── OPTIONAL_HEADER32 ─────────────────────────────────────────────────────
    let opt_off = fh_off + core::mem::size_of::<ImageFileHeader>();
    // magic
    buf[opt_off..opt_off + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
    // entry point RVA at offset 16
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
    // image base at offset 28
    buf[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
    // SizeOfImage at offset 56 (covers .text at 0x1000 and .data at 0x2000)
    let size_of_image: u32 = 0x3000;
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());
    // SizeOfHeaders at offset 60
    let size_of_headers: u32 = 0x400;
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&size_of_headers.to_le_bytes());
    // number of data directories at offset 92
    let n_dirs: u32 = 16;
    buf[opt_off + 92..opt_off + 96].copy_from_slice(&n_dirs.to_le_bytes());

    // ── Section headers (.text, .data) ───────────────────────────────────────
    let sh_off = opt_off + opt_sz as usize;
    let text_rva: u32 = 0x1000;
    let text_raw: u32 = 0x600;
    let text_off = size_of_headers as usize;
    buf[sh_off..sh_off + 5].copy_from_slice(b".text");
    buf[sh_off + 8..sh_off + 12].copy_from_slice(&(text_raw).to_le_bytes());
    buf[sh_off + 12..sh_off + 16].copy_from_slice(&text_rva.to_le_bytes());
    buf[sh_off + 16..sh_off + 20].copy_from_slice(&text_raw.to_le_bytes());
    buf[sh_off + 20..sh_off + 24].copy_from_slice(&size_of_headers.to_le_bytes());
    let text_chars: u32 = SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_CNT_CODE;
    buf[sh_off + 36..sh_off + 40].copy_from_slice(&text_chars.to_le_bytes());

    let sh2 = sh_off + 40;
    let data_rva: u32 = 0x2000;
    let data_raw: u32 = 0x600;
    let data_off = (size_of_headers + text_raw) as usize;
    buf[sh2..sh2 + 5].copy_from_slice(b".data");
    buf[sh2 + 8..sh2 + 12].copy_from_slice(&(data_raw).to_le_bytes());
    buf[sh2 + 12..sh2 + 16].copy_from_slice(&data_rva.to_le_bytes());
    buf[sh2 + 16..sh2 + 20].copy_from_slice(&data_raw.to_le_bytes());
    buf[sh2 + 20..sh2 + 24].copy_from_slice(&(size_of_headers + text_raw).to_le_bytes());
    let data_chars: u32 = SCN_MEM_READ | SCN_MEM_WRITE | SCN_CNT_INITIALIZED_DATA;
    buf[sh2 + 36..sh2 + 40].copy_from_slice(&data_chars.to_le_bytes());

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
    let import_int_rva: u32 = data_rva + 0x1C8;
    let import_iat_rva: u32 = data_rva + 0x1D0;
    let import_ibn_rva: u32 = data_rva + 0x1E0;
    let import_dll_rva: u32 = data_rva + 0x1F0;
    let import_iat_va = image_base.wrapping_add(import_iat_rva);
    let sysenter_iosb_va = image_base.wrapping_add(data_rva + 0xD0);
    let sysenter_msg_va = image_base.wrapping_add(data_rva + 0xD8);
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
    let sysenter_msg = b"[smoke] SYSENTER path hit\n";

    let mut code = alloc::vec::Vec::<u8>::new();
    code.extend_from_slice(&[0x66, 0xB8, 0x23, 0x00]);
    code.extend_from_slice(&[0x8E, 0xD8]);
    code.extend_from_slice(&[0x8E, 0xC0]);
    code.push(0xBA);
    emit_u32(&mut code, args_write_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.push(0xBA);
    emit_u32(&mut code, 0);
    code.extend_from_slice(&[0xB8, 0x50, 0x20, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.push(0xBA);
    emit_u32(&mut code, args_create_proc_va);
    code.extend_from_slice(&[0xB8, 0x1B, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xA1]);
    emit_u32(&mut code, out_proc_handle_va);
    code.extend_from_slice(&[0xA3]);
    emit_u32(&mut code, args_create_thread_va + 12);
    code.push(0xBA);
    emit_u32(&mut code, args_create_thread_va);
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
    code.extend_from_slice(&[0xFF, 0x15]);
    emit_u32(&mut code, import_iat_va);
    code.push(0xBA);
    emit_u32(&mut code, args_iat_proof_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.push(0xBA);
    emit_u32(&mut code, args_alloc_va);
    code.extend_from_slice(&[0xB8, 0x11, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0x8B, 0x1D]);
    emit_u32(&mut code, out_base_va);
    code.extend_from_slice(&[0xC7, 0x03]);
    emit_u32(&mut code, 0x1234_5678);

    // SYSENTER from compatibility mode #UDs on non-Intel CPUs (ADR-004): skip the
    // direct SYSENTER test there and say so, so the smoke script can tell.
    if hal::cpuid::is_intel() {
        // NtWriteFile via SYSENTER (XP SP2 ABI).
        // Stack layout at SYSENTER: [EDX+0]=ret_addr  [EDX+4..]=args[0..8].
        // Push in reverse: Key → ... → FileHandle → then call/pop trick for ret_addr.
        code.extend_from_slice(&[0x6A, 0x00]); // push 0  (Key)
        code.extend_from_slice(&[0x6A, 0x00]); // push 0  (ByteOffset)
        emit_push_u32(&mut code, sysenter_msg.len() as u32); // push Length
        emit_push_u32(&mut code, sysenter_msg_va); // push Buffer
        emit_push_u32(&mut code, sysenter_iosb_va); // push IoStatusBlock
        code.extend_from_slice(&[0x6A, 0x00]); // push 0  (ApcContext)
        code.extend_from_slice(&[0x6A, 0x00]); // push 0  (ApcRoutine)
        code.extend_from_slice(&[0x6A, 0x00]); // push 0  (Event)
        code.extend_from_slice(&[0x6A, 0xFF]); // push -1 (FileHandle = serial)
                                               // call/pop trick: push address of `pop eax`, add 16 → .after_sysenter.
                                               // delta = 1(pop)+5(add)+1(push)+2(mov edx,esp)+5(mov eax,imm)+2(sysenter) = 16
        code.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call .se_eip
        code.push(0x58); // pop eax  (.se_eip)
        code.extend_from_slice(&[0x05, 16, 0, 0, 0]); // add eax, 16
        code.push(0x50); // push eax (ret addr)
        code.extend_from_slice(&[0x89, 0xE2]); // mov edx, esp
        code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]); // mov eax, NtWriteFile
        code.extend_from_slice(&[0x0F, 0x34]); // sysenter
                                               // .after_sysenter: ret@SharedUserData+0x300 popped ret_addr; 9 args remain.
        code.extend_from_slice(&[0x83, 0xC4, 0x24]); // add esp, 36
    } else {
        log::info!("[smoke] SYSENTER path skipped: CPU is not Intel (ADR-004)");
    }

    code.push(0xBA);
    emit_u32(&mut code, args_term_va);
    code.extend_from_slice(&[0xB8, 0xC2, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E, 0xEB, 0xFE]);
    let code_end = text_off + code.len();
    buf[text_off..code_end].copy_from_slice(&code);

    let args_write_off = data_off;
    let args_alloc_off = data_off + 0x20;
    let sysenter_iosb_off = data_off + 0xD0;
    let sysenter_msg_off = data_off + 0xD8;
    let iat_iosb_off = data_off + 0x130;
    let iat_msg_off = data_off + 0x138;
    let args_iat_proof_off = data_off + 0x148;
    let iat_proof_msg_off = data_off + 0x160;
    let import_desc_off = data_off + 0x1A0;
    let import_int_off = data_off + 0x1C8;
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
        if n == 1 && line_buf[0] == 0x1B {
            return;
        }
        let cmd = core::str::from_utf8(&line_buf[..n]).unwrap_or("").trim();
        if cmd.is_empty() {
            continue;
        }

        if cmd == "help" {
            shell_write("  ls [path]   list directory\n");
            shell_write("  cat <file>  print file contents\n");
            shell_write("  run <file>  load and exec PE32 image\n");
            shell_write("  help        this message\n");
            shell_write("  ESC         back to launcher\n");
        } else if cmd == "ls" || cmd.starts_with("ls ") {
            let path = if cmd.len() > 3 { cmd[3..].trim() } else { "/" };
            shell_ls(path);
        } else if let Some(path) = cmd.strip_prefix("cat ") {
            shell_cat(path.trim());
        } else if let Some(path) = cmd.strip_prefix("run ") {
            shell_run(path.trim(), hhdm_offset);
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
            if let Some(byte) = hal::serial::try_read_byte() {
                break byte;
            }
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
            // Not a match guard: on an empty line, DEL (0x7F) would fall
            // through to the printable arm below.
            #[expect(clippy::collapsible_match, reason = "a backspace on an empty line must be ignored")]
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
                if b == b'\n' || b >= 0x20 {
                    hal::fb::write_byte(b);
                }
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
            while ke::sched::is_thread_running(t) {
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
    if !(64..=512 * 1024).contains(&size) {
        log::warn!("shell_load_and_spawn: bad size {}", size);
        return None;
    }
    let mut bytes = alloc::vec![0u8; size];
    let n = io_manager::read_fat_file(&mut file, &mut bytes).ok()?;
    bytes.truncate(n);

    let pt = unsafe { mm::MmPageTables::new(hhdm_offset) };
    let mut mapper = KernelPageMapper { pt };
    let mut vad = mm::vad::VadTree::new();
    let img = ps::loader::load_image(&bytes, &mut vad, &mut mapper, None).ok()?;

    // Use a fresh PID for each spawned process (start at 8 to avoid colliding
    // with the initial smoke-test process which used PID=4).
    static SHELL_NEXT_PID: hal::sync::KSpinLock<u32> = hal::sync::KSpinLock::new(8);
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

    spawn_user_thread(img.entry_point as u32, ctx.stack_top)
}

/// Normalise a shell path argument → FAT-style "/NAME.EXT" uppercase.
fn shell_norm_path(s: &str) -> alloc::string::String {
    let s = s.trim();
    if s.is_empty() || s == "/" {
        return alloc::string::String::from("/");
    }
    let mut out = alloc::string::String::new();
    if !s.starts_with('/') {
        out.push('/');
    }
    for ch in s.chars() {
        if ch == '\\' {
            out.push('/');
        } else {
            out.push(ch.to_ascii_uppercase());
        }
    }
    out
}

/// Write a u32 to serial in decimal (no heap allocation).
fn serial_write_u32(mut n: u32) {
    if n == 0 {
        hal::serial::write_byte(b'0');
        return;
    }
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

/// A `panic!` is a violated invariant (06 §5): it stops the system through
/// `KeBugCheckEx`, like a failed assertion on XP without a kernel debugger
/// (KMODE_EXCEPTION_NOT_HANDLED, P1 = STATUS_BREAKPOINT). The message and its
/// location are the STOP screen's reason.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    ke::bugcheck::ke_bug_check_with_reason(
        ke::bugcheck::BugCheckCode::KMODE_EXCEPTION_NOT_HANDLED,
        [u64::from(abi::ntstatus::STATUS_BREAKPOINT.0), 0, 0, 0],
        info,
    )
}
