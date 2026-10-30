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
mod syscall;

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
    for ty in
        [&mm::section::SECTION_TYPE, &ps::eprocess::PROCESS_TYPE, &ps::ethread::THREAD_TYPE, &io_manager::FILE_TYPE]
    {
        ob::namespace().register_type(ty).expect("an object type registered twice");
    }
    ps::init();
    io_manager::init(boot_info.ramdisk_phys_base, boot_info.ramdisk_size, boot_info.hhdm_offset);
    fat_smoke_probe();

    // Wire preemptive round-robin: each clock tick ends the quantum, and the
    // DISPATCH interrupt (timer ISR below DISPATCH_LEVEL, or IRQL drop) drains
    // the DPC queue, then runs schedule(); the APC interrupt delivers the
    // current thread's kernel APCs. Registered after ke::init() (scheduler
    // table ready) and before interrupts re-enable.
    hal::irql::set_dispatch_hook(Some(ke::dpc::ki_dispatch_interrupt));
    hal::irql::set_apc_hook(Some(ke::apc::ki_apc_interrupt));
    hal::timer::set_clock_hook(Some(ke::clock::ki_clock_interrupt));
    hal::idt::set_syscall_hook(Some(syscall::dispatch));
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

/// A user-mode fault that nothing resolved (`hal::idt`, interrupts masked):
/// until exceptions reach user mode (M3), the process of a Ps thread ends
/// with the exception's code, as an unhandled exception would end it; a
/// thread of the legacy loader just ends.
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
    let to_waiter = leak(KApc::new(waiter, record, None, Some(normal), ProcessorMode::Kernel, core::ptr::null_mut()));
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
        "[smoke] Ps: processes ended on request, on a fault and before their first run; pages, pool, handles, kernel stacks and IDs given back"
    );
}

/// Four processes on images built here, all at 0x400000:
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
///   only the pages written take memory (M2 exit criterion 2).
///
/// Then each process has its exit status, its handles closed, its address
/// space gone; with the last reference, its IDs are free. Returns the
/// counters of `one` and `two`.
fn process_round() -> ([u32; 2], [u32; 2]) {
    use abi::ntstatus::{
        NtStatus, STATUS_ACCESS_VIOLATION, STATUS_INVALID_CID, STATUS_PENDING, STATUS_PROCESS_IS_TERMINATING,
        STATUS_THREAD_IS_TERMINATING, STATUS_WAIT_0,
    };
    use abi::peb32::Peb32;
    use abi::teb32::Teb32;
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
    let image = |first: &[u8], second: &[u8], marker: &[u8; 8]| {
        let mut text = [0xCC; 0x40];
        text[..first.len()].copy_from_slice(first);
        text[0x20..0x20 + second.len()].copy_from_slice(second);
        let mut data = [0; 0x28];
        data[0x20..].copy_from_slice(marker);
        let file = Pe32Builder::new(IMAGE_BASE)
            .entry_point(0x1000)
            .section(".text", 0x1000, 0x40, &text, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ)
            .section(".data", 0x2000, 0x28, &data, pe::SCN_MEM_READ | pe::SCN_MEM_WRITE)
            .build();
        Section::create_image(Arc::from(file)).expect("image section")
    };
    let system = ps::system_process();
    // A process, with a thread at each RVA.
    let start = |section: &Arc<Section>, name: &str, rvas: &[u32]| {
        let process = ps::create_process(&system, section, name, false).expect("create a process");
        let info = section.image().expect("an image").info;
        let threads: Vec<Arc<Object<EThread>>> = rvas
            .iter()
            .map(|rva| {
                let stack =
                    ps::create_user_stack(&process, info.stack_reserve, info.stack_commit).expect("a user stack");
                ps::create_thread(&process, IMAGE_BASE + rva, &stack).expect("create a thread")
            })
            .collect();
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
        image(&spinner(0, 1), &spinner(1, 1), b"image 1\0"),
        image(&spinner(0, 2), &spinner(1, 2), b"image 2\0"),
        image(&FAULT, &spinner(1, 1), b"faulty\0\0"),
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
    ps::wait_for_reaper();

    let ended = [(&a, &ta, NtStatus(0xA0A0)), (&b, &tb, NtStatus(0xB0B0)), (&c, &tc, STATUS_ACCESS_VIOLATION)];
    for (process, threads, status) in ended.into_iter().chain([(&d, &td, NtStatus(0xD0D0))]) {
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

    let ids: Vec<u32> = [&a, &b, &c, &d]
        .iter()
        .map(|p| p.pid())
        .chain([&ta, &tb, &tc, &td].iter().flat_map(|threads| threads.iter().map(|t| t.tid())))
        .collect();
    drop((a, b, c, d, ta, tb, tc, td, section_object, one, two, faulty, system));
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
    assert_eq!(names, ["Directory", "File", "Process", "Section", "SymbolicLink", "Thread", "Type"]);

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
