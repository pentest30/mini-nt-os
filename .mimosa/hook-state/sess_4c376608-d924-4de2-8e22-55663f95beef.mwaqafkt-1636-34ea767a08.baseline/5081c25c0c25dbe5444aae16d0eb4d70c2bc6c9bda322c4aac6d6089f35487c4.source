# Specification — Phase 1: HAL + Physical Memory + Boot to kernel_main

**Feature:** `phase1-hal-boot`
**Status:** In progress
**Last updated:** 2026-03-16

---

## Overview

Boot the micro-nt-os kernel on x86_64 via UEFI firmware and produce a running
`kernel_main` with a fully initialised HAL, a working physical memory allocator,
4-level page tables with a Higher-Half Direct Map (HHDM), a kernel heap, and a
calibrated APIC timer.

Phase 1 is purely kernel-internal: no user-mode processes, no Win32 API, no game
binary loading. Its success proof is serial output from `kernel_main` showing each
subsystem status, with the APIC timer firing and `GetTickCount`-equivalent ticks
incrementing.

---

## Goals

| # | Goal | Done when |
|---|---|---|
| G1 | UEFI bootloader hands off to kernel | Serial prints `kernel_main reached` |
| G2 | HAL fully initialised | GDT, IDT, IRQL model, serial all live |
| G3 | Physical memory available | Buddy allocator returns pages from UEFI map |
| G4 | 4-level page tables active | Kernel identity-mapped + HHDM in place |
| G5 | Kernel heap live | `alloc::boxed::Box` and `Vec` compile and run |
| G6 | APIC timer firing | Timer ISR increments tick counter at ~100 Hz |
| G7 | `GetTickCount` / `timeGetTime` work | Return monotonically increasing ms values |

---

## Out of scope (Phase 1)

- User-mode processes, PEB/TEB setup
- Context switching / scheduler
- Win32 API surface (kernel32, user32, …)
- DirectX shims
- PE32 loader
- Page-fault-driven demand paging (VAD tree stubbed only)
- SMP (single CPU assumed)

---

## Architecture constraints (from CLAUDE.md — do not relax)

| Rule | Detail |
|---|---|
| `no_std` everywhere | All crates except `tools/pe-loader` must compile without std |
| PEB OS version | `OSMajorVersion=5`, `OSMinorVersion=1`, `OSBuildNumber=2600` (XP SP2) |
| IRQL discipline | No heap allocation at `IRQL >= DISPATCH_LEVEL` |
| `unsafe` discipline | Every `unsafe` block must have a `// SAFETY:` comment |
| Win32 ABI | All Win32 exports use `stdcall` (not relevant in Phase 1, but set up stubs) |
| Kernel load address | `0xFFFF_8000_0010_0000` |
| User/kernel split | User: `0x0000_0001_0000 – 0x7FFF_FFFF`, Kernel: `0xFFFF_8000_0000_0000+` |

---

## Subsystems and acceptance criteria

### 1. UEFI Bootloader (`bootloader/`)

**Current state:** Stub — initialises UEFI helpers, logs, halts.

**Acceptance criteria:**
- AC-BL1: Reads the UEFI memory map and identifies all `EfiConventionalMemory`
  regions.
- AC-BL2: Loads the kernel image (ELF or flat binary) from the EFI System
  Partition into the physical range starting at `0x0010_0000`.
- AC-BL3: Builds a minimal 4-level page table:
  - Identity map for first 4 GiB (covers UEFI runtime + MMIO).
  - HHDM: all physical RAM mapped at `0xFFFF_8000_0000_0000`.
  - Kernel image mapped at `0xFFFF_8000_0010_0000`.
- AC-BL4: Calls `ExitBootServices()` successfully.
- AC-BL5: Jumps to `kernel_main` passing a `BootInfo` struct containing:
  - Physical memory map (type, start, page count per region).
  - HHDM offset.
  - Kernel physical base address.
- AC-BL6: Serial output at each major step (before ExitBootServices).

### 2. HAL — GDT (`hal/src/gdt.rs`)

**Current state:** Exists (assumed correct from init call).

**Acceptance criteria:**
- AC-GDT1: 64-bit code and data segment descriptors present.
- AC-GDT2: TSS descriptor present with a valid TSS.
- AC-GDT3: Interrupt Stack Table entry 0 in TSS points to a dedicated double-fault
  stack (≥ 4 KiB).
- AC-GDT4: `gdt::init()` callable with interrupts disabled, no panic.

### 3. HAL — IDT (`hal/src/idt.rs`)

**Current state:** Handlers registered for breakpoint, double fault, page fault,
GPF, timer (0x20), syscall gate (0x2E).

**Acceptance criteria:**
- AC-IDT1: Breakpoint exception (`INT3`) is handled and execution resumes.
- AC-IDT2: Double fault uses IST stack 0 (never stack-overflows the kernel).
- AC-IDT3: Page fault handler logs faulting address from CR2 then panics
  (demand paging is Phase 3).
- AC-IDT4: Timer vector 0x20 handler runs after APIC timer fires.
- AC-IDT5: Syscall gate 0x2E dispatches to the NT syscall table stub.

### 4. HAL — IRQL model (`hal/src/irql.rs`)

**Acceptance criteria:**
- AC-IRQL1: `IRQL` type with at least `PASSIVE(0)`, `APC(1)`, `DISPATCH(2)`,
  `CLOCK(28)`, `HIGH(31)` levels defined.
- AC-IRQL2: `raise_irql(new)` and `lower_irql(old)` functions that mask/unmask
  interrupts at the appropriate APIC TPR level.
- AC-IRQL3: Debug assertion: heap allocation attempted at `>= DISPATCH` triggers
  a kernel panic in debug builds.

### 5. HAL — APIC Timer (`hal/src/timer.rs`)

**Current state:** Stub — logs a message, does nothing.

**Acceptance criteria:**
- AC-TMR1: APIC base detected via `IA32_APIC_BASE` MSR; MMIO mapped into kernel
  virtual space.
- AC-TMR2: APIC timer calibrated against PIT channel 0 (or HPET if available) to
  determine APIC ticks per millisecond.
- AC-TMR3: Periodic APIC timer set to fire at 100 Hz (10 ms) into vector 0x20.
- AC-TMR4: `timeBeginPeriod(1)` equivalent: timer can be reprogrammed to 1 ms
  resolution via `hal::timer::set_resolution(10_000)` (100-ns units).
- AC-TMR5: Global `TICK_COUNT: AtomicU64` incremented in the timer ISR.
- AC-TMR6: `hal::timer::get_tick_count()` returns milliseconds since boot
  (feeds `GetTickCount` and `timeGetTime`).

### 6. Physical Memory Manager (`executive/mm/src/buddy.rs`)

**Current state:** Data structures defined; `add_region` / `alloc` / `free` are
stubs.

**Acceptance criteria:**
- AC-BMM1: `BuddyAllocator::add_region(start_pfn, page_count)` correctly inserts
  free blocks into the right order free lists.
- AC-BMM2: `alloc_pages(order)` returns a `Pfn` aligned to `2^order` pages, or
  `None` if OOM.
- AC-BMM3: `free_pages(pfn, order)` merges buddies up to `MAX_ORDER`.
- AC-BMM4: Allocator is initialised from the `BootInfo` memory map in `Mm::init`.
- AC-BMM5: `total_pages` and `free_pages` counters remain consistent after alloc
  + free cycles.
- AC-BMM6: All UEFI `EfiConventionalMemory` regions added; no overlap with kernel
  image or UEFI runtime.

### 7. Page Tables (`bootloader/` + `executive/mm/`)

**Acceptance criteria:**
- AC-PT1: 4-level page tables built by bootloader (see AC-BL3).
- AC-PT2: After `kernel_main` takes over, `OffsetPageTable` (`x86_64` crate) is
  constructed from the HHDM offset passed in `BootInfo`.
- AC-PT3: `mm::map_page(virt, phys, flags)` maps a single 4 KiB page, allocating
  intermediate tables from the buddy allocator.
- AC-PT4: `mm::unmap_page(virt)` unmaps and returns the frame to the buddy
  allocator (TLB flush via `invlpg`).
- AC-PT5: Kernel stack (≥ 16 KiB) and BSS section mapped writable, non-executable.
- AC-PT6: Kernel text section mapped read-only, executable.

### 8. Kernel Heap (`kernel/src/`)

**Acceptance criteria:**
- AC-HEAP1: `#[global_allocator]` implemented using `linked_list_allocator::
  LockedHeap` (already in workspace deps).
- AC-HEAP2: Heap virtual range: `0xFFFF_8800_0000_0000 – 0xFFFF_8800_0010_0000`
  (1 MiB initial).
- AC-HEAP3: Heap pages mapped in `kernel_main` before the allocator is
  initialised.
- AC-HEAP4: `Box::new(42u64)` and `Vec::<u8>::with_capacity(64)` succeed without
  panic.
- AC-HEAP5: Allocating at IRQL >= DISPATCH panics in debug builds (IRQL
  discipline check from AC-IRQL3).

### 9. Kernel Entry Point (`kernel/src/main.rs` or `lib.rs`)

**Acceptance criteria:**
- AC-KE1: `kernel_main(boot_info: &BootInfo)` is the first Rust function called
  after the bootloader jumps.
- AC-KE2: Initialisation order:
  1. Serial (HAL)
  2. GDT
  3. IDT
  4. IRQL model
  5. Physical memory (buddy from BootInfo map)
  6. Page tables (OffsetPageTable)
  7. Kernel heap
  8. APIC timer
  9. Log "kernel_main ready" with tick count
- AC-KE3: Each init step logs success/failure on the serial port.
- AC-KE4: After init, enters `hlt` loop; timer ISR continues running (serial
  output every second to prove liveness).

---

## BootInfo struct contract

```rust
/// Passed from bootloader to kernel. Must be `#[repr(C)]`.
#[repr(C)]
pub struct BootInfo {
    /// Physical address of the start of the memory map array.
    pub memory_map_ptr:   u64,
    pub memory_map_count: u64,
    /// Virtual address of HHDM base (physical 0 maps here).
    pub hhdm_offset:      u64,
    /// Physical address where the kernel image was loaded.
    pub kernel_phys_base: u64,
    /// Size of the kernel image in bytes.
    pub kernel_size:      u64,
    /// RSDP physical address (for ACPI — needed by APIC timer).
    pub rsdp_phys:        u64,
}

#[repr(C)]
pub struct MemoryRegion {
    pub kind:        MemoryKind,
    pub start_pfn:   u64,
    pub page_count:  u64,
}

#[repr(u32)]
pub enum MemoryKind {
    Usable        = 0,
    Reserved      = 1,
    AcpiReclaimable = 2,
    UefiRuntime   = 3,
    KernelImage   = 4,
}
```

---

## Dependencies between subsystems

```
UEFI firmware
    └── bootloader
            ├── reads memory map
            ├── builds page tables
            └── jumps → kernel_main(BootInfo)
                    ├── hal::serial::init()      [no deps]
                    ├── hal::gdt::init()          [no deps]
                    ├── hal::idt::init()          [needs GDT]
                    ├── hal::irql::init()         [needs IDT]
                    ├── mm::init(BootInfo)        [no deps beyond BootInfo]
                    ├── mm::page_tables::init()  [needs mm + BootInfo hhdm]
                    ├── kernel::heap::init()     [needs page tables]
                    └── hal::timer::init()       [needs IDT + ACPI RSDP]
```

---

## Testing strategy

| Test type | How | What |
|---|---|---|
| QEMU serial smoke | `cargo run` in QEMU, check serial | Each init step logs OK |
| APIC timer liveness | Serial shows tick count climbing | Ticks increment at ~100/s |
| Buddy allocator unit | `cargo test -p executive-mm` | alloc + free + merge |
| Page table unit | `cargo test -p executive-mm` | map + unmap + translate |
| Heap smoke | `kernel_main` allocates Box/Vec | No panic |
| Double fault recovery | `INT3` in `kernel_main` | Breakpoint logged, continues |

---

## Assumptions

1. Single CPU (AP startup is Phase 2+).
2. UEFI firmware provides a valid ACPI RSDP for APIC discovery.
3. QEMU with OVMF is the initial test environment; real hardware is Phase 2+.
4. The kernel image fits in a contiguous physical region below 4 GiB.
5. `bootloader-api` crate (or a hand-rolled equivalent) provides the `BootInfo`
   ABI between bootloader and kernel.
6. The HHDM offset is `0xFFFF_8000_0000_0000` (matches CLAUDE.md kernel-mode
   base).
