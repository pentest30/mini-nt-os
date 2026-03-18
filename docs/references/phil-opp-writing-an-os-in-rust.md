# Reference: "Writing an OS in Rust" — Philipp Oppermann
# https://os.phil-opp.com/

> **TL;DR** — Directly useful for Phase 1 (HAL + page tables + heap) and Phase 2
> (context switching, memory mapping). Read the chapters marked ★ before
> implementing the corresponding micro-nt-os subsystem.

---

## How it maps to micro-nt-os

| Phil-opp chapter | micro-nt-os subsystem | Phase | Relevance |
|---|---|---|---|
| Freestanding Rust Binary | `hal/`, `kernel/` | done | no_std patterns, panic=abort, `#[no_main]` |
| A Minimal Rust Kernel | `bootloader/` | done | entry point, target JSON, red zone disable |
| CPU Exceptions (IDT) | `hal/src/idt.rs` | done | `x86-interrupt` ABI, IDT entry format |
| Hardware Interrupts ★ | `hal/src/timer.rs` | **1** | PIC→APIC remapping, EOI, timer vector |
| Paging Introduction ★ | `executive/mm/` | **1** | 4-level tables, CR3, PTE flags, huge pages |
| Paging Implementation ★ | `executive/mm/` | **1** | OffsetPageTable, HHDM offset, map_to() |
| Heap Allocation ★ | `kernel/src/` | **1** | GlobalAlloc, linked_list_allocator setup |
| Allocator Designs | `executive/mm/src/buddy.rs` | **1** | bump / linked-list / fixed-block trade-offs |
| Async/Await | `executive/ke/` | 3+ | cooperative multitasking (low priority) |

---

## Chapter summaries with micro-nt-os notes

### ★ Hardware Interrupts
**URL:** https://os.phil-opp.com/hardware-interrupts/

- Uses `pic8259` crate to remap IRQ 0–15 to vectors 32–47 (avoids collision with
  CPU exceptions 0–31).
- Timer on IRQ 0 → vector 32; keyboard on IRQ 1 → vector 33.
- Requires explicit `notify_end_of_interrupt()` after every handler; without it the
  PIC stops sending further interrupts.
- Post notes the 8259 is superseded by the APIC — micro-nt-os MUST use the APIC
  (games use `timeGetTime` / `GetTickCount` which need a calibrated APIC timer).

**micro-nt-os action:** `hal/src/timer.rs` — use this chapter to bootstrap the
legacy PIC, then layer in the local APIC. The `x86_64` crate's APIC support and
`pic8259` crate are already compatible with the workspace.

---

### ★ Introduction to Paging
**URL:** https://os.phil-opp.com/paging-introduction/

- x86_64 uses 4-level page tables; each level has 512 × 8-byte entries.
- Virtual address split: [47:39] L4 index, [38:30] L3, [29:21] L2, [20:12] L1,
  [11:0] page offset. Bits 48–63 must be sign-extended copies of bit 47.
- CR3 holds the *physical* address of the active L4 table — critical for
  context switching in Phase 2.
- Huge pages: L3 entry with Present+Huge → 1 GiB page; L2+Huge → 2 MiB page.
  The UEFI bootloader uses 2 MiB identity-map huge pages initially.

**micro-nt-os action:** Phase 1 page table setup in `executive/mm/`. The NT kernel
image maps at `0xFFFF_8000_0010_0000` (see CLAUDE.md) — this chapter explains
exactly which L4/L3/L2/L1 indices that address hits and which PTEs to set.

---

### ★ Paging Implementation
**URL:** https://os.phil-opp.com/paging-implementation/

- **Physical Memory Offset (HHDM):** bootloader maps all of physical RAM at a
  known virtual offset. Access any physical address `p` as `hhdm_offset + p`.
  This is the approach micro-nt-os should use (matches the HHDM pattern in the
  `uefi` + `bootloader-api` crates).
- **`OffsetPageTable`** from the `x86_64` crate: wraps a physical offset and
  implements `Mapper` + `Translate`. Zero-copy, safe abstraction over raw PTEs.
- **`BootInfoFrameAllocator`:** consumes the UEFI memory map to yield usable
  physical frames — feed these to the buddy allocator in `executive/mm/src/buddy.rs`.
- `map_to(page, frame, flags, frame_allocator)` allocates intermediate page tables
  automatically and flushes the TLB entry.

**micro-nt-os action:** Wire `BootInfoFrameAllocator` → buddy allocator for physical
pages, then use `OffsetPageTable::map_to()` to back `VirtualAlloc` in Phase 2.

---

### ★ Heap Allocation
**URL:** https://os.phil-opp.com/heap-allocation/

- Implement `GlobalAlloc` with a static `#[global_allocator]` to enable `alloc`
  crate usage (`Box`, `Vec`, `Arc`, etc.) in `no_std` kernel code.
- `linked_list_allocator::LockedHeap` (already in workspace deps) is a drop-in
  `#[global_allocator]` backed by a spinlock — safe to use at IRQL < DISPATCH.
- The kernel heap must be mapped before the allocator is initialized. Phil-opp
  maps a fixed virtual range (e.g. `0x4444_4444_0000`); micro-nt-os should pick a
  range in kernel space (`0xFFFF_8000_xxxx_xxxx`).

**micro-nt-os action:** `kernel/src/` — add heap init in `kernel_main` after the
HHDM frame allocator is up. The `linked-list-allocator` dep is already in
`Cargo.toml`.

---

### Allocator Designs
**URL:** https://os.phil-opp.com/allocator-designs/

Three designs and their trade-offs relevant to `buddy.rs`:

| Design | Alloc cost | Fragmentation | Notes |
|---|---|---|---|
| Bump | O(1) | None (no free) | Useful only for boot-time scratch |
| Linked list | O(n) free list scan | External | Already similar to current buddy stub |
| Fixed-size block | O(1) per size class | Internal only | Best for kernel small allocations |

**micro-nt-os note:** The buddy allocator in `executive/mm/src/buddy.rs` is the
right choice for physical page allocation (power-of-2 granularity). For kernel
virtual-address slab allocation (IRPs, EPROCESSes, etc.) a fixed-size block
allocator per slab is what Windows uses — align with this in Phase 2.

---

### CPU Exceptions / IDT
**URL:** https://os.phil-opp.com/cpu-exceptions/

- Already done in `hal/src/idt.rs`, but the chapter is useful reference for:
  - The `extern "x86-interrupt"` ABI (mandatory for handler functions).
  - `InterruptStackFrame` layout — the hardware-pushed state at interrupt entry.
  - How to register a page fault handler with `PageFaultHandlerFunc` — needed
    before paging is live.

---

### Freestanding Rust Binary + Minimal Rust Kernel
**URLs:** https://os.phil-opp.com/freestanding-rust-binary/
         https://os.phil-opp.com/minimal-rust-kernel/

Already covered by the micro-nt-os workspace setup, but useful for:
- Confirming `panic = "abort"` in `Cargo.toml` profiles (already set).
- `#[unsafe(no_mangle)] extern "C" fn _start()` entry point pattern.
- Disabling the red zone in the custom target JSON — **critical** for interrupt
  safety (signals/exceptions must not corrupt the caller's stack frame).
- Disabling SIMD (`-mmx,-sse`) to avoid saving XMM registers on every interrupt.

**Check:** verify `bootloader/` target JSON has `"red-zone": false` and
`"features": "-mmx,-sse,+soft-float"`.

---

## What phil-opp does NOT cover (fill from other references)

| Gap | micro-nt-os reference |
|---|---|
| NT object manager, handle tables | `mino-nt-expert-skill/references/ob.md` |
| EPROCESS / PEB / TEB layouts | `mino-nt-expert-skill/references/ps.md` |
| VAD tree, section objects | `mino-nt-expert-skill/references/mm.md` |
| IRQL discipline, DPC/APC | `mino-nt-expert-skill/references/hal-exec.md` |
| Win32 / DirectX compat quirks | `mino-nt-expert-skill/references/win32-compat.md` |
| APIC timer calibration | ReactOS `hal/halx86/apic/` |
| PE32 loader, import resolution | ReactOS `ntdll/ldr/` |
| Context switching (KTHREAD) | Windows Internals 7e Ch. 4 |

---

## Crates from phil-opp already in workspace

| Crate | workspace dep | Used for |
|---|---|---|
| `x86_64` | ✅ 0.15 | page tables, IDT, GDT, registers |
| `uart_16550` | ✅ 0.3 | serial output (equivalent to phil-opp's serial driver) |
| `spin` | ✅ 0.9 | spinlock for IDT/heap (LockedHeap uses this) |
| `linked-list-allocator` | ✅ 0.10 | GlobalAlloc implementation |
| `uefi` | ✅ 0.26 | replaces phil-opp's BIOS bootloader |

The only crate phil-opp uses that micro-nt-os should consider adding:
- `pic8259` — for the initial PIC bootstrap before switching to APIC.
