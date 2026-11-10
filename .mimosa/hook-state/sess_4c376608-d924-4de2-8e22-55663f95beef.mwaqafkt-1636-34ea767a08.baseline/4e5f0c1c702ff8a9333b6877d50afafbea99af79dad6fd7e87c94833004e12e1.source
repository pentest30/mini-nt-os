# Tasks — Phase 1: HAL + Physical Memory + Boot to kernel_main

**Spec:** [docs/spec.md](spec.md)
**Status legend:** ✅ done · 🔄 in progress · ⬜ todo · 🔒 blocked

Tasks are ordered by dependency. Complete them top-to-bottom within each group.

---

## Group A — Shared contracts (no deps, do first)

### A1 — Define `BootInfo` ABI ⬜
**File:** `bootloader/src/boot_info.rs` (new) + `kernel/src/boot_info.rs` (re-export or shared crate)
**Spec:** AC-BL5, BootInfo struct contract section
**Steps:**
1. Create a `boot-info` crate (or add to `kernel` crate) with `BootInfo`, `MemoryRegion`, `MemoryKind` as `#[repr(C)]` types.
2. Add `#![no_std]` — no dependencies other than `core`.
3. Export from both `bootloader` and `kernel` crates.
4. Verify `size_of::<BootInfo>()` and field offsets match the spec table.

**Done when:** `cargo check --workspace` passes; `BootInfo` accessible from both crates.

---

### A2 — Add `IRQL` type and API ✅→🔄
**File:** `hal/src/irql.rs`
**Spec:** AC-IRQL1, AC-IRQL2, AC-IRQL3
**Steps:**
1. Define `Irql(u8)` newtype with constants `PASSIVE=0`, `APC=1`, `DISPATCH=2`, `CLOCK=28`, `HIGH=31`.
2. Implement `raise_irql(new: Irql) -> Irql` — mask APIC TPR; return previous level.
3. Implement `lower_irql(old: Irql)` — restore APIC TPR; `sti` if back to PASSIVE.
4. Add a debug-only guard: if `alloc` is invoked and current IRQL >= DISPATCH → `panic!`.
5. Unit test: raise to DISPATCH, try lowering back, verify previous level returned.

**Done when:** AC-IRQL1–3 pass; `cargo check` clean.

---

## Group B — Bootloader (depends on A1)

### B1 — Parse UEFI memory map ✅
**File:** `bootloader/src/main.rs`
**Spec:** AC-BL1, AC-BMM4, AC-BMM6
**Steps:**
1. Before `ExitBootServices`, call `st.boot_services().memory_map(buf)` to get all descriptors.
2. Iterate descriptors; classify into `MemoryKind` values.
3. Mark kernel image range as `KernelImage` (not `Usable`).
4. Store as array of `MemoryRegion` in a static buffer (max 512 entries is enough for QEMU).
5. Log total usable pages found on serial.

**Done when:** Serial shows correct usable page count; no UEFI conventional memory region overlaps kernel.

---

### B2 — Build 4-level page tables ✅
**File:** `bootloader/src/paging.rs` (new)
**Spec:** AC-BL3, AC-PT1
**Reference:** `docs/references/phil-opp-writing-an-os-in-rust.md` §Paging Implementation
**Steps:**
1. Allocate L4, L3, L2, L1 tables from UEFI `allocate_pages`.
2. **Identity map 0 – 4 GiB** using 2 MiB huge pages (L2 with Huge flag). Covers UEFI runtime + MMIO.
3. **HHDM map**: for each physical page (all RAM), map `0xFFFF_8000_0000_0000 + phys` → `phys`. Use 2 MiB huge pages where possible.
4. **Kernel map**: map `0xFFFF_8000_0010_0000` → kernel physical base, page-by-page, with correct R/W/NX flags (text=RX, data/BSS=RW+NX).
5. Write L4 physical address to CR3.
6. Verify serial still works after CR3 switch (identity map covers UART MMIO).

**Done when:** Serial output continues after CR3 switch; kernel image accessible at `0xFFFF_8000_0010_0000`.

---

### B3 — Load kernel image from ESP ✅
**File:** `bootloader/src/main.rs`
**Spec:** AC-BL2
**Steps:**
1. Use `uefi::proto::media::fs::SimpleFileSystem` to open the ESP.
2. Read `\EFI\BOOT\kernel.bin` (flat binary, no ELF parsing needed for Phase 1).
3. Allocate physical pages at `0x0010_0000` and copy image there.
4. Record `kernel_phys_base` and `kernel_size` in `BootInfo`.

**Done when:** Kernel binary loaded; `BootInfo.kernel_phys_base` = `0x0010_0000`.

---

### B4 — Exit boot services and jump to kernel ✅
**File:** `bootloader/src/main.rs`
**Spec:** AC-BL4, AC-BL5, AC-BL6
**Steps:**
1. Finalise `BootInfo` (fill `hhdm_offset`, `rsdp_phys` from ACPI table search).
2. Call `st.exit_boot_services()`.
3. Cast `kernel_virt_entry = 0xFFFF_8000_0010_0000 as *const ()` to a function pointer `fn(&BootInfo) -> !`.
4. Call it with a reference to `BootInfo`.
5. Must not return (kernel entry is `-> !`).

**Done when:** QEMU boots and serial shows `kernel_main reached`.

---

## Group C — HAL hardening (depends on A2; some parallel with B)

### C1 — GDT: add TSS + IST stack ✅→🔄
**File:** `hal/src/gdt.rs`
**Spec:** AC-GDT2, AC-GDT3
**Steps:**
1. Allocate a static `[u8; 4096]` as the double-fault stack.
2. Create a `TaskStateSegment` with `interrupt_stack_table[0]` pointing to the top of that stack.
3. Add TSS descriptor to GDT; call `ltr` to load it.
4. In IDT, set the double-fault handler to use IST index 0.

**Done when:** Triple fault in QEMU shows double fault handler output instead of reboot loop.

---

### C2 — IDT: page fault logs + GPF improvement ✅→🔄
**File:** `hal/src/idt.rs`
**Spec:** AC-IDT3
**Steps:**
1. Page fault handler: read CR2, log `PAGE FAULT at 0x{cr2:016x} error={error:?}`, then `panic!`.
2. GPF handler: log segment selector and error code.
3. Ensure both handlers use IST 0 (same double-fault stack as fallback).

**Done when:** Deliberate NULL pointer deref in `kernel_main` prints faulting address on serial.

---

### C3 — APIC timer: detect + calibrate + start ✅
**File:** `hal/src/timer.rs`
**Spec:** AC-TMR1 – AC-TMR6
**Reference:** `docs/references/phil-opp-writing-an-os-in-rust.md` §Hardware Interrupts
**Steps:**
1. Read `IA32_APIC_BASE` MSR; map APIC MMIO at a fixed kernel virtual address.
2. Software-enable APIC (bit 8 of Spurious Interrupt Vector Register).
3. **Calibrate**: use PIT channel 0 in one-shot mode:
   - Set APIC timer to max count, divisor 16.
   - Wait 10 ms via PIT.
   - Read remaining APIC count; compute `ticks_per_ms`.
4. Set APIC timer to periodic mode, initial count = `ticks_per_ms * 10` (10 ms = 100 Hz).
5. Set timer vector to `0x20`; unmask it.
6. In the timer ISR (`hal/src/idt.rs` irq_timer handler):
   - Increment `TICK_COUNT: AtomicU64` (relaxed ordering is fine here).
   - Send EOI to APIC.
7. Expose `hal::timer::get_tick_count() -> u64` (ms since boot).
8. Expose `hal::timer::set_resolution(hundred_ns: u32)` (reprograms initial count).

**Done when:** Serial prints incrementing tick count once per second; AC-TMR1–6 pass.

---

## Group D — Memory manager (depends on B4 for BootInfo, A1)

### D1 — Buddy allocator: implement alloc/free/merge ⬜
**File:** `executive/mm/src/buddy.rs`
**Spec:** AC-BMM1 – AC-BMM5
**Reference:** `docs/references/phil-opp-writing-an-os-in-rust.md` §Allocator Designs
**Steps:**
1. `add_region(start_pfn, count)`: split region into maximal power-of-2 blocks; push to `free_lists[order]`.
2. `alloc_pages(order) -> Option<Pfn>`:
   - Find smallest free list ≥ order with an entry.
   - Split down to requested order if needed; return leftover halves.
3. `free_pages(pfn, order)`:
   - Compute buddy PFN = `pfn ^ (1 << order)`.
   - If buddy is in the free list at this order, merge and recurse to order+1.
4. Wrap in `spin::Mutex`; expose global `BUDDY` accessor.
5. Unit tests (run on host with `cargo test`):
   - Single region, alloc all pages, verify free_pages == 0.
   - Alloc + free single page, verify merge restores original block.
   - OOM returns `None`.

**Done when:** Unit tests pass; `cargo test -p executive-mm` green.

---

### D2 — Feed BootInfo memory map to buddy ⬜
**File:** `executive/mm/src/lib.rs` → `Mm::init(boot_info: &BootInfo)`
**Spec:** AC-BMM4, AC-BMM6
**Steps:**
1. Iterate `BootInfo.memory_map` array.
2. For each `MemoryKind::Usable` region, call `BUDDY.lock().add_region(start_pfn, count)`.
3. Log total usable pages added.

**Done when:** `kernel_main` shows buddy total_pages matching QEMU RAM (minus kernel + UEFI).

---

### D3 — Page table management in mm ✅
**File:** `executive/mm/src/paging.rs` (new)
**Spec:** AC-PT2 – AC-PT6
**Reference:** `docs/references/phil-opp-writing-an-os-in-rust.md` §Paging Implementation
**Steps:**
1. Create `MmPageTables` wrapping `x86_64::structures::paging::OffsetPageTable`.
2. `MmPageTables::new(hhdm_offset)` — construct from `BootInfo.hhdm_offset`.
3. `map_page(virt: VirtAddr, phys: PhysAddr, flags: PageTableFlags)`:
   - Use `OffsetPageTable::map_to()`.
   - Allocate intermediate frames from buddy via a `BuddyFrameAllocator` impl.
   - Flush TLB via `x86_64::instructions::tlb::flush(virt)`.
4. `unmap_page(virt: VirtAddr) -> PhysAddr`:
   - Translate, unmap, flush, return freed physical frame to buddy.
5. Mark kernel text pages RX (no write), data/stack RW+NX.

**Done when:** `map_page` and `unmap_page` pass round-trip test; translate confirms mapping.

---

## Group E — Kernel heap (depends on D3)

### E1 — Initialise kernel heap ✅
**File:** `kernel/src/heap.rs` (new), `kernel/src/main.rs`
**Spec:** AC-HEAP1 – AC-HEAP5
**Reference:** `docs/references/phil-opp-writing-an-os-in-rust.md` §Heap Allocation
**Steps:**
1. Define `HEAP_START: u64 = 0xFFFF_8800_0000_0000` and `HEAP_SIZE: usize = 1024 * 1024` (1 MiB).
2. In `heap::init(page_tables: &mut MmPageTables)`:
   - For each 4 KiB page in `HEAP_START..HEAP_START+HEAP_SIZE`:
     - Allocate a physical frame from buddy.
     - Map it RW+NX using `page_tables.map_page()`.
3. Call `HEAP_ALLOCATOR.init(HEAP_START as usize, HEAP_SIZE)`.
4. Declare `#[global_allocator] static HEAP_ALLOCATOR: LockedHeap`.
5. Smoke test in `kernel_main`: `let _ = Box::new(0xDEAD_BEEFu64);` — must not panic.

**Done when:** AC-HEAP1–5 pass; `alloc` crate available everywhere in kernel.

---

## Group F — Integration + verification (depends on all above)

### F1 — Wire `kernel_main` init sequence ✅
**File:** `kernel/src/main.rs`
**Spec:** AC-KE1 – AC-KE4
**Steps:**
1. Implement `kernel_main(boot_info: &'static BootInfo) -> !`.
2. Call subsystems in spec order (see §Dependencies in spec.md).
3. After all inits, print: `kernel_main ready — ticks: {}, free_pages: {}`.
4. Enter liveness loop: every ~1 s (100 timer ticks) print `[alive] tick={n}` on serial.

**Done when:** QEMU serial shows each init step OK and ticking liveness output.

---

### F2 — QEMU smoke test script ✅
**File:** `tools/qemu-run.sh` (new)
**Steps:**
1. Build bootloader: `cargo build -p bootloader --target x86_64-unknown-uefi --profile kernel`.
2. Build kernel: `cargo build -p kernel --target x86_64-unknown-none --profile kernel`.
3. Assemble OVMF-based ESP image with both binaries.
4. Run: `qemu-system-x86_64 -bios OVMF.fd -drive format=raw,file=fat:rw:esp -serial stdio -display none -m 128M`.
5. Script exits 0 if serial output contains `kernel_main ready` within 10 s.

**Done when:** `./tools/qemu-run.sh` exits 0 in CI / locally.

---

### F3 — Buddy allocator: unit test suite ⬜
**File:** `executive/mm/src/buddy.rs` (test module)
**Spec:** AC-BMM1–5
**Steps:**
1. `test_add_single_region` — add 1024 pages, verify `total_pages = 1024`.
2. `test_alloc_and_free_order0` — alloc 1 page, free it, verify merge.
3. `test_alloc_exact_order` — alloc order-3 block (8 pages), verify PFN alignment.
4. `test_oom` — exhaust all pages, next alloc returns `None`.
5. `test_merge_buddies` — alloc two adjacent order-0 blocks, free both, verify they merge to order-1.

**Done when:** `cargo test -p executive-mm` shows 5 tests passing.

---

## Summary table

| Task | Group | Status | Blocks |
|---|---|---|---|
| A1 BootInfo ABI | A | ✅ | B1, B4, D2 |
| A2 IRQL model | A | ✅ | C3, E1 |
| B1 Parse UEFI map | B | ✅ | B4 |
| B2 Build page tables | B | ✅ | B4 |
| B3 Load kernel image | B | ✅ | B4 |
| B4 ExitBootServices + jump | B | ✅ | D2, F1 |
| C1 GDT TSS/IST | C | ✅ | — |
| C2 IDT page fault log | C | ✅ | — |
| C3 APIC timer | C | ✅ | F1 |
| D1 Buddy alloc/free | D | ✅ | D2, F3 |
| D2 Feed BootInfo to buddy | D | ✅ | D3 |
| D3 Page table mgmt (mm) | D | ✅ | E1 |
| E1 Kernel heap | E | ✅ | F1 |
| F1 kernel_main sequence | F | ✅ | — |
| F2 QEMU smoke test | F | ✅ | F1 |
| F3 Buddy unit tests | F | ✅ | — |

**Critical path:** A1 → B1 → B2 → B3 → B4 → D2 → D3 → E1 → F1 → F2

---

## Phase 2 preview (out of scope here, tracked separately)

- Context switching (KTHREAD save/restore, scheduler round-robin)
- `VirtualAlloc` backed by buddy + page tables (VAD tree)
- PE32 loader (map sections, resolve imports, set up PEB/TEB)
- First user-mode process running a simple NT native binary
