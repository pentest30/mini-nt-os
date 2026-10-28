# micro-nt-os (Mino) — Architecture & Implementation Guide

A simple text guide to what we have built and how it works.

---

## 1. What Is This Project?

**micro-nt-os** (nickname: Mino) is a minimal NT-compatible operating system kernel written in Rust. The goal is to run XP-era (2000–2007) Win32 games. We are not building a full Windows clone — we aim for "good enough" compatibility.

The kernel is **monolithic** (like real Windows NT): all core services run in kernel space. We use **no_std** everywhere — no standard library, only a small allocator for dynamic memory.

---

## 2. Boot Sequence (What Happens When You Power On)

### Step 1: UEFI Firmware

When the machine starts, the UEFI firmware runs first. It finds our bootloader on the EFI System Partition (ESP) and loads it.

### Step 2: Bootloader

Our bootloader (`bootloader` crate) runs as a UEFI application. It does:

1. **Load the kernel** — Reads `kernel.bin` from the ESP and puts it in physical memory at address 0x0010_0000 (1 MiB).

2. **Get the memory map** — Asks UEFI for the list of usable memory regions. We need this so the kernel knows which physical pages it can use.

3. **Build page tables** — Creates 4-level x86_64 page tables that map:
   - **Identity map**: Physical addresses 0–4 GiB map to the same virtual addresses (so we can access RAM before we switch to long mode).
   - **HHDM (Higher Half Direct Map)**: Physical RAM is also mapped at a high virtual address (around 0xFFFF_8000_0000_0000) so the kernel can access any physical frame.

4. **Fill BootInfo** — Writes a small structure with: kernel address, kernel size, memory map, HHDM offset. The kernel will read this.

5. **Exit UEFI** — Calls `ExitBootServices()`. After this, UEFI services (console, disk, etc.) are gone. We own the machine.

6. **Switch page tables** — Loads our PML4 into CR3. Now our mappings are active.

7. **Jump to kernel** — Sets up a stack, passes a pointer to BootInfo in RDI, and jumps to the kernel entry point.

### Step 3: Kernel Entry

The kernel (`kernel` crate) starts at `kernel_main`. The bootloader has already:
- Placed the kernel at 0x0010_0000 physical
- Built page tables so the kernel is also visible at HHDM + 0x0010_0000
- Passed a BootInfo pointer

The kernel never returns. It initialises everything and then hands control to user-mode code.

---

## 3. Kernel Initialisation Order

The kernel follows the NT startup sequence:

### 3.1 HAL (Hardware Abstraction Layer)

**What it does:** Abstracts the CPU and hardware from the rest of the kernel.

- **GDT (Global Descriptor Table)** — Defines memory segments. We have:
  - Kernel code and data (ring 0)
  - User code and data (ring 3)
  - A special segment for FS that points to the TEB (Thread Environment Block)
  - TSS (Task State Segment) with RSP0 for interrupt stacks and a double-fault stack

- **IDT (Interrupt Descriptor Table)** — Defines what happens when interrupts fire:
  - CPU exceptions (divide error, page fault, etc.) → panic or log
  - APIC timer (vector 0x20) → tick counter + scheduler
  - INT 0x2E → syscall gate (user code calls this to enter the kernel)

- **Serial port** — Writes log messages to COM1. Our only output during early boot.

- **APIC timer** — Calibrated to tick every ~1 ms. Drives the scheduler and prints "[alive] tick=N" every second.

- **IRQL** — Interrupt Request Level. Tracks whether we are in normal code (PASSIVE) or in an interrupt handler (DISPATCH or higher). We must not allocate heap memory at high IRQL.

### 3.2 Memory Manager (Mm)

**What it does:** Manages physical and virtual memory.

- **Buddy allocator** — Hands out physical pages (4 KiB frames). The bootloader gave us a memory map; we add all "usable" regions to the buddy. It never gives us pages that overlap the kernel image.

- **VAD tree** — Virtual Address Descriptor. Each process has a tree of regions: "this virtual range is mapped with these permissions." Used for VirtualAlloc and the PE loader.

- **VirtualAlloc** — Reserves and commits virtual address ranges. When you "commit," we ask the buddy for physical pages and map them into the page tables. We support user-mode mappings (USER_ACCESSIBLE flag).

- **Page tables** — We use the bootloader's 4-level tables. The kernel has a `MmPageTables` that wraps the active page table and can map/unmap pages.

### 3.3 Heap

The kernel needs dynamic memory (for Vec, Box, etc.). We use a **bump allocator**:

- Pre-allocate 4 MiB of physical pages
- Map them at virtual address 0xFFFF_8800_0000_0000
- The allocator just bumps a pointer. No free-list, no fragmentation. Simple and reliable.

### 3.4 Executive (Ke, Ob, Ps, Io)

- **Ke (Kernel)** — Scheduler, threads, events. We have a round-robin scheduler: boot thread, idle thread, and (later) user threads. The APIC timer fires every tick and calls `schedule()`, which switches to the next runnable thread.

- **Ob (Object Manager)** — Handles, names. Stubs for now. Real NT has a namespace of named objects (files, events, mutexes). We have the types but not the full implementation.

- **Ps (Process/Thread)** — Process and thread structures. We have EPROCESS, ETHREAD, PEB, TEB. The loader uses these.

- **Io (I/O)** — IRP, drivers, devices. Stubs. Real NT has a driver stack; we will add a FAT32 driver later.

### 3.5 Loader Demo

After init, the kernel runs `loader_demo`. This is our test: load a PE32 binary and run it in user mode.

---

## 4. How the PE Loader Works

### 4.1 What Is a PE32?

PE32 is the Windows executable format. A .exe file has:
- DOS header (starts with "MZ")
- NT headers (signature "PE", file header, optional header)
- Section table (.text, .data, etc.)
- Section data (code, globals)

The optional header tells us: image base (where to load), entry point (RVA), size of image.

### 4.2 load_image

1. **Parse** — Validate DOS and NT signatures, check PE32 (32-bit) magic.
2. **Choose address** — Use preferred image base (e.g. 0x0200_0000) or a forced base.
3. **Reserve + commit** — Call VirtualAlloc to map the full image size. Insert a VAD entry.
4. **Copy sections** — For each section (.text, .data), copy the raw bytes from the PE file into the mapped virtual addresses. Set page permissions (execute, read, write) per section.

The result: the PE is in memory at the right virtual address, ready to run.

### 4.3 setup_process

Before we can run user code, we need:

- **PEB (Process Environment Block)** — At 0x7FFD_E000. Contains: image base, OS version (5.1.2600 for XP), subsystem, etc. Games read this.

- **TEB (Thread Environment Block)** — At 0x7FFD_F000. Contains: pointer to PEB, stack base/limit, ClientId (PID, TID). The CRT and many APIs read `FS:[0x18]` to get the TEB. We set up a GDT segment so FS points to this page.

- **User stack** — 64 KiB at 0x7FFF_0000 (grows down). We map it and set TEB stack fields.

All of these are mapped with USER_ACCESSIBLE so ring-3 code can read them.

### 4.4 Test PE (build_test_pe32)

We don't load a real .exe from disk yet. Instead, we **build one in memory**:

- Valid PE32 headers
- .text section with hand-written x86 code
- .data section with syscall argument blocks

The code does:
1. **NtWriteFile** — Writes "[smoke] int2e write+alloc+term\n" to the console (serial).
2. **NtAllocateVirtualMemory** — Allocates 0x3000 bytes. The syscall writes the base address back.
3. **NtTerminateProcess** — Exits.
4. **JMP $** — Infinite loop (in case terminate is not reached).

---

## 5. Ring-3 Transition (User Mode)

### 5.1 Why Ring-3?

The CPU has privilege levels. Ring 0 = kernel (full access). Ring 3 = user (restricted). User code must run in ring-3. When it needs the kernel, it triggers an interrupt (INT 0x2E) and we switch to ring-0, handle the syscall, then return to ring-3.

### 5.2 How We Switch to Ring-3

We use **IRETQ** (Interrupt Return). The CPU uses IRET to return from an interrupt. We trick it:

1. Load **FS** with the TEB segment selector. So when we land in ring-3, `FS:[0x18]` already points to the TEB.

2. Push a fake "interrupt return" frame on the kernel stack:
   - SS = user data segment (ring-3)
   - RSP = top of user stack
   - RFLAGS = interrupts enabled
   - CS = user code segment (ring-3)
   - RIP = entry point of our PE

3. Execute **IRETQ**. The CPU pops this frame and "returns" to user mode. We are now executing our PE code at ring-3.

### 5.3 32-bit Compatibility Mode

We use 32-bit user segments (L=0, D=1 in the GDT). So the CPU runs in **IA-32e compatibility mode**: 64-bit kernel, 32-bit user. Our PE is 32-bit (PE32). This matches XP-era games.

---

## 6. Syscalls (How User Code Talks to the Kernel)

### 6.1 The INT 0x2E Gate

User code executes `INT 0x2E`. The CPU:
1. Switches to ring-0
2. Looks up vector 0x2E in the IDT
3. Jumps to our `syscall_gate` handler

We set the IDT entry with DPL=3 so user code is allowed to call it.

### 6.2 Syscall ABI (x86 NT Style)

On entry, the user has set:
- **EAX** = syscall number (e.g. 0x0112 for NtWriteFile)
- **EDX** = pointer to arguments on the user stack

We read EAX and EDX, call our dispatch function, and put the return value (NT status code) in EAX before returning.

### 6.3 Implemented Syscalls

| Syscall | Number | What it does |
|---------|--------|--------------|
| NtTerminateProcess | 0x00C2 | Exits the process. We return success. |
| NtWriteFile | 0x0112 | Writes bytes to a handle. We send them to the serial port. |
| NtAllocateVirtualMemory | 0x0011 | Reserves/commits user virtual memory. Uses VAD + buddy + page tables. |

### 6.4 Syscall Context

We have a global `SYSCALL_CTX` that holds a VAD tree and HHDM offset. NtAllocateVirtualMemory uses this to allocate in the "process" address space. For our single-process demo, this works. For multiple processes, we will need per-process context.

---

## 7. Scheduler (Preemption)

### 7.1 Threads

We have:
- **Boot thread** — Runs kernel_main, then loader_demo, then jumps to ring-3.
- **Idle thread** — Runs `hlt` in a loop. Used when nothing else is runnable.
- **User thread** — The one running our PE. (Currently not in the scheduler's run queue; kernel_main jumps to it directly. The timer still fires and can preempt it.)

### 7.2 Context Switch

Each thread has a **KContext**: saved CPU state (RSP, RIP, callee-saved registers). When we switch:
1. Save current thread's registers to its KContext
2. Load next thread's KContext
3. Jump to its RIP

The switch is written in assembly. We use static stacks (no heap in the switch path).

### 7.3 Timer Tick

Every ~1 ms the APIC timer fires. The handler:
1. Increments tick counter
2. Logs "[alive] tick=N" every 1000 ms
3. Sends EOI to the APIC
4. Calls the scheduler hook → `schedule()`

So even when our user code is running (or spinning in JMP $), the timer can fire and we can switch threads. This proves preemption works across ring-0 and ring-3.

---

## 8. Address Space Layout

### User Mode (0 – 2 GiB)

- 0x0000_1000 – 0x7FFF_FFFF: User space
- 0x0200_0000: Our test PE image base
- 0x7FFD_E000: PEB
- 0x7FFD_F000: TEB
- 0x7FFF_0000: Top of user stack (64 KiB below)

### Kernel Mode (High Half)

- 0xFFFF_8000_0010_0000: Kernel image (HHDM + 1 MiB)
- 0xFFFF_8800_0000_0000: Kernel heap (4 MiB)
- HHDM maps all physical RAM for the kernel to access

---

## 9. Crate Layout

```
bootloader     — UEFI app, loads kernel, builds page tables, jumps
boot-info      — BootInfo structure (kernel_phys_base, memory_map, etc.)
hal            — GDT, IDT, serial, timer, IRQL, ring3
bump-alloc     — Kernel heap allocator
kernel         — main.rs, syscall dispatch, loader_demo
executive/
  ke           — Scheduler, threads, KContext, events, APC, DPC
  mm           — Buddy, VAD, VirtualAlloc, paging
  ob           — Object manager (handles, namespace) — stubs
  ps           — Loader, PEB, TEB, EPROCESS, ETHREAD
  io           — IRP, drivers — stubs
win32/         — kernel32, user32, winmm, msvcrt — stubs
directx/       — d3d9, dsound, dinput8 — stubs
tools/pe-loader — Host tool to analyse PE files
```

---

## 10. What Works Today

- Boot from UEFI
- Physical memory management (buddy)
- Virtual memory (VAD, VirtualAlloc, page tables)
- Kernel heap (bump allocator)
- Thread scheduler (round-robin, context switch)
- PE32 loader (map sections, PEB/TEB, user stack)
- Ring-3 transition (IRETQ to 32-bit user code)
- Syscalls (NtTerminateProcess, NtWriteFile, NtAllocateVirtualMemory)
- Test PE that writes to serial, allocates memory, and exits

---

## 11. What's Next (Phase 2.5+)

- PE32 import resolution (IAT patching) — so we can load real .exe files that import from ntdll
- NtCreateProcess / NtCreateThread — run arbitrary executables
- FAT32 driver — read files from disk (ls, cat, load .exe)
- GOP framebuffer — text on screen instead of serial only
- SharedUserData — map at 0x7FFE0000 for GetTickCount, etc.
- Win32 + DirectX — for games

---

## 12. How to Run

Build the bootloader and kernel, put them on a UEFI bootable disk, and run in QEMU with serial output. You will see kernel logs and then "[smoke] int2e write+alloc+term" when the test PE runs, followed by "[alive] tick=N" every second from the timer.

---

*Last updated: Phase 2.5*
