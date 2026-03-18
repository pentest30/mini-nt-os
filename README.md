
## Mino — micro-nt-os

Mino is a bare-metal operating system kernel written entirely in Rust, designed to run XP-era Win32 games (2000–2007) on modern x86_64 hardware without Windows. It is not a Windows clone and not an emulator — it is a minimal, purpose-built NT-compatible kernel that implements just enough of the Windows NT architecture for real games to run natively on top of it.

### What it is

At its core Mino is a monolithic kernel structured after Windows NT's Executive layer model. It boots via UEFI, sets up 4-level x86_64 page tables, initialises the NT subsystems in the correct order, loads Win32 game binaries as PE32 executables, and dispatches their syscalls through a real NT-compatible syscall table. The OS version it reports to software is Windows XP SP2 (5.1.2600) — the same version those games were built for.

The project has five completed phases and is currently entering its third:

- The hardware abstraction layer handles GDT, IDT, APIC timer calibration, IRQL levels, serial output, and GOP framebuffer initialisation.
- The NT Executive implements the Object Manager (handle tables, named object namespace), Process Manager (EPROCESS, ETHREAD, PEB, TEB at exact XP offsets), Memory Manager (buddy allocator, VAD tree, VirtualAlloc backed by real page tables), I/O Manager (IRP lifecycle, driver/device objects), and Kernel layer (scheduler, KEvent, APC/DPC queues, KTHREAD context switching).
- Ring-3 user mode works — a PE32 binary can be loaded, have its imports resolved from stub DLLs, and run in unprivileged mode with INT 0x2E and SYSENTER syscall dispatch both functional.
- A read-only FAT32 driver is implemented. `NtCreateProcess` can load a real executable from disk.
- Win32 stubs for `kernel32.dll`, `user32.dll`, `winmm.dll`, and `msvcrt.dll` expose the ~50 APIs that XP-era games actually call, including a working message pump with `PeekMessage`, `DispatchMessage`, `WM_PAINT`, and `WM_KEYDOWN`.

### What makes it different

Most hobby OS projects stop at "hello world from ring 0" or at best a shell. Mino's scope is deliberately narrower and more concrete: run a specific game (Tom Clancy's Ghost Recon, 2001) from boot to main menu, with real 3D rendering. Every architectural decision is driven by that goal.

The DirectX strategy is intentionally pragmatic — rather than implementing D3D8 and D3D9 from scratch (a multi-year effort), Mino loads the prebuilt DXVK PE DLLs unmodified. DXVK already translates DirectX 8/9/10/11 to Vulkan with battle-tested compatibility. The only piece Mino writes itself is `vulkan-1.dll` — a thin ICD loader shim of around 500 lines that routes Vulkan calls from DXVK to Mino's HAL Vulkan backend. This collapses years of DirectX work into weeks.

The user-facing interface is a console-style game launcher — think PS3 XMB or Steam Big Picture — rendered with `egui` directly to the framebuffer. There is no Win32 desktop, no window manager, no GDI. Games run in D3D exclusive fullscreen, the display server hands the framebuffer directly to the DXVK device, and on exit it reclaims it. Game installation uses a custom `.mpack` archive format: users install games on Windows normally, run the `mino-pack` host tool to package the installed folder, copy it to USB, and the Mino launcher installs it directly.

### Technical facts

| Property | Value |
|---|---|
| Language | Rust (nightly, `no_std` throughout kernel) |
| Architecture | x86_64, bare metal, UEFI boot |
| NT compatibility | Windows XP SP2 (5.1.2600) |
| Syscall ABI | INT 0x2E + SYSENTER, exact XP SP2 syscall numbers |
| Memory model | 2GB/2GB user/kernel split, no ASLR, buddy allocator + VAD tree |
| DirectX | DXVK 2.4 prebuilt (D3D8/D3D9 → Vulkan), custom vulkan-1.dll shim |
| Audio | OpenAL Soft prebuilt PE DLL |
| Launcher UI | egui → raw framebuffer, console game launcher aesthetic |
| Primary target game | Tom Clancy's Ghost Recon (2001), GOG version |
| Current phase | Phase 3 — display server, launcher, vulkan-1.dll, DXVK integration |

### What it is not

Mino does not implement DRM bypass — it targets DRM-free GOG versions of games. It does not implement a full Win32 desktop or Win32k GDI. It does not support MSI or graphical installers. It does not run DOS games (v8086 support is deferred to Phase 5). It is not trying to be ReactOS — the goal is game compatibility, not full NT fidelity.

### Status

Phases 1 and 2 are complete. The kernel boots on VirtualBox and QEMU, reaches `kernel_main`, initialises all NT subsystems, runs ring-3 code, dispatches syscalls, and can load and execute a real PE32 binary from a FAT32 ramdisk. Phase 3 is beginning: display server, game launcher UI, `vulkan-1.dll` shim, DXVK integration, and the first game rendering a frame.
