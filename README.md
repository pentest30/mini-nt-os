# micro-nt-os

A minimal NT-compatible OS kernel written in Rust, targeting XP-era (2000–2007) Win32 game compatibility.

## Goal

Run XP-era games on bare metal by implementing the NT kernel + Win32 subsystem + DirectX translation layer in Rust.

## Architecture

```
┌─────────────────────────────────────────────────┐
│           XP-era game (.exe, PE32)              │
├─────────────────────────────────────────────────┤
│  Win32 subsystem                                │
│  kernel32 · user32 · winmm · msvcrt            │
├────────────────────┬────────────────────────────┤
│  DirectX shim      │  NT Executive              │
│  d3d9 · dsound     │  Ob · Ps · Mm · Io · Ke   │
│  dinput8           │                            │
├────────────────────┴────────────────────────────┤
│  NT Kernel (Ke) — scheduler, IRQL, APC, DPC    │
├─────────────────────────────────────────────────┤
│  HAL — GDT, IDT, APIC, serial, timer           │
├─────────────────────────────────────────────────┤
│  x86_64 hardware / QEMU                        │
└─────────────────────────────────────────────────┘
```

## Development phases

| Phase | Milestone |
|-------|-----------|
| 1 | HAL + physical memory manager + boot to kernel_main |
| 2 | Context switching + VirtualAlloc + PE32 loader + first process |
| 3 | Win32 message pump + D3D9→Vulkan + first game frame |
| 4 | Broad game compatibility (audio, input, save files) |

**Current phase: 2.5** — Ring-3 + syscalls + first native binary. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a full guide to what we have built and how it works.

## Quick start

```bash
# Prerequisites
rustup toolchain install nightly
rustup target add x86_64-unknown-uefi
cargo install cargo-make   # optional, for build scripts

# Check everything compiles
cargo check --workspace

# Analyse a game binary (host tool, runs on your machine)
cargo run -p pe-loader -- /path/to/game.exe

# Build the UEFI bootloader
cargo build -p bootloader --target x86_64-unknown-uefi --profile kernel

# Run in QEMU (once bootloader is functional)
# See docs/qemu.md for the full command
```

## Key references

- **Windows Internals** (Yosifovich et al.) — NT design bible
- **ReactOS** — open source NT-compatible kernel, primary reference for data structure layouts
- **Wine** — Win32 API implementation, reference for API semantics
- **DXVK** — D3D9→Vulkan translation, reference for DirectX shim architecture
- **Geoff Chappell's site** — undocumented NT internals (PEB/TEB offsets, syscall numbers)
- **"Writing an OS in Rust"** (Philipp Oppermann, https://os.phil-opp.com/) — Rust no_std kernel
  patterns for paging, IDT, heap allocation, and interrupt handling. See
  [`docs/references/phil-opp-writing-an-os-in-rust.md`](docs/references/phil-opp-writing-an-os-in-rust.md)
  for a full chapter-by-chapter relevance mapping to micro-nt-os Phase 1/2 tasks.

## Repository layout

```
micro-nt-os/
├── CLAUDE.md          ← Claude Code context (read this first)
├── Cargo.toml         ← workspace root
├── bootloader/        ← UEFI application, jumps to kernel
├── hal/               ← hardware abstraction (GDT, IDT, IRQL, timer)
├── kernel/            ← kernel entry point, heap allocator
├── executive/
│   ├── ke/            ← scheduler, sync, APC, DPC
│   ├── mm/            ← physical + virtual memory manager
│   ├── ob/            ← object manager, handle tables, namespace
│   ├── ps/            ← process + thread manager, PEB/TEB
│   └── io/            ← I/O manager, IRP, driver model
├── win32/
│   ├── kernel32/      ← core Win32 API (memory, process, timing, sync)
│   ├── user32/        ← window management, message pump
│   ├── winmm/         ← multimedia timer
│   └── msvcrt/        ← C runtime (malloc, memcpy, etc.)
├── directx/
│   ├── d3d9/          ← Direct3D 9 COM skeleton → Vulkan backend
│   ├── dsound/        ← DirectSound 8 → HDA audio
│   └── dinput8/       ← DirectInput 8 → HID
└── tools/
    └── pe-loader/     ← host tool: analyse PE32 game binaries
```

## Contributing / using Claude Code

This project is designed to be developed with [Claude Code](https://claude.ai/code).
The `CLAUDE.md` file at the root provides full context for every session.

Key rules:
- Every `unsafe` block needs a `// SAFETY:` comment
- No heap allocation at `IRQL >= DISPATCH_LEVEL`  
- PEB OS version fields must remain XP-compatible (5.1.2600)
- All Win32 exports use `stdcall` calling convention
