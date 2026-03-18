# micro-nt-os (Mino) — Claude Code Context

## Project goal
Build a minimal NT-compatible OS kernel in Rust that can run XP-era (2000–2007)
Win32 games. Target: "good enough" compatibility, not bit-perfect NT clone.

Primary game target: **Tom Clancy's Ghost Recon (2001) — GOG version (DRM-free, v1.4)**
Use GOG version only — original disc uses SafeDisc v2 which is out of scope.

---

## Architecture decisions (do not change without discussion)

### Kernel model
- Monolithic kernel with NT Executive layering (not microkernel)
- `no_std` throughout all kernel crates (`hal`, `kernel`, `executive/*`, `win32/*`)
- Tools (`tools/*`) are `std` and run on the host for analysis

### Address space (XP-compatible 2GB/2GB split on x86_64)
- User mode:   `0x0000_0000_0000_1000` – `0x0000_0000_7FFF_FFFF`
- Kernel mode: `0xFFFF_8000_0000_0000` – `0xFFFF_FFFF_FFFF_FFFF`
- Kernel image mapped at: `0xFFFF_8000_0010_0000`
- No ASLR by default — old games assume fixed load addresses
- Fixed user-mode addresses games depend on:
  - `0x00400000` — default .exe base (PE32 ImageBase default)
  - `0x77F00000` — NTDLL (XP SP2)
  - `0x7C800000` — kernel32.dll (XP SP2)
  - `0x7FFD0000` — SharedUserData (KUSER_SHARED_DATA)
  - `0x7FFDF000` — PEB (initial process)
  - `0x7FFDE000` — TEB (initial thread)

### OS version reported to games (NEVER change)
- `PEB.OSMajorVersion = 5`, `OSMinorVersion = 1` (Windows XP)
- `PEB.OSBuildNumber  = 2600` (XP SP2)
- `SharedUserData.NtMajorVersion = 5`, `NtMinorVersion = 1`
- `SharedUserData.TestRetInstruction = 0xC3` (INT 0x2E syscall path, max compat)

### GUI model (decided)
- **No Win32 desktop / no Win32k GDI** — games go fullscreen D3D exclusive only
- **Mino Display Server**: owns the physical framebuffer; arbitrates exclusive access
  - Mode A (launcher): Mino launcher renders its UI via egui → framebuffer
  - Mode B (game): D3D8/D3D9 `CreateDevice(Windowed=FALSE)` triggers exclusive handoff
  - On game exit: display server reclaims framebuffer, launcher redraws
- **Mino Launcher**: custom native Mino process (NOT Win32), immediate-mode UI
  - Shows game list, launches selected game via `NtCreateProcess`
  - Implemented in Phase 3 alongside the display server
- No window manager, no overlapping windows, no WM_PAINT, no GDI rasterizer

### Mino Launcher — UI design (decided)
Console-style full-screen game launcher, keyboard/gamepad navigable.
Inspired by PS3 XMB / Xbox 360 dashboard / Steam Big Picture.

**Three screens:**
1. **Game library** — horizontal card strip + hero panel for selected game
   - Reads `games.json` from FAT32 partition (path, name, year, DX version, genre)
   - Arrow keys / gamepad d-pad to navigate, Enter to launch
2. **Installer screen** — triggered on disc/USB insert
   - Progress bar: "Installing Ghost Recon... 73%"
   - Copies files to games partition via FAT32 driver
3. **Launch handoff** — Enter → `NtCreateProcess` → display server hands
   framebuffer to DXVK device → on game exit: launcher reclaims and redraws

**Rendering:** `egui` (pure Rust immediate-mode, renders to any framebuffer)

**Visual design (dark console theme):**
- Background: `#0a0a0f`, accent blue: `#378ADD`, text: `#e8e6e0`, muted: `#888780`
- Top bar: OS name + clock (13px)
- Hero panel: 180×240px cover art + title, year, DX API tag, genre tag, Play button
- Game strip: 130×170px cards, 16px gap, selected card = blue border highlight
- Bottom bar: "Install from disc / USB" + keyboard hint strip (← → Enter Del)

### Game installation strategy (decided)
MSI, InstallShield, NSIS, Inno Setup and GOG offline installers are NOT supported.
They require a near-complete Win32 subsystem — out of scope for Phase 3/4.

**Model: install on Windows, play on Mino** (same as gaming consoles).
Users install the game on Windows first, then use `mino-pack` host tool to
package the installed folder into a `.mpack` file for transfer to Mino.

**Workflow:**
```
1. Install game on Windows (GOG Galaxy, Steam, etc.) as normal
2. On host machine run:
     mino-pack pack "C:\GOG Games\Ghost Recon" --out ghostrecon.mpack
3. Copy ghostrecon.mpack to USB drive
4. Insert USB into Mino machine
5. Launcher shows "Install Ghost Recon? [Enter / Esc]"
6. Extracts .mpack → games FAT32 partition, writes games.json entry
7. Game appears in launcher library
```

**`.mpack` manifest (JSON header inside tar archive):**
```json
{
  "id":      "ghost-recon-2001",
  "name":    "Tom Clancy's Ghost Recon",
  "version": "1.4",
  "exe":     "GhostRecon.exe",
  "args":    ["-nointro"],
  "dx_api":  "d3d8",
  "year":    2001,
  "genre":   "Tactical shooter",
  "color_a": [13, 26, 46],
  "color_b": [26, 13, 42],
  "files":   ["GhostRecon.exe", "Data/", "Mods/", "dbghelp.old.dll"]
}
```

**Tools:**
- `tools/mino-pack/` — host-side packer (`std` Rust, Windows + Linux)
  - `mino-pack pack <folder> --out <file.mpack>`
  - `mino-pack info <file.mpack>`
- `tools/mino-unpack/` — Mino-side extractor (`no_std`, runs on Mino kernel)
  - Called by launcher on USB insert, writes to FAT32 games partition

**Installer support matrix:**

| Method | Supported | Phase |
|---|---|---|
| `.mpack` from USB | ✅ | 3 |
| `.bat` installer | ✅ | 3 (cmd.exe clone) |
| `.mpack` from disc | Phase 4 | After disc/ISO driver |
| MSI / InstallShield / NSIS / InnoSetup | ❌ | Never |
| GOG offline `.exe` installer | ❌ | Use GOG Galaxy on Windows first |

### DirectX strategy — use DXVK prebuilt PE binaries (decided)
DXVK ships as standard Windows PE DLLs that work without Wine.
Do NOT implement D3D8/D3D9 translation from scratch.

**Translation chain:**
```
GhostRecon.exe
  → DXVK d3d8.dll  (prebuilt PE — all D3D8→Vulkan translation, battle-tested)
  → DXVK d3d9.dll  (required dependency of d3d8.dll)
  → DXVK dxgi.dll  (swap chain / adapter)
  → vulkan-1.dll   ← THE ONLY FILE YOU WRITE (~500 lines Rust)
  → Vulkan HAL → GPU
```

**What to build vs borrow:**

| Component | Build | Borrow |
|---|---|---|
| NT kernel (HAL, Mm, Ps, Ke, Ob) | ✓ | — |
| Win32 stubs (kernel32, user32) | ✓ enough for DXVK init | — |
| `vulkan-1.dll` ICD loader shim | ✓ ~500 lines | — |
| D3D8/D3D9 translation | — | DXVK 2.4 prebuilt PE DLLs (zlib) |
| Audio (dsound) | — | OpenAL Soft prebuilt PE DLL |
| Input (dinput8) | ✓ thin HID wrapper | — |

**DXVK notes:**
- Version 2.4+ required (first release with D3D8 support from D8VK merger)
- `d3d8.dll` requires `d3d9.dll` alongside it — both must be present
- License: zlib — free to study, use, redistribute
- Place in `prebuilt/x32/` in the workspace; PE loader copies to game dir at launch

### DOS / cmd.exe (decided)
- **Phase 3**: `cmd.exe` clone — native Mino process, handles `.bat` installers
  - Commands: `COPY`, `XCOPY`, `MD`, `DEL`, `SET`, `IF EXIST`, `CALL`,
    `START`, `ECHO`, `@ECHO OFF`, `REM`, `EXIT`, `REG ADD`
- **Phase 4**: VDM stub — INT 21h subset (~20 functions) for DOS installer helpers
  - No v8086 mode, no DPMI — installer-only scope
- Full VDM (real DOS games, DPMI) deferred to Phase 5+

### Win32 ABI
- All Win32 exports use `stdcall` (`__stdcall`) calling convention
- 32-bit PE32 game binaries run in a Wow64-like compatibility layer (Phase 4)
- For now: assume 64-bit native games during early phases

### IRQL discipline (CRITICAL — never violate)
- Page faults only allowed at IRQL < DISPATCH (i.e. PASSIVE or APC)
- No heap allocation at `IRQL >= DISPATCH_LEVEL`
- All `spin::Mutex` usage implies DISPATCH_LEVEL — check call sites
- Use `ke::event::KEvent` for blocking waits, never spin at PASSIVE
- Tag every function with `/// # IRQL: PASSIVE` etc. in doc comments

### Memory safety rules for unsafe blocks
- Every `unsafe` block MUST have a `// SAFETY:` comment
- Raw pointer arithmetic: bounds-check before dereferencing
- FFI boundaries: validate all pointer arguments for null before use

---

## Current development phase

**PHASE 3 — Display server + launcher + DXVK + first game** (starting)

### Phase 1 ✅ / Phase 2 ✅ / Phase 2.5 ✅ / Phase 3 entry ✅
- [x] HAL: GDT, IDT, serial, IRQL, APIC timer, GOP framebuffer
- [x] Mm: buddy allocator, VAD tree, VirtualAlloc + page tables
- [x] Ke: KEvent, scheduler, APC/DPC, KTHREAD
- [x] Ob: object header, handle table, NT namespace
- [x] Ps: EPROCESS, ETHREAD, PEB32 (XP), TEB32
- [x] Io: IRP, driver/device objects, file object
- [x] Win32: kernel32, user32, winmm, msvcrt stubs
- [x] Bootloader: UEFI, 4-level paging (identity + HHDM)
- [x] Ring-3 IRETQ trampoline, INT 0x2E + SYSENTER syscall dispatch
- [x] PE32 loader + IAT patching — real MSVC PEs (RVA→file-offset via section table)
- [x] SharedUserData at 0x7FFE0000 (XP layout)
- [x] NtCreateProcess / NtCreateThread / NtTerminateProcess
- [x] FAT32 read-only driver (ramdisk probe, mkfat tool, dynamic image builder)
- [x] Win32 message pump (PeekMessage, DispatchMessage, WM_PAINT, WM_KEYDOWN)
- [x] DispatchMessageA → WndProc ring-3 call (hwnd→wndproc lookup, stub at 0x310)
- [x] ExitProcess → terminate_current_thread (scheduler context-switch out)
- [x] NtQueryInformationFile, NtClose
- [x] All 8 Phase 2.5 smoke markers passing + both Phase 3 bonus markers
- [x] Real MSVC PE32 (HELLO.EXE, no CRT) loads, runs Win32 message loop, exits cleanly

### Key bugs fixed
- **RVA ≠ file offset** (`loader.rs` `ImportIter`/`rva_to_str`): MSVC PE sections have
  `PointerToRawData ≠ VirtualAddress`. Added `rva_to_file_offset()` that walks the
  section table. Previously all import parsing silently returned empty for real PEs.
- **ExitProcess infinite HLT**: `win32_exit_process` spun without calling
  `terminate_current_thread()`, so the parent wait loop never unblocked.

### Phase 3 — Active
#### Immediate next steps (unblocked)
- [ ] **FAT32 write support** — needed for mino-unpack to install game files
- [ ] **NtCreateSection / NtMapViewOfSection** — DXVK DLLs use section-backed mapping
- [ ] **LoadLibraryA / GetProcAddress** — load DXVK DLLs at runtime from game dir
- [ ] **Relocations** (`IMAGE_DIRECTORY_ENTRY_BASERELOC`) — DXVK DLLs have ASLR relocs

#### Display & launcher
- [ ] **Mino display server** (framebuffer ownership, exclusive mode handoff)
- [ ] **Mino launcher** — console-style game selection UI
  - `egui` rendering to framebuffer, `games.json` config
  - Keyboard navigation, cover art placeholders, install screen
- [ ] `cmd.exe` clone (batch interpreter + debug shell)

#### DirectX / audio / input
- [ ] **`vulkan-1.dll` ICD loader shim** ← key Phase 3 deliverable
  - Re-exports every `vk*` symbol, routes to Mino HAL Vulkan backend
  - Enables DXVK prebuilt DLLs to load and run unmodified
- [ ] Add `prebuilt/x32/` with DXVK 2.4: `d3d8.dll`, `d3d9.dll`, `dxgi.dll`
- [ ] Validate DXVK PE DLLs load + IAT resolves against `vulkan-1.dll` shim
- [ ] `dsound.dll` → OpenAL Soft (prebuilt PE, drop-in)
- [ ] `dinput8.dll` → thin HID wrapper

#### Game installation
- [ ] **`mino-pack` host tool** — pack installed game folder → `.mpack` archive
- [ ] **`mino-unpack`** — Mino-side extractor, writes to FAT32 games partition

#### Milestone
- [ ] **Ghost Recon 2001 (GOG) boots to main menu** ← Phase 3 milestone

### Phase 4
- [ ] VDM stub (INT 21h ~20 functions, installer helpers)
- [ ] Wow64 (32-bit games on 64-bit kernel)
- [ ] Registry hive persistence
- [ ] NtCreateSection / MapViewOfSection

### Phase 5+
- [ ] Full VDM / v8086 / DPMI (real DOS games)
- [ ] DirectDraw (ddraw.dll)

---

## Ghost Recon 2001 — specific compatibility requirements

**GOG version only. Launch with `-nointro` to skip FMV (no ddraw.dll needed).**

### DLL sources

| DLL | Source |
|---|---|
| `d3d8.dll` | DXVK 2.4 prebuilt x32 |
| `d3d9.dll` | DXVK 2.4 prebuilt x32 (required by d3d8) |
| `dxgi.dll` | DXVK 2.4 prebuilt x32 |
| `vulkan-1.dll` | **Your shim — only D3D file to write** |
| `dsound.dll` | OpenAL Soft prebuilt |
| `dinput8.dll` | Your HID wrapper |
| `kernel32/user32/winmm/msvcrt` | Your stubs (exist) |

### Registry keys GR checks

```
HKLM\Software\Microsoft\DirectX\Version         = "4.08.00.0400"
HKLM\Software\Microsoft\DirectX\InstalledVersion = "4.08.00.0400"
HKLM\Software\Microsoft\Windows NT\CurrentVersion\CurrentVersion    = "5.1"
HKLM\Software\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber = "2600"
```

### Known GR quirks
- `QueryPerformanceFrequency` → return 1193182 (PIT freq, some engines expect this)
- `timeBeginPeriod(1)` → must achieve real 1ms timer resolution
- `CreateMutexA("DirectDrawDeviceHandle")` → named mutex in `\BaseNamedObjects\`
- `dbghelp.dll` in game folder conflicts — rename to `dbghelp.old.dll`
- Always launch with `-nointro` (FMV crashes without ddraw.dll)
- Fullscreen exclusive mode is broken on modern Windows — Mino avoids this entirely
  (display server owns framebuffer, hands directly to DXVK device)

---

## Crate dependency graph

```
bootloader → hal

kernel
  ├── hal  (gdt, idt, serial, timer, irql, ring3, fb, sysenter)
  ├── ke ── hal
  ├── mm ── hal
  ├── ob
  ├── ps ── ob, mm, ke
  ├── io-manager ── ob, ke
  └── bump-alloc

boot-info  (BootInfo struct)

display-server  (Phase 3)
launcher        (Phase 3 — egui UI, NOT Win32)
cmd             (Phase 3 — batch interpreter)

win32/kernel32 ── ob, ps, mm, io, ke
win32/user32
win32/winmm ── hal
win32/msvcrt
win32/vulkan-1  ← Phase 3: ICD shim (~500 lines)

prebuilt/x32/   ← DXVK 2.4: d3d8.dll d3d9.dll dxgi.dll
prebuilt/x32/   ← OpenAL Soft: dsound.dll

directx/dinput8  (HID wrapper — build this)

tools/pe-loader   (std, host only — analyse PE32 imports)
tools/mino-pack   (std, host only — pack installed game folder → .mpack)
tools/mino-unpack (no_std, Mino only — extract .mpack → FAT32 games partition)
```

---

## Build commands

```bash
cargo check --workspace
cargo build -p pe-loader
cargo run -p pe-loader -- /path/to/GhostRecon.exe
cargo build -p mino-pack           # host tool: pack game folder → .mpack
cargo run -p mino-pack -- pack "C:\GOG Games\Ghost Recon" --out ghostrecon.mpack
cargo build -p kernel --profile kernel
cargo build -p bootloader --target x86_64-unknown-uefi --profile kernel

# QEMU Phase 3 (with display)
# qemu-system-x86_64 -bios /usr/share/ovmf/OVMF.fd \
#   -drive format=raw,file=fat:rw:esp \
#   -serial stdio \
#   -device virtio-gpu-pci \
#   -display sdl
```

---

## Reference codebases

| Subsystem | Reference | Notes |
|---|---|---|
| NT data structures | ReactOS `ntoskrnl/` | EPROCESS, PEB, VAD offsets |
| Win32 API semantics | Wine `dlls/kernel32/`, `dlls/user32/` | Behaviour, error codes |
| D3D8/D3D9 concepts | DXVK `src/d3d8/`, `src/d3d9/` | Study for vulkan-1.dll design |
| Vulkan ICD loader | Khronos `vulkan-loader` | Port concepts to Rust |
| PE loader | ReactOS `ntdll/ldr/` | Import resolution, relocations |
| Memory manager | ReactOS `ntoskrnl/mm/` | VAD tree, PFN database |
| IRQL / scheduling | *Windows Internals* 7e ch. 3–4 | Authoritative |
| Kernel boot / HAL | os.phil-opp.com | GDT, IDT, paging in Rust no_std |
| Launcher UI | `egui` docs + examples | Immediate-mode framebuffer GUI |
| Ghost Recon compat | PCGamingWiki GR page | Bugs, patches, DLL requirements |

---

## NT status codes

```
STATUS_SUCCESS                = 0x0000_0000
STATUS_PENDING                = 0x0000_0103
STATUS_NO_MEMORY              = 0xC000_0017
STATUS_ACCESS_DENIED          = 0xC000_0022
STATUS_INVALID_HANDLE         = 0xC000_0008
STATUS_INVALID_PARAMETER      = 0xC000_000D
STATUS_NOT_IMPLEMENTED        = 0xC000_0002
STATUS_OBJECT_NAME_NOT_FOUND  = 0xC000_0034
STATUS_HANDLE_NOT_CLOSABLE    = 0xC000_0235
```

## NT syscall numbers (XP SP2 x86)

```
NtClose                    = 0x0019
NtAllocateVirtualMemory    = 0x0011
NtFreeVirtualMemory        = 0x0083
NtCreateEvent              = 0x0027
NtCreateFile               = 0x0029
NtCreateMutant             = 0x002F
NtCreateProcess            = 0x004F
NtCreateSection            = 0x0032
NtCreateThread             = 0x0035
NtMapViewOfSection         = 0x00A0
NtOpenFile                 = 0x00B7
NtProtectVirtualMemory     = 0x004D
NtQueryInformationProcess  = 0x00DA
NtQueryInformationFile     = 0x00EF
NtReadFile                 = 0x00F6
NtSetTimerResolution       = 0x0122
NtTerminateProcess         = 0x0101
NtUnmapViewOfSection       = 0x012A
NtWaitForSingleObject      = 0x00C9
NtWriteFile                = 0x0112
NtVdmControl               = 0x0133  ← stub: STATUS_NOT_IMPLEMENTED
```

---

## Game compatibility priority list

1. ~~NT native .exe (NtWriteFile, NtAllocateVirtualMemory, NtTerminateProcess)~~ ✅
2. ~~Minimal Win32 app (CreateWindow, RegisterClass, DispatchMessage, WndProc, ExitProcess)~~ ✅
   - Real MSVC-compiled PE32 (hello.exe 3 KiB, no CRT, `/entry:_start`)
   - Verified: IAT patching, Win32 message pump, WndProc dispatch, ExitProcess → thread termination
3. **Ghost Recon 2001 GOG — boots to main menu** ← Phase 3 milestone
4. Quake 3 Arena
5. Halo: Combat Evolved
6. Half-Life 2

---

## What NOT to do

- Do NOT implement MSI / InstallShield / NSIS / InnoSetup support — use mino-pack
- Do NOT implement D3D8/D3D9 translation — use DXVK prebuilt PE DLLs
- Do NOT write more than `vulkan-1.dll` shim for DirectX support
- Do NOT implement Win32k GDI — fullscreen D3D exclusive only
- Do NOT build a window manager — single fullscreen context only
- Do NOT target original disc Ghost Recon — SafeDisc v2 out of scope
- Do NOT implement real DOS / v8086 / DPMI before Phase 5
- Do NOT implement COM fully — stub only vtable slots games actually call
- Do NOT allocate on heap at `IRQL >= DISPATCH_LEVEL`
- Do NOT use `std` in kernel crates
- Do NOT change PEB OS version fields (OSMajorVersion=5, OSMinorVersion=1)
- Do NOT add dependencies without verifying `no_std` support