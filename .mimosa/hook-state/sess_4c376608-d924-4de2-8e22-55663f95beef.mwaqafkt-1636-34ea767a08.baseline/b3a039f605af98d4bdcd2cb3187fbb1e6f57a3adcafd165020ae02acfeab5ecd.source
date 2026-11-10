
# Mino (mini-nt-os)
<img width="1280" height="800" alt="image-1793803234557" src="https://github.com/pentest30/mini-nt-os/blob/claude/installer-desktop-redesign/docs/images/desktop-ui-redesign.png" />
**Mino is a free, open-source, Windows XP-compatible operating system with a kernel written in Rust.**

The system boots into an XP-style desktop (taskbar, Start menu, file explorer, Control Panel), where users can run 32-bit applications and games from the Windows XP era (2001–2008) without modifying them.

- **Written in Rust**: All privileged code (NT kernel, Win32 kernel subsystem, drivers).
- **Reused components**: ReactOS user-mode components (`ntdll`, `kernel32`, `user32`, `csrss`, `explorer`, etc.), using version-pinned binaries.

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│ PE32 i386 applications: explorer, notepad, D3D8/9 games…     │
├──────────────────────────────────────────────────────────────┤
│ Win32 DLLs and system processes (ReactOS, version-pinned)    │
│ d3d8/d3d9/ddraw → wined3d → opengl32 (Mesa, software render) │
├══════════════════════════════════════════════════════════════┤ ← ring 3 / ring 0
│ win32k (Rust): USER · GDI · fonts                             │
│ NT Executive (Rust): Ob · Ps · Mm · Io · Cm · Se · Lpc · Ex      │
│ Ke (Rust): dispatcher, scheduler, IRQL, APC, DPC              │
│ HAL and drivers (Rust)                                        │
├──────────────────────────────────────────────────────────────┤
│ UEFI bootloader (Rust) → ntoskrnl ELF64                       │
└──────────────────────────────────────────────────────────────┘
```

## Documentation

| **Document** | **Description** |
| --- | --- |
| [01 — Vision and Scope](https://github.com/pentest30/mini-nt-os/blob/main/docs/01-vision.md) | Goals, scope, and observable milestones |
| [02 — Architecture](https://github.com/pentest30/mini-nt-os/blob/main/docs/02-architecture.md) | Target architecture, component by component |
| [03 — Decisions](https://github.com/pentest30/mini-nt-os/blob/main/docs/03-decisions.md) | Architecture Decision Records (ADRs) |
| [04 — Audit and Reuse](https://github.com/pentest30/mini-nt-os/blob/main/docs/04-audit-reutilisation.md) | Existing codebase assessment and migration plan |
| [05 — Roadmap](https://github.com/pentest30/mini-nt-os/blob/main/docs/05-feuille-de-route.md) | Milestones M0–M10 and completion criteria |
| [06 — Conventions](https://github.com/pentest30/mini-nt-os/blob/main/docs/06-conventions.md) | Development guidelines (legal compliance, `unsafe`, IRQL, testing, Git) |

**Current milestone: M1 — Ke Kernel** (M0 is complete).

The current codebase still follows the previous architecture, in which Win32 functionality was reimplemented inside the kernel. The migration to the target architecture is described in the audit document.

## Quick Start

```bash
# Install the pinned nightly toolchain specified in rust-toolchain.toml
rustup toolchain install

# Run host tests, followed by headless QEMU boot tests
# validated using serial output markers
cargo xtask test

# Boot the OS in QEMU, with serial output redirected to stdio
cargo xtask run
```

QEMU and OVMF must be installed.

On Debian or Ubuntu:

```bash
sudo apt install qemu-system-x86 ovmf
```

Run `cargo xtask help` to see all available options.

## Supported Platforms

**QEMU (OVMF, q35)** is the primary reference platform, while **VirtualBox (EFI)** serves as a secondary testing platform.

Support for real x86-64 UEFI hardware is planned for milestone M9.

## Contributing — With or Without Claude Code

All contributions must follow [06 — Conventions](https://github.com/pentest30/mini-nt-os/blob/main/docs/06-conventions.md), starting with strict legal compliance:

- No Microsoft source code, binaries, or resources.
- Consulting leaked Windows XP or Windows Server 2003 source code is strictly prohibited.

The [`CLAUDE.md`](https://github.com/pentest30/mini-nt-os/blob/main/CLAUDE.md) file summarizes the project context and non-negotiable rules for Claude Code sessions.

## License

MIT for now. The final licensing decision remains open (ADR-007).
