#!/usr/bin/env bash
# F2 — QEMU smoke test for micro-nt-os Phase 1.
#
# Usage:
#   ./tools/qemu-run.sh [--timeout N] [--memory M] [--ovmf /path/to/OVMF.fd]
#                       [--ovmf-code /path/to/code.fd] [--ovmf-vars /path/to/vars.fd]
#
# OVMF modes (auto-detected):
#   Combined  : single OVMF.fd  → -bios OVMF.fd
#   Split     : code.fd + vars  → -drive if=pflash (code ro) + (vars rw copy)
#
# Exits 0 if serial output contains "kernel_main ready" within the timeout.
# Exits 1 otherwise.
#
# Environment:
#   OVMF_PATH  — override combined OVMF firmware path
#   QEMU       — override qemu-system-x86_64 binary path

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TIMEOUT=30
MEMORY=256
OVMF_ARG=""
OVMF_CODE_ARG=""
OVMF_VARS_ARG=""

make_fat_img_with_mkfat() {
    local out="$1"
    # Build the host-side FAT image generator (std Rust, host target).
    echo "[F2] Building mkfat..."
    "$CARGO" build -p mkfat --manifest-path "$ROOT/Cargo.toml" --quiet

    # Locate the binary (cross-platform: .exe on Windows/MSYS).
    local mkfat="$ROOT/target/debug/mkfat"
    [[ -x "$mkfat" ]]     || mkfat="$ROOT/target/debug/mkfat.exe"
    [[ -x "$mkfat" ]]     || { echo "[F2] ERROR: mkfat binary not found"; exit 1; }

    # Optional Phase 3 binary: embed HELLO.EXE if it has been compiled.
    # Build it first if the source exists but the binary is missing/stale.
    local hello_src="$ROOT/target/win32test/hello.c"
    local hello_exe="$ROOT/target/win32test/hello.exe"
    local hello_bat="$ROOT/target/win32test/build.bat"
    # Inline path converter (cygpath if available, else identity).
    _wp() { command -v cygpath &>/dev/null && cygpath -w "$1" || echo "$1"; }

    if [[ -f "$hello_bat" ]] && { [[ ! -f "$hello_exe" ]] || [[ "$hello_src" -nt "$hello_exe" ]]; }; then
        echo "[F2] Building HELLO.EXE (MSVC x86)..."
        cmd //c "$(_wp "$hello_bat")" 2>&1 || echo "[F2] WARNING: HELLO.EXE build failed (skipping)"
    fi

    local extra_args=()
    if [[ -f "$hello_exe" ]]; then
        extra_args+=("$(_wp "$hello_exe"):HELLO.EXE")
        echo "[F2] Including HELLO.EXE in ramdisk"
    fi

    # DXVK x32 prebuilt DLLs (Phase 3: d3d8→d3d9→vulkan-1 chain)
    local dxvk_dir="$ROOT/prebuilt/x32"
    for dll in d3d8.dll d3d9.dll dxgi.dll; do
        local dll_path="$dxvk_dir/$dll"
        if [[ -f "$dll_path" ]]; then
            local fat_name
            fat_name="$(echo "$dll" | tr '[:lower:]' '[:upper:]')"
            extra_args+=("$(_wp "$dll_path"):$fat_name")
            echo "[F2] Including $dll ($(ls -lh "$dll_path" | awk '{print $5}')) in ramdisk"
        fi
    done

    "$mkfat" "$out" "${extra_args[@]}"
    echo "[F2] FAT image: $(ls -lh "$out" | awk '{print $5}') at $out"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)   TIMEOUT="$2";    shift 2 ;;
        --memory)    MEMORY="$2";     shift 2 ;;
        --ovmf)      OVMF_ARG="$2";   shift 2 ;;
        --ovmf-code) OVMF_CODE_ARG="$2"; shift 2 ;;
        --ovmf-vars) OVMF_VARS_ARG="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ── Locate cargo ───────────────────────────────────────────────────────────────
CARGO="${CARGO:-}"
for c in cargo "$HOME/.cargo/bin/cargo" "/c/Users/$USERNAME/.cargo/bin/cargo"; do
    if command -v "$c" &>/dev/null || [[ -x "$c" ]]; then CARGO="$c"; break; fi
done
if [[ -z "$CARGO" ]]; then echo "[F2] ERROR: cargo not found."; exit 1; fi

# ── Locate objcopy ────────────────────────────────────────────────────────────
# Prefer rust-objcopy/llvm-objcopy from the Rust toolchain.
OBJCOPY="${OBJCOPY:-}"
if [[ -z "$OBJCOPY" ]]; then
    # Glob all rustup toolchain bin dirs for rust-objcopy / llvm-objcopy.
    RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
    for name in rust-objcopy llvm-objcopy; do
        for cand in "$RUSTUP_HOME"/toolchains/*/lib/rustlib/*/bin/"$name"{,.exe}; do
            [[ -f "$cand" ]] && { OBJCOPY="$cand"; break 2; }
        done
    done
fi
# Fall back to any objcopy in PATH
if [[ -z "$OBJCOPY" ]]; then
    for cmd in rust-objcopy llvm-objcopy objcopy; do
        command -v "$cmd" &>/dev/null && { OBJCOPY="$cmd"; break; }
    done
fi
if [[ -z "$OBJCOPY" ]]; then
    echo "[F2] ERROR: No objcopy found. Run: rustup component add llvm-tools"
    exit 1
fi
echo "[F2] Using objcopy: $OBJCOPY"

# ── Build ──────────────────────────────────────────────────────────────────────
echo "[F2] Building bootloader (x86_64-unknown-uefi, profile=kernel)..."
"$CARGO" build -p bootloader --target x86_64-unknown-uefi --profile kernel \
    --manifest-path "$ROOT/Cargo.toml"

echo "[F2] Building kernel (x86_64-unknown-none, profile=kernel)..."
"$CARGO" build -p kernel --target x86_64-unknown-none --profile kernel \
    --manifest-path "$ROOT/Cargo.toml"

# ── Locate binaries ────────────────────────────────────────────────────────────
BL_EFI="$ROOT/target/x86_64-unknown-uefi/kernel/bootloader.efi"
KRN_ELF="$ROOT/target/x86_64-unknown-none/kernel/kernel"

[[ -f "$BL_EFI" ]] || { echo "[F2] ERROR: bootloader EFI not found at $BL_EFI"; exit 1; }
[[ -f "$KRN_ELF" ]] || { echo "[F2] ERROR: kernel ELF not found at $KRN_ELF"; exit 1; }

# ── Extract flat kernel binary ─────────────────────────────────────────────────
KRN_BIN="$ROOT/target/x86_64-unknown-none/kernel/kernel.bin"
# Always delete the old .bin so objcopy re-extracts from the current ELF.
rm -f "$KRN_BIN"
echo "[F2] Extracting flat binary: $OBJCOPY -O binary $KRN_ELF $KRN_BIN"
"$OBJCOPY" -O binary "$KRN_ELF" "$KRN_BIN"

# ── Assemble ESP directory ─────────────────────────────────────────────────────
RUNDIR="$ROOT/target/qemu-run"
ESP="$RUNDIR/esp"
rm -rf "$RUNDIR"
mkdir -p "$ESP/EFI/BOOT"

cp "$BL_EFI"  "$ESP/EFI/BOOT/BOOTX64.EFI"
cp "$KRN_BIN" "$ESP/kernel.bin"
make_fat_img_with_mkfat "$ESP/fat.img"

echo "[F2] ESP assembled at $ESP"
ls -lh "$ESP/EFI/BOOT/BOOTX64.EFI" "$ESP/kernel.bin" "$ESP/fat.img"

# ── Locate OVMF firmware ───────────────────────────────────────────────────────
# Strategy 1: combined OVMF.fd for -bios mode.
OVMF_COMBINED=""
for candidate in \
    "$OVMF_ARG" \
    "${OVMF_PATH:-}" \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/edk2/ovmf/OVMF.fd \
    /usr/local/share/qemu/OVMF.fd \
    /usr/share/qemu/OVMF.fd
do
    [[ -z "$candidate" ]] && continue
    [[ -f "$candidate" ]] && { OVMF_COMBINED="$candidate"; break; }
done

# Strategy 2: split edk2 code.fd + optional vars.fd for pflash mode.
OVMF_CODE=""
OVMF_VARS=""
for candidate in \
    "$OVMF_CODE_ARG" \
    "/c/Program Files/qemu/share/edk2-x86_64-code.fd" \
    /usr/share/qemu/edk2-x86_64-code.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.fd
do
    [[ -z "$candidate" ]] && continue
    [[ -f "$candidate" ]] && { OVMF_CODE="$candidate"; break; }
done

for candidate in \
    "$OVMF_VARS_ARG" \
    "/c/Program Files/qemu/share/edk2-x86_64-vars.fd" \
    /usr/share/qemu/edk2-x86_64-vars.fd
do
    [[ -z "$candidate" ]] && continue
    [[ -f "$candidate" ]] && { OVMF_VARS="$candidate"; break; }
done

# Decide which mode to use.
USE_PFLASH=0
if [[ -n "$OVMF_CODE" ]]; then
    USE_PFLASH=1
    CODE_SIZE="$(stat -c%s "$OVMF_CODE")"

    # Build writable vars: copy existing or create zeros of same size.
    OVMF_VARS_RW="$RUNDIR/edk2-vars-rw.fd"
    if [[ -n "$OVMF_VARS" ]]; then
        cp "$OVMF_VARS" "$OVMF_VARS_RW"
    else
        # Create a zero-filled vars image the same size as the code file.
        dd if=/dev/zero of="$OVMF_VARS_RW" bs=1 count="$CODE_SIZE" 2>/dev/null
    fi

    echo "[F2] OVMF pflash mode:"
    echo "     code (ro) : $OVMF_CODE  ($CODE_SIZE bytes)"
    echo "     vars (rw) : $OVMF_VARS_RW"
elif [[ -n "$OVMF_COMBINED" ]]; then
    echo "[F2] OVMF bios mode : $OVMF_COMBINED"
else
    echo "[F2] ERROR: OVMF firmware not found."
    echo "     On Windows: QEMU installs edk2-x86_64-code.fd in its share/ dir."
    echo "     Or set: OVMF_PATH=/path/to/OVMF.fd"
    exit 1
fi

# ── Locate QEMU ───────────────────────────────────────────────────────────────
QEMU_BIN="${QEMU:-}"
for candidate in \
    "qemu-system-x86_64" \
    "/c/Program Files/qemu/qemu-system-x86_64.exe" \
    "/usr/bin/qemu-system-x86_64"
do
    [[ -z "$candidate" ]] && continue
    if command -v "$candidate" &>/dev/null || [[ -x "$candidate" ]]; then
        QEMU_BIN="$candidate"; break
    fi
done
if [[ -z "$QEMU_BIN" ]]; then
    echo "[F2] ERROR: qemu-system-x86_64 not found. Install QEMU."
    exit 1
fi
echo "[F2] Using QEMU: $QEMU_BIN"

# ── Run QEMU ──────────────────────────────────────────────────────────────────
SERIAL_LOG="$RUNDIR/serial.log"
echo "[F2] Starting QEMU (timeout=${TIMEOUT}s, memory=${MEMORY}M)..."

# On Windows, the QEMU .exe needs native Windows paths (backslash).
# cygpath -w converts Unix/MSYS paths; fall back to identity if not available.
_winpath() { command -v cygpath &>/dev/null && cygpath -w "$1" || echo "$1"; }

# Build QEMU firmware args depending on mode.
FIRMWARE_ARGS=()
if [[ $USE_PFLASH -eq 1 ]]; then
    FIRMWARE_ARGS+=(
        -drive "if=pflash,format=raw,readonly=on,file=$(_winpath "$OVMF_CODE")"
        -drive "if=pflash,format=raw,file=$(_winpath "$OVMF_VARS_RW")"
    )
else
    FIRMWARE_ARGS+=(-bios "$(_winpath "$OVMF_COMBINED")")
fi

ESP_WIN="$(_winpath "$ESP")"
SERIAL_WIN="$(_winpath "$SERIAL_LOG")"

timeout "$TIMEOUT" "$QEMU_BIN" \
    "${FIRMWARE_ARGS[@]}" \
    -drive "format=raw,file=fat:rw:$ESP_WIN" \
    -serial "file:$SERIAL_WIN" \
    -display none \
    -m "${MEMORY}M" \
    -no-reboot \
    2>&1 | head -5 || true   # show first QEMU errors; allow timeout exit code

# ── Check output ──────────────────────────────────────────────────────────────
SUCCESS_TEXT="kernel_main ready"
SMOKE_TEXT="[smoke] int2e write path hit"
IAT_TEXT="[smoke] IAT NtWriteFile path hit"
CREATE_PROCESS_TEXT="[smoke] NtCreateProcess ok"
CREATE_THREAD_TEXT="[smoke] NtCreateThread ok"
FAT_PROBE_TEXT="[smoke] FAT read probe hit"
SYSENTER_TEXT="[smoke] SYSENTER path hit"
WNDPROC_TEXT="[smoke] WndProc called"
HELLO_EXE_TEXT="[smoke] HELLO.EXE ran ok"

if [[ -f "$SERIAL_LOG" ]] \
    && grep -Fq "$SUCCESS_TEXT" "$SERIAL_LOG" \
    && grep -Fq "$SMOKE_TEXT" "$SERIAL_LOG" \
    && grep -Fq "$IAT_TEXT" "$SERIAL_LOG" \
    && grep -Fq "$CREATE_PROCESS_TEXT" "$SERIAL_LOG" \
    && grep -Fq "$CREATE_THREAD_TEXT" "$SERIAL_LOG" \
    && grep -Fq "$FAT_PROBE_TEXT" "$SERIAL_LOG" \
    && grep -Fq "$SYSENTER_TEXT" "$SERIAL_LOG"
then
    echo "[F2] PASS — all Phase 2.5 smoke markers found"
    # Report bonus Phase 3 markers if present
    if grep -Fq "$WNDPROC_TEXT" "$SERIAL_LOG"; then
        echo "[F2] BONUS — Phase 3 WndProc marker also present"
    fi
    if grep -Fq "$HELLO_EXE_TEXT" "$SERIAL_LOG"; then
        echo "[F2] BONUS — Phase 3 HELLO.EXE (real MSVC PE32) ran successfully"
    fi
    echo "--- Serial output ---"
    cat "$SERIAL_LOG"
    exit 0
else
    echo "[F2] FAIL — required markers not found within ${TIMEOUT}s"
    echo "      required: '$SUCCESS_TEXT'"
    echo "      required: '$SMOKE_TEXT'"
    echo "      required: '$IAT_TEXT'"
    echo "      required: '$CREATE_PROCESS_TEXT'"
    echo "      required: '$CREATE_THREAD_TEXT'"
    echo "      required: '$FAT_PROBE_TEXT'"
    echo "      required: '$SYSENTER_TEXT'"
    echo "      optional: '$WNDPROC_TEXT'  ← Phase 3: Win32 WndProc dispatch via user32 stub"
    echo "--- Serial output ($SERIAL_LOG) ---"
    cat "$SERIAL_LOG" 2>/dev/null || echo "(no output)"
    exit 1
fi
