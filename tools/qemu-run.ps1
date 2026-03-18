param(
    [int]$TimeoutSec = 10,
    [int]$MemoryMb = 128,
    [string]$QemuExe = "qemu-system-x86_64",
    [string]$OvmfPath = "",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FirstExistingPath {
    param([string[]]$Candidates)

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    return $null
}

function Resolve-CommandPath {
    param([string[]]$Names)

    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            return $cmd.Source
        }
    }

    return $null
}

function Resolve-RustLlvmObjcopy {
    $rustc = Resolve-CommandPath -Names @("rustc")
    if (-not $rustc) {
        return $null
    }

    $sysroot = (& $rustc --print sysroot).Trim()
    if ([string]::IsNullOrWhiteSpace($sysroot)) {
        return $null
    }

    $hostLine = (& $rustc -vV | Where-Object { $_ -like "host:*" } | Select-Object -First 1)
    if (-not $hostLine) {
        return $null
    }

    $hostTriple = ($hostLine -replace "^host:\s*", "").Trim()
    if ([string]::IsNullOrWhiteSpace($hostTriple)) {
        return $null
    }

    $candidates = @(
        (Join-Path $sysroot "lib\rustlib\$hostTriple\bin\llvm-objcopy.exe"),
        (Join-Path $sysroot "lib\rustlib\$hostTriple\bin\llvm-objcopy")
    )

    return Resolve-FirstExistingPath -Candidates $candidates
}

function Ensure-KernelBin {
    param(
        [string]$RepoRoot,
        [string]$ProfileDir
    )

    $targetRoot = Join-Path $RepoRoot "target"
    $kernelTargetDir = Join-Path $targetRoot "x86_64-unknown-none\$ProfileDir"
    $kernelBinPath = Join-Path $kernelTargetDir "kernel.bin"

    if (Test-Path -LiteralPath $kernelBinPath) {
        return $kernelBinPath
    }

    $elfCandidates = @(
        (Join-Path $kernelTargetDir "kernel"),
        (Join-Path $targetRoot "x86_64-unknown-none\release\kernel"),
        (Join-Path $targetRoot "x86_64-unknown-none\debug\kernel")
    )

    $kernelElfPath = Resolve-FirstExistingPath -Candidates $elfCandidates
    if (-not $kernelElfPath) {
        throw "kernel.bin not found, and no kernel ELF artifact found. Expected one of: $($elfCandidates -join ', ')."
    }

    $objcopy = Resolve-CommandPath -Names @("rust-objcopy", "llvm-objcopy")
    if (-not $objcopy) {
        $objcopy = Resolve-RustLlvmObjcopy
    }
    if (-not $objcopy) {
        throw "No objcopy found. Install cargo-binutils (rust-objcopy) or ensure rustup llvm-tools are installed."
    }

    Write-Host "Generating kernel.bin from $kernelElfPath via $objcopy..."
    & $objcopy -O binary $kernelElfPath $kernelBinPath
    if ($LASTEXITCODE -ne 0) {
        throw "objcopy failed with exit code $LASTEXITCODE while generating kernel.bin."
    }

    if (-not (Test-Path -LiteralPath $kernelBinPath)) {
        throw "objcopy reported success but kernel.bin was not created at $kernelBinPath."
    }

    return $kernelBinPath
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot "..")
$profileDir = "kernel"

$bootloaderEfi = Join-Path $repoRoot "target\x86_64-unknown-uefi\$profileDir\bootloader.efi"

$ovmfCandidates = @(
    $OvmfPath,
    "C:\Program Files\qemu\share\edk2-x86_64-code.fd",
    "C:\Program Files\qemu\share\OVMF.fd",
    "C:\Program Files\qemu\share\OVMF\OVMF_CODE.fd",
    "C:\ProgramData\chocolatey\lib\qemu\tools\share\edk2-x86_64-code.fd"
)

$resolvedOvmf = Resolve-FirstExistingPath -Candidates $ovmfCandidates
if (-not $resolvedOvmf) {
    $resolvedOvmf = "OVMF.fd"
}

$resolvedQemu = Resolve-CommandPath -Names @($QemuExe, "qemu-system-x86_64.exe")
if (-not $resolvedQemu) {
    throw "QEMU executable not found. Ensure '$QemuExe' is installed and in PATH."
}

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        Write-Host "Building bootloader (UEFI, profile=$profileDir)..."
        cargo build -p bootloader --target x86_64-unknown-uefi --profile $profileDir
        if ($LASTEXITCODE -ne 0) {
            throw "Bootloader build failed with exit code $LASTEXITCODE."
        }

        Write-Host "Building kernel (target x86_64-unknown-none, profile=$profileDir)..."
        cargo build -p kernel --target x86_64-unknown-none --profile $profileDir
        if ($LASTEXITCODE -ne 0) {
            throw "Kernel build failed with exit code $LASTEXITCODE."
        }
    }

    if (-not (Test-Path -LiteralPath $bootloaderEfi)) {
        throw "Bootloader EFI artifact not found: $bootloaderEfi"
    }

    $kernelBin = Ensure-KernelBin -RepoRoot $repoRoot -ProfileDir $profileDir

    $workDir = Join-Path $repoRoot "target\qemu-run"
    $espDir = Join-Path $workDir "esp"
    $efiBootDir = Join-Path $espDir "EFI\BOOT"
    $serialLog = Join-Path $workDir "serial.log"

    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $efiBootDir -Force | Out-Null

    Copy-Item -LiteralPath $bootloaderEfi -Destination (Join-Path $efiBootDir "BOOTX64.EFI") -Force
    Copy-Item -LiteralPath $kernelBin -Destination (Join-Path $espDir "kernel.bin") -Force

    Write-Host "Starting QEMU..."
    Write-Host "QEMU: $resolvedQemu"
    Write-Host "OVMF: $resolvedOvmf"

    $qemuArgs = @(
        "-bios", $resolvedOvmf,
        "-drive", "format=raw,file=fat:rw:$espDir",
        "-serial", "file:$serialLog",
        "-display", "none",
        "-m", "$MemoryMb",
        "-no-reboot"
    )

    $proc = Start-Process -FilePath $resolvedQemu -ArgumentList $qemuArgs -PassThru

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $successText = "kernel_main ready"
    $detected = $false

    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $serialLog) {
            $content = Get-Content -LiteralPath $serialLog -Raw -ErrorAction SilentlyContinue
            if ($null -ne $content -and $content.Contains($successText)) {
                $detected = $true
                break
            }
        }

        Start-Sleep -Milliseconds 200
    }

    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
    }

    if ($detected) {
        Write-Host "PASS: Found '$successText' in serial output within $TimeoutSec seconds."
        exit 0
    }

    Write-Error "FAIL: '$successText' not found within $TimeoutSec seconds."
    if (Test-Path -LiteralPath $serialLog) {
        Write-Host "Last 40 lines of serial output:"
        Get-Content -LiteralPath $serialLog | Select-Object -Last 40
    } else {
        Write-Host "No serial log produced at $serialLog."
    }
    exit 1
}
finally {
    Pop-Location
}
