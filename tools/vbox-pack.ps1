param(
    [string]$VhdPath = "",
    [int]$VhdSizeMb = 128,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-CommandPath {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Resolve-RustLlvmObjcopy {
    $rustc = Resolve-CommandPath -Names @("rustc")
    if (-not $rustc) { return $null }
    $sysroot = (& $rustc --print sysroot).Trim()
    if ([string]::IsNullOrWhiteSpace($sysroot)) { return $null }
    $hostLine = (& $rustc -vV | Where-Object { $_ -like "host:*" } | Select-Object -First 1)
    if (-not $hostLine) { return $null }
    $hostTriple = ($hostLine -replace "^host:\s*", "").Trim()
    if ([string]::IsNullOrWhiteSpace($hostTriple)) { return $null }
    $candidates = @(
        (Join-Path $sysroot "lib\rustlib\$hostTriple\bin\llvm-objcopy.exe"),
        (Join-Path $sysroot "lib\rustlib\$hostTriple\bin\llvm-objcopy"),
        (Join-Path $sysroot "lib\rustlib\$hostTriple\bin\rust-objcopy.exe"),
        (Join-Path $sysroot "lib\rustlib\$hostTriple\bin\rust-objcopy")
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

function Ensure-KernelBin {
    param(
        [string]$RepoRoot,
        [string]$ProfileDir
    )
    $targetRoot = Join-Path $RepoRoot "target"
    $kernelTargetDir = Join-Path $targetRoot "x86_64-unknown-none\$ProfileDir"
    $kernelBinPath = Join-Path $kernelTargetDir "kernel.bin"
    if (Test-Path -LiteralPath $kernelBinPath) { return $kernelBinPath }
    $kernelElfPath = Join-Path $kernelTargetDir "kernel"
    if (-not (Test-Path -LiteralPath $kernelElfPath)) {
        throw "Kernel ELF not found at $kernelElfPath"
    }
    $objcopy = Resolve-CommandPath -Names @("rust-objcopy", "llvm-objcopy")
    if (-not $objcopy) { $objcopy = Resolve-RustLlvmObjcopy }
    if (-not $objcopy) {
        throw "No objcopy found. Install llvm-tools or cargo-binutils."
    }
    & $objcopy -O binary $kernelElfPath $kernelBinPath
    if ($LASTEXITCODE -ne 0) {
        throw "objcopy failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $kernelBinPath)) {
        throw "kernel.bin not created at $kernelBinPath"
    }
    return $kernelBinPath
}

function New-FatImageFromMkfat {
    param(
        [string]$RepoRoot,
        [string]$OutPath
    )
    $cargo = Resolve-CommandPath -Names @("cargo")
    if (-not $cargo) { throw "cargo not found in PATH." }
    & $cargo build -p mkfat --manifest-path (Join-Path $RepoRoot "Cargo.toml") --quiet
    if ($LASTEXITCODE -ne 0) { throw "mkfat build failed." }
    $mkfat = Join-Path $RepoRoot "target\debug\mkfat.exe"
    if (-not (Test-Path -LiteralPath $mkfat)) {
        $mkfat = Join-Path $RepoRoot "target\debug\mkfat"
    }
    if (-not (Test-Path -LiteralPath $mkfat)) {
        throw "mkfat binary not found at target\debug\mkfat(.exe)"
    }
    & $mkfat $OutPath
    if ($LASTEXITCODE -ne 0) { throw "mkfat image generation failed." }
}


function Invoke-DiskpartScript {
    param([string[]]$Lines)
    $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "micro-nt-os-diskpart-$([guid]::NewGuid().ToString('N')).txt")
    try {
        $Lines | Set-Content -LiteralPath $tmp -Encoding ASCII
        & diskpart /s $tmp | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "diskpart failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force
        }
    }
}

function Get-VBoxManagePath {
    $vbox = Get-Command "VBoxManage.exe" -ErrorAction SilentlyContinue
    if ($null -ne $vbox) { return $vbox.Source }
    $cand = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    if (Test-Path -LiteralPath $cand) { return $cand }
    return $null
}

function Release-VBoxMediumAttachments {
    param([string]$Path)
    $vboxPath = Get-VBoxManagePath
    if ($null -eq $vboxPath) { return }
    $norm = [System.IO.Path]::GetFullPath($Path).ToLowerInvariant()
    $vms = & $vboxPath list vms 2>$null
    if ($LASTEXITCODE -ne 0) { return }
    foreach ($line in $vms) {
        if ($line -notmatch '^"([^"]+)"\s+\{[0-9a-fA-F-]+\}$') { continue }
        $vmName = $Matches[1]
        $info = & $vboxPath showvminfo $vmName --machinereadable 2>$null
        if ($LASTEXITCODE -ne 0) { continue }
        foreach ($kv in $info) {
            if ($kv -notmatch '^"([^"]+)"="(.*)"$') { continue }
            $slot = $Matches[1]
            $val = $Matches[2]
            if ($val -eq "none") { continue }
            $valNorm = ($val -replace '\\\\','\')
            try { $valNorm = [System.IO.Path]::GetFullPath($valNorm) } catch {}
            if ($valNorm.ToLowerInvariant() -ne $norm) { continue }
            if ($slot -notmatch '^(.+)-(\d+)-(\d+)$') { continue }
            $ctl = $Matches[1]
            $port = $Matches[2]
            $dev = $Matches[3]
            $prev = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                & $vboxPath storageattach $vmName --storagectl $ctl --port $port --device $dev --type hdd --medium none 1>$null 2>$null
            }
            finally {
                $ErrorActionPreference = $prev
            }
        }
    }
}

function Unlock-VhdIfBusy {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }

    # 1. PowerShell native dismount (works without diskpart, handles OS-level attachment)
    try { Dismount-DiskImage -ImagePath $Path -ErrorAction Stop } catch {}
    Start-Sleep -Milliseconds 300

    # 2. diskpart detach (handles diskpart-attached VHDs)
    try {
        Invoke-DiskpartScript -Lines @(
            "select vdisk file=""$Path""",
            "detach vdisk"
        )
    }
    catch {}

    Release-VBoxMediumAttachments -Path $Path
    $vboxPath = Get-VBoxManagePath
    if ($null -ne $vboxPath) {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & $vboxPath closemedium disk $Path 1>$null 2>$null
        }
        finally {
            $ErrorActionPreference = $prev
        }
    }
    Start-Sleep -Milliseconds 200
}

function Remove-VhdWithRetry {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    for ($i = 0; $i -lt 5; $i++) {
        Unlock-VhdIfBusy -Path $Path
        try {
            Remove-Item -LiteralPath $Path -Force
            return
        }
        catch {
            if ($i -eq 4) {
                throw "Impossible de supprimer le VHD verrouillé: $Path. Fermez VirtualBox/VMs puis réessayez."
            }
            Start-Sleep -Milliseconds 400
        }
    }
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot "..")
$profileDir = "kernel"

$vboxDir = Join-Path $repoRoot "target\vbox"
if ([string]::IsNullOrWhiteSpace($VhdPath)) {
    $VhdPath = Join-Path $vboxDir "micro-nt-os.vhd"
}
$VhdPath = [System.IO.Path]::GetFullPath($VhdPath)

$bootloaderEfi = Join-Path $repoRoot "target\x86_64-unknown-uefi\$profileDir\bootloader.efi"

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        cargo build -p bootloader --target x86_64-unknown-uefi --profile $profileDir
        if ($LASTEXITCODE -ne 0) { throw "Bootloader build failed." }
        cargo build -p kernel --target x86_64-unknown-none --profile $profileDir
        if ($LASTEXITCODE -ne 0) { throw "Kernel build failed." }
    }
    if (-not (Test-Path -LiteralPath $bootloaderEfi)) {
        throw "Bootloader EFI missing: $bootloaderEfi"
    }
    $kernelBin = Ensure-KernelBin -RepoRoot $repoRoot -ProfileDir $profileDir
    New-Item -ItemType Directory -Path $vboxDir -Force | Out-Null
    $fatImg = Join-Path $vboxDir "fat.img"
    New-FatImageFromMkfat -RepoRoot $repoRoot -OutPath $fatImg
    Remove-VhdWithRetry -Path $VhdPath
    $sizeKb = $VhdSizeMb * 1024

    # Pass 1 (diskpart): create VHD + attach + convert GPT
    Invoke-DiskpartScript -Lines @(
        "create vdisk file=""$VhdPath"" maximum=$sizeKb type=expandable",
        "select vdisk file=""$VhdPath""",
        "attach vdisk",
        "convert gpt"
    )
    Start-Sleep -Seconds 2

    # Pass 2 (PowerShell disk cmdlets): create primary partition, format FAT32, copy files.
    # We use 'primary' (not 'efi') so Windows assigns a drive letter; then we retag
    # the partition type to the EFI GUID via diskpart so UEFI firmware finds it.
    $diskImg  = Get-DiskImage -ImagePath $VhdPath
    $diskNum  = ($diskImg | Get-Disk).Number
    $part     = New-Partition -DiskNumber $diskNum -Size 60MB -AssignDriveLetter
    $null     = Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel "MICROOS" -Force -Confirm:$false
    $driveLetter = $part.DriveLetter
    if (-not $driveLetter) { throw "New-Partition did not assign a drive letter." }

    try {
        $root    = "$driveLetter`:\"
        $efiBoot = Join-Path $root "EFI\BOOT"
        New-Item -ItemType Directory -Path $efiBoot -Force | Out-Null
        Copy-Item -LiteralPath $bootloaderEfi -Destination (Join-Path $efiBoot "BOOTX64.EFI") -Force
        Copy-Item -LiteralPath $kernelBin     -Destination (Join-Path $root    "kernel.bin")   -Force
        Copy-Item -LiteralPath $fatImg        -Destination (Join-Path $root    "fat.img")      -Force
    }
    finally {
        # Retag partition to EFI System Partition GUID so UEFI firmware recognises it,
        # then detach the VHD cleanly.
        $partNum = $part.PartitionNumber
        Invoke-DiskpartScript -Lines @(
            "select vdisk file=""$VhdPath""",
            "select partition $partNum",
            "set id=C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
            "detach vdisk"
        )
    }
    Write-Host "VHD ready: $VhdPath"
    Write-Host "Contents:"
    Write-Host "  EFI\BOOT\BOOTX64.EFI"
    Write-Host "  kernel.bin"
    Write-Host "  fat.img"
}
finally {
    Pop-Location
}
