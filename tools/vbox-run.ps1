param(
    [string]$VmName = "micro-nt-os",
    [string]$VhdPath = "",
    [string]$SerialLog = "",
    [int]$MemoryMb = 256,
    [int]$TimeoutSec = 60,
    [switch]$CreateVmIfMissing
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

function Invoke-VBoxManage {
    param([string[]]$Args)
    & $script:VBoxManage @Args
    if ($LASTEXITCODE -ne 0) {
        throw "VBoxManage failed: $($Args -join ' ')"
    }
}

function Invoke-VBoxManageBestEffort {
    param([string[]]$Args)
    & $script:VBoxManage @Args 2>$null *> $null
    return $LASTEXITCODE
}

function Test-VmExists {
    param([string]$Name)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $script:VBoxManage showvminfo $Name --machinereadable 1>$null 2>$null
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        $ErrorActionPreference = $prev
    }
}

function Get-VmState {
    param([string]$Name)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & $script:VBoxManage showvminfo $Name --machinereadable 2>$null
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($LASTEXITCODE -ne 0) {
        return ""
    }
    foreach ($line in $lines) {
        if ($line -like 'VMState=*') {
            return ($line -replace '^VMState="', '' -replace '"$', '')
        }
    }
    return ""
}

function Test-VhdAttached {
    param([string]$Name, [string]$ExpectedPath)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & $script:VBoxManage showvminfo $Name --machinereadable 2>$null
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($LASTEXITCODE -ne 0) { return $false }
    $sata00 = $null
    foreach ($line in $lines) {
        if ($line -match '^"SATA-0-0"="(.*)"$') {
            $sata00 = $Matches[1]
        }
        if ($line -notmatch '^"[^"]+-\d+-\d+"="(.*)"$') { continue }
        $raw = $Matches[1]
        if ($raw -eq "none") { continue }
        $norm = ($raw -replace '\\\\','\')
        try { $norm = [System.IO.Path]::GetFullPath($norm) } catch {}
        if ($norm.ToLowerInvariant().EndsWith("\micro-nt-os.vhd")) { return $true }
    }
    if ($null -ne $sata00 -and $sata00 -ne "none") {
        return $true
    }
    return $false
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot "..")
$vboxDir = Join-Path $repoRoot "target\vbox"
if ([string]::IsNullOrWhiteSpace($VhdPath)) {
    $VhdPath = Join-Path $vboxDir "micro-nt-os.vhd"
}
if ([string]::IsNullOrWhiteSpace($SerialLog)) {
    $SerialLog = Join-Path $vboxDir "serial-vbox.log"
}
$VhdPath = [System.IO.Path]::GetFullPath($VhdPath)
$SerialLog = [System.IO.Path]::GetFullPath($SerialLog)

if (-not (Test-Path -LiteralPath $VhdPath)) {
    throw "VHD not found: $VhdPath. Run tools\vbox-pack.ps1 first."
}

$script:VBoxManage = Resolve-CommandPath -Names @("VBoxManage.exe", "VBoxManage")
if (-not $script:VBoxManage) {
    $cand = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    if (Test-Path -LiteralPath $cand) {
        $script:VBoxManage = $cand
    }
}
if (-not $script:VBoxManage) {
    throw "VBoxManage not found. Install VirtualBox or add VBoxManage to PATH."
}

New-Item -ItemType Directory -Path (Split-Path -Parent $SerialLog) -Force | Out-Null
if (Test-Path -LiteralPath $SerialLog) {
    Remove-Item -LiteralPath $SerialLog -Force
}

$vmExists = ((Invoke-VBoxManageBestEffort -Args @("showvminfo", $VmName, "--machinereadable")) -eq 0)
if (-not $vmExists) {
    if (-not $CreateVmIfMissing) {
        Write-Host "VM '$VmName' not found; creating it automatically."
    }
    Invoke-VBoxManage -Args @("createvm", "--name", $VmName, "--ostype", "Other_64", "--register")
    Invoke-VBoxManage -Args @("storagectl", $VmName, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci")
}
for ($i = 0; $i -lt 10; $i++) {
    if ((Invoke-VBoxManageBestEffort -Args @("showvminfo", $VmName, "--machinereadable")) -eq 0) {
        break
    }
    Start-Sleep -Milliseconds 200
}
if ((Invoke-VBoxManageBestEffort -Args @("showvminfo", $VmName, "--machinereadable")) -ne 0) {
    throw "VM '$VmName' is still not visible to VBoxManage. Verify VirtualBox registration and permissions."
}

Invoke-VBoxManage -Args @("modifyvm", $VmName, "--firmware", "efi", "--memory", "$MemoryMb", "--ioapic", "on")
Invoke-VBoxManage -Args @("modifyvm", $VmName, "--uart1", "0x3F8", "4")
Invoke-VBoxManage -Args @("modifyvm", $VmName, "--uartmode1", "file", $SerialLog)

$null = Invoke-VBoxManageBestEffort -Args @("storageattach", $VmName, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", "none")
Invoke-VBoxManage -Args @("storageattach", $VmName, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", $VhdPath)
if (-not (Test-VhdAttached -Name $VmName -ExpectedPath $VhdPath)) {
    Invoke-VBoxManage -Args @("storageattach", $VmName, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", $VhdPath)
}
if (-not (Test-VhdAttached -Name $VmName -ExpectedPath $VhdPath)) {
    throw "VHD not attached to VM '$VmName' after storageattach. Check controller name and VirtualBox VM settings."
}

if ((Get-VmState -Name $VmName) -eq "running") {
    Invoke-VBoxManage -Args @("controlvm", $VmName, "poweroff")
    Start-Sleep -Seconds 1
}

Invoke-VBoxManage -Args @("startvm", $VmName, "--type", "headless")

$requiredMarkers = @(
    "kernel_main ready",
    "[smoke] int2e write path hit",
    "[smoke] NtCreateProcess ok",
    "[smoke] NtCreateThread ok"
)

$deadline = (Get-Date).AddSeconds($TimeoutSec)
$pass = $false
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $SerialLog) {
        $content = Get-Content -LiteralPath $SerialLog -Raw -ErrorAction SilentlyContinue
        if ($null -ne $content) {
            $allFound = $true
            foreach ($m in $requiredMarkers) {
                if (-not $content.Contains($m)) {
                    $allFound = $false
                    break
                }
            }
            if ($allFound) {
                $pass = $true
                break
            }
        }
    }
    Start-Sleep -Milliseconds 300
}

if ((Get-VmState -Name $VmName) -eq "running") {
    Invoke-VBoxManage -Args @("controlvm", $VmName, "poweroff")
}

if ($pass) {
    Write-Host "PASS: VBox serial log contains all required smoke markers."
    exit 0
}

Write-Error "FAIL: VBox run did not reach required markers within $TimeoutSec seconds."
if (Test-Path -LiteralPath $SerialLog) {
    Write-Host "Last 80 lines:"
    Get-Content -LiteralPath $SerialLog | Select-Object -Last 80
}
exit 1
