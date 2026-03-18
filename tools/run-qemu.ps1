param(
    [int]$Timeout = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$gitBash = "C:\Program Files\Git\bin\bash.exe"

if (-not (Test-Path -LiteralPath $gitBash)) {
    throw "Git Bash not found at '$gitBash'. Install Git for Windows or update this path."
}

$repoPosix = $repoRoot -replace "\\", "/"
if ($repoPosix -match "^([A-Za-z]):/(.*)$") {
    $drive = $Matches[1].ToLowerInvariant()
    $rest = $Matches[2]
    $repoPosix = "/$drive/$rest"
}

$cmd = "cd '$repoPosix' && ./tools/qemu-run.sh --timeout $Timeout"
& $gitBash -lc $cmd
exit $LASTEXITCODE
