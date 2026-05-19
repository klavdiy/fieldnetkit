# FieldNet Kit (FNkit) — Windows launcher
# Requires Python 3 on PATH.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyScript = Join-Path $ScriptDir "fnkit.py"

if (-not (Test-Path -LiteralPath $PyScript)) {
    Write-Error "fnkit.py not found: $PyScript"
    exit 1
}

$launcher = $null
foreach ($name in @("python3", "python", "py")) {
    if (Get-Command $name -ErrorAction SilentlyContinue) {
        $launcher = $name
        break
    }
}

if (-not $launcher) {
    Write-Host "Error: Python 3 not found. Install from https://www.python.org/downloads/ and re-open the terminal." -ForegroundColor Red
    exit 1
}

if ($env:INSTALL_DEPS -eq "1") {
    $profile = if ($env:INSTALL_PROFILE) { $env:INSTALL_PROFILE } else { "minimal" }
    & (Join-Path $ScriptDir "scripts\install-deps.ps1") -Profile $profile
}

if ($launcher -eq "py") {
    & py -3 $PyScript @args
} else {
    & $launcher $PyScript @args
}
exit $LASTEXITCODE
