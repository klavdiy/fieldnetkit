# Install ip_checker dependencies on Windows (winget/choco + pip).
# Usage: .\scripts\install-deps.ps1 [-Profile minimal|full|dns|pcap|owasp|enrichment]

param(
    [ValidateSet("minimal", "core", "full", "dns", "pcap", "owasp", "enrichment", "diagnostics", "scan", "all")]
    [string]$Profile = "minimal"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Invoke-IfCommand {
    param([string]$Name, [scriptblock]$Block)
    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        & $Block
        return $true
    }
    return $false
}

function Install-PipRequirements {
    param([string[]]$Files)
    $py = $null
    foreach ($name in @("python", "python3", "py")) {
        if (Get-Command $name -ErrorAction SilentlyContinue) { $py = $name; break }
    }
    if (-not $py) {
        Write-Warning "Python not found. Install Python 3.10+ first."
        return
    }
    if ($py -eq "py") {
        & py -3 -m pip install --upgrade pip
        foreach ($f in $Files) { & py -3 -m pip install -r (Join-Path $RepoRoot $f) }
    } else {
        & $py -m pip install --upgrade pip
        foreach ($f in $Files) { & $py -m pip install -r (Join-Path $RepoRoot $f) }
    }
}

function Install-Winget {
    param([string[]]$Ids)
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return $false }
    foreach ($id in $Ids) {
        Write-Host "winget install $id"
        winget install --id $id -e --accept-source-agreements --accept-package-agreements 2>$null
    }
    return $true
}

function Install-Choco {
    param([string[]]$Packages)
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) { return $false }
    foreach ($p in $Packages) {
        Write-Host "choco install $p -y"
        choco install $p -y
    }
    return $true
}

function Install-Core {
  $ok = Install-Winget @("Python.Python.3.12")
  if (-not $ok) { Install-Choco @("python") | Out-Null }
  Install-Choco @("whois") | Out-Null
}

function Install-Scan {
  Install-Choco @("nmap") | Out-Null
  if (-not $?) { Install-Winget @("Insecure.Nmap") | Out-Null }
}

function Install-Pcap {
  Install-Choco @("wireshark") | Out-Null
  if (-not $?) { Install-Winget @("WiresharkFoundation.Wireshark") | Out-Null }
}

switch ($Profile) {
    { $_ -in "minimal", "core" } { Install-Core }
    "diagnostics" { Install-Core }
    "scan" { Install-Scan }
    "pcap" { Install-Pcap }
    "dns" {
        Install-Core
        Install-PipRequirements @("requirements-dns.txt")
        Install-Pcap
    }
    "enrichment" { Install-PipRequirements @("requirements-optional.txt") }
    "owasp" {
        Install-Choco @("amass") | Out-Null
        Write-Host "Nettacker (AGPL): git clone https://github.com/OWASP/Nettacker.git `$HOME\Nettacker"
    }
    { $_ -in "full", "all" } {
        Install-Core
        Install-Scan
        Install-Pcap
        Install-PipRequirements @("requirements-dns.txt", "requirements-optional.txt")
        Install-Choco @("amass") | Out-Null
        Write-Host "Nettacker: clone to `$HOME\Nettacker (see docs/OWASP_THIRD_PARTY.md)"
    }
}

Write-Host "`nRunning dependency check..."
$check = Join-Path $RepoRoot "scripts\check_deps.py"
if (Get-Command python -ErrorAction SilentlyContinue) {
    python $check --group $Profile --no-fail
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 $check --group $Profile --no-fail
}

Write-Host "Done."
