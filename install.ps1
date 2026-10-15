# Moto Firmware Downloader (MFD) installer for Windows.
# GitHub-only distribution: no npm registry, no tokens involved.
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/JoshRob297/moto-firmware-downloader/main/install.ps1 | iex
#
# Environment overrides:
#   MFD_DEST   install directory (default: %LOCALAPPDATA%\mfd)
#   MFD_REF    install from a git ref branch/tag instead of the latest release
#   MFD_SOURCE path to a local mfd-cli.mjs

$ErrorActionPreference = 'Stop'

$Repo = 'JoshRob297/moto-firmware-downloader'
$BinName = 'mfd'
$DestDir = if ($env:MFD_DEST) { $env:MFD_DEST } else { Join-Path $env:LOCALAPPDATA 'mfd' }

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    Write-Error '[!] Node.js 18 or newer is required. Install it from https://nodejs.org'
}

$major = [int](& node -e "console.log(process.versions.node.split('.')[0])")
if ($major -lt 18) {
    Write-Error "[!] Node.js 18 or newer is required, found $(& node -v)"
}

$Target = Join-Path $DestDir 'mfd-cli.mjs'

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null

if ($env:MFD_SOURCE) {
    Write-Host "[*] Installing from local file $($env:MFD_SOURCE)..."
    Copy-Item -Force $env:MFD_SOURCE $Target
} else {
    if ($env:MFD_REF) {
        $Urls = @("https://raw.githubusercontent.com/$Repo/$($env:MFD_REF)/mfd-cli.mjs")
        Write-Host "[*] Fetching mfd-cli.mjs (git ref $($env:MFD_REF))..."
    } else {
        $Urls = @(
            "https://github.com/$Repo/releases/latest/download/mfd-cli.mjs",
            "https://raw.githubusercontent.com/$Repo/main/mfd-cli.mjs"
        )
        Write-Host '[*] Fetching mfd-cli.mjs (latest release, fallback: main branch)...'
    }

    $Fetched = $false
    foreach ($Url in $Urls) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing
            $Fetched = $true
            break
        } catch {
            Write-Host "[!] Could not fetch $Url"
        }
    }

    if (-not $Fetched) {
        Write-Error "[!] All download sources failed. Check your network path with 'mfd doctor'."
    }
}

if ((Get-Item $Target).Length -eq 0) {
    Write-Error '[!] Downloaded file is empty. Check the ref or your network path.'
}

& node --check $Target

$Shim = Join-Path $DestDir 'mfd.cmd'
$ShimContent = "@echo off`r`nnode `"%~dp0mfd-cli.mjs`" %*`r`n"
Set-Content -Path $Shim -Value $ShimContent -Encoding ASCII

Write-Host "[+] Installed $BinName -> $Shim"

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($UserPath -notlike "*$DestDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$UserPath;$DestDir", 'User')
    Write-Host "[!] Added $DestDir to the user PATH. Restart your terminal to use '$BinName'."
} else {
    Write-Host "[*] $DestDir is already in PATH."
}

& node $Target --version
