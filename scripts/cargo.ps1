# BitFlip dev entrypoint for cargo (Windows).
#
# Why a wrapper is needed:
#   - The sandbox/permissions only allow writes inside the repo, so CARGO_HOME
#     must live at <repo>/.cargo-home.
#   - Cargo's libcurl/Schannel backend cannot reach the network on this machine,
#     so crates.io is reached through the local Node proxy
#     (scripts/crates-proxy.mjs). The source replacement is generated into
#     .cargo-home/config.toml on first run, from scripts/cargo-home.config.toml.
#
# Usage (from the repo root):
#   & .\scripts\cargo.ps1 build --workspace
#   & .\scripts\cargo.ps1 test --workspace
#   & .\scripts\cargo.ps1 clippy --all-targets -- -D warnings
#   & .\scripts\cargo.ps1 add serde --features derive
#
# Keep this file's param() block to exactly ONE parameter. Windows PowerShell 5.1
# mis-binds ValueFromRemainingArguments when a second (unused) parameter is
# declared: "test --workspace" arrives as @('--workspace','','test'). Verified on
# 5.1.19041.6456. If a new parameter is needed, verify with a throwaway script
# first.
#
# Before pulling a NEW dependency, start the proxy in another terminal:
#   node scripts/crates-proxy.mjs
#
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads non-BOM files as
# ANSI, which breaks on UTF-8 comments.

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CargoArgs
)

# Deliberately NOT 'Stop': on Windows PowerShell 5.1 every stderr line from a
# native command (cargo prints progress there) would become a terminating error.
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $PSScriptRoot
$cargoHome = Join-Path $root '.cargo-home'
$env:CARGO_HOME = $cargoHome

New-Item -ItemType Directory -Force $cargoHome | Out-Null

$configPath = Join-Path $cargoHome 'config.toml'
if (-not (Test-Path $configPath)) {
    Copy-Item (Join-Path $PSScriptRoot 'cargo-home.config.toml') $configPath
    Write-Host "[cargo.ps1] generated $configPath (crates.io -> local proxy)"
    Write-Host "[cargo.ps1] start the proxy first: node scripts/crates-proxy.mjs"
}

$all = @()
if ($CargoArgs) { $all += $CargoArgs }

# PowerShell's parser eats a bare '--' wherever it appears in a command line, and
# cargo needs it back: "clippy --all-targets -- -D warnings" must reach cargo as
# exactly that. The separator goes right before the first tail token, which is
# where the caller put it -- so re-insert it at the position it was swallowed.
$separatorAt = -1
for ($i = 0; $i -lt $all.Count; $i++) {
    if ($all[$i] -match '^-D$|^--deny$') {
        $separatorAt = $i
        break
    }
}
if ($separatorAt -ge 0) {
    $all = @($all[0..($separatorAt - 1)]) + @('--') + @($all[$separatorAt..($all.Count - 1)])
}

Write-Host ("[cargo.ps1] cargo " + ($all -join ' '))
& cargo @all
exit $LASTEXITCODE
