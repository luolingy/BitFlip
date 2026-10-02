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
# Usage (from the repo root), exactly as you would call cargo:
#   & .\scripts\cargo.ps1 build --workspace
#   & .\scripts\cargo.ps1 test --workspace
#   & .\scripts\cargo.ps1 clippy --all-targets -- -D warnings
#   & .\scripts\cargo.ps1 build --release -p bitflip-app -p bitflip-cli
#   & .\scripts\cargo.ps1 add serde --features derive
#
# Before pulling a NEW dependency, start the proxy in another terminal:
#   node scripts/crates-proxy.mjs
#
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads non-BOM files as
# ANSI, which breaks on UTF-8 comments.
#
# NOTE: this script deliberately declares NO param() block. Two reasons, both
# verified on Windows PowerShell 5.1.19041:
#   1. Declaring a second parameter (even unused) mis-binds
#      ValueFromRemainingArguments: "test --workspace" arrives as
#      @('--workspace','','test').
#   2. With a param() block, common parameters are recognized, so a repeated
#      short flag binds to the cmdlet parameter instead of being forwarded:
#      "build -p a -p b" fails with
#      "parameter 'PipelineVariable' is specified more than once" (-p is a
#      prefix of -PipelineVariable).
# Reading $args in a plain script forwards every token verbatim and avoids both.
# If you must add a parameter, verify these two cases by hand before committing.

$ErrorActionPreference = 'Continue'

$all = @($args)

# PowerShell's parser eats a bare '--' wherever it appears in a command line, and
# cargo needs it back: "clippy --all-targets -- -D warnings" must reach cargo as
# exactly that. Re-insert the separator at the position it was swallowed.
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

Write-Host ("[cargo.ps1] cargo " + ($all -join ' '))
& cargo @all
exit $LASTEXITCODE
