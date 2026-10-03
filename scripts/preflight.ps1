# BitFlip preflight: one-shot version of the CLAUDE.md section 5 checklist.
#
# Runs: staged temp/ guard, cargo fmt --check, clippy -D warnings, tests,
# (when web/node_modules exists) the SPA typecheck, and (when a built binary
# exists) the bind-address smoke test.
#
# Exits non-zero if any step fails, so it can be used by hand or in a hook.
#
# Usage:
#   & .\scripts\preflight.ps1
#   & .\scripts\preflight.ps1 -SkipWeb -SkipSmoke
#
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads non-BOM files as
# ANSI, so any non-ASCII byte breaks parsing (see CLAUDE.md section 6).

[CmdletBinding()]
param(
    [switch]$SkipWeb,
    [switch]$SkipSmoke
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoWrapper = Join-Path $PSScriptRoot 'cargo.ps1'

$script:results = New-Object System.Collections.ArrayList

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host ("=== " + $Name)
    $code = 0
    & $Action
    # Native commands set $LASTEXITCODE; the temp-guard step sets it explicitly.
    if ($null -ne $LASTEXITCODE) { $code = $LASTEXITCODE }

    if ($code -eq 0) {
        [void]$script:results.Add(@{ Name = $Name; Ok = $true })
        Write-Host ("--- OK   " + $Name)
    }
    else {
        [void]$script:results.Add(@{ Name = $Name; Ok = $false; Code = $code })
        Write-Host ("--- FAIL " + $Name + " (exit " + $code + ")")
    }
    return $code
}

Push-Location $repoRoot
try {
    Write-Host "BitFlip preflight"
    Write-Host ("  repo: " + $repoRoot)

    Invoke-Step -Name 'temp/ not staged' -Action {
        $staged = git diff --cached --name-only | Select-String '^temp/'
        if ($staged) {
            Write-Host "staged content under temp/ must be removed:" -ForegroundColor Red
            $staged | ForEach-Object { Write-Host ("  " + $_.Line) }
            $global:LASTEXITCODE = 1
        }
        else {
            $global:LASTEXITCODE = 0
        }
    } | Out-Null

    Invoke-Step -Name 'cargo fmt --check' -Action {
        & $cargoWrapper fmt --all -- --check
    } | Out-Null

    Invoke-Step -Name 'cargo clippy -D warnings' -Action {
        & $cargoWrapper clippy --all-targets -- -D warnings
    } | Out-Null

    Invoke-Step -Name 'cargo test --workspace' -Action {
        & $cargoWrapper test --workspace
    } | Out-Null

    # PLAN M5 acceptance criterion 3. Cheap (a grep) and guards an invariant
    # that decays silently, so it runs before the slow web/smoke steps.
    Invoke-Step -Name 'arch layering (M5 gate)' -Action {
        & (Join-Path $PSScriptRoot 'check-arch-layering.ps1') | Out-Host
    } | Out-Null

    if (-not $SkipWeb) {
        $webDir = Join-Path $repoRoot 'web'
        $nodeModules = Join-Path $webDir 'node_modules'
        if (Test-Path -LiteralPath $nodeModules) {
            Invoke-Step -Name 'npm run typecheck' -Action {
                Push-Location $webDir
                try { npm run typecheck } finally { Pop-Location }
            } | Out-Null
        }
        else {
            Write-Host ""
            Write-Host "=== npm run typecheck"
            Write-Host "--- SKIP (web/node_modules missing; run: npm install --cache .npm-cache)"
        }
    }

    # The loopback-only bind is a security claim, so it is checked against a real
    # listening socket rather than the CLI default. Skipped when nothing is built.
    if (-not $SkipSmoke) {
        $smokeBin = Join-Path $repoRoot '.cargo-target/debug/bitflip-cli.exe'
        if (Test-Path -LiteralPath $smokeBin) {
            Invoke-Step -Name 'loopback-only bind' -Action {
                & (Join-Path $PSScriptRoot 'smoke-bind.ps1') -Bin '.cargo-target/debug/bitflip-cli.exe' | Out-Host
            } | Out-Null
        }
        else {
            Write-Host ""
            Write-Host "=== loopback-only bind"
            Write-Host "--- SKIP (no debug binary; run: & .\scripts\cargo.ps1 build --workspace)"
        }
    }

    Write-Host ""
    Write-Host "summary"
    $failed = @($script:results | Where-Object { -not $_.Ok })
    foreach ($result in $script:results) {
        $mark = 'PASS'
        if (-not $result.Ok) { $mark = 'FAIL' }
        Write-Host ("  " + $mark + "  " + $result.Name)
    }

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host ("preflight FAILED: " + $failed.Count + " step(s)") -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    Write-Host "preflight passed"
    exit 0
}
finally {
    Pop-Location
}
