# Reclaims disk space and removes transient build artifacts.
#
# Why a script instead of "just delete the files": this repo has a hard disk
# budget (C: had ~2.8 GB free; CLAUDE.md section 3) and the cleanup is done
# repeatedly, so it must be (a) safe to re-run, (b) explicit about what it
# deletes VS what it keeps, and (c) never able to touch tracked source.
#
# The ordering below is not arbitrary -- it comes from CLAUDE.md section 3:
#
#   1. `deps/*.pdb`       - linker debug-info copies. Deleting them does NOT
#                           affect running tests or binaries. Measured on this
#                           repo: 95 files / 5.1 GB. By far the best first cut.
#   2. `*/incremental/`   - rustc incremental caches. Deleting them only means
#                           the next build is a full build (not a clean build).
#   3. `.smoke-logs/*`    - smoke-test logs. Kept: the newest of each kind, so
#                           there is always one recent piece of evidence.
#
# DELIBERATELY NOT DELETED: `deps/` itself. It is ~20 GB and deleting it forces
# a complete rebuild of every dependency -- far worse than the space it frees.
# If you find yourself reaching for it, delete the `.pdb` files first (step 1).
#
# Usage:
#   & .\scripts\clean.ps1                 # default: pdbs + incremental + logs
#   & .\scripts\clean.ps1 -WhatIf         # report what WOULD be deleted, delete nothing
#   & .\scripts\clean.ps1 -SkipLogs       # keep all smoke logs
#   & .\scripts\clean.ps1 -LogKeep 8      # keep 8 recent smoke logs instead of 3
#
# NOTE: -WhatIf is implemented here rather than using [CmdletBinding(SupportsShouldProcess)]
# because the size reporting needs to walk the same file set either way, and
# having two code paths for "which files" is how a cleanup script deletes the
# wrong thing.

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$SkipLogs,
    [int]$LogKeep = 3
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$targetDir = Join-Path $repoRoot '.cargo-target'
$logDir = Join-Path $repoRoot '.smoke-logs'

function Get-DirSizeMb {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if (-not $sum) { return 0 }
    return [math]::Round($sum / 1MB, 1)
}

function Get-ItemSizeMb {
    param([object]$Item)
    if ($Item.PSIsContainer) {
        $sum = (Get-ChildItem -LiteralPath $Item.FullName -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if (-not $sum) { return 0 }
        return [math]::Round($sum / 1MB, 2)
    }
    return [math]::Round($Item.Length / 1MB, 2)
}

function Remove-Items {
    param([string]$Label, [object[]]$Items)

    if (-not $Items -or $Items.Count -eq 0) {
        Write-Host ("  {0,-34} nothing to do" -f $Label)
        return
    }

    # Sizes must be summed per item: a DIRECTORY has no `Length` property, so
    # `Measure-Object -Property Length` silently reports nothing for it and the
    # step prints "0 MB" while actually deleting several hundred MB. That is the
    # worst kind of wrong number -- it makes the cleanup look ineffective right
    # when it is doing the most work.
    $mb = 0
    foreach ($item in $Items) { $mb += Get-ItemSizeMb -Item $item }
    $mb = [math]::Round($mb, 1)

    if ($WhatIf) {
        Write-Host ("  {0,-34} WOULD remove {1} item(s), {2} MB" -f $Label, $Items.Count, $mb)
        $script:freedMb += $mb
        return
    }

    $failed = 0
    foreach ($item in $Items) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $item.FullName) { $failed++ }
    }
    if ($failed -gt 0) {
        Write-Host ("  {0,-34} removed {1}, FAILED {2} (file in use?)" -f $Label, ($Items.Count - $failed), $failed)
    }
    else {
        Write-Host ("  {0,-34} removed {1} item(s), {2} MB" -f $Label, $Items.Count, $mb)
    }
    $script:freedMb += $mb
}

Write-Host "BitFlip cleanup"
Write-Host ("  repo:  " + $repoRoot)
if ($WhatIf) { Write-Host "  mode:  -WhatIf (nothing will be deleted)" -ForegroundColor Yellow }
Write-Host ""

$script:freedMb = 0
$before = Get-DirSizeMb $targetDir

# --- 1. Linker debug-info copies -----------------------------------------------
# The single highest-value cut. These are copies of debug info written by the
# linker; nothing reads them at test time. Measured at ~5 GB on this repo.
if (Test-Path -LiteralPath $targetDir) {
    $pdbs = @(Get-ChildItem -LiteralPath $targetDir -Recurse -Filter '*.pdb' -File -ErrorAction SilentlyContinue)
    Remove-Items -Label 'deps/*.pdb (linker copies)' -Items $pdbs
}

# --- 2. rustc incremental caches ----------------------------------------------
# Costs one full rebuild on the next `cargo build`; does not break anything.
if (Test-Path -LiteralPath $targetDir) {
    $incremental = @(Get-ChildItem -LiteralPath $targetDir -Recurse -Directory -Filter 'incremental' -ErrorAction SilentlyContinue)
    Remove-Items -Label '*/*/incremental (rustc cache)' -Items $incremental
}

# --- 3. Smoke-test logs, keeping the newest ------------------------------------
# These are evidence: when something fails, the log is how you find out. So keep
# the newest few rather than everything -- and never delete a log the caller
# might be about to read.
if (-not $SkipLogs -and (Test-Path -LiteralPath $logDir)) {
    $logs = @(Get-ChildItem -LiteralPath $logDir -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($logs.Count -le $LogKeep) {
        Write-Host ("  {0,-34} {1} file(s), all kept (<= -LogKeep {2})" -f '.smoke-logs/*', $logs.Count, $LogKeep)
    }
    else {
        $stale = @($logs | Select-Object -Skip $LogKeep)
        Remove-Items -Label ('.smoke-logs/* (keep newest ' + $LogKeep + ')') -Items $stale
    }
}

# --- report --------------------------------------------------------------------
Write-Host ""
if ($WhatIf) {
    Write-Host ("Would free about " + [math]::Round($script:freedMb, 1) + " MB.")
    Write-Host "Re-run without -WhatIf to actually delete."
}
else {
    $after = Get-DirSizeMb $targetDir
    Write-Host ("Freed about {0} MB.  .cargo-target: {1} MB -> {2} MB" -f [math]::Round($script:freedMb, 1), $before, $after)
}

# A real check that the volume can be written to. `Get-PSDrive` and
# `Get-CimInstance Win32_LogicalDisk` both report 0 / unavailable under this
# sandbox, so asking them would prove nothing -- write a probe instead.
if (-not $WhatIf) {
    $probe = Join-Path $repoRoot '.smoke-logs/.write-probe'
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    try {
        $bytes = New-Object byte[] (10MB)
        [System.IO.File]::WriteAllBytes($probe, $bytes)
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        Write-Host "Disk write check: OK (10 MB probe)"
    }
    catch {
        Write-Host ("Disk write check: FAILED -- " + $_.Exception.Message) -ForegroundColor Red
        Write-Host "  If this says 'not enough space', delete .cargo-target/deps next" -ForegroundColor Yellow
        Write-Host "  (it forces a full rebuild -- only as a last resort)." -ForegroundColor Yellow
        exit 1
    }
}

exit 0
