# requires -Version 5.1
#
# Measure a DSH-free timing run properly.
#
# WHY THIS EXISTS: on this machine, single-shot timings of the same binary swing
# by nearly 2x (measured 379 / 576 / 790 ms for the same stage, same sample,
# three consecutive runs). Any perf claim built on one run is fiction. This
# script runs N times, keeps every sample, and reports the MEDIAN plus min/max,
# so noise is visible instead of being mistaken for a speedup.
#
# It also supports interleaved A/B comparison: -CompareExe runs both binaries
# alternately (A,B,A,B,...) so slow drift (thermal, background load) hits both
# sides equally instead of favouring whichever ran first.
#
# ASCII only (CLAUDE.md 6.1): PowerShell 5.1 reads BOM-less scripts as ANSI.

param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [int]$Runs = 5,
    [string]$CompareExe = "",
    [string]$TestArgs = "--ignored --nocapture",
    [string]$Tag = ""
)

if ($Runs -lt 1) { Write-Host "Runs must be >= 1"; exit 2 }
if ($Runs -gt 20) { Write-Host "Runs capped at 20 (each run is a full analysis)"; exit 2 }

function Resolve-Exe([string]$path) {
    if (-not (Test-Path $path)) {
        Write-Host "not found: $path"
        exit 2
    }
    return (Resolve-Path $path).Path
}

$ExeFull = Resolve-Exe $Exe
$CmpFull = ""
if ($CompareExe -ne "") { $CmpFull = Resolve-Exe $CompareExe }

# One run -> hashtable of stage name -> microseconds (plus "__total").
function Invoke-OneRun([string]$exePath) {
    $env:BITFLIP_TIMING = "1"
    $argv = $TestArgs.Split(" ")
    $out = & $exePath @argv 2>&1
    $stages = @{}
    $sum = 0
    foreach ($line in $out) {
        $text = [string]$line
        # Stage rows look like: "  <name>   12345"  (two or more leading spaces,
        # trailing number). Header rows end with ':' and are skipped by the regex.
        if ($text -match '^\s{2,}(.+?)\s+(\d+)\s*$') {
            $name = $Matches[1].TrimEnd()
            $us = [int]$Matches[2]
            if ($stages.ContainsKey($name)) { $stages[$name] = $stages[$name] + $us }
            else { $stages[$name] = $us }
            $sum = $sum + $us
        }
    }
    # Only the last "total" row matters, but stage names are localized data
    # (not literals in this file), so keep the summed value for a coarse total.
    $stages["__sum"] = $sum
    return $stages
}

function Get-Median($values) {
    $sorted = @($values | Sort-Object)
    $n = $sorted.Count
    if ($n -eq 0) { return 0 }
    if ($n % 2 -eq 1) {
        return $sorted[[int](($n - 1) / 2)]
    }
    return [int](([int]$sorted[$n / 2 - 1] + [int]$sorted[$n / 2]) / 2)
}

function Summarize([hashtable[]]$results) {
    $names = @{}
    foreach ($r in $results) {
        foreach ($k in $r.Keys) { if ($k -ne "__sum") { $names[$k] = $true } }
    }
    $rows = @()
    foreach ($name in ($names.Keys | Sort-Object)) {
        $vals = @()
        foreach ($r in $results) {
            if ($r.ContainsKey($name)) { $vals += [int]$r[$name] }
        }
        if ($vals.Count -eq 0) { continue }
        $rows += [pscustomobject]@{
            Stage = $name
            Median = Get-Median $vals
            Min = ($vals | Measure-Object -Minimum).Minimum
            Max = ($vals | Measure-Object -Maximum).Maximum
            N = $vals.Count
        }
    }
    return $rows
}

function Show-Table([string]$label, [string]$exePath, $table) {
    Write-Host ""
    Write-Host "== $label =="
    Write-Host "exe : $exePath"
    Write-Host "runs: $Runs"
    Write-Host ""
    $table | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    $totals = @()
    foreach ($row in $table) { if ($row.Stage -eq "__sum") { $totals += $row.Median } }
    if ($totals.Count -gt 0) { Write-Host "median sum: $($totals[0]) us" }
}

# Collect samples.
$A = @()
$B = @()
for ($i = 0; $i -lt $Runs; $i++) {
    $A += Invoke-OneRun $ExeFull
    if ($CmpFull -ne "") { $B += Invoke-OneRun $CmpFull }
    Write-Host "run $($i + 1)/$Runs done"
}

$labelA = "A"
if ($Tag -ne "") { $labelA = $Tag }
Show-Table $labelA $ExeFull (Summarize $A)
if ($CmpFull -ne "") {
    Show-Table "B (compare)" $CmpFull (Summarize $B)
    Write-Host ""
    Write-Host "Reminder: only trust a difference if the median ranges do not overlap."
}
