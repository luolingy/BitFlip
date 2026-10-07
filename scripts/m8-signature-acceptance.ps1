# BitFlip M8 acceptance (PLAN section M8, criterion 1): a signature library
# built from THIS machine's mingw static libraries must give readable names to
# functions in a STRIPPED statically-linked exe, with a quantified result:
# identified count + false-positive rate.
#
# Why the numbers can only come from here:
#   * The signature library is a derivative the user builds from libraries they
#     own -- this project ships no prebuilt signature database (no network, no
#     bundled third-party fingerprints). So the library has to be built on this
#     machine, from real static libraries, right now.
#   * The ground truth is captured by objdump BEFORE stripping (an independent
#     tool, see scripts/gen-m3-coverage-sample.ps1). Comparing signatures against
#     an analysis output would be grading our own homework.
#
# Therefore the script degrades honestly: when the sample, the ground truth or
# the mingw libraries are missing it prints why, prints SKIPPED, and exits 0.
# It never prints numbers it could not have produced.
#
# What is gated:
#   * wrong names == 0. A signature match that writes the wrong function name is
#     worse than no name at all (CLAUDE.md section 7), so false positives are a
#     hard failure, not a quality metric.
#   * identified > 0, so "green" cannot mean "the library did nothing".
# Recall is reported (against both the truth set and the reachable subset) and
# recorded in docs/PLAN.md section M8, but not gated on a number invented here.
#
# Usage:
#   & .\scripts\m8-signature-acceptance.ps1
#   & .\scripts\m8-signature-acceptance.ps1 -MingwRoot E:\mingw64
#   & .\scripts\m8-signature-acceptance.ps1 -Signatures .cargo-tmp\mingw.sig.json
#   & .\scripts\m8-signature-acceptance.ps1 -Cli .cargo-target\release\bitflip-cli.exe

[CmdletBinding()]
param(
    [string]$MingwRoot = '',
    [string]$Signatures = '',
    [string]$Cli = '',
    [switch]$AsJson
)

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot
$sample = Join-Path $repo 'tests\fixtures\generated\m3-mingw-static.exe'
$truth = Join-Path $repo 'tests\fixtures\generated\m3-mingw-static.funcs.txt'
$buildDir = Join-Path $repo '.cargo-tmp'

if (-not $Cli) { $Cli = Join-Path $repo '.cargo-target\debug\bitflip-cli.exe' }

function Write-Skipped([string]$reason) {
    Write-Host "SKIPPED: $reason"
    exit 0
}

# ---------------------------------------------------------------- preconditions

if (-not (Test-Path $sample)) {
    Write-Skipped "sample $sample is missing; run scripts/gen-m3-coverage-sample.ps1 first"
}
if (-not (Test-Path $truth)) {
    Write-Skipped "ground truth $truth is missing; run scripts/gen-m3-coverage-sample.ps1 first"
}
if (-not (Test-Path $Cli)) {
    Write-Skipped "CLI $Cli is missing; build it first (cargo build -p bitflip-cli)"
}

# The mingw libraries are what the signature library is built FROM. Candidates
# are probed in order; the first root that has all four archives wins.
$candidates = @()
if ($MingwRoot) { $candidates += $MingwRoot }
$candidates += @('E:\mingw64', 'C:\mingw64', 'C:\msys64\mingw64', 'D:\mingw64')

$libs = @()
$probed = @()
foreach ($root in $candidates) {
    $probed += $root
    if (-not (Test-Path (Join-Path $root 'x86_64-w64-mingw32\lib'))) { continue }
    $found = @()
    foreach ($name in @('libmingw32.a', 'libmingwex.a', 'libmsvcrt.a')) {
        $path = Join-Path $root "x86_64-w64-mingw32\lib\$name"
        if (Test-Path $path) { $found += $path }
    }
    # libgcc.a lives under a versioned directory; take the highest version so the
    # script does not break when the toolchain is upgraded.
    $gccRoot = Join-Path $root 'lib\gcc\x86_64-w64-mingw32'
    if (Test-Path $gccRoot) {
        $libgcc = Get-ChildItem -Path $gccRoot -Recurse -Filter 'libgcc.a' -ErrorAction SilentlyContinue |
            Sort-Object FullName | Select-Object -Last 1
        if ($libgcc) { $found += $libgcc.FullName }
    }
    if ($found.Count -ge 4) { $libs = $found; break }
}

if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Force -Path $buildDir | Out-Null }

if (-not $Signatures) {
    if ($libs.Count -lt 4) {
        Write-Skipped ("mingw static libraries not found (probed: " + ($probed -join ', ') +
            "); pass -MingwRoot or -Signatures to measure")
    }
    $Signatures = Join-Path $buildDir 'm8-acceptance.sig.json'
    Write-Host "Building signature library from $($libs.Count) static libraries ..."
    $buildOut = & $Cli signature build @libs --out $Signatures --force 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Host $buildOut
        Write-Host "FAILED: signature build exited $LASTEXITCODE"
        exit 1
    }
} elseif (-not (Test-Path $Signatures)) {
    Write-Skipped "signature library $Signatures does not exist"
}

# The sample is stripped: its symbol table is empty, so every name below either
# comes from the signature library or does not exist at all.
$json = & $Cli functions $sample --signatures $Signatures --count 100000 --json 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Write-Host $json
    Write-Host "FAILED: functions exited $LASTEXITCODE"
    exit 1
}
$report = $json | ConvertFrom-Json

# ------------------------------------------------------------------ comparison

$truthMap = @{}
$truthCount = 0
foreach ($line in [System.IO.File]::ReadAllLines($truth, [System.Text.Encoding]::UTF8)) {
    $line = $line.Trim()
    if ($line.Length -eq 0 -or $line.StartsWith('#')) { continue }
    $parts = $line.Split(':', 2)
    if ($parts.Count -lt 2) { continue }
    $addr = [System.Convert]::ToUInt64($parts[0].Trim().Replace('0x', ''), 16)
    $truthMap[$addr] = $parts[1].Trim()
    $truthCount++
}

# Names the library could possibly produce: recall must be read against this,
# not against the whole truth set -- most truth functions are small internal
# helpers that simply are not in these four archives.
$libraryNames = @{}
$sigDoc = Get-Content $Signatures -Raw | ConvertFrom-Json
foreach ($sig in $sigDoc.signatures) { $libraryNames[$sig.name] = $true }
$librarySize = $sigDoc.signatures.Count

$identified = 0
$correct = 0
$wrong = @()
$readable = @{}
foreach ($fn in $report.functions) {
    if ($fn.source -ne 'signature') { continue }
    $identified++
    $addr = [System.Convert]::ToUInt64($fn.start, 16)
    if ($truthMap.ContainsKey($addr) -and $truthMap[$addr] -eq $fn.name) {
        $correct++
        $readable[$fn.name] = $true
    } else {
        $truthName = '<not a function start>'
        if ($truthMap.ContainsKey($addr)) { $truthName = $truthMap[$addr] }
        $wrong += ("{0} named '{1}' but truth says '{2}'" -f $fn.start, $fn.name, $truthName)
    }
}

$reachable = 0
foreach ($name in $truthMap.Values) { if ($libraryNames.ContainsKey($name)) { $reachable++ } }

$recallOfTruth = 0
$recallOfReachable = 0
if ($truthCount -gt 0) { $recallOfTruth = [math]::Round(100.0 * $correct / $truthCount, 1) }
if ($reachable -gt 0) { $recallOfReachable = [math]::Round(100.0 * $correct / $reachable, 1) }
$fpRate = 0
if ($identified -gt 0) { $fpRate = [math]::Round(100.0 * $wrong.Count / $identified, 1) }

if ($AsJson) {
    $out = [ordered]@{
        sample          = $sample
        signatures      = $Signatures
        library_size    = $librarySize
        truth_functions = $truthCount
        reachable       = $reachable
        identified      = $identified
        correct         = $correct
        wrong           = $wrong.Count
        recall_truth    = $recallOfTruth
        recall_reachable = $recallOfReachable
        false_positive_rate = $fpRate
        candidates_compared = $report.total
        notes           = @($report.notes)
    }
    $out | ConvertTo-Json -Depth 4
} else {
    Write-Host ""
    Write-Host "Target      : $sample (stripped)"
    Write-Host "Signatures  : $Signatures ($librarySize signatures)"
    Write-Host "Truth       : $truthCount functions (objdump, captured before stripping)"
    Write-Host ""
    Write-Host "Candidates compared : $($report.total)"
    Write-Host "Identified (source=signature) : $identified"
    Write-Host "  correct names       : $correct"
    Write-Host "  wrong names         : $($wrong.Count)"
    Write-Host ""
    Write-Host "Library reachability : $reachable of $truthCount truth names exist in the library"
    Write-Host "Recall               : $recallOfReachable% of reachable, $recallOfTruth% of all truth"
    Write-Host "False-positive rate  : $fpRate%"
    if ($wrong.Count -gt 0) {
        Write-Host ""
        Write-Host "Wrong names:"
        foreach ($line in $wrong) { Write-Host "  $line" }
    }
    Write-Host ""
    foreach ($note in $report.notes) {
        if ($note -match 'signature|signature library') { Write-Host "note: $note" }
    }
}

# --------------------------------------------------------------------- verdict

if ($wrong.Count -gt 0) {
    Write-Host "FAIL: $($wrong.Count) function(s) got the WRONG name from the signature library"
    exit 1
}
if ($identified -eq 0) {
    Write-Host "FAIL: the signature library named nothing at all"
    exit 1
}
Write-Host "PASS: $correct function(s) named from signatures, 0 wrong names"
exit 0
