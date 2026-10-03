# BitFlip M3 coverage-sample builder (PLAN section M3, acceptance criterion 1).
#
# Criterion 1 says: "for an unsigned mingw statically-linked exe, function
# identification coverage vs objdump/dumpbin's function list must be >= 95%".
# That claim needs a sample that is actually representative, so this script
# builds a real statically-linked program and then STRIPS it.
#
# Why strip: the whole difficulty of function identification is the stripped
# case. Comparing against a binary that still has a full symbol table would
# measure symbol-table reading, not function discovery -- the test would pass
# while proving nothing about the actual requirement.
#
# The ground truth is captured from objdump BEFORE stripping, so the comparison
# is against the true function list rather than a heuristic guess.
#
# Usage:
#   & .\scripts\gen-m3-coverage-sample.ps1
#   & .\scripts\gen-m3-coverage-sample.ps1 -Force

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot
$src = Join-Path $repo 'tests\fixtures\m3_coverage_sample.c'
$outDir = Join-Path $repo 'tests\fixtures\generated'
$exe = Join-Path $outDir 'm3-mingw-static.exe'
$unstripped = Join-Path $outDir 'm3-mingw-static.unstripped.exe'
$truth = Join-Path $outDir 'm3-mingw-static.funcs.txt'

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

# gcc/ld need a writable temp dir. The sandbox-provided TEMP is not writable by
# child processes here, and the failure surfaces as a confusing
# "Cannot create temporary file ... Permission denied" from the compiler rather
# than anything mentioning the sandbox. Point them at a repo-local directory.
$tmpDir = Join-Path $repo '.cargo-tmp'
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null }
$env:TMP = $tmpDir
$env:TEMP = $tmpDir

if ((Test-Path $exe) -and -not $Force) {
    Write-Host "sample already exists: $exe (use -Force to rebuild)"
    exit 0
}

$gcc = 'E:\mingw64\bin\gcc.exe'
$objdump = 'E:\mingw64\bin\objdump.exe'
$strip = 'E:\mingw64\bin\strip.exe'

foreach ($tool in @($gcc, $objdump, $strip)) {
    if (-not (Test-Path $tool)) {
        Write-Host "missing tool: $tool" -ForegroundColor Red
        exit 1
    }
}

# -static: fully static so the sample exercises the "no dynamic imports to lean
#          on" path, which is what the criterion names.
# -O2:     realistic optimization; -O0 would leave a prologue on every function
#          and make discovery artificially easy.
# -fno-asynchronous-unwind-tables on mingw is not applicable the same way as on
#          Linux, but we deliberately keep unwind info OUT of the ground truth's
#          advantage by deriving truth from the symbol table instead.
# -Wl,--gc-sections: drops unreferenced functions; without it the binary carries
#          dead code that no call-target heuristic could ever find, which would
#          unfairly depress coverage.
Write-Host "compiling static sample..."
& $gcc -O2 -static '-Wl,--gc-sections' -o $unstripped $src -lm 2>&1 |
    ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Host "compile failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# Ground truth: objdump's function list from the UNSTRIPPED binary, taken BEFORE
# strip. This is the reference set the criterion names.
#
# Two traps here, both of which produce a silently wrong denominator:
#
#  1. `objdump -t` on a PE prints SECTION-RELATIVE offsets (0x0, 0x10, 0x3d0),
#     not virtual addresses. Comparing those against the analyzer's absolute
#     VAs (0x140001000...) gives 0% coverage on a perfectly good analyzer.
#     `objdump -d` prints true absolute VAs in its `<addr> <name>:` labels.
#
#  2. `objdump -d` also emits compiler-internal local labels (`.l_startw`,
#     `.l_endw`). Those are branch targets INSIDE a function, not function
#     entries; counting them would inflate the denominator with addresses no
#     function-finder could legitimately report.
#
# So: take `-d` labels for the addresses, and keep only those whose name also
# appears as a type-20 (function) symbol in `-t`. That intersection is exactly
# "real function entry points with true virtual addresses".
Write-Host "capturing ground truth with objdump..."
$rawSymbols = & $objdump -t $unstripped 2>&1
$functionNames = @{}
foreach ($line in $rawSymbols) {
    if ($line -match '\(sec\s+1\).*\(ty\s+20\)') {
        if ($line -match '\)\s+(?:0x[0-9a-fA-F]+)\s+(\S+)\s*$') {
            $functionNames[$Matches[1]] = $true
        }
    }
}
Write-Host "  type-20 function symbols: $($functionNames.Count)"

$rawDisasm = & $objdump -d $unstripped 2>&1
$truthRecords = @()
foreach ($line in $rawDisasm) {
    if ($line -notmatch '^([0-9a-fA-F]+)\s+<([^>]+)>:') { continue }
    $addr = $Matches[1]
    $name = $Matches[2]
    # drop compiler-internal local labels
    if ($name.StartsWith('.l') -or $name.StartsWith('.L')) { continue }
    # keep only real function symbols
    if (-not $functionNames.ContainsKey($name)) { continue }
    $truthRecords += ("0x" + $addr + ":" + $name)
}

$truthRecords = @($truthRecords | Sort-Object -Unique)

@(
    "# BitFlip M3 coverage ground truth",
    "# source: objdump -d labels (absolute VA) intersected with objdump -t type-20 symbols",
    "# captured from: $unstripped  (BEFORE strip)",
    "# format: <address>:<name>, one function entry per line"
) + $truthRecords | Set-Content -Path $truth -Encoding ASCII

$funcCount = $truthRecords.Count
Write-Host "ground-truth functions with absolute VA: $funcCount"

# Strip: this is the state the analysis actually faces.
Copy-Item -Path $unstripped -Destination $exe -Force
& $strip --strip-all $exe 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Host "strip failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

$size = (Get-Item $exe).Length
$symCount = 0

# Verify the strip actually removed the symbol table. A "stripped" sample that
# still has symbols would make the coverage test meaningless, so this is checked
# rather than assumed.
$symOut = & $objdump -t $exe 2>&1 | Out-String
if ($symOut -match 'no symbols') { $symCount = 0 }
else { $symCount = @(($symOut -split "`n") | Where-Object { $_ -match '\(ty\s+20\)' }).Count }

Write-Host ""
Write-Host "sample:      $exe"
Write-Host "size:        $size bytes"
Write-Host "truth:       $truth"
Write-Host "truth funcs: $funcCount"
Write-Host "post-strip .text symbols: $symCount"

if ($symCount -ne 0) {
    Write-Host "WARNING: sample still exposes $symCount .text symbols; " -ForegroundColor Yellow
    Write-Host "the coverage test would be measuring symbol reading, not discovery." -ForegroundColor Yellow
}

if ($funcCount -lt 30) {
    Write-Host "WARNING: only $funcCount ground-truth functions; a 95% target on so " -ForegroundColor Yellow
    Write-Host "few functions is not a meaningful measurement." -ForegroundColor Yellow
}

# Machine-readable summary for the test to pick up.
$meta = Join-Path $outDir 'm3-mingw-static.meta.txt'
@(
    "exe=$exe",
    "size=$size",
    "truth_funcs=$funcCount",
    "stripped_symbols=$symCount"
) | Set-Content -Path $meta -Encoding ASCII

Write-Host "wrote $meta"
exit 0
