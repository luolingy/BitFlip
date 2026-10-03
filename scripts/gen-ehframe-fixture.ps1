# BitFlip: build a REAL ELF fixture with .eh_frame, to verify the FDE parser
# against compiler output rather than against my own hand-written bytes.
#
# Produces three artifacts:
#   elf-ehframe.exe             stripped: .eh_frame is the ONLY boundary source
#   elf-ehframe.unstripped.exe  reference for the true function set
#   elf-ehframe.funcs.txt       ground truth: function names + addresses (external tool)
#
# Why ELF and not PE here: PE unwind (.pdata) was already parsed in M1; this
# fixture is specifically about the ELF .eh_frame path added in M3.
#
# Usage:
#   & .\scripts\gen-ehframe-fixture.ps1
#   & .\scripts\gen-ehframe-fixture.ps1 -Force

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot
$src = Join-Path $repo 'tests\fixtures\eh_frame_sample.c'
$outDir = Join-Path $repo 'tests\fixtures\generated'
$unstripped = Join-Path $outDir 'elf-ehframe.unstripped.exe'
$stripped = Join-Path $outDir 'elf-ehframe.exe'
$truth = Join-Path $outDir 'elf-ehframe.funcs.txt'
$meta = Join-Path $outDir 'elf-ehframe.meta.txt'

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

# Compiler/linker need a writable temp dir; the sandbox TEMP is not usable by
# child processes and the failure message does not mention the sandbox.
$tmpDir = Join-Path $repo '.cargo-tmp'
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null }
$env:TMP = $tmpDir
$env:TEMP = $tmpDir

if ((Test-Path $stripped) -and -not $Force) {
    Write-Host "fixture already exists: $stripped (use -Force to rebuild)"
    exit 0
}

$clang = 'E:\LLVM\bin\clang.exe'
$readobj = 'E:\LLVM\bin\llvm-readobj.exe'
$objdump = 'E:\mingw64\bin\objdump.exe'
$strip = 'E:\mingw64\bin\strip.exe'

foreach ($tool in @($clang, $readobj, $objdump, $strip)) {
    if (-not (Test-Path $tool)) {
        Write-Host "missing tool: $tool" -ForegroundColor Red
        exit 1
    }
}

# --target=x86_64-unknown-linux-gnu is REQUIRED. Plain clang on Windows defaults
# to the MSVC/PE target, which produces a PE file with .pdata and NO .eh_frame --
# the build then "succeeds" while the fixture is useless for this test.
#
# -fuse-ld=lld is ALSO required: clang would otherwise invoke mingw's ld.exe,
# which only supports i386pe/i386pep and fails with
# "unrecognised emulation mode: elf_x86_64". LLVM's ld.lld can link ELF here.
#
# -fno-omit-frame-pointer: forces a real frame so an FDE is emitted for each
#   function even at -O2.
# -funwind-tables: guarantees .eh_frame exists regardless of optimisation.
# -nostdlib: no Linux sysroot exists on this machine, and linking a CRT would
#   pull in hundreds of extra FDEs and make the function count noisy.
Write-Host "compiling ELF fixture (unstripped reference)..."
$target = 'x86_64-unknown-linux-gnu'
& $clang "--target=$target" -fuse-ld=lld -O2 -fno-omit-frame-pointer -funwind-tables -nostdlib -static -o $unstripped $src 2>&1 |
    ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Host "compile failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# Fail loudly if we got a PE instead of an ELF: every downstream assertion
# would otherwise be measuring an empty set.
$head = & $objdump -h $unstripped 2>&1 | Out-String
if ($head -match 'file format pe') {
    Write-Host "ERROR: clang produced a PE file, not ELF. Expected --target=$target." -ForegroundColor Red
    exit 1
}

# Ground truth from an EXTERNAL tool, taken before stripping.
Write-Host "capturing ground truth (objdump -t, function symbols)..."
$rawSymbols = & $objdump -t $unstripped 2>&1
$records = @()
foreach ($line in $rawSymbols) {
    # ELF symbol table format: "ADDR FLAGS SECTION SIZE NAME" with F = function
    if ($line -match '^([0-9a-fA-F]+)\s+\S*\s*F\s+\.text\s+\S+\s+(\S+)\s*$') {
        $records += ("0x" + $Matches[1] + ":" + $Matches[2])
    }
}
$records = @($records | Sort-Object -Unique)

@(
    "# BitFlip .eh_frame verification ground truth",
    "# source: objdump -t (EXTERNAL tool), taken from the UNSTRIPPED build",
    "# format: <address>:<name>",
    "# section: .text function symbols only"
) + $records | Set-Content -Path $truth -Encoding ASCII

# Count FDEs with llvm-readobj as an INDEPENDENT cross-check of the parser.
# If our parser and llvm disagree, one of them is wrong.
#
# llvm-readobj prints `fde_count: N` inside EHFrameHeader when .eh_frame_hdr
# exists. (A naive match on "Function:" lines yields 0 -- llvm does not print
# that here. An earlier version of this script did exactly that and silently
# reported 0 FDEs.)
Write-Host "counting FDEs with llvm-readobj (independent cross-check)..."
$unwindOut = & $readobj --unwind $unstripped 2>&1 | Out-String
$fdeCount = 0
if ($unwindOut -match 'fde_count:\s*(\d+)') {
    $fdeCount = [int]$Matches[1]
}

# Strip: this is the state the analysis actually faces.
Copy-Item -Path $unstripped -Destination $stripped -Force
& $strip --strip-all $stripped 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Host "strip failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# Verify the strip really removed the symbol table, and that .eh_frame survived
# (if -fno-asynchronous-unwind-tables had won, the whole test would be vacuous).
$postSymbols = & $objdump -t $stripped 2>&1 | Out-String
$postFuncs = 0
if ($postSymbols -notmatch 'no symbols') {
    $postFuncs = @(($postSymbols -split "`n") | Where-Object { $_ -match 'F\s+\.text' }).Count
}
$postSections = & $objdump -h $stripped 2>&1 | Out-String
$hasEhFrame = ($postSections -match '\.eh_frame')

Write-Host ""
Write-Host "stripped:            $stripped"
Write-Host "unstripped:          $unstripped"
Write-Host "size (stripped):     $((Get-Item $stripped).Length) bytes"
Write-Host "truth funcs:         $($records.Count)"
Write-Host "llvm FDE count:      $fdeCount"
Write-Host "post-strip .text F:  $postFuncs"
Write-Host ".eh_frame present:   $hasEhFrame"

if ($postFuncs -ne 0) {
    Write-Host "WARNING: stripped binary still exposes $postFuncs function symbols" -ForegroundColor Yellow
}
if (-not $hasEhFrame) {
    Write-Host "WARNING: .eh_frame is absent after stripping - the test would be vacuous" -ForegroundColor Yellow
}
if ($fdeCount -lt 5) {
    Write-Host "WARNING: only $fdeCount FDEs reported by llvm-readobj" -ForegroundColor Yellow
}

@(
    "stripped=$stripped",
    "unstripped=$unstripped",
    "truth_funcs=$($records.Count)",
    "llvm_fdes=$fdeCount",
    "stripped_symbols=$postFuncs",
    "has_eh_frame=$hasEhFrame"
) | Set-Content -Path $meta -Encoding ASCII

Write-Host "wrote $meta"
exit 0
