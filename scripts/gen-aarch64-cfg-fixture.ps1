# BitFlip: build a REAL AArch64 ELF for CFG verification (PLAN M5 criterion 2).
#
# Why a second ARM64 fixture: the existing elf-aarch64.exe is tiny (one
# straight-line function plus a loop). M5 acceptance asks for a CFG
# correctness spot check on ARM64, which needs functions whose *expected*
# basic-block structure can be written down by hand -- conditional branches,
# back edges, calls in the middle of a block, nested conditionals, a switch,
# and recursion. See tests/fixtures/aarch64_cfg_sample.c for the per-function
# expectations.
#
# Outputs:
#   elf-aarch64-cfg.exe        the target (entry 0x400000-class, executable)
#   elf-aarch64-cfg.syms.txt   ground truth: function names + addresses, from
#                              llvm-readobj, so the test compares against an
#                              external tool rather than against my own parser
#   elf-aarch64-cfg.dis.txt    full external disassembly, for CFG cross-checks
#   elf-aarch64-cfg.meta.txt   which tools/versions produced it
#
# Usage:
#   & .\scripts\gen-aarch64-cfg-fixture.ps1
#   & .\scripts\gen-aarch64-cfg-fixture.ps1 -Force

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot
$src = Join-Path $repo 'tests\fixtures\aarch64_cfg_sample.c'
$outDir = Join-Path $repo 'tests\fixtures\generated'
$exe = Join-Path $outDir 'elf-aarch64-cfg.exe'
$syms = Join-Path $outDir 'elf-aarch64-cfg.syms.txt'
$dis = Join-Path $outDir 'elf-aarch64-cfg.dis.txt'
$meta = Join-Path $outDir 'elf-aarch64-cfg.meta.txt'

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

# Compiler/linker need a writable temp dir; the sandbox TEMP is not usable by
# child processes and the failure message does not mention the sandbox.
$tmpDir = Join-Path $repo '.cargo-tmp'
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null }
$env:TMP = $tmpDir
$env:TEMP = $tmpDir

if ((Test-Path $exe) -and -not $Force) {
    Write-Host "fixture already exists: $exe (use -Force to rebuild)"
    exit 0
}

$clang = 'E:\LLVM\bin\clang.exe'
$readobj = 'E:\LLVM\bin\llvm-readobj.exe'
$objdump = 'E:\LLVM\bin\llvm-objdump.exe'

foreach ($tool in @($clang, $readobj, $objdump)) {
    if (-not (Test-Path $tool)) {
        Write-Host "missing tool: $tool" -ForegroundColor Red
        exit 1
    }
}

# --target=aarch64-unknown-linux-gnu is REQUIRED. Plain clang on Windows
# defaults to the MSVC/PE target, which would silently produce an x86-64 PE
# and make every ARM64 assertion vacuous.
#
# -O0, NOT -O1: this fixture exists to check the CFG, and at -O1 clang
# compiled away most of the branches we want to test -- `cfg_absdiff` became a
# branchless `cneg`, `cfg_ladder` became `cset`/`cinc`/`csel`. Those are
# correct code but they have no conditional branches, so a CFG test built on
# them would assert almost nothing. -O0 keeps the branches (and the stack
# traffic) that the CFG builder has to handle.
#
# -fno-builtin, -nostdlib: there is no aarch64 Linux sysroot on this machine,
# so we cannot link against libc. The sample provides _start and uses a raw
# svc #0 for exit.
#
# -Wl,-e,_start: with -nostdlib the linker does not know the entry point.
#
# NOTE: the args are passed as a quoted array. PowerShell would otherwise eat
# '-Wl,-e,_start' (see CLAUDE.md section 6.4).
Write-Host "compiling AArch64 CFG fixture..."
& $clang @(
    '--target=aarch64-unknown-linux-gnu',
    '-O0',
    '-fno-builtin',
    '-nostdlib',
    '-static',
    '-fuse-ld=lld',
    '-Wl,-e,_start',
    '-o', $exe,
    $src
) 2>&1 | ForEach-Object { Write-Host "  $_" }

if ($LASTEXITCODE -ne 0) {
    Write-Host "clang failed with exit $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

# Ground truth from an external tool. The test reads this file, so it is
# comparing BitFlip against LLVM's idea of the function list -- not against
# my own parser's idea (which would be circular).
Write-Host "extracting symbol ground truth..."
$symLines = & $readobj '--syms' $exe 2>&1
$symLines | Set-Content -Path $syms -Encoding UTF8

Write-Host "extracting external disassembly..."
$disLines = & $objdump '-d' '--no-show-raw-insn' $exe 2>&1
$disLines | Set-Content -Path $dis -Encoding UTF8

$clangVer = (& $clang '--version' 2>&1 | Select-Object -First 1)
@(
    "source: tests/fixtures/aarch64_cfg_sample.c",
    "target: aarch64-unknown-linux-gnu (ELF64, little-endian)",
    "clang: $clangVer",
    "built by: scripts/gen-aarch64-cfg-fixture.ps1",
    "",
    "Purpose: PLAN M5 acceptance criterion 2 -- ARM64 CFG spot check.",
    "Each function in the source states its expected basic-block structure;",
    "the tests assert those expectations against BitFlip's CFG."
) | Set-Content -Path $meta -Encoding UTF8

Write-Host ""
Write-Host "built: $exe" -ForegroundColor Green
Get-Item $exe | ForEach-Object { Write-Host ("  size: {0} bytes" -f $_.Length) }
