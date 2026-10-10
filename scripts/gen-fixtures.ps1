# BitFlip fixture generator
#
# Generates sample binaries for loader/decoder tests. NOTHING generated here is
# committed (see .gitignore and CLAUDE.md section 0): samples are reproducible
# from this script plus the local toolchain.
#
# Uses whatever is available; every skipped sample is reported explicitly with a
# reason instead of being silently omitted.
#
# Usage:
#   & .\scripts\gen-fixtures.ps1
#   & .\scripts\gen-fixtures.ps1 -OutDir tests\fixtures\generated -Clean
#
# Notes on the tricky parts (learned the hard way, do not "simplify" them away):
#   * External tool arguments are passed as single-quoted tokens inside an array.
#     PowerShell 5.1 does NOT expand a bare comma-separated list the way cmd does,
#     and unquoted things like -Wl,-e,_start are parsed as parameters.
#   * clang ships its own fake MSVC headers, so `cl` needs an INCLUDE path while
#     clang does not; the MSVC sample is generated with -nostdinc + a local shim.
#   * mingw needs -nostartfiles/mWinMainCRTStartup for a freestanding exe.
#   * Native tools write errors to stderr, and PowerShell 5.1 turns each such line
#     into a RemoteException record; collect with 2>&1 and check $LASTEXITCODE.

[CmdletBinding()]
param(
    [string]$OutDir = 'tests/fixtures/generated',
    [switch]$Clean
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir

$script:produced = New-Object System.Collections.ArrayList
$script:skipped = New-Object System.Collections.ArrayList

function Resolve-Tool {
    param([string]$Name, [string[]]$Candidates = @())

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Invoke-Step {
    param(
        [string]$Label,
        [string]$Tool,
        [string[]]$Arguments,
        [string]$OutputName
    )

    if (-not $Tool) {
        [void]$script:skipped.Add("$Label (tool not found)")
        Write-Host ("  skip " + $Label + " (tool not found)")
        return
    }

    $captured = $null
    Push-Location $outPath
    try {
        $captured = & $Tool @Arguments 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($code -ne 0) {
        [void]$script:skipped.Add("$Label (exit code $code)")
        Write-Host ("  skip " + $Label + " (exit " + $code + ")")
        if ($captured) {
            $captured | Select-Object -First 4 | ForEach-Object { Write-Host ("       " + $_) }
        }
        return
    }

    if ($OutputName -and -not (Test-Path -LiteralPath (Join-Path $outPath $OutputName))) {
        [void]$script:skipped.Add("$Label (no output produced)")
        Write-Host ("  skip " + $Label + " (no output produced)")
        return
    }

    [void]$script:produced.Add($Label)
    Write-Host ("  ok   " + $Label)
}

function Write-Text-File {
    param([string]$Name, [string]$Content, [string]$Label)

    Set-Content -LiteralPath (Join-Path $outPath $Name) -Value $Content -Encoding ASCII
    [void]$script:produced.Add($Label)
    Write-Host ("  ok   " + $Label)
}

function New-Sources {
    # A minimal C file with a call, a loop and a string: enough for future
    # decoder/analysis tests (function discovery, xrefs, strings).
    $c = @'
const char *bf_banner = "BitFlip sample: no linking against libc required";

int bf_add(int a, int b) { return a + b; }

int bf_loop(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { acc += bf_add(i, acc); }
    return acc;
}

int bf_entry(void) { return bf_loop(16) + (int)(unsigned long)bf_banner; }
'@
    Set-Content -LiteralPath (Join-Path $outPath 'sample.c') -Value $c -Encoding ASCII

    # Freestanding ELF entry. Deliberately NO inline assembly: `_start` gets the
    # C-entry ABI (argc in the first argument register) rather than the raw kernel
    # entry ABI (argc on the stack), so `-Wl,-e,_start` links and runs, and the
    # source stays portable across x86_64 / aarch64 / riscv64. These samples exist
    # to exercise the *loader*, not to be runnable programs.
    $start = @'
int bf_entry(void);

int _start(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return bf_entry();
}
'@
    Set-Content -LiteralPath (Join-Path $outPath 'start.c') -Value $start -Encoding ASCII

    # Entry point for the mingw PE sample: mingw's default CRT entry is WinMainCRTStartup,
    # so the freestanding build needs that symbol instead of main.
    $peStart = @'
int bf_entry(void);

void WinMainCRTStartup(void) { (void)bf_entry(); }
'@
    Set-Content -LiteralPath (Join-Path $outPath 'pe-start.c') -Value $peStart -Encoding ASCII

    # Local shim so the MSVC sample can be compiled without the Windows SDK / VC
    # headers (-nostdinc): the sample only needs a pointer-sized integer type.
    Set-Content -LiteralPath (Join-Path $outPath 'bfshim.h') -Value "typedef unsigned long long bf_uintptr;" -Encoding ASCII

    # MSVC variant of the sample: no system headers at all.
    $msvcC = @'
#include "bfshim.h"

const char *bf_banner = "BitFlip sample: MSVC, no system headers";

int bf_add(int a, int b) { return a + b; }

int bf_loop(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { acc += bf_add(i, acc); }
    return acc;
}

int bf_entry(void) { return bf_loop(16) + (int)(bf_uintptr)bf_banner; }
'@
    Set-Content -LiteralPath (Join-Path $outPath 'sample-msvc.c') -Value $msvcC -Encoding ASCII
}

Write-Host "BitFlip fixture generator"
Write-Host ("  repo:  " + $repoRoot)
Write-Host ("  out:   " + $outPath)

if ($Clean -and (Test-Path -LiteralPath $outPath)) {
    Remove-Item -LiteralPath $outPath -Recurse -Force
}
if (-not (Test-Path -LiteralPath $outPath)) {
    New-Item -ItemType Directory -Path $outPath -Force | Out-Null
}

$clang = Resolve-Tool -Name 'clang' -Candidates @('E:\LLVM\bin\clang.exe')
$lld = Resolve-Tool -Name 'ld.lld' -Candidates @('E:\LLVM\bin\ld.lld.exe', 'E:\LLVM\bin\lld.exe')
$llvmAr = Resolve-Tool -Name 'llvm-ar' -Candidates @('E:\LLVM\bin\llvm-ar.exe')
$llvmLib = Resolve-Tool -Name 'llvm-lib' -Candidates @('E:\LLVM\bin\llvm-lib.exe')
$mingw = Resolve-Tool -Name 'x86_64-w64-mingw32-gcc' -Candidates @(
    'E:\mingw64\bin\x86_64-w64-mingw32-gcc.exe',
    'E:\mingw64\bin\gcc.exe'
)
$mingwAr = Resolve-Tool -Name 'x86_64-w64-mingw32-ar' -Candidates @('E:\mingw64\bin\ar.exe')
$msvc = Resolve-Tool -Name 'cl' -Candidates @(
    'E:\VS2022\IDE\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe'
)

Write-Host ""
Write-Host "toolchain"
foreach ($pair in @(
        @('clang', $clang), @('ld.lld', $lld), @('llvm-ar', $llvmAr), @('llvm-lib', $llvmLib),
        @('mingw gcc', $mingw), @('mingw ar', $mingwAr), @('msvc cl', $msvc))) {
    $state = if ($pair[1]) { $pair[1] } else { 'not found' }
    Write-Host ("  {0,-12} {1}" -f $pair[0], $state)
}

Write-Host ""
Write-Host "sources"
New-Sources
[void]$script:produced.Add('C sources')
Write-Host "  ok   C sources (sample.c, start.c, pe-start.c, sample-msvc.c, bfshim.h)"

Write-Host ""
Write-Host "ELF objects (clang cross, no sysroot needed)"

$elfTargets = @(
    @('x86_64-unknown-linux-gnu', 'elf-x86_64.o'),
    @('i386-unknown-linux-gnu', 'elf-i386.o'),
    @('aarch64-unknown-linux-gnu', 'elf-aarch64.o'),
    @('armv7-unknown-linux-gnueabihf', 'elf-armv7.o'),
    @('riscv64-unknown-linux-gnu', 'elf-riscv64.o'),
    @('mips-unknown-linux-gnu', 'elf-mips32.o')
)
foreach ($target in $elfTargets) {
    Invoke-Step -Label ("object " + $target[1]) -Tool $clang -OutputName $target[1] -Arguments @(
        '-c', '-O1', '-fno-stack-protector', ('--target=' + $target[0]), 'sample.c', '-o', $target[1]
    )
}

Write-Host ""
Write-Host "ELF executables and shared objects (freestanding, linked with lld)"
Invoke-Step -Label 'elf-x86_64.exe (static, no libc)' -Tool $clang -OutputName 'elf-x86_64.exe' -Arguments @(
    '--target=x86_64-unknown-linux-gnu', '-nostdlib', '-static', '-fuse-ld=lld', '-O1',
    '-Wl,-e,_start', 'start.c', 'sample.c', '-o', 'elf-x86_64.exe'
)
Invoke-Step -Label 'elf-x86_64.so (shared, no libc)' -Tool $clang -OutputName 'elf-x86_64.so' -Arguments @(
    '--target=x86_64-unknown-linux-gnu', '-nostdlib', '-shared', '-fPIC', '-fuse-ld=lld', '-O1',
    'sample.c', '-o', 'elf-x86_64.so'
)
Invoke-Step -Label 'elf-aarch64.exe (static, no libc)' -Tool $clang -OutputName 'elf-aarch64.exe' -Arguments @(
    '--target=aarch64-unknown-linux-gnu', '-nostdlib', '-static', '-fuse-ld=lld', '-O1',
    '-Wl,-e,_start', 'start.c', 'sample.c', '-o', 'elf-aarch64.exe'
)

Write-Host ""
Write-Host "PE / COFF"
Invoke-Step -Label 'pe-x86_64.obj (mingw COFF object)' -Tool $mingw -OutputName 'pe-x86_64.obj' -Arguments @(
    '-c', '-O1', 'sample.c', '-o', 'pe-x86_64.obj'
)
Invoke-Step -Label 'pe-x86_64.exe (mingw, freestanding console)' -Tool $mingw -OutputName 'pe-x86_64.exe' -Arguments @(
    '-O1', '-nostartfiles', 'pe-start.c', 'sample.c', '-o', 'pe-x86_64.exe',
    '-Wl,--subsystem,console', '-Wl,-e,WinMainCRTStartup'
)
Invoke-Step -Label 'pe-x86_64.dll (mingw shared)' -Tool $mingw -OutputName 'pe-x86_64.dll' -Arguments @(
    '-shared', '-nostartfiles', '-O1', 'pe-start.c', 'sample.c', '-o', 'pe-x86_64.dll'
)
Invoke-Step -Label 'pe-x86_64-msvc.obj (MSVC COFF object)' -Tool $msvc -OutputName 'pe-x86_64-msvc.obj' -Arguments @(
    '/nologo', '/c', '/O1', '/nostdinc', 'sample-msvc.c', '/Fope-x86_64-msvc.obj'
)

Write-Host ""
Write-Host "archives"
Invoke-Step -Label 'libelf-x86_64.a (llvm-ar, ELF members)' -Tool $llvmAr -OutputName 'libelf-x86_64.a' -Arguments @(
    'rcs', 'libelf-x86_64.a', 'elf-x86_64.o'
)
Invoke-Step -Label 'libelf-multi.a (llvm-ar, 3 members)' -Tool $llvmAr -OutputName 'libelf-multi.a' -Arguments @(
    'rcs', 'libelf-multi.a', 'elf-x86_64.o', 'elf-aarch64.o', 'elf-i386.o'
)
Invoke-Step -Label 'libpe-x86_64.a (mingw ar, COFF members)' -Tool $mingwAr -OutputName 'libpe-x86_64.a' -Arguments @(
    'rcs', 'libpe-x86_64.a', 'pe-x86_64.obj'
)
Invoke-Step -Label 'pe-x86_64.lib (llvm-lib, MSVC style)' -Tool $llvmLib -OutputName 'pe-x86_64.lib' -Arguments @(
    '/nologo', '/out:pe-x86_64.lib', 'pe-x86_64.obj'
)

Write-Host ""
Write-Host "diff pairs (M9: two versions of one program, plus golden truth)"

# Why this belongs HERE and not in a hand-run command: the diff smoke test in
# preflight SKIPs when the pair is missing, and a SKIP reads as a pass. That is
# exactly the "the green light lies" failure mode called out in CLAUDE.md 7, so
# the fixture has to come from the standard generation path.
#
# The generator is Python (it derives the truth by set arithmetic over two
# llvm-nm symbol tables); it resolves clang/llvm-nm itself.
$python = Resolve-Tool -Name 'python' -Candidates @()
$diffGenerator = Join-Path $PSScriptRoot 'gen-diff-fixture.py'
if ($python -and (Test-Path -LiteralPath $diffGenerator)) {
    Invoke-Step -Label 'diff-pe-x86_64 (v1/v2 + truth.txt)' -Tool $python `
        -OutputName 'diff-pe-x86_64.truth.txt' `
        -Arguments @($diffGenerator, '--out', 'diff-pe-x86_64')
}
else {
    [void]$script:skipped.Add('diff-pe-x86_64 (python or gen-diff-fixture.py not found)')
    Write-Host "  skip diff-pe-x86_64 (python or gen-diff-fixture.py not found)"
}

Write-Host ""
Write-Host "edge cases"
# Raw binary: no recognizable header at all.
$raw = New-Object byte[] 4096
for ($i = 0; $i -lt $raw.Length; $i++) { $raw[$i] = [byte](($i * 7 + 13) % 256) }
[System.IO.File]::WriteAllBytes((Join-Path $outPath 'raw-blob.bin'), $raw)
[void]$script:produced.Add('raw-blob.bin (no header)')
Write-Host "  ok   raw-blob.bin (no header)"

# Truncated ELF: header cut in the middle.
$elfPath = Join-Path $outPath 'elf-x86_64.o'
if (Test-Path -LiteralPath $elfPath) {
    $bytes = [System.IO.File]::ReadAllBytes($elfPath)
    $take = [Math]::Min(20, $bytes.Length)
    $slice = New-Object byte[] $take
    [Array]::Copy($bytes, $slice, $take)
    [System.IO.File]::WriteAllBytes((Join-Path $outPath 'elf-truncated.bin'), $slice)
    [void]$script:produced.Add('elf-truncated.bin (20 bytes)')
    Write-Host "  ok   elf-truncated.bin (20 bytes)"
}

# File larger than the sniff window (8 MiB): loader must flag truncation.
$big = Join-Path $outPath 'elf-large.bin'
$stream = [System.IO.File]::Create($big)
try {
    $header = New-Object byte[] 64
    $header[0] = 0x7f
    $header[1] = [byte][char]'E'
    $header[2] = [byte][char]'L'
    $header[3] = [byte][char]'F'
    $header[4] = 2
    $header[5] = 1
    $header[6] = 1
    $header[16] = 2
    $header[18] = 62
    $stream.Write($header, 0, $header.Length)
    $chunk = New-Object byte[] (1024 * 1024)
    for ($i = 0; $i -lt 9; $i++) { $stream.Write($chunk, 0, $chunk.Length) }
}
finally {
    $stream.Dispose()
}
[void]$script:produced.Add('elf-large.bin (9 MiB, exceeds sniff window)')
Write-Host "  ok   elf-large.bin (9 MiB, exceeds sniff window)"

Write-Host ""
Write-Host ("produced: " + $script:produced.Count)
foreach ($item in $script:produced) { Write-Host ("  + " + $item) }

if ($script:skipped.Count -gt 0) {
    Write-Host ""
    Write-Host ("skipped: " + $script:skipped.Count)
    foreach ($item in $script:skipped) { Write-Host ("  - " + $item) }
    Write-Host ""
    Write-Host "A skipped sample is not fatal: the matching test is simply not runnable"
    Write-Host "on this machine. Re-run after fixing the toolchain to fill the gap."
}

Write-Host ""
Write-Host "done. These files are gitignored; regenerate any time."
Write-Host "quick check: cargo run -p bitflip-cli -- info tests/fixtures/generated/libelf-multi.a"
exit 0
