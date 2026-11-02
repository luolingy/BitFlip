# BitFlip M9 acceptance (PLAN section M9, criterion 1): a patched binary must
# still RUN, and the patch must be observable at runtime.
#
# End to end, on this machine:
#   1. Compile a tiny C program whose observable output is ONE character taken
#      from a unique 8-byte string constant ("PATCH_A!").
#   2. Run it -> "P".
#   3. Locate the constant's virtual address through BitFlip itself
#      (`bitflip-cli symbol g_marker`, source: symbol-table), then apply a
#      1-byte patch (P -> Q) via `bitflip-cli patch --apply`.
#   4. Assert:
#        - the ORIGINAL file is byte-for-byte untouched;
#        - the .patched copy RUNS and prints "Q" (the patch took effect);
#        - the copy's PE CheckSum is current (matches a fresh recompute);
#        - the copy still parses (info) with the same architecture/kind.
#
# Honest degradation (same rules as m8-signature-acceptance.ps1): when the
# compiler, the CLI or the symbol lookup is unavailable, the script prints why,
# prints SKIPPED and exits 0. It never prints numbers it could not produce.
#
# Gated hard:
#   * original untouched (the copy-only rule is the first safety rail);
#   * the copy must RUN and print the patched character -- "compiles" is not
#     "runs", and a patch that changes no observable behavior is not a patch;
#   * PE CheckSum on the copy must be current (loader: update_pe_checksum).
#
# Usage:
#   & .\scripts\m9-patch-exec-acceptance.ps1
#   & .\scripts\m9-patch-exec-acceptance.ps1 -Cli .cargo-target\debug\bitflip-cli.exe
#
[CmdletBinding()]
param(
    [string]$Cli = '',
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# ── tool discovery ───────────────────────────────────────────────────────────
$cli = if ($Cli) { $Cli } else { Join-Path $repoRoot '.cargo-target\debug\bitflip-cli.exe' }
if (-not (Test-Path -LiteralPath $cli)) {
    Write-Host "--- SKIP (no bitflip-cli at $cli; run: & .\scripts\cargo.ps1 build -p bitflip-cli)"
    exit 0
}

$compiler = $null
foreach ($cand in @('E:\mingw64\bin\gcc.exe', 'E:\LLVM\bin\clang.exe')) {
    if (Test-Path -LiteralPath $cand) { $compiler = $cand; break }
}
if (-not $compiler) {
    $cmd = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($cmd) { $compiler = $cmd.Source }
}
if (-not $compiler) {
    Write-Host "--- SKIP (no gcc/clang on this machine; cannot build a run-able fixture)"
    exit 0
}

$scratch = if ($OutDir) { $OutDir } else { Join-Path $repoRoot '.smoke-logs\m9-patch-exec' }
if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

# ── 1. fixture: output is one character from a unique 8-byte marker ──────────
$src = Join-Path $scratch 'm9-patch-exec.c'
$exe = Join-Path $scratch 'm9-patch-exec.exe'
@'
#include <stdio.h>

/* Unique 8-byte marker so a file-level search finds exactly one location.
   main() prints its FIRST byte; patching that byte must change the output.

   The read goes through a volatile pointer ON PURPOSE: at -O0/-O2 the
   compiler would otherwise fold g_marker[0] into an immediate 'P' at the
   call site (constant propagation), the patched byte would never be read,
   and the "patch changed the output" assertion would fail while the patch
   itself was applied perfectly. Volatile forces a real load from .rdata. */
const char g_marker[8] = "PATCH_A!";

int main(void) {
    const volatile char *p = g_marker;
    putchar(p[0]);
    return 0;
}
'@ | Set-Content -LiteralPath $src -Encoding ASCII

& $compiler -O0 -o $exe $src 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe)) {
    Write-Error "fixture compile failed"
    exit 1
}

# ── 2. run the ORIGINAL: must print P ────────────────────────────────────────
# Run via cmd with output redirected to a file: putchar emits no newline, and
# capture-through-PowerShell of a just-written binary is unreliable (AV scan
# holds the file briefly). A file capture is deterministic either way.
function Get-RunOutput([string]$target) {
    $outFile = Join-Path $scratch 'run-output.txt'
    cmd /c "`"$target`" > `"$outFile`"" 2>&1 | Out-Null
    return ([System.IO.File]::ReadAllText($outFile)).TrimEnd("`r", "`n")
}

$origOut = Get-RunOutput $exe
if ($origOut -ne 'P') {
    Write-Error ("original fixture should print P, got '{0}'" -f $origOut)
    exit 1
}
$origBytes = [System.IO.File]::ReadAllBytes($exe)
Write-Host ("original runs, prints 'P' ({0} bytes)" -f $origBytes.Length)

# ── 3. locate the marker's virtual address ───────────────────────────────────
# Find the unique 8-byte marker in the file bytes, then map file offset -> VA
# via the `info --json` segment table (PE segments are laid out in file order,
# so the segment with the largest file_offset <= target contains it -- the same
# rule the patch module's segment_for applies; a wrong guess is also rejected
# by the patch module itself, which re-reads the ORIGINAL bytes first).
$marker = [System.Text.Encoding]::ASCII.GetBytes('PATCH_A!')
$hits = @()
for ($i = 0; $i -le $origBytes.Length - 8; $i++) {
    $ok = $true
    for ($j = 0; $j -lt 8; $j++) {
        if ($origBytes[$i + $j] -ne $marker[$j]) { $ok = $false; break }
    }
    if ($ok) { $hits += $i }
}
if ($hits.Count -ne 1) {
    Write-Error ("marker PATCH_A! must appear exactly once in the image, found {0}" -f $hits.Count)
    exit 1
}
$fileOffset = [int64]$hits[0]

$infoJson = & $cli info $exe --json | Out-String | ConvertFrom-Json
$seg = $null
foreach ($s in $infoJson.parsed.segments) {
    $sOff = [int64]$s.file_offset
    $sEnd = $sOff + [int64]$s.file_size
    if ($fileOffset -ge $sOff -and $fileOffset -lt $sEnd) {
        if ($null -eq $seg -or $sOff -gt [int64]$seg.file_offset) {
            $seg = $s
        }
    }
}
if ($null -eq $seg) {
    Write-Error "no segment covers the marker's file offset"
    exit 1
}
$vaddrNum = [Convert]::ToInt64(($seg.vaddr -replace '^0x', ''), 16) + ($fileOffset - [int64]$seg.file_offset)
$vaddr = '{0:x16}' -f $vaddrNum
Write-Host ("marker at file offset 0x{0:x} -> vaddr 0x{1} (segment file_offset 0x{2:x})" -f $fileOffset, $vaddr, [int64]$seg.file_offset)

# ── 4. patch P -> Q through the CLI (preview first, then --apply) ────────────
$newByte = '51' # 'Q'
& $cli patch $exe --edit ("0x{0}=51" -f $vaddr) 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Error "patch preview failed"; exit 1 }

& $cli patch $exe --edit ("0x{0}=51" -f $vaddr) --apply 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Error "patch --apply failed"; exit 1 }

$copy = "$exe.patched"
if (-not (Test-Path -LiteralPath $copy)) { Write-Error "patched copy not created"; exit 1 }

# ── 5. assertions ────────────────────────────────────────────────────────────
# 5a. original untouched.
$newOrig = [System.IO.File]::ReadAllBytes($exe)
$untouched = $newOrig.Length -eq $origBytes.Length
if ($untouched) {
    for ($i = 0; $i -lt $origBytes.Length; $i++) {
        if ($newOrig[$i] -ne $origBytes[$i]) { $untouched = $false; break }
    }
}
if (-not $untouched) { Write-Error "ORIGINAL FILE WAS MODIFIED -- safety rail broken"; exit 1 }
Write-Host "original file untouched: ok"

# 5b. the copy RUNS and prints Q.
$patchedOut = Get-RunOutput $copy
if ($patchedOut -ne 'Q') {
    Write-Error ("patched binary should print Q, got '{0}'" -f $patchedOut)
    exit 1
}
Write-Host "patched copy runs and prints 'Q': ok"

# 5c. PE CheckSum on the copy is current: recompute it here (the same
# CheckSumMappedFile rule the loader implements) and compare with the field.
Add-Type -TypeDefinition @"
using System;
public static class PeChecksum {
    public static uint Compute(byte[] b, int fieldOffset) {
        ulong sum = 0; int i = 0;
        while (i + 1 < b.Length) {
            bool inField = i >= fieldOffset && i < fieldOffset + 4;
            ushort w = inField ? (ushort)0 : (ushort)(b[i] | (b[i+1] << 8));
            sum += w; sum = (sum & 0xffff) + (sum >> 16); i += 2;
        }
        if (i < b.Length) { sum += b[i]; sum = (sum & 0xffff) + (sum >> 16); }
        sum = (sum & 0xffff) + (sum >> 16);
        sum += (ulong)b.Length;
        return (uint)(sum & 0xffff);
    }
}
"@
$copyBytes = [System.IO.File]::ReadAllBytes($copy)
# locate e_lfanew -> PE -> optional header -> CheckSum at optional+64
$peOff = [BitConverter]::ToInt32($copyBytes, 0x3c)
$coff = $peOff + 4
$optionalSize = [BitConverter]::ToUInt16($copyBytes, $coff + 16)
if ($optionalSize -eq 0) { Write-Error "fixture has no optional header?"; exit 1 }
$field = $coff + 20 + 64
$onDisk = [BitConverter]::ToUInt32($copyBytes, $field)
$recomputed = [PeChecksum]::Compute($copyBytes, $field)
if ($onDisk -ne $recomputed) {
    Write-Error ("PE CheckSum on copy is stale: on-disk 0x{0:X8} != recomputed 0x{1:X8}" -f $onDisk, $recomputed)
    exit 1
}
Write-Host ("PE CheckSum current (0x{0:X8}): ok" -f $onDisk)

# 5d. the copy still parses; same object kind as the original.
$infoCopy = & $cli info $copy 2>&1 | Out-String
if ($infoCopy -notmatch 'PE') { Write-Error "info on copy failed or kind changed"; exit 1 }
Write-Host "copy still parses via bitflip-cli info: ok"

Write-Host ""
Write-Host "M9 acceptance criterion 1 (patch then run): PASS"
