# BitFlip M8 debug-info fixture builder (PLAN section M8, deliverable 1).
#
# Deliverable 1 is DWARF + PDB: function names, source files and line numbers.
# The M3 sample (m3-mingw-static.unstripped.exe) is a bad fixture for that: its
# DWARF only covers the prebuilt libgcc objects (no DW_TAG_subprogram for our
# own functions, line table only for libgcc sources), so a parser could be
# totally broken and still "find" something.
#
# This script builds a fixture that actually exercises the path:
#
#   m8-debug.exe        -g -O0 -gdwarf-4 -static : our source, with symbols AND DWARF
#   m8-debug-nosym.exe  same code, DWARF KEPT, symbol table REMOVED
#   m8-debug.golden.txt independent truth from llvm-dwarfdump (see below)
#
# Why -O0: at -O0 the address->line mapping is one-to-one and easy to check by
# hand. Line-table behaviour under -O2 (inlining, line jumps) is a separate,
# later problem and is deliberately not mixed into this fixture.
#
# Why the nosym variant: the whole point of debug info as a symbol SOURCE is the
# case where the symbol table is gone. With symbols present, a parser bug hides
# behind the symbol table; without them, every name in the output came from
# DWARF or does not exist. objcopy --strip-all --keep-section is what makes that
# variant possible, and the script verifies both halves of the claim (debug
# sections still there, symbol table actually gone) instead of assuming.
#
# Why the golden file comes from llvm-dwarfdump: the project rule is that golden
# values come from an INDEPENDENT tool. Parsing DWARF with gimli and then
# comparing against gimli would prove nothing.
#
# Usage:
#   & .\scripts\gen-debug-fixture.ps1
#   & .\scripts\gen-debug-fixture.ps1 -Force

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot
$src = Join-Path $repo 'tests\fixtures\m3_coverage_sample.c'
$outDir = Join-Path $repo 'tests\fixtures\generated'
$exe = Join-Path $outDir 'm8-debug.exe'
$nosym = Join-Path $outDir 'm8-debug-nosym.exe'
$golden = Join-Path $outDir 'm8-debug.golden.txt'

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

# gcc/ld need a writable temp dir; the sandbox-provided TEMP is not writable by
# child processes here (see gen-m3-coverage-sample.ps1 for the full story).
$tmpDir = Join-Path $repo '.cargo-tmp'
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null }
$env:TMP = $tmpDir
$env:TEMP = $tmpDir

function Find-Tool([string]$name, [string[]]$fallbacks) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in $fallbacks) {
        if (Test-Path $candidate) { return $candidate }
    }
    return ''
}

$gcc = Find-Tool 'gcc.exe' @('E:\mingw64\bin\gcc.exe')
$objcopy = Find-Tool 'objcopy.exe' @('E:\mingw64\bin\objcopy.exe')
$objdump = Find-Tool 'objdump.exe' @('E:\mingw64\bin\objdump.exe')
$addr2line = Find-Tool 'addr2line.exe' @('E:\mingw64\bin\addr2line.exe')
$dwarfdump = Find-Tool 'llvm-dwarfdump.exe' @(
    'E:\LLVM\bin\llvm-dwarfdump.exe',
    'F:\Swift\Toolchains\6.1.0+Asserts\usr\bin\llvm-dwarfdump.exe')

foreach ($pair in @(@('gcc', $gcc), @('objcopy', $objcopy), @('objdump', $objdump), @('addr2line', $addr2line), @('llvm-dwarfdump', $dwarfdump))) {
    if (-not $pair[1]) {
        Write-Host ("missing tool: " + $pair[0]) -ForegroundColor Red
        exit 1
    }
}

if ((Test-Path $exe) -and (Test-Path $golden) -and -not $Force) {
    Write-Host "fixture already exists: $exe (use -Force to rebuild)"
    exit 0
}

Write-Host "compiling debug sample ..."
& $gcc -g -O0 -gdwarf-4 -static '-Wl,--gc-sections' -o $exe $src -lm 2>&1 |
    ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Host "compile failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit 1
}

# ---- DWARF kept, symbol table removed --------------------------------------
#
# --strip-all removes the COFF symbol table; --keep-section puts the debug
# sections back. Both halves are verified below: a leftover symbol table would
# silently turn "named from DWARF" into "named from the symbol table", which is
# exactly the bug this fixture exists to catch.
$debugSections = @(
    '.debug_info', '.debug_abbrev', '.debug_line', '.debug_str',
    '.debug_line_str', '.debug_aranges', '.debug_frame', '.debug_loc',
    '.debug_ranges', '.debug_addr', '.debug_str_offsets', '.debug_rnglists'
)
$keepArgs = @()
foreach ($name in $debugSections) { $keepArgs += "--keep-section=$name" }
& $objcopy --strip-all @keepArgs $exe $nosym 2>&1 | ForEach-Object { Write-Host "  $_" }
$nosymOk = $LASTEXITCODE -eq 0

if ($nosymOk -and (Test-Path $nosym)) {
    $sections = (& $objdump -h $nosym 2>&1) -join "`n"
    $hasDebugInfo = $sections -match '\.debug_info'
    $symbols = (& $objdump -t $nosym 2>&1) -join "`n"
    $symbolCount = ([regex]::Matches($symbols, '\(ty\s+20\)')).Count
    if (-not $hasDebugInfo) {
        Write-Host "nosym variant kept no .debug_info - dropping it" -ForegroundColor Yellow
        Remove-Item $nosym -Force
    } elseif ($symbolCount -ne 0) {
        Write-Host "nosym variant still has $symbolCount function symbols - dropping it" -ForegroundColor Yellow
        Remove-Item $nosym -Force
    } else {
        Write-Host "nosym variant ok: .debug_info present, 0 function symbols"
    }
} elseif (Test-Path $nosym) {
    Remove-Item $nosym -Force
}

# ---- ground truth from llvm-dwarfdump --------------------------------------
#
# Two shapes are captured:
#   subprogram  <low_pc-hex> <high_pc-hex> <decl_line> <name> <decl_file>
#   line        <addr-hex> <line> <file>
# Subprograms are sorted by address; line rows keep dwarfdump's order.
Write-Host "capturing ground truth with llvm-dwarfdump ..."
$info = & $dwarfdump --debug-info $exe 2>&1
$subprograms = New-Object System.Collections.ArrayList
# Walk the dump linearly: after each "DW_TAG_subprogram" header, the following
# DW_AT_* lines belong to that DIE until the next DIE header shows up.
$pending = $null
foreach ($raw in $info) {
    $line = $raw.Trim()
    if ($line -match '^0x[0-9a-f]+:\s+DW_TAG_') {
        if ($pending -and $pending['name'] -and $pending['low']) { [void]$subprograms.Add($pending) }
        if ($line -match 'DW_TAG_subprogram') {
            $pending = @{ name = ''; file = ''; line = ''; low = ''; high = ''; decl = $false }
        } else {
            $pending = $null
        }
        continue
    }
    if (-not $pending) { continue }
    if ($line -match '^DW_AT_name\s+\("(.*)"\)') { $pending['name'] = $Matches[1] }
    elseif ($line -match '^DW_AT_decl_file\s+\("(.*)"\)') { $pending['file'] = $Matches[1] }
    elseif ($line -match '^DW_AT_decl_line\s+\((\d+)\)') { $pending['line'] = $Matches[1] }
    elseif ($line -match '^DW_AT_low_pc\s+\((0x[0-9a-f]+)\)') { $pending['low'] = $Matches[1] }
    elseif ($line -match '^DW_AT_high_pc\s+\((0x[0-9a-f]+)\)') { $pending['high'] = $Matches[1] }
    elseif ($line -match '^DW_AT_declaration\s+\(true\)') { $pending['decl'] = $true }
}
if ($pending -and $pending['name'] -and $pending['low']) { [void]$subprograms.Add($pending) }

$defined = $subprograms | Where-Object { -not $_['decl'] -and $_['low'] }
if (-not $defined -or $defined.Count -lt 5) {
    Write-Host "llvm-dwarfdump reported fewer than 5 defined subprograms - fixture is not usable" -ForegroundColor Red
    exit 1
}

# Line rows: take the ADDRESSES from dwarfdump's line dump (parsing its file
# table by hand is a trap - DWARF 4 file tables are per-compile-unit, so index 1
# means a different file in each unit), then ask addr2line for the resolved
# file:line. addr2line is the standard tool for exactly this question and is
# independent of gimli, which is what makes it usable as a golden source.
$lineDump = & $dwarfdump --debug-line $exe 2>&1
$lineAddrs = New-Object System.Collections.ArrayList
$seenAddr = @{}
foreach ($raw in $lineDump) {
    $line = $raw.Trim()
    if ($line -notmatch '^(0x[0-9a-f]+)\s+\d+\s+\d+\s+\d+\s') { continue }
    $addr = [System.Convert]::ToUInt64($Matches[1], 16)
    if ($seenAddr.ContainsKey($addr)) { continue }
    $seenAddr[$addr] = $true
    [void]$lineAddrs.Add($addr)
}
if ($lineAddrs.Count -lt 5) {
    Write-Host "llvm-dwarfdump reported fewer than 5 line rows - fixture is not usable" -ForegroundColor Red
    exit 1
}
$sortedAddrs = $lineAddrs | Sort-Object

$addrArgs = @('-e', $exe, '-f')
foreach ($addr in $sortedAddrs) { $addrArgs += ('0x' + $addr.ToString('x')) }
$addrLines = & $addr2line @addrArgs 2>&1
$lineRows = New-Object System.Collections.ArrayList
for ($i = 0; $i + 1 -lt $addrLines.Count; $i += 2) {
    $addrIndex = [int]($i / 2)
    if ($addrIndex -ge $sortedAddrs.Count) { break }
    $where = $addrLines[$i + 1]
    $addr = $sortedAddrs[$addrIndex]
    # "file:line" (Windows drive letters contain a colon, so split from the right).
    $split = $where.LastIndexOf(':')
    if ($split -lt 0) { continue }
    $file = $where.Substring(0, $split)
    $lineNo = $where.Substring($split + 1)
    if ($file -eq '??' -or -not ($lineNo -match '^\d+$')) { continue }
    [void]$lineRows.Add([pscustomobject]@{
            addr = ('0x' + $addr.ToString('x16'))
            line = [int]$lineNo
            file = $file
        })
}
if ($lineRows.Count -lt 5) {
    Write-Host "addr2line resolved fewer than 5 line rows - fixture is not usable" -ForegroundColor Red
    exit 1
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# BitFlip M8 debug-info ground truth')
[void]$sb.AppendLine('# source: llvm-dwarfdump --debug-info / --debug-line (independent tool)')
[void]$sb.AppendLine('# target: tests/fixtures/generated/m8-debug.exe')
[void]$sb.AppendLine('#   built by: scripts/gen-debug-fixture.ps1 (-g -O0 -gdwarf-4 -static)')
[void]$sb.AppendLine('# format: "subprogram <low_pc> <high_pc> <decl_line> <name> <decl_file>"')
[void]$sb.AppendLine('#         "line <addr> <line> <file>"')
foreach ($s in ($defined | Sort-Object { [System.Convert]::ToUInt64($_['low'], 16) })) {
    [void]$sb.AppendLine("subprogram $($s['low']) $($s['high']) $($s['line']) $($s['name']) $($s['file'])")
}
foreach ($r in $lineRows) {
    [void]$sb.AppendLine("line $($r.addr) $($r.line) $($r.file)")
}
[System.IO.File]::WriteAllText($golden, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "fixture   : $exe"
Write-Host "nosym     : $nosym"
Write-Host "golden    : $golden"
Write-Host "subprograms: $($defined.Count)  line rows: $($lineRows.Count)"
