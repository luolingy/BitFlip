# BitFlip M8 PDB fixture generator.
#
# ASCII only: PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so any non-ASCII byte
# breaks parsing (CLAUDE.md section 6.1). Keep this file English-only.
#
# Produces (under tests/fixtures/generated/, all gitignored):
#   m8-pdb.exe         MSVC-style PE whose CodeView debug info lives in a separate .pdb
#   m8-pdb.pdb         the PDB itself
#   m8-pdb-nosym.exe   the same image with the COFF symbol table stripped (PDB untouched)
#   m8-pdb-nosym.pdb   its same-named PDB copy (see the note where it is written)
#   m8-pdb.golden.txt  ground truth: procedures and line records, from llvm-pdbutil
#
# Ground truth comes from an independent tool (llvm-pdbutil + llvm-readobj), never from
# BitFlip: comparing our parser against itself proves nothing.
#
# Golden addresses are virtual addresses (image base included), like every other fixture.
# Two conversions are needed and both are easy to get wrong:
#   * llvm-pdbutil prints SECTION-RELATIVE offsets -> add the section's own base;
#   * llvm-readobj prints VirtualAddress as an RVA -> add the image base.
# The loader works in virtual addresses, so the golden must too.

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Find-Tool {
    param([string]$Name, [string[]]$Fallbacks)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($f in $Fallbacks) {
        if (Test-Path $f) { return $f }
    }
    throw "missing tool $Name (tried PATH and $($Fallbacks -join ', '))"
}

$clangCl = Find-Tool 'clang-cl' @('E:\LLVM\bin\clang-cl.exe')
$lldLink = Find-Tool 'lld-link' @('E:\LLVM\bin\lld-link.exe')
$pdbutil = Find-Tool 'llvm-pdbutil' @('E:\LLVM\bin\llvm-pdbutil.exe')
$readobj = Find-Tool 'llvm-readobj' @('E:\LLVM\bin\llvm-readobj.exe')

$outDir = Join-Path $repo 'tests\fixtures\generated'
$work = Join-Path $repo '.cargo-tmp\m8-pdb-build'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $work | Out-Null

$src = Join-Path $repo 'tests\fixtures\m8_pdb_sample.c'
$obj = Join-Path $work 'm8_pdb_sample.obj'
$exe = Join-Path $outDir 'm8-pdb.exe'
$pdb = Join-Path $outDir 'm8-pdb.pdb'

Write-Host 'BitFlip M8 PDB fixture'
Write-Host ("  clang-cl : " + $clangCl)
Write-Host ("  lld-link : " + $lldLink)
Write-Host ("  pdbutil  : " + $pdbutil)

# /Z7 keeps CodeView inside the .obj; the linker then writes the PDB.
& $clangCl @('/c', '/Z7', '/Od', '/GS-', '/GR-', '/nologo', "/Fo$obj", $src) 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "clang-cl failed (exit $LASTEXITCODE)" }

# /NODEFAULTLIB + /ENTRY: the sample must link without the CRT.
& $lldLink @('/NOLOGO', '/DEBUG', '/SUBSYSTEM:CONSOLE', '/NODEFAULTLIB', '/ENTRY:bf_pdb_entry', "/OUT:$exe", "/PDB:$pdb", $obj) 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "lld-link failed (exit $LASTEXITCODE)" }
if (-not (Test-Path $pdb)) { throw "no PDB was produced at $pdb" }

# --- independent truth: image layout -------------------------------------------------
$headers = & $readobj '--file-headers' $exe 2>&1 | Out-String
$m = [regex]::Match($headers, 'ImageBase:\s*0x([0-9A-Fa-f]+)')
if (-not $m.Success) { throw "cannot read ImageBase from llvm-readobj output" }
$imageBase = [uint64]::Parse($m.Groups[1].Value, [System.Globalization.NumberStyles]::HexNumber)
Write-Host ("  ImageBase: 0x" + $imageBase.ToString('x'))

$sections = & $readobj '--sections' $exe 2>&1 | Out-String
$textVa = [uint64]0
$secIndex = 0
$secVaByIndex = @{}
foreach ($sm in [regex]::Matches($sections, 'Name:\s*(\S+)[\s\S]{0,600}?VirtualAddress:\s*0x([0-9A-Fa-f]+)')) {
    $secIndex++
    $rva = [uint64]::Parse($sm.Groups[2].Value, [System.Globalization.NumberStyles]::HexNumber)
    $secVaByIndex[$secIndex] = $imageBase + $rva
    if ($sm.Groups[1].Value -eq '.text') { $textVa = $secVaByIndex[$secIndex] }
}
if ($secVaByIndex.Count -eq 0) { throw "cannot read section headers (llvm-readobj --sections)" }
if ($textVa -lt $imageBase) { throw "no .text section found" }
Write-Host ("  .text VA: 0x" + $textVa.ToString('x'))

# --- procedures: S_GPROC32 / S_LPROC32 ---------------------------------------------
# Format (llvm-pdbutil dump -symbols):
#      112 | S_GPROC32 [size = 52] `bf_pdb_add`
#            parent = 0, end = 252, addr = 0001:0000, code size = 17
#
# TRAP: in this dump llvm-pdbutil prints `addr` as section:DECIMAL, not hex.
# A function that really sits at 0x20 is printed as `0001:0032`. Reading that as hex
# silently produces a wrong golden for every function whose offset has no A-F digits
# (measured: 5 of 6 procedures came out wrong). The check below makes it impossible to
# ship that mistake: each procedure's address must be exactly where its first line
# record is, otherwise this script fails.
$symDump = & $pdbutil 'dump' '-symbols' $pdb 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "llvm-pdbutil dump -symbols failed (exit $LASTEXITCODE)" }
$procPattern = 'S_[GL]PROC32\s*\[size = \d+\]\s*`(?<name>[^`]+)`[\s\S]{0,200}?addr = (?<sec>\d+):(?<off>\d+), code size = (?<size>\d+)'
$procs = New-Object System.Collections.Generic.List[object]
foreach ($pm in [regex]::Matches($symDump, $procPattern)) {
    $sec = [int]::Parse($pm.Groups['sec'].Value, [System.Globalization.NumberStyles]::None)
    $off = [uint64]::Parse($pm.Groups['off'].Value, [System.Globalization.NumberStyles]::None)
    if (-not $secVaByIndex.ContainsKey($sec)) { continue }
    $low = $secVaByIndex[$sec] + $off
    $size = [uint64]$pm.Groups['size'].Value
    $procs.Add([pscustomobject]@{ Name = $pm.Groups['name'].Value; Low = $low; High = $low + $size; Size = $size })
}
if ($procs.Count -eq 0) { throw "no S_GPROC32/S_LPROC32 records parsed" }

# --- line records --------------------------------------------------------------------
# Format (llvm-pdbutil dump -l):
#   F:\...\m8_pdb_sample.c (MD5: ...)
#     0001:00000000-00000011, line/addr entries = 2
#       12 00000000 !   13 00000008 !
$lineDump = & $pdbutil 'dump' '-l' $pdb 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "llvm-pdbutil dump -l failed (exit $LASTEXITCODE)" }

$rows = New-Object System.Collections.Generic.List[object]
$currentFile = ''
$currentSec = 0
foreach ($line in ($lineDump -split "`n")) {
    $fileMatch = [regex]::Match($line, '^(?<file>[A-Za-z]:\\.+?)\s+\(MD5:')
    if ($fileMatch.Success) { $currentFile = $fileMatch.Groups['file'].Value; continue }
    $rangeMatch = [regex]::Match($line, '^\s+(?<sec>[0-9A-Fa-f]{4}):(?<start>[0-9A-Fa-f]{8})-(?<end>[0-9A-Fa-f]{8}),')
    if ($rangeMatch.Success) {
        $currentSec = [int]::Parse($rangeMatch.Groups['sec'].Value, [System.Globalization.NumberStyles]::HexNumber)
        continue
    }
    if ($currentSec -eq 0 -or -not $secVaByIndex.ContainsKey($currentSec)) { continue }
    foreach ($em in [regex]::Matches($line, '(?<line>\d+)\s+(?<off>[0-9A-Fa-f]{8})\s+!')) {
        $off = [uint64]::Parse($em.Groups['off'].Value, [System.Globalization.NumberStyles]::HexNumber)
        $rows.Add([pscustomobject]@{
            Address = $secVaByIndex[$currentSec] + $off
            Line = [int]$em.Groups['line'].Value
            File = $currentFile
        })
    }
}
if ($rows.Count -eq 0) { throw "no line records parsed" }

# Declaration line: a PDB has no decl-line field, so use the procedure's first line record.
# At /Od the first line record sits exactly on the procedure entry, which is what makes the
# decimal-vs-hex check above meaningful: if the two dumps disagree about where a procedure
# starts, something is being misread and we must not write a golden from it.
$golden = New-Object System.Collections.Generic.List[string]
foreach ($p in ($procs | Sort-Object Low)) {
    $first = $rows | Where-Object { $_.Address -ge $p.Low -and $_.Address -lt $p.High } | Sort-Object Address, Line | Select-Object -First 1
    if (-not $first) { throw ("no line record inside " + $p.Name + " (0x" + $p.Low.ToString('x') + ")") }
    if ($first.Address -ne $p.Low) {
        throw ("cross-check failed: " + $p.Name + " starts at 0x" + $p.Low.ToString('x') + " but its first line record is at 0x" + $first.Address.ToString('x') + " - the symbol dump and the line dump disagree, do not trust either")
    }
    $golden.Add(("subprogram 0x{0} 0x{1} {2} {3} {4}" -f $p.Low.ToString('x8'), $p.High.ToString('x8'), $first.Line, $p.Name, $first.File))
}
foreach ($row in ($rows | Sort-Object Address, Line)) {
    $golden.Add(("line 0x{0} {1} {2}" -f $row.Address.ToString('x8'), $row.Line, $row.File))
}

$goldenPath = Join-Path $outDir 'm8-pdb.golden.txt'
[System.IO.File]::WriteAllLines($goldenPath, $golden, (New-Object System.Text.UTF8Encoding($false)))

# The interesting target: same image, no COFF symbol table, PDB intact.
$nosym = Join-Path $outDir 'm8-pdb-nosym.exe'
$objcopy = Get-Command 'objcopy' -ErrorAction SilentlyContinue
if ($objcopy) {
    Copy-Item $exe $nosym -Force
    & $objcopy.Source '--strip-all' $nosym 2>&1 | Out-Null
    # A stripped copy keeps its PDB. Stripping never renames a PDB in the real world; we
    # place a same-named copy because our lookup does not read the PE debug directory yet
    # (see crates/bitflip-debug/src/pdb.rs). The fixture is leaning on the implementation
    # here, so it says so instead of making it look like a coincidence.
    Copy-Item $pdb (Join-Path $outDir 'm8-pdb-nosym.pdb') -Force
    Write-Host "  wrote m8-pdb-nosym.exe (stripped) + m8-pdb-nosym.pdb"
} else {
    Write-Host "  skipped m8-pdb-nosym.exe: no objcopy"
}

$procCount = ($golden | Where-Object { $_.StartsWith('subprogram ') }).Count
$lineCount = ($golden | Where-Object { $_.StartsWith('line ') }).Count
Write-Host ("  golden: " + $procCount + " procedures, " + $lineCount + " line records")
Write-Host ("  exe: " + $exe)
Write-Host ("  pdb: " + $pdb)
