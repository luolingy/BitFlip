# M8 deliverable 3 (compiler builtin pattern library) fixture.
#
# Produces, under tests/fixtures/generated/:
#   m8-builtins.exe         unstripped twin (truth: symbol table)
#   m8-builtins-nosym.exe   objcopy --strip-all twin (what the pattern must work on)
#   m8-builtins.golden.txt  third-party-derived truth for the stack-probe helper
#
# Truth comes from mingw's objdump only -- nothing here trusts BitFlip's own output.
# The script FAILS LOUDLY when the sample did not produce a real page-stepping probe:
# a stub (plain `xor eax, eax; ret`) would make any "the pattern matched" claim vacuous,
# because plenty of tiny functions look like that.
#
# ASCII only: PowerShell 5.1 reads BOM-less scripts as ANSI (CLAUDE.md 6.1).

$root = Split-Path -Parent $PSScriptRoot
$gen = Join-Path $root 'tests\fixtures\generated'
$src = Join-Path $root 'tests\fixtures\m8_builtins_sample.c'
$gcc = 'E:\mingw64\bin\gcc.exe'
$objcopy = 'E:\mingw64\bin\objcopy.exe'
$objdump = 'E:\mingw64\bin\objdump.exe'

foreach ($tool in @($gcc, $objcopy, $objdump)) {
  if (-not (Test-Path $tool)) { throw "missing tool: $tool" }
}
if (-not (Test-Path $gen)) { New-Item -ItemType Directory -Path $gen | Out-Null }

$exe = Join-Path $gen 'm8-builtins.exe'
$nosym = Join-Path $gen 'm8-builtins-nosym.exe'
$golden = Join-Path $gen 'm8-builtins.golden.txt'

# -O1 keeps the stack frame; no -fomit-frame-pointer games needed. The probe helper is
# pulled in by the link because bf_builtins_big() has an 8 KiB frame.
& $gcc -O1 -o $exe $src
if ($LASTEXITCODE -ne 0) { throw "gcc failed: exit $LASTEXITCODE" }
$version = ((& $gcc --version 2>&1 | Select-Object -First 1) -as [string]).Trim()

# Image base + .text VMA: for PE, objdump reports symbol offsets as section-relative,
# so VA = imageBase + textVma + offset. (Same trap the PDB fixture hit in another form.)
$headers = (& $objdump -x $exe 2>&1 | Out-String)
$baseMatch = [regex]::Match($headers, 'ImageBase\s+([0-9a-fA-F]+)')
if (-not $baseMatch.Success) { throw 'no ImageBase in objdump -x output' }
$imageBase = [System.Convert]::ToUInt64($baseMatch.Groups[1].Value, 16)

$sectionText = (& $objdump -h $exe 2>&1 | Out-String)
$textMatch = [regex]::Match($sectionText, '(?m)^\s*\d+\s+\.text\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)')
if (-not $textMatch.Success) { throw 'no .text section in objdump -h output' }
$textSize = [System.Convert]::ToUInt64($textMatch.Groups[1].Value, 16)
$textVma = [System.Convert]::ToUInt64($textMatch.Groups[2].Value, 16)

$symbols = (& $objdump -t $exe 2>&1 | Out-String)
$symPattern = '(?m)^\[[^\]]*\]\(sec\s+1\)\(fl[^)]*\)\(ty\s+\d+\)\(scl\s+\d+\)\s+\(nx\s+\d+\)\s+0x([0-9a-fA-F]+)\s+___chkstk_ms\s*$'
$symMatch = [regex]::Match($symbols, $symPattern)
if (-not $symMatch.Success) {
  throw 'no ___chkstk_ms symbol: the sample did not need the stack-probe helper'
}
# Careful: mingw's objdump prints an *absolute* VMA for the section (image base already
# folded in) while symbol values stay section-relative. So VA = textVma + symbolOffset,
# NOT imageBase + textVma + symbolOffset. Getting this wrong put the window at 0x2800025c0
# and the disassembly came back empty -- which is why the check right below exists.
$helperVa = $textVma + [System.Convert]::ToUInt64($symMatch.Groups[1].Value, 16)
if ($textVma -lt $imageBase) { throw ('section VMA 0x{0:x} is below the image base -- offset convention changed' -f $textVma) }

# Disassemble the helper (bounded window) and check it really is a page-stepping probe.
$startArg = '0x{0:x}' -f $helperVa
$stopArg = '0x{0:x}' -f ($helperVa + 0x80)
$dump = (& $objdump -d -j .text --start-address=$startArg --stop-address=$stopArg $exe 2>&1 | Out-String)
$insnLines = @(($dump -split "`n") | Where-Object { $_ -match '^\s+[0-9a-f]+:' })
if ($insnLines.Count -eq 0) { throw "no instructions disassembled at $startArg" }
$firstVa = [System.Convert]::ToUInt64([regex]::Match($insnLines[0], '^\s+([0-9a-f]+):').Groups[1].Value, 16)
if ($firstVa -ne $helperVa) {
  throw ('disassembly starts at 0x{0:x} but the symbol says 0x{1:x}' -f $firstVa, $helperVa)
}

$end = -1
for ($i = 0; $i -lt $insnLines.Count; $i++) {
  if ($insnLines[$i] -match '\bret\b') { $end = $i; break }
}
if ($end -lt 0) { throw 'the probe helper has no ret within 0x80 bytes' }
$bodyLines = @($insnLines[0..$end])
$body = $bodyLines -join "`n"

if ($body -notmatch '\$0x1000') {
  throw "no 0x1000 page step -- this is a stub, not a probe:`n$body"
}
if ($body -notmatch '(test|or|and|mov)[a-z]*\s+[^\n]*\(%r') {
  throw "no memory probe in the helper body:`n$body"
}
if ($body -notmatch '\bj[a-z]+\s') {
  throw "no conditional branch in the helper body:`n$body"
}

$retLine = [regex]::Match($bodyLines[-1], '^\s+([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)')
if (-not $retLine.Success) { throw "cannot read the last instruction line: $($bodyLines[-1])" }
$retVa = [System.Convert]::ToUInt64($retLine.Groups[1].Value, 16)
$retBytes = @([regex]::Matches($retLine.Groups[2].Value, '[0-9a-f]{2}')).Count
$helperLen = $retVa + $retBytes - $helperVa
if ($helperLen -le 4 -or $helperLen -gt 0x60) { throw "implausible helper length: 0x$('{0:x}' -f $helperLen)" }

# Stripped twin: same addresses, no symbol table. This is what the pattern must name.
& $objcopy --strip-all $exe $nosym
if ($LASTEXITCODE -ne 0) { throw "objcopy --strip-all failed: exit $LASTEXITCODE" }

$goldenLines = @(
  'BitFlip M8 deliverable 3 fixture -- stack-probe helper truth',
  'source:        tests/fixtures/m8_builtins_sample.c',
  "compiler:      $version",
  ('imageBase:     0x{0:x}' -f $imageBase),
  ('textVma:       0x{0:x}' -f $textVma),
  ('textSize:      0x{0:x}' -f $textSize),
  'helperSymbol:  ___chkstk_ms',
  ('helperVa:      0x{0:x}' -f $helperVa),
  ('helperLength:  0x{0:x}' -f $helperLen),
  "-- disassembly as printed by $objdump (truth, not BitFlip output) --"
) + $bodyLines
[System.IO.File]::WriteAllLines($golden, $goldenLines, (New-Object System.Text.UTF8Encoding($false)))

$exeSize = (Get-Item $exe).Length
$nosymSize = (Get-Item $nosym).Length
Write-Output "builtins fixture: $exe ($exeSize B), $nosym ($nosymSize B)"
Write-Output ('helper ___chkstk_ms at 0x{0:x}, length 0x{1:x} ({2} instructions)' -f $helperVa, $helperLen, $bodyLines.Count)
Write-Output "golden: $golden"
