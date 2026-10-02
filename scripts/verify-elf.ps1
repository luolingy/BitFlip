# Cross-checks bitflip's ELF parsing against llvm-readobj ground truth.
#
# M1 acceptance criterion 1 says the section table and entry point must be CORRECT
# for real samples -- not merely present. The only way to know that is to compare
# against an independent tool. This script parses both outputs and diffs them.
#
# NOTE: ASCII only. PowerShell 5.1 reads BOM-less files as ANSI, so non-ASCII
# text here would corrupt parsing (see CLAUDE.md section 6, trap 1).

[CmdletBinding()]
param(
    [string]$Bin = '.cargo-target/debug/bitflip-cli.exe',
    [string]$FixtureDir = 'tests/fixtures/generated'
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$binPath = Join-Path $repoRoot $Bin
$fixturePath = Join-Path $repoRoot $FixtureDir

$readobj = Get-Command llvm-readobj -ErrorAction SilentlyContinue
if (-not $readobj) { $readobj = Get-Command readelf -ErrorAction SilentlyContinue }
if (-not $readobj) {
    Write-Host "SKIP: neither llvm-readobj nor readelf is on PATH" -ForegroundColor Yellow
    exit 0
}
if (-not (Test-Path -LiteralPath $binPath)) {
    Write-Host "binary not found: $binPath" -ForegroundColor Red
    exit 1
}

$script:failures = 0
$script:checked = 0

function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    if ($Ok) {
        Write-Host ("  PASS  " + $Label)
    }
    else {
        $script:failures += 1
        $msg = "  FAIL  " + $Label
        if ($Detail) { $msg = $msg + " -- " + $Detail }
        Write-Host $msg -ForegroundColor Red
    }
}

# Parse bitflip's JSON output.
function Get-BitflipInfo {
    param([string]$File)
    $json = & $binPath info $File --json 2>&1 | Out-String
    $start = $json.IndexOf('{')
    if ($start -lt 0) { return $null }
    try { return ($json.Substring($start) | ConvertFrom-Json) } catch { return $null }
}

# Parse llvm-readobj JSON output.
# Shape: [ { ElfHeader: { Entry: <int>, ... }, Sections: [ { Section: { Name: { Name: ".text" } } } ] } ]
function Get-ReadobjInfo {
    param([string]$File)
    $raw = & $readobj.Source --elf-output-style=JSON -h -S $File 2>&1 | Out-String
    $start = $raw.IndexOf('[')
    if ($start -lt 0) { return $null }
    try {
        $parsed = ($raw.Substring($start) | ConvertFrom-Json)
        $entry = $null
        $sections = @()
        foreach ($obj in $parsed) {
            if ($obj.ElfHeader) { $entry = [uint64]$obj.ElfHeader.Entry }
            if ($obj.Sections) {
                foreach ($s in $obj.Sections) {
                    if ($s.Section) { $sections += $s.Section.Name.Name }
                }
            }
        }
        return @{ Entry = $entry; Sections = $sections }
    }
    catch { return $null }
}

Write-Host "ELF cross-check against llvm-readobj"
Write-Host ("  bitflip: " + $binPath)
Write-Host ("  readobj: " + $readobj.Source)
Write-Host ""

$targets = Get-ChildItem -LiteralPath $fixturePath -Filter 'elf-*' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -ne '.a' } |
    Sort-Object Name

if ($targets.Count -eq 0) {
    Write-Host "SKIP: no elf-* fixtures; run & .\scripts\gen-fixtures.ps1" -ForegroundColor Yellow
    exit 0
}

foreach ($target in $targets) {
    # Deliberately malformed inputs are not part of the equality comparison.
    if ($target.Name -match 'truncated|large') { continue }

    Write-Host ("=== " + $target.Name)
    $mine = Get-BitflipInfo -File $target.FullName
    $theirs = Get-ReadobjInfo -File $target.FullName

    if (-not $mine) {
        Check -Label "bitflip produced JSON" -Ok $false -Detail "no parseable output"
        continue
    }
    if (-not $theirs) {
        Write-Host "  SKIP  readobj could not parse this file"
        continue
    }

    $script:checked += 1

    $mineNames = @($mine.parsed.sections | ForEach-Object { $_.name })
    $theirNames = @($theirs.Sections)

    # readobj lists the SHT_NULL placeholder section 0; bitflip deliberately omits it.
    # Drop exactly one leading empty name from the readobj side if present.
    if ($theirNames.Count -gt 0 -and $theirNames[0] -eq '') {
        $theirNames = @($theirNames | Select-Object -Skip 1)
    }

    $onlyMine = @($mineNames | Where-Object { $_ -notin $theirNames })
    $onlyTheirs = @($theirNames | Where-Object { $_ -notin $mineNames })

    Check -Label ("section count matches (bitflip $($mineNames.Count) / readobj $($theirNames.Count))") `
        -Ok ($mineNames.Count -eq $theirNames.Count) `
        -Detail ("extra: " + ($onlyMine -join ',') + " missing: " + ($onlyTheirs -join ','))

    Check -Label "section name sets are identical" `
        -Ok (($onlyMine.Count -eq 0) -and ($onlyTheirs.Count -eq 0)) `
        -Detail ("only bitflip: " + ($onlyMine -join ',') + " only readobj: " + ($onlyTheirs -join ','))

    # Entry point: .o files legitimately have no meaningful entry on either side.
    if ($mine.target.entry) {
        $mineEntry = [Convert]::ToUInt64($mine.target.entry, 16)
        Check -Label ("entry point matches (" + $mine.target.entry + ")") `
            -Ok ($mineEntry -eq $theirs.Entry) `
            -Detail ("readobj=0x" + $theirs.Entry.ToString('x'))
    }
    else {
        Check -Label "no entry reported, and readobj agrees" `
            -Ok (($theirs.Entry -eq 0) -or ($target.Extension -eq '.o')) `
            -Detail ("readobj=0x" + $theirs.Entry.ToString('x'))
    }
    Write-Host ""
}

Write-Host ""
if ($script:checked -eq 0) {
    Write-Host "NO FILES CHECKED" -ForegroundColor Yellow
    exit 1
}
if ($script:failures -eq 0) {
    Write-Host ("ALL CHECKS PASSED (compared " + $script:checked + " files)")
    exit 0
}
Write-Host ("{0} CHECK(S) FAILED" -f $script:failures) -ForegroundColor Red
exit 1
