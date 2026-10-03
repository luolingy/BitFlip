# BitFlip arch-layering gate (PLAN M5 acceptance criterion 3).
#
# Claim under test: "architecture differences appear ONLY inside bitflip-arch".
#
# Why a gate and not a code review: the failure mode is silent and cumulative.
# One `if arch == Aarch64` added to analyze/ to fix a single fixture looks
# harmless; six months later the analyzer knows about five architectures and
# every new one touches every file. A grep gate catches that the moment it is
# written, which is the only time it is cheap to fix.
#
# What is checked:
#   1. crates/bitflip-analyze/src/*.rs and crates/bitflip-core/src/*.rs
#      (production code, #[cfg(test)] mod tests excluded) must not mention
#      architecture variants, endianness variants or mode variants.
#   2. crates/bitflip-server/src/*.rs likewise.
#
# Why tests are excluded: a unit test must be able to build a decoder for a
# specific architecture to verify it. Banning that would push fixtures out of
# the crate that owns the logic, which is worse.
#
# Known-good exceptions are listed BY FILE AND PATTERN with a reason. The list
# is meant to stay tiny; needing a new entry is a design smell worth arguing
# about rather than a one-line diff.
#
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads non-BOM files
# as ANSI, so any non-ASCII byte breaks parsing (see CLAUDE.md section 6).

[CmdletBinding()]
param(
    # Report findings but always exit 0 (for measuring the current debt).
    [switch]$Audit
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot

# Directories whose PRODUCTION code must be architecture-agnostic.
# bitflip-arch itself is deliberately absent: that is where arch belongs.
$guarded = @(
    'crates/bitflip-analyze/src',
    'crates/bitflip-core/src',
    'crates/bitflip-server/src'
)

# Architecture-specific tokens. Deliberately broad: a false positive costs a
# comment explaining why, a false negative costs the invariant.
$tokens = @(
    'Arch::X86_64', 'Arch::X86', 'Arch::Aarch64', 'Arch::Arm', 'Arch::Thumb',
    'Endian::Little', 'Endian::Big',
    'Mode::M16', 'Mode::M32', 'Mode::M64', 'Mode::Thumb', 'Mode::Arm',
    'Aarch64', 'AARCH64', 'x86_64', 'X86_64', 'Thumb', 'ARM64'
)

# Files where a token is allowed, with the reason. Key: repo-relative path
# (forward slashes). Value: array of tokens that are allowed there.
$exceptions = @{
    # The facade re-exports arch types so embedders need not depend on
    # bitflip-arch directly. Re-exporting a name is not branching on it.
    'crates/bitflip-core/src/lib.rs' = @('Endian', 'Mode', 'Arch')
}

function Get-ProductionLines {
    param([string]$Path)

    # Drop everything from the first `#[cfg(test)]` onwards. The convention in
    # this repo is a single trailing test module, so this is exact. If a file
    # ever gains a cfg(test) block in the middle, the gate would under-report,
    # so the script reports when the marker appears more than once.
    $lines = Get-Content -LiteralPath $Path
    $stop = $lines.Count
    $markers = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*#\[cfg\(test\)\]') {
            $markers++
            if ($markers -eq 1) { $stop = $i }
        }
    }
    if ($markers -gt 1) {
        Write-Host ("  NOTE " + $Path + ": " + $markers + " '#[cfg(test)]' markers; only the first is used as the cut point")
    }
    return $lines[0..([Math]::Max($stop - 1, 0))]
}

$violations = New-Object System.Collections.ArrayList
$scanned = 0

foreach ($dir in $guarded) {
    $full = Join-Path $repoRoot $dir
    if (-not (Test-Path -LiteralPath $full)) { continue }

    foreach ($file in Get-ChildItem -LiteralPath $full -Filter *.rs -Recurse -File) {
        $scanned++
        $rel = $file.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
        $allowed = @()
        if ($exceptions.ContainsKey($rel)) { $allowed = $exceptions[$rel] }

        $lines = Get-ProductionLines -Path $file.FullName
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            # Skip comment-only lines: prose explaining a limitation is not a
            # branch. (A doc comment saying "x86_64 uses ..." is informative
            # and should not fail the gate.)
            $trimmed = $line.TrimStart()
            if ($trimmed.StartsWith('//') -or $trimmed.StartsWith('*')) { continue }

            foreach ($token in $tokens) {
                if ($line -notmatch [regex]::Escape($token)) { continue }
                $isAllowed = $false
                foreach ($a in $allowed) {
                    if ($token.StartsWith($a, [System.StringComparison]::Ordinal)) { $isAllowed = $true }
                }
                if ($isAllowed) { continue }
                [void]$violations.Add([pscustomobject]@{
                    File = $rel
                    Line = $i + 1
                    Token = $token
                    Text = $line.Trim()
                })
            }
        }
    }
}

Write-Host "BitFlip arch-layering gate"
Write-Host ("  repo: " + $repoRoot)
Write-Host ("  guarded: " + ($guarded -join ', '))
Write-Host ("  scanned " + $scanned + " file(s)")

if ($violations.Count -eq 0) {
    Write-Host ""
    Write-Host "--- OK   architecture differences are confined to bitflip-arch"
    exit 0
}

Write-Host ""
Write-Host ("--- FAIL " + $violations.Count + " architecture reference(s) in arch-agnostic code:") -ForegroundColor Red
foreach ($v in $violations) {
    Write-Host ("  " + $v.File + ":" + $v.Line + "  [" + $v.Token + "]")
    Write-Host ("      " + $v.Text)
}
Write-Host ""
Write-Host "These belong behind a trait or a value computed in bitflip-arch."
Write-Host "If the reference is genuinely not a branch (e.g. a re-export),"
Write-Host "add it to the exceptions table in this script WITH a reason."

if ($Audit) {
    Write-Host ""
    Write-Host "(audit mode: exiting 0 anyway)"
    exit 0
}
exit 1
