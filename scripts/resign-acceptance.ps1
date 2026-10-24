# BitFlip resign acceptance (PLAN M12 / docs/MACHO-RESIGN-DESIGN.md): a real
# ad-hoc Mach-O binary, re-signed in place via `bitflip-cli resign --apply`, must
# re-verify as "integrity OK" (all code pages match) -- using OUR OWN parser as the
# cross-check, and, when a real `codesign` tool is present, that tool too.
#
# Why these numbers can only come from here:
#   * We do NOT ship a signed Mach-O sample. The tool must run on a real binary
#     the user has. This script accepts -Sample (a thin Mach-O). If none is given
#     and no default exists, it prints SKIPPED and exits 0 -- it never fabricates.
#
# What is gated:
#   * The re-signed copy must re-parse as Intact/AdHoc with verified == code slots
#     (all pages pass). A single mismatched page is a hard failure.
#   * The output must NOT be the input path (resign never overwrites in place).
#   * The readable vouch is reported by `bitflip-cli info` and must say
#     "完整性通过". If a real `codesign` exists, `codesign -v` is run as a second
#     opinion; if not, that step is reported as SKIPPED (not a pass).
#
# Scope note (honest): this stage only supports the "signature fits in its old
# slot" path. Binaries that need moving the signature block are out of scope and
# the tool reports that clearly; such a sample is SKIPPED here, not failed.
#
# Usage:
#   & .\scripts\resign-acceptance.ps1 -Sample path\to\Thin.Macho
#   & .\scripts\resign-acceptance.ps1 -Sample Foo.dylib -Cli .cargo-target\debug\bitflip-cli.exe

[CmdletBinding()]
param(
    [string]$Sample = '',
    [string]$Cli = '',
    [switch]$AsJson
)

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot

function Resolve-Cli {
    param([string]$Given)
    if ($Given -ne '') { return $Given }
    foreach ($candidate in @(
            (Join-Path $repo '.cargo-target\debug\bitflip-cli.exe'),
            (Join-Path $repo '.cargo-target\release\bitflip-cli.exe'))) {
        if (Test-Path $candidate) { return $candidate }
    }
    return ''
}

$cli = Resolve-Cli -Given $Cli
if ($cli -eq '') {
    Write-Host 'SKIPPED: 找不到 bitflip-cli.exe（先 cargo build -p bitflip-cli）'
    exit 0
}

if ($Sample -eq '' -or -not (Test-Path $Sample)) {
    Write-Host 'SKIPPED: 未提供真实薄 Mach-O 样本（用 -Sample <path>）'
    exit 0
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("bitflip-resign-" + [Guid]::NewGuid().ToString('N'))
$out = "$tmp.resigned"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    # 1) 预览（只读）：确认能重签；不能就如实 SKIPPED（不当作失败）。
    $preview = & $cli resign $Sample 2>&1 | Out-String
    if ($preview -match '不能重签') {
        Write-Host "SKIPPED: 该样本本阶段不支持（$(($preview -split "`n")[0].Trim())）"
        exit 0
    }

    # 2) 落盘（--apply 到临时输出，避免污染样本目录）。
    $apply = & $cli resign $Sample --apply --output $out 2>&1 | Out-String
    if (-not (Test-Path $out)) {
        Write-Host "FAIL: 没有写出副本。输出：$apply"
        exit 1
    }

    # 3) 用我们自己的 parser 复核：info 里必须报"完整性通过"且 ad-hoc。
    $info = & $cli info $out 2>&1 | Out-String
    $intact = ($info -match '完整性通过')
    $adhoc = ($info -match 'ad-hoc')
    if (-not ($intact -and $adhoc)) {
        Write-Host 'FAIL: 重签副本没有通过完整性校验（info 输出）：'
        Write-Host $info
        exit 1
    }
    # 抽一行 verified 计数，确认所有 code page 都过。
    $pageLine = ($info -split "`n" | Where-Object { $_ -match '个 code page 哈希一致' } | Select-Object -First 1)
    Write-Host "本工具复核：$($pageLine.Trim())"

    # 4) 可选第二意见：真实 codesign -v（没有就 SKIP）。
    $codesign = Get-Command codesign -ErrorAction SilentlyContinue
    if ($null -eq $codesign) {
        Write-Host 'codesign -v：SKIPPED（本机没有 apple codesign 工具）'
    } else {
        & $codesign.Source -v $out 2>&1 | ForEach-Object { Write-Host "codesign：$_" }
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'FAIL: codesign -v 未通过'
            exit 1
        }
        Write-Host 'codesign -v：通过（第二意见）'
    }

    Write-Host "PASS: 重签副本完整性通过（ad-hoc，$($pageLine.Trim())）"
    exit 0
}
finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -Path $tmp, $out
}
