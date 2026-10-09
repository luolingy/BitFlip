# BitFlip MSVC C++ fixture (M8 leftover: name demangling).
#
# Why this fixture exists: demangling can only be verified end to end on a target that
# actually carries MSVC-decorated names (`?bar@Widget@@QEAAHH@Z`). Every other fixture in
# this repo is C or Itanium-mangled, so none of them exercises that path.
#
# Traps (do not "simplify" them away):
#   * clang-cl writes the object as /Fo<path> -- NO colon. `/Fo:<path>` is parsed as `/Fo`
#     plus a stray `:...` argument and fails with "unable to open output file ':...'".
#     The same applies to /Fd.
#   * The sample has no `virtual` member and is built with /GR-: a vtable/RTTI would want
#     type_info from the runtime library, and we link with /nodefaultlib.
#   * The sample includes no headers: clang-cl here runs without a vcvars environment, so
#     the MSVC standard headers are not on the include path.
#
# Truth comes from third-party tools only: `dumpbin /symbols` for the decorated names and
# `undname` for the readable ones. We never hand-write the expected strings.

[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\tests\fixtures\generated')
)

$ErrorActionPreference = 'Continue'
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
$src = Join-Path $PSScriptRoot '..\tests\fixtures\m8_cxx_sample.cpp'
if (-not (Test-Path -LiteralPath $src)) { throw "missing sample: $src" }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

function Resolve-Tool([string]$name, [string[]]$candidates) {
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "tool not found: $name"
}

$clangCl = Resolve-Tool 'clang-cl' @('E:\LLVM\bin\clang-cl.exe')
$lld = Resolve-Tool 'lld-link' @('E:\LLVM\bin\lld-link.exe')
$undname = Resolve-Tool 'undname' (Get-ChildItem 'E:\VS2022\IDE\VC\Tools\MSVC\*\bin\Hostx64\x64\undname.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$dumpbin = Resolve-Tool 'dumpbin' (Get-ChildItem 'E:\VS2022\IDE\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })

$obj = Join-Path $OutDir 'm8-cxx.obj'
$exe = Join-Path $OutDir 'm8-cxx.exe'
$pdb = Join-Path $OutDir 'm8-cxx.pdb'

Write-Host "compiling $src"
& $clangCl @('/c', '/Zi', '/GR-', '/GS-', '/nologo', "/Fo$obj", "/Fd$pdb", $src) 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) { throw "clang-cl failed with $LASTEXITCODE" }

Write-Host "linking $exe"
& $lld @('/debug', "/pdb:$pdb", '/machine:x64', '/entry:bf_cxx_entry', '/subsystem:console', '/nodefaultlib', "/out:$exe", $obj) 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) { throw "lld-link failed with $LASTEXITCODE" }

foreach ($f in @($obj, $exe, $pdb)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "expected output missing: $f" }
    Write-Host ("  {0}  {1} bytes" -f (Split-Path $f -Leaf), (Get-Item -LiteralPath $f).Length)
}

# Decorated names from the object file, readable names from undname. Both are third-party
# output; anything we assert in tests should come from here.
$symbols = (& $dumpbin /symbols $obj 2>&1 | Out-String)
$decorated = [regex]::Matches($symbols, '\?[A-Za-z_0-9@?$]+') | ForEach-Object { $_.Value } | Sort-Object -Unique
if (-not $decorated) { throw "no decorated names in $obj -- the fixture is not proving anything" }

$rows = @()
foreach ($name in $decorated) {
    $out = (& $undname $name 2>&1 | Out-String)
    $quoted = [regex]::Matches($out, '"([^"]*)"')
    # undname prints the input first and the result last; taking the first one is the bug
    # that made an earlier version of the demangling tests self-confirming.
    $readable = if ($quoted.Count -ge 2) { $quoted[$quoted.Count - 1].Groups[1].Value } else { '' }
    if (-not $readable) { throw "undname gave no readable form for $name" }
    $rows += ("{0}`t{1}" -f $name, $readable)
}
$rows += ("{0}`t{1}" -f 'bf_cxx_entry', 'bf_cxx_entry')

$golden = Join-Path $OutDir 'm8-cxx.golden.txt'
$lines = @('# BitFlip M8 C++ fixture truth (dumpbin /symbols + undname)')
$lines += '# decorated<TAB>readable'
$lines += $rows
$lines += ($symbols -split "`n" | Where-Object { $_ -match '^\s+\d+\s+\S+\s+\S+' } | Select-Object -First 40)
[System.IO.File]::WriteAllLines($golden, $lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("golden: {0} ({1} name pairs)" -f $golden, $rows.Count)