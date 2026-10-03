# BitFlip M4 crash-safety acceptance test (PLAN section M4, criterion 2).
#
# The claim under test: "kill the process mid-analysis; after restart the
# project database is readable and work can continue -- and the derived file is
# either the old version or the new one, never a half-written one."
#
# In-process tests cannot make that claim: exiting the test process proves
# nothing about a *separate* process dying. So this script starts
# m4-crash-tool.exe, kills it with Stop-Process -Force at each write stage, and
# then runs the verify subcommand in a fresh process.
#
# Why PowerShell and not Node: in this sandbox Node's child_process.spawn always
# fails with EPERM, so a Node script cannot start the process under test
# (CLAUDE.md section 6.6).
#
# Usage:
#   & .\scripts\m4-crash-test.ps1
#   & .\scripts\m4-crash-test.ps1 -KeepTemp
#
# Exits 0 only if every stage left the database readable.

[CmdletBinding()]
param(
    [switch]$KeepTemp
)

$ErrorActionPreference = 'Continue'

$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo '.cargo-target\debug\m4-crash-tool.exe'
$work = Join-Path $repo '.cargo-target\m4-crash'

if (-not (Test-Path $tool)) {
    Write-Host "m4-crash-tool.exe not found at $tool" -ForegroundColor Red
    Write-Host "Build it first:  & .\scripts\cargo.ps1 build -p bitflip-project" -ForegroundColor Yellow
    exit 1
}

if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$failures = @()
$stages = 0

function Invoke-Stage {
    param(
        [string]$Name,
        [string]$Subcommand,
        [string[]]$Arguments,
        [string]$KillPattern
    )

    $script:stages++
    Write-Host ""
    Write-Host "=== stage: $Name ===" -ForegroundColor Cyan

    $outFile = Join-Path $work "$Name.out.txt"
    $errFile = Join-Path $work "$Name.err.txt"

    # Start the tool, wait for it to reach the kill point (it prints KILLING),
    # then hard-kill it. Waiting for the marker (rather than sleeping a fixed
    # time) is what makes this deterministic: killing too early would test
    # "process never started", which is not the interesting case.
    #
    # Start-Process with -PassThru is used ONLY to get a killable PID. Its
    # ExitCode is not reliable here (it reads back as -1 under redirected
    # streams), so the writer's exit code is treated as informational only.
    # The verdict comes from the verifier below, which is invoked directly.
    $proc = Start-Process -FilePath $tool `
        -ArgumentList (@($Subcommand) + $Arguments) `
        -RedirectStandardOutput $outFile `
        -RedirectStandardError $errFile `
        -PassThru -NoNewWindow

    if ($KillPattern) {
        $deadline = (Get-Date).AddSeconds(30)
        $sawMarker = $false
        while ((Get-Date) -lt $deadline -and -not $proc.HasExited) {
            if (Test-Path $errFile) {
                $text = [string](Get-Content $errFile -Raw -ErrorAction SilentlyContinue)
                if ($text -match $KillPattern) { $sawMarker = $true; break }
            }
            Start-Sleep -Milliseconds 25
        }
        if ($sawMarker -or -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
        if (-not $sawMarker) {
            # A stage that was supposed to be killed but finished on its own
            # tests NOTHING: the verifier would pass simply because a complete
            # run is readable. Reporting that as PASS would be a false pass, so
            # it is recorded as a failure instead.
            $script:failures += "${Name}: writer was never killed (the '$KillPattern' marker was not observed); this stage did not exercise crash recovery"
            Write-Host "  RESULT: FAIL (writer not killed - stage proves nothing)" -ForegroundColor Red
            return
        }
        Write-Host "  killed after the '$KillPattern' marker"
    } else {
        $proc.WaitForExit()
    }

    # Verification runs in a FRESH process: that is the point of the test.
    # Invoked directly (& tool) rather than via Start-Process: direct invocation
    # reliably propagates $LASTEXITCODE and stdout, which Start-Process with
    # redirects does not in this environment.
    $verifyOut = Join-Path $work "$Name.verify.txt"
    $verifyErr = Join-Path $work "$Name.verify.err.txt"
    $verifyArgs = $Arguments
    if ($Subcommand -eq 'write-bfp') { $verifySub = 'verify-bfp'; $verifyArgs = @($Arguments[0], $Arguments[1]) }
    elseif ($Subcommand -eq 'write-bda') { $verifySub = 'verify-bda'; $verifyArgs = @($Arguments[0], $Arguments[1]) }
    elseif ($Subcommand -eq 'verify-index') { $verifySub = 'verify-index'; $verifyArgs = @($Arguments[0]) }
    else { $verifySub = $Subcommand }

    $verifyText = ''
    if (Test-Path $verifyOut) { Remove-Item $verifyOut -Force -ErrorAction SilentlyContinue }
    if (Test-Path $verifyErr) { Remove-Item $verifyErr -Force -ErrorAction SilentlyContinue }
    # NOTE: build one flat array. `@verifySub` would splat the *string* into
    # individual characters ("v"), which is exactly the bug this replaced.
    $allVerifyArgs = @($verifySub) + $verifyArgs
    $verifyStdout = & $tool $allVerifyArgs 2> $verifyErr | Out-String
    $verifyCode = $LASTEXITCODE
    $verifyText = [string]$verifyStdout
    if (Test-Path $verifyErr) {
        $verifyText += [string](Get-Content $verifyErr -Raw -ErrorAction SilentlyContinue)
    }
    $verifyText | Set-Content -Path $verifyOut -Encoding UTF8

    # The verdict rests on the verifier's own exit code. Additionally require the
    # "OK" line: an empty output with exit 0 would mean the tool did nothing,
    # which must not count as a pass.
    $saidOk = ($verifyText -match '(?m)^OK\s*$')
    if ($verifyCode -ne 0 -or -not $saidOk) {
        $script:failures += "${Name}: verification failed (exit $verifyCode, ok=$saidOk)`n$verifyText"
        Write-Host "  RESULT: FAIL" -ForegroundColor Red
        Write-Host "  $verifyText"
    } else {
        Write-Host "  RESULT: PASS" -ForegroundColor Green
        Write-Host "  $($verifyText.Trim())"
    }
}

$hash = ('ab' * 32)

# Each stage gets its OWN database. Reusing one file across stages would let the
# earlier complete run's rows show up in a later killed run's verification
# ("20000 rows readable" after a kill at 2000), which muddies the evidence even
# though the pass/fail verdict would be the same. A fresh file per stage makes
# the surviving prefix attributable to that stage alone.
function Stage-Path {
    param([string]$Name, [string]$Extension)
    return (Join-Path $work "$Name.$Extension")
}

# Control: a writer that runs to completion. Its output must be readable too --
# otherwise "readable after kill" would be trivially true because nothing works.
# The counts are deliberately large enough that the writer lives for several
# seconds: a 25ms poll cannot reliably catch a marker in a run that finishes in
# milliseconds, and a kill that lands after the writer already exited tests
# nothing.
Invoke-Stage -Name 'bfp-complete' -Subcommand 'write-bfp' `
    -Arguments @((Stage-Path 'bfp-complete' 'bfp'), $hash, '20000', '0') -KillPattern $null

# Kill mid-transaction, repeatedly at different points. SQLite's WAL means the
# committed prefix survives and the in-flight transaction vanishes; what must
# NEVER happen is "file unreadable".
foreach ($after in @(2000, 8000, 15000)) {
    $stageName = "bfp-kill-after-$after"
    Invoke-Stage -Name $stageName -Subcommand 'write-bfp' `
        -Arguments @((Stage-Path $stageName 'bfp'), $hash, '20000', "$after") -KillPattern 'KILLING'
}

# Derived file: killed while the tmp file is half-written. The published .bda
# must not exist yet (or must be the previous complete version).
Invoke-Stage -Name 'bda-kill-before-rename' -Subcommand 'write-bda' `
    -Arguments @((Stage-Path 'bda-kill-before-rename' 'bda'), $hash, '5000', '1') -KillPattern 'KILLING'

# Control: complete derived write, then verify it parses.
Invoke-Stage -Name 'bda-complete' -Subcommand 'write-bda' `
    -Arguments @((Stage-Path 'bda-complete' 'bda'), $hash, '5000', '0') -KillPattern $null

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
if ($failures.Count -eq 0) {
    Write-Host "crash-safety: ALL $stages STAGES PASSED" -ForegroundColor Green
    if (-not $KeepTemp) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
    exit 0
} else {
    Write-Host "crash-safety: $($failures.Count) OF $stages STAGES FAILED" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host "---"; Write-Host $f }
    Write-Host "artifacts kept at $work" -ForegroundColor Yellow
    exit 1
}
