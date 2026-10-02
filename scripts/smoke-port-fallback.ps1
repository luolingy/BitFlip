# Verifies port fallback and that the Origin allow-list is bound to the port the
# server ACTUALLY got, not the one that was requested.
#
# Written in PowerShell rather than Node because this sandbox denies
# child_process.spawn from Node (EPERM), while PowerShell background jobs work.
#
# Usage:
#   & .\scripts\smoke-port-fallback.ps1

[CmdletBinding()]
param(
    [string]$Bin = '.cargo-target/debug/bitflip-cli.exe',
    [string]$Target = 'tests/fixtures/generated/elf-x86_64.o',
    [int]$Port = 8790
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$binPath = Join-Path $repoRoot $Bin
$logDir = Join-Path $repoRoot '.smoke-logs'
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $binPath)) {
    Write-Host "binary not found: $binPath" -ForegroundColor Red
    Write-Host "build it first:  & .\scripts\cargo.ps1 build --workspace"
    exit 1
}

$script:failures = 0

function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    if ($Ok) {
        Write-Host ("  PASS  " + $Label + $(if ($Detail) { " -- $Detail" } else { '' }))
    }
    else {
        $script:failures += 1
        Write-Host ("  FAIL  " + $Label + $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}

function Start-Bitflip {
    param([int]$RequestedPort, [string]$Token, [string]$Tag)

    $out = Join-Path $logDir "$Tag.out.log"
    $err = Join-Path $logDir "$Tag.err.log"
    $arguments = @('serve', $Target, '--no-open', '--port', "$RequestedPort", '--token', $Token)

    return Start-Process -FilePath $binPath -ArgumentList $arguments -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
}

function Wait-ForPort {
    param([string]$Tag, [int]$TimeoutSeconds = 30)

    $out = Join-Path $logDir "$Tag.out.log"
    for ($i = 0; $i -lt ($TimeoutSeconds * 5); $i++) {
        if (Test-Path -LiteralPath $out) {
            # -Raw returns $null for an empty file, and [regex]::Match rejects a
            # null input with an ArgumentNullException -- coerce to '' first.
            $text = [string](Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
            $match = [regex]::Match($text, 'http://127\.0\.0\.1:(\d+)/#token=')
            if ($match.Success) { return [int]$match.Groups[1].Value }
        }
        # Bail out early if the process already died (bind error, bad target, ...).
        # Matched with ASCII patterns only: this file must stay ASCII because
        # Windows PowerShell 5.1 reads non-BOM scripts as ANSI (see scripts/cargo.ps1).
        $errLog = Join-Path $logDir "$Tag.err.log"
        if (Test-Path -LiteralPath $errLog) {
            $errText = [string](Get-Content -LiteralPath $errLog -Raw -ErrorAction SilentlyContinue)
            if ($errText -match 'error:|panic|not found|failed') {
                Write-Host ("  " + $Tag + " failed to start:")
                ($errText -split "`n" | Select-Object -First 4) | ForEach-Object { Write-Host ("       " + $_) }
                return 0
            }
        }
        Start-Sleep -Milliseconds 200
    }
    return 0
}

function Invoke-Status {
    param([string]$Uri, [hashtable]$Headers = @{})

    try {
        $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -UseBasicParsing -ErrorAction Stop
        return [int]$response.StatusCode
    }
    catch {
        if ($_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode.value__
        }
        return 0
    }
}

Write-Host "BitFlip port fallback smoke test"
Write-Host ("  binary: " + $binPath)
Write-Host ("  target: " + $Target)
Write-Host ""

# Kill anything left over from a previous run so the port is genuinely free.
Get-Process bitflip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$first = $null
$second = $null

# NOTE: cleanup happens AFTER the checks, at the end of the script. Putting it in a
# finally block here would tear both servers down before a single check ran -- the
# test would then "pass" against a dead server.
try {
    $first = Start-Bitflip -RequestedPort $Port -Token 'tokenone' -Tag 'first'
    $firstPort = Wait-ForPort -Tag 'first'
    Write-Host "first server port: $firstPort"
    Check -Label "first server listens on the requested port" -Ok ($firstPort -eq $Port) -Detail "got $firstPort"

    $second = Start-Bitflip -RequestedPort $Port -Token 'tokentwo' -Tag 'second'
    $secondPort = Wait-ForPort -Tag 'second'
    Write-Host "second server port: $secondPort"
    Check -Label "second server moved off the occupied port" -Ok ($secondPort -eq ($Port + 1)) -Detail "got $secondPort"

    if ($secondPort -gt 0) {
        $base = "http://127.0.0.1:$secondPort/api/health"
        Check -Label "origin of the ACTUAL port is allowed" `
            -Ok ((Invoke-Status -Uri $base -Headers @{ 'x-bitflip-token' = 'tokentwo'; 'Origin' = "http://127.0.0.1:$secondPort" }) -eq 200)

        Check -Label "origin of the REQUESTED (unused) port is rejected" `
            -Ok ((Invoke-Status -Uri $base -Headers @{ 'x-bitflip-token' = 'tokentwo'; 'Origin' = "http://127.0.0.1:$Port" }) -eq 403)

        Check -Label "the first server's token is not valid on the second" `
            -Ok ((Invoke-Status -Uri $base -Headers @{ 'x-bitflip-token' = 'tokenone' }) -eq 403)

        Check -Label "no token is still rejected on the fallback port" `
            -Ok ((Invoke-Status -Uri $base) -eq 403)

        Check -Label "SPA is served on the fallback port without a token" `
            -Ok ((Invoke-Status -Uri "http://127.0.0.1:$secondPort/") -eq 200)

        # The banner must print the port it actually got.
        $secondOut = [string](Get-Content -LiteralPath (Join-Path $logDir 'second.out.log') -Raw -ErrorAction SilentlyContinue)
        Check -Label "banner reports the actual port" -Ok ($secondOut -match "127\.0\.0\.1:$secondPort") -Detail "port $secondPort"
    }
}
catch {
    $script:failures += 1
    Write-Host ("  FAIL  unexpected error: " + $_.Exception.Message) -ForegroundColor Red
}

foreach ($proc in @($second, $first)) {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Milliseconds 500
Get-Process bitflip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($script:failures -eq 0) {
    Write-Host "ALL CHECKS PASSED"
    exit 0
}
Write-Host ("{0} CHECK(S) FAILED" -f $script:failures) -ForegroundColor Red
exit 1
