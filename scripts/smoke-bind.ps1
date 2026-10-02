# Verifies the server really binds 127.0.0.1 and NOT 0.0.0.0 (or any other local IP).
#
# Why this test exists: "loopback-only bind" is a security claim in README/CLAUDE.md,
# and a claim like that must be checked against the listening socket, not just the
# default value in the CLI definition.
#
# Implementation note: Get-NetTCPConnection / Get-NetIPAddress are denied in this
# sandbox, so this uses System.Net.Sockets and .NET's own view of the local NICs.
#
# NOTE: keep this file ASCII-only (see CLAUDE.md section 6).
#
# Usage:
#   & .\scripts\smoke-bind.ps1
#   & .\scripts\smoke-bind.ps1 -Bin '.cargo-target/release/bitflip-cli.exe'

[CmdletBinding()]
param(
    [string]$Bin = '.cargo-target/debug/bitflip-cli.exe',
    [string]$Target = 'tests/fixtures/generated/pe-x86_64.exe',
    [int]$Port = 8790,
    [string]$Token = 'bindprobe'
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

function Test-TcpConnect {
    param([string]$Address, [int]$TestPort, [int]$TimeoutMs = 1500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Address, $TestPort)
        if ($task.Wait($TimeoutMs) -and $client.Connected) { return $true }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

# Enumerate non-loopback IPv4 addresses via .NET (sandbox-friendly).
$localIps = @()
try {
    $localIps = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
            -not [System.Net.IPAddress]::IsLoopback($_) } |
        ForEach-Object { $_.ToString() } |
        Select-Object -Unique
}
catch {
    Write-Host ("  note: could not enumerate NICs: " + $_.Exception.Message)
}

Write-Host "BitFlip bind-address smoke test"
Write-Host ("  binary: " + $binPath)
if ($localIps.Count -gt 0) {
    Write-Host ("  non-loopback IPv4: " + ($localIps -join ', '))
}
else {
    Write-Host "  non-loopback IPv4: (none enumerable)"
}
Write-Host ""

Get-Process bitflip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$out = Join-Path $logDir 'bind.out.log'
$err = Join-Path $logDir 'bind.err.log'
$proc = $null

try {
    $arguments = @('serve', $Target, '--no-open', '--port', "$Port", '--token', $Token)
    $proc = Start-Process -FilePath $binPath -ArgumentList $arguments -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru

    $ready = $false
    for ($i = 0; $i -lt 100; $i++) {
        if (Test-TcpConnect -Address '127.0.0.1' -TestPort $Port) { $ready = $true; break }
        Start-Sleep -Milliseconds 200
    }

    Check -Label "server accepts connections on 127.0.0.1" -Ok $ready
    if (-not $ready) {
        $errText = [string](Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue)
        Write-Host ("       stderr: " + ($errText -split "`n" | Select-Object -First 3))
    }

    Check -Label "server does NOT accept connections on 0.0.0.0 literal" `
        -Ok (-not (Test-TcpConnect -Address '0.0.0.0' -TestPort $Port -TimeoutMs 800))

    foreach ($ip in $localIps) {
        Check -Label ("server is NOT reachable on LAN address " + $ip) `
            -Ok (-not (Test-TcpConnect -Address $ip -TestPort $Port -TimeoutMs 1200))
    }

    # Sanity: the loopback endpoint really is our server (not some other listener).
    if ($ready) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/health?token=$Token" -UseBasicParsing -TimeoutSec 5
            Check -Label "loopback endpoint serves our health payload" -Ok ($response.StatusCode -eq 200) -Detail "status $($response.StatusCode)"
        }
        catch {
            Check -Label "loopback endpoint serves our health payload" -Ok $false -Detail $_.Exception.Message
        }
    }
}
catch {
    $script:failures += 1
    Write-Host ("  FAIL  unexpected error: " + $_.Exception.Message) -ForegroundColor Red
}

if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
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
