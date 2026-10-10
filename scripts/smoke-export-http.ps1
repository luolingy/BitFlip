# Verifies GET /api/export against a REAL server process.
#
# Why a live-server test instead of only unit tests: the HTTP path is where the
# metadata can silently disappear. If the warnings and truncation flags do not
# survive serialization, the client sees a clean "200 OK" and believes the export
# is complete. Unit tests on the core function cannot catch that.
#
# Written in PowerShell rather than Node because this sandbox denies
# child_process.spawn from Node (EPERM), while Start-Process works.
#
# Usage:
#   & .\scripts\smoke-export-http.ps1

[CmdletBinding()]
param(
    [string]$Bin = '.cargo-target/debug/bitflip-cli.exe',
    [string]$Target = 'tests/fixtures/generated/m3-mingw-static.exe',
    [string]$ArmTarget = 'tests/fixtures/generated/elf-aarch64.exe',
    [int]$Port = 8797
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
$script:checks = 0

function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $script:checks += 1
    if ($Ok) {
        Write-Host ("  PASS  " + $Label + $(if ($Detail) { " -- $Detail" } else { '' }))
    }
    else {
        $script:failures += 1
        Write-Host ("  FAIL  " + $Label + $(if ($Detail) { " -- $Detail" } else { '' })) -ForegroundColor Red
    }
}

function Start-Bitflip {
    param([int]$RequestedPort, [string]$Token, [string]$TargetFile, [string]$Tag)

    $out = Join-Path $logDir "$Tag.out.log"
    $err = Join-Path $logDir "$Tag.err.log"
    $arguments = @('serve', $TargetFile, '--no-open', '--port', "$RequestedPort", '--token', $Token)

    return Start-Process -FilePath $binPath -ArgumentList $arguments -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
}

function Wait-ForPort {
    param([string]$Tag, [int]$TimeoutSeconds = 30)

    $out = Join-Path $logDir "$Tag.out.log"
    for ($i = 0; $i -lt ($TimeoutSeconds * 5); $i++) {
        if (Test-Path -LiteralPath $out) {
            # -Raw returns $null for an empty file; coerce to '' before regex.
            $text = [string](Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
            $match = [regex]::Match($text, 'http://127\.0\.0\.1:(\d+)/#token=')
            if ($match.Success) { return [int]$match.Groups[1].Value }
        }
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

# Returns @{ Status = <int>; Body = <string>; Headers = <hashtable> }
#
# Uses HttpWebRequest rather than Invoke-WebRequest on purpose: this PowerShell /
# .NET combination hands back an EMPTY body for non-2xx responses through
# Invoke-WebRequest's catch path, even though the server did send one. Error
# bodies are exactly what these checks are about ("does the 400 explain itself?"),
# so reading them reliably matters more than brevity.
function Invoke-Export {
    param([string]$Uri, [string]$Token)

    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Headers.Add('x-bitflip-token', $Token)
    $request.Method = 'GET'
    $request.Timeout = 60000

    try {
        $response = $request.GetResponse()
    }
    catch [System.Net.WebException] {
        if (-not $_.Exception.Response) {
            return @{ Status = 0; Body = ''; Headers = @{} }
        }
        $response = $_.Exception.Response
    }

    $status = [int]$response.StatusCode
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
    $body = $reader.ReadToEnd()
    $reader.Close()

    $headers = @{}
    foreach ($key in $response.Headers.AllKeys) {
        $headers[$key.ToLowerInvariant()] = $response.Headers[$key]
    }
    $response.Close()

    return @{ Status = $status; Body = $body; Headers = $headers }
}

Write-Host "BitFlip export HTTP smoke test"
Write-Host ("  binary: " + $binPath)
Write-Host ("  target: " + $Target)
Write-Host ""

Get-Process bitflip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$server = $null
$armServer = $null

# Cleanup happens AFTER the checks: a finally block here would kill the server
# before a single assertion ran, and the test would pass against a dead port.
try {
    $server = Start-Bitflip -RequestedPort $Port -Token 'tokexport' -TargetFile $Target -Tag 'export'
    $port = Wait-ForPort -Tag 'export'
    Check -Label "server started" -Ok ($port -gt 0) -Detail "port $port"

    if ($port -gt 0) {
        $base = "http://127.0.0.1:$port/api/export"

        # NOTE: always write ${base} with braces, never $base.  PowerShell treats
        # '?' as a legal variable-name character, so "$base?format=..." silently
        # expands a variable named `base?` and yields "=asm-intel&..." -- a
        # UriFormatException, i.e. status 0 with no clue why.  That typo cost one
        # debug round here; the braces are not cosmetic.

        # --- 1. Intel disassembly: text body plus honest metadata headers ---
        # `limit` is deliberately large here: with a small budget the export is
        # truncated, and this first check is about the metadata contract, not
        # about truncation (which gets its own check with a tiny budget below).
        $asm = Invoke-Export -Uri "${base}?format=asm-intel&limit=1000000" -Token 'tokexport'
        Check -Label "asm-intel returns 200" -Ok ($asm.Status -eq 200) -Detail "status $($asm.Status)"
        Check -Label "asm-intel body is the exported bytes" `
            -Ok ($asm.Body.StartsWith("# bitflip-export v1 format=asm-intel"))
        Check -Label "asm-intel content-type is text/plain" `
            -Ok ($asm.Headers['content-type'] -like 'text/plain*') -Detail $asm.Headers['content-type']
        Check -Label "format echoed in a header" `
            -Ok ($asm.Headers['x-bitflip-format'] -eq 'asm-intel')
        Check -Label "export format version advertised" `
            -Ok ($asm.Headers['x-bitflip-export-format-version'] -eq '1')
        Check -Label "a complete export is not flagged as truncated" `
            -Ok ($asm.Headers['x-bitflip-truncated'] -eq 'false') -Detail $asm.Headers['x-bitflip-truncated']
        Check -Label "item count is reported" `
            -Ok ([int]$asm.Headers['x-bitflip-items'] -gt 0) -Detail $asm.Headers['x-bitflip-items']

        # --- 1b. A tiny budget MUST surface as truncation, not as a short answer ---
        $cut = Invoke-Export -Uri "${base}?format=asm-intel&limit=20000" -Token 'tokexport'
        Check -Label "a tiny budget still returns the partial content" `
            -Ok (($cut.Status -eq 200) -and ($cut.Body.Length -le 20000))
        Check -Label "truncation is flagged, not silent" `
            -Ok ($cut.Headers['x-bitflip-truncated'] -eq 'true') -Detail $cut.Headers['x-bitflip-truncated']
        Check -Label "a warning header explains the truncation" `
            -Ok ([bool]$cut.Headers['x-bitflip-warning-1'])
        Check -Label "the truncated body ends on a line boundary" `
            -Ok ($cut.Body.EndsWith("`n"))

        # --- 2. AT&T on x86: real sigils, and the same truncation honesty ---
        $att = Invoke-Export -Uri "${base}?format=asm-att&limit=1000000" -Token 'tokexport'
        Check -Label "asm-att returns 200" -Ok ($att.Status -eq 200) -Detail "status $($att.Status)"
        Check -Label "asm-att body carries AT&T sigils" `
            -Ok (($att.Body -match '%') -and ($att.Body -match '\$') -and ($att.Body -notmatch 'qword ptr'))

        # --- 3. JSON formats must parse, and their totals must match the data ---
        foreach ($spec in @(
                @{ Format = 'json-functions'; Array = 'functions' },
                @{ Format = 'json-symbols'; Array = 'imports' },
                @{ Format = 'json-xrefs'; Array = 'xrefs' },
                @{ Format = 'dot-cfg'; Array = '' })) {

            $result = Invoke-Export -Uri "${base}?format=$($spec.Format)&limit=4000000" -Token 'tokexport'
            Check -Label "$($spec.Format) returns 200" -Ok ($result.Status -eq 200) -Detail "status $($result.Status)"

            if ($spec.Format -eq 'dot-cfg') {
                Check -Label "dot-cfg is a balanced digraph" `
                    -Ok (($result.Body -match 'digraph bitflip \{') -and `
                        (([regex]::Matches($result.Body, '\{')).Count -eq ([regex]::Matches($result.Body, '\}')).Count))
                continue
            }

            $parsed = $null
            try { $parsed = $result.Body | ConvertFrom-Json } catch { $parsed = $null }
            Check -Label "$($spec.Format) body is valid JSON" -Ok ($null -ne $parsed)
            if ($null -eq $parsed) { continue }
            Check -Label "$($spec.Format) carries format_version" -Ok ($parsed.format_version -eq 1)
            Check -Label "$($spec.Format) carries a producer string" `
                -Ok ($parsed.producer -like 'bitflip *') -Detail $parsed.producer

            $count = @($parsed.$($spec.Array)).Count
            Check -Label "$($spec.Format) has data" -Ok ($count -gt 0) -Detail "$count items"
            if ($spec.Format -ne 'json-symbols') {
                Check -Label "$($spec.Format) totals match the data" `
                    -Ok (@($parsed.$($spec.Array)).Count -eq [int]$parsed.totals.written `
                        -or @($parsed.$($spec.Array)).Count -eq [int]$parsed.totals.xrefs)
            }
        }

        # --- 4. Address range narrows the result ---
        $ranged = Invoke-Export -Uri "${base}?format=json-xrefs&from=0x140001000&to=0x140001100" -Token 'tokexport'
        $full = Invoke-Export -Uri "${base}?format=json-xrefs" -Token 'tokexport'
        $rangedCount = 0
        $fullCount = 0
        try { $rangedCount = @(($ranged.Body | ConvertFrom-Json).xrefs).Count } catch { $rangedCount = -1 }
        try { $fullCount = @(($full.Body | ConvertFrom-Json).xrefs).Count } catch { $fullCount = -1 }
        Check -Label "address range actually narrows the export" `
            -Ok ($rangedCount -ge 0 -and $rangedCount -lt $fullCount) -Detail "$rangedCount < $fullCount"

        # --- 5. Bad input is rejected with a usable message, not a 500 ---
        $bad = Invoke-Export -Uri "${base}?format=nope" -Token 'tokexport'
        Check -Label "unknown format is a 400" -Ok ($bad.Status -eq 400) -Detail "status $($bad.Status)"
        Check -Label "unknown format lists the valid values" -Ok ($bad.Body -match 'asm-intel')

        # A misspelled parameter must NOT be silently ignored: serde_urlencoded
        # drops unknown fields by default, which would have handed back a
        # full-size export for `limit-bytes=1000` with a cheerful 200.
        $typo = Invoke-Export -Uri "${base}?format=asm-intel&limit-bytes=1000" -Token 'tokexport'
        Check -Label "a misspelled parameter is rejected, not ignored" `
            -Ok ($typo.Status -eq 400) -Detail "status $($typo.Status)"
        Check -Label "the rejection lists the available parameters" `
            -Ok ($typo.Body -match 'limit')

        $conflict = Invoke-Export -Uri "${base}?function=0x140001000&from=0x140001000" -Token 'tokexport'
        Check -Label "function+range conflict is a 400" -Ok ($conflict.Status -eq 400) -Detail "status $($conflict.Status)"

        $backwards = Invoke-Export -Uri "${base}?from=0x140002000&to=0x140001000" -Token 'tokexport'
        Check -Label "reversed range is a 400" -Ok ($backwards.Status -eq 400) -Detail "status $($backwards.Status)"

        $tiny = Invoke-Export -Uri "${base}?format=json-functions&limit=500" -Token 'tokexport'
        Check -Label "over-budget JSON is a 400, not a half document" `
            -Ok ($tiny.Status -eq 400) -Detail "status $($tiny.Status)"
        Check -Label "over-budget message carries the numbers" -Ok ($tiny.Body -match '500')
    }

    # --- 6. Capability gap: AT&T on a non-x86 target is "not implemented" ---
    $armServer = Start-Bitflip -RequestedPort ($Port + 1) -Token 'tokarm' -TargetFile $ArmTarget -Tag 'export-arm'
    $armPort = Wait-ForPort -Tag 'export-arm'
    Check -Label "arm server started" -Ok ($armPort -gt 0) -Detail "port $armPort"

    if ($armPort -gt 0) {
        $armBase = "http://127.0.0.1:$armPort/api/export"
        $armAtt = Invoke-Export -Uri "${armBase}?format=asm-att" -Token 'tokarm'
        Check -Label "AT&T on aarch64 is 501 (not implemented), not a silent fallback" `
            -Ok ($armAtt.Status -eq 501) -Detail "status $($armAtt.Status)"
        Check -Label "the 501 message names the milestone and the alternative" `
            -Ok (($armAtt.Body -match 'M9') -and ($armAtt.Body -match 'asm-intel'))

        $armIntel = Invoke-Export -Uri "${armBase}?format=asm-intel" -Token 'tokarm'
        Check -Label "the same target exports Intel fine (so the 501 is about AT&T)" `
            -Ok ($armIntel.Status -eq 200) -Detail "status $($armIntel.Status)"
    }
}
catch {
    $script:failures += 1
    Write-Host ("  FAIL  unexpected error: " + $_.Exception.Message) -ForegroundColor Red
}

foreach ($proc in @($armServer, $server)) {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Milliseconds 500
Get-Process bitflip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("checks: " + $script:checks)
if ($script:failures -eq 0) {
    Write-Host "ALL CHECKS PASSED"
    exit 0
}
Write-Host ("{0} CHECK(S) FAILED" -f $script:failures) -ForegroundColor Red
exit 1
