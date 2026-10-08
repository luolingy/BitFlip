# BitFlip script-console smoke test (M7).
#
# Starts a real server on a real target and drives the script endpoints over
# HTTP: run, observe, cancel. This is the only place where the whole stack
# (SPA bundle -> HTTP -> script engine -> core analysis -> project store) is
# exercised end to end.
#
# Why PowerShell and not Node: this sandbox denies child_process.spawn from
# Node (EPERM), so a Node script cannot start the server (see CLAUDE.md 6.6).
#
# Why .NET HttpClient instead of Invoke-RestMethod: the server answers JSON
# with `Content-Type: application/json` and no charset, which is correct for
# JSON (RFC 8259 says JSON is always UTF-8). Windows PowerShell 5.1 has no
# way to know that and falls back to ISO-8859-1, so every CJK character comes
# back mojibake -- and posting that mojibake back would corrupt the script
# source. HttpClient with explicit UTF-8 on both legs sidesteps the issue
# entirely. (Browsers always decode JSON as UTF-8, so the UI is unaffected.)
#
# This file must stay ASCII-only: Windows PowerShell 5.1 reads non-BOM
# scripts as ANSI, which breaks parsing (see CLAUDE.md 6.1).
#
# Usage:
#   & .\scripts\smoke-script-console.ps1

[CmdletBinding()]
param(
    [string]$Bin = '.cargo-target/release/bitflip-cli.exe',
    [string]$Target = 'tests/fixtures/generated/m3-mingw-static.unstripped.exe',
    [int]$Port = 8797
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$binPath = Join-Path $repoRoot $Bin
$targetPath = Join-Path $repoRoot $Target
$logDir = Join-Path $repoRoot '.smoke-logs'
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $binPath)) {
    Write-Host "binary not found: $binPath" -ForegroundColor Red
    Write-Host "build it first:  & .\scripts\cargo.ps1 build --release -p bitflip-cli"
    exit 1
}
if (-not (Test-Path -LiteralPath $targetPath)) {
    Write-Host "target not found: $targetPath" -ForegroundColor Red
    Write-Host "generate fixtures first:  & .\scripts\gen-fixtures.ps1"
    exit 1
}

$script:failures = 0
$script:checks = 0

function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $script:checks += 1
    $suffix = if ($Detail) { " -- $Detail" } else { '' }
    if ($Ok) {
        Write-Host ("  PASS  " + $Label + $suffix)
    }
    else {
        $script:failures += 1
        Write-Host ("  FAIL  " + $Label + $suffix) -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# HTTP client (UTF-8 on both legs)
# ---------------------------------------------------------------------------

Add-Type -AssemblyName System.Net.Http
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromSeconds(120)

function Start-Client {
    param([string]$Token)
    $client.DefaultRequestHeaders.Remove('x-bitflip-token') | Out-Null
    $client.DefaultRequestHeaders.Add('x-bitflip-token', $Token)
}

function Read-Utf8 {
    param($Response)
    $bytes = $Response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Get-Text {
    param([string]$Uri)
    $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
    return @{ Status = [int]$response.StatusCode; Text = (Read-Utf8 $response) }
}

function Get-Json {
    param([string]$Uri)
    $result = Get-Text $Uri
    $body = $null
    if ($result.Text) { $body = $result.Text | ConvertFrom-Json }
    return @{ Status = $result.Status; Body = $body }
}

function Post-Json {
    param([string]$Uri, $Payload)
    # ConvertTo-Json escapes non-ASCII as \uXXXX, which is valid JSON and
    # round-trips exactly -- no ANSI/UTF-8 guessing involved.
    $json = if ($null -eq $Payload) { 'null' } else { $Payload | ConvertTo-Json -Compress -Depth 8 }
    $content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, 'application/json')
    $response = $client.PostAsync($Uri, $content).GetAwaiter().GetResult()
    $text = Read-Utf8 $response
    $body = $null
    if ($text) { $body = $text | ConvertFrom-Json }
    return @{ Status = [int]$response.StatusCode; Body = $body }
}

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

function Wait-ForPort {
    param([string]$Tag, [int]$TimeoutSeconds = 60)
    $out = Join-Path $logDir "$Tag.out.log"
    for ($i = 0; $i -lt ($TimeoutSeconds * 5); $i++) {
        if (Test-Path -LiteralPath $out) {
            # -Raw returns $null for an empty file and [regex]::Match rejects
            # $null with an ArgumentNullException -- coerce to '' first.
            $text = [string](Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)
            $match = [regex]::Match($text, 'http://127\.0\.0\.1:(\d+)/#token=')
            if ($match.Success) { return [int]$match.Groups[1].Value }
        }
        $errLog = Join-Path $logDir "$Tag.err.log"
        if (Test-Path -LiteralPath $errLog) {
            $errText = [string](Get-Content -LiteralPath $errLog -Raw -ErrorAction SilentlyContinue)
            if ($errText -match 'error:|panic') {
                Write-Host ("  " + $Tag + " failed to start:")
                ($errText -split "`n" | Select-Object -First 4) | ForEach-Object { Write-Host ("       " + $_) }
                return 0
            }
        }
        Start-Sleep -Milliseconds 200
    }
    return 0
}

<#
    Poll /api/script/status until the run settles.

    Returns the last status seen (or $null when nothing came back). A script
    that never finishes must fail the check rather than hang the test, so the
    loop is bounded.
#>
function Wait-ForDone {
    param([string]$Base, [int]$Tries = 400)
    $last = $null
    for ($i = 0; $i -lt $Tries; $i++) {
        $result = Get-Json "$Base/api/script/status"
        if ($result.Status -ne 200) { return $null }
        $last = $result.Body
        if ($last.state -eq 'done') { return $last }
        Start-Sleep -Milliseconds 250
    }
    return $last
}

function Wait-ForState {
    param([string]$Base, [string]$Wanted, [int]$Tries = 200)
    for ($i = 0; $i -lt $Tries; $i++) {
        $result = Get-Json "$Base/api/script/status"
        if ($result.Status -eq 200 -and $result.Body.state -eq $Wanted) { return $result.Body }
        Start-Sleep -Milliseconds 100
    }
    return $null
}

function Join-Logs {
    param($Status)
    $parts = @()
    foreach ($log in $Status.logs) { $parts += [string]$log.message }
    return ($parts -join "`n")
}

# ---------------------------------------------------------------------------
# Test target: a COPY, so the smoke run never writes a .bitflip store into
# tests/fixtures/generated (the script writes annotations, and annotations
# live next to the target).
# ---------------------------------------------------------------------------

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bitflip-script-smoke-" + $PID)
if (Test-Path -LiteralPath $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force }
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$workTarget = Join-Path $workDir 'target.exe'
Copy-Item -LiteralPath $targetPath -Destination $workTarget -Force

Write-Host "BitFlip script console smoke test"
Write-Host ("  binary: " + $binPath)
Write-Host ("  target: " + $Target + " (copied)")
Write-Host ""

Get-Process bitflip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$token = 'scriptsmoketoken'
$proc = $null

# NOTE: cleanup runs AFTER all checks. Putting it in a finally block would tear
# the server down before the first check, and the test would then "pass"
# against a dead port (CLAUDE.md 6.9).
try {
    $proc = Start-Process -FilePath $binPath `
        -ArgumentList @('serve', $workTarget, '--no-open', '--port', "$Port", '--token', $token) `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput (Join-Path $logDir 'script.out.log') `
        -RedirectStandardError (Join-Path $logDir 'script.err.log') `
        -NoNewWindow -PassThru

    $actualPort = Wait-ForPort -Tag 'script'
    Check -Label "server starts and prints its URL" -Ok ($actualPort -gt 0) -Detail "port $actualPort"

    $base = "http://127.0.0.1:$actualPort"

    if ($actualPort -gt 0) {
        Start-Client -Token $token

        # -- token gate --
        Start-Client -Token ''
        $noToken = Post-Json "$base/api/script/run" @{ source = "1+1;" }
        Check -Label "run without a token is rejected" -Ok ($noToken.Status -eq 403) -Detail "HTTP $($noToken.Status)"
        Start-Client -Token $token

        # -- script library --
        $library = Get-Json "$base/api/script/library"
        Check -Label "library answers 200" -Ok ($library.Status -eq 200)
        $ids = @()
        if ($library.Body) { $ids = @($library.Body.scripts | ForEach-Object { $_.id }) }
        foreach ($expected in @('memcpy-args', 'rename-by-string', 'export-functions', 'library-patterns')) {
            Check -Label "library ships $expected" -Ok ($ids -contains $expected) -Detail ($ids -join ',')
        }
        $apiVersion = 0
        if ($library.Body) { $apiVersion = [int]$library.Body.api_version }
        Check -Label "library reports the script API version" -Ok ($apiVersion -ge 1) -Detail "v$apiVersion"

        # -- the shipped SPA actually contains the console --
        $bundle = Get-Text "$base/assets/app.js"
        Check -Label "SPA bundle is served" -Ok ($bundle.Status -eq 200)
        Check -Label "SPA bundle contains the script console" `
            -Ok ($bundle.Text -match 'bitflip\.script\.library\.v1')

        # M8 deliverable 4: the alias/conflict marker must be inside the EMBEDDED bundle.
        # Checking the source is not enough -- the bundle is what users see, and a stale
        # bundle is the realistic failure here. The class name only exists in the new build.
        Check -Label "SPA bundle contains the alias/conflict marker" `
            -Ok ($bundle.Text -match 'chip-conflict')

        # M8: every function row must carry an aliases array (empty is fine, missing is not),
        # and the builtin-pattern accounting must reach the notes the UI shows.
        $functions = Get-Json "$base/api/functions?offset=0&count=200"
        Check -Label "functions answers 200" -Ok ($functions.Status -eq 200) -Detail "HTTP $($functions.Status)"
        $rows = @()
        if ($functions.Body) { $rows = @($functions.Body.functions) }
        Check -Label "functions returns rows" -Ok ($rows.Count -gt 0) -Detail "$($rows.Count) row(s)"
        $missing = @($rows | Where-Object { $null -eq $_.aliases }).Count
        Check -Label "every function row carries an aliases array" -Ok ($missing -eq 0) -Detail "missing=$missing"
        $notes = @()
        if ($functions.Body) { $notes = @($functions.Body.notes) }
        $builtin = @($notes | Where-Object { $_ -match '___chkstk_ms' }).Count
        Check -Label "notes carry the builtin pattern accounting" -Ok ($builtin -ge 1) -Detail "$builtin line(s)"

        # -- acceptance 1 through HTTP, using the SHIPPED source --
        $memcpySource = [string](($library.Body.scripts | Where-Object { $_.id -eq 'memcpy-args' }).source)
        Check -Label "memcpy script source came back" -Ok ($memcpySource.Length -gt 500) -Detail "$($memcpySource.Length) chars"

        $started = Post-Json "$base/api/script/run" @{ source = $memcpySource }
        Check -Label "run accepts the request immediately" -Ok ($started.Status -eq 202) -Detail "HTTP $($started.Status)"
        Check -Label "run reports warming or running, not a final state" `
            -Ok ($started.Body.state -eq 'warming' -or $started.Body.state -eq 'running') `
            -Detail "state=$($started.Body.state)"

        $memcpy = Wait-ForDone -Base $base
        Check -Label "acceptance 1: the shipped memcpy script completes" -Ok ($null -ne $memcpy -and $memcpy.state -eq 'done')
        if ($null -ne $memcpy -and $memcpy.state -eq 'done') {
            Check -Label "acceptance 1: no error" -Ok ($null -eq $memcpy.error) -Detail ([string]$memcpy.error.kind)

            $logText = Join-Logs $memcpy
            $entry = ''
            if ($memcpy.logs.Count -gt 0) { $entry = [string]$memcpy.logs[0].message }
            Check -Label "acceptance 1: found memcpy at the recorded address" `
                -Ok ($entry -eq 'memcpy@0000000140009218') -Detail $entry

            $annotated = 0
            if ($memcpy.logs.Count -gt 1) {
                $match = [regex]::Match([string]$memcpy.logs[1].message, '^annotated=(\d+)$')
                if ($match.Success) { $annotated = [int]$match.Groups[1].Value }
            }
            Check -Label "acceptance 1: every call site was annotated" -Ok ($annotated -gt 0) -Detail "annotated=$annotated"
            Check -Label "acceptance 1: commit count matches what the script reported" `
                -Ok ($null -ne $memcpy.committed -and [int]$memcpy.committed -eq $annotated) `
                -Detail "committed=$($memcpy.committed)"

            # The annotations must be readable back over HTTP: the script has to
            # write into the SAME store the UI reads, not a private copy.
            #
            # Get-Text, not Get-Json, on purpose: the assertion is on the raw
            # body. A mistyped property on a PSCustomObject evaluates to $null
            # without error, so `$x.Text` on a Get-Json result would make this
            # check pass no matter what the server did.
            $annotations = Get-Text "$base/api/annotations?from=0000000140000000&to=0000000140010000"
            Check -Label "acceptance 1: annotations are readable back over HTTP" `
                -Ok ($annotations.Status -eq 200 -and $annotations.Text -match 'memcpy\(dst, src, n\)') `
                -Detail "HTTP $($annotations.Status)"
        }

        # -- the library's own scripts run on a real target --
        $exportSource = [string](($library.Body.scripts | Where-Object { $_.id -eq 'export-functions' }).source)
        $null = Post-Json "$base/api/script/run" @{ source = $exportSource }
        $export = Wait-ForDone -Base $base
        Check -Label "library script export-functions completes" `
            -Ok ($null -ne $export -and $export.state -eq 'done' -and $null -eq $export.error)
        $exportText = ''
        if ($null -ne $export) { $exportText = Join-Logs $export }
        # Tab-separated output is what the console renders as its result table.
        Check -Label "export-functions emits tab-separated rows" -Ok ($exportText -match "`t")

        # -- script-declared tables reach the UI (custom view data sources) --
        # @() around the property: PS 5.1 gives no .Count on a single object, so
        # an unwrapped one-table result would make these checks pass vacuously.
        $exportTables = @($export.tables)
        Check -Label "export-functions publishes one declared table" `
            -Ok ($exportTables.Count -eq 1 -and $exportTables[0].row_count -gt 0) `
            -Detail "tables=$($exportTables.Count)"
        Check -Label "the declared table reports its column kinds" `
            -Ok ($exportTables.Count -eq 1 -and $exportTables[0].columns[0].kind -eq 'address') `
            -Detail "kind=$($exportTables[0].columns[0].kind)"
        Check -Label "the status summary carries no table data rows" `
            -Ok ($exportTables.Count -eq 1 -and $null -eq $exportTables[0].rows)

        # ASCII table name on purpose: this script must stay ASCII-only (PS 5.1
        # reads a BOM-less .ps1 as ANSI), so the endpoint checks use their own run.
        $tableSource = "bitflip.table('SMOKE-TABLE', " +
            "[{name: 'addr', type: 'address'}, {name: 'n', type: 'number'}, " +
            "{name: 'ok', type: 'bool'}, {name: 'note'}], " +
            "[['0000000140009218', 3, true, 'x'], [null, 0, false, 'y']], " +
            "{description: 'smoke'}); bitflip.log('TABLE-OK');"
        $null = Post-Json "$base/api/script/run" @{ source = $tableSource }
        $tableRun = Wait-ForDone -Base $base
        $tableText = ''
        if ($null -ne $tableRun) { $tableText = Join-Logs $tableRun }
        Check -Label "a script can publish a table" -Ok ($tableText -match 'TABLE-OK') `
            -Detail ("state=" + [string]$tableRun.state + " err=" + [string]$tableRun.error.kind)

        $tablePage = Get-Json "$base/api/script/table?name=SMOKE-TABLE"
        $rows = @($tablePage.Body.rows)
        Check -Label "the table data comes back from its own endpoint" `
            -Ok ($tablePage.Status -eq 200 -and $rows.Count -eq 2 -and $tablePage.Body.total -eq 2) `
            -Detail "HTTP $($tablePage.Status) rows=$($rows.Count)"
        # The address must travel as fixed-width hex text: a JSON number would
        # reach the UI as 140009218 and stop being an address.
        Check -Label "address cells travel as 16-hex strings, not numbers" `
            -Ok ($rows.Count -eq 2 -and $rows[0][0] -eq '0000000140009218') `
            -Detail ("first=" + [string]$rows[0][0])
        Check -Label "an empty cell stays empty instead of becoming 0 or ''" `
            -Ok ($rows.Count -eq 2 -and $null -eq $rows[1][0])

        $missing = Get-Json "$base/api/script/table?name=NOPE"
        Check -Label "asking for a table that does not exist is a 404, not an empty table" `
            -Ok ($missing.Status -eq 404 -and $missing.Body.error -match 'SMOKE-TABLE') `
            -Detail "HTTP $($missing.Status)"
        $noName = Get-Json "$base/api/script/table"
        Check -Label "asking for a table without a name is refused" `
            -Ok ($noName.Status -eq 400) -Detail "HTTP $($noName.Status)"
        $tooBig = Get-Json "$base/api/script/table?name=SMOKE-TABLE&count=999999"
        Check -Label "an oversized page is refused instead of silently clamped" `
            -Ok ($tooBig.Status -eq 400) -Detail "HTTP $($tooBig.Status)"

        # A run that publishes nothing must not leave the previous table visible.
        $null = Post-Json "$base/api/script/run" @{ source = "bitflip.log('no table here');" }
        $noTableRun = Wait-ForDone -Base $base
        Check -Label "a run without tables clears the previous run's tables" `
            -Ok ($null -ne $noTableRun -and @($noTableRun.tables).Count -eq 0)
        $gone = Get-Json "$base/api/script/table?name=SMOKE-TABLE"
        Check -Label "the previous run's table is not served under the new run" `
            -Ok ($gone.Status -eq 404) -Detail "HTTP $($gone.Status)"

        # -- symbols come back through the live path too --
        $symbolSource = "const hit = bitflip.symbols.find('memcpy'); bitflip.log('SYM=' + hit.length); bitflip.log('SYMVAL=' + hit[0].value);"
        $null = Post-Json "$base/api/script/run" @{ source = $symbolSource }
        $symbolRun = Wait-ForDone -Base $base
        $symbolText = ''
        if ($null -ne $symbolRun) { $symbolText = Join-Logs $symbolRun }
        # A failed run produces no logs at all, so an empty detail would tell the
        # reader nothing -- fall back to the error kind.
        $symbolDetail = $symbolText -replace "`n", ' '
        if (-not $symbolDetail -and $null -ne $symbolRun) {
            $symbolDetail = 'error=' + [string]$symbolRun.error.kind
        }
        # The value must be the real virtual address: a PE COFF symbol's Value is
        # a section offset, and getting that wrong is a defect this project has
        # already shipped once.
        Check -Label "symbols are readable over the live path" `
            -Ok ($symbolText -match 'SYM=[1-9]' -and $symbolText -match 'SYMVAL=0000000140009218') `
            -Detail $symbolDetail

        # -- progress is observable while the script is still running --
        $progressSource = "bitflip.progress(3, 7, 'x'); while (true) { }"
        $null = Post-Json "$base/api/script/run" @{ source = $progressSource }
        $running = Wait-ForState -Base $base -Wanted 'running'
        Check -Label "a dead loop reaches the running state" -Ok ($null -ne $running)
        Check -Label "stop is offered while the script runs" `
            -Ok ($null -ne $running -and $running.can_cancel -eq $true)

        # -- cancel stops it, and the outcome is "cancelled" not "timeout" --
        $cancelled = Post-Json "$base/api/script/cancel" $null
        Check -Label "cancel request is accepted" -Ok ($cancelled.Status -eq 200 -and $cancelled.Body.ok -eq $true) `
            -Detail "HTTP $($cancelled.Status)"
        $deadLoop = Wait-ForDone -Base $base
        Check -Label "a dead loop can be interrupted" -Ok ($null -ne $deadLoop -and $deadLoop.state -eq 'done')
        if ($null -ne $deadLoop) {
            Check -Label "the user's stop is reported as cancelled, not as a timeout" `
                -Ok ([string]$deadLoop.error.kind -eq 'cancelled') -Detail ([string]$deadLoop.error.kind)
        }

        # -- cancel with nothing running is refused, not silently accepted --
        $nothing = Post-Json "$base/api/script/cancel" $null
        Check -Label "cancelling with nothing running is refused" `
            -Ok ($nothing.Status -eq 409 -and $nothing.Body.ok -eq $false) -Detail "HTTP $($nothing.Status)"

        # -- a failed script leaves no annotations behind --
        $half = "bitflip.setComment('0000000140001000', 'SHOULD-NOT-SURVIVE'); throw new Error('x');"
        $null = Post-Json "$base/api/script/run" @{ source = $half }
        $failed = Wait-ForDone -Base $base
        Check -Label "a throwing script reports a runtime error" `
            -Ok ($null -ne $failed -and [string]$failed.error.kind -eq 'runtime') -Detail ([string]$failed.error.kind)
        $afterFailure = Get-Text "$base/api/annotations?from=0000000140000000&to=0000000140010000"
        # Guard against a vacuous pass: if the request itself failed we would be
        # matching against an empty string, which "notmatch" would happily call
        # a success -- the exact bug this check previously had.
        Check -Label "a failed script leaves no half-written annotations" `
            -Ok ($afterFailure.Status -eq 200 -and $afterFailure.Text -notmatch 'SHOULD-NOT-SURVIVE') `
            -Detail "HTTP $($afterFailure.Status)"

        # -- the single slot really is single --
        $null = Post-Json "$base/api/script/run" @{ source = "while (true) { }" }
        $null = Wait-ForState -Base $base -Wanted 'running'
        $second = Post-Json "$base/api/script/run" @{ source = "bitflip.log('second');" }
        Check -Label "a second concurrent run is rejected with 409" -Ok ($second.Status -eq 409) -Detail "HTTP $($second.Status)"
        $null = Post-Json "$base/api/script/cancel" $null
        $null = Wait-ForDone -Base $base

        # -- recovery: the slot is not a one-shot lock --
        $again = Post-Json "$base/api/script/run" @{ source = "bitflip.log('AGAIN-OK');" }
        Check -Label "a new run is accepted after the previous one ended" -Ok ($again.Status -eq 202) -Detail "HTTP $($again.Status)"
        $recovered = Wait-ForDone -Base $base
        $recoveredText = ''
        if ($null -ne $recovered) { $recoveredText = Join-Logs $recovered }
        Check -Label "the follow-up run actually executed" -Ok ($recoveredText -match 'AGAIN-OK')

        # -- the SPA itself is up --
        $page = Get-Text "$base/"
        Check -Label "SPA is served without a token" -Ok ($page.Status -eq 200)
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
if (Test-Path -LiteralPath $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue }
if ($client) { $client.Dispose() }

Write-Host ""
Write-Host ("{0} check(s) run" -f $script:checks)
if ($script:failures -eq 0) {
    Write-Host "ALL CHECKS PASSED"
    exit 0
}
Write-Host ("{0} CHECK(S) FAILED" -f $script:failures) -ForegroundColor Red
exit 1
