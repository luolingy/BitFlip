# Verifies GET /api/diff against a REAL server process.
#
# Why a live-server test instead of only core unit tests: the HTTP surface is
# where the honesty of the diff can quietly disappear. Two things matter here
# that the core test cannot see:
#
#   1. The normalization method and BOTH measured image bases must survive JSON
#      serialization. Without them a client cannot re-check the report, and the
#      list of "every function changed" looks perfectly normal.
#   2. A misspelled or missing parameter must be a 400, not a silently ignored
#      field. serde_urlencoded drops unknown fields by default, so a typo would
#      hand back a full-size default report with a cheerful 200.
#
# Written in PowerShell rather than Node because this sandbox denies
# child_process.spawn from Node (EPERM), while Start-Process works.
#
# Usage:
#   & .\scripts\smoke-diff-http.ps1

[CmdletBinding()]
param(
    [string]$Bin = '.cargo-target/debug/bitflip-cli.exe',
    [string]$Old = 'tests/fixtures/generated/diff-pe-x86_64-v1.exe',
    [string]$New = 'tests/fixtures/generated/diff-pe-x86_64-v2.exe',
    [int]$Port = 8798
)

$ErrorActionPreference = 'Continue'

$repoRoot = Split-Path -Parent $PSScriptRoot
$binPath = Join-Path $repoRoot $Bin
$oldPath = Join-Path $repoRoot $Old
$newPath = Join-Path $repoRoot $New
$logDir = Join-Path $repoRoot '.smoke-logs'
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $binPath)) {
    Write-Host "binary not found: $binPath" -ForegroundColor Red
    Write-Host "build it first:  & .\scripts\cargo.ps1 build --workspace"
    exit 1
}
foreach ($needed in @($oldPath, $newPath)) {
    if (-not (Test-Path -LiteralPath $needed)) {
        Write-Host "fixture not found: $needed" -ForegroundColor Red
        Write-Host "generate it: python scripts/gen-diff-fixture.py --out tests/fixtures/generated/diff-pe-x86_64"
        exit 1
    }
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
# HttpWebRequest rather than Invoke-WebRequest: this PowerShell / .NET
# combination hands back an EMPTY body for non-2xx responses through
# Invoke-WebRequest, and error bodies are exactly what half of these checks are
# about ("does the 400 explain itself?").
function Invoke-Api {
    param([string]$Uri, [string]$Token)

    $request = [System.Net.HttpWebRequest]::Create($Uri)
    if ($Token) {
        $request.Headers.Add('x-bitflip-token', $Token)
    }
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

function Convert-ToJson {
    param([string]$Body)
    try { return $Body | ConvertFrom-Json } catch { return $null }
}

# Builds a CJK string from code points, at run time.
#
# Why not just write the Chinese text here: files under scripts/ must stay
# ASCII-only. PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so CJK bytes break
# parsing outright (see CLAUDE.md 6.1).
#
# Why bother at all instead of asserting on something ASCII: the user-facing
# messages ARE Chinese, and "does the error explain itself in plain words" is
# precisely the property being tested. Asserting on a proxy (status code, or an
# ASCII word that happens to appear) would let a message regress into gibberish
# while the check stayed green.
function Cjk {
    param([int[]]$Codes)
    $out = ''
    foreach ($code in $Codes) { $out += [char]$code }
    return $out
}

Write-Host "BitFlip diff HTTP smoke test"
Write-Host ("  binary: " + $binPath)
Write-Host ("  old:    " + $oldPath)
Write-Host ("  new:    " + $newPath)
Write-Host ""

Get-Process bitflip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

$server = $null
$against = [System.Uri]::EscapeDataString($newPath)

# Cleanup happens AFTER the checks: a finally block here would kill the server
# before a single assertion ran, and the test would pass against a dead port.
try {
    $server = Start-Bitflip -RequestedPort $Port -Token 'tokdiff' -TargetFile $oldPath -Tag 'diff'
    $port = Wait-ForPort -Tag 'diff'
    Check -Label "server started" -Ok ($port -gt 0) -Detail "port $port"

    if ($port -gt 0) {
        $base = "http://127.0.0.1:$port/api/diff"

        # NOTE: always write ${base} with braces, never $base.  PowerShell treats
        # '?' as a legal variable-name character, so "$base?against=..." silently
        # expands a variable named `base?` and yields "=..." -- a
        # UriFormatException, i.e. status 0 with no clue why.  That typo cost a
        # debug round on the export smoke test; the braces are not cosmetic.

        # --- 1. The honest header: which dimension was compared, and both bases ---
        $r = Invoke-Api -Uri "${base}?against=$against" -Token 'tokdiff'
        Check -Label "diff returns 200" -Ok ($r.Status -eq 200) -Detail "status $($r.Status)"

        $report = Convert-ToJson -Body $r.Body
        Check -Label "diff body is valid JSON" -Ok ($null -ne $report)
        if ($null -eq $report) {
            throw "diff body did not parse; cannot continue"
        }

        Check -Label "diff carries format_version 1" -Ok ($report.format_version -eq 1) `
            -Detail "$($report.format_version)"
        Check -Label "diff carries a producer string" `
            -Ok ($report.producer -like 'bitflip *') -Detail $report.producer
        Check -Label "normalization is rva (both bases are known)" `
            -Ok ($report.normalization.method -eq 'rva') -Detail $report.normalization.method
        Check -Label "v1 image base is reported" `
            -Ok ($report.v1_image_base -eq 0x140000000) -Detail "$($report.v1_image_base)"
        Check -Label "v2 image base is reported" `
            -Ok ($report.v2_image_base -eq 0x180000000) -Detail "$($report.v2_image_base)"
        Check -Label "the two bases really differ (so normalization matters)" `
            -Ok ($report.v1_image_base -ne $report.v2_image_base)

        # --- 2. The controlled differences, straight from the JSON contract ---
        Check -Label "one function removed" -Ok ($report.totals.removed -eq 1) `
            -Detail "removed=$($report.totals.removed)"
        Check -Label "one function added" -Ok ($report.totals.added -eq 1) `
            -Detail "added=$($report.totals.added)"
        Check -Label "one function changed" -Ok ($report.totals.changed -eq 1) `
            -Detail "changed=$($report.totals.changed)"
        Check -Label "two functions moved" -Ok ($report.totals.moved -eq 2) `
            -Detail "moved=$($report.totals.moved)"
        Check -Label "two functions unchanged" -Ok ($report.totals.unchanged -eq 2) `
            -Detail "unchanged=$($report.totals.unchanged)"
        Check -Label "the accounting is balanced" `
            -Ok ($report.entries.Count -eq ($report.totals.added + $report.totals.removed + `
                    $report.totals.changed + $report.totals.moved + $report.totals.unchanged)) `
            -Detail "$($report.entries.Count) entries"

        $byName = @{}
        foreach ($entry in $report.entries) { $byName[$entry.name] = $entry.kind }
        Check -Label "df_removed is reported as removed" -Ok ($byName['df_removed'] -eq 'removed') `
            -Detail "$($byName['df_removed'])"
        Check -Label "df_added is reported as added" -Ok ($byName['df_added'] -eq 'added') `
            -Detail "$($byName['df_added'])"
        Check -Label "df_stable stays unchanged (no false positive from the base shift)" `
            -Ok ($byName['df_stable'] -eq 'unchanged') -Detail "$($byName['df_stable'])"
        Check -Label "df_helper stays unchanged" -Ok ($byName['df_helper'] -eq 'unchanged') `
            -Detail "$($byName['df_helper'])"
        Check -Label "df_changed is reported as changed" -Ok ($byName['df_changed'] -eq 'changed') `
            -Detail "$($byName['df_changed'])"
        Check -Label "df_entry is reported as moved" -Ok ($byName['df_entry'] -eq 'moved') `
            -Detail "$($byName['df_entry'])"

        # Every entry has to say how it was matched, or the pairing is unfalsifiable.
        $withoutBasis = @($report.entries | Where-Object { -not $_.match_basis })
        Check -Label "every entry carries a match basis" -Ok ($withoutBasis.Count -eq 0) `
            -Detail "$($withoutBasis.Count) without"

        $placeholder = @($report.entries | Where-Object { $_.name -like 'func_*' -or $_.name -like 'sub_*' })
        Check -Label "no entry invents a placeholder name" -Ok ($placeholder.Count -eq 0) `
            -Detail "$($placeholder.Count) placeholders"

        # --- 3. Scope and filtering must not corrupt the accounting ---
        $all = Invoke-Api -Uri "${base}?against=$against&scope=all" -Token 'tokdiff'
        $allReport = Convert-ToJson -Body $all.Body
        Check -Label "scope=all returns 200" -Ok ($all.Status -eq 200) -Detail "status $($all.Status)"
        Check -Label "scope is echoed as all" -Ok ($allReport.scope -eq 'all') -Detail "$($allReport.scope)"
        Check -Label "scope=all sees at least as much as functions only" `
            -Ok ($allReport.entries.Count -ge $report.entries.Count) `
            -Detail "$($allReport.entries.Count) >= $($report.entries.Count)"

        $onlyAdded = Convert-ToJson -Body (Invoke-Api -Uri "${base}?against=$against&only=added" -Token 'tokdiff').Body
        $notAdded = @($onlyAdded.entries | Where-Object { $_.kind -ne 'added' })
        Check -Label "only=added returns added entries only" -Ok ($notAdded.Count -eq 0) `
            -Detail "$($notAdded.Count) other kinds"
        # Filtering must not touch "how much was compared": that number is the
        # denominator, and shrinking it to 1 would misrepresent the comparison.
        Check -Label "filtering does not pollute v1_total" `
            -Ok ($onlyAdded.v1_total -eq $report.v1_total) `
            -Detail "$($onlyAdded.v1_total) vs $($report.v1_total)"
        Check -Label "filtering keeps the real added count" `
            -Ok ($onlyAdded.totals.added -eq $report.totals.added)

        # --- 4. Truncation on the HTTP surface must be visible, never silent ---
        $cut = Convert-ToJson -Body (Invoke-Api -Uri "${base}?against=$against&scope=all&entries=1" -Token 'tokdiff').Body
        Check -Label "a 1-entry cap truncates" -Ok ($cut.truncated -eq $true)
        Check -Label "the dropped count is reported" -Ok ($cut.dropped -gt 0) -Detail "dropped=$($cut.dropped)"
        Check -Label "exactly one entry is listed" -Ok ($cut.entries.Count -eq 1) `
            -Detail "$($cut.entries.Count)"
        $cutNotes = ($cut.notes -join ' | ')
        $truncatedMarker = Cjk @(0x622A, 0x65AD)   # "truncated"
        Check -Label "the truncation is explained in notes" `
            -Ok ($cutNotes.Contains($truncatedMarker)) -Detail $cutNotes

        # --- 5. Bad input is rejected with a usable message, not a 500 ---
        $noAgainst = Invoke-Api -Uri "${base}" -Token 'tokdiff'
        Check -Label "a missing against is a 400" -Ok ($noAgainst.Status -eq 400) `
            -Detail "status $($noAgainst.Status)"
        Check -Label "the rejection lists the available parameters" `
            -Ok ($noAgainst.Body -match 'against')

        # A misspelled parameter must NOT be silently ignored: serde_urlencoded
        # drops unknown fields by default, which would hand back a full-size
        # report for `max-entries=1` with a cheerful 200.
        $typo = Invoke-Api -Uri "${base}?against=$against&max-entries=1" -Token 'tokdiff'
        Check -Label "a misspelled parameter is rejected, not ignored" `
            -Ok ($typo.Status -eq 400) -Detail "status $($typo.Status)"
        Check -Label "the rejection names the expected parameters" `
            -Ok ($typo.Body -match 'entries')

        $badScope = Invoke-Api -Uri "${base}?against=$against&scope=nope" -Token 'tokdiff'
        Check -Label "an unknown scope is a 400" -Ok ($badScope.Status -eq 400) `
            -Detail "status $($badScope.Status)"
        Check -Label "the scope rejection lists the valid values" `
            -Ok ($badScope.Body -match 'functions')

        $badOnly = Invoke-Api -Uri "${base}?against=$against&only=nope" -Token 'tokdiff'
        Check -Label "an unknown only is a 400" -Ok ($badOnly.Status -eq 400) `
            -Detail "status $($badOnly.Status)"
        Check -Label "the only rejection lists the valid values" `
            -Ok ($badOnly.Body -match 'added')

        # --- 6. `against` must be a readable regular file, said in plain words ---
        $missing = [System.Uri]::EscapeDataString((Join-Path $repoRoot 'no-such-file.exe'))
        $missingResult = Invoke-Api -Uri "${base}?against=$missing" -Token 'tokdiff'
        Check -Label "a missing against is a 400" -Ok ($missingResult.Status -eq 400) `
            -Detail "status $($missingResult.Status)"
        Check -Label "the missing-file message says it could not be read" `
            -Ok ($missingResult.Body -match 'no-such-file')

        $dirResult = Invoke-Api -Uri "${base}?against=$([System.Uri]::EscapeDataString($repoRoot))" -Token 'tokdiff'
        # The point of this check is that the user gets "it is not a regular
        # file", not a confusing "this target could not be parsed" -- pointing
        # at a directory must not masquerade as a format problem.
        $notRegularFile = Cjk @(0x4E0D, 0x662F, 0x5E38, 0x89C4, 0x6587, 0x4EF6)
        Check -Label "a directory against is rejected with the real reason" `
            -Ok (($dirResult.Status -eq 400) -and ($dirResult.Body.Contains($notRegularFile))) `
            -Detail "status $($dirResult.Status)"

        # --- 7. The endpoint is token-guarded like every other /api route ---
        $noToken = Invoke-Api -Uri "${base}?against=$against" -Token ''
        Check -Label "diff without a token is 403" -Ok ($noToken.Status -eq 403) `
            -Detail "status $($noToken.Status)"
    }
}
catch {
    $script:failures += 1
    Write-Host ("  FAIL  unexpected error: " + $_.Exception.Message) -ForegroundColor Red
}

foreach ($proc in @($server)) {
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
