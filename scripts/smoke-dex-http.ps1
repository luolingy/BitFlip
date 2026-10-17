# Verifies the DEX endpoints (/api/dex/*) against a REAL server process and a
# REAL APK.
#
# Why a live-server test on top of the HTTP unit tests (crates/bitflip-server/
# tests/dex_api.rs): the unit tests run the router in-process with a synthetic
# 600-byte DEX. Three things only a real process with a real app package can
# show:
#
#   1. That a multi-DEX APK really does produce one entry per file, in
#      container order, with its own tolerance notes (the synthetic sample has
#      exactly one DEX and no notes at all).
#   2. That the class browser survives real obfuscated descriptors and that
#      paging totals line up with what the payload actually holds.
#   3. That the NEW UI really is embedded in the binary. The SPA is compiled
#      into the executable by rust-embed, so "the source has a DEX view" and
#      "the binary serves a DEX view" are different claims. A browser is not
#      needed to check the second one: fetch /assets/app.js and look for the
#      DEX strings.
#
# Written in PowerShell rather than Node because this sandbox denies
# child_process.spawn from Node (EPERM), while Start-Process works.
#
# Usage:
#   & .\scripts\smoke-dex-http.ps1
#   & .\scripts\smoke-dex-http.ps1 -Apk 'C:\path\to\app.apk' -Port 8796

[CmdletBinding()]
param(
    [string]$Bin = '.cargo-target/debug/bitflip-cli.exe',
    [string]$Apk = 'C:\Users\Administrator\Downloads\ah-app-release.apk',
    [int]$Port = 8796
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
    Write-Host "build it first:  & .\scripts\cargo.ps1 build -p bitflip-cli"
    exit 1
}
# A missing sample must FAIL, never skip: a skipped end-to-end check reports
# green while proving nothing (CLAUDE.md section 7).
if (-not (Test-Path -LiteralPath $Apk)) {
    Write-Host "APK not found: $Apk" -ForegroundColor Red
    Write-Host "pass one explicitly:  & .\scripts\smoke-dex-http.ps1 -Apk <path>"
    exit 1
}

$script:failures = 0
$script:checks = 0

function Check {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $script:checks += 1
    if ($Ok) {
        Write-Host ("  PASS  " + $Label + $(if ($Detail) { " -- " + $Detail } else { '' }))
    }
    else {
        $script:failures += 1
        Write-Host ("  FAIL  " + $Label + $(if ($Detail) { " -- " + $Detail } else { '' })) -ForegroundColor Red
    }
}

$script:token = ''

function Start-Bitflip {
    param([string]$Tag, [string]$TargetFile)

    $out = Join-Path $logDir "$Tag.out.log"
    $err = Join-Path $logDir "$Tag.err.log"
    $arguments = @('serve', $TargetFile, '--no-open', '--port', "$Port", '--token', $script:token)

    return Start-Process -FilePath $binPath -ArgumentList $arguments -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
}

function Wait-ForPort {
    param([string]$Tag, [int]$TimeoutSeconds = 60)

    $out = Join-Path $logDir "$Tag.out.log"
    for ($i = 0; $i -lt ($TimeoutSeconds * 5); $i++) {
        if (Test-Path -LiteralPath $out) {
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

# HttpWebRequest rather than Invoke-WebRequest: this combination hands back an
# EMPTY body for non-2xx responses, and error bodies are half of what these
# checks are about.
function Invoke-Api {
    param([string]$Uri, [string]$Token = '')

    $request = [System.Net.HttpWebRequest]::Create($Uri)
    if ($Token) {
        $request.Headers.Add('x-bitflip-token', $Token)
    }
    $request.Method = 'GET'
    # Parsing three real DEX files takes seconds on first touch; the cache in
    # the server makes later calls cheap.
    $request.Timeout = 180000

    try {
        $response = $request.GetResponse()
    }
    catch [System.Net.WebException] {
        if (-not $_.Exception.Response) {
            return @{ Status = 0; Body = '' }
        }
        $response = $_.Exception.Response
    }

    $status = [int]$response.StatusCode
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
    $body = $reader.ReadToEnd()
    $reader.Close()
    $response.Close()

    return @{ Status = $status; Body = $body }
}

function Invoke-ApiJson {
    param([string]$PathAndQuery, [string]$Token)

    $result = Invoke-Api -Uri ("http://127.0.0.1:$Port" + $PathAndQuery) -Token $Token
    $json = $null
    if ($result.Body) {
        try { $json = $result.Body | ConvertFrom-Json } catch { $json = $null }
    }
    return @{ Status = $result.Status; Body = $result.Body; Json = $json }
}

function Get-ErrorMessage {
    param($Payload)
    if ($Payload -and $Payload.Json -and $Payload.Json.error) { return [string]$Payload.Json.error }
    return ''
}

# Escape a value for a query string (smali identifiers contain ->, [, ]).
function Get-Escaped {
    param([string]$Value)
    return [System.Uri]::EscapeDataString($Value)
}

# ---------------------------------------------------------------- checks ----

$script:token = [guid]::NewGuid().ToString('N')
$process = Start-Bitflip -Tag 'dex-apk' -TargetFile $Apk
$actualPort = Wait-ForPort -Tag 'dex-apk'
if ($actualPort -eq 0) {
    Write-Host "server did not come up on port $Port" -ForegroundColor Red
    exit 1
}
Write-Host "server up on $actualPort (token $($script:token.Substring(0, 8))...)"

try {
    # ---- 1. inputs: one entry per DEX, in container order, with own notes
    $inputs = Invoke-ApiJson -PathAndQuery '/api/dex/inputs' -Token $script:token
    Check '/api/dex/inputs answers 200' ($inputs.Status -eq 200) "status=$($inputs.Status)"
    $names = @($inputs.Json.inputs | ForEach-Object { $_.name })
    Check 'three DEX files are listed in container order' `
        (($names.Count -eq 3) -and ($names[0] -eq 'classes.dex') -and ($names[1] -eq 'classes2.dex') -and ($names[2] -eq 'classes3.dex')) `
        ($names -join ', ')
    Check 'format_version is echoed' (($inputs.Json.format_version -eq 1) -and ($inputs.Json.server_api_version -eq 1)) `
        "format=$($inputs.Json.format_version) server=$($inputs.Json.server_api_version)"
    $first = $inputs.Json.inputs[0]
    Check 'every entry carries a role label' `
        ((@($inputs.Json.inputs | Where-Object { [string]$_.role -eq '' }).Count) -eq 0) `
        ((@($inputs.Json.inputs | ForEach-Object { "$($_.name)=$($_.role)" })) -join ' ')
    Check 'class counts look like a real app' ([int]$first.class_count -gt 1000) "classes=$($first.class_count)"
    Check 'method counts look like a real app' ([int]$first.method_count -gt 1000) "methods=$($first.method_count)"
    Check 'methods with code are a subset' ([int]$first.method_count_with_code -le [int]$first.method_count) `
        "with_code=$($first.method_count_with_code)"
    $noteText = (@($first.notes) -join ' | ')
    Check 'tolerance notes travel with their own file' ($noteText -match 'OutOfOrder') $noteText

    $tabLine = (@($inputs.Json.inputs | ForEach-Object { "$($_.name):$($_.class_count)" }) -join ' ')
    Write-Host "  info  per-file classes: $tabLine"

    # ---- 2. classes: paging + filter totals
    $classes = Invoke-ApiJson -PathAndQuery '/api/dex/classes?member=classes.dex&limit=3' -Token $script:token
    Check '/api/dex/classes answers 200' ($classes.Status -eq 200) "status=$($classes.Status)"
    Check 'the page honours limit' (@($classes.Json.classes).Count -eq 3) "count=$(@($classes.Json.classes).Count)"
    Check 'total counts every class, not the page' ([int]$classes.Json.total -gt 1000) "total=$($classes.Json.total)"
    $descriptor = [string]$classes.Json.classes[0].descriptor
    Check 'class descriptors use smali syntax' (($descriptor.StartsWith('L')) -and ($descriptor.EndsWith(';'))) $descriptor

    $filtered = Invoke-ApiJson -PathAndQuery '/api/dex/classes?member=classes.dex&search=Activity&limit=1' -Token $script:token
    Check 'search narrows the total' (([int]$filtered.Json.total -gt 0) -and ([int]$filtered.Json.total -lt [int]$classes.Json.total)) `
        "total=$($filtered.Json.total) of $($classes.Json.total)"

    # ---- 3. class detail
    $detail = Invoke-ApiJson -PathAndQuery ("/api/dex/class?member=classes.dex&descriptor=" + (Get-Escaped $descriptor)) -Token $script:token
    Check '/api/dex/class answers 200' ($detail.Status -eq 200) "status=$($detail.Status)"
    Check 'the class detail reports its descriptor' ([string]$detail.Json.descriptor -eq $descriptor) "descriptor=$($detail.Json.descriptor)"
    $methodCount = @($detail.Json.methods).Count
    Check 'the class lists methods' ($methodCount -gt 0) "methods=$methodCount"
    $withCode = @($detail.Json.methods | Where-Object { $_.has_code } | Select-Object -First 1)
    Check 'at least one method has bytecode' ($withCode.Count -eq 1) "found=$($withCode.Count)"

    # ---- 4. method detail: instructions + text CFG
    $signature = [string]$withCode[0].signature
    $method = Invoke-ApiJson -PathAndQuery ("/api/dex/method?member=classes.dex&signature=" + (Get-Escaped $signature)) -Token $script:token
    Check '/api/dex/method answers 200' ($method.Status -eq 200) "status=$($method.Status)"
    Check 'the method reports its smali signature' ([string]$method.Json.signature -eq $signature) $signature
    Check 'code_off is 16 lowercase hex digits' ([string]$method.Json.code_off -cmatch '^[0-9a-f]{16}$') "code_off=$($method.Json.code_off)"
    Check 'the instruction count is positive' ([int]$method.Json.instruction_count -gt 0) "instructions=$($method.Json.instruction_count)"
    $firstInsn = [string]$method.Json.instructions[0].text
    Check 'instructions render as address: mnemonic' ($firstInsn -match '^[0-9a-f]{4}: ') $firstInsn
    Check 'addresses on the wire are 16 hex digits' ([string]$method.Json.instructions[0].address -cmatch '^[0-9a-f]{16}$') `
        "address=$($method.Json.instructions[0].address)"
    $cfg = [string]$method.Json.cfg_text
    Check 'a text CFG is provided' ($cfg.Length -gt 0) "length=$($cfg.Length)"
    # The CFG is human-readable text (Chinese prose plus '@' block starts), so
    # only its ASCII skeleton is asserted here: the header keyword, and at
    # least one '@<hex>' block start.
    Check 'the text CFG has a header and block starts' (($cfg -match 'CFG') -and ($cfg -match '@[0-9a-f]+')) `
        "head=$(($cfg -split "`n")[0])"
    Check 'symbols are on by default' ($method.Json.symbols -eq $true) "symbols=$($method.Json.symbols)"
    Check 'the symbol accounting is reported' `
        (($null -ne $method.Json.unsupported_operands) -and ($null -ne $method.Json.unavailable_operands) -and ($null -ne $method.Json.unresolved_edge_targets)) `
        "unsupported=$($method.Json.unsupported_operands) unavailable=$($method.Json.unavailable_operands) unresolved=$($method.Json.unresolved_edge_targets)"

    Write-Host "  info  $signature -> $($method.Json.instruction_count) instructions, $($method.Json.block_count) blocks, $($method.Json.edge_count) edges"

    # ---- 5. honest failures
    $missingMember = Invoke-ApiJson -PathAndQuery '/api/dex/classes' -Token $script:token
    Check 'a missing member is a 400' ($missingMember.Status -eq 400) "status=$($missingMember.Status)"
    Check 'the missing-member error is not empty' ((Get-ErrorMessage $missingMember).Length -gt 0) (Get-ErrorMessage $missingMember)

    $unknownMember = Invoke-ApiJson -PathAndQuery '/api/dex/classes?member=classes9.dex' -Token $script:token
    Check 'an unknown member is a 400' ($unknownMember.Status -eq 400) "status=$($unknownMember.Status)"
    Check 'the unknown-member error names the request' ((Get-ErrorMessage $unknownMember) -match 'classes9\.dex') (Get-ErrorMessage $unknownMember)

    $badDescriptor = Invoke-ApiJson -PathAndQuery '/api/dex/class?member=classes.dex&descriptor=Foo' -Token $script:token
    $missingClass = Invoke-ApiJson -PathAndQuery '/api/dex/class?member=classes.dex&descriptor=Lcom/definitely/NotHere;' -Token $script:token
    Check 'a non-descriptor is a 404' ($badDescriptor.Status -eq 404) "status=$($badDescriptor.Status)"
    Check 'a missing class is a 404' ($missingClass.Status -eq 404) "status=$($missingClass.Status)"
    Check 'the format hint is distinguishable from a plain miss' `
        ((Get-ErrorMessage $badDescriptor) -ne (Get-ErrorMessage $missingClass)) `
        "hint-vs-miss: $([int]((Get-ErrorMessage $badDescriptor) -ne (Get-ErrorMessage $missingClass)))"

    $typo = Invoke-ApiJson -PathAndQuery '/api/dex/classes?member=classes.dex&limt=5' -Token $script:token
    Check 'a misspelled parameter is a 400, not silently ignored' ($typo.Status -eq 400) "status=$($typo.Status)"

    # ---- 6. GET /api/export with a DEX format (M2c / ADR-0021)
    # One endpoint, two views, discriminated by `format`. What only a real
    # process + real APK can show here: that an ARCHIVE target reaches the DEX
    # exporter at all (the CLI bails on archives before this point) and that the
    # two views' selectors are rejected rather than silently ignored.
    $exportBase = "http://127.0.0.1:$Port/api/export"
    $dexExport = Invoke-Api -Uri ("$exportBase" + "?format=dex-json&member=classes.dex&limit=2000000&class=" + (Get-Escaped $descriptor)) -Token $script:token
    Check '/api/export?format=dex-json answers 200' ($dexExport.Status -eq 200) "status=$($dexExport.Status)"
    $dexSnapshot = $null
    try { $dexSnapshot = $dexExport.Body | ConvertFrom-Json } catch { $dexSnapshot = $null }
    Check 'the DEX snapshot is valid JSON' ($null -ne $dexSnapshot) "bytes=$($dexExport.Body.Length)"
    Check 'the snapshot names the member it came from' ([string]$dexSnapshot.member -eq 'classes.dex') "member=$($dexSnapshot.member)"
    Check 'the snapshot carries the DEX view version' ($dexSnapshot.meta.format_versions.dex -eq 1) `
        "dex=$($dexSnapshot.meta.format_versions.dex)"
    Check 'the snapshot exports the requested class' ([string]$dexSnapshot.classes[0].descriptor -eq $descriptor) `
        "descriptor=$($dexSnapshot.classes[0].descriptor)"
    Check 'the header counts every class of the member' ([int]$dexSnapshot.header.class_count -gt 1000) `
        "classes=$($dexSnapshot.header.class_count)"
    Check 'skipped methods are accounted for, not dropped' ($null -ne $dexSnapshot.skipped.methods_without_code) `
        "without_code=$($dexSnapshot.skipped.methods_without_code)"

    # The selectors of one view must be REJECTED by the other (ADR-0021):
    # ignoring --member on asm-intel would hand back a plausible-looking file.
    $mixedSelector = Invoke-ApiJson -PathAndQuery '/api/export?format=asm-intel&member=classes.dex' -Token $script:token
    Check 'a DEX selector on a machine-code format is a 400' ($mixedSelector.Status -eq 400) "status=$($mixedSelector.Status)"
    Check 'the mixed-selector error names the selector' ((Get-ErrorMessage $mixedSelector) -match 'member') `
        (Get-ErrorMessage $mixedSelector)

    $mixedOption = Invoke-ApiJson -PathAndQuery '/api/export?format=dex-json&member=classes.dex&function=401000' -Token $script:token
    Check 'an address on a DEX format is a 400' ($mixedOption.Status -eq 400) "status=$($mixedOption.Status)"
    Check 'the address error names the option' ((Get-ErrorMessage $mixedOption) -match 'function') `
        (Get-ErrorMessage $mixedOption)

    $smaliExport = Invoke-Api -Uri ("$exportBase" + "?format=dex-smali&member=classes.dex&limit=2000000&class=" + (Get-Escaped $descriptor)) -Token $script:token
    Check 'dex-smali answers 200 as a self-describing text' `
        (($smaliExport.Status -eq 200) -and ($smaliExport.Body.StartsWith('# bitflip-export v1 format=dex-smali'))) `
        "status=$($smaliExport.Status)"
    # The header promise that this is NOT assemblable smali input. Spelled with
    # [char] codes on purpose: every .ps1 in this repo must stay ASCII-only
    # (CLAUDE.md section 6.1), so a Chinese literal cannot live here.
    $notAssemblable = [string]([char]0x4E0D) + [char]0x662F + [char]0x53EF + [char]0x56DE + [char]0x6C47 + [char]0x7F16
    Check 'dex-smali says it is not assemblable input' ($smaliExport.Body -match $notAssemblable) `
        'looked for the leading warning line'
    # The renderer already prefixes every instruction with its code-unit offset;
    # the exporter must not add a second one (it used to: "0000: 0000: ...").
    Check 'dex-smali does not repeat the code-unit prefix' `
        (-not ($smaliExport.Body -match '(?m)^\s+[0-9a-f]{4}: [0-9a-f]{4}: ')) 'looked for a doubled prefix'

    $dotExport = Invoke-Api -Uri ("$exportBase" + "?format=dex-dot-cfg&member=classes.dex&class=" + (Get-Escaped $descriptor)) -Token $script:token
    Check 'dex-dot-cfg answers 200' ($dotExport.Status -eq 200) "status=$($dotExport.Status)"
    Check 'dex-dot-cfg is a balanced digraph' `
        ((($dotExport.Body -match 'digraph bitflip \{') -and (($dotExport.Body.ToCharArray() | Where-Object { $_ -eq '{' }).Count -eq ($dotExport.Body.ToCharArray() | Where-Object { $_ -eq '}' }).Count))) `
        "braces=$(($dotExport.Body.ToCharArray() | Where-Object { $_ -eq '{' }).Count)/$(($dotExport.Body.ToCharArray() | Where-Object { $_ -eq '}' }).Count)"
    Check 'the entry block is marked with peripheries, not a bogus shape' `
        (($dotExport.Body -match 'peripheries=2') -and (-not ($dotExport.Body -match 'shape="box,'))) `
        'looked for peripheries=2'

    # ---- 7. the served SPA really contains the DEX view
    $bundle = Invoke-Api -Uri "http://127.0.0.1:$Port/assets/app.js" -Token ''
    Check 'the embedded bundle is served' (($bundle.Status -eq 200) -and ($bundle.Body.Length -gt 100000)) `
        "status=$($bundle.Status) bytes=$($bundle.Body.Length)"
    Check 'the embedded bundle contains the DEX view' ($bundle.Body -match '/api/dex/classes') 'looked for /api/dex/classes'
    # The DEX view keeps its selection in the URL hash, so a link can be shared.
    # 'hashchange' is the string that only the URL-state module introduces; if the
    # built bundle stopped carrying it, the shipped UI would lose refresh/share
    # and nothing else would notice (the source tree would still look right).
    Check 'the embedded bundle carries the DEX url-state wiring' ($bundle.Body -match 'hashchange') 'looked for hashchange'
    Check 'the embedded bundle carries the member size fields' ($bundle.Body -match 'uncompressed_size') 'looked for uncompressed_size'
    Check 'the embedded stylesheet has the CFG block' `
        ((Invoke-Api -Uri "http://127.0.0.1:$Port/assets/app.css" -Token '').Body -match 'dex-cfg') 'looked for .dex-cfg'
}
finally {
    # Cleanup AFTER the assertions: killing the server earlier makes the
    # remaining checks "pass" against a dead port.
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "checks=$($script:checks) failures=$($script:failures)"
if ($script:failures -gt 0) { exit 1 }
exit 0
