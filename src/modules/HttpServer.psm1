<#
.SYNOPSIS
    SCGuardian HTTP server: bearer auth, replay protection, routing, HttpListener loop.
.DESCRIPTION
    Purpose : authenticated JSON-over-HTTP(S) front door for the Hub.
    Author  : Badr
    Version : 4.0.0
    Depends : Common.psm1 (Write-ScgLog, Get-ScgUtcNow, ConvertFrom-ScgUtcIso, Protect-Secret)
    Worker rule: handlers and OnReject are re-created per worker from their text, so they must be self-contained
    or use only functions from modules passed via Start-ScgHttpServer -WorkerModule (no closure variables).
    Route table convention: hashtable whose keys are "METHOD /path" (for example "POST /heartbeat",
    path relative to /api/v1) and whose values are scriptblocks taking param($Request) and returning
    @{Status=<int>; Body=<object>}. $Request has Method, Path, Body (parsed JSON), RemoteIp and Headers
    (case-insensitive hashtable of request headers, Authorization excluded; v2.0 device token lives here).
#>

Set-StrictMode -Version 2.0

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -DisableNameChecking

$script:ModulePath = $PSCommandPath
if (-not $script:ModulePath) { $script:ModulePath = $MyInvocation.MyCommand.Path }
$script:Server = $null
$script:ApiPrefix = '/api/v1'
$script:TlsAppId = '{7f3c1e52-4b8a-4d6e-9a21-5c0d8e3b6f14}'

function Test-ScgBearer {
<#
.SYNOPSIS
    Constant-time check of an Authorization header against the shared secret.
.PARAMETER Header
    The raw Authorization header value ("Bearer <secret>").
.PARAMETER Secret
    The expected shared secret. Never logged.
.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Header,
        [AllowNull()][AllowEmptyString()][string]$Secret
    )
    if ([string]::IsNullOrEmpty($Secret)) { return $false }
    if ($null -eq $Header) { $Header = '' }
    $utf8 = [System.Text.Encoding]::UTF8
    $expected = $utf8.GetBytes('Bearer ' + $Secret)
    $actual = $utf8.GetBytes($Header)
    $diff = [int]($expected.Length -bxor $actual.Length)
    for ($i = 0; $i -lt $expected.Length; $i++) {
        $a = 0
        if ($i -lt $actual.Length) { $a = [int]$actual[$i] }
        $diff = $diff -bor ([int]$expected[$i] -bxor $a)
    }
    return ($diff -eq 0)
}

function Assert-ScgReplayWindow {
<#
.SYNOPSIS
    Throws unless NonceTtlSec is at least twice MaxSkewSec (otherwise a nonce could expire while its timestamp is still valid).
.PARAMETER MaxSkewSec
    Allowed clock skew either side of Now.
.PARAMETER NonceTtlSec
    How long a nonce is remembered.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$MaxSkewSec, [Parameter(Mandatory)][int]$NonceTtlSec)
    if ($MaxSkewSec -lt 1) { throw 'MaxSkewSec must be at least 1.' }
    if ($NonceTtlSec -lt (2 * $MaxSkewSec)) {
        throw ('NonceTtlSec ({0}) must be >= 2 * MaxSkewSec ({1}); a shorter TTL lets a captured request be replayed.' -f $NonceTtlSec, $MaxSkewSec)
    }
}

function New-ScgReplayCache {
<#
.SYNOPSIS
    Creates a nonce store for replay detection (hashtable plus time-ordered queue for O(1) amortised expiry).
.DESCRIPTION
    When MaxEntries live nonces are stored, Test-ScgReplay fails closed with 503 rather than evicting live nonces.
.PARAMETER MaxEntries
    Upper bound on stored nonces.
.PARAMETER MaxSkewSec
    Skew the cache will be used with; validated against NonceTtlSec.
.PARAMETER NonceTtlSec
    Nonce memory the cache will be used with; must be >= 2 * MaxSkewSec.
.OUTPUTS
    PSCustomObject with Nonces, Order, MaxEntries.
#>
    [CmdletBinding()]
    param(
        [ValidateRange(10, 1000000)][int]$MaxEntries = 10000,
        [int]$MaxSkewSec = 300,
        [int]$NonceTtlSec = 600
    )
    Assert-ScgReplayWindow -MaxSkewSec $MaxSkewSec -NonceTtlSec $NonceTtlSec
    [pscustomobject]@{
        Nonces     = [hashtable]::Synchronized(@{})
        Order      = (New-Object System.Collections.Generic.Queue[object])
        MaxEntries = $MaxEntries
    }
}

function Test-ScgReplay {
<#
.SYNOPSIS
    Validates timestamp window and nonce uniqueness; records the nonce when accepted.
.PARAMETER Cache
    Object from New-ScgReplayCache.
.PARAMETER Timestamp
    X-SCG-Timestamp header value (UTC ISO8601 with Z).
.PARAMETER Nonce
    X-SCG-Nonce header value.
.PARAMETER MaxSkewSec
    Allowed clock skew either side of Now.
.PARAMETER NonceTtlSec
    How long a nonce is remembered.
.PARAMETER Now
    Injectable current time (UTC) for tests.
.OUTPUTS
    PSCustomObject {Ok; Status; Reason} where Status is 200, 400, 408, 409 or 503 (cache full, fail closed).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Cache,
        [AllowNull()][AllowEmptyString()][string]$Timestamp,
        [AllowNull()][AllowEmptyString()][string]$Nonce,
        [int]$MaxSkewSec = 300,
        [int]$NonceTtlSec = 600,
        [datetime]$Now = [datetime]::UtcNow
    )
    $fail = {
        param($status, $reason)
        [pscustomobject]@{ Ok = $false; Status = $status; Reason = $reason }
    }
    $nowUtc = $Now.ToUniversalTime()

    if ([string]::IsNullOrEmpty($Timestamp) -or $Timestamp -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$') {
        return (& $fail 400 'malformed timestamp')
    }
    if ([string]::IsNullOrEmpty($Nonce) -or $Nonce -notmatch '^[A-Za-z0-9\-]{8,64}$') {
        return (& $fail 400 'malformed nonce')
    }
    try { $ts = (ConvertFrom-ScgUtcIso -Value $Timestamp).ToUniversalTime() }
    catch { return (& $fail 400 'malformed timestamp') }

    if ([math]::Abs(($nowUtc - $ts).TotalSeconds) -gt $MaxSkewSec) {
        return (& $fail 408 'timestamp outside allowed window')
    }

    $key = $Nonce.ToLowerInvariant()
    $store = $Cache.Nonces
    $lock = $store.SyncRoot
    [System.Threading.Monitor]::Enter($lock)
    try {
        $order = $Cache.Order
        $cutoff = $nowUtc.AddSeconds(-$NonceTtlSec)
        while ($order.Count -gt 0 -and $order.Peek().At -lt $cutoff) {
            $old = $order.Dequeue()
            $store.Remove($old.Key)
        }

        if ($store.ContainsKey($key)) {
            return (& $fail 409 'replayed nonce')
        }
        if ($store.Count -ge $Cache.MaxEntries) {
            return (& $fail 503 'replay cache full')
        }
        $store[$key] = $nowUtc
        $order.Enqueue([pscustomobject]@{ Key = $key; At = $nowUtc })
    }
    finally {
        [System.Threading.Monitor]::Exit($lock)
    }
    [pscustomobject]@{ Ok = $true; Status = 200; Reason = '' }
}

function ConvertTo-ScgRoutePath {
<#
.SYNOPSIS
    Normalises a path: drops query string and /api/v1 prefix, trims trailing slash.
.PARAMETER Path
    Raw path.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ($null -eq $Path) { $Path = '' }
    $p = $Path.Split('?')[0]
    if ($p.StartsWith($script:ApiPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $p = $p.Substring($script:ApiPrefix.Length)
    }
    if (-not $p.StartsWith('/')) { $p = '/' + $p }
    if ($p.Length -gt 1) { $p = $p.TrimEnd('/') }
    if ([string]::IsNullOrEmpty($p)) { $p = '/' }
    return $p.ToLowerInvariant()
}

function Resolve-ScgRoute {
<#
.SYNOPSIS
    Finds the handler for a method and path.
.PARAMETER Method
    HTTP method.
.PARAMETER Path
    Request path (with or without /api/v1 prefix).
.PARAMETER Route
    Route table: keys "METHOD /path", values scriptblocks.
.OUTPUTS
    Hashtable with Handler on success, or Status 404 / 405.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Route
    )
    $want = ConvertTo-ScgRoutePath -Path $Path
    $m = $Method.ToUpperInvariant()
    $pathSeen = $false
    foreach ($key in $Route.Keys) {
        $parts = ([string]$key).Trim().Split(' ', 2)
        if ($parts.Count -ne 2) { continue }
        if ((ConvertTo-ScgRoutePath -Path $parts[1].Trim()) -ne $want) { continue }
        $pathSeen = $true
        if ($parts[0].ToUpperInvariant() -eq $m) {
            return @{ Handler = $Route[$key] }
        }
    }
    if ($pathSeen) { return @{ Status = 405 } }
    return @{ Status = 404 }
}

function Get-ScgHeaderValue {
<#
.SYNOPSIS
    Reads a header case-insensitively from a dictionary or NameValueCollection.
.PARAMETER Headers
    Header container.
.PARAMETER Name
    Header name.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param($Headers, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Headers) { return $null }
    if ($Headers -is [System.Collections.Specialized.NameValueCollection]) {
        return [string]$Headers[$Name]
    }
    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($k in $Headers.Keys) {
            if ([string]$k -ieq $Name) { return [string]$Headers[$k] }
        }
    }
    return $null
}

function ConvertTo-ScgHeaderTable {
<#
.SYNOPSIS
    Copies request headers into a case-insensitive hashtable for handlers (Authorization is never copied).
.PARAMETER Headers
    Dictionary or NameValueCollection (may be null).
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param($Headers)
    $table = New-Object System.Collections.Hashtable ([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Headers) { return $table }
    $keys = @()
    if ($Headers -is [System.Collections.Specialized.NameValueCollection]) { $keys = @($Headers.AllKeys) }
    elseif ($Headers -is [System.Collections.IDictionary]) { $keys = @($Headers.Keys) }
    foreach ($k in $keys) {
        if ($null -eq $k) { continue }
        $name = [string]$k
        if ($name -ieq 'Authorization') { continue }
        $table[$name] = [string]$Headers[$k]
    }
    return $table
}

function New-ScgErrorResult {
<#
.SYNOPSIS
    Builds the standard error result {Status; Body={ok=false;error}}.
.PARAMETER Status
    HTTP status.
.PARAMETER Message
    Error text.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Status, [Parameter(Mandatory)][string]$Message)
    @{ Status = $Status; Body = @{ ok = $false; error = $Message } }
}

function Invoke-ScgReject {
<#
.SYNOPSIS
    Invokes the audit callback with (reason, remoteIp); never throws.
.PARAMETER OnReject
    Callback scriptblock or null.
.PARAMETER Reason
    Short machine reason.
.PARAMETER RemoteIp
    Caller IP.
#>
    [CmdletBinding()]
    param([scriptblock]$OnReject, [Parameter(Mandatory)][string]$Reason, [string]$RemoteIp)
    if ($null -eq $OnReject) { return }
    try { & $OnReject $Reason $RemoteIp | Out-Null } catch { Write-Verbose 'OnReject callback failed' }
}

function Invoke-ScgRequestPipeline {
<#
.SYNOPSIS
    Pure request pipeline: bearer, timestamp, nonce, route (404/405), body read and parse, handler.
.DESCRIPTION
    Auth order (api-registry v1.1): unauthenticated callers always get 401/400/408/409/503 and never 404/405.
    Returns @{Status; Body}. On a 500 the hashtable also carries Detail (masked) for logging only.
.PARAMETER Method
    HTTP method.
.PARAMETER Path
    Request path including /api/v1.
.PARAMETER Headers
    Dictionary or NameValueCollection of request headers.
.PARAMETER Body
    Raw request body text.
.PARAMETER RemoteIp
    Caller IP for audit.
.PARAMETER Secret
    Shared secret.
.PARAMETER Route
    Route table.
.PARAMETER ReplayCache
    Cache from New-ScgReplayCache.
.PARAMETER MaxSkewSec
    Allowed timestamp skew.
.PARAMETER NonceTtlSec
    Nonce memory.
.PARAMETER OnReject
    Callback (reason, remoteIp) for audit.
.PARAMETER Now
    Injectable UTC time.
.PARAMETER BodyTooLarge
    Set by the listener when the body exceeded the cap and was not read.
.PARAMETER MaxBodyBytes
    Body cap in bytes (default 1 MB).
.PARAMETER BodyProvider
    Optional scriptblock returning @{Text; TooLarge}; invoked only after bearer, timestamp, nonce and routing succeed,
    so unauthenticated callers never cause a body read. When given, Body and BodyTooLarge are ignored.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Headers,
        [AllowNull()][AllowEmptyString()][string]$Body,
        [string]$RemoteIp = '',
        [Parameter(Mandatory)][string]$Secret,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Route,
        [Parameter(Mandatory)]$ReplayCache,
        [int]$MaxSkewSec = 300,
        [int]$NonceTtlSec = 600,
        [scriptblock]$OnReject,
        [datetime]$Now,
        [switch]$BodyTooLarge,
        [int]$MaxBodyBytes = 1048576,
        [scriptblock]$BodyProvider
    )
    $rawPath = $Path.Split('?')[0]

    if (-not (Test-ScgBearer -Header (Get-ScgHeaderValue -Headers $Headers -Name 'Authorization') -Secret $Secret)) {
        Invoke-ScgReject -OnReject $OnReject -Reason 'bad_bearer' -RemoteIp $RemoteIp
        return (New-ScgErrorResult -Status 401 -Message 'unauthorized')
    }

    $replayArgs = @{
        Cache       = $ReplayCache
        Timestamp   = (Get-ScgHeaderValue -Headers $Headers -Name 'X-SCG-Timestamp')
        Nonce       = (Get-ScgHeaderValue -Headers $Headers -Name 'X-SCG-Nonce')
        MaxSkewSec  = $MaxSkewSec
        NonceTtlSec = $NonceTtlSec
    }
    if ($PSBoundParameters.ContainsKey('Now')) { $replayArgs['Now'] = $Now }
    $replay = Test-ScgReplay @replayArgs
    if (-not $replay.Ok) {
        $reasonMap = @{ 400 = 'bad_replay_headers'; 408 = 'stale_timestamp'; 409 = 'replayed_nonce'; 503 = 'replay_cache_full' }
        Invoke-ScgReject -OnReject $OnReject -Reason $reasonMap[[int]$replay.Status] -RemoteIp $RemoteIp
        return (New-ScgErrorResult -Status ([int]$replay.Status) -Message $replay.Reason)
    }

    $routeHit = $null
    if ($rawPath.StartsWith($script:ApiPrefix + '/', [System.StringComparison]::OrdinalIgnoreCase)) {
        $routeHit = Resolve-ScgRoute -Method $Method -Path $rawPath -Route $Route
    }
    else {
        $routeHit = @{ Status = 404 }
    }
    if ($routeHit.ContainsKey('Status')) {
        if ($routeHit.Status -eq 405) {
            Invoke-ScgReject -OnReject $OnReject -Reason 'method_not_allowed' -RemoteIp $RemoteIp
            return (New-ScgErrorResult -Status 405 -Message 'method not allowed')
        }
        Invoke-ScgReject -OnReject $OnReject -Reason 'route_not_found' -RemoteIp $RemoteIp
        return (New-ScgErrorResult -Status 404 -Message 'not found')
    }

    if ($BodyProvider) {
        $read = & $BodyProvider
        $Body = [string]$read.Text
        if ($read.TooLarge) { $BodyTooLarge = [switch]$true }
    }

    $parsed = $null
    if ($BodyTooLarge -or ([System.Text.Encoding]::UTF8.GetByteCount([string]$Body) -gt $MaxBodyBytes)) {
        Invoke-ScgReject -OnReject $OnReject -Reason 'body_too_large' -RemoteIp $RemoteIp
        return (New-ScgErrorResult -Status 413 -Message 'request body too large')
    }
    if ($Method.ToUpperInvariant() -ne 'GET') {
        if ([string]::IsNullOrWhiteSpace($Body)) {
            Invoke-ScgReject -OnReject $OnReject -Reason 'bad_body' -RemoteIp $RemoteIp
            return (New-ScgErrorResult -Status 400 -Message 'invalid json body')
        }
        try { $parsed = $Body | ConvertFrom-Json -ErrorAction Stop }
        catch {
            Invoke-ScgReject -OnReject $OnReject -Reason 'bad_body' -RemoteIp $RemoteIp
            return (New-ScgErrorResult -Status 400 -Message 'invalid json body')
        }
        if ($null -eq $parsed) {
            Invoke-ScgReject -OnReject $OnReject -Reason 'bad_body' -RemoteIp $RemoteIp
            return (New-ScgErrorResult -Status 400 -Message 'invalid json body')
        }
    }

    $request = [pscustomobject]@{
        Method   = $Method.ToUpperInvariant()
        Path     = (ConvertTo-ScgRoutePath -Path $rawPath)
        Body     = $parsed
        RemoteIp = $RemoteIp
        Headers  = (ConvertTo-ScgHeaderTable -Headers $Headers)
    }
    try {
        $out = @(& $routeHit.Handler $request)
        $result = $null
        if ($out.Count -gt 0) { $result = $out[$out.Count - 1] }
        if ($result -isnot [System.Collections.IDictionary] -or -not $result.Contains('Status')) {
            throw 'handler returned an invalid result'
        }
        return @{ Status = [int]$result['Status']; Body = $result['Body'] }
    }
    catch {
        $detail = $_.Exception.Message
        try { $detail = Protect-Secret -Text $detail -Secret @($Secret) } catch { $detail = 'handler failure' }
        $r = New-ScgErrorResult -Status 500 -Message 'internal error'
        $r['Detail'] = $detail
        return $r
    }
}

function Read-ScgRequestBody {
<#
.SYNOPSIS
    Reads an HttpListenerRequest body as UTF8 text with a hard byte cap.
.PARAMETER Request
    System.Net.HttpListenerRequest.
.PARAMETER MaxBytes
    Cap in bytes.
.OUTPUTS
    Hashtable {Text; TooLarge}.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Request, [int]$MaxBytes = 1048576)
    if (-not $Request.HasEntityBody) { return @{ Text = ''; TooLarge = $false } }
    if ($Request.ContentLength64 -gt $MaxBytes) { return @{ Text = ''; TooLarge = $true } }
    $ms = New-Object System.IO.MemoryStream
    try {
        $buffer = New-Object byte[] 8192
        $total = 0
        $stream = $Request.InputStream
        while (($n = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $n
            if ($total -gt $MaxBytes) { return @{ Text = ''; TooLarge = $true } }
            $ms.Write($buffer, 0, $n)
        }
        return @{ Text = [System.Text.Encoding]::UTF8.GetString($ms.ToArray()); TooLarge = $false }
    }
    finally { $ms.Dispose() }
}

function Send-ScgJsonResponse {
<#
.SYNOPSIS
    Writes a UTF8 JSON response and closes it.
.PARAMETER Response
    System.Net.HttpListenerResponse.
.PARAMETER Status
    HTTP status code.
.PARAMETER Body
    Object serialised as JSON.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Response, [Parameter(Mandatory)][int]$Status, $Body)
    try {
        $json = '{}'
        if ($null -ne $Body) { $json = ConvertTo-Json -InputObject $Body -Depth 10 -Compress }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $Response.StatusCode = $Status
        $Response.ContentType = 'application/json; charset=utf-8'
        $Response.ContentLength64 = $bytes.Length
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    }
    catch { Write-Verbose 'response write failed' }
    finally {
        try { $Response.Close() } catch { Write-Verbose 'response close failed' }
    }
}

function ConvertTo-ScgWorkerScriptBlock {
<#
.SYNOPSIS
    Re-creates a scriptblock in the current session state so it never runs against another runspace's SessionState.
.DESCRIPTION
    Uses [scriptblock]::Create($sb.ToString()). Closure-captured variables are NOT preserved: handlers must be
    self-contained or call only functions available in the worker (modules passed via -WorkerModule).
.PARAMETER ScriptBlock
    Source scriptblock (null returns null).
#>
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param([AllowNull()][scriptblock]$ScriptBlock)
    if ($null -eq $ScriptBlock) { return $null }
    return [scriptblock]::Create($ScriptBlock.ToString())
}

function ConvertTo-ScgWorkerConfig {
<#
.SYNOPSIS
    Returns a copy of the listener Config whose Route handlers and OnReject are re-created for the current runspace.
.PARAMETER Config
    Hashtable: Secret, Route, ReplayCache, OnReject, MaxSkewSec, NonceTtlSec.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)
    $copy = @{}
    foreach ($k in $Config.Keys) { $copy[$k] = $Config[$k] }
    $routes = @{}
    foreach ($k in $Config.Route.Keys) { $routes[$k] = ConvertTo-ScgWorkerScriptBlock -ScriptBlock $Config.Route[$k] }
    $copy['Route'] = $routes
    $copy['OnReject'] = ConvertTo-ScgWorkerScriptBlock -ScriptBlock $Config.OnReject
    return $copy
}

function Invoke-ScgListenerContext {
<#
.SYNOPSIS
    Adapts one HttpListenerContext to the pipeline and sends the reply.
.PARAMETER Context
    System.Net.HttpListenerContext.
.PARAMETER Config
    Hashtable: Secret, Route, ReplayCache, OnReject, MaxSkewSec, NonceTtlSec.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][hashtable]$Config)
    $req = $Context.Request
    $remote = ''
    try { $remote = $req.RemoteEndPoint.Address.ToString() } catch { $remote = '' }
    try {
        $bodyReq = $req
        $args2 = @{
            Method       = $req.HttpMethod
            Path         = $req.Url.AbsolutePath
            Headers      = $req.Headers
            BodyProvider = { Read-ScgRequestBody -Request $bodyReq }
            RemoteIp     = $remote
            Secret      = $Config.Secret
            Route       = $Config.Route
            ReplayCache = $Config.ReplayCache
            MaxSkewSec  = $Config.MaxSkewSec
            NonceTtlSec = $Config.NonceTtlSec
        }
        if ($Config.OnReject) { $args2['OnReject'] = $Config.OnReject }
        $res = Invoke-ScgRequestPipeline @args2
        if ($res.ContainsKey('Detail')) {
            Write-ScgLog -Message ('handler failure: ' + $res.Detail) -Level ERROR -Actor 'system' -Target $req.Url.AbsolutePath -Action 'http.error' -Result 'fail'
        }
        Send-ScgJsonResponse -Response $Context.Response -Status $res.Status -Body $res.Body
    }
    catch {
        $why = $_.Exception.Message
        try { $why = Protect-Secret -Text $why -Secret @($Config.Secret) } catch { $why = 'unavailable' }
        try { Write-ScgLog -Message ('listener failure: ' + $why) -Level ERROR -Actor 'system' -Action 'http.error' -Result 'fail' } catch { Write-Verbose 'log failed' }
        $e = New-ScgErrorResult -Status 500 -Message 'internal error'
        Send-ScgJsonResponse -Response $Context.Response -Status 500 -Body $e.Body
    }
}

function Initialize-ScgTlsBinding {
<#
.SYNOPSIS
    Binds a certificate to 0.0.0.0:<Port> with netsh (idempotent). Requires elevation.
.PARAMETER Port
    TCP port.
.PARAMETER Thumbprint
    Certificate thumbprint, or 'auto' for the newest valid LocalMachine\My cert with CN ostazna.pro.
.OUTPUTS
    String: the thumbprint bound.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
        [Parameter(Mandatory)][string]$Thumbprint
    )
    $thumb = ($Thumbprint -replace '[^0-9A-Za-z]', '').ToUpperInvariant()
    if ($Thumbprint.Trim().ToLowerInvariant() -eq 'auto') {
        $now = Get-Date
        $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' |
            Where-Object { $_.Subject -match '(^|,\s*)CN=ostazna\.pro(,|$)' -and $_.NotAfter -gt $now -and $_.NotBefore -le $now } |
            Sort-Object -Property NotBefore -Descending |
            Select-Object -First 1
        if (-not $cert) {
            throw 'No valid certificate with CN=ostazna.pro found in LocalMachine\My. Install one or set listen.cert_thumbprint explicitly.'
        }
        $thumb = $cert.Thumbprint.ToUpperInvariant()
    }
    if ($thumb -notmatch '^[0-9A-F]{40}$') {
        throw 'Invalid certificate thumbprint (expected 40 hex characters or auto).'
    }
    $ipPort = "0.0.0.0:$Port"
    $show = (& netsh http show sslcert "ipport=$ipPort" 2>&1 | Out-String)
    if ($show -match 'Certificate Hash\s*:\s*([0-9A-Fa-f]{40})') {
        if ($Matches[1].ToUpperInvariant() -eq $thumb) { return $thumb }
        & netsh http delete sslcert "ipport=$ipPort" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "netsh could not remove the existing certificate binding on port $Port (run elevated)." }
    }
    $add = (& netsh http add sslcert "ipport=$ipPort" "certhash=$thumb" "appid=$script:TlsAppId" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw ('netsh add sslcert failed on port {0}: {1}' -f $Port, $add.Trim())
    }
    Write-ScgLog -Message "TLS binding set on port $Port" -Level INFO -Actor 'system' -Action 'tls.bind' -Result 'ok'
    return $thumb
}

function Start-ScgHttpServer {
<#
.SYNOPSIS
    Starts the listener; each request runs in a RunspacePool worker.
.PARAMETER Url
    Listener prefix, for example https://+:8443/ or http://localhost:8080/.
.PARAMETER Secret
    Shared secret.
.PARAMETER Route
    Route table (see module header).
.PARAMETER ReplayCache
    Cache from New-ScgReplayCache (created when omitted).
.PARAMETER OnReject
    Callback (reason, remoteIp) for audit.
.PARAMETER Thumbprint
    For https URLs: certificate thumbprint or 'auto'; binds via Initialize-ScgTlsBinding.
.PARAMETER MaxSkewSec
    Allowed timestamp skew.
.PARAMETER NonceTtlSec
    Nonce memory.
.PARAMETER MaxWorkers
    Maximum concurrent handlers. Work in flight is capped at MaxWorkers * 4; beyond that requests get 503.
.PARAMETER WorkerModule
    Module paths imported into every worker runspace (so route handlers can call their functions).
.PARAMETER LogContext
    Hashtable with Path, MaxBytes, Secret; applied with Set-ScgLogContext inside each worker. The server Secret is always masked too.
.PARAMETER TimeoutSec
    HttpListener TimeoutManager value for EntityBody, HeaderWait and IdleConnection (default 15).
.NOTES
    Route handlers and OnReject are re-created in each worker with [scriptblock]::Create($sb.ToString()), so they
    never run against the caller's SessionState. Closure-captured variables are lost: handlers must be
    self-contained or reference only functions from modules listed in -WorkerModule.
.OUTPUTS
    The server state object.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Secret,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Route,
        $ReplayCache,
        [scriptblock]$OnReject,
        [string]$Thumbprint,
        [int]$MaxSkewSec = 300,
        [int]$NonceTtlSec = 600,
        [ValidateRange(1, 64)][int]$MaxWorkers = 8,
        [string[]]$WorkerModule = @(),
        [hashtable]$LogContext,
        [ValidateRange(5, 300)][int]$TimeoutSec = 15
    )
    if ($script:Server) { throw 'HTTP server is already running.' }
    Assert-ScgReplayWindow -MaxSkewSec $MaxSkewSec -NonceTtlSec $NonceTtlSec
    if (-not $Url.EndsWith('/')) { $Url = $Url + '/' }
    if (-not $ReplayCache) { $ReplayCache = New-ScgReplayCache -MaxSkewSec $MaxSkewSec -NonceTtlSec $NonceTtlSec }

    if ($Url.StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase)) {
        if ([string]::IsNullOrWhiteSpace($Thumbprint)) { $Thumbprint = 'auto' }
        $port = ([uri]($Url -replace '^(https://)\+', '$1localhost' -replace '^(https://)\*', '$1localhost')).Port
        [void](Initialize-ScgTlsBinding -Port $port -Thumbprint $Thumbprint)
    }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($Url)
    try {
        $tm = $listener.TimeoutManager
        $span = [TimeSpan]::FromSeconds($TimeoutSec)
        $tm.EntityBody = $span
        $tm.HeaderWait = $span
        $tm.IdleConnection = $span
    }
    catch { Write-Verbose 'listener timeouts not applied' }
    $listener.Start()

    $iss = [initialsessionstate]::CreateDefault()
    $iss.ImportPSModule(@($script:ModulePath) + @($WorkerModule | Where-Object { $_ }))
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxWorkers, $iss, $Host)
    $pool.Open()

    $state = [hashtable]::Synchronized(@{ Stop = $false; Listener = $listener })
    $cfg = @{
        Secret      = $Secret
        Route       = $Route
        ReplayCache = $ReplayCache
        OnReject    = $OnReject
        MaxSkewSec  = $MaxSkewSec
        NonceTtlSec = $NonceTtlSec
    }
    $logCtx = $null
    if ($LogContext) {
        $secrets = @($Secret)
        if ($LogContext.ContainsKey('Secret') -and $LogContext['Secret']) { $secrets += @($LogContext['Secret']) }
        $logCtx = @{ Path = [string]$LogContext['Path']; MaxBytes = 5242880; Secret = @($secrets | Select-Object -Unique) }
        if ($LogContext.ContainsKey('MaxBytes') -and $LogContext['MaxBytes']) { $logCtx['MaxBytes'] = [int]$LogContext['MaxBytes'] }
    }
    $cfg['LogContext'] = $logCtx
    $worker = @'
param($Context, $Cfg)
try {
    $m = Get-Module -Name HttpServer
    & $m {
        param($c, $cfg)
        $lc = $cfg.LogContext
        if ($lc -and $lc.Path) { Set-ScgLogContext -Path $lc.Path -MaxBytes $lc.MaxBytes -Secret $lc.Secret }
        $wcfg = ConvertTo-ScgWorkerConfig -Config $cfg
        Invoke-ScgListenerContext -Context $c -Config $wcfg
    } $Context $Cfg
}
catch {
    try { $Context.Response.StatusCode = 500; $Context.Response.Close() } catch { $null = $_ }
}
'@
    $loop = @'
param($State, $Pool, $WorkerScript, $Cfg, $MaxInFlight)
$active = New-Object System.Collections.ArrayList
$reap = {
    for ($i = $active.Count - 1; $i -ge 0; $i--) {
        if ($active[$i].H.IsCompleted) {
            try { [void]$active[$i].PS.EndInvoke($active[$i].H) } catch { $null = $_ }
            $active[$i].PS.Dispose()
            $active.RemoveAt($i)
        }
    }
}
while (-not $State.Stop) {
    try {
        $task = $State.Listener.GetContextAsync()
        while (-not $task.Wait(250)) {
            if ($State.Stop) { break }
            & $reap
        }
        if ($State.Stop) { break }
        $ctx = $task.Result
        & $reap
        if ($active.Count -ge $MaxInFlight) {
            try {
                $ctx.Response.StatusCode = 503
                $ctx.Response.AddHeader('Retry-After', '1')
                $ctx.Response.Close()
            }
            catch { $null = $_ }
            continue
        }
        $ps = [powershell]::Create()
        $ps.RunspacePool = $Pool
        [void]$ps.AddScript($WorkerScript).AddArgument($ctx).AddArgument($Cfg)
        $h = $ps.BeginInvoke()
        [void]$active.Add(@{ PS = $ps; H = $h })
    }
    catch {
        if ($State.Stop) { break }
        Start-Sleep -Milliseconds 100
    }
    & $reap
}
foreach ($a in @($active)) { try { $a.PS.Dispose() } catch { $null = $_ } }
'@
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $loopPs = [powershell]::Create()
    $loopPs.Runspace = $rs
    [void]$loopPs.AddScript($loop).AddArgument($state).AddArgument($pool).AddArgument($worker).AddArgument($cfg).AddArgument($MaxWorkers * 4)
    $handle = $loopPs.BeginInvoke()

    $script:Server = [pscustomobject]@{
        Url = $Url; State = $state; Listener = $listener; Pool = $pool
        LoopPs = $loopPs; LoopRunspace = $rs; LoopHandle = $handle
    }
    Write-ScgLog -Message "HTTP server listening on $Url" -Level INFO -Actor 'system' -Action 'http.start' -Result 'ok'
    return $script:Server
}

function Stop-ScgHttpServer {
<#
.SYNOPSIS
    Stops the listener, the accept loop and the worker pool.
.PARAMETER Server
    Server object from Start-ScgHttpServer (defaults to the running one).
#>
    [CmdletBinding()]
    param($Server = $script:Server)
    if (-not $Server) { return }
    $Server.State.Stop = $true
    try { $Server.Listener.Stop() } catch { Write-Verbose 'listener stop failed' }
    try { $Server.Listener.Close() } catch { Write-Verbose 'listener close failed' }
    try { [void]$Server.LoopHandle.AsyncWaitHandle.WaitOne(3000) } catch { Write-Verbose 'loop wait failed' }
    try { $Server.LoopPs.Stop() } catch { Write-Verbose 'loop stop failed' }
    try { $Server.LoopPs.Dispose() } catch { Write-Verbose 'loop dispose failed' }
    try { $Server.LoopRunspace.Dispose() } catch { Write-Verbose 'runspace dispose failed' }
    try { $Server.Pool.Close(); $Server.Pool.Dispose() } catch { Write-Verbose 'pool dispose failed' }
    if ($script:Server -and [object]::ReferenceEquals($script:Server, $Server)) { $script:Server = $null }
    try { Write-ScgLog -Message 'HTTP server stopped' -Level INFO -Actor 'system' -Action 'http.stop' -Result 'ok' } catch { Write-Verbose 'log failed' }
}

Export-ModuleMember -Function Test-ScgBearer, New-ScgReplayCache, Test-ScgReplay, Resolve-ScgRoute,
    ConvertTo-ScgWorkerScriptBlock, ConvertTo-ScgWorkerConfig,
    Start-ScgHttpServer, Stop-ScgHttpServer, Initialize-ScgTlsBinding, Invoke-ScgRequestPipeline
