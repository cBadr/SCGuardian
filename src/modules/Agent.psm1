<#
.SYNOPSIS
    SCGuardian Agent module: config, hub client, command execution, local watchdog, backoff.
.DESCRIPTION
    Purpose : the endpoint agent cycle (watchdog first, then enroll/heartbeat/commands/results/events).
    Author  : Badr
    Version : 4.0.0
    Depends : Common.psm1, Discovery.psm1, Hardening.psm1
#>

Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'Discovery.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'Hardening.psm1') -Force -DisableNameChecking

$script:AgentVersion = '4.0.1'
$script:ProcessStartUtc = [datetime]::UtcNow
$script:PinWarned = $false
$script:ValidLayer = @('Recovery', 'FolderAcl', 'ServiceSd', 'RegistryAcl')
$script:FailureLogGapMin = 10
$script:BackoffMaxSec = 300
$script:HubTimeoutMs = 30000
$script:DeviceTokenPath = @('/heartbeat', '/result', '/event')
$script:ErrNotEnrolled = 'hub http 401: device not enrolled'
$script:ErrBadToken = 'hub http 401: invalid device token'
$script:ErrUnknownDevice = 'hub http 404: unknown device'
$script:ErrEnrollConflict = 'hub http 409: hostname already enrolled'

function Get-ScgProp {
    <#
    .SYNOPSIS
        Reads a property or key from an object or dictionary with a default (StrictMode safe).
    .PARAMETER InputObject
        Source object, hashtable or null.
    .PARAMETER Name
        Property or key name.
    .PARAMETER Default
        Value returned when absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()][object]$Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    $value = $Default
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { $value = $InputObject[$Name] }
    }
    else {
        $p = $InputObject.PSObject.Properties[$Name]
        if ($null -ne $p) { $value = $p.Value }
    }
    if ($value -is [array]) { return , $value }
    return $value
}

function Get-ScgList {
    <#
    .SYNOPSIS
        Reads a list property as a flat object[] (never wrapped, never stringified).
    .PARAMETER InputObject
        Source object, hashtable or null.
    .PARAMETER Name
        Property or key name.
    .PARAMETER Default
        List returned when absent.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()][object]$Default = $null
    )
    $value = Get-ScgProp -InputObject $InputObject -Name $Name -Default $Default
    $out = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push($value)
    $ordered = New-Object System.Collections.Generic.List[object]
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        if ($null -eq $item) { continue }
        if (($item -is [System.Collections.IEnumerable]) -and ($item -isnot [string]) -and ($item -isnot [System.Collections.IDictionary])) {
            $children = @($item.GetEnumerator())
            for ($i = $children.Count - 1; $i -ge 0; $i--) { $stack.Push($children[$i]) }
        }
        else { $ordered.Add($item) }
    }
    foreach ($o in $ordered) { $out.Add($o) }
    return , $out.ToArray()
}

function Set-ScgProp {
    <#
    .SYNOPSIS
        Sets (or adds) a note property on a PSCustomObject.
    .PARAMETER InputObject
        Target object.
    .PARAMETER Name
        Property name.
    .PARAMETER Value
        Value to store.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()][object]$Value
    )
    if (-not $PSCmdlet.ShouldProcess($Name, 'Set property')) { return }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $p) { $p.Value = $Value }
    else { Add-Member -InputObject $InputObject -NotePropertyName $Name -NotePropertyValue $Value }
}

function ConvertTo-ScgIdArray {
    <#
    .SYNOPSIS
        Normalizes a list of instance ids: lowercase, unique, sorted.
    .PARAMETER Value
        Raw list (array, single string or null).
    .PARAMETER SkipInvalid
        Drops invalid ids instead of throwing.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()][AllowNull()][object]$Value,
        [switch]$SkipInvalid
    )
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        try {
            $id = ConvertTo-ScgInstanceId -Id ([string]$v)
            if (-not $out.Contains($id)) { $out.Add($id) }
        }
        catch {
            if (-not $SkipInvalid) { throw "allowed_ids contains an invalid instance id" }
        }
    }
    $arr = @($out | Sort-Object)
    return , [string[]]$arr
}

function Get-ScgAgentConfig {
    <#
    .SYNOPSIS
        Loads agent.config.json, fills defaults, resolves hostname AUTO, validates.
    .PARAMETER Path
        Path to agent.config.json.
    .OUTPUTS
        PSCustomObject with every agent config field (allowed_ids lowercase).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Agent config not found: $Path" }
    $raw = Read-ScgJsonFile -Path $Path

    $hubUrl = [string](Get-ScgProp $raw 'hub_url' '')
    $secret = [string](Get-ScgProp $raw 'shared_secret' '')
    if ([string]::IsNullOrWhiteSpace($hubUrl)) { throw 'hub_url is required.' }
    $uri = $null
    if (-not [System.Uri]::TryCreate($hubUrl, [System.UriKind]::Absolute, [ref]$uri)) { throw 'hub_url is not a valid URL.' }
    $loopback = @('localhost', '127.0.0.1', '[::1]', '::1')
    if ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and ($loopback -contains $uri.Host))) {
        throw 'hub_url must be https (http is allowed for loopback only).'
    }
    if ([string]::IsNullOrWhiteSpace($secret) -or $secret -eq 'REPLACE_ME') { throw 'shared_secret is missing or still REPLACE_ME.' }

    $hb = [int](Get-ScgProp $raw 'heartbeat_sec' 60)
    $scan = [int](Get-ScgProp $raw 'scan_interval_sec' 30)
    if ($hb -lt 5 -or $hb -gt 86400) { throw 'heartbeat_sec must be between 5 and 86400.' }
    if ($scan -lt 5 -or $scan -gt 86400) { throw 'scan_interval_sec must be between 5 and 86400.' }
    $throttle = [int](Get-ScgProp $raw 'alert_throttle_min' 15)
    if ($throttle -lt 0 -or $throttle -gt 10080) { throw 'alert_throttle_min must be between 0 and 10080.' }

    $hostName = [string](Get-ScgProp $raw 'hostname' 'AUTO')
    if ([string]::IsNullOrWhiteSpace($hostName) -or $hostName -ieq 'AUTO') { $hostName = $env:COMPUTERNAME }

    $layers = @(foreach ($item in (Get-ScgList $raw 'layers' $script:ValidLayer)) { [string]$item })
    foreach ($l in $layers) {
        if ($script:ValidLayer -cnotcontains $l) { throw "Unknown hardening layer: $l" }
    }

    $thumb = [string](Get-ScgProp $raw 'trusted_server_thumbprint' '')
    $thumb = ($thumb -replace '[\s:]', '').ToUpperInvariant()
    if ($thumb -and $thumb -notmatch '^[0-9A-F]{40}$') { throw 'trusted_server_thumbprint must be a 40-hex SHA-1 thumbprint.' }

    $deviceId = Get-ScgProp $raw 'device_id' $null
    if ($null -ne $deviceId -and [string]::IsNullOrWhiteSpace([string]$deviceId)) { $deviceId = $null }
    $deviceToken = Get-ScgProp $raw 'device_token' $null
    if ($null -ne $deviceToken) {
        $deviceToken = [string]$deviceToken
        if ([string]::IsNullOrWhiteSpace($deviceToken)) { $deviceToken = $null }
    }

    return [pscustomobject]@{
        hub_url                   = $hubUrl.TrimEnd('/')
        shared_secret             = $secret
        device_id                 = $deviceId
        device_token              = $deviceToken
        hostname                  = $hostName
        heartbeat_sec             = $hb
        scan_interval_sec         = $scan
        alert_throttle_min        = $throttle
        allowed_ids               = (ConvertTo-ScgIdArray -Value (Get-ScgList $raw 'allowed_ids' @()))
        layers                    = [string[]]$layers
        take_ownership            = [bool](Get-ScgProp $raw 'take_ownership' $false)
        local_watchdog            = [bool](Get-ScgProp $raw 'local_watchdog' $true)
        trusted_server_thumbprint = $thumb
    }
}

function Update-ScgAgentConfig {
    <#
    .SYNOPSIS
        Adopts server-pushed settings into agent.config.json (whitelist only); returns whether anything changed.
    .DESCRIPTION
        Only heartbeat_sec, scan_interval_sec, allowed_ids and alert_throttle_min are read from ServerConfig.
        shared_secret, hub_url, trusted_server_thumbprint, device_id and device_token can never be changed by this function.
    .PARAMETER Path
        Path to agent.config.json.
    .PARAMETER ServerConfig
        The config object from the heartbeat response.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter()][AllowNull()][object]$ServerConfig
    )
    if ($null -eq $ServerConfig) { return $false }
    $file = Read-ScgJsonFile -Path $Path
    $changed = $false

    $ranges = @{ heartbeat_sec = @(5, 86400); scan_interval_sec = @(5, 86400); alert_throttle_min = @(0, 10080) }
    foreach ($key in @('heartbeat_sec', 'scan_interval_sec', 'alert_throttle_min')) {
        $incoming = Get-ScgProp $ServerConfig $key $null
        if ($null -eq $incoming) { continue }
        $n = 0
        if (-not [int]::TryParse([string]$incoming, [ref]$n)) { continue }
        if ($n -lt $ranges[$key][0] -or $n -gt $ranges[$key][1]) { continue }
        $current = Get-ScgProp $file $key $null
        if ($null -eq $current -or [int]$current -ne $n) {
            Set-ScgProp -InputObject $file -Name $key -Value $n
            $changed = $true
        }
    }

    $hasIds = $false
    if ($ServerConfig -is [System.Collections.IDictionary]) { $hasIds = $ServerConfig.Contains('allowed_ids') }
    else { $hasIds = ($null -ne $ServerConfig.PSObject.Properties['allowed_ids']) }
    if ($hasIds) {
        $incomingIds = Get-ScgList $ServerConfig 'allowed_ids' @()
        $newIds = ConvertTo-ScgIdArray -Value $incomingIds -SkipInvalid
        $oldIds = ConvertTo-ScgIdArray -Value (Get-ScgList $file 'allowed_ids' @()) -SkipInvalid
        if ($newIds.Count -eq 0) {
            Write-ScgLog -Message 'Rejected pushed allowed_ids: empty or no valid instance id; keeping the local list' -Level WARN -Actor 'system' -Action 'heartbeat.config_change' -Result 'rejected'
        }
        elseif ((@($newIds) -join ',') -ne (@($oldIds) -join ',')) {
            Set-ScgProp -InputObject $file -Name 'allowed_ids' -Value ([string[]]@($newIds))
            $changed = $true
        }
    }

    if ($changed) {
        Save-ScgJsonFile -Path $Path -InputObject $file
        Write-ScgLog -Message 'Adopted server config' -Level INFO -Actor 'system' -Action 'heartbeat.config_change' -Result 'ok'
    }
    return $changed
}

function Initialize-ScgCertPin {
    <#
    .SYNOPSIS
        Compiles the thumbprint-pinning validation helper once per process.
    #>
    [CmdletBinding()]
    param()
    if ('ScgCertPin' -as [type]) { return }
    $src = @'
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ScgCertPin {
    private readonly string _thumb;
    public ScgCertPin(string thumb) { _thumb = thumb; }
    public bool Check(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        if (cert == null) { return false; }
        X509Certificate2 c = new X509Certificate2(cert);
        return string.Equals(c.Thumbprint, _thumb, StringComparison.OrdinalIgnoreCase);
    }
    public RemoteCertificateValidationCallback Callback() {
        return new RemoteCertificateValidationCallback(Check);
    }
}
'@
    Add-Type -TypeDefinition $src
}

function Invoke-HubApi {
    <#
    .SYNOPSIS
        Sole HTTP client of the agent: signed JSON request to the hub (TLS 1.2, optional thumbprint pin, 30 s timeout).
    .PARAMETER Config
        Agent config (hub_url, shared_secret, trusted_server_thumbprint).
    .PARAMETER Method
        GET or POST.
    .PARAMETER Path
        Endpoint path such as /heartbeat (appended to hub_url + /api/v1).
    .PARAMETER Body
        Optional object serialized as UTF-8 JSON.
    .PARAMETER DeviceToken
        Per-device token sent as X-SCG-Device-Token, only on /heartbeat, /result and /event (never on /enroll or /health).
    .OUTPUTS
        The parsed JSON response; throws on network or non-2xx errors (message never contains the secret or the device token).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter()][AllowNull()][object]$Body,
        [Parameter()][AllowNull()][AllowEmptyString()][string]$DeviceToken
    )
    $secret = [string](Get-ScgProp $Config 'shared_secret' '')
    $sendToken = (-not [string]::IsNullOrEmpty($DeviceToken)) -and ($script:DeviceTokenPath -ccontains $Path)
    $base = ([string](Get-ScgProp $Config 'hub_url' '')).TrimEnd('/')
    $url = $base + '/api/v1' + $Path
    $thumb = ([string](Get-ScgProp $Config 'trusted_server_thumbprint' '') -replace '[\s:]', '')

    try {
        $tls12 = [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor $tls12

        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = $Method
        $req.Timeout = $script:HubTimeoutMs
        $req.ReadWriteTimeout = $script:HubTimeoutMs
        $req.Accept = 'application/json'
        $req.UserAgent = 'SCGuardian-Agent/' + $script:AgentVersion
        $req.Headers.Add('Authorization', 'Bearer ' + $secret)
        $req.Headers.Add('X-SCG-Timestamp', (Get-ScgUtcNow))
        $req.Headers.Add('X-SCG-Nonce', (New-ScgGuid))
        if ($sendToken) { $req.Headers.Add('X-SCG-Device-Token', $DeviceToken) }

        if ($req.RequestUri.Scheme -eq 'https') {
            if ($thumb) {
                Initialize-ScgCertPin
                $pin = New-Object ScgCertPin -ArgumentList $thumb
                $req.ServerCertificateValidationCallback = $pin.Callback()
            }
            elseif (-not $script:PinWarned) {
                $script:PinWarned = $true
                Write-ScgLog -Message 'trusted_server_thumbprint not set: dev-mode accepts any valid TLS certificate' -Level WARN
            }
        }

        if ($Method -eq 'POST') {
            $json = '{}'
            if ($null -ne $Body) { $json = ConvertTo-Json -InputObject $Body -Depth 8 -Compress }
            $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
            $req.ContentType = 'application/json; charset=utf-8'
            $req.ContentLength = $bytes.Length
            $rs = $req.GetRequestStream()
            try { $rs.Write($bytes, 0, $bytes.Length) } finally { $rs.Dispose() }
        }

        $resp = $null
        $status = 0
        try {
            $resp = $req.GetResponse()
            $status = [int]$resp.StatusCode
        }
        catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($null -eq $resp) { throw }
            $status = [int]$resp.StatusCode
        }
        $text = ''
        try {
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
            try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        finally { $resp.Dispose() }

        $parsed = $null
        if ($text) { try { $parsed = $text | ConvertFrom-Json } catch { $parsed = $null } }
        if ($status -lt 200 -or $status -ge 300) {
            $detail = [string](Get-ScgProp $parsed 'error' '')
            throw "hub http ${status}: $detail"
        }
        return $parsed
    }
    catch {
        throw (Protect-Secret -Text $_.Exception.Message -Secret @($secret, $DeviceToken))
    }
}

function New-ScgAgentState {
    <#
    .SYNOPSIS
        Returns an empty agent state object.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param()
    if (-not $PSCmdlet.ShouldProcess('agent state', 'Create')) { return }
    return [pscustomobject]@{
        consecutive_failures = 0
        next_heartbeat_utc   = $null
        last_failure_log_utc = $null
        alerts               = [pscustomobject]@{}
    }
}

function Read-ScgAgentState {
    <#
    .SYNOPSIS
        Loads agent.state.json (missing or corrupt file gives a fresh state).
    .PARAMETER Path
        State file path.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)
    $state = New-ScgAgentState
    if (-not (Test-Path -LiteralPath $Path)) { return $state }
    try {
        $raw = Read-ScgJsonFile -Path $Path
        $state.consecutive_failures = [int](Get-ScgProp $raw 'consecutive_failures' 0)
        $state.next_heartbeat_utc = Get-ScgProp $raw 'next_heartbeat_utc' $null
        $state.last_failure_log_utc = Get-ScgProp $raw 'last_failure_log_utc' $null
        $alerts = Get-ScgProp $raw 'alerts' $null
        if ($null -ne $alerts) { $state.alerts = $alerts }
    }
    catch {
        Write-ScgLog -Message 'agent.state.json unreadable, starting fresh' -Level WARN
    }
    return $state
}

function Update-ScgBackoffState {
    <#
    .SYNOPSIS
        Applies a hub success or failure to the state: failure counter, next heartbeat time, rate-limited logging.
    .DESCRIPTION
        3 or more consecutive failures push the next heartbeat to max(HeartbeatSec, 300) s. A failure is logged at most once per
        10 minutes; the first success after failures resets the counter and logs recovery once.
    .PARAMETER State
        State object (consecutive_failures, next_heartbeat_utc, last_failure_log_utc, alerts).
    .PARAMETER Success
        Present when the hub exchange succeeded.
    .PARAMETER Now
        Injectable clock (UTC).
    .PARAMETER HeartbeatSec
        Normal heartbeat interval.
    .PARAMETER Reason
        Failure reason text (already secret-masked by the caller).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$State,
        [switch]$Success,
        [Parameter()][datetime]$Now = [datetime]::UtcNow,
        [Parameter()][int]$HeartbeatSec = 60,
        [Parameter()][string]$Reason = ''
    )
    if (-not $PSCmdlet.ShouldProcess('agent state', 'Update backoff')) { return $State }
    $nowUtc = $Now.ToUniversalTime()
    $failures = [int](Get-ScgProp $State 'consecutive_failures' 0)

    if ($Success) {
        if ($failures -gt 0) {
            Write-ScgLog -Message "Hub reachable again after $failures failure(s)" -Level INFO -Result 'recovered'
        }
        Set-ScgProp -InputObject $State -Name 'consecutive_failures' -Value 0
        Set-ScgProp -InputObject $State -Name 'last_failure_log_utc' -Value $null
        $next = $nowUtc.AddSeconds($HeartbeatSec)
    }
    else {
        $failures++
        Set-ScgProp -InputObject $State -Name 'consecutive_failures' -Value $failures
        $lastLog = Get-ScgProp $State 'last_failure_log_utc' $null
        $shouldLog = $true
        if ($lastLog) {
            $age = ($nowUtc - (ConvertFrom-ScgUtcIso -Value ([string]$lastLog))).TotalMinutes
            if ($age -lt $script:FailureLogGapMin) { $shouldLog = $false }
        }
        if ($shouldLog) {
            Write-ScgLog -Message "Hub exchange failed (consecutive=$failures): $Reason" -Level WARN -Result 'failed'
            Set-ScgProp -InputObject $State -Name 'last_failure_log_utc' -Value (ConvertTo-ScgUtcIso -InputObject $nowUtc)
        }
        $maxSec = [math]::Max($script:BackoffMaxSec, $HeartbeatSec)
        $delay = Get-ScgBackoffSec -Failures $failures -BaseSec $HeartbeatSec -MaxSec $maxSec
        if ($failures -ge 3) { $delay = [int]$maxSec }
        $next = $nowUtc.AddSeconds($delay)
    }
    Set-ScgProp -InputObject $State -Name 'next_heartbeat_utc' -Value (ConvertTo-ScgUtcIso -InputObject $next)
    return $State
}

function Get-ScgNextDelaySec {
    <#
    .SYNOPSIS
        Seconds the scheduler loop should sleep: the sooner of the scan interval and the next heartbeat (min 1).
    .PARAMETER ConfigPath
        Path to agent.config.json (state is read from agent.state.json under the SCG root).
    .PARAMETER Config
        Already loaded config (use with State).
    .PARAMETER State
        Already loaded state (use with Config).
    .PARAMETER Now
        Injectable clock (UTC).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([int])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$ConfigPath,
        [Parameter(Mandatory, ParameterSetName = 'Object')][object]$Config,
        [Parameter(Mandatory, ParameterSetName = 'Object')][object]$State,
        [Parameter()][datetime]$Now = [datetime]::UtcNow
    )
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $Config = Get-ScgAgentConfig -Path $ConfigPath
        $State = Read-ScgAgentState -Path (Join-Path (Get-ScgRoot) 'agent.state.json')
    }
    $nowUtc = $Now.ToUniversalTime()
    $delay = [double][int](Get-ScgProp $Config 'scan_interval_sec' 30)
    $next = Get-ScgProp $State 'next_heartbeat_utc' $null
    if ($next) {
        $untilHb = ((ConvertFrom-ScgUtcIso -Value ([string]$next)) - $nowUtc).TotalSeconds
        if ($untilHb -lt $delay) { $delay = $untilHb }
    }
    return [int][math]::Max(1, [math]::Ceiling($delay))
}

function Invoke-ScgLocalWatchdog {
    <#
    .SYNOPSIS
        Hub-independent local watchdog (legacy Monitor): restart my stopped service, force Automatic start, re-harden.
    .PARAMETER Config
        Agent config (local_watchdog, allowed_ids, layers, take_ownership).
    .OUTPUTS
        Findings: objects with Id, Service, Detail (restarted, start_failed, missing). A clean cycle emits nothing;
        callers wrap the call in @() and keep PSCustomObject items only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Config)
    $findings = New-Object System.Collections.Generic.List[object]
    if (-not [bool](Get-ScgProp $Config 'local_watchdog' $false)) { return }

    $backupDir = Join-Path (Get-ScgRoot) 'Backup'
    $agents = @(Get-ScAgent -AllowedId ([string[]](Get-ScgList $Config 'allowed_ids' @())))
    $mine = @($agents | Where-Object { $_.Authorized })
    foreach ($a in $mine) {
        if (-not $a.ServiceName) {
            Write-ScgLog -Message "MY agent service is MISSING (id=$($a.Id))" -Level ERROR -Target ([string]$a.Id) -Action 'watchdog'
            $findings.Add([pscustomobject]@{ Id = [string]$a.Id; Service = ''; Detail = 'missing' })
        }
        else {
            $svc = Get-Service -Name $a.ServiceName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Running') {
                try {
                    Start-Service -Name $a.ServiceName -ErrorAction Stop
                    Write-ScgLog -Message "Watchdog restarted my agent (was $($svc.Status))" -Level WARN -Target ([string]$a.Id) -Action 'watchdog' -Result 'restarted'
                    $findings.Add([pscustomobject]@{ Id = [string]$a.Id; Service = [string]$a.ServiceName; Detail = 'restarted' })
                }
                catch {
                    Write-ScgLog -Message "Watchdog FAILED to start my agent: $($_.Exception.Message)" -Level ERROR -Target ([string]$a.Id) -Action 'watchdog' -Result 'failed'
                    $findings.Add([pscustomobject]@{ Id = [string]$a.Id; Service = [string]$a.ServiceName; Detail = 'start_failed' })
                }
            }
            if ($svc -and $svc.StartType -ne 'Automatic') {
                try { Set-Service -Name $a.ServiceName -StartupType Automatic -ErrorAction Stop }
                catch { Write-ScgLog -Message "Could not set StartType Automatic: $($_.Exception.Message)" -Level WARN -Target ([string]$a.Id) }
            }
        }
        $layers = (Get-ScgList $Config 'layers' @())
        if ($layers.Count -gt 0) {
            $null = Invoke-ScHardening -Agent $a -Layer ([string[]]$layers) -BackupDir $backupDir -TakeOwnership:([bool](Get-ScgProp $Config 'take_ownership' $false))
        }
    }
    foreach ($f in $findings) { $f }
}

function Select-ScgFinding {
    <#
    .SYNOPSIS
        Keeps only real watchdog findings (PSCustomObject with Detail) from raw pipeline output.
    .PARAMETER InputObject
        Raw items.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object[]]$InputObject)
    foreach ($i in @($InputObject)) {
        if ($null -eq $i) { continue }
        if ($i -isnot [System.Management.Automation.PSCustomObject]) { continue }
        if ($null -eq $i.PSObject.Properties['Detail']) { continue }
        $i
    }
}

function ConvertTo-ScgCommandPayload {
    <#
    .SYNOPSIS
        Normalizes a command payload (object, JSON string or null) to an object.
    .PARAMETER Payload
        Raw payload from the heartbeat response.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Payload)
    if ($null -eq $Payload) { return $null }
    if ($Payload -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Payload)) { return $null }
        try { return ($Payload | ConvertFrom-Json) } catch { return $null }
    }
    return $Payload
}

function Invoke-ScgAgentCommand {
    <#
    .SYNOPSIS
        Executes one hub command (harden, restore, remove, status, agents, ping) and returns ok/output.
    .DESCRIPTION
        Payload may carry sc_id (16 hex) to target one agent; harden and restore without sc_id target all of my agents;
        remove requires sc_id and goes only through Remove-ScAgent, which refuses allow-listed agents.
    .PARAMETER Command
        Object with id, type, payload.
    .PARAMETER Config
        Agent config.
    .PARAMETER PreviousAllowedId
        Allow list in force before this cycle's config update; the effective list is the UNION with Config.allowed_ids,
        so a same-heartbeat shrink can never authorise removing one of my agents.
    .OUTPUTS
        Hashtable with ok (bool) and output (string).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$Command,
        [Parameter(Mandatory)][object]$Config,
        [Parameter()][AllowNull()][AllowEmptyCollection()][string[]]$PreviousAllowedId
    )
    $type = [string](Get-ScgProp $Command 'type' '')
    $payload = ConvertTo-ScgCommandPayload -Payload (Get-ScgProp $Command 'payload' $null)
    $idPool = New-Object System.Collections.Generic.List[object]
    foreach ($i in (Get-ScgList $Config 'allowed_ids' @())) { $idPool.Add($i) }
    foreach ($i in @($PreviousAllowedId)) { if ($null -ne $i) { $idPool.Add($i) } }
    $allowed = ConvertTo-ScgIdArray -Value $idPool.ToArray() -SkipInvalid
    $backupDir = Join-Path (Get-ScgRoot) 'Backup'
    try {
        if ($type -eq 'ping') { return @{ ok = $true; output = 'pong' } }

        $agents = @(Get-ScAgent -AllowedId $allowed)
        $mine = @($agents | Where-Object { $_.Authorized })
        $targetId = [string](Get-ScgProp $payload 'sc_id' '')
        $target = $null
        if ($targetId) {
            try { $targetId = ConvertTo-ScgInstanceId -Id $targetId }
            catch { return @{ ok = $false; output = 'invalid agent id in payload' } }
        }

        switch ($type) {
            'status' {
                $running = @($mine | Where-Object { $_.ServiceState -eq 'Running' }).Count
                $unknown = @($agents | Where-Object { -not $_.Authorized }).Count
                return @{ ok = $true; output = "mine=$($mine.Count) running=$running unknown=$unknown" }
            }
            'agents' {
                $lines = @($agents | ForEach-Object { "$($_.Id) service=$($_.ServiceName) state=$($_.ServiceState) mine=$($_.Authorized)" })
                return @{ ok = $true; output = ($lines -join "`n") }
            }
            'harden' {
                $layers = [string[]]@(foreach ($l in (Get-ScgList $Config 'layers' @())) { if ($null -ne $l -and [string]$l) { [string]$l } })
                if ($layers.Count -eq 0) { return @{ ok = $false; output = 'no layers configured' } }
                $set = @($mine)
                if ($targetId) { $set = @($mine | Where-Object { $_.Id -ieq $targetId }) }
                if ($set.Count -eq 0) { return @{ ok = $false; output = 'no matching agent of mine' } }
                foreach ($a in $set) {
                    $null = Invoke-ScHardening -Agent $a -Layer $layers -BackupDir $backupDir -TakeOwnership:([bool](Get-ScgProp $Config 'take_ownership' $false))
                }
                return @{ ok = $true; output = "hardened $($set.Count) agent(s)" }
            }
            'restore' {
                $set = @($mine)
                if ($targetId) { $set = @($mine | Where-Object { $_.Id -ieq $targetId }) }
                if ($set.Count -eq 0) { return @{ ok = $false; output = 'no matching agent of mine' } }
                $allOk = $true
                $msgs = New-Object System.Collections.Generic.List[string]
                foreach ($a in $set) {
                    $r = Invoke-ScRestore -Agent $a -BackupDir $backupDir
                    if (-not [bool](Get-ScgProp $r 'Ok' $false)) { $allOk = $false }
                    foreach ($m in (Get-ScgList $r 'Messages' @())) { $msgs.Add([string]$m) }
                }
                return @{ ok = $allOk; output = ($msgs -join "`n") }
            }
            'remove' {
                if (-not $targetId) { return @{ ok = $false; output = 'remove requires payload sc_id' } }
                $target = @($agents | Where-Object { $_.Id -ieq $targetId }) | Select-Object -First 1
                if ($allowed -contains $targetId) { return @{ ok = $false; output = "refused: $targetId is allow-listed (one of YOURS)" } }
                if (-not $target) { return @{ ok = $false; output = "agent $targetId not found" } }
                if ([bool](Get-ScgProp $target 'Authorized' $false)) { return @{ ok = $false; output = "refused: $targetId is authorized (one of YOURS)" } }
                $res = [string](Remove-ScAgent -Agent $target -AllowedId $allowed -BackupDir $backupDir)
                $failed = $res -match '^(refused|aborted):'
                return @{ ok = (-not $failed); output = $res }
            }
            default { return @{ ok = $false; output = "unsupported command type: $type" } }
        }
    }
    catch {
        return @{ ok = $false; output = (Protect-Secret -Text $_.Exception.Message -Secret @([string](Get-ScgProp $Config 'shared_secret' ''))) }
    }
}

function Send-ScgEvent {
    <#
    .SYNOPSIS
        Posts one event to the hub; failures are logged and swallowed (the hub dedupes).
    .PARAMETER Config
        Agent config (device_id is set).
    .PARAMETER Type
        Event type.
    .PARAMETER Severity
        info, warn or critical.
    .PARAMETER Payload
        Stable payload (no timestamps, so dedupe works).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][object]$Payload
    )
    if (-not $PSCmdlet.ShouldProcess($Type, 'Post event')) { return $false }
    try {
        $null = Invoke-HubApi -Config $Config -Method POST -Path '/event' -DeviceToken ([string](Get-ScgProp $Config 'device_token' '')) -Body @{
            device_id = [string]$Config.device_id
            type      = $Type
            severity  = $Severity
            payload   = $Payload
        }
        return $true
    }
    catch {
        Write-ScgLog -Message "event $Type not delivered: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Reset-ScgAgentIdentity {
    <#
    .SYNOPSIS
        Clears device_id and device_token in agent.config.json (atomic save) so the next cycle re-enrolls; returns success.
    .PARAMETER ConfigPath
        Path to agent.config.json.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$ConfigPath)
    if (-not $PSCmdlet.ShouldProcess($ConfigPath, 'Clear device identity')) { return $false }
    try {
        $file = Read-ScgJsonFile -Path $ConfigPath
        Set-ScgProp -InputObject $file -Name 'device_id' -Value $null
        Set-ScgProp -InputObject $file -Name 'device_token' -Value $null
        Save-ScgJsonFile -Path $ConfigPath -InputObject $file
        return $true
    }
    catch { return $false }
}

function Invoke-ScgAgentCycle {
    <#
    .SYNOPSIS
        One agent cycle: local watchdog, enroll if needed, heartbeat, adopt config, commands, results, events.
    .DESCRIPTION
        The watchdog always runs first and never depends on the hub. The hub exchange runs only when a heartbeat
        is due (or -Force); hub errors feed the backoff state and never stop the cycle from returning.
    .PARAMETER ConfigPath
        Path to agent.config.json.
    .PARAMETER Now
        Injectable clock (UTC).
    .PARAMETER Force
        Run the hub exchange even if the next heartbeat is not yet due.
    .OUTPUTS
        Summary object (HubOk, HubAttempted, Enrolled, Commands, Events, Findings).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter()][datetime]$Now = [datetime]::UtcNow,
        [switch]$Force
    )
    $nowUtc = $Now.ToUniversalTime()
    $root = Get-ScgRoot
    $statePath = Join-Path $root 'agent.state.json'
    $backupDir = Join-Path $root 'Backup'
    $null = Initialize-ScgSecureDirectory -Path $root
    $null = Initialize-ScgSecureDirectory -Path $backupDir
    $config = Get-ScgAgentConfig -Path $ConfigPath
    $state = Read-ScgAgentState -Path $statePath
    $secret = [string]$config.shared_secret
    Add-ScgLogSecret -Secret @($secret, [string]$config.device_token)

    $summary = [pscustomobject]@{ HubAttempted = $false; HubOk = $false; Enrolled = $false; Commands = 0; Events = 0; Findings = @() }

    try {
        $rawFindings = @(Invoke-ScgLocalWatchdog -Config $config)
        $summary.Findings = @(Select-ScgFinding -InputObject $rawFindings)
    }
    catch { Write-ScgLog -Message "watchdog error: $($_.Exception.Message)" -Level ERROR -Action 'watchdog' }

    $due = $Force.IsPresent
    if (-not $due) {
        $next = Get-ScgProp $state 'next_heartbeat_utc' $null
        if (-not $next) { $due = $true }
        elseif ((ConvertFrom-ScgUtcIso -Value ([string]$next)) -le $nowUtc) { $due = $true }
    }
    if (-not $due) { return $summary }

    $summary.HubAttempted = $true
    $phase = 'heartbeat'
    try {
        if (-not $config.device_id) {
            $phase = 'enroll'
            $enr = Invoke-HubApi -Config $config -Method POST -Path '/enroll' -Body @{
                hostname      = $config.hostname
                os            = 'windows'
                os_version    = [System.Environment]::OSVersion.Version.ToString()
                agent_version = $script:AgentVersion
            }
            $newId = [string](Get-ScgProp $enr 'device_id' '')
            $newToken = [string](Get-ScgProp $enr 'device_token' '')
            if ([string]::IsNullOrWhiteSpace($newId)) { throw 'enroll response has no device_id' }
            if ([string]::IsNullOrWhiteSpace($newToken)) { throw 'enroll response has no device_token' }
            Add-ScgLogSecret -Secret @($newToken)
            $file = Read-ScgJsonFile -Path $ConfigPath
            Set-ScgProp -InputObject $file -Name 'device_id' -Value $newId
            Set-ScgProp -InputObject $file -Name 'device_token' -Value $newToken
            Save-ScgJsonFile -Path $ConfigPath -InputObject $file
            $config.device_id = $newId
            $config.device_token = $newToken
            $summary.Enrolled = $true
            Write-ScgLog -Message 'Enrolled with hub' -Level INFO -Actor 'system' -Action 'enroll' -Result 'ok'
            $phase = 'heartbeat'
        }

        $discoveryOk = $true
        $hbAgents = @()
        try {
            $agents = @(Get-ScAgent -AllowedId @($config.allowed_ids))
            $hbAgents = @($agents | ForEach-Object { ConvertTo-ScHeartbeatAgent -Agent $_ })
        }
        catch {
            $discoveryOk = $false
            $hbAgents = @()
            Write-ScgLog -Message "discovery failed: $($_.Exception.Message)" -Level ERROR -Action 'discovery'
        }
        $uptime = [int][math]::Max(0, ($nowUtc - $script:ProcessStartUtc).TotalSeconds)
        $hb = Invoke-HubApi -Config $config -Method POST -Path '/heartbeat' -DeviceToken ([string]$config.device_token) -Body @{
            device_id     = [string]$config.device_id
            hostname      = $config.hostname
            sc_agents     = $hbAgents
            discovery_ok  = $discoveryOk
            uptime_sec    = $uptime
            agent_version = $script:AgentVersion
        }

        $preIds = [string[]]@($config.allowed_ids)
        if (Update-ScgAgentConfig -Path $ConfigPath -ServerConfig (Get-ScgProp $hb 'config' $null)) {
            $fresh = Get-ScgAgentConfig -Path $ConfigPath
            $fresh.device_id = $config.device_id
            $fresh.device_token = $config.device_token
            $config = $fresh
        }

        foreach ($cmd in (Get-ScgList $hb 'commands' @())) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $res = Invoke-ScgAgentCommand -Command $cmd -Config $config -PreviousAllowedId $preIds
            $sw.Stop()
            $out = [string](Get-ScgProp $res 'output' '')
            if ($out.Length -gt 16000) { $out = $out.Substring(0, 16000) }
            try {
                $null = Invoke-HubApi -Config $config -Method POST -Path '/result' -DeviceToken ([string]$config.device_token) -Body @{
                    device_id   = [string]$config.device_id
                    command_id  = Get-ScgProp $cmd 'id' $null
                    ok          = [bool](Get-ScgProp $res 'ok' $false)
                    output      = $out
                    duration_ms = [int]$sw.ElapsedMilliseconds
                }
                $summary.Commands++
            }
            catch {
                Write-ScgLog -Message "result not delivered: $($_.Exception.Message)" -Level WARN -Action 'command.result'
            }
        }

        $live = @()
        if ($discoveryOk) {
            try { $live = @(Get-ScAgent -AllowedId @($config.allowed_ids)) }
            catch { Write-ScgLog -Message "discovery failed before events: $($_.Exception.Message)" -Level ERROR -Action 'discovery' }
        }
        foreach ($u in @($live | Where-Object { -not $_.Authorized })) {
            if (Send-ScgEvent -Config $config -Type 'unknown_agent' -Severity 'warn' -Payload @{ sc_id = [string]$u.Id; service = [string]$u.ServiceName; folder = [string]$u.Folder }) { $summary.Events++ }
        }
        foreach ($m in @($live | Where-Object { $_.Authorized -and $_.ServiceName })) {
            $tampered = $false
            try { $tampered = [bool](Test-ScTamper -Agent $m -BackupDir $backupDir) }
            catch { Write-ScgLog -Message "tamper check failed: $($_.Exception.Message)" -Level WARN }
            if ($tampered) {
                if (Send-ScgEvent -Config $config -Type 'tamper' -Severity 'critical' -Payload @{ sc_id = [string]$m.Id; service = [string]$m.ServiceName }) { $summary.Events++ }
            }
        }
        foreach ($f in @($summary.Findings)) {
            $sev = 'warn'
            if ($f.Detail -eq 'restarted') { $sev = 'info' }
            if (Send-ScgEvent -Config $config -Type 'service_down' -Severity $sev -Payload @{ sc_id = $f.Id; service = $f.Service; detail = $f.Detail }) { $summary.Events++ }
        }

        $state = Update-ScgBackoffState -State $state -Success -Now $nowUtc -HeartbeatSec $config.heartbeat_sec
        $summary.HubOk = $true
    }
    catch {
        $reason = Protect-Secret -Text $_.Exception.Message -Secret @($secret, [string]$config.device_token)
        if ($reason -ceq $script:ErrNotEnrolled -and $config.device_id) {
            if (Reset-ScgAgentIdentity -ConfigPath $ConfigPath) {
                Write-ScgLog -Message 'Hub reports this device is not enrolled (operator reset): cleared device_id and device_token, re-enrolling on the next cycle' -Level INFO -Actor 'system' -Action 'enroll' -Result 'reset'
            }
            else { Write-ScgLog -Message 'could not clear device_id and device_token after device not enrolled' -Level WARN }
            Set-ScgProp -InputObject $state -Name 'next_heartbeat_utc' -Value $null
        }
        else {
            if ($reason -ceq $script:ErrUnknownDevice -and $config.device_id) {
                if (-not (Reset-ScgAgentIdentity -ConfigPath $ConfigPath)) { Write-ScgLog -Message 'could not reset device_id after 404' -Level WARN }
            }
            elseif ($reason -ceq $script:ErrBadToken) {
                $reason = $reason + ' (device token rejected; an operator must /reset this device)'
            }
            elseif ($phase -eq 'enroll' -and $reason -ceq $script:ErrEnrollConflict) {
                $reason = 'hostname already enrolled; ask the operator to /reset this device'
            }
            $state = Update-ScgBackoffState -State $state -Now $nowUtc -HeartbeatSec $config.heartbeat_sec -Reason $reason
        }
    }
    try { Save-ScgJsonFile -Path $statePath -InputObject $state }
    catch { Write-ScgLog -Message "state not saved: $($_.Exception.Message)" -Level WARN }
    return $summary
}

Export-ModuleMember -Function Get-ScgAgentConfig, Update-ScgAgentConfig, Invoke-HubApi, Invoke-ScgAgentCycle, Invoke-ScgAgentCommand, Invoke-ScgLocalWatchdog, Update-ScgBackoffState, Get-ScgNextDelaySec
