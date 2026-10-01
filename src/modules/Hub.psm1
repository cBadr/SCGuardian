<#
.SYNOPSIS
    SCGuardian Hub: config loading, the five API handlers, maintenance tick and the HTTP/ticker/Telegram host.
.DESCRIPTION
    Purpose : server side of SCGuardian. Pure handlers (Config + Body in, @{Status;Body} out) over Database
              functions only (no SQL here), a route table for HttpServer, and Start-ScgHub which runs the HTTP
              listener, a maintenance ticker and the Telegram long-poll loop in separate runspaces.
    Author  : Badr
    Version : 4.0.0
    Depends : Common.psm1, Database.psm1, HttpServer.psm1, Telegram.psm1
    Note    : the Hub does not harden itself (no Hardening import). Every behaviour value comes from
              hub.config.json (ticker period: defaults.tick_sec; Telegram error pause:
              defaults.telegram_error_pause_sec); the only constant here is the contract version string.
#>

Set-StrictMode -Version 2.0

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'Database.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'HttpServer.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'Telegram.psm1') -DisableNameChecking

$script:HubModulePath = $PSCommandPath
if (-not $script:HubModulePath) { $script:HubModulePath = $MyInvocation.MyCommand.Path }
$script:HubModuleDir = Split-Path -Path $script:HubModulePath -Parent
$script:HubConfig = $null
$script:HubVersion = '4.0.0'
$script:HubStartUtc = [datetime]::UtcNow
$script:HubCommandTypeSet = @('harden', 'restore', 'remove', 'status', 'agents', 'ping')
$script:HubEventTypeSet = @('unknown_agent', 'new_install', 'tamper', 'agent_error', 'service_down')
$script:HubSeveritySet = @('info', 'warn', 'critical')

function Get-ScgHubValue {
<#
.SYNOPSIS
    Reads a property or dictionary key; returns null when absent.
.PARAMETER Object
    PSCustomObject or dictionary (may be null).
.PARAMETER Name
    Property or key name.
#>
    [CmdletBinding()]
    param([AllowNull()]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-ScgHubHas {
<#
.SYNOPSIS
    True when the property or dictionary key exists (even with a null value).
.PARAMETER Object
    PSCustomObject or dictionary (may be null).
.PARAMETER Name
    Property or key name.
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return [bool]$Object.Contains($Name) }
    return [bool]($Object.PSObject.Properties[$Name])
}

function Get-ScgHubText {
<#
.SYNOPSIS
    Returns the trimmed string value of a field, or null when absent, not a string or blank.
.PARAMETER Object
    Source object or dictionary.
.PARAMETER Name
    Field name.
#>
    [CmdletBinding()]
    param([AllowNull()]$Object, [Parameter(Mandatory)][string]$Name)
    $v = Get-ScgHubValue -Object $Object -Name $Name
    if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim() }
    return $null
}

function Get-ScgHubSetting {
<#
.SYNOPSIS
    Reads Section.Key from a hub config (object or dictionary) with a fallback.
.PARAMETER Config
    Hub config.
.PARAMETER Section
    Section name.
.PARAMETER Key
    Key name.
.PARAMETER Default
    Value returned when absent.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key,
        [AllowNull()]$Default = $null
    )
    $sec = Get-ScgHubValue -Object $Config -Name $Section
    $v = Get-ScgHubValue -Object $sec -Name $Key
    if ($null -eq $v) { return $Default }
    return $v
}

function New-ScgHubResult {
<#
.SYNOPSIS
    Builds the handler result @{Status;Body}.
.PARAMETER Status
    HTTP status.
.PARAMETER Body
    Response body.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][int]$Status, [AllowNull()]$Body)
    return @{ Status = $Status; Body = $Body }
}

function New-ScgHubError {
<#
.SYNOPSIS
    Builds an error result with the registry error shape.
.PARAMETER Status
    HTTP status.
.PARAMETER Message
    Error text (no secrets).
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][int]$Status, [Parameter(Mandatory)][string]$Message)
    return @{ Status = $Status; Body = [ordered]@{ ok = $false; error = $Message } }
}

function ConvertTo-ScgHubIdList {
<#
.SYNOPSIS
    Normalises agent ids to lowercase 16-hex; throws on an invalid entry. De-duplicates.
.PARAMETER Id
    Candidate ids.
#>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()]$Id)
    $out = New-Object System.Collections.ArrayList
    foreach ($i in @($Id)) {
        if ($null -eq $i) { continue }
        $n = ConvertTo-ScgInstanceId -Id ([string]$i)
        if (-not $out.Contains($n)) { [void]$out.Add($n) }
    }
    return [string[]]$out.ToArray()
}

function Get-ScgHubConfig {
<#
.SYNOPSIS
    Loads and validates hub.config.json, filling defaults.
.DESCRIPTION
    Throws one error listing every problem (never the secret values). Rejects REPLACE_ME placeholders in
    shared_secret and telegram.bot_token only. Optional defaults.tick_sec and defaults.telegram_error_pause_sec
    drive the ticker period and the Telegram error pause. allowed_ids are normalised to lowercase 16-hex.
.PARAMETER Path
    Path of hub.config.json.
.OUTPUTS
    PSCustomObject with sections listen, telegram, database, defaults, logging and shared_secret.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $raw = Read-ScgJsonFile -Path $Path
    $errs = New-Object System.Collections.ArrayList

    $listen = Get-ScgHubValue -Object $raw -Name 'listen'
    $tg = Get-ScgHubValue -Object $raw -Name 'telegram'
    $db = Get-ScgHubValue -Object $raw -Name 'database'
    $def = Get-ScgHubValue -Object $raw -Name 'defaults'
    $log = Get-ScgHubValue -Object $raw -Name 'logging'

    $url = Get-ScgHubText -Object $listen -Name 'url'
    if (-not $url) { [void]$errs.Add('listen.url is required') }
    $thumb = Get-ScgHubText -Object $listen -Name 'cert_thumbprint'
    if (-not $thumb) { $thumb = 'auto' }

    $secret = Get-ScgHubText -Object $raw -Name 'shared_secret'
    if (-not $secret) { [void]$errs.Add('shared_secret is required') }
    $token = Get-ScgHubText -Object $tg -Name 'bot_token'
    if (-not $token) { [void]$errs.Add('telegram.bot_token is required') }
    $chat = $null
    $chatRaw = Get-ScgHubValue -Object $tg -Name 'chat_id'
    if ($null -ne $chatRaw -and -not [string]::IsNullOrWhiteSpace([string]$chatRaw)) { $chat = ([string]$chatRaw).Trim() }
    if (-not $chat) { [void]$errs.Add('telegram.chat_id is required') }
    foreach ($pair in @(@('shared_secret', $secret), @('telegram.bot_token', $token))) {
        if ($pair[1] -and ([string]$pair[1]) -match '(?i)REPLACE_ME') { [void]$errs.Add($pair[0] + ' still holds the REPLACE_ME placeholder') }
    }

    $adminIds = New-Object System.Collections.ArrayList
    foreach ($a in @(Get-ScgHubValue -Object $tg -Name 'admin_user_ids')) {
        if ($null -ne $a -and -not [string]::IsNullOrWhiteSpace([string]$a)) { [void]$adminIds.Add(([string]$a).Trim()) }
    }
    $adminNames = New-Object System.Collections.ArrayList
    foreach ($a in @(Get-ScgHubValue -Object $tg -Name 'admin_usernames')) {
        if ($null -ne $a -and -not [string]::IsNullOrWhiteSpace([string]$a)) { [void]$adminNames.Add(([string]$a).Trim()) }
    }
    if ($adminIds.Count -eq 0 -and $adminNames.Count -eq 0) { [void]$errs.Add('telegram.admin_user_ids or telegram.admin_usernames must list at least one admin') }
    if (($adminIds -join ' ') -match '(?i)REPLACE_ME') { [void]$errs.Add('telegram.admin_user_ids still holds the REPLACE_ME placeholder') }

    $dbPath = Get-ScgHubText -Object $db -Name 'path'
    if (-not $dbPath) { [void]$errs.Add('database.path is required') }
    $logPath = Get-ScgHubText -Object $log -Name 'path'
    if (-not $logPath) { $logPath = Join-Path (Get-ScgRoot) 'logs\hub.log' }

    $allowed = @()
    $allowedValid = $true
    try { $allowed = @(ConvertTo-ScgHubIdList -Id (Get-ScgHubValue -Object $def -Name 'allowed_ids')) }
    catch { $allowedValid = $false; [void]$errs.Add('defaults.allowed_ids holds an invalid id (expected 16 hex characters)') }
    if ($allowedValid -and $allowed.Count -eq 0) { [void]$errs.Add('defaults.allowed_ids must list at least one id (an empty list would strip protection fleet-wide)') }

    $ints = [ordered]@{}
    $intDefaults = [ordered]@{
        scan_interval_sec = 60; heartbeat_sec = 60; alert_throttle_min = 15; command_confirm_sec = 300
        stale_after_min = 5; command_timeout_sec = 300; nonce_ttl_sec = 600; max_skew_sec = 300
        tick_sec = 30; telegram_error_pause_sec = 5
    }
    foreach ($k in @($intDefaults.Keys)) {
        $v = Get-ScgHubValue -Object $def -Name $k
        if ($null -eq $v) { $ints[$k] = [int]$intDefaults[$k]; continue }
        $n = 0
        if (-not ([int]::TryParse([string]$v, [ref]$n)) -or $n -lt 1) {
            [void]$errs.Add("defaults.$k must be a positive integer")
            $ints[$k] = [int]$intDefaults[$k]
        }
        else { $ints[$k] = $n }
    }
    $maxBytes = 5242880
    $mb = Get-ScgHubValue -Object $log -Name 'max_bytes'
    if ($null -ne $mb) {
        $n = 0
        if (-not ([int]::TryParse([string]$mb, [ref]$n)) -or $n -lt 1) { [void]$errs.Add('logging.max_bytes must be a positive integer') }
        else { $maxBytes = $n }
    }

    if ($errs.Count -gt 0) { throw ('Invalid hub config: ' + ($errs.ToArray() -join '; ')) }

    $defaultsOut = [ordered]@{ allowed_ids = [string[]]$allowed }
    foreach ($k in @($ints.Keys)) { $defaultsOut[$k] = $ints[$k] }
    return [pscustomobject]@{
        listen        = [pscustomobject]@{ url = $url; cert_thumbprint = $thumb }
        shared_secret = $secret
        telegram      = [pscustomobject]@{
            bot_token        = $token
            chat_id          = $chat
            admin_user_ids   = [string[]]$adminIds.ToArray()
            admin_usernames  = [string[]]$adminNames.ToArray()
        }
        database      = [pscustomobject]@{ path = $dbPath }
        defaults      = [pscustomobject]$defaultsOut
        logging       = [pscustomobject]@{ path = $logPath; max_bytes = $maxBytes }
    }
}

function Write-ScgHubHostnameDrift {
<#
.SYNOPSIS
    Audits heartbeat.config_change once per change when a device reports a hostname different from the stored one.
.DESCRIPTION
    The stored hostname is authoritative and is never overwritten from a device report. Comparison is
    case-insensitive (Windows hostnames). A new audit row is written only when the newest
    heartbeat.config_change row for this device does not already record the same reported/stored pair.
.PARAMETER Db
    Database path.
.PARAMETER DeviceId
    Device id (audit target).
.PARAMETER Stored
    Hostname stored for the device.
.PARAMETER Reported
    Hostname reported in the request body.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DbPath,
        [Parameter(Mandatory)][string]$DeviceId,
        [AllowEmptyString()][string]$Stored = '',
        [AllowEmptyString()][string]$Reported = ''
    )
    if ([string]::IsNullOrEmpty($Reported)) { return }
    if ([string]::Equals($Stored, $Reported, [System.StringComparison]::OrdinalIgnoreCase)) { return }
    $meta = [ordered]@{ field = 'hostname'; reported = $Reported; stored = $Stored }
    $metaJson = ConvertTo-Json -InputObject $meta -Compress -Depth 3
    $last = Get-ScgLastAudit -Path $DbPath -Action 'heartbeat.config_change' -Target $DeviceId
    if ($null -ne $last -and [string](Get-ScgHubValue -Object $last -Name 'meta_json') -ceq $metaJson) { return }
    Add-ScgAudit -Path $DbPath -Actor ('device:' + $Stored) -Action 'heartbeat.config_change' -Target $DeviceId -Meta $metaJson
}

function Invoke-ScgEnroll {
<#
.SYNOPSIS
    POST /enroll: registers (or re-registers) a device and returns its id.
.PARAMETER Config
    Hub config.
.PARAMETER Body
    Parsed request body: hostname, os, os_version, agent_version.
.PARAMETER RemoteIp
    Caller IP.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Config, [AllowNull()]$Body, [string]$RemoteIp = '')
    $db = [string](Get-ScgHubSetting -Config $Config -Section 'database' -Key 'path')
    $hostname = Get-ScgHubText -Object $Body -Name 'hostname'
    $os = Get-ScgHubText -Object $Body -Name 'os'
    $osv = Get-ScgHubText -Object $Body -Name 'os_version'
    $av = Get-ScgHubText -Object $Body -Name 'agent_version'
    foreach ($f in @(@('hostname', $hostname), @('os', $os), @('os_version', $osv), @('agent_version', $av))) {
        if (-not $f[1]) { return (New-ScgHubError -Status 400 -Message ('missing or invalid field: ' + $f[0])) }
    }
    if ($hostname.Length -gt 255) { return (New-ScgHubError -Status 400 -Message 'hostname too long') }
    $reenroll = $false
    $existing = @(Get-ScgDevice -Path $db -Hostname $hostname)
    if ($existing.Count -gt 0 -and $null -ne $existing[0]) {
        $stale = [int](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'stale_after_min' -Default 5)
        if (Test-ScgDeviceOnline -Path $db -DeviceId ([string]$existing[0].id) -StaleAfterMin $stale) {
            Add-ScgAudit -Path $db -Actor 'system' -Action 'auth.reject' -Target $RemoteIp -Meta ([ordered]@{ reason = 'enroll_conflict'; hostname = $hostname })
            return (New-ScgHubError -Status 409 -Message 'hostname already enrolled and online')
        }
        $reenroll = $true
    }
    $dev = Register-ScgDevice -Path $db -Hostname $hostname -Os $os -OsVersion $osv -AgentVersion $av -LastIp $RemoteIp
    $meta = [ordered]@{ os = $os; os_version = $osv; agent_version = $av; ip = $RemoteIp }
    if ($reenroll) { $meta['reenroll'] = $true }
    Add-ScgAudit -Path $db -Actor ('device:' + $hostname) -Action 'enroll' -Target ([string]$dev.id) -Meta $meta
    return (New-ScgHubResult -Status 200 -Body ([ordered]@{ ok = $true; device_id = [string]$dev.id }))
}

function Invoke-ScgHeartbeat {
<#
.SYNOPSIS
    POST /heartbeat: touches the device, syncs its agents, returns dispatchable commands once plus config.
.PARAMETER Config
    Hub config.
.PARAMETER Body
    Parsed request body: device_id, hostname, sc_agents, uptime_sec, agent_version, optional discovery_ok
    (false means the agent's discovery failed: rows are never deleted for that beat).
.PARAMETER RemoteIp
    Caller IP.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Config, [AllowNull()]$Body, [string]$RemoteIp = '')
    $db = [string](Get-ScgHubSetting -Config $Config -Section 'database' -Key 'path')
    $deviceId = Get-ScgHubText -Object $Body -Name 'device_id'
    $hostname = Get-ScgHubText -Object $Body -Name 'hostname'
    if (-not $deviceId) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: device_id') }
    if (-not $hostname) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: hostname') }
    if (-not (Test-ScgHubHas -Object $Body -Name 'sc_agents')) { return (New-ScgHubError -Status 400 -Message 'missing field: sc_agents') }
    $rawAgents = Get-ScgHubValue -Object $Body -Name 'sc_agents'
    if ($rawAgents -is [string] -or $rawAgents -is [ValueType]) { return (New-ScgHubError -Status 400 -Message 'invalid field: sc_agents') }
    $explicitEmpty = $false
    if ($Body -is [System.Collections.IDictionary]) { $direct = $Body['sc_agents'] } else { $direct = $Body.PSObject.Properties['sc_agents'].Value }
    if ($direct -is [System.Array] -and $direct.Count -eq 0) { $explicitEmpty = $true }
    $discoveryOk = $true
    if (Test-ScgHubHas -Object $Body -Name 'discovery_ok') {
        $dv = Get-ScgHubValue -Object $Body -Name 'discovery_ok'
        if ($null -ne $dv) {
            if ($dv -isnot [bool]) { return (New-ScgHubError -Status 400 -Message 'invalid field: discovery_ok') }
            $discoveryOk = [bool]$dv
        }
    }
    $agents = New-Object System.Collections.ArrayList
    if ($null -ne $rawAgents) {
        foreach ($a in @($rawAgents)) {
            if ($null -eq $a) { return (New-ScgHubError -Status 400 -Message 'invalid sc_agents entry') }
            $rid = Get-ScgHubValue -Object $a -Name 'id'
            $nid = $null
            if ($rid -is [string]) { $nid = $rid.Trim().ToLowerInvariant() }
            if (-not $nid -or -not (Test-ScgInstanceId -Id $nid)) { return (New-ScgHubError -Status 400 -Message 'invalid sc_agents entry: id must be 16 hex characters') }
            [void]$agents.Add([pscustomobject]@{
                    id            = $nid
                    service       = [string](Get-ScgHubValue -Object $a -Name 'service')
                    folder        = [string](Get-ScgHubValue -Object $a -Name 'folder')
                    uninstall_key = [string](Get-ScgHubValue -Object $a -Name 'uninstall_key')
                    state         = [string](Get-ScgHubValue -Object $a -Name 'state')
                })
        }
    }

    $found = @(Get-ScgDevice -Path $db -DeviceId $deviceId)
    if ($found.Count -eq 0) { return (New-ScgHubError -Status 404 -Message 'unknown device') }

    $stored = [string](Get-ScgHubValue -Object $found[0] -Name 'hostname')
    Write-ScgHubHostnameDrift -DbPath $db -DeviceId $deviceId -Stored $stored -Reported $hostname
    $hostname = $stored
    $seen = @{ Path = $db; DeviceId = $deviceId }
    $av = Get-ScgHubText -Object $Body -Name 'agent_version'
    if ($av) { $seen['AgentVersion'] = $av }
    if (-not [string]::IsNullOrEmpty($RemoteIp)) { $seen['LastIp'] = $RemoteIp }
    [void](Update-ScgDeviceSeen @seen)

    $allowed = @(ConvertTo-ScgHubIdList -Id (Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'allowed_ids' -Default @()))
    $sync = @{ Path = $db; DeviceId = $deviceId; ScAgent = $agents.ToArray(); AllowedId = ([string[]]$allowed) }
    if ($explicitEmpty -and $discoveryOk) { $sync['AllowEmpty'] = $true }
    Sync-ScgScAgent @sync

    $commands = New-Object System.Collections.ArrayList
    foreach ($row in @(Get-ScgDispatchableCommand -Path $db -DeviceId $deviceId)) {
        if ($null -eq $row) { continue }
        $payload = [pscustomobject]@{}
        $pj = [string](Get-ScgHubValue -Object $row -Name 'payload_json')
        if (-not [string]::IsNullOrWhiteSpace($pj)) {
            try { $payload = $pj | ConvertFrom-Json -ErrorAction Stop } catch { $payload = [pscustomobject]@{} }
        }
        [void]$commands.Add([ordered]@{ id = [string]$row.id; type = [string]$row.type; payload = $payload })
        Add-ScgAudit -Path $db -Actor 'system' -Action 'command.dispatch' -Target ([string]$row.id) -Meta @{ device_id = $deviceId; type = [string]$row.type; hostname = $hostname }
    }

    $cfg = [ordered]@{
        scan_interval_sec  = [int](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'scan_interval_sec' -Default 30)
        heartbeat_sec      = [int](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'heartbeat_sec' -Default 60)
        allowed_ids        = [string[]]$allowed
        alert_throttle_min = [int](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'alert_throttle_min' -Default 30)
    }
    return (New-ScgHubResult -Status 200 -Body ([ordered]@{ ok = $true; commands = [object[]]$commands.ToArray(); config = $cfg }))
}

function Invoke-ScgResult {
<#
.SYNOPSIS
    POST /result: completes a dispatched command and notifies Telegram when a chat is configured.
.PARAMETER Config
    Hub config.
.PARAMETER Body
    Parsed request body: device_id, command_id, ok, output, duration_ms.
.PARAMETER RemoteIp
    Caller IP.
.PARAMETER Send
    Optional injectable Telegram sender (text, markup, chat id, edit id).
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Config, [AllowNull()]$Body, [string]$RemoteIp = '', [scriptblock]$Send)
    $db = [string](Get-ScgHubSetting -Config $Config -Section 'database' -Key 'path')
    $deviceId = Get-ScgHubText -Object $Body -Name 'device_id'
    $commandId = Get-ScgHubText -Object $Body -Name 'command_id'
    if (-not $deviceId) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: device_id') }
    if (-not $commandId) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: command_id') }
    $ok = Get-ScgHubValue -Object $Body -Name 'ok'
    if ($ok -isnot [bool]) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: ok') }
    $outRaw = Get-ScgHubValue -Object $Body -Name 'output'
    $output = ''
    if ($null -ne $outRaw) { $output = [string]$outRaw }
    $duration = [long]0
    $durRaw = Get-ScgHubValue -Object $Body -Name 'duration_ms'
    if ($null -ne $durRaw) {
        $d = [double]0
        if (-not [double]::TryParse([string]$durRaw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) -or $d -lt 0) {
            return (New-ScgHubError -Status 400 -Message 'invalid field: duration_ms')
        }
        $duration = [long][math]::Round($d)
    }

    $found = @(Get-ScgDevice -Path $db -DeviceId $deviceId)
    if ($found.Count -eq 0) { return (New-ScgHubError -Status 404 -Message 'unknown device') }
    $hostname = [string](Get-ScgHubValue -Object $found[0] -Name 'hostname')
    $reported = Get-ScgHubText -Object $Body -Name 'hostname'
    if ($reported) { Write-ScgHubHostnameDrift -DbPath $db -DeviceId $deviceId -Stored $hostname -Reported $reported }
    $cmdRow = Get-ScgCommand -Path $db -CommandId $commandId -DeviceId $deviceId
    if ($null -eq $cmdRow) { return (New-ScgHubError -Status 409 -Message 'command not dispatched to this device') }
    $cmdType = [string](Get-ScgHubValue -Object $cmdRow -Name 'type')

    try {
        Complete-ScgCommand -Path $db -DeviceId $deviceId -CommandId $commandId -Ok $ok -Output $output -DurationMs $duration
    }
    catch {
        $m = $_.Exception.Message
        if ($m -like 'Command not found*' -or $m -like 'Illegal command transition*') {
            return (New-ScgHubError -Status 409 -Message 'command not dispatched to this device')
        }
        throw
    }
    $status = 'failed'
    if ($ok) { $status = 'done' }
    Add-ScgAudit -Path $db -Actor ('device:' + $hostname) -Action 'command.result' -Target $commandId -Meta @{ device_id = $deviceId; ok = $ok; duration_ms = $duration }

    $chat = [string](Get-ScgHubSetting -Config $Config -Section 'telegram' -Key 'chat_id' -Default '')
    if ($chat -ne '') {
        try {
            $cmd = @{ id = $commandId; type = $cmdType; device_id = $deviceId; hostname = $hostname; status = $status; ok = $ok; output = $output; duration_ms = $duration }
            $notice = @{ Config = $Config; Command = $cmd }
            if ($Send) { $notice['Send'] = $Send }
            Send-TgResultNotice @notice
        }
        catch {
            Write-ScgLog -Message ('result notice failed: ' + $_.Exception.Message) -Level WARN -Actor 'system' -Target $commandId -Action 'telegram.notice' -Result 'error'
        }
    }
    return (New-ScgHubResult -Status 200 -Body ([ordered]@{ ok = $true }))
}

function Invoke-ScgEventIngest {
<#
.SYNOPSIS
    POST /event: stores an agent event (deduplicated by Database) and audits new ones.
.PARAMETER Config
    Hub config.
.PARAMETER Body
    Parsed request body: device_id, type, severity, payload.
.PARAMETER RemoteIp
    Caller IP.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Config, [AllowNull()]$Body, [string]$RemoteIp = '')
    $db = [string](Get-ScgHubSetting -Config $Config -Section 'database' -Key 'path')
    $deviceId = Get-ScgHubText -Object $Body -Name 'device_id'
    $type = Get-ScgHubText -Object $Body -Name 'type'
    $severity = Get-ScgHubText -Object $Body -Name 'severity'
    if (-not $deviceId) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: device_id') }
    if (-not $type -or $script:HubEventTypeSet -cnotcontains $type) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: type') }
    if (-not $severity -or $script:HubSeveritySet -cnotcontains $severity) { return (New-ScgHubError -Status 400 -Message 'missing or invalid field: severity') }
    $payload = Get-ScgHubValue -Object $Body -Name 'payload'
    if ($null -eq $payload) { $payload = [pscustomobject]@{} }
    $payloadJson = ConvertTo-Json -InputObject $payload -Compress -Depth 8

    $found = @(Get-ScgDevice -Path $db -DeviceId $deviceId)
    if ($found.Count -eq 0) { return (New-ScgHubError -Status 404 -Message 'unknown device') }
    $hostname = [string](Get-ScgHubValue -Object $found[0] -Name 'hostname')
    $reported = Get-ScgHubText -Object $Body -Name 'hostname'
    if ($reported) { Write-ScgHubHostnameDrift -DbPath $db -DeviceId $deviceId -Stored $hostname -Reported $reported }

    $throttle = [double](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'alert_throttle_min' -Default 30)
    $id = Add-ScgEvent -Path $db -DeviceId $deviceId -Type $type -Severity $severity -Payload $payloadJson -ThrottleMin $throttle
    if ($null -ne $id) {
        Add-ScgAudit -Path $db -Actor ('device:' + $hostname) -Action 'event.ingest' -Target ([string]$id) -Meta @{ device_id = $deviceId; type = $type; severity = $severity }
    }
    return (New-ScgHubResult -Status 200 -Body ([ordered]@{ ok = $true }))
}

function Get-ScgHealth {
<#
.SYNOPSIS
    GET /health: version, uptime and queue counters.
.PARAMETER Config
    Hub config.
.PARAMETER StartUtc
    Hub start time (defaults to module load time).
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Config, [datetime]$StartUtc = $script:HubStartUtc)
    $db = [string](Get-ScgHubSetting -Config $Config -Section 'database' -Key 'path')
    $stale = [int](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'stale_after_min' -Default 5)
    $counts = Get-ScgHealthCounts -Path $db -StaleAfterMin $stale
    $uptime = [int][math]::Max(0, ([datetime]::UtcNow - $StartUtc.ToUniversalTime()).TotalSeconds)
    return (New-ScgHubResult -Status 200 -Body ([ordered]@{
                ok               = $true
                version          = $script:HubVersion
                uptime_sec       = $uptime
                devices_online   = [int]$counts.devices_online
                commands_pending = [int]$counts.commands_pending
            }))
}

function Get-ScgHubActiveConfig {
<#
.SYNOPSIS
    Returns the module-scoped active config (set by New-ScgHubRoute); in a fresh worker runspace it
    lazy-loads it from the path in the SCG_HUB_CONFIG environment variable.
#>
    [CmdletBinding()]
    param()
    if ($null -eq $script:HubConfig) {
        $p = [Environment]::GetEnvironmentVariable('SCG_HUB_CONFIG')
        if ([string]::IsNullOrEmpty($p)) { throw 'Hub config is not initialised.' }
        $script:HubConfig = Get-ScgHubConfig -Path $p
    }
    return $script:HubConfig
}

function Write-ScgHubReject {
<#
.SYNOPSIS
    Audits an authentication rejection (auth.reject) using the active config. Never throws.
.PARAMETER Reason
    Rejection reason code (no secret, no bearer value).
.PARAMETER RemoteIp
    Caller IP.
#>
    [CmdletBinding()]
    param([string]$Reason, [string]$RemoteIp)
    try {
        $cfg = Get-ScgHubActiveConfig
        Add-ScgAudit -Path ([string]$cfg.database.path) -Actor 'system' -Action 'auth.reject' -Target $RemoteIp -Meta @{ reason = $Reason }
    }
    catch { $null = $_ }
}

function New-ScgHubRoute {
<#
.SYNOPSIS
    Builds the HttpServer route table for the five endpoints.
.DESCRIPTION
    Stores Config as the module-scoped active config; the handlers read it from there (no closures over
    caller variables), so they work in any runspace that imports this module.
.PARAMETER Config
    Hub config.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Config)
    $script:HubConfig = $Config
    return @{
        'POST /enroll'    = { param($Request) Invoke-ScgEnroll -Config (Get-ScgHubActiveConfig) -Body $Request.Body -RemoteIp $Request.RemoteIp }
        'POST /heartbeat' = { param($Request) Invoke-ScgHeartbeat -Config (Get-ScgHubActiveConfig) -Body $Request.Body -RemoteIp $Request.RemoteIp }
        'POST /result'    = { param($Request) Invoke-ScgResult -Config (Get-ScgHubActiveConfig) -Body $Request.Body -RemoteIp $Request.RemoteIp }
        'POST /event'     = { param($Request) Invoke-ScgEventIngest -Config (Get-ScgHubActiveConfig) -Body $Request.Body -RemoteIp $Request.RemoteIp }
        'GET /health'     = { param($Request) Get-ScgHealth -Config (Get-ScgHubActiveConfig) }
    }
}

function Invoke-ScgHubTick {
<#
.SYNOPSIS
    Maintenance pass: marks stale devices and times out old commands (audited).
.PARAMETER Config
    Hub config.
.OUTPUTS
    Hashtable with stale and timeouts counts.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)]$Config)
    $db = [string](Get-ScgHubSetting -Config $Config -Section 'database' -Key 'path')
    $staleMin = [int](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'stale_after_min' -Default 5)
    $timeoutSec = [int](Get-ScgHubSetting -Config $Config -Section 'defaults' -Key 'command_timeout_sec' -Default 300)
    $stale = [int](Set-ScgStaleDevice -Path $db -StaleAfterMin $staleMin)
    $timeouts = [int](Invoke-ScgCommandTimeout -Path $db -TimeoutSec $timeoutSec)
    if ($timeouts -gt 0) {
        Add-ScgAudit -Path $db -Actor 'system' -Action 'command.timeout' -Target 'commands' -Meta @{ count = $timeouts; timeout_sec = $timeoutSec }
    }
    if ($stale -gt 0) {
        Write-ScgLog -Message "marked $stale device(s) stale" -Level INFO -Actor 'system' -Action 'hub.tick' -Result 'ok'
    }
    return @{ stale = $stale; timeouts = $timeouts }
}

function Stop-ScgHubWorker {
<#
.SYNOPSIS
    Stops one background worker (PowerShell instance plus runspace) with a bounded wait.
.PARAMETER Worker
    Object with Ps and Runspace members (may be null).
#>
    [CmdletBinding()]
    param([AllowNull()]$Worker)
    if ($null -eq $Worker) { return }
    try {
        $async = $Worker.Ps.BeginStop($null, $null)
        [void]$async.AsyncWaitHandle.WaitOne(5000)
    }
    catch { Write-Verbose 'worker stop failed' }
    try { $Worker.Ps.Dispose() } catch { Write-Verbose 'worker dispose failed' }
    try { $Worker.Runspace.Dispose() } catch { Write-Verbose 'runspace dispose failed' }
}

function Start-ScgHubWorker {
<#
.SYNOPSIS
    Starts a script in its own runspace.
.PARAMETER Script
    Script text taking the given arguments.
.PARAMETER Argument
    Arguments passed positionally.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Script, [object[]]$Argument)
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($Script)
    foreach ($a in @($Argument)) { [void]$ps.AddArgument($a) }
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{ Ps = $ps; Runspace = $rs; Handle = $handle }
}

function Start-ScgHub {
<#
.SYNOPSIS
    Runs the Hub: HTTP server, 30 s ticker and Telegram long-poll loop, each in its own runspace.
.DESCRIPTION
    Loads the config, initialises the database, sets the log context (masking shared_secret and bot_token),
    binds TLS automatically for https URLs (via Start-ScgHttpServer) and blocks until stopped. With -NoWait
    it returns a handle whose Stop scriptblock shuts everything down (call: & $hub.Stop).
.PARAMETER ConfigPath
    Path of hub.config.json.
.PARAMETER NoWait
    Return the handle instead of blocking.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath, [switch]$NoWait)
    $cfg = Get-ScgHubConfig -Path $ConfigPath
    $dbPath = [string]$cfg.database.path
    $dbDir = Split-Path -Path $dbPath -Parent
    $logDir = Split-Path -Path ([string]$cfg.logging.path) -Parent
    if (Get-Command -Name 'Initialize-ScgSecureDirectory' -ErrorAction SilentlyContinue) {
        foreach ($d in @($dbDir, $logDir)) {
            if ($d) { [void](Initialize-ScgSecureDirectory -Path $d) }
        }
    }
    if ($dbDir -and -not (Test-Path -LiteralPath $dbDir)) { [void](New-Item -ItemType Directory -Path $dbDir -Force) }
    Set-ScgLogContext -Path $cfg.logging.path -MaxBytes ([int]$cfg.logging.max_bytes) -Secret @($cfg.shared_secret, $cfg.telegram.bot_token)
    [void](Initialize-ScgDatabase -Path $dbPath)

    [Environment]::SetEnvironmentVariable('SCG_HUB_CONFIG', (Resolve-Path -LiteralPath $ConfigPath).ProviderPath)
    $onReject = { param($Reason, $RemoteIp) Write-ScgHubReject -Reason ([string]$Reason) -RemoteIp ([string]$RemoteIp) }

    $state = [hashtable]::Synchronized(@{ Stop = $false })
    $commonPath = Join-Path $script:HubModuleDir 'Common.psm1'
    $tgPath = Join-Path $script:HubModuleDir 'Telegram.psm1'
    $dbModPath = Join-Path $script:HubModuleDir 'Database.psm1'

    $tickScript = @'
param($CommonPath, $HubPath, $Config, $State, $TickSec)
Import-Module $CommonPath -DisableNameChecking
Import-Module $HubPath -DisableNameChecking
Set-ScgLogContext -Path $Config.logging.path -MaxBytes ([int]$Config.logging.max_bytes) -Secret @($Config.shared_secret, $Config.telegram.bot_token)
while (-not $State.Stop) {
    try { [void](Invoke-ScgHubTick -Config $Config) }
    catch { Write-ScgLog -Message ('tick failed: ' + $_.Exception.Message) -Level ERROR -Actor 'system' -Action 'hub.tick' -Result 'error' }
    for ($i = 0; $i -lt $TickSec -and -not $State.Stop; $i++) { Start-Sleep -Seconds 1 }
}
'@
    $pollScript = @'
param($CommonPath, $TgPath, $Config, $State, $PauseSec)
Import-Module $CommonPath -DisableNameChecking
Import-Module $TgPath -DisableNameChecking
Set-ScgLogContext -Path $Config.logging.path -MaxBytes ([int]$Config.logging.max_bytes) -Secret @($Config.shared_secret, $Config.telegram.bot_token)
$poll = @{ Offset = 0 }
while (-not $State.Stop) {
    try { [void](Invoke-TgPollOnce -Config $Config -State $poll) }
    catch {
        Write-ScgLog -Message ('telegram poll failed: ' + $_.Exception.Message) -Level WARN -Actor 'system' -Action 'telegram.poll' -Result 'error'
        for ($i = 0; $i -lt $PauseSec -and -not $State.Stop; $i++) { Start-Sleep -Seconds 1 }
    }
}
'@

    $server = $null
    $tick = $null
    $poller = $null
    try {
        $route = New-ScgHubRoute -Config $cfg
        $serverArgs = @{
            Url         = [string]$cfg.listen.url
            Secret      = [string]$cfg.shared_secret
            Route       = $route
            ReplayCache = (New-ScgReplayCache)
            OnReject    = $onReject
            MaxSkewSec  = [int]$cfg.defaults.max_skew_sec
            NonceTtlSec = [int]$cfg.defaults.nonce_ttl_sec
            WorkerModule = @($commonPath, $dbModPath, $script:HubModulePath, $tgPath)
            LogContext  = @{ Path = [string]$cfg.logging.path; MaxBytes = [int]$cfg.logging.max_bytes; Secret = @([string]$cfg.shared_secret, [string]$cfg.telegram.bot_token) }
        }
        if (([string]$cfg.listen.url).StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase)) {
            $serverArgs['Thumbprint'] = [string]$cfg.listen.cert_thumbprint
        }
        $server = Start-ScgHttpServer @serverArgs
        $tick = Start-ScgHubWorker -Script $tickScript -Argument @($commonPath, $script:HubModulePath, $cfg, $state, [int]$cfg.defaults.tick_sec)
        $poller = Start-ScgHubWorker -Script $pollScript -Argument @($commonPath, $tgPath, $cfg, $state, [int]$cfg.defaults.telegram_error_pause_sec)
    }
    catch {
        $state.Stop = $true
        Stop-ScgHubWorker -Worker $tick
        Stop-ScgHubWorker -Worker $poller
        if ($server) { Stop-ScgHttpServer -Server $server }
        throw
    }
    Write-ScgLog -Message 'Hub started' -Level INFO -Actor 'system' -Action 'hub.start' -Result 'ok'

    $stopper = {
        $state.Stop = $true
        Stop-ScgHubWorker -Worker $poller
        Stop-ScgHubWorker -Worker $tick
        Stop-ScgHttpServer -Server $server
        Write-ScgLog -Message 'Hub stopped' -Level INFO -Actor 'system' -Action 'hub.stop' -Result 'ok'
    }.GetNewClosure()

    $handle = [pscustomobject]@{ Config = $cfg; State = $state; Server = $server; Stop = $stopper }
    if ($NoWait) { return $handle }
    try {
        while (-not $state.Stop) { Start-Sleep -Seconds 1 }
    }
    finally {
        & $stopper
    }
}

Export-ModuleMember -Function Get-ScgHubConfig, New-ScgHubRoute, Invoke-ScgEnroll, Invoke-ScgHeartbeat, Invoke-ScgResult, Invoke-ScgEventIngest, Get-ScgHealth, Invoke-ScgHubTick, Start-ScgHub, Get-ScgHubActiveConfig, Write-ScgHubReject
