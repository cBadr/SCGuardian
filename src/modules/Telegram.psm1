# Telegram.psm1 - SCGuardian v4 Telegram command center (API client, menus, command router).
# Author: Badr (@Idlexaz) - Version 4.0.0 - Windows PowerShell 5.1 compatible.
# Deps: Common.psm1, Database.psm1 (all persistence goes through Database.psm1; no SQL here).
# Source is pure ASCII on purpose (PS 5.1 reads BOM-less files as ANSI); emoji are built from code points.

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'Database.psm1') -DisableNameChecking

# ---------------------------------------------------------------- module state
# Pending removals: key = admin user id (string) -> @{Code;DeviceId;Hostname;ScId;ExpiresUtc;Attempts}
$script:TgPending = @{}
# Test seam: seconds added to the clock used for pending-remove expiry.
$script:TgClockSkewSec = 0
# Last time a 409 Conflict WARN was written (throttle: once per 5 minutes, uses Get-TgNow so tests can skew it).
$script:TgLast409Utc = [datetime]::MinValue
$script:TgConflictLogSec = 300
$script:TgMaxText = 4000
$script:TgPageSize = 10
$script:TgMaxWrongCodes = 3
# Pending fleet updates (/update all): key = 8-hex token placed in callback_data -> @{AdminId;Version;SetupUrl;Sha256;Percent;DeviceIds;Eligible;ExpiresUtc}.
# The url+hash never travel in callback_data (64-byte limit); only the short token does.
$script:TgPendingUpdate = @{}
$script:TgVersionMax = 40

$script:TgIcon = @{
    Devices = [char]::ConvertFromUtf32(0x1F5A5)
    Fleet   = [char]::ConvertFromUtf32(0x1F4CA)
    Events  = [char]::ConvertFromUtf32(0x1F4DC)
    Audit   = [char]::ConvertFromUtf32(0x1F9FE)
    Help    = [char]::ConvertFromUtf32(0x2753)
    Online  = [char]::ConvertFromUtf32(0x1F7E2)
    Stale   = [char]::ConvertFromUtf32(0x1F7E1)
    Quar    = [char]::ConvertFromUtf32(0x1F534)
    Harden  = [char]::ConvertFromUtf32(0x1F6E1)
    Trash   = [char]::ConvertFromUtf32(0x1F5D1)
    Broom   = [char]::ConvertFromUtf32(0x1F9F9)
    Ok      = [char]::ConvertFromUtf32(0x2705)
    No      = [char]::ConvertFromUtf32(0x274C)
    Back    = [char]::ConvertFromUtf32(0x2B05)
    Next    = [char]::ConvertFromUtf32(0x27A1)
    Warn    = [string][char]0x26A0
    Stop    = [string][char]0x26D4
    Gear    = [string][char]0x2699
    Bell    = [char]::ConvertFromUtf32(0x1F514)
    Ping    = [char]::ConvertFromUtf32(0x1F4E1)
    Puzzle  = [char]::ConvertFromUtf32(0x1F9E9)
    Recycle = [string][char]0x267B
    Key     = [char]::ConvertFromUtf32(0x1F511)
    Refresh = [char]::ConvertFromUtf32(0x1F504)
    Check   = [string][char]0x2714
    Cross   = [string][char]0x2716
    Dot     = [string][char]0x2022
    Ell     = [string][char]0x2026
}
# ' . ' separator (middle dot) used in every screen.
$script:TgSep = ' ' + [char]0x00B7 + ' '
$script:TgFilterName = @{ a = 'All'; o = 'Online'; s = 'Offline'; x = 'Attention' }
$script:TgFleetAttentionMax = 8
$script:TgCardAgentMax = 20

$script:TgHelpText = @'
<b>SCGuardian - commands</b>
/panel - open the button control panel
/fleet - fleet card: counts and what needs attention
/devices [page] - list devices (attention first)
/device &lt;host&gt; - device card with actions
/status &lt;host|all&gt; - queue a status check on a host, or show the fleet card
/agents &lt;host&gt; - list SC agents on a host
/harden &lt;host|all&gt; - queue a hardening pass
/restore &lt;host&gt; - queue undo-hardening on a host
/remove &lt;host&gt; &lt;sc_id&gt; - remove an UNKNOWN agent (2-step confirm)
/confirm &lt;code&gt; - confirm a pending removal
/ping &lt;host&gt; - ping a device through the hub
/reset &lt;host&gt; - revoke a device token so it re-enrolls (specific host only)
/update &lt;host&gt; &lt;version&gt; &lt;setup_url&gt; &lt;sha256&gt; - queue an agent update on one host (SHA-256 pinned)
/update all &lt;version&gt; &lt;setup_url&gt; &lt;sha256&gt; [percent] - update the first percent% (default 100) of non-quarantined devices, sorted by id (confirm button)
/versions - agent versions across the fleet
/events [n] - latest events
/audit [n] - latest audit entries
/whoami - show your Telegram id
Buttons: Harden, Restore, Reset token and Harden all ask for confirmation first.
'@

# ---------------------------------------------------------------- small helpers
function ConvertTo-TgHtml {
    <#
    .SYNOPSIS
    Escapes text for Telegram HTML parse mode.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][object]$Text)
    if ($null -eq $Text) { return '' }
    return ([string]$Text).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
}

function Limit-TgHtml {
    <#
    .SYNOPSIS
    Truncates ALREADY-ESCAPED Telegram HTML to at most Max chars on a safe boundary: never inside a tag or an entity, and every opened b/i/u/s/code/pre tag is closed.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$Max = 4000)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    $prefix = $Text.Substring(0, [Math]::Max(0, $Max - 40))
    $lt = $prefix.LastIndexOf('<')
    if ($lt -gt $prefix.LastIndexOf('>')) { $prefix = $prefix.Substring(0, $lt) }
    $amp = $prefix.LastIndexOf('&')
    if ($amp -ge 0 -and $prefix.IndexOf(';', $amp) -lt 0) { $prefix = $prefix.Substring(0, $amp) }
    $stack = New-Object System.Collections.ArrayList
    foreach ($m in [regex]::Matches($prefix, '<(/?)(b|i|u|s|code|pre)>')) {
        $tag = $m.Groups[2].Value
        if ($m.Groups[1].Value -eq '/') {
            $ix = $stack.LastIndexOf($tag)
            if ($ix -ge 0) { $stack.RemoveAt($ix) }
        } else {
            [void]$stack.Add($tag)
        }
    }
    $closers = ''
    for ($k = $stack.Count - 1; $k -ge 0; $k--) { $closers += ('</{0}>' -f $stack[$k]) }
    return ($prefix + '...' + $closers)
}

function ConvertTo-TgPlain {
    <#
    .SYNOPSIS
    Strips tags from Telegram HTML and decodes the three entities, for the plain-text fallback send.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    $t = [regex]::Replace($Text, '<[^>]*>', '')
    return $t.Replace('&lt;', '<').Replace('&gt;', '>').Replace('&amp;', '&')
}

function Get-TgField {
    <#
    .SYNOPSIS
    Returns the first non-null property (or hashtable key) among the candidate names.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Row,
        [Parameter(Mandatory)][string[]]$Name,
        [AllowNull()][object]$Default = $null
    )
    if ($null -eq $Row) { return $Default }
    foreach ($n in $Name) {
        if ($Row -is [System.Collections.IDictionary]) {
            if ($Row.Contains($n) -and $null -ne $Row[$n]) { return $Row[$n] }
        } else {
            $p = $Row.PSObject.Properties[$n]
            if ($p -and $null -ne $p.Value) { return $p.Value }
        }
    }
    return $Default
}

function Get-TgNow {
    <#
    .SYNOPSIS
    UTC clock used for pending-remove expiry (skewable in tests).
    #>
    [CmdletBinding()]
    param()
    return [datetime]::UtcNow.AddSeconds($script:TgClockSkewSec)
}

function Get-TgCfgValue {
    <#
    .SYNOPSIS
    Reads a nested config value (Section.Key) from a PSCustomObject or hashtable config.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key,
        [AllowNull()][object]$Default = $null
    )
    $sec = Get-TgField -Row $Config -Name @($Section)
    return (Get-TgField -Row $sec -Name @($Key) -Default $Default)
}

function Get-TgDeviceId8 {
    <#
    .SYNOPSIS
    First 8 characters of a device GUID (callback_data short id).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Device)
    $id = [string](Get-TgField -Row $Device -Name @('id', 'device_id') -Default '')
    if ($id.Length -gt 8) { return $id.Substring(0, 8) }
    return $id
}

function ConvertTo-TgIso {
    <#
    .SYNOPSIS
    Formats a datetime as UTC ISO8601 with milliseconds and Z (field-dictionary convention).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][datetime]$Value)
    return $Value.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-TgIso {
    <#
    .SYNOPSIS
    Parses a UTC ISO timestamp (or passes a datetime through). Returns $null when empty or unparseable.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $dt = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt }
    return $null
}

function Format-TgAgo {
    <#
    .SYNOPSIS
    Relative time: '12s ago', '5m ago', '3h ago', '2d ago', or 'never' for empty/unparseable input. Pure; -Now is injectable.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$IsoUtc,
        [datetime]$Now = (Get-TgNow)
    )
    $t = ConvertFrom-TgIso -Value $IsoUtc
    if ($null -eq $t) { return 'never' }
    $sec = [Math]::Floor(($Now - $t).TotalSeconds)
    if ($sec -lt 0) { $sec = 0 }
    if ($sec -lt 60) { return ('{0}s ago' -f [int64]$sec) }
    if ($sec -lt 3600) { return ('{0}m ago' -f [int64][Math]::Floor($sec / 60)) }
    if ($sec -lt 86400) { return ('{0}h ago' -f [int64][Math]::Floor($sec / 3600)) }
    return ('{0}d ago' -f [int64][Math]::Floor($sec / 86400))
}

function Get-TgDeviceState {
    <#
    .SYNOPSIS
    Single source of device state: 'quarantined' when status=quarantined, else 'online' when last_seen is within StaleMin minutes of Now, else 'offline'. The status column is NOT trusted for online/offline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Device,
        [int]$StaleMin = 5,
        [datetime]$Now = (Get-TgNow)
    )
    $st = [string](Get-TgField -Row $Device -Name @('status') -Default '')
    if ($st -eq 'quarantined') { return 'quarantined' }
    $seen = ConvertFrom-TgIso -Value (Get-TgField -Row $Device -Name @('last_seen'))
    if ($null -ne $seen -and ($Now - $seen).TotalMinutes -le $StaleMin) { return 'online' }
    return 'offline'
}

function Get-TgStateIcon {
    <#
    .SYNOPSIS
    Glyph for a device state: online / offline / quarantined.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$State)
    if ($State -eq 'quarantined') { return $script:TgIcon.Quar }
    if ($State -eq 'online') { return $script:TgIcon.Online }
    return $script:TgIcon.Stale
}

function Get-TgNum {
    <#
    .SYNOPSIS
    Reads a numeric field (default 0) as Int64.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Row, [Parameter(Mandatory)][string]$Name)
    $v = Get-TgField -Row $Row -Name @($Name) -Default 0
    $n = [int64]0
    if (-not [int64]::TryParse("$v", [ref]$n)) { $n = 0 }
    return $n
}

function Get-TgPlural {
    <#
    .SYNOPSIS
    '<n> <word>' with an 's' appended when n is not 1.
    #>
    [CmdletBinding()]
    param([int64]$Count, [Parameter(Mandatory)][string]$Word)
    if ($Count -eq 1) { return ('{0} {1}' -f $Count, $Word) }
    return ('{0} {1}s' -f $Count, $Word)
}

function Get-TgAgentShortId {
    <#
    .SYNOPSIS
    first4...last4 of an agent id (full id when shorter than 9 chars).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Id)
    if ($Id.Length -lt 9) { return $Id }
    return ($Id.Substring(0, 4) + $script:TgIcon.Ell + $Id.Substring($Id.Length - 4))
}

function Test-TgAgentUnauthorized {
    <#
    .SYNOPSIS
    True only when the DB row explicitly marks the agent as not authorized.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Agent)
    if ($null -eq $Agent) { return $false }
    $v = Get-TgField -Row $Agent -Name @('authorized', 'Authorized')
    if ($null -eq $v) { return $false }
    return (-not [bool][int]("$v" -replace '^(?i:true)$', '1' -replace '^(?i:false)$', '0'))
}

function New-TgButton {
    <#
    .SYNOPSIS
    Builds one inline button; throws when callback_data exceeds 64 UTF-8 bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Data
    )
    if ([Text.Encoding]::UTF8.GetByteCount($Data) -gt 64) { throw "callback_data too long: $Data" }
    if ($Text.Length -gt 40) { $Text = $Text.Substring(0, 40) }
    return @{ text = $Text; callback_data = $Data }
}

function New-TgRemoveCode {
    <#
    .SYNOPSIS
    Returns a random 6-digit confirmation code (100000-999999).
    #>
    [CmdletBinding()]
    param()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try {
        $b = New-Object byte[] 4
        $rng.GetBytes($b)
        $n = [BitConverter]::ToUInt32($b, 0)
        return [string](100000 + ($n % 900000))
    } finally { $rng.Dispose() }
}

# ---------------------------------------------------------------- Telegram HTTP
function Invoke-TgApi {
    <#
    .SYNOPSIS
    Sole Telegram Bot API client. TLS 1.2, UTF-8 JSON body, 35 s timeout. Returns $null on failure; never logs the token or URL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Token,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]+$')][string]$Method,
        [hashtable]$Body = @{}
    )
    if ([string]::IsNullOrWhiteSpace($Token)) { return $null }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $json = $Body | ConvertTo-Json -Depth 12 -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $uri = 'https://api.telegram.org/bot{0}/{1}' -f $Token, $Method
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 35 -ErrorAction Stop
        if ($null -ne $resp -and $resp.PSObject.Properties['ok'] -and $resp.ok -eq $false) { return $null }
        return $resp
    } catch {
        $probe = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
        if ($probe -match '409|Conflict') {
            $now = Get-TgNow
            if (($now - $script:TgLast409Utc).TotalSeconds -ge $script:TgConflictLogSec) {
                $script:TgLast409Utc = $now
                Write-ScgLog -Message "telegram 409 Conflict: another consumer is polling this bot (method=$Method); throttled to once per 5 min" -Level WARN -Action 'telegram.conflict' -Result 'conflict'
            }
        } else {
            Write-ScgLog -Message "telegram api call failed: method=$Method" -Level WARN -Action 'telegram.api' -Result 'fail'
        }
        return $null
    }
}

function Get-TgUpdate {
    <#
    .SYNOPSIS
    Long-polls getUpdates (timeout=25) for message and callback_query updates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Token,
        [int]$Offset = 0
    )
    $body = @{ timeout = 25; allowed_updates = @('message', 'callback_query') }
    if ($Offset -gt 0) { $body.offset = $Offset }
    $resp = Invoke-TgApi -Token $Token -Method 'getUpdates' -Body $body
    if ($null -eq $resp -or $null -eq $resp.result) { return @() }
    return @($resp.result)
}

function Send-TgMessage {
    <#
    .SYNOPSIS
    Default sender: sendMessage, or editMessageText when EditMessageId is given. Text must already be escaped; it is cut safely to 4000 chars. If the HTML send fails, retries once as plain text (tags stripped, no parse_mode).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$Text,
        [AllowNull()][object]$Markup,
        [Parameter(Mandatory)][string]$ChatId,
        [AllowNull()][object]$EditMessageId
    )
    $token = [string](Get-TgCfgValue -Config $Config -Section 'telegram' -Key 'bot_token' -Default '')
    $Text = Limit-TgHtml -Text $Text -Max $script:TgMaxText
    $method = 'sendMessage'
    $body = @{ chat_id = $ChatId; text = $Text; parse_mode = 'HTML'; disable_web_page_preview = $true }
    if ($null -ne $Markup) { $body.reply_markup = $Markup }
    if ($null -ne $EditMessageId -and "$EditMessageId" -ne '') {
        $body.message_id = [int64]$EditMessageId
        $method = 'editMessageText'
    }
    $resp = Invoke-TgApi -Token $token -Method $method -Body $body
    if ($null -ne $resp) { return $resp }
    $plain = @{ chat_id = $ChatId; text = (ConvertTo-TgPlain -Text $Text); disable_web_page_preview = $true }
    if ($null -ne $Markup) { $plain.reply_markup = $Markup }
    if ($body.ContainsKey('message_id')) { $plain.message_id = $body.message_id }
    return (Invoke-TgApi -Token $token -Method $method -Body $plain)
}

function Invoke-TgSend {
    <#
    .SYNOPSIS
    Routes an outgoing message through the injected sender or the default one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][string]$Text,
        [AllowNull()][object]$Markup = $null,
        [AllowNull()][object]$EditMessageId = $null
    )
    $Text = Limit-TgHtml -Text $Text -Max $script:TgMaxText
    if ($Ctx.Send) {
        & $Ctx.Send $Text $Markup $Ctx.ChatId $EditMessageId | Out-Null
    } else {
        Send-TgMessage -Config $Ctx.Config -Text $Text -Markup $Markup -ChatId $Ctx.ChatId -EditMessageId $EditMessageId | Out-Null
    }
}

# ---------------------------------------------------------------- parsing / auth
function ConvertFrom-TgCommand {
    <#
    .SYNOPSIS
    Parses '/cmd@bot a  b' into @{Command='/cmd'; Argument=@('a','b')}. Returns $null for non-commands.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text".Trim()
    if (-not $t.StartsWith('/')) { return $null }
    $parts = @($t -split '\s+' | Where-Object { $_ -ne '' })
    $cmd = ($parts[0] -replace '@.*$', '').ToLowerInvariant()
    $rest = [string[]]@()
    if ($parts.Count -gt 1) { $rest = [string[]]@($parts[1..($parts.Count - 1)]) }
    return [pscustomobject]@{ Command = $cmd; Argument = $rest }
}

function Test-TgAdmin {
    <#
    .SYNOPSIS
    True when the sender matches an admin user id or an admin username (case-insensitive, '@' optional).
    SECURITY: Telegram user ids are immutable and are the secure path; usernames can be changed or re-claimed.
    Username auth is kept for compatibility (admin_usernames), but every call that authorises a sender ONLY by username (id not in admin_user_ids) writes a WARN log line. Prefer admin_user_ids.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$From,
        [string[]]$AdminUserId = @(),
        [string[]]$AdminUsername = @()
    )
    if ($null -eq $From) { return $false }
    $id = [string](Get-TgField -Row $From -Name @('id') -Default '')
    $user = ([string](Get-TgField -Row $From -Name @('username') -Default '')).TrimStart('@')
    if ($id -ne '' -and (@($AdminUserId | ForEach-Object { "$_" }) -contains $id)) { return $true }
    if ($user -ne '') {
        foreach ($u in @($AdminUsername)) {
            if ("$u".TrimStart('@') -ieq $user) {
                Write-ScgLog -Message "telegram admin authorised by USERNAME only (id not in admin_user_ids): id=$id username=$user - add the id to admin_user_ids" -Level WARN -Actor "telegram:$id" -Action 'telegram.auth.username' -Result 'warn'
                return $true
            }
        }
    }
    return $false
}

# ---------------------------------------------------------------- menus
function Get-TgPageSlice {
    <#
    .SYNOPSIS
    Slices a list into 10-per-page pages; clamps the page into range.
    #>
    [CmdletBinding()]
    param([AllowNull()][object[]]$Item = @(), [int]$Page = 1)
    $items = @($Item | Where-Object { $null -ne $_ })
    $pages = [int][Math]::Max(1, [Math]::Ceiling($items.Count / [double]$script:TgPageSize))
    if ($Page -lt 1) { $Page = 1 }
    if ($Page -gt $pages) { $Page = $pages }
    $skip = ($Page - 1) * $script:TgPageSize
    $slice = @($items | Select-Object -Skip $skip -First $script:TgPageSize)
    return [pscustomobject]@{ Items = $slice; Page = $Page; Pages = $pages }
}

function Get-TgAgentSummaryMap {
    <#
    .SYNOPSIS
    One Get-ScgDeviceAgentSummary call per render, as a hashtable keyed by device_id (never a per-device agent query).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][datetime]$Now)
    $map = @{}
    foreach ($r in @(Get-ScgDeviceAgentSummary -Path $Ctx.Path -Now (ConvertTo-TgIso -Value $Now))) {
        if ($null -eq $r) { continue }
        $k = [string](Get-TgField -Row $r -Name @('device_id') -Default '')
        if ($k -ne '') { $map[$k] = $r }
    }
    return $map
}

function Get-TgDeviceView {
    <#
    .SYNOPSIS
    Builds one view row per device (state, unknown/stopped/failed counts, attention, rank) and sorts: attention first, then offline, then online; ties by hostname (case-insensitive). Pure.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$Device = @(),
        [AllowNull()][hashtable]$Summary = $null,
        [int]$StaleMin = 5,
        [datetime]$Now = (Get-TgNow)
    )
    $out = New-Object System.Collections.ArrayList
    foreach ($d in @($Device)) {
        if ($null -eq $d) { continue }
        $id = [string](Get-TgField -Row $d -Name @('id', 'device_id') -Default '')
        $s = $null
        if ($null -ne $Summary -and $id -ne '' -and $Summary.ContainsKey($id)) { $s = $Summary[$id] }
        $unk = Get-TgNum -Row $s -Name 'agents_unknown'
        $stop = Get-TgNum -Row $s -Name 'agents_stopped'
        $fail = Get-TgNum -Row $s -Name 'commands_failed_24h'
        $state = Get-TgDeviceState -Device $d -StaleMin $StaleMin -Now $Now
        $att = ($state -eq 'quarantined') -or ($unk -gt 0) -or ($stop -gt 0) -or ($fail -gt 0)
        $rank = 2
        if ($att) { $rank = 0 } elseif ($state -eq 'offline') { $rank = 1 }
        $id8 = Get-TgDeviceId8 -Device $d
        [void]$out.Add([pscustomobject]@{
                Device    = $d
                Id8       = $id8
                Host      = [string](Get-TgField -Row $d -Name @('hostname') -Default $id8)
                State     = $state
                Unknown   = $unk
                Stopped   = $stop
                Failed    = $fail
                Attention = [bool]$att
                SeenIso   = Get-TgField -Row $d -Name @('last_seen')
                Rank      = $rank
            })
    }
    return @($out | Sort-Object -Property @{ Expression = { $_.Rank } }, @{ Expression = { $_.Host.ToLowerInvariant() } })
}

function Get-TgViewCount {
    <#
    .SYNOPSIS
    Counts per filter: a (all), o (online), s (offline), q (quarantined), x (attention).
    #>
    [CmdletBinding()]
    param([AllowNull()][object[]]$View = @())
    $v = @($View | Where-Object { $null -ne $_ })
    return @{
        a = $v.Count
        o = @($v | Where-Object { $_.State -eq 'online' }).Count
        s = @($v | Where-Object { $_.State -eq 'offline' }).Count
        q = @($v | Where-Object { $_.State -eq 'quarantined' }).Count
        x = @($v | Where-Object { $_.Attention }).Count
    }
}

function Select-TgViewFilter {
    <#
    .SYNOPSIS
    Applies a list filter (a all, o online, s offline, x attention) to sorted view rows, keeping the order.
    #>
    [CmdletBinding()]
    param([AllowNull()][object[]]$View = @(), [string]$Filter = 'a')
    $v = @($View | Where-Object { $null -ne $_ })
    if ($Filter -eq 'o') { return @($v | Where-Object { $_.State -eq 'online' }) }
    if ($Filter -eq 's') { return @($v | Where-Object { $_.State -eq 'offline' }) }
    if ($Filter -eq 'x') { return @($v | Where-Object { $_.Attention }) }
    return $v
}

function Get-TgFilterKey {
    <#
    .SYNOPSIS
    Normalises a filter key to a|o|s|x (anything else becomes a).
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Filter)
    $f = "$Filter".ToLowerInvariant()
    if (@('a', 'o', 's', 'x') -contains $f) { return $f }
    return 'a'
}

function Format-TgDeviceButtonText {
    <#
    .SYNOPSIS
    Device row label '<icon> <host> <warn>N . 12s ago' (warn N = unknown agents); the hostname is shortened so the label stays within 40 chars.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$View, [Parameter(Mandatory)][datetime]$Now)
    $icon = Get-TgStateIcon -State $View.State
    $suffix = ''
    if ($View.Unknown -gt 0) { $suffix += (' ' + $script:TgIcon.Warn + $View.Unknown) }
    $suffix += ($script:TgSep + (Format-TgAgo -IsoUtc $View.SeenIso -Now $Now))
    $max = 40 - $icon.Length - 1 - $suffix.Length
    $h = [string]$View.Host
    if ($h.Length -gt $max) { $h = $h.Substring(0, [Math]::Max(1, $max - 1)) + $script:TgIcon.Ell }
    return ('{0} {1}{2}' -f $icon, $h, $suffix)
}

function New-TgMenu {
    <#
    .SYNOPSIS
    Builds an inline-keyboard reply_markup. Names: main, devices, device, fleet, confirm, remove-list, remove-confirm, reset-confirm, back.
    Context keys: devices {Devices,Page,Filter,Summary,Counts,StaleMin,Now} | device {Device,UnknownCount} | fleet {Counts} | confirm {Action=harden|restore|reset|hall|update-all,DeviceId8,Token} | remove-list {DeviceId8,UnknownId} | remove-confirm {DeviceId8,ScId} | reset-confirm {DeviceId8} | back {Callback}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('main', 'devices', 'device', 'fleet', 'confirm', 'remove-list', 'remove-confirm', 'reset-confirm', 'back')][string]$Name,
        [hashtable]$Context = @{}
    )
    $i = $script:TgIcon
    $rows = New-Object System.Collections.ArrayList
    switch ($Name) {
        'main' {
            [void]$rows.Add(@((New-TgButton "$($i.Devices) Devices" 'm:devs'), (New-TgButton "$($i.Fleet) Fleet status" 'm:fleet')))
            [void]$rows.Add(@((New-TgButton "$($i.Events) Events" 'm:events'), (New-TgButton "$($i.Audit) Audit" 'm:audit')))
            [void]$rows.Add(@((New-TgButton "$($i.Help) Help" 'm:help')))
        }
        'devices' {
            $f = Get-TgFilterKey -Filter ([string]$Context.Filter)
            $now = Get-TgNow
            if ($Context.ContainsKey('Now') -and $null -ne $Context.Now) { $now = [datetime]$Context.Now }
            $stale = 5
            if ($Context.ContainsKey('StaleMin') -and $null -ne $Context.StaleMin) { $stale = [int]$Context.StaleMin }
            $summary = $null
            if ($Context.Summary -is [hashtable]) { $summary = $Context.Summary }
            $views = @(Get-TgDeviceView -Device @($Context.Devices) -Summary $summary -StaleMin $stale -Now $now)
            $counts = $Context.Counts
            if ($null -eq $counts) { $counts = Get-TgViewCount -View $views }
            $list = @(Select-TgViewFilter -View $views -Filter $f)
            $slice = Get-TgPageSlice -Item $list -Page ([int]$Context.Page)
            $filterRow = New-Object System.Collections.ArrayList
            foreach ($k in @('a', 'o', 's', 'x')) {
                $label = @{ a = ('All {0}' -f $counts.a); o = ('{0} {1}' -f $i.Online, $counts.o); s = ('{0} {1}' -f $i.Stale, $counts.s); x = ('{0} {1}' -f $i.Warn, $counts.x) }[$k]
                if ($k -eq $f) { $label = $i.Dot + ' ' + $label }
                [void]$filterRow.Add((New-TgButton $label ('dl:{0}:1' -f $k)))
            }
            [void]$rows.Add($filterRow.ToArray())
            foreach ($v in @($slice.Items)) {
                [void]$rows.Add(@((New-TgButton (Format-TgDeviceButtonText -View $v -Now $now) ('d:{0}' -f $v.Id8))))
            }
            $pager = New-Object System.Collections.ArrayList
            if ($slice.Page -gt 1) { [void]$pager.Add((New-TgButton "$($i.Back) Prev" ('dl:{0}:{1}' -f $f, ($slice.Page - 1)))) }
            [void]$pager.Add((New-TgButton ('{0}/{1}' -f $slice.Page, $slice.Pages) ('dl:{0}:{1}' -f $f, $slice.Page)))
            if ($slice.Page -lt $slice.Pages) { [void]$pager.Add((New-TgButton "Next $($i.Next)" ('dl:{0}:{1}' -f $f, ($slice.Page + 1)))) }
            [void]$rows.Add($pager.ToArray())
            [void]$rows.Add(@(
                    (New-TgButton "$($i.Fleet) Fleet" 'm:fleet'),
                    (New-TgButton "$($i.Refresh) Refresh" ('dl:{0}:{1}' -f $f, $slice.Page)),
                    (New-TgButton "$($i.Back) Menu" 'm:main')))
        }
        'device' {
            $d8 = Get-TgDeviceId8 -Device $Context.Device
            $n = 0
            if ($null -ne $Context.UnknownCount) { $n = [int]$Context.UnknownCount }
            [void]$rows.Add(@(
                    (New-TgButton "$($i.Fleet) Status" "a:status:$d8"),
                    (New-TgButton "$($i.Ping) Ping" "a:ping:$d8"),
                    (New-TgButton "$($i.Puzzle) Agents" "a:agents:$d8")))
            [void]$rows.Add(@((New-TgButton "$($i.Harden) Harden" "a:harden:$d8"), (New-TgButton "$($i.Recycle) Restore" "a:restore:$d8")))
            if ($n -gt 0) { [void]$rows.Add(@((New-TgButton ("{0} Remove unknown ({1})" -f $i.Broom, $n) "a:listrm:$d8"))) }
            [void]$rows.Add(@((New-TgButton "$($i.Key) Reset token" "a:reset:$d8")))
            [void]$rows.Add(@((New-TgButton "$($i.Refresh) Refresh" "d:$d8"), (New-TgButton "$($i.Back) Devices" 'm:devs')))
        }
        'fleet' {
            $x = 0
            if ($null -ne $Context.Counts) { $x = [int]$Context.Counts.x }
            [void]$rows.Add(@((New-TgButton "$($i.Devices) Devices" 'dl:a:1'), (New-TgButton ("{0} Attention ({1})" -f $i.Warn, $x) 'dl:x:1')))
            [void]$rows.Add(@((New-TgButton "$($i.Online) Online" 'dl:o:1'), (New-TgButton "$($i.Stale) Offline" 'dl:s:1')))
            [void]$rows.Add(@((New-TgButton "$($i.Harden) Harden all" 'fl:hall'), (New-TgButton "$($i.Ping) Ping all" 'fl:pall')))
            [void]$rows.Add(@((New-TgButton "$($i.Refresh) Refresh" 'fl:r'), (New-TgButton "$($i.Back) Menu" 'm:main')))
        }
        'confirm' {
            $act = [string]$Context.Action
            $d8 = [string]$Context.DeviceId8
            $okData = ''; $cancel = "d:$d8"
            if ($act -eq 'harden') { $okData = "ok:harden:$d8" }
            elseif ($act -eq 'restore') { $okData = "ok:restore:$d8" }
            elseif ($act -eq 'reset') { $okData = "rst:$d8" }
            elseif ($act -eq 'hall') { $okData = 'fl:hallok'; $cancel = 'fl:r' }
            elseif ($act -eq 'update-all') { $tok = [string]$Context.Token; $okData = "up:ok:$tok"; $cancel = "up:no:$tok" }
            else { throw "unknown confirm action: $act" }
            [void]$rows.Add(@((New-TgButton "$($i.Ok) Confirm" $okData), (New-TgButton "$($i.No) Cancel" $cancel)))
        }
        'remove-list' {
            foreach ($u in @($Context.UnknownId)) {
                [void]$rows.Add(@((New-TgButton "$($i.Trash) $u" "rm:$($Context.DeviceId8):$u")))
            }
            if ($rows.Count -eq 0) { [void]$rows.Add(@((New-TgButton '(no unknown agents)' "d:$($Context.DeviceId8)"))) }
            [void]$rows.Add(@((New-TgButton "$($i.Back) Back" "d:$($Context.DeviceId8)")))
        }
        'remove-confirm' {
            [void]$rows.Add(@(
                    (New-TgButton "$($i.Ok) CONFIRM remove" "rmc:$($Context.DeviceId8):$($Context.ScId)"),
                    (New-TgButton "$($i.No) Cancel" "d:$($Context.DeviceId8)")))
        }
        'reset-confirm' {
            [void]$rows.Add(@(
                    (New-TgButton "$($i.Ok) CONFIRM reset" "rst:$($Context.DeviceId8)"),
                    (New-TgButton "$($i.No) Cancel" "d:$($Context.DeviceId8)")))
        }
        'back' {
            [void]$rows.Add(@((New-TgButton "$($i.Back) Back" ([string]$Context.Callback))))
        }
    }
    return @{ inline_keyboard = $rows.ToArray() }
}

# ---------------------------------------------------------------- data helpers
function Get-TgAllDevice {
    <#
    .SYNOPSIS
    All devices from the DB, sorted by hostname.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx)
    return @(Get-ScgDevice -Path $Ctx.Path | Where-Object { $null -ne $_ } | Sort-Object { [string](Get-TgField -Row $_ -Name @('hostname') -Default '') })
}

function Resolve-TgDevice {
    <#
    .SYNOPSIS
    Resolves a hostname or an 8-char id prefix to exactly one device; $null when missing or ambiguous.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][string]$Name,
        [switch]$ByIdPrefix
    )
    $all = Get-TgAllDevice -Ctx $Ctx
    if ($ByIdPrefix) {
        $m = @($all | Where-Object { ([string](Get-TgField -Row $_ -Name @('id', 'device_id') -Default '')).StartsWith($Name, [StringComparison]::OrdinalIgnoreCase) })
    } else {
        $m = @($all | Where-Object { [string](Get-TgField -Row $_ -Name @('hostname') -Default '') -ieq $Name })
    }
    if ($m.Count -eq 1) { return $m[0] }
    return $null
}

function Get-TgUnknownAgent {
    <#
    .SYNOPSIS
    Agents the DB marks unauthorized for a device, excluding allow-listed ids.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][object]$Device,
        [AllowNull()][object[]]$Agent
    )
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $out = @()
    if ($PSBoundParameters.ContainsKey('Agent')) { $src = @($Agent) } else { $src = @(Get-ScgScAgent -Path $Ctx.Path -DeviceId $did) }
    foreach ($a in $src) {
        if ($null -eq $a) { continue }
        if (-not (Test-TgAgentUnauthorized -Agent $a)) { continue }
        $aid = ([string](Get-TgField -Row $a -Name @('id', 'sc_id'))).ToLowerInvariant()
        if ($Ctx.AllowedIds -contains $aid) { continue }
        $out += $aid
    }
    return @($out)
}

function Invoke-TgIssue {
    <#
    .SYNOPSIS
    Queues one command for a device and writes the command.issue audit row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][object]$Device,
        [Parameter(Mandatory)][ValidateSet('harden', 'restore', 'remove', 'status', 'agents', 'ping')][string]$Type,
        [hashtable]$Payload = @{},
        [string]$AuditAction = 'command.issue'
    )
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $host1 = [string](Get-TgField -Row $Device -Name @('hostname') -Default $did)
    $cid = New-ScgCommand -Path $Ctx.Path -DeviceId $did -Type $Type -Payload $Payload -IssuedBy $Ctx.Actor -IssuedVia 'telegram'
    Add-ScgAudit -Path $Ctx.Path -Actor $Ctx.Actor -Action $AuditAction -Target $host1 -Meta @{ type = $Type; command_id = "$cid" } | Out-Null
    return $cid
}

function Invoke-TgReset {
    <#
    .SYNOPSIS
    Revokes a device token (Clear-ScgDeviceToken), audits device.reset, returns the HTML reply. Returns @{Ok;Text}.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][object]$Device)
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $host1 = [string](Get-TgField -Row $Device -Name @('hostname') -Default $did)
    $hostHtml = ConvertTo-TgHtml $host1
    $cleared = Clear-ScgDeviceToken -Path $Ctx.Path -DeviceId $did
    if (-not $cleared) { return @{ Ok = $false; Text = ("Reset failed for <b>{0}</b>: no token was cleared." -f $hostHtml) } }
    Add-ScgAudit -Path $Ctx.Path -Actor $Ctx.Actor -Action 'device.reset' -Target $did -Meta @{ hostname = $host1 } | Out-Null
    $txt = ("Token of <b>{0}</b> was revoked. The agent will re-enroll on its next cycle.`n" -f $hostHtml) +
    "WARNING: until it re-enrolls, anyone holding the fleet secret could claim this hostname. Watch /events."
    return @{ Ok = $true; Text = $txt }
}

function Get-TgFleetSummaryRow {
    <#
    .SYNOPSIS
    Reads Get-ScgFleetSummary once (single row) for the given clock.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][datetime]$Now)
    $r = @(Get-ScgFleetSummary -Path $Ctx.Path -StaleAfterMin ([int]$Ctx.StaleMin) -Now (ConvertTo-TgIso -Value $Now)) | Where-Object { $null -ne $_ } | Select-Object -First 1
    return $r
}

function Get-TgFleetView {
    <#
    .SYNOPSIS
    Sorted view rows for the whole fleet: one Get-ScgDevice call and one Get-ScgDeviceAgentSummary call.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][datetime]$Now)
    $devs = @(Get-TgAllDevice -Ctx $Ctx)
    $sum = Get-TgAgentSummaryMap -Ctx $Ctx -Now $Now
    return [pscustomobject]@{
        Devices = $devs
        Summary = $sum
        View    = @(Get-TgDeviceView -Device $devs -Summary $sum -StaleMin ([int]$Ctx.StaleMin) -Now $Now)
    }
}

function Format-TgDevicesHeader {
    <#
    .SYNOPSIS
    Two-line header of the Devices list: filter + page, then online/offline/quarantined counts (Get-ScgFleetSummary) and the attention count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [string]$Filter = 'a',
        [int]$Page = 1,
        [int]$Pages = 1,
        [int]$AttentionCount = 0,
        [datetime]$Now = (Get-TgNow)
    )
    $i = $script:TgIcon; $s = $script:TgSep
    $f = Get-TgFleetSummaryRow -Ctx $Ctx -Now $Now
    $name = $script:TgFilterName[(Get-TgFilterKey -Filter $Filter)]
    $l1 = ('<b>{0} Devices</b>{1}filter: {2}{1}page {3}/{4}' -f $i.Devices, $s, $name, $Page, $Pages)
    $l2 = ('{0} {1} online{8}{2} {3} offline{8}{4} {5} quarantined{8}{6} {7} need attention' -f
        $i.Online, (Get-TgNum -Row $f -Name 'devices_online'),
        $i.Stale, (Get-TgNum -Row $f -Name 'devices_offline'),
        $i.Quar, (Get-TgNum -Row $f -Name 'devices_quarantined'),
        $i.Warn, $AttentionCount, $s)
    return ($l1 + "`n" + $l2)
}

function Format-TgAttentionLine {
    <#
    .SYNOPSIS
    One needs-attention line for the fleet card: icon, escaped hostname and every reason (quarantined, unknown, stopped, failed, offline).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$View, [Parameter(Mandatory)][datetime]$Now)
    $i = $script:TgIcon
    $why = New-Object System.Collections.ArrayList
    if ($View.State -eq 'quarantined') { [void]$why.Add('quarantined') }
    if ($View.Unknown -gt 0) { [void]$why.Add((Get-TgPlural -Count $View.Unknown -Word 'unknown agent')) }
    if ($View.Stopped -gt 0) { [void]$why.Add((Get-TgPlural -Count $View.Stopped -Word 'stopped agent')) }
    if ($View.Failed -gt 0) { [void]$why.Add((Get-TgPlural -Count $View.Failed -Word 'failed command')) }
    if ($View.State -eq 'offline') {
        $ago = Format-TgAgo -IsoUtc $View.SeenIso -Now $Now
        if ($ago -eq 'never') { [void]$why.Add('offline (never seen)') } else { [void]$why.Add(('offline ' + ($ago -replace ' ago$', ''))) }
    }
    $icon = $i.Stale
    if ($View.State -eq 'quarantined') { $icon = $i.Quar } elseif ($View.Attention) { $icon = $i.Warn }
    return ('{0} {1}{2}{3}' -f $icon, (ConvertTo-TgHtml $View.Host), $script:TgSep, ($why -join $script:TgSep))
}

function Get-TgAttentionRank {
    <#
    .SYNOPSIS
    Needs-attention order: 0 quarantined, 1 unknown agents, 2 stopped agents, 3 failed commands, 4 offline only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$View)
    if ($View.State -eq 'quarantined') { return 0 }
    if ($View.Unknown -gt 0) { return 1 }
    if ($View.Stopped -gt 0) { return 2 }
    if ($View.Failed -gt 0) { return 3 }
    return 4
}

function Format-TgFleetText {
    <#
    .SYNOPSIS
    Fleet card: state counts, agents, commands, events (Get-ScgFleetSummary) and up to 8 needs-attention devices plus '(+N more)'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [AllowNull()][object[]]$View,
        [datetime]$Now
    )
    if (-not $PSBoundParameters.ContainsKey('Now')) { $Now = Get-TgNow }
    if (-not $PSBoundParameters.ContainsKey('View')) { $View = @((Get-TgFleetView -Ctx $Ctx -Now $Now).View) }
    $i = $script:TgIcon; $s = $script:TgSep
    $f = Get-TgFleetSummaryRow -Ctx $Ctx -Now $Now
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(('<b>{0} Fleet</b>' -f $i.Fleet))
    [void]$lines.Add(('{0} {1} online{7}{2} {3} offline{7}{4} {5} quarantined ({6} devices)' -f $i.Online, (Get-TgNum -Row $f -Name 'devices_online'), $i.Stale, (Get-TgNum -Row $f -Name 'devices_offline'), $i.Quar, (Get-TgNum -Row $f -Name 'devices_quarantined'), (Get-TgNum -Row $f -Name 'devices_total'), $s))
    [void]$lines.Add(('{0} Agents: {1} mine{5}{2} {3} unknown (on {4} devices)' -f $i.Harden, (Get-TgNum -Row $f -Name 'agents_mine'), $i.Warn, (Get-TgNum -Row $f -Name 'agents_unknown'), (Get-TgNum -Row $f -Name 'devices_with_unknown'), $s))
    [void]$lines.Add(('{0} Commands: {1} pending{4}{2} in flight{4}{3} failed (24h)' -f $i.Gear, (Get-TgNum -Row $f -Name 'commands_pending'), (Get-TgNum -Row $f -Name 'commands_dispatched'), (Get-TgNum -Row $f -Name 'commands_failed_24h'), $s))
    [void]$lines.Add(('{0} Events (24h, unacked): {1} critical{3}{2} warn' -f $i.Bell, (Get-TgNum -Row $f -Name 'events_critical_24h'), (Get-TgNum -Row $f -Name 'events_warn_24h'), $s))
    [void]$lines.Add('')
    $need = @($View | Where-Object { $null -ne $_ -and ($_.Attention -or $_.State -eq 'offline') } |
        Sort-Object -Property @{ Expression = { Get-TgAttentionRank -View $_ } }, @{ Expression = { $_.Host.ToLowerInvariant() } })
    if ($need.Count -eq 0) {
        [void]$lines.Add('Needs attention: none')
    } else {
        [void]$lines.Add('Needs attention:')
        foreach ($v in @($need | Select-Object -First $script:TgFleetAttentionMax)) { [void]$lines.Add((Format-TgAttentionLine -View $v -Now $Now)) }
        if ($need.Count -gt $script:TgFleetAttentionMax) { [void]$lines.Add(('(+{0} more)' -f ($need.Count - $script:TgFleetAttentionMax))) }
    }
    return ($lines -join "`n")
}

function Format-TgDeviceCard {
    <#
    .SYNOPSIS
    Device card: state + relative last_seen, OS/agent version, IP/enrolled, agents (first4...last4 ids) and the last 3 commands (Get-ScgRecentCommand).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][object]$Device,
        [datetime]$Now,
        [AllowNull()][object[]]$Agent
    )
    if (-not $PSBoundParameters.ContainsKey('Now')) { $Now = Get-TgNow }
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    if ($PSBoundParameters.ContainsKey('Agent')) { $agents = @($Agent | Where-Object { $null -ne $_ }) }
    else { $agents = @(Get-ScgScAgent -Path $Ctx.Path -DeviceId $did | Where-Object { $null -ne $_ }) }
    $i = $script:TgIcon; $s = $script:TgSep
    $state = Get-TgDeviceState -Device $Device -StaleMin ([int]$Ctx.StaleMin) -Now $Now
    $host1 = ConvertTo-TgHtml (Get-TgField -Row $Device -Name @('hostname') -Default $did)
    $os = ('{0} {1}' -f [string](Get-TgField -Row $Device -Name @('os') -Default ''), [string](Get-TgField -Row $Device -Name @('os_version') -Default '')).Trim()
    if ($os -eq '') { $os = '-' }
    $ver = [string](Get-TgField -Row $Device -Name @('agent_version') -Default '-')
    $ip = [string](Get-TgField -Row $Device -Name @('last_ip') -Default '-')
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(('{0} <b>{1}</b>{2}{3} ({4})' -f (Get-TgStateIcon -State $state), $host1, $s, $state, (Format-TgAgo -IsoUtc (Get-TgField -Row $Device -Name @('last_seen')) -Now $Now)))
    [void]$lines.Add(('OS: {0}{1}agent {2}' -f (ConvertTo-TgHtml $os), $s, (ConvertTo-TgHtml $ver)))
    [void]$lines.Add(('IP: {0}{1}enrolled {2}' -f (ConvertTo-TgHtml $ip), $s, (Format-TgAgo -IsoUtc (Get-TgField -Row $Device -Name @('first_seen')) -Now $Now)))
    [void]$lines.Add('')
    [void]$lines.Add(('{0} Agents ({1})' -f $i.Harden, $agents.Count))
    if ($agents.Count -eq 0) { [void]$lines.Add('none reported') }
    foreach ($a in @($agents | Select-Object -First $script:TgCardAgentMax)) {
        $aid = ([string](Get-TgField -Row $a -Name @('id', 'sc_id') -Default '')).ToLowerInvariant()
        $unknown = (Test-TgAgentUnauthorized -Agent $a) -and -not (@($Ctx.AllowedIds) -contains $aid)
        $st = [string](Get-TgField -Row $a -Name @('state', 'service_state') -Default '')
        $icon = $i.Ok; $tag = 'mine'
        if ($unknown) { $icon = $i.Warn; $tag = 'UNKNOWN' } elseif ($st -ne 'Running') { $icon = $i.Stop }
        if ($st -eq '') { $st = '-' }
        [void]$lines.Add(('{0} {1} {2}{3}{4}' -f $icon, (ConvertTo-TgHtml (Get-TgAgentShortId -Id $aid)), $tag, $s, (ConvertTo-TgHtml $st)))
    }
    if ($agents.Count -gt $script:TgCardAgentMax) { [void]$lines.Add(('(+{0} more, see Agents)' -f ($agents.Count - $script:TgCardAgentMax))) }
    [void]$lines.Add('')
    [void]$lines.Add(('{0} Recent commands' -f $i.Gear))
    $cmds = @(Get-ScgRecentCommand -Path $Ctx.Path -DeviceId $did -Last 3 | Where-Object { $null -ne $_ })
    if ($cmds.Count -eq 0) { [void]$lines.Add('none') }
    foreach ($c in @($cmds | Select-Object -First 3)) {
        $cst = [string](Get-TgField -Row $c -Name @('status') -Default '')
        $when = Get-TgField -Row $c -Name @('finished_at')
        if ($null -eq $when -or "$when" -eq '') { $when = Get-TgField -Row $c -Name @('created_at') }
        $icon = $i.Gear
        if ($cst -eq 'done') { $icon = $i.Check } elseif ($cst -eq 'failed' -or $cst -eq 'timeout') { $icon = $i.Cross }
        $line = ('{0} {1}{2}{3}' -f $icon, (ConvertTo-TgHtml (Get-TgField -Row $c -Name @('type') -Default '?')), $s, (Format-TgAgo -IsoUtc $when -Now $Now))
        if ($cst -ne 'done') { $line += ($s + (ConvertTo-TgHtml $cst)) }
        [void]$lines.Add($line)
    }
    return ($lines -join "`n")
}

function Format-TgAgentText {
    <#
    .SYNOPSIS
    Agent inventory text for one device.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][object]$Device)
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $agents = @(Get-ScgScAgent -Path $Ctx.Path -DeviceId $did)
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(("<b>Agents on {0}</b> ({1})" -f (ConvertTo-TgHtml (Get-TgField -Row $Device -Name @('hostname'))), $agents.Count))
    foreach ($a in @($agents | Select-Object -First 40)) {
        $aid = ConvertTo-TgHtml (Get-TgField -Row $a -Name @('id', 'sc_id'))
        $tag = 'mine'
        if (Test-TgAgentUnauthorized -Agent $a) { $tag = 'UNKNOWN' }
        $svc = ConvertTo-TgHtml (Get-TgField -Row $a -Name @('service', 'service_name') -Default '')
        $state = ConvertTo-TgHtml (Get-TgField -Row $a -Name @('state', 'service_state') -Default '')
        [void]$lines.Add(("<code>{0}</code> {1} {2} {3}" -f $aid, $tag, $svc, $state))
    }
    return ($lines -join "`n")
}

function Show-TgDevices {
    <#
    .SYNOPSIS
    Renders the Devices list (header + filter row + one row per device + pager + Fleet/Refresh/Menu) and sends or edits it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [string]$Filter = 'a',
        [int]$Page = 1,
        [AllowNull()][object]$EditMessageId = $null
    )
    $f = Get-TgFilterKey -Filter $Filter
    $now = Get-TgNow
    $fv = Get-TgFleetView -Ctx $Ctx -Now $now
    $views = @($fv.View)
    $counts = Get-TgViewCount -View $views
    $list = @(Select-TgViewFilter -View $views -Filter $f)
    $slice = Get-TgPageSlice -Item $list -Page $Page
    $text = Format-TgDevicesHeader -Ctx $Ctx -Filter $f -Page $slice.Page -Pages $slice.Pages -AttentionCount $counts.x -Now $now
    if ($list.Count -eq 0) { $text += "`n`nNo devices match this filter." }
    $markup = New-TgMenu -Name 'devices' -Context @{ Devices = @($fv.Devices); Summary = $fv.Summary; Filter = $f; Page = $slice.Page; StaleMin = [int]$Ctx.StaleMin; Now = $now; Counts = $counts }
    Invoke-TgSend -Ctx $Ctx -Text $text -Markup $markup -EditMessageId $EditMessageId
}

function Show-TgFleet {
    <#
    .SYNOPSIS
    Renders the Fleet card with its keyboard and sends or edits it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [AllowNull()][object]$EditMessageId = $null)
    $now = Get-TgNow
    $views = @((Get-TgFleetView -Ctx $Ctx -Now $now).View)
    $text = Format-TgFleetText -Ctx $Ctx -View $views -Now $now
    $markup = New-TgMenu -Name 'fleet' -Context @{ Counts = (Get-TgViewCount -View $views) }
    Invoke-TgSend -Ctx $Ctx -Text $text -Markup $markup -EditMessageId $EditMessageId
}

function Get-TgDeviceMarkup {
    <#
    .SYNOPSIS
    Device-card keyboard; Remove unknown (N) only when the device has N greater than 0 non-allow-listed unknown agents.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][object]$Device, [AllowNull()][object[]]$Agent)
    if ($PSBoundParameters.ContainsKey('Agent')) { $unk = @(Get-TgUnknownAgent -Ctx $Ctx -Device $Device -Agent $Agent) }
    else { $unk = @(Get-TgUnknownAgent -Ctx $Ctx -Device $Device) }
    return (New-TgMenu -Name 'device' -Context @{ Device = $Device; UnknownCount = $unk.Count })
}

function Show-TgDevice {
    <#
    .SYNOPSIS
    Renders the Device card (optionally prefixed by a note) with its keyboard; one Get-ScgScAgent call.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][object]$Device,
        [string]$Note = '',
        [AllowNull()][object]$EditMessageId = $null
    )
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $agents = @(Get-ScgScAgent -Path $Ctx.Path -DeviceId $did | Where-Object { $null -ne $_ })
    $text = Format-TgDeviceCard -Ctx $Ctx -Device $Device -Now (Get-TgNow) -Agent $agents
    if ($Note -ne '') { $text = $Note + "`n`n" + $text }
    Invoke-TgSend -Ctx $Ctx -Text $text -Markup (Get-TgDeviceMarkup -Ctx $Ctx -Device $Device -Agent $agents) -EditMessageId $EditMessageId
}

function Format-TgQueuedNote {
    <#
    .SYNOPSIS
    '<ok> Queued <type> on <host>.' (escaped).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][object]$Device)
    return ('{0} Queued <b>{1}</b> on <b>{2}</b>.' -f $script:TgIcon.Ok, (ConvertTo-TgHtml $Type), (ConvertTo-TgHtml (Get-TgField -Row $Device -Name @('hostname'))))
}

function Test-TgCallbackAdmin {
    <#
    .SYNOPSIS
    Re-checks that the callback sender is an admin before anything executes; otherwise answers 'Unauthorized' (alert), audits auth.reject and returns $false.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][object]$Callback)
    $from = Get-TgField -Row $Callback -Name @('from')
    if (Test-TgAdmin -From $from -AdminUserId @($Ctx.AdminIds | Where-Object { $null -ne $_ }) -AdminUsername @($Ctx.AdminNames | Where-Object { $null -ne $_ })) { return $true }
    $fid = [string](Get-TgField -Row $from -Name @('id') -Default '')
    Invoke-TgApi -Token ([string]$Ctx.Token) -Method 'answerCallbackQuery' -Body @{ callback_query_id = "$($Callback.id)"; text = 'Unauthorized'; show_alert = $true } | Out-Null
    Add-ScgAudit -Path $Ctx.Path -Actor "telegram:$fid" -Action 'auth.reject' -Target 'callback' -Meta @{ data = "$($Callback.data)" } | Out-Null
    return $false
}

function Invoke-TgIssueAll {
    <#
    .SYNOPSIS
    Queues one command of the given type on every device (each audited command.issue). Returns the device count.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][ValidateSet('harden', 'ping')][string]$Type)
    $devs = @(Get-TgAllDevice -Ctx $Ctx)
    foreach ($d in $devs) { Invoke-TgIssue -Ctx $Ctx -Device $d -Type $Type | Out-Null }
    return $devs.Count
}

# ---------------------------------------------------------------- remove flow
function Test-TgRemoveTarget {
    <#
    .SYNOPSIS
    Validates a removal target: 16-hex id, not allow-listed, present in DB as unauthorized. Returns @{Ok;Error;ScId}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][object]$Device,
        [AllowEmptyString()][string]$ScId
    )
    if ([string]::IsNullOrWhiteSpace($ScId) -or -not (Test-ScgInstanceId -Id $ScId)) { return @{ Ok = $false; Error = 'invalid agent id format (need 16 hex characters)' } }
    $id = (ConvertTo-ScgInstanceId -Id $ScId)
    if ($Ctx.AllowedIds -contains $id) { return @{ Ok = $false; Error = "refused: <code>$id</code> is on the allow-list" } }
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $row = @(Get-ScgScAgent -Path $Ctx.Path -DeviceId $did | Where-Object { ([string](Get-TgField -Row $_ -Name @('id', 'sc_id'))).ToLowerInvariant() -eq $id }) | Select-Object -First 1
    if (-not $row) { return @{ Ok = $false; Error = "no agent <code>$id</code> on that host" } }
    if (-not (Test-TgAgentUnauthorized -Agent $row)) { return @{ Ok = $false; Error = "refused: <code>$id</code> is not an unknown agent" } }
    return @{ Ok = $true; ScId = $id }
}

function Clear-TgExpiredPending {
    <#
    .SYNOPSIS
    Drops expired pending removals from the module store.
    #>
    [CmdletBinding()]
    param()
    $now = Get-TgNow
    foreach ($k in @($script:TgPending.Keys)) {
        if ($now -gt $script:TgPending[$k].ExpiresUtc) { $script:TgPending.Remove($k) }
    }
}

function Request-TgRemove {
    <#
    .SYNOPSIS
    Step 1: validates, stores a pending removal bound to the admin, audits remove.request. Returns @{Ok;Error;Code}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][object]$Device,
        [AllowEmptyString()][string]$ScId
    )
    $v = Test-TgRemoveTarget -Ctx $Ctx -Device $Device -ScId $ScId
    if (-not $v.Ok) { return $v }
    Clear-TgExpiredPending
    $code = New-TgRemoveCode
    $host1 = [string](Get-TgField -Row $Device -Name @('hostname'))
    $script:TgPending[$Ctx.AdminId] = [pscustomobject]@{
        Code       = $code
        DeviceId   = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
        Hostname   = $host1
        ScId       = $v.ScId
        ExpiresUtc = (Get-TgNow).AddSeconds($Ctx.ConfirmSec)
        Attempts   = 0
    }
    Add-ScgAudit -Path $Ctx.Path -Actor $Ctx.Actor -Action 'remove.request' -Target $host1 -Meta @{ sc_id = $v.ScId } | Out-Null
    return @{ Ok = $true; Code = $code; ScId = $v.ScId }
}

function Complete-TgRemove {
    <#
    .SYNOPSIS
    Step 2: consumes the admin's pending removal (one-use), re-validates, queues the remove command. Returns @{Ok;Error}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [AllowEmptyString()][string]$Code,
        [switch]$SkipCode,
        [string]$DeviceId8 = '',
        [string]$ScId = ''
    )
    Clear-TgExpiredPending
    $p = $script:TgPending[$Ctx.AdminId]
    if (-not $p) { return @{ Ok = $false; Error = 'nothing pending to confirm (or it expired) - re-issue /remove' } }
    if ($SkipCode) {
        if (-not $p.DeviceId.StartsWith($DeviceId8, [StringComparison]::OrdinalIgnoreCase) -or $p.ScId -ne $ScId.ToLowerInvariant()) {
            return @{ Ok = $false; Error = 'this confirmation does not match your pending removal' }
        }
    } elseif ("$Code" -ne $p.Code) {
        $p.Attempts = [int]$p.Attempts + 1
        if ($p.Attempts -ge $script:TgMaxWrongCodes) {
            $script:TgPending.Remove($Ctx.AdminId)
            return @{ Ok = $false; Error = 'too many wrong codes - pending removal cancelled' }
        }
        return @{ Ok = $false; Error = 'wrong confirmation code' }
    }
    $script:TgPending.Remove($Ctx.AdminId)
    $prefix8 = $p.DeviceId.Substring(0, [Math]::Min(8, $p.DeviceId.Length))
    $dev = Resolve-TgDevice -Ctx $Ctx -Name $prefix8 -ByIdPrefix
    if (-not $dev) { return @{ Ok = $false; Error = 'device no longer available' } }
    $v = Test-TgRemoveTarget -Ctx $Ctx -Device $dev -ScId $p.ScId
    if (-not $v.Ok) { return $v }
    Invoke-TgIssue -Ctx $Ctx -Device $dev -Type 'remove' -Payload @{ sc_id = $p.ScId } -AuditAction 'remove.confirm' | Out-Null
    return @{ Ok = $true; Hostname = $p.Hostname; ScId = $p.ScId }
}

# ---------------------------------------------------------------- self-update (contract v2.2)
function New-TgToken {
    <#
    .SYNOPSIS
    Returns a random 8-hex token (short key for callback_data).
    #>
    [CmdletBinding()]
    param()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try {
        $b = New-Object byte[] 4
        $rng.GetBytes($b)
        return ((@($b) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $rng.Dispose() }
}

function Test-TgUpdateSpec {
    <#
    .SYNOPSIS
    Friendly pre-check of an operator-supplied update spec (version present, https url, 64-hex sha256) so a bad value gets a clean reply before New-ScgCommand. Returns @{Ok;Error;Version;SetupUrl;Sha256} (sha256 lowercased).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Version,
        [AllowEmptyString()][string]$SetupUrl,
        [AllowEmptyString()][string]$Sha256
    )
    if ([string]::IsNullOrWhiteSpace($Version)) { return @{ Ok = $false; Error = 'version is required' } }
    if ("$SetupUrl" -notmatch '^https://\S+\z') { return @{ Ok = $false; Error = 'setup_url must start with https://' } }
    if ("$Sha256" -notmatch '^[0-9a-fA-F]{64}\z') { return @{ Ok = $false; Error = 'sha256 must be exactly 64 hex characters' } }
    return @{ Ok = $true; Error = ''; Version = $Version.Trim(); SetupUrl = $SetupUrl; Sha256 = $Sha256.ToLowerInvariant() }
}

function Test-TgOnVersion {
    <#
    .SYNOPSIS
    True when the device's agent_version equals Version (exact, case-insensitive). Empty versions never match.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Device, [AllowEmptyString()][string]$Version)
    $cur = ([string](Get-TgField -Row $Device -Name @('agent_version') -Default '')).Trim()
    $want = "$Version".Trim()
    if ($cur -eq '' -or $want -eq '') { return $false }
    return [string]::Equals($cur, $want, [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-TgUpdateOne {
    <#
    .SYNOPSIS
    Queues one 'update' command for a device unless it is already on the version. Every outcome is audited (command.issue, meta result already_current|failed when nothing was queued). Never throws. Returns @{Result=queued|current|failed;Error}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][object]$Device,
        [Parameter(Mandatory)][hashtable]$Spec
    )
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $host1 = [string](Get-TgField -Row $Device -Name @('hostname') -Default $did)
    if (Test-TgOnVersion -Device $Device -Version $Spec.Version) {
        try { Add-ScgAudit -Path $Ctx.Path -Actor $Ctx.Actor -Action 'command.issue' -Target $host1 -Meta @{ type = 'update'; version = $Spec.Version; result = 'already_current' } | Out-Null } catch { $null = $_ }
        return @{ Result = 'current'; Error = '' }
    }
    $payload = @{ version = $Spec.Version; setup_url = $Spec.SetupUrl; sha256 = $Spec.Sha256 }
    try {
        $cid = New-ScgCommand -Path $Ctx.Path -DeviceId $did -Type 'update' -Payload $payload -IssuedBy $Ctx.Actor -IssuedVia 'telegram'
    } catch {
        $msg = "$($_.Exception.Message)"
        try {
            Write-ScgLog -Message "update not queued for ${host1}: $msg" -Level WARN -Actor $Ctx.Actor -Action 'telegram.update' -Result 'fail'
            Add-ScgAudit -Path $Ctx.Path -Actor $Ctx.Actor -Action 'command.issue' -Target $host1 -Meta @{ type = 'update'; version = $Spec.Version; result = 'failed'; error = $msg } | Out-Null
        } catch { $null = $_ }
        return @{ Result = 'failed'; Error = $msg }
    }
    try { Add-ScgAudit -Path $Ctx.Path -Actor $Ctx.Actor -Action 'command.issue' -Target $host1 -Meta @{ type = 'update'; command_id = "$cid"; version = $Spec.Version } | Out-Null } catch { $null = $_ }
    return @{ Result = 'queued'; Error = '' }
}

function Select-TgUpdateTarget {
    <#
    .SYNOPSIS
    Deterministic rollout subset: non-quarantined devices sorted by id (ordinal), first ceiling(M*Percent/100) of them (at least 1 when M>0). Returns @{Selected;Eligible=M}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [ValidateRange(1, 100)][int]$Percent = 100,
        [AllowNull()][object[]]$Device,
        [datetime]$Now
    )
    if (-not $PSBoundParameters.ContainsKey('Now')) { $Now = Get-TgNow }
    if (-not $PSBoundParameters.ContainsKey('Device')) { $Device = @(Get-TgAllDevice -Ctx $Ctx) }
    $stale = 5
    if ($null -ne $Ctx.StaleMin) { $stale = [int]$Ctx.StaleMin }
    $byId = @{}
    $ids = New-Object 'System.Collections.Generic.List[string]'
    foreach ($d in @($Device)) {
        if ($null -eq $d) { continue }
        if ((Get-TgDeviceState -Device $d -StaleMin $stale -Now $Now) -eq 'quarantined') { continue }
        $id = [string](Get-TgField -Row $d -Name @('id', 'device_id') -Default '')
        if ($id -eq '' -or $byId.ContainsKey($id)) { continue }
        $byId[$id] = $d
        $ids.Add($id)
    }
    $ids.Sort([StringComparer]::Ordinal)
    $m = $ids.Count
    $n = 0
    if ($m -gt 0) {
        $n = [int][Math]::Floor(($m * $Percent + 99) / 100)
        if ($n -lt 1) { $n = 1 }
        if ($n -gt $m) { $n = $m }
    }
    $sel = New-Object System.Collections.ArrayList
    for ($k = 0; $k -lt $n; $k++) { [void]$sel.Add($byId[$ids[$k]]) }
    return [pscustomobject]@{ Selected = $sel.ToArray(); Eligible = $m }
}

function Clear-TgExpiredUpdate {
    <#
    .SYNOPSIS
    Drops expired pending fleet updates from the module store.
    #>
    [CmdletBinding()]
    param()
    $now = Get-TgNow
    foreach ($k in @($script:TgPendingUpdate.Keys)) {
        if ($now -gt $script:TgPendingUpdate[$k].ExpiresUtc) { $script:TgPendingUpdate.Remove($k) }
    }
}

function Request-TgUpdateAll {
    <#
    .SYNOPSIS
    Step 1 of /update all: computes the subset and stores the spec under a short token bound to the admin. Queues nothing. Returns @{Ok;Error;Token;Count;Eligible}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][hashtable]$Spec,
        [ValidateRange(1, 100)][int]$Percent = 100
    )
    Clear-TgExpiredUpdate
    $sub = Select-TgUpdateTarget -Ctx $Ctx -Percent $Percent
    $sel = @($sub.Selected)
    if ($sub.Eligible -eq 0 -or $sel.Count -eq 0) { return @{ Ok = $false; Error = 'No eligible devices (none enrolled, or all quarantined).' } }
    $tok = New-TgToken
    while ($script:TgPendingUpdate.ContainsKey($tok)) { $tok = New-TgToken }
    $confirmSec = 120
    if ($null -ne $Ctx.ConfirmSec) { $confirmSec = [int]$Ctx.ConfirmSec }
    $script:TgPendingUpdate[$tok] = [pscustomobject]@{
        AdminId    = [string]$Ctx.AdminId
        Version    = $Spec.Version
        SetupUrl   = $Spec.SetupUrl
        Sha256     = $Spec.Sha256
        Percent    = $Percent
        DeviceIds  = @($sel | ForEach-Object { [string](Get-TgField -Row $_ -Name @('id', 'device_id')) })
        Eligible   = $sub.Eligible
        ExpiresUtc = (Get-TgNow).AddSeconds($confirmSec)
    }
    return @{ Ok = $true; Error = ''; Token = $tok; Count = $sel.Count; Eligible = $sub.Eligible }
}

function Complete-TgUpdateAll {
    <#
    .SYNOPSIS
    Step 2 of /update all: consumes the pending spec (one-use, same admin only) and queues one update per selected device, skipping already-current ones. Returns @{Ok;Error;Version;Queued;Current;Failed}.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [AllowEmptyString()][string]$Token)
    Clear-TgExpiredUpdate
    $p = $null
    if ("$Token" -match '^[0-9a-f]{8}\z') { $p = $script:TgPendingUpdate[$Token] }
    if (-not $p) { return @{ Ok = $false; Error = 'Nothing pending to confirm (or it expired) - re-issue /update all.' } }
    if ($p.AdminId -ne [string]$Ctx.AdminId) { return @{ Ok = $false; Error = 'This confirmation belongs to another admin.' } }
    $script:TgPendingUpdate.Remove($Token)
    $spec = @{ Version = $p.Version; SetupUrl = $p.SetupUrl; Sha256 = $p.Sha256 }
    $byId = @{}
    foreach ($d in @(Get-TgAllDevice -Ctx $Ctx)) {
        $id = [string](Get-TgField -Row $d -Name @('id', 'device_id') -Default '')
        if ($id -ne '') { $byId[$id] = $d }
    }
    $q = 0; $c = 0; $f = 0
    foreach ($id in @($p.DeviceIds)) {
        if (-not $byId.ContainsKey([string]$id)) { $f++; continue }
        $r = Invoke-TgUpdateOne -Ctx $Ctx -Device $byId[[string]$id] -Spec $spec
        if ($r.Result -eq 'queued') { $q++ } elseif ($r.Result -eq 'current') { $c++ } else { $f++ }
    }
    return @{ Ok = $true; Error = ''; Version = $p.Version; Queued = $q; Current = $c; Failed = $f }
}

function Format-TgVersionText {
    <#
    .SYNOPSIS
    /versions: one line per agent_version group from Get-ScgVersionDistribution (order kept), capped at 40 groups plus '(+N more)'.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [datetime]$Now)
    if (-not $PSBoundParameters.ContainsKey('Now')) { $Now = Get-TgNow }
    $rows = @(Get-ScgVersionDistribution -Path $Ctx.Path | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return 'No devices enrolled yet.' }
    $total = [int64]0
    foreach ($r in $rows) { $total += (Get-TgNum -Row $r -Name 'device_count') }
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(('<b>{0} Agent versions</b> ({1})' -f $script:TgIcon.Harden, (Get-TgPlural -Count $total -Word 'device')))
    foreach ($r in @($rows | Select-Object -First $script:TgVersionMax)) {
        $ver = ([string](Get-TgField -Row $r -Name @('agent_version') -Default '')).Trim()
        if ($ver -eq '') { $ver = '(unknown)' }
        [void]$lines.Add(('{0}: {1} (newest seen {2})' -f (ConvertTo-TgHtml $ver), (Get-TgPlural -Count (Get-TgNum -Row $r -Name 'device_count') -Word 'device'), (Format-TgAgo -IsoUtc (Get-TgField -Row $r -Name @('newest_seen')) -Now $Now)))
    }
    if ($rows.Count -gt $script:TgVersionMax) { [void]$lines.Add(('(+{0} more)' -f ($rows.Count - $script:TgVersionMax))) }
    return (Limit-TgHtml -Text ($lines -join "`n") -Max $script:TgMaxText)
}

function Invoke-TgUpdateCommand {
    <#
    .SYNOPSIS
    Typed /update: 'host v url sha' queues one update (no confirm, like /harden host); 'all v url sha [percent]' shows a confirm prompt (token in callback_data).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [string[]]$Argument = @())
    $arg = @($Argument)
    $usage = 'usage: /update &lt;host&gt; &lt;version&gt; &lt;setup_url&gt; &lt;sha256&gt;' + "`n" + 'or: /update all &lt;version&gt; &lt;setup_url&gt; &lt;sha256&gt; [percent]'
    if ($arg.Count -lt 4) { Invoke-TgSend -Ctx $Ctx -Text $usage; return }
    $a0 = [string]$arg[0]
    if ($a0 -ieq 'all') {
        if ($arg.Count -gt 5) { Invoke-TgSend -Ctx $Ctx -Text $usage; return }
        $pct = 100
        if ($arg.Count -eq 5) {
            $pv = 0
            if (-not [int]::TryParse([string]$arg[4], [ref]$pv) -or $pv -lt 1 -or $pv -gt 100) {
                Invoke-TgSend -Ctx $Ctx -Text ("percent must be a whole number from 1 to 100.`n" + $usage)
                return
            }
            $pct = $pv
        }
        $spec = Test-TgUpdateSpec -Version ([string]$arg[1]) -SetupUrl ([string]$arg[2]) -Sha256 ([string]$arg[3])
        if (-not $spec.Ok) { Invoke-TgSend -Ctx $Ctx -Text ('Update not queued: {0}.' -f (ConvertTo-TgHtml $spec.Error)); return }
        $r = Request-TgUpdateAll -Ctx $Ctx -Spec $spec -Percent $pct
        if (-not $r.Ok) { Invoke-TgSend -Ctx $Ctx -Text (ConvertTo-TgHtml $r.Error); return }
        $txt = ('Update {0} of {1} devices ({2}%) to {3}? Already-current devices are skipped.' -f $r.Count, $r.Eligible, $pct, (ConvertTo-TgHtml $spec.Version))
        Invoke-TgSend -Ctx $Ctx -Text $txt -Markup (New-TgMenu -Name 'confirm' -Context @{ Action = 'update-all'; Token = $r.Token })
        return
    }
    if ($arg.Count -ne 4) { Invoke-TgSend -Ctx $Ctx -Text $usage; return }
    $spec = Test-TgUpdateSpec -Version ([string]$arg[1]) -SetupUrl ([string]$arg[2]) -Sha256 ([string]$arg[3])
    if (-not $spec.Ok) { Invoke-TgSend -Ctx $Ctx -Text ('Update not queued: {0}.' -f (ConvertTo-TgHtml $spec.Error)); return }
    $dev = Resolve-TgDevice -Ctx $Ctx -Name $a0
    if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $a0)); return }
    $hostHtml = ConvertTo-TgHtml (Get-TgField -Row $dev -Name @('hostname'))
    $verHtml = ConvertTo-TgHtml $spec.Version
    $r = Invoke-TgUpdateOne -Ctx $Ctx -Device $dev -Spec $spec
    if ($r.Result -eq 'current') { Invoke-TgSend -Ctx $Ctx -Text ('<b>{0}</b> is already on <b>{1}</b> - nothing queued.' -f $hostHtml, $verHtml); return }
    if ($r.Result -eq 'failed') { Invoke-TgSend -Ctx $Ctx -Text ('Update not queued for <b>{0}</b>: {1}' -f $hostHtml, (ConvertTo-TgHtml $r.Error)); return }
    Invoke-TgSend -Ctx $Ctx -Text ('{0} Queued <b>update</b> to <b>{1}</b> on <b>{2}</b>.' -f $script:TgIcon.Ok, $verHtml, $hostHtml)
}

# ---------------------------------------------------------------- command handlers
function Invoke-TgFanOut {
    <#
    .SYNOPSIS
    Issues one command per target device (host or 'all') and replies with the count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Ctx,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Type,
        [switch]$AllowAll
    )
    if ($Target -ieq 'all') {
        if (-not $AllowAll) { Invoke-TgSend -Ctx $Ctx -Text "<b>/$Type</b>: a specific host is required." ; return }
        $devs = Get-TgAllDevice -Ctx $Ctx
        if ($devs.Count -eq 0) { Invoke-TgSend -Ctx $Ctx -Text 'No devices enrolled.'; return }
        foreach ($d in $devs) { Invoke-TgIssue -Ctx $Ctx -Device $d -Type $Type | Out-Null }
        Invoke-TgSend -Ctx $Ctx -Text ("Queued <b>{0}</b> on {1} device(s)." -f (ConvertTo-TgHtml $Type), $devs.Count)
        return
    }
    $dev = Resolve-TgDevice -Ctx $Ctx -Name $Target
    if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $Target)); return }
    Invoke-TgIssue -Ctx $Ctx -Device $dev -Type $Type | Out-Null
    Invoke-TgSend -Ctx $Ctx -Text ("Queued <b>{0}</b> on <b>{1}</b>." -f (ConvertTo-TgHtml $Type), (ConvertTo-TgHtml (Get-TgField -Row $dev -Name @('hostname'))))
}

function Get-TgCount {
    <#
    .SYNOPSIS
    Parses an optional count argument (default 10, clamp 1..20).
    #>
    [CmdletBinding()]
    param([string[]]$Argument = @())
    $n = 10
    if (@($Argument).Count -gt 0) { [void][int]::TryParse($Argument[0], [ref]$n) }
    if ($n -lt 1) { $n = 10 }
    if ($n -gt 20) { $n = 20 }
    return $n
}

function Format-TgEventText {
    <#
    .SYNOPSIS
    Latest events as HTML text.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [int]$Last = 10)
    $rows = @(Get-ScgEvent -Path $Ctx.Path -Last $Last)
    $lines = @('<b>Latest events</b>')
    if ($rows.Count -eq 0) { $lines += 'none' }
    foreach ($r in $rows) {
        $lines += ("{0} {1} {2} {3}" -f (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('ts', 'created_at', 'created_utc', 'timestamp') -Default '')),
            (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('severity') -Default '')),
            (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('type') -Default '')),
            (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('hostname', 'device_id') -Default '')))
    }
    return ($lines -join "`n")
}

function Format-TgAuditText {
    <#
    .SYNOPSIS
    Latest audit rows as HTML text.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [int]$Last = 10)
    $rows = @(Get-ScgAudit -Path $Ctx.Path -Last $Last)
    $lines = @('<b>Latest audit</b>')
    if ($rows.Count -eq 0) { $lines += 'none' }
    foreach ($r in $rows) {
        $lines += ("{0} {1} {2} {3}" -f (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('ts', 'created_at', 'created_utc', 'timestamp') -Default '')),
            (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('actor') -Default '')),
            (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('action') -Default '')),
            (ConvertTo-TgHtml (Get-TgField -Row $r -Name @('target') -Default '')))
    }
    return ($lines -join "`n")
}

function Invoke-TgMessageCommand {
    <#
    .SYNOPSIS
    Handles one text command from the ops chat.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][object]$Parsed)
    $cmd = $Parsed.Command
    $arg = @($Parsed.Argument)
    $a0 = ''
    if ($arg.Count -gt 0) { $a0 = [string]$arg[0] }
    switch ($cmd) {
        { $_ -in @('/start', '/panel') } {
            Invoke-TgSend -Ctx $Ctx -Text '<b>SCGuardian Panel</b>' -Markup (New-TgMenu -Name 'main')
        }
        '/help' { Invoke-TgSend -Ctx $Ctx -Text $script:TgHelpText }
        '/devices' {
            $page = 1
            if ($a0) { [void][int]::TryParse($a0, [ref]$page) }
            Show-TgDevices -Ctx $Ctx -Filter 'a' -Page $page
        }
        '/fleet' { Show-TgFleet -Ctx $Ctx }
        '/device' {
            if (-not $a0) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /device &lt;host&gt;'; return }
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $a0
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $a0)); return }
            Show-TgDevice -Ctx $Ctx -Device $dev
        }
        '/status' {
            if (-not $a0) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /status &lt;host|all&gt;'; return }
            if ($a0 -ieq 'all') { Show-TgFleet -Ctx $Ctx; return }
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $a0
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $a0)); return }
            Invoke-TgIssue -Ctx $Ctx -Device $dev -Type 'status' | Out-Null
            Show-TgDevice -Ctx $Ctx -Device $dev -Note ('{0} status check queued' -f $script:TgIcon.Ok)
        }
        '/agents' {
            if (-not $a0 -or $a0 -ieq 'all') { Invoke-TgSend -Ctx $Ctx -Text 'usage: /agents &lt;host&gt;'; return }
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $a0
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $a0)); return }
            Invoke-TgIssue -Ctx $Ctx -Device $dev -Type 'agents' | Out-Null
            Invoke-TgSend -Ctx $Ctx -Text (Format-TgAgentText -Ctx $Ctx -Device $dev)
        }
        '/harden' {
            if (-not $a0) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /harden &lt;host|all&gt;'; return }
            Invoke-TgFanOut -Ctx $Ctx -Target $a0 -Type 'harden' -AllowAll
        }
        '/restore' {
            if (-not $a0) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /restore &lt;host&gt;'; return }
            Invoke-TgFanOut -Ctx $Ctx -Target $a0 -Type 'restore'
        }
        '/ping' {
            if (-not $a0) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /ping &lt;host&gt;'; return }
            Invoke-TgFanOut -Ctx $Ctx -Target $a0 -Type 'ping'
        }
        '/remove' {
            $sc = ''
            if ($arg.Count -gt 1) { $sc = [string]$arg[1] }
            if (-not $a0 -or -not $sc) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /remove &lt;host&gt; &lt;sc_id&gt;'; return }
            if ($a0 -ieq 'all') { Invoke-TgSend -Ctx $Ctx -Text 'refused: /remove needs a specific host.'; return }
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $a0
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $a0)); return }
            $r = Request-TgRemove -Ctx $Ctx -Device $dev -ScId $sc
            if (-not $r.Ok) { Invoke-TgSend -Ctx $Ctx -Text $r.Error; return }
            Invoke-TgSend -Ctx $Ctx -Text ("About to <b>REMOVE</b> agent <code>{0}</code> on <b>{1}</b>.`nReply <b>/confirm {2}</b> within {3} s." -f $r.ScId, (ConvertTo-TgHtml $a0), $r.Code, $Ctx.ConfirmSec)
        }
        '/confirm' {
            $r = Complete-TgRemove -Ctx $Ctx -Code $a0
            if (-not $r.Ok) { Invoke-TgSend -Ctx $Ctx -Text $r.Error; return }
            Invoke-TgSend -Ctx $Ctx -Text ("Removal of <code>{0}</code> queued for <b>{1}</b>." -f $r.ScId, (ConvertTo-TgHtml $r.Hostname))
        }
        '/reset' {
            if (-not $a0) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /reset &lt;host&gt;'; return }
            if ($a0 -ieq 'all') { Invoke-TgSend -Ctx $Ctx -Text 'refused: /reset needs a specific host.'; return }
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $a0
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $a0)); return }
            $r = Invoke-TgReset -Ctx $Ctx -Device $dev
            Invoke-TgSend -Ctx $Ctx -Text $r.Text
        }
        '/update' { Invoke-TgUpdateCommand -Ctx $Ctx -Argument ([string[]]$arg) }
        '/versions' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgVersionText -Ctx $Ctx) }
        '/events' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgEventText -Ctx $Ctx -Last (Get-TgCount -Argument $arg)) }
        '/audit' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgAuditText -Ctx $Ctx -Last (Get-TgCount -Argument $arg)) }
        default { Invoke-TgSend -Ctx $Ctx -Text ("unknown command: {0} - try /help" -f (ConvertTo-TgHtml $cmd)) }
    }
}

function Invoke-TgCallback {
    <#
    .SYNOPSIS
    Handles one button tap (callback_query) from an admin.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][object]$Callback)
    $mid = $Callback.message.message_id
    $p = @("$($Callback.data)" -split ':')
    $p0 = $p[0]
    $p1 = ''; if ($p.Count -gt 1) { $p1 = $p[1] }
    $p2 = ''; if ($p.Count -gt 2) { $p2 = $p[2] }

    $notFound = { Invoke-TgSend -Ctx $Ctx -Text 'Device not found.' -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:devs' }) -EditMessageId $mid }
    # Routes that change state (issue a command, revoke a token, start/confirm a removal) re-check admin here.
    $executing = @('a:status', 'a:agents', 'a:ping', 'ok:harden', 'ok:restore', 'rst', 'rm', 'rmc', 'fl:hallok', 'fl:pall', 'up:ok', 'up:no')
    $routeKey = $p0
    if (@('a', 'ok', 'fl', 'up') -contains $p0) { $routeKey = "${p0}:${p1}" }
    if ($executing -contains $routeKey) {
        if (-not (Test-TgCallbackAdmin -Ctx $Ctx -Callback $Callback)) { return }
    }

    switch ($p0) {
        'm' {
            switch ($p1) {
                'main' { Invoke-TgSend -Ctx $Ctx -Text '<b>SCGuardian Panel</b>' -Markup (New-TgMenu -Name 'main') -EditMessageId $mid }
                'devs' { Show-TgDevices -Ctx $Ctx -Filter 'a' -Page 1 -EditMessageId $mid }
                'fleet' { Show-TgFleet -Ctx $Ctx -EditMessageId $mid }
                'events' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgEventText -Ctx $Ctx) -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' }) -EditMessageId $mid }
                'audit' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgAuditText -Ctx $Ctx) -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' }) -EditMessageId $mid }
                'help' { Invoke-TgSend -Ctx $Ctx -Text $script:TgHelpText -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' }) -EditMessageId $mid }
            }
        }
        'pg' {
            $n = 1; [void][int]::TryParse($p1, [ref]$n)
            Show-TgDevices -Ctx $Ctx -Filter 'a' -Page $n -EditMessageId $mid
        }
        'dl' {
            $n = 1; [void][int]::TryParse($p2, [ref]$n)
            Show-TgDevices -Ctx $Ctx -Filter (Get-TgFilterKey -Filter $p1) -Page $n -EditMessageId $mid
        }
        'fl' {
            if ($p1 -eq 'r') { Show-TgFleet -Ctx $Ctx -EditMessageId $mid; return }
            $back = New-TgMenu -Name 'back' -Context @{ Callback = 'fl:r' }
            if ($p1 -eq 'hall') {
                $n = @(Get-TgAllDevice -Ctx $Ctx).Count
                if ($n -eq 0) { Invoke-TgSend -Ctx $Ctx -Text 'No devices enrolled.' -Markup $back -EditMessageId $mid; return }
                Invoke-TgSend -Ctx $Ctx -Text ('Harden ALL <b>{0}</b> devices?' -f $n) -Markup (New-TgMenu -Name 'confirm' -Context @{ Action = 'hall' }) -EditMessageId $mid
                return
            }
            if ($p1 -eq 'hallok' -or $p1 -eq 'pall') {
                $type = 'harden'; if ($p1 -eq 'pall') { $type = 'ping' }
                $n = Invoke-TgIssueAll -Ctx $Ctx -Type $type
                if ($n -eq 0) { Invoke-TgSend -Ctx $Ctx -Text 'No devices enrolled.' -Markup $back -EditMessageId $mid; return }
                Invoke-TgSend -Ctx $Ctx -Text ('{0} Queued <b>{1}</b> on {2} device(s).' -f $script:TgIcon.Ok, $type, $n) -Markup $back -EditMessageId $mid
            }
        }
        'up' {
            $back = New-TgMenu -Name 'back' -Context @{ Callback = 'fl:r' }
            if ($p1 -eq 'no') {
                Clear-TgExpiredUpdate
                if ("$p2" -match '^[0-9a-f]{8}\z' -and $script:TgPendingUpdate.ContainsKey($p2) -and $script:TgPendingUpdate[$p2].AdminId -eq [string]$Ctx.AdminId) { $script:TgPendingUpdate.Remove($p2) }
                Invoke-TgSend -Ctx $Ctx -Text 'Update cancelled - nothing was queued.' -Markup $back -EditMessageId $mid
                return
            }
            if ($p1 -ne 'ok') { return }
            $r = Complete-TgUpdateAll -Ctx $Ctx -Token $p2
            if (-not $r.Ok) { Invoke-TgSend -Ctx $Ctx -Text (ConvertTo-TgHtml $r.Error) -Markup $back -EditMessageId $mid; return }
            $txt = ('{0} Update to <b>{1}</b>: {2} queued{5}{3} already current{5}{4} failed.' -f $script:TgIcon.Ok, (ConvertTo-TgHtml $r.Version), $r.Queued, $r.Current, $r.Failed, $script:TgSep)
            Invoke-TgSend -Ctx $Ctx -Text $txt -Markup $back -EditMessageId $mid
        }
        'd' {
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p1 -ByIdPrefix
            if (-not $dev) { & $notFound; return }
            Show-TgDevice -Ctx $Ctx -Device $dev -EditMessageId $mid
        }
        'ok' {
            if (@('harden', 'restore') -notcontains $p1) { return }
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p2 -ByIdPrefix
            if (-not $dev) { & $notFound; return }
            Invoke-TgIssue -Ctx $Ctx -Device $dev -Type $p1 | Out-Null
            Show-TgDevice -Ctx $Ctx -Device $dev -Note (Format-TgQueuedNote -Type $p1 -Device $dev) -EditMessageId $mid
        }
        'a' {
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p2 -ByIdPrefix
            if (-not $dev) { & $notFound; return }
            $name = ConvertTo-TgHtml (Get-TgField -Row $dev -Name @('hostname'))
            $d8 = Get-TgDeviceId8 -Device $dev
            switch ($p1) {
                'status' {
                    Invoke-TgIssue -Ctx $Ctx -Device $dev -Type 'status' | Out-Null
                    Show-TgDevice -Ctx $Ctx -Device $dev -Note ('{0} status check queued' -f $script:TgIcon.Ok) -EditMessageId $mid
                }
                'ping' {
                    Invoke-TgIssue -Ctx $Ctx -Device $dev -Type 'ping' | Out-Null
                    Show-TgDevice -Ctx $Ctx -Device $dev -Note (Format-TgQueuedNote -Type 'ping' -Device $dev) -EditMessageId $mid
                }
                'agents' {
                    Invoke-TgIssue -Ctx $Ctx -Device $dev -Type 'agents' | Out-Null
                    Invoke-TgSend -Ctx $Ctx -Text (Format-TgAgentText -Ctx $Ctx -Device $dev) -Markup (Get-TgDeviceMarkup -Ctx $Ctx -Device $dev) -EditMessageId $mid
                }
                'harden' {
                    Invoke-TgSend -Ctx $Ctx -Text ('Apply protection (service recovery, folder ACL, service SD, registry ACL) to allow-listed agents on <b>{0}</b>?' -f $name) -Markup (New-TgMenu -Name 'confirm' -Context @{ Action = 'harden'; DeviceId8 = $d8 }) -EditMessageId $mid
                }
                'restore' {
                    Invoke-TgSend -Ctx $Ctx -Text ('{0} Remove SCGuardian protection from <b>{1}</b> (restores backed-up ACLs/SD)?' -f $script:TgIcon.Warn, $name) -Markup (New-TgMenu -Name 'confirm' -Context @{ Action = 'restore'; DeviceId8 = $d8 }) -EditMessageId $mid
                }
                'reset' {
                    Invoke-TgSend -Ctx $Ctx -Text ("Revoke the device token of <b>{0}</b>?`nThe agent will re-enroll on its next cycle." -f $name) -Markup (New-TgMenu -Name 'confirm' -Context @{ Action = 'reset'; DeviceId8 = $d8 }) -EditMessageId $mid
                }
                'listrm' {
                    $unknown = @(Get-TgUnknownAgent -Ctx $Ctx -Device $dev)
                    Invoke-TgSend -Ctx $Ctx -Text ("<b>Unknown agents on {0}</b>`npick one to remove:" -f $name) -Markup (New-TgMenu -Name 'remove-list' -Context @{ DeviceId8 = $d8; UnknownId = $unknown }) -EditMessageId $mid
                }
            }
        }
        'rm' {
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p1 -ByIdPrefix
            if (-not $dev) { & $notFound; return }
            $r = Request-TgRemove -Ctx $Ctx -Device $dev -ScId $p2
            if (-not $r.Ok) { Invoke-TgSend -Ctx $Ctx -Text $r.Error -Markup (New-TgMenu -Name 'back' -Context @{ Callback = "d:$p1" }) -EditMessageId $mid; return }
            Invoke-TgSend -Ctx $Ctx -Text ("Remove agent <code>{0}</code> on <b>{1}</b>?`nTap CONFIRM within {2} s." -f $r.ScId, (ConvertTo-TgHtml (Get-TgField -Row $dev -Name @('hostname'))), $Ctx.ConfirmSec) -Markup (New-TgMenu -Name 'remove-confirm' -Context @{ DeviceId8 = $p1; ScId = $r.ScId }) -EditMessageId $mid
        }
        'rst' {
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p1 -ByIdPrefix
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text 'Device not found.' -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:devs' }) -EditMessageId $mid; return }
            $r = Invoke-TgReset -Ctx $Ctx -Device $dev
            Invoke-TgSend -Ctx $Ctx -Text $r.Text -Markup (New-TgMenu -Name 'back' -Context @{ Callback = "d:$p1" }) -EditMessageId $mid
        }
        'rmc' {
            $r = Complete-TgRemove -Ctx $Ctx -SkipCode -DeviceId8 $p1 -ScId $p2
            if (-not $r.Ok) { Invoke-TgSend -Ctx $Ctx -Text $r.Error -Markup (New-TgMenu -Name 'back' -Context @{ Callback = "d:$p1" }) -EditMessageId $mid; return }
            Invoke-TgSend -Ctx $Ctx -Text ("Removal of <code>{0}</code> queued for <b>{1}</b>." -f $r.ScId, (ConvertTo-TgHtml $r.Hostname)) -Markup (New-TgMenu -Name 'back' -Context @{ Callback = "d:$p1" }) -EditMessageId $mid
        }
    }
}

function Invoke-TgRouter {
    <#
    .SYNOPSIS
    Routes one Telegram update. -Send is an injectable scriptblock param($Text,$Markup,$ChatId,$EditMessageId); default uses the Bot API.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Update,
        [Parameter(Mandatory)][object]$Config,
        [scriptblock]$Send
    )
    $token = [string](Get-TgCfgValue -Config $Config -Section 'telegram' -Key 'bot_token' -Default '')
    $chat = [string](Get-TgCfgValue -Config $Config -Section 'telegram' -Key 'chat_id' -Default '')
    $adminIds = @(Get-TgCfgValue -Config $Config -Section 'telegram' -Key 'admin_user_ids' -Default @())
    $adminNames = @(Get-TgCfgValue -Config $Config -Section 'telegram' -Key 'admin_usernames' -Default @())
    $path = [string](Get-TgCfgValue -Config $Config -Section 'database' -Key 'path' -Default '')
    $allowed = @(Get-TgCfgValue -Config $Config -Section 'defaults' -Key 'allowed_ids' -Default @() | ForEach-Object { "$_".ToLowerInvariant() })
    $confirmSec = [int](Get-TgCfgValue -Config $Config -Section 'defaults' -Key 'command_confirm_sec' -Default 120)
    $staleMin = [int](Get-TgCfgValue -Config $Config -Section 'defaults' -Key 'stale_after_min' -Default 5)

    $cb = Get-TgField -Row $Update -Name @('callback_query')
    $msg = Get-TgField -Row $Update -Name @('message')
    $from = $null; $srcChat = ''
    if ($cb) { $from = $cb.from; $srcChat = [string]$cb.message.chat.id }
    elseif ($msg) { $from = $msg.from; $srcChat = [string]$msg.chat.id }
    else { return }
    if ($chat -eq '' -or $srcChat -ne $chat) { return }

    $fromId = [string](Get-TgField -Row $from -Name @('id') -Default '')
    $isAdmin = Test-TgAdmin -From $from -AdminUserId $adminIds -AdminUsername $adminNames
    $ctx = @{
        Config = $Config; Send = $Send; Path = $path; ChatId = $chat; AdminId = $fromId
        Actor = "telegram:$fromId"; AllowedIds = $allowed; ConfirmSec = $confirmSec; StaleMin = $staleMin
        Token = $token; AdminIds = $adminIds; AdminNames = $adminNames
    }

    try {
        if ($cb) {
            if (-not $isAdmin) {
                Invoke-TgApi -Token $token -Method 'answerCallbackQuery' -Body @{ callback_query_id = $cb.id; text = 'Unauthorized'; show_alert = $true } | Out-Null
                Add-ScgAudit -Path $path -Actor $ctx.Actor -Action 'auth.reject' -Target 'callback' -Meta @{ data = "$($cb.data)" } | Out-Null
                return
            }
            Invoke-TgApi -Token $token -Method 'answerCallbackQuery' -Body @{ callback_query_id = $cb.id } | Out-Null
            Invoke-TgCallback -Ctx $ctx -Callback $cb
            return
        }
        $parsed = ConvertFrom-TgCommand -Text ([string]$msg.text)
        if (-not $parsed) { return }
        if ($parsed.Command -eq '/whoami') {
            $uname = ConvertTo-TgHtml (Get-TgField -Row $from -Name @('username') -Default '')
            Invoke-TgSend -Ctx $ctx -Text ("id: <code>{0}</code> username: @{1} admin: {2}" -f (ConvertTo-TgHtml $fromId), $uname, $isAdmin)
            return
        }
        if (-not $isAdmin) {
            Add-ScgAudit -Path $path -Actor $ctx.Actor -Action 'auth.reject' -Target $parsed.Command -Meta @{ via = 'message' } | Out-Null
            return
        }
        Invoke-TgMessageCommand -Ctx $ctx -Parsed $parsed
    } catch {
        Write-ScgLog -Message "telegram router error: $($_.Exception.Message)" -Level ERROR -Actor $ctx.Actor -Action 'telegram.router' -Result 'error'
        try { Invoke-TgSend -Ctx $ctx -Text 'Internal error - see hub log.' } catch { $null = $_ }
    }
}

function Invoke-TgPollOnce {
    <#
    .SYNOPSIS
    One long-poll cycle: fetch updates from State.Offset, route each, advance the offset. Returns the update count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][hashtable]$State,
        [scriptblock]$Send
    )
    $token = [string](Get-TgCfgValue -Config $Config -Section 'telegram' -Key 'bot_token' -Default '')
    if (-not $State.ContainsKey('Offset')) { $State['Offset'] = 0 }
    $updates = @(Get-TgUpdate -Token $token -Offset ([int]$State['Offset']))
    foreach ($u in $updates) {
        if ($null -eq $u) { continue }
        $uid = [int64](Get-TgField -Row $u -Name @('update_id') -Default 0)
        if ($uid -ge [int64]$State['Offset']) { $State['Offset'] = [int]($uid + 1) }
        $routeArg = @{ Update = $u; Config = $Config }
        if ($Send) { $routeArg.Send = $Send }
        Invoke-TgRouter @routeArg
    }
    return $updates.Count
}

function Send-TgResultNotice {
    <#
    .SYNOPSIS
    Formats a finished command (type, status/ok, output, device) and posts it to the ops chat.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][object]$Command,
        [scriptblock]$Send
    )
    $path = [string](Get-TgCfgValue -Config $Config -Section 'database' -Key 'path' -Default '')
    $chat = [string](Get-TgCfgValue -Config $Config -Section 'telegram' -Key 'chat_id' -Default '')
    if ($chat -eq '') { return }
    $type = [string](Get-TgField -Row $Command -Name @('type') -Default 'command')
    $status = [string](Get-TgField -Row $Command -Name @('status') -Default '')
    if ($status -eq '') {
        $okv = Get-TgField -Row $Command -Name @('ok')
        if ($null -ne $okv -and [bool]$okv) { $status = 'done' } else { $status = 'failed' }
    }
    $host1 = [string](Get-TgField -Row $Command -Name @('hostname') -Default '')
    if ($host1 -eq '') {
        $did = [string](Get-TgField -Row $Command -Name @('device_id') -Default '')
        if ($did -ne '' -and $path -ne '') {
            $dev = @(Get-ScgDevice -Path $path -DeviceId $did) | Select-Object -First 1
            $host1 = [string](Get-TgField -Row $dev -Name @('hostname') -Default $did)
        }
    }
    $output = [string](Get-TgField -Row $Command -Name @('output') -Default '')
    $dur = Get-TgField -Row $Command -Name @('duration_ms')
    $icon = $script:TgIcon.Ok
    if ($status -ne 'done') { $icon = $script:TgIcon.No }
    $text = "{0} <b>{1}</b> on <b>{2}</b>: {3}" -f $icon, (ConvertTo-TgHtml $type), (ConvertTo-TgHtml $host1), (ConvertTo-TgHtml $status)
    if ($null -ne $dur) { $text += (" ({0} ms)" -f (ConvertTo-TgHtml $dur)) }
    if ($output -ne '') { $text += "`n<pre>" + (ConvertTo-TgHtml $output) + '</pre>' }
    $ctx = @{ Config = $Config; Send = $Send; ChatId = $chat }
    Invoke-TgSend -Ctx $ctx -Text $text
}

Export-ModuleMember -Function Invoke-TgApi, Get-TgUpdate, ConvertFrom-TgCommand, Test-TgAdmin, New-TgMenu, Invoke-TgRouter, New-TgRemoveCode, Invoke-TgPollOnce, Send-TgResultNotice, Get-TgDeviceState, Format-TgAgo
