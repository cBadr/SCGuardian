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
}

$script:TgHelpText = @'
<b>SCGuardian - commands</b>
/panel - open the button control panel
/devices [page] - list devices
/status &lt;host|all&gt; - device or fleet status
/agents &lt;host&gt; - list SC agents on a host
/harden &lt;host|all&gt; - queue a hardening pass
/restore &lt;host&gt; - queue undo-hardening on a host
/remove &lt;host&gt; &lt;sc_id&gt; - remove an UNKNOWN agent (2-step confirm)
/confirm &lt;code&gt; - confirm a pending removal
/ping &lt;host&gt; - ping a device through the hub
/events [n] - latest events
/audit [n] - latest audit entries
/whoami - show your Telegram id
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

function Get-TgDeviceIcon {
    <#
    .SYNOPSIS
    Status glyph: online / stale / quarantined.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Device)
    $st = [string](Get-TgField -Row $Device -Name @('status') -Default 'active')
    if ($st -eq 'quarantined') { return $script:TgIcon.Quar }
    if ($st -eq 'stale') { return $script:TgIcon.Stale }
    return $script:TgIcon.Online
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
    param([object[]]$Item = @(), [int]$Page = 1)
    $items = @($Item)
    $pages = [int][Math]::Max(1, [Math]::Ceiling($items.Count / [double]$script:TgPageSize))
    if ($Page -lt 1) { $Page = 1 }
    if ($Page -gt $pages) { $Page = $pages }
    $skip = ($Page - 1) * $script:TgPageSize
    $slice = @($items | Select-Object -Skip $skip -First $script:TgPageSize)
    return [pscustomobject]@{ Items = $slice; Page = $Page; Pages = $pages }
}

function New-TgMenu {
    <#
    .SYNOPSIS
    Builds an inline-keyboard reply_markup. Names: main, devices, device, remove-list, remove-confirm, back.
    Context keys: devices {Devices,Page} | device {Device,HasUnknown} | remove-list {DeviceId8,UnknownId} | remove-confirm {DeviceId8,ScId} | back {Callback}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('main', 'devices', 'device', 'remove-list', 'remove-confirm', 'back')][string]$Name,
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
            $slice = Get-TgPageSlice -Item @($Context.Devices) -Page ([int]$Context.Page)
            foreach ($d in $slice.Items) {
                $d8 = Get-TgDeviceId8 -Device $d
                $host1 = [string](Get-TgField -Row $d -Name @('hostname') -Default $d8)
                [void]$rows.Add(@((New-TgButton "$(Get-TgDeviceIcon -Device $d) $host1" "d:$d8")))
                [void]$rows.Add(@(
                        (New-TgButton 'Status' "a:status:$d8"),
                        (New-TgButton 'Harden' "a:harden:$d8"),
                        (New-TgButton 'Agents' "a:agents:$d8"),
                        (New-TgButton 'Restore' "a:restore:$d8")))
            }
            $pager = New-Object System.Collections.ArrayList
            if ($slice.Page -gt 1) { [void]$pager.Add((New-TgButton "$($i.Back) Prev" ("pg:{0}" -f ($slice.Page - 1)))) }
            [void]$pager.Add((New-TgButton ("{0}/{1}" -f $slice.Page, $slice.Pages) ("pg:{0}" -f $slice.Page)))
            if ($slice.Page -lt $slice.Pages) { [void]$pager.Add((New-TgButton "Next $($i.Next)" ("pg:{0}" -f ($slice.Page + 1)))) }
            [void]$rows.Add($pager.ToArray())
            [void]$rows.Add(@((New-TgButton "$($i.Back) Back" 'm:main')))
        }
        'device' {
            $d8 = Get-TgDeviceId8 -Device $Context.Device
            [void]$rows.Add(@((New-TgButton 'Status' "a:status:$d8"), (New-TgButton "$($i.Harden) Harden" "a:harden:$d8")))
            [void]$rows.Add(@((New-TgButton 'Agents' "a:agents:$d8"), (New-TgButton 'Restore' "a:restore:$d8")))
            if ($Context.HasUnknown) { [void]$rows.Add(@((New-TgButton "$($i.Broom) Remove unknown" "a:listrm:$d8"))) }
            [void]$rows.Add(@((New-TgButton "$($i.Back) Devices" 'm:devs')))
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
    param([Parameter(Mandatory)][hashtable]$Ctx, [Parameter(Mandatory)][object]$Device)
    $did = [string](Get-TgField -Row $Device -Name @('id', 'device_id'))
    $out = @()
    foreach ($a in @(Get-ScgScAgent -Path $Ctx.Path -DeviceId $did)) {
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

function Format-TgDeviceLine {
    <#
    .SYNOPSIS
    One HTML line describing a device.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Device)
    $host1 = ConvertTo-TgHtml (Get-TgField -Row $Device -Name @('hostname') -Default '?')
    $st = ConvertTo-TgHtml (Get-TgField -Row $Device -Name @('status') -Default 'active')
    $seen = ConvertTo-TgHtml (Get-TgField -Row $Device -Name @('last_seen', 'last_seen_utc') -Default '-')
    return ("{0} <b>{1}</b> - {2} - seen {3}" -f (Get-TgDeviceIcon -Device $Device), $host1, $st, $seen)
}

function Format-TgFleetText {
    <#
    .SYNOPSIS
    Fleet summary text (counts + one line per device, capped).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $devs = Get-TgAllDevice -Ctx $Ctx
    $health = Get-ScgHealthCounts -Path $Ctx.Path -StaleAfterMin $Ctx.StaleMin
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('<b>Fleet status</b>')
    [void]$lines.Add(("devices: {0} | online: {1} | pending commands: {2}" -f $devs.Count, (ConvertTo-TgHtml (Get-TgField -Row $health -Name @('devices_online') -Default 0)), (ConvertTo-TgHtml (Get-TgField -Row $health -Name @('commands_pending') -Default 0))))
    foreach ($d in @($devs | Select-Object -First 30)) { [void]$lines.Add((Format-TgDeviceLine -Device $d)) }
    if ($devs.Count -gt 30) { [void]$lines.Add(("... and {0} more (see /devices)" -f ($devs.Count - 30))) }
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
            Invoke-TgSend -Ctx $Ctx -Text '<b>Devices</b> (tap one)' -Markup (New-TgMenu -Name 'devices' -Context @{ Devices = (Get-TgAllDevice -Ctx $Ctx); Page = $page })
        }
        '/status' {
            if (-not $a0) { Invoke-TgSend -Ctx $Ctx -Text 'usage: /status &lt;host|all&gt;'; return }
            if ($a0 -ieq 'all') { Invoke-TgSend -Ctx $Ctx -Text (Format-TgFleetText -Ctx $Ctx); return }
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $a0
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text ("Unknown host: <code>{0}</code>" -f (ConvertTo-TgHtml $a0)); return }
            Invoke-TgIssue -Ctx $Ctx -Device $dev -Type 'status' | Out-Null
            Invoke-TgSend -Ctx $Ctx -Text ((Format-TgDeviceLine -Device $dev) + "`n" + 'status check queued')
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

    $deviceMenu = {
        param($dev)
        $has = ((Get-TgUnknownAgent -Ctx $Ctx -Device $dev).Count -gt 0)
        New-TgMenu -Name 'device' -Context @{ Device = $dev; HasUnknown = $has }
    }

    switch ($p0) {
        'm' {
            switch ($p1) {
                'main' { Invoke-TgSend -Ctx $Ctx -Text '<b>SCGuardian Panel</b>' -Markup (New-TgMenu -Name 'main') -EditMessageId $mid }
                'devs' { Invoke-TgSend -Ctx $Ctx -Text '<b>Devices</b> (tap one)' -Markup (New-TgMenu -Name 'devices' -Context @{ Devices = (Get-TgAllDevice -Ctx $Ctx); Page = 1 }) -EditMessageId $mid }
                'fleet' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgFleetText -Ctx $Ctx) -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' }) -EditMessageId $mid }
                'events' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgEventText -Ctx $Ctx) -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' }) -EditMessageId $mid }
                'audit' { Invoke-TgSend -Ctx $Ctx -Text (Format-TgAuditText -Ctx $Ctx) -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' }) -EditMessageId $mid }
                'help' { Invoke-TgSend -Ctx $Ctx -Text $script:TgHelpText -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' }) -EditMessageId $mid }
            }
        }
        'pg' {
            $n = 1; [void][int]::TryParse($p1, [ref]$n)
            Invoke-TgSend -Ctx $Ctx -Text '<b>Devices</b> (tap one)' -Markup (New-TgMenu -Name 'devices' -Context @{ Devices = (Get-TgAllDevice -Ctx $Ctx); Page = $n }) -EditMessageId $mid
        }
        'd' {
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p1 -ByIdPrefix
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text 'Device not found.' -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:devs' }) -EditMessageId $mid; return }
            Invoke-TgSend -Ctx $Ctx -Text (Format-TgDeviceLine -Device $dev) -Markup (& $deviceMenu $dev) -EditMessageId $mid
        }
        'a' {
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p2 -ByIdPrefix
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text 'Device not found.' -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:devs' }) -EditMessageId $mid; return }
            $name = ConvertTo-TgHtml (Get-TgField -Row $dev -Name @('hostname'))
            switch ($p1) {
                { $_ -in @('status', 'harden', 'restore', 'agents') } {
                    Invoke-TgIssue -Ctx $Ctx -Device $dev -Type $p1 | Out-Null
                    $txt = ("Queued <b>{0}</b> on <b>{1}</b>." -f (ConvertTo-TgHtml $p1), $name)
                    if ($p1 -eq 'agents') { $txt = Format-TgAgentText -Ctx $Ctx -Device $dev }
                    if ($p1 -eq 'status') { $txt = (Format-TgDeviceLine -Device $dev) + "`nstatus check queued" }
                    Invoke-TgSend -Ctx $Ctx -Text $txt -Markup (& $deviceMenu $dev) -EditMessageId $mid
                }
                'listrm' {
                    $unknown = Get-TgUnknownAgent -Ctx $Ctx -Device $dev
                    Invoke-TgSend -Ctx $Ctx -Text ("<b>Unknown agents on {0}</b>`npick one to remove:" -f $name) -Markup (New-TgMenu -Name 'remove-list' -Context @{ DeviceId8 = (Get-TgDeviceId8 -Device $dev); UnknownId = $unknown }) -EditMessageId $mid
                }
            }
        }
        'rm' {
            $dev = Resolve-TgDevice -Ctx $Ctx -Name $p1 -ByIdPrefix
            if (-not $dev) { Invoke-TgSend -Ctx $Ctx -Text 'Device not found.' -Markup (New-TgMenu -Name 'back' -Context @{ Callback = 'm:devs' }) -EditMessageId $mid; return }
            $r = Request-TgRemove -Ctx $Ctx -Device $dev -ScId $p2
            if (-not $r.Ok) { Invoke-TgSend -Ctx $Ctx -Text $r.Error -Markup (New-TgMenu -Name 'back' -Context @{ Callback = "d:$p1" }) -EditMessageId $mid; return }
            Invoke-TgSend -Ctx $Ctx -Text ("Remove agent <code>{0}</code> on <b>{1}</b>?`nTap CONFIRM within {2} s." -f $r.ScId, (ConvertTo-TgHtml (Get-TgField -Row $dev -Name @('hostname'))), $Ctx.ConfirmSec) -Markup (New-TgMenu -Name 'remove-confirm' -Context @{ DeviceId8 = $p1; ScId = $r.ScId }) -EditMessageId $mid
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

Export-ModuleMember -Function Invoke-TgApi, Get-TgUpdate, ConvertFrom-TgCommand, Test-TgAdmin, New-TgMenu, Invoke-TgRouter, New-TgRemoveCode, Invoke-TgPollOnce, Send-TgResultNotice
