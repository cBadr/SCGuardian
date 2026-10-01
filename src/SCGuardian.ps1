<#
================================================================================
 SCGuardian.ps1  -  ScreenConnect Agent Guardian  (single-file, rev 3)
--------------------------------------------------------------------------------
 GOAL: Protect YOUR ScreenConnect Access agents (allow-listed instance IDs)
       and REPORT everything else via Telegram. A human decides what to do
       about anything that is not yours.

 Intentionally VISIBLE, LOGGED and REVERSIBLE. The opposite of hiding software.
   - Discover + classify agents by instance ID: MINE (allow-list) vs UNKNOWN.
   - Harden MY agents only: service recovery, folder ACL, service SD, registry ACL.
   - Watchdog: RESTART my service if stopped and re-assert config/permissions.
   - Telegram alerts (unknown agent, new install, tamper, watchdog action).
   - Back up every ACL/SD before changing it, with a full Restore mode.
 It NEVER removes/disables/uninstalls any agent, NEVER blocks installs, and
 NEVER re-installs my agent (restart only) - those stay human decisions.

--------------------------------------------------------------------------------
 SINGLE-FILE DEPLOYMENT
   1. Edit the CONFIG block below (allow-list IDs, Telegram token/chat id, and
      the $Defaults that control what a bare run does).
   2. Copy this ONE file to each machine and just run it:
        - right-click > "Run with PowerShell", or
        - powershell -ExecutionPolicy Bypass -File .\SCGuardian.ps1
      With no parameters it applies $Defaults automatically (harden + watchdog),
      and if it is not elevated it asks for Administrator rights via UAC.

 MODES (optional overrides; bare run uses $Defaults instead)
   -TestTelegram                   send a test message, print the exact result
   -Mode Report                    scan + print, no changes
   -Mode Harden [-InstallSchedule] apply hardening (+ install the watchdog task)
   -Mode Monitor                   what the scheduled task runs (restart+alert)
   -Mode Restore [-RemoveSchedule] undo all hardening (+ remove the task)
   -TakeOwnership                  (Harden) take ownership of the agent folder
                                   first, so folder ACL applies even when the
                                   installer locked it (more invasive).
   -AlertThrottleMinutes N         min gap between repeats of the same alert
                                   (default from $Defaults; 0 = never throttle)
   -Mode Listen                    one command-poll cycle (for testing 2-way Telegram)

 TWO-WAY TELEGRAM (ops center)
   The watchdog (Monitor) also polls the ops group for /commands and acts on the
   ones addressed to its hostname. Only AdminUserIds/AdminUsernames may command;
   destructive /remove needs a 2-step /confirm. Commands: /help /status /agents
   /harden /remove <host> <id> /confirm <code> /restore <host> <id> /whoami

 v4 HUB/AGENT MODES (module-based; ignore the CONFIG block and legacy token)
   -Mode Hub       [-HubConfigPath]    run the central hub (modules: Common, Database,
                                       HttpServer, Telegram, Hub - no self-hardening)
   -Mode Agent     [-AgentConfigPath]  one agent cycle against the hub, then exit
   -Mode AgentLoop [-AgentConfigPath]  agent scheduler loop (stop-file: agent.stop)
   -InstallAgent / -RemoveAgent        register/remove task 'SCGuardian-Agent'
   Modules are loaded from .\modules, else C:\Program Files\SCGuardian\modules.

 EXIT CODES: 0 = ok / work done   1 = nothing matched   2 = error / restore incomplete
================================================================================
#>

[CmdletBinding()]
param(
    [string[]] $AllowedIds,

    [ValidateSet('Report','Harden','Monitor','Restore','Listen','Controller','Hub','Agent','AgentLoop')]
    [string]   $Mode,                          # unset => use CONFIG $Defaults.Mode

    [ValidateSet('Recovery','FolderAcl','ServiceSd','RegistryAcl')]
    [string[]] $Layers,                        # unset => use CONFIG $Defaults.Layers

    [string]   $TelegramBotToken,
    [string]   $TelegramChatId,

    [switch]   $TestTelegram,
    [switch]   $InstallSchedule,
    [switch]   $RemoveSchedule,
    [switch]   $InstallController,
    [switch]   $TakeOwnership,
    [int]      $ScanIntervalMinutes = 0,      # 0  = use CONFIG $Defaults
    [int]      $HeartbeatHours       = -1,     # -1 = use CONFIG $Defaults
    [int]      $AlertThrottleMinutes = -1,     # -1 = use CONFIG $Defaults
    [switch]   $SaveConfig,
    [string]   $HubConfigPath   = 'C:\ProgramData\SCGuardian\hub.config.json',
    [string]   $AgentConfigPath = 'C:\ProgramData\SCGuardian\agent.config.json',
    [switch]   $InstallAgent,
    [switch]   $RemoveAgent,
    [switch]   $Elevated                      # internal: set when auto-relaunched elevated
)

# ============================== CONFIG (EDIT ME) ==============================
$EmbeddedConfig = @{
    AllowedIds       = @('5d0931a9fafc2a8b','4c37282122b38af3')
    TelegramBotToken = ''      # <-- paste your BotFather token here
    TelegramChatId   = ''   # supergroup id (migrated from the old group id -5425199858)
    # Who is allowed to send COMMANDS from Telegram (destructive ones included).
    AdminUserIds     = @()    # numeric Telegram user id(s) - the secure way (@Idlexaz)
    AdminUsernames   = @('Idlexaz')       # username fallback (less secure; usernames can change)
}

# What a BARE run (no parameters / right-click Run) does automatically, and the
# values the scheduled watchdog uses. EDIT THESE to change default behavior.
$Defaults = @{
    Mode                 = 'Harden'      # bare-run action: Report | Harden | Monitor | Restore
    InstallSchedule      = $true         # bare run also installs/refreshes the watchdog
    Layers               = @('Recovery','FolderAcl','ServiceSd','RegistryAcl')
    ScanIntervalMinutes  = 1            # how often the watchdog runs
    HeartbeatHours       = 24            # periodic "all OK" ping; 0 = off
    AlertThrottleMinutes = 15            # min gap between repeats of the SAME alert.
                                         #  <= ScanIntervalMinutes => alert on (almost) every scan; 0 = never throttle
    TakeOwnership        = $false        # take folder ownership to force H2 when the installer locked it
    ListenForCommands    = $false        # legacy per-device text polling; keep OFF - the Controller is the sole poller
    CommandConfirmSeconds= 300           # how long a /remove confirmation code stays valid
}
# ==============================================================================

# ------------------------------------------------------------------ constants --
$ErrorActionPreference = 'Stop'
$Root      = 'C:\ProgramData\SCGuardian'
$LogFile   = Join-Path $Root 'guardian.log'
$StateFile = Join-Path $Root 'state.json'
$ConfigFile= Join-Path $Root 'SCGuardian.config.json'
$BackupDir = Join-Path $Root 'Backup'
$TaskName  = 'SCGuardian-Watchdog'
$IdRegex   = '\(([0-9A-Fa-f]{16})\)'
$LogMaxBytes = 5MB

# well-known SIDs (locale-independent)
$SID_SYSTEM = '*S-1-5-18'
$SID_ADMINS = '*S-1-5-32-544'
$SID_USERS  = '*S-1-5-32-545'

# fallback SDDLs used by Restore when no backup exists (unlock to a sane default)
$DEFAULT_SVC_SDDL = 'D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
$DEFAULT_REG_SDDL = 'D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;AU)'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$script:RestoreFailed   = $false
$script:ScheduleChanged = $false

# ------------------------------------------------------------------- helpers ---
function Ensure-Dirs {
    foreach ($d in @($Root,$BackupDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    # lock the working dir so the stored token / copied script are not world-readable
    Invoke-Native 'icacls' @($Root,'/inheritance:r','/grant:r',"$($SID_SYSTEM):(OI)(CI)F","$($SID_ADMINS):(OI)(CI)F") | Out-Null
}

function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR','ALERT')][string]$Level='INFO')
    try {
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt $LogMaxBytes)) {
            $roll = "$LogFile.1"; if (Test-Path $roll) { Remove-Item $roll -Force }
            Rename-Item $LogFile $roll -Force
        }
    } catch {}
    $line = "{0}  [{1}]  {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ALERT' { Write-Host $line -ForegroundColor Cyan }
        default { Write-Host $line }
    }
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch {}
}

function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# path of THIS artifact (the .exe when packed, else the .ps1) - used for self-copy + relaunch
function Get-SelfPath {
    if ($env:SCG_SELF) { return $env:SCG_SELF }                 # set by the .exe launcher
    if ($PSCommandPath) { return $PSCommandPath }
    try { $p = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
          if ($p -and ($p -notmatch '(?i)\\(powershell|powershell_ise|pwsh)\.exe$')) { return $p } } catch {}
    if ($MyInvocation.MyCommand.Path) { return $MyInvocation.MyCommand.Path }
    return $null
}

# run sc.exe and return exit code + captured output
# run a native exe capturing exit code + merged output, WITHOUT letting stderr
# become a terminating error (icacls/takeown write to stderr; ErrorActionPreference
# = 'Stop' would otherwise throw on that).
function Invoke-Native {
    param([string]$Exe,[string[]]$Arguments)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = $null
    try   { $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } }
    catch { $out = @("$($_.Exception.Message)") }
    finally { $ErrorActionPreference = $old }
    return [pscustomobject]@{ Code=$LASTEXITCODE; Out=((@($out)) -join ' ').Trim() }
}

# ---------------------------------------------------- settings resolution ------
# precedence:  explicit -param  >  json config file  >  embedded CONFIG block
function Resolve-Settings {
    param([hashtable]$Bound)
    $ids   = $EmbeddedConfig.AllowedIds
    $token = $EmbeddedConfig.TelegramBotToken
    $chat  = $EmbeddedConfig.TelegramChatId
    $aids  = @($EmbeddedConfig.AdminUserIds)
    $anames= @($EmbeddedConfig.AdminUsernames)
    if (Test-Path $ConfigFile) {
        try {
            $c = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            if ($c.AllowedIds)       { $ids   = @($c.AllowedIds) }
            if ($c.TelegramBotToken) { $token = $c.TelegramBotToken }
            if ($c.TelegramChatId)   { $chat  = $c.TelegramChatId }
            if ($c.AdminUserIds)     { $aids  = @($c.AdminUserIds) }
            if ($c.AdminUsernames)   { $anames= @($c.AdminUsernames) }
        } catch { Write-Log "Could not read config file: $($_.Exception.Message)" WARN }
    }
    if ($Bound.ContainsKey('AllowedIds')       -and $AllowedIds)       { $ids   = $AllowedIds }
    if ($Bound.ContainsKey('TelegramBotToken') -and $TelegramBotToken) { $token = $TelegramBotToken }
    if ($Bound.ContainsKey('TelegramChatId')   -and $TelegramChatId)   { $chat  = $TelegramChatId }
    $script:AllowedIds       = @($ids)
    $script:TelegramBotToken = $token
    $script:TelegramChatId   = $chat
    $script:AdminUserIds     = @($aids   | ForEach-Object { "$_" })
    $script:AdminUsernames   = @($anames | ForEach-Object { "$_" })
}

# fill any parameter not given on the command line from the CONFIG $Defaults.
function Resolve-Defaults {
    param([hashtable]$Bound)
    $bareRun = -not $Bound.ContainsKey('Mode')
    if (-not $Bound.ContainsKey('Mode'))          { $script:Mode   = $Defaults.Mode }
    if (-not $Bound.ContainsKey('Layers'))        { $script:Layers = $Defaults.Layers }
    if (-not $Bound.ContainsKey('TakeOwnership')) { $script:TakeOwnership = [switch]([bool]$Defaults.TakeOwnership) }
    # InstallSchedule default applies only on a true bare run (never forces it under -Mode Monitor/Report)
    if (-not $Bound.ContainsKey('InstallSchedule')) { $script:InstallSchedule = [switch]($bareRun -and [bool]$Defaults.InstallSchedule) }
    if ((-not $Bound.ContainsKey('ScanIntervalMinutes'))  -or ($ScanIntervalMinutes -le 0))  { $script:ScanIntervalMinutes  = [int]$Defaults.ScanIntervalMinutes }
    if ((-not $Bound.ContainsKey('HeartbeatHours'))       -or ($HeartbeatHours -lt 0))       { $script:HeartbeatHours       = [int]$Defaults.HeartbeatHours }
    if ((-not $Bound.ContainsKey('AlertThrottleMinutes')) -or ($AlertThrottleMinutes -lt 0)) { $script:AlertThrottleMinutes = [int]$Defaults.AlertThrottleMinutes }
    if ($ScanIntervalMinutes -lt 1 -or $ScanIntervalMinutes -gt 1440) { $script:ScanIntervalMinutes = 15 }
    $script:ListenForCommands     = [bool]$Defaults.ListenForCommands
    $script:CommandConfirmSeconds = [int]$Defaults.CommandConfirmSeconds
    if ($CommandConfirmSeconds -lt 30) { $script:CommandConfirmSeconds = 300 }
}

# re-launch elevated (UAC prompt), passing the same parameters through, then exit.
function Invoke-Elevation {
    param([hashtable]$Bound)
    $self = Get-SelfPath
    if (-not $self) { return $false }
    $isExe = $self -match '(?i)\.exe$'
    $a = @()
    if (-not $isExe) { $a += @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$self+'"')) }
    foreach ($k in $Bound.Keys) {
        if ($k -eq 'Elevated') { continue }
        $v = $Bound[$k]
        if     ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $a += "-$k" } }
        elseif ($v -is [array]) { $a += "-$k"; $a += ('"'+($v -join ',')+'"') }
        else   { $a += "-$k"; $a += ('"'+$v+'"') }
    }
    $a += '-Elevated'
    try {
        if ($isExe) { Start-Process -FilePath $self -ArgumentList $a -Verb RunAs | Out-Null }
        else        { Start-Process -FilePath 'powershell.exe' -ArgumentList $a -Verb RunAs | Out-Null }
        return $true
    } catch { return $false }
}

function Save-ConfigFile {
    $obj = [ordered]@{
        AllowedIds       = $AllowedIds
        TelegramBotToken = $TelegramBotToken
        TelegramChatId   = $TelegramChatId
        AdminUserIds     = $AdminUserIds
        AdminUsernames   = $AdminUsernames
    }
    $obj | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
    Write-Log "Config saved to $ConfigFile"
}

# ------------------------------------------------------------------- state -----
function Load-State {
    if (Test-Path $StateFile) {
        try { return Get-Content $StateFile -Raw | ConvertFrom-Json } catch {}
    }
    return [pscustomobject]@{ KnownSignatures=@(); Alerts=(New-Object psobject); LastHeartbeatUtc=$null; ProcessedUpdateIds=@(); CommandChannelInit=$false; PendingRemoval=$null }
}
function Save-State($state) {
    try { $state | ConvertTo-Json -Depth 6 | Set-Content -Path $StateFile -Encoding UTF8 } catch { Write-Log "state save failed: $($_.Exception.Message)" WARN }
}

# ------------------------------------------------------------------ telegram ---
function ConvertTo-HtmlSafe([string]$s) {
    if ($null -eq $s) { return '' }
    return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
}

# low-level send; returns $true/$false and logs the exact Telegram error body on failure
function Invoke-TelegramSend([string]$Text) {
    if (-not $TelegramBotToken -or -not $TelegramChatId) { Write-Log 'Telegram not configured; alert logged only.' WARN; return $false }
    $uri  = "https://api.telegram.org/bot$TelegramBotToken/sendMessage"
    $payload = @{ chat_id = $TelegramChatId; text = $Text; parse_mode = 'HTML'; disable_web_page_preview = $true }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
    try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 25 | Out-Null
        return $true
    } catch {
        # $_.ErrorDetails.Message carries Telegram's JSON body (the real reason, e.g. chat migrated / not found)
        $desc = $_.ErrorDetails.Message
        if (-not $desc -and $_.Exception.Response) { try { $sr = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream()); $desc = $sr.ReadToEnd(); $sr.Close() } catch {} }
        Write-Log "Telegram send failed: $($_.Exception.Message) | $desc" WARN   # note: never logs the URI/token
        return $false
    }
}

function Send-Telegram {
    param([string]$Text,[string]$Key,[switch]$Force,$State)
    Write-Log "ALERT: $($Text -replace '\s+',' ')" ALERT
    if (-not $TelegramBotToken -or -not $TelegramChatId) { return }

    if ($Key -and $State -and -not $Force) {
        $prev = $null
        if ($State.Alerts.PSObject.Properties.Name -contains $Key) { $prev = $State.Alerts.$Key }
        if ($prev -and $AlertThrottleMinutes -gt 0) {
            $age = (Get-Date).ToUniversalTime() - ([datetime]$prev).ToUniversalTime()
            if ($age.TotalMinutes -lt $AlertThrottleMinutes) { Write-Log "throttled alert '$Key' (last sent $([int]$age.TotalMinutes)m ago; throttle=${AlertThrottleMinutes}m)"; return }
        }
    }

    $hostName = ConvertTo-HtmlSafe $env:COMPUTERNAME
    $full = "<b>SCGuardian</b> @ $hostName`n$Text"
    if (Invoke-TelegramSend $full) {
        if ($Key -and $State) { $State.Alerts | Add-Member -NotePropertyName $Key -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force }
    }
}

# ------------------------------------------------------ telegram command center
$script:CmdHelp = @"
<b>SCGuardian - commands</b>
/panel               - open the button control panel
/status [host|all]   - inventory + counts
/agents [host|all]   - list agents (mine / unknown)
/harden [host|all]   - force a hardening pass
/remove &lt;host&gt; &lt;id&gt;  - remove a specific UNKNOWN agent (2-step confirm)
/confirm &lt;code&gt;      - confirm a pending removal
/restore &lt;host&gt; &lt;id&gt; - undo hardening on one of YOUR agents
/whoami              - show your Telegram id
(host = a machine name, or 'all')
"@

function Reply-Tg([string]$Text) {
    $h = ConvertTo-HtmlSafe $env:COMPUTERNAME
    Invoke-TelegramSend ("<b>SCGuardian</b> @ $h`n$Text") | Out-Null
}

function Test-HostTarget($h) {
    if (-not $h) { return $true }
    if ($h -eq 'all') { return $true }
    return ($h -ieq $env:COMPUTERNAME)
}

function Get-InventoryText {
    $agents  = @(Get-Agents)
    $mine    = @($agents | Where-Object { $_.Authorized })
    $unknown = @($agents | Where-Object { -not $_.Authorized })
    $lines = @("<b>inventory</b>  mine=$($mine.Count)  unknown=$($unknown.Count)")
    foreach ($a in $mine)    { $lines += "MINE    <code>$($a.Id)</code>  svc=$(ConvertTo-HtmlSafe $a.ServiceState)" }
    foreach ($a in $unknown) { $lines += "UNKNOWN <code>$($a.Id)</code>  svc=$(ConvertTo-HtmlSafe $a.ServiceState)  -> /remove $env:COMPUTERNAME $($a.Id)" }
    return ($lines -join "`n")
}

# read pending Telegram messages (no offset: dedup locally so many devices can share one bot)
function Get-TelegramUpdates {
    if (-not $TelegramBotToken -or -not $TelegramChatId) { return @() }
    try {
        $r = Invoke-RestMethod -Uri "https://api.telegram.org/bot$TelegramBotToken/getUpdates?timeout=0&allowed_updates=%5B%22message%22%5D" -Method Get -TimeoutSec 20
        if ($r.ok) { return @($r.result) }
    } catch {
        $d = $_.ErrorDetails.Message
        if ("$($_.Exception.Message) $d" -match '409|Conflict') { Write-Log "cmd: getUpdates conflict (another poller) - skipping cycle" }
        else { Write-Log "cmd: getUpdates failed: $($_.Exception.Message)" WARN }
    }
    return @()
}

# DANGEROUS action - only ever reached via an explicit, admin-confirmed /remove command.
function Remove-Agent($id) {
    $a = @(Get-Agents) | Where-Object { $_.Id -eq $id } | Select-Object -First 1
    if (-not $a) { return "agent <code>$id</code> not found here" }
    if ($AllowedIds -contains $id) { return "refused: <code>$id</code> is allow-listed (one of YOURS)" }
    Write-Log "REMOVE agent $id (svc='$($a.ServiceName)' folder='$($a.Folder)')" WARN
    $bdir = Join-Path $BackupDir ("removed_{0}" -f $id)
    if (-not (Test-Path $bdir)) { New-Item -ItemType Directory -Force $bdir | Out-Null }
    # backups first (recoverable)
    if ($a.ServiceName) { Invoke-Native 'reg' @('export',"HKLM\SYSTEM\CurrentControlSet\Services\$($a.ServiceName)",(Join-Path $bdir 'service.reg'),'/y') | Out-Null }
    if ($a.UninstallKey) {
        foreach ($base in @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            Invoke-Native 'reg' @('export',"$base\$($a.UninstallKey)",(Join-Path $bdir 'uninstall.reg'),'/y') | Out-Null
        }
    }
    Set-Content -Path (Join-Path $bdir 'info.txt') -Encoding UTF8 -Value ("id=$id`nservice=$($a.ServiceName)`nfolder=$($a.Folder)`nuninstallKey=$($a.UninstallKey)`nremovedUtc=$((Get-Date).ToUniversalTime().ToString('o'))")
    # removal
    $steps = @()
    if ($a.ServiceName) {
        $s1 = Invoke-Native 'sc.exe' @('stop',$a.ServiceName);   $steps += "stop=$($s1.Code)"
        Start-Sleep -Seconds 2
        $s2 = Invoke-Native 'sc.exe' @('delete',$a.ServiceName); $steps += "delete=$($s2.Code)"
    }
    if ($a.Folder -and (Test-Path $a.Folder)) {
        try { Remove-Item -Path $a.Folder -Recurse -Force -ErrorAction Stop; $steps += "folder=removed" }
        catch { $steps += "folder=in-use(pending-reboot)" }
    }
    if ($a.UninstallKey) {
        foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $k = "$base\$($a.UninstallKey)"; if (Test-Path $k) { try { Remove-Item $k -Recurse -Force } catch {} }
        }
        $steps += "uninstallKey=removed"
    }
    Write-Log "REMOVE done for ${id}: $($steps -join ' ')" WARN
    return "removed agent <code>$id</code>`nsteps: $($steps -join '  ')`nbackup: $(ConvertTo-HtmlSafe $bdir)"
}

function Handle-Command($m,$state) {
    $text = "$($m.text)".Trim()
    if (-not $text.StartsWith('/')) { return }
    $parts = $text -split '\s+'
    $cmd  = ($parts[0] -replace '@.*$','').ToLower()
    $rest = @(); if ($parts.Count -gt 1) { $rest = $parts[1..($parts.Count-1)] }
    $fromId   = "$($m.from.id)"
    $fromUser = "$($m.from.username)"
    $isAdmin  = ($AdminUserIds -contains $fromId) -or ($AdminUsernames -contains $fromUser)

    if ($cmd -eq '/whoami') { Reply-Tg ("id: <code>$fromId</code>  username: @$(ConvertTo-HtmlSafe $fromUser)  admin: $isAdmin"); return }
    if (-not $isAdmin) { Write-Log "cmd: ignored '$cmd' from non-admin @$fromUser ($fromId)"; return }
    Write-Log "cmd: '$text' from admin @$fromUser ($fromId)"

    switch ($cmd) {
        '/panel'   { Send-Menu "<b>SCGuardian Panel</b> @ $(ConvertTo-HtmlSafe $env:COMPUTERNAME)" (Menu-Main) }
        '/help'    { Reply-Tg $script:CmdHelp }
        '/status'  { if (Test-HostTarget $rest[0]) { Reply-Tg (Get-InventoryText) } }
        '/agents'  { if (Test-HostTarget $rest[0]) { Reply-Tg (Get-InventoryText) } }
        '/harden'  { if (Test-HostTarget $rest[0]) { foreach ($x in (@(Get-Agents) | Where-Object { $_.Authorized })) { Invoke-Hardening $x }; Reply-Tg "hardening pass done" } }
        '/restore' {
            $h=$rest[0]; $id=$rest[1]
            if (-not (Test-HostTarget $h)) { break }
            if (-not $id) { Reply-Tg "usage: /restore &lt;host&gt; &lt;id&gt;"; break }
            $x = @(Get-Agents) | Where-Object { $_.Id -eq $id -and $_.Authorized } | Select-Object -First 1
            if (-not $x) { Reply-Tg "no owned agent <code>$id</code> here"; break }
            Invoke-Restore $x; Reply-Tg "restore done for <code>$id</code>"
        }
        '/remove'  {
            $h=$rest[0]; $id=$rest[1]
            if (-not (Test-HostTarget $h) -or $h -eq 'all') { break }   # specific host only, for safety
            if (-not $id) { Reply-Tg "usage: /remove &lt;host&gt; &lt;agentId&gt;"; break }
            if ($id -notmatch '^[0-9A-Fa-f]{16}$') { Reply-Tg "invalid agent id format"; break }
            if ($AllowedIds -contains $id) { Reply-Tg "refused: <code>$id</code> is one of YOUR allow-listed agents"; break }
            $x = @(Get-Agents) | Where-Object { $_.Id -eq $id } | Select-Object -First 1
            if (-not $x) { Reply-Tg "no agent <code>$id</code> found on this host"; break }
            $code = "$(Get-Random -Minimum 100000 -Maximum 999999)"
            $pend = [pscustomobject]@{ Id=$id; Code=$code; ExpiresUtc=((Get-Date).ToUniversalTime().AddSeconds($CommandConfirmSeconds).ToString('o')); By=$fromId }
            $state | Add-Member -NotePropertyName PendingRemoval -NotePropertyValue $pend -Force
            Reply-Tg ("About to <b>REMOVE</b> agent <code>$id</code> (service=$(ConvertTo-HtmlSafe $x.ServiceName)).`nReply <b>/confirm $code</b> within $([int]($CommandConfirmSeconds/60)) min to proceed.")
        }
        '/confirm' {
            $code=$rest[0]
            $p = $state.PendingRemoval
            if (-not $p) { Reply-Tg "nothing pending to confirm"; break }
            if ((Get-Date).ToUniversalTime() -gt [datetime]$p.ExpiresUtc) { $state.PendingRemoval=$null; Reply-Tg "confirmation expired - re-issue /remove"; break }
            if ("$code" -ne "$($p.Code)") { Reply-Tg "wrong confirmation code"; break }
            $rid = $p.Id; $state.PendingRemoval=$null
            Reply-Tg "removing <code>$rid</code>..."
            Reply-Tg (Remove-Agent $rid)
        }
        default    { Reply-Tg "unknown command: $(ConvertTo-HtmlSafe $cmd) - try /help" }
    }
}

# poll + dispatch commands. First run baselines existing messages (won't execute stale commands).
function Invoke-CommandPoll($state) {
    if (-not $ListenForCommands -or -not $TelegramBotToken -or -not $TelegramChatId) { return }
    $updates = @(Get-TelegramUpdates)
    $processed = @(); if ($state.ProcessedUpdateIds) { $processed = @($state.ProcessedUpdateIds) }
    $inited = ($state.PSObject.Properties.Name -contains 'CommandChannelInit') -and $state.CommandChannelInit
    foreach ($u in ($updates | Sort-Object update_id)) {
        if ($processed -contains $u.update_id) { continue }
        $processed += $u.update_id
        if (-not $inited) { continue }            # baseline only on first run
        $msg = $u.message
        if (-not $msg -or -not $msg.text) { continue }
        if ("$($msg.chat.id)" -ne "$TelegramChatId") { continue }   # only our ops chat
        try { Handle-Command $msg $state } catch { Write-Log "cmd handler error: $($_.Exception.Message)" WARN }
    }
    if ($processed.Count -gt 300) { $processed = @($processed[($processed.Count-300)..($processed.Count-1)]) }
    $state | Add-Member -NotePropertyName ProcessedUpdateIds -NotePropertyValue $processed -Force
    if (-not $inited) {
        $state | Add-Member -NotePropertyName CommandChannelInit -NotePropertyValue $true -Force
        Write-Log "command channel initialized (baseline set; new commands will now be processed)"
    }
}

# ============================================= telegram CONTROLLER (buttons) ====
# The Controller is the SOLE Telegram poller (offset-based long-poll) so inline
# buttons / callback_query work with zero multi-device interference.
# PHASE 1: acts on the local (server) machine; remote devices arrive in phase 2.

function Invoke-TgApi($method, $payloadObj) {
    if (-not $TelegramBotToken) { return $null }
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($payloadObj | ConvertTo-Json -Depth 12 -Compress))
        return Invoke-RestMethod -Uri "https://api.telegram.org/bot$TelegramBotToken/$method" -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 35
    } catch {
        $d=$_.ErrorDetails.Message
        if ("$($_.Exception.Message) $d" -notmatch '409|Conflict') { Write-Log "tg $method failed: $($_.Exception.Message) | $d" WARN }
        return $null
    }
}
function Edit-Menu($chatId,$msgId,$text,$markup) {
    Invoke-TgApi 'editMessageText' @{ chat_id=$chatId; message_id=$msgId; text=$text; parse_mode='HTML'; disable_web_page_preview=$true; reply_markup=$markup } | Out-Null
}
function Send-Menu($text,$markup) {
    Invoke-TgApi 'sendMessage' @{ chat_id=$TelegramChatId; text=$text; parse_mode='HTML'; disable_web_page_preview=$true; reply_markup=$markup } | Out-Null
}

# --- device registry (phase 1: just this host; phase 2: remote check-ins) -------
function Get-Devices($state) {
    $list = @($env:COMPUTERNAME)
    if ($state.PSObject.Properties.Name -contains 'Devices' -and $state.Devices) {
        foreach ($d in $state.Devices) { if ($d.Host -and ($list -notcontains $d.Host)) { $list += $d.Host } }
    }
    return $list
}

# --- menu builders --------------------------------------------------------------
function Menu-Main {
    @{ inline_keyboard = @(
        ,@(@{ text='🖥 Devices'; callback_data='m:devs' })
        ,@(@{ text='📊 This host'; callback_data="d:$env:COMPUTERNAME" }, @{ text='🔄 Refresh'; callback_data='m:main' })
        ,@(@{ text='❓ Help'; callback_data='m:help' })
    )}
}
function Menu-Devices($state) {
    $rows=@()
    foreach ($d in (Get-Devices $state)) { $rows += ,@(@{ text="🖥 $d"; callback_data="d:$d" }) }
    $rows += ,@(@{ text='⬅ Back'; callback_data='m:main' })
    @{ inline_keyboard = $rows }
}
function Menu-Device($h) {
    @{ inline_keyboard = @(
        ,@(@{ text='📊 Status'; callback_data="a:status:$h" }, @{ text='🛡 Harden'; callback_data="a:harden:$h" })
        ,@(@{ text='🧹 Remove unknown agent'; callback_data="a:listrm:$h" })
        ,@(@{ text='⬅ Devices'; callback_data='m:devs' })
    )}
}
function Menu-RemoveList($state,$h) {
    $rows=@()
    if ($h -ieq $env:COMPUTERNAME) {
        foreach ($u in (@(Get-Agents) | Where-Object { -not $_.Authorized })) {
            $rows += ,@(@{ text="🗑 $($u.Id)"; callback_data="rm:${h}:$($u.Id)" })
        }
    }
    if ($rows.Count -eq 0) { $rows += ,@(@{ text='(no unknown agents)'; callback_data="d:$h" }) }
    $rows += ,@(@{ text='⬅ Back'; callback_data="d:$h" })
    @{ inline_keyboard = $rows }
}
function Menu-Confirm($h,$id) {
    @{ inline_keyboard = @(
        ,@(@{ text='✅ CONFIRM remove'; callback_data="rmc:${h}:$id" }, @{ text='❌ Cancel'; callback_data="d:$h" })
    )}
}
function Menu-Back($cb) { @{ inline_keyboard = @( ,@(@{ text='⬅ Back'; callback_data=$cb }) ) } }

# --- callback (button tap) router ----------------------------------------------
function Handle-Callback($cb,$state) {
    $fromId="$($cb.from.id)"; $fromUser="$($cb.from.username)"
    $isAdmin=($AdminUserIds -contains $fromId) -or ($AdminUsernames -contains $fromUser)
    if (-not $isAdmin) { Invoke-TgApi 'answerCallbackQuery' @{ callback_query_id=$cb.id; text='Unauthorized'; show_alert=$true } | Out-Null; Write-Log "cb: unauthorized tap from @$fromUser ($fromId)"; return }
    Invoke-TgApi 'answerCallbackQuery' @{ callback_query_id=$cb.id } | Out-Null
    $chatId=$cb.message.chat.id; $msgId=$cb.message.message_id
    $p = "$($cb.data)" -split ':'
    switch ($p[0]) {
        'm' {
            switch ($p[1]) {
                'main' { Edit-Menu $chatId $msgId "<b>SCGuardian Panel</b> @ $(ConvertTo-HtmlSafe $env:COMPUTERNAME)" (Menu-Main) }
                'devs' { Edit-Menu $chatId $msgId "<b>Devices</b> (tap one)" (Menu-Devices $state) }
                'help' { Edit-Menu $chatId $msgId $script:CmdHelp (Menu-Back 'm:main') }
            }
        }
        'd' { Edit-Menu $chatId $msgId "<b>Device: $(ConvertTo-HtmlSafe $p[1])</b>" (Menu-Device $p[1]) }
        'a' {
            $act=$p[1]; $h=$p[2]
            if ($h -ieq $env:COMPUTERNAME) {
                switch ($act) {
                    'status' { Edit-Menu $chatId $msgId (Get-InventoryText) (Menu-Device $h) }
                    'harden' { foreach ($x in (@(Get-Agents) | Where-Object { $_.Authorized })) { Invoke-Hardening $x }; Edit-Menu $chatId $msgId "✅ hardening pass done on $(ConvertTo-HtmlSafe $h)" (Menu-Device $h) }
                    'listrm' { Edit-Menu $chatId $msgId "<b>Unknown agents on $(ConvertTo-HtmlSafe $h)</b>`npick one to remove:" (Menu-RemoveList $state $h) }
                }
            } else {
                Edit-Menu $chatId $msgId "remote actions for <b>$(ConvertTo-HtmlSafe $h)</b> arrive in phase 2" (Menu-Device $h)
            }
        }
        'rm'  { Edit-Menu $chatId $msgId "Remove agent <code>$($p[2])</code> on $(ConvertTo-HtmlSafe $p[1])?" (Menu-Confirm $p[1] $p[2]) }
        'rmc' {
            $h=$p[1]; $id=$p[2]
            if ($h -ieq $env:COMPUTERNAME) { $r = Remove-Agent $id; Edit-Menu $chatId $msgId $r (Menu-Device $h) }
            else { Edit-Menu $chatId $msgId "remote removal arrives in phase 2" (Menu-Device $h) }
        }
    }
}

# --- controller poll (sole consumer, offset-based long-poll) --------------------
function Invoke-ControllerPoll($state) {
    if (-not $TelegramBotToken -or -not $TelegramChatId) { return }
    $offset=0; if ($state.PSObject.Properties.Name -contains 'TgOffset') { $offset=[int]$state.TgOffset }
    $r = $null
    try { $r = Invoke-RestMethod -Uri "https://api.telegram.org/bot$TelegramBotToken/getUpdates?timeout=25&offset=$offset&allowed_updates=%5B%22message%22%2C%22callback_query%22%5D" -Method Get -TimeoutSec 35 }
    catch { $d=$_.ErrorDetails.Message; if ("$($_.Exception.Message) $d" -match '409|Conflict') { Write-Log "controller: another poller active (409) - is a second controller running?" WARN; Start-Sleep -Seconds 3 } else { Write-Log "controller getUpdates: $($_.Exception.Message)" WARN; Start-Sleep -Seconds 3 }; return }
    if (-not $r.ok) { return }
    foreach ($u in ($r.result | Sort-Object update_id)) {
        $state | Add-Member -NotePropertyName TgOffset -NotePropertyValue ([int]$u.update_id + 1) -Force
        try {
            if ($u.message -and $u.message.text) { if ("$($u.message.chat.id)" -eq "$TelegramChatId") { Handle-Command $u.message $state } }
            elseif ($u.callback_query) { Handle-Callback $u.callback_query $state }
        } catch { Write-Log "controller handler error: $($_.Exception.Message)" WARN }
    }
    Save-State $state
}

function Install-Controller {
    Ensure-Dirs
    $src=Get-SelfPath; $isExe = $src -match '(?i)\.exe$'
    $dst=Join-Path $Root ($(if($isExe){'SCGuardian.exe'}else{'SCGuardian.ps1'}))
    if ($src -and ($src -ne $dst)) { Copy-Item $src $dst -Force }
    if ($TelegramBotToken -and $TelegramChatId) { Save-ConfigFile }
    if ($isExe) { $action = New-ScheduledTaskAction -Execute $dst -Argument "-Mode Controller" }
    else        { $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dst`" -Mode Controller" }
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999
    Register-ScheduledTask -TaskName 'SCGuardian-Controller' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    try { Start-ScheduledTask -TaskName 'SCGuardian-Controller' } catch {}
    $script:ScheduleChanged = $true
    Write-Log "controller task installed + started (SCGuardian-Controller, SYSTEM, at startup, sole Telegram poller)."
}

# --------------------------------------------------------------- discovery -----
function Get-Agents {
    $found = @{}

    function New-Entry($id) {
        if (-not $found.ContainsKey($id)) {
            $found[$id] = [pscustomobject]@{
                Id=$id; ServiceName=$null; ServiceState=$null; StartMode=$null;
                Folder=$null; UninstallKey=$null; Authorized=($AllowedIds -contains $id)
            }
        }
        return $found[$id]
    }

    Get-CimInstance Win32_Service -OperationTimeoutSec 30 -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'ScreenConnect Client' -or $_.DisplayName -match 'ScreenConnect Client'
    } | ForEach-Object {
        $m = [regex]::Match("$($_.Name) $($_.DisplayName)", $IdRegex)
        if ($m.Success) { $e=New-Entry $m.Groups[1].Value; $e.ServiceName=$_.Name; $e.ServiceState=$_.State; $e.StartMode=$_.StartMode }
    }

    $bases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, ${env:ProgramW6432}) | Where-Object { $_ } | Select-Object -Unique
    foreach ($base in $bases) {
        if (Test-Path $base) {
            Get-ChildItem -Path $base -Directory -Filter 'ScreenConnect Client (*' -ErrorAction SilentlyContinue | ForEach-Object {
                $m=[regex]::Match($_.Name,$IdRegex); if ($m.Success){ (New-Entry $m.Groups[1].Value).Folder = $_.FullName }
            }
        }
    }

    foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path $p) {
            Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
                $d=(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                if ($d -match 'ScreenConnect Client') { $m=[regex]::Match($d,$IdRegex); if($m.Success){ (New-Entry $m.Groups[1].Value).UninstallKey=$_.PSChildName } }
            }
        }
    }
    return $found.Values
}

function Get-ServerProducts {
    $list=@()
    foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path $p) {
            Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
                $d=(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                if ($d -and $d -match 'ScreenConnect' -and $d -notmatch 'Client') { $list += $d }
            }
        }
    }
    return ($list | Select-Object -Unique)
}

# --------------------------------------------------------------- hardening -----
function Set-Recovery($agent) {
    if (-not $agent.ServiceName) { return }
    $svc = $agent.ServiceName
    # idempotent: if already auto-start + restart-on-failure, do nothing (avoids
    # noisy 'access denied' when a prior H3 removed CHANGE_CONFIG from admins).
    $qc = Invoke-Native 'sc.exe' @('qc',$svc)
    $qf = Invoke-Native 'sc.exe' @('qfailure',$svc)
    if (($qc.Out -match 'AUTO_START') -and ($qf.Out -match 'RESTART')) { Write-Log "[H1] recovery already enforced: $svc"; return }
    $ok = $true; $denied = $false
    foreach ($call in @(@('config',$svc,'start=','auto'),
                        @('failure',$svc,'reset=','86400','actions=','restart/60000/restart/60000/restart/60000'),
                        @('failureflag',$svc,'1'))) {
        $r = Invoke-Native 'sc.exe' $call
        if ($r.Code -ne 0) {
            $ok = $false
            if ($r.Out -match 'denied|FAILED 5') { $denied = $true }
            else { Write-Log "[H1] sc.exe $($call[0]) failed (exit $($r.Code)) for ${svc}: $($r.Out)" WARN }
        }
    }
    if ($ok) { Write-Log "[H1] recovery set (auto-start + restart-on-failure): $svc" }
    elseif ($denied) { Write-Log "[H1] change-config is restricted to SYSTEM (service already hardened); recovery stays in effect and the SYSTEM watchdog maintains it: $svc" }
    else { Write-Log "[H1] recovery only partially applied: $svc" WARN }
}

function Set-FolderHardening($agent) {
    if (-not $agent.Folder) { return }
    $f = $agent.Folder
    # idempotent: already protected (inheritance off) with admins not-full => done
    try {
        $cacl = Get-Acl -Path $f
        $af = $cacl.Access | Where-Object { "$($_.IdentityReference)" -match 'Administrators' -and "$($_.FileSystemRights)" -match 'FullControl' -and $_.AccessControlType -eq 'Allow' }
        if ($cacl.AreAccessRulesProtected -and -not $af) { Write-Log "[H2] folder already hardened: $f"; return }
    } catch {}
    $bak = Join-Path $BackupDir ("folderAcl_{0}.acl.txt" -f $agent.Id)
    if (-not (Test-Path $bak)) {
        Push-Location (Split-Path $f -Parent)
        Invoke-Native 'icacls' @((Split-Path $f -Leaf),'/save',$bak,'/T','/C') | Out-Null
        Pop-Location
    }
    if ($TakeOwnership) { Invoke-Native 'takeown' @('/F',$f,'/A','/R','/D','Y') | Out-Null }
    $r1 = Invoke-Native 'icacls' @($f,'/inheritance:d','/C')
    Invoke-Native 'icacls' @($f,'/remove:g',$SID_ADMINS,'/T','/C') | Out-Null
    $r3 = Invoke-Native 'icacls' @($f,'/grant:r',"$($SID_SYSTEM):(OI)(CI)F","$($SID_ADMINS):(OI)(CI)RX","$($SID_USERS):(OI)(CI)RX",'/T','/C')
    if ($r1.Code -eq 0 -and $r3.Code -eq 0) {
        Write-Log "[H2] folder hardened (SYSTEM full, admins/users read-only, no delete): $f"
    } elseif ((($r1.Out + ' ' + $r3.Out) -match 'denied') -and -not $TakeOwnership) {
        Write-Log "[H2] folder ACL is locked by the ScreenConnect installer (admin lacks rights) - it is already protected, skipping. Use -TakeOwnership to force SCGuardian's own ACL: $f"
    } else {
        Write-Log "[H2] folder not fully hardened (icacls exit d=$($r1.Code) grant=$($r3.Code)): $($r3.Out)" WARN
    }
}
function Restore-FolderHardening($agent) {
    if (-not $agent.Folder) { return }
    $f = $agent.Folder
    $bak = Join-Path $BackupDir ("folderAcl_{0}.acl.txt" -f $agent.Id)
    if (Test-Path $bak) {
        Push-Location (Split-Path $f -Parent)
        Invoke-Native 'icacls' @((Split-Path $f -Leaf),'/restore',$bak,'/C') | Out-Null
        Pop-Location
        Write-Log "[H2] folder ACL restored from backup: $f"
    } else {
        Invoke-Native 'icacls' @($f,'/reset','/T','/C') | Out-Null
        Invoke-Native 'icacls' @($f,'/inheritance:e') | Out-Null
        Write-Log "[H2] no backup; reset folder ACL to inherited defaults: $f" WARN
    }
}

function Set-ServiceSd($agent) {
    if (-not $agent.ServiceName) { return }
    $svc=$agent.ServiceName
    $sddl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'
    # idempotent: skip if the current SD already contains our hardened DACL
    $cur = ((Invoke-Native 'sc.exe' @('sdshow',$svc)).Out) -replace '\s',''
    if ($cur.Contains(($sddl -replace '\s',''))) { Write-Log "[H3] service SD already hardened: $svc"; return }
    $bak=Join-Path $BackupDir ("serviceSd_{0}.txt" -f $agent.Id)
    if (-not (Test-Path $bak)) {
        $orig = (& sc.exe sdshow "$svc") | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^[OGDS]:' } | Select-Object -First 1
        if ($orig) { Set-Content -Path $bak -Value $orig -Encoding ASCII }
    }
    $r = Invoke-Native 'sc.exe' @('sdset',$svc,$sddl)
    if ($r.Code -eq 0) { Write-Log "[H3] service SD hardened (no stop/delete for non-SYSTEM): $svc" }
    elseif ($r.Out -match 'denied|FAILED 5') { Write-Log "[H3] SD change restricted (already hardened; SYSTEM watchdog maintains it): $svc" }
    else { Write-Log "[H3] sc.exe sdset failed (exit $($r.Code)) for ${svc}: $($r.Out)" ERROR }
}
function Restore-ServiceSd($agent) {
    if (-not $agent.ServiceName) { return }
    $svc=$agent.ServiceName
    $bak=Join-Path $BackupDir ("serviceSd_{0}.txt" -f $agent.Id)
    $target = $null; $fallback = $false
    if (Test-Path $bak) { $target = (Get-Content $bak -Raw).Trim() }
    if (-not $target) { $target = $DEFAULT_SVC_SDDL; $fallback = $true }
    $r = Invoke-Native 'sc.exe' @('sdset',$svc,$target)
    if ($r.Code -eq 0) {
        if ($fallback) { Write-Log "[H3] no backup; applied DEFAULT service SD (admins regain control): $svc" WARN }
        else           { Write-Log "[H3] service SD restored: $svc" }
    } else { $script:RestoreFailed = $true; Write-Log "[H3] restore sdset failed (exit $($r.Code)) for ${svc}: $($r.Out)" ERROR }
}

function Set-RegistryHardening($agent) {
    if (-not $agent.ServiceName) { return }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($agent.ServiceName)"
    if (-not (Test-Path $key)) { return }
    $bak = Join-Path $BackupDir ("regSddl_{0}.txt" -f $agent.Id)
    $acl = $null
    try { $acl = Get-Acl -Path $key } catch { Write-Log "[H4] cannot read registry ACL: $($_.Exception.Message)" WARN; return }
    if (-not (Test-Path $bak)) { try { Set-Content -Path $bak -Value $acl.Sddl -Encoding ASCII } catch {} }
    # idempotent: already protected (inheritance off) with admins not-full => done
    $adminFull = $acl.Access | Where-Object { "$($_.IdentityReference)" -match 'Administrators' -and "$($_.RegistryRights)" -match 'FullControl' -and $_.AccessControlType -eq 'Allow' }
    if ($acl.AreAccessRulesProtected -and -not $adminFull) { Write-Log "[H4] registry key already hardened: $key"; return }
    # Get-Acl/Set-Acl reopens the key with ChangePermissions; write DACL only.
    try {
        $acl.SetSecurityDescriptorSddlForm('D:P(A;CI;KA;;;SY)(A;CI;KR;;;BA)(A;CI;KR;;;AU)', [System.Security.AccessControl.AccessControlSections]::Access)
        Set-Acl -Path $key -AclObject $acl
        Write-Log "[H4] registry key hardened (SYSTEM full, others read): $key"
    } catch {
        Write-Log "[H4] change restricted (already hardened; SYSTEM watchdog maintains it): $key"
    }
}
function Restore-RegistryHardening($agent) {
    if (-not $agent.ServiceName) { return }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($agent.ServiceName)"
    if (-not (Test-Path $key)) { return }
    $bak = Join-Path $BackupDir ("regSddl_{0}.txt" -f $agent.Id)
    $sddl = $null; $fallback = $false
    if (Test-Path $bak) { $sddl = (Get-Content $bak -Raw).Trim() }
    if (-not $sddl) { $sddl = $DEFAULT_REG_SDDL; $fallback = $true }
    try {
        $acl = Get-Acl -Path $key
        $acl.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access)
        Set-Acl -Path $key -AclObject $acl
        if ($fallback) { Write-Log "[H4] no backup; applied DEFAULT registry ACL (admins full): $key" WARN }
        else           { Write-Log "[H4] registry key ACL restored: $key" }
    } catch { $script:RestoreFailed = $true; Write-Log "[H4] restore failed for ${key}: $($_.Exception.Message)" ERROR }
}

function Invoke-Hardening($agent) {
    Write-Log "Hardening MY agent $($agent.Id) (service='$($agent.ServiceName)')"
    if ($Layers -contains 'Recovery')    { try { Set-Recovery        $agent } catch { Write-Log "H1 failed: $($_.Exception.Message)" ERROR } }
    if ($Layers -contains 'FolderAcl')   { try { Set-FolderHardening  $agent } catch { Write-Log "H2 failed: $($_.Exception.Message)" ERROR } }
    if ($Layers -contains 'ServiceSd')   { try { Set-ServiceSd        $agent } catch { Write-Log "H3 failed: $($_.Exception.Message)" ERROR } }
    if ($Layers -contains 'RegistryAcl') { try { Set-RegistryHardening $agent } catch { Write-Log "H4 failed: $($_.Exception.Message)" ERROR } }
}
function Invoke-Restore($agent) {
    Write-Log "Restoring MY agent $($agent.Id)"
    try { Restore-ServiceSd        $agent } catch { $script:RestoreFailed=$true; Write-Log "H3 restore failed: $($_.Exception.Message)" ERROR }
    try { Restore-RegistryHardening $agent } catch { $script:RestoreFailed=$true; Write-Log "H4 restore failed: $($_.Exception.Message)" ERROR }
    try { Restore-FolderHardening   $agent } catch { $script:RestoreFailed=$true; Write-Log "H2 restore failed: $($_.Exception.Message)" ERROR }
    Write-Log "Note: service recovery flags (H1) left as-is; adjust with sc.exe if needed."
}

# --------------------------------------------------------------- watchdog ------
function Install-Watchdog {
    Ensure-Dirs
    $src   = Get-SelfPath
    $isExe = $src -match '(?i)\.exe$'
    $dst   = Join-Path $Root ($(if ($isExe) { 'SCGuardian.exe' } else { 'SCGuardian.ps1' }))
    if ($src -and ($src -ne $dst)) { Copy-Item $src $dst -Force }
    if (-not (Test-Path $dst)) { Write-Log "cannot install watchdog: $dst missing" ERROR; return }
    if ($TelegramBotToken -and $TelegramChatId) { Save-ConfigFile }   # ensure SYSTEM has current config
    if ($isExe) {
        $action = New-ScheduledTaskAction -Execute $dst -Argument "-Mode Monitor -ScanIntervalMinutes $ScanIntervalMinutes -HeartbeatHours $HeartbeatHours"
    } else {
        $arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dst`" -Mode Monitor -ScanIntervalMinutes $ScanIntervalMinutes -HeartbeatHours $HeartbeatHours"
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    }
    $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $ScanIntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $limit     = New-TimeSpan -Minutes ([Math]::Max(10, $ScanIntervalMinutes * 2))
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit $limit
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    $script:ScheduleChanged = $true
    Write-Log "[H5] watchdog task installed: '$TaskName' every $ScanIntervalMinutes min as SYSTEM (Mode=Monitor, kill-after=$([int]$limit.TotalMinutes)m)."
}
function Remove-Watchdog {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        $script:ScheduleChanged = $true
        Write-Log "[H5] watchdog scheduled task removed."
    }
}

# --------------------------------------------------------------- reporting -----
function Show-Report($agents,$servers) {
    Write-Host ""
    Write-Host "==================== ScreenConnect inventory ====================" -ForegroundColor Green
    if (-not $agents) { Write-Host "  (no ScreenConnect Client agents found)" }
    foreach ($a in $agents) {
        $tag = if ($a.Authorized) { 'MINE   ' } else { 'UNKNOWN' }
        $col = if ($a.Authorized) { 'Green' } else { 'Red' }
        Write-Host ("  [{0}] id={1}  service={2}  state={3}  folder={4}" -f `
            $tag,$a.Id,($a.ServiceName),$a.ServiceState,($a.Folder)) -ForegroundColor $col
    }
    if ($servers) { Write-Host "  Server product(s): $($servers -join '; ')" -ForegroundColor Yellow }
    Write-Host "  Allow-list: $($AllowedIds -join ', ')"
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host ""
}

# ------------------------------------------------------------------ scan -------
function Invoke-Scan {
    param([switch]$Harden,[switch]$Watch)
    $state   = Load-State
    $agents  = @(Get-Agents)
    $servers = @(Get-ServerProducts)
    $mine    = @($agents | Where-Object { $_.Authorized })
    $unknown = @($agents | Where-Object { -not $_.Authorized })

    Show-Report $agents $servers

    foreach ($u in $unknown) {
        $t = "[!] Unknown ScreenConnect agent detected`nID: <code>$(ConvertTo-HtmlSafe $u.Id)</code>`nService: $(ConvertTo-HtmlSafe $u.ServiceName)`nFolder: $(ConvertTo-HtmlSafe $u.Folder)`n(No action taken - review and remove manually if unauthorized.)"
        Send-Telegram -State $state -Key ("unknown_"+$u.Id) -Text $t
    }

    $sig = @()
    foreach ($a in $agents) { $sig += "agent:$($a.Id)" }
    foreach ($s in $servers){ $sig += "server:$s" }
    $known = @(); if ($state.KnownSignatures) { $known = @($state.KnownSignatures) }
    foreach ($new in ($sig | Where-Object { $known -notcontains $_ })) {
        if ($known.Count -gt 0) { Send-Telegram -State $state -Key ("newinstall_"+$new) -Force -Text ("[NEW] New ScreenConnect install detected: <code>$(ConvertTo-HtmlSafe $new)</code>") }
    }
    $state.KnownSignatures = $sig

    foreach ($a in $mine) {
        if ($Harden) { Invoke-Hardening $a }
        if ($Watch) {
            if (-not $a.ServiceName) {
                Send-Telegram -State $state -Key ("missing_"+$a.Id) -Text ("[X] MY agent service is MISSING`nID: <code>$(ConvertTo-HtmlSafe $a.Id)</code>`n(No auto-reinstall - manual action needed.)")
            } else {
                $svc = Get-Service -Name $a.ServiceName -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -ne 'Running') {
                    try { Start-Service $a.ServiceName
                        Send-Telegram -State $state -Key ("restart_"+$a.Id) -Text ("[RESTART] Watchdog restarted my agent`nID: <code>$(ConvertTo-HtmlSafe $a.Id)</code>`nService was: $($svc.Status)")
                    } catch { Send-Telegram -State $state -Key ("startfail_"+$a.Id) -Text ("[X] Watchdog FAILED to start my agent`nID: <code>$(ConvertTo-HtmlSafe $a.Id)</code>`n$(ConvertTo-HtmlSafe $_.Exception.Message)") }
                }
                if ($svc -and $svc.StartType -ne 'Automatic') { try { Set-Service $a.ServiceName -StartupType Automatic } catch {} }
            }
            Invoke-Hardening $a
        }
    }

    if ($HeartbeatHours -gt 0) {
        $due = $true
        if ($state.LastHeartbeatUtc) { $due = ((Get-Date).ToUniversalTime() - ([datetime]$state.LastHeartbeatUtc).ToUniversalTime()).TotalHours -ge $HeartbeatHours }
        if ($due) {
            $running = @($mine | Where-Object { $_.ServiceState -eq 'Running' }).Count
            Send-Telegram -Force -State $state -Text ("[OK] Heartbeat OK`nMine: $($mine.Count) (running: $running)`nUnknown: $($unknown.Count)")
            $state.LastHeartbeatUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
    }

    if ($Watch -and $ListenForCommands) { Invoke-CommandPoll $state }
    Save-State $state
    return @{ Agents=$agents; Mine=$mine; Unknown=$unknown }
}

# ===================================================== v4 hub / agent modes ====
# These never touch $EmbeddedConfig, the legacy config file or the legacy token.
$AgentTaskName = 'SCGuardian-Agent'
$AgentStopFile = Join-Path $Root 'agent.stop'

function Get-ScgEntryModuleDir {
    $candidates = @()
    if ($PSScriptRoot) { $candidates += (Join-Path $PSScriptRoot 'modules') }
    $candidates += 'C:\Program Files\SCGuardian\modules'
    foreach ($d in $candidates) {
        if (Test-Path (Join-Path $d 'Common.psm1')) { return $d }
    }
    throw "SCGuardian modules not found (looked in: $($candidates -join '; '))"
}

function Import-ScgEntryModule {
    param([string[]]$Name)
    $dir = Get-ScgEntryModuleDir
    foreach ($n in $Name) {
        Import-Module (Join-Path $dir "$n.psm1") -Force -DisableNameChecking -Global
    }
}

function Write-ScgEntryLog {
    param([string]$Message,[string]$Level='INFO')
    try {
        if (Get-Command Write-ScgLog -ErrorAction SilentlyContinue) { Write-ScgLog -Message $Message -Level $Level }
        else { Write-Host "[$Level] $Message" }
    } catch {}
}

function Invoke-ScgHubMode {
    Import-ScgEntryModule -Name @('Common','Database','HttpServer','Telegram','Hub')
    Write-ScgEntryLog "hub starting (config=$HubConfigPath)"
    Start-ScgHub -ConfigPath $HubConfigPath
}

function Invoke-ScgAgentMode {
    Import-ScgEntryModule -Name @('Common','Discovery','Hardening','Agent')
    Invoke-ScgAgentCycle -ConfigPath $AgentConfigPath
}

function Invoke-ScgAgentLoopMode {
    Import-ScgEntryModule -Name @('Common','Discovery','Hardening','Agent')
    Write-ScgEntryLog "agent loop started (config=$AgentConfigPath, stop-file=$AgentStopFile)"
    while (-not (Test-Path $AgentStopFile)) {
        $delay = 30
        try {
            Invoke-ScgAgentCycle -ConfigPath $AgentConfigPath
            $delay = [int](Get-ScgNextDelaySec -ConfigPath $AgentConfigPath)
        } catch {
            Write-ScgEntryLog "agent loop error: $($_.Exception.Message)" 'ERROR'
            $delay = 10
        }
        if ($delay -lt 1) { $delay = 1 }
        $deadline = (Get-Date).AddSeconds($delay)
        while (((Get-Date) -lt $deadline) -and -not (Test-Path $AgentStopFile)) {
            try { Start-Sleep -Seconds 1 } catch {}
        }
    }
    Write-ScgEntryLog "agent loop stopped (stop-file present)"
}

function Install-ScgAgentTask {
    Ensure-Dirs
    $self = Get-SelfPath
    if (-not $self) { throw "cannot resolve the script path for the agent task" }
    if (Test-Path $AgentStopFile) { Remove-Item $AgentStopFile -Force }
    if ($self -match '(?i)\.exe$') {
        $action = New-ScheduledTaskAction -Execute $self -Argument "-Mode AgentLoop -AgentConfigPath `"$AgentConfigPath`""
    } else {
        $arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$self`" -Mode AgentLoop -AgentConfigPath `"$AgentConfigPath`""
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    }
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $AgentTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    try { Start-ScheduledTask -TaskName $AgentTaskName } catch {}
    Write-Log "agent task installed: '$AgentTaskName' AtStartup as SYSTEM (Mode=AgentLoop, restart on failure)."
}

function Remove-ScgAgentTask {
    if (Get-ScheduledTask -TaskName $AgentTaskName -ErrorAction SilentlyContinue) {
        try { Stop-ScheduledTask -TaskName $AgentTaskName } catch {}
        Unregister-ScheduledTask -TaskName $AgentTaskName -Confirm:$false
        Write-Log "agent task removed: '$AgentTaskName'."
    }
}

if ($InstallAgent -or $RemoveAgent -or ($Mode -in @('Hub','Agent','AgentLoop'))) {
    if (-not (Test-Admin)) {
        Write-Host "SCGuardian needs Administrator rights. Requesting elevation - please approve the UAC prompt..." -ForegroundColor Yellow
        if (Invoke-Elevation -Bound $PSBoundParameters) { exit 0 }
        Write-Host "Elevation was declined or failed. Right-click PowerShell > Run as Administrator." -ForegroundColor Red
        exit 2
    }
    try {
        if ($RemoveAgent)  { Remove-ScgAgentTask }
        if ($InstallAgent) { Install-ScgAgentTask }
        switch ($Mode) {
            'Hub'       { Invoke-ScgHubMode }
            'Agent'     { Invoke-ScgAgentMode }
            'AgentLoop' { Invoke-ScgAgentLoopMode }
        }
    } catch {
        Write-ScgEntryLog "FATAL (Mode=${Mode}): $($_.Exception.Message)" 'ERROR'
        exit 2
    }
    exit 0
}

# =============================================================== MAIN ==========
Resolve-Settings -Bound $PSBoundParameters
Resolve-Defaults -Bound $PSBoundParameters

# -TestTelegram needs no admin; handle it before elevation.
if ($TestTelegram) {
    Ensure-Dirs
    Write-Log "----- SCGuardian Telegram test -----"
    if (-not $TelegramBotToken -or -not $TelegramChatId) { Write-Log "Telegram token/chat id not set (edit CONFIG block or pass -TelegramBotToken/-TelegramChatId)." ERROR; exit 2 }
    $ok = Invoke-TelegramSend ("<b>SCGuardian</b> test message from " + (ConvertTo-HtmlSafe $env:COMPUTERNAME) + " - if you can read this, alerts work.")
    if ($ok) { Write-Log "Telegram test SUCCEEDED - check your chat." ; exit 0 } else { Write-Log "Telegram test FAILED - see the error above." ERROR; exit 2 }
}

# auto-elevate: if not Administrator, request UAC and re-launch; the elevated copy does the work.
if (-not (Test-Admin)) {
    Write-Host "SCGuardian needs Administrator rights. Requesting elevation - please approve the UAC prompt..." -ForegroundColor Yellow
    if (Invoke-Elevation -Bound $PSBoundParameters) { exit 0 }
    Write-Host "Elevation was declined or failed. Right-click PowerShell > Run as Administrator." -ForegroundColor Red
    if ($Elevated) { Read-Host "Press Enter to close" | Out-Null }
    exit 2
}

Ensure-Dirs
Write-Log "----- SCGuardian start (Mode=$Mode, Layers=$($Layers -join '+'), interval=${ScanIntervalMinutes}m, throttle=${AlertThrottleMinutes}m) -----"
if ($SaveConfig) { Save-ConfigFile }
if ($InstallController) { Install-Controller; Write-Log "----- SCGuardian done -----"; exit 0 }

$result = $null
try {
    switch ($Mode) {
        'Report'  { $result = Invoke-Scan }
        'Harden'  { $result = Invoke-Scan -Harden;  if ($InstallSchedule) { Install-Watchdog } }
        'Monitor' { $result = Invoke-Scan -Watch }
        'Listen'  { $st = Load-State; Invoke-CommandPoll $st; Save-State $st }
        'Controller' {
            Write-Log "controller loop started (sole Telegram poller; inline buttons live)"
            $st = Load-State
            while ($true) {
                try { Invoke-ControllerPoll $st } catch { Write-Log "controller loop error: $($_.Exception.Message)" WARN; Start-Sleep -Seconds 2 }
            }
        }
        'Restore' {
            $agents = @(Get-Agents) | Where-Object { $_.Authorized }
            foreach ($a in $agents) { Invoke-Restore $a }
            if ($RemoveSchedule) { Remove-Watchdog }
            Write-Log "Restore complete."
        }
    }
    if ($InstallSchedule -and $Mode -eq 'Monitor') { Install-Watchdog }
    if ($RemoveSchedule  -and $Mode -ne 'Restore') { Remove-Watchdog }
} catch {
    Write-Log "FATAL: $($_.Exception.Message)" ERROR
    exit 2
}

Write-Log "----- SCGuardian done -----"
if ($Elevated -and -not $env:SCG_SELF) { Write-Host ""; Read-Host "Done. Press Enter to close this window" | Out-Null }
if ($Mode -eq 'Restore') { if ($script:RestoreFailed) { exit 2 } else { exit 0 } }
if ($script:ScheduleChanged) { exit 0 }
if ($result -and $result.Mine.Count -eq 0 -and $result.Unknown.Count -eq 0) { exit 1 }
exit 0
