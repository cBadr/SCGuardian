<#
.SYNOPSIS
    Test-only helpers for the SCGuardian integration suite (local fleet + chaos tests).
.DESCRIPTION
    Purpose : temp roots, hub/agent configs, an in-process agent shim (fake discovery/hardening),
              a network guard that blackholes Telegram, and raw signed HTTP calls for auth checks.
    Author  : Badr
    Version : 4.0.0
    Never touches C:\ProgramData\SCGuardian, real services, real ACLs or the Telegram API.
#>

Set-StrictMode -Version 2.0

$script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
$script:ModuleDir = Join-Path $script:RepoRoot 'src\modules'
$script:SavedProxy = $null
$script:GuardOn = $false
$script:IdMine = '5d0931a9fafc2a8b'
$script:IdUnknown = 'deadbeefdeadbeef'

function Get-ScgTestModuleDir { [CmdletBinding()] param() return $script:ModuleDir }
function Get-ScgTestKnownId { [CmdletBinding()] param() return [pscustomobject]@{ Mine = $script:IdMine; Unknown = $script:IdUnknown } }

function Import-ScgTestProductModule {
    <# .SYNOPSIS Imports the hub-side product modules into the global session state. #>
    [CmdletBinding()]
    param()
    foreach ($m in @('Common', 'Database', 'HttpServer', 'Telegram', 'Hub')) {
        Import-Module (Join-Path $script:ModuleDir ($m + '.psm1')) -DisableNameChecking -Global
    }
}

function Test-ScgTestElevated {
    [CmdletBinding()]
    param()
    $p = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ScgTestPortFree {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Port)
    $l = $null
    try {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
        $l.Start()
        return $true
    }
    catch { return $false }
    finally { if ($l) { $l.Stop() } }
}

function Get-ScgTestFreePort {
    [CmdletBinding()]
    param()
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    try { return ([System.Net.IPEndPoint]$l.LocalEndpoint).Port } finally { $l.Stop() }
}

function New-ScgTestSecret {
    [CmdletBinding()]
    param()
    $bytes = New-Object byte[] 32
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-ScgTestRoot {
    <# .SYNOPSIS Creates a unique temp root (never under ProgramData). #>
    [CmdletBinding()]
    param([string]$Prefix = 'scg-it')
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ($Prefix + '-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    if ($p -like ($env:ProgramData + '*')) { throw 'refusing a test root under ProgramData' }
    [void](New-Item -ItemType Directory -Path $p -Force)
    return $p
}

function Remove-ScgTestPath {
    <# .SYNOPSIS Deletes a test path with retries (SQLite/log handles may linger briefly). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    if ('System.Data.SQLite.SQLiteConnection' -as [type]) {
        try { [System.Data.SQLite.SQLiteConnection]::ClearAllPools() } catch { $null = $_ }
    }
    for ($i = 0; $i -lt 6; $i++) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop; return $true }
        catch { Start-Sleep -Milliseconds 700 }
    }
    return -not (Test-Path -LiteralPath $Path)
}

function Write-ScgTestJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$InputObject)
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $json = ConvertTo-Json -InputObject $InputObject -Depth 8
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function New-ScgTestHubConfig {
    <# .SYNOPSIS Writes hub.config.json under HubRoot with a fake Telegram token/chat. Returns the path. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HubRoot,
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Secret,
        [string]$Thumbprint = 'auto',
        [string]$AdminId = '424242',
        [string]$ChatId = '-1000000000042',
        [int]$HeartbeatSec = 5,
        [int]$ScanSec = 5
    )
    $cfg = [ordered]@{
        listen        = [ordered]@{ url = $Url; cert_thumbprint = $Thumbprint }
        shared_secret = $Secret
        telegram      = [ordered]@{ bot_token = '000000000:TEST_ONLY_FAKE_TOKEN'; chat_id = $ChatId; admin_user_ids = @($AdminId); admin_usernames = @() }
        database      = [ordered]@{ path = (Join-Path $HubRoot 'hub.db') }
        defaults      = [ordered]@{
            allowed_ids = @($script:IdMine); scan_interval_sec = $ScanSec; heartbeat_sec = $HeartbeatSec
            alert_throttle_min = 15; command_confirm_sec = 300; stale_after_min = 5; command_timeout_sec = 300
            nonce_ttl_sec = 600; max_skew_sec = 300; tick_sec = 30; telegram_error_pause_sec = 5
        }
        logging       = [ordered]@{ path = (Join-Path $HubRoot 'logs\hub.log'); max_bytes = 10485760 }
    }
    $p = Join-Path $HubRoot 'hub.config.json'
    [void](New-Item -ItemType Directory -Path (Join-Path $HubRoot 'logs') -Force)
    Write-ScgTestJson -Path $p -InputObject $cfg
    return $p
}

function New-ScgTestAgentConfig {
    <# .SYNOPSIS Writes agent.config.json under AgentRoot with an explicit hostname. Returns the path. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AgentRoot,
        [Parameter(Mandatory)][string]$HubUrl,
        [Parameter(Mandatory)][string]$Secret,
        [Parameter(Mandatory)][string]$Hostname,
        [string]$Thumbprint = '',
        [int]$HeartbeatSec = 5,
        [int]$ScanSec = 5
    )
    [void](New-Item -ItemType Directory -Path (Join-Path $AgentRoot 'logs') -Force)
    $cfg = [ordered]@{
        hub_url = $HubUrl.TrimEnd('/'); shared_secret = $Secret; device_id = $null; hostname = $Hostname
        heartbeat_sec = $HeartbeatSec; scan_interval_sec = $ScanSec; alert_throttle_min = 15
        allowed_ids = @($script:IdMine); layers = @('Recovery', 'ServiceSd'); take_ownership = $false
        local_watchdog = $true; trusted_server_thumbprint = $Thumbprint
    }
    $p = Join-Path $AgentRoot 'agent.config.json'
    Write-ScgTestJson -Path $p -InputObject $cfg
    return $p
}

function Enable-ScgTestNetworkGuard {
    <#
    .SYNOPSIS
        TEST SWITCH: points the process-wide default proxy at a closed loopback port so every non-local request
        (the hub's Telegram poller and result notices) fails fast offline. Loopback traffic bypasses it.
    #>
    [CmdletBinding()]
    param()
    if ($script:GuardOn) { return }
    $script:SavedProxy = [System.Net.WebRequest]::DefaultWebProxy
    $proxy = New-Object System.Net.WebProxy('http://127.0.0.1:9', $true)
    [System.Net.WebRequest]::DefaultWebProxy = $proxy
    $script:GuardOn = $true
}

function Disable-ScgTestNetworkGuard {
    [CmdletBinding()]
    param()
    if (-not $script:GuardOn) { return }
    [System.Net.WebRequest]::DefaultWebProxy = $script:SavedProxy
    $script:GuardOn = $false
}

function Set-ScgTestModuleAlias {
    <# .SYNOPSIS Installs script-scope aliases inside a loaded module (aliases win over functions, like Pester mocks). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ModuleName, [Parameter(Mandatory)][hashtable]$Map)
    $mod = @(Get-Module -Name $ModuleName) | Select-Object -Last 1
    if (-not $mod) { throw "module not loaded: $ModuleName" }
    & $mod { param($m) foreach ($k in @($m.Keys)) { Set-Alias -Name $k -Value $m[$k] -Scope Script -Force } } $Map
}

function Install-ScgTestStub {
    <# .SYNOPSIS Defines the global stub functions targeted by the module aliases. #>
    [CmdletBinding()]
    param()
    function global:ScgTest_NoSecureDirectory {
        param([AllowEmptyString()][string]$Path)
        if ($Path -and -not (Test-Path -LiteralPath $Path)) { [void](New-Item -ItemType Directory -Path $Path -Force) }
        return $true
    }
    function global:ScgTest_WriteCall {
        param([string]$Fn, $Agent)
        $names = @(Get-PSCallStack | ForEach-Object { [string]$_.FunctionName })
        $phase = 'cycle'
        if ($names -contains 'Invoke-ScgLocalWatchdog') { $phase = 'watchdog' }
        elseif ($names -contains 'Invoke-ScgAgentCommand') { $phase = 'command' }
        $id = ''
        if ($null -ne $Agent) { $id = [string]$Agent.Id }
        $line = ConvertTo-Json -Compress -InputObject ([ordered]@{ utc = [datetime]::UtcNow.ToString('o'); fn = $Fn; phase = $phase; sc_id = $id; pid = $PID })
        $path = Join-Path $env:SCG_ROOT 'shim-calls.jsonl'
        [System.IO.File]::AppendAllText($path, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
    }
    function global:ScgTest_GetScAgent {
        param([string[]]$AllowedId = @())
        $allow = @($AllowedId | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        foreach ($id in @('5d0931a9fafc2a8b', 'deadbeefdeadbeef')) {
            [pscustomobject]@{
                Id = $id; ServiceName = ('ScgTestFakeSvc_' + $id); ServiceState = 'Running'; StartMode = 'Auto'
                Folder = ('C:\ScgTestFake\' + $id); UninstallKey = ''; Authorized = ($allow -contains $id)
            }
        }
    }
    function global:ScgTest_InvokeScHardening {
        param($Agent, [string[]]$Layer, [string]$BackupDir, [switch]$TakeOwnership)
        ScgTest_WriteCall -Fn 'Invoke-ScHardening' -Agent $Agent
        return [pscustomobject]@{ Ok = $true; Messages = @('stub') }
    }
    function global:ScgTest_InvokeScRestore {
        param($Agent, [string]$BackupDir)
        ScgTest_WriteCall -Fn 'Invoke-ScRestore' -Agent $Agent
        return [pscustomobject]@{ Ok = $true; Messages = @('stub') }
    }
    function global:ScgTest_RemoveScAgent {
        param($Agent, [string[]]$AllowedId, [string]$BackupDir)
        ScgTest_WriteCall -Fn 'Remove-ScAgent' -Agent $Agent
        return 'removed (stub)'
    }
    function global:ScgTest_TestScTamper {
        param($Agent, [string]$BackupDir)
        ScgTest_WriteCall -Fn 'Test-ScTamper' -Agent $Agent
        return $false
    }
}

function Install-ScgAgentShim {
    <#
    .SYNOPSIS
        Imports the REAL Agent module (global) and overrides discovery, hardening and directory locking inside it.
        No sc.exe, icacls or service change can run afterwards in this process.
    #>
    [CmdletBinding()]
    param()
    Import-Module (Join-Path $script:ModuleDir 'Agent.psm1') -DisableNameChecking -Global
    Install-ScgTestStub
    Set-ScgTestModuleAlias -ModuleName 'Agent' -Map @{
        'Get-ScAgent'                   = 'ScgTest_GetScAgent'
        'Invoke-ScHardening'            = 'ScgTest_InvokeScHardening'
        'Invoke-ScRestore'              = 'ScgTest_InvokeScRestore'
        'Remove-ScAgent'                = 'ScgTest_RemoveScAgent'
        'Test-ScTamper'                 = 'ScgTest_TestScTamper'
        'Initialize-ScgSecureDirectory' = 'ScgTest_NoSecureDirectory'
    }
}

function Invoke-ScgTestAgentCycle {
    <# .SYNOPSIS One shimmed agent cycle for the agent rooted at Root (sets SCG_ROOT and the agent log). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ConfigPath,
        [datetime]$Now = [datetime]::UtcNow,
        [switch]$Force
    )
    $env:SCG_ROOT = $Root
    $logPath = Join-Path $Root 'logs\agent.log'
    $secret = [string]((Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json).shared_secret)
    $mod = @(Get-Module -Name 'Agent') | Select-Object -Last 1
    & $mod { param($p, $s) Set-ScgLogContext -Path $p -MaxBytes 10485760 -Secret @($s) } $logPath $secret
    return (Invoke-ScgAgentCycle -ConfigPath $ConfigPath -Now $Now -Force:$Force)
}

function Read-ScgTestShimLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $p = Join-Path $Root 'shim-calls.jsonl'
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    $out = New-Object System.Collections.ArrayList
    foreach ($l in [System.IO.File]::ReadAllLines($p)) {
        if (-not [string]::IsNullOrWhiteSpace($l)) { try { [void]$out.Add(($l | ConvertFrom-Json)) } catch { $null = $_ } }
    }
    return $out.ToArray()
}

function Start-ScgTestHub {
    <# .SYNOPSIS Starts the real hub in-process (-NoWait) with directory locking disabled for the temp root. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    Install-ScgTestStub
    Set-ScgTestModuleAlias -ModuleName 'Hub' -Map @{ 'Initialize-ScgSecureDirectory' = 'ScgTest_NoSecureDirectory' }
    return (Start-ScgHub -ConfigPath $ConfigPath -NoWait)
}

function Stop-ScgTestHub {
    <# .SYNOPSIS Stops a hub handle; falls back to flag + Stop-ScgHttpServer if the handle's Stop fails. #>
    [CmdletBinding()]
    param([AllowNull()]$Hub)
    if ($null -eq $Hub) { return }
    try { & $Hub.Stop }
    catch {
        try { $Hub.State.Stop = $true } catch { $null = $_ }
        try { Stop-ScgHttpServer -Server $Hub.Server } catch { $null = $_ }
    }
}

function Initialize-ScgTestTrust {
    [CmdletBinding()]
    param()
    if ('ScgTestPin' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class ScgTestPin {
    private readonly string _t;
    public ScgTestPin(string t) { _t = t; }
    public bool Check(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) {
        if (c == null) { return false; }
        return string.Equals(new X509Certificate2(c).Thumbprint, _t, StringComparison.OrdinalIgnoreCase);
    }
    public RemoteCertificateValidationCallback Callback() { return new RemoteCertificateValidationCallback(Check); }
}
'@
}

function Invoke-ScgTestRequest {
    <# .SYNOPSIS Raw hub call with caller-chosen bearer and nonce (for 401/409 checks). Returns Status and Text. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [string]$Bearer = '',
        [string]$Nonce = ([guid]::NewGuid().ToString()),
        [string]$Timestamp = ([datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)),
        $Body = $null,
        [string]$Thumbprint = '',
        [hashtable]$Headers = @{}
    )
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method = $Method
    $req.Proxy = $null
    $req.KeepAlive = $false
    $req.Timeout = 30000
    if ($Thumbprint) {
        Initialize-ScgTestTrust
        $req.ServerCertificateValidationCallback = (New-Object ScgTestPin -ArgumentList $Thumbprint).Callback()
    }
    $req.Headers.Add('Authorization', 'Bearer ' + $Bearer)
    $req.Headers.Add('X-SCG-Timestamp', $Timestamp)
    $req.Headers.Add('X-SCG-Nonce', $Nonce)
    foreach ($hk in @($Headers.Keys)) { $req.Headers.Add([string]$hk, [string]$Headers[$hk]) }
    if ($Method -eq 'POST') {
        $json = '{}'
        if ($null -ne $Body) { $json = ConvertTo-Json -InputObject $Body -Depth 8 -Compress }
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
        $req.ContentType = 'application/json; charset=utf-8'
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream()
        try { $s.Write($bytes, 0, $bytes.Length) } finally { $s.Dispose() }
    }
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { return [pscustomobject]@{ Status = 0; Text = $_.Exception.Message } }
    }
    try {
        $r = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { $text = $r.ReadToEnd() } finally { $r.Dispose() }
        return [pscustomobject]@{ Status = [int]$resp.StatusCode; Text = $text }
    }
    finally { $resp.Dispose() }
}

function Get-ScgTestAgentToken {
    <# .SYNOPSIS Reads device_token from an agent.config.json ('' when absent). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    try {
        $c = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $p = $c.PSObject.Properties['device_token']
        if ($p -and $p.Value) { return [string]$p.Value }
    }
    catch { $null = $_ }
    return ''
}

function Test-ScgTestTextContains {
    <# .SYNOPSIS True when any file under the given roots (recursive, text-ish) contains Needle. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Root, [Parameter(Mandatory)][string]$Needle, [string[]]$Include = @('*.log', '*.txt', '*.jsonl', '*.log.*'))
    foreach ($r in $Root) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        # -Include is ignored with -LiteralPath on Windows PowerShell 5.1, so filter by name explicitly
        $candidates = @(Get-ChildItem -LiteralPath $r -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $n = $_.Name
                @($Include | Where-Object { $n -like $_ }).Count -gt 0
            })
        foreach ($f in $candidates) {
            try {
                $fs = New-Object System.IO.FileStream($f.FullName, 'Open', 'Read', 'ReadWrite')
                try {
                    $sr = New-Object System.IO.StreamReader($fs)
                    $t = $sr.ReadToEnd()
                }
                finally { $fs.Dispose() }
                if ($t.Contains($Needle)) { return $true }
            }
            catch { $null = $_ }
        }
    }
    return $false
}

function New-ScgTestTgUpdate {
    <# .SYNOPSIS Synthetic Telegram message update. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$FromId, [Parameter(Mandatory)][string]$ChatId, [int]$UpdateId = 1)
    return [pscustomobject]@{
        update_id = $UpdateId
        message   = [pscustomobject]@{
            message_id = $UpdateId
            date       = 0
            text       = $Text
            chat       = [pscustomobject]@{ id = [long]$ChatId; type = 'supergroup' }
            from       = [pscustomobject]@{ id = [long]$FromId; is_bot = $false; username = 'scg_it_admin' }
        }
    }
}

Export-ModuleMember -Function Get-ScgTestModuleDir, Get-ScgTestKnownId, Import-ScgTestProductModule, Test-ScgTestElevated,
    Test-ScgTestPortFree, Get-ScgTestFreePort, New-ScgTestSecret, New-ScgTestRoot, Remove-ScgTestPath, Write-ScgTestJson,
    New-ScgTestHubConfig, New-ScgTestAgentConfig, Enable-ScgTestNetworkGuard, Disable-ScgTestNetworkGuard,
    Set-ScgTestModuleAlias, Install-ScgTestStub, Install-ScgAgentShim, Invoke-ScgTestAgentCycle, Read-ScgTestShimLog,
    Start-ScgTestHub, Stop-ScgTestHub, Initialize-ScgTestTrust, Invoke-ScgTestRequest, New-ScgTestTgUpdate, Get-ScgTestAgentToken, Test-ScgTestTextContains
