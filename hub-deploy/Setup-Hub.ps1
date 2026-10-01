<#
.SYNOPSIS
    One-command SCGuardian Hub setup: download, install, configure, certificate, start, verify and
    generate the per-hub agent bootstrap.
.DESCRIPTION
    Run once as Administrator on the Hub server. Steps:
      0 admin check and TLS 1.2
      1 optional cleanup (-Reinstall)
      2 download and extract the release source (skipped with -SourceRoot)
      3 install-hub.ps1 (program files, data folder, firewall rule, scheduled task)
      4 complete C:\ProgramData\SCGuardian\hub.config.json (keeps every value already set, generates the
        shared secret, prompts only for Telegram fields that still hold placeholders)
      5 TLS certificate (reuses a valid pinned certificate; creates a self-signed one otherwise)
      6 restart the SCGuardian-Hub task and wait for the port
      7 signed health check with the certificate pinned by thumbprint
      8 render C:\ProgramData\SCGuardian\agent-bootstrap.ps1 for the devices
    The shared secret and the bot token are never printed. Safe to re-run: the certificate is not
    replaced unless -NewCert is given, so already-enrolled agents keep working.
.PARAMETER Domain
    Public DNS name of the Hub.
.PARAMETER Port
    HTTPS port the Hub listens on.
.PARAMETER Version
    Release tag (without the leading v) to download and to pin in the agent bootstrap.
.PARAMETER SourceRoot
    Already-extracted repository (or a folder containing it). Skips the download.
.PARAMETER Reinstall
    Stops and unregisters the SCGuardian-Hub task, removes the firewall rule and deletes
    C:\Program Files\SCGuardian first. Config, database and certificate in C:\ProgramData\SCGuardian are kept.
.PARAMETER NewCert
    Forces a new self-signed certificate. Every agent must then receive a regenerated bootstrap.
.PARAMETER SkipHealthCheck
    Skips step 7.
.PARAMETER Desktop
    Also copies agent-bootstrap.ps1 to the current user's Desktop.
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\Setup-Hub.ps1"
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Setup-Hub.ps1 -Reinstall -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^[A-Za-z0-9.-]+$')][string]$Domain = 'ostazna.pro',
    [ValidateRange(1, 65535)][int]$Port = 8443,
    [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$')][string]$Version = '4.0.1',
    [string]$SourceRoot,
    [switch]$Reinstall,
    [switch]$NewCert,
    [switch]$SkipHealthCheck,
    [switch]$Desktop
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:RepoUrl = 'https://github.com/cBadr/SCGuardian'

function New-HubSecret {
<#
.SYNOPSIS
    Returns 32 CSPRNG bytes as 64 lowercase hex characters.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-HubConfigValue {
<#
.SYNOPSIS
    Reads a dotted path (for example telegram.chat_id) from a config object; null when missing.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Config, [Parameter(Mandatory = $true)][string]$Path)
    $cur = $Config
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $null }
        $prop = $cur.PSObject.Properties[$part]
        if ($null -eq $prop) { return $null }
        $cur = $prop.Value
    }
    return , $cur
}

function Set-HubConfigValue {
<#
.SYNOPSIS
    Sets a dotted path on a config object, creating missing sections.
#>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][object]$Value
    )
    $parts = $Path.Split('.')
    $cur = $Config
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        $prop = $cur.PSObject.Properties[$parts[$i]]
        if ($null -eq $prop -or $null -eq $prop.Value) {
            $section = New-Object PSObject
            if ($null -eq $prop) { $cur | Add-Member -NotePropertyName $parts[$i] -NotePropertyValue $section }
            else { $prop.Value = $section }
            $cur = $section
        }
        else { $cur = $prop.Value }
    }
    $leaf = $parts[$parts.Length - 1]
    $prop = $cur.PSObject.Properties[$leaf]
    if ($null -eq $prop) { $cur | Add-Member -NotePropertyName $leaf -NotePropertyValue $Value }
    else { $prop.Value = $Value }
}

function Test-HubConfigPlaceholder {
<#
.SYNOPSIS
    True when a hub.config.json field is empty or still holds its template placeholder.
.PARAMETER Field
    shared_secret, telegram.bot_token, telegram.chat_id or telegram.admin_user_ids.
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Field, [AllowNull()][object]$Value)
    switch ($Field) {
        'shared_secret' { return ([string]::IsNullOrWhiteSpace([string]$Value) -or ([string]$Value) -match '(?i)REPLACE_ME') }
        'telegram.bot_token' { return ([string]::IsNullOrWhiteSpace([string]$Value) -or ([string]$Value) -match '(?i)REPLACE_ME') }
        'telegram.chat_id' {
            $s = [string]$Value
            return ([string]::IsNullOrWhiteSpace($s) -or $s -match '(?i)REPLACE_ME' -or $s -match '\.\.\.')
        }
        'telegram.admin_user_ids' {
            $items = @(@($Value) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
            if ($items.Count -eq 0) { return $true }
            foreach ($it in $items) { if ($it -eq '123456789' -or $it -match '(?i)REPLACE_ME') { return $true } }
            return $false
        }
        default { throw "Unknown config field: $Field" }
    }
}

function Get-HubPlaceholderField {
<#
.SYNOPSIS
    Lists the tracked config fields that are still empty or placeholders.
#>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory = $true)]$Config)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($f in @('shared_secret', 'telegram.bot_token', 'telegram.chat_id', 'telegram.admin_user_ids')) {
        if (Test-HubConfigPlaceholder -Field $f -Value (Get-HubConfigValue -Config $Config -Path $f)) { $list.Add($f) }
    }
    return , ([string[]]$list.ToArray())
}

function ConvertTo-HubAdminIdList {
<#
.SYNOPSIS
    Normalises admin ids (comma/space separated text or an array) to a string array.
#>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][object]$Value)
    $raw = @()
    if ($Value -is [string]) { $raw = $Value -split '[,;\s]+' } else { $raw = @($Value) }
    $out = @($raw | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
    return , ([string[]]$out)
}

function Test-HubAnswerFormat {
<#
.SYNOPSIS
    Validates an operator answer for a Telegram field.
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Field, [AllowNull()][object]$Value)
    switch ($Field) {
        'telegram.bot_token' { return ([string]$Value -match '^\d{5,}:[A-Za-z0-9_-]{20,}$') }
        'telegram.chat_id' { return ([string]$Value -match '^(-?\d+|@[A-Za-z0-9_]{5,})$') }
        'telegram.admin_user_ids' {
            $ids = ConvertTo-HubAdminIdList -Value $Value
            if ($ids.Count -eq 0) { return $false }
            foreach ($i in $ids) { if ($i -notmatch '^\d+$' -or $i -eq '123456789') { return $false } }
            return $true
        }
        default { return $false }
    }
}

function Update-HubConfig {
<#
.SYNOPSIS
    Completes a hub config in memory: keeps operator values, fills placeholders only.
.DESCRIPTION
    Sets listen.url to https://+:<Port>/, generates shared_secret when it is a placeholder, and fills
    Telegram placeholder fields from -Answers (keys are the dotted field names). Returns an object with
    Config, SecretGenerated, Filled and Unresolved (placeholder fields without an answer).
#>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true)]$Config,
        [ValidateRange(1, 65535)][int]$Port = 8443,
        [hashtable]$Answers = @{},
        [string]$NewSecret
    )
    $filled = New-Object System.Collections.Generic.List[string]
    $unresolved = New-Object System.Collections.Generic.List[string]
    Set-HubConfigValue -Config $Config -Path 'listen.url' -Value ('https://+:{0}/' -f $Port)

    $secretGenerated = $false
    if (Test-HubConfigPlaceholder -Field 'shared_secret' -Value (Get-HubConfigValue -Config $Config -Path 'shared_secret')) {
        $s = $NewSecret
        if ([string]::IsNullOrWhiteSpace($s)) { $s = New-HubSecret }
        Set-HubConfigValue -Config $Config -Path 'shared_secret' -Value $s
        $secretGenerated = $true
        $filled.Add('shared_secret')
    }

    foreach ($f in @('telegram.bot_token', 'telegram.chat_id', 'telegram.admin_user_ids')) {
        if (-not (Test-HubConfigPlaceholder -Field $f -Value (Get-HubConfigValue -Config $Config -Path $f))) { continue }
        if ($null -eq $Answers -or -not $Answers.ContainsKey($f) -or [string]::IsNullOrWhiteSpace(([string]@($Answers[$f])[0]))) {
            $unresolved.Add($f)
            continue
        }
        $v = $Answers[$f]
        if ($f -eq 'telegram.admin_user_ids') { $v = ConvertTo-HubAdminIdList -Value $v }
        else { $v = ([string]$v).Trim() }
        Set-HubConfigValue -Config $Config -Path $f -Value $v
        $filled.Add($f)
    }

    return [pscustomobject]@{
        Config          = $Config
        SecretGenerated = $secretGenerated
        Filled          = [string[]]$filled.ToArray()
        Unresolved      = [string[]]$unresolved.ToArray()
    }
}

function Read-HubConfig {
<#
.SYNOPSIS
    Parses hub.config.json.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Config not found: $Path" }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Save-HubConfig {
<#
.SYNOPSIS
    Writes a config object as UTF-8 JSON without BOM (existing file ACL is kept).
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Config, [Parameter(Mandatory = $true)][string]$Path)
    $json = $Config | ConvertTo-Json -Depth 10
    if ($PSCmdlet.ShouldProcess($Path, 'Write hub config')) {
        [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
    }
}

function Test-HubThumbprint {
<#
.SYNOPSIS
    True for a 40-hex SHA-1 thumbprint.
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][object]$Value)
    return ($null -ne $Value -and ([string]$Value) -match '^[0-9A-Fa-f]{40}$')
}

function Test-SslBindingMatch {
<#
.SYNOPSIS
    True when netsh http show sslcert output contains the given certificate hash.
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string]$NetshOutput, [Parameter(Mandatory = $true)][string]$Thumbprint)
    if ([string]::IsNullOrEmpty($NetshOutput)) { return $false }
    return ($NetshOutput.IndexOf($Thumbprint, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function Get-Sha256FromSums {
<#
.SYNOPSIS
    Extracts the lowercase SHA-256 of one file from SHA256SUMS.txt content (either column order).
#>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content, [string]$FileName = 'SCGuardian.Agent.Setup.exe')
    foreach ($line in ($Content -split "`r?`n")) {
        $name = $null; $hash = $null
        if ($line -match '^\s*([0-9A-Fa-f]{64})\s+\*?(\S.*?)\s*$') { $hash = $Matches[1]; $name = $Matches[2] }
        elseif ($line -match '^\s*(\S.*?)\s+([0-9A-Fa-f]{64})\s*$') { $name = $Matches[1]; $hash = $Matches[2] }
        else { continue }
        $leaf = $name -replace '^.*[\\/]', ''
        if ([string]::Equals($leaf, $FileName, [StringComparison]::OrdinalIgnoreCase)) { return $hash.ToLowerInvariant() }
    }
    throw "No SHA-256 entry for $FileName in SHA256SUMS.txt."
}

function ConvertTo-SingleQuotedContent {
<#
.SYNOPSIS
    Escapes text for use inside a PowerShell single-quoted string (doubles every single-quote character).
#>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $out = $Text
    foreach ($code in 0x27, 0x2018, 0x2019, 0x201A, 0x201B) {
        $q = [string][char]$code
        $out = $out.Replace($q, $q + $q)
    }
    return $out
}

function ConvertTo-AgentBootstrap {
<#
.SYNOPSIS
    Renders agent-bootstrap.template.ps1 with the Hub values (single quotes escaped).
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Template,
        [Parameter(Mandatory = $true)][string]$HubUrl,
        [Parameter(Mandatory = $true)][string]$SharedSecret,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$SetupSha256
    )
    if ($HubUrl -notmatch '^https://[^\s"]+$') { throw 'HubUrl must be an https:// URL without spaces.' }
    if ($SharedSecret -match '[\s"]' -or $SharedSecret -match '\p{Cc}') {
        throw 'shared_secret contains whitespace, a double quote or a control character; agents cannot receive it on the installer command line. Clear it in hub.config.json to regenerate.'
    }
    if (-not (Test-HubThumbprint $Thumbprint)) { throw 'Thumbprint must be 40 hex characters.' }
    if ($SetupSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'SetupSha256 must be 64 hex characters.' }
    if ($Version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { throw 'Invalid version.' }

    $map = [ordered]@{
        '{{HUB_URL}}'       = $HubUrl
        '{{SHARED_SECRET}}' = $SharedSecret
        '{{THUMBPRINT}}'    = $Thumbprint.ToUpperInvariant()
        '{{VERSION}}'       = $Version
        '{{SETUP_SHA256}}'  = $SetupSha256.ToLowerInvariant()
    }
    $out = $Template
    foreach ($k in $map.Keys) {
        if (-not $Template.Contains($k)) { throw "Template is missing the placeholder $k." }
        $out = $out.Replace($k, (ConvertTo-SingleQuotedContent -Text ([string]$map[$k])))
    }
    $left = [regex]::Match($out, '\{\{[A-Z0-9_]+\}\}')
    if ($left.Success) { throw "Unrendered placeholder left in the bootstrap: $($left.Value)" }
    return $out
}

function Find-ExtractedRoot {
<#
.SYNOPSIS
    Finds the repository root (the folder containing hub-deploy\install-hub.ps1) at most two levels below Path.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    $level = @(Get-Item -LiteralPath $Path)
    for ($depth = 0; $depth -le 2; $depth++) {
        $next = @()
        foreach ($dir in $level) {
            if (Test-Path -LiteralPath (Join-Path $dir.FullName 'hub-deploy\install-hub.ps1') -PathType Leaf) { return $dir.FullName }
            $next += @(Get-ChildItem -LiteralPath $dir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name)
        }
        $level = $next
    }
    return $null
}

function Hide-HubSecret {
<#
.SYNOPSIS
    Masks known secrets, bot tokens and bearer values in text.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Text, [AllowNull()][string[]]$Secret)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    foreach ($s in @($Secret)) {
        if (-not [string]::IsNullOrEmpty($s) -and $s.Length -ge 4) { $out = $out.Replace($s, '***') }
    }
    $out = $out -replace '\d{5,}:[A-Za-z0-9_-]{20,}', '***'
    $out = $out -replace '(?i)(Bearer\s+)\S+', '$1***'
    return $out
}

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step {
    param([int]$Number, [string]$Text)
    Write-Host ''
    Write-Host ('[{0}/8] {1}' -f $Number, $Text) -ForegroundColor Cyan
}

function Set-LockedFileAcl {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($PSCmdlet.ShouldProcess($Path, 'Restrict ACL to SYSTEM and Administrators')) {
        & icacls.exe $Path '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
    }
}

function Read-HubAnswer {
<#
.SYNOPSIS
    Prompts the operator for one Telegram field (bot token read as a secure string), three attempts.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Field)
    $prompts = @{
        'telegram.bot_token'      = 'Telegram bot token (from @BotFather, input hidden)'
        'telegram.chat_id'        = 'Telegram chat id for alerts (e.g. -1001234567890, or your numeric user id)'
        'telegram.admin_user_ids' = 'Telegram admin user id(s), numeric, comma separated (get yours from @userinfobot)'
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        if ($Field -eq 'telegram.bot_token') {
            $secure = Read-Host -Prompt $prompts[$Field] -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try { $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        else { $value = Read-Host -Prompt $prompts[$Field] }
        $value = ([string]$value).Trim()
        if (Test-HubAnswerFormat -Field $Field -Value $value) { return $value }
        Write-Warning "That does not look like a valid $Field. Try again."
    }
    throw "No valid value entered for $Field."
}

function Wait-HubPort {
    param([int]$Port, [int]$TimeoutSec = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $client = New-Object Net.Sockets.TcpClient
        try {
            $ar = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne(1000) -and $client.Connected) { return $true }
        }
        catch { $null = $_ }
        finally { $client.Close() }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Invoke-HubHealthCheck {
<#
.SYNOPSIS
    Signed GET /api/v1/health on localhost with the server certificate pinned by thumbprint.
#>
    [CmdletBinding()]
    param([int]$Port, [string]$Secret, [string]$Thumbprint)
    $expected = $Thumbprint.ToUpperInvariant()
    $callback = {
        param($s, $cert, $chain, $policyErrors)
        if ($null -eq $cert) { return $false }
        return ($cert.GetCertHashString().ToUpperInvariant() -eq $expected)
    }.GetNewClosure()
    $previous = [Net.ServicePointManager]::ServerCertificateValidationCallback
    $body = $null
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = [Net.Security.RemoteCertificateValidationCallback]$callback
        $req = [Net.HttpWebRequest]::Create(('https://localhost:{0}/api/v1/health' -f $Port))
        $req.Method = 'GET'
        $req.Timeout = 15000
        $req.KeepAlive = $false
        $req.Headers.Add('Authorization', 'Bearer ' + $Secret)
        $req.Headers.Add('X-SCG-Timestamp', [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture))
        $req.Headers.Add('X-SCG-Nonce', [guid]::NewGuid().ToString())
        try { $resp = $req.GetResponse() }
        catch {
            $ex = $_.Exception
            while ($null -ne $ex.InnerException -and -not ($ex -is [Net.WebException])) { $ex = $ex.InnerException }
            $status = ''
            if ($ex -is [Net.WebException] -and $null -ne $ex.Response) { $status = ' (HTTP ' + [int]$ex.Response.StatusCode + ')' }
            throw ('Health request failed' + $status + ': ' + $ex.Message)
        }
        try {
            $reader = New-Object IO.StreamReader($resp.GetResponseStream())
            $body = $reader.ReadToEnd()
        }
        finally { $resp.Close() }
    }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $previous }
    $obj = $body | ConvertFrom-Json
    if ($null -eq $obj -or $null -eq $obj.PSObject.Properties['ok'] -or $obj.ok -ne $true) { throw 'Health endpoint did not return ok=true.' }
    return $obj
}

if ($MyInvocation.InvocationName -eq '.') { return }

# ----------------------------------------------------------------------------------------------- main
$ProgressPreference = 'SilentlyContinue'
$selfPath = $MyInvocation.MyCommand.Path
if (-not $selfPath) { $selfPath = $PSCommandPath }
$selfDir = $null
if ($selfPath) { $selfDir = Split-Path -Parent $selfPath }

$dry = [bool]$WhatIfPreference
$TaskName = 'SCGuardian-Hub'
$RuleName = 'SCGuardian Hub'
$InstallDir = 'C:\Program Files\SCGuardian'
$DataDir = 'C:\ProgramData\SCGuardian'
$ConfigPath = Join-Path $DataDir 'hub.config.json'
$BootstrapPath = Join-Path $DataDir 'agent-bootstrap.ps1'
$HubUrl = 'https://{0}:{1}' -f $Domain, $Port
$knownSecrets = @()

try {
    Write-Step 0 'Checking prerequisites'
    if ($PSVersionTable.PSVersion.Major -ne 5 -or ($PSVersionTable.ContainsKey('PSEdition') -and $PSVersionTable.PSEdition -ne 'Desktop')) {
        throw 'Run this script with Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.'
    }
    if (-not (Test-IsAdministrator)) { throw 'Run this script from an elevated (Administrator) PowerShell prompt.' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Host "      Domain $Domain, port $Port, version $Version$(if ($dry) { ' (WhatIf: nothing is changed)' })"

    Write-Step 1 'Cleanup for reinstall'
    if ($Reinstall) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Stop and unregister scheduled task')) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($PSCmdlet.ShouldProcess($RuleName, 'Remove firewall rule')) {
            Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        }
        if ((Test-Path -LiteralPath $InstallDir) -and $PSCmdlet.ShouldProcess($InstallDir, 'Delete program files')) {
            Start-Sleep -Seconds 2
            Remove-Item -LiteralPath $InstallDir -Recurse -Force
        }
        Write-Host "      Kept $DataDir (config, database, certificate)."
    }
    else { Write-Host '      Skipped (no -Reinstall).' }

    Write-Step 2 'Getting the Hub source'
    $root = $null
    if ($SourceRoot) {
        $root = Find-ExtractedRoot -Path $SourceRoot
        if (-not $root) { throw "No folder containing hub-deploy\install-hub.ps1 was found under $SourceRoot." }
        Write-Host "      Using $root"
    }
    else {
        $zipUrl = '{0}/archive/refs/tags/v{1}.zip' -f $script:RepoUrl, $Version
        $work = Join-Path $env:TEMP ('scg-hub-' + $Version)
        $zip = Join-Path $env:TEMP ('scg-hub-' + $Version + '.zip')
        if ($PSCmdlet.ShouldProcess($zipUrl, 'Download and extract release source')) {
            if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
            Invoke-WebRequest -Uri $zipUrl -OutFile $zip -UseBasicParsing
            Expand-Archive -LiteralPath $zip -DestinationPath $work -Force
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
            $root = Find-ExtractedRoot -Path $work
            if (-not $root) { throw "The downloaded archive has no hub-deploy\install-hub.ps1 (tag v$Version)." }
            Write-Host "      Extracted to $root"
        }
    }

    Write-Step 3 'Installing the Hub (install-hub.ps1)'
    if ($root) {
        $installScript = Join-Path $root 'hub-deploy\install-hub.ps1'
        & $installScript -SourceRoot $root -Port $Port -WhatIf:$dry
    }
    else { Write-Host '      WhatIf: would run install-hub.ps1 from the downloaded source.' }

    Write-Step 4 'Completing hub.config.json'
    $cfg = $null
    if (Test-Path -LiteralPath $ConfigPath) {
        $cfg = Read-HubConfig -Path $ConfigPath
        $missing = Get-HubPlaceholderField -Config $cfg
        $answers = @{}
        foreach ($f in $missing) {
            if ($f -eq 'shared_secret') { continue }
            if ($dry) { Write-Host "      WhatIf: would prompt for $f"; continue }
            $answers[$f] = Read-HubAnswer -Field $f
        }
        if ($dry) {
            Write-Host "      WhatIf: would set listen.url to https://+:$Port/ and fill: $(if ($missing.Count) { $missing -join ', ' } else { 'nothing' })"
        }
        else {
            $result = Update-HubConfig -Config $cfg -Port $Port -Answers $answers
            if ($result.Unresolved.Count -gt 0) { throw ('Config fields still missing: ' + ($result.Unresolved -join ', ')) }
            $cfg = $result.Config
            Save-HubConfig -Config $cfg -Path $ConfigPath
            if ($result.SecretGenerated) { Write-Host '      Generated a new shared_secret (64 hex, not shown).' }
            if ($result.Filled.Count -gt 0) { Write-Host ('      Filled: ' + ($result.Filled -join ', ')) }
            else { Write-Host '      All values were already set; kept them.' }
        }
        $knownSecrets = @([string](Get-HubConfigValue -Config $cfg -Path 'shared_secret'), [string](Get-HubConfigValue -Config $cfg -Path 'telegram.bot_token'))
    }
    elseif ($dry) { Write-Host "      WhatIf: $ConfigPath would be created from the template and completed." }
    else { throw "Config not found after install: $ConfigPath" }

    Write-Step 5 'TLS certificate'
    $certScript = if ($root) { Join-Path $root 'hub-deploy\cert-setup.ps1' } else { $null }
    $thumb = $null
    if ($cfg) { $thumb = [string](Get-HubConfigValue -Config $cfg -Path 'listen.cert_thumbprint') }
    $reuse = $false
    if (-not $NewCert -and (Test-HubThumbprint $thumb)) {
        $existing = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $thumb.ToUpperInvariant()) -ErrorAction SilentlyContinue
        if ($existing -and $existing.HasPrivateKey -and $existing.NotAfter -gt (Get-Date).AddDays(1)) { $reuse = $true }
    }
    if ($reuse) {
        Write-Host "      Reusing certificate $($thumb.ToUpperInvariant()) (agents pin this thumbprint)."
        $show = & netsh.exe http show sslcert ("ipport=0.0.0.0:{0}" -f $Port) 2>&1 | Out-String
        if (Test-SslBindingMatch -NetshOutput $show -Thumbprint $thumb) { Write-Host '      HTTP.sys binding present.' }
        else {
            if (-not $certScript -or -not (Test-Path -LiteralPath $certScript)) { throw 'cert-setup.ps1 not available to restore the HTTP.sys binding.' }
            $tokens = $null; $parseErrors = $null
            $certAst = [Management.Automation.Language.Parser]::ParseFile($certScript, [ref]$tokens, [ref]$parseErrors)
            if ($parseErrors.Count -gt 0) { throw 'cert-setup.ps1 has parse errors.' }
            $appMatch = [regex]::Match($certAst.Extent.Text, '\$script:HubAppId\s*=\s*''(\{[0-9A-Fa-f-]+\})''')
            if (-not $appMatch.Success) { throw 'Cannot read the Hub appid from cert-setup.ps1.' }
            $script:HubAppId = $appMatch.Groups[1].Value
            $helperNames = @('Format-ThumbprintClean', 'Get-NetshBindingArgument', 'Set-HubSslBinding')
            $helperDefs = $certAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $helperNames -contains $n.Name }, $true)
            foreach ($d in $helperDefs) { . ([scriptblock]::Create($d.Extent.Text)) }
            Set-HubSslBinding -Port $Port -Thumbprint $thumb
            Write-Host '      HTTP.sys binding restored.'
        }
    }
    elseif ($certScript) {
        if ($NewCert) { Write-Warning 'New certificate requested: every agent needs a regenerated bootstrap.' }
        if ($PSCmdlet.ShouldProcess($Domain, 'Create self-signed certificate and bind it (cert-setup.ps1)')) {
            & $certScript -Domain $Domain -Port $Port -SelfSigned -ConfigPath $ConfigPath | Out-Null
        }
    }
    else { Write-Host '      WhatIf: would run cert-setup.ps1 -SelfSigned.' }
    if (-not $dry) {
        $cfg = Read-HubConfig -Path $ConfigPath
        $thumb = ([string](Get-HubConfigValue -Config $cfg -Path 'listen.cert_thumbprint')).ToUpperInvariant()
        if (-not (Test-HubThumbprint $thumb)) { throw 'listen.cert_thumbprint is not a 40-hex thumbprint after certificate setup.' }
        Write-Host "      Thumbprint: $thumb"
    }

    Write-Step 6 'Restarting the Hub task'
    if ($PSCmdlet.ShouldProcess($TaskName, 'Restart scheduled task')) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-ScheduledTask -TaskName $TaskName
        if (Wait-HubPort -Port $Port -TimeoutSec 30) { Write-Host "      Listening on TCP $Port." }
        else { Write-Warning "Nothing is listening on TCP $Port after 30 seconds." }
    }

    Write-Step 7 'Health check'
    if ($SkipHealthCheck) { Write-Host '      Skipped (-SkipHealthCheck).' }
    elseif ($dry) { Write-Host '      WhatIf: skipped.' }
    else {
        try {
            $health = Invoke-HubHealthCheck -Port $Port -Secret ([string](Get-HubConfigValue -Config $cfg -Path 'shared_secret')) -Thumbprint $thumb
            Write-Host ("      ok=true, version {0}, devices online {1}" -f $health.version, $health.devices_online) -ForegroundColor Green
        }
        catch {
            Write-Host ('Health check FAILED: ' + (Hide-HubSecret -Text $_.Exception.Message -Secret $knownSecrets)) -ForegroundColor Red
            $logPath = [string](Get-HubConfigValue -Config $cfg -Path 'logging.path')
            if (-not $logPath) { $logPath = Join-Path $DataDir 'hub.log' }
            if (Test-Path -LiteralPath $logPath) {
                Write-Host "Last 15 lines of ${logPath}:"
                foreach ($line in @(Get-Content -LiteralPath $logPath -Tail 15)) { Write-Host ('  ' + (Hide-HubSecret -Text $line -Secret $knownSecrets)) }
            }
            else { Write-Host "No hub log at $logPath." }
            exit 1
        }
    }

    Write-Step 8 'Generating the agent bootstrap'
    if ($dry) { Write-Host "      WhatIf: would write $BootstrapPath$(if ($Desktop) { ' and a Desktop copy' })." }
    else {
        $sumsUrl = '{0}/releases/download/v{1}/SHA256SUMS.txt' -f $script:RepoUrl, $Version
        $sumsFile = Join-Path $env:TEMP ('scg-sums-' + $Version + '.txt')
        try {
            Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsFile -UseBasicParsing
            $sha = Get-Sha256FromSums -Content ([IO.File]::ReadAllText($sumsFile)) -FileName 'SCGuardian.Agent.Setup.exe'
        }
        catch { throw ("Cannot get the agent SHA-256 from $sumsUrl ($($_.Exception.Message)). The Hub itself is running; publish release v$Version and re-run this command.") }
        finally { Remove-Item -LiteralPath $sumsFile -Force -ErrorAction SilentlyContinue }

        $templatePath = $null
        $candidates = @()
        if ($root) { $candidates += (Join-Path $root 'hub-deploy\agent-bootstrap.template.ps1') }
        if ($selfDir) { $candidates += (Join-Path $selfDir 'agent-bootstrap.template.ps1') }
        foreach ($c in $candidates) { if (Test-Path -LiteralPath $c -PathType Leaf) { $templatePath = $c; break } }
        if ($templatePath) { $template = [IO.File]::ReadAllText($templatePath) }
        else {
            $template = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/cBadr/SCGuardian/main/hub-deploy/agent-bootstrap.template.ps1' -UseBasicParsing).Content
            if ($template -is [byte[]]) { $template = [Text.Encoding]::UTF8.GetString($template) }
        }

        $rendered = ConvertTo-AgentBootstrap -Template $template -HubUrl $HubUrl -SharedSecret ([string](Get-HubConfigValue -Config $cfg -Path 'shared_secret')) `
            -Thumbprint $thumb -Version $Version -SetupSha256 $sha
        if ($PSCmdlet.ShouldProcess($BootstrapPath, 'Write agent bootstrap')) {
            [IO.File]::WriteAllText($BootstrapPath, $rendered, (New-Object Text.UTF8Encoding($true)))
            Set-LockedFileAcl -Path $BootstrapPath
            Write-Host "      Wrote $BootstrapPath (SYSTEM and Administrators only)."
        }
        if ($Desktop) {
            $desktopCopy = Join-Path ([Environment]::GetFolderPath('Desktop')) 'agent-bootstrap.ps1'
            if ($PSCmdlet.ShouldProcess($desktopCopy, 'Copy agent bootstrap to Desktop')) {
                Copy-Item -LiteralPath $BootstrapPath -Destination $desktopCopy -Force
                Set-LockedFileAcl -Path $desktopCopy
                Write-Host "      Copied to $desktopCopy"
            }
        }
    }
}
catch {
    Write-Host ('FAILED: ' + (Hide-HubSecret -Text $_.Exception.Message -Secret $knownSecrets)) -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '================ SCGuardian Hub ready ================' -ForegroundColor Green
Write-Host "Hub URL        : $HubUrl"
Write-Host "Thumbprint     : $(if ($thumb) { $thumb } else { '(WhatIf)' })"
Write-Host "Agent bootstrap: $BootstrapPath"
Write-Host ''
Write-Host 'Next steps:'
Write-Host "  1. DNS: an A record for $Domain must point to this server's public IP."
Write-Host "  2. Open inbound TCP $Port on the router/cloud firewall (Windows Firewall rule '$RuleName' is already set)."
Write-Host '  3. Copy agent-bootstrap.ps1 to each device over a PRIVATE channel and run it as Administrator:'
Write-Host '       powershell -NoProfile -ExecutionPolicy Bypass -File .\agent-bootstrap.ps1'
Write-Host '     Delete it from the device afterwards.'
Write-Host '  WARNING: agent-bootstrap.ps1 contains the shared secret. Per-device tokens limit what a leaked'
Write-Host '  secret can do to enrolled devices, but it can still enroll NEW hostnames. If it leaks, clear'
Write-Host '  shared_secret in hub.config.json, re-run this command and redeploy the new bootstrap.'
Write-Host '  Re-enroll a device (reinstalled or rebuilt with the same hostname): send /reset <hostname> to the'
Write-Host '  Telegram bot; the agent enrolls again on its next cycle.'
exit 0
