# Runs as SYSTEM from the MSI (deferred custom action) or manually as admin.
# Exit codes: 0 ok | 10 bad hub url | 11 bad/missing secret | 12 config write failed
#             13 ACL failed | 14 agent task install failed | 15 bad thumbprint | 20 remove failed
param(
    [ValidateSet('Install', 'Uninstall')][string]$Action,
    [string]$HubUrl,
    [string]$SharedSecret,
    [string]$Thumbprint,
    [string]$DataDir = (Join-Path $env:ProgramData 'SCGuardian')
)

Set-StrictMode -Version 2.0

function Test-HubUrl {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
    $u = $null
    if (-not [Uri]::TryCreate($Url.Trim(), [UriKind]::Absolute, [ref]$u)) { return $false }
    if ([string]::IsNullOrEmpty($u.Host)) { return $false }
    if ($u.Scheme -eq 'https') { return $true }
    if ($u.Scheme -eq 'http') { return ($u.IsLoopback -or $u.Host -in @('localhost', '127.0.0.1', '[::1]', '::1')) }
    return $false
}

function Test-SharedSecret {
    param([string]$Secret)
    if ([string]::IsNullOrWhiteSpace($Secret)) { return $false }
    return ($Secret.Trim() -ne 'REPLACE_ME')
}

function Test-ThumbprintValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }   # optional
    return [bool](($Value -replace '\s', '') -match '^[0-9A-Fa-f]{40}$')
}

function Protect-Secret {
    param([string]$Text, [string]$Secret)
    if ([string]::IsNullOrEmpty($Text) -or [string]::IsNullOrEmpty($Secret)) { return $Text }
    return $Text.Replace($Secret, '***')
}

function Merge-AgentConfig {
    # Base: PSCustomObject or IDictionary (template/existing). Returns an ordered hashtable.
    param($Base, [string]$HubUrl, [string]$SharedSecret, [string]$Thumbprint)
    $cfg = [ordered]@{}
    if ($Base -is [System.Collections.IDictionary]) {
        foreach ($k in $Base.Keys) { $cfg[$k] = $Base[$k] }
    } elseif ($null -ne $Base) {
        foreach ($p in $Base.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
    }
    if (-not [string]::IsNullOrWhiteSpace($HubUrl))       { $cfg['hub_url'] = $HubUrl.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($SharedSecret)) { $cfg['shared_secret'] = $SharedSecret.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($Thumbprint))   { $cfg['trusted_server_thumbprint'] = ($Thumbprint -replace '\s', '').ToUpperInvariant() }
    return $cfg
}

function Get-IcaclsArguments {
    # SYSTEM + Administrators only, no inheritance (SIDs: locale independent).
    param([Parameter(Mandatory)][string]$Path)
    return @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
}

function Write-InstallLog {
    param([string]$Message, [string]$Secret)
    $line = Protect-Secret -Text ("{0:u}  {1}" -f (Get-Date), $Message) -Secret $Secret
    Write-Output $line
    try { Add-Content -Path (Join-Path $DataDir 'install.log') -Value $line -Encoding UTF8 } catch {}
}

function Invoke-AgentInstall {
    param([string]$HubUrl, [string]$SharedSecret, [string]$Thumbprint, [string]$DataDir, [string]$AppDir)
    $cfgPath  = Join-Path $DataDir 'agent.config.json'
    $supplied = (-not [string]::IsNullOrWhiteSpace($HubUrl)) -or (-not [string]::IsNullOrWhiteSpace($SharedSecret)) -or (-not [string]::IsNullOrWhiteSpace($Thumbprint))

    if (-not (Test-ThumbprintValue $Thumbprint)) { Write-InstallLog 'THUMBPRINT must be 40 hex characters.' $SharedSecret; return 15 }
    if ($supplied -and -not [string]::IsNullOrWhiteSpace($HubUrl) -and -not (Test-HubUrl $HubUrl)) {
        Write-InstallLog 'HUBURL must be https:// (or http on loopback).' $SharedSecret; return 10
    }

    $null = New-Item -ItemType Directory -Path $DataDir -Force
    $exists = Test-Path $cfgPath
    if (-not $exists -or $supplied) {
        try {
            $baseFile = if ($exists) { $cfgPath } else { Join-Path $AppDir 'agent.config.template.json' }
            $base = Get-Content $baseFile -Raw | ConvertFrom-Json
            $cfg  = Merge-AgentConfig -Base $base -HubUrl $HubUrl -SharedSecret $SharedSecret -Thumbprint $Thumbprint
        } catch { Write-InstallLog "Cannot read config source: $($_.Exception.Message)" $SharedSecret; return 12 }
    } else {
        try { $cfg = Merge-AgentConfig -Base (Get-Content $cfgPath -Raw | ConvertFrom-Json) }
        catch { Write-InstallLog "Existing config unreadable: $($_.Exception.Message)" $SharedSecret; return 12 }
    }

    # validate the EFFECTIVE config (covers: first install without properties, template REPLACE_ME)
    if (-not (Test-HubUrl "$($cfg['hub_url'])"))          { Write-InstallLog 'Effective hub_url is missing or not https://.' $SharedSecret; return 10 }
    if (-not (Test-SharedSecret "$($cfg['shared_secret'])")) { Write-InstallLog 'Effective shared_secret is missing or REPLACE_ME. Pass SHAREDSECRET=...' $SharedSecret; return 11 }

    if (-not $exists -or $supplied) {
        try {
            $json = $cfg | ConvertTo-Json -Depth 6
            [IO.File]::WriteAllText($cfgPath, $json, (New-Object Text.UTF8Encoding($false)))
            Write-InstallLog "Wrote $cfgPath (secret ***)." $SharedSecret
        } catch { Write-InstallLog "Config write failed: $($_.Exception.Message)" $SharedSecret; return 12 }
    }

    $ic = & icacls.exe @(Get-IcaclsArguments -Path $DataDir) 2>&1
    if ($LASTEXITCODE -ne 0) { Write-InstallLog "icacls failed ($LASTEXITCODE): $ic" $SharedSecret; return 13 }

    $main = Join-Path $AppDir 'SCGuardian.ps1'
    $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $main -InstallAgent -AgentConfigPath $cfgPath 2>&1
    $code = $LASTEXITCODE
    Write-InstallLog ("SCGuardian.ps1 -InstallAgent exit $code : " + (($out | ForEach-Object { "$_" }) -join ' ')) $SharedSecret
    if ($code -ne 0) { return 14 }
    return 0
}

function Invoke-AgentUninstall {
    param([string]$AppDir, [string]$DataDir)
    $main = Join-Path $AppDir 'SCGuardian.ps1'
    $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $main -RemoveAgent -AgentConfigPath (Join-Path $DataDir 'agent.config.json') 2>&1
    $code = $LASTEXITCODE
    Write-InstallLog ("SCGuardian.ps1 -RemoveAgent exit $code : " + (($out | ForEach-Object { "$_" }) -join ' '))
    if ($code -ne 0) { return 20 }
    return 0   # ProgramData (config/state/logs) intentionally left in place
}

if ($MyInvocation.InvocationName -ne '.' -and $Action) {
    $exit = 1
    try {
        if ($Action -eq 'Install') { $exit = Invoke-AgentInstall -HubUrl $HubUrl -SharedSecret $SharedSecret -Thumbprint $Thumbprint -DataDir $DataDir -AppDir $PSScriptRoot }
        else                       { $exit = Invoke-AgentUninstall -AppDir $PSScriptRoot -DataDir $DataDir }
    } catch {
        Write-InstallLog "Unexpected failure: $($_.Exception.Message)" $SharedSecret
        $exit = 1
    }
    exit $exit
}
