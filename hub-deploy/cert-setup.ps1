<#
.SYNOPSIS
    Obtains (Let's Encrypt via win-acme) or generates (self-signed) the Hub TLS certificate,
    binds it to the HTTP.sys port and records the thumbprint in hub.config.json.
.PARAMETER Domain
    Public DNS name of the Hub.
.PARAMETER Port
    HTTPS port the Hub listens on.
.PARAMETER WinAcmePath
    Optional path to wacs.exe (or its folder). Otherwise PATH and C:\Tools\win-acme are searched.
.PARAMETER SelfSigned
    Force a self-signed certificate even when win-acme is available.
.PARAMETER ConfigPath
    Path to hub.config.json. listen.cert_thumbprint is updated there.
.NOTES
    Let's Encrypt validation uses the win-acme self-hosting http-01 listener on TCP port 80,
    so port 80 must be reachable from the internet while the certificate is requested.
    The private key is never exported. Requires Windows PowerShell 5.1 and an elevated prompt.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Domain = 'ostazna.pro',
    [int]$Port = 8443,
    [string]$WinAcmePath,
    [switch]$SelfSigned,
    [string]$ConfigPath = 'C:\ProgramData\SCGuardian\hub.config.json'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:HubAppId = '{7f3c1e52-4b8a-4d6e-9a21-5c0d8e3b6f14}'

function Format-ThumbprintClean {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Thumbprint)
    $clean = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($clean.Length -ne 40) {
        throw "Invalid SHA1 thumbprint: expected 40 hex characters, got $($clean.Length)."
    }
    return $clean
}

function ConvertTo-CertPem {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$DerBytes)
    $b64 = [Convert]::ToBase64String($DerBytes)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('-----BEGIN CERTIFICATE-----')
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $lines.Add($b64.Substring($i, [Math]::Min(64, $b64.Length - $i)))
    }
    $lines.Add('-----END CERTIFICATE-----')
    return ($lines -join "`n")
}

function Get-NetshBindingArgument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [string]$Thumbprint,
        [switch]$Delete
    )
    if ($Port -lt 1 -or $Port -gt 65535) { throw "Invalid port: $Port" }
    $ipport = "ipport=0.0.0.0:$Port"
    if ($Delete) {
        return @('http', 'delete', 'sslcert', $ipport)
    }
    $hash = Format-ThumbprintClean -Thumbprint $Thumbprint
    return @('http', 'add', 'sslcert', $ipport, "certhash=$hash", "appid=$script:HubAppId", 'certstorename=MY')
}

function Set-ConfigThumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )
    $clean = Format-ThumbprintClean -Thumbprint $Thumbprint
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Config not found: $ConfigPath" }
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $cfg.PSObject.Properties['listen']) {
        $cfg | Add-Member -NotePropertyName listen -NotePropertyValue ([pscustomobject]@{ url = ('https://+:8443/'); cert_thumbprint = $clean })
    }
    elseif ($null -eq $cfg.listen.PSObject.Properties['cert_thumbprint']) {
        $cfg.listen | Add-Member -NotePropertyName cert_thumbprint -NotePropertyValue $clean
    }
    else {
        $cfg.listen.cert_thumbprint = $clean
    }
    $json = $cfg | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($ConfigPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    return $clean
}

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-WinAcme {
    param([string]$Hint)
    $candidates = @()
    if ($Hint) {
        if (Test-Path -LiteralPath $Hint -PathType Container) { $candidates += (Join-Path $Hint 'wacs.exe') }
        else { $candidates += $Hint }
    }
    $cmd = Get-Command 'wacs.exe' -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    $candidates += 'C:\Tools\win-acme\wacs.exe'
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c }
    }
    return $null
}

function Set-HubSslBinding {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([int]$Port, [string]$Thumbprint)
    $show = & netsh.exe http show sslcert "ipport=0.0.0.0:$Port" 2>&1 | Out-String
    if ($show -match 'IP:port') {
        if ($PSCmdlet.ShouldProcess("0.0.0.0:$Port", 'Remove existing SSL binding')) {
            & netsh.exe (Get-NetshBindingArgument -Port $Port -Delete) | Out-Null
        }
    }
    if ($PSCmdlet.ShouldProcess("0.0.0.0:$Port", "Bind certificate $Thumbprint")) {
        $out = & netsh.exe (Get-NetshBindingArgument -Port $Port -Thumbprint $Thumbprint) 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "netsh failed: $out" }
    }
}

# Allows dot-sourcing for unit tests without executing the deployment.
if ($MyInvocation.InvocationName -eq '.') { return }

if (-not (Test-IsAdministrator)) {
    Write-Error 'cert-setup.ps1 must run from an elevated (Administrator) PowerShell prompt.'
    return
}

$wacs = $null
if (-not $SelfSigned) { $wacs = Find-WinAcme -Hint $WinAcmePath }

$cert = $null
if ($wacs) {
    Write-Host "Using win-acme: $wacs"
    Write-Host 'Validation: self-hosting http-01 on TCP port 80 (must be open to the internet).'
    $started = (Get-Date).AddMinutes(-1)
    if ($PSCmdlet.ShouldProcess($Domain, "Request Let's Encrypt certificate")) {
        $acmeArgs = @('--target', 'manual', '--host', $Domain, '--validation', 'selfhosting',
            '--validationport', '80', '--store', 'certificatestore', '--installation', 'none',
            '--accepttos', '--emailaddress', "admin@$Domain", '--verbose')
        & $wacs @acmeArgs
        if ($LASTEXITCODE -ne 0) { throw "win-acme failed with exit code $LASTEXITCODE" }
        $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Subject -match [regex]::Escape("CN=$Domain") -or ($_.DnsNameList | Where-Object { $_.Unicode -eq $Domain }) } |
            Sort-Object NotBefore -Descending | Select-Object -First 1
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -match [regex]::Escape("CN=$Domain") } |
                Sort-Object NotBefore -Descending | Select-Object -First 1
        }
        if (-not $cert) { throw "Issued certificate for $Domain was not found in the machine store." }
    }
}
else {
    if (-not $SelfSigned) { Write-Warning 'win-acme (wacs.exe) not found; falling back to a self-signed certificate.' }
    if ($PSCmdlet.ShouldProcess($Domain, 'Create self-signed certificate')) {
        $cert = New-SelfSignedCertificate -DnsName @($Domain, 'localhost') -CertStoreLocation 'Cert:\LocalMachine\My' `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5) `
            -KeyExportPolicy NonExportable -FriendlyName 'SCGuardian Hub'
    }
}

if (-not $cert) {
    Write-Host 'WhatIf: no certificate was created; nothing bound.'
    return
}

$thumb = Format-ThumbprintClean -Thumbprint $cert.Thumbprint
Set-HubSslBinding -Port $Port -Thumbprint $thumb

if (Test-Path -LiteralPath $ConfigPath) {
    if ($PSCmdlet.ShouldProcess($ConfigPath, 'Write listen.cert_thumbprint')) {
        Set-ConfigThumbprint -ConfigPath $ConfigPath -Thumbprint $thumb | Out-Null
        Write-Host "Updated listen.cert_thumbprint in $ConfigPath"
    }
}
else {
    Write-Warning "Config not found at $ConfigPath. Set listen.cert_thumbprint to $thumb manually."
}

if ($wacs -and -not $SelfSigned) {
    Write-Host "Let's Encrypt certificate bound. Thumbprint: $thumb"
    Write-Host 'Renewal: win-acme creates its own scheduled task; after renewal re-run this script to rebind.'
    return
}

$der = $cert.RawData
$cerPath = Join-Path (Split-Path -Parent $ConfigPath) 'hub-cert.cer'
if ($PSCmdlet.ShouldProcess($cerPath, 'Export public certificate')) {
    [System.IO.File]::WriteAllBytes($cerPath, $der)
}

Write-Host ''
Write-Host '=== Self-signed Hub certificate ==='
Write-Host "SHA1 thumbprint : $thumb"
Write-Host "Public cert file: $cerPath (private key is NOT exported)"
Write-Host ''
Write-Host 'Base64 (DER):'
Write-Host ([Convert]::ToBase64String($der))
Write-Host ''
Write-Host 'PEM:'
Write-Host (ConvertTo-CertPem -DerBytes $der)
Write-Host ''
Write-Host 'On every agent, set in agent.config.json:'
Write-Host "  `"trusted_server_thumbprint`": `"$thumb`""
