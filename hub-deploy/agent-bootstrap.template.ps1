<#
.SYNOPSIS
    SCGuardian agent bootstrap for one Hub: downloads, verifies, installs and enrolls the agent on this device.
.DESCRIPTION
    Rendered by hub-deploy\Setup-Hub.ps1. The rendered file CONTAINS THE HUB SHARED SECRET: copy it to each
    device over a private channel only, run it once as Administrator, then delete it.
    Steps: admin check, TLS 1.2, download SCGuardian.Agent.Setup.exe from the GitHub release, verify its
    SHA-256, run it silently, confirm the SCGuardian-Agent task, then wait up to 60 seconds for enrollment.
    The secret and the device token are never printed. Exit codes: 0 enrolled, 1 failure, 2 installed but
    not yet enrolled.
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\agent-bootstrap.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$HubUrl = '{{HUB_URL}}'
$SharedSecret = '{{SHARED_SECRET}}'
$Thumbprint = '{{THUMBPRINT}}'
$Version = '{{VERSION}}'
$ExpectedSha256 = '{{SETUP_SHA256}}'

$TaskName = 'SCGuardian-Agent'
$AgentConfigPath = 'C:\ProgramData\SCGuardian\agent.config.json'
$WorkDir = Join-Path $env:TEMP 'scg-agent'
$SetupPath = Join-Path $WorkDir 'Setup.exe'
$DownloadUrl = 'https://github.com/cBadr/SCGuardian/releases/download/v' + $Version + '/SCGuardian.Agent.Setup.exe'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step {
    param([string]$Number, [string]$Text)
    Write-Host ('[' + $Number + '/5] ' + $Text) -ForegroundColor Cyan
}

function Test-AgentEnrolled {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try { $cfg = [IO.File]::ReadAllText($Path) | ConvertFrom-Json } catch { return $false }
    if ($null -eq $cfg) { return $false }
    $p = $cfg.PSObject.Properties['device_token']
    return ($null -ne $p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value))
}

function Test-HubReachable {
    param([string]$HostName, [int]$Port)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($HostName, $Port, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(5000) -and $client.Connected) { return $true }
        return $false
    }
    catch { return $false }
    finally { $client.Close() }
}

if ($MyInvocation.InvocationName -eq '.') { return }

if ($HubUrl -notmatch '^https://') {
    Write-Host 'This is the unrendered template. Run hub-deploy\Setup-Hub.ps1 on the Hub to generate agent-bootstrap.ps1.' -ForegroundColor Red
    exit 1
}
if (-not (Test-IsAdministrator)) {
    Write-Host 'Run this script from an elevated (Administrator) PowerShell prompt.' -ForegroundColor Red
    exit 1
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host ('SCGuardian agent bootstrap v' + $Version + ' for ' + $HubUrl)
try {
    Write-Step 1 'Downloading SCGuardian.Agent.Setup.exe'
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    if (Test-Path -LiteralPath $SetupPath) { Remove-Item -LiteralPath $SetupPath -Force }
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $SetupPath -UseBasicParsing

    Write-Step 2 'Verifying SHA-256'
    $actual = (Get-FileHash -LiteralPath $SetupPath -Algorithm SHA256).Hash
    if (-not [string]::Equals($actual, $ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $SetupPath -Force -ErrorAction SilentlyContinue
        throw ('SHA-256 mismatch: expected ' + $ExpectedSha256 + ', got ' + $actual.ToLowerInvariant() + '. The download was deleted; nothing was installed.')
    }
    Write-Host '      SHA-256 OK'

    Write-Step 3 'Installing the agent (silent)'
    $installArgs = @('/quiet', ('HubUrl=' + $HubUrl), ('SharedSecret=' + $SharedSecret), ('Thumbprint=' + $Thumbprint))
    $proc = Start-Process -FilePath $SetupPath -ArgumentList $installArgs -Wait -PassThru
    $code = $proc.ExitCode
    Write-Host ('      Installer exit code: ' + $code)
    if ($code -ne 0 -and $code -ne 3010) { throw ('Installer failed with exit code ' + $code + '. See the setup logs in ' + $env:TEMP + '.') }
    if ($code -eq 3010) { Write-Warning 'Installed; Windows asks for a reboot to complete.' }
}
catch {
    Write-Host ('FAILED: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
finally {
    Remove-Item -LiteralPath $SetupPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Step 4 ('Checking scheduled task ' + $TaskName)
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host ('FAILED: scheduled task ' + $TaskName + ' was not created.') -ForegroundColor Red
    exit 1
}
$state = [string]$task.State
if ($state -eq 'Ready' -or $state -eq 'Running') { Write-Host ('      Task state: ' + $state) }
else { Write-Warning ('Task ' + $TaskName + ' is in state ' + $state + ' (expected Ready or Running).') }

Write-Step 5 'Waiting up to 60 seconds for enrollment'
$deadline = (Get-Date).AddSeconds(60)
$enrolled = $false
while ((Get-Date) -lt $deadline) {
    if (Test-AgentEnrolled -Path $AgentConfigPath) { $enrolled = $true; break }
    Start-Sleep -Seconds 3
}

if ($enrolled) {
    Write-Host ('Enrolled: ' + $env:COMPUTERNAME + ' is registered with the Hub.') -ForegroundColor Green
    Write-Host 'Delete this bootstrap file now: it contains the Hub shared secret.'
    exit 0
}

$uri = [Uri]$HubUrl
if (-not (Test-HubReachable -HostName $uri.Host -Port $uri.Port)) {
    Write-Warning ('Not enrolled: the Hub is unreachable at ' + $uri.Host + ':' + $uri.Port + '. Check the DNS A record, the router/cloud rule for TCP ' + $uri.Port + ', the Windows Firewall rule on the Hub and that the SCGuardian-Hub task is running. The agent keeps retrying on its own.')
}
else {
    Write-Warning ('Not enrolled within 60 seconds although the Hub is reachable. If the hostname ' + $env:COMPUTERNAME + ' was enrolled before (reinstall or rebuilt machine), ask the Hub admin to send /reset ' + $env:COMPUTERNAME + ' to the Telegram bot; the agent re-enrolls on its next cycle. If the Hub certificate changed, regenerate this file with Setup-Hub.ps1. Logs: C:\ProgramData\SCGuardian.')
}
Write-Host 'Delete this bootstrap file when done: it contains the Hub shared secret.'
exit 2
