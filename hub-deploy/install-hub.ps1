<#
.SYNOPSIS
    Installs the SCGuardian Hub as a SYSTEM scheduled task (does NOT install the agent or hardening).
.PARAMETER SourceRoot
    Repository root containing src\. Defaults to the parent of this script's folder.
.PARAMETER InstallDir
    Program files destination.
.PARAMETER ConfigPath
    Hub config path (data lives in its folder).
.PARAMETER Port
    Inbound TCP port to open in Windows Firewall.
.PARAMETER Uninstall
    Removes the scheduled task and firewall rule. Data and config are kept.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallDir = 'C:\Program Files\SCGuardian',
    [string]$ConfigPath = 'C:\ProgramData\SCGuardian\hub.config.json',
    [int]$Port = 8443,
    [switch]$Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'SCGuardian-Hub'
$RuleName = 'SCGuardian Hub'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-LockedAcl {
    param([string]$Path)
    & icacls.exe $Path '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

function Set-LockedFileAcl {
    param([string]$Path)
    & icacls.exe $Path '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

if ($MyInvocation.InvocationName -eq '.') { return }

if (-not (Test-IsAdministrator)) {
    Write-Error 'install-hub.ps1 must run from an elevated (Administrator) PowerShell prompt.'
    return
}

if ($Uninstall) {
    if ($PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled task')) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($PSCmdlet.ShouldProcess($RuleName, 'Remove firewall rule')) {
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    }
    Write-Host "Removed task and firewall rule. Data kept in $(Split-Path -Parent $ConfigPath); files kept in $InstallDir."
    return
}

$srcDir = Join-Path $SourceRoot 'src'
foreach ($p in @('modules', 'lib', 'SCGuardian.ps1', 'config\hub.config.template.json')) {
    if (-not (Test-Path -LiteralPath (Join-Path $srcDir $p))) { throw "Missing source item: $(Join-Path $srcDir $p)" }
}

if ($PSCmdlet.ShouldProcess($InstallDir, 'Copy program files')) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    foreach ($d in @('modules', 'lib')) {
        $dest = Join-Path $InstallDir $d
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        Copy-Item -LiteralPath (Join-Path $srcDir $d) -Destination $dest -Recurse -Force
    }
    Copy-Item -LiteralPath (Join-Path $srcDir 'SCGuardian.ps1') -Destination (Join-Path $InstallDir 'SCGuardian.ps1') -Force
}

$dataDir = Split-Path -Parent $ConfigPath
if ($PSCmdlet.ShouldProcess($dataDir, 'Create locked data directory')) {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    Set-LockedAcl -Path $dataDir
}

$configCreated = $false
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    if ($PSCmdlet.ShouldProcess($ConfigPath, 'Create config from template')) {
        Copy-Item -LiteralPath (Join-Path $srcDir 'config\hub.config.template.json') -Destination $ConfigPath
        $configCreated = $true
    }
}
if (Test-Path -LiteralPath $ConfigPath) {
    if ($PSCmdlet.ShouldProcess($ConfigPath, 'Lock config ACL')) { Set-LockedFileAcl -Path $ConfigPath }
}

$needsEdit = $true
if (Test-Path -LiteralPath $ConfigPath) {
    $needsEdit = [bool](Select-String -LiteralPath $ConfigPath -Pattern 'REPLACE_ME' -SimpleMatch -Quiet)
}

if ($PSCmdlet.ShouldProcess($RuleName, "Open inbound TCP $Port")) {
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
}

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'SCGuardian.ps1')`" -Mode Hub -HubConfigPath `"$ConfigPath`""
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

    if ($needsEdit) {
        Write-Warning "Config still contains REPLACE_ME. The Hub task is registered but NOT started: edit $ConfigPath first."
    }
    else {
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "Task $TaskName started."
    }
}

Write-Host ''
Write-Host 'Next steps:'
Write-Host "  1. Edit $ConfigPath (shared_secret, telegram.*, defaults.allowed_ids)."
Write-Host "  2. Run hub-deploy\cert-setup.ps1 to obtain/bind the TLS certificate."
Write-Host "  3. Start-ScheduledTask -TaskName $TaskName   (if not started above)"
Write-Host "  4. Verify: GET https://<domain>:$Port/api/v1/health (see hub-deploy\README.md)."
Write-Host 'Note: the Hub does NOT install the agent or hardening on itself.'
