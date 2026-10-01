#Requires -RunAsAdministrator
# Interactive wrapper: prompts for Hub URL / secret, installs the MSI silently,
# then forces one heartbeat. Exit codes: 0 ok | 1 bad input | MSI exit code | 3 heartbeat failed
param(
    [string]$HubUrl,
    [securestring]$SharedSecret,
    [string]$Thumbprint,
    [string]$MsiPath = (Join-Path $PSScriptRoot 'SCGuardian.Agent.msi')
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $MsiPath)) { Write-Host "MSI not found: $MsiPath" -ForegroundColor Red; exit 1 }
if (-not $HubUrl)       { $HubUrl = Read-Host 'Hub URL (https://host:port)' }
if (-not $SharedSecret) { $SharedSecret = Read-Host 'Shared secret' -AsSecureString }

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SharedSecret)
try { $secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

$u = $null
$okUrl = [Uri]::TryCreate($HubUrl, [UriKind]::Absolute, [ref]$u) -and
         ($u.Scheme -eq 'https' -or ($u.Scheme -eq 'http' -and $u.IsLoopback))
if (-not $okUrl) { Write-Host 'Hub URL must be https:// (or http on loopback).' -ForegroundColor Red; exit 1 }
if ([string]::IsNullOrWhiteSpace($secret) -or $secret -eq 'REPLACE_ME') { Write-Host 'Shared secret is empty or REPLACE_ME.' -ForegroundColor Red; exit 1 }
if ($secret -match '["\s]' -or $HubUrl -match '["\s]') { Write-Host 'Quotes and spaces are not allowed in the URL or secret.' -ForegroundColor Red; exit 1 }

$log = Join-Path $env:TEMP 'SCGuardian.Agent.install.log'
$args = @('/i', "`"$MsiPath`"", '/qn', '/l*v', "`"$log`"", "HUBURL=`"$HubUrl`"", "SHAREDSECRET=`"$secret`"")
if ($Thumbprint) { $args += "THUMBPRINT=`"$Thumbprint`"" }
$p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
$secret = $null
if ($p.ExitCode -notin 0, 3010) { Write-Host "msiexec failed with exit code $($p.ExitCode). Log: $log" -ForegroundColor Red; exit $p.ExitCode }

$main = Join-Path $env:ProgramFiles 'SCGuardian\SCGuardian.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $main -Mode Agent
if ($LASTEXITCODE -ne 0) { Write-Host "Installed, but the first heartbeat failed (exit $LASTEXITCODE)." -ForegroundColor Yellow; exit 3 }
Write-Host 'SCGuardian Agent installed and first heartbeat sent.' -ForegroundColor Green
exit 0
