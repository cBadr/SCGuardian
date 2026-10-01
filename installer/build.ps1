param(
    [string]$Version = '4.0.0',
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [string]$OutputDir = '.\artifacts',
    [switch]$Bundle
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Installer.Functions.ps1')

$repo   = Split-Path $PSScriptRoot -Parent
$src    = Join-Path $repo 'src'
$null   = New-Item -ItemType Directory -Path $OutputDir -Force
$outAbs = (Resolve-Path $OutputDir).Path
$stage  = Join-Path $outAbs 'stage'

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    Write-Host 'WiX v4 CLI not found. Install it with:' -ForegroundColor Red
    Write-Host '  dotnet tool install --global wix' -ForegroundColor Yellow
    Write-Host '  wix extension add --global WixToolset.Util.wixext' -ForegroundColor Yellow
    Write-Host '  wix extension add --global WixToolset.BootstrapperApplications.wixext   (only for -Bundle)' -ForegroundColor Yellow
    exit 2
}

Write-Host "[1/3] Staging -> $stage"
$files = Copy-AgentStage -SrcRoot $src -StageDir $stage -InstallAgentScript (Join-Path $PSScriptRoot 'Install-Agent.ps1')
$files | ForEach-Object { Write-Host "   $_" }

Write-Host '[2/3] Generating SCGuardian.Agent.wxs'
$wxs = Join-Path $outAbs 'SCGuardian.Agent.wxs'
$null = New-AgentWxs -TemplatePath (Join-Path $PSScriptRoot 'SCGuardian.Agent.wxs.template') -StageDir $stage -Version $Version -OutputPath $wxs

Write-Host '[3/3] wix build'
$msi = Join-Path $outAbs 'SCGuardian.Agent.msi'
& wix build -arch x64 -ext WixToolset.Util.wixext -o $msi $wxs
if ($LASTEXITCODE -ne 0) { Write-Host 'wix build failed (is WixToolset.Util.wixext installed?)' -ForegroundColor Red; exit $LASTEXITCODE }

Copy-Item (Join-Path $PSScriptRoot 'Setup.ps1') $outAbs -Force

if ($Bundle) {
    $bwxs = Join-Path $outAbs 'Bootstrapper.wxs'
    $null = New-BootstrapperWxs -TemplatePath (Join-Path $PSScriptRoot 'Bootstrapper.wxs.template') -Version $Version -MsiPath $msi -OutputPath $bwxs
    & wix build -ext WixToolset.BootstrapperApplications.wixext -o (Join-Path $outAbs 'SCGuardian.Agent.Setup.exe') $bwxs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
Write-Host "Done: $msi (Configuration=$Configuration, Version=$Version)" -ForegroundColor Green
exit 0
