<#
.SYNOPSIS
    CI entry point: runs the Pester 5 suites and writes JUnit XML.
.DESCRIPTION
    Equivalent of `Invoke-Pester -CI` expressed as a configuration (the -CI switch cannot be combined with an
    output path/format), but with JUnit XML instead of NUnit and without Run.Exit, so the exit code is computed here:
        exit code = failed tests + failed blocks/containers (+1 when -IncludeFleet fails); 0 = green.
    Never touches C:\ProgramData\SCGuardian; integration tests use temp roots only.
    Author: Badr - Version 4.0.0
.PARAMETER SkipChaos
    Run only tests\Pester (skip tests\integration\Chaos.Tests.ps1, which takes about a minute).
.PARAMETER IncludeFleet
    Also run tests\integration\Run-LocalFleet.ps1 (spawns agent processes; https when elevated).
.PARAMETER ResultPath
    JUnit XML output path (default tests\results.xml).
.PARAMETER Output
    Pester console verbosity: None, Normal, Detailed, Diagnostic (default Normal).
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-CI.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\Run-CI.ps1 -SkipChaos -Output Detailed
#>
[CmdletBinding()]
param(
    [switch]$SkipChaos,
    [switch]$IncludeFleet,
    [string]$ResultPath = (Join-Path $PSScriptRoot 'results.xml'),
    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')][string]$Output = 'Normal'
)
$ErrorActionPreference = 'Stop'

$pester = Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version.Major -ge 5 } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) { Write-Error 'Pester 5 is required: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser'; exit 1 }
Import-Module $pester.Path -Force

$paths = @(Join-Path $PSScriptRoot 'Pester')
if (-not $SkipChaos) { $paths += (Join-Path $PSScriptRoot 'integration\Chaos.Tests.ps1') }

$cfg = New-PesterConfiguration
$cfg.Run.Path = [string[]]$paths
$cfg.Run.PassThru = $true
$cfg.Run.Exit = $false
$cfg.Output.Verbosity = $Output
$cfg.TestResult.Enabled = $true
$cfg.TestResult.OutputFormat = 'JUnitXml'
$cfg.TestResult.OutputPath = $ResultPath

$result = Invoke-Pester -Configuration $cfg
$failed = [int]$result.FailedCount + [int]$result.FailedBlocksCount + [int]$result.FailedContainersCount
Write-Output ("Pester: passed={0} failed={1} skipped={2} failedBlocks={3} failedContainers={4} -> {5}" -f `
        $result.PassedCount, $result.FailedCount, $result.SkippedCount, $result.FailedBlocksCount, $result.FailedContainersCount, $ResultPath)

if ($IncludeFleet) {
    $fleet = Join-Path $PSScriptRoot 'integration\Run-LocalFleet.ps1'
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $fleet
    if ($LASTEXITCODE -ne 0) { $failed++ ; Write-Output 'Fleet: FAILED' } else { Write-Output 'Fleet: passed' }
}

exit $failed
