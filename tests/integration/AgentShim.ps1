<#
.SYNOPSIS
    TEST-ONLY agent worker: runs the REAL Agent module cycle in a loop with discovery and hardening stubbed.
.DESCRIPTION
    Imports Agent.psm1 and overrides Get-ScAgent (fixed fake inventory: one allow-listed agent plus one unknown),
    Invoke-ScHardening / Invoke-ScRestore / Remove-ScAgent / Test-ScTamper (each call appended to
    <Root>\shim-calls.jsonl) and directory locking, so no sc.exe, icacls or service change ever runs.
    Each iteration calls Invoke-ScgAgentCycle -Force (the product enforces heartbeat_sec >= 5, so the 1-2 s
    cadence is driven here). Exits when <Root>\stop.flag appears or after MaxSeconds.
    Author: Badr - Version 4.0.0
.PARAMETER Root
    Per-agent SCG_ROOT (temp folder).
.PARAMETER ConfigPath
    agent.config.json of this worker.
.PARAMETER LoopSec
    Seconds between cycles (default 1.5).
.PARAMETER MaxSeconds
    Safety stop.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$ConfigPath,
    [double]$LoopSec = 1.5,
    [int]$MaxSeconds = 900
)
$ErrorActionPreference = 'Stop'
$env:SCG_ROOT = $Root
Import-Module (Join-Path $PSScriptRoot 'ScgTestHelpers.psm1') -Force -DisableNameChecking
Install-ScgAgentShim

$stopFlag = Join-Path $Root 'stop.flag'
$errFile = Join-Path $Root 'shim-errors.txt'
$deadline = [datetime]::UtcNow.AddSeconds($MaxSeconds)
while (-not (Test-Path -LiteralPath $stopFlag) -and [datetime]::UtcNow -lt $deadline) {
    try { $null = Invoke-ScgTestAgentCycle -Root $Root -ConfigPath $ConfigPath -Force }
    catch {
        $msg = [datetime]::UtcNow.ToString('o') + ' ' + $_.Exception.Message + [Environment]::NewLine
        [System.IO.File]::AppendAllText($errFile, $msg, (New-Object System.Text.UTF8Encoding($false)))
    }
    Start-Sleep -Milliseconds ([int]($LoopSec * 1000))
}
