#Requires -Modules Pester
<#
    Chaos.Tests.ps1 - hub outage and recovery against the REAL Agent cycle and REAL Hub (in-process, http loopback).
    Discovery/hardening are stubbed by Install-ScgAgentShim (no sc.exe, icacls or service change ever runs).
    The agent clock is injected with -Now; Telegram is blackholed by Enable-ScgTestNetworkGuard.
    Author: Badr - Version 4.0.0
#>

Describe 'Chaos: hub outage and recovery' {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot 'ScgTestHelpers.psm1') -Force -DisableNameChecking
        Install-ScgAgentShim
        Import-ScgTestProductModule

        $script:SavedRoot = $env:SCG_ROOT
        $script:Root = New-ScgTestRoot -Prefix 'scg-chaos'
        $script:HubRoot = Join-Path $script:Root 'hub'
        $script:AgentRoot = Join-Path $script:Root 'agent'
        [void](New-Item -ItemType Directory -Path $script:HubRoot -Force)
        $script:Secret = New-ScgTestSecret
        $url = 'http://localhost:{0}/' -f (Get-ScgTestFreePort)
        $script:HubCfg = New-ScgTestHubConfig -HubRoot $script:HubRoot -Url $url -Secret $script:Secret -HeartbeatSec 60 -ScanSec 30
        $script:AgentCfg = New-ScgTestAgentConfig -AgentRoot $script:AgentRoot -HubUrl $url -Secret $script:Secret -Hostname 'scg-chaos-host' -HeartbeatSec 60 -ScanSec 30
        $script:StatePath = Join-Path $script:AgentRoot 'agent.state.json'
        $script:AgentLog = Join-Path $script:AgentRoot 'logs\agent.log'
        $script:Base = [datetime]::UtcNow
        $script:StepMin = 2
        $script:DownCycles = 11
        $script:LastNow = $script:Base

        function Get-ChaosState { return (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json) }
        function Get-ChaosLogCount {
            param([string]$Pattern)
            if (-not (Test-Path -LiteralPath $script:AgentLog)) { return 0 }
            return @([System.IO.File]::ReadAllLines($script:AgentLog) | Where-Object { $_ -like ('*' + $Pattern + '*') }).Count
        }
        function Get-ChaosWatchdogCount {
            return @(Read-ScgTestShimLog -Root $script:AgentRoot | Where-Object { $_.phase -eq 'watchdog' }).Count
        }
        function Invoke-ChaosCycle {
            param([datetime]$Now)
            return (Invoke-ScgTestAgentCycle -Root $script:AgentRoot -ConfigPath $script:AgentCfg -Now $Now -Force)
        }

        Enable-ScgTestNetworkGuard
        $script:Hub = Start-ScgTestHub -ConfigPath $script:HubCfg
    }

    AfterAll {
        Stop-ScgTestHub -Hub $script:Hub
        Disable-ScgTestNetworkGuard
        foreach ($m in @('Agent', 'Hub')) {
            $mod = @(Get-Module -Name $m) | Select-Object -Last 1
            if ($mod) {
                & $mod {
                    foreach ($n in @('Get-ScAgent', 'Invoke-ScHardening', 'Invoke-ScRestore', 'Remove-ScAgent', 'Test-ScTamper', 'Initialize-ScgSecureDirectory')) {
                        if (Test-Path -LiteralPath ('Alias:\' + $n)) { Remove-Item -LiteralPath ('Alias:\' + $n) -Force -ErrorAction SilentlyContinue }
                    }
                }
            }
        }
        [Environment]::SetEnvironmentVariable('SCG_HUB_CONFIG', $null)
        $env:SCG_ROOT = $script:SavedRoot
        if ($script:Root) { [void](Remove-ScgTestPath -Path $script:Root) }
    }

    It 'enrolls and heartbeats while the hub is up' {
        $s = Invoke-ChaosCycle -Now $script:Base
        $s.HubOk | Should -BeTrue
        $s.Enrolled | Should -BeTrue
        [int](Get-ChaosState).consecutive_failures | Should -Be 0
        (Get-ChaosWatchdogCount) | Should -BeGreaterOrEqual 1
    }

    It 'keeps running the local watchdog and counts failures while the hub is down' {
        Stop-ScgTestHub -Hub $script:Hub
        $script:Hub = $null
        $wdBefore = Get-ChaosWatchdogCount
        $failures = New-Object System.Collections.ArrayList
        $hubOk = New-Object System.Collections.ArrayList
        for ($i = 1; $i -le $script:DownCycles; $i++) {
            $now = $script:Base.AddMinutes($i * $script:StepMin)
            $s = Invoke-ChaosCycle -Now $now
            [void]$hubOk.Add([bool]$s.HubOk)
            [void]$failures.Add([int](Get-ChaosState).consecutive_failures)
            $script:LastNow = $now
        }
        @($hubOk | Where-Object { $_ }).Count | Should -Be 0
        ($failures -join ',') | Should -Be ((1..$script:DownCycles) -join ',')
        ((Get-ChaosWatchdogCount) - $wdBefore) | Should -Be $script:DownCycles
    }

    It 'pushes the next heartbeat to max(heartbeat,300) seconds after three failures' {
        $state = Get-ChaosState
        $next = ConvertFrom-ScgUtcIso -Value ([string]$state.next_heartbeat_utc)
        [math]::Round(($next - $script:LastNow.ToUniversalTime()).TotalSeconds) | Should -Be 300
        $cfgLike = [pscustomobject]@{ scan_interval_sec = 3600 }
        Get-ScgNextDelaySec -Config $cfgLike -State $state -Now $script:LastNow | Should -Be 300

        $slow = [pscustomobject]@{
            consecutive_failures = 2; next_heartbeat_utc = $null
            last_failure_log_utc = (ConvertTo-ScgUtcIso -InputObject $script:LastNow); alerts = [pscustomobject]@{}
        }
        $r = Update-ScgBackoffState -State $slow -Now $script:LastNow -HeartbeatSec 600 -Reason 'chaos'
        $n2 = ConvertFrom-ScgUtcIso -Value ([string]$r.next_heartbeat_utc)
        [math]::Round(($n2 - $script:LastNow.ToUniversalTime()).TotalSeconds) | Should -Be 600
    }

    It 'logs hub failures at most once per 10 minutes' {
        $spanMin = ($script:DownCycles - 1) * $script:StepMin
        $expected = [int][math]::Floor($spanMin / 10) + 1
        Get-ChaosLogCount -Pattern 'Hub exchange failed' | Should -Be $expected
    }

    It 'recovers after a hub restart, resets the state and logs recovery once' {
        $script:Hub = Start-ScgTestHub -ConfigPath $script:HubCfg
        $s1 = Invoke-ChaosCycle -Now $script:LastNow.AddMinutes(1)
        $s1.HubOk | Should -BeTrue
        $st = Get-ChaosState
        [int]$st.consecutive_failures | Should -Be 0
        $st.last_failure_log_utc | Should -BeNullOrEmpty
        $s2 = Invoke-ChaosCycle -Now $script:LastNow.AddMinutes(2)
        $s2.HubOk | Should -BeTrue
        Get-ChaosLogCount -Pattern 'Hub reachable again' | Should -Be 1
    }
}
