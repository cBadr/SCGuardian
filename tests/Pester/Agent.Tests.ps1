#Requires -Modules Pester
# Agent.Tests.ps1 - mocked tests for Agent.psm1 (never touches real services, ACLs or the live hub).

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\src\modules\Agent.psm1'
    Import-Module $script:ModulePath -Force
    Import-Module (Join-Path $PSScriptRoot '..\..\src\modules\Common.psm1') -Force
    $script:OldRoot = $env:SCG_ROOT
    $env:SCG_ROOT = $TestDrive
    $script:Cfg = Join-Path $TestDrive 'agent.config.json'
    $script:StatePath = Join-Path $TestDrive 'agent.state.json'
    $script:IdMine = 'aaaaaaaaaaaaaaaa'
    $script:IdOther = 'bbbbbbbbbbbbbbbb'

    function Write-TestConfig {
        param([hashtable]$Override = @{})
        $base = [ordered]@{
            hub_url                   = 'https://hub.example.test:8443'
            shared_secret             = 'test-secret-value'
            device_id                 = $null
            hostname                  = 'AUTO'
            heartbeat_sec             = 60
            scan_interval_sec         = 30
            allowed_ids               = @('AAAAAAAAAAAAAAAA')
            layers                    = @('Recovery', 'ServiceSd')
            take_ownership            = $false
            local_watchdog            = $false
            trusted_server_thumbprint = ''
        }
        foreach ($k in $Override.Keys) { $base[$k] = $Override[$k] }
        $json = ConvertTo-Json -InputObject $base -Depth 5
        [System.IO.File]::WriteAllText($script:Cfg, $json, (New-Object System.Text.UTF8Encoding($false)))
    }

    function New-TestState {
        return [pscustomobject]@{ consecutive_failures = 0; next_heartbeat_utc = $null; last_failure_log_utc = $null; alerts = [pscustomobject]@{} }
    }

    function Start-TestListener {
        param([int]$Status = 200, [string]$ResponseText = '{"ok":true}')
        $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $tcp.Start()
        $port = ([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port
        $tcp.Stop()
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add("http://127.0.0.1:$port/")
        $l.Start()
        $ps = [powershell]::Create()
        $null = $ps.AddScript({
                param($listener, $status, $text)
                $ctx = $listener.GetContext()
                $req = $ctx.Request
                $sr = New-Object System.IO.StreamReader($req.InputStream, [System.Text.Encoding]::UTF8)
                $body = $sr.ReadToEnd()
                $captured = @{
                    Path = $req.Url.AbsolutePath; Method = $req.HttpMethod; Body = $body; ContentType = $req.ContentType
                    Auth = $req.Headers['Authorization']; Ts = $req.Headers['X-SCG-Timestamp']; Nonce = $req.Headers['X-SCG-Nonce']
                }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
                $ctx.Response.StatusCode = $status
                $ctx.Response.ContentType = 'application/json'
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $ctx.Response.Close()
                return $captured
            }).AddArgument($l).AddArgument($Status).AddArgument($ResponseText)
        $handle = $ps.BeginInvoke()
        return [pscustomobject]@{ Port = $port; Listener = $l; PS = $ps; Handle = $handle }
    }

    function Stop-TestListener {
        param($Server)
        $out = $null
        try {
            $res = $Server.PS.EndInvoke($Server.Handle)
            $out = $res[0]
        }
        finally {
            $Server.Listener.Close()
            $Server.PS.Dispose()
        }
        return $out
    }
}

AfterAll {
    $env:SCG_ROOT = $script:OldRoot
    Remove-Variable -Name ScgTestOrder -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Get-ScgAgentConfig' {
    It 'fills defaults, resolves hostname AUTO and lowercases allowed ids' {
        Write-TestConfig
        $c = Get-ScgAgentConfig -Path $script:Cfg
        $c.hostname | Should -Be $env:COMPUTERNAME
        $c.allowed_ids | Should -Be @('aaaaaaaaaaaaaaaa')
        $c.heartbeat_sec | Should -Be 60
        $c.local_watchdog | Should -BeFalse
    }
    It 'rejects the REPLACE_ME secret' {
        Write-TestConfig -Override @{ shared_secret = 'REPLACE_ME' }
        { Get-ScgAgentConfig -Path $script:Cfg } | Should -Throw
    }
    It 'rejects an invalid allowed id' {
        Write-TestConfig -Override @{ allowed_ids = @('not-an-id') }
        { Get-ScgAgentConfig -Path $script:Cfg } | Should -Throw
    }
    It 'rejects plain http to a non-loopback hub' {
        Write-TestConfig -Override @{ hub_url = 'http://hub.example.test' }
        { Get-ScgAgentConfig -Path $script:Cfg } | Should -Throw
    }
}

Describe 'Update-ScgAgentConfig' {
    It 'adopts whitelisted keys only and never overwrites secret, url or thumbprint' {
        Write-TestConfig
        $server = [pscustomobject]@{
            heartbeat_sec             = 120
            scan_interval_sec         = 45
            alert_throttle_min        = 15
            allowed_ids               = @('CCCCCCCCCCCCCCCC', 'aaaaaaaaaaaaaaaa')
            shared_secret             = 'evil-secret'
            hub_url                   = 'https://evil.example.test'
            trusted_server_thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        }
        (Update-ScgAgentConfig -Path $script:Cfg -ServerConfig $server) | Should -BeTrue
        $f = Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json
        $f.shared_secret | Should -Be 'test-secret-value'
        $f.hub_url | Should -Be 'https://hub.example.test:8443'
        $f.trusted_server_thumbprint | Should -Be ''
        $f.heartbeat_sec | Should -Be 120
        $f.scan_interval_sec | Should -Be 45
        $f.alert_throttle_min | Should -Be 15
        @($f.allowed_ids) | Should -Be @('aaaaaaaaaaaaaaaa', 'cccccccccccccccc')
    }
    It 'returns false when nothing changed' {
        Write-TestConfig
        $server = [pscustomobject]@{ heartbeat_sec = 60; scan_interval_sec = 30; allowed_ids = @('aaaaaaaaaaaaaaaa') }
        (Update-ScgAgentConfig -Path $script:Cfg -ServerConfig $server) | Should -BeFalse
    }
    It 'ignores an empty pushed allowed_ids list and keeps the local list' {
        Write-TestConfig
        Mock Write-ScgLog {} -ModuleName Agent
        $server = [pscustomobject]@{ allowed_ids = @() }
        (Update-ScgAgentConfig -Path $script:Cfg -ServerConfig $server) | Should -BeFalse
        $f = Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json
        @($f.allowed_ids) | Should -Be @('AAAAAAAAAAAAAAAA')
        Should -Invoke Write-ScgLog -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Level -eq 'WARN' -and $Result -eq 'rejected' }
    }
    It 'ignores a pushed allowed_ids list with no valid id' {
        Write-TestConfig
        Mock Write-ScgLog {} -ModuleName Agent
        $server = [pscustomobject]@{ allowed_ids = @('junk', 'not-an-id') }
        (Update-ScgAgentConfig -Path $script:Cfg -ServerConfig $server) | Should -BeFalse
        $f = Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json
        @($f.allowed_ids) | Should -Be @('AAAAAAAAAAAAAAAA')
    }
    It 'drops invalid entries but adopts the valid ones' {
        Write-TestConfig
        $server = [pscustomobject]@{ allowed_ids = @('junk', 'CCCCCCCCCCCCCCCC') }
        (Update-ScgAgentConfig -Path $script:Cfg -ServerConfig $server) | Should -BeTrue
        $f = Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json
        @($f.allowed_ids) | Should -Be @('cccccccccccccccc')
    }
    It 'ignores out-of-range numbers' {
        Write-TestConfig
        (Update-ScgAgentConfig -Path $script:Cfg -ServerConfig ([pscustomobject]@{ heartbeat_sec = 1 })) | Should -BeFalse
    }
}

Describe 'Update-ScgBackoffState' {
    BeforeEach { Mock Write-ScgLog {} -ModuleName Agent }

    It 'pushes the next heartbeat to 300 seconds from the third failure' {
        $t0 = [datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', [System.DateTimeKind]::Utc)
        $s = New-TestState
        $s = Update-ScgBackoffState -State $s -Now $t0 -HeartbeatSec 60
        $s = Update-ScgBackoffState -State $s -Now $t0.AddSeconds(60) -HeartbeatSec 60
        $s = Update-ScgBackoffState -State $s -Now $t0.AddSeconds(120) -HeartbeatSec 60
        $s.consecutive_failures | Should -Be 3
        $next = ConvertFrom-ScgUtcIso -Value $s.next_heartbeat_utc
        ($next - $t0.AddSeconds(120)).TotalSeconds | Should -Be 300
    }
    It 'never backs off below a configured heartbeat longer than 300 seconds' {
        $t0 = [datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', [System.DateTimeKind]::Utc)
        $s = New-TestState
        $s = Update-ScgBackoffState -State $s -Now $t0 -HeartbeatSec 600
        $s = Update-ScgBackoffState -State $s -Now $t0.AddSeconds(600) -HeartbeatSec 600
        $s = Update-ScgBackoffState -State $s -Now $t0.AddSeconds(1200) -HeartbeatSec 600
        $s.consecutive_failures | Should -Be 3
        $next = ConvertFrom-ScgUtcIso -Value $s.next_heartbeat_utc
        ($next - $t0.AddSeconds(1200)).TotalSeconds | Should -Be 600
    }
    It 'logs a failure at most once per 10 minutes' {
        $t0 = [datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', [System.DateTimeKind]::Utc)
        $s = New-TestState
        $s = Update-ScgBackoffState -State $s -Now $t0
        $s = Update-ScgBackoffState -State $s -Now $t0.AddMinutes(3)
        $s = Update-ScgBackoffState -State $s -Now $t0.AddMinutes(9)
        Should -Invoke Write-ScgLog -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Level -eq 'WARN' }
        $s = Update-ScgBackoffState -State $s -Now $t0.AddMinutes(11)
        Should -Invoke Write-ScgLog -ModuleName Agent -Times 2 -Exactly -ParameterFilter { $Level -eq 'WARN' }
    }
    It 'resets on success and logs recovery once' {
        $t0 = [datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', [System.DateTimeKind]::Utc)
        $s = New-TestState
        $s = Update-ScgBackoffState -State $s -Now $t0
        $s = Update-ScgBackoffState -State $s -Now $t0.AddSeconds(30) -Success -HeartbeatSec 60
        $s = Update-ScgBackoffState -State $s -Now $t0.AddSeconds(90) -Success -HeartbeatSec 60
        $s.consecutive_failures | Should -Be 0
        $s.last_failure_log_utc | Should -BeNullOrEmpty
        Should -Invoke Write-ScgLog -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Result -eq 'recovered' }
        ((ConvertFrom-ScgUtcIso -Value $s.next_heartbeat_utc) - $t0.AddSeconds(90)).TotalSeconds | Should -Be 60
    }
}

Describe 'Get-ScgNextDelaySec' {
    It 'returns the sooner of scan interval and next heartbeat, never below 1' {
        $t0 = [datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', [System.DateTimeKind]::Utc)
        $cfg = [pscustomobject]@{ scan_interval_sec = 30 }
        $far = [pscustomobject]@{ next_heartbeat_utc = (ConvertTo-ScgUtcIso -InputObject $t0.AddSeconds(300)) }
        $near = [pscustomobject]@{ next_heartbeat_utc = (ConvertTo-ScgUtcIso -InputObject $t0.AddSeconds(10)) }
        $past = [pscustomobject]@{ next_heartbeat_utc = (ConvertTo-ScgUtcIso -InputObject $t0.AddSeconds(-5)) }
        (Get-ScgNextDelaySec -Config $cfg -State $far -Now $t0) | Should -Be 30
        (Get-ScgNextDelaySec -Config $cfg -State $near -Now $t0) | Should -Be 10
        (Get-ScgNextDelaySec -Config $cfg -State $past -Now $t0) | Should -Be 1
    }
}

Describe 'Invoke-ScgLocalWatchdog' {
    BeforeEach {
        Mock Write-ScgLog {} -ModuleName Agent
        Mock Get-ScAgent { @([pscustomobject]@{ Id = 'aaaaaaaaaaaaaaaa'; ServiceName = 'ScreenConnect Client (aaaaaaaaaaaaaaaa)'; ServiceState = 'Stopped'; StartMode = 'Manual'; Folder = $null; UninstallKey = $null; Authorized = $true }) } -ModuleName Agent
        Mock Get-Service { [pscustomobject]@{ Status = 'Stopped'; StartType = 'Manual' } } -ModuleName Agent
        Mock Start-Service {} -ModuleName Agent
        Mock Set-Service {} -ModuleName Agent
        Mock Invoke-ScHardening {} -ModuleName Agent
    }
    It 'restarts a stopped service, sets Automatic and re-hardens honoring take_ownership' {
        $cfg = [pscustomobject]@{ local_watchdog = $true; allowed_ids = @('aaaaaaaaaaaaaaaa'); layers = @('ServiceSd'); take_ownership = $true }
        $f = @(Invoke-ScgLocalWatchdog -Config $cfg)
        Should -Invoke Start-Service -ModuleName Agent -Times 1 -Exactly
        Should -Invoke Set-Service -ModuleName Agent -Times 1 -Exactly
        Should -Invoke Invoke-ScHardening -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $TakeOwnership.IsPresent }
        $f[0].Detail | Should -Be 'restarted'
    }
    It 'does nothing when local_watchdog is false' {
        $cfg = [pscustomobject]@{ local_watchdog = $false; allowed_ids = @('aaaaaaaaaaaaaaaa'); layers = @('ServiceSd'); take_ownership = $false }
        $f = @(Invoke-ScgLocalWatchdog -Config $cfg)
        $f.Count | Should -Be 0
        Should -Invoke Get-ScAgent -ModuleName Agent -Times 0 -Exactly
        Should -Invoke Invoke-ScHardening -ModuleName Agent -Times 0 -Exactly
    }
    It 'returns zero findings for a clean state even when hardening writes output' {
        Mock Get-Service { [pscustomobject]@{ Status = 'Running'; StartType = 'Automatic' } } -ModuleName Agent
        Mock Invoke-ScHardening { 'hardening-output' } -ModuleName Agent
        $cfg = [pscustomobject]@{ local_watchdog = $true; allowed_ids = @('aaaaaaaaaaaaaaaa'); layers = @('ServiceSd'); take_ownership = $false }
        $f = @(Invoke-ScgLocalWatchdog -Config $cfg)
        $f.Count | Should -Be 0
        Should -Invoke Start-Service -ModuleName Agent -Times 0 -Exactly
        Should -Invoke Invoke-ScHardening -ModuleName Agent -Times 1 -Exactly
    }
}

Describe 'Invoke-ScgAgentCommand' {
    BeforeEach {
        Mock Write-ScgLog {} -ModuleName Agent
        Mock Get-ScAgent {
            @(
                [pscustomobject]@{ Id = 'aaaaaaaaaaaaaaaa'; ServiceName = 'svcA'; ServiceState = 'Running'; StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = $true },
                [pscustomobject]@{ Id = 'bbbbbbbbbbbbbbbb'; ServiceName = 'svcB'; ServiceState = 'Running'; StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = $false }
            )
        } -ModuleName Agent
        Mock Invoke-ScHardening {} -ModuleName Agent
        Mock Invoke-ScRestore { @{ Ok = $true; Messages = @('restored') } } -ModuleName Agent
        Mock Remove-ScAgent { 'removed agent' } -ModuleName Agent
        $script:CmdCfg = [pscustomobject]@{ allowed_ids = @('aaaaaaaaaaaaaaaa'); layers = @('ServiceSd'); take_ownership = $false; shared_secret = 'test-secret-value' }
    }
    It 'ping answers pong without discovery' {
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c1'; type = 'ping'; payload = $null }) -Config $script:CmdCfg
        $r.ok | Should -BeTrue
        $r.output | Should -Be 'pong'
        Should -Invoke Get-ScAgent -ModuleName Agent -Times 0 -Exactly
    }
    It 'status counts mine and unknown agents' {
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c2'; type = 'status'; payload = $null }) -Config $script:CmdCfg
        $r.ok | Should -BeTrue
        $r.output | Should -Match 'mine=1'
        $r.output | Should -Match 'unknown=1'
    }
    It 'agents lists every discovered agent' {
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c3'; type = 'agents'; payload = $null }) -Config $script:CmdCfg
        $r.output | Should -Match 'aaaaaaaaaaaaaaaa'
        $r.output | Should -Match 'bbbbbbbbbbbbbbbb'
    }
    It 'harden hardens only my agents' {
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c4'; type = 'harden'; payload = $null }) -Config $script:CmdCfg
        $r.ok | Should -BeTrue
        Should -Invoke Invoke-ScHardening -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Agent.Id -eq 'aaaaaaaaaaaaaaaa' }
    }
    It 'restore maps to Invoke-ScRestore and reports its result' {
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c5'; type = 'restore'; payload = $null }) -Config $script:CmdCfg
        $r.ok | Should -BeTrue
        $r.output | Should -Match 'restored'
        Should -Invoke Invoke-ScRestore -ModuleName Agent -Times 1 -Exactly
    }
    It 'remove of an unknown agent goes through Remove-ScAgent with the allow list' {
        $cmd = [pscustomobject]@{ id = 'c6'; type = 'remove'; payload = [pscustomobject]@{ sc_id = 'BBBBBBBBBBBBBBBB' } }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg
        $r.ok | Should -BeTrue
        Should -Invoke Remove-ScAgent -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Agent.Id -eq 'bbbbbbbbbbbbbbbb' -and ($AllowedId -contains 'aaaaaaaaaaaaaaaa') }
    }
    It 'remove of an allow-listed agent is refused and reported as failed' {
        Mock Remove-ScAgent { 'refused: <code>aaaaaaaaaaaaaaaa</code> is allow-listed (one of YOURS)' } -ModuleName Agent
        $cmd = [pscustomobject]@{ id = 'c7'; type = 'remove'; payload = '{"sc_id":"aaaaaaaaaaaaaaaa"}' }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg
        $r.ok | Should -BeFalse
        $r.output | Should -Match '^refused:'
    }
    It 'remove reported as aborted by Remove-ScAgent is failed' {
        Mock Remove-ScAgent { 'aborted: could not back up before removal' } -ModuleName Agent
        $cmd = [pscustomobject]@{ id = 'c7b'; type = 'remove'; payload = [pscustomobject]@{ sc_id = 'bbbbbbbbbbbbbbbb' } }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg
        $r.ok | Should -BeFalse
        $r.output | Should -Match '^aborted:'
    }
    It 'remove does not accept the legacy id key in the payload' {
        $cmd = [pscustomobject]@{ id = 'c7c'; type = 'remove'; payload = [pscustomobject]@{ id = 'bbbbbbbbbbbbbbbb' } }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg
        $r.ok | Should -BeFalse
        Should -Invoke Remove-ScAgent -ModuleName Agent -Times 0 -Exactly
    }
    It 'remove accepts the payload exactly as Telegram builds it' {
        $payload = @{ sc_id = 'bbbbbbbbbbbbbbbb' }
        $cmd = [pscustomobject]@{ id = 'c7d'; type = 'remove'; payload = $payload }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg
        $r.ok | Should -BeTrue
        Should -Invoke Remove-ScAgent -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Agent.Id -eq 'bbbbbbbbbbbbbbbb' }
    }
    It 'harden targets one agent by sc_id' {
        $cmd = [pscustomobject]@{ id = 'c7e'; type = 'harden'; payload = @{ sc_id = 'aaaaaaaaaaaaaaaa' } }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg
        $r.ok | Should -BeTrue
        Should -Invoke Invoke-ScHardening -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Agent.Id -eq 'aaaaaaaaaaaaaaaa' }
    }
    It 'remove without a payload id fails without calling Remove-ScAgent' {
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c8'; type = 'remove'; payload = $null }) -Config $script:CmdCfg
        $r.ok | Should -BeFalse
        Should -Invoke Remove-ScAgent -ModuleName Agent -Times 0 -Exactly
    }
    It 'harden with no layers configured fails' {
        $cfg = [pscustomobject]@{ allowed_ids = @('aaaaaaaaaaaaaaaa'); layers = @(); take_ownership = $false; shared_secret = 'x' }
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c10'; type = 'harden'; payload = $null }) -Config $cfg
        $r.ok | Should -BeFalse
        $r.output | Should -Be 'no layers configured'
        Should -Invoke Invoke-ScHardening -ModuleName Agent -Times 0 -Exactly
    }
    It 'remove refuses an id that is only in the previous allow list' {
        $cmd = [pscustomobject]@{ id = 'c11'; type = 'remove'; payload = @{ sc_id = 'bbbbbbbbbbbbbbbb' } }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg -PreviousAllowedId @('bbbbbbbbbbbbbbbb')
        $r.ok | Should -BeFalse
        $r.output | Should -Match '^refused:'
        Should -Invoke Remove-ScAgent -ModuleName Agent -Times 0 -Exactly
    }
    It 'remove refuses an authorized agent even when it is not allow-listed' {
        Mock Get-ScAgent { @([pscustomobject]@{ Id = 'cccccccccccccccc'; ServiceName = 'svcC'; ServiceState = 'Running'; StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = $true }) } -ModuleName Agent
        $cmd = [pscustomobject]@{ id = 'c12'; type = 'remove'; payload = @{ sc_id = 'cccccccccccccccc' } }
        $r = Invoke-ScgAgentCommand -Command $cmd -Config $script:CmdCfg
        $r.ok | Should -BeFalse
        $r.output | Should -Match '^refused:'
        Should -Invoke Remove-ScAgent -ModuleName Agent -Times 0 -Exactly
    }
    It 'unknown type fails' {
        $r = Invoke-ScgAgentCommand -Command ([pscustomobject]@{ id = 'c9'; type = 'explode'; payload = $null }) -Config $script:CmdCfg
        $r.ok | Should -BeFalse
    }
}

Describe 'Invoke-ScgAgentCycle' {
    BeforeEach {
        Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue
        $global:ScgTestOrder = New-Object System.Collections.Generic.List[string]
        Mock Write-ScgLog {} -ModuleName Agent
        Mock Initialize-ScgSecureDirectory { $true } -ModuleName Agent
        Mock Invoke-ScgLocalWatchdog { $global:ScgTestOrder.Add('watchdog'); return @() } -ModuleName Agent
        Mock Get-ScAgent { @() } -ModuleName Agent
        Mock Test-ScTamper { $false } -ModuleName Agent
        Mock Invoke-ScHardening {} -ModuleName Agent
        Mock Invoke-HubApi {
            $global:ScgTestOrder.Add($Path)
            switch ($Path) {
                '/enroll' { return [pscustomobject]@{ ok = $true; device_id = 'dev-0001' } }
                '/heartbeat' { return [pscustomobject]@{ ok = $true; commands = @(); config = [pscustomobject]@{ heartbeat_sec = 60; scan_interval_sec = 30; allowed_ids = @('aaaaaaaaaaaaaaaa'); alert_throttle_min = 60 } } }
                default { return [pscustomobject]@{ ok = $true } }
            }
        } -ModuleName Agent
        $script:T0 = [datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', [System.DateTimeKind]::Utc)
    }

    It 'enrolls when device_id is null and persists the id' {
        Write-TestConfig
        $s = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        $s.Enrolled | Should -BeTrue
        (Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json).device_id | Should -Be 'dev-0001'
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/enroll' }
    }
    It 'runs the watchdog first, then enroll, then heartbeat' {
        Write-TestConfig
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        $global:ScgTestOrder[0] | Should -Be 'watchdog'
        $global:ScgTestOrder[1] | Should -Be '/enroll'
        $global:ScgTestOrder[2] | Should -Be '/heartbeat'
    }
    It 'still runs the watchdog when the hub throws and records the failure' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Invoke-HubApi { throw 'network down' } -ModuleName Agent
        $s = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        $s.HubOk | Should -BeFalse
        Should -Invoke Invoke-ScgLocalWatchdog -ModuleName Agent -Times 1 -Exactly
        (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json).consecutive_failures | Should -Be 1
    }
    It 'skips the hub when the next heartbeat is not due but still runs the watchdog' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0.AddSeconds(5)
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/heartbeat' }
        Should -Invoke Invoke-ScgLocalWatchdog -ModuleName Agent -Times 2 -Exactly
    }
    It 'clears device_id when the hub answers 404 so the next cycle re-enrolls' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Invoke-HubApi { throw 'hub http 404: unknown device' } -ModuleName Agent
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        (Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json).device_id | Should -BeNullOrEmpty
    }
    It 'keeps device_id on a 404 that is not unknown device' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Invoke-HubApi { throw 'hub http 404: route_not_found' } -ModuleName Agent
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        (Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json).device_id | Should -Be 'dev-0001'
        Mock Invoke-HubApi { throw 'hub http 404: ' } -ModuleName Agent
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0 -Force
        (Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json).device_id | Should -Be 'dev-0001'
    }
    It 'locks the root and Backup folders before the watchdog runs' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Initialize-ScgSecureDirectory { $global:ScgTestOrder.Add('secure:' + $Path); $true } -ModuleName Agent
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        $global:ScgTestOrder[0] | Should -Be ('secure:' + $TestDrive)
        $global:ScgTestOrder[1] | Should -Be ('secure:' + (Join-Path $TestDrive 'Backup'))
        $global:ScgTestOrder[2] | Should -Be 'watchdog'
    }
    It 'refuses a remove of my own id when the same heartbeat shrinks the allow list' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Remove-ScAgent { 'removed agent' } -ModuleName Agent
        Mock Get-ScAgent {
            @([pscustomobject]@{ Id = 'aaaaaaaaaaaaaaaa'; ServiceName = 'svcA'; ServiceState = 'Running'; StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = (@($AllowedId) -contains 'aaaaaaaaaaaaaaaa') })
        } -ModuleName Agent
        Mock Invoke-HubApi {
            if ($Path -eq '/heartbeat') {
                return [pscustomobject]@{ ok = $true
                    commands = @([pscustomobject]@{ id = 'r1'; type = 'remove'; payload = [pscustomobject]@{ sc_id = 'aaaaaaaaaaaaaaaa' } })
                    config = [pscustomobject]@{ allowed_ids = @('dddddddddddddddd') }
                }
            }
            return [pscustomobject]@{ ok = $true }
        } -ModuleName Agent
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        Should -Invoke Remove-ScAgent -ModuleName Agent -Times 0 -Exactly
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/result' -and $Body.command_id -eq 'r1' -and $Body.ok -eq $false -and $Body.output -match '^refused:' }
        @((Get-Content -LiteralPath $script:Cfg -Raw | ConvertFrom-Json).allowed_ids) | Should -Be @('dddddddddddddddd')
    }
    It 'executes each command and posts one result per command' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Invoke-HubApi {
            $global:ScgTestOrder.Add($Path)
            if ($Path -eq '/heartbeat') {
                return [pscustomobject]@{ ok = $true; commands = @(
                        [pscustomobject]@{ id = 'c1'; type = 'ping'; payload = $null },
                        [pscustomobject]@{ id = 'c2'; type = 'status'; payload = $null }
                    ); config = [pscustomobject]@{ heartbeat_sec = 60; scan_interval_sec = 30; allowed_ids = @('aaaaaaaaaaaaaaaa') }
                }
            }
            return [pscustomobject]@{ ok = $true }
        } -ModuleName Agent
        $s = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        $s.Commands | Should -Be 2
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 2 -Exactly -ParameterFilter { $Path -eq '/result' }
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/result' -and $Body.command_id -eq 'c1' -and $Body.ok -eq $true -and $Body.output -eq 'pong' -and $Body.device_id -eq 'dev-0001' }
    }
    It 'posts unknown_agent and tamper events every cycle' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Get-ScAgent {
            @(
                [pscustomobject]@{ Id = 'aaaaaaaaaaaaaaaa'; ServiceName = 'svcA'; ServiceState = 'Running'; StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = $true },
                [pscustomobject]@{ Id = 'bbbbbbbbbbbbbbbb'; ServiceName = 'svcB'; ServiceState = 'Running'; StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = $false }
            )
        } -ModuleName Agent
        Mock Test-ScTamper { $true } -ModuleName Agent
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/event' -and $Body.type -eq 'unknown_agent' -and $Body.payload.sc_id -eq 'bbbbbbbbbbbbbbbb' }
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/event' -and $Body.type -eq 'tamper' -and $Body.payload.sc_id -eq 'aaaaaaaaaaaaaaaa' }
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0.AddSeconds(120)
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 2 -Exactly -ParameterFilter { $Path -eq '/event' -and $Body.type -eq 'tamper' }
    }
    It 'sends discovery_ok false and no agents when discovery throws, and posts no agent events' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        Mock Get-ScAgent { throw 'cim failure' } -ModuleName Agent
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/heartbeat' -and $Body.discovery_ok -eq $false -and @($Body.sc_agents).Count -eq 0 }
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 0 -Exactly -ParameterFilter { $Path -eq '/event' }
    }
    It 'sends discovery_ok true on a normal heartbeat' {
        Write-TestConfig -Override @{ device_id = 'dev-0001' }
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/heartbeat' -and $Body.discovery_ok -eq $true }
    }
    It 'is idempotent: a re-run enrolls once and leaves the config file unchanged' {
        Write-TestConfig
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        $h1 = (Get-FileHash -LiteralPath $script:Cfg).Hash
        $null = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0.AddSeconds(120)
        $h2 = (Get-FileHash -LiteralPath $script:Cfg).Hash
        $h2 | Should -Be $h1
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Path -eq '/enroll' }
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 2 -Exactly -ParameterFilter { $Path -eq '/heartbeat' }
        (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json).consecutive_failures | Should -Be 0
    }
}

Describe 'Invoke-ScgAgentCycle with the real watchdog' {
    BeforeEach {
        Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue
        Mock Write-ScgLog {} -ModuleName Agent
        Mock Initialize-ScgSecureDirectory { $true } -ModuleName Agent
        Mock Get-ScAgent { @([pscustomobject]@{ Id = 'aaaaaaaaaaaaaaaa'; ServiceName = 'svcA'; ServiceState = 'Running'; StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = $true }) } -ModuleName Agent
        Mock Get-Service { [pscustomobject]@{ Status = 'Running'; StartType = 'Automatic' } } -ModuleName Agent
        Mock Start-Service {} -ModuleName Agent
        Mock Set-Service {} -ModuleName Agent
        Mock Invoke-ScHardening { 'hardening-output' } -ModuleName Agent
        Mock Test-ScTamper { $false } -ModuleName Agent
        Mock Invoke-HubApi {
            if ($Path -eq '/heartbeat') { return [pscustomobject]@{ ok = $true; commands = @(); config = [pscustomobject]@{ heartbeat_sec = 60 } } }
            return [pscustomobject]@{ ok = $true }
        } -ModuleName Agent
        $script:T0 = [datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', [System.DateTimeKind]::Utc)
    }
    It 'a clean cycle yields zero findings, zero events and no failure' {
        Write-TestConfig -Override @{ device_id = 'dev-0001'; local_watchdog = $true }
        $s = Invoke-ScgAgentCycle -ConfigPath $script:Cfg -Now $script:T0
        @($s.Findings).Count | Should -Be 0
        $s.Events | Should -Be 0
        $s.HubOk | Should -BeTrue
        Should -Invoke Invoke-ScHardening -ModuleName Agent -Times 1 -Exactly
        Should -Invoke Start-Service -ModuleName Agent -Times 0 -Exactly
        Should -Invoke Invoke-HubApi -ModuleName Agent -Times 0 -Exactly -ParameterFilter { $Path -eq '/event' }
        (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json).consecutive_failures | Should -Be 0
    }
}

Describe 'Invoke-HubApi' {
    It 'sends a well-formed signed request (loopback listener)' {
        $srv = Start-TestListener -Status 200 -ResponseText '{"ok":true,"device_id":"d1"}'
        $cfg = [pscustomobject]@{ hub_url = "http://127.0.0.1:$($srv.Port)"; shared_secret = 'sekret-123'; trusted_server_thumbprint = '' }
        $r = Invoke-HubApi -Config $cfg -Method POST -Path '/enroll' -Body @{ hostname = 'pc1'; note = 'caf' }
        $cap = Stop-TestListener -Server $srv
        $r.ok | Should -BeTrue
        $r.device_id | Should -Be 'd1'
        $cap.Path | Should -Be '/api/v1/enroll'
        $cap.Method | Should -Be 'POST'
        $cap.Auth | Should -Be 'Bearer sekret-123'
        $cap.Ts | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
        $guid = [guid]::Empty
        [guid]::TryParse($cap.Nonce, [ref]$guid) | Should -BeTrue
        $cap.ContentType | Should -Match 'application/json'
        ($cap.Body | ConvertFrom-Json).hostname | Should -Be 'pc1'
    }
    It 'uses a fresh nonce on every request' {
        $nonces = @()
        foreach ($i in 1..2) {
            $srv = Start-TestListener
            $cfg = [pscustomobject]@{ hub_url = "http://127.0.0.1:$($srv.Port)"; shared_secret = 'sekret-123'; trusted_server_thumbprint = '' }
            $null = Invoke-HubApi -Config $cfg -Method GET -Path '/health'
            $nonces += (Stop-TestListener -Server $srv).Nonce
        }
        $nonces[0] | Should -Not -Be $nonces[1]
    }
    It 'throws on a non-2xx status and masks the secret in the message' {
        $srv = Start-TestListener -Status 401 -ResponseText '{"ok":false,"error":"bad sekret-123"}'
        $cfg = [pscustomobject]@{ hub_url = "http://127.0.0.1:$($srv.Port)"; shared_secret = 'sekret-123'; trusted_server_thumbprint = '' }
        $msg = ''
        try { $null = Invoke-HubApi -Config $cfg -Method GET -Path '/health' } catch { $msg = $_.Exception.Message }
        $null = Stop-TestListener -Server $srv
        $msg | Should -Match 'hub http 401'
        $msg | Should -Not -Match 'sekret-123'
    }
    It 'logs the dev-mode warning only once per process when no thumbprint is pinned' {
        Mock Write-ScgLog {} -ModuleName Agent
        InModuleScope Agent { $script:PinWarned = $false }
        $cfg = [pscustomobject]@{ hub_url = 'https://127.0.0.1:1'; shared_secret = 'sekret-123'; trusted_server_thumbprint = '' }
        foreach ($i in 1..2) { try { $null = Invoke-HubApi -Config $cfg -Method GET -Path '/health' } catch { $null = $_ } }
        Should -Invoke Write-ScgLog -ModuleName Agent -Times 1 -Exactly -ParameterFilter { $Message -like '*dev-mode*' }
        Should -Invoke Write-ScgLog -ModuleName Agent -Times 0 -Exactly -ParameterFilter { $Message -like '*sekret-123*' }
    }
    It 'does not warn when a thumbprint is pinned' {
        Mock Write-ScgLog {} -ModuleName Agent
        InModuleScope Agent { $script:PinWarned = $false }
        $cfg = [pscustomobject]@{ hub_url = 'https://127.0.0.1:1'; shared_secret = 'sekret-123'; trusted_server_thumbprint = ('A' * 40) }
        try { $null = Invoke-HubApi -Config $cfg -Method GET -Path '/health' } catch { $null = $_ }
        Should -Invoke Write-ScgLog -ModuleName Agent -Times 0 -Exactly -ParameterFilter { $Message -like '*dev-mode*' }
    }
    It 'pin callback rejects a missing certificate' {
        $ok = InModuleScope Agent {
            Initialize-ScgCertPin
            $pin = New-Object ScgCertPin -ArgumentList ('A' * 40)
            $pin.Check($null, $null, $null, [System.Net.Security.SslPolicyErrors]::None)
        }
        $ok | Should -BeFalse
    }
}
