#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Purpose: Pester 5 tests for Hub.psm1 | Author: Badr | Version: 4.0.0

BeforeAll {
    $modulesDir = Join-Path $PSScriptRoot '..\..\src\modules'
    Import-Module (Join-Path $modulesDir 'Common.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $modulesDir 'Database.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $modulesDir 'HttpServer.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $modulesDir 'Telegram.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $modulesDir 'Hub.psm1') -Force -DisableNameChecking

    $script:TemplatePath = Join-Path $PSScriptRoot '..\..\src\config\hub.config.template.json'
    $script:Secret = 'hub-test-secret-value-123'
    $script:IdA = '5d0931a9fafc2a8b'
    $script:IdB = '4c37282122b38af3'

    function New-TestConfig {
        param([string]$Db, [string]$ChatId = '', [int]$TimeoutSec = 300)
        [pscustomobject]@{
            listen        = [pscustomobject]@{ url = 'http://localhost:18443/'; cert_thumbprint = 'auto' }
            shared_secret = $script:Secret
            telegram      = [pscustomobject]@{ bot_token = 'test-token'; chat_id = $ChatId; admin_user_ids = @('1'); admin_usernames = @('Idlexaz') }
            database      = [pscustomobject]@{ path = $Db }
            defaults      = [pscustomobject]@{
                allowed_ids = @($script:IdA, $script:IdB); scan_interval_sec = 30; heartbeat_sec = 60; alert_throttle_min = 30
                command_confirm_sec = 60; stale_after_min = 5; command_timeout_sec = $TimeoutSec; nonce_ttl_sec = 600; max_skew_sec = 300
            }
            logging       = [pscustomobject]@{ path = (Join-Path $TestDrive 'hub.log'); max_bytes = 1048576 }
        }
    }
    function ConvertTo-TestBody {
        param($Value)
        ($Value | ConvertTo-Json -Depth 8 -Compress) | ConvertFrom-Json
    }
    function Register-TestDevice {
        param([string]$Name = 'PC-01')
        $r = Invoke-ScgEnroll -Config $script:Cfg -Body (ConvertTo-TestBody @{ hostname = $Name; os = 'Windows'; os_version = '10.0'; agent_version = '4.0.0' }) -RemoteIp '10.0.0.5'
        $script:Tokens[[string]$r.Body.device_id] = [string]$r.Body.device_token
        $r.Body.device_id
    }
    function Get-TestAuth {
        param($Body)
        $h = @{}
        if ($null -eq $Body -or -not $Body.PSObject.Properties['device_id']) { return $h }
        $id = [string]$Body.device_id
        if ($script:Tokens.ContainsKey($id)) { $h['X-SCG-Device-Token'] = $script:Tokens[$id] }
        return $h
    }
    function Invoke-TestHeartbeat {
        param($Body, $Config = $script:Cfg)
        Invoke-ScgHeartbeat -Config $Config -Body $Body -RemoteIp '10.0.0.5' -Headers (Get-TestAuth $Body)
    }
    function Invoke-TestResult {
        param($Body, $Config = $script:Cfg, [scriptblock]$Send)
        $p = @{ Config = $Config; Body = $Body; Headers = (Get-TestAuth $Body) }
        if ($Send) { $p['Send'] = $Send }
        Invoke-ScgResult @p
    }
    function Invoke-TestEvent {
        param($Body, $Config = $script:Cfg)
        Invoke-ScgEventIngest -Config $Config -Body $Body -Headers (Get-TestAuth $Body)
    }
    function Get-TestRejectReason {
        @(@(Get-ScgAudit -Path $script:Db -Last 200) | Where-Object { $_.action -eq 'auth.reject' } | ForEach-Object { ($_.meta_json | ConvertFrom-Json).reason })
    }
    function Get-TestDeviceHeader {
        param([string]$Token, [string]$Nonce = ([guid]::NewGuid().ToString()))
        $h = New-TestHeader -Nonce $Nonce
        if ($Token) { $h['X-SCG-Device-Token'] = $Token }
        $h
    }
    function New-TestHeader {
        param([string]$Bearer = $script:Secret, [string]$Nonce = ([guid]::NewGuid().ToString()))
        @{ 'Authorization' = "Bearer $Bearer"; 'X-SCG-Timestamp' = (Get-ScgUtcNow); 'X-SCG-Nonce' = $Nonce }
    }
    function Write-TestConfigFile {
        param([hashtable]$Override = @{}, [string[]]$Remove = @())
        $cfg = @{
            listen        = @{ url = 'https://+:8443/'; cert_thumbprint = 'auto' }
            shared_secret = 'a-real-secret'
            telegram      = @{ bot_token = '123456:real-token'; chat_id = '-100123'; admin_user_ids = @('1'); admin_usernames = @('Idlexaz') }
            database      = @{ path = 'C:\x\hub.db' }
            defaults      = @{ allowed_ids = @('5D0931A9FAFC2A8B') }
            logging       = @{ path = 'C:\x\hub.log' }
        }
        foreach ($k in $Override.Keys) { $cfg[$k] = $Override[$k] }
        foreach ($k in $Remove) { $cfg.Remove($k) }
        $p = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.json')
        ($cfg | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $p -Encoding UTF8
        $p
    }
    function Reset-TestState {
        $script:Db = Join-Path $TestDrive ('t' + [guid]::NewGuid().ToString('N') + '.db')
        [void](Initialize-ScgDatabase -Path $script:Db)
        $script:Cfg = New-TestConfig -Db $script:Db
        $script:Tokens = @{}
    }
}

Describe 'Get-ScgHubConfig' {
    BeforeEach { Reset-TestState }
    It 'fills defaults and normalises allowed ids to lowercase' {
        $c = Get-ScgHubConfig -Path (Write-TestConfigFile)
        $c.defaults.command_timeout_sec | Should -Be 300
        $c.defaults.nonce_ttl_sec | Should -Be 600
        $c.defaults.max_skew_sec | Should -Be 300
        $c.defaults.tick_sec | Should -Be 30
        $c.defaults.telegram_error_pause_sec | Should -Be 5
        $c.defaults.allowed_ids | Should -Contain '5d0931a9fafc2a8b'
        $c.logging.max_bytes | Should -BeGreaterThan 0
    }
    It 'honours explicit values over defaults' {
        $c = Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ defaults = @{ command_timeout_sec = 42; allowed_ids = @('5D0931A9FAFC2A8B', '5d0931a9fafc2a8b') } })
        $c.defaults.command_timeout_sec | Should -Be 42
        @($c.defaults.allowed_ids).Count | Should -Be 1
    }
    It 'rejects an empty or missing allow-list' {
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ defaults = @{ allowed_ids = @() } }) } | Should -Throw '*allowed_ids must list at least one id*'
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ defaults = @{ command_timeout_sec = 42 } }) } | Should -Throw '*allowed_ids must list at least one id*'
    }
    It 'rejects REPLACE_ME secrets' {
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ shared_secret = 'REPLACE_ME' }) } | Should -Throw '*REPLACE_ME*'
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ telegram = @{ bot_token = 'REPLACE_ME'; chat_id = '1'; admin_user_ids = @('1') } }) } | Should -Throw '*REPLACE_ME*'
    }
    It 'rejects a missing required key' {
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Remove @('database')) } | Should -Throw '*database.path*'
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Remove @('shared_secret')) } | Should -Throw '*shared_secret*'
    }
    It 'rejects an invalid allowed id and a non-positive interval' {
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ defaults = @{ allowed_ids = @('xyz') } }) } | Should -Throw '*allowed_ids*'
        { Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ defaults = @{ heartbeat_sec = 0 } }) } | Should -Throw '*heartbeat_sec*'
    }
    It 'never echoes the secret in an error' {
        $msg = ''
        try { Get-ScgHubConfig -Path (Write-TestConfigFile -Override @{ defaults = @{ allowed_ids = @('bad') } }) } catch { $msg = $_.Exception.Message }
        $msg | Should -Not -Match 'a-real-secret'
    }
}

Describe 'hub.config.template.json' {
    BeforeEach { Reset-TestState }
    It 'loads its non-secret defaults once secret and token are replaced' {
        $t = Get-Content -LiteralPath $script:TemplatePath -Raw | ConvertFrom-Json
        $t.shared_secret = 'a-real-secret'
        $t.telegram.bot_token = '123456:real-token'
        $p = Join-Path $TestDrive 'filled.json'
        ($t | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $p -Encoding UTF8
        $c = Get-ScgHubConfig -Path $p
        $c.listen.url | Should -Be 'https://+:8443/'
        $c.defaults.scan_interval_sec | Should -Be 60
        $c.defaults.alert_throttle_min | Should -Be 15
        $c.defaults.command_confirm_sec | Should -Be 300
        $c.defaults.stale_after_min | Should -Be 5
        $c.database.path | Should -Be 'C:\ProgramData\SCGuardian\hub.db'
        $c.logging.max_bytes | Should -Be 5242880
        @($c.defaults.allowed_ids).Count | Should -Be 2
    }
    It 'parses, holds placeholders only and the two public allow-list ids' {
        $raw = Get-Content -LiteralPath $script:TemplatePath -Raw
        $t = $raw | ConvertFrom-Json
        $t.shared_secret | Should -Be 'REPLACE_ME'
        $t.telegram.bot_token | Should -Be 'REPLACE_ME'
        @($t.defaults.allowed_ids) | Should -Be @('5d0931a9fafc2a8b', '4c37282122b38af3')
        @($t.telegram.admin_usernames) | Should -Be @('Idlexaz')
        $raw | Should -Not -Match '\d{6,}:[A-Za-z0-9_\-]{30,}'
    }
    It 'is rejected by Get-ScgHubConfig until the placeholders are replaced' {
        { Get-ScgHubConfig -Path $script:TemplatePath } | Should -Throw '*REPLACE_ME*'
    }
}

Describe 'Invoke-ScgEnroll' {
    BeforeEach { Reset-TestState }
    It 'registers a device and audits the enroll' {
        $r = Invoke-ScgEnroll -Config $script:Cfg -Body (ConvertTo-TestBody @{ hostname = 'PC-01'; os = 'Windows'; os_version = '10.0'; agent_version = '4.0.0' }) -RemoteIp '10.0.0.5'
        $r.Status | Should -Be 200
        $r.Body.ok | Should -BeTrue
        $r.Body.device_id | Should -Not -BeNullOrEmpty
        @(@(Get-ScgAudit -Path $script:Db -Last 10) | Where-Object { $_.action -eq 'enroll' }).Count | Should -Be 1
    }
    It 'returns a device token once and stores only its hash' {
        $r = Invoke-ScgEnroll -Config $script:Cfg -Body (ConvertTo-TestBody @{ hostname = 'PC-01'; os = 'Windows'; os_version = '10.0'; agent_version = '4.0.0' }) -RemoteIp '10.0.0.5'
        $r.Status | Should -Be 200
        $tok = [string]$r.Body.device_token
        $tok | Should -Match '^[A-Za-z0-9_-]{43}$'
        $row = @(Get-ScgDevice -Path $script:Db -DeviceId $r.Body.device_id)[0]
        $row.token_hash | Should -BeExactly (Get-ScgTokenHash -Token $tok)
        $row.token_hash | Should -Not -Be $tok
        $dump = (@(Invoke-ScgSql -Path $script:Db -Sql 'SELECT * FROM devices') + @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT * FROM audit_log') | ConvertTo-Json -Depth 4 -Compress)
        $dump.Contains($tok) | Should -BeFalse
        $script:Tokens[[string]$r.Body.device_id] = $tok
        $hb = Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $r.Body.device_id; hostname = 'PC-01'; sc_agents = @() })
        $hb.Status | Should -Be 200
        (ConvertTo-Json -InputObject $hb.Body -Depth 6 -Compress).Contains($tok) | Should -BeFalse
        [bool]($hb.Body.Contains('device_token')) | Should -BeFalse
    }
    It 'answers 409 on re-enroll while a token hash is set, even when the device is stale' {
        $a = Register-TestDevice -Name 'PC-01'
        $hash = (@(Get-ScgDevice -Path $script:Db -DeviceId $a))[0].token_hash
        [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE devices SET last_seen=@t WHERE id=@id' -Parameter @{ t = '2020-01-01T00:00:00.000Z'; id = $a })
        $r = Invoke-ScgEnroll -Config $script:Cfg -Body (ConvertTo-TestBody @{ hostname = 'PC-01'; os = 'Windows'; os_version = '10.0'; agent_version = '4.0.1' }) -RemoteIp '10.0.0.66'
        $r.Status | Should -Be 409
        $r.Body.ok | Should -BeFalse
        $r.Body.error | Should -BeExactly 'hostname already enrolled'
        [bool]($r.Body.Contains('device_token')) | Should -BeFalse
        $rej = @(@(Get-ScgAudit -Path $script:Db -Last 20) | Where-Object { $_.action -eq 'auth.reject' })
        $rej.Count | Should -Be 1
        $m = $rej[0].meta_json | ConvertFrom-Json
        $m.reason | Should -Be 'enroll_conflict'
        $m.hostname | Should -Be 'PC-01'
        @(@(Get-ScgAudit -Path $script:Db -Last 20) | Where-Object { $_.action -eq 'enroll' }).Count | Should -Be 1
        $row = (@(Get-ScgDevice -Path $script:Db -DeviceId $a))[0]
        $row.last_ip | Should -Be '10.0.0.5'
        $row.token_hash | Should -BeExactly $hash
    }
    It 're-enrolls after Clear-ScgDeviceToken with the same id and a new token, and the old token then fails' {
        $a = Register-TestDevice -Name 'PC-01'
        $old = $script:Tokens[$a]
        Clear-ScgDeviceToken -Path $script:Db -DeviceId $a | Should -BeTrue
        $hbBody = ConvertTo-TestBody @{ device_id = $a; hostname = 'PC-01'; sc_agents = @() }
        $nr = Invoke-ScgHeartbeat -Config $script:Cfg -Body $hbBody -Headers @{ 'X-SCG-Device-Token' = $old }
        $nr.Status | Should -Be 401
        $nr.Body.error | Should -BeExactly 'device not enrolled'
        Get-TestRejectReason | Should -Contain 'device_not_enrolled'
        $r = Invoke-ScgEnroll -Config $script:Cfg -Body (ConvertTo-TestBody @{ hostname = 'PC-01'; os = 'Windows'; os_version = '10.0'; agent_version = '4.0.1' }) -RemoteIp '10.0.0.6'
        $r.Status | Should -Be 200
        $r.Body.device_id | Should -Be $a
        $new = [string]$r.Body.device_token
        $new | Should -Not -BeNullOrEmpty
        $new | Should -Not -Be $old
        @(Get-ScgDevice -Path $script:Db).Count | Should -Be 1
        (@(Get-ScgDevice -Path $script:Db -DeviceId $a))[0].token_hash | Should -BeExactly (Get-ScgTokenHash -Token $new)
        $enrolls = @(@(Get-ScgAudit -Path $script:Db -Last 50) | Where-Object { $_.action -eq 'enroll' })
        $enrolls.Count | Should -Be 2
        ($enrolls[0].meta_json | ConvertFrom-Json).reenroll | Should -BeTrue
        [bool](($enrolls[1].meta_json | ConvertFrom-Json).PSObject.Properties['reenroll']) | Should -BeFalse
        $bad = Invoke-ScgHeartbeat -Config $script:Cfg -Body $hbBody -Headers @{ 'X-SCG-Device-Token' = $old }
        $bad.Status | Should -Be 401
        $bad.Body.error | Should -BeExactly 'invalid device token'
        (Invoke-ScgHeartbeat -Config $script:Cfg -Body $hbBody -Headers @{ 'X-SCG-Device-Token' = $new }).Status | Should -Be 200
    }
    It 'enrolls a first-time hostname with a new id and no reenroll flag' {
        $a = Register-TestDevice -Name 'PC-01'
        $b = Register-TestDevice -Name 'PC-02'
        $b | Should -Not -BeNullOrEmpty
        $b | Should -Not -Be $a
        @(Get-ScgDevice -Path $script:Db).Count | Should -Be 2
    }
    It 'answers 400 for each missing field and for a null body' {
        foreach ($drop in @('hostname', 'os', 'os_version', 'agent_version')) {
            $h = @{ hostname = 'PC-01'; os = 'Windows'; os_version = '10.0'; agent_version = '4.0.0' }
            $h.Remove($drop)
            (Invoke-ScgEnroll -Config $script:Cfg -Body (ConvertTo-TestBody $h)).Status | Should -Be 400
        }
        (Invoke-ScgEnroll -Config $script:Cfg -Body $null).Status | Should -Be 400
    }
}

Describe 'Invoke-ScgHeartbeat' {
    BeforeEach { Reset-TestState }
    It 'answers 400 for missing device_id, hostname, sc_agents or a non-16-hex agent id' {
        $id = Register-TestDevice
        (Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ hostname = 'PC-01'; sc_agents = @() })).Status | Should -Be 400
        (Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; sc_agents = @() })).Status | Should -Be 400
        (Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01' })).Status | Should -Be 400
        $bad = @{ device_id = $id; hostname = 'PC-01'; sc_agents = @(@{ id = 'nothex'; service = 's'; folder = 'f'; uninstall_key = 'k'; state = 'Running' }) }
        (Invoke-TestHeartbeat -Body (ConvertTo-TestBody $bad)).Status | Should -Be 400
    }
    It 'answers 404 for an unknown device' {
        $r = Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = 'no-such-device'; hostname = 'X'; sc_agents = @() })
        $r.Status | Should -Be 404
        $r.Body.ok | Should -BeFalse
        $r.Body.error | Should -BeExactly 'unknown device'
    }
    It 'keeps the stored hostname when a device reports an existing name and commands still flow' {
        $a = Register-TestDevice -Name 'PC-A'
        $b = Register-TestDevice -Name 'PC-B'
        $cmdA = New-ScgCommand -Path $script:Db -DeviceId $a -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system'
        $cmdB = New-ScgCommand -Path $script:Db -DeviceId $b -Type 'status' -Payload $null -IssuedBy 'system' -IssuedVia 'system'
        $hb = ConvertTo-TestBody @{ device_id = $b; hostname = 'PC-A'; sc_agents = @() }
        $first = Invoke-TestHeartbeat -Body $hb
        $first.Status | Should -Be 200
        @($first.Body.commands).Count | Should -Be 1
        $first.Body.commands[0].id | Should -Be $cmdB
        $second = Invoke-TestHeartbeat -Body $hb
        $second.Status | Should -Be 200
        (@(Get-ScgDevice -Path $script:Db -DeviceId $b))[0].hostname | Should -Be 'PC-B'
        (@(Get-ScgDevice -Path $script:Db -DeviceId $a))[0].hostname | Should -Be 'PC-A'
        (Get-ScgCommand -Path $script:Db -CommandId $cmdA).status | Should -Be 'pending'
        $changes = @(@(Get-ScgAudit -Path $script:Db -Last 50) | Where-Object { $_.action -eq 'heartbeat.config_change' })
        $changes.Count | Should -Be 1
        $m = $changes[0].meta_json | ConvertFrom-Json
        $m.field | Should -Be 'hostname'
        $m.reported | Should -Be 'PC-A'
        $m.stored | Should -Be 'PC-B'
    }
    It 'audits a new config_change when the reported hostname changes again' {
        $id = Register-TestDevice -Name 'PC-01'
        [void](Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'NEW-1'; sc_agents = @() }))
        [void](Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'NEW-2'; sc_agents = @() }))
        [void](Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @() }))
        @(@(Get-ScgAudit -Path $script:Db -Last 50) | Where-Object { $_.action -eq 'heartbeat.config_change' }).Count | Should -Be 2
        (@(Get-ScgDevice -Path $script:Db -DeviceId $id))[0].hostname | Should -Be 'PC-01'
    }
    It 'serves a result from a device whose reported hostname mismatches but never another device command' {
        $a = Register-TestDevice -Name 'PC-A'
        $b = Register-TestDevice -Name 'PC-B'
        $cmdA = New-ScgCommand -Path $script:Db -DeviceId $a -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system'
        $hbB = Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $b; hostname = 'PC-A'; sc_agents = @() })
        @($hbB.Body.commands).Count | Should -Be 0
        $hbA = Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $a; hostname = 'PC-A'; sc_agents = @() })
        $hbA.Body.commands[0].id | Should -Be $cmdA
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $b; hostname = 'PC-A'; command_id = $cmdA; ok = $true })).Status | Should -Be 409
        (Get-ScgCommand -Path $script:Db -CommandId $cmdA).status | Should -Be 'dispatched'
        (Invoke-TestEvent -Body (ConvertTo-TestBody @{ device_id = $b; hostname = 'PC-A'; type = 'tamper'; severity = 'warn' })).Status | Should -Be 200
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $a; hostname = 'PC-A'; command_id = $cmdA; ok = $true })).Status | Should -Be 200
    }
    It 'answers exactly unknown device for result and event too' {
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = 'ghost'; command_id = 'x'; ok = $true })).Body.error | Should -BeExactly 'unknown device'
        (Invoke-TestEvent -Body (ConvertTo-TestBody @{ device_id = 'ghost'; type = 'tamper'; severity = 'warn' })).Body.error | Should -BeExactly 'unknown device'
    }
    It 'returns config with the authoritative allow-list' {
        $id = Register-TestDevice
        $r = Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @(); uptime_sec = 5; agent_version = '4.0.0' })
        $r.Status | Should -Be 200
        $r.Body.config.heartbeat_sec | Should -Be 60
        $r.Body.config.scan_interval_sec | Should -Be 30
        $r.Body.config.alert_throttle_min | Should -Be 30
        @($r.Body.config.allowed_ids) | Should -Be @($script:IdA, $script:IdB)
    }
    It 'authorises allow-listed agents and is idempotent with no duplicate rows' {
        $id = Register-TestDevice
        $agents = @(
            @{ id = $script:IdA.ToUpperInvariant(); service = 'ScreenConnect Client (a)'; folder = 'C:\a'; uninstall_key = 'ka'; state = 'Running' },
            @{ id = 'aaaaaaaaaaaaaaaa'; service = 'ScreenConnect Client (b)'; folder = 'C:\b'; uninstall_key = 'kb'; state = 'Running' }
        )
        $body = ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = $agents; uptime_sec = 1; agent_version = '4.0.0' }
        [void](Invoke-TestHeartbeat -Body $body)
        [void](Invoke-TestHeartbeat -Body $body)
        $rows = @(Get-ScgScAgent -Path $script:Db -DeviceId $id)
        $rows.Count | Should -Be 2
        @(Get-ScgDevice -Path $script:Db).Count | Should -Be 1
        ($rows | Where-Object { $_.id -eq $script:IdA }).authorized | Should -Be 1
        ($rows | Where-Object { $_.id -eq 'aaaaaaaaaaaaaaaa' }).authorized | Should -Be 0
    }
    It 'removes absent agents only on an explicit empty list with discovery ok' {
        $id = Register-TestDevice
        $one = @{ id = $script:IdA; service = 's'; folder = 'f'; uninstall_key = 'k'; state = 'Running' }
        [void](Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @($one) }))
        @(Get-ScgScAgent -Path $script:Db -DeviceId $id).Count | Should -Be 1
        [void](Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @(); discovery_ok = $false }))
        @(Get-ScgScAgent -Path $script:Db -DeviceId $id).Count | Should -Be 1
        [void](Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @() }))
        @(Get-ScgScAgent -Path $script:Db -DeviceId $id).Count | Should -Be 0
    }
    It 'answers 400 for a non-boolean discovery_ok' {
        $id = Register-TestDevice
        (Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @(); discovery_ok = 'no' })).Status | Should -Be 400
    }
    It 'returns a pending command exactly once and audits the dispatch' {
        $id = Register-TestDevice
        $cid = New-ScgCommand -Path $script:Db -DeviceId $id -Type 'ping' -Payload $null -IssuedBy 'telegram:1' -IssuedVia 'telegram'
        $hb = ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @() }
        $first = Invoke-TestHeartbeat -Body $hb
        @($first.Body.commands).Count | Should -Be 1
        $first.Body.commands[0].id | Should -Be $cid
        $first.Body.commands[0].type | Should -Be 'ping'
        $second = Invoke-TestHeartbeat -Body $hb
        @($second.Body.commands).Count | Should -Be 0
        @(@(Get-ScgAudit -Path $script:Db -Last 20) | Where-Object { $_.action -eq 'command.dispatch' }).Count | Should -Be 1
    }
    It 'reactivates a stale device' {
        $id = Register-TestDevice
        [void](Set-ScgDeviceStatus -Path $script:Db -DeviceId $id -Status 'stale')
        [void](Invoke-TestHeartbeat -Body (ConvertTo-TestBody @{ device_id = $id; hostname = 'PC-01'; sc_agents = @() }))
        (@(Get-ScgDevice -Path $script:Db -DeviceId $id))[0].status | Should -Be 'active'
    }
}

Describe 'Invoke-ScgResult' {
    BeforeEach {
        Reset-TestState
        $script:DevA = Register-TestDevice -Name 'PC-A'
        $script:DevB = Register-TestDevice -Name 'PC-B'
        $script:CmdA = New-ScgCommand -Path $script:Db -DeviceId $script:DevA -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system'
    }
    It 'completes a dispatched command and audits it' {
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:DevA)
        $r = Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = $true; output = 'pong'; duration_ms = 12 })
        $r.Status | Should -Be 200
        $r.Body.ok | Should -BeTrue
        @(@(Get-ScgAudit -Path $script:Db -Last 20) | Where-Object { $_.action -eq 'command.result' }).Count | Should -Be 1
    }
    It 'answers 400 for missing or invalid fields' {
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ command_id = $script:CmdA; ok = $true })).Status | Should -Be 400
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $script:DevA; ok = $true })).Status | Should -Be 400
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA })).Status | Should -Be 400
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = 'yes' })).Status | Should -Be 400
    }
    It 'answers 404 for an unknown device' {
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = 'ghost'; command_id = $script:CmdA; ok = $true })).Status | Should -Be 404
    }
    It 'answers 409 for a command that is still pending' {
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = $true })).Status | Should -Be 409
    }
    It 'answers 409 when another device reports the command' {
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:DevA)
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $script:DevB; command_id = $script:CmdA; ok = $true })).Status | Should -Be 409
    }
    It 'answers 409 for an unknown command id and for a second result' {
        (Invoke-TestResult -Body (ConvertTo-TestBody @{ device_id = $script:DevA; command_id = 'nope'; ok = $true })).Status | Should -Be 409
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:DevA)
        $body = ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = $false; output = 'x'; duration_ms = 1 }
        (Invoke-TestResult -Body $body).Status | Should -Be 200
        (Invoke-TestResult -Body $body).Status | Should -Be 409
    }
    It 'sends a Telegram notice only when a chat is configured' {
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:DevA)
        $script:Sent = New-Object System.Collections.ArrayList
        $sink = $script:Sent
        $send = { param($Text, $Markup, $ChatId, $EditId) [void]$sink.Add($Text) }.GetNewClosure()
        $cfgChat = New-TestConfig -Db $script:Db -ChatId '-100123'
        $body = ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = $true; output = 'pong'; duration_ms = 5 }
        (Invoke-TestResult -Config $cfgChat -Body $body -Send $send).Status | Should -Be 200
        $script:Sent.Count | Should -Be 1
        $script:Sent[0] | Should -Match 'PC-A'
        $script:Sent[0] | Should -Match 'ping'

        $cmd2 = New-ScgCommand -Path $script:Db -DeviceId $script:DevA -Type 'status' -Payload $null -IssuedBy 'system' -IssuedVia 'system'
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:DevA)
        $body2 = ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $cmd2; ok = $true }
        (Invoke-TestResult -Body $body2 -Send $send).Status | Should -Be 200
        $script:Sent.Count | Should -Be 1
    }
}

Describe 'Invoke-ScgEventIngest' {
    BeforeEach { Reset-TestState }
    It 'stores an event and audits it' {
        $id = Register-TestDevice
        $r = Invoke-TestEvent -Body (ConvertTo-TestBody @{ device_id = $id; type = 'tamper'; severity = 'critical'; payload = @{ agent = $script:IdA } })
        $r.Status | Should -Be 200
        @(Get-ScgEvent -Path $script:Db -Last 10).Count | Should -Be 1
        @(@(Get-ScgAudit -Path $script:Db -Last 20) | Where-Object { $_.action -eq 'event.ingest' }).Count | Should -Be 1
    }
    It 'dedupes a repeated identical event yet still answers ok' {
        $id = Register-TestDevice
        $body = ConvertTo-TestBody @{ device_id = $id; type = 'service_down'; severity = 'warn'; payload = @{ service = 'x' } }
        (Invoke-TestEvent -Body $body).Status | Should -Be 200
        $again = Invoke-TestEvent -Body $body
        $again.Status | Should -Be 200
        $again.Body.ok | Should -BeTrue
        @(Get-ScgEvent -Path $script:Db -Last 10).Count | Should -Be 1
    }
    It 'answers 400 for a bad type, bad severity or missing device_id' {
        $id = Register-TestDevice
        (Invoke-TestEvent -Body (ConvertTo-TestBody @{ device_id = $id; type = 'bogus'; severity = 'warn' })).Status | Should -Be 400
        (Invoke-TestEvent -Body (ConvertTo-TestBody @{ device_id = $id; type = 'tamper'; severity = 'huge' })).Status | Should -Be 400
        (Invoke-TestEvent -Body (ConvertTo-TestBody @{ type = 'tamper'; severity = 'warn' })).Status | Should -Be 400
    }
    It 'answers 404 for an unknown device' {
        (Invoke-TestEvent -Body (ConvertTo-TestBody @{ device_id = 'ghost'; type = 'tamper'; severity = 'warn' })).Status | Should -Be 404
    }
}

Describe 'Get-ScgHealth' {
    BeforeEach { Reset-TestState }
    It 'reports version, uptime and counters' {
        $id = Register-TestDevice
        [void](New-ScgCommand -Path $script:Db -DeviceId $id -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system')
        $r = Get-ScgHealth -Config $script:Cfg
        $r.Status | Should -Be 200
        $r.Body.ok | Should -BeTrue
        $r.Body.version | Should -Not -BeNullOrEmpty
        $r.Body.uptime_sec | Should -BeGreaterOrEqual 0
        $r.Body.devices_online | Should -Be 1
        $r.Body.commands_pending | Should -Be 1
    }
}

Describe 'Invoke-ScgHubTick' {
    BeforeEach { Reset-TestState }
    It 'marks devices stale after stale_after_min' {
        $id = Register-TestDevice
        [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE devices SET last_seen=@t WHERE id=@id' -Parameter @{ t = '2020-01-01T00:00:00.000Z'; id = $id })
        $r = Invoke-ScgHubTick -Config $script:Cfg
        $r.stale | Should -Be 1
        (@(Get-ScgDevice -Path $script:Db -DeviceId $id))[0].status | Should -Be 'stale'
    }
    It 'times out old dispatched commands and audits command.timeout' {
        $cfg0 = New-TestConfig -Db $script:Db -TimeoutSec 1
        $id = Register-TestDevice
        [void](New-ScgCommand -Path $script:Db -DeviceId $id -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system')
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $id)
        Start-Sleep -Milliseconds 1300
        $r = Invoke-ScgHubTick -Config $cfg0
        $r.timeouts | Should -Be 1
        @(@(Get-ScgAudit -Path $script:Db -Last 20) | Where-Object { $_.action -eq 'command.timeout' }).Count | Should -Be 1
    }
    It 'leaves fresh commands and devices alone' {
        $id = Register-TestDevice
        [void](New-ScgCommand -Path $script:Db -DeviceId $id -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system')
        $r = Invoke-ScgHubTick -Config $script:Cfg
        $r.stale | Should -Be 0
        $r.timeouts | Should -Be 0
    }
}

Describe 'Start-ScgHub hardening hooks' {
    It 'secures the database and log directories only when Initialize-ScgSecureDirectory exists' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\modules\Hub.psm1') -Raw
        $src | Should -Match "Get-Command -Name 'Initialize-ScgSecureDirectory' -ErrorAction SilentlyContinue"
        $src | Should -Match 'Initialize-ScgSecureDirectory -Path \$d'
        $src | Should -Match 'foreach \(\$d in @\(\$dbDir, \$logDir\)\)'
    }
}

Describe 'Hub routes through Invoke-ScgRequestPipeline' {
    BeforeEach {
        Reset-TestState
        $script:Routes = New-ScgHubRoute -Config $script:Cfg
        $script:Cache = New-ScgReplayCache
    }
    It 'exposes the five endpoints' {
        ($script:Routes.Keys | Sort-Object) -join ',' | Should -Be 'GET /health,POST /enroll,POST /event,POST /heartbeat,POST /result'
    }
    It 'enrolls, heartbeats and reads health with auth and replay protection' {
        $enroll = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/enroll' -Headers (New-TestHeader) -Body '{"hostname":"PC-9","os":"Windows","os_version":"10","agent_version":"4.0.0"}' -RemoteIp '10.0.0.9' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache
        $enroll.Status | Should -Be 200
        $id = $enroll.Body.device_id
        $hbBody = (@{ device_id = $id; hostname = 'PC-9'; sc_agents = @(); uptime_sec = 3; agent_version = '4.0.0' } | ConvertTo-Json -Compress)
        $hb = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (Get-TestDeviceHeader -Token $enroll.Body.device_token) -Body $hbBody -RemoteIp '10.0.0.9' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache
        $hb.Status | Should -Be 200
        @($hb.Body.commands).Count | Should -Be 0
        $health = Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/health' -Headers (New-TestHeader) -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache
        $health.Status | Should -Be 200
        $health.Body.devices_online | Should -Be 1
    }
    It 'rejects a bad bearer with 401 and a replayed nonce with 409' {
        $bad = Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/health' -Headers (New-TestHeader -Bearer 'wrong') -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache
        $bad.Status | Should -Be 401
        $h = New-TestHeader
        (Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/health' -Headers $h -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache).Status | Should -Be 200
        (Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/health' -Headers $h -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache).Status | Should -Be 409
    }
    It 'maps handler errors to the registry statuses' {
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -Body '{"device_id":"ghost","hostname":"X","sc_agents":[]}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache
        $r.Status | Should -Be 404
        $r2 = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/enroll' -Headers (New-TestHeader) -Body '{"hostname":"only"}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache
        $r2.Status | Should -Be 400
    }
    It 'enforces device tokens end to end on heartbeat, event and result and 409 on re-enroll' {
        $pipe = @{ Secret = $script:Secret; Route = $script:Routes; ReplayCache = $script:Cache; RemoteIp = '10.0.0.9' }
        $ea = Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/enroll' -Headers (New-TestHeader) -Body '{"hostname":"PC-A","os":"Windows","os_version":"10","agent_version":"4.0.0"}'
        $eb = Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/enroll' -Headers (New-TestHeader) -Body '{"hostname":"PC-B","os":"Windows","os_version":"10","agent_version":"4.0.0"}'
        $ea.Status | Should -Be 200
        $eb.Status | Should -Be 200
        $idA = [string]$ea.Body.device_id
        $tokA = [string]$ea.Body.device_token
        $tokB = [string]$eb.Body.device_token
        $hbA = (@{ device_id = $idA; hostname = 'PC-A'; sc_agents = @() } | ConvertTo-Json -Compress)
        $evA = (@{ device_id = $idA; type = 'tamper'; severity = 'warn'; payload = @{ detail = 'x' } } | ConvertTo-Json -Compress)

        $noTok = Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -Body $hbA
        $noTok.Status | Should -Be 401
        $noTok.Body.error | Should -BeExactly 'invalid device token'
        (Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/heartbeat' -Headers (Get-TestDeviceHeader -Token $tokB) -Body $hbA).Status | Should -Be 401
        (Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/event' -Headers (Get-TestDeviceHeader -Token $tokB) -Body $evA).Status | Should -Be 401
        @(Get-ScgEvent -Path $script:Db -Last 10).Count | Should -Be 0

        $cmd = New-ScgCommand -Path $script:Db -DeviceId $idA -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system'
        $ok = Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/heartbeat' -Headers (Get-TestDeviceHeader -Token $tokA) -Body $hbA
        $ok.Status | Should -Be 200
        @($ok.Body.commands).Count | Should -Be 1
        $resA = (@{ device_id = $idA; command_id = $cmd; ok = $true; output = 'pong'; duration_ms = 3 } | ConvertTo-Json -Compress)
        (Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/result' -Headers (Get-TestDeviceHeader -Token $tokB) -Body $resA).Status | Should -Be 401
        (Get-ScgCommand -Path $script:Db -CommandId $cmd).status | Should -Be 'dispatched'
        (Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/result' -Headers (Get-TestDeviceHeader -Token $tokA) -Body $resA).Status | Should -Be 200
        (Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/event' -Headers (Get-TestDeviceHeader -Token $tokA) -Body $evA).Status | Should -Be 200

        $again = Invoke-ScgRequestPipeline @pipe -Method POST -Path '/api/v1/enroll' -Headers (New-TestHeader) -Body '{"hostname":"PC-A","os":"Windows","os_version":"10","agent_version":"4.0.1"}'
        $again.Status | Should -Be 409
        $again.Body.error | Should -BeExactly 'hostname already enrolled'
        $dump = (@(Get-ScgAudit -Path $script:Db -Last 200) | ConvertTo-Json -Depth 4 -Compress)
        $dump.Contains($tokA) | Should -BeFalse
        $dump.Contains($tokB) | Should -BeFalse
    }
}

Describe 'Device token enforcement' {
    BeforeEach {
        Reset-TestState
        $script:DevA = Register-TestDevice -Name 'PC-A'
        $script:DevB = Register-TestDevice -Name 'PC-B'
        $script:TokB = $script:Tokens[$script:DevB]
        $script:CmdA = New-ScgCommand -Path $script:Db -DeviceId $script:DevA -Type 'ping' -Payload $null -IssuedBy 'system' -IssuedVia 'system'
        $script:OldSeen = '2020-01-01T00:00:00.000Z'
        [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE devices SET last_seen=@t WHERE id=@id' -Parameter @{ t = $script:OldSeen; id = $script:DevA })
    }
    It 'rejects device B token for device A on heartbeat without any state change' {
        $one = @{ id = $script:IdA; service = 's'; folder = 'f'; uninstall_key = 'k'; state = 'Running' }
        $body = ConvertTo-TestBody @{ device_id = $script:DevA; hostname = 'RENAMED'; sc_agents = @($one) }
        $r = Invoke-ScgHeartbeat -Config $script:Cfg -Body $body -RemoteIp '10.9.9.9' -Headers @{ 'X-SCG-Device-Token' = $script:TokB }
        $r.Status | Should -Be 401
        $r.Body.error | Should -BeExactly 'invalid device token'
        $row = (@(Get-ScgDevice -Path $script:Db -DeviceId $script:DevA))[0]
        $row.last_seen | Should -Be $script:OldSeen
        $row.last_ip | Should -Be '10.0.0.5'
        @(Get-ScgScAgent -Path $script:Db -DeviceId $script:DevA).Count | Should -Be 0
        (Get-ScgCommand -Path $script:Db -CommandId $script:CmdA).status | Should -Be 'pending'
        @(@(Get-ScgAudit -Path $script:Db -Last 50) | Where-Object { $_.action -eq 'heartbeat.config_change' }).Count | Should -Be 0
        Get-TestRejectReason | Should -Contain 'bad_device_token'
    }
    It 'rejects device B token for device A on result and event' {
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:DevA)
        $res = Invoke-ScgResult -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = $true }) -Headers @{ 'X-SCG-Device-Token' = $script:TokB }
        $res.Status | Should -Be 401
        $res.Body.error | Should -BeExactly 'invalid device token'
        (Get-ScgCommand -Path $script:Db -CommandId $script:CmdA).status | Should -Be 'dispatched'
        $ev = Invoke-ScgEventIngest -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = $script:DevA; type = 'tamper'; severity = 'warn' }) -Headers @{ 'X-SCG-Device-Token' = $script:TokB }
        $ev.Status | Should -Be 401
        $ev.Body.error | Should -BeExactly 'invalid device token'
        @(Get-ScgEvent -Path $script:Db -Last 10).Count | Should -Be 0
        @(Get-TestRejectReason | Where-Object { $_ -eq 'bad_device_token' }).Count | Should -Be 2
    }
    It 'answers 401 for a missing or empty device token header on all three endpoints' {
        [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:DevA)
        $hb = ConvertTo-TestBody @{ device_id = $script:DevA; hostname = 'PC-A'; sc_agents = @() }
        $res = ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = $true }
        $ev = ConvertTo-TestBody @{ device_id = $script:DevA; type = 'tamper'; severity = 'warn' }
        foreach ($hdr in @($null, @{}, @{ 'X-SCG-Device-Token' = '' })) {
            $r1 = Invoke-ScgHeartbeat -Config $script:Cfg -Body $hb -Headers $hdr
            $r2 = Invoke-ScgResult -Config $script:Cfg -Body $res -Headers $hdr
            $r3 = Invoke-ScgEventIngest -Config $script:Cfg -Body $ev -Headers $hdr
            foreach ($r in @($r1, $r2, $r3)) {
                $r.Status | Should -Be 401
                $r.Body.error | Should -BeExactly 'invalid device token'
            }
        }
        (Invoke-ScgHeartbeat -Config $script:Cfg -Body $hb).Status | Should -Be 401
        (Get-ScgCommand -Path $script:Db -CommandId $script:CmdA).status | Should -Be 'dispatched'
        @(Get-ScgEvent -Path $script:Db -Last 10).Count | Should -Be 0
        (@(Get-ScgDevice -Path $script:Db -DeviceId $script:DevA))[0].last_seen | Should -Be $script:OldSeen
    }
    It 'answers 401 device not enrolled on all three endpoints after a reset' {
        $tokA = $script:Tokens[$script:DevA]
        [void](Clear-ScgDeviceToken -Path $script:Db -DeviceId $script:DevA)
        $h = @{ 'X-SCG-Device-Token' = $tokA }
        $r1 = Invoke-ScgHeartbeat -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = $script:DevA; hostname = 'PC-A'; sc_agents = @() }) -Headers $h
        $r2 = Invoke-ScgResult -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = $script:DevA; command_id = $script:CmdA; ok = $true }) -Headers $h
        $r3 = Invoke-ScgEventIngest -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = $script:DevA; type = 'tamper'; severity = 'warn' }) -Headers $h
        foreach ($r in @($r1, $r2, $r3)) {
            $r.Status | Should -Be 401
            $r.Body.error | Should -BeExactly 'device not enrolled'
        }
        @(Get-TestRejectReason | Where-Object { $_ -eq 'device_not_enrolled' }).Count | Should -Be 3
    }
    It 'answers 404 unknown device before checking the token' {
        $r = Invoke-ScgHeartbeat -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = 'ghost'; hostname = 'X'; sc_agents = @() }) -Headers @{ 'X-SCG-Device-Token' = $script:TokB }
        $r.Status | Should -Be 404
        $r.Body.error | Should -BeExactly 'unknown device'
    }
    It 'accepts the header name in any case and never writes the token to the audit log' {
        $tokA = $script:Tokens[$script:DevA]
        $nvc = New-Object System.Collections.Specialized.NameValueCollection
        $nvc.Add('x-scg-device-token', $tokA)
        (Invoke-ScgHeartbeat -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = $script:DevA; hostname = 'PC-A'; sc_agents = @() }) -Headers $nvc).Status | Should -Be 200
        [void](Invoke-ScgEventIngest -Config $script:Cfg -Body (ConvertTo-TestBody @{ device_id = $script:DevA; type = 'tamper'; severity = 'warn' }) -Headers @{ 'X-SCG-Device-Token' = $script:TokB })
        $dump = (@(Get-ScgAudit -Path $script:Db -Last 200) | ConvertTo-Json -Depth 4 -Compress)
        $dump.Contains($tokA) | Should -BeFalse
        $dump.Contains($script:TokB) | Should -BeFalse
    }
}
