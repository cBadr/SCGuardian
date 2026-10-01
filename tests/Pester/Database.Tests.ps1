# Purpose: Pester 5 tests for Database.psm1 | Author: Badr | Version: 4.0.0

BeforeAll {
    $env:SCG_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '..\..\src\modules\Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\..\src\modules\Database.psm1') -Force

    function Add-TestDevice {
        param([string]$Db, [string]$Id, [string]$Status, [string]$Seen)
        [void](Invoke-ScgSql -Path $Db -NonQuery -Sql 'INSERT INTO devices (id, hostname, first_seen, last_seen, status) VALUES (@id, @h, @s, @s, @st)' -Parameter @{ id = $Id; h = ('host-' + $Id); s = $Seen; st = $Status })
    }
    function Add-TestAgent {
        param([string]$Db, [string]$Dev, [string]$Id, [int]$Auth, [object]$State)
        [void](Invoke-ScgSql -Path $Db -NonQuery -Sql 'INSERT INTO sc_agents (id, device_id, authorized, state, first_seen, last_seen) VALUES (@id, @d, @a, @st, @t, @t)' -Parameter @{ id = $Id; d = $Dev; a = $Auth; st = $State; t = '2026-06-15T00:00:00.000Z' })
    }
    function Add-TestCommand {
        param([string]$Db, [string]$Id, [string]$Dev, [string]$Status, [string]$Created, [object]$Finished)
        [void](Invoke-ScgSql -Path $Db -NonQuery -Sql 'INSERT INTO commands (id, device_id, type, status, created_at, finished_at) VALUES (@id, @d, ''ping'', @st, @c, @f)' -Parameter @{ id = $Id; d = $Dev; st = $Status; c = $Created; f = $Finished })
    }
    function Add-TestEvent {
        param([string]$Db, [string]$Dev, [string]$Sev, [string]$Created, [object]$Acked)
        [void](Invoke-ScgSql -Path $Db -NonQuery -Sql 'INSERT INTO events (device_id, type, severity, created_at, acked_at) VALUES (@d, ''tamper'', @s, @c, @a)' -Parameter @{ d = $Dev; s = $Sev; c = $Created; a = $Acked })
    }
}

Describe 'Database' {
    BeforeEach {
        $script:Db = Join-Path $TestDrive ('t' + [guid]::NewGuid().ToString('N') + '.db')
        [void](Initialize-ScgDatabase -Path $script:Db)
        $script:Old = ConvertTo-ScgUtcIso -InputObject ([datetime]::UtcNow.AddHours(-2))
    }

    Context 'Migrations' {
        It 'applies migrations 1 to 3 and records schema_version' {
            Get-ScgSchemaVersion -Path $script:Db | Should -Be 3
            $cols = @(Invoke-ScgSql -Path $script:Db -Sql "SELECT name FROM pragma_table_info('devices')" | ForEach-Object { $_.name })
            $cols | Should -Contain 'token_hash'
            $t = @(Invoke-ScgSql -Path $script:Db -Sql "SELECT name FROM sqlite_master WHERE type='table'" | ForEach-Object { $_.name })
            foreach ($n in 'schema_version', 'devices', 'sc_agents', 'commands', 'events', 'audit_log') {
                $t | Should -Contain $n
            }
            $i = @(Invoke-ScgSql -Path $script:Db -Sql "SELECT name FROM sqlite_master WHERE type='index'" | ForEach-Object { $_.name })
            foreach ($n in 'idx_devices_last_seen', 'idx_sc_agents_device', 'idx_commands_device_status', 'idx_events_created', 'idx_events_acked', 'idx_audit_ts') {
                $i | Should -Contain $n
            }
        }
        It 'is idempotent' {
            Invoke-ScgMigration -Path $script:Db | Should -Be 3
            Invoke-ScgMigration -Path $script:Db | Should -Be 3
            $r = @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT COUNT(*) AS n FROM schema_version')
            $r[0].n | Should -Be 3
        }
        It 'migration 3 skips the column when it already exists' {
            $old = Join-Path $TestDrive ('m' + [guid]::NewGuid().ToString('N') + '.db')
            [void](Initialize-ScgDatabase -Path $old)
            [void](Invoke-ScgSql -Path $old -NonQuery -Sql 'DELETE FROM schema_version WHERE version=3')
            Invoke-ScgMigration -Path $old | Should -Be 3
            @(Invoke-ScgSql -Path $old -Sql "SELECT name FROM pragma_table_info('devices') WHERE name='token_hash'").Count | Should -Be 1
        }
        It 'enables foreign keys per connection' {
            $r = @(Invoke-ScgSql -Path $script:Db -Sql 'PRAGMA foreign_keys')
            $r[0].foreign_keys | Should -Be 1
        }
    }

    Context 'Devices' {
        It 'returns the same id on re-enroll' {
            $a = Register-ScgDevice -Path $script:Db -Hostname 'PC1' -Os 'Windows' -OsVersion '10' -AgentVersion '4.0.0'
            $b = Register-ScgDevice -Path $script:Db -Hostname 'PC1' -Os 'Windows' -OsVersion '11' -AgentVersion '4.0.1'
            $b.id | Should -Be $a.id
            $b.os_version | Should -Be '11'
            $b.status | Should -Be 'active'
            @(Get-ScgDevice -Path $script:Db).Count | Should -Be 1
        }
        It 'stores and clears the token hash and keeps the id on re-register' {
            $a = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            $a.PSObject.Properties.Name | Should -Contain 'token_hash'
            $a.token_hash | Should -BeNullOrEmpty
            $h = ('AB' * 32)
            Set-ScgDeviceToken -Path $script:Db -DeviceId $a.id -TokenHash $h -IfUnset | Should -BeTrue
            Set-ScgDeviceToken -Path $script:Db -DeviceId $a.id -TokenHash ('cd' * 32) -IfUnset | Should -BeFalse
            @(Get-ScgDevice -Path $script:Db -DeviceId $a.id)[0].token_hash | Should -BeExactly ('ab' * 32)
            $b = Register-ScgDevice -Path $script:Db -Hostname 'PC1' -Os 'Windows'
            $b.id | Should -Be $a.id
            $b.token_hash | Should -BeExactly ('ab' * 32)
            Clear-ScgDeviceToken -Path $script:Db -DeviceId $a.id | Should -BeTrue
            @(Get-ScgDevice -Path $script:Db -Hostname 'PC1')[0].token_hash | Should -BeNullOrEmpty
            Clear-ScgDeviceToken -Path $script:Db -DeviceId 'nope' | Should -BeFalse
            Set-ScgDeviceToken -Path $script:Db -DeviceId 'nope' -TokenHash $h | Should -BeFalse
            { Set-ScgDeviceToken -Path $script:Db -DeviceId $a.id -TokenHash 'plain-token' } | Should -Throw
        }
        It 'updates seen and status, and looks up by id prefix' {
            $a = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            Set-ScgDeviceStatus -Path $script:Db -DeviceId $a.id -Status quarantined | Should -BeTrue
            @(Get-ScgDevice -Path $script:Db -DeviceId $a.id)[0].status | Should -Be 'quarantined'
            Update-ScgDeviceSeen -Path $script:Db -DeviceId $a.id -AgentVersion '9.9' -ConfigJson '{"x":1}' | Should -BeTrue
            $d = @(Get-ScgDevice -Path $script:Db -DeviceId $a.id)[0]
            $d.agent_version | Should -Be '9.9'
            $d.config_json | Should -Be '{"x":1}'
            $d.hostname | Should -Be 'PC1'
            @(Get-ScgDevice -Path $script:Db -IdPrefix $a.id.Substring(0, 8)).Count | Should -Be 1
            Update-ScgDeviceSeen -Path $script:Db -DeviceId 'nope' | Should -BeFalse
        }
        It 'never renames on seen unless -Rename is given and reports online state' {
            $a = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            $b = Register-ScgDevice -Path $script:Db -Hostname 'PC2'
            Update-ScgDeviceSeen -Path $script:Db -DeviceId $b.id -Hostname 'PC1' | Should -BeTrue
            @(Get-ScgDevice -Path $script:Db -DeviceId $b.id)[0].hostname | Should -Be 'PC2'
            Update-ScgDeviceSeen -Path $script:Db -DeviceId $b.id -Hostname 'PC3' -Rename | Should -BeTrue
            @(Get-ScgDevice -Path $script:Db -DeviceId $b.id)[0].hostname | Should -Be 'PC3'
            Test-ScgDeviceOnline -Path $script:Db -DeviceId $a.id -StaleAfterMin 5 | Should -BeTrue
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE devices SET last_seen=@t WHERE id=@id' -Parameter @{ t = $script:Old; id = $a.id })
            Test-ScgDeviceOnline -Path $script:Db -DeviceId $a.id -StaleAfterMin 5 | Should -BeFalse
            Test-ScgDeviceOnline -Path $script:Db -DeviceId 'nope' -StaleAfterMin 5 | Should -BeFalse
        }
        It 'returns the newest audit row for an action and target' {
            Get-ScgLastAudit -Path $script:Db -Action 'heartbeat.config_change' -Target 'd1' | Should -BeNullOrEmpty
            Add-ScgAudit -Path $script:Db -Actor 'system' -Action 'heartbeat.config_change' -Target 'd1' -Meta '{"n":1}'
            Add-ScgAudit -Path $script:Db -Actor 'system' -Action 'heartbeat.config_change' -Target 'd1' -Meta '{"n":2}'
            Add-ScgAudit -Path $script:Db -Actor 'system' -Action 'heartbeat.config_change' -Target 'd2' -Meta '{"n":3}'
            (Get-ScgLastAudit -Path $script:Db -Action 'heartbeat.config_change' -Target 'd1').meta_json | Should -Be '{"n":2}'
        }
        It 'marks stale devices and reactivates on seen' {
            $a = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            $b = Register-ScgDevice -Path $script:Db -Hostname 'PC2'
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE devices SET last_seen=@t WHERE id=@id' -Parameter @{ t = $script:Old; id = $a.id })
            Set-ScgStaleDevice -Path $script:Db -StaleAfterMin 30 | Should -Be 1
            @(Get-ScgDevice -Path $script:Db -DeviceId $a.id)[0].status | Should -Be 'stale'
            @(Get-ScgDevice -Path $script:Db -DeviceId $b.id)[0].status | Should -Be 'active'
            $h = Get-ScgHealthCounts -Path $script:Db -StaleAfterMin 30
            $h.devices_online | Should -Be 1
            [void](Update-ScgDeviceSeen -Path $script:Db -DeviceId $a.id)
            @(Get-ScgDevice -Path $script:Db -DeviceId $a.id)[0].status | Should -Be 'active'
        }
    }

    Context 'sc_agents' {
        It 'upserts, sets authorized and deletes missing in one sync' {
            $dev = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            $a1 = [pscustomobject]@{ id = '0123456789abcdef'; service = 'SvcA'; folder = 'C:\A'; uninstall_key = 'ka'; state = 'Running' }
            $a2 = @{ id = 'fedcba9876543210'; service = 'SvcB'; folder = 'C:\B'; uninstall_key = 'kb'; state = 'Stopped' }
            Sync-ScgScAgent -Path $script:Db -DeviceId $dev.id -ScAgent @($a1, $a2) -AllowedId @('0123456789ABCDEF')
            $rows = @(Get-ScgScAgent -Path $script:Db -DeviceId $dev.id)
            $rows.Count | Should -Be 2
            (@($rows | Where-Object { $_.id -eq '0123456789abcdef' })[0]).authorized | Should -Be 1
            (@($rows | Where-Object { $_.id -eq 'fedcba9876543210' })[0]).authorized | Should -Be 0

            $a1.state = 'Stopped'
            Sync-ScgScAgent -Path $script:Db -DeviceId $dev.id -ScAgent @($a1) -AllowedId @()
            $rows = @(Get-ScgScAgent -Path $script:Db -DeviceId $dev.id)
            $rows.Count | Should -Be 1
            $rows[0].state | Should -Be 'Stopped'
            $rows[0].authorized | Should -Be 0

            Sync-ScgScAgent -Path $script:Db -DeviceId $dev.id -ScAgent @() -AllowedId @()
            @(Get-ScgScAgent -Path $script:Db -DeviceId $dev.id).Count | Should -Be 1
            Sync-ScgScAgent -Path $script:Db -DeviceId $dev.id -ScAgent @() -AllowedId @() -AllowEmpty
            @(Get-ScgScAgent -Path $script:Db -DeviceId $dev.id).Count | Should -Be 0
        }
        It 'keeps separate rows when two devices report the same id' {
            $d1 = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            $d2 = Register-ScgDevice -Path $script:Db -Hostname 'PC2'
            Sync-ScgScAgent -Path $script:Db -DeviceId $d1.id -ScAgent @(@{ id = '0123456789abcdef'; service = 'S1'; state = 'Running' }) -AllowedId @('0123456789abcdef')
            Sync-ScgScAgent -Path $script:Db -DeviceId $d2.id -ScAgent @(@{ id = '0123456789abcdef'; service = 'S2'; state = 'Stopped' }) -AllowedId @()
            $r1 = @(Get-ScgScAgent -Path $script:Db -DeviceId $d1.id)
            $r2 = @(Get-ScgScAgent -Path $script:Db -DeviceId $d2.id)
            $r1.Count | Should -Be 1
            $r2.Count | Should -Be 1
            $r1[0].state | Should -Be 'Running'
            $r1[0].authorized | Should -Be 1
            $r2[0].state | Should -Be 'Stopped'
            $r2[0].authorized | Should -Be 0
            Sync-ScgScAgent -Path $script:Db -DeviceId $d2.id -ScAgent @() -AllowedId @() -AllowEmpty
            @(Get-ScgScAgent -Path $script:Db -DeviceId $d1.id).Count | Should -Be 1
            @(Get-ScgScAgent -Path $script:Db -DeviceId $d2.id).Count | Should -Be 0
        }
        It 'rebuilds an old-schema sc_agents table in migration 2' {
            $old = Join-Path $TestDrive ('o' + [guid]::NewGuid().ToString('N') + '.db')
            $ddl = @(
                'CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)',
                "INSERT INTO schema_version (version, applied_at) VALUES (1, '2026-01-01T00:00:00.000Z')",
                'CREATE TABLE devices (id TEXT PRIMARY KEY, hostname TEXT NOT NULL UNIQUE, os TEXT, os_version TEXT, last_ip TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT ''active'', agent_version TEXT, tags TEXT, config_json TEXT)',
                "INSERT INTO devices (id, hostname, first_seen, last_seen) VALUES ('d1', 'PC1', 'x', 'x')",
                'CREATE TABLE sc_agents (id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, service_name TEXT, folder TEXT, uninstall_key TEXT, authorized INTEGER NOT NULL DEFAULT 0, state TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)',
                'CREATE INDEX idx_sc_agents_device ON sc_agents(device_id)',
                "INSERT INTO sc_agents (id, device_id, service_name, authorized, state, first_seen, last_seen) VALUES ('0123456789abcdef', 'd1', 'S', 1, 'Running', 'x', 'x')"
            )
            foreach ($s in $ddl) { [void](Invoke-ScgSql -Path $old -NonQuery -Sql $s) }
            Invoke-ScgMigration -Path $old | Should -Be 3
            Invoke-ScgMigration -Path $old | Should -Be 3
            $rows = @(Get-ScgScAgent -Path $old -DeviceId 'd1')
            $rows.Count | Should -Be 1
            $rows[0].state | Should -Be 'Running'
            $rows[0].authorized | Should -Be 1
            $pk = @(Invoke-ScgSql -Path $old -Sql "SELECT name, pk FROM pragma_table_info('sc_agents') WHERE pk > 0 ORDER BY pk" | ForEach-Object { $_.name })
            ($pk -join ',') | Should -Be 'device_id,id'
            $i = @(Invoke-ScgSql -Path $old -Sql "SELECT name FROM sqlite_master WHERE type='index'" | ForEach-Object { $_.name })
            $i | Should -Contain 'idx_sc_agents_device'
        }
        It 'cascades on device delete' {
            $dev = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            Sync-ScgScAgent -Path $script:Db -DeviceId $dev.id -ScAgent @(@{ id = '0123456789abcdef'; service = 'S' }) -AllowedId @()
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'DELETE FROM devices WHERE id=@id' -Parameter @{ id = $dev.id })
            @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT id FROM sc_agents').Count | Should -Be 0
        }
    }

    Context 'Commands' {
        BeforeEach {
            $script:Dev = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
        }
        It 'dedupes identical pending commands' {
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type harden -Payload '{"l":1}' -IssuedBy 'telegram:1' -IssuedVia telegram
            $b = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type harden -Payload '{"l":1}' -IssuedBy 'telegram:1' -IssuedVia telegram
            $b | Should -Be $a
            $c = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type harden -Payload '{"l":2}' -IssuedBy 'telegram:1' -IssuedVia telegram
            $c | Should -Not -Be $a
            @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT id FROM commands').Count | Should -Be 2
        }
        It 'dedupes against dispatched but not finished commands' {
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type ping -Payload $null
            [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:Dev.id)
            (New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type ping -Payload $null) | Should -Be $a
            Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $true -Output 'pong' -DurationMs 5
            (New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type ping -Payload $null) | Should -Not -Be $a
        }
        It 'dispatches each command exactly once' {
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type status -Payload '{}'
            $first = @(Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:Dev.id)
            $first.Count | Should -Be 1
            $first[0].id | Should -Be $a
            $first[0].status | Should -Be 'dispatched'
            @(Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:Dev.id).Count | Should -Be 0
        }
        It 'completes dispatched as done or failed with result_json' {
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type status -Payload '{}'
            $b = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type agents -Payload '{}'
            [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:Dev.id)
            Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $true -Output 'fine' -DurationMs 10
            Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $b -Ok $false -Output 'bad' -DurationMs 20
            $ra = @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT * FROM commands WHERE id=@id' -Parameter @{ id = $a })[0]
            $rb = @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT * FROM commands WHERE id=@id' -Parameter @{ id = $b })[0]
            $ra.status | Should -Be 'done'
            $rb.status | Should -Be 'failed'
            $ra.finished_at | Should -Not -BeNullOrEmpty
            ($ra.result_json | ConvertFrom-Json).output | Should -Be 'fine'
        }
        It 'Get-ScgCommand returns the full row or null' {
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type agents -Payload '{"x":1}'
            $row = Get-ScgCommand -Path $script:Db -CommandId $a -DeviceId $script:Dev.id
            $row.type | Should -Be 'agents'
            $row.status | Should -Be 'pending'
            $row.device_id | Should -Be $script:Dev.id
            $row.payload_json | Should -Be '{"x":1}'
            (Get-ScgCommand -Path $script:Db -CommandId $a).id | Should -Be $a
            [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:Dev.id)
            Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $true -Output 'o' -DurationMs 1
            $done = Get-ScgCommand -Path $script:Db -CommandId $a -DeviceId $script:Dev.id
            $done.status | Should -Be 'done'
            ($done.result_json | ConvertFrom-Json).output | Should -Be 'o'
            Get-ScgCommand -Path $script:Db -CommandId 'missing' -DeviceId $script:Dev.id | Should -BeNullOrEmpty
            Get-ScgCommand -Path $script:Db -CommandId $a -DeviceId 'other' | Should -BeNullOrEmpty
        }
        It 'never lets another device dispatch or complete a command' {
            $other = Register-ScgDevice -Path $script:Db -Hostname 'PC2'
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type ping -Payload '{}'
            @(Get-ScgDispatchableCommand -Path $script:Db -DeviceId $other.id).Count | Should -Be 0
            (Get-ScgCommand -Path $script:Db -CommandId $a).status | Should -Be 'pending'
            @(Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:Dev.id).Count | Should -Be 1
            { Complete-ScgCommand -Path $script:Db -DeviceId $other.id -CommandId $a -Ok $true -Output 'x' -DurationMs 1 } | Should -Throw '*not found*'
            (Get-ScgCommand -Path $script:Db -CommandId $a).status | Should -Be 'dispatched'
            Get-ScgCommand -Path $script:Db -CommandId $a -DeviceId $other.id | Should -BeNullOrEmpty
        }
        It 'rejects illegal transitions' {
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type status -Payload '{}'
            { Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $true -Output 'x' -DurationMs 1 } | Should -Throw
            [void](Get-ScgDispatchableCommand -Path $script:Db -DeviceId $script:Dev.id)
            Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $true -Output 'x' -DurationMs 1
            { Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $false -Output 'x' -DurationMs 1 } | Should -Throw
            { Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $true -Output 'x' -DurationMs 1 } | Should -Throw
            @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT status FROM commands WHERE id=@id' -Parameter @{ id = $a })[0].status | Should -Be 'done'
        }
        It 'rejects timeout to done and wrong device or unknown command' {
            $a = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type status -Payload '{}'
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE commands SET created_at=@t WHERE id=@id' -Parameter @{ t = $script:Old; id = $a })
            Invoke-ScgCommandTimeout -Path $script:Db -TimeoutSec 60 | Should -Be 1
            { Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId $a -Ok $true -Output 'x' -DurationMs 1 } | Should -Throw
            { Complete-ScgCommand -Path $script:Db -DeviceId 'other' -CommandId $a -Ok $true -Output 'x' -DurationMs 1 } | Should -Throw
            { Complete-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -CommandId 'missing' -Ok $true -Output 'x' -DurationMs 1 } | Should -Throw
        }
        It 'times out dispatched and pending commands past the threshold only' {
            $fresh = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type ping -Payload '{}'
            $disp = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type status -Payload '{}'
            $pend = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type agents -Payload '{}'
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql "UPDATE commands SET status='dispatched', dispatched_at=@t WHERE id=@id" -Parameter @{ t = $script:Old; id = $disp })
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE commands SET created_at=@t WHERE id=@id' -Parameter @{ t = $script:Old; id = $pend })
            Invoke-ScgCommandTimeout -Path $script:Db -TimeoutSec 300 | Should -Be 2
            $st = @{}
            foreach ($r in @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT id, status FROM commands')) { $st[$r.id] = $r.status }
            $st[$fresh] | Should -Be 'pending'
            $st[$disp] | Should -Be 'timeout'
            $st[$pend] | Should -Be 'timeout'
            Invoke-ScgCommandTimeout -Path $script:Db -TimeoutSec 300 | Should -Be 0
        }
        It 'counts pending commands in health' {
            [void](New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type ping -Payload '{}')
            (Get-ScgHealthCounts -Path $script:Db -StaleAfterMin 30).commands_pending | Should -Be 1
        }
        It 'validates the command type' {
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type 'explode' -Payload '{}' } | Should -Throw
        }
    }

    Context 'Events' {
        It 'dedupes identical unacked events within the throttle window' {
            $a = Add-ScgEvent -Path $script:Db -DeviceId 'd1' -Type tamper -Severity critical -Payload '{"k":1}' -ThrottleMin 30
            $a | Should -BeGreaterThan 0
            Add-ScgEvent -Path $script:Db -DeviceId 'd1' -Type tamper -Severity critical -Payload '{"k":1}' -ThrottleMin 30 | Should -BeNullOrEmpty
            $c = Add-ScgEvent -Path $script:Db -DeviceId 'd1' -Type tamper -Severity critical -Payload '{"k":2}' -ThrottleMin 30
            $c | Should -BeGreaterThan $a
        }
        It 'does not dedupe once acked or outside the window' {
            $a = Add-ScgEvent -Path $script:Db -DeviceId 'd1' -Type agent_error -Severity warn -Payload '{}' -ThrottleMin 30
            Confirm-ScgEvent -Path $script:Db -Id $a -By 'telegram:1' | Should -BeTrue
            Confirm-ScgEvent -Path $script:Db -Id $a -By 'telegram:1' | Should -BeFalse
            $b = Add-ScgEvent -Path $script:Db -DeviceId 'd1' -Type agent_error -Severity warn -Payload '{}' -ThrottleMin 30
            $b | Should -Not -BeNullOrEmpty
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql 'UPDATE events SET created_at=@t WHERE id=@id' -Parameter @{ t = $script:Old; id = $b })
            Add-ScgEvent -Path $script:Db -DeviceId 'd1' -Type agent_error -Severity warn -Payload '{}' -ThrottleMin 30 | Should -Not -BeNullOrEmpty
        }
        It 'lists newest first and honours Last' {
            1..3 | ForEach-Object { [void](Add-ScgEvent -Path $script:Db -DeviceId 'd1' -Type service_down -Severity info -Payload ('{"n":' + $_ + '}') -ThrottleMin 30) }
            $e = @(Get-ScgEvent -Path $script:Db -Last 2)
            $e.Count | Should -Be 2
            $e[0].payload_json | Should -Be '{"n":3}'
            $e[1].payload_json | Should -Be '{"n":2}'
        }
    }

    Context 'Audit' {
        It 'returns newest first with Last limit and stores meta' {
            Add-ScgAudit -Path $script:Db -Actor 'system' -Action enroll -Target 'PC1' -Meta @{ a = 1 }
            Add-ScgAudit -Path $script:Db -Actor 'system' -Action 'command.issue' -Target 'PC1' -Meta $null
            Add-ScgAudit -Path $script:Db -Actor 'telegram:5' -Action 'event.ack' -Target '7' -Meta '{"x":2}'
            $a = @(Get-ScgAudit -Path $script:Db -Last 2)
            $a.Count | Should -Be 2
            $a[0].action | Should -Be 'event.ack'
            $a[1].action | Should -Be 'command.issue'
            $all = @(Get-ScgAudit -Path $script:Db -Last 10)
            $all[2].meta_json | Should -Be '{"a":1}'
            $all[1].meta_json | Should -BeNullOrEmpty
        }
        It 'rejects unknown actions' {
            { Add-ScgAudit -Path $script:Db -Actor 'system' -Action 'bogus' -Target 'x' } | Should -Throw
        }
    }

    Context 'Parameterization' {
        It 'treats values as data, not SQL' {
            $evil = "x'); DROP TABLE devices; --"
            [void](Register-ScgDevice -Path $script:Db -Hostname $evil)
            @(Get-ScgDevice -Path $script:Db -Hostname $evil).Count | Should -Be 1
            @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT * FROM devices').Count | Should -Be 1
        }
    }

    Context 'Fleet summaries' {
        BeforeEach {
            $script:Now = '2026-06-15T12:00:00.000Z'
            $script:Recent = '2026-06-15T11:58:00.000Z'
            $script:Stale = '2026-06-15T11:00:00.000Z'
            $script:Inside = '2026-06-15T01:00:00.000Z'
            $script:Outside = '2026-06-13T01:00:00.000Z'
        }

        It 'empty database returns all zeros as integers' {
            $s = Get-ScgFleetSummary -Path $script:Db -StaleAfterMin 5 -Now $script:Now
            $names = 'devices_total', 'devices_online', 'devices_offline', 'devices_quarantined', 'agents_total', 'agents_mine', 'agents_unknown', 'devices_with_unknown', 'commands_pending', 'commands_dispatched', 'commands_failed_24h', 'events_critical_24h', 'events_warn_24h'
            foreach ($n in $names) {
                $s.PSObject.Properties[$n] | Should -Not -BeNullOrEmpty
                $s.$n | Should -BeOfType [int]
                $s.$n | Should -Be 0
            }
            @(Get-ScgDeviceAgentSummary -Path $script:Db -Now $script:Now).Count | Should -Be 0
        }

        It 'counts a seeded mix correctly' {
            Add-TestDevice -Db $script:Db -Id 'd1' -Status 'active' -Seen $script:Recent
            Add-TestDevice -Db $script:Db -Id 'd2' -Status 'active' -Seen $script:Stale
            Add-TestDevice -Db $script:Db -Id 'd3' -Status 'stale' -Seen $script:Stale
            Add-TestDevice -Db $script:Db -Id 'd4' -Status 'quarantined' -Seen $script:Recent
            Add-TestDevice -Db $script:Db -Id 'd5' -Status 'active' -Seen $script:Recent
            Add-TestAgent -Db $script:Db -Dev 'd1' -Id 'a1' -Auth 1 -State 'Running'
            Add-TestAgent -Db $script:Db -Dev 'd1' -Id 'a2' -Auth 0 -State 'Running'
            Add-TestAgent -Db $script:Db -Dev 'd2' -Id 'a3' -Auth 1 -State 'Stopped'
            Add-TestAgent -Db $script:Db -Dev 'd2' -Id 'a4' -Auth 0 -State $null
            Add-TestAgent -Db $script:Db -Dev 'd2' -Id 'a5' -Auth 0 -State 'Stopped'
            Add-TestAgent -Db $script:Db -Dev 'd4' -Id 'a6' -Auth 1 -State $null
            Add-TestCommand -Db $script:Db -Id 'c1' -Dev 'd1' -Status 'pending' -Created $script:Inside
            Add-TestCommand -Db $script:Db -Id 'c2' -Dev 'd1' -Status 'dispatched' -Created $script:Inside
            Add-TestCommand -Db $script:Db -Id 'c3' -Dev 'd2' -Status 'failed' -Created $script:Inside -Finished $script:Inside
            Add-TestCommand -Db $script:Db -Id 'c4' -Dev 'd2' -Status 'timeout' -Created $script:Inside
            Add-TestCommand -Db $script:Db -Id 'c5' -Dev 'd2' -Status 'failed' -Created $script:Outside -Finished $script:Outside
            Add-TestCommand -Db $script:Db -Id 'c6' -Dev 'd1' -Status 'failed' -Created $script:Outside -Finished $script:Inside
            Add-TestCommand -Db $script:Db -Id 'c7' -Dev 'd1' -Status 'done' -Created $script:Inside -Finished $script:Inside
            Add-TestCommand -Db $script:Db -Id 'c9' -Dev 'd5' -Status 'failed' -Created $script:Inside -Finished $script:Inside
            Add-TestEvent -Db $script:Db -Dev 'd1' -Sev 'critical' -Created $script:Inside
            Add-TestEvent -Db $script:Db -Dev 'd1' -Sev 'critical' -Created $script:Inside
            Add-TestEvent -Db $script:Db -Dev 'd1' -Sev 'warn' -Created $script:Inside
            Add-TestEvent -Db $script:Db -Dev 'd1' -Sev 'critical' -Created $script:Inside -Acked $script:Inside
            Add-TestEvent -Db $script:Db -Dev 'd1' -Sev 'warn' -Created $script:Outside
            Add-TestEvent -Db $script:Db -Dev 'd1' -Sev 'info' -Created $script:Inside

            $s = Get-ScgFleetSummary -Path $script:Db -StaleAfterMin 5 -Now $script:Now
            $s.devices_total | Should -Be 5
            $s.devices_online | Should -Be 2
            $s.devices_offline | Should -Be 2
            $s.devices_quarantined | Should -Be 1
            $s.agents_total | Should -Be 6
            $s.agents_mine | Should -Be 3
            $s.agents_unknown | Should -Be 3
            $s.devices_with_unknown | Should -Be 2
            $s.commands_pending | Should -Be 1
            $s.commands_dispatched | Should -Be 1
            $s.commands_failed_24h | Should -Be 4
            $s.events_critical_24h | Should -Be 2
            $s.events_warn_24h | Should -Be 1

            $rows = @(Get-ScgDeviceAgentSummary -Path $script:Db -Now $script:Now)
            $rows.Count | Should -Be 4
            $d1 = @($rows | Where-Object { $_.device_id -eq 'd1' })[0]
            $d1.agents_total | Should -Be 2
            $d1.agents_mine | Should -Be 1
            $d1.agents_unknown | Should -Be 1
            $d1.agents_stopped | Should -Be 0
            $d1.commands_failed_24h | Should -Be 1
            $d2 = @($rows | Where-Object { $_.device_id -eq 'd2' })[0]
            $d2.agents_total | Should -Be 3
            $d2.agents_mine | Should -Be 1
            $d2.agents_unknown | Should -Be 2
            $d2.agents_stopped | Should -Be 1
            $d2.commands_failed_24h | Should -Be 2
            $d4 = @($rows | Where-Object { $_.device_id -eq 'd4' })[0]
            $d4.agents_stopped | Should -Be 0
            $d5 = @($rows | Where-Object { $_.device_id -eq 'd5' })[0]
            $d5.agents_total | Should -Be 0
            $d5.commands_failed_24h | Should -Be 1
            @($rows | Where-Object { $_.device_id -in 'd3' }).Count | Should -Be 0
        }

        It 'Get-ScgRecentCommand orders newest first, honours the limit and excludes other devices' {
            Add-TestDevice -Db $script:Db -Id 'd1' -Status 'active' -Seen $script:Recent
            Add-TestDevice -Db $script:Db -Id 'd2' -Status 'active' -Seen $script:Recent
            Add-TestCommand -Db $script:Db -Id 'r1' -Dev 'd1' -Status 'done' -Created '2026-06-15T01:00:00.000Z'
            Add-TestCommand -Db $script:Db -Id 'r2' -Dev 'd1' -Status 'done' -Created '2026-06-15T02:00:00.000Z'
            Add-TestCommand -Db $script:Db -Id 'r3' -Dev 'd1' -Status 'done' -Created '2026-06-15T03:00:00.000Z'
            Add-TestCommand -Db $script:Db -Id 'r4' -Dev 'd1' -Status 'pending' -Created '2026-06-15T04:00:00.000Z'
            Add-TestCommand -Db $script:Db -Id 'x1' -Dev 'd2' -Status 'pending' -Created '2026-06-15T05:00:00.000Z'
            $r = @(Get-ScgRecentCommand -Path $script:Db -DeviceId 'd1')
            $r.Count | Should -Be 3
            ($r | ForEach-Object { $_.id }) -join ',' | Should -Be 'r4,r3,r2'
            $r[0].PSObject.Properties['result_json'] | Should -Not -BeNullOrEmpty
            @(Get-ScgRecentCommand -Path $script:Db -DeviceId 'd1' -Last 10).Count | Should -Be 4
            @(Get-ScgRecentCommand -Path $script:Db -DeviceId 'd1' -Last 1).Count | Should -Be 1
            @(Get-ScgRecentCommand -Path $script:Db -DeviceId 'none').Count | Should -Be 0
            { Get-ScgRecentCommand -Path $script:Db -DeviceId 'd1' -Last 21 } | Should -Throw
        }

        It 'a 500 device seed finishes under 5 seconds' {
            $t = $script:Recent
            $cte = 'WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<500) '
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Parameter @{ t = $t } -Sql ($cte + "INSERT INTO devices (id, hostname, first_seen, last_seen, status) SELECT printf('dev%04d', i), printf('host%04d', i), @t, @t, 'active' FROM n"))
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Parameter @{ t = $t } -Sql ($cte + "INSERT INTO sc_agents (id, device_id, authorized, state, first_seen, last_seen) SELECT printf('ag%04d_%d', i, k), printf('dev%04d', i), k - 1, 'Running', @t, @t FROM n CROSS JOIN (SELECT 1 AS k UNION SELECT 2) AS ks"))
            [void](Invoke-ScgSql -Path $script:Db -NonQuery -Parameter @{ t = $t } -Sql ($cte + "INSERT INTO commands (id, device_id, type, status, created_at, finished_at) SELECT printf('cm%04d', i), printf('dev%04d', i), 'ping', 'failed', @t, @t FROM n"))
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $s = Get-ScgFleetSummary -Path $script:Db -StaleAfterMin 5 -Now $script:Now
            $rows = @(Get-ScgDeviceAgentSummary -Path $script:Db -Now $script:Now)
            $sw.Stop()
            $sw.ElapsedMilliseconds | Should -BeLessThan 5000
            $s.devices_total | Should -Be 500
            $s.devices_online | Should -Be 500
            $s.agents_total | Should -Be 1000
            $s.commands_failed_24h | Should -Be 500
            $rows.Count | Should -Be 500
            $rows[0].agents_total | Should -Be 2
        }
    }

    Context 'Update command payload' {
        BeforeEach {
            $script:Dev = Register-ScgDevice -Path $script:Db -Hostname 'PC1'
            $script:Sha = 'ab' * 32
            $script:Url = 'https://github.com/cBadr/SCGuardian/releases/download/v4.0.2/SCGuardian.Agent.Setup.exe'
        }
        It 'accepts an update command with a valid payload and round-trips the exact payload' {
            $json = '{"version":"4.0.2","setup_url":"' + $script:Url + '","sha256":"' + $script:Sha + '"}'
            $id = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload $json -IssuedBy 'telegram:1' -IssuedVia telegram
            $id | Should -Not -BeNullOrEmpty
            $c = Get-ScgCommand -Path $script:Db -CommandId $id -DeviceId $script:Dev.id
            $c.type | Should -Be 'update'
            $c.status | Should -Be 'pending'
            $c.payload_json | Should -BeExactly $json
        }
        It 'accepts a hashtable payload on the release asset CDN and stores its fields' {
            $cdn = 'https://objects.githubusercontent.com/github-production-release-asset/1/abc?x=1'
            $id = New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = '4.0.2'; setup_url = $cdn; sha256 = $script:Sha }
            $p = ConvertFrom-Json -InputObject (Get-ScgCommand -Path $script:Db -CommandId $id).payload_json
            $p.version | Should -BeExactly '4.0.2'
            $p.setup_url | Should -BeExactly $cdn
            $p.sha256 | Should -BeExactly $script:Sha
        }
        It 'accepts a githubusercontent.com subdomain' {
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = '4.0.2'; setup_url = 'https://release-assets.githubusercontent.com/a/b.exe'; sha256 = $script:Sha } } | Should -Not -Throw
        }
        It 'rejects an http url naming setup_url' {
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = '4.0.2'; setup_url = 'http://github.com/a/b.exe'; sha256 = $script:Sha } } | Should -Throw -ExceptionType ([System.ArgumentException]) -ExpectedMessage '*setup_url*'
        }
        It 'rejects a non-github host' {
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = '4.0.2'; setup_url = 'https://evil.example.com/b.exe'; sha256 = $script:Sha } } | Should -Throw -ExceptionType ([System.ArgumentException]) -ExpectedMessage '*setup_url*'
        }
        It 'rejects github.com lookalike hosts and userinfo tricks' {
            foreach ($bad in @('https://github.com.evil.com/b.exe', 'https://evilgithub.com/b.exe', 'https://evilgithubusercontent.com/b.exe', 'https://githubusercontent.com.evil.com/b.exe', 'https://github.com@evil.com/b.exe', 'https://github.com./b.exe', 'not a url', '')) {
                { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = '4.0.2'; setup_url = $bad; sha256 = $script:Sha } } | Should -Throw -ExceptionType ([System.ArgumentException]) -ExpectedMessage '*setup_url*'
            }
        }
        It 'rejects a short, uppercase or non-hex sha256' {
            foreach ($bad in @(('ab' * 31), ('AB' * 32), (('ab' * 31) + 'zz'), (('ab' * 32) + 'a'), (('ab' * 32) + "`n"))) {
                { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = '4.0.2'; setup_url = $script:Url; sha256 = $bad } } | Should -Throw -ExceptionType ([System.ArgumentException]) -ExpectedMessage '*sha256*'
            }
        }
        It 'rejects a missing or empty version' {
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ setup_url = $script:Url; sha256 = $script:Sha } } | Should -Throw -ExceptionType ([System.ArgumentException]) -ExpectedMessage '*version*'
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = ' '; setup_url = $script:Url; sha256 = $script:Sha } } | Should -Throw -ExceptionType ([System.ArgumentException]) -ExpectedMessage '*version*'
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload $null } | Should -Throw -ExceptionType ([System.ArgumentException]) -ExpectedMessage '*version*'
        }
        It 'never inserts a row when validation fails' {
            { New-ScgCommand -Path $script:Db -DeviceId $script:Dev.id -Type update -Payload @{ version = '4.0.2'; setup_url = 'https://github.com.evil.com/b.exe'; sha256 = $script:Sha } } | Should -Throw
            @(Invoke-ScgSql -Path $script:Db -Sql 'SELECT id FROM commands').Count | Should -Be 0
        }
    }

    Context 'Version distribution' {
        It 'returns an empty result for an empty devices table' {
            $r = @(Get-ScgVersionDistribution -Path $script:Db)
            $r.Count | Should -Be 0
        }
        It 'groups by agent_version with unknown for NULL or empty, ordered by count then version' {
            $seed = @(
                @('d1', '4.0.1', '2026-06-10T00:00:00.000Z'),
                @('d2', '4.0.1', '2026-06-12T00:00:00.000Z'),
                @('d3', '4.0.1', '2026-06-11T00:00:00.000Z'),
                @('d4', '4.0.0', '2026-06-09T00:00:00.000Z'),
                @('d5', $null, '2026-06-13T00:00:00.000Z'),
                @('d6', '', '2026-06-08T00:00:00.000Z'),
                @('d7', '3.9.0', '2026-06-14T00:00:00.000Z')
            )
            foreach ($s in $seed) {
                [void](Invoke-ScgSql -Path $script:Db -NonQuery -Sql "INSERT INTO devices (id, hostname, first_seen, last_seen, status, agent_version) VALUES (@id, @h, @t, @t, 'active', @av)" -Parameter @{ id = $s[0]; h = ('host-' + $s[0]); t = $s[2]; av = $s[1] })
            }
            $r = @(Get-ScgVersionDistribution -Path $script:Db)
            $r.Count | Should -Be 4
            ($r | ForEach-Object { $_.agent_version }) -join ',' | Should -BeExactly '4.0.1,unknown,3.9.0,4.0.0'
            $r[0].device_count | Should -Be 3
            $r[0].newest_seen | Should -BeExactly '2026-06-12T00:00:00.000Z'
            $r[1].device_count | Should -Be 2
            $r[1].newest_seen | Should -BeExactly '2026-06-13T00:00:00.000Z'
            $r[2].device_count | Should -Be 1
            $r[2].newest_seen | Should -BeExactly '2026-06-14T00:00:00.000Z'
            $r[3].device_count | Should -Be 1
            $r[3].newest_seen | Should -BeExactly '2026-06-09T00:00:00.000Z'
        }
    }
}
