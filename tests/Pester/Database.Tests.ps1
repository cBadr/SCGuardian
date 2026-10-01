# Purpose: Pester 5 tests for Database.psm1 | Author: Badr | Version: 4.0.0

BeforeAll {
    $env:SCG_ROOT = $TestDrive
    Import-Module (Join-Path $PSScriptRoot '..\..\src\modules\Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\..\src\modules\Database.psm1') -Force
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
}
