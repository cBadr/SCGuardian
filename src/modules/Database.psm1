<#
.SYNOPSIS
    SCGuardian Database module: the only module holding SQL (SQLite via System.Data.SQLite).
.DESCRIPTION
    Purpose : schema migrations, devices, agents, commands, events, audit, health counts.
    Author  : Badr
    Version : 4.0.0
    Depends : Common.psm1, src\lib\System.Data.SQLite.dll
#>

Set-StrictMode -Version 2.0

Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -DisableNameChecking

$script:SqliteLoaded = $false

$script:CommandTransitions = @{
    'pending'    = @('dispatched', 'timeout')
    'dispatched' = @('done', 'failed', 'timeout')
}

$script:Migrations = @{
    1 = @(
        'CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, hostname TEXT NOT NULL UNIQUE, os TEXT, os_version TEXT, last_ip TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL DEFAULT ''active'', agent_version TEXT, tags TEXT, config_json TEXT)',
        'CREATE TABLE IF NOT EXISTS sc_agents (id TEXT NOT NULL, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, service_name TEXT, folder TEXT, uninstall_key TEXT, authorized INTEGER NOT NULL DEFAULT 0, state TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (device_id, id))',
        'CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, type TEXT NOT NULL, payload_json TEXT, status TEXT NOT NULL DEFAULT ''pending'', created_at TEXT NOT NULL, dispatched_at TEXT, finished_at TEXT, result_json TEXT, issued_by TEXT, issued_via TEXT)',
        'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, type TEXT NOT NULL, severity TEXT NOT NULL, payload_json TEXT, created_at TEXT NOT NULL, acked_at TEXT, acked_by TEXT)',
        'CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, meta_json TEXT)',
        'CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)',
        'CREATE INDEX IF NOT EXISTS idx_sc_agents_device ON sc_agents(device_id)',
        'CREATE INDEX IF NOT EXISTS idx_commands_device_status ON commands(device_id, status)',
        'CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC)',
        'CREATE INDEX IF NOT EXISTS idx_events_acked ON events(acked_at)',
        'CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC)'
    )
    2 = @(
        'DROP TABLE IF EXISTS sc_agents_new',
        'CREATE TABLE sc_agents_new (id TEXT NOT NULL, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, service_name TEXT, folder TEXT, uninstall_key TEXT, authorized INTEGER NOT NULL DEFAULT 0, state TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY (device_id, id))',
        'INSERT OR REPLACE INTO sc_agents_new (id, device_id, service_name, folder, uninstall_key, authorized, state, first_seen, last_seen) SELECT id, device_id, service_name, folder, uninstall_key, authorized, state, first_seen, last_seen FROM sc_agents',
        'DROP TABLE sc_agents',
        'ALTER TABLE sc_agents_new RENAME TO sc_agents',
        'CREATE INDEX IF NOT EXISTS idx_sc_agents_device ON sc_agents(device_id)'
    )
}

function Import-ScgSqliteAssembly {
    <#
    .SYNOPSIS
        Loads System.Data.SQLite.dll once.
    #>
    [CmdletBinding()]
    param()
    if ($script:SqliteLoaded) { return }
    if (-not ('System.Data.SQLite.SQLiteConnection' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot '..\lib\System.Data.SQLite.dll')
    }
    $script:SqliteLoaded = $true
}

function Invoke-ScgSqlCore {
    <#
    .SYNOPSIS
        Runs one parameterized statement on an open connection.
    .PARAMETER Connection
        Open SQLite connection.
    .PARAMETER Sql
        Statement text with @name placeholders.
    .PARAMETER Parameter
        Parameter values by name.
    .PARAMETER NonQuery
        Return affected row count instead of rows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Connection,
        [Parameter(Mandatory = $true)][string]$Sql,
        [Parameter()][hashtable]$Parameter,
        [Parameter()][switch]$NonQuery
    )
    $cmd = $Connection.CreateCommand()
    try {
        $cmd.CommandText = $Sql
        if ($null -ne $Parameter) {
            foreach ($key in @($Parameter.Keys)) {
                $name = ([string]$key).TrimStart('@', ':', '$')
                $val = $Parameter[$key]
                if ($null -eq $val) { $val = [System.DBNull]::Value }
                [void]$cmd.Parameters.AddWithValue('@' + $name, $val)
            }
        }
        if ($NonQuery) {
            return [int]$cmd.ExecuteNonQuery()
        }
        $reader = $cmd.ExecuteReader()
        try {
            $rows = New-Object System.Collections.ArrayList
            while ($reader.Read()) {
                $o = [ordered]@{}
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $v = $reader.GetValue($i)
                    if ($v -is [System.DBNull]) { $v = $null }
                    $o[$reader.GetName($i)] = $v
                }
                [void]$rows.Add([pscustomobject]$o)
            }
            return $rows.ToArray()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $cmd.Dispose()
    }
}

function Open-ScgConnection {
    <#
    .SYNOPSIS
        Opens a SQLite connection and applies the per-connection PRAGMAs.
    .PARAMETER Path
        Database file path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    Import-ScgSqliteAssembly
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        [void](New-Item -ItemType Directory -Path $dir -Force)
    }
    $conn = New-Object System.Data.SQLite.SQLiteConnection ('Data Source=' + $Path + ';Version=3;Pooling=False;')
    try {
        $conn.Open()
        [void](Invoke-ScgSqlCore -Connection $conn -Sql 'PRAGMA busy_timeout=5000' )
        [void](Invoke-ScgSqlCore -Connection $conn -Sql 'PRAGMA journal_mode=WAL')
        [void](Invoke-ScgSqlCore -Connection $conn -Sql 'PRAGMA foreign_keys=ON')
    }
    catch {
        $conn.Dispose()
        throw
    }
    return $conn
}

function Start-ScgTx {
    <#
    .SYNOPSIS
        Begins an immediate write transaction.
    .PARAMETER Connection
        Open connection.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Connection)
    [void](Invoke-ScgSqlCore -Connection $Connection -Sql 'BEGIN IMMEDIATE' -NonQuery)
}

function Complete-ScgTx {
    <#
    .SYNOPSIS
        Commits the current transaction.
    .PARAMETER Connection
        Open connection.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Connection)
    [void](Invoke-ScgSqlCore -Connection $Connection -Sql 'COMMIT' -NonQuery)
}

function Undo-ScgTx {
    <#
    .SYNOPSIS
        Rolls back the current transaction, ignoring errors.
    .PARAMETER Connection
        Open connection.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Connection)
    try { [void](Invoke-ScgSqlCore -Connection $Connection -Sql 'ROLLBACK' -NonQuery) } catch { $null = $_ }
}

function Get-ScgPropValue {
    <#
    .SYNOPSIS
        Reads the first present property or key from an object or hashtable.
    .PARAMETER Object
        Source object.
    .PARAMETER Name
        Candidate names in priority order.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Name
    )
    if ($null -eq $Object) { return $null }
    foreach ($n in $Name) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($n)) { return $Object[$n] }
        }
        else {
            $p = $Object.PSObject.Properties[$n]
            if ($null -ne $p) { return $p.Value }
        }
    }
    return $null
}

function ConvertTo-ScgJsonText {
    <#
    .SYNOPSIS
        Returns strings unchanged, serializes other objects to compact JSON, null stays null.
    .PARAMETER Value
        Value to convert.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    return (ConvertTo-Json -InputObject $Value -Compress -Depth 8)
}

function Assert-ScgCommandTransition {
    <#
    .SYNOPSIS
        Throws unless From to To is a legal command status move.
    .PARAMETER From
        Current status.
    .PARAMETER To
        Requested status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$To
    )
    $ok = $false
    if ($script:CommandTransitions.ContainsKey($From)) {
        if ($script:CommandTransitions[$From] -contains $To) { $ok = $true }
    }
    if (-not $ok) {
        throw ('Illegal command transition: ' + $From + ' -> ' + $To)
    }
}

function Get-ScgCutoff {
    <#
    .SYNOPSIS
        ISO timestamp for now minus the given seconds.
    .PARAMETER Second
        Seconds to subtract.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][double]$Second)
    return (ConvertTo-ScgUtcIso -InputObject ([datetime]::UtcNow.AddSeconds(-$Second)))
}

function Get-ScgSchemaVersion {
    <#
    .SYNOPSIS
        Returns the applied schema version (0 when none).
    .PARAMETER Path
        Database file path.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $conn = Open-ScgConnection -Path $Path
    try {
        $t = @(Invoke-ScgSqlCore -Connection $conn -Sql "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        if ($t.Count -eq 0) { return 0 }
        $r = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT MAX(version) AS v FROM schema_version')
        if ($r.Count -eq 0 -or $null -eq $r[0].v) { return 0 }
        return [int]$r[0].v
    }
    finally {
        $conn.Dispose()
    }
}

function Invoke-ScgMigration {
    <#
    .SYNOPSIS
        Applies pending migrations; safe to run repeatedly. Returns the schema version.
    .PARAMETER Path
        Database file path.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $conn = Open-ScgConnection -Path $Path
    try {
        [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql 'CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)')
        $r = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT MAX(version) AS v FROM schema_version')
        $current = 0
        if ($r.Count -gt 0 -and $null -ne $r[0].v) { $current = [int]$r[0].v }
        foreach ($ver in @($script:Migrations.Keys | Sort-Object)) {
            if ([int]$ver -le $current) { continue }
            Start-ScgTx -Connection $conn
            try {
                foreach ($stmt in $script:Migrations[$ver]) {
                    [void](Invoke-ScgSqlCore -Connection $conn -Sql $stmt -NonQuery)
                }
                [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql 'INSERT INTO schema_version (version, applied_at) VALUES (@v, @t)' -Parameter @{ v = [int]$ver; t = (Get-ScgUtcNow) })
                Complete-ScgTx -Connection $conn
            }
            catch {
                Undo-ScgTx -Connection $conn
                throw
            }
            $current = [int]$ver
        }
        return $current
    }
    finally {
        $conn.Dispose()
    }
}

function Initialize-ScgDatabase {
    <#
    .SYNOPSIS
        Opens or creates the database, applies migrations, returns the schema version.
    .PARAMETER Path
        Database file path.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Invoke-ScgMigration -Path $Path)
}

function Invoke-ScgSql {
    <#
    .SYNOPSIS
        Runs one parameterized statement; returns rows as PSCustomObject or, with -NonQuery, the affected count.
    .PARAMETER Path
        Database file path.
    .PARAMETER Sql
        Statement with @name placeholders.
    .PARAMETER Parameter
        Parameter values by name.
    .PARAMETER NonQuery
        Return affected row count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Sql,
        [Parameter()][hashtable]$Parameter,
        [Parameter()][switch]$NonQuery
    )
    $conn = Open-ScgConnection -Path $Path
    try {
        if ($NonQuery) {
            return (Invoke-ScgSqlCore -Connection $conn -Sql $Sql -Parameter $Parameter -NonQuery)
        }
        return (Invoke-ScgSqlCore -Connection $conn -Sql $Sql -Parameter $Parameter)
    }
    finally {
        $conn.Dispose()
    }
}

function Register-ScgDevice {
    <#
    .SYNOPSIS
        Upserts a device by hostname; re-enroll returns the same id.
    .PARAMETER Path
        Database file path.
    .PARAMETER Hostname
        Device hostname (unique).
    .PARAMETER Os
        Operating system name.
    .PARAMETER OsVersion
        Operating system version.
    .PARAMETER AgentVersion
        Agent version.
    .PARAMETER LastIp
        Last seen IP.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter()][string]$Os,
        [Parameter()][string]$OsVersion,
        [Parameter()][string]$AgentVersion,
        [Parameter()][string]$LastIp
    )
    $conn = Open-ScgConnection -Path $Path
    try {
        $now = Get-ScgUtcNow
        Start-ScgTx -Connection $conn
        try {
            $ex = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT id FROM devices WHERE hostname=@h' -Parameter @{ h = $Hostname })
            if ($ex.Count -gt 0) {
                [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql "UPDATE devices SET os=@os, os_version=@osv, agent_version=@av, last_ip=@ip, last_seen=@now, status=CASE WHEN status='stale' THEN 'active' ELSE status END WHERE id=@id" -Parameter @{ os = $Os; osv = $OsVersion; av = $AgentVersion; ip = $LastIp; now = $now; id = $ex[0].id })
            }
            else {
                [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql "INSERT INTO devices (id, hostname, os, os_version, last_ip, first_seen, last_seen, status, agent_version) VALUES (@id, @h, @os, @osv, @ip, @now, @now, 'active', @av)" -Parameter @{ id = (New-ScgGuid); h = $Hostname; os = $Os; osv = $OsVersion; ip = $LastIp; now = $now; av = $AgentVersion })
            }
            Complete-ScgTx -Connection $conn
        }
        catch {
            Undo-ScgTx -Connection $conn
            throw
        }
        $row = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT * FROM devices WHERE hostname=@h' -Parameter @{ h = $Hostname })
        return $row[0]
    }
    finally {
        $conn.Dispose()
    }
}

function Update-ScgDeviceSeen {
    <#
    .SYNOPSIS
        Touches last_seen (reactivating stale devices) and updates supplied fields. Returns false for unknown device.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device id.
    .PARAMETER Hostname
        New hostname; applied only together with -Rename (default: the stored hostname is kept).
    .PARAMETER Rename
        Apply -Hostname. Without it the hostname is never changed (no UNIQUE collision possible).
    .PARAMETER AgentVersion
        Agent version.
    .PARAMETER LastIp
        Source IP.
    .PARAMETER ConfigJson
        Reported config as JSON text.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter()][string]$Hostname,
        [Parameter()][switch]$Rename,
        [Parameter()][string]$AgentVersion,
        [Parameter()][string]$LastIp,
        [Parameter()][string]$ConfigJson
    )
    $h = $null; $av = $null; $ip = $null; $cj = $null
    if ($Rename -and $PSBoundParameters.ContainsKey('Hostname')) { $h = $Hostname }
    if ($PSBoundParameters.ContainsKey('AgentVersion')) { $av = $AgentVersion }
    if ($PSBoundParameters.ContainsKey('LastIp')) { $ip = $LastIp }
    if ($PSBoundParameters.ContainsKey('ConfigJson')) { $cj = $ConfigJson }
    $n = Invoke-ScgSql -Path $Path -NonQuery -Sql "UPDATE devices SET last_seen=@now, status=CASE WHEN status='stale' THEN 'active' ELSE status END, hostname=COALESCE(@h, hostname), agent_version=COALESCE(@av, agent_version), last_ip=COALESCE(@ip, last_ip), config_json=COALESCE(@cj, config_json) WHERE id=@id" -Parameter @{ now = (Get-ScgUtcNow); h = $h; av = $av; ip = $ip; cj = $cj; id = $DeviceId }
    return ($n -gt 0)
}

function Test-ScgDeviceOnline {
    <#
    .SYNOPSIS
        True when the device exists and its last_seen is within StaleAfterMin minutes.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device id.
    .PARAMETER StaleAfterMin
        Online window in minutes.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter(Mandatory = $true)][int]$StaleAfterMin
    )
    $cutoff = Get-ScgCutoff -Second ($StaleAfterMin * 60)
    $r = @(Invoke-ScgSql -Path $Path -Sql 'SELECT COUNT(*) AS n FROM devices WHERE id=@id AND last_seen >= @c' -Parameter @{ id = $DeviceId; c = $cutoff })
    return ([int]$r[0].n -gt 0)
}

function Set-ScgDeviceStatus {
    <#
    .SYNOPSIS
        Sets device status (active, stale, quarantined). Returns false for unknown device.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device id.
    .PARAMETER Status
        New status.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter(Mandatory = $true)][ValidateSet('active', 'stale', 'quarantined')][string]$Status
    )
    $n = Invoke-ScgSql -Path $Path -NonQuery -Sql 'UPDATE devices SET status=@s WHERE id=@id' -Parameter @{ s = $Status; id = $DeviceId }
    return ($n -gt 0)
}

function Sync-ScgScAgent {
    <#
    .SYNOPSIS
        Transactionally upserts a device's agents and deletes the ones missing from the heartbeat.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device id.
    .PARAMETER ScAgent
        Agents in wire shape (id, service, folder, uninstall_key, state).
    .PARAMETER AllowedId
        Allow-listed agent ids; matching agents get authorized=1.
    .PARAMETER AllowEmpty
        When the reported list is empty, delete the device's rows anyway; without it an empty list deletes nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter()][AllowNull()][AllowEmptyCollection()][object[]]$ScAgent,
        [Parameter()][AllowNull()][AllowEmptyCollection()][string[]]$AllowedId,
        [Parameter()][switch]$AllowEmpty
    )
    $allowed = New-Object System.Collections.ArrayList
    foreach ($a in @($AllowedId)) {
        if (-not [string]::IsNullOrEmpty($a)) { [void]$allowed.Add($a.ToLowerInvariant()) }
    }
    $conn = Open-ScgConnection -Path $Path
    try {
        $now = Get-ScgUtcNow
        Start-ScgTx -Connection $conn
        try {
            $keep = New-Object System.Collections.ArrayList
            foreach ($ag in @($ScAgent)) {
                if ($null -eq $ag) { continue }
                $rawId = Get-ScgPropValue -Object $ag -Name @('id', 'Id')
                if ([string]::IsNullOrEmpty([string]$rawId)) { continue }
                $id = ([string]$rawId).ToLowerInvariant()
                [void]$keep.Add($id)
                $auth = 0
                if ($allowed.Contains($id)) { $auth = 1 }
                $p = @{
                    id     = $id
                    d      = $DeviceId
                    svc    = [string](Get-ScgPropValue -Object $ag -Name @('service', 'ServiceName', 'service_name'))
                    folder = [string](Get-ScgPropValue -Object $ag -Name @('folder', 'Folder'))
                    uk     = [string](Get-ScgPropValue -Object $ag -Name @('uninstall_key', 'UninstallKey'))
                    auth   = $auth
                    state  = [string](Get-ScgPropValue -Object $ag -Name @('state', 'ServiceState'))
                    now    = $now
                }
                $ex = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT id FROM sc_agents WHERE device_id=@d AND id=@id' -Parameter @{ d = $DeviceId; id = $id })
                if ($ex.Count -gt 0) {
                    [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql 'UPDATE sc_agents SET service_name=@svc, folder=@folder, uninstall_key=@uk, authorized=@auth, state=@state, last_seen=@now WHERE device_id=@d AND id=@id' -Parameter $p)
                }
                else {
                    [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql 'INSERT INTO sc_agents (id, device_id, service_name, folder, uninstall_key, authorized, state, first_seen, last_seen) VALUES (@id, @d, @svc, @folder, @uk, @auth, @state, @now, @now)' -Parameter $p)
                }
            }
            if ($keep.Count -gt 0 -or $AllowEmpty) {
                $existing = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT id FROM sc_agents WHERE device_id=@d' -Parameter @{ d = $DeviceId })
                foreach ($row in $existing) {
                    if (-not $keep.Contains([string]$row.id)) {
                        [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql 'DELETE FROM sc_agents WHERE device_id=@d AND id=@id' -Parameter @{ id = $row.id; d = $DeviceId })
                    }
                }
            }
            Complete-ScgTx -Connection $conn
        }
        catch {
            Undo-ScgTx -Connection $conn
            throw
        }
    }
    finally {
        $conn.Dispose()
    }
}

function Get-ScgDevice {
    <#
    .SYNOPSIS
        Gets devices by id, hostname or id prefix, or a page of all devices.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Exact id.
    .PARAMETER Hostname
        Exact hostname.
    .PARAMETER IdPrefix
        Id prefix (hex and dashes only).
    .PARAMETER Page
        1-based page number; omit to return all.
    .PARAMETER PageSize
        Rows per page (default 20).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter()][string]$DeviceId,
        [Parameter()][string]$Hostname,
        [Parameter()][string]$IdPrefix,
        [Parameter()][ValidateRange(1, 1000000)][int]$Page,
        [Parameter()][ValidateRange(1, 1000)][int]$PageSize = 20
    )
    if ($PSBoundParameters.ContainsKey('DeviceId')) {
        $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM devices WHERE id=@id' -Parameter @{ id = $DeviceId }
        return $r
    }
    if ($PSBoundParameters.ContainsKey('Hostname')) {
        $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM devices WHERE hostname=@h' -Parameter @{ h = $Hostname }
        return $r
    }
    if ($PSBoundParameters.ContainsKey('IdPrefix')) {
        if ($IdPrefix -notmatch '^[0-9a-fA-F\-]+$') { throw 'Invalid device id prefix.' }
        $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM devices WHERE substr(id, 1, @len)=@p ORDER BY hostname' -Parameter @{ len = $IdPrefix.Length; p = $IdPrefix.ToLowerInvariant() }
        return $r
    }
    if ($PSBoundParameters.ContainsKey('Page')) {
        $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM devices ORDER BY hostname LIMIT @lim OFFSET @off' -Parameter @{ lim = $PageSize; off = (($Page - 1) * $PageSize) }
        return $r
    }
    $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM devices ORDER BY hostname'
    return $r
}

function Get-ScgScAgent {
    <#
    .SYNOPSIS
        Gets the agents recorded for a device.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId
    )
    $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM sc_agents WHERE device_id=@d ORDER BY service_name, id' -Parameter @{ d = $DeviceId }
    return $r
}

function New-ScgCommand {
    <#
    .SYNOPSIS
        Creates a pending command; returns the existing id when an identical pending or dispatched one exists.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Target device id.
    .PARAMETER Type
        Command type.
    .PARAMETER Payload
        Payload as JSON text or object (null becomes an empty object).
    .PARAMETER IssuedBy
        Actor that issued the command.
    .PARAMETER IssuedVia
        telegram or system.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter(Mandatory = $true)][ValidateSet('harden', 'restore', 'remove', 'status', 'agents', 'ping')][string]$Type,
        [Parameter()][AllowNull()][object]$Payload,
        [Parameter()][string]$IssuedBy = 'system',
        [Parameter()][ValidateSet('telegram', 'system')][string]$IssuedVia = 'system'
    )
    $pj = ConvertTo-ScgJsonText -Value $Payload
    if ($null -eq $pj) { $pj = '{}' }
    $conn = Open-ScgConnection -Path $Path
    try {
        Start-ScgTx -Connection $conn
        try {
            $ex = @(Invoke-ScgSqlCore -Connection $conn -Sql "SELECT id FROM commands WHERE device_id=@d AND type=@t AND payload_json=@p AND status IN ('pending','dispatched') ORDER BY created_at LIMIT 1" -Parameter @{ d = $DeviceId; t = $Type; p = $pj })
            if ($ex.Count -gt 0) {
                $id = [string]$ex[0].id
            }
            else {
                $id = New-ScgGuid
                [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql "INSERT INTO commands (id, device_id, type, payload_json, status, created_at, issued_by, issued_via) VALUES (@id, @d, @t, @p, 'pending', @now, @by, @via)" -Parameter @{ id = $id; d = $DeviceId; t = $Type; p = $pj; now = (Get-ScgUtcNow); by = $IssuedBy; via = $IssuedVia })
            }
            Complete-ScgTx -Connection $conn
        }
        catch {
            Undo-ScgTx -Connection $conn
            throw
        }
        return $id
    }
    finally {
        $conn.Dispose()
    }
}

function Get-ScgDispatchableCommand {
    <#
    .SYNOPSIS
        Returns the device's pending commands, atomically flipped to dispatched (each is returned once).
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId
    )
    $conn = Open-ScgConnection -Path $Path
    try {
        $now = Get-ScgUtcNow
        $out = New-Object System.Collections.ArrayList
        Start-ScgTx -Connection $conn
        try {
            $rows = @(Invoke-ScgSqlCore -Connection $conn -Sql "SELECT * FROM commands WHERE device_id=@d AND status='pending' ORDER BY created_at, id" -Parameter @{ d = $DeviceId })
            foreach ($r in $rows) {
                Assert-ScgCommandTransition -From 'pending' -To 'dispatched'
                $n = Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql "UPDATE commands SET status='dispatched', dispatched_at=@now WHERE id=@id AND status='pending'" -Parameter @{ now = $now; id = $r.id }
                if ($n -gt 0) {
                    $r.status = 'dispatched'
                    $r.dispatched_at = $now
                    [void]$out.Add($r)
                }
            }
            Complete-ScgTx -Connection $conn
        }
        catch {
            Undo-ScgTx -Connection $conn
            throw
        }
        return $out.ToArray()
    }
    finally {
        $conn.Dispose()
    }
}

function Get-ScgCommand {
    <#
    .SYNOPSIS
        Returns the full command row for a device and command id, or null when none exists.
    .PARAMETER Path
        Database file path.
    .PARAMETER CommandId
        Command id.
    .PARAMETER DeviceId
        Optional owner device id; when given, the row must belong to that device.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CommandId,
        [Parameter()][string]$DeviceId
    )
    if ($PSBoundParameters.ContainsKey('DeviceId')) {
        $rows = @(Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM commands WHERE id=@id AND device_id=@d' -Parameter @{ id = $CommandId; d = $DeviceId })
    }
    else {
        $rows = @(Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM commands WHERE id=@id' -Parameter @{ id = $CommandId })
    }
    if ($rows.Count -eq 0) { return $null }
    return $rows[0]
}

function Complete-ScgCommand {
    <#
    .SYNOPSIS
        Finishes a dispatched command as done or failed; throws on unknown command or illegal transition.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device that must own the command.
    .PARAMETER CommandId
        Command id.
    .PARAMETER Ok
        True for done, false for failed.
    .PARAMETER Output
        Command output text.
    .PARAMETER DurationMs
        Execution time in milliseconds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter(Mandatory = $true)][string]$CommandId,
        [Parameter(Mandatory = $true)][bool]$Ok,
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Output,
        [Parameter()][long]$DurationMs = 0
    )
    $target = 'failed'
    if ($Ok) { $target = 'done' }
    $result = ConvertTo-Json -InputObject ([ordered]@{ ok = $Ok; output = $Output; duration_ms = $DurationMs }) -Compress -Depth 4
    $conn = Open-ScgConnection -Path $Path
    try {
        Start-ScgTx -Connection $conn
        try {
            $rows = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT status FROM commands WHERE id=@id AND device_id=@d' -Parameter @{ id = $CommandId; d = $DeviceId })
            if ($rows.Count -eq 0) { throw 'Command not found for this device.' }
            Assert-ScgCommandTransition -From ([string]$rows[0].status) -To $target
            [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql 'UPDATE commands SET status=@s, finished_at=@now, result_json=@r WHERE id=@id AND device_id=@d' -Parameter @{ s = $target; now = (Get-ScgUtcNow); r = $result; id = $CommandId; d = $DeviceId })
            Complete-ScgTx -Connection $conn
        }
        catch {
            Undo-ScgTx -Connection $conn
            throw
        }
    }
    finally {
        $conn.Dispose()
    }
}

function Invoke-ScgCommandTimeout {
    <#
    .SYNOPSIS
        Moves pending and dispatched commands older than TimeoutSec to timeout; returns the count.
    .PARAMETER Path
        Database file path.
    .PARAMETER TimeoutSec
        Age threshold in seconds (pending by created_at, dispatched by dispatched_at).
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSec
    )
    Assert-ScgCommandTransition -From 'pending' -To 'timeout'
    Assert-ScgCommandTransition -From 'dispatched' -To 'timeout'
    $cutoff = Get-ScgCutoff -Second $TimeoutSec
    $res = '{"ok":false,"output":"timeout","duration_ms":0}'
    $conn = Open-ScgConnection -Path $Path
    try {
        $total = 0
        Start-ScgTx -Connection $conn
        try {
            $now = Get-ScgUtcNow
            $total += Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql "UPDATE commands SET status='timeout', finished_at=@now, result_json=@r WHERE status='dispatched' AND dispatched_at < @c" -Parameter @{ now = $now; r = $res; c = $cutoff }
            $total += Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql "UPDATE commands SET status='timeout', finished_at=@now, result_json=@r WHERE status='pending' AND created_at < @c" -Parameter @{ now = $now; r = $res; c = $cutoff }
            Complete-ScgTx -Connection $conn
        }
        catch {
            Undo-ScgTx -Connection $conn
            throw
        }
        return [int]$total
    }
    finally {
        $conn.Dispose()
    }
}

function Set-ScgStaleDevice {
    <#
    .SYNOPSIS
        Marks active devices unseen for StaleAfterMin minutes as stale; returns the count.
    .PARAMETER Path
        Database file path.
    .PARAMETER StaleAfterMin
        Minutes without a heartbeat.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$StaleAfterMin
    )
    $cutoff = Get-ScgCutoff -Second ($StaleAfterMin * 60)
    $n = Invoke-ScgSql -Path $Path -NonQuery -Sql "UPDATE devices SET status='stale' WHERE status='active' AND last_seen < @c" -Parameter @{ c = $cutoff }
    return [int]$n
}

function Add-ScgEvent {
    <#
    .SYNOPSIS
        Inserts an event; returns its id, or null when an identical unacked event exists within ThrottleMin.
    .PARAMETER Path
        Database file path.
    .PARAMETER DeviceId
        Device id.
    .PARAMETER Type
        Event type.
    .PARAMETER Severity
        info, warn or critical.
    .PARAMETER Payload
        Payload as JSON text or object.
    .PARAMETER ThrottleMin
        Dedupe window in minutes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$DeviceId,
        [Parameter(Mandatory = $true)][ValidateSet('unknown_agent', 'new_install', 'tamper', 'agent_error', 'service_down')][string]$Type,
        [Parameter(Mandatory = $true)][ValidateSet('info', 'warn', 'critical')][string]$Severity,
        [Parameter()][AllowNull()][object]$Payload,
        [Parameter()][double]$ThrottleMin = 30
    )
    $pj = ConvertTo-ScgJsonText -Value $Payload
    if ($null -eq $pj) { $pj = '{}' }
    $cutoff = Get-ScgCutoff -Second ($ThrottleMin * 60)
    $conn = Open-ScgConnection -Path $Path
    try {
        $id = $null
        Start-ScgTx -Connection $conn
        try {
            $ex = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT id FROM events WHERE device_id=@d AND type=@t AND payload_json=@p AND acked_at IS NULL AND created_at >= @c LIMIT 1' -Parameter @{ d = $DeviceId; t = $Type; p = $pj; c = $cutoff })
            if ($ex.Count -eq 0) {
                [void](Invoke-ScgSqlCore -Connection $conn -NonQuery -Sql 'INSERT INTO events (device_id, type, severity, payload_json, created_at) VALUES (@d, @t, @s, @p, @now)' -Parameter @{ d = $DeviceId; t = $Type; s = $Severity; p = $pj; now = (Get-ScgUtcNow) })
                $r = @(Invoke-ScgSqlCore -Connection $conn -Sql 'SELECT last_insert_rowid() AS id')
                $id = [long]$r[0].id
            }
            Complete-ScgTx -Connection $conn
        }
        catch {
            Undo-ScgTx -Connection $conn
            throw
        }
        return $id
    }
    finally {
        $conn.Dispose()
    }
}

function Get-ScgEvent {
    <#
    .SYNOPSIS
        Gets the latest events, newest first.
    .PARAMETER Path
        Database file path.
    .PARAMETER Last
        Maximum rows (default 20).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter()][ValidateRange(1, 100000)][int]$Last = 20
    )
    $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM events ORDER BY created_at DESC, id DESC LIMIT @n' -Parameter @{ n = $Last }
    return $r
}

function Confirm-ScgEvent {
    <#
    .SYNOPSIS
        Acknowledges an unacked event; returns false when not found or already acked.
    .PARAMETER Path
        Database file path.
    .PARAMETER Id
        Event id.
    .PARAMETER By
        Acknowledging actor.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$Id,
        [Parameter(Mandatory = $true)][string]$By
    )
    $n = Invoke-ScgSql -Path $Path -NonQuery -Sql 'UPDATE events SET acked_at=@now, acked_by=@by WHERE id=@id AND acked_at IS NULL' -Parameter @{ now = (Get-ScgUtcNow); by = $By; id = $Id }
    return ($n -gt 0)
}

function Add-ScgAudit {
    <#
    .SYNOPSIS
        Appends an audit_log row.
    .PARAMETER Path
        Database file path.
    .PARAMETER Actor
        telegram:id, system or device:hostname.
    .PARAMETER Action
        Audit action name.
    .PARAMETER Target
        Target of the action.
    .PARAMETER Meta
        Extra data as JSON text or object (never include secrets).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Actor,
        [Parameter(Mandatory = $true)][ValidateSet('command.issue', 'command.dispatch', 'command.result', 'command.timeout', 'enroll', 'heartbeat.config_change', 'event.ingest', 'event.ack', 'remove.request', 'remove.confirm', 'auth.reject')][string]$Action,
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Target,
        [Parameter()][AllowNull()][object]$Meta
    )
    $mj = ConvertTo-ScgJsonText -Value $Meta
    [void](Invoke-ScgSql -Path $Path -NonQuery -Sql 'INSERT INTO audit_log (ts, actor, action, target, meta_json) VALUES (@ts, @actor, @action, @target, @meta)' -Parameter @{ ts = (Get-ScgUtcNow); actor = $Actor; action = $Action; target = $Target; meta = $mj })
}

function Get-ScgAudit {
    <#
    .SYNOPSIS
        Gets the latest audit rows, newest first.
    .PARAMETER Path
        Database file path.
    .PARAMETER Last
        Maximum rows (default 20).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter()][ValidateRange(1, 100000)][int]$Last = 20
    )
    $r = Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM audit_log ORDER BY ts DESC, id DESC LIMIT @n' -Parameter @{ n = $Last }
    return $r
}

function Get-ScgLastAudit {
    <#
    .SYNOPSIS
        Returns the newest audit_log row for an action and target, or null when none exists.
    .PARAMETER Path
        Database file path.
    .PARAMETER Action
        Audit action name.
    .PARAMETER Target
        Audit target.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Target
    )
    $rows = @(Invoke-ScgSql -Path $Path -Sql 'SELECT * FROM audit_log WHERE action=@a AND target=@t ORDER BY id DESC LIMIT 1' -Parameter @{ a = $Action; t = $Target })
    if ($rows.Count -eq 0) { return $null }
    return $rows[0]
}

function Get-ScgHealthCounts {
    <#
    .SYNOPSIS
        Returns devices_online (seen within StaleAfterMin) and commands_pending.
    .PARAMETER Path
        Database file path.
    .PARAMETER StaleAfterMin
        Online window in minutes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$StaleAfterMin
    )
    $cutoff = Get-ScgCutoff -Second ($StaleAfterMin * 60)
    $d = @(Invoke-ScgSql -Path $Path -Sql 'SELECT COUNT(*) AS n FROM devices WHERE last_seen >= @c' -Parameter @{ c = $cutoff })
    $c = @(Invoke-ScgSql -Path $Path -Sql "SELECT COUNT(*) AS n FROM commands WHERE status='pending'")
    return [pscustomobject]@{ devices_online = [int]$d[0].n; commands_pending = [int]$c[0].n }
}

Export-ModuleMember -Function Initialize-ScgDatabase, Get-ScgSchemaVersion, Invoke-ScgMigration, Invoke-ScgSql, Register-ScgDevice, Update-ScgDeviceSeen, Test-ScgDeviceOnline, Set-ScgDeviceStatus, Sync-ScgScAgent, Get-ScgDevice, Get-ScgScAgent, New-ScgCommand, Get-ScgDispatchableCommand, Get-ScgCommand, Complete-ScgCommand, Invoke-ScgCommandTimeout, Set-ScgStaleDevice, Add-ScgEvent, Get-ScgEvent, Confirm-ScgEvent, Add-ScgAudit, Get-ScgAudit, Get-ScgLastAudit, Get-ScgHealthCounts
