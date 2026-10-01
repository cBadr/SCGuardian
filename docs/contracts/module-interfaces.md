# SCGuardian v4 — Module Interfaces (FROZEN, contract v1)

Rules: `[CmdletBinding()]`, approved verbs, comment-based help, no `Write-Host`, no `Invoke-Expression`, no aliases.
Modules never read `$script:` globals owned by another module; everything flows through parameters.
Each module exports ONLY the functions listed. Header comment: purpose · author Badr · version.
Target: Windows PowerShell 5.1 (also loads on 7).

## Common.psm1 (no dependencies)
- `Get-ScgRoot` → string (`$env:SCG_ROOT` else `C:\ProgramData\SCGuardian`)
- `Get-ScgUtcNow` → string ISO8601 UTC ms `Z` · `ConvertTo-ScgUtcIso -InputObject [datetime]` · `ConvertFrom-ScgUtcIso -Value [string]` → `[datetime]` UTC
- `Protect-Secret -Text [string] -Secret [string[]]` → text with each secret replaced by `***` (also masks `Bearer <x>` and `bot<digits>:<token>` patterns)
- `Set-ScgLogContext -Path -MaxBytes -Secret [string[]]` (module-scoped log config) · `Write-ScgLog -Message -Level INFO|WARN|ERROR|ALERT -Actor -Target -Action -Result` (masks, rotates at MaxBytes → `.1`, never throws)
- `Read-ScgJsonFile -Path` → PSCustomObject · `Save-ScgJsonFile -Path -InputObject` (atomic write via temp+move, UTF8 no BOM)
- `Test-ScgInstanceId -Id` → bool · `ConvertTo-ScgInstanceId -Id` → lowercase string
- `New-ScgGuid` → string
- `Invoke-ScgNative -Exe -Argument [string[]]` → `{Code,Out}` (stderr-safe)
- `Get-ScgBackoffSec -Failures [int] -BaseSec [int] -MaxSec [int]` → int (agent: ≥3 failures → 300)
- `Test-ScgThrottle -LastUtc -ThrottleMin` → bool (true = still throttled)

## Database.psm1 (deps: Common; System.Data.SQLite loaded from `src/lib/`)
- `Initialize-ScgDatabase -Path` → opens/creates, applies migrations, returns schema version
- `Get-ScgSchemaVersion -Path` · `Invoke-ScgMigration -Path` (idempotent)
- `Invoke-ScgSql -Path -Sql -Parameter [hashtable] -NonQuery` / default returns rows as PSCustomObject (only function that holds raw SQL besides the domain functions below; **no other module contains SQL**)
- `Register-ScgDevice -Path -Hostname -Os -OsVersion -AgentVersion -LastIp` → device row (same id on re-enroll)
- `Update-ScgDeviceSeen -Path -DeviceId -Hostname -AgentVersion -LastIp -ConfigJson` · `Set-ScgDeviceStatus -Path -DeviceId -Status`
- `Sync-ScgScAgent -Path -DeviceId -ScAgent [object[]] -AllowedId [string[]]` (transactional upsert + delete-missing)
- `Get-ScgDevice -Path [-DeviceId] [-Hostname] [-IdPrefix] [-Page] [-PageSize]` · `Get-ScgScAgent -Path -DeviceId`
- `New-ScgCommand -Path -DeviceId -Type -Payload -IssuedBy -IssuedVia` → command id (deduped)
- `Get-ScgDispatchableCommand -Path -DeviceId` → rows, flipped to `dispatched` atomically
- `Complete-ScgCommand -Path -DeviceId -CommandId -Ok -Output -DurationMs` (enforces transitions; throws on illegal)
- `Invoke-ScgCommandTimeout -Path -TimeoutSec` → count · `Set-ScgStaleDevice -Path -StaleAfterMin` → count
- `Add-ScgEvent -Path -DeviceId -Type -Severity -Payload -ThrottleMin` → id or `$null` · `Get-ScgEvent -Path -Last` · `Confirm-ScgEvent -Path -Id -By`
- `Add-ScgAudit -Path -Actor -Action -Target -Meta` · `Get-ScgAudit -Path -Last`
- `Get-ScgHealthCounts -Path -StaleAfterMin` → `{devices_online, commands_pending}`

## HttpServer.psm1 (deps: Common)
- `Test-ScgBearer -Header -Secret` → bool (constant-time)
- `New-ScgReplayCache` → cache object · `Test-ScgReplay -Cache -Timestamp -Nonce -MaxSkewSec -NonceTtlSec -Now` → `{Ok,Status,Reason}` (Status 408/409/400)
- `Resolve-ScgRoute -Method -Path -Route` → `{Handler|Status}`
- `Start-ScgHttpServer -Url -Secret -Route -ReplayCache -OnReject -Thumbprint` / `Stop-ScgHttpServer` (listener loop; handlers run as `param($Request)` scriptblocks returning `@{Status=200;Body=<obj>}`; body ≤1 MB)
- `Initialize-ScgTlsBinding -Port -Thumbprint` (netsh http add sslcert, idempotent)

## Contract v1.2 interface additions (already implemented)
Database: `Get-ScgCommand -Path -CommandId [-DeviceId]`; `Sync-ScgScAgent -AllowEmpty`. HttpServer: exports `Invoke-ScgRequestPipeline`, `ConvertTo-ScgWorkerScriptBlock`, `ConvertTo-ScgWorkerConfig`; `Start-ScgHttpServer -MaxSkewSec -NonceTtlSec -MaxWorkers -WorkerModule -LogContext -TimeoutSec`; pipeline `-BodyProvider`. Discovery: `ConvertTo-ScAgentId`, `ConvertTo-ScAgentEntry`, `Test-ScAgentAuthorized`. Telegram: `Invoke-TgPollOnce`, `Send-TgResultNotice`. Hub handlers take `-RemoteIp`; `Start-ScgHub -NoWait`. **Hub deps also include Telegram.**

## Hub.psm1 (deps: Common, Database, HttpServer, Telegram)
- `Get-ScgHubConfig -Path` (validates, fills defaults, rejects `REPLACE_ME`)
- `New-ScgHubRoute -Config` → route table for the 5 endpoints
- `Invoke-ScgEnroll|Invoke-ScgHeartbeat|Invoke-ScgResult|Invoke-ScgEventIngest|Get-ScgHealth` (pure: take `-Config -Body` → `@{Status;Body}`)
- `Invoke-ScgHubTick -Config` (stale + timeouts) · `Start-ScgHub -ConfigPath` (HTTP + ticker + Telegram poller in runspaces)

## Discovery.psm1 (deps: Common)
- `Get-ScAgent -AllowedId` → `{Id,ServiceName,ServiceState,StartMode,Folder,UninstallKey,Authorized}` (legacy `Get-Agents` logic, parameterised)
- `Get-ScServerProduct` · `ConvertTo-ScHeartbeatAgent -Agent` → wire shape `{id,service,folder,uninstall_key,state}`

## Hardening.psm1 (deps: Common)
Legacy H1–H4 verbatim logic, parameterised: `Invoke-ScHardening -Agent -Layer -BackupDir [-TakeOwnership]` · `Invoke-ScRestore -Agent -BackupDir` → `{Ok,Messages}` · `Remove-ScAgent -Agent -AllowedId -BackupDir` (refuses allow-listed, backs up first) · `Test-ScTamper -Agent -BackupDir` → bool (service SD differs from hardened SD)

## Agent.psm1 (deps: Common, Discovery, Hardening)
- `Get-ScgAgentConfig -Path` / `Update-ScgAgentConfig -Path -ServerConfig` (whitelist keys only)
- `Invoke-HubApi -Config -Method -Path -Body` (**sole HTTP client**: signs headers, TLS 1.2, thumbprint pinning, timeout 30s)
- `Invoke-ScgAgentCycle -ConfigPath` (watchdog first → enroll if needed → heartbeat → config → commands → results → events)
- `Invoke-ScgAgentCommand -Command -Config` → `{ok,output}` · `Invoke-ScgLocalWatchdog -Config` (legacy Monitor behaviour)
- `Update-ScgBackoffState -State -Success` (3 failures → 300 s; log once/10 min)
- `Get-ScgNextDelaySec` (`-ConfigPath` | `-Config -State`) → seconds until next cycle (scheduler loop)

## Telegram.psm1 (deps: Common, Database)
- `Invoke-TgApi -Token -Method -Body` (**sole Telegram client**; never logs token)
- `Get-TgUpdate -Token -Offset` (long-poll `timeout=25`)
- `ConvertFrom-TgCommand -Text` → `{Command,Argument[]}` (strips `@bot`)
- `Test-TgAdmin -From -AdminUserId -AdminUsername` → bool
- `New-TgMenu -Name -Context` → reply_markup · `Invoke-TgRouter -Update -Config -Send [scriptblock]` (injectable sender for tests)
- `New-TgRemoveCode`/pending-remove stored in memory with TTL `command_confirm_sec`; 6 digits; one-use.
