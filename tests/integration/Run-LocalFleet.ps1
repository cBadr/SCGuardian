<#
.SYNOPSIS
    End-to-end local fleet: real Hub in-process + N shimmed agent workers + mock Telegram dispatcher.
.DESCRIPTION
    Everything lives in a temp root (SCG_ROOT is set per process; C:\ProgramData\SCGuardian is never touched).
    Elevated  : https://localhost:PORT/ with a throw-away self-signed cert (netsh sslcert + cert removed in finally).
    Otherwise : http://localhost:PORT/ (agents accept http on loopback only).
    Telegram  : fake token/chat; Enable-ScgTestNetworkGuard blackholes every non-loopback request in this process,
                so the hub's poller and result notices never reach the Internet. Commands are driven by calling
                Invoke-TgRouter with synthetic admin updates and an injected -Send.
    Prints PASS/FAIL lines; exit code 0 when all pass, else 1.
    Author: Badr - Version 4.0.0
.PARAMETER Port
    Listen port (default 8443; a free port is chosen when busy).
.PARAMETER Agents
    Number of agent workers (default 3, minimum 2 for the isolation check).
.PARAMETER KeepArtifacts
    Keep the temp root for inspection.
.PARAMETER TimeoutSec
    Max wait for each asynchronous expectation.
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\integration\Run-LocalFleet.ps1 -Agents 3
#>
[CmdletBinding()]
param(
    [int]$Port = 8443,
    [ValidateRange(2, 9)][int]$Agents = 3,
    [switch]$KeepArtifacts,
    [ValidateRange(10, 600)][int]$TimeoutSec = 90
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

Import-Module (Join-Path $PSScriptRoot 'ScgTestHelpers.psm1') -Force -DisableNameChecking
Import-ScgTestProductModule

$script:Fail = 0
function Write-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Output ('PASS: ' + $Name) }
    else { $script:Fail++; Write-Output ('FAIL: ' + $Name + $(if ($Detail) { ' -- ' + $Detail } else { '' })) }
}
function Wait-Condition {
    param([scriptblock]$Condition, [int]$Seconds)
    $end = [datetime]::UtcNow.AddSeconds($Seconds)
    while ([datetime]::UtcNow -lt $end) {
        $ok = $false
        try { $ok = [bool](& $Condition) } catch { $ok = $false }
        if ($ok) { return $true }
        Start-Sleep -Milliseconds 750
    }
    return $false
}
function Get-CommandCallCount {
    param([string]$Root)
    return @(Read-ScgTestShimLog -Root $Root | Where-Object { $_.phase -eq 'command' -and $_.fn -eq 'Invoke-ScHardening' }).Count
}

$root = New-ScgTestRoot -Prefix 'scg-fleet'
$savedRoot = $env:SCG_ROOT
$hubRoot = Join-Path $root 'hub'
[void](New-Item -ItemType Directory -Path $hubRoot -Force)
$env:SCG_ROOT = $hubRoot

$hub = $null
$procs = New-Object System.Collections.ArrayList
$workers = New-Object System.Collections.ArrayList
$certThumb = ''
$bindPort = 0
$elevated = Test-ScgTestElevated
try {
    if (-not (Test-ScgTestPortFree -Port $Port)) {
        $old = $Port
        $Port = Get-ScgTestFreePort
        Write-Output "INFO: port $old busy, using $Port"
    }
    $secret = New-ScgTestSecret
    $adminId = '424242'
    $chatId = '-1000000000042'
    if ($elevated) {
        $cert = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'SCGuardian integration test (temporary)' -NotAfter (Get-Date).AddDays(1)
        $certThumb = $cert.Thumbprint.ToUpperInvariant()
        $bindPort = $Port
        $listenUrl = "https://localhost:$Port/"
        Write-Output "MODE: https (elevated, temporary self-signed cert $certThumb)"
    }
    else {
        $listenUrl = "http://localhost:$Port/"
        Write-Output 'MODE: http loopback (not elevated; TLS path not exercised)'
    }
    $thumbCfg = 'auto'
    if ($certThumb) { $thumbCfg = $certThumb }
    $hubCfgPath = New-ScgTestHubConfig -HubRoot $hubRoot -Url $listenUrl -Secret $secret -Thumbprint $thumbCfg -AdminId $adminId -ChatId $chatId
    $base = $listenUrl.TrimEnd('/')

    Enable-ScgTestNetworkGuard
    $hub = Start-ScgTestHub -ConfigPath $hubCfgPath
    $cfg = $hub.Config
    $db = [string]$cfg.database.path

    $shim = Join-Path $PSScriptRoot 'AgentShim.ps1'
    for ($i = 1; $i -le $Agents; $i++) {
        $aRoot = Join-Path $root ("agent$i")
        $hostName = "scg-it-host$i"
        $aCfg = New-ScgTestAgentConfig -AgentRoot $aRoot -HubUrl $base -Secret $secret -Hostname $hostName -Thumbprint $certThumb
        $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Root "{1}" -ConfigPath "{2}" -LoopSec 1.5 -MaxSeconds {3}' -f $shim, $aRoot, $aCfg, ($TimeoutSec * 6)
        $p = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $argLine -NoNewWindow -PassThru `
            -RedirectStandardOutput (Join-Path $aRoot 'stdout.txt') -RedirectStandardError (Join-Path $aRoot 'stderr.txt')
        [void]$procs.Add($p)
        [void]$workers.Add([pscustomobject]@{ Host = $hostName; Root = $aRoot; Config = $aCfg })
    }

    # 1. enrollment
    $enrolled = Wait-Condition -Seconds $TimeoutSec -Condition { @(Get-ScgDevice -Path $db).Count -ge $Agents }
    $devs = @(Get-ScgDevice -Path $db)
    $names = @($devs | ForEach-Object { [string]$_.hostname })
    $allIn = $enrolled -and (@($workers | Where-Object { $names -notcontains $_.Host }).Count -eq 0)
    Write-Check "all $Agents devices enrolled" $allIn ('enrolled: ' + ($names -join ','))
    foreach ($w in $workers) {
        $d = @($devs | Where-Object { [string]$_.hostname -eq $w.Host }) | Select-Object -First 1
        $id = ''
        if ($d) { $id = [string]$d.id }
        $w | Add-Member -NotePropertyName DeviceId -NotePropertyValue $id
    }

    # 1b. per-device tokens: agent config holds the raw token, DB only a 64-hex hash
    $tokOk = Wait-Condition -Seconds $TimeoutSec -Condition { @($workers | Where-Object { -not (Get-ScgTestAgentToken -ConfigPath $_.Config) }).Count -eq 0 }
    foreach ($w in $workers) { $w | Add-Member -NotePropertyName Token -NotePropertyValue (Get-ScgTestAgentToken -ConfigPath $w.Config) -Force }
    Write-Check 'every agent.config.json holds a device_token' ($tokOk -and (@($workers | Where-Object { $_.Token.Length -lt 20 }).Count -eq 0))
    $devs = @(Get-ScgDevice -Path $db)
    $hashBad = @($devs | Where-Object { ([string]$_.token_hash) -notmatch '^[0-9a-f]{64}$' })
    $rawInDb = @($workers | Where-Object { $t = $_.Token; $t -and (@($devs | Where-Object { ([string]$_.token_hash) -eq $t }).Count -gt 0) })
    Write-Check 'DB holds only 64-hex token_hash (no raw token)' (($hashBad.Count -eq 0) -and ($rawInDb.Count -eq 0)) ('bad hashes: ' + $hashBad.Count)
    $uniq = @($workers | ForEach-Object { $_.Token } | Select-Object -Unique).Count
    Write-Check 'each agent has a distinct token' ($uniq -eq $Agents)

    # 2. mock Telegram: /devices
    $sent = New-Object System.Collections.ArrayList
    $send = { param($Text, $Markup, $ChatId, $EditMessageId) [void]$sent.Add([pscustomobject]@{ Text = [string]$Text; Markup = (ConvertTo-Json -InputObject $Markup -Depth 10 -Compress) }) }.GetNewClosure()
    $uid = 1
    Invoke-TgRouter -Update (New-ScgTestTgUpdate -Text '/devices' -FromId $adminId -ChatId $chatId -UpdateId ($uid++)) -Config $cfg -Send $send
    $menu = (@($sent) | ForEach-Object { $_.Text + ' ' + $_.Markup }) -join ' '
    Write-Check '/devices lists every host' (@($workers | Where-Object { $menu -notlike ('*' + $_.Host + '*') }).Count -eq 0) $menu

    # 3. /harden <host>: delivered only to the target
    $target = $workers[1]
    $others = @($workers | Where-Object { $_.Host -ne $target.Host })
    Invoke-TgRouter -Update (New-ScgTestTgUpdate -Text ('/harden ' + $target.Host) -FromId $adminId -ChatId $chatId -UpdateId ($uid++)) -Config $cfg -Send $send
    $done = Wait-Condition -Seconds $TimeoutSec -Condition {
        @(Invoke-ScgSql -Path $db -Sql "SELECT id FROM commands WHERE device_id=@d AND type='harden' AND status IN ('done','failed')" -Parameter @{ d = $target.DeviceId }).Count -ge 1
    }
    $row = @(Invoke-ScgSql -Path $db -Sql "SELECT status, result_json FROM commands WHERE device_id=@d AND type='harden'" -Parameter @{ d = $target.DeviceId }) | Select-Object -First 1
    $rowOk = $done -and $row -and ([string]$row.status -eq 'done') -and -not [string]::IsNullOrWhiteSpace([string]$row.result_json)
    $rowDetail = 'no row'
    if ($row) { $rowDetail = 'status=' + [string]$row.status }
    Write-Check 'targeted command row is done with result_json' $rowOk $rowDetail
    Start-Sleep -Seconds 4
    Write-Check 'target agent executed the command (shim log)' ((Get-CommandCallCount -Root $target.Root) -ge 1)
    $leak = @($others | Where-Object { (Get-CommandCallCount -Root $_.Root) -gt 0 -or @(Invoke-ScgSql -Path $db -Sql 'SELECT id FROM commands WHERE device_id=@d' -Parameter @{ d = $_.DeviceId }).Count -gt 0 })
    Write-Check 'non-targeted agents received nothing' ($leak.Count -eq 0) ('leaked to: ' + (@($leak | ForEach-Object { $_.Host }) -join ','))

    # 4. unknown_agent stored once per device despite many cycles
    $ev = @(Invoke-ScgSql -Path $db -Sql "SELECT device_id, COUNT(*) AS n FROM events WHERE type='unknown_agent' GROUP BY device_id")
    $evOk = ($ev.Count -eq $Agents) -and (@($ev | Where-Object { [int]$_.n -ne 1 }).Count -eq 0)
    Write-Check 'unknown_agent event deduplicated (exactly one per device)' $evOk (($ev | ForEach-Object { "$($_.device_id)=$($_.n)" }) -join ',')

    # 5. /harden all
    Invoke-TgRouter -Update (New-ScgTestTgUpdate -Text '/harden all' -FromId $adminId -ChatId $chatId -UpdateId ($uid++)) -Config $cfg -Send $send
    $allDone = Wait-Condition -Seconds $TimeoutSec -Condition {
        @(Invoke-ScgSql -Path $db -Sql "SELECT DISTINCT device_id FROM commands WHERE type='harden' AND status='done'").Count -ge $Agents -and
        @(Invoke-ScgSql -Path $db -Sql "SELECT id FROM commands WHERE type='harden' AND status IN ('pending','dispatched')").Count -eq 0
    }
    Start-Sleep -Seconds 3
    $missing = @($workers | Where-Object { (Get-CommandCallCount -Root $_.Root) -lt 1 })
    Write-Check '/harden all reached every agent' ($allDone -and $missing.Count -eq 0) ('missing: ' + (@($missing | ForEach-Object { $_.Host }) -join ','))

    # 6. audit trail
    $acts = @(Invoke-ScgSql -Path $db -Sql 'SELECT DISTINCT action FROM audit_log' | ForEach-Object { [string]$_.action })
    foreach ($a in @('command.issue', 'command.dispatch', 'command.result')) { Write-Check "audit contains $a" ($acts -contains $a) }

    # 7. raw HTTP: health, replay, wrong bearer
    $nonce = [guid]::NewGuid().ToString()
    $h1 = Invoke-ScgTestRequest -Url ($base + '/api/v1/health') -Bearer $secret -Nonce $nonce -Thumbprint $certThumb
    $okBody = $false
    try { $okBody = [bool](($h1.Text | ConvertFrom-Json).ok) } catch { $okBody = $false }
    Write-Check '/health ok' (($h1.Status -eq 200) -and $okBody) ("status=$($h1.Status)")
    $h2 = Invoke-ScgTestRequest -Url ($base + '/api/v1/health') -Bearer $secret -Nonce $nonce -Thumbprint $certThumb
    Write-Check 'replayed nonce returns 409' ($h2.Status -eq 409) ("status=$($h2.Status)")
    $h3 = Invoke-ScgTestRequest -Url ($base + '/api/v1/health') -Bearer ('wrong-' + $secret.Substring(0, 8)) -Thumbprint $certThumb
    Write-Check 'wrong bearer returns 401 with no data' (($h3.Status -eq 401) -and ($h3.Text -notmatch 'devices_online|uptime_sec|commands_pending|version')) ("status=$($h3.Status)")

    # 8. device token enforcement on raw heartbeats
    $vic = $workers[0]
    $oth = $workers[1]
    $hbBody = { param($w) @{ device_id = $w.DeviceId; hostname = $w.Host; sc_agents = @(); uptime_sec = 1; agent_version = '0.0.0-it' } }
    $r1 = Invoke-ScgTestRequest -Url ($base + '/api/v1/heartbeat') -Method POST -Bearer $secret -Body (& $hbBody $vic) -Thumbprint $certThumb
    Write-Check 'heartbeat without X-SCG-Device-Token returns 401' ($r1.Status -eq 401) ("status=$($r1.Status)")
    $r2 = Invoke-ScgTestRequest -Url ($base + '/api/v1/heartbeat') -Method POST -Bearer $secret -Body (& $hbBody $vic) -Thumbprint $certThumb -Headers @{ 'X-SCG-Device-Token' = $oth.Token }
    Write-Check "heartbeat with another device's token returns 401 and leaks nothing" (($r2.Status -eq 401) -and ($r2.Text -notmatch '"commands"|allowed_ids|scan_interval_sec')) ("status=$($r2.Status)")
    $r3 = Invoke-ScgTestRequest -Url ($base + '/api/v1/heartbeat') -Method POST -Bearer $secret -Body (& $hbBody $vic) -Thumbprint $certThumb -Headers @{ 'X-SCG-Device-Token' = 'x' * 43 }
    Write-Check 'heartbeat with a garbage token returns 401' ($r3.Status -eq 401) ("status=$($r3.Status)")

    # 9. duplicate raw /enroll for an enrolled hostname
    $enBody = @{ hostname = $vic.Host; os = 'Windows'; os_version = '10.0'; agent_version = '0.0.0-it' }
    $e1 = Invoke-ScgTestRequest -Url ($base + '/api/v1/enroll') -Method POST -Bearer $secret -Body $enBody -Thumbprint $certThumb
    Write-Check 'second /enroll for an enrolled hostname returns 409 without a token' (($e1.Status -eq 409) -and ($e1.Text -notmatch 'device_token')) ("status=$($e1.Status)")
    $hbBefore = [string](@(Get-ScgDevice -Path $db -DeviceId $vic.DeviceId) | Select-Object -First 1).last_seen
    $kept = Wait-Condition -Seconds $TimeoutSec -Condition { [string](@(Get-ScgDevice -Path $db -DeviceId $vic.DeviceId) | Select-Object -First 1).last_seen -ne $hbBefore }
    Write-Check 'existing agent keeps working after the rejected enroll' ($kept -and ((Get-ScgTestAgentToken -ConfigPath $vic.Config) -eq $vic.Token))

    # 10. admin /reset <host>: 401 device not enrolled, re-enroll, NEW token, old token dead
    $oldTok = $vic.Token
    Invoke-TgRouter -Update (New-ScgTestTgUpdate -Text ('/reset ' + $vic.Host) -FromId $adminId -ChatId $chatId -UpdateId ($uid++)) -Config $cfg -Send $send
    $rej = Wait-Condition -Seconds $TimeoutSec -Condition {
        @(Invoke-ScgSql -Path $db -Sql "SELECT id FROM audit_log WHERE action='auth.reject' AND meta_json LIKE '%device_not_enrolled%'").Count -ge 1
    }
    Write-Check 'reset agent is answered 401 device not enrolled (audit)' $rej
    $newTok = ''
    $renew = Wait-Condition -Seconds $TimeoutSec -Condition {
        $t = Get-ScgTestAgentToken -ConfigPath $vic.Config
        $d = @(Get-ScgDevice -Path $db -DeviceId $vic.DeviceId) | Select-Object -First 1
        $t -and ($t -ne $oldTok) -and $d -and ([string]$d.token_hash -match '^[0-9a-f]{64}$')
    }
    $newTok = Get-ScgTestAgentToken -ConfigPath $vic.Config
    Write-Check 'agent re-enrolled and received a NEW token' ($renew -and $newTok -and ($newTok -ne $oldTok))
    $r4 = Invoke-ScgTestRequest -Url ($base + '/api/v1/heartbeat') -Method POST -Bearer $secret -Body (& $hbBody $vic) -Thumbprint $certThumb -Headers @{ 'X-SCG-Device-Token' = $oldTok }
    Write-Check 'old token is rejected with 401 after re-enroll' ($r4.Status -eq 401) ("status=$($r4.Status)")
    $stillDev = @(Get-ScgDevice -Path $db | Where-Object { [string]$_.hostname -eq $vic.Host }).Count
    Write-Check 're-enroll reuses the same device row' ($stillDev -eq 1)

    # 11. raw tokens never reach logs
    $allTokens = @($workers | ForEach-Object { $_.Token }) + @($newTok) | Where-Object { $_ } | Select-Object -Unique
    $leakedTok = @($allTokens | Where-Object { Test-ScgTestTextContains -Root @($root) -Needle $_ })
    Write-Check 'no raw device token appears in hub or agent logs' ($leakedTok.Count -eq 0) ('leaked: ' + $leakedTok.Count)
}
catch {
    $script:Fail++
    Write-Output ('FAIL: harness error -- ' + $_.Exception.Message)
}
finally {
    foreach ($w in $workers) { try { [void](New-Item -ItemType File -Path (Join-Path $w.Root 'stop.flag') -Force) } catch { $null = $_ } }
    foreach ($p in $procs) {
        try { if (-not $p.WaitForExit(10000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch { $null = $_ }
    }
    Stop-ScgTestHub -Hub $hub
    Disable-ScgTestNetworkGuard
    if ($bindPort -gt 0) { & netsh http delete sslcert "ipport=0.0.0.0:$bindPort" 2>&1 | Out-Null }
    if ($certThumb) { Remove-Item -LiteralPath ("Cert:\LocalMachine\My\" + $certThumb) -Force -ErrorAction SilentlyContinue }
    [Environment]::SetEnvironmentVariable('SCG_HUB_CONFIG', $null)
    $env:SCG_ROOT = $savedRoot
    if ($KeepArtifacts) { Write-Output "INFO: artifacts kept at $root" }
    elseif (-not (Remove-ScgTestPath -Path $root)) { Write-Output "WARN: could not fully remove $root" }
}

if ($script:Fail -gt 0) { Write-Output "RESULT: $($script:Fail) check(s) failed"; exit 1 }
Write-Output 'RESULT: all checks passed'
exit 0
