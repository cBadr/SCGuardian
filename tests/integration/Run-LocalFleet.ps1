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
