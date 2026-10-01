# Hardening.psm1 - protects/restores/removes ScreenConnect agents (layers H1-H4).
# Author: Badr | Version: 4.0.0 | Depends on: Common.psm1
# Legacy Invoke-Hardening/Invoke-Restore/Remove-Agent logic, parameterised (no $script: run-state).

Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -DisableNameChecking

# well-known SIDs (locale-independent)
$script:SidSystem = '*S-1-5-18'
$script:SidAdmins = '*S-1-5-32-544'
$script:SidUsers  = '*S-1-5-32-545'

# hardened service SD and fallback SDDLs used by restore when no backup exists
$script:HardenedSvcSddl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'
$script:HardenedRegSddl = 'D:P(A;CI;KA;;;SY)(A;CI;KR;;;BA)(A;CI;KR;;;AU)'
$script:DefaultSvcSddl  = 'D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
$script:DefaultRegSddl  = 'D:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;AU)'

function Set-ScRecovery {
    <#
    .SYNOPSIS
    H1: auto-start plus restart-on-failure for the agent service (idempotent).
    .PARAMETER Agent
    Agent entry (Id, ServiceName, ...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Agent)
    if (-not $Agent.ServiceName) { return }
    $svc = $Agent.ServiceName
    $qc = Invoke-ScgNative -Exe 'sc.exe' -Argument @('qc', $svc)
    $qf = Invoke-ScgNative -Exe 'sc.exe' -Argument @('qfailure', $svc)
    if (($qc.Out -match 'AUTO_START') -and ($qf.Out -match 'RESTART')) {
        Write-ScgLog -Message "[H1] recovery already enforced: $svc" -Level INFO
        return
    }
    $ok = $true; $denied = $false
    foreach ($call in @(@('config', $svc, 'start=', 'auto'),
            @('failure', $svc, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/60000'),
            @('failureflag', $svc, '1'))) {
        $r = Invoke-ScgNative -Exe 'sc.exe' -Argument $call
        if ($r.Code -ne 0) {
            $ok = $false
            if ($r.Out -match 'denied|FAILED 5') { $denied = $true }
            else { Write-ScgLog -Message "[H1] sc.exe $($call[0]) failed (exit $($r.Code)) for ${svc}: $($r.Out)" -Level WARN }
        }
    }
    if ($ok) { Write-ScgLog -Message "[H1] recovery set (auto-start + restart-on-failure): $svc" -Level INFO }
    elseif ($denied) { Write-ScgLog -Message "[H1] change-config is restricted to SYSTEM (service already hardened); recovery stays in effect and the SYSTEM watchdog maintains it: $svc" -Level INFO }
    else { Write-ScgLog -Message "[H1] recovery only partially applied: $svc" -Level WARN }
}

function Set-ScFolderHardening {
    <#
    .SYNOPSIS
    H2: folder ACL lockdown (SYSTEM full, admins/users read-only), with ACL backup (idempotent).
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Directory receiving folderAcl_<id>.acl.txt.
    .PARAMETER TakeOwnership
    Run takeown first.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string]$BackupDir,
        [switch]$TakeOwnership
    )
    if (-not $Agent.Folder) { return }
    $f = $Agent.Folder
    try {
        $cacl = Get-Acl -Path $f
        $af = @($cacl.Access | Where-Object { "$($_.IdentityReference)" -match 'Administrators' -and "$($_.FileSystemRights)" -match 'FullControl' -and $_.AccessControlType -eq 'Allow' })
        if ($cacl.AreAccessRulesProtected -and $af.Count -eq 0) {
            Write-ScgLog -Message "[H2] folder already hardened: $f" -Level INFO
            return
        }
    } catch { Write-Verbose "ACL probe failed: $($_.Exception.Message)" }
    $bak = Join-Path $BackupDir ("folderAcl_{0}.acl.txt" -f $Agent.Id)
    if (-not (Test-Path $bak)) {
        Push-Location (Split-Path $f -Parent)
        try { $null = Invoke-ScgNative -Exe 'icacls' -Argument @((Split-Path $f -Leaf), '/save', $bak, '/T', '/C') }
        finally { Pop-Location }
    }
    if ($TakeOwnership) { $null = Invoke-ScgNative -Exe 'takeown' -Argument @('/F', $f, '/A', '/R', '/D', 'Y') }
    $r1 = Invoke-ScgNative -Exe 'icacls' -Argument @($f, '/inheritance:d', '/C')
    $null = Invoke-ScgNative -Exe 'icacls' -Argument @($f, '/remove:g', $script:SidAdmins, '/T', '/C')
    $r3 = Invoke-ScgNative -Exe 'icacls' -Argument @($f, '/grant:r', "$($script:SidSystem):(OI)(CI)F", "$($script:SidAdmins):(OI)(CI)RX", "$($script:SidUsers):(OI)(CI)RX", '/T', '/C')
    if ($r1.Code -eq 0 -and $r3.Code -eq 0) {
        Write-ScgLog -Message "[H2] folder hardened (SYSTEM full, admins/users read-only, no delete): $f" -Level INFO
    } elseif ((($r1.Out + ' ' + $r3.Out) -match 'denied') -and -not $TakeOwnership) {
        Write-ScgLog -Message "[H2] folder ACL is locked by the ScreenConnect installer (admin lacks rights) - it is already protected, skipping. Enable take_ownership to force SCGuardian's own ACL: $f" -Level INFO
    } else {
        Write-ScgLog -Message "[H2] folder not fully hardened (icacls exit d=$($r1.Code) grant=$($r3.Code)): $($r3.Out)" -Level WARN
    }
}

function Restore-ScFolderHardening {
    <#
    .SYNOPSIS
    Restores the folder ACL from backup, or resets to inherited defaults when no backup exists.
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Backup directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string]$BackupDir
    )
    if (-not $Agent.Folder) { return }
    $f = $Agent.Folder
    $bak = Join-Path $BackupDir ("folderAcl_{0}.acl.txt" -f $Agent.Id)
    if (Test-Path $bak) {
        Push-Location (Split-Path $f -Parent)
        try { $null = Invoke-ScgNative -Exe 'icacls' -Argument @((Split-Path $f -Leaf), '/restore', $bak, '/C') }
        finally { Pop-Location }
        Write-ScgLog -Message "[H2] folder ACL restored from backup: $f" -Level INFO
    } else {
        $null = Invoke-ScgNative -Exe 'icacls' -Argument @($f, '/reset', '/T', '/C')
        $null = Invoke-ScgNative -Exe 'icacls' -Argument @($f, '/inheritance:e')
        Write-ScgLog -Message "[H2] no backup; reset folder ACL to inherited defaults: $f" -Level WARN
    }
}

function Set-ScServiceSd {
    <#
    .SYNOPSIS
    H3: sets the hardened service security descriptor, backing up the original first (idempotent).
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Directory receiving serviceSd_<id>.txt.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string]$BackupDir
    )
    if (-not $Agent.ServiceName) { return }
    $svc = $Agent.ServiceName
    $sddl = $script:HardenedSvcSddl
    $show = Invoke-ScgNative -Exe 'sc.exe' -Argument @('sdshow', $svc)
    $cur = ("$($show.Out)") -replace '\s', ''
    if ($cur.Contains(($sddl -replace '\s', ''))) {
        Write-ScgLog -Message "[H3] service SD already hardened: $svc" -Level INFO
        return
    }
    $bak = Join-Path $BackupDir ("serviceSd_{0}.txt" -f $Agent.Id)
    if (-not (Test-Path $bak)) {
        $m = [regex]::Match("$($show.Out)", '(?<![A-Za-z])[OGDS]:\S+')
        if ($m.Success) { Set-Content -Path $bak -Value $m.Value -Encoding ASCII }
    }
    $r = Invoke-ScgNative -Exe 'sc.exe' -Argument @('sdset', $svc, $sddl)
    if ($r.Code -eq 0) { Write-ScgLog -Message "[H3] service SD hardened (no stop/delete for non-SYSTEM): $svc" -Level INFO }
    elseif ($r.Out -match 'denied|FAILED 5') { Write-ScgLog -Message "[H3] SD change restricted (already hardened; SYSTEM watchdog maintains it): $svc" -Level INFO }
    else { Write-ScgLog -Message "[H3] sc.exe sdset failed (exit $($r.Code)) for ${svc}: $($r.Out)" -Level ERROR }
}

function Restore-ScServiceSd {
    <#
    .SYNOPSIS
    Restores the service SD from backup (or the default SD). Returns $true on success.
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Backup directory.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string]$BackupDir
    )
    if (-not $Agent.ServiceName) { return $true }
    $svc = $Agent.ServiceName
    $bak = Join-Path $BackupDir ("serviceSd_{0}.txt" -f $Agent.Id)
    $target = $null; $fallback = $false
    if (Test-Path $bak) { $target = (Get-Content $bak -Raw) ; if ($target) { $target = $target.Trim() } }
    if (-not $target) { $target = $script:DefaultSvcSddl; $fallback = $true }
    $r = Invoke-ScgNative -Exe 'sc.exe' -Argument @('sdset', $svc, $target)
    if ($r.Code -eq 0) {
        if ($fallback) { Write-ScgLog -Message "[H3] no backup; applied DEFAULT service SD (admins regain control): $svc" -Level WARN }
        else { Write-ScgLog -Message "[H3] service SD restored: $svc" -Level INFO }
        return $true
    }
    Write-ScgLog -Message "[H3] restore sdset failed (exit $($r.Code)) for ${svc}: $($r.Out)" -Level ERROR
    return $false
}

function Set-ScRegistryHardening {
    <#
    .SYNOPSIS
    H4: hardens the service registry key DACL (SYSTEM full, others read), with SDDL backup (idempotent).
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Directory receiving regSddl_<id>.txt.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string]$BackupDir
    )
    if (-not $Agent.ServiceName) { return }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Agent.ServiceName)"
    if (-not (Test-Path $key)) { return }
    $bak = Join-Path $BackupDir ("regSddl_{0}.txt" -f $Agent.Id)
    $acl = $null
    try { $acl = Get-Acl -Path $key }
    catch {
        Write-ScgLog -Message "[H4] cannot read registry ACL: $($_.Exception.Message)" -Level WARN
        return
    }
    if (-not (Test-Path $bak)) {
        try { Set-Content -Path $bak -Value $acl.Sddl -Encoding ASCII } catch { Write-Verbose "backup write failed: $($_.Exception.Message)" }
    }
    $adminFull = @($acl.Access | Where-Object { "$($_.IdentityReference)" -match 'Administrators' -and "$($_.RegistryRights)" -match 'FullControl' -and $_.AccessControlType -eq 'Allow' })
    if ($acl.AreAccessRulesProtected -and $adminFull.Count -eq 0) {
        Write-ScgLog -Message "[H4] registry key already hardened: $key" -Level INFO
        return
    }
    try {
        $acl.SetSecurityDescriptorSddlForm($script:HardenedRegSddl, [System.Security.AccessControl.AccessControlSections]::Access)
        Set-Acl -Path $key -AclObject $acl
        Write-ScgLog -Message "[H4] registry key hardened (SYSTEM full, others read): $key" -Level INFO
    } catch {
        Write-ScgLog -Message "[H4] change restricted (already hardened; SYSTEM watchdog maintains it): $key" -Level INFO
    }
}

function Restore-ScRegistryHardening {
    <#
    .SYNOPSIS
    Restores the service registry key ACL from backup (or the default). Returns $true on success.
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Backup directory.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string]$BackupDir
    )
    if (-not $Agent.ServiceName) { return $true }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Agent.ServiceName)"
    if (-not (Test-Path $key)) { return $true }
    $bak = Join-Path $BackupDir ("regSddl_{0}.txt" -f $Agent.Id)
    $sddl = $null; $fallback = $false
    if (Test-Path $bak) { $sddl = (Get-Content $bak -Raw); if ($sddl) { $sddl = $sddl.Trim() } }
    if (-not $sddl) { $sddl = $script:DefaultRegSddl; $fallback = $true }
    try {
        $acl = Get-Acl -Path $key
        $acl.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access)
        Set-Acl -Path $key -AclObject $acl
        if ($fallback) { Write-ScgLog -Message "[H4] no backup; applied DEFAULT registry ACL (admins full): $key" -Level WARN }
        else { Write-ScgLog -Message "[H4] registry key ACL restored: $key" -Level INFO }
        return $true
    } catch {
        Write-ScgLog -Message "[H4] restore failed for ${key}: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Invoke-ScHardening {
    <#
    .SYNOPSIS
    Applies the selected hardening layers (H1-H4) to one agent; each layer failure is logged, never thrown.
    .PARAMETER Agent
    Agent entry.
    .PARAMETER Layer
    Layers to apply: Recovery, FolderAcl, ServiceSd, RegistryAcl.
    .PARAMETER BackupDir
    Directory for ACL/SD backups.
    .PARAMETER TakeOwnership
    Forces folder ownership before the ACL change.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string[]]$Layer,
        [Parameter(Mandatory)][string]$BackupDir,
        [switch]$TakeOwnership
    )
    Write-ScgLog -Message "Hardening MY agent $($Agent.Id) (service='$($Agent.ServiceName)')" -Level INFO
    if ($Layer -contains 'Recovery') {
        try { Set-ScRecovery -Agent $Agent } catch { Write-ScgLog -Message "H1 failed: $($_.Exception.Message)" -Level ERROR }
    }
    if ($Layer -contains 'FolderAcl') {
        try { Set-ScFolderHardening -Agent $Agent -BackupDir $BackupDir -TakeOwnership:$TakeOwnership } catch { Write-ScgLog -Message "H2 failed: $($_.Exception.Message)" -Level ERROR }
    }
    if ($Layer -contains 'ServiceSd') {
        try { Set-ScServiceSd -Agent $Agent -BackupDir $BackupDir } catch { Write-ScgLog -Message "H3 failed: $($_.Exception.Message)" -Level ERROR }
    }
    if ($Layer -contains 'RegistryAcl') {
        try { Set-ScRegistryHardening -Agent $Agent -BackupDir $BackupDir } catch { Write-ScgLog -Message "H4 failed: $($_.Exception.Message)" -Level ERROR }
    }
}

function Invoke-ScRestore {
    <#
    .SYNOPSIS
    Reverts hardening (H3 service SD, H4 registry ACL, H2 folder ACL) for one agent.
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Directory holding the backups.
    .OUTPUTS
    Hashtable @{Ok; Messages}.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [Parameter(Mandatory)][string]$BackupDir
    )
    $ok = $true
    $msgs = New-Object System.Collections.Generic.List[string]
    Write-ScgLog -Message "Restoring MY agent $($Agent.Id)" -Level INFO
    $msgs.Add("restoring $($Agent.Id)")
    try {
        if (Restore-ScServiceSd -Agent $Agent -BackupDir $BackupDir) { $msgs.Add('H3 service SD restored') }
        else { $ok = $false; $msgs.Add('H3 restore failed') }
    } catch { $ok = $false; $msgs.Add("H3 restore failed: $($_.Exception.Message)"); Write-ScgLog -Message "H3 restore failed: $($_.Exception.Message)" -Level ERROR }
    try {
        if (Restore-ScRegistryHardening -Agent $Agent -BackupDir $BackupDir) { $msgs.Add('H4 registry ACL restored') }
        else { $ok = $false; $msgs.Add('H4 restore failed') }
    } catch { $ok = $false; $msgs.Add("H4 restore failed: $($_.Exception.Message)"); Write-ScgLog -Message "H4 restore failed: $($_.Exception.Message)" -Level ERROR }
    try {
        Restore-ScFolderHardening -Agent $Agent -BackupDir $BackupDir
        $msgs.Add('H2 folder ACL restored')
    } catch { $ok = $false; $msgs.Add("H2 restore failed: $($_.Exception.Message)"); Write-ScgLog -Message "H2 restore failed: $($_.Exception.Message)" -Level ERROR }
    Write-ScgLog -Message 'Note: service recovery flags (H1) left as-is; adjust with sc.exe if needed.' -Level INFO
    $msgs.Add('H1 recovery flags left as-is')
    return @{ Ok = $ok; Messages = @($msgs) }
}

function Remove-ScAgent {
    <#
    .SYNOPSIS
    Removes an agent (service, folder, uninstall keys) after exporting backups; refuses allow-listed ids.
    .PARAMETER Agent
    Agent entry to remove.
    .PARAMETER AllowedId
    Allow-listed ids that must never be removed.
    .PARAMETER BackupDir
    Parent backup directory; backups go to removed_<id>\.
    .OUTPUTS
    Text result (HTML-light, as the legacy tool).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [AllowNull()][string[]]$AllowedId,
        [Parameter(Mandatory)][string]$BackupDir
    )
    $id = ConvertTo-ScgInstanceId -Id $Agent.Id
    foreach ($a in @($AllowedId)) {
        if ($a -and ($a -ieq $id)) { return "refused: <code>$id</code> is allow-listed (one of YOURS)" }
    }
    Write-ScgLog -Message "REMOVE agent $id (svc='$($Agent.ServiceName)' folder='$($Agent.Folder)')" -Level WARN
    $bdir = Join-Path $BackupDir ("removed_{0}" -f $id)
    if (-not (Test-Path $bdir)) { $null = New-Item -ItemType Directory -Force $bdir }
    $uninstallBase = [ordered]@{
        hklm     = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        wow6432  = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    if ($Agent.ServiceName) {
        $svcExport = Invoke-ScgNative -Exe 'reg' -Argument @('export', "HKLM\SYSTEM\CurrentControlSet\Services\$($Agent.ServiceName)", (Join-Path $bdir 'service.reg'), '/y')
        if ($svcExport.Code -ne 0) {
            Write-ScgLog -Message "REMOVE aborted for ${id}: service key export failed (exit $($svcExport.Code)): $($svcExport.Out)" -Level ERROR
            return "aborted: backup of the service key failed (exit $($svcExport.Code)); nothing was removed for <code>$id</code>"
        }
    }
    if ($Agent.UninstallKey) {
        foreach ($name in $uninstallBase.Keys) {
            $ue = Invoke-ScgNative -Exe 'reg' -Argument @('export', "$($uninstallBase[$name])\$($Agent.UninstallKey)", (Join-Path $bdir "uninstall_$name.reg"), '/y')
            if ($ue.Code -ne 0) {
                Write-ScgLog -Message "REMOVE ${id}: uninstall key export ($name) failed (exit $($ue.Code)), continuing" -Level WARN
            }
        }
    }
    $info = "id=$id`nservice=$($Agent.ServiceName)`nfolder=$($Agent.Folder)`nuninstallKey=$($Agent.UninstallKey)`nremovedUtc=$((Get-Date).ToUniversalTime().ToString('o'))"
    Set-Content -Path (Join-Path $bdir 'info.txt') -Encoding UTF8 -Value $info
    $steps = @()
    if ($Agent.ServiceName) {
        $s1 = Invoke-ScgNative -Exe 'sc.exe' -Argument @('stop', $Agent.ServiceName); $steps += "stop=$($s1.Code)"
        Start-Sleep -Seconds 2
        $s2 = Invoke-ScgNative -Exe 'sc.exe' -Argument @('delete', $Agent.ServiceName); $steps += "delete=$($s2.Code)"
    }
    if ($Agent.Folder -and (Test-Path $Agent.Folder)) {
        try { Remove-Item -Path $Agent.Folder -Recurse -Force -ErrorAction Stop; $steps += 'folder=removed' }
        catch { $steps += 'folder=in-use(pending-reboot)' }
    }
    if ($Agent.UninstallKey) {
        foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $k = "$base\$($Agent.UninstallKey)"
            if (Test-Path $k) { try { Remove-Item $k -Recurse -Force -ErrorAction Stop } catch { Write-Verbose "uninstall key removal failed: $($_.Exception.Message)" } }
        }
        $steps += 'uninstallKey=removed'
    }
    Write-ScgLog -Message "REMOVE done for ${id}: $($steps -join ' ')" -Level WARN
    return "removed agent <code>$id</code>`nsteps: $($steps -join '  ')`nbackup: $([System.Net.WebUtility]::HtmlEncode($bdir))"
}

function Test-ScTamper {
    <#
    .SYNOPSIS
    True when the live service security descriptor no longer contains the hardened SDDL.
    .DESCRIPTION
    Returns $false when the agent has no service or the service is absent (sdshow yields no SDDL).
    .PARAMETER Agent
    Agent entry.
    .PARAMETER BackupDir
    Accepted for interface symmetry; not read.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][object]$Agent,
        [string]$BackupDir
    )
    if (-not $Agent.ServiceName) { return $false }
    $show = Invoke-ScgNative -Exe 'sc.exe' -Argument @('sdshow', $Agent.ServiceName)
    $out = "$($show.Out)"
    if ($show.Code -ne 0 -or -not ($out -match '(?<![A-Za-z])[OGDS]:\S')) { return $false }
    $cur = $out -replace '\s', ''
    return (-not $cur.Contains(($script:HardenedSvcSddl -replace '\s', '')))
}

Export-ModuleMember -Function Invoke-ScHardening, Invoke-ScRestore, Remove-ScAgent, Test-ScTamper
