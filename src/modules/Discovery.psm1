# Discovery.psm1 - finds ScreenConnect client agents (services, folders, uninstall keys).
# Author: Badr | Version: 4.0.0 | Depends on: Common.psm1
# Legacy Get-Agents / Get-ServerProducts logic, parameterised (no $script: globals).

Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force -DisableNameChecking

$script:IdRegex = '\(([0-9A-Fa-f]{16})\)'
$script:UninstallPath = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

function ConvertTo-ScAgentId {
    <#
    .SYNOPSIS
    Extracts the 16-hex agent instance id from text such as "ScreenConnect Client (0123456789abcdef)".
    .DESCRIPTION
    Pure helper. Returns the lowercase id, or $null when the text holds no "(<16 hex>)" token.
    .PARAMETER Text
    Service name, display name or folder name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $m = [regex]::Match($Text, $script:IdRegex)
    if (-not $m.Success) { return $null }
    return (ConvertTo-ScgInstanceId -Id $m.Groups[1].Value)
}

function Test-ScAgentAuthorized {
    <#
    .SYNOPSIS
    Decides whether an agent id belongs to the allow-list.
    .PARAMETER Id
    Agent instance id.
    .PARAMETER AllowedId
    Allow-listed ids (case-insensitive compare).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [AllowNull()][string[]]$AllowedId
    )
    foreach ($a in @($AllowedId)) {
        if ($a -and ($a -ieq $Id)) { return $true }
    }
    return $false
}

function ConvertTo-ScAgentEntry {
    <#
    .SYNOPSIS
    Builds an empty agent entry object for an id with Authorized classified.
    .PARAMETER Id
    Agent instance id.
    .PARAMETER AllowedId
    Allow-listed ids.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [AllowNull()][string[]]$AllowedId
    )
    return [pscustomobject]@{
        Id           = $Id
        ServiceName  = $null
        ServiceState = $null
        StartMode    = $null
        Folder       = $null
        UninstallKey = $null
        Authorized   = (Test-ScAgentAuthorized -Id $Id -AllowedId $AllowedId)
    }
}

function Get-ScAgent {
    <#
    .SYNOPSIS
    Lists every ScreenConnect client agent found via services, Program Files folders and uninstall keys.
    .PARAMETER AllowedId
    Allow-listed ids; sets Authorized on each entry.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([AllowNull()][string[]]$AllowedId = @())

    $found = @{}
    $getEntry = {
        param($id)
        if (-not $found.ContainsKey($id)) { $found[$id] = ConvertTo-ScAgentEntry -Id $id -AllowedId $AllowedId }
        return $found[$id]
    }

    $services = @(Get-CimInstance Win32_Service -OperationTimeoutSec 30 -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match 'ScreenConnect Client' -or $_.DisplayName -match 'ScreenConnect Client'
        })
    foreach ($s in $services) {
        $id = ConvertTo-ScAgentId -Text "$($s.Name) $($s.DisplayName)"
        if ($id) {
            $e = & $getEntry $id
            $e.ServiceName = $s.Name
            $e.ServiceState = $s.State
            $e.StartMode = $s.StartMode
        }
    }

    $bases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) | Where-Object { $_ } | Select-Object -Unique
    foreach ($base in $bases) {
        if (Test-Path $base) {
            $dirs = @(Get-ChildItem -Path $base -Directory -Filter 'ScreenConnect Client (*' -ErrorAction SilentlyContinue)
            foreach ($d in $dirs) {
                $id = ConvertTo-ScAgentId -Text $d.Name
                if ($id) { (& $getEntry $id).Folder = $d.FullName }
            }
        }
    }

    foreach ($p in $script:UninstallPath) {
        if (Test-Path $p) {
            $keys = @(Get-ChildItem $p -ErrorAction SilentlyContinue)
            foreach ($k in $keys) {
                $props = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
                $dn = $null
                if ($props -and ($props.PSObject.Properties.Name -contains 'DisplayName')) { $dn = $props.DisplayName }
                if ($dn -and ($dn -match 'ScreenConnect Client')) {
                    $id = ConvertTo-ScAgentId -Text $dn
                    if ($id) { (& $getEntry $id).UninstallKey = $k.PSChildName }
                }
            }
        }
    }
    return @($found.Values)
}

function Get-ScServerProduct {
    <#
    .SYNOPSIS
    Lists installed ScreenConnect server/non-client products (DisplayName) from the uninstall keys.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $list = @()
    foreach ($p in $script:UninstallPath) {
        if (Test-Path $p) {
            $keys = @(Get-ChildItem $p -ErrorAction SilentlyContinue)
            foreach ($k in $keys) {
                $props = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
                $dn = $null
                if ($props -and ($props.PSObject.Properties.Name -contains 'DisplayName')) { $dn = $props.DisplayName }
                if ($dn -and $dn -match 'ScreenConnect' -and $dn -notmatch 'Client') { $list += $dn }
            }
        }
    }
    return @($list | Select-Object -Unique)
}

function ConvertTo-ScHeartbeatAgent {
    <#
    .SYNOPSIS
    Converts a discovered agent into the heartbeat wire shape {id,service,folder,uninstall_key,state}.
    .PARAMETER Agent
    Entry as returned by Get-ScAgent.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][object]$Agent)
    return [pscustomobject]@{
        id            = $Agent.Id
        service       = $Agent.ServiceName
        folder        = $Agent.Folder
        uninstall_key = $Agent.UninstallKey
        state         = $Agent.ServiceState
    }
}

Export-ModuleMember -Function Get-ScAgent, Get-ScServerProduct, ConvertTo-ScHeartbeatAgent, ConvertTo-ScAgentId, ConvertTo-ScAgentEntry, Test-ScAgentAuthorized
