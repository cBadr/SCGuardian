# Pure helper functions for build.ps1 (dot-source only; no side effects on load).
Set-StrictMode -Version 2.0

# Fixed forever: changing it breaks upgrades of installed agents.
$script:AgentUpgradeCode  = 'B7A1C3D2-5E4F-4A6B-9C8D-1F2E3A4B5C6D'
$script:BundleUpgradeCode = '0C9E7A11-3B52-4D8E-A6F4-7D2B8E1C5A90'
$script:GuidNamespace     = 'SCGuardian.Agent.v4'

# modules the agent must NOT ship (Hub side, SQLite dependent)
$script:ExcludedModules = @('Hub.psm1', 'HttpServer.psm1', 'Telegram.psm1', 'Database.psm1')

function Test-MsiVersion {
    param([string]$Version)
    return [bool]($Version -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,5})(\.\d{1,5})?$')
}

function New-DeterministicGuid {
    param([Parameter(Mandatory)][string]$Name, [string]$Namespace = $script:GuidNamespace)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Namespace|$($Name.ToLowerInvariant())")) }
    finally { $sha.Dispose() }
    $b = New-Object byte[] 16
    [Array]::Copy($hash, 0, $b, 0, 16)
    $b[6] = ($b[6] -band 0x0F) -bor 0x50      # version 5 (name-based)
    $b[8] = ($b[8] -band 0x3F) -bor 0x80      # RFC 4122 variant
    return ([guid]::new($b)).ToString().ToUpperInvariant()
}

function Copy-AgentStage {
    # Stages exactly what an agent needs. Returns relative paths staged.
    param(
        [Parameter(Mandatory)][string]$SrcRoot,
        [Parameter(Mandatory)][string]$StageDir,
        [Parameter(Mandatory)][string]$InstallAgentScript
    )
    if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
    $null = New-Item -ItemType Directory -Path (Join-Path $StageDir 'modules') -Force

    Copy-Item (Join-Path $SrcRoot 'SCGuardian.ps1') $StageDir
    Copy-Item (Join-Path $SrcRoot 'config\agent.config.template.json') $StageDir
    Copy-Item $InstallAgentScript $StageDir
    Get-ChildItem (Join-Path $SrcRoot 'modules') -Filter '*.psm1' -File |
        Where-Object { $script:ExcludedModules -notcontains $_.Name } |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $StageDir 'modules') }
    # src\lib (System.Data.SQLite) is deliberately NOT staged.
    return (Get-StageFileList -StageDir $StageDir)
}

function Get-StageFileList {
    param([Parameter(Mandatory)][string]$StageDir)
    $root = (Resolve-Path $StageDir).Path.TrimEnd('\')
    $list = foreach ($f in (Get-ChildItem $root -Recurse -File)) {
        $rel = $f.FullName.Substring($root.Length + 1)
        if (($rel -split '\\').Count -gt 2 -or (($rel -split '\\').Count -eq 2 -and ($rel -split '\\')[0] -ne 'modules')) {
            throw "Unsupported staged layout: $rel (only root files and modules\ are allowed)"
        }
        if ($script:ExcludedModules -contains $f.Name) { throw "Excluded file present in stage: $rel" }
        $rel
    }
    return @($list | Sort-Object)
}

function ConvertTo-WixId {
    param([string]$Prefix, [string]$RelPath)
    $clean = ($RelPath -replace '[^A-Za-z0-9_.]', '_')
    return "$Prefix$clean"
}

function New-AgentWxs {
    param(
        [Parameter(Mandatory)][string]$TemplatePath,
        [Parameter(Mandatory)][string]$StageDir,
        [Parameter(Mandatory)][string]$Version,
        [string]$OutputPath
    )
    if (-not (Test-MsiVersion $Version)) { throw "Invalid MSI version '$Version' (expected major.minor.build)" }
    $template = [IO.File]::ReadAllText($TemplatePath)
    foreach ($tok in '{{VERSION}}', '{{UPGRADE_CODE}}', '{{COMPONENTS}}') {
        if (-not $template.Contains($tok)) { throw "Template is missing token $tok" }
    }
    $root  = (Resolve-Path $StageDir).Path.TrimEnd('\')
    $files = Get-StageFileList -StageDir $StageDir
    $sb = New-Object Text.StringBuilder
    foreach ($rel in $files) {
        $dir  = if ($rel -like 'modules\*') { 'MODULESDIR' } else { 'INSTALLFOLDER' }
        $cid  = ConvertTo-WixId 'C_' $rel
        $fid  = ConvertTo-WixId 'F_' $rel
        $guid = New-DeterministicGuid -Name $rel
        $src  = [Security.SecurityElement]::Escape((Join-Path $root $rel))
        [void]$sb.AppendLine("      <Component Id=`"$cid`" Directory=`"$dir`" Guid=`"{$guid}`">")
        [void]$sb.AppendLine("        <File Id=`"$fid`" Source=`"$src`" KeyPath=`"yes`" />")
        [void]$sb.AppendLine('      </Component>')
    }
    $out = $template.Replace('{{VERSION}}', $Version).
                     Replace('{{UPGRADE_CODE}}', "{$script:AgentUpgradeCode}").
                     Replace('{{COMPONENTS}}', $sb.ToString().TrimEnd())
    if ($out -match '\{\{[A-Z_]+\}\}') { throw "Unreplaced token in generated wxs: $($Matches[0])" }
    [void][xml]$out    # throws if not well-formed
    if ($OutputPath) { [IO.File]::WriteAllText($OutputPath, $out, (New-Object Text.UTF8Encoding($false))) }
    return $out
}

function New-BootstrapperWxs {
    param(
        [Parameter(Mandatory)][string]$TemplatePath,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$MsiPath,
        [string]$OutputPath
    )
    if (-not (Test-MsiVersion $Version)) { throw "Invalid version '$Version'" }
    $out = [IO.File]::ReadAllText($TemplatePath).
        Replace('{{VERSION}}', $Version).
        Replace('{{BUNDLE_UPGRADE_CODE}}', "{$script:BundleUpgradeCode}").
        Replace('{{MSI_PATH}}', [Security.SecurityElement]::Escape($MsiPath))
    if ($out -match '\{\{[A-Z_]+\}\}') { throw "Unreplaced token in bootstrapper wxs: $($Matches[0])" }
    [void][xml]$out
    if ($OutputPath) { [IO.File]::WriteAllText($OutputPath, $out, (New-Object Text.UTF8Encoding($false))) }
    return $out
}
