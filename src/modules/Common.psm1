<#
.SYNOPSIS
    SCGuardian Common module: time, secrets masking, logging, JSON files, native process helper.
.DESCRIPTION
    Purpose : shared helpers with no dependencies (contract v1).
    Author  : Badr
    Version : 4.0.0
#>

Set-StrictMode -Version 2.0

$script:LogPath = $null
$script:LogMaxBytes = 5242880
$script:LogSecret = @()

function Get-ScgRoot {
    <#
    .SYNOPSIS
        Returns the SCGuardian root folder (SCG_ROOT override, else ProgramData).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if (-not [string]::IsNullOrEmpty($env:SCG_ROOT)) { return $env:SCG_ROOT }
    return 'C:\ProgramData\SCGuardian'
}

function Get-ScgUtcNow {
    <#
    .SYNOPSIS
        Current UTC time as ISO8601 with milliseconds and Z.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return ConvertTo-ScgUtcIso -InputObject ([datetime]::UtcNow)
}

function ConvertTo-ScgUtcIso {
    <#
    .SYNOPSIS
        Formats a datetime as yyyy-MM-ddTHH:mm:ss.fffZ (UTC).
    .PARAMETER InputObject
        The datetime. Unspecified kind is treated as UTC.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$InputObject
    )
    $d = $InputObject
    if ($d.Kind -eq [System.DateTimeKind]::Local) {
        $d = $d.ToUniversalTime()
    }
    return $d.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-ScgUtcIso {
    <#
    .SYNOPSIS
        Parses an ISO8601 UTC string into a UTC datetime.
    .PARAMETER Value
        The ISO8601 string.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    return [datetime]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Protect-Secret {
    <#
    .SYNOPSIS
        Masks secrets, Bearer tokens and Telegram bot tokens in text.
    .PARAMETER Text
        Input text.
    .PARAMETER Secret
        Literal secrets to replace with ***.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Secret
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $result = $Text
    $list = New-Object System.Collections.ArrayList
    foreach ($s in @($Secret)) {
        if (-not [string]::IsNullOrEmpty($s)) { [void]$list.Add($s) }
    }
    $sorted = @($list | Sort-Object -Property Length -Descending)
    foreach ($s in $sorted) {
        $result = $result.Replace($s, '***')
    }
    $result = [regex]::Replace($result, '(?i)Bearer\s+[A-Za-z0-9\-\._~\+/=]+', 'Bearer ***')
    $result = [regex]::Replace($result, '(?i)bot\d+:[A-Za-z0-9_\-]+', 'bot***')
    $result = [regex]::Replace($result, '\b\d{6,}:[A-Za-z0-9_\-]{30,}', '***')
    return $result
}

function Set-ScgLogContext {
    <#
    .SYNOPSIS
        Configures the module-scoped log file, rotation size and secrets to mask.
    .PARAMETER Path
        Log file path.
    .PARAMETER MaxBytes
        Rotation threshold in bytes.
    .PARAMETER Secret
        Secrets masked in every log line.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [int]$MaxBytes = 5242880,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Secret
    )
    $script:LogPath = $Path
    $script:LogMaxBytes = $MaxBytes
    $script:LogSecret = @($Secret | Where-Object { -not [string]::IsNullOrEmpty($_) })
}

function Add-ScgLogSecret {
    <#
    .SYNOPSIS
        Appends secrets to the module-scoped mask list (keeps path, size and existing secrets); ignores empty and duplicate values.
    .PARAMETER Secret
        Secrets masked in every later log line.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Secret
    )
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($script:LogSecret)) { if (-not [string]::IsNullOrEmpty($s)) { $list.Add($s) } }
    foreach ($s in @($Secret)) {
        if ([string]::IsNullOrEmpty($s)) { continue }
        if (-not $list.Contains($s)) { $list.Add($s) }
    }
    $script:LogSecret = $list.ToArray()
}

function New-ScgDeviceToken {
    <#
    .SYNOPSIS
        Returns a new per-device token: 32 random bytes (RNGCryptoServiceProvider) as base64url without padding (43 chars).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $bytes = New-Object byte[] 32
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $b64 = [System.Convert]::ToBase64String($bytes)
    return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-ScgTokenHash {
    <#
    .SYNOPSIS
        Lowercase hex SHA-256 of the UTF-8 bytes of Token.
    .PARAMETER Token
        Raw token text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Token
    )
    $data = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Token)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($data) } finally { $sha.Dispose() }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $digest) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

function Test-ScgDeviceToken {
    <#
    .SYNOPSIS
        Constant-time check that SHA-256(Token) equals Hash (hex, case-insensitive); false on null, empty or malformed input, never throws.
    .PARAMETER Token
        Raw token presented by the caller.
    .PARAMETER Hash
        Stored lowercase hex SHA-256.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Token,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Hash
    )
    try {
        if ([string]::IsNullOrEmpty($Token) -or [string]::IsNullOrEmpty($Hash)) { return $false }
        if ($Hash.Length -ne 64) { return $false }
        if ($Hash -notmatch '^[0-9a-fA-F]{64}\z') { return $false }
        $calc = Get-ScgTokenHash -Token $Token
        $want = $Hash.ToLowerInvariant()
        $diff = 0
        for ($i = 0; $i -lt 64; $i++) {
            $diff = $diff -bor (([int][char]$calc[$i]) -bxor ([int][char]$want[$i]))
        }
        return ($diff -eq 0)
    }
    catch {
        return $false
    }
}

function Write-ScgLog {
    <#
    .SYNOPSIS
        Appends a masked log line; rotates at MaxBytes to .1; never throws.
    .PARAMETER Message
        Log text.
    .PARAMETER Level
        INFO, WARN, ERROR or ALERT (unknown values become INFO).
    .PARAMETER Actor
        Who acted.
    .PARAMETER Target
        What was acted on.
    .PARAMETER Action
        Action name.
    .PARAMETER Result
        Outcome.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Message = '',
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Level = 'INFO',
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Actor,
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Target,
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Action,
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Result
    )
    try {
        $lvl = 'INFO'
        if ($null -ne $Level) {
            $u = $Level.ToUpperInvariant()
            if (@('INFO', 'WARN', 'ERROR', 'ALERT') -contains $u) { $lvl = $u }
        }
        $path = $script:LogPath
        if ([string]::IsNullOrEmpty($path)) {
            $path = Join-Path (Get-ScgRoot) 'logs\scguardian.log'
        }
        $parts = New-Object System.Collections.ArrayList
        [void]$parts.Add((Get-ScgUtcNow))
        [void]$parts.Add('[' + $lvl + ']')
        if (-not [string]::IsNullOrEmpty($Actor)) { [void]$parts.Add('actor=' + $Actor) }
        if (-not [string]::IsNullOrEmpty($Target)) { [void]$parts.Add('target=' + $Target) }
        if (-not [string]::IsNullOrEmpty($Action)) { [void]$parts.Add('action=' + $Action) }
        if (-not [string]::IsNullOrEmpty($Result)) { [void]$parts.Add('result=' + $Result) }
        if (-not [string]::IsNullOrEmpty($Message)) { [void]$parts.Add($Message) }
        $line = ($parts.ToArray() -join ' ')
        $line = $line.Replace("`r", ' ').Replace("`n", ' ')
        $line = Protect-Secret -Text $line -Secret $script:LogSecret

        $dir = Split-Path -Path $path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force)
        }
        if ($script:LogMaxBytes -gt 0 -and (Test-Path -LiteralPath $path -ErrorAction Stop)) {
            $len = (Get-Item -LiteralPath $path).Length
            if ($len -ge $script:LogMaxBytes) {
                $old = $path + '.1'
                if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force }
                Move-Item -LiteralPath $path -Destination $old -Force
            }
        }
        [System.IO.File]::AppendAllText($path, $line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        $null = $_
    }
}

function Read-ScgJsonFile {
    <#
    .SYNOPSIS
        Reads a JSON file into a PSCustomObject.
    .PARAMETER Path
        File path.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    return ($raw | ConvertFrom-Json)
}

function Save-ScgJsonFile {
    <#
    .SYNOPSIS
        Writes an object as JSON atomically (temp file + replace), UTF8 without BOM.
    .PARAMETER Path
        Destination path.
    .PARAMETER InputObject
        Object to serialize.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject
    )
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        [void](New-Item -ItemType Directory -Path $dir -Force)
    }
    $json = ConvertTo-Json -InputObject $InputObject -Depth 10
    $tmp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $Path) {
            [System.IO.File]::Replace($tmp, $Path, [NullString]::Value)
        }
        else {
            [System.IO.File]::Move($tmp, $Path)
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-ScgInstanceId {
    <#
    .SYNOPSIS
        True when Id is exactly 16 lowercase hex characters.
    .PARAMETER Id
        Candidate id.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Id
    )
    if ([string]::IsNullOrEmpty($Id)) { return $false }
    return ($Id -cmatch '^[0-9a-f]{16}\z')
}

function ConvertTo-ScgInstanceId {
    <#
    .SYNOPSIS
        Normalizes an instance id to lowercase; throws when invalid.
    .PARAMETER Id
        Candidate id.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Id
    )
    $n = ''
    if ($null -ne $Id) { $n = $Id.Trim().ToLowerInvariant() }
    if (-not (Test-ScgInstanceId -Id $n)) {
        throw 'Invalid instance id: expected 16 hex characters.'
    }
    return $n
}

function New-ScgGuid {
    <#
    .SYNOPSIS
        Returns a new GUID string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return [guid]::NewGuid().ToString()
}

function ConvertTo-ScgNativeArgument {
    <#
    .SYNOPSIS
        Quotes one command-line argument (CommandLineToArgvW rules); doubles backslashes before a quote or the closing quote.
    .PARAMETER Value
        Raw argument text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $s = [regex]::Replace($Value, '(\\*)"', { param($m) $m.Groups[1].Value + $m.Groups[1].Value + '\"' })
    $s = [regex]::Replace($s, '(\\+)\z', { param($m) $m.Groups[1].Value + $m.Groups[1].Value })
    return ('"' + $s + '"')
}

function Invoke-ScgNative {
    <#
    .SYNOPSIS
        Runs a native executable capturing exit code and combined output (stderr-safe).
    .PARAMETER Exe
        Executable path or name.
    .PARAMETER Argument
        Arguments.
    .PARAMETER TimeoutSec
        Maximum run time; on expiry the process tree is killed and Code=-1 Out='timeout' is returned.
    .OUTPUTS
        PSCustomObject with Code and Out.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Exe,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Argument,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSec = 120
    )
    $quoted = New-Object System.Collections.ArrayList
    foreach ($a in @($Argument)) {
        if ($null -eq $a) { continue }
        [void]$quoted.Add((ConvertTo-ScgNativeArgument -Value $a))
    }
    $p = $null
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = ($quoted.ToArray() -join ' ')
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            Stop-ScgProcessTree -Process $p
            return [pscustomobject]@{ Code = -1; Out = 'timeout' }
        }
        $p.WaitForExit()
        $text = [string]$outTask.Result + [string]$errTask.Result
        return [pscustomobject]@{ Code = [int]$p.ExitCode; Out = $text.TrimEnd() }
    }
    catch {
        return [pscustomobject]@{ Code = -1; Out = $_.Exception.Message }
    }
    finally {
        if ($null -ne $p) { $p.Dispose() }
    }
}

function Stop-ScgProcessTree {
    <#
    .SYNOPSIS
        Kills a process and all of its descendants (taskkill /T /F, then Kill as fallback); never throws.
    .PARAMETER Process
        The running process.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    if (-not $PSCmdlet.ShouldProcess([string]$Process.Id, 'Kill process tree')) { return }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'taskkill.exe'
        $psi.Arguments = '/PID ' + [string]$Process.Id + ' /T /F'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $k = [System.Diagnostics.Process]::Start($psi)
        try { [void]$k.WaitForExit(10000) } finally { $k.Dispose() }
    }
    catch { $null = $_ }
    try { if (-not $Process.HasExited) { $Process.Kill() } } catch { $null = $_ }
}

$script:SecureSid = @('S-1-5-18', 'S-1-5-32-544')

function Test-ScgSecureAcl {
    <#
    .SYNOPSIS
        True when Path has a protected ACL granting FullControl to SYSTEM and Administrators and nobody else.
    .PARAMETER Path
        Directory path.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if (-not $acl.AreAccessRulesProtected) { return $false }
        $full = [System.Security.AccessControl.FileSystemRights]::FullControl
        $hasFull = @{}
        foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = [string]$r.IdentityReference.Value
            if ($script:SecureSid -notcontains $sid) { return $false }
            if ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and (($r.FileSystemRights -band $full) -eq $full)) {
                $hasFull[$sid] = $true
            }
        }
        foreach ($s in $script:SecureSid) { if (-not $hasFull.ContainsKey($s)) { return $false } }
        return $true
    }
    catch { return $false }
}

function Get-ScgForeignAceSid {
    <#
    .SYNOPSIS
        Emits the SIDs on Path's ACL other than SYSTEM and Administrators (unique, plain strings).
    .PARAMETER Path
        Directory path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $seen = New-Object System.Collections.Generic.List[string]
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = [string]$r.IdentityReference.Value
            if (($script:SecureSid -notcontains $sid) -and (-not $seen.Contains($sid))) { $seen.Add($sid) }
        }
    }
    catch { $null = $_ }
    foreach ($s in $seen) { $s }
}

function Initialize-ScgSecureDirectory {
    <#
    .SYNOPSIS
        Creates Path if missing and locks it to SYSTEM + Administrators only (FullControl, inheritance removed); never throws.
    .DESCRIPTION
        Uses locale-independent SIDs (*S-1-5-18, *S-1-5-32-544) through icacls. Idempotent: an already locked
        directory (protected ACL with exactly those two FullControl grants) is left untouched.
    .PARAMETER Path
        Directory path.
    .OUTPUTS
        True when the directory exists and is (or already was) locked.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path
    )
    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            [void](New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop)
        }
        if (Test-ScgSecureAcl -Path $Path) { return $true }
        $r = Invoke-ScgNative -Exe 'icacls.exe' -Argument @($Path, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
        if ($r.Code -ne 0) {
            Write-ScgLog -Message "could not lock directory: $($r.Out)" -Level WARN -Target $Path -Action 'secure_dir' -Result 'failed'
            return $false
        }
        $ok = $true
        foreach ($sid in @(Get-ScgForeignAceSid -Path $Path)) {
            $x = Invoke-ScgNative -Exe 'icacls.exe' -Argument @($Path, '/remove', ('*' + [string]$sid))
            if ($x.Code -ne 0) { $ok = $false }
        }
        if (-not $ok) { Write-ScgLog -Message 'could not remove a foreign ACE' -Level WARN -Target $Path -Action 'secure_dir' -Result 'failed' }
        return $ok
    }
    catch {
        Write-ScgLog -Message "secure directory error: $($_.Exception.Message)" -Level WARN -Target $Path -Action 'secure_dir' -Result 'failed'
        return $false
    }
}

function Get-ScgBackoffSec {
    <#
    .SYNOPSIS
        Backoff seconds: 3 or more failures return MaxSec (300 default); fewer grow exponentially from BaseSec.
    .PARAMETER Failures
        Consecutive failures.
    .PARAMETER BaseSec
        Base interval.
    .PARAMETER MaxSec
        Ceiling, returned at 3+ failures.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Failures,

        [Parameter()]
        [int]$BaseSec = 60,

        [Parameter()]
        [int]$MaxSec = 300
    )
    if ($Failures -ge 3) { return $MaxSec }
    if ($Failures -le 0) { return $BaseSec }
    $v = $BaseSec * [math]::Pow(2, $Failures - 1)
    if ($v -gt $MaxSec) { $v = $MaxSec }
    return [int]$v
}

function Test-ScgThrottle {
    <#
    .SYNOPSIS
        True when LastUtc is within ThrottleMin minutes of now (still throttled).
    .PARAMETER LastUtc
        Last occurrence, ISO8601 UTC. Empty means never.
    .PARAMETER ThrottleMin
        Throttle window in minutes.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$LastUtc,

        [Parameter(Mandatory = $true)]
        [double]$ThrottleMin
    )
    if ([string]::IsNullOrEmpty($LastUtc)) { return $false }
    $last = ConvertFrom-ScgUtcIso -Value $LastUtc
    $age = ([datetime]::UtcNow - $last).TotalMinutes
    return ($age -lt $ThrottleMin)
}

Export-ModuleMember -Function Get-ScgRoot, Get-ScgUtcNow, ConvertTo-ScgUtcIso, ConvertFrom-ScgUtcIso, Protect-Secret, Set-ScgLogContext, Add-ScgLogSecret, Write-ScgLog, Read-ScgJsonFile, Save-ScgJsonFile, Test-ScgInstanceId, ConvertTo-ScgInstanceId, New-ScgGuid, Invoke-ScgNative, Initialize-ScgSecureDirectory, Get-ScgBackoffSec, Test-ScgThrottle, New-ScgDeviceToken, Get-ScgTokenHash, Test-ScgDeviceToken
