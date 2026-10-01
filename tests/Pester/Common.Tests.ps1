# Purpose: Pester 5 tests for Common.psm1 | Author: Badr | Version: 4.0.0

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\src\modules\Common.psm1'
    Import-Module $script:ModulePath -Force
    $env:SCG_ROOT = $TestDrive
}

Describe 'Get-ScgRoot' {
    It 'honours SCG_ROOT' {
        Get-ScgRoot | Should -Be $TestDrive
    }
}

Describe 'Protect-Secret' {
    It 'masks explicit secrets' {
        $r = Protect-Secret -Text 'password is hunter2 ok' -Secret 'hunter2'
        $r | Should -Be 'password is *** ok'
    }
    It 'masks Bearer tokens' {
        $r = Protect-Secret -Text 'Authorization: Bearer abc.DEF-123_xyz=' -Secret @()
        $r | Should -Not -Match 'abc\.DEF'
        $r | Should -Match 'Bearer \*\*\*'
    }
    It 'masks bot tokens inside URLs' {
        $r = Protect-Secret -Text 'https://api.telegram.org/bot123456789:AAE-abcDEF_ghi123/getUpdates' -Secret @()
        $r | Should -Not -Match 'AAE-abcDEF'
        $r | Should -Match '\*\*\*'
    }
    It 'ignores empty secrets and null text' {
        Protect-Secret -Text 'abc' -Secret @('') | Should -Be 'abc'
        Protect-Secret -Text $null | Should -Be ''
    }
}

Describe 'ISO8601 helpers' {
    It 'Get-ScgUtcNow has the contract shape' {
        Get-ScgUtcNow | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
    }
    It 'round-trips' {
        $d = [datetime]::new(2026, 3, 4, 5, 6, 7, 89, [System.DateTimeKind]::Utc)
        $s = ConvertTo-ScgUtcIso -InputObject $d
        $s | Should -Be '2026-03-04T05:06:07.089Z'
        $back = ConvertFrom-ScgUtcIso -Value $s
        $back.Kind | Should -Be ([System.DateTimeKind]::Utc)
        $back.Ticks | Should -Be $d.Ticks
    }
}

Describe 'Instance id' {
    It 'accepts 16 lowercase hex' {
        Test-ScgInstanceId -Id '0123456789abcdef' | Should -BeTrue
    }
    It 'rejects bad ids' {
        Test-ScgInstanceId -Id '0123456789abcde' | Should -BeFalse
        Test-ScgInstanceId -Id '0123456789abcdeg' | Should -BeFalse
        Test-ScgInstanceId -Id '0123456789ABCDEF' | Should -BeFalse
        Test-ScgInstanceId -Id '' | Should -BeFalse
    }
    It 'normalizes to lowercase and throws on invalid' {
        ConvertTo-ScgInstanceId -Id '0123456789ABCDEF' | Should -Be '0123456789abcdef'
        { ConvertTo-ScgInstanceId -Id 'zzz' } | Should -Throw
    }
}

Describe 'Backoff and throttle' {
    It 'returns 300 at 3 failures' {
        Get-ScgBackoffSec -Failures 3 -BaseSec 60 -MaxSec 300 | Should -Be 300
        Get-ScgBackoffSec -Failures 10 | Should -Be 300
    }
    It 'grows below 3 failures' {
        Get-ScgBackoffSec -Failures 0 -BaseSec 30 | Should -Be 30
        Get-ScgBackoffSec -Failures 2 -BaseSec 30 | Should -Be 60
    }
    It 'throttles recent timestamps only' {
        Test-ScgThrottle -LastUtc (Get-ScgUtcNow) -ThrottleMin 10 | Should -BeTrue
        $old = ConvertTo-ScgUtcIso -InputObject ([datetime]::UtcNow.AddMinutes(-30))
        Test-ScgThrottle -LastUtc $old -ThrottleMin 10 | Should -BeFalse
        Test-ScgThrottle -LastUtc '' -ThrottleMin 10 | Should -BeFalse
    }
}

Describe 'JSON files' {
    It 'saves atomically and reads back without BOM' {
        $p = Join-Path $TestDrive 'sub\cfg.json'
        Save-ScgJsonFile -Path $p -InputObject ([pscustomobject]@{ a = 1; b = 'x' })
        Save-ScgJsonFile -Path $p -InputObject ([pscustomobject]@{ a = 2; b = 'y' })
        $o = Read-ScgJsonFile -Path $p
        $o.a | Should -Be 2
        $o.b | Should -Be 'y'
        $bytes = [System.IO.File]::ReadAllBytes($p)
        $bytes[0] | Should -Not -Be 0xEF
        @(Get-ChildItem -Path (Split-Path $p) -Filter '*.tmp').Count | Should -Be 0
    }
}

Describe 'Logging' {
    It 'masks secrets and writes a line' {
        $log = Join-Path $TestDrive 'logs\a.log'
        Set-ScgLogContext -Path $log -MaxBytes 100000 -Secret @('topsecret')
        Write-ScgLog -Message 'value topsecret Bearer abc123' -Level WARN -Actor 'system'
        $txt = Get-Content -LiteralPath $log -Raw
        $txt | Should -Not -Match 'topsecret'
        $txt | Should -Not -Match 'abc123'
        $txt | Should -Match '\[WARN\]'
    }
    It 'rotates to .1 at MaxBytes' {
        $log = Join-Path $TestDrive 'logs\rot.log'
        Set-ScgLogContext -Path $log -MaxBytes 200
        1..20 | ForEach-Object { Write-ScgLog -Message ('line number ' + $_ + ' padding padding padding') }
        Test-Path ($log + '.1') | Should -BeTrue
        (Get-Item $log).Length | Should -BeLessThan 400
    }
    It 'never throws on an unwritable path' {
        Set-ScgLogContext -Path (Join-Path $TestDrive 'bad<>|name.log') -MaxBytes 100
        { Write-ScgLog -Message 'x' } | Should -Not -Throw
    }
}

Describe 'Invoke-ScgNative' {
    It 'captures exit code and output including stderr' {
        $r = Invoke-ScgNative -Exe 'cmd.exe' -Argument @('/c', 'echo hello & echo err 1>&2 & exit 3')
        $r.Code | Should -Be 3
        $r.Out | Should -Match 'hello'
        $r.Out | Should -Match 'err'
    }
    It 'reports a missing executable without throwing' {
        $r = Invoke-ScgNative -Exe 'definitely-not-here.exe'
        $r.Code | Should -Be -1
    }
    It 'kills a native that outlives TimeoutSec and reports timeout' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-ScgNative -Exe 'powershell.exe' -Argument @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 5') -TimeoutSec 1
        $sw.Stop()
        $r.Code | Should -Be -1
        $r.Out | Should -Be 'timeout'
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 4.5
    }
}

Describe 'Initialize-ScgSecureDirectory' {
    It 'creates a missing directory and locks it with locale-independent SIDs' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 0; Out = 'ok' } } -ModuleName Common
        Mock Test-ScgSecureAcl { $false } -ModuleName Common
        Mock Get-ScgForeignAceSid {} -ModuleName Common
        $dir = Join-Path $TestDrive 'secure-new'
        (Initialize-ScgSecureDirectory -Path $dir) | Should -BeTrue
        Test-Path -LiteralPath $dir -PathType Container | Should -BeTrue
        Should -Invoke Invoke-ScgNative -ModuleName Common -Times 1 -Exactly -ParameterFilter {
            $Exe -eq 'icacls.exe' -and $Argument[0] -eq $dir -and ($Argument -contains '/inheritance:r') -and
            ($Argument -contains '*S-1-5-18:(OI)(CI)F') -and ($Argument -contains '*S-1-5-32-544:(OI)(CI)F')
        }
    }
    It 'skips icacls when the directory is already locked' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 0; Out = 'ok' } } -ModuleName Common
        Mock Test-ScgSecureAcl { $true } -ModuleName Common
        $dir = Join-Path $TestDrive 'secure-locked'
        $null = New-Item -ItemType Directory -Path $dir -Force
        (Initialize-ScgSecureDirectory -Path $dir) | Should -BeTrue
        Should -Invoke Invoke-ScgNative -ModuleName Common -Times 0 -Exactly
    }
    It 'removes foreign ACEs left after the grant' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 0; Out = 'ok' } } -ModuleName Common
        Mock Test-ScgSecureAcl { $false } -ModuleName Common
        Mock Get-ScgForeignAceSid { 'S-1-5-32-545' } -ModuleName Common
        $dir = Join-Path $TestDrive 'secure-foreign'
        (Initialize-ScgSecureDirectory -Path $dir) | Should -BeTrue
        Should -Invoke Invoke-ScgNative -ModuleName Common -Times 1 -Exactly -ParameterFilter { ($Argument -contains '/remove') -and ($Argument -contains '*S-1-5-32-545') }
    }
    It 'returns false without throwing when icacls fails' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 5; Out = 'Access is denied.' } } -ModuleName Common
        Mock Test-ScgSecureAcl { $false } -ModuleName Common
        Mock Write-ScgLog {} -ModuleName Common
        $dir = Join-Path $TestDrive 'secure-fail'
        { $script:SecRes = Initialize-ScgSecureDirectory -Path $dir } | Should -Not -Throw
        $script:SecRes | Should -BeFalse
    }
    It 'returns false for an empty path' {
        (Initialize-ScgSecureDirectory -Path '') | Should -BeFalse
    }
}

Describe 'ConvertTo-ScgNativeArgument' {
    It 'leaves plain arguments unquoted' {
        InModuleScope Common { ConvertTo-ScgNativeArgument -Value 'abc' } | Should -Be 'abc'
    }
    It 'quotes an empty argument' {
        InModuleScope Common { ConvertTo-ScgNativeArgument -Value '' } | Should -Be '""'
    }
    It 'doubles a trailing backslash when the argument contains a space' {
        $r = InModuleScope Common { ConvertTo-ScgNativeArgument -Value 'C:\Program Files\X\' }
        $r | Should -Be ('"C:\Program Files\X\\"')
    }
    It 'escapes embedded quotes and the backslashes before them' {
        $r = InModuleScope Common { ConvertTo-ScgNativeArgument -Value 'a "b\"c' }
        $r | Should -Be ('"a \"b\\\"c"')
    }
    It 'does not touch backslashes in a path without spaces' {
        InModuleScope Common { ConvertTo-ScgNativeArgument -Value 'C:\X\' } | Should -Be 'C:\X\'
    }
}

Describe 'New-ScgGuid' {
    It 'returns a parsable guid' {
        $g = New-ScgGuid
        { [guid]::Parse($g) } | Should -Not -Throw
    }
}
