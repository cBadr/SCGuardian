#Requires -Modules Pester
# Hardening.Tests.ps1 - mocked tests for Hardening.psm1 (never runs real sc/icacls/takeown).

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\src\modules\Hardening.psm1'
    Import-Module $script:ModulePath -Force
    $script:Hardened = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'
    $script:Agent = [pscustomobject]@{ Id = '0123456789abcdef'; ServiceName = 'ScreenConnect Client (0123456789abcdef)'; ServiceState = 'Running'
        StartMode = 'Auto'; Folder = $null; UninstallKey = $null; Authorized = $false }
}

Describe 'Remove-ScAgent' {
    It 'refuses an allow-listed id without touching anything' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 0; Out = '' } } -ModuleName Hardening
        Mock Write-ScgLog {} -ModuleName Hardening
        Mock New-Item {} -ModuleName Hardening
        Mock Set-Content {} -ModuleName Hardening
        Mock Remove-Item {} -ModuleName Hardening
        $bdir = Join-Path $TestDrive 'Backup'
        $r = Remove-ScAgent -Agent $script:Agent -AllowedId @('0123456789ABCDEF') -BackupDir $bdir
        $r | Should -Match '^refused:'
        Should -Invoke Invoke-ScgNative -ModuleName Hardening -Times 0 -Exactly
        Should -Invoke New-Item -ModuleName Hardening -Times 0 -Exactly
        Should -Invoke Set-Content -ModuleName Hardening -Times 0 -Exactly
        Should -Invoke Remove-Item -ModuleName Hardening -Times 0 -Exactly
        Test-Path (Join-Path $bdir 'removed_0123456789abcdef') | Should -BeFalse
    }
    It 'aborts without deleting anything when the service key export fails' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 1; Out = 'ERROR: access denied' } } -ModuleName Hardening
        Mock Write-ScgLog {} -ModuleName Hardening
        Mock Start-Sleep {} -ModuleName Hardening
        Mock Remove-Item {} -ModuleName Hardening
        $ag = [pscustomobject]@{ Id = '0123456789abcdef'; ServiceName = 'SvcX'; Folder = $TestDrive; UninstallKey = 'KeyX' }
        $r = Remove-ScAgent -Agent $ag -AllowedId @() -BackupDir (Join-Path $TestDrive 'Backup2')
        $r | Should -Match '^aborted:'
        Should -Invoke Invoke-ScgNative -ModuleName Hardening -Times 1 -Exactly
        Should -Invoke Invoke-ScgNative -ModuleName Hardening -Times 0 -Exactly -ParameterFilter { $Exe -eq 'sc.exe' }
        Should -Invoke Remove-Item -ModuleName Hardening -Times 0 -Exactly
    }
    It 'continues when only an uninstall key export fails and uses distinct file names' {
        Mock Invoke-ScgNative {
            if ($Exe -eq 'reg' -and ($Argument -join ' ') -match 'Uninstall') { return [pscustomobject]@{ Code = 1; Out = 'not found' } }
            return [pscustomobject]@{ Code = 0; Out = '' }
        } -ModuleName Hardening
        Mock Write-ScgLog {} -ModuleName Hardening
        Mock Start-Sleep {} -ModuleName Hardening
        Mock Remove-Item {} -ModuleName Hardening
        $ag = [pscustomobject]@{ Id = '0123456789abcdef'; ServiceName = 'SvcX'; Folder = $null; UninstallKey = 'KeyX' }
        $r = Remove-ScAgent -Agent $ag -AllowedId @() -BackupDir (Join-Path $TestDrive 'Backup3')
        $r | Should -Match '^removed agent'
        Should -Invoke Invoke-ScgNative -ModuleName Hardening -Times 1 -Exactly -ParameterFilter { $Exe -eq 'sc.exe' -and $Argument[0] -eq 'delete' }
        Should -Invoke Invoke-ScgNative -ModuleName Hardening -Times 1 -Exactly -ParameterFilter { $Exe -eq 'reg' -and ($Argument -join '|') -match 'uninstall_hklm\.reg' }
        Should -Invoke Invoke-ScgNative -ModuleName Hardening -Times 1 -Exactly -ParameterFilter { $Exe -eq 'reg' -and ($Argument -join '|') -match 'uninstall_wow6432\.reg' }
    }
}

Describe 'Test-ScTamper' {
    It 'is false when the live SD contains the hardened SDDL' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 0; Out = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)' } } -ModuleName Hardening
        Test-ScTamper -Agent $script:Agent -BackupDir $TestDrive | Should -BeFalse
    }
    It 'is true when the live SD differs' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 0; Out = 'D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)' } } -ModuleName Hardening
        Test-ScTamper -Agent $script:Agent -BackupDir $TestDrive | Should -BeTrue
    }
    It 'is false when the service is absent' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 1060; Out = '[SC] OpenService FAILED 1060: The specified service does not exist as an installed service.' } } -ModuleName Hardening
        Test-ScTamper -Agent $script:Agent -BackupDir $TestDrive | Should -BeFalse
    }
    It 'is false when the agent has no service name' {
        Mock Invoke-ScgNative { [pscustomobject]@{ Code = 0; Out = '' } } -ModuleName Hardening
        $a = [pscustomobject]@{ Id = '0123456789abcdef'; ServiceName = $null; Folder = $null }
        Test-ScTamper -Agent $a -BackupDir $TestDrive | Should -BeFalse
        Should -Invoke Invoke-ScgNative -ModuleName Hardening -Times 0 -Exactly
    }
}

Describe 'Invoke-ScHardening layer filter' {
    BeforeEach {
        Mock Write-ScgLog {} -ModuleName Hardening
        Mock Set-ScRecovery {} -ModuleName Hardening
        Mock Set-ScFolderHardening {} -ModuleName Hardening
        Mock Set-ScServiceSd {} -ModuleName Hardening
        Mock Set-ScRegistryHardening {} -ModuleName Hardening
    }
    It 'runs only the requested layers' {
        Invoke-ScHardening -Agent $script:Agent -Layer @('Recovery', 'ServiceSd') -BackupDir $TestDrive
        Should -Invoke Set-ScRecovery -ModuleName Hardening -Times 1 -Exactly
        Should -Invoke Set-ScServiceSd -ModuleName Hardening -Times 1 -Exactly
        Should -Invoke Set-ScFolderHardening -ModuleName Hardening -Times 0 -Exactly
        Should -Invoke Set-ScRegistryHardening -ModuleName Hardening -Times 0 -Exactly
    }
    It 'runs all four layers when all are listed' {
        Invoke-ScHardening -Agent $script:Agent -Layer @('Recovery', 'FolderAcl', 'ServiceSd', 'RegistryAcl') -BackupDir $TestDrive -TakeOwnership
        Should -Invoke Set-ScRecovery -ModuleName Hardening -Times 1 -Exactly
        Should -Invoke Set-ScFolderHardening -ModuleName Hardening -Times 1 -Exactly -ParameterFilter { $TakeOwnership -eq $true }
        Should -Invoke Set-ScServiceSd -ModuleName Hardening -Times 1 -Exactly
        Should -Invoke Set-ScRegistryHardening -ModuleName Hardening -Times 1 -Exactly
    }
    It 'continues with later layers when one layer throws' {
        Mock Set-ScRecovery { throw 'boom' } -ModuleName Hardening
        Invoke-ScHardening -Agent $script:Agent -Layer @('Recovery', 'RegistryAcl') -BackupDir $TestDrive
        Should -Invoke Set-ScRegistryHardening -ModuleName Hardening -Times 1 -Exactly
    }
    It 'runs nothing for an unknown layer' {
        Invoke-ScHardening -Agent $script:Agent -Layer @('Nope') -BackupDir $TestDrive
        Should -Invoke Set-ScRecovery -ModuleName Hardening -Times 0 -Exactly
        Should -Invoke Set-ScServiceSd -ModuleName Hardening -Times 0 -Exactly
    }
}
