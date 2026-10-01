#Requires -Modules Pester
# Discovery.Tests.ps1 - pure-logic tests for Discovery.psm1 (no services/registry touched).

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\src\modules\Discovery.psm1'
    Import-Module $script:ModulePath -Force
}

Describe 'ConvertTo-ScAgentId' {
    It 'extracts and lowercases the 16-hex id' {
        ConvertTo-ScAgentId -Text 'ScreenConnect Client (0123456789ABCDEF)' | Should -Be '0123456789abcdef'
    }
    It 'returns null when no id is present' {
        ConvertTo-ScAgentId -Text 'ScreenConnect Client' | Should -BeNullOrEmpty
    }
    It 'rejects ids that are not exactly 16 hex chars inside parentheses' {
        ConvertTo-ScAgentId -Text 'ScreenConnect Client (0123456789abcde)' | Should -BeNullOrEmpty
        ConvertTo-ScAgentId -Text 'ScreenConnect Client (0123456789abcdeg)' | Should -BeNullOrEmpty
    }
    It 'handles empty text' {
        ConvertTo-ScAgentId -Text '' | Should -BeNullOrEmpty
    }
}

Describe 'Test-ScAgentAuthorized' {
    It 'is true for an allow-listed id regardless of case' {
        Test-ScAgentAuthorized -Id '0123456789abcdef' -AllowedId @('0123456789ABCDEF') | Should -BeTrue
    }
    It 'is false for other ids and for an empty list' {
        Test-ScAgentAuthorized -Id '0123456789abcdef' -AllowedId @('fedcba9876543210') | Should -BeFalse
        Test-ScAgentAuthorized -Id '0123456789abcdef' -AllowedId @() | Should -BeFalse
        Test-ScAgentAuthorized -Id '0123456789abcdef' -AllowedId $null | Should -BeFalse
    }
}

Describe 'ConvertTo-ScAgentEntry' {
    It 'builds an empty entry with Authorized set' {
        $e = ConvertTo-ScAgentEntry -Id '0123456789abcdef' -AllowedId @('0123456789abcdef')
        $e.Id | Should -Be '0123456789abcdef'
        $e.Authorized | Should -BeTrue
        $e.ServiceName | Should -BeNullOrEmpty
        $e.Folder | Should -BeNullOrEmpty
        ($e.PSObject.Properties.Name -join ',') | Should -Be 'Id,ServiceName,ServiceState,StartMode,Folder,UninstallKey,Authorized'
    }
}

Describe 'ConvertTo-ScHeartbeatAgent' {
    It 'produces the wire shape' {
        $a = [pscustomobject]@{ Id = '0123456789abcdef'; ServiceName = 'ScreenConnect Client (0123456789abcdef)'; ServiceState = 'Running'
            StartMode = 'Auto'; Folder = 'C:\Program Files (x86)\ScreenConnect Client (0123456789abcdef)'; UninstallKey = '{GUID}'; Authorized = $true }
        $w = ConvertTo-ScHeartbeatAgent -Agent $a
        ($w.PSObject.Properties.Name -join ',') | Should -Be 'id,service,folder,uninstall_key,state'
        $w.id | Should -Be '0123456789abcdef'
        $w.service | Should -Be $a.ServiceName
        $w.folder | Should -Be $a.Folder
        $w.uninstall_key | Should -Be '{GUID}'
        $w.state | Should -Be 'Running'
    }
}
