BeforeAll {
    $script:Inst = Join-Path $PSScriptRoot '..\..\installer' | Resolve-Path | Select-Object -ExpandProperty Path
    . (Join-Path $script:Inst 'Installer.Functions.ps1')
    . (Join-Path $script:Inst 'Install-Agent.ps1')

    $script:Src = Join-Path $TestDrive 'src'
    New-Item -ItemType Directory -Path (Join-Path $script:Src 'modules'), (Join-Path $script:Src 'config'), (Join-Path $script:Src 'lib') -Force | Out-Null
    foreach ($m in 'Common', 'Agent', 'Discovery', 'Hardening', 'Hub', 'HttpServer', 'Telegram', 'Database') {
        Set-Content (Join-Path $script:Src "modules\$m.psm1") '# stub'
    }
    Set-Content (Join-Path $script:Src 'SCGuardian.ps1') '# stub'
    Set-Content (Join-Path $script:Src 'lib\System.Data.SQLite.dll') 'x'
    Copy-Item (Join-Path $script:Inst '..\src\config\agent.config.template.json') (Join-Path $script:Src 'config') -ErrorAction SilentlyContinue
    if (-not (Test-Path (Join-Path $script:Src 'config\agent.config.template.json'))) {
        Set-Content (Join-Path $script:Src 'config\agent.config.template.json') '{"hub_url":"https://x","shared_secret":"REPLACE_ME"}'
    }
    $script:Template = Join-Path $script:Inst 'SCGuardian.Agent.wxs.template'
    $script:Stage1 = Join-Path $TestDrive 'stage1'
    $script:Stage2 = Join-Path $TestDrive 'stage2'
    $script:Files = Copy-AgentStage -SrcRoot $script:Src -StageDir $script:Stage1 -InstallAgentScript (Join-Path $script:Inst 'Install-Agent.ps1')
    $null = Copy-AgentStage -SrcRoot $script:Src -StageDir $script:Stage2 -InstallAgentScript (Join-Path $script:Inst 'Install-Agent.ps1')
}

Describe 'Staging' {
    It 'excludes Hub, HttpServer, Telegram, Database and lib' {
        $script:Files | Should -Not -Contain 'modules\Hub.psm1'
        $script:Files | Should -Not -Contain 'modules\HttpServer.psm1'
        $script:Files | Should -Not -Contain 'modules\Telegram.psm1'
        $script:Files | Should -Not -Contain 'modules\Database.psm1'
        ($script:Files -join ';') | Should -Not -Match 'lib'
    }
    It 'includes the agent modules, entry script, helper and template' {
        $script:Files | Should -Contain 'modules\Agent.psm1'
        $script:Files | Should -Contain 'modules\Common.psm1'
        $script:Files | Should -Contain 'SCGuardian.ps1'
        $script:Files | Should -Contain 'Install-Agent.ps1'
        $script:Files | Should -Contain 'agent.config.template.json'
    }
}

Describe 'New-AgentWxs' {
    BeforeAll {
        $script:Wxs1 = New-AgentWxs -TemplatePath $script:Template -StageDir $script:Stage1 -Version '4.0.0'
        $script:Wxs2 = New-AgentWxs -TemplatePath $script:Template -StageDir $script:Stage2 -Version '4.0.0'
    }
    It 'is well-formed XML' {
        { [xml]$script:Wxs1 } | Should -Not -Throw
    }
    It 'contains the version and fixed upgrade code' {
        $script:Wxs1 | Should -Match 'Version="4\.0\.0"'
        $script:Wxs1 | Should -Match 'UpgradeCode="\{B7A1C3D2-5E4F-4A6B-9C8D-1F2E3A4B5C6D\}"'
    }
    It 'declares HUBURL and SHAREDSECRET, the latter hidden' {
        $x = [xml]$script:Wxs1
        $ns = New-Object Xml.XmlNamespaceManager($x.NameTable); $ns.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
        $x.SelectSingleNode('//w:Property[@Id="HUBURL"]', $ns) | Should -Not -BeNullOrEmpty
        $x.SelectSingleNode('//w:Property[@Id="SHAREDSECRET"][@Hidden="yes"]', $ns) | Should -Not -BeNullOrEmpty
    }
    It 'ships no Hub or HttpServer files' {
        $script:Wxs1 | Should -Not -Match 'Hub\.psm1'
        $script:Wxs1 | Should -Not -Match 'HttpServer\.psm1'
    }
    It 'produces deterministic GUIDs across two runs' {
        $g1 = [regex]::Matches($script:Wxs1, 'Guid="\{[0-9A-F-]{36}\}"').Value
        $g2 = [regex]::Matches($script:Wxs2, 'Guid="\{[0-9A-F-]{36}\}"').Value
        $g1.Count | Should -BeGreaterThan 3
        ($g1 -join ',') | Should -Be ($g2 -join ',')
        ($g1 | Select-Object -Unique).Count | Should -Be $g1.Count
    }
    It 'rejects an invalid version' {
        { New-AgentWxs -TemplatePath $script:Template -StageDir $script:Stage1 -Version 'abc' } | Should -Throw
    }
}

Describe 'Install-Agent helpers' {
    It 'accepts https and loopback http only' {
        Test-HubUrl 'https://ostazna.pro:8443' | Should -BeTrue
        Test-HubUrl 'http://127.0.0.1:8443' | Should -BeTrue
        Test-HubUrl 'http://localhost:8443' | Should -BeTrue
        Test-HubUrl 'http://example.com' | Should -BeFalse
        Test-HubUrl 'ftp://example.com' | Should -BeFalse
        Test-HubUrl '' | Should -BeFalse
    }
    It 'rejects empty and REPLACE_ME secrets' {
        Test-SharedSecret '' | Should -BeFalse
        Test-SharedSecret 'REPLACE_ME' | Should -BeFalse
        Test-SharedSecret 's3cret-value' | Should -BeTrue
    }
    It 'masks the secret in text' {
        Protect-Secret -Text 'auth s3cret-value ok' -Secret 's3cret-value' | Should -Be 'auth *** ok'
        Protect-Secret -Text 'nothing' -Secret '' | Should -Be 'nothing'
    }
    It 'merges supplied values over a base config and keeps other keys' {
        $base = '{"hub_url":"https://old","shared_secret":"REPLACE_ME","allowed_ids":["a","b"],"heartbeat_sec":60,"trusted_server_thumbprint":""}' | ConvertFrom-Json
        $m = Merge-AgentConfig -Base $base -HubUrl 'https://new:8443' -SharedSecret 'abc' -Thumbprint 'aa bb'
        $m['hub_url'] | Should -Be 'https://new:8443'
        $m['shared_secret'] | Should -Be 'abc'
        $m['trusted_server_thumbprint'] | Should -Be 'AABB'
        $m['heartbeat_sec'] | Should -Be 60
        @($m['allowed_ids']).Count | Should -Be 2
    }
    It 'keeps base values when nothing is supplied' {
        $base = '{"hub_url":"https://old","shared_secret":"keep"}' | ConvertFrom-Json
        $m = Merge-AgentConfig -Base $base
        $m['shared_secret'] | Should -Be 'keep'
    }
    It 'validates thumbprints as optional 40 hex' {
        Test-ThumbprintValue '' | Should -BeTrue
        Test-ThumbprintValue ('A' * 40) | Should -BeTrue
        Test-ThumbprintValue 'XYZ' | Should -BeFalse
    }
    It 'builds icacls args using SYSTEM and Administrators SIDs' {
        $a = Get-IcaclsArguments -Path 'C:\ProgramData\SCGuardian'
        $a | Should -Contain '*S-1-5-18:(OI)(CI)F'
        $a | Should -Contain '*S-1-5-32-544:(OI)(CI)F'
        $a | Should -Contain '/inheritance:r'
    }
}
