#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SetupScript = Join-Path $script:RepoRoot 'hub-deploy\Setup-Hub.ps1'
    $script:TemplateScript = Join-Path $script:RepoRoot 'hub-deploy\agent-bootstrap.template.ps1'
    $script:CmdTemplate = Join-Path $script:RepoRoot 'hub-deploy\agent-bootstrap.cmd.template'
    $script:ConfigTemplate = Join-Path $script:RepoRoot 'src\config\hub.config.template.json'

    function script:Get-Ast([string]$Path) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        return [pscustomobject]@{ Ast = $ast; Errors = $errors }
    }

    $parsed = script:Get-Ast $script:SetupScript
    $names = @('New-HubSecret', 'Get-HubConfigValue', 'Set-HubConfigValue', 'Test-HubConfigPlaceholder', 'Get-HubPlaceholderField',
        'ConvertTo-HubAdminIdList', 'Test-HubAnswerFormat', 'Update-HubConfig', 'Read-HubConfig', 'Save-HubConfig', 'Test-HubThumbprint',
        'Test-SslBindingMatch', 'Get-Sha256FromSums', 'ConvertTo-SingleQuotedContent', 'ConvertTo-AgentBootstrap', 'Find-ExtractedRoot', 'Hide-HubSecret')
    $defs = $parsed.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $n.Name }, $true)
    foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }

    $script:Thumb = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
    $script:Sha = ('ab' * 32)
    $script:Answers = @{
        'telegram.bot_token'      = '1234567:AAbbCCddEEffGGhhIIjjKKllMMnnOOpp'
        'telegram.chat_id'        = '-1009876543210'
        'telegram.admin_user_ids' = '111, 222'
    }

    function script:New-Rendered([string]$Secret) {
        $tpl = [IO.File]::ReadAllText($script:TemplateScript)
        return (ConvertTo-AgentBootstrap -Template $tpl -HubUrl 'https://ostazna.pro:8443' -SharedSecret $Secret -Thumbprint $script:Thumb -Version '4.0.1' -SetupSha256 $script:Sha)
    }
}

Describe 'Script hygiene' {
    It 'Setup-Hub parses without errors' {
        (script:Get-Ast $script:SetupScript).Errors.Count | Should -Be 0
    }
    It 'the bootstrap template parses without errors' {
        (script:Get-Ast $script:TemplateScript).Errors.Count | Should -Be 0
    }
    It 'neither script uses iex or Invoke-Expression' {
        foreach ($f in $script:SetupScript, $script:TemplateScript) {
            $text = Get-Content -LiteralPath $f -Raw
            $text | Should -Not -Match '(?i)\biex\b'
            $text | Should -Not -Match '(?i)Invoke-Expression'
        }
    }
    It 'no param default references PSScriptRoot' {
        foreach ($f in $script:SetupScript, $script:TemplateScript) {
            $ast = (script:Get-Ast $f).Ast
            $blocks = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParamBlockAst] }, $true)
            foreach ($b in $blocks) { $b.Extent.Text | Should -Not -Match '(?i)PSScriptRoot' }
        }
    }
    It 'Setup-Hub declares the required parameters and ShouldProcess' {
        $p = (script:Get-Ast $script:SetupScript).Ast.ParamBlock.Parameters.Name.VariablePath.UserPath
        foreach ($n in 'Domain', 'Port', 'Version', 'SourceRoot', 'Reinstall', 'NewCert', 'SkipHealthCheck', 'Desktop') { $p | Should -Contain $n }
        (Get-Content -LiteralPath $script:SetupScript -Raw) | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
    }
    It 'Setup-Hub guards execution when dot-sourced' {
        (Get-Content -LiteralPath $script:SetupScript -Raw) | Should -Match ([regex]::Escape("if (`$MyInvocation.InvocationName -eq '.') { return }"))
    }
    It 'the bootstrap template self-elevates and never bypasses the admin check' {
        $text = Get-Content -LiteralPath $script:TemplateScript -Raw
        $text | Should -Match '(?i)Test-IsAdministrator'
        $text | Should -Match '(?i)-Verb\s+RunAs'
        $text | Should -Match '(?i)\[switch\]\$Elevated'
    }
    It 'the cmd launcher exists, is plain ASCII batch and runs the ps1 unattended' {
        Test-Path -LiteralPath $script:CmdTemplate -PathType Leaf | Should -BeTrue
        $bytes = [IO.File]::ReadAllBytes($script:CmdTemplate)
        # no UTF-8/UTF-16 BOM: a BOM at the top of a .cmd file can corrupt the first command on some cmd.exe builds
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        $text = [IO.File]::ReadAllText($script:CmdTemplate)
        $text | Should -Match '(?i)^@echo off'
        $text | Should -Match '(?i)agent-bootstrap\.ps1'
        $text | Should -Match '(?i)-ExecutionPolicy\s+Bypass'
        $text | Should -Not -Match '\{\{'
    }
    It 'Setup-Hub writes both the ps1 and the cmd launcher, and copies both to Desktop' {
        $text = Get-Content -LiteralPath $script:SetupScript -Raw
        $text | Should -Match 'CmdBootstrapPath'
        $text | Should -Match "'agent-bootstrap\.cmd'"
        $text | Should -Match 'agent-bootstrap\.cmd\.template'
    }
}

Describe 'New-HubSecret' {
    It 'returns 64 lowercase hex characters' {
        New-HubSecret | Should -MatchExactly '^[0-9a-f]{64}$'
    }
    It 'differs on each call' {
        New-HubSecret | Should -Not -Be (New-HubSecret)
    }
}

Describe 'Test-HubConfigPlaceholder' {
    It 'flags shared_secret placeholders' {
        Test-HubConfigPlaceholder -Field 'shared_secret' -Value 'REPLACE_ME' | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'shared_secret' -Value '' | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'shared_secret' -Value $null | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'shared_secret' -Value 'abc123' | Should -BeFalse
    }
    It 'flags bot_token placeholders' {
        Test-HubConfigPlaceholder -Field 'telegram.bot_token' -Value 'REPLACE_ME' | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'telegram.bot_token' -Value '123:abc' | Should -BeFalse
    }
    It 'flags chat_id placeholders' {
        Test-HubConfigPlaceholder -Field 'telegram.chat_id' -Value '-100...' | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'telegram.chat_id' -Value '' | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'telegram.chat_id' -Value '-1001234' | Should -BeFalse
    }
    It 'flags admin_user_ids placeholders' {
        Test-HubConfigPlaceholder -Field 'telegram.admin_user_ids' -Value @('123456789') | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'telegram.admin_user_ids' -Value @() | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'telegram.admin_user_ids' -Value $null | Should -BeTrue
        Test-HubConfigPlaceholder -Field 'telegram.admin_user_ids' -Value @('555') | Should -BeFalse
    }
    It 'throws on an unknown field' {
        { Test-HubConfigPlaceholder -Field 'nope' -Value 'x' } | Should -Throw
    }
}

Describe 'Update-HubConfig' {
    It 'fills every placeholder of the shipped template' {
        $path = Join-Path $TestDrive 'fresh.json'
        Copy-Item -LiteralPath $script:ConfigTemplate -Destination $path
        $cfg = Read-HubConfig -Path $path
        (Get-HubPlaceholderField -Config $cfg).Count | Should -Be 4
        $r = Update-HubConfig -Config $cfg -Port 9443 -Answers $script:Answers
        $r.Unresolved.Count | Should -Be 0
        $r.SecretGenerated | Should -BeTrue
        Save-HubConfig -Config $r.Config -Path $path
        $back = Read-HubConfig -Path $path
        $back.shared_secret | Should -MatchExactly '^[0-9a-f]{64}$'
        $back.telegram.bot_token | Should -Be $script:Answers['telegram.bot_token']
        $back.telegram.chat_id | Should -Be '-1009876543210'
        @($back.telegram.admin_user_ids) | Should -Be @('111', '222')
        $back.listen.url | Should -Be 'https://+:9443/'
        @($back.defaults.allowed_ids).Count | Should -Be 2
        (Get-HubPlaceholderField -Config $back).Count | Should -Be 0
    }
    It 'preserves values the operator already set' {
        $path = Join-Path $TestDrive 'set.json'
        '{"listen":{"url":"https://+:8443/","cert_thumbprint":"auto"},"shared_secret":"operator-secret","telegram":{"bot_token":"999999:operatorTokenValue_abcdefghij","chat_id":"-100555","admin_user_ids":["42"],"admin_usernames":["Idlexaz"]},"defaults":{"heartbeat_sec":30}}' |
            Set-Content -LiteralPath $path -Encoding UTF8
        $cfg = Read-HubConfig -Path $path
        $r = Update-HubConfig -Config $cfg -Port 8443 -Answers $script:Answers
        $r.Filled.Count | Should -Be 0
        $r.SecretGenerated | Should -BeFalse
        $r.Config.shared_secret | Should -Be 'operator-secret'
        $r.Config.telegram.bot_token | Should -Be '999999:operatorTokenValue_abcdefghij'
        $r.Config.telegram.chat_id | Should -Be '-100555'
        @($r.Config.telegram.admin_user_ids) | Should -Be @('42')
        $r.Config.defaults.heartbeat_sec | Should -Be 30
    }
    It 'fills only the fields that still hold placeholders' {
        $cfg = '{"shared_secret":"keep-me","telegram":{"bot_token":"REPLACE_ME","chat_id":"-100777","admin_user_ids":["123456789"]}}' | ConvertFrom-Json
        $r = Update-HubConfig -Config $cfg -Port 8443 -Answers $script:Answers
        $r.Filled | Should -Be @('telegram.bot_token', 'telegram.admin_user_ids')
        $r.Config.shared_secret | Should -Be 'keep-me'
        $r.Config.telegram.chat_id | Should -Be '-100777'
        $r.Config.listen.url | Should -Be 'https://+:8443/'
    }
    It 'reports unresolved fields when no answer is given' {
        $cfg = '{"shared_secret":"REPLACE_ME","telegram":{"bot_token":"REPLACE_ME","chat_id":"-100...","admin_user_ids":[]}}' | ConvertFrom-Json
        $r = Update-HubConfig -Config $cfg -Port 8443 -Answers @{} -NewSecret ('c' * 64)
        $r.Config.shared_secret | Should -Be ('c' * 64)
        $r.Unresolved | Should -Be @('telegram.bot_token', 'telegram.chat_id', 'telegram.admin_user_ids')
    }
}

Describe 'Test-HubAnswerFormat' {
    It 'accepts valid answers and rejects bad ones' {
        Test-HubAnswerFormat -Field 'telegram.bot_token' -Value $script:Answers['telegram.bot_token'] | Should -BeTrue
        Test-HubAnswerFormat -Field 'telegram.bot_token' -Value 'nope' | Should -BeFalse
        Test-HubAnswerFormat -Field 'telegram.chat_id' -Value '-100123' | Should -BeTrue
        Test-HubAnswerFormat -Field 'telegram.chat_id' -Value '-100...' | Should -BeFalse
        Test-HubAnswerFormat -Field 'telegram.admin_user_ids' -Value '1, 2' | Should -BeTrue
        Test-HubAnswerFormat -Field 'telegram.admin_user_ids' -Value '123456789' | Should -BeFalse
    }
}

Describe 'Get-Sha256FromSums' {
    It 'parses sha256sum style lines' {
        $c = "$('11' * 32)  SCGuardian.Hub.zip`n$('AB' * 32) *SCGuardian.Agent.Setup.exe`n"
        Get-Sha256FromSums -Content $c | Should -Be ('ab' * 32)
    }
    It 'parses name-first lines with CRLF' {
        $c = "SCGuardian.Agent.Setup.exe  $('cd' * 32)`r`nother.txt $('00' * 32)"
        Get-Sha256FromSums -Content $c -FileName 'SCGuardian.Agent.Setup.exe' | Should -Be ('cd' * 32)
    }
    It 'throws when the file is not listed' {
        { Get-Sha256FromSums -Content "$('11' * 32)  other.exe" } | Should -Throw
    }
}

Describe 'ConvertTo-AgentBootstrap' {
    It 'leaves no placeholder and contains the values' {
        $out = script:New-Rendered 'deadbeef1234'
        $out | Should -Not -Match '\{\{[A-Z0-9_]+\}\}'
        $out | Should -Match ([regex]::Escape("'https://ostazna.pro:8443'"))
        $out | Should -Match ([regex]::Escape("'deadbeef1234'"))
        $out | Should -Match ([regex]::Escape("'$($script:Thumb)'"))
        $out | Should -Match ([regex]::Escape("'4.0.1'"))
        $out | Should -Match ([regex]::Escape("'$($script:Sha)'"))
    }
    It 'escapes single quotes and still parses clean' {
        $secret = "ab'cd" + [char]0x2019 + 'ef'
        $out = script:New-Rendered $secret
        $out | Should -Match ([regex]::Escape("ab''cd"))
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($out, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
        $hits = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -eq $secret }, $true)
        @($hits).Count | Should -BeGreaterThan 0
    }
    It 'the rendered script parses with zero errors' {
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseInput((script:New-Rendered ('a' * 64)), [ref]$tokens, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0
    }
    It 'rejects a secret with whitespace' {
        { script:New-Rendered 'has space' } | Should -Throw
    }
    It 'rejects a template missing a placeholder' {
        { ConvertTo-AgentBootstrap -Template "'{{HUB_URL}}'" -HubUrl 'https://h:1' -SharedSecret 'x' -Thumbprint $script:Thumb -Version '4.0.1' -SetupSha256 $script:Sha } | Should -Throw
    }
}

Describe 'Find-ExtractedRoot' {
    It 'finds the extracted folder without knowing its name' {
        $base = Join-Path $TestDrive 'extract'
        $repo = Join-Path $base 'SCGuardian-4.0.1'
        New-Item -ItemType Directory -Path (Join-Path $repo 'hub-deploy') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $repo 'hub-deploy\install-hub.ps1') -Value '#'
        Find-ExtractedRoot -Path $base | Should -Be (Get-Item -LiteralPath $repo).FullName
        Find-ExtractedRoot -Path $repo | Should -Be (Get-Item -LiteralPath $repo).FullName
    }
    It 'returns null when nothing matches' {
        $empty = Join-Path $TestDrive 'empty'
        New-Item -ItemType Directory -Path $empty -Force | Out-Null
        Find-ExtractedRoot -Path $empty | Should -BeNullOrEmpty
        Find-ExtractedRoot -Path (Join-Path $TestDrive 'missing') | Should -BeNullOrEmpty
    }
}

Describe 'Small helpers' {
    It 'Test-HubThumbprint accepts 40 hex only' {
        Test-HubThumbprint $script:Thumb | Should -BeTrue
        Test-HubThumbprint 'auto' | Should -BeFalse
    }
    It 'Test-SslBindingMatch finds the hash case-insensitively' {
        Test-SslBindingMatch -NetshOutput "    Certificate Hash             : $($script:Thumb.ToLower())" -Thumbprint $script:Thumb | Should -BeTrue
        Test-SslBindingMatch -NetshOutput 'The system cannot find the file specified.' -Thumbprint $script:Thumb | Should -BeFalse
    }
    It 'Hide-HubSecret masks secrets, bot tokens and bearer values' {
        $t = Hide-HubSecret -Text 'secret=topsecret1 token 1234567:AAbbCCddEEffGGhhIIjjKKll Bearer xyz' -Secret @('topsecret1')
        $t | Should -Not -Match 'topsecret1'
        $t | Should -Not -Match 'AAbbCC'
        $t | Should -Not -Match 'xyz'
    }
}
