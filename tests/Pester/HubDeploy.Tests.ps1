#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:DeployDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'hub-deploy'
    $script:CertScript = Join-Path $script:DeployDir 'cert-setup.ps1'
    $script:InstallScript = Join-Path $script:DeployDir 'install-hub.ps1'

    function script:Get-Ast([string]$Path) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        return [pscustomobject]@{ Ast = $ast; Errors = $errors }
    }

    # Load only the pure helpers (function definitions) from cert-setup.ps1.
    $parsed = script:Get-Ast $script:CertScript
    $script:HubAppId = '{7f3c1e52-4b8a-4d6e-9a21-5c0d8e3b6f14}'
    $names = @('Format-ThumbprintClean', 'ConvertTo-CertPem', 'Get-NetshBindingArgument', 'Set-ConfigThumbprint')
    $defs = $parsed.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $n.Name }, $true)
    foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
}

Describe 'Script parsing' {
    It 'cert-setup parses without errors' {
        (script:Get-Ast $script:CertScript).Errors.Count | Should -Be 0
    }
    It 'install-hub parses without errors' {
        (script:Get-Ast $script:InstallScript).Errors.Count | Should -Be 0
    }
    It 'cert-setup declares the required parameters' {
        $p = (script:Get-Ast $script:CertScript).Ast.ParamBlock.Parameters.Name.VariablePath.UserPath
        foreach ($n in 'Domain', 'Port', 'WinAcmePath', 'SelfSigned', 'ConfigPath') { $p | Should -Contain $n }
    }
    It 'install-hub declares the required parameters' {
        $p = (script:Get-Ast $script:InstallScript).Ast.ParamBlock.Parameters.Name.VariablePath.UserPath
        foreach ($n in 'SourceRoot', 'InstallDir', 'ConfigPath', 'Uninstall') { $p | Should -Contain $n }
    }
    It 'both scripts support ShouldProcess' {
        foreach ($f in $script:CertScript, $script:InstallScript) {
            (Get-Content -LiteralPath $f -Raw) | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
        }
    }
    It 'cert-setup defaults Domain and Port' {
        $params = (script:Get-Ast $script:CertScript).Ast.ParamBlock.Parameters
        ($params | Where-Object { $_.Name.VariablePath.UserPath -eq 'Domain' }).DefaultValue.Value | Should -Be 'ostazna.pro'
        ($params | Where-Object { $_.Name.VariablePath.UserPath -eq 'Port' }).DefaultValue.Value | Should -Be 8443
    }
    It 'install-hub never contains a real secret placeholder replacement' {
        (Get-Content -LiteralPath $script:InstallScript -Raw) | Should -Not -Match 'bot_token\s*=\s*[''"]\d'
    }
}

Describe 'Format-ThumbprintClean' {
    It 'uppercases and strips separators and spaces' {
        Format-ThumbprintClean -Thumbprint 'ab:cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01' | Should -Be 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
    }
    It 'strips invisible leading characters' {
        Format-ThumbprintClean -Thumbprint ([string][char]0x200E + 'ABCDEF0123456789ABCDEF0123456789ABCDEF01') | Should -Be 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
    }
    It 'throws on wrong length' {
        { Format-ThumbprintClean -Thumbprint 'ABCD' } | Should -Throw
    }
}

Describe 'ConvertTo-CertPem' {
    It 'wraps with header and footer' {
        $pem = ConvertTo-CertPem -DerBytes ([byte[]](1..10))
        $pem | Should -Match '^-----BEGIN CERTIFICATE-----\n'
        $pem | Should -Match '\n-----END CERTIFICATE-----$'
    }
    It 'wraps base64 at 64 columns' {
        $bytes = [byte[]](0..199)
        $lines = (ConvertTo-CertPem -DerBytes $bytes) -split "`n"
        $body = $lines[1..($lines.Count - 2)]
        ($body | Select-Object -SkipLast 1 | ForEach-Object { $_.Length } | Sort-Object -Unique) | Should -Be 64
        ($body -join '') | Should -Be ([Convert]::ToBase64String($bytes))
    }
}

Describe 'Get-NetshBindingArgument' {
    It 'builds the add arguments with the fixed appid' {
        $a = Get-NetshBindingArgument -Port 8443 -Thumbprint 'abcdef0123456789abcdef0123456789abcdef01'
        $a | Should -Contain 'ipport=0.0.0.0:8443'
        $a | Should -Contain 'certhash=ABCDEF0123456789ABCDEF0123456789ABCDEF01'
        $a | Should -Contain 'appid={7f3c1e52-4b8a-4d6e-9a21-5c0d8e3b6f14}'
        $a | Should -Contain 'certstorename=MY'
    }
    It 'builds the delete arguments' {
        (Get-NetshBindingArgument -Port 9000 -Delete) -join ' ' | Should -Be 'http delete sslcert ipport=0.0.0.0:9000'
    }
    It 'rejects an out of range port' {
        { Get-NetshBindingArgument -Port 70000 -Delete } | Should -Throw
    }
}

Describe 'Set-ConfigThumbprint' {
    It 'writes the thumbprint and preserves other fields' {
        $path = Join-Path $TestDrive 'hub.config.json'
        '{"listen":{"url":"https://+:8443/","cert_thumbprint":"auto"},"shared_secret":"x"}' | Set-Content -LiteralPath $path -Encoding UTF8
        Set-ConfigThumbprint -ConfigPath $path -Thumbprint 'abcdef0123456789abcdef0123456789abcdef01' | Out-Null
        $cfg = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $cfg.listen.cert_thumbprint | Should -Be 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
        $cfg.listen.url | Should -Be 'https://+:8443/'
        $cfg.shared_secret | Should -Be 'x'
    }
    It 'throws when the config is missing' {
        { Set-ConfigThumbprint -ConfigPath (Join-Path $TestDrive 'none.json') -Thumbprint 'abcdef0123456789abcdef0123456789abcdef01' } | Should -Throw
    }
}
