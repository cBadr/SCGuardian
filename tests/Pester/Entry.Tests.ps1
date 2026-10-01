# Entry.Tests.ps1 - static checks for src/SCGuardian.ps1 (never executes the script)
# Author: Badr - SCGuardian v4

BeforeAll {
    $script:EntryPath = Join-Path $PSScriptRoot '..\..\src\SCGuardian.ps1'
    $tokens = $null; $errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $script:EntryPath).Path, [ref]$tokens, [ref]$errors)
    $script:ParseErrors = $errors
    $script:Text = [IO.File]::ReadAllText((Resolve-Path $script:EntryPath).Path)
    $script:Functions = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    $script:GetFunctionText = {
        param([string]$Name)
        $f = $script:Functions | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($f) { $f.Extent.Text } else { $null }
    }
}

Describe 'SCGuardian entry point - parse' {
    It 'parses with zero errors' {
        @($script:ParseErrors).Count | Should -Be 0
    }
    It 'keeps the UTF-8 BOM' {
        $b = [IO.File]::ReadAllBytes((Resolve-Path $script:EntryPath).Path)
        ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) | Should -BeTrue
    }
}

Describe 'SCGuardian entry point - parameters' {
    BeforeAll {
        $script:ModeParam = $script:Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' }
        $vs = $script:ModeParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
        $script:ModeSet = @($vs.PositionalArguments | ForEach-Object { $_.Value })
        $script:ParamNames = @($script:Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    }
    It 'ValidateSet keeps the 6 legacy modes' {
        foreach ($m in @('Report','Harden','Monitor','Restore','Listen','Controller')) { $script:ModeSet | Should -Contain $m }
    }
    It 'ValidateSet adds Hub, Agent, AgentLoop' {
        foreach ($m in @('Hub','Agent','AgentLoop')) { $script:ModeSet | Should -Contain $m }
    }
    It 'ValidateSet has exactly 9 modes' {
        $script:ModeSet.Count | Should -Be 9
    }
    It 'declares all legacy and new parameters' {
        foreach ($p in @('AllowedIds','Layers','TelegramBotToken','TelegramChatId','TestTelegram','InstallSchedule','RemoveSchedule','InstallController','TakeOwnership','ScanIntervalMinutes','HeartbeatHours','AlertThrottleMinutes','SaveConfig','Elevated','HubConfigPath','AgentConfigPath','InstallAgent','RemoveAgent')) {
            $script:ParamNames | Should -Contain $p
        }
    }
    It 'defaults config paths under ProgramData' {
        $script:Text | Should -Match ([regex]::Escape("'C:\ProgramData\SCGuardian\hub.config.json'"))
        $script:Text | Should -Match ([regex]::Escape("'C:\ProgramData\SCGuardian\agent.config.json'"))
    }
}

Describe 'SCGuardian entry point - legacy functions intact' {
    It 'defines every legacy function' {
        foreach ($f in @('Ensure-Dirs','Write-Log','Test-Admin','Get-SelfPath','Invoke-Native','Resolve-Settings','Resolve-Defaults','Invoke-Elevation','Save-ConfigFile','Load-State','Save-State','Send-Telegram','Get-Agents','Remove-Agent','Handle-Command','Invoke-CommandPoll','Invoke-ControllerPoll','Install-Controller','Invoke-Hardening','Invoke-Restore','Install-Watchdog','Remove-Watchdog','Show-Report','Invoke-Scan')) {
            ($script:Functions.Name) | Should -Contain $f
        }
    }
}

Describe 'SCGuardian entry point - legacy $Defaults unchanged' {
    BeforeAll {
        $assign = $script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$Defaults' }, $true) | Select-Object -First 1
        $hash = $assign.Right.Expression
        $script:DefaultKeys = @($hash.KeyValuePairs | ForEach-Object { $_.Item1.Value })
    }
    It 'has exactly the legacy keys' {
        $expected = @('Mode','InstallSchedule','Layers','ScanIntervalMinutes','HeartbeatHours','AlertThrottleMinutes','TakeOwnership','ListenForCommands','CommandConfirmSeconds')
        ($script:DefaultKeys | Sort-Object) -join ',' | Should -Be (($expected | Sort-Object) -join ',')
    }
    It 'bare-run default mode is still Harden' {
        $script:Text | Should -Match "Mode\s+=\s+'Harden'"
    }
}

Describe 'SCGuardian entry point - secrets and module isolation' {
    It 'contains no Telegram bot token pattern' {
        $script:Text | Should -Not -Match '\d{8,10}:[A-Za-z0-9_-]{30,}'
    }
    It 'embedded TelegramBotToken is blank' {
        $script:Text | Should -Match "TelegramBotToken\s*=\s*''"
    }
    It 'hub mode imports the hub modules only' {
        $hub = & $script:GetFunctionText 'Invoke-ScgHubMode'
        $hub | Should -Not -BeNullOrEmpty
        $hub | Should -Match 'Start-ScgHub'
        $hub | Should -Not -Match 'Hardening'
        $hub | Should -Not -Match 'Discovery'
    }
    It 'agent modes do not import hub-side modules' {
        foreach ($n in @('Invoke-ScgAgentMode','Invoke-ScgAgentLoopMode')) {
            $t = & $script:GetFunctionText $n
            $t | Should -Not -BeNullOrEmpty
            $t | Should -Match 'Invoke-ScgAgentCycle'
            $t | Should -Not -Match "'(Database|HttpServer|Telegram|Hub)'"
        }
    }
    It 'agent loop honours the stop-file and sleeps by Get-ScgNextDelaySec' {
        $t = & $script:GetFunctionText 'Invoke-ScgAgentLoopMode'
        $t | Should -Match 'AgentStopFile'
        $t | Should -Match 'Get-ScgNextDelaySec'
        $t | Should -Match 'catch'
        $script:Text | Should -Match ([regex]::Escape("Join-Path `$Root 'agent.stop'"))
    }
    It 'new-mode helpers never touch legacy settings' {
        foreach ($n in @('Invoke-ScgHubMode','Invoke-ScgAgentMode','Invoke-ScgAgentLoopMode','Install-ScgAgentTask','Remove-ScgAgentTask')) {
            $t = & $script:GetFunctionText $n
            $t | Should -Not -Match 'EmbeddedConfig|TelegramBotToken|Resolve-Settings'
        }
    }
    It 'new-mode dispatch runs before legacy Resolve-Settings' {
        $dispatch = $script:Text.IndexOf("'Hub'       { Invoke-ScgHubMode }")
        $legacy = $script:Text.IndexOf('Resolve-Settings -Bound $PSBoundParameters')
        $dispatch | Should -BeGreaterThan 0
        $dispatch | Should -BeLessThan $legacy
    }
    It 'agent task is SYSTEM, highest, at startup, restarts, runs AgentLoop' {
        $t = & $script:GetFunctionText 'Install-ScgAgentTask'
        $t | Should -Match 'S-1-5-18'
        $t | Should -Match 'RunLevel Highest'
        $t | Should -Match 'AtStartup'
        $t | Should -Match 'RestartCount'
        $t | Should -Match '-Mode AgentLoop'
        $script:Text | Should -Match "AgentTaskName = 'SCGuardian-Agent'"
    }
    It 'module lookup checks script modules then Program Files' {
        $t = & $script:GetFunctionText 'Get-ScgEntryModuleDir'
        $t | Should -Match 'PSScriptRoot'
        $t | Should -Match ([regex]::Escape('C:\Program Files\SCGuardian\modules'))
    }
}
