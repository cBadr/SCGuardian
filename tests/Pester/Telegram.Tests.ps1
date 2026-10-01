# Telegram.Tests.ps1 - Pester 5 tests for src/modules/Telegram.psm1 (no network, DB functions mocked).
# Author: Badr (@Idlexaz)

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\src\modules\Telegram.psm1') -Force -DisableNameChecking

    $script:Cfg = [pscustomobject]@{
        telegram = [pscustomobject]@{
            bot_token        = ''
            chat_id          = '-100123'
            admin_user_ids   = @('42', '43')
            admin_usernames  = @('opsadmin')
        }
        database = [pscustomobject]@{ path = 'test.db' }
        defaults = [pscustomobject]@{
            allowed_ids         = @('aaaaaaaaaaaaaaaa')
            command_confirm_sec = 120
            stale_after_min     = 5
        }
    }

    function New-TestMessage {
        param([string]$Text, [string]$FromId = '42', [string]$User = 'someone', [string]$Chat = '-100123')
        [pscustomobject]@{
            update_id = 1
            message   = [pscustomobject]@{
                text = $Text
                from = [pscustomobject]@{ id = $FromId; username = $User }
                chat = [pscustomobject]@{ id = $Chat }
            }
        }
    }

    function New-TestCallback {
        param([string]$Data, [string]$FromId = '42', [string]$User = 'someone', [string]$Chat = '-100123')
        [pscustomobject]@{
            update_id      = 2
            callback_query = [pscustomobject]@{
                id      = 'cbq1'
                data    = $Data
                from    = [pscustomobject]@{ id = $FromId; username = $User }
                message = [pscustomobject]@{ message_id = 77; chat = [pscustomobject]@{ id = $Chat } }
            }
        }
    }

    function Get-TestButton {
        param($Markup)
        @($Markup.inline_keyboard | ForEach-Object { $_ })
    }

    $script:Sent = New-Object System.Collections.ArrayList
    $script:Sender = {
        param($Text, $Markup, $ChatId, $EditMessageId)
        [void]$script:Sent.Add([pscustomobject]@{ Text = $Text; Markup = $Markup; ChatId = $ChatId; EditId = $EditMessageId })
    }

    function Send-Test {
        param($Update)
        $script:Sent.Clear()
        Invoke-TgRouter -Update $Update -Config $script:Cfg -Send $script:Sender
    }
}

Describe 'Telegram module' {
    BeforeEach {
        InModuleScope Telegram { $script:TgPending.Clear(); $script:TgClockSkewSec = 0 }
        $script:Sent.Clear()

        Mock Write-ScgLog -ModuleName Telegram { }
        Mock Add-ScgAudit -ModuleName Telegram { }
        Mock New-ScgCommand -ModuleName Telegram { 'cmd-1' }
        Mock Invoke-TgApi -ModuleName Telegram { $null }
        Mock Get-ScgHealthCounts -ModuleName Telegram { [pscustomobject]@{ devices_online = 1; commands_pending = 0 } }
        Mock Get-ScgEvent -ModuleName Telegram { @([pscustomobject]@{ ts = '2026-01-01T00:00:00.000Z'; severity = 'warn'; type = 'unknown_agent'; hostname = 'PC1' }) }
        Mock Get-ScgAudit -ModuleName Telegram { @([pscustomobject]@{ ts = '2026-01-01T00:00:00.000Z'; actor = 'system'; action = 'enroll'; target = 'PC1' }) }
        Mock Get-ScgDevice -ModuleName Telegram {
            @(
                [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active' },
                [pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222'; hostname = 'PC2'; status = 'stale' },
                [pscustomobject]@{ id = '33333333-3333-3333-3333-333333333333'; hostname = 'PC3'; status = 'quarantined' }
            )
        }
        Mock Get-ScgScAgent -ModuleName Telegram {
            @(
                [pscustomobject]@{ id = 'bbbbbbbbbbbbbbbb'; service = 'evil'; state = 'Running'; authorized = 0 },
                [pscustomobject]@{ id = 'aaaaaaaaaaaaaaaa'; service = 'listed'; state = 'Running'; authorized = 0 },
                [pscustomobject]@{ id = 'cccccccccccccccc'; service = 'mine'; state = 'Running'; authorized = 1 }
            )
        }
    }

    Context 'ConvertFrom-TgCommand' {
        It 'parses a plain command' {
            $r = ConvertFrom-TgCommand -Text '/status PC1'
            $r.Command | Should -Be '/status'
            $r.Argument | Should -Be @('PC1')
        }
        It 'strips the @bot suffix and extra spaces' {
            $r = ConvertFrom-TgCommand -Text '  /Harden@SCGuardianBot    all   '
            $r.Command | Should -Be '/harden'
            @($r.Argument).Count | Should -Be 1
            $r.Argument[0] | Should -Be 'all'
        }
        It 'returns null for non-commands' {
            ConvertFrom-TgCommand -Text 'hello' | Should -BeNullOrEmpty
        }
        It 'handles a command with no arguments' {
            @((ConvertFrom-TgCommand -Text '/panel').Argument).Count | Should -Be 0
        }
    }

    Context 'Test-TgAdmin' {
        It 'matches by user id' {
            Test-TgAdmin -From ([pscustomobject]@{ id = 42; username = '' }) -AdminUserId @('42') -AdminUsername @() | Should -BeTrue
        }
        It 'matches by username case-insensitively, with or without @' {
            Test-TgAdmin -From ([pscustomobject]@{ id = 9; username = 'OpsAdmin' }) -AdminUserId @() -AdminUsername @('@opsadmin') | Should -BeTrue
        }
        It 'rejects strangers and empty usernames' {
            Test-TgAdmin -From ([pscustomobject]@{ id = 9; username = '' }) -AdminUserId @('42') -AdminUsername @('') | Should -BeFalse
            Test-TgAdmin -From $null -AdminUserId @('42') -AdminUsername @() | Should -BeFalse
        }
    }

    Context 'authorization' {
        It 'admin by id passes, admin by username passes' {
            Send-Test (New-TestMessage '/help' -FromId '42')
            $script:Sent.Count | Should -Be 1
            Send-Test (New-TestMessage '/help' -FromId '999' -User 'opsadmin')
            $script:Sent.Count | Should -Be 1
        }
        It 'non-admin is blocked on every command except /whoami' {
            foreach ($c in @('/start', '/help', '/panel', '/devices', '/status all', '/agents PC1', '/harden all', '/restore PC1', '/remove PC1 bbbbbbbbbbbbbbbb', '/confirm 123456', '/events', '/audit', '/ping PC1')) {
                Send-Test (New-TestMessage $c -FromId '999' -User 'nobody')
                $script:Sent.Count | Should -Be 0 -Because $c
            }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It '/whoami is answered for anyone' {
            Send-Test (New-TestMessage '/whoami' -FromId '999' -User 'nobody')
            $script:Sent.Count | Should -Be 1
            $script:Sent[0].Text | Should -Match '999'
            $script:Sent[0].Text | Should -Match 'admin: False'
        }
        It 'ignores messages from other chats' {
            Send-Test (New-TestMessage '/help' -Chat '-999')
            $script:Sent.Count | Should -Be 0
        }
        It 'non-admin callback gets Unauthorized alert and nothing else' {
            Send-Test (New-TestCallback 'm:main' -FromId '999' -User 'nobody')
            $script:Sent.Count | Should -Be 0
            Should -Invoke Invoke-TgApi -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Method -eq 'answerCallbackQuery' -and $Body.text -eq 'Unauthorized' -and $Body.show_alert -eq $true }
        }
    }

    Context 'fan-out and state-changing commands' {
        It '/harden all creates one command per device and audits each' {
            Send-Test (New-TestMessage '/harden all')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 3 -Exactly -ParameterFilter { $Type -eq 'harden' -and $IssuedVia -eq 'telegram' -and $IssuedBy -eq 'telegram:42' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 3 -Exactly -ParameterFilter { $Action -eq 'command.issue' -and $Actor -eq 'telegram:42' }
        }
        It '/harden host creates exactly one command' {
            Send-Test (New-TestMessage '/harden pc2')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $DeviceId -like '2222*' }
        }
        It '/restore all and /ping all are refused' {
            Send-Test (New-TestMessage '/restore all')
            Send-Test (New-TestMessage '/ping all')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'unknown host creates nothing' {
            Send-Test (New-TestMessage '/harden nope')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            $script:Sent[0].Text | Should -Match 'Unknown host'
        }
        It '/ping, /status and /agents queue their command types' {
            Send-Test (New-TestMessage '/ping PC1')
            Send-Test (New-TestMessage '/status PC1')
            Send-Test (New-TestMessage '/agents PC1')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'ping' }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'status' }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'agents' }
        }
        It '/events and /audit read from the DB without issuing commands' {
            Send-Test (New-TestMessage '/events 5')
            $script:Sent[0].Text | Should -Match 'unknown_agent'
            Send-Test (New-TestMessage '/audit')
            $script:Sent[0].Text | Should -Match 'enroll'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
    }

    Context '/remove two-step confirmation' {
        It 'happy path: request issues a 6-digit code, confirm queues a remove command once' {
            Send-Test (New-TestMessage '/remove PC1 bbbbbbbbbbbbbbbb')
            $code = InModuleScope Telegram { $script:TgPending['42'].Code }
            $code | Should -Match '^\d{6}$'
            $script:Sent[0].Text | Should -Match $code
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'remove.request' }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly

            Send-Test (New-TestMessage "/confirm $code")
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'remove' -and $Payload.sc_id -eq 'bbbbbbbbbbbbbbbb' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'remove.confirm' }
        }
        It 'wrong code is rejected and queues nothing' {
            Send-Test (New-TestMessage '/remove PC1 bbbbbbbbbbbbbbbb')
            $code = InModuleScope Telegram { $script:TgPending['42'].Code }
            $wrong = if ($code -eq '111111') { '222222' } else { '111111' }
            Send-Test (New-TestMessage "/confirm $wrong")
            $script:Sent[0].Text | Should -Match 'wrong'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'expired code is rejected' {
            Send-Test (New-TestMessage '/remove PC1 bbbbbbbbbbbbbbbb')
            $code = InModuleScope Telegram { $script:TgPending['42'].Code }
            InModuleScope Telegram { $script:TgClockSkewSec = 500 }
            Send-Test (New-TestMessage "/confirm $code")
            $script:Sent[0].Text | Should -Match 'expired|nothing pending'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'code is one-use' {
            Send-Test (New-TestMessage '/remove PC1 bbbbbbbbbbbbbbbb')
            $code = InModuleScope Telegram { $script:TgPending['42'].Code }
            Send-Test (New-TestMessage "/confirm $code")
            Send-Test (New-TestMessage "/confirm $code")
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'remove' }
        }
        It 'code is bound to the issuing admin' {
            Send-Test (New-TestMessage '/remove PC1 bbbbbbbbbbbbbbbb' -FromId '42')
            $code = InModuleScope Telegram { $script:TgPending['42'].Code }
            Send-Test (New-TestMessage "/confirm $code" -FromId '43')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'three wrong codes cancel the pending removal' {
            Send-Test (New-TestMessage '/remove PC1 bbbbbbbbbbbbbbbb')
            $code = InModuleScope Telegram { $script:TgPending['42'].Code }
            $wrong = if ($code -eq '111111') { '222222' } else { '111111' }
            1..3 | ForEach-Object { Send-Test (New-TestMessage "/confirm $wrong") }
            Send-Test (New-TestMessage "/confirm $code")
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'refuses an allow-listed id' {
            Send-Test (New-TestMessage '/remove PC1 aaaaaaaaaaaaaaaa')
            $script:Sent[0].Text | Should -Match 'allow-list'
            InModuleScope Telegram { $script:TgPending.Count } | Should -Be 0
        }
        It 'refuses non-16-hex ids' {
            Send-Test (New-TestMessage '/remove PC1 xyz')
            $script:Sent[0].Text | Should -Match 'invalid agent id'
            InModuleScope Telegram { $script:TgPending.Count } | Should -Be 0
        }
        It "refuses host 'all'" {
            Send-Test (New-TestMessage '/remove all bbbbbbbbbbbbbbbb')
            $script:Sent[0].Text | Should -Match 'specific host'
            InModuleScope Telegram { $script:TgPending.Count } | Should -Be 0
        }
        It 'refuses an agent the DB shows as authorized' {
            Send-Test (New-TestMessage '/remove PC1 cccccccccccccccc')
            InModuleScope Telegram { $script:TgPending.Count } | Should -Be 0
        }
        It 'refuses an agent the DB does not know' {
            Send-Test (New-TestMessage '/remove PC1 dddddddddddddddd')
            InModuleScope Telegram { $script:TgPending.Count } | Should -Be 0
        }
        It 'button flow: rm shows confirm menu, rmc queues the command' {
            Send-Test (New-TestCallback 'rm:11111111:bbbbbbbbbbbbbbbb')
            $btn = Get-TestButton $script:Sent[0].Markup
            ($btn | Where-Object { $_.callback_data -eq 'rmc:11111111:bbbbbbbbbbbbbbbb' }) | Should -Not -BeNullOrEmpty
            Send-Test (New-TestCallback 'rmc:11111111:bbbbbbbbbbbbbbbb')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'remove' }
        }
        It 'button confirm without a pending request does nothing' {
            Send-Test (New-TestCallback 'rmc:11111111:bbbbbbbbbbbbbbbb')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
    }

    Context '/reset device token' {
        BeforeEach {
            Mock Clear-ScgDeviceToken -ModuleName Telegram { $true }
        }
        It 'admin /reset host revokes the token and warns about the fleet secret' {
            Send-Test (New-TestMessage '/reset pc1')
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 1 -Exactly
            $script:Sent[0].Text | Should -Match 'revoked'
            $script:Sent[0].Text | Should -Match 're-enroll'
            $script:Sent[0].Text | Should -Match 'fleet secret'
            $script:Sent[0].Text | Should -Match '/events'
        }
        It 'non-admin /reset is blocked and clears nothing' {
            Send-Test (New-TestMessage '/reset PC1' -FromId '999' -User 'nobody')
            $script:Sent.Count | Should -Be 0
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
        }
        It 'reset all is refused' {
            Send-Test (New-TestMessage '/reset all')
            $script:Sent[0].Text | Should -Match 'refused'
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 0 -Exactly -ParameterFilter { $Action -eq 'device.reset' }
        }
        It 'unknown host gives an error and no reset audit' {
            Send-Test (New-TestMessage '/reset nope')
            $script:Sent[0].Text | Should -Match 'Unknown host'
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 0 -Exactly -ParameterFilter { $Action -eq 'device.reset' }
        }
        It 'writes the device.reset audit row with actor, device id and hostname' {
            Send-Test (New-TestMessage '/reset PC2')
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter {
                $Action -eq 'device.reset' -and $Actor -eq 'telegram:42' -and $Target -eq '22222222-2222-2222-2222-222222222222' -and $Meta.hostname -eq 'PC2'
            }
        }
        It 'calls Clear-ScgDeviceToken once with the right device id' {
            Send-Test (New-TestMessage '/reset PC3')
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $DeviceId -eq '33333333-3333-3333-3333-333333333333' -and $Path -eq 'test.db' }
        }
        It 'a failed clear writes no audit row' {
            Mock Clear-ScgDeviceToken -ModuleName Telegram { $false }
            Send-Test (New-TestMessage '/reset PC1')
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 0 -Exactly -ParameterFilter { $Action -eq 'device.reset' }
        }
        It 'button flow: a:reset shows confirm and acts only on rst' {
            Send-Test (New-TestCallback 'a:reset:11111111')
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
            $btn = Get-TestButton $script:Sent[0].Markup
            $btn.Count | Should -Be 2
            $btn[0].callback_data | Should -Be 'rst:11111111'
            $btn[1].callback_data | Should -Be 'd:11111111'
            Send-Test (New-TestCallback 'rst:11111111')
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $DeviceId -eq '11111111-1111-1111-1111-111111111111' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'device.reset' }
        }
        It 'device menu carries the Reset token button and callbacks stay within 64 bytes' {
            $d = [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active' }
            (Get-TestButton (New-TgMenu -Name 'device' -Context @{ Device = $d; HasUnknown = $false })).callback_data | Should -Contain 'a:reset:11111111'
            foreach ($b in (Get-TestButton (New-TgMenu -Name 'reset-confirm' -Context @{ DeviceId8 = 'ffffffff' }))) {
                [Text.Encoding]::UTF8.GetByteCount($b.callback_data) | Should -BeLessOrEqual 64
            }
        }
        It 'non-admin reset callback is rejected' {
            Send-Test (New-TestCallback 'rst:11111111' -FromId '999' -User 'nobody')
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
        }
    }

    Context 'menus' {
        It 'main menu has the five buttons with grammar-valid data' {
            $btn = Get-TestButton (New-TgMenu -Name 'main')
            $btn.Count | Should -Be 5
            ($btn.callback_data) | Should -Be @('m:devs', 'm:fleet', 'm:events', 'm:audit', 'm:help')
        }
        It 'every generated callback_data is <= 64 bytes' {
            $devs = 1..25 | ForEach-Object { [pscustomobject]@{ id = ('{0:x8}-0000-0000-0000-000000000000' -f $_); hostname = ('H' * 60); status = 'active' } }
            $menus = @(
                (New-TgMenu -Name 'main'),
                (New-TgMenu -Name 'devices' -Context @{ Devices = $devs; Page = 1 }),
                (New-TgMenu -Name 'devices' -Context @{ Devices = $devs; Page = 3 }),
                (New-TgMenu -Name 'device' -Context @{ Device = $devs[0]; HasUnknown = $true }),
                (New-TgMenu -Name 'remove-list' -Context @{ DeviceId8 = '00000001'; UnknownId = @('bbbbbbbbbbbbbbbb', 'dddddddddddddddd') }),
                (New-TgMenu -Name 'remove-confirm' -Context @{ DeviceId8 = '00000001'; ScId = 'bbbbbbbbbbbbbbbb' }),
                (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' })
            )
            foreach ($m in $menus) {
                foreach ($b in (Get-TestButton $m)) {
                    [Text.Encoding]::UTF8.GetByteCount($b.callback_data) | Should -BeLessOrEqual 64
                }
            }
        }
        It 'device menu shows Remove unknown only when unknown agents exist' {
            $d = [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active' }
            (Get-TestButton (New-TgMenu -Name 'device' -Context @{ Device = $d; HasUnknown = $true })).callback_data | Should -Contain 'a:listrm:11111111'
            (Get-TestButton (New-TgMenu -Name 'device' -Context @{ Device = $d; HasUnknown = $false })).callback_data | Should -Not -Contain 'a:listrm:11111111'
        }
        It 'remove-confirm has CONFIRM and Cancel' {
            $btn = Get-TestButton (New-TgMenu -Name 'remove-confirm' -Context @{ DeviceId8 = '11111111'; ScId = 'bbbbbbbbbbbbbbbb' })
            $btn.Count | Should -Be 2
            $btn[0].callback_data | Should -Be 'rmc:11111111:bbbbbbbbbbbbbbbb'
            $btn[1].callback_data | Should -Be 'd:11111111'
        }
        It 'device row carries Status, Harden, Agents and Restore buttons' {
            $d = [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active' }
            $data = (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = @($d); Page = 1 })).callback_data
            $data | Should -Contain 'a:status:11111111'
            $data | Should -Contain 'a:harden:11111111'
            $data | Should -Contain 'a:agents:11111111'
            $data | Should -Contain 'a:restore:11111111'
        }
        It 'devices list shows online / stale / quarantined glyphs' {
            $mk = New-TgMenu -Name 'devices' -Context @{ Devices = @(
                    [pscustomobject]@{ id = '11111111-0'; hostname = 'A'; status = 'active' },
                    [pscustomobject]@{ id = '22222222-0'; hostname = 'B'; status = 'stale' },
                    [pscustomobject]@{ id = '33333333-0'; hostname = 'C'; status = 'quarantined' }); Page = 1 }
            $labels = @(Get-TestButton $mk | Where-Object { $_.callback_data -match '^d:' } | ForEach-Object { $_.text })
            $labels[0] | Should -Match ([regex]::Escape([char]::ConvertFromUtf32(0x1F7E2)))
            $labels[1] | Should -Match ([regex]::Escape([char]::ConvertFromUtf32(0x1F7E1)))
            $labels[2] | Should -Match ([regex]::Escape([char]::ConvertFromUtf32(0x1F534)))
        }
    }

    Context 'pagination (10 per page)' {
        BeforeAll {
            $script:Many = 1..25 | ForEach-Object { [pscustomobject]@{ id = ('{0:x8}-0000-0000-0000-000000000000' -f $_); hostname = "H$_"; status = 'active' } }
            function Get-DeviceButtonCount { param($Page, $Devices) @(Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = $Devices; Page = $Page }) | Where-Object { $_.callback_data -match '^d:' }).Count }
        }
        It 'page 1 and 2 hold 10 rows, page 3 holds 5' {
            Get-DeviceButtonCount 1 $script:Many | Should -Be 10
            Get-DeviceButtonCount 2 $script:Many | Should -Be 10
            Get-DeviceButtonCount 3 $script:Many | Should -Be 5
        }
        It 'out-of-range pages clamp' {
            Get-DeviceButtonCount 99 $script:Many | Should -Be 5
            Get-DeviceButtonCount 0 $script:Many | Should -Be 10
        }
        It 'exactly 10 devices fit on one page with no Next button' {
            $ten = @($script:Many | Select-Object -First 10)
            Get-DeviceButtonCount 1 $ten | Should -Be 10
            (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = $ten; Page = 1 })).callback_data | Should -Not -Contain 'pg:2'
        }
        It '11 devices need a second page' {
            $eleven = @($script:Many | Select-Object -First 11)
            Get-DeviceButtonCount 2 $eleven | Should -Be 1
            (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = $eleven; Page = 1 })).callback_data | Should -Contain 'pg:2'
        }
        It 'empty list still renders a pager and Back' {
            $data = (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = @(); Page = 1 })).callback_data
            $data | Should -Contain 'm:main'
        }
        It 'pg: callback edits the message in place' {
            Send-Test (New-TestCallback 'pg:1')
            $script:Sent[0].EditId | Should -Be 77
        }
    }

    Context 'HTML escaping' {
        It 'escapes ampersand and angle brackets' {
            $escaped = InModuleScope -ModuleName Telegram -ScriptBlock { ConvertTo-TgHtml -Text '<b>x</b> & y' }
            $escaped | Should -Be '&lt;b&gt;x&lt;/b&gt; &amp; y'
        }
        It 'escapes hostnames echoed in replies' {
            Send-Test (New-TestMessage '/harden <script>')
            $script:Sent[0].Text | Should -Not -Match '<script>'
            $script:Sent[0].Text | Should -Match '&lt;script&gt;'
        }
        It 'escapes result output in Send-TgResultNotice' {
            Send-TgResultNotice -Config $script:Cfg -Send $script:Sender -Command ([pscustomobject]@{ type = 'ping'; status = 'done'; hostname = 'PC<1>'; output = '<pong>'; duration_ms = 12 })
            $script:Sent[-1].Text | Should -Match '&lt;pong&gt;'
            $script:Sent[-1].Text | Should -Match 'PC&lt;1&gt;'
        }
    }

    Context 'Invoke-TgPollOnce' {
        It 'advances the offset past the last update' {
            Mock Get-TgUpdate -ModuleName Telegram {
                @(
                    [pscustomobject]@{ update_id = 100; message = [pscustomobject]@{ text = '/help'; from = [pscustomobject]@{ id = '42'; username = '' }; chat = [pscustomobject]@{ id = '-100123' } } },
                    [pscustomobject]@{ update_id = 101; message = [pscustomobject]@{ text = '/help'; from = [pscustomobject]@{ id = '42'; username = '' }; chat = [pscustomobject]@{ id = '-100123' } } }
                )
            }
            $state = @{ Offset = 0 }
            $n = Invoke-TgPollOnce -Config $script:Cfg -State $state -Send $script:Sender
            $n | Should -Be 2
            $state.Offset | Should -Be 102
            $script:Sent.Count | Should -Be 2
        }
    }
}

Describe 'Telegram hardening' {
    BeforeEach {
        InModuleScope Telegram { $script:TgClockSkewSec = 0; $script:TgLast409Utc = [datetime]::MinValue }
        Mock Write-ScgLog -ModuleName Telegram { }
        Mock Add-ScgAudit -ModuleName Telegram { }
    }
    AfterEach {
        InModuleScope Telegram { $script:TgClockSkewSec = 0; $script:TgLast409Utc = [datetime]::MinValue }
    }

    Context '409 Conflict logging' {
        BeforeEach {
            Mock Invoke-RestMethod -ModuleName Telegram { throw (New-Object System.Exception 'The remote server returned an error: (409) Conflict.') }
        }
        It 'logs a WARN on 409 and throttles to once per 5 minutes' {
            Get-TgUpdate -Token 'x' | Should -BeNullOrEmpty
            Get-TgUpdate -Token 'x' | Should -BeNullOrEmpty
            Should -Invoke Write-ScgLog -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Level -eq 'WARN' -and $Action -eq 'telegram.conflict' }
        }
        It 'logs again after the throttle window passes' {
            Get-TgUpdate -Token 'x' | Out-Null
            InModuleScope Telegram { $script:TgClockSkewSec = 301 }
            Get-TgUpdate -Token 'x' | Out-Null
            Should -Invoke Write-ScgLog -ModuleName Telegram -Times 2 -Exactly -ParameterFilter { $Action -eq 'telegram.conflict' }
        }
    }

    Context 'safe truncation' {
        It 'never cuts inside an entity and stays within 4000' {
            $r = InModuleScope Telegram { Limit-TgHtml -Text ('&amp;' * 3000) }
            $r.Length | Should -BeLessOrEqual 4000
            ($r -replace '&amp;', '') | Should -Not -Match '&'
        }
        It 'closes an open pre tag' {
            $r = InModuleScope Telegram { Limit-TgHtml -Text ('<b>h</b>' + "`n<pre>" + ('&lt;' * 2000) + '</pre>') }
            $r.Length | Should -BeLessOrEqual 4000
            $r | Should -Match '</pre>$'
            ([regex]::Matches($r, '<pre>')).Count | Should -Be ([regex]::Matches($r, '</pre>')).Count
        }
        It 'never cuts inside a tag and closes open b' {
            $r = InModuleScope Telegram { Limit-TgHtml -Text (('a' * 3958) + '<b>' + ('x' * 500) + '</b>') }
            $r.Length | Should -BeLessOrEqual 4000
            $r | Should -Not -Match '<[^>]*$'
            ([regex]::Matches($r, '<b>')).Count | Should -Be ([regex]::Matches($r, '</b>')).Count
        }
        It 'leaves short text untouched' {
            InModuleScope Telegram { Limit-TgHtml -Text '<b>hi</b>' } | Should -Be '<b>hi</b>'
        }
        It 'Send-TgResultNotice escapes first, then truncates safely' {
            $script:Sent = New-Object System.Collections.ArrayList
            $snd = { param($Text, $Markup, $ChatId, $EditMessageId) [void]$script:Sent.Add($Text) }
            $cfg = [pscustomobject]@{ telegram = [pscustomobject]@{ chat_id = '-100123' }; database = [pscustomobject]@{ path = '' } }
            Send-TgResultNotice -Config $cfg -Send $snd -Command ([pscustomobject]@{ type = 'ping'; status = 'done'; hostname = 'PC1'; output = ('<' * 3000) })
            $t = $script:Sent[-1]
            $t.Length | Should -BeLessOrEqual 4000
            $t | Should -Match '</pre>$'
            ($t -replace '&lt;', '' -replace '</?(b|pre)>', '') | Should -Not -Match '[<&](?!\.)'
        }
    }

    Context 'plain-text fallback' {
        It 'retries once without parse_mode when the HTML send returns null' {
            Mock Invoke-TgApi -ModuleName Telegram { $null }
            InModuleScope Telegram {
                $cfg = [pscustomobject]@{ telegram = [pscustomobject]@{ bot_token = 'x' } }
                Send-TgMessage -Config $cfg -Text '<b>a &lt; b</b>' -Markup $null -ChatId '1' -EditMessageId $null | Out-Null
            }
            Should -Invoke Invoke-TgApi -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Method -eq 'sendMessage' -and $Body.parse_mode -eq 'HTML' }
            Should -Invoke Invoke-TgApi -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Method -eq 'sendMessage' -and -not $Body.ContainsKey('parse_mode') -and $Body.text -eq 'a < b' }
        }
        It 'does not retry when the HTML send succeeds' {
            Mock Invoke-TgApi -ModuleName Telegram { [pscustomobject]@{ ok = $true } }
            InModuleScope Telegram {
                $cfg = [pscustomobject]@{ telegram = [pscustomobject]@{ bot_token = 'x' } }
                Send-TgMessage -Config $cfg -Text 'hi' -Markup $null -ChatId '1' -EditMessageId $null | Out-Null
            }
            Should -Invoke Invoke-TgApi -ModuleName Telegram -Times 1 -Exactly
        }
    }

    Context 'username-only admin warning' {
        It 'warns when authorised only by username' {
            Test-TgAdmin -From ([pscustomobject]@{ id = 9; username = 'opsadmin' }) -AdminUserId @('42') -AdminUsername @('opsadmin') | Should -BeTrue
            Should -Invoke Write-ScgLog -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Level -eq 'WARN' -and $Action -eq 'telegram.auth.username' }
        }
        It 'stays silent when the id matches' {
            Test-TgAdmin -From ([pscustomobject]@{ id = 42; username = 'opsadmin' }) -AdminUserId @('42') -AdminUsername @('opsadmin') | Should -BeTrue
            Should -Invoke Write-ScgLog -ModuleName Telegram -Times 0 -Exactly -ParameterFilter { $Action -eq 'telegram.auth.username' }
        }
    }
}
