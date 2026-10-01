# Telegram.Tests.ps1 - Pester 5 tests for src/modules/Telegram.psm1 (no network, DB functions mocked).
# Author: Badr (@Idlexaz)

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\src\modules\Telegram.psm1') -Force -DisableNameChecking

    # Fallback stubs so Mock can bind even if the parallel Database slice is not merged yet (no-op when the real functions exist).
    InModuleScope Telegram {
        if (-not (Get-Command Get-ScgFleetSummary -ErrorAction SilentlyContinue)) { function script:Get-ScgFleetSummary { param($Path, $StaleAfterMin, $Now) } }
        if (-not (Get-Command Get-ScgDeviceAgentSummary -ErrorAction SilentlyContinue)) { function script:Get-ScgDeviceAgentSummary { param($Path, $Now) } }
        if (-not (Get-Command Get-ScgRecentCommand -ErrorAction SilentlyContinue)) { function script:Get-ScgRecentCommand { param($Path, $DeviceId, $Last = 3) } }
        if (-not (Get-Command Get-ScgVersionDistribution -ErrorAction SilentlyContinue)) { function script:Get-ScgVersionDistribution { param($Path) } }
    }

    # Glyphs (built from code points: this file is pure ASCII on purpose).
    $script:IcOn = [char]::ConvertFromUtf32(0x1F7E2)
    $script:IcOff = [char]::ConvertFromUtf32(0x1F7E1)
    $script:IcQ = [char]::ConvertFromUtf32(0x1F534)
    $script:W = [string][char]0x26A0
    $script:S = ' ' + [char]0x00B7 + ' '
    $script:Ell = [string][char]0x2026
    $script:Dot = [string][char]0x2022
    $script:Shield = [char]::ConvertFromUtf32(0x1F6E1)
    $script:Gear = [string][char]0x2699
    $script:Bell = [char]::ConvertFromUtf32(0x1F514)
    $script:OkI = [string][char]0x2705
    $script:StopI = [string][char]0x26D4
    $script:Chk = [string][char]0x2714
    $script:Crs = [string][char]0x2716
    $script:Now0 = New-Object DateTime 2026, 10, 1, 12, 0, 0, ([DateTimeKind]::Utc)

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
        if ($null -eq $Markup) { return @() }
        @($Markup.inline_keyboard | ForEach-Object { $_ })
    }

    function Get-DeviceRowData {
        param($Markup)
        @(Get-TestButton $Markup | Where-Object { $_.callback_data -match '^d:' } | ForEach-Object { $_.callback_data })
    }

    function Get-DeviceRowText {
        param($Markup)
        @(Get-TestButton $Markup | Where-Object { $_.callback_data -match '^d:' } | ForEach-Object { $_.text })
    }

    function Assert-AllSentButtonsValid {
        foreach ($s in $script:Sent) {
            foreach ($b in (Get-TestButton $s.Markup)) {
                [Text.Encoding]::UTF8.GetByteCount([string]$b.callback_data) | Should -BeLessOrEqual 64
                ([string]$b.text).Length | Should -BeLessOrEqual 40
            }
            ([string]$s.Text).Length | Should -BeLessOrEqual 4000
        }
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
        Mock Get-ScgFleetSummary -ModuleName Telegram {
            [pscustomobject]@{ devices_total = 3; devices_online = 0; devices_offline = 2; devices_quarantined = 1; agents_total = 3; agents_mine = 1; agents_unknown = 1; devices_with_unknown = 1
                commands_pending = 0; commands_dispatched = 0; commands_failed_24h = 0; events_critical_24h = 0; events_warn_24h = 0 }
        }
        Mock Get-ScgDeviceAgentSummary -ModuleName Telegram { @() }
        Mock Get-ScgRecentCommand -ModuleName Telegram { @() }
        Mock Clear-ScgDeviceToken -ModuleName Telegram { $true }
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
            foreach ($c in @('/start', '/help', '/panel', '/devices', '/status all', '/agents PC1', '/harden all', '/restore PC1', '/remove PC1 bbbbbbbbbbbbbbbb', '/confirm 123456', '/events', '/audit', '/ping PC1', '/fleet', '/device PC1', '/status PC1', '/reset PC1')) {
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
            (Get-TestButton (New-TgMenu -Name 'device' -Context @{ Device = $d; UnknownCount = 0 })).callback_data | Should -Contain 'a:reset:11111111'
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
        It 'every generated callback_data is at most 64 bytes and every label at most 40 chars' {
            $devs = 1..25 | ForEach-Object { [pscustomobject]@{ id = ('{0:x8}-0000-0000-0000-000000000000' -f $_); hostname = ('H' * 60); status = 'active'; last_seen = '2026-10-01T11:59:00.000Z' } }
            $sum = @{}
            foreach ($d in $devs) { $sum[$d.id] = [pscustomobject]@{ device_id = $d.id; agents_unknown = 999; agents_stopped = 1; commands_failed_24h = 1 } }
            $menus = @(
                (New-TgMenu -Name 'main'),
                (New-TgMenu -Name 'devices' -Context @{ Devices = $devs; Page = 1 }),
                (New-TgMenu -Name 'devices' -Context @{ Devices = $devs; Page = 3; Filter = 's' }),
                (New-TgMenu -Name 'devices' -Context @{ Devices = $devs; Page = 2; Filter = 'x'; Summary = $sum; StaleMin = 5; Now = $script:Now0 }),
                (New-TgMenu -Name 'device' -Context @{ Device = $devs[0]; UnknownCount = 3 }),
                (New-TgMenu -Name 'fleet' -Context @{ Counts = @{ a = 500; o = 1; s = 2; q = 3; x = 999 } }),
                (New-TgMenu -Name 'confirm' -Context @{ Action = 'harden'; DeviceId8 = 'ffffffff' }),
                (New-TgMenu -Name 'confirm' -Context @{ Action = 'restore'; DeviceId8 = 'ffffffff' }),
                (New-TgMenu -Name 'confirm' -Context @{ Action = 'reset'; DeviceId8 = 'ffffffff' }),
                (New-TgMenu -Name 'confirm' -Context @{ Action = 'hall' }),
                (New-TgMenu -Name 'reset-confirm' -Context @{ DeviceId8 = 'ffffffff' }),
                (New-TgMenu -Name 'remove-list' -Context @{ DeviceId8 = '00000001'; UnknownId = @('bbbbbbbbbbbbbbbb', 'dddddddddddddddd') }),
                (New-TgMenu -Name 'remove-confirm' -Context @{ DeviceId8 = '00000001'; ScId = 'bbbbbbbbbbbbbbbb' }),
                (New-TgMenu -Name 'back' -Context @{ Callback = 'm:main' })
            )
            foreach ($m in $menus) {
                foreach ($b in (Get-TestButton $m)) {
                    [Text.Encoding]::UTF8.GetByteCount($b.callback_data) | Should -BeLessOrEqual 64
                    $b.text.Length | Should -BeLessOrEqual 40
                }
            }
        }
        It 'device menu shows Remove unknown with its count only when unknown agents exist' {
            $d = [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active' }
            $btn = Get-TestButton (New-TgMenu -Name 'device' -Context @{ Device = $d; UnknownCount = 2 })
            $btn.callback_data | Should -Contain 'a:listrm:11111111'
            ($btn | Where-Object { $_.callback_data -eq 'a:listrm:11111111' }).text | Should -Match 'Remove unknown \(2\)'
            (Get-TestButton (New-TgMenu -Name 'device' -Context @{ Device = $d; UnknownCount = 0 })).callback_data | Should -Not -Contain 'a:listrm:11111111'
        }
        It 'device card keyboard follows the contract order' {
            $d = [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active' }
            (Get-TestButton (New-TgMenu -Name 'device' -Context @{ Device = $d; UnknownCount = 1 })).callback_data | Should -Be @(
                'a:status:11111111', 'a:ping:11111111', 'a:agents:11111111', 'a:harden:11111111', 'a:restore:11111111',
                'a:listrm:11111111', 'a:reset:11111111', 'd:11111111', 'm:devs')
        }
        It 'confirm menus map to the executing callbacks and a cancel' {
            (Get-TestButton (New-TgMenu -Name 'confirm' -Context @{ Action = 'harden'; DeviceId8 = '11111111' })).callback_data | Should -Be @('ok:harden:11111111', 'd:11111111')
            (Get-TestButton (New-TgMenu -Name 'confirm' -Context @{ Action = 'restore'; DeviceId8 = '11111111' })).callback_data | Should -Be @('ok:restore:11111111', 'd:11111111')
            (Get-TestButton (New-TgMenu -Name 'confirm' -Context @{ Action = 'reset'; DeviceId8 = '11111111' })).callback_data | Should -Be @('rst:11111111', 'd:11111111')
            (Get-TestButton (New-TgMenu -Name 'confirm' -Context @{ Action = 'hall' })).callback_data | Should -Be @('fl:hallok', 'fl:r')
        }
        It 'remove-confirm has CONFIRM and Cancel' {
            $btn = Get-TestButton (New-TgMenu -Name 'remove-confirm' -Context @{ DeviceId8 = '11111111'; ScId = 'bbbbbbbbbbbbbbbb' })
            $btn.Count | Should -Be 2
            $btn[0].callback_data | Should -Be 'rmc:11111111:bbbbbbbbbbbbbbbb'
            $btn[1].callback_data | Should -Be 'd:11111111'
        }
        It 'device list has one d: button per device and no per-row action buttons' {
            $d = [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active' }
            $data = (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = @($d); Page = 1 })).callback_data
            @($data | Where-Object { $_ -eq 'd:11111111' }).Count | Should -Be 1
            @($data | Where-Object { $_ -match '^a:' }).Count | Should -Be 0
            $data | Should -Contain 'm:fleet'
            $data | Should -Contain 'm:main'
        }
        It 'devices list glyphs come from last_seen, not from the status column' {
            $mk = New-TgMenu -Name 'devices' -Context @{ Now = $script:Now0; StaleMin = 5; Page = 1; Devices = @(
                    [pscustomobject]@{ id = '11111111-0'; hostname = 'A'; status = 'stale'; last_seen = '2026-10-01T11:58:00.000Z' },
                    [pscustomobject]@{ id = '22222222-0'; hostname = 'B'; status = 'active'; last_seen = '2026-10-01T11:00:00.000Z' },
                    [pscustomobject]@{ id = '33333333-0'; hostname = 'C'; status = 'quarantined'; last_seen = '2026-10-01T11:59:00.000Z' }) }
            $btn = Get-TestButton $mk
            ($btn | Where-Object { $_.callback_data -eq 'd:11111111' }).text | Should -Be ('{0} A{1}2m ago' -f $script:IcOn, $script:S)
            ($btn | Where-Object { $_.callback_data -eq 'd:22222222' }).text | Should -Be ('{0} B{1}1h ago' -f $script:IcOff, $script:S)
            ($btn | Where-Object { $_.callback_data -eq 'd:33333333' }).text | Should -Be ('{0} C{1}1m ago' -f $script:IcQ, $script:S)
            Get-DeviceRowData $mk | Should -Be @('d:33333333', 'd:22222222', 'd:11111111')
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
            (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = $ten; Page = 1 })).callback_data | Should -Not -Contain 'dl:a:2'
        }
        It '11 devices need a second page' {
            $eleven = @($script:Many | Select-Object -First 11)
            Get-DeviceButtonCount 2 $eleven | Should -Be 1
            (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = $eleven; Page = 1 })).callback_data | Should -Contain 'dl:a:2'
        }
        It 'pager keeps the active filter' {
            $data = (Get-TestButton (New-TgMenu -Name 'devices' -Context @{ Devices = $script:Many; Page = 2; Filter = 's' })).callback_data
            $data | Should -Contain 'dl:s:1'
            $data | Should -Contain 'dl:s:3'
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

    Context 'Get-TgDeviceState and Format-TgAgo' {
        It 'formats relative times with an injected clock' {
            Format-TgAgo -IsoUtc '2026-10-01T11:59:48.000Z' -Now $script:Now0 | Should -Be '12s ago'
            Format-TgAgo -IsoUtc '2026-10-01T11:55:00.000Z' -Now $script:Now0 | Should -Be '5m ago'
            Format-TgAgo -IsoUtc '2026-10-01T09:00:00.000Z' -Now $script:Now0 | Should -Be '3h ago'
            Format-TgAgo -IsoUtc '2026-09-29T12:00:00.000Z' -Now $script:Now0 | Should -Be '2d ago'
            Format-TgAgo -IsoUtc '2026-10-01T12:00:30.000Z' -Now $script:Now0 | Should -Be '0s ago'
        }
        It 'returns never for empty or unparseable input' {
            Format-TgAgo -IsoUtc '' -Now $script:Now0 | Should -Be 'never'
            Format-TgAgo -IsoUtc $null -Now $script:Now0 | Should -Be 'never'
            Format-TgAgo -IsoUtc 'not-a-date' -Now $script:Now0 | Should -Be 'never'
        }
        It 'derives online/offline from last_seen and StaleMin, quarantined from status' {
            Get-TgDeviceState -Device ([pscustomobject]@{ status = 'quarantined'; last_seen = '2026-10-01T11:59:59.000Z' }) -StaleMin 5 -Now $script:Now0 | Should -Be 'quarantined'
            Get-TgDeviceState -Device ([pscustomobject]@{ status = 'stale'; last_seen = '2026-10-01T11:58:00.000Z' }) -StaleMin 5 -Now $script:Now0 | Should -Be 'online'
            Get-TgDeviceState -Device ([pscustomobject]@{ status = 'active'; last_seen = '2026-10-01T11:55:00.000Z' }) -StaleMin 5 -Now $script:Now0 | Should -Be 'online'
            Get-TgDeviceState -Device ([pscustomobject]@{ status = 'active'; last_seen = '2026-10-01T11:54:00.000Z' }) -StaleMin 5 -Now $script:Now0 | Should -Be 'offline'
            Get-TgDeviceState -Device ([pscustomobject]@{ status = 'active' }) -StaleMin 5 -Now $script:Now0 | Should -Be 'offline'
            Get-TgDeviceState -Device @{ status = 'active'; last_seen = '2026-10-01T11:59:00.000Z' } -StaleMin 5 -Now $script:Now0 | Should -Be 'online'
        }
    }

    Context 'rendered screens (seeded fleet, injected clock)' {
        BeforeEach {
            Mock Get-TgNow -ModuleName Telegram { New-Object DateTime 2026, 10, 1, 12, 0, 0, ([DateTimeKind]::Utc) }
            Mock Get-ScgDevice -ModuleName Telegram {
                @(
                    [pscustomobject]@{ id = 'a0000001-0000-0000-0000-000000000001'; hostname = 'PC-A'; status = 'active'; last_seen = '2026-10-01T11:59:48.000Z' },
                    [pscustomobject]@{ id = 'b0000002-0000-0000-0000-000000000002'; hostname = 'PC-B'; status = 'active'; last_seen = '2026-10-01T11:57:00.000Z'; os = 'Windows 10 Pro'; os_version = '22H2'; agent_version = '4.0.1'; last_ip = '1.2.3.4'; first_seen = '2026-09-29T12:00:00.000Z' },
                    [pscustomobject]@{ id = 'c0000003-0000-0000-0000-000000000003'; hostname = 'PC-C'; status = 'active'; last_seen = '2026-10-01T09:00:00.000Z' },
                    [pscustomobject]@{ id = 'd0000004-0000-0000-0000-000000000004'; hostname = 'PC-D'; status = 'quarantined'; last_seen = '2026-10-01T11:59:00.000Z' },
                    [pscustomobject]@{ id = 'e0000005-0000-0000-0000-000000000005'; hostname = 'pc-e'; status = 'stale'; last_seen = '2026-10-01T11:59:30.000Z' },
                    [pscustomobject]@{ id = 'f0000006-0000-0000-0000-000000000006'; hostname = 'PC-F'; status = 'active'; last_seen = '2026-09-29T11:00:00.000Z' },
                    [pscustomobject]@{ id = '70000007-0000-0000-0000-000000000007'; hostname = 'PC-G'; status = 'active'; last_seen = '' }
                )
            }
            Mock Get-ScgDeviceAgentSummary -ModuleName Telegram {
                @(
                    [pscustomobject]@{ device_id = 'a0000001-0000-0000-0000-000000000001'; agents_total = 1; agents_mine = 1; agents_unknown = 0; agents_stopped = 0; commands_failed_24h = 0 },
                    [pscustomobject]@{ device_id = 'b0000002-0000-0000-0000-000000000002'; agents_total = 2; agents_mine = 1; agents_unknown = 1; agents_stopped = 0; commands_failed_24h = 0 },
                    [pscustomobject]@{ device_id = 'e0000005-0000-0000-0000-000000000005'; agents_total = 1; agents_mine = 1; agents_unknown = 0; agents_stopped = 1; commands_failed_24h = 0 },
                    [pscustomobject]@{ device_id = 'f0000006-0000-0000-0000-000000000006'; agents_total = 0; agents_mine = 0; agents_unknown = 0; agents_stopped = 0; commands_failed_24h = 2 }
                )
            }
            Mock Get-ScgFleetSummary -ModuleName Telegram {
                [pscustomobject]@{ devices_total = 7; devices_online = 3; devices_offline = 3; devices_quarantined = 1; agents_total = 4; agents_mine = 3; agents_unknown = 1; devices_with_unknown = 1
                    commands_pending = 1; commands_dispatched = 0; commands_failed_24h = 2; events_critical_24h = 1; events_warn_24h = 3 }
            }
        }
        AfterEach { Assert-AllSentButtonsValid }

        It 'devices list: header counts, filter row, attention-first order, warn markers and relative times' {
            Send-Test (New-TestMessage '/devices')
            $m = $script:Sent[0]
            $m.Text | Should -Match 'filter: All'
            $m.Text | Should -Match 'page 1/1'
            $m.Text.Contains(('{0} 3 online{1}{2} 3 offline{1}{3} 1 quarantined{1}{4} 4 need attention' -f $script:IcOn, $script:S, $script:IcOff, $script:IcQ, $script:W)) | Should -BeTrue
            $kb = $m.Markup.inline_keyboard
            @($kb[0] | ForEach-Object { $_.text }) | Should -Be @(('{0} All 7' -f $script:Dot), ('{0} 3' -f $script:IcOn), ('{0} 3' -f $script:IcOff), ('{0} 4' -f $script:W))
            @($kb[0] | ForEach-Object { $_.callback_data }) | Should -Be @('dl:a:1', 'dl:o:1', 'dl:s:1', 'dl:x:1')
            Get-DeviceRowText $m.Markup | Should -Be @(
                ('{0} PC-B {1}1{2}3m ago' -f $script:IcOn, $script:W, $script:S),
                ('{0} PC-D{1}1m ago' -f $script:IcQ, $script:S),
                ('{0} pc-e{1}30s ago' -f $script:IcOn, $script:S),
                ('{0} PC-F{1}2d ago' -f $script:IcOff, $script:S),
                ('{0} PC-C{1}3h ago' -f $script:IcOff, $script:S),
                ('{0} PC-G{1}never' -f $script:IcOff, $script:S),
                ('{0} PC-A{1}12s ago' -f $script:IcOn, $script:S))
            Get-DeviceRowData $m.Markup | Should -Be @('d:b0000002', 'd:d0000004', 'd:e0000005', 'd:f0000006', 'd:c0000003', 'd:70000007', 'd:a0000001')
            @($kb[-2] | ForEach-Object { $_.callback_data }) | Should -Be @('dl:a:1')
            @($kb[-1] | ForEach-Object { $_.callback_data }) | Should -Be @('m:fleet', 'dl:a:1', 'm:main')
            Should -Invoke Get-ScgDeviceAgentSummary -ModuleName Telegram -Times 1 -Exactly
            Should -Invoke Get-ScgScAgent -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'filters x, o and s keep the sort order and mark the active filter' {
            Send-Test (New-TestCallback 'dl:x:1')
            $script:Sent[0].EditId | Should -Be 77
            $script:Sent[0].Text | Should -Match 'filter: Attention'
            Get-DeviceRowData $script:Sent[0].Markup | Should -Be @('d:b0000002', 'd:d0000004', 'd:e0000005', 'd:f0000006')
            $script:Sent[0].Markup.inline_keyboard[0][3].text | Should -Be ('{0} {1} 4' -f $script:Dot, $script:W)
            Send-Test (New-TestCallback 'dl:o:1')
            $script:Sent[0].Text | Should -Match 'filter: Online'
            Get-DeviceRowData $script:Sent[0].Markup | Should -Be @('d:b0000002', 'd:e0000005', 'd:a0000001')
            Send-Test (New-TestCallback 'dl:s:1')
            $script:Sent[0].Text | Should -Match 'filter: Offline'
            Get-DeviceRowData $script:Sent[0].Markup | Should -Be @('d:f0000006', 'd:c0000003', 'd:70000007')
        }
        It 'an unknown filter falls back to All and pages clamp' {
            Send-Test (New-TestCallback 'dl:z:9')
            $script:Sent[0].Text | Should -Match 'filter: All'
            $script:Sent[0].Text | Should -Match 'page 1/1'
            @(Get-DeviceRowData $script:Sent[0].Markup).Count | Should -Be 7
        }
        It 'pg: is an alias of dl:a:' {
            Send-Test (New-TestCallback 'pg:1')
            $a = $script:Sent[0]
            Send-Test (New-TestCallback 'dl:a:1')
            $b = $script:Sent[0]
            $a.Text | Should -Be $b.Text
            (Get-TestButton $a.Markup).callback_data | Should -Be (Get-TestButton $b.Markup).callback_data
            $a.EditId | Should -Be 77
        }
        It 'fleet card: counts, agents, commands, events and the ordered needs-attention list' {
            Send-Test (New-TestMessage '/fleet')
            $lines = @($script:Sent[0].Text -split "`n")
            $lines[0] | Should -Match 'Fleet'
            $lines[1] | Should -Be ('{0} 3 online{1}{2} 3 offline{1}{3} 1 quarantined (7 devices)' -f $script:IcOn, $script:S, $script:IcOff, $script:IcQ)
            $lines[2] | Should -Be ('{0} Agents: 3 mine{1}{2} 1 unknown (on 1 devices)' -f $script:Shield, $script:S, $script:W)
            $lines[3] | Should -Be ('{0} Commands: 1 pending{1}0 in flight{1}2 failed (24h)' -f $script:Gear, $script:S)
            $lines[4] | Should -Be ('{0} Events (24h, unacked): 1 critical{1}3 warn' -f $script:Bell, $script:S)
            $lines[5] | Should -Be ''
            $lines[6] | Should -Be 'Needs attention:'
            @($lines[7..12]) | Should -Be @(
                ('{0} PC-D{1}quarantined' -f $script:IcQ, $script:S),
                ('{0} PC-B{1}1 unknown agent' -f $script:W, $script:S),
                ('{0} pc-e{1}1 stopped agent' -f $script:W, $script:S),
                ('{0} PC-F{1}2 failed commands{1}offline 2d' -f $script:W, $script:S),
                ('{0} PC-C{1}offline 3h' -f $script:IcOff, $script:S),
                ('{0} PC-G{1}offline (never seen)' -f $script:IcOff, $script:S))
            $lines.Count | Should -Be 13
            $script:Sent[0].Text | Should -Not -Match 'PC-A'
            $btn = Get-TestButton $script:Sent[0].Markup
            $btn.callback_data | Should -Be @('dl:a:1', 'dl:x:1', 'dl:o:1', 'dl:s:1', 'fl:hall', 'fl:pall', 'fl:r', 'm:main')
            ($btn | Where-Object { $_.callback_data -eq 'dl:x:1' }).text | Should -Be ('{0} Attention (4)' -f $script:W)
            Should -Invoke Get-ScgScAgent -ModuleName Telegram -Times 0 -Exactly
        }
        It '/status all, m:fleet and fl:r render the same fleet card' {
            Send-Test (New-TestMessage '/fleet'); $ref = $script:Sent[0].Text
            Send-Test (New-TestMessage '/status all'); $script:Sent[0].Text | Should -Be $ref
            Send-Test (New-TestCallback 'm:fleet'); $script:Sent[0].Text | Should -Be $ref; $script:Sent[0].EditId | Should -Be 77
            Send-Test (New-TestCallback 'fl:r'); $script:Sent[0].Text | Should -Be $ref; $script:Sent[0].EditId | Should -Be 77
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'fleet card caps the needs-attention list at 8 and adds the remainder' {
            Mock Get-ScgDevice -ModuleName Telegram { 1..12 | ForEach-Object { [pscustomobject]@{ id = ('{0:x8}-0000-0000-0000-000000000000' -f $_); hostname = ('OFF{0:d2}' -f $_); status = 'active'; last_seen = '' } } }
            Mock Get-ScgDeviceAgentSummary -ModuleName Telegram { @() }
            Send-Test (New-TestMessage '/fleet')
            $t = $script:Sent[0].Text
            ([regex]::Matches($t, 'offline \(never seen\)')).Count | Should -Be 8
            $t | Should -Match '\(\+4 more\)'
            $t | Should -Match 'OFF08'
            $t | Should -Not -Match 'OFF09'
        }
        It 'device card: header, OS, IP, agents with short ids and the last 3 commands' {
            Mock Get-ScgScAgent -ModuleName Telegram {
                @(
                    [pscustomobject]@{ id = '5d09aaaaaaaa8a2b'; service_name = 'mine'; state = 'Running'; authorized = 1 },
                    [pscustomobject]@{ id = '9f3cbbbbbbbb11ee'; service_name = 'evil'; state = 'Running'; authorized = 0 },
                    [pscustomobject]@{ id = 'aaaaaaaaaaaaaaaa'; service_name = 'listed'; state = 'Stopped'; authorized = 0 }
                )
            }
            Mock Get-ScgRecentCommand -ModuleName Telegram {
                @(
                    [pscustomobject]@{ id = 'c1'; type = 'ping'; status = 'pending'; created_at = '2026-10-01T11:59:50.000Z'; finished_at = $null; result_json = $null },
                    [pscustomobject]@{ id = 'c2'; type = 'harden'; status = 'done'; created_at = '2026-10-01T11:54:00.000Z'; finished_at = '2026-10-01T11:55:00.000Z'; result_json = '{}' },
                    [pscustomobject]@{ id = 'c3'; type = 'remove'; status = 'failed'; created_at = '2026-10-01T10:59:00.000Z'; finished_at = '2026-10-01T11:00:00.000Z'; result_json = '{}' }
                )
            }
            Send-Test (New-TestMessage '/device pc-b')
            $lines = @($script:Sent[0].Text -split "`n")
            $lines | Should -Be @(
                ('{0} <b>PC-B</b>{1}online (3m ago)' -f $script:IcOn, $script:S),
                ('OS: Windows 10 Pro 22H2{0}agent 4.0.1' -f $script:S),
                ('IP: 1.2.3.4{0}enrolled 2d ago' -f $script:S),
                '',
                ('{0} Agents (3)' -f $script:Shield),
                ('{0} 5d09{1}8a2b mine{2}Running' -f $script:OkI, $script:Ell, $script:S),
                ('{0} 9f3c{1}11ee UNKNOWN{2}Running' -f $script:W, $script:Ell, $script:S),
                ('{0} aaaa{1}aaaa mine{2}Stopped' -f $script:StopI, $script:Ell, $script:S),
                '',
                ('{0} Recent commands' -f $script:Gear),
                ('{0} ping{1}10s ago{1}pending' -f $script:Gear, $script:S),
                ('{0} harden{1}5m ago' -f $script:Chk, $script:S),
                ('{0} remove{1}1h ago{1}failed' -f $script:Crs, $script:S))
            $btn = Get-TestButton $script:Sent[0].Markup
            $btn.callback_data | Should -Be @('a:status:b0000002', 'a:ping:b0000002', 'a:agents:b0000002', 'a:harden:b0000002', 'a:restore:b0000002', 'a:listrm:b0000002', 'a:reset:b0000002', 'd:b0000002', 'm:devs')
            ($btn | Where-Object { $_.callback_data -eq 'a:listrm:b0000002' }).text | Should -Match 'Remove unknown \(1\)'
            Should -Invoke Get-ScgRecentCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $DeviceId -eq 'b0000002-0000-0000-0000-000000000002' -and $Last -eq 3 }
            Should -Invoke Get-ScgScAgent -ModuleName Telegram -Times 1 -Exactly
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'device card hides Remove unknown when there is none, and d: refresh edits in place' {
            Mock Get-ScgScAgent -ModuleName Telegram { @([pscustomobject]@{ id = '5d09aaaaaaaa8a2b'; state = 'Running'; authorized = 1 }) }
            Send-Test (New-TestCallback 'd:a0000001')
            $script:Sent[0].EditId | Should -Be 77
            $script:Sent[0].Text | Should -Match 'Recent commands'
            (Get-TestButton $script:Sent[0].Markup).callback_data | Should -Not -Contain 'a:listrm:a0000001'
            (Get-TestButton $script:Sent[0].Markup).callback_data | Should -Contain 'd:a0000001'
        }
        It '/device without a host prints usage and an unknown host is reported' {
            Send-Test (New-TestMessage '/device')
            $script:Sent[0].Text | Should -Match 'usage: /device'
            Send-Test (New-TestMessage '/device nope')
            $script:Sent[0].Text | Should -Match 'Unknown host'
        }
        It 'escapes hostnames in the fleet card and the device card' {
            Mock Get-ScgDevice -ModuleName Telegram { @([pscustomobject]@{ id = 'abcdef01-0000-0000-0000-000000000000'; hostname = 'PC<x>&'; status = 'quarantined'; last_seen = '2026-10-01T11:59:00.000Z'; os = '<os>' }) }
            Send-Test (New-TestMessage '/fleet')
            $script:Sent[0].Text | Should -Match 'PC&lt;x&gt;&amp;'
            $script:Sent[0].Text | Should -Not -Match 'PC<x>'
            Send-Test (New-TestCallback 'd:abcdef01')
            $script:Sent[0].Text | Should -Match 'PC&lt;x&gt;&amp;'
            $script:Sent[0].Text | Should -Match '&lt;os&gt;'
            $script:Sent[0].Text | Should -Not -Match '<x>|<os>'
        }
    }

    Context 'scale: 500 devices' {
        BeforeEach {
            Mock Get-TgNow -ModuleName Telegram { New-Object DateTime 2026, 10, 1, 12, 0, 0, ([DateTimeKind]::Utc) }
            Mock Get-ScgDevice -ModuleName Telegram { 1..500 | ForEach-Object { [pscustomobject]@{ id = ('{0:x8}-0000-0000-0000-000000000000' -f $_); hostname = ('HOST-{0:d3}-{1}' -f $_, ('x' * 50)); status = 'active'; last_seen = '2026-10-01T11:59:00.000Z' } } }
            Mock Get-ScgDeviceAgentSummary -ModuleName Telegram { 1..500 | ForEach-Object { [pscustomobject]@{ device_id = ('{0:x8}-0000-0000-0000-000000000000' -f $_); agents_total = 2; agents_mine = 1; agents_unknown = 1; agents_stopped = 0; commands_failed_24h = 0 } } }
        }
        AfterEach { Assert-AllSentButtonsValid }
        It 'devices list shows 10 rows, 50 pages, short labels, one summary query and no per-device agent query' {
            Send-Test (New-TestMessage '/devices 3')
            $m = $script:Sent[0]
            $m.Text.Length | Should -BeLessOrEqual 4000
            $m.Text | Should -Match 'page 3/50'
            @(Get-DeviceRowData $m.Markup).Count | Should -Be 10
            (Get-DeviceRowText $m.Markup)[0] | Should -Match ([regex]::Escape($script:Ell))
            (Get-TestButton $m.Markup).callback_data | Should -Contain 'dl:a:4'
            Should -Invoke Get-ScgDeviceAgentSummary -ModuleName Telegram -Times 1 -Exactly
            Should -Invoke Get-ScgScAgent -ModuleName Telegram -Times 0 -Exactly
        }
        It 'fleet card stays within 4000 chars with 8 attention lines and the remainder' {
            Send-Test (New-TestMessage '/fleet')
            $t = $script:Sent[0].Text
            $t.Length | Should -BeLessOrEqual 4000
            ([regex]::Matches($t, '1 unknown agent')).Count | Should -Be 8
            $t | Should -Match '\(\+492 more\)'
            Should -Invoke Get-ScgDeviceAgentSummary -ModuleName Telegram -Times 1 -Exactly
            Should -Invoke Get-ScgScAgent -ModuleName Telegram -Times 0 -Exactly
        }
    }

    Context 'callback routes' {
        AfterEach { Assert-AllSentButtonsValid }

        It 'navigation routes edit in place and issue nothing' {
            foreach ($d in @('m:main', 'm:devs', 'm:fleet', 'm:events', 'm:audit', 'm:help', 'd:11111111', 'dl:a:1', 'dl:o:1', 'dl:s:1', 'dl:x:1', 'pg:1', 'fl:r', 'a:listrm:11111111')) {
                Send-Test (New-TestCallback $d)
                $script:Sent.Count | Should -Be 1 -Because $d
                $script:Sent[0].EditId | Should -Be 77 -Because $d
                $script:Sent[0].Text | Should -Not -Match 'Internal error' -Because $d
                Assert-AllSentButtonsValid
            }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
        }
        It 'a:harden, a:restore, a:reset and fl:hall only show a confirm prompt' {
            Send-Test (New-TestCallback 'a:harden:11111111')
            $script:Sent[0].Text | Should -Match 'Apply protection \(service recovery, folder ACL, service SD, registry ACL\) to allow-listed agents on <b>PC1</b>\?'
            (Get-TestButton $script:Sent[0].Markup).callback_data | Should -Be @('ok:harden:11111111', 'd:11111111')
            Send-Test (New-TestCallback 'a:restore:11111111')
            $script:Sent[0].Text | Should -Match 'Remove SCGuardian protection from <b>PC1</b> \(restores backed-up ACLs/SD\)\?'
            (Get-TestButton $script:Sent[0].Markup).callback_data | Should -Be @('ok:restore:11111111', 'd:11111111')
            Send-Test (New-TestCallback 'a:reset:11111111')
            (Get-TestButton $script:Sent[0].Markup).callback_data | Should -Be @('rst:11111111', 'd:11111111')
            Send-Test (New-TestCallback 'fl:hall')
            $script:Sent[0].Text | Should -Match 'Harden ALL <b>3</b> devices\?'
            (Get-TestButton $script:Sent[0].Markup).callback_data | Should -Be @('fl:hallok', 'fl:r')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 0 -Exactly
        }
        It 'ok:harden and ok:restore execute once and audit command.issue' {
            Send-Test (New-TestCallback 'ok:harden:11111111')
            $script:Sent[0].Text | Should -Match 'Queued <b>harden</b> on <b>PC1</b>'
            $script:Sent[0].EditId | Should -Be 77
            Send-Test (New-TestCallback 'ok:restore:22222222')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'harden' -and $DeviceId -like '1111*' -and $IssuedVia -eq 'telegram' -and $IssuedBy -eq 'telegram:42' }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'restore' -and $DeviceId -like '2222*' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'command.issue' -and $Target -eq 'PC1' -and $Meta.type -eq 'harden' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'command.issue' -and $Target -eq 'PC2' -and $Meta.type -eq 'restore' }
        }
        It 'a:ping, a:status and a:agents queue their command immediately' {
            Send-Test (New-TestCallback 'a:ping:11111111')
            $script:Sent[0].Text | Should -Match 'Queued <b>ping</b> on <b>PC1</b>'
            Send-Test (New-TestCallback 'a:status:11111111')
            Send-Test (New-TestCallback 'a:agents:11111111')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'ping' }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'status' }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'agents' }
        }
        It 'fl:hallok hardens every device and fl:pall pings every device' {
            Send-Test (New-TestCallback 'fl:hallok')
            $script:Sent[0].Text | Should -Match 'on 3 device'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 3 -Exactly -ParameterFilter { $Type -eq 'harden' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 3 -Exactly -ParameterFilter { $Action -eq 'command.issue' }
            Send-Test (New-TestCallback 'fl:pall')
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 3 -Exactly -ParameterFilter { $Type -eq 'ping' }
        }
        It 'rst executes the reset and audits device.reset' {
            Send-Test (New-TestCallback 'rst:22222222')
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $DeviceId -eq '22222222-2222-2222-2222-222222222222' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'device.reset' }
        }
        It 'unknown ok: action and unknown device do nothing harmful' {
            Send-Test (New-TestCallback 'ok:remove:11111111')
            $script:Sent.Count | Should -Be 0
            Send-Test (New-TestCallback 'ok:harden:99999999')
            $script:Sent[0].Text | Should -Match 'Device not found'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'non-admin gets Unauthorized on every executing route and nothing runs (router)' {
            $routes = @('a:status:11111111', 'a:agents:11111111', 'a:ping:11111111', 'ok:harden:11111111', 'ok:restore:11111111', 'rst:11111111', 'rm:11111111:bbbbbbbbbbbbbbbb', 'rmc:11111111:bbbbbbbbbbbbbbbb', 'fl:hallok', 'fl:pall')
            foreach ($d in $routes) {
                Send-Test (New-TestCallback $d -FromId '999' -User 'nobody')
                $script:Sent.Count | Should -Be 0 -Because $d
            }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Invoke-TgApi -ModuleName Telegram -Times $routes.Count -Exactly -ParameterFilter { $Method -eq 'answerCallbackQuery' -and $Body.text -eq 'Unauthorized' }
            InModuleScope Telegram { $script:TgPending.Count } | Should -Be 0
        }
        It 'executing routes re-check admin inside Invoke-TgCallback itself' {
            $routes = @('a:status:11111111', 'a:agents:11111111', 'a:ping:11111111', 'ok:harden:11111111', 'ok:restore:11111111', 'rst:11111111', 'rm:11111111:bbbbbbbbbbbbbbbb', 'rmc:11111111:bbbbbbbbbbbbbbbb', 'fl:hallok', 'fl:pall')
            foreach ($d in $routes) {
                InModuleScope Telegram -Parameters @{ Data = $d; Snd = $script:Sender } {
                    param($Data, $Snd)
                    $ctx = @{
                        Config = $null; Send = $Snd; Path = 'test.db'; ChatId = '-100123'; AdminId = '999'; Actor = 'telegram:999'
                        AllowedIds = @('aaaaaaaaaaaaaaaa'); ConfirmSec = 120; StaleMin = 5; Token = ''; AdminIds = @('42', '43'); AdminNames = @('opsadmin')
                    }
                    $cb = [pscustomobject]@{ id = 'cbq9'; data = $Data; from = [pscustomobject]@{ id = '999'; username = 'nobody' }; message = [pscustomobject]@{ message_id = 77; chat = [pscustomobject]@{ id = '-100123' } } }
                    Invoke-TgCallback -Ctx $ctx -Callback $cb
                }
            }
            $script:Sent.Count | Should -Be 0
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Clear-ScgDeviceToken -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Invoke-TgApi -ModuleName Telegram -Times $routes.Count -Exactly -ParameterFilter { $Method -eq 'answerCallbackQuery' -and $Body.text -eq 'Unauthorized' -and $Body.show_alert -eq $true }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times $routes.Count -Exactly -ParameterFilter { $Action -eq 'auth.reject' -and $Actor -eq 'telegram:999' }
            InModuleScope Telegram { $script:TgPending.Count } | Should -Be 0
        }
        It 'the inner re-check lets an admin through' {
            InModuleScope Telegram -Parameters @{ Snd = $script:Sender } {
                param($Snd)
                $ctx = @{
                    Config = $null; Send = $Snd; Path = 'test.db'; ChatId = '-100123'; AdminId = '42'; Actor = 'telegram:42'
                    AllowedIds = @('aaaaaaaaaaaaaaaa'); ConfirmSec = 120; StaleMin = 5; Token = ''; AdminIds = @('42'); AdminNames = @()
                }
                $cb = [pscustomobject]@{ id = 'cbq9'; data = 'a:ping:11111111'; from = [pscustomobject]@{ id = '42'; username = '' }; message = [pscustomobject]@{ message_id = 77; chat = [pscustomobject]@{ id = '-100123' } } }
                Invoke-TgCallback -Ctx $ctx -Callback $cb
            }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'ping' }
        }
        It 'help lists the new typed commands' {
            Send-Test (New-TestMessage '/help')
            $script:Sent[0].Text | Should -Match '/fleet'
            $script:Sent[0].Text | Should -Match '/device &lt;host&gt;'
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

    Context 'self-update: /update and /versions' {
        BeforeAll {
            $script:Sha = 'ab' * 32
            $script:Url = 'https://github.com/cBadr/SCGuardian/releases/download/v4.0.2/SCGuardian.Agent.Setup.exe'
            function Get-UpdateOkData { @(Get-TestButton $script:Sent[0].Markup)[0].callback_data }
            function Get-UpdateNoData { @(Get-TestButton $script:Sent[0].Markup)[1].callback_data }
        }
        BeforeEach {
            InModuleScope Telegram { $script:TgPendingUpdate.Clear() }
            Mock Get-ScgDevice -ModuleName Telegram {
                @(
                    [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; hostname = 'PC1'; status = 'active'; agent_version = '4.0.1' },
                    [pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222'; hostname = 'PC2'; status = 'stale'; agent_version = '4.0.2' },
                    [pscustomobject]@{ id = '33333333-3333-3333-3333-333333333333'; hostname = 'PC3'; status = 'quarantined'; agent_version = '4.0.1' }
                )
            }
            Mock Get-ScgVersionDistribution -ModuleName Telegram { @() }
        }
        AfterEach { Assert-AllSentButtonsValid }

        It 'single host: queues one update with the full payload and audits command.issue' {
            Send-Test (New-TestMessage "/update PC1 4.0.2 $($script:Url) $($script:Sha)")
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter {
                $Type -eq 'update' -and $DeviceId -like '1111*' -and $IssuedVia -eq 'telegram' -and $IssuedBy -eq 'telegram:42' -and
                $Payload.version -eq '4.0.2' -and $Payload.setup_url -like 'https://github.com/*Setup.exe' -and $Payload.sha256 -eq ('ab' * 32)
            }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'command.issue' -and $Target -eq 'PC1' -and $Meta.type -eq 'update' -and $Meta.command_id -eq 'cmd-1' }
            $script:Sent.Count | Should -Be 1
            $script:Sent[0].Text | Should -Match 'Queued <b>update</b> to <b>4\.0\.2</b> on <b>PC1</b>'
            $script:Sent[0].Markup | Should -BeNullOrEmpty
        }
        It 'single host: uppercase sha256 is accepted and stored lowercase' {
            Send-Test (New-TestMessage "/update PC1 4.0.2 $($script:Url) $(('AB' * 32))")
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Payload.sha256 -ceq ('ab' * 32) }
        }
        It 'single host already on the version (case-insensitive) is not queued' {
            Send-Test (New-TestMessage "/update pc2 4.0.2 $($script:Url) $($script:Sha)")
            $script:Sent[0].Text | Should -Match '<b>PC2</b> is already on <b>4\.0\.2</b>'
            Mock Get-ScgDevice -ModuleName Telegram { @([pscustomobject]@{ id = '44444444-4444-4444-4444-444444444444'; hostname = 'PC4'; status = 'active'; agent_version = '4.0.2-RC1' }) }
            Send-Test (New-TestMessage "/update PC4 4.0.2-rc1 $($script:Url) $($script:Sha)")
            $script:Sent[0].Text | Should -Match 'is already on'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'unknown host gives a clear error and queues nothing' {
            Send-Test (New-TestMessage "/update nope 4.0.2 $($script:Url) $($script:Sha)")
            $script:Sent[0].Text | Should -Match 'Unknown host: <code>nope</code>'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'bad sha256 or url gets a clean escaped reply and New-ScgCommand is never called' {
            $cmds = @(
                "/update PC1 4.0.2 $($script:Url) 1234",
                "/update PC1 4.0.2 $($script:Url) $(('g' * 64))",
                "/update PC1 4.0.2 $($script:Url) $(('a' * 65))",
                "/update PC1 4.0.2 http://github.com/x/Setup.exe $($script:Sha)",
                "/update PC1 4.0.2 github.com/x/Setup.exe $($script:Sha)",
                "/update PC1 4.0.2 $($script:Url) <script>",
                "/update all 4.0.2 ftp://github.com/x $($script:Sha)",
                "/update all 4.0.2 $($script:Url) xyz 50"
            )
            foreach ($c in $cmds) {
                Send-Test (New-TestMessage $c)
                $script:Sent.Count | Should -Be 1 -Because $c
                $script:Sent[0].Text | Should -Match 'Update not queued' -Because $c
                $script:Sent[0].Text | Should -Not -Match '<script>' -Because $c
                $script:Sent[0].Text | Should -Not -Match 'Internal error' -Because $c
            }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            InModuleScope Telegram { $script:TgPendingUpdate.Count } | Should -Be 0
        }
        It 'an exception from New-ScgCommand becomes a clean escaped reply' {
            Mock New-ScgCommand -ModuleName Telegram { throw 'setup_url host not allowed: <evil.example>' }
            Send-Test (New-TestMessage "/update PC1 4.0.2 https://evil.example/x.exe $($script:Sha)")
            $script:Sent.Count | Should -Be 1
            $script:Sent[0].Text | Should -Match 'Update not queued for <b>PC1</b>: setup_url host not allowed: &lt;evil\.example&gt;'
            $script:Sent[0].Text | Should -Not -Match 'Internal error'
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'command.issue' -and $Meta.result -eq 'failed' }
        }
        It 'wrong argument counts and bad percent give usage and queue nothing' {
            foreach ($c in @('/update', '/update PC1 4.0.2', "/update PC1 4.0.2 $($script:Url) $($script:Sha) extra", "/update all 4.0.2 $($script:Url) $($script:Sha) 10 extra")) {
                Send-Test (New-TestMessage $c)
                $script:Sent[0].Text | Should -Match 'usage: /update' -Because $c
            }
            foreach ($p in @('0', '101', 'abc', '10.5', '-5')) {
                Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha) $p")
                $script:Sent[0].Text | Should -Match 'percent must be a whole number from 1 to 100' -Because $p
            }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            InModuleScope Telegram { $script:TgPendingUpdate.Count } | Should -Be 0
        }
        It 'percent math: ceiling of count times percent, at least 1, stable by sorted id' {
            InModuleScope Telegram {
                $ctx = @{ Path = 'test.db'; StaleMin = 5 }
                $d25 = @(25..1 | ForEach-Object { [pscustomobject]@{ id = ('{0:d2}-dev' -f $_); hostname = "H$_"; status = 'active' } })
                $d7 = @($d25 | Select-Object -First 7)
                $r = Select-TgUpdateTarget -Ctx $ctx -Percent 10 -Device $d25
                @($r.Selected).Count | Should -Be 3
                $r.Eligible | Should -Be 25
                @($r.Selected | ForEach-Object { $_.id }) | Should -Be @('01-dev', '02-dev', '03-dev')
                @((Select-TgUpdateTarget -Ctx $ctx -Percent 10 -Device $d7).Selected).Count | Should -Be 1
                @((Select-TgUpdateTarget -Ctx $ctx -Percent 1 -Device $d25).Selected).Count | Should -Be 1
                @((Select-TgUpdateTarget -Ctx $ctx -Percent 50 -Device $d25).Selected).Count | Should -Be 13
                @((Select-TgUpdateTarget -Ctx $ctx -Percent 100 -Device $d7).Selected).Count | Should -Be 7
                @((Select-TgUpdateTarget -Ctx $ctx -Percent 100 -Device @()).Selected).Count | Should -Be 0
                $mixed = @([pscustomobject]@{ id = 'a1'; status = 'active' }, [pscustomobject]@{ id = 'c3'; status = 'active' }, [pscustomobject]@{ id = 'B2'; status = 'active' })
                @((Select-TgUpdateTarget -Ctx $ctx -Percent 34 -Device $mixed).Selected | ForEach-Object { $_.id }) | Should -Be @('B2', 'a1')
            }
        }
        It 'quarantined devices are excluded from the all subset' {
            InModuleScope Telegram {
                $r = Select-TgUpdateTarget -Ctx @{ Path = 'test.db'; StaleMin = 5 } -Percent 100
                $r.Eligible | Should -Be 2
                @($r.Selected | ForEach-Object { $_.hostname }) | Should -Not -Contain 'PC3'
            }
            Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha)")
            $script:Sent[0].Text | Should -Match 'Update 2 of 2 devices \(100%\) to 4\.0\.2\? Already-current devices are skipped\.'
            $ids = InModuleScope Telegram { @(@($script:TgPendingUpdate.Values)[0].DeviceIds) }
            $ids | Should -Not -Contain '33333333-3333-3333-3333-333333333333'
        }
        It 'update all: nothing is queued until confirmed, cancel discards the pending spec' {
            Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha) 50")
            $script:Sent[0].Text | Should -Match 'Update 1 of 2 devices \(50%\) to 4\.0\.2\?'
            $ok = Get-UpdateOkData
            $no = Get-UpdateNoData
            $ok | Should -Match '^up:ok:[0-9a-f]{8}$'
            $no | Should -Match '^up:no:[0-9a-f]{8}$'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            Send-Test (New-TestCallback $no)
            $script:Sent[0].Text | Should -Match 'Update cancelled'
            $script:Sent[0].EditId | Should -Be 77
            InModuleScope Telegram { $script:TgPendingUpdate.Count } | Should -Be 0
            Send-Test (New-TestCallback $ok)
            $script:Sent[0].Text | Should -Match 'Nothing pending to confirm'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'update all: confirm fans out, skips already-current devices, reports counts, and is one-use' {
            Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha)")
            $ok = Get-UpdateOkData
            Send-Test (New-TestCallback $ok)
            $script:Sent[0].EditId | Should -Be 77
            $script:Sent[0].Text | Should -Match '1 queued'
            $script:Sent[0].Text | Should -Match '1 already current'
            $script:Sent[0].Text | Should -Match '0 failed'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Type -eq 'update' -and $DeviceId -like '1111*' -and $Payload.version -eq '4.0.2' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'command.issue' -and $Target -eq 'PC1' -and $Meta.type -eq 'update' }
            Should -Invoke Add-ScgAudit -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Action -eq 'command.issue' -and $Target -eq 'PC2' -and $Meta.result -eq 'already_current' }
            Send-Test (New-TestCallback $ok)
            $script:Sent[0].Text | Should -Match 'Nothing pending to confirm'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 1 -Exactly
        }
        It 'update all: a failing device is counted as failed, not as an internal error' {
            Mock New-ScgCommand -ModuleName Telegram { throw 'db busy <x>' }
            Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha)")
            Send-Test (New-TestCallback (Get-UpdateOkData))
            $script:Sent[0].Text | Should -Match '0 queued'
            $script:Sent[0].Text | Should -Match '1 failed'
            $script:Sent[0].Text | Should -Not -Match 'Internal error'
        }
        It 'update all: non-admin is blocked on the confirm callback (router and inner re-check)' {
            Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha)")
            $ok = Get-UpdateOkData
            $no = Get-UpdateNoData
            Send-Test (New-TestCallback $ok -FromId '999' -User 'nobody')
            $script:Sent.Count | Should -Be 0
            Send-Test (New-TestCallback $no -FromId '999' -User 'nobody')
            $script:Sent.Count | Should -Be 0
            foreach ($d in @($ok, $no)) {
                InModuleScope Telegram -Parameters @{ Data = $d; Snd = $script:Sender } {
                    param($Data, $Snd)
                    $ctx = @{
                        Config = $null; Send = $Snd; Path = 'test.db'; ChatId = '-100123'; AdminId = '999'; Actor = 'telegram:999'
                        AllowedIds = @('aaaaaaaaaaaaaaaa'); ConfirmSec = 120; StaleMin = 5; Token = ''; AdminIds = @('42', '43'); AdminNames = @('opsadmin')
                    }
                    $cb = [pscustomobject]@{ id = 'cbq9'; data = $Data; from = [pscustomobject]@{ id = '999'; username = 'nobody' }; message = [pscustomobject]@{ message_id = 77; chat = [pscustomobject]@{ id = '-100123' } } }
                    Invoke-TgCallback -Ctx $ctx -Callback $cb
                }
            }
            $script:Sent.Count | Should -Be 0
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Invoke-TgApi -ModuleName Telegram -Times 4 -Exactly -ParameterFilter { $Method -eq 'answerCallbackQuery' -and $Body.text -eq 'Unauthorized' }
            InModuleScope Telegram { $script:TgPendingUpdate.Count } | Should -Be 1
        }
        It 'update all: another admin cannot confirm a pending update they did not start' {
            Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha)")
            $ok = Get-UpdateOkData
            Send-Test (New-TestCallback $ok -FromId '43')
            $script:Sent[0].Text | Should -Match 'belongs to another admin'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            InModuleScope Telegram { $script:TgPendingUpdate.Count } | Should -Be 1
        }
        It 'update all: pending spec expires after the confirm window' {
            Send-Test (New-TestMessage "/update all 4.0.2 $($script:Url) $($script:Sha)")
            $ok = Get-UpdateOkData
            InModuleScope Telegram { $script:TgClockSkewSec = 500 }
            Send-Test (New-TestCallback $ok)
            $script:Sent[0].Text | Should -Match 'Nothing pending to confirm'
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It 'callback_data stays within 64 bytes with a long version and url' {
            $longVer = '4.0.2-' + ('x' * 300)
            $longUrl = 'https://github.com/cBadr/SCGuardian/releases/download/' + ('y' * 1500) + '/SCGuardian.Agent.Setup.exe'
            Send-Test (New-TestMessage "/update all $longVer $longUrl $($script:Sha) 10")
            $script:Sent.Count | Should -Be 1
            foreach ($b in (Get-TestButton $script:Sent[0].Markup)) {
                [Text.Encoding]::UTF8.GetByteCount([string]$b.callback_data) | Should -BeLessOrEqual 64
            }
            $stored = InModuleScope Telegram { @($script:TgPendingUpdate.Values)[0] }
            $stored.SetupUrl.Length | Should -Be $longUrl.Length
            $stored.Version | Should -Be $longVer
            InModuleScope Telegram {
                $m = New-TgMenu -Name 'confirm' -Context @{ Action = 'update-all'; Token = (New-TgToken) }
                foreach ($row in $m.inline_keyboard) { foreach ($b in $row) { [Text.Encoding]::UTF8.GetByteCount([string]$b.callback_data) | Should -BeLessOrEqual 64 } }
            }
        }
        It '/versions renders one line per group in the given order with relative time and escaping' {
            Mock Get-ScgVersionDistribution -ModuleName Telegram {
                $iso = { param($dt) $dt.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture) }
                @(
                    [pscustomobject]@{ agent_version = '4.0.2'; device_count = 12; newest_seen = (& $iso ([datetime]::UtcNow.AddMinutes(-5).AddSeconds(-10))) },
                    [pscustomobject]@{ agent_version = '4.0.1'; device_count = 1; newest_seen = (& $iso ([datetime]::UtcNow.AddDays(-2).AddMinutes(-1))) },
                    [pscustomobject]@{ agent_version = '<b>x'; device_count = 1; newest_seen = '' }
                )
            }
            Send-Test (New-TestMessage '/versions')
            $t = [string]$script:Sent[0].Text
            $t | Should -Match '4\.0\.2: 12 devices \(newest seen 5m ago\)'
            $t | Should -Match '4\.0\.1: 1 device \(newest seen 2d ago\)'
            $t | Should -Match '&lt;b&gt;x: 1 device \(newest seen never\)'
            $t | Should -Match '\(14 devices\)'
            $t.IndexOf('4.0.2:') | Should -BeLessThan $t.IndexOf('4.0.1:')
            Should -Invoke Get-ScgVersionDistribution -ModuleName Telegram -Times 1 -Exactly -ParameterFilter { $Path -eq 'test.db' }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
        }
        It '/versions on an empty fleet says no devices enrolled yet' {
            Send-Test (New-TestMessage '/versions')
            $script:Sent[0].Text | Should -Be 'No devices enrolled yet.'
        }
        It '/versions caps the list at 40 groups with a more tail' {
            Mock Get-ScgVersionDistribution -ModuleName Telegram { @(1..45 | ForEach-Object { [pscustomobject]@{ agent_version = "v$_"; device_count = 1; newest_seen = '' } }) }
            Send-Test (New-TestMessage '/versions')
            $t = [string]$script:Sent[0].Text
            $t | Should -Match 'v40: 1 device'
            $t | Should -Not -Match 'v41: '
            $t | Should -Match '\(\+5 more\)'
            $t.Length | Should -BeLessOrEqual 4000
        }
        It 'non-admin is blocked on /update and /versions' {
            foreach ($c in @("/update PC1 4.0.2 $($script:Url) $($script:Sha)", "/update all 4.0.2 $($script:Url) $($script:Sha)", '/versions')) {
                Send-Test (New-TestMessage $c -FromId '999' -User 'nobody')
                $script:Sent.Count | Should -Be 0 -Because $c
            }
            Should -Invoke New-ScgCommand -ModuleName Telegram -Times 0 -Exactly
            Should -Invoke Get-ScgVersionDistribution -ModuleName Telegram -Times 0 -Exactly
            InModuleScope Telegram { $script:TgPendingUpdate.Count } | Should -Be 0
        }
        It 'help lists the update commands with their exact syntax' {
            Send-Test (New-TestMessage '/help')
            $t = [string]$script:Sent[0].Text
            $t | Should -Match '/update &lt;host&gt; &lt;version&gt; &lt;setup_url&gt; &lt;sha256&gt;'
            $t | Should -Match '/update all &lt;version&gt; &lt;setup_url&gt; &lt;sha256&gt; \[percent\]'
            $t | Should -Match '/versions'
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
