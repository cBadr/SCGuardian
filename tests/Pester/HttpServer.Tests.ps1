#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Purpose: Pester 5 tests for HttpServer.psm1 | Author: Badr | Version: 4.0.0

BeforeAll {
    $modulesDir = Join-Path $PSScriptRoot '..\..\src\modules'
    Import-Module (Join-Path $modulesDir 'Common.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $modulesDir 'HttpServer.psm1') -Force -DisableNameChecking

    $script:Secret = 'test-secret-value-123'
    $script:Now = [datetime]::new(2026, 1, 1, 12, 0, 0, [System.DateTimeKind]::Utc)

    function ConvertTo-TestIso {
        param([datetime]$Value)
        $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    function New-TestHeader {
        param([string]$Bearer = $script:Secret, [datetime]$At = $script:Now, [string]$Nonce = ([guid]::NewGuid().ToString()))
        @{
            'Authorization'   = "Bearer $Bearer"
            'X-SCG-Timestamp' = (ConvertTo-TestIso -Value $At)
            'X-SCG-Nonce'     = $Nonce
        }
    }
}

Describe 'Test-ScgBearer' {
    It 'accepts the correct bearer' {
        Test-ScgBearer -Header "Bearer $script:Secret" -Secret $script:Secret | Should -BeTrue
    }
    It 'rejects a wrong bearer of equal length' {
        $wrong = 'x' * $script:Secret.Length
        Test-ScgBearer -Header "Bearer $wrong" -Secret $script:Secret | Should -BeFalse
    }
    It 'rejects a missing or empty header' {
        Test-ScgBearer -Header $null -Secret $script:Secret | Should -BeFalse
        Test-ScgBearer -Header '' -Secret $script:Secret | Should -BeFalse
    }
    It 'rejects length mismatches (prefix and extension)' {
        Test-ScgBearer -Header "Bearer $($script:Secret.Substring(1))" -Secret $script:Secret | Should -BeFalse
        Test-ScgBearer -Header "Bearer $($script:Secret)x" -Secret $script:Secret | Should -BeFalse
    }
    It 'rejects everything when the configured secret is empty' {
        Test-ScgBearer -Header 'Bearer ' -Secret '' | Should -BeFalse
    }
}

Describe 'Test-ScgReplay' {
    BeforeEach { $script:Cache = New-ScgReplayCache }

    It 'accepts a fresh timestamp and nonce' {
        $r = Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce ([guid]::NewGuid().ToString()) -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now
        $r.Ok | Should -BeTrue
    }
    It 'accepts 299s old and rejects 301s old with 408' {
        $ok = Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now.AddSeconds(-299)) -Nonce ([guid]::NewGuid().ToString()) -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now
        $ok.Ok | Should -BeTrue
        $old = Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now.AddSeconds(-301)) -Nonce ([guid]::NewGuid().ToString()) -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now
        $old.Ok | Should -BeFalse
        $old.Status | Should -Be 408
    }
    It 'rejects future skew beyond the window with 408' {
        $r = Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now.AddSeconds(301)) -Nonce ([guid]::NewGuid().ToString()) -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now
        $r.Status | Should -Be 408
        $okFuture = Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now.AddSeconds(299)) -Nonce ([guid]::NewGuid().ToString()) -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now
        $okFuture.Ok | Should -BeTrue
    }
    It 'rejects a reused nonce with 409' {
        $n = [guid]::NewGuid().ToString()
        $ts = ConvertTo-TestIso $script:Now
        (Test-ScgReplay -Cache $script:Cache -Timestamp $ts -Nonce $n -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now).Ok | Should -BeTrue
        $again = Test-ScgReplay -Cache $script:Cache -Timestamp $ts -Nonce $n -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now
        $again.Ok | Should -BeFalse
        $again.Status | Should -Be 409
    }
    It 'forgets a nonce after the TTL' {
        $n = [guid]::NewGuid().ToString()
        (Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce $n -MaxSkewSec 300 -NonceTtlSec 600 -Now $script:Now).Ok | Should -BeTrue
        $later = $script:Now.AddSeconds(601)
        $r = Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $later) -Nonce $n -MaxSkewSec 300 -NonceTtlSec 600 -Now $later
        $r.Ok | Should -BeTrue
    }
    It 'rejects malformed timestamp and nonce with 400' {
        (Test-ScgReplay -Cache $script:Cache -Timestamp 'yesterday' -Nonce ([guid]::NewGuid().ToString()) -Now $script:Now).Status | Should -Be 400
        (Test-ScgReplay -Cache $script:Cache -Timestamp '' -Nonce ([guid]::NewGuid().ToString()) -Now $script:Now).Status | Should -Be 400
        (Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce 'bad nonce!' -Now $script:Now).Status | Should -Be 400
        (Test-ScgReplay -Cache $script:Cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce '' -Now $script:Now).Status | Should -Be 400
    }
    It 'stays bounded in size and fails closed with 503 when full' {
        $cache = New-ScgReplayCache -MaxEntries 20
        $statuses = @(1..60 | ForEach-Object {
            (Test-ScgReplay -Cache $cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce ([guid]::NewGuid().ToString()) -Now $script:Now).Status
        })
        $cache.Nonces.Count | Should -BeLessOrEqual 20
        @($statuses | Where-Object { $_ -eq 200 }).Count | Should -Be 20
        $statuses[59] | Should -Be 503
    }
    It 'does not evict a live nonce when full' {
        $cache = New-ScgReplayCache -MaxEntries 10
        $first = 'aaaaaaaa-0000'
        [void](Test-ScgReplay -Cache $cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce $first -Now $script:Now)
        1..30 | ForEach-Object {
            [void](Test-ScgReplay -Cache $cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce ([guid]::NewGuid().ToString()) -Now $script:Now)
        }
        (Test-ScgReplay -Cache $cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce $first -Now $script:Now).Status | Should -Be 409
    }
    It 'sweeps expired nonces from the time-ordered queue' {
        $cache = New-ScgReplayCache -MaxEntries 10
        1..10 | ForEach-Object {
            [void](Test-ScgReplay -Cache $cache -Timestamp (ConvertTo-TestIso $script:Now) -Nonce ([guid]::NewGuid().ToString()) -Now $script:Now)
        }
        $later = $script:Now.AddSeconds(601)
        (Test-ScgReplay -Cache $cache -Timestamp (ConvertTo-TestIso $later) -Nonce ([guid]::NewGuid().ToString()) -Now $later).Ok | Should -BeTrue
        $cache.Nonces.Count | Should -Be 1
        $cache.Order.Count | Should -Be 1
    }
    It 'rejects NonceTtlSec below twice MaxSkewSec' {
        { New-ScgReplayCache -MaxSkewSec 300 -NonceTtlSec 500 } | Should -Throw '*NonceTtlSec*'
        { Start-ScgHttpServer -Url 'http://localhost:1/' -Secret 'x' -Route @{} -MaxSkewSec 300 -NonceTtlSec 100 } | Should -Throw '*NonceTtlSec*'
    }
}

Describe 'Resolve-ScgRoute' {
    BeforeAll {
        $script:RouteTable = @{
            'POST /heartbeat' = { param($Request) @{ Status = 200; Body = @{ ok = $true } } }
            'GET /health'     = { param($Request) @{ Status = 200; Body = @{ ok = $true } } }
        }
    }
    It 'returns the handler for a known route' {
        $r = Resolve-ScgRoute -Method 'POST' -Path '/api/v1/heartbeat' -Route $script:RouteTable
        $r.Handler | Should -Not -BeNullOrEmpty
    }
    It 'returns 404 for an unknown path' {
        (Resolve-ScgRoute -Method 'GET' -Path '/api/v1/nope' -Route $script:RouteTable).Status | Should -Be 404
    }
    It 'returns 405 for a wrong method' {
        (Resolve-ScgRoute -Method 'GET' -Path '/api/v1/heartbeat' -Route $script:RouteTable).Status | Should -Be 405
    }
}

Describe 'Invoke-ScgRequestPipeline' {
    BeforeEach {
        $script:Cache = New-ScgReplayCache
        $script:Probe = @{ Called = 0; Rejects = @() }
        $probe = $script:Probe
        $script:Routes = @{
            'POST /heartbeat' = { param($Request) $probe.Called++; @{ Status = 200; Body = @{ ok = $true; got = $Request.Body.device_id } } }.GetNewClosure()
            'GET /health'     = { param($Request) $probe.Called++; @{ Status = 200; Body = @{ ok = $true } } }.GetNewClosure()
            'POST /boom'      = { param($Request) throw 'SENSITIVE-DETAIL at C:\secret\stack.ps1:42' }
        }
        $script:OnReject = { param($Reason, $Ip) $probe.Rejects += $Reason }.GetNewClosure()
    }

    It 'runs the handler for a valid request and passes the parsed body' {
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -Body '{"device_id":"d1"}' -RemoteIp '10.0.0.1' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -OnReject $script:OnReject -Now $script:Now
        $r.Status | Should -Be 200
        $r.Body.got | Should -Be 'd1'
        $script:Probe.Called | Should -Be 1
    }
    It 'passes request headers to the handler as a case-insensitive table without Authorization' {
        $probe = $script:Probe
        $routes = @{ 'POST /heartbeat' = { param($Request) $probe.Req = $Request; @{ Status = 200; Body = @{ ok = $true } } }.GetNewClosure() }
        $h = New-TestHeader
        $h['x-scg-device-token'] = 'tok-123'
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $h -Body '{"device_id":"d1"}' -RemoteIp '10.0.0.7' -Secret $script:Secret -Route $routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 200
        $req = $script:Probe.Req
        $req.Method | Should -Be 'POST'
        $req.Path | Should -Not -BeNullOrEmpty
        $req.RemoteIp | Should -Be '10.0.0.7'
        $req.Body.device_id | Should -Be 'd1'
        $req.Headers | Should -BeOfType [hashtable]
        $req.Headers['X-SCG-Device-Token'] | Should -Be 'tok-123'
        $req.Headers['X-SCG-DEVICE-TOKEN'] | Should -Be 'tok-123'
        $req.Headers.ContainsKey('Authorization') | Should -BeFalse
    }
    It 'reads headers from a NameValueCollection' {
        $probe = $script:Probe
        $routes = @{ 'POST /heartbeat' = { param($Request) $probe.Req = $Request; @{ Status = 200; Body = @{ ok = $true } } }.GetNewClosure() }
        $nvc = New-Object System.Collections.Specialized.NameValueCollection
        foreach ($kv in (New-TestHeader).GetEnumerator()) { $nvc.Add([string]$kv.Key, [string]$kv.Value) }
        $nvc.Add('X-SCG-Device-Token', 'tok-nvc')
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $nvc -Body '{"device_id":"d1"}' -Secret $script:Secret -Route $routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 200
        $script:Probe.Req.Headers['x-scg-device-token'] | Should -Be 'tok-nvc'
    }
    It 'keeps the bearer, timestamp, nonce order even when a device token header is present' {
        $h = New-TestHeader -Bearer 'wrong'
        $h['X-SCG-Device-Token'] = 'tok'
        $r1 = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $h -Body '{"device_id":"d1"}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -OnReject $script:OnReject -Now $script:Now
        $r1.Status | Should -Be 401
        $h2 = New-TestHeader -At $script:Now.AddSeconds(-301)
        $h2['X-SCG-Device-Token'] = 'tok'
        $r2 = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $h2 -Body '{"device_id":"d1"}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -OnReject $script:OnReject -Now $script:Now
        $r2.Status | Should -Be 408
        $h3 = New-TestHeader
        $h3['X-SCG-Device-Token'] = 'tok'
        [void](Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $h3 -Body '{"device_id":"d1"}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now)
        $r3 = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $h3 -Body '{"device_id":"d1"}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -OnReject $script:OnReject -Now $script:Now
        $r3.Status | Should -Be 409
        $script:Probe.Called | Should -Be 1
        $script:Probe.Rejects | Should -Contain 'bad_bearer'
        $script:Probe.Rejects | Should -Contain 'stale_timestamp'
        $script:Probe.Rejects | Should -Contain 'replayed_nonce'
    }
    It 'never reaches the handler on a bad bearer' {
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader -Bearer 'wrong') -Body '{"device_id":"d1"}' -RemoteIp '10.0.0.1' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -OnReject $script:OnReject -Now $script:Now
        $r.Status | Should -Be 401
        $r.Body.ok | Should -BeFalse
        $script:Probe.Called | Should -Be 0
        $script:Probe.Rejects | Should -Contain 'bad_bearer'
        ($script:Probe.Rejects -join ' ') | Should -Not -Match $script:Secret
    }
    It 'checks bearer before consuming the nonce' {
        $n = [guid]::NewGuid().ToString()
        [void](Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/health' -Headers (New-TestHeader -Bearer 'wrong' -Nonce $n) -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now)
        $r = Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/health' -Headers (New-TestHeader -Nonce $n) -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 200
    }
    It 'rejects a replayed nonce with 409 before the handler' {
        $h = New-TestHeader
        [void](Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $h -Body '{"device_id":"d1"}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now)
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers $h -Body '{"device_id":"d1"}' -RemoteIp '10.0.0.1' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -OnReject $script:OnReject -Now $script:Now
        $r.Status | Should -Be 409
        $script:Probe.Called | Should -Be 1
        $script:Probe.Rejects | Should -Contain 'replayed_nonce'
    }
    It 'rejects a stale timestamp with 408 before the handler' {
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader -At $script:Now.AddSeconds(-301)) -Body '{"device_id":"d1"}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 408
        $script:Probe.Called | Should -Be 0
    }
    It 'returns 401 not 404 or 405 to unauthenticated callers' {
        (Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/nope' -Headers @{} -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now).Status | Should -Be 401
        (Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/heartbeat' -Headers @{} -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now).Status | Should -Be 401
        (Invoke-ScgRequestPipeline -Method GET -Path '/health' -Headers @{} -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now).Status | Should -Be 401
    }
    It 'returns 404 and 405 only after authentication' {
        (Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/nope' -Headers (New-TestHeader) -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now).Status | Should -Be 404
        (Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now).Status | Should -Be 405
        (Invoke-ScgRequestPipeline -Method GET -Path '/health' -Headers (New-TestHeader) -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now).Status | Should -Be 404
    }
    It 'does not read the body for unauthenticated or unrouted requests' {
        $state = @{ Reads = 0 }
        $provider = { $state.Reads++; @{ Text = '{"a":1}'; TooLarge = $false } }.GetNewClosure()
        [void](Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader -Bearer 'wrong') -BodyProvider $provider -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now)
        [void](Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/nope' -Headers (New-TestHeader) -BodyProvider $provider -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now)
        $state.Reads | Should -Be 0
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -BodyProvider { @{ Text = '{"device_id":"d9"}'; TooLarge = $false } } -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now
        $r.Body.got | Should -Be 'd9'
    }
    It 'maps an oversized body from the provider to 413' {
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -BodyProvider { @{ Text = ''; TooLarge = $true } } -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 413
    }
    It 'returns 503 when the replay cache is full' {
        $full = New-ScgReplayCache -MaxEntries 10
        1..10 | ForEach-Object { [void](Test-ScgReplay -Cache $full -Timestamp (ConvertTo-TestIso $script:Now) -Nonce ([guid]::NewGuid().ToString()) -Now $script:Now) }
        $r = Invoke-ScgRequestPipeline -Method GET -Path '/api/v1/health' -Headers (New-TestHeader) -Body '' -Secret $script:Secret -Route $script:Routes -ReplayCache $full -Now $script:Now
        $r.Status | Should -Be 503
        $script:Probe.Called | Should -Be 0
    }
    It 'returns 400 for a malformed JSON body' {
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -Body '{not json' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 400
        $script:Probe.Called | Should -Be 0
    }
    It 'returns 413 for a body over 1 MB' {
        $big = '{"device_id":"' + ('a' * 1100000) + '"}'
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/heartbeat' -Headers (New-TestHeader) -Body $big -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 413
        $script:Probe.Called | Should -Be 0
    }
    It 'maps a handler exception to a generic 500 without leaking details' {
        $r = Invoke-ScgRequestPipeline -Method POST -Path '/api/v1/boom' -Headers (New-TestHeader) -Body '{"a":1}' -Secret $script:Secret -Route $script:Routes -ReplayCache $script:Cache -Now $script:Now
        $r.Status | Should -Be 500
        $r.Body.error | Should -Be 'internal error'
        ($r.Body | ConvertTo-Json -Compress) | Should -Not -Match 'SENSITIVE|stack\.ps1'
    }
}

Describe 'Worker scriptblock re-creation' {
    It 'rebuilds a scriptblock from its text without closure state' {
        $captured = 'from-closure'
        $sb = { param($Request) 'static-value' }.GetNewClosure()
        $copy = ConvertTo-ScgWorkerScriptBlock -ScriptBlock $sb
        $copy | Should -Not -BeNullOrEmpty
        [object]::ReferenceEquals($copy, $sb) | Should -BeFalse
        (& $copy $null) | Should -Be 'static-value'
        ConvertTo-ScgWorkerScriptBlock -ScriptBlock $null | Should -BeNullOrEmpty
    }
    It 'rebuilds every route handler and OnReject in the config' {
        $cfg = @{ Route = @{ 'GET /a' = { 1 }; 'GET /b' = { 2 } }; OnReject = { 3 }; Secret = 's' }
        $out = ConvertTo-ScgWorkerConfig -Config $cfg
        $out.Route.Count | Should -Be 2
        (& $out.Route['GET /b']) | Should -Be 2
        (& $out.OnReject) | Should -Be 3
        [object]::ReferenceEquals($out.Route['GET /a'], $cfg.Route['GET /a']) | Should -BeFalse
    }
}

Describe 'HTTP listener loopback' {
    BeforeAll {
        $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $tcp.Start()
        $script:Port = ([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port
        $tcp.Stop()
        $script:Rejects = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $rejects = $script:Rejects
        $routes = @{
            'GET /health' = { param($Request) @{ Status = 200; Body = @{ ok = $true; version = '4.0.0' } } }
        }
        $onReject = { param($Reason, $Ip) [void]$rejects.Add($Reason) }.GetNewClosure()
        $script:Srv = Start-ScgHttpServer -Url "http://localhost:$($script:Port)/" -Secret $script:Secret -Route $routes -OnReject $onReject
    }
    AfterAll {
        Stop-ScgHttpServer
    }
    It 'serves /api/v1/health with valid auth' {
        $h = @{
            'Authorization'   = "Bearer $script:Secret"
            'X-SCG-Timestamp' = (Get-ScgUtcNow)
            'X-SCG-Nonce'     = ([guid]::NewGuid().ToString())
        }
        $r = Invoke-RestMethod -Uri "http://localhost:$($script:Port)/api/v1/health" -Headers $h -Method Get -TimeoutSec 15
        $r.ok | Should -BeTrue
        $r.version | Should -Be '4.0.0'
    }
    It 'answers 401 for a wrong bearer' {
        $h = @{
            'Authorization'   = 'Bearer nope'
            'X-SCG-Timestamp' = (Get-ScgUtcNow)
            'X-SCG-Nonce'     = ([guid]::NewGuid().ToString())
        }
        $code = 0
        try { Invoke-RestMethod -Uri "http://localhost:$($script:Port)/api/v1/health" -Headers $h -Method Get -TimeoutSec 15 | Out-Null }
        catch { $code = [int]$_.Exception.Response.StatusCode }
        $code | Should -Be 401
    }
    It 'answers 401 not 404 for an unknown route without auth' {
        $code = 0
        try { Invoke-RestMethod -Uri "http://localhost:$($script:Port)/api/v1/nope" -Method Get -TimeoutSec 15 | Out-Null }
        catch { $code = [int]$_.Exception.Response.StatusCode }
        $code | Should -Be 401
    }
}
