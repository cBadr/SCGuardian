# SCGuardian v4 - Hub API

Base URL: `https://ostazna.pro:8443/api/v1` (host and port come from your DNS name and `listen.url`).
JSON only (`application/json; charset=utf-8`). This page explains the contract in `docs/contracts/api-registry.md`
(frozen, contract v1.2); if the two ever disagree, the contract and the code win.

## 1. Endpoints

| Method | Path | Request body | Success response | Error statuses |
|---|---|---|---|---|
| POST | `/enroll` | `{hostname, os, os_version, agent_version}` | `{ok, device_id}` | 400, 401, 408, 409 |
| POST | `/heartbeat` | `{device_id, hostname, sc_agents:[{id,service,folder,uninstall_key,state}], uptime_sec, agent_version, discovery_ok?}` | `{ok, commands:[{id,type,payload}], config:{scan_interval_sec,heartbeat_sec,allowed_ids,alert_throttle_min}}` | 400, 401, 404, 408, 409 |
| POST | `/result` | `{device_id, command_id, ok, output, duration_ms}` | `{ok}` | 400, 401, 404, 408, 409 |
| POST | `/event` | `{device_id, type, severity, payload}` | `{ok}` (a deduplicated event still returns `ok`) | 400, 401, 404, 408, 409 |
| GET | `/health` | none | `{ok, version, uptime_sec, devices_online, commands_pending}` | 401, 408, 409 |

Every endpoint, including `/health`, requires the three auth headers below. 408/409/503 can be returned by any
endpoint, because the replay check runs for all authenticated requests.

## 2. Required headers

| Header | Value |
|---|---|
| `Authorization` | `Bearer <shared_secret>` |
| `X-SCG-Timestamp` | current UTC time, ISO 8601 with a trailing `Z`, for example `2026-10-01T09:30:00.123Z` (fraction of 1 to 7 digits is accepted, or none) |
| `X-SCG-Nonce` | a fresh unique string, 8 to 64 characters of `A-Za-z0-9-` (a GUID fits). Never reuse one. |

Placeholders below: `<SECRET>` is the value of `shared_secret`. Never paste a real secret into tickets or chat.

### 2.1 PowerShell: build the headers and call the API

```powershell
$HubUrl = 'https://ostazna.pro:8443'
$Secret = '<SECRET>'

function New-ScgHeader {
    @{
        Authorization     = "Bearer $Secret"
        'X-SCG-Timestamp' = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        'X-SCG-Nonce'     = [guid]::NewGuid().ToString()
    }
}

function Invoke-ScgApi {
    param([string]$Method, [string]$Path, $Body)
    $p = @{ Uri = "$HubUrl/api/v1$Path"; Method = $Method; Headers = (New-ScgHeader); UseBasicParsing = $true }
    if ($null -ne $Body) {
        $p.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 8 -Compress))
        $p.ContentType = 'application/json; charset=utf-8'
    }
    try { Invoke-RestMethod @p }
    catch {
        $r = $_.Exception.Response
        if ($r) { Write-Warning ("HTTP {0}" -f [int]$r.StatusCode) }
        throw
    }
}

# GET /health
Invoke-ScgApi -Method GET -Path '/health'

# POST /enroll
Invoke-ScgApi -Method POST -Path '/enroll' -Body @{
    hostname = 'PC-TEST-01'; os = 'windows'; os_version = '10.0.19045.0'; agent_version = '4.0.0'
}

# POST /heartbeat (empty sc_agents with discovery_ok = true means "this device has none")
Invoke-ScgApi -Method POST -Path '/heartbeat' -Body @{
    device_id = '<DEVICE_ID>'; hostname = 'PC-TEST-01'; sc_agents = @()
    discovery_ok = $true; uptime_sec = 120; agent_version = '4.0.0'
}
```

Notes: build a new header set for every call (new nonce, new timestamp). Sending `sc_agents = @()` from a
test script with `discovery_ok = $true` makes the hub delete all stored agents for that device; use a throw-away
device for experiments.

### 2.2 curl (Linux, macOS, Git Bash)

```bash
HUB=https://ostazna.pro:8443
SECRET='<SECRET>'
hdr() {
  printf -- '-H\0Authorization: Bearer %s\0-H\0X-SCG-Timestamp: %s\0-H\0X-SCG-Nonce: %s\0' \
    "$SECRET" "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$(cat /proc/sys/kernel/random/uuid)"
}
call() { # usage: call METHOD PATH [JSON]
  local m=$1 p=$2 b=$3 args=()
  while IFS= read -r -d '' a; do args+=("$a"); done < <(hdr)
  if [ -n "$b" ]; then
    curl -sS -X "$m" "$HUB/api/v1$p" "${args[@]}" -H 'Content-Type: application/json' --data "$b" -w '\nHTTP %{http_code}\n'
  else
    curl -sS -X "$m" "$HUB/api/v1$p" "${args[@]}" -w '\nHTTP %{http_code}\n'
  fi
}

call GET  /health
call POST /enroll '{"hostname":"PC-TEST-01","os":"windows","os_version":"10.0.19045.0","agent_version":"4.0.0"}'
call POST /heartbeat '{"device_id":"<DEVICE_ID>","hostname":"PC-TEST-01","sc_agents":[],"discovery_ok":true,"uptime_sec":120,"agent_version":"4.0.0"}'
call POST /result '{"device_id":"<DEVICE_ID>","command_id":"<COMMAND_ID>","ok":true,"output":"pong","duration_ms":12}'
call POST /event '{"device_id":"<DEVICE_ID>","type":"unknown_agent","severity":"warn","payload":{"sc_id":"0123456789abcdef","service":"ScreenConnect Client (0123456789abcdef)","folder":"C:\\Program Files (x86)\\ScreenConnect Client (0123456789abcdef)"}}'
```

On macOS use `uuidgen | tr A-Z a-z` instead of `/proc/sys/kernel/random/uuid`. For a self-signed hub certificate
add `-k` (testing only) or `--cacert hub-cert.pem` with the exported PEM.

## 3. Status codes

| Code | Meaning | Typical cause |
|---|---|---|
| 200 | ok | |
| 400 | bad request | malformed `X-SCG-Timestamp` or `X-SCG-Nonce`; empty or non-JSON body; missing/invalid field (`error` names it) |
| 401 | unauthorized | missing or wrong bearer (body: `{"ok":false,"error":"unauthorized"}`) |
| 404 | not found | unknown route, or `unknown device` for an unknown `device_id` |
| 405 | method not allowed | known path, wrong verb |
| 408 | stale timestamp | `X-SCG-Timestamp` more than `max_skew_sec` (default 300 s) from hub time, in either direction. Check the endpoint's clock. |
| 409 | conflict | replayed nonce; or `/enroll` for a hostname that is already enrolled and online; or `/result` for a command that was not dispatched to that device |
| 413 | body too large | request body over 1 MB (1,048,576 bytes) |
| 500 | internal error | generic body `{"ok":false,"error":"internal error"}`; the detail is only in the hub log (masked) |
| 503 | unavailable | nonce store at capacity (`replay cache full`, fail closed), or the hub is saturated (more than 32 requests in flight; empty body, `Retry-After: 1`). Retry later. |

Error body shape: `{"ok": false, "error": "<message>"}`.

## 4. Order of checks

The hub evaluates a request in this fixed order and stops at the first failure:

1. **Bearer** - constant-time comparison against `shared_secret`, read from the headers before any body is read.
   Failure: 401.
2. **Timestamp window and nonce** - format check (400), `|now - timestamp| <= max_skew_sec` (else 408), nonce not seen
   within `nonce_ttl_sec` (else 409), nonce store not full (else 503). An accepted nonce is recorded immediately, even if
   the request later fails on routing or body validation.
3. **Route** - 404 or 405.
4. **Body** - read up to 1 MB (413), must be valid non-empty JSON for POST (400).
5. **Handler** - field validation (400), existence checks (404), state checks (409).

Consequences: an unauthenticated caller can never tell which routes exist (always 401); a wrong-secret request
does not consume a nonce; every rejection at steps 1 to 4 is written to `audit_log` as `auth.reject` with a reason
code (`bad_bearer`, `bad_replay_headers`, `stale_timestamp`, `replayed_nonce`, `replay_cache_full`,
`route_not_found`, `method_not_allowed`, `body_too_large`, `bad_body`) and the caller IP. Neither the secret nor the
bearer value is ever stored.

## 5. Replay protection (summary)

- Timestamp window: `max_skew_sec`, default 300 s.
- Nonce memory: `nonce_ttl_sec`, default 600 s. The hub refuses to start if `nonce_ttl_sec < 2 * max_skew_sec`.
- The nonce store is in memory, case-insensitive, capped at 10,000 live entries (not configurable in v1). When full,
  new requests get 503 instead of evicting live nonces.
- A hub restart empties the store; the timestamp window still limits replay of a captured request to `max_skew_sec`.

Details and limits: `docs/SECURITY.md` section 5.

## 6. Semantics

### 6.1 `/enroll`

- All four fields are required, non-blank strings; `hostname` is at most 255 characters.
- The hub keys devices by hostname. A new hostname creates a device and returns a new `device_id`.
- If the hostname already exists **and the device is online** (`last_seen` within `stale_after_min`, default 5 min),
  the answer is **409 `hostname already enrolled and online`** and an `auth.reject` audit row (`enroll_conflict`) is
  written. This blocks a second machine, or an attacker holding the secret, from taking over a live identity.
- If the existing device is stale/offline, re-enroll succeeds and returns the **same** `device_id` (audited as `enroll`
  with `reenroll: true`).
- The agent stores `device_id` in `agent.config.json`. If a later heartbeat gets `404 unknown device`, the agent clears
  its `device_id` and enrolls again on its next cycle.

### 6.2 `/heartbeat`

- Required: `device_id`, `hostname`, `sc_agents` (an array; may be empty). Each entry needs `id` of exactly 16 hex
  characters (stored lowercase). Other fields are free text.
- The **stored** hostname is authoritative. If the reported hostname differs (case-insensitive) the hub keeps the stored one
  and writes one `heartbeat.config_change` audit row per distinct change.
- `discovery_ok` is optional, default `true`, and must be a boolean if present (else 400). The agent sends `false`
  when its discovery threw; the hub then never deletes `sc_agents` rows for that beat.
- Row deletion rule: rows missing from the reported list are deleted in the same transaction, **except** when the list is
  empty. An empty list deletes rows only if it was sent explicitly (`"sc_agents": []`) **and** `discovery_ok` is true.
- `commands` contains the commands flipped `pending -> dispatched` by this call. **A command is delivered once**: it is never
  returned by a later heartbeat. If the response is lost in transit, the command ends as `timeout`.
- `config` is authoritative: the agent adopts `heartbeat_sec`, `scan_interval_sec`, `alert_throttle_min` and
  `allowed_ids`. Values come from `defaults.*` in `hub.config.json`.

### 6.3 `/result`

- `ok` must be a JSON boolean; `output` is text (the agent truncates to 16,000 characters); `duration_ms` is a non-negative
  number.
- 404 if the device is unknown. 409 `command not dispatched to this device` if the command does not exist for that device
  or is not in a state that may move to `done`/`failed` (for example already finished or timed out).
- For `remove`, an output starting with `refused:` or `aborted:` is reported by the agent with `ok = false` (nothing was removed).
- On success the hub posts a result notice to the ops chat.

### 6.4 `/event`

- `type` is one of `unknown_agent`, `new_install`, `tamper`, `agent_error`, `service_down`; `severity` is `info`, `warn` or
  `critical`. Anything else is 400.
- `payload` is an arbitrary JSON object (default `{}`). Defined keys: `unknown_agent` `{sc_id, service, folder}`,
  `tamper` `{sc_id, detail}` (current agents send `{sc_id, service}`), `agent_error` `{detail}`,
  `service_down` `{sc_id, service}` (current agents also add `detail`).
- An identical event (same device, type and payload) that is still unacknowledged within `alert_throttle_min` is not stored again,
  and the call still returns `{"ok": true}`. Keep payloads free of timestamps so deduplication works.

### 6.5 Command payload

`commands.payload_json` is an object. The only defined key is `sc_id` (16 hex, lowercase):

| Command type | Payload |
|---|---|
| `remove` | `{"sc_id": "<16 hex>"}` mandatory |
| `harden`, `restore` | `{"sc_id": "<16 hex>"}` optional; absent means every allow-listed agent on the device |
| `status`, `agents`, `ping` | `{}` |

The key `id` is **not** part of the contract. Producers and consumers must use `sc_id`.

### 6.6 `/health`

Returns `version` (hub version string), `uptime_sec`, `devices_online` (seen within `stale_after_min`) and
`commands_pending` (status `pending`). It needs the same auth headers as every other call, so it is not usable as an
anonymous load-balancer probe.

## 7. Device and command lifecycle values

- `devices.status`: `active`, `stale` (set by the ticker after `stale_after_min`; a heartbeat or enroll reactivates it),
  `quarantined` (reserved; no code path sets it in v1).
- `commands.status`: `pending`, `dispatched`, `done`, `failed`, `timeout`.
- Commands that stay `dispatched` (age counted from `dispatched_at`) or `pending` (from `created_at`) longer than
  `command_timeout_sec` (default 300) become `timeout` on the next tick. A command queued for an offline device
  therefore expires after about five minutes.
