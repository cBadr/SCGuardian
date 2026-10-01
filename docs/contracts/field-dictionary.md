# SCGuardian v4 — Field Dictionary (FROZEN, contract v1)

Source of truth for every name used in code, DB, API and config.
**Do not invent a field.** If one is missing, request an addition here first.

## Conventions
- Timestamps: UTC ISO8601 with milliseconds and `Z` — `yyyy-MM-ddTHH:mm:ss.fffZ` (helper: `Get-ScgUtcNow`).
- DB columns / JSON wire fields: `snake_case`. PowerShell params: `PascalCase`.
- Agent instance ID: exactly 16 hex chars, stored lowercase, regex `^[0-9a-f]{16}$`.
- All paths rooted at `C:\ProgramData\SCGuardian\` (test-only override: env `SCG_ROOT`).
- Secrets masked as `***` by `Protect-Secret` before any log write.

## Enums
| Name | Values |
|---|---|
| device.status | `active` `stale` `quarantined` |
| command.type | `harden` `restore` `remove` `status` `agents` `ping` |
| command.status | `pending` `dispatched` `done` `failed` `timeout` |
| command transitions | pending→dispatched→(done\|failed\|timeout); pending→timeout. No other moves. |
| command.issued_via | `telegram` `system` |
| event.type | `unknown_agent` `new_install` `tamper` `agent_error` `service_down` |
| event.severity | `info` `warn` `critical` |
| audit.actor | `telegram:<id>` `system` `device:<hostname>` |
| audit.action | `command.issue` `command.dispatch` `command.result` `command.timeout` `enroll` `heartbeat.config_change` `event.ingest` `event.ack` `remove.request` `remove.confirm` `auth.reject` |
| agent.layer | `Recovery` `FolderAcl` `ServiceSd` `RegistryAcl` |

## SQLite schema
Exactly as in the project brief §2 (tables: `schema_version`, `devices`, `sc_agents`, `commands`, `events`, `audit_log`; indices as listed). Created only by `Database.psm1` migration `1`.
`PRAGMA foreign_keys=ON`, `journal_mode=WAL`, `busy_timeout=5000` on every connection.

**Contract amendment v1.1 (deviation from brief §2, review finding #1):** the 16-hex ScreenConnect id identifies the SC *server instance*, so it is identical on every machine joined to it. `sc_agents` therefore uses `PRIMARY KEY (device_id, id)` (not `id` alone). Every sc_agents lookup/update/delete MUST filter by both. Existing DBs: migration 2 rebuilds the table.

Idempotency rules (enforced in `Database.psm1`):
- `devices`: upsert by `hostname` (UNIQUE). Re-enroll returns the SAME `id`.
- `sc_agents`: upsert by `(device_id,id)`; rows for the device absent from a heartbeat are deleted in the same transaction — EXCEPT when the reported list is empty: then nothing is deleted unless `-AllowEmpty` is passed (discovery can fail silently). Hub passes `-AllowEmpty` only when the heartbeat carries an explicit `sc_agents: []` AND agent reports discovery_ok (see api-registry).
- `commands`: `New-ScgCommand` refuses a second `pending|dispatched` row with same `(device_id,type,payload_json)`; returns the existing id.
- `events`: `Add-ScgEvent` suppresses a row with same `(device_id,type,payload_json)` unacked within `alert_throttle_min`; returns `$null` when deduped.

## Hub config — `hub.config.json`
`listen.url` · `listen.cert_thumbprint` (`auto`|thumbprint) · `shared_secret` · `telegram.bot_token` · `telegram.chat_id` · `telegram.admin_user_ids[]` · `telegram.admin_usernames[]` · `database.path` · `defaults.allowed_ids[]` · `defaults.scan_interval_sec` · `defaults.heartbeat_sec` · `defaults.alert_throttle_min` · `defaults.command_confirm_sec` · `defaults.stale_after_min` · `logging.path` · `logging.max_bytes`

Additional (added to contract v1 for operability, all in DB-or-file settings, none in code):
`defaults.command_timeout_sec` (default 300) · `defaults.nonce_ttl_sec` (default 600) · `defaults.max_skew_sec` (default 300)

## Agent config — `agent.config.json`
`hub_url` · `shared_secret` · `device_id` · `hostname` (`AUTO`) · `heartbeat_sec` · `scan_interval_sec` · `allowed_ids[]` · `layers[]` · `take_ownership` · `local_watchdog` · `trusted_server_thumbprint` (optional) · `alert_throttle_min` (adopted from Hub; v1.1)

Heartbeat wire field (v1.1): `discovery_ok` (bool, default true).

Server-pushable (Hub → agent): `heartbeat_sec` `scan_interval_sec` `allowed_ids` `alert_throttle_min`. **Never** `shared_secret`, `hub_url`, `trusted_server_thumbprint`.

## Agent local state — `agent.state.json` (agent-only)
`consecutive_failures` · `next_heartbeat_utc` · `last_failure_log_utc` · `alerts{<key>:<utc>}`

## Per-device tokens (v2.0, FROZEN — supersedes the v1.1 "enroll online/stale" rule)
Goal: a stolen fleet-wide shared secret can no longer impersonate an existing device.
- DB: `devices.token_hash TEXT NULL` = lowercase hex SHA-256 of the raw token. Migration 3 (`ALTER TABLE devices ADD COLUMN token_hash TEXT`), schema_version → 3. The raw token is NEVER stored or logged.
- Token: 32 random bytes (RNGCryptoServiceProvider) → base64url without padding (43 chars). Generated only by the Hub, returned ONCE in the `/enroll` response as `device_token`.
- Header `X-SCG-Device-Token` is REQUIRED on `/heartbeat`, `/result`, `/event` (not on `/enroll`, `/health`). Verified against `token_hash` of the `device_id` in the body, constant-time. Wrong/missing → 401 `invalid device token`; device exists but `token_hash` is NULL → 401 `device not enrolled`; unknown device_id → 404 `unknown device` (unchanged). Each failure audits `auth.reject` (reason `bad_device_token` | `device_not_enrolled`), never the token.
- `/enroll`: new hostname → create device, issue token, store hash. Existing hostname with `token_hash` set → **409 always** (`hostname already enrolled`, audit `auth.reject` reason `enroll_conflict`). Existing hostname with `token_hash` NULL → same `device_id`, issue a NEW token (audit `enroll` meta `{reenroll:true}`).
- Admin reset: Telegram `/reset <host>` sets `token_hash` NULL (audit action `device.reset`). The agent then gets 401 `device not enrolled`, clears `device_id` and `device_token`, and re-enrolls on its next cycle.
- Agent config key `device_token` (written by the Agent after enroll into agent.config.json — folder ACL-locked; never server-pushable). Secrets masked in logs: shared_secret AND device_token.
- Common functions (exact names): `New-ScgDeviceToken` → string · `Get-ScgTokenHash -Token` → hex string · `Test-ScgDeviceToken -Token -Hash` → bool (constant-time, false on null/empty).
- Database functions (exact names): `Set-ScgDeviceToken -Path -DeviceId -TokenHash` · `Clear-ScgDeviceToken -Path -DeviceId` → bool · device rows expose `token_hash`.
- HttpServer: handlers receive `$Request.Headers` (case-insensitive hashtable, at least `X-SCG-Device-Token`) in addition to Method/Path/Body/RemoteIp. The shared-secret/replay pipeline order is unchanged; device-token checks happen inside the Hub handlers.
- New audit action: `device.reset`.

## Command payload (v1.2, FROZEN)
`commands.payload_json` is a JSON object. Only key defined: `sc_id` (16-hex, lowercase) — the ScreenConnect instance targeted by `remove` (mandatory), `harden` and `restore` (optional: absent = all allow-listed agents on the device). `status`/`agents`/`ping`: `{}`. Producers (Telegram) and consumers (Agent) MUST use `sc_id`; the key `id` is NOT part of the contract.
Agent result for `remove`: a result string starting `refused:` or `aborted:` means `ok=false` (nothing was removed).

## Event payload (v1.2)
`payload_json` keys: `unknown_agent` → `{sc_id, service, folder}` · `tamper` → `{sc_id, detail}` · `agent_error` → `{detail}` · `service_down` → `{sc_id, service}`. (Agent emits `sc_id` — aligned in v1.2.)

## Additional config keys (v1.2)
Hub `defaults.tick_sec` (30) · `defaults.telegram_error_pause_sec` (5) · `defaults.max_workers` (8) · `defaults.http_timeout_sec` (15). Agent `alert_throttle_min` default 15 (= Hub default).

## HTTP headers
`Authorization: Bearer <secret>` · `X-SCG-Timestamp` (UTC ISO8601) · `X-SCG-Nonce` (GUID)

## Telegram callback_data grammar (≤64 bytes)
`m:main|devs|fleet|events|audit|help` · `d:<device_id8>` · `a:<status|harden|restore|agents|listrm>:<device_id8>` · `rm:<device_id8>:<sc_id>` · `rmc:<device_id8>:<sc_id>` · `pg:<n>`
(`device_id8` = first 8 chars of device GUID; resolved by prefix, must be unique.)
