# SCGuardian v4 — API Registry (FROZEN, contract v1)

Base: `https://ostazna.pro:8443/api/v1` · JSON only · every endpoint requires `Authorization`, `X-SCG-Timestamp`, `X-SCG-Nonce`.
Error shape: `{ "ok": false, "error": "<msg>" }`.

| Method | Path | Request | Response | Errors |
|---|---|---|---|---|
| POST | /enroll | `{hostname, os, os_version, agent_version}` | `{ok, device_id}` | 400 missing field · 401 · 409 replay |
| POST | /heartbeat | `{device_id, hostname, sc_agents:[{id,service,folder,uninstall_key,state}], uptime_sec, agent_version}` | `{ok, commands:[{id,type,payload}], config:{scan_interval_sec,heartbeat_sec,allowed_ids,alert_throttle_min}}` | 400 · 401 · 404 unknown device · 409 replay |
| POST | /result | `{device_id, command_id, ok, output, duration_ms}` | `{ok}` | 400 · 404 · 409 command not dispatched to this device |
| POST | /event | `{device_id, type, severity, payload}` | `{ok}` (deduped events still return ok) | 400 · 404 |
| GET | /health | – | `{ok, version, uptime_sec, devices_online, commands_pending}` | 401 |

Status 503 (v1.2): `replay_cache_full` (nonce store at capacity — fail closed) or worker queue saturated.
Status codes: 200 ok · 400 bad body · 401 bad/missing bearer · 404 unknown route/device · 405 wrong method · 408 stale timestamp (>`max_skew_sec`) · 409 replayed nonce · 413 body >1 MB · 500 internal (generic message, detail in log).

Auth order (amended v1.1): bearer (constant-time compare, checked from headers BEFORE reading any body) → timestamp window → nonce → route (404/405) → body read (≤1 MB) + parse → handler. Unauthenticated callers can never enumerate routes. Each rejection writes audit `auth.reject` (no secret, no bearer value).

Heartbeat addition (v1.1): optional `discovery_ok` boolean (default true). Agent sets false when discovery threw; the Hub then never deletes sc_agents rows for that beat.

Semantics:
- `/heartbeat` returns commands flipped `pending→dispatched` atomically; a command is returned at most once.
- Commands `dispatched` longer than `command_timeout_sec` become `timeout` (Hub tick).
- `allowed_ids` in the response is authoritative; agent adopts it.
- Device is `online` when `last_seen` within `stale_after_min`.
