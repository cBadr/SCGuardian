# SCGuardian v4 - Architecture

Scope: how the pieces fit together as implemented in `src/`. The frozen contracts in `docs/contracts/` remain the
source of truth for names, types and endpoints; this document explains the design around them.

## 1. Hub-and-spoke overview

```
                                   Telegram Bot API (api.telegram.org)
                                          ^   |
                          sendMessage /   |   | getUpdates (long-poll, timeout=25)
                          editMessage     |   v
   +---------------------------------------------------------------------------+
   |  HUB   (one Windows host, scheduled task "SCGuardian-Hub", SYSTEM)         |
   |                                                                           |
   |   runspace A: HTTP accept loop --> RunspacePool workers (default 8)       |
   |                bearer -> timestamp -> nonce -> route -> body -> handler   |
   |   runspace B: ticker   (every defaults.tick_sec: stale devices, timeouts) |
   |   runspace C: Telegram poller (Invoke-TgPollOnce loop)                    |
   |                                                                           |
   |   Hub.psm1 handlers --> Database.psm1 --> hub.db (SQLite, WAL)            |
   |   in-memory only: nonce store, pending /remove confirmations              |
   +---------------------------------------------------------------------------+
          ^  HTTPS :8443  (agents always call OUT; the hub never calls in)
          |  POST /enroll /heartbeat /result /event   GET /health
          |
   +------+-----------+     +------------------+     +------------------+
   | AGENT (spoke 1)  |     | AGENT (spoke 2)  | ... | AGENT (spoke N)  |
   | task SCGuardian- |     |                  |     |                  |
   | Agent, SYSTEM    |     |                  |     |                  |
   | local watchdog   |     |                  |     |                  |
   | + Discovery      |     |                  |     |                  |
   | + Hardening      |     |                  |     |                  |
   +------------------+     +------------------+     +------------------+
```

The hub holds the fleet database and is the only component that talks to Telegram. Agents hold a local config
(`agent.config.json`) and a local state file (`agent.state.json`) and never listen on a port.

## 2. Modules and dependencies

All modules live in `src/modules/`. A module never reads another module's `$script:` variables; everything flows
through parameters (contract rule).

```
                     Common.psm1   (no dependencies)
                          ^
     +----------+---------+-----------+------------+
     |          |                     |            |
 Database   HttpServer            Discovery    Hardening
     ^          ^                     ^            ^
     |          |                     +-----+------+
     |          |                           |
 Telegram       |                         Agent
 (Common,       |
  Database)     |
     ^          |
     +----+-----+
          |
         Hub    (Common, Database, HttpServer, Telegram)
```

| Module | Responsibility | Notes |
|---|---|---|
| `Common` | UTC time helpers, `Protect-Secret`, logging with rotation, atomic JSON files, instance-id validation, `Invoke-ScgNative`, secure-directory ACLs, backoff and throttle helpers | no dependencies |
| `Database` | the only module that contains SQL (SQLite via `src/lib/System.Data.SQLite.dll`); migrations, devices, agents, commands, events, audit, health counts | see section 5 |
| `HttpServer` | bearer check (constant-time), replay cache, route resolution, request pipeline, `HttpListener` loop with a runspace pool, TLS binding through `netsh` | handlers are re-created per worker from their text |
| `Discovery` | find ScreenConnect client services/folders/uninstall keys; classify by 16-hex instance id (mine vs unknown) | legacy `Get-Agents` logic, parameterised |
| `Hardening` | the four legacy layers (Recovery, FolderAcl, ServiceSd, RegistryAcl), restore, tamper test, guarded removal | `Remove-ScAgent` refuses allow-listed ids and backs up first |
| `Telegram` | Bot API client, command parser, admin check, menus, router, 2-step remove, result notices | no SQL; persistence through `Database` |
| `Hub` | config loading/validation, the five handlers, maintenance tick, `Start-ScgHub` host | the Hub never imports `Hardening` and never hardens itself |
| `Agent` | agent config, the sole HTTP client (`Invoke-HubApi`), command execution, local watchdog, backoff, cycle | depends on Common, Discovery, Hardening |

Entry point: `src/SCGuardian.ps1` (see README for modes). It loads modules from `.\modules`, else
`C:\Program Files\SCGuardian\modules`.

## 3. Data flows

All flows are agent-initiated. The hub never opens a connection to an agent.

### 3.1 Heartbeat (the carrier of everything else)

```
Agent                                              Hub
  | POST /heartbeat {device_id, hostname,           |
  |   sc_agents[], discovery_ok, uptime_sec, ...}   |
  |------------------------------------------------>|  auth pipeline (see API.md)
  |                                                 |  device lookup (404 if unknown)
  |                                                 |  update last_seen / ip / agent_version
  |                                                 |  Sync-ScgScAgent (upsert + delete-missing)
  |                                                 |  Get-ScgDispatchableCommand:
  |                                                 |    pending -> dispatched, atomically
  |<------------------------------------------------|  {ok, commands[], config{...}}
  | adopt config (whitelisted keys only)            |
```

The agent then executes each returned command, posts one `/result` per command, and finally emits events.

### 3.2 Command

```
Telegram admin --/harden host-->  Hub poller  --New-ScgCommand (status=pending, audit command.issue)
                                      ...next heartbeat of that host...
Hub returns command in heartbeat response  (pending -> dispatched, audit command.dispatch)
Agent executes (harden | restore | remove | status | agents | ping)
Agent POST /result  -->  Complete-ScgCommand (dispatched -> done|failed), audit command.result
Hub posts a result notice to the ops chat
```

A command is returned at most once. The ticker moves a command to `timeout` when it has been `dispatched`
(since `dispatched_at`) or `pending` (since `created_at`) for longer than `defaults.command_timeout_sec`
(default 300). Identical `(device, type, payload)` commands that are still
`pending` or `dispatched` are not queued twice.

### 3.3 Result

`POST /result` is accepted only for a command that exists for that device and is in a state that can legally
transition (otherwise 409). The agent truncates output to 16000 characters. There is no retry queue: if the
`/result` call fails, the agent logs a warning and the command ends as `timeout` on the hub (see SECURITY.md,
known limitations).

### 3.4 Event

After each successful heartbeat the agent re-scans and posts `unknown_agent` (warn), `tamper` (critical) and
`service_down` events. The hub validates type and severity, stores the event and audits `event.ingest`.
An identical unacknowledged event inside `alert_throttle_min` is dropped (the request still returns `ok`).
In v1 events are stored and readable through `/events` and the panel; the hub does not push them to Telegram.

## 4. Why these design choices

### 4.1 Pull model (agents call the hub)

- Endpoints are typically behind NAT or a firewall with no inbound rule; outbound HTTPS works everywhere.
- The attack surface of an endpoint stays at zero listening ports. Only the hub exposes TCP 8443.
- Commands wait in the database until the device checks in; the hub does not need to know device addresses.
  A command that is still `pending` after `command_timeout_sec` (default 300 s) is moved to `timeout`, so an offline
  device does **not** collect old commands later: re-issue the command once the device is back.
- The cost is latency: a command is delivered on the next heartbeat (default `heartbeat_sec` 60).

### 4.2 The agent's local watchdog runs first

`Invoke-ScgAgentCycle` runs `Invoke-ScgLocalWatchdog` before any network call. It restarts a stopped allow-listed
service, forces Automatic start and re-asserts the hardening layers. It does not depend on the hub, so protection
continues when the hub is down, the secret was rotated, DNS fails or the certificate pin no longer matches.
Hub errors only feed the backoff state; they never stop the cycle from returning. The watchdog can be disabled per
device with `local_watchdog` in `agent.config.json`.

### 4.3 Server-pushed config is a whitelist

The heartbeat response carries `scan_interval_sec`, `heartbeat_sec`, `allowed_ids`, `alert_throttle_min`. The agent
adopts only those keys, range-checked, and never `shared_secret`, `hub_url` or `trusted_server_thumbprint`. An empty
or invalid pushed `allowed_ids` is rejected and the local list kept. For `remove`, the effective allow-list is the
union of the current and the pre-update list, so a same-heartbeat shrink cannot authorise removing an allow-listed
agent.

### 4.4 Single-writer SQL and a thin Hub

All SQL is in `Database.psm1`. Hub handlers are pure functions of `(Config, Body)` returning `@{Status; Body}`,
which is why they are unit-testable without a listener (see `tests/Pester/`).

## 5. Database

SQLite, file path from `database.path` (default `C:\ProgramData\SCGuardian\hub.db`). Every connection sets
`busy_timeout=5000`, `journal_mode=WAL`, `foreign_keys=ON`. Migrations are applied by `Initialize-ScgDatabase`
(schema version table, idempotent).

| Table | Purpose | Key columns |
|---|---|---|
| `schema_version` | applied migrations | `version`, `applied_at` |
| `devices` | one row per host | `id` (GUID), `hostname` (UNIQUE), `os`, `os_version`, `last_ip`, `first_seen`, `last_seen`, `status` (`active`/`stale`/`quarantined`), `agent_version`, `tags`, `config_json` |
| `sc_agents` | ScreenConnect instances seen per device | PK `(device_id, id)`, `service_name`, `folder`, `uninstall_key`, `authorized` (0/1), `state`, `first_seen`, `last_seen` |
| `commands` | command queue and history | `id`, `device_id`, `type`, `payload_json`, `status`, `created_at`, `dispatched_at`, `finished_at`, `result_json`, `issued_by`, `issued_via` |
| `events` | agent-reported events | `id`, `device_id`, `type`, `severity`, `payload_json`, `created_at`, `acked_at`, `acked_by` |
| `audit_log` | append-only record of actions | `id`, `ts`, `actor`, `action`, `target`, `meta_json` |

Indices: `devices(last_seen)`, `sc_agents(device_id)`, `commands(device_id,status)`, `events(created_at DESC)`,
`events(acked_at)`, `audit_log(ts DESC)`.

Why `sc_agents` is keyed by `(device_id, id)`: the 16-hex ScreenConnect id identifies the SC server instance, so the
same id appears on every machine joined to it (contract amendment v1.1, migration 2).

Command state machine: `pending -> dispatched -> done | failed | timeout`, and `pending -> timeout`. Nothing else.

Idempotency rules enforced in `Database.psm1`: devices upsert by hostname (re-enroll returns the same id);
`sc_agents` rows absent from a heartbeat are deleted in the same transaction, except when the list is empty and
`-AllowEmpty` was not passed; duplicate pending/dispatched commands return the existing id; events dedupe inside the
throttle window.

There is no retention job in v1: `events`, `commands` and `audit_log` grow without pruning.

## 6. Hub runspace model

`Start-ScgHub` loads and validates the config, locks the data and log directories (SYSTEM + Administrators),
initialises the database, sets the masking log context (`shared_secret` and `bot_token` are masked in every log
line), and starts three independent units:

| Unit | Where | What it does |
|---|---|---|
| HTTP server | accept loop in its own runspace; requests handled by a `RunspacePool` (min 1, max 8) | in-flight work is capped at 4x the worker count (32); beyond that the listener answers 503 with `Retry-After: 1` |
| Ticker | own runspace | every `defaults.tick_sec` (30): `Set-ScgStaleDevice` and `Invoke-ScgCommandTimeout`, audited as `command.timeout` |
| Telegram poller | own runspace | `Invoke-TgPollOnce` in a loop; on error logs a warning and pauses `defaults.telegram_error_pause_sec` (5) |

Workers are fresh runspaces: route handlers are recreated from their text (`[scriptblock]::Create`) and can only call
functions from modules imported into the worker (`Common`, `Database`, `Hub`, `Telegram`). Closure variables are not
available, so the active hub config is stored module-scoped and lazily re-loaded from the `SCG_HUB_CONFIG`
environment variable in a worker. Consequence: the config is read at start; **changing `hub.config.json` requires a
hub restart**.

Shared state between units is limited to a synchronized `Stop` flag. The nonce store is created once in the hub
process and shared by the pool workers; it is guarded by a monitor lock. Pending `/remove` confirmations live in the
Telegram module's memory.

Shutdown (the `Stop` scriptblock on the handle returned by `Start-ScgHub -NoWait`, or the `finally` block of the
blocking run) sets the flag, stops poller and ticker (5 s bounded wait each), then stops the listener and pool.

## 7. Telegram: single consumer

Only the hub polls the bot (`getUpdates` with an offset). A second consumer of the same bot token produces
`409 Conflict`; the hub logs that at most once per 5 minutes. Updates from any chat other than `telegram.chat_id` are
ignored. Callback data is limited to 64 bytes and uses the grammar in `docs/contracts/field-dictionary.md`.

## 8. Related documents

- `docs/API.md` - wire protocol
- `docs/OPERATIONS.md` - install, rotate, back up, troubleshoot, PostgreSQL migration outline
- `docs/SECURITY.md` - threat model and limits
- `docs/contracts/` - frozen contracts
