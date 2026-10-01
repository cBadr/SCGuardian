# SCGuardian v4 — Telegram UI (FROZEN, contract v2.1)

English UI. Pull-only (no push alerts in this wave). All text is HTML parse mode; every dynamic value goes through `ConvertTo-TgHtml`. Messages ≤ 4000 chars (use `Limit-TgHtml`). Menus edit the current message in place.

## Shared definitions
- **Device state** (single source, `Get-TgDeviceState -Device -StaleMin -Now`): `quarantined` if `status = quarantined`; else `online` when `last_seen` is within `StaleMin` minutes of now; else `offline`. (Do NOT trust the `status` column for online/offline: the Hub tick lags.)
- Icons: 🟢 online · 🟡 offline · 🔴 quarantined · ⚠ attention · ✅ mine/running · ⛔ stopped · 🛡 agents · ⚙ commands · 🔔 events.
- **Attention** = quarantined OR `agents_unknown > 0` OR `agents_stopped > 0` (allow-listed agent not Running) OR `commands_failed_24h > 0`.
- **Relative time** `Format-TgAgo -IsoUtc -Now` → `12s ago` · `5m ago` · `3h ago` · `2d ago` · `never` (empty/unparseable).
- Page size stays **10**. Sort for filter All: attention first, then offline, then online; ties by hostname (case-insensitive).

## Screens
**Devices list** (`/devices [page]`, `m:devs`, `dl:*`)
```
🖥 Devices · filter: All · page 1/2
🟢 12 online · 🟡 3 offline · 🔴 0 quarantined · ⚠ 2 need attention
```
Keyboard: filter row `[• All 15][🟢 12][🟡 3][⚠ 2]` (active filter prefixed `• `) → one row per device, button text `🟢 PC-07 ⚠1 · 12s ago` (⚠N = unknown agents; hostname truncated so text ≤ 40 chars) → pager `[⬅ Prev][1/2][Next ➡]` → `[📊 Fleet][🔄 Refresh][⬅ Menu]`.

**Fleet card** (`/fleet`, `/status all`, `m:fleet`)
```
📊 Fleet
🟢 12 online · 🟡 3 offline · 🔴 0 quarantined (15 devices)
🛡 Agents: 18 mine · ⚠ 2 unknown (on 2 devices)
⚙ Commands: 1 pending · 0 in flight · 2 failed (24h)
🔔 Events (24h, unacked): 1 critical · 3 warn

Needs attention:
⚠ PC-07 · 1 unknown agent
🟡 PC-12 · offline 3h
(+N more)
```
Needs-attention list: up to 8 devices ordered quarantined, unknown agents, stopped agents, failed commands, offline (offline-only devices last). Keyboard: `[🖥 Devices][⚠ Attention (N)]` / `[🟢 Online][🟡 Offline]` / `[🛡 Harden all][📡 Ping all]` / `[🔄 Refresh][⬅ Menu]`.

**Device card** (`/device <host>`, `d:<id8>`, refresh = same callback)
```
🟢 PC-07 · online (12s ago)
OS: Windows 10 Pro 22H2 · agent 4.0.1
IP: 1.2.3.4 · enrolled 2d ago

🛡 Agents (2)
✅ 5d09…8a2b mine · Running
⚠ 9f3c…11ee UNKNOWN · Running

⚙ Recent commands
✔ harden · 5m ago
✖ remove · 1h ago · failed
```
Keyboard: `[📊 Status][📡 Ping][🧩 Agents]` / `[🛡 Harden][♻ Restore]` / `[🧹 Remove unknown (N)]` (only when N>0) / `[🔑 Reset token]` / `[🔄 Refresh][⬅ Devices]`. Agent id shown as first4…last4 of the 16-hex id (full id only in the Agents screen and remove flow).

**Confirmations** (buttons only; typed commands keep their current behaviour): Harden, Restore, Reset token, Harden all each show a prompt + `[✅ Confirm][❌ Cancel]`:
- Harden `<host>`: "Apply protection (service recovery, folder ACL, service SD, registry ACL) to allow-listed agents on `<host>`?"
- Restore `<host>`: "⚠ Remove SCGuardian protection from `<host>` (restores backed-up ACLs/SD)?"
- Harden all: "Harden ALL `<N>` devices?"
Remove-unknown keeps its existing 2-step flow.

## Callback grammar (all ≤ 64 bytes)
Existing kept: `m:main|devs|fleet|events|audit|help` · `d:<id8>` · `a:status|agents|listrm:<id8>` · `rm:<id8>:<sc_id>` · `rmc:<id8>:<sc_id>` · `rst:<id8>` (execute reset) · `pg:<n>` (alias of `dl:a:<n>`).
Changed: `a:harden:<id8>`, `a:restore:<id8>`, `a:reset:<id8>` now only SHOW the confirm prompt (never issue a command).
New: `dl:<f>:<page>` (f = `a` all · `o` online · `s` offline · `x` attention) · `a:ping:<id8>` (immediate, harmless) · `ok:harden:<id8>` · `ok:restore:<id8>` (execute, audit `command.issue`) · `fl:r` (refresh fleet) · `fl:hall` (confirm harden-all) · `fl:hallok` (execute) · `fl:pall` (ping all) · `up:ok:<token8>` / `up:no:<token8>` (v2.2, self-update.md: confirm/cancel a pending `/update all`; token keys an in-memory one-use spec, admin-bound, expires after `command_confirm_sec`).
Every executing callback re-checks admin; non-admin → `answerCallbackQuery` "Unauthorized".

## Database additions (module `Database.psm1`, only place with SQL)
- `Get-ScgFleetSummary -Path -StaleAfterMin [-Now]` → object: `devices_total devices_online devices_offline devices_quarantined agents_total agents_mine agents_unknown devices_with_unknown commands_pending commands_dispatched commands_failed_24h events_critical_24h events_warn_24h` (events = unacked, created within 24h; `-Now` injectable for tests, UTC ISO).
- `Get-ScgDeviceAgentSummary -Path [-Now]` → one row per device that has any agent or failed command: `device_id agents_total agents_mine agents_unknown agents_stopped commands_failed_24h` (stopped = authorized agent whose state is not `Running`; failed = commands status `failed` or `timeout` finished/created within 24h).
- `Get-ScgRecentCommand -Path -DeviceId [-Last 3]` → newest first: `id type status created_at finished_at result_json`.
All three are read-only, parameterised, and must stay fast for 500 devices (single grouped queries, no per-device loops).

## Telegram module additions
`Get-TgDeviceState`, `Format-TgAgo` (pure, injectable `-Now`), `Format-TgFleetText`/`Format-TgDeviceCard`/`Format-TgDevicesHeader` (use the three Database functions), `New-TgMenu` gains names `fleet`, `confirm` (Context `Action`,`DeviceId8`) and its `devices`/`device` contexts are extended (`Filter`, `Summary`, `Counts`, `StaleMin`, `Now`, `UnknownCount`). New typed commands: `/fleet`, `/device <host>`.
