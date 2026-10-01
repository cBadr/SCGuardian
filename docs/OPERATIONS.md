# SCGuardian v4 - Operations guide

Audience: the administrator running the hub and the fleet. All commands assume an elevated Windows PowerShell 5.1
prompt. Placeholders in angle brackets (`<SECRET>`, `<DEVICE_ID>`) must be replaced; never write real secrets into
tickets, chat or scripts that are committed.

Paths used below:

| What | Path |
|---|---|
| Hub program files | `C:\Program Files\SCGuardian` (`modules`, `lib`, `SCGuardian.ps1`) |
| Data directory (hub and agent) | `C:\ProgramData\SCGuardian` (ACL: SYSTEM + Administrators only) |
| Hub config / database / log | `hub.config.json`, `hub.db` (+ `hub.db-wal`, `hub.db-shm`), `hub.log` in the data directory (paths are configurable) |
| Agent config / state / log | `agent.config.json`, `agent.state.json`, `logs\scguardian.log` in the data directory |
| Scheduled tasks | `SCGuardian-Hub` (hub host), `SCGuardian-Agent` (endpoints), both SYSTEM at startup |

## 1. Install the hub

The full procedure is in `hub-deploy/README.md`; this is the short version.

1. DNS: an `A` record (for example `ostazna.pro`) to the hub's public IP. Open TCP 8443 (and TCP 80 only while a Let's
   Encrypt certificate is being issued).
2. `Set-Location <repo>\hub-deploy; .\install-hub.ps1` (add `-WhatIf` to preview). It copies the program files, creates and
   locks the data directory, creates `hub.config.json` from the template **only if missing**, opens the Windows Firewall
   rule `SCGuardian Hub` and registers the `SCGuardian-Hub` task. If the config still contains `REPLACE_ME` the task is
   registered but not started.
3. Edit `hub.config.json`: `shared_secret`, `telegram.bot_token`, `telegram.chat_id`, `telegram.admin_user_ids`,
   `defaults.allowed_ids`.
4. Certificate: `.\cert-setup.ps1 -SelfSigned` (RSA 2048, 5 years) is the **recommended choice for fleets**, combined with `THUMBPRINT` on every agent.
   `.\cert-setup.ps1 -Domain ostazna.pro -Port 8443` (Let's Encrypt via win-acme) works, but its leaf thumbprint changes at each renewal and would
   disconnect every pinned agent, so do not pin a Let's Encrypt certificate unless you accept a fleet re-deploy at each renewal.
5. `Start-ScheduledTask -TaskName SCGuardian-Hub`, then verify with the signed `GET /health` call in `docs/API.md`.

Rules:

- **Never run the agent installer or `harden` on the hub machine.** The hub does not harden itself.
- The hub reads `hub.config.json` once at start. After any edit run
  `Stop-ScheduledTask SCGuardian-Hub; Start-ScheduledTask SCGuardian-Hub`.
- Optional hub keys (all under `defaults`, positive integers): `command_timeout_sec` (300), `nonce_ttl_sec` (600),
  `max_skew_sec` (300), `tick_sec` (30), `telegram_error_pause_sec` (5). Keep `nonce_ttl_sec >= 2 * max_skew_sec`
  or the hub refuses to start the listener.

## 2. Install agents at scale

Every install needs: `HUBURL` (https, or http on loopback only), `SHAREDSECRET`, and optionally `THUMBPRINT` (the hub
certificate's SHA-1, written to `trusted_server_thumbprint`). **Set `THUMBPRINT` in production** (see `docs/SECURITY.md`).

Secret format: use a value without spaces or quotes (the install scripts reject quotes and whitespace). Generate one
that is safe on a command line:

```powershell
$b = New-Object byte[] 32
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$rng.GetBytes($b); $rng.Dispose()
-join ($b | ForEach-Object { $_.ToString('x2') })      # 64 hex characters
```

### 2.1 Manual or scripted, one machine

```
msiexec /i SCGuardian.Agent.msi HUBURL=https://ostazna.pro:8443 SHAREDSECRET=*** /qn
```

Optional additions: `THUMBPRINT=<40 hex>`, `/norestart`, `/l*v "%TEMP%\scg-agent.log"`. `SHAREDSECRET` is a hidden MSI property,
so it is masked in the MSI log. The command line itself is briefly visible to other administrators in the process list.

What the MSI does: installs `modules`, `SCGuardian.ps1` and `Install-Agent.ps1` under `C:\Program Files\SCGuardian`, then a
SYSTEM custom action runs `Install-Agent.ps1`, which writes `agent.config.json` into `C:\ProgramData\SCGuardian` (merged
from the template), locks that directory to SYSTEM + Administrators, and registers the `SCGuardian-Agent` task (at startup,
restart on failure). Uninstall removes the task and keeps `C:\ProgramData\SCGuardian`.

`Install-Agent.ps1` exit codes (read `install.log` in the data directory when the MSI fails):

| Code | Meaning |
|---|---|
| 10 | bad hub URL |
| 11 | bad or missing secret |
| 12 | config could not be read or written |
| 13 | ACL step failed |
| 14 | agent task could not be installed |
| 15 | bad thumbprint |
| 20 | removal failed |

Interactive alternative: `installer\Setup.ps1` prompts for the URL and (masked) secret, installs silently and forces one
heartbeat. Building the MSI is described in `installer/README.md` (WiX v4).

On its first cycle the agent enrolls with the shared secret, receives its `device_id` and a one-time `device_token`, and stores both in
`agent.config.json` (ACL-locked). Every later call carries the token. **Reinstalling a machine under the same hostname requires
`/reset <host>` first** (section 6.2), otherwise the hub answers 409 `hostname already enrolled`.

Check on the endpoint:

```powershell
Get-ScheduledTask -TaskName SCGuardian-Agent | Get-ScheduledTaskInfo
(Get-Content C:\ProgramData\SCGuardian\agent.config.json -Raw | ConvertFrom-Json).device_id   # filled after the first enroll (never print device_token)
Get-Content C:\ProgramData\SCGuardian\logs\scguardian.log -Tail 30
```

### 2.2 Active Directory: GPO

Group Policy "Software Installation" (Computer Configuration) can deploy an MSI but **cannot pass `HUBURL`/`SHAREDSECRET` on a
command line**. You have two options:

1. **Startup script (recommended).** Computer Configuration > Policies > Windows Settings > Scripts > Startup > PowerShell
   Scripts. Put the MSI and a file holding the secret on a share that only the target computers can read (NTFS and share
   ACL: a security group containing exactly those computer accounts, plus administrators). Example script:

   ```powershell
   $share = '\\fileserver\scg$'
   if (Get-ScheduledTask -TaskName 'SCGuardian-Agent' -ErrorAction SilentlyContinue) { exit 0 }
   $secret = (Get-Content "$share\secret.txt" -Raw).Trim()
   $msi = @('/i', "`"$share\SCGuardian.Agent.msi`"", 'HUBURL=https://ostazna.pro:8443', "SHAREDSECRET=$secret",
            'THUMBPRINT=<HUB_CERT_THUMBPRINT>', '/qn', '/norestart', '/l*v', "`"$env:windir\Temp\scg-agent.log`"")
   $p = Start-Process -FilePath msiexec.exe -ArgumentList $msi -Wait -PassThru
   exit $p.ExitCode
   ```

   Computers install on their next boot. Scope the GPO with a security group so a pilot set goes first.
2. **MSI transform (.mst)** that sets the properties, assigned through Software Installation. The transform contains the secret
   in clear form on SYSVOL, readable by every authenticated user. Avoid it unless that exposure is acceptable.

Trade-off to accept consciously: any computer allowed to read the share can read the secret. The secret is fleet-wide anyway
(see `docs/SECURITY.md`).

### 2.3 Microsoft Intune: Win32 app

1. Wrap `SCGuardian.Agent.msi` with the Microsoft Win32 Content Prep Tool (`.intunewin`).
2. App information: install behavior **System**; 64-bit.
3. Install command:
   `msiexec /i "SCGuardian.Agent.msi" HUBURL=https://ostazna.pro:8443 SHAREDSECRET=<SECRET> THUMBPRINT=<HUB_CERT_THUMBPRINT> /qn /norestart`
4. Uninstall command: `msiexec /x "SCGuardian.Agent.msi" /qn /norestart`
5. Return codes: keep the defaults (0 success, 3010 soft reboot, 1641 hard reboot, 1618 retry).
6. Detection rule: **custom script**, 64-bit, run as SYSTEM, not signature-checked:

   ```powershell
   if (Get-ScheduledTask -TaskName 'SCGuardian-Agent' -ErrorAction SilentlyContinue) { Write-Output 'installed'; exit 0 }
   exit 1
   ```

   (Alternative: a file rule on `C:\Program Files\SCGuardian\SCGuardian.ps1`, "File or folder exists".)
7. Assign to a pilot device group first; then to the fleet.

The secret is visible to Intune administrators inside the install command. Restrict who can edit or view the app.

### 2.4 After rollout

- `GET /health` -> `devices_online`; Telegram `/devices` or `/status all` for the fleet.
- Never deploy to the hub machine.
- A hostname that already holds a device token makes `/enroll` answer 409 (online or not); see section 6.2 and troubleshooting.

## 3. Rotate the shared secret

Scope: since contract v2.0 the shared secret guards **enrollment** and is the transport credential on every request; device identity is the
per-device token. Rotating the secret does not change device tokens, so no device needs re-enrolling (`/reset` is not part of rotation).

**Honest limitation: v1 has no dual-secret window.** The hub accepts exactly one `shared_secret`, and the agents' secret
is never pushed from the hub (by design). Between the moment the hub restarts with the new secret and the moment an agent
receives the new secret, that agent cannot talk to the hub (401). The rotation is therefore a short, planned outage of
hub connectivity, not a zero-downtime change. What keeps running during that window:

- The agent's **local watchdog** (restart, Automatic start, hardening layers) does not need the hub and keeps protecting.
- Commands queued for the window expire after `command_timeout_sec` (300 s) and are not delivered later. Issue none.
- Agents back off after repeated failures: 3 consecutive failures push the next attempt to at least 300 s.
- Events are re-derived from live state on the next successful heartbeat; results of commands executed before the window
  but not yet reported are lost (no retry queue).

Procedure (hub first; use this order when the old secret may be compromised, because it cuts off whoever holds it):

1. **Prepare** (no outage): generate the new secret (section 2). Prepare the deployment that applies it: update the GPO
   share file or the Intune app command, but keep it unassigned or scoped to a pilot group. Back up the hub (section 4) and
   keep a copy of the current `hub.config.json`.
2. **Pilot**: apply the new secret on one test endpoint *and* a test hub, or accept a pilot outage on the real hub with a
   few machines. Confirm the flow end to end.
3. **Window start**: edit `shared_secret` in the hub's `hub.config.json`, then
   `Stop-ScheduledTask SCGuardian-Hub; Start-ScheduledTask SCGuardian-Hub`. Check `hub.log` for `Hub started`.
   From now on every agent still holding the old secret gets 401 (audited as `auth.reject`, reason `bad_bearer`).
4. **Push to agents immediately** with the prepared deployment. Per machine, either:
   - re-run the installer logic with the new value (merges into the existing config and re-registers the task):
     `powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SCGuardian\Install-Agent.ps1" -Action Install -HubUrl https://ostazna.pro:8443 -SharedSecret <NEW_SECRET>`
     (this path is exercised by the installer code; the running agent loop re-reads `agent.config.json` every cycle, so no
     restart is needed), or
   - re-run `msiexec /i ... HUBURL=... SHAREDSECRET=<NEW_SECRET> /qn` with `REINSTALL=ALL` to force the custom action. Test this
     variant on a pilot machine first; the repository does not verify Windows Installer's re-install behaviour.
5. **Shorten the reconnect** (optional): delete `C:\ProgramData\SCGuardian\agent.state.json` on the endpoint after the
   new secret is in place. A missing state file means "heartbeat due now" instead of waiting out the backoff delay.
6. **Verify**: `GET /health` `devices_online` returns to the expected count; Telegram `/devices` shows no `stale` machines other
   than those that are genuinely off. Machines that were powered off keep the old secret until they receive the deployment;
   they appear stale and reconnect once the policy or Intune app reaches them.
7. **Rollback** (if the pilot fails): restore the previous `hub.config.json` secret and restart the hub.

Expected offline window per agent: the time from step 3 to that agent's update, plus up to one scan interval (default 60 s),
or up to 300 s if it had already entered backoff and the state file was not removed. Plan for the longest deployment latency
of GPO/Intune, which can be hours for machines that are off.

Telegram bot token rotation is independent: change `telegram.bot_token` through BotFather and in `hub.config.json`, then
restart the hub. Agents are unaffected.

## 4. Back up `hub.db`

The hub opens a short-lived connection per operation (WAL mode), so the database is usually checkpointed, but a safe copy must
include the `-wal` and `-shm` files or be taken with the SQLite backup API. Always back up `hub.config.json` too. It holds
the secrets; store the backup with the same restricted ACL (SYSTEM + Administrators). `hub.db` holds the device token hashes, so a restore
brings back the tokens that were valid at backup time; devices enrolled or reset since then need `/reset <host>`.

### 4.1 Stop-and-copy (matches `hub-deploy/README.md`)

```powershell
$dst = "D:\Backup\SCGuardian\$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))"
New-Item -ItemType Directory -Path $dst -Force | Out-Null
Stop-ScheduledTask -TaskName SCGuardian-Hub
Start-Sleep -Seconds 5
Copy-Item C:\ProgramData\SCGuardian\hub.db* $dst -Force
Copy-Item C:\ProgramData\SCGuardian\hub.config.json $dst -Force
Start-ScheduledTask -TaskName SCGuardian-Hub
```

Agents tolerate a few seconds of hub downtime (they simply retry on the next cycle).

### 4.2 Online backup (hub keeps running)

`System.Data.SQLite.dll` ships with the hub and exposes the SQLite online backup API (`BackupDatabase`). Run it from the
program folder so the interop DLL resolves; test on a copy first:

```powershell
$lib = 'C:\Program Files\SCGuardian\lib\System.Data.SQLite.dll'
Add-Type -Path $lib
$dstFile = "D:\Backup\SCGuardian\hub-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')).db"
$src = New-Object System.Data.SQLite.SQLiteConnection('Data Source=C:\ProgramData\SCGuardian\hub.db;Version=3;Pooling=False;')
$dst = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$dstFile;Version=3;Pooling=False;")
try { $src.Open(); $dst.Open(); $src.BackupDatabase($dst, 'main', 'main', -1, $null, 0) }
finally { $dst.Dispose(); $src.Dispose() }
```

If the `sqlite3` command-line tool is installed on the machine (it is not shipped with SCGuardian),
`sqlite3 hub.db ".backup 'D:\Backup\SCGuardian\hub.db'"` does the same.

### 4.3 Scheduled backup task

Save the 4.1 or 4.2 script as `C:\Program Files\SCGuardian\backup-hub.ps1` (or any admin-only folder), then:

```powershell
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\SCGuardian\backup-hub.ps1"'
$t = New-ScheduledTaskTrigger -Daily -At 03:00
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'SCGuardian-Hub-Backup' -Action $a -Trigger $t -Principal $p
```

Add your own retention (for example delete backups older than 30 days). Restore: stop the hub task, put `hub.db` (and remove any
stale `hub.db-wal`/`hub.db-shm` that do not belong to it) in place, start the task. The hub applies migrations on start.

## 5. Logs and rotation

| Log | Where | Rotation |
|---|---|---|
| Hub | `logging.path` (template: `C:\ProgramData\SCGuardian\hub.log`) | at `logging.max_bytes` (5 MiB by default) the file moves to `hub.log.1`, replacing any earlier `.1` |
| Agent | `C:\ProgramData\SCGuardian\logs\scguardian.log` | same rule, 5 MiB, one generation `.1` |
| Installer | `C:\ProgramData\SCGuardian\install.log` | none |
| Legacy modes | `guardian.log` in the data directory | 5 MB, one `.1` |
| Audit | table `audit_log` in `hub.db` | none; grows until you prune it |

Only one rotated generation is kept, so disk use is bounded at roughly twice `max_bytes` per log. If you need longer
retention, copy the `.1` files to your archive on a schedule. Log lines are `UTC [LEVEL] actor= target= action= result= message`,
CR/LF stripped, and pass through `Protect-Secret`: the shared secret, the device token, `Bearer <x>` and Telegram bot tokens appear as `***`.
Events, commands and audit rows are never pruned in v1; plan a manual retention job (for example delete audit rows older than a
year after archiving them).

## 6. Telegram command reference

The bot only reacts in the chat whose id equals `telegram.chat_id`, and only to senders listed in
`telegram.admin_user_ids` (or, less safely, `telegram.admin_usernames`). Non-admins are ignored and audited as `auth.reject`;
`/whoami` answers anyone in the chat so you can find your id. Commands can be written `/status@YourBot host`.

| Command | Effect |
|---|---|
| `/panel` (or `/start`) | button panel: Devices, Fleet status, Events, Audit, Help |
| `/help` | command list |
| `/devices [page]` | paged device list with per-device buttons (Status, Harden, Agents, Restore) |
| `/status <host\|all>` | queues `status` for a host (result comes back as a notice); `all` prints the fleet summary |
| `/agents <host>` | queues `agents` and prints the stored agent inventory (mine / UNKNOWN) |
| `/harden <host\|all>` | queues `harden` on one host or every device |
| `/restore <host>` | queues `restore` (undo hardening of my agents) on one host |
| `/ping <host>` | queues `ping`; the agent answers `pong` |
| `/reset <host>` | revokes the device token of that host (a specific host only, `all` is refused); the agent re-enrolls on its next cycle. Also the "Reset token" button on the device card, with a CONFIRM step |
| `/remove <host> <sc_id>` | step 1 of removing an UNKNOWN agent |
| `/confirm <code>` | step 2 of removal |
| `/events [n]` | latest events (default 10, maximum 20) |
| `/audit [n]` | latest audit rows (default 10, maximum 20) |
| `/whoami` | your Telegram id, username, admin flag |

Examples:

```
/devices
/status PC-FRONTDESK
/harden all
/agents PC-FRONTDESK
/events 15
```

Commands are delivered on the target's next heartbeat (default within about 60 s). The outcome arrives in the chat as
`<icon> <type> on <host>: done|failed (<ms>)` with the agent's output. If the host is offline, the command expires after
`command_timeout_sec` (300 s) without a notice; re-issue it later.

### 6.1 `/remove` is a two-step action

```
you:  /remove PC-FRONTDESK 0123456789abcdef
bot:  About to REMOVE agent 0123456789abcdef on PC-FRONTDESK.
      Reply /confirm 482913 within 300 s.
you:  /confirm 482913
bot:  Removal of 0123456789abcdef queued for PC-FRONTDESK.
bot:  (on the next heartbeat) remove on PC-FRONTDESK: done  ...
```

Rules enforced in code:

- The host must be named exactly (`all` is refused). `sc_id` is 16 hex characters.
- The id must **not** be allow-listed, and must exist on that host in the database as an unknown (unauthorized) agent. Otherwise it is refused.
- The code is 6 digits, random, valid for `defaults.command_confirm_sec` (300 s), bound to the admin who asked, usable once.
  Three wrong codes cancel the request.
- Pending confirmations are held in hub memory: restarting the hub cancels them.
- The button path is the same two steps (`Remove unknown` -> pick the agent -> CONFIRM within the same window).
- The agent re-checks on its side: it refuses allow-listed ids, exports registry backups into `Backup\removed_<id>\` first and
  aborts (removing nothing) if a backup export fails. The result output starts with `refused:` or `aborted:` in those cases.

### 6.2 `/reset <host>`: revoke a device token

```
you:  /reset PC-FRONTDESK
bot:  (token revoked; audit device.reset)
agent (next cycle): hub http 401 device not enrolled -> clears device_id and device_token -> POST /enroll -> new token
```

What it does: sets the host's `token_hash` to NULL in `hub.db` and audits `device.reset`. The old token stops working at once. The agent
clears `device_id` and `device_token` from `agent.config.json` and re-enrolls on its next cycle (default within about 60 s), keeping the same
`device_id` (history is preserved) and receiving a new token. From the reset until that re-enroll, the hostname can be claimed by anyone holding the shared secret
(see `docs/SECURITY.md` 2.4), so check `/devices` afterwards.

Use it when:

- **A machine is reinstalled or re-imaged** (the new install has no token): run `/reset <host>` **before** installing the agent again.
- **Token theft is suspected** (a copied `agent.config.json`, a compromised endpoint backup): reset, then review `/audit` for `enroll` rows with `reenroll: true`.
- **The agent log shows `hub http 409: hostname already enrolled`** (or "ask the operator to /reset this device"): the agent lost its token while the hub still holds
  the hash. Run `/reset <host>`; the agent re-enrolls by itself.

If the host is offline, the reset still takes effect immediately; the agent re-enrolls when it next comes online.

## 7. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| Hub task not running | config still has `REPLACE_ME`, invalid config, port in use | `Get-ScheduledTaskInfo -TaskName SCGuardian-Hub`; read `hub.log`; config errors list every problem (never the values) |
| Agent log: `hub http 401` (plain `unauthorized`) | wrong or rotated shared secret | compare the agent's `shared_secret` with the hub's; see section 3 |
| `hub http 408` | clock skew above `max_skew_sec` (default 300 s) | fix time sync (NTP/w32time) on the endpoint or hub |
| `hub http 409: hostname already enrolled` | the hostname already holds a device token: the machine was reinstalled, the agent lost its token, or another machine or cloned image uses the same hostname | if it is the same machine: `/reset <host>` (section 6.2), the agent re-enrolls by itself. If it is a different machine: rename it |
| `hub http 401: invalid device token` | wrong or missing `X-SCG-Device-Token`: stale or hand-edited `agent.config.json`, or a restored hub database with older hashes | `/reset <host>`; the agent then re-enrolls |
| `hub http 401: device not enrolled` | the device was reset (or has no token) | none needed: the agent clears `device_id` and `device_token` and re-enrolls on the next cycle |
| `hub http 409: replayed nonce` | request repeated by a proxy/retry layer, or nonce reuse in a custom script | do not retry with the same headers; build fresh headers each call |
| `hub http 404: unknown device` | hub database was restored/replaced | none needed: the agent clears its `device_id` and re-enrolls on the next cycle |
| `hub http 503` / `replay cache full` | more than 10,000 live nonces in the hub (about 17 requests per second sustained), or more than 32 requests in flight | wait and retry; reduce request rate (raise `heartbeat_sec`); see `docs/SECURITY.md` |
| TLS error from the agent | certificate untrusted, expired, or pin mismatch (a renewed Let's Encrypt certificate changes the pinned thumbprint; fleets should use the 5-year self-signed certificate) | check `trusted_server_thumbprint` equals the hub certificate; on the hub `netsh http show sslcert ipport=0.0.0.0:8443` |
| `trusted_server_thumbprint not set` warning in agent log | pinning not configured (dev mode) | set it (section 2) |
| Agent offline but hardening still applied | expected: local watchdog runs without the hub | fix connectivity; nothing is lost |
| Device shows `stale` | no heartbeat for `stale_after_min` (5 min) | check the endpoint's `SCGuardian-Agent` task and log; a heartbeat reactivates it |
| Commands never execute | host offline longer than 300 s, or device not heartbeating | re-issue after the device is back; check `/audit` for `command.timeout` |
| Telegram `409 Conflict` in `hub.log` | another process polls the same bot token (old controller, second hub) | stop the other consumer; only the hub may poll the bot |
| Bot silent | wrong `chat_id`, sender not in `admin_user_ids`, bot not in the group | `/whoami` in the chat; compare ids; check `hub.log` for `telegram api call failed` |
| Username-only admin warning in log | admin matched by `admin_usernames` | add the numeric id to `admin_user_ids` and drop the username |
| Let's Encrypt fails | port 80 busy or closed during issuance | see `hub-deploy/README.md` |
| TLS binding differs after a restart | the hub rebinds the certificate on start with its own application id when the thumbprint differs | known inconsistency: `HttpServer.psm1` and `cert-setup.ps1` use different `netsh` application ids. Keep `listen.cert_thumbprint` equal to the certificate bound by `cert-setup.ps1` so the hub finds a matching binding and leaves it alone. |

## 8. Migrating to PostgreSQL later

Not implemented in v1; this is the plan the code structure supports.

### 8.1 What is isolated

- **All SQL is in `src/modules/Database.psm1`.** Contract rule: no other module contains SQL. `Hub.psm1` and `Telegram.psm1`
  call domain functions (`Register-ScgDevice`, `New-ScgCommand`, `Add-ScgAudit`, ...) and pass a `-Path`.
- The module uses a small core (`Open-ScgConnection`, `Invoke-ScgSqlCore`, transaction helpers) and named `@parameters`,
  which Npgsql also accepts.
- Timestamps are stored as UTC ISO 8601 text and compared as text, which works unchanged in PostgreSQL with `text` columns
  (or can be converted to `timestamptz` with matching parameter types).

### 8.2 What is SQLite-specific and must change

| Item | Where | PostgreSQL equivalent |
|---|---|---|
| `System.Data.SQLite` connection, `Pooling=False` | `Open-ScgConnection`, `Import-ScgSqliteAssembly` | `Npgsql` connection (ship the .NET Framework Npgsql build and its dependencies in `src/lib`; confirm it loads in Windows PowerShell 5.1) |
| `PRAGMA busy_timeout / journal_mode=WAL / foreign_keys=ON` | `Open-ScgConnection` | not needed (foreign keys always on; use `lock_timeout`/`statement_timeout` if desired) |
| `INTEGER PRIMARY KEY AUTOINCREMENT`, `last_insert_rowid()` | `events`, `audit_log`, `Add-ScgEvent` | `bigserial`/identity column and `INSERT ... RETURNING id` |
| `BEGIN IMMEDIATE` | `Start-ScgTx` | `BEGIN` (default isolation; take row locks where the code relies on write exclusivity, notably command dispatch) |
| `sqlite_master` lookup | schema version check | `information_schema.tables` |
| `INSERT OR REPLACE` | migration 2 only | `INSERT ... ON CONFLICT` (not needed on a fresh PostgreSQL schema) |
| `-Path` is a file path | every Database function, plus `database.path` in config | treat it as a connection string/DSN; rename the parameter only through a contract amendment |
| Single-writer assumption | atomic `pending -> dispatched` flip | use `UPDATE ... WHERE status='pending' ... RETURNING` or `FOR UPDATE SKIP LOCKED` |

### 8.3 Steps

1. Amend `docs/contracts/` first (field dictionary: the config key for the connection string; module interfaces for `Database.psm1`).
2. Implement a PostgreSQL variant of the core in `Database.psm1`, selected by config; keep every exported function name and result shape.
3. Reuse the Pester suites in `tests/Pester/Database.Tests.ps1` against a disposable PostgreSQL database; they define the behaviour to match
   (idempotency, transitions, dedupe, `-AllowEmpty`).
4. Create the schema (tables and indices listed in `docs/ARCHITECTURE.md`) and record the schema version.
5. **Export/import**: stop the hub task (so nothing writes), then copy table by table in dependency order
   `devices -> sc_agents -> commands -> events -> audit_log` (`schema_version` is created by the new migration). Export from SQLite with
   the shipped DLL or `sqlite3 -csv`, import with `COPY`; keep ids as they are (`devices.id`, `commands.id` are GUID text) and
   reset the identity sequences of `events` and `audit_log` to `max(id)+1`.
6. Verify row counts per table, then start the hub with the new config, check `/health`, issue `/ping` to a test host and confirm the audit rows.
7. Keep the old `hub.db` as a cold backup until the new database has run for a full backup cycle.
