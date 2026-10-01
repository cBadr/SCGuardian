# SCGuardian Hub deployment

The Hub is a PowerShell process (`SCGuardian.ps1 -Mode Hub`) that serves the agent API over HTTPS
(HTTP.sys) and runs the Telegram bot. It runs as a SYSTEM scheduled task named `SCGuardian-Hub`.

> **The Hub must NOT run the agent or hardening on itself.** `install-hub.ps1` installs only the Hub.
> Never run the agent installer or `harden` on the Hub machine.

Requirements: Windows Server/10+ with Windows PowerShell 5.1, an elevated prompt, a public IP.

## One-command setup (recommended)

Open **Windows PowerShell as Administrator** on the Hub server and run:

```powershell
Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/cBadr/SCGuardian/main/hub-deploy/Setup-Hub.ps1 -OutFile "$env:TEMP\Setup-Hub.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\Setup-Hub.ps1"
```

Defaults: `-Domain ostazna.pro -Port 8443 -Version 4.0.1`. The script prints numbered steps:

| Step | What happens |
|---|---|
| 0 | Admin and Windows PowerShell 5.1 check, TLS 1.2 |
| 1 | Cleanup, only with `-Reinstall` |
| 2 | Downloads `v<Version>` source from GitHub to `%TEMP%` (skip with `-SourceRoot <extracted repo>`) |
| 3 | Runs `install-hub.ps1` (program files, locked data folder, firewall rule, scheduled task) |
| 4 | Completes `hub.config.json`: keeps every value already set, generates `shared_secret` (64 hex, never shown) and asks **only** for Telegram fields that still hold placeholders (bot token input is hidden) |
| 5 | Certificate: reuses the pinned certificate if it is valid (re-runs never change the thumbprint), otherwise creates a self-signed one with `cert-setup.ps1 -SelfSigned` |
| 6 | Restarts `SCGuardian-Hub` and waits up to 30 s for the port |
| 7 | Signed health check on `https://localhost:<Port>/api/v1/health`, certificate pinned by thumbprint; on failure it prints the last 15 log lines (secrets masked) and exits 1 |
| 8 | Writes `C:\ProgramData\SCGuardian\agent-bootstrap.ps1` and the double-click launcher `agent-bootstrap.cmd` (SYSTEM + Administrators only) |

Flags:

| Flag | Effect |
|---|---|
| `-Reinstall` | Stops/unregisters the task, removes the firewall rule and deletes `C:\Program Files\SCGuardian`. Config, database and certificate in `C:\ProgramData\SCGuardian` are **kept** |
| `-NewCert` | Forces a new self-signed certificate. Every agent then needs the regenerated bootstrap |
| `-WhatIf` | Shows every change without making it |
| `-SkipHealthCheck` | Skips step 7 |
| `-Desktop` | Also copies `agent-bootstrap.ps1` and `agent-bootstrap.cmd` to your Desktop |

The command is safe to re-run (for example after a failed step or to regenerate the bootstrap).

### Agent bootstrap

`agent-bootstrap.ps1` is rendered from `agent-bootstrap.template.ps1` with this Hub's URL, shared secret,
certificate thumbprint, version and the SHA-256 of `SCGuardian.Agent.Setup.exe` (read from the release
`SHA256SUMS.txt`). `agent-bootstrap.cmd` is a static launcher copied next to it unchanged.

Copy **both files, in the same folder**, to each device over a **private channel**, then just
double-click `agent-bootstrap.cmd`. It asks for Administrator rights once (a single UAC prompt) and
then installs and enrolls completely silently - no console, no typing. (Running the `.ps1` directly
from an already-elevated prompt also still works: `powershell -NoProfile -ExecutionPolicy Bypass -File
.\agent-bootstrap.ps1`.)

It downloads the agent setup, verifies the SHA-256 (aborts and deletes on mismatch), installs silently,
checks the `SCGuardian-Agent` task and waits up to 60 s for enrollment (exit 0 enrolled, 1 failed,
2 installed but not enrolled yet). Delete both files from the device afterwards.

> **The bootstrap contains the shared secret.** Per-device tokens limit what a leaked secret can do to
> enrolled devices, but it can still enroll **new** hostnames. If it leaks: clear `shared_secret` in
> `hub.config.json`, re-run the setup command and redeploy the new bootstrap.

Re-enrolling a device that was reinstalled with the same hostname: send `/reset <hostname>` to the
Telegram bot; the agent enrolls again on its next cycle.

Still required outside the server: the DNS `A` record and the inbound **TCP 8443** rule on the router or
cloud firewall (section 1 below).

---

# Manual installation

## 1. DNS and ports

1. Create an `A` record `ostazna.pro` pointing to the Hub's public IP.
2. Open on the router/cloud firewall: **TCP 8443** (agents and health checks) and, only while
   requesting a Let's Encrypt certificate, **TCP 80** (http-01 validation).
3. `install-hub.ps1` opens the Windows Firewall inbound rule `SCGuardian Hub` for the port.

## 2. Install

```powershell
Set-Location <repo>\hub-deploy
.\install-hub.ps1            # add -WhatIf to preview
```

It copies `src\modules`, `src\lib`, `src\SCGuardian.ps1` to `C:\Program Files\SCGuardian`, creates
`C:\ProgramData\SCGuardian` (ACL: SYSTEM + Administrators only), copies the config template to
`hub.config.json` **only if missing** (never overwritten), opens the firewall and registers the task.
If the config still contains `REPLACE_ME`, the task is registered but not started.

## 3. Configure `C:\ProgramData\SCGuardian\hub.config.json`

| Field | Meaning |
|---|---|
| `listen.url` | e.g. `https://+:8443/` |
| `listen.cert_thumbprint` | `auto` or SHA1 thumbprint (written by `cert-setup.ps1`) |
| `shared_secret` | long random string, identical in every `agent.config.json` |
| `telegram.bot_token`, `telegram.chat_id` | bot credentials and target chat |
| `telegram.admin_user_ids[]`, `telegram.admin_usernames[]` | who may issue commands |
| `database.path`, `logging.path`, `logging.max_bytes` | storage locations |
| `defaults.*` | `allowed_ids`, `scan_interval_sec`, `heartbeat_sec`, `alert_throttle_min`, `command_confirm_sec`, `stale_after_min` |

Generate a secret (CSPRNG, hex so it is safe on msiexec/command lines):
`$b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ([BitConverter]::ToString($b) -replace '-','').ToLower()`.
Never commit real secrets.

## 4. Certificate

Option A, Let's Encrypt (recommended): place win-acme (`wacs.exe`) in `C:\Tools\win-acme` or on PATH, then

```powershell
.\cert-setup.ps1 -Domain ostazna.pro -Port 8443
```

Validation is `selfhosting` http-01 on port 80. The cert is stored in `LocalMachine\My`, bound with
`netsh http add sslcert` (appid `{7f3c1e52-4b8a-4d6e-9a21-5c0d8e3b6f14}`, existing binding replaced)
and the thumbprint is written to `listen.cert_thumbprint`. Re-run after each renewal to rebind.

Option B, self-signed: `.\cert-setup.ps1 -SelfSigned`. It prints the SHA1 thumbprint, the DER base64
and the PEM, and exports the public `hub-cert.cer` to `C:\ProgramData\SCGuardian` (private key never
exported). Put the thumbprint into each agent's `agent.config.json` as `trusted_server_thumbprint`.

## 5. First start

```powershell
Start-ScheduledTask -TaskName SCGuardian-Hub
Get-ScheduledTaskInfo -TaskName SCGuardian-Hub
Get-Content C:\ProgramData\SCGuardian\hub.log -Tail 50
```

## 6. Verify

The health endpoint requires the signed headers: `Authorization: Bearer <secret>`,
`X-SCG-Timestamp` (UTC ISO8601) and `X-SCG-Nonce` (a fresh GUID).

```powershell
$secret = '<shared_secret>'
$h = @{
  Authorization   = "Bearer $secret"
  'X-SCG-Timestamp' = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  'X-SCG-Nonce'   = [guid]::NewGuid().ToString()
}
Invoke-RestMethod -Uri https://ostazna.pro:8443/api/v1/health -Headers $h
```

```bash
curl -sS https://ostazna.pro:8443/api/v1/health \
  -H "Authorization: Bearer $SECRET" \
  -H "X-SCG-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.000Z)" \
  -H "X-SCG-Nonce: $(cat /proc/sys/kernel/random/uuid)"
# self-signed: add -k, or --pinnedpubkey / --cacert with the exported PEM
```

Each request needs a new nonce; reusing one is rejected (replay protection).

## 7. Backup

Stop the task (or rely on WAL) and copy `hub.db`, `hub.db-wal`, `hub.db-shm` and `hub.config.json`:

```powershell
Stop-ScheduledTask SCGuardian-Hub
Copy-Item C:\ProgramData\SCGuardian\hub.db* D:\Backup\SCGuardian\ -Force
Start-ScheduledTask SCGuardian-Hub
```

Keep backups ACL-restricted; the config holds secrets.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Task not running | `Get-ScheduledTaskInfo`; config still has `REPLACE_ME`; read `hub.log` |
| `401`/`403` | wrong secret, clock skew over `max_skew_sec` (default 300), reused nonce |
| TLS error | `netsh http show sslcert ipport=0.0.0.0:8443`; thumbprint exists in `LocalMachine\My` |
| Unreachable from outside | DNS record, router/cloud rule for 8443, Windows Firewall rule `SCGuardian Hub` |
| Let's Encrypt fails | port 80 free and open; nothing else listening on 80 during issuance |
| Agent rejects cert | self-signed: `trusted_server_thumbprint` must match the printed thumbprint |

Uninstall: `.\install-hub.ps1 -Uninstall` removes the task and firewall rule and keeps data.
