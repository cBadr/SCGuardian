# SCGuardian Hub deployment

The Hub is a PowerShell process (`SCGuardian.ps1 -Mode Hub`) that serves the agent API over HTTPS
(HTTP.sys) and runs the Telegram bot. It runs as a SYSTEM scheduled task named `SCGuardian-Hub`.

> **The Hub must NOT run the agent or hardening on itself.** `install-hub.ps1` installs only the Hub.
> Never run the agent installer or `harden` on the Hub machine.

Requirements: Windows Server/10+ with Windows PowerShell 5.1, an elevated prompt, a public IP.

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

Generate a secret: `[Convert]::ToBase64String((1..32 | % { [byte](Get-Random -Max 256) }))`.
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
