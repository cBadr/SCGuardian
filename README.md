# SCGuardian v4

Central protection and monitoring for your own ScreenConnect (ConnectWise Control) access agents on a Windows fleet.

SCGuardian identifies ScreenConnect agents by their 16-hex instance id. Ids on your allow-list are **yours**: they are
hardened and kept running. Every other instance is **unknown**: it is reported to you through Telegram, and a human decides
what happens next. Removal exists, but only as an explicit, two-step, admin-confirmed action, and it can never touch an
allow-listed id.

Everything is visible, logged and reversible. Every ACL or security descriptor is backed up before it is changed, and a
restore path exists.

## Why v4 is hub-and-spoke

Earlier revisions were a single script copied to each machine, each with its own Telegram token. v4 adds a central **hub**
and a small **agent** per endpoint:

- One Telegram bot and one place to read the whole fleet (devices, agents, events, audit trail).
- Agents connect **out** to the hub over HTTPS (pull model): no inbound ports on endpoints, works behind NAT.
- A local watchdog on each endpoint keeps protecting even when the hub is down.
- Every request is authenticated (bearer), replay-protected (timestamp and nonce) and audited.
- **Per-device tokens:** each endpoint gets its own token at enrollment (only a SHA-256 hash is stored on the hub). A stolen shared secret can no longer impersonate an
  existing device; an admin revokes a token with `/reset <host>`. Details: [docs/SECURITY.md](docs/SECURITY.md).

The original single-file behaviour is preserved as legacy modes of the same script (see "Modes").

```
   Telegram  <-->  HUB  (HTTPS :8443, SQLite)  <--  agents (outbound HTTPS, heartbeat every 60 s)
```

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

Requirements: Windows with Windows PowerShell 5.1 and an elevated prompt. The hub also needs a DNS name, a public IP and TCP 8443.

### 1. Hub

```powershell
Set-Location <repo>\hub-deploy
.\install-hub.ps1                      # -WhatIf to preview
# edit C:\ProgramData\SCGuardian\hub.config.json  (shared_secret, telegram.*, defaults.allowed_ids)
.\cert-setup.ps1 -SelfSigned                          # recommended for fleets (5-year cert, pin its thumbprint)
# or Let's Encrypt: .\cert-setup.ps1 -Domain ostazna.pro -Port 8443   (leaf thumbprint changes at each renewal; do not pin it)
Start-ScheduledTask -TaskName SCGuardian-Hub
```

Steps, certificate options and verification: [hub-deploy/README.md](hub-deploy/README.md). Do not install the agent on the hub machine.

### 2. Agent (each endpoint)

```
msiexec /i SCGuardian.Agent.msi HUBURL=https://ostazna.pro:8443 SHAREDSECRET=*** THUMBPRINT=<hub-cert-sha1> /qn
```

`THUMBPRINT` pins the hub certificate (recommended for production; use the 5-year self-signed certificate for fleets, because a Let's Encrypt leaf thumbprint changes at each renewal and would disconnect every agent). The agent enrolls on its first cycle and stores its own device token. Reinstalling a machine needs `/reset <host>` first. Building the MSI and the exit codes:
[installer/README.md](installer/README.md). Rolling out through GPO or Intune: [docs/OPERATIONS.md](docs/OPERATIONS.md).

### 3. Control

Open your ops chat and send `/panel` or `/devices`. Command reference: [docs/OPERATIONS.md](docs/OPERATIONS.md) section 6.

## Repository layout

```
src/
  SCGuardian.ps1            entry point: legacy modes + v4 Hub/Agent/AgentLoop
  modules/                  Common, Database, HttpServer, Discovery, Hardening, Telegram, Hub, Agent (.psm1)
  config/                   hub.config.template.json, agent.config.template.json
  lib/                      System.Data.SQLite.dll and native interop (x86, x64)
hub-deploy/                 install-hub.ps1, cert-setup.ps1, README.md
installer/                  WiX templates, build.ps1, Install-Agent.ps1, Setup.ps1, README.md
tests/Pester/               one *.Tests.ps1 per module, installer and hub-deploy
docs/
  ARCHITECTURE.md  API.md  OPERATIONS.md  SECURITY.md
  contracts/                frozen contracts: api-registry, field-dictionary, module-interfaces
```

## Run the tests

Requires Windows PowerShell 5.1 and **Pester 5.7.x**:

```powershell
Install-Module Pester -MinimumVersion 5.7.0 -MaximumVersion 5.7.99 -Scope CurrentUser -Force -SkipPublisherCheck
Set-Location <repo>
Invoke-Pester -CI
```

`-CI` sets a non-zero exit code on failure. The suite has 377 Pester tests (including the chaos tests), and a separate 26-check fleet integration run covers
enroll, tokens and reset end to end; run both yourself before relying on those numbers. `SCG_ROOT` is the test-only override of the data root (`C:\ProgramData\SCGuardian`).

## Modes of `SCGuardian.ps1`

```powershell
powershell -ExecutionPolicy Bypass -File .\src\SCGuardian.ps1 [-Mode <mode>] [options]
```

### v4 modes (module based; they ignore the script's CONFIG block and legacy token)

| Mode / switch | What it does |
|---|---|
| `-Mode Hub [-HubConfigPath <path>]` | run the hub (HTTP API, ticker, Telegram poller). The `SCGuardian-Hub` task runs this |
| `-Mode Agent [-AgentConfigPath <path>]` | one agent cycle (watchdog, enroll if needed, heartbeat, commands, results, events), then exit |
| `-Mode AgentLoop [-AgentConfigPath <path>]` | agent scheduler loop; stops when `agent.stop` appears in the data directory |
| `-InstallAgent` / `-RemoveAgent` | register or remove the `SCGuardian-Agent` task (SYSTEM, at startup) |

Modules are loaded from `.\modules` next to the script, else `C:\Program Files\SCGuardian\modules`. Default config paths are
`C:\ProgramData\SCGuardian\hub.config.json` and `agent.config.json`.

### Legacy modes (preserved single-file behaviour)

| Mode / switch | What it does |
|---|---|
| (no parameters) | applies the CONFIG `$Defaults`: harden and install the watchdog task, with UAC elevation if needed |
| `-Mode Report` | scan and print, no changes |
| `-Mode Harden [-InstallSchedule]` | apply hardening layers (Recovery, FolderAcl, ServiceSd, RegistryAcl) and optionally install the `SCGuardian-Watchdog` task |
| `-Mode Monitor` | what the watchdog task runs: restart stopped allow-listed services, re-harden, alert on unknown agents |
| `-Mode Restore [-RemoveSchedule]` | undo hardening from the backups (and remove the task) |
| `-Mode Listen` | one command-poll cycle for the legacy two-way Telegram test |
| `-Mode Controller` / `-InstallController` | legacy button controller as sole Telegram poller / install it as the `SCGuardian-Controller` task |
| `-TestTelegram` | send a test message and print the exact result |
| `-TakeOwnership` | (Harden) take ownership of the agent folder first; more invasive |
| `-AlertThrottleMinutes N` | minimum gap between repeats of the same alert (0 = never throttle) |
| `-ScanIntervalMinutes`, `-HeartbeatHours`, `-Layers`, `-AllowedIds`, `-TelegramBotToken`, `-TelegramChatId`, `-SaveConfig` | overrides of the CONFIG block values |

Legacy modes never remove, disable or reinstall an agent on their own and never block installs; `/remove` exists only as an admin-confirmed command.
Exit codes: `0` ok or work done, `1` nothing matched, `2` error or incomplete restore. Do not point a legacy controller and the hub at the same bot token
(two pollers cause `409 Conflict`).

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | design, data flows, modules, database, runspace model |
| [docs/API.md](docs/API.md) | endpoints, headers, curl and PowerShell examples, status codes, semantics |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | install at scale, secret rotation, backup, logs, Telegram commands, troubleshooting, PostgreSQL outline |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, shared secret and per-device tokens, pinning, replay protection, audit, known limitations |
| [hub-deploy/README.md](hub-deploy/README.md) | hub installation and certificates |
| [installer/README.md](installer/README.md) | building and installing the agent MSI |
| [docs/contracts/](docs/contracts/) | frozen contracts (read-only) |

---

Rights & signature: Badr · Telegram @Idlexaz · Cairo, Egypt
