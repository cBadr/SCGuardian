# SCGuardian v4 — Self-Update (FROZEN, contract v2.2)

Goal: push a new Agent build to the fleet (or a subset) from Telegram, verified by SHA-256, with
an audit trail — without opening a free-form command channel.

## Design choices (locked)
- **No free-form remote execution.** This is a new, single-purpose `command.type = 'update'`, same
  queue/audit/result model as `harden`/`restore`/`remove`/`status`/`agents`/`ping` — nothing new to trust.
- **Verification = SHA-256 pinned by the operator**, same model the MSI/bootstrapper already use. No
  code-signing certificate exists yet; this is the honest v1 level (documented in SECURITY.md).
- **Source = GitHub Releases**, same as today's manual install. The operator supplies the URL+hash
  (from that release's `SHA256SUMS.txt`); the Hub never fetches or re-hosts the file itself.
- **No automatic version comparison, no automatic rollout.** The operator explicitly names a version,
  a target scope (`host` or `all` with an optional rollout fraction) and confirms via a button. This
  stays explicit and auditable rather than silently "always latest".
- **No automatic binary rollback in v1.** An update is forward-only. To revert, the operator issues
  another `/update` with the older version's asset URL/hash (see "Downgrades" below). This is stated
  plainly in docs/SECURITY.md — do not imply auto-rollback anywhere in UI text.

## Command payload (extends field-dictionary.md "Command payload v1.2")
`type = 'update'`, `payload_json`:
```json
{ "version": "4.0.2", "setup_url": "https://github.com/.../SCGuardian.Agent.Setup.exe", "sha256": "<64-hex>" }
```
- `version`: free string, compared only for the "already on this version → no-op" short-circuit (exact match, case-insensitive). Not parsed as semver.
- `setup_url`: must be `https://` and host-allowlisted to `github.com` / `objects.githubusercontent.com` (release asset CDN) — reject anything else at issuance time (Hub) AND at execution time (Agent), defence in depth.
- `sha256`: exactly 64 lowercase hex chars, mandatory (no "skip verification" option, ever).

## Hub / Telegram command semantics
`/update <host> <version> <setup_url> <sha256>` — single device.
`/update all <version> <setup_url> <sha256> [percent]` — fans out like `/harden all`, but targets a
**deterministic subset**: sort all non-quarantined device ids, take the first `percent`% (default 100,
range 1-100). Same subset every re-run with the same inputs (stable by sorted device id), so a staged
rollout ("10 then 100") is two commands, not random each time. Requires the existing 2-step confirm
button (`[✅ Confirm][❌ Cancel]`) because of fleet-wide blast radius — same pattern as `fl:hall`.
Refuses when a device's `agent_version` already equals `version` (reported back in the summary, not
silently skipped from the audit). Writes `Add-ScgAudit action=command.issue` per device, same as today.

`/versions` (new, read-only): groups devices by `agent_version`, newest-reporting first per group,
via `Get-ScgVersionDistribution`.

## Agent execution (`Invoke-ScgAgentCommand` for type `update`)
1. Short-circuit: if local `$script:AgentVersion` already equals `payload.version` → result
   `ok=true`, output `"already on <version>"`, no download.
2. Validate `setup_url` host against the allowlist (`github.com`, `objects.githubusercontent.com`)
   and scheme `https`; validate `sha256` is 64 hex. Reject anything else → `ok=false`.
3. Download to `<Root>\update\SCGuardian.Agent.Setup.<guid8>.exe` (fresh name per attempt; `update\`
   locked SYSTEM+Administrators like `Backup\`). Verify SHA-256; mismatch → delete file, `ok=false`,
   result text includes expected vs actual hash (never partial downloads left on disk).
4. **Never run the installer in the Agent's own process tree** (Task Scheduler may kill the whole job
   when the install step stops/restarts the `SCGuardian-Agent` task, aborting mid-upgrade). Instead
   register a **transient one-time scheduled task** `SCGuardian-Agent-Update` (SYSTEM, RunLevel
   Highest, one-time trigger ~5s in the future, `DeleteExpiredTaskAfter` / self-unregister on
   completion) whose action is:
   `powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '<setup.exe>' -ArgumentList '/quiet' -Wait; Unregister-ScheduledTask -TaskName 'SCGuardian-Agent-Update' -Confirm:$false; Remove-Item '<setup.exe>' -Force"`.
   `-Wait` is mandatory: the Setup.exe is a Burn bootstrapper and returns immediately without it,
   which would delete the installer out from under itself mid-install.
   **No HUBURL/SHAREDSECRET/THUMBPRINT properties are passed** — `Install-Agent.ps1` already preserves
   the existing `agent.config.json` (device_id, device_token, everything) whenever no properties are
   supplied and the file exists; re-running the MSI only replaces program files and re-registers the
   `SCGuardian-Agent` task (idempotent `Register-ScheduledTask -Force`).
5. Report back `ok=true`, output `"update task scheduled for <version>"` **immediately** (the actual
   install result is not known this cycle — it is observed next cycle via the new `agent_version` the
   upgraded Agent reports at its next heartbeat; a stalled version after a reasonable window is the
   operator's signal to investigate, visible via `/versions`).
6. If a transient update task from a previous attempt is still present and overdue (> 10 min, meaning
   the installer likely failed silently), remove it and log a WARN before registering a new one —
   never stack update tasks.

## Installer
`SCGuardian.Agent.wxs.template`'s `MajorUpgrade` must set `AllowDowngrades="yes"` (with
`DowngradeErrorMessage` removed/neutral) so an emergency `/update <host> <older-version> ...` is not
silently blocked by Windows Installer's default anti-downgrade behaviour. This is the only installer
change this contract requires.

## What this deliberately does NOT do (document in SECURITY.md)
- No automatic "check for updates" — every rollout is an explicit operator action.
- No automatic rollback — a failed upgrade needs a manual `/update` back to the previous version.
- No code signing yet — SHA-256 pinning is the only integrity check (same trust level as the existing
  installer/bootstrapper). Upgrading to Authenticode verification later is additive, not breaking.
