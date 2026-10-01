# SCGuardian v4 - Security

This document states what the v1 design protects, what it does not, and how to harden it further. It describes the
code as it is. Where v1 is weak, it says so.

## 1. Threat model

### 1.1 Assets

| Asset | Why it matters |
|---|---|
| Fleet control (`harden`, `restore`, `remove` commands) | `remove` deletes a service, folder and registry keys on endpoints running as SYSTEM; `restore` lowers protection |
| Shared secret (`shared_secret`) | the only credential for the hub API |
| Telegram bot token and ops chat | the only way to issue commands |
| Allow-list (`allowed_ids`) | decides which ScreenConnect instances are protected and which are reported or removable |
| `hub.db` | device inventory, command history, events, audit trail |
| The protected ScreenConnect agents | the reason the product exists |

### 1.2 Adversaries

| Adversary | Capability assumed |
|---|---|
| Network attacker | observes or modifies traffic between endpoint and hub, or tries to impersonate the hub |
| Internet scanner | reaches TCP 8443, has no credentials |
| Standard user on an endpoint | cannot read `C:\ProgramData\SCGuardian` (ACL) or stop the hardened services |
| Local administrator / SYSTEM on one endpoint | can read `agent.config.json`, including the shared secret |
| Rogue insider with the shared secret | can call the API from anywhere that reaches the hub |
| Telegram account or chat compromise | sends commands as an admin, or reads fleet data |
| Hub host compromise | SYSTEM on the hub machine |
| Third-party remote-access installers | the unknown ScreenConnect instances SCGuardian reports (and, only on explicit admin request, removes) |

### 1.3 Trust boundaries

1. Internet to hub (TCP 8443, TLS). Authenticated by shared secret; integrity and confidentiality come from TLS.
2. Hub to Telegram Bot API (outbound HTTPS, bot token in the URL path as Telegram requires).
3. Endpoint user space to SYSTEM (ACLs on the data directory; hardening of the allow-listed services).
4. Admin chat to hub: Telegram user id (or username) membership of the configured admin lists, in the configured chat only.
5. Hub to agent: the agent trusts the hub for commands and for the pushed allow-list (see 2.3).

Agents never listen on a port; only the hub is exposed.

## 2. The shared secret in v1

### 2.1 Why a shared secret

One value deploys through one MSI property or one GPO/Intune command, with no certificate authority and no per-device
enrollment workflow. That kept v1 deployable at fleet scale with a small team.

### 2.2 Honest limits

- **It is fleet-wide.** Every endpoint holds the same secret in `agent.config.json`. Local administrator or SYSTEM on **any one
  endpoint** reveals it. Treat the secret as exposed to everyone who administers any machine in the fleet.
- **What a secret holder can do:** call every endpoint of the API; enroll; send heartbeats, results and events for any
  `device_id` they know or can obtain. The device id is a random GUID, not a secret, and a secret holder can obtain
  the id of any **offline** host by re-enrolling its hostname (the hub returns the same id; see 2.4).
  With a device id they can collect that device's queued commands (each is delivered once, so the genuine agent never
  receives them), report a fabricated agent inventory (for example an explicit empty list with `discovery_ok: true`,
  which hides unknown agents from the hub), and flood events and audit rows.
- **What a secret holder cannot do:** issue commands. Commands originate only from Telegram admins. A secret alone does not give
  code execution on endpoints.
- **Request bodies are not signed.** The bearer, timestamp and nonce authenticate the caller; body integrity relies on TLS.
- **No dual-secret window.** Rotation causes a short outage (see `docs/OPERATIONS.md` section 3).
- The device id is not bound to the caller's network identity.

### 2.3 Hub compromise equals fleet control

SYSTEM on the hub can queue `harden`, `restore` and `remove` for every device and push a new `allowed_ids`. The agent-side
guards narrow, but do not remove, that power:

- The agent refuses to remove an allow-listed id and `Remove-ScAgent` refuses it again, backing up registry keys before it deletes anything.
- A pushed `allowed_ids` that is empty or has no valid id is rejected and the local list is kept.
- For commands in the same heartbeat as a config update, the effective allow-list is the **union** of the old and new lists, so a one-step shrink
  cannot authorise removing an agent that was protected a moment earlier.
- Limit: a hub that shrinks the list in one heartbeat can remove the dropped id in a later one, and it can add an attacker's
  ScreenConnect instance to the list, after which the agent hardens it and stops reporting it as unknown. The hub is the root of trust.
- The pushable keys are limited to `heartbeat_sec`, `scan_interval_sec`, `allowed_ids`, `alert_throttle_min`, range-checked. The hub can never change an
  agent's `shared_secret`, `hub_url` or `trusted_server_thumbprint`.
- The local watchdog keeps running when the hub is unreachable; a hub outage does not stop hardening.

**Never remove allow-listed agents** is enforced in three places (Telegram request, agent command handler, `Remove-ScAgent`), all using the allow-list
the hub distributes. Keep `defaults.allowed_ids` in `hub.config.json` non-empty (the hub refuses an empty list) and under change control.

### 2.4 Enroll takeover

`POST /enroll` keys devices by hostname. While a device is online (`last_seen` within `stale_after_min`), a second `/enroll` for that hostname is
refused with 409 and audited as `auth.reject` (`enroll_conflict`) with the caller IP. That blocks duplicate and cloned
identities and live takeover. It does **not** protect offline hosts: a secret holder can re-enroll a stale hostname and obtain its id. The event is audited
as `enroll` with `reenroll: true` and the source IP. Review these rows. The durable fix is per-device credentials (section 6).

## 3. TLS and pinning

- Agents use TLS 1.2 and a 30 s timeout. Over `http://` the agent only accepts loopback.
- Without `trusted_server_thumbprint`, the agent accepts any certificate that the Windows trust store accepts for the host name, and logs a one-time warning
  ("dev-mode"). An attacker who can obtain a publicly trusted certificate for your host name, or who controls a CA trusted by the endpoint, can impersonate the hub
  and harvest the secret.
- With `trusted_server_thumbprint` (40-hex SHA-1 of the hub's leaf certificate) the agent accepts **only** that certificate. Chain and name errors are then ignored on
  purpose, so self-signed works.
- **Recommendation: set it in every production agent** (`THUMBPRINT=` in the MSI). It turns the secret-harvesting risk above into a connection failure.
- The thumbprint cannot be changed from the hub (not pushable). A certificate renewal that changes the leaf certificate breaks pinned agents until they are updated.
  Let's Encrypt certificates change about every 60 to 90 days, so a pinned fleet needs either a long-lived certificate (`cert-setup.ps1 -SelfSigned` issues RSA 2048 /
  SHA-256 valid 5 years with a non-exportable key) or a planned re-deploy. Plan the certificate lifetime before enabling the pin.
- The hub binds its certificate with `netsh http add sslcert` for port 8443.

## 4. Telegram administration

- Commands are processed only from the chat whose id equals `telegram.chat_id`. Other chats are ignored.
- Admins are matched by `telegram.admin_user_ids` (immutable numeric ids) or `telegram.admin_usernames`.
- **Prefer ids. Do not rely on usernames.** A username can be changed or released and claimed by someone else, who then passes the check. Every action authorised by username alone is logged
  as a WARN line ("authorised by USERNAME only"). The template ships a placeholder id and a username; replace the id with real ones (`/whoami` shows yours) and delete
  `admin_usernames` once ids are set.
- Anyone in the chat can run `/whoami`; everything else requires admin. Non-admin messages and button taps are ignored and audited as `auth.reject`.
- Destructive `remove` needs two steps: a random 6-digit code valid for `defaults.command_confirm_sec` (300 s), bound to the requesting admin, single-use, cancelled after 3 wrong codes;
  allow-listed and non-unknown ids are refused. Pending codes live in memory only.
- Keep the ops chat small and private. Every member's Telegram account is part of your security perimeter.
- **Bot token advice:** the token authorises everything the bot can do. Store it only in `hub.config.json` (restricted ACL). Revoke and reissue it through BotFather when an admin
  leaves, when the config or a backup may have leaked, and periodically. After changing it, update `telegram.bot_token` and restart the hub. The hub never logs the token
  (`Invoke-TgApi` logs only the method name; `Protect-Secret` also masks `bot<digits>:<token>` patterns).
- Do not reuse the hub's bot token in the legacy `-Mode Controller`/`Listen` modes: two pollers on one token cause `409 Conflict`.

## 5. Replay protection

Every request carries `X-SCG-Timestamp` and `X-SCG-Nonce`. After the bearer check:

1. The timestamp must be well-formed and within **+/- `max_skew_sec` (300 s)** of hub time, else 408.
2. The nonce (8 to 64 characters of `A-Za-z0-9-`, compared case-insensitively) must not have been seen within **`nonce_ttl_sec` (600 s)**, else 409.
3. An accepted nonce is stored immediately.

Design points:

- TTL is at least twice the skew window, enforced at start. A captured request that is still inside the timestamp window is therefore always still inside the nonce memory.
- The nonce store is an **in-memory** table in the hub process. It holds at most **10,000** live nonces and is not configurable in v1. At capacity, new requests get 503
  (fail closed); live nonces are never evicted. 10,000 nonces over 600 s is about 17 requests per second sustained (roughly 1,000 agents at a 60 s heartbeat plus results and events). Larger fleets need a
  longer heartbeat or a code change.
- **A hub restart clears the nonce store.** Replay is still bounded: a captured request is only acceptable while its timestamp is within `max_skew_sec`, so after a restart an attacker can
  replay a captured request for at most about 5 minutes, and only if they hold a capture (which TLS prevents unless TLS is broken or terminated by the attacker).
- Clock drift above 300 s makes an endpoint's requests fail with 408; keep NTP healthy.
- Replay protection does not replace TLS; it limits what a captured header set is worth.

## 6. Audit log: what it guarantees and what it does not

The `audit_log` table records actor, action, target and a JSON `meta`. The code only ever inserts into it.

**Guarantees (v1):**

- Each security-relevant hub action writes a row with a UTC timestamp. Actors: `telegram:<id>`, `system`, `device:<hostname>`.
- Rows recorded: `command.issue` (Telegram), `command.dispatch` (heartbeat delivered it), `command.result`, `command.timeout` (aggregate count), `enroll` (including re-enroll),
  `heartbeat.config_change` (a device reporting a different hostname), `event.ingest` (new, non-deduplicated events), `remove.request`, `remove.confirm`, and `auth.reject`
  (bad bearer, bad or stale timestamp, replayed nonce, cache full, unknown route, wrong method, oversized or invalid body, enroll conflict, non-admin Telegram message or button).
- Secrets are never written to `meta` (the bearer value is not stored, only the reason code).

**Does not guarantee:**

- **Not tamper-proof.** It is append-only by convention. Anyone with write access to `hub.db` (SYSTEM or Administrators on the hub, or a backup holder) can edit or delete rows. There is no hash chain, signature, or
  remote forwarding.
- Gaps are possible: audit writes for rejects are best-effort and swallow errors; read-only Telegram commands (`/devices`, `/events`, `/audit`) are not audited; successful heartbeats are not audited;
  `event.ack` is defined but nothing writes it in v1.
- There is no retention or size limit, and each unauthenticated reject writes a row with no rate limit. A scanner hitting port 8443 can grow the database. Restrict who can reach the port at the firewall where possible.
- It records the claimed hostname and source IP; neither is proof of identity (see 2.2).

For stronger evidence, ship `hub.log` and periodic `hub.db` backups to write-once storage.

## 7. Secrets handling

- **At rest:** `shared_secret` and `telegram.bot_token` are plain text in `hub.config.json`; `shared_secret` is plain text in each `agent.config.json`. Protection is the file ACL.
  `C:\ProgramData\SCGuardian` is locked to SYSTEM and Administrators (inheritance removed, via `Initialize-ScgSecureDirectory` and the installers), `hub.config.json` gets a locked ACL in `install-hub.ps1`.
  Local administrators can read them. Keep backups under the same ACL.
- **In logs:** every log line passes `Protect-Secret`, which replaces the configured secrets with `***` and also masks `Bearer <value>` and Telegram token patterns. The HTTP layer and the agent mask
  exception text before logging or returning it. Clients get only a generic `internal error` on a 500.
- **In the installer:** `SHAREDSECRET` is a hidden MSI property (masked in the MSI log) and `install.log` masks it. The value is visible in the process command line during install. The
  Intune app command and the GPO share both expose it to their administrators.
- **In the repository:** the config templates contain only `REPLACE_ME` placeholders; the hub refuses to start with a placeholder secret or token. Never commit real values.
- **Legacy modes** (`-Mode Harden`, `Monitor`, `Controller` ...) keep their own token in the script's CONFIG block or in `SCGuardian.config.json`. Hub and agent modes ignore it. Do not put a real
  token in a script you distribute.

## 8. Moving to stronger authentication

### 8.1 Per-device tokens (smaller change, recommended first)

1. Amend the contracts first (field dictionary, API registry, module interfaces): new fields for the token, a new migration (for example `devices.token_hash`).
2. Keep a shared **enrollment** secret, used only for `/enroll`, ideally short-lived.
3. On enroll, the hub generates a random 32-byte device token, stores only its hash (SHA-256), and returns the token once in the `/enroll` response. The agent saves it in
   `agent.config.json` (ACL protected).
4. All other endpoints use `Authorization: Bearer <device token>` plus the device id; the hub looks up the hash and compares in constant time. One compromised endpoint then exposes only itself.
5. Re-enrolling an existing hostname requires admin approval in Telegram (new command) instead of being automatic. This closes the offline-hostname takeover (2.4).
6. Revocation: set the device to `quarantined` (the status already exists in the schema and Telegram icons, but no code sets it yet) and reject its token.
7. Per-device rotation becomes possible without an outage: the hub returns a new token in a heartbeat response and the agent switches after acknowledging it.
8. Roll out in two phases: the hub accepts both the shared secret and tokens; once every agent has a token, disable the shared secret for all but `/enroll`.

### 8.2 Mutual TLS (stronger, needs a PKI)

1. Run a private CA (for example Active Directory Certificate Services) and issue a machine certificate per endpoint through GPO auto-enrollment or Intune SCEP into `LocalMachine\My`.
2. Hub: enable client certificate negotiation on the HTTP.sys binding (`netsh http add sslcert ... clientcertnegotiation=enable`), read the client certificate in the listener, validate the chain
   against your CA (and revocation), and map the certificate subject or thumbprint to a device row. Add this as a new step before the bearer check in `HttpServer.psm1`.
3. Agent: `Invoke-HubApi` (the sole HTTP client) attaches the client certificate to the `HttpWebRequest`; add a config key naming the certificate.
4. Keep `trusted_server_thumbprint` for server pinning; mTLS authenticates the client, pinning authenticates the server.
5. Pilot with a device group, make mTLS mandatory, then drop the shared secret.

Either path needs contract amendments in `docs/contracts/` before code changes, and a new Pester suite for the auth step.

## 9. Known v1 limitations

| # | Limitation | Impact / mitigation |
|---|---|---|
| 1 | One fleet-wide shared secret; no dual-secret rotation | section 2; rotation is a planned short outage |
| 2 | Hub is a single point of failure (one process, one SQLite file, no HA) | during an outage there are no commands or events; local watchdogs keep protecting; back up regularly |
| 3 | No result retry queue | if `/result` fails the agent only logs it; the command ends as `timeout` on the hub although it may have run |
| 4 | Commands expire after `command_timeout_sec` (300 s), also while still `pending` | commands for offline hosts are lost, not queued |
| 5 | Each command is delivered once | a heartbeat response lost in transit loses the command (it times out) |
| 6 | Nonce store in memory, capped at 10,000, not configurable; cleared on restart | section 5 |
| 7 | `defaults.max_workers` and `defaults.http_timeout_sec` appear in the field dictionary but the hub does not read them | the listener uses 8 workers, a 32-request in-flight cap and a 15 s timeout |
| 8 | Hub config is read at start only | restart the hub task after every change; pending `/remove` confirmations are lost |
| 9 | Events are stored but not pushed to Telegram; no acknowledge flow | check `/events` or the panel; `event.ack` is unused |
| 10 | No retention for `events`, `commands`, `audit_log` | prune manually; see `docs/OPERATIONS.md` |
| 11 | Audit log is not tamper-proof; unauthenticated rejects write a row each | section 6 |
| 12 | Device identity is the hostname; the device id is not bound to the caller | cloned or renamed machines collide; see 2.2 and 2.4 |
| 13 | Hub compromise controls the fleet, including the allow-list the agents obey | section 2.3 |
| 14 | `trusted_server_thumbprint` is not pushable and pins the leaf certificate | renewals that change the certificate need a fleet update |
| 15 | Clock dependence: skew over 300 s means 408 | keep time sync healthy |
| 16 | `quarantined` device status exists but nothing sets or enforces it | reserved for per-device credentials |
| 17 | Hub and agent target Windows PowerShell 5.1; the tasks run scripts with `-ExecutionPolicy Bypass` | keep `C:\Program Files\SCGuardian` writable by Administrators only |
| 18 | The TLS `netsh` application id in `HttpServer.psm1` differs from the one in `cert-setup.ps1` | cosmetic inconsistency; keep `listen.cert_thumbprint` aligned with the bound certificate |
