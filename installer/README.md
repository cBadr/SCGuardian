# SCGuardian Agent installer

Build (needs WiX v4): `dotnet tool install --global wix` then `wix extension add --global WixToolset.Util.wixext`, then
`.\installer\build.ps1 -Version 4.0.0 -Configuration Release -OutputDir .\artifacts [-Bundle]`.

Install: `msiexec /i SCGuardian.Agent.msi /qn HUBURL=https://hub:8443 SHAREDSECRET=... [THUMBPRINT=...]`
or run `Setup.ps1` (prompts, installs silently, forces one heartbeat). Uninstall removes the task, keeps `C:\ProgramData\SCGuardian`.

Notes: SHAREDSECRET is Hidden (masked in the MSI log). The standard burn BA has no text fields, so the
bundle takes `HubUrl=` / `SharedSecret=` on its command line; use Setup.ps1 for prompts.
Exit codes of Install-Agent.ps1: 10 url, 11 secret, 12 config, 13 ACL, 14 task, 15 thumbprint, 20 remove.
