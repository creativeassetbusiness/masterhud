# MasterHUD

MasterHUD is a local Windows server dashboard for managing small website VPS fleets without installing a full monitoring stack.

It is designed to stay bound to `127.0.0.1` and be opened through the server console, RDP, or a trusted tunnel. Do not expose it directly to the public internet unless you add authentication and TLS.

## Run

```powershell
npm start
```

Then open:

```text
http://127.0.0.1:3927
```

Optional knobs:

```powershell
$env:PORT=3999
$env:SAMPLE_MS=3000
npm start
```

## Configure Client Profiles

For a single-server install, copy the example config and edit it:

```powershell
Copy-Item .\masterhud.config.example.json .\masterhud.config.json
notepad .\masterhud.config.json
```

`masterhud.config.json` is intentionally ignored by Git because it contains client-specific domains, local paths, and service names.

For multi-client work, use local profiles instead:

```powershell
New-Item -ItemType Directory -Force .\profiles
Copy-Item .\profiles\client.example.json .\profiles\client-a.json
notepad .\profiles\client-a.json
```

Then select the profile from the Operator Console, or preselect one by creating `data\active-profile.json`:

```json
{
  "profile": "client-a"
}
```

Profile files are ignored by Git except `*.example.json`, so every VPS can keep its own client paths, domains, services, and quick links while sharing the same public MasterHUD code.

Useful config fields:

- `publicUrls`: public sites to check for uptime and TLS expiry.
- `expectedWorkloads`: app folders to include in drift, backup, and dependency checks.
- `managedServices`: allow-listed Windows services shown in the Operator Console.
- `requiredServices` and `requiredPorts`: reboot-readiness expectations.
- `appRoot`, `healthUrl`, `caddyConfigPath`: app-specific diagnostic actions.
- `quickLinks`: buttons shown in the Operator Console.

## What It Watches

- CPU pressure and per-sample history
- Memory pressure
- Disk read/write throughput, queue pressure, and volume free space
- Network receive/send throughput
- Top processes by accumulated CPU
- TCP listening ports and owning processes
- Automatic running services
- Detected app workloads from Windows service metadata
- Drift checks for service images, app directories, Node entrypoints, package files, Caddyfile, logs, and git metadata
- Enabled scheduled tasks and startup commands
- Recent System/Application warnings and errors
- Optimization radar focused on no-quality-loss wins
- Alert trail with local dedupe and optional webhook delivery through `data/alerts-config.json`
- Reboot readiness for the app services, MasterHUD boot tasks, and expected listeners
- Local operator console with quick app links, IP block/unblock, blocked-IP review, allow-listed service start/restart, app health, Caddy config validation, optional client-defined readiness verification, failed-logon blocker run, HUD refresh, and forced security scan
- Security history in `data/history.jsonl` for trend review

## What Not To Commit

The following are runtime/local files and are ignored:

- `masterhud.config.json`
- `profiles/*.json` except `profiles/*.example.json`
- `data/*.json`, `data/*.jsonl`
- `security/allowlist.txt`
- Defender onboarding packages, logs, temp files, and zip files

## Practical No-Sacrifice Wins To Look For

- Repeated event log errors before changing random settings
- One process growing memory across hours
- Disk queue spikes when backups, logs, databases, and servers share the same drive
- Low free space on any server volume
- Unexpected public listening ports
- Services set to automatic that are unrelated to the server workload
- Workload drift where a service still exists but an expected app file, config, executable, or directory moved or disappeared

Run the HUD during normal idle time, then again during peak server use. The difference between those two views is where the real optimization work starts.

For compromise monitoring and hardening priorities, see [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md).
