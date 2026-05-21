# Security Monitoring Checklist

## Watch Every Day

- Security Watch hot alerts in MasterHUD.
- Alert Trail entries in MasterHUD, especially repeated hot signals after cooldown.
- Reboot Readiness before and after Windows updates or provider restarts.
- Security Coverage missing/limited layers in MasterHUD.
- New listening ports, especially `22`, `135`, `139`, `445`, `3389`, `5985`, `5986`, and non-loopback app ports.
- Failed logon bursts, account lockouts, new users, and Administrators group changes.
- New scheduled tasks, startup commands, or services you do not recognize.
- Processes running from `Temp`, `Downloads`, `ProgramData`, or unexpected user profile paths.
- Defender real-time protection, signature age, and scan age.
- Workload drift: missing/moved service executable, app directory, entrypoint, config, logs, or package files.
- Caddy access logs for repeated 404/401/403 bursts, strange user agents, and probes for `.env`, `.git`, `wp-admin`, `phpmyadmin`, or backup files.

## Detection Layers To Keep Improving

- File integrity hashing is now active for workload anchor files; expand it only after deciding which folders should be trusted baselines.
- Caddy/app log anomaly parsing is now active for known service logs; tune thresholds as traffic patterns become clear.
- Uptime/TLS checks now run from this server; add an outside monitor for true internet-vantage checks.
- Sysmon/EDR detection is monitored; install Sysmon or enable an EDR if the HUD reports this layer as missing.
- Backup freshness checks are active; add explicit restore-drill report files for true restore verification.
- Dependency audit monitoring is active; required LLM tooling should be reviewed instead of removed blindly.
- Alert delivery outside the server, such as email, SMS, Slack, or another machine, so alerts still arrive if the server UI is unavailable.
- Local response actions are active in MasterHUD; keep the HUD bound to `127.0.0.1` unless you add authentication and TLS.

## Lock Down First

- Restrict RDP to a VPN or fixed trusted IPs.
- Keep SMB/file sharing closed to the internet.
- Keep Postgres and Node app ports bound to localhost unless there is a deliberate reason.
- Use Caddy as the only public web entry point on `80` and `443`.
- Keep WinRM loopback-only or VPN-only.
- Rotate secrets after any suspected exposure.
- Keep service accounts least-privileged; avoid running app services as `LocalSystem` where possible.
- Apply the same security headers to every public site.
- Keep `npm audit --omit=dev` clean for production dependencies.

## If You Suspect A Hack

- Preserve evidence first: do not delete logs.
- Disconnect public access or firewall the host if active compromise is likely.
- Check Security Watch, Windows Security log, Caddy logs, app security logs, startup entries, services, scheduled tasks, and Administrators group membership.
- Rotate app secrets, database passwords, admin passwords, API keys, and backup encryption keys from a trusted machine.
- Review recent file changes and redeploy from known-good source.
- Assume secrets stored in service environment variables are compromised if an attacker gained admin access.

## Strong Baseline

- Public: only `80` and `443`.
- Admin: RDP/SSH/WinRM only through VPN or trusted IP.
- Database: localhost only.
- Apps: localhost behind Caddy.
- Backups: encrypted, tested restore, separate credentials.
- Logs: retained long enough to investigate.
- MFA: enabled wherever the provider supports it.
