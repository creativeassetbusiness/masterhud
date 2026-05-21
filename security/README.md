# MasterHUD Security Tools

These scripts protect management access without requiring your home IP to be stable.

## What Is Installed

- `Watch-FailedLogons.ps1`: blocks remote IPs that repeatedly fail Windows logon attempts.
- `Set-ManagementAllowIp.ps1`: emergency mode to restrict RDP/SSH to one IP, optionally your current public IP.
- `Reset-ManagementFirewall.ps1`: resets MasterHUD-created management allow/block rules.
- `Block-Ip.ps1`: manually block a hostile IP.
- `Unblock-Ip.ps1`: remove a manual or automatic block.
- `Ensure-AutoBoot.ps1`: re-applies boot startup and service recovery settings for MasterHUD and the app services.
- `Apply-DefenderForEndpointOnboarding.ps1`: applies the official Microsoft Defender for Endpoint local onboarding package.
- `Test-DefenderForEndpointStatus.ps1`: checks the local Defender for Endpoint sensor and onboarding state.

## Normal Use

The scheduled task `MasterHUD-FailedLogonBlocker` runs every 5 minutes as SYSTEM. It watches Security event `4625` and blocks remote IPs that cross the threshold.

Copy `allowlist.example.txt` to `allowlist.txt` if you need to protect trusted public IPs from automatic blocking. `allowlist.txt` is intentionally ignored by Git.

## Emergency Use

From your provider web console, you can run:

```powershell
$Root = "C:\apps\MasterHUD"
powershell -ExecutionPolicy Bypass -File "$Root\security\Set-ManagementAllowIp.ps1" -CurrentPublicIp
```

Or set an exact IP:

```powershell
$Root = "C:\apps\MasterHUD"
powershell -ExecutionPolicy Bypass -File "$Root\security\Set-ManagementAllowIp.ps1" -Ip 203.0.113.10
```

To reset MasterHUD-created allow rules:

```powershell
$Root = "C:\apps\MasterHUD"
powershell -ExecutionPolicy Bypass -File "$Root\security\Reset-ManagementFirewall.ps1"
```

## Repair Auto-Boot

If a reboot ever leaves monitoring or app services offline, run this from the provider web console:

```powershell
$Root = "C:\apps\MasterHUD"
powershell -ExecutionPolicy Bypass -File "$Root\security\Ensure-AutoBoot.ps1"
```

To also set recovery settings for client app services, pass their service names:

```powershell
$Root = "C:\apps\MasterHUD"
powershell -ExecutionPolicy Bypass -File "$Root\security\Ensure-AutoBoot.ps1" -ServiceNames CaddyProxy,ExampleWebsite,postgresql-x64-17
```

## Microsoft Defender for Endpoint

The `Sense` EDR sensor is built into this Windows Server version, but it needs your tenant-specific Microsoft onboarding package before it can run.

1. Open `https://security.microsoft.com/securitysettings/endpoints/onboarding`.
2. Select Windows Server 2019, 2022, and 2025.
3. Select Local script and download `WindowsDefenderATPOnboardingPackage.zip`.
4. Put the zip in this folder, the Desktop, or Downloads.
5. Run:

```powershell
$Root = "C:\apps\MasterHUD"
powershell -ExecutionPolicy Bypass -File "$Root\security\Apply-DefenderForEndpointOnboarding.ps1" -PackagePath C:\Path\To\WindowsDefenderATPOnboardingPackage.zip
```

Then verify:

```powershell
$Root = "C:\apps\MasterHUD"
powershell -ExecutionPolicy Bypass -File "$Root\security\Test-DefenderForEndpointStatus.ps1"
```
