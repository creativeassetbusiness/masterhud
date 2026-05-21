param(
  [Parameter(Mandatory=$true)]
  [string]$PackagePath,

  [switch]$DisableSampleCollection
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
  }
}

function Get-MdeStatus {
  $sense = Get-Service -Name Sense -ErrorAction SilentlyContinue
  $statusKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue
  [pscustomobject]@{
    SenseInstalled = [bool]$sense
    SenseStatus = if ($sense) { [string]$sense.Status } else { "missing" }
    SenseStartType = if ($sense) { [string]$sense.StartType } else { "missing" }
    OnboardingState = $statusKey.OnboardingState
    OrgId = $statusKey.OrgId
    LastConnected = $statusKey.LastConnected
  }
}

Assert-Admin

$resolvedPackage = Resolve-Path -LiteralPath $PackagePath
if ($resolvedPackage.ProviderPath -notmatch "\.zip$") {
  throw "Expected a WindowsDefenderATPOnboardingPackage.zip file."
}

$workRoot = Join-Path $PSScriptRoot "mde-onboarding"
if (Test-Path -LiteralPath $workRoot) {
  Remove-Item -LiteralPath $workRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
Expand-Archive -LiteralPath $resolvedPackage.ProviderPath -DestinationPath $workRoot -Force

$script = Get-ChildItem -LiteralPath $workRoot -Filter "WindowsDefenderATPLocalOnboardingScript.cmd" -Recurse |
  Select-Object -First 1
if (-not $script) {
  throw "The package did not contain WindowsDefenderATPLocalOnboardingScript.cmd."
}

if ($DisableSampleCollection) {
  $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
  New-Item -Path $policyPath -Force | Out-Null
  New-ItemProperty -Path $policyPath -Name "AllowSampleCollection" -Value 0 -PropertyType DWord -Force | Out-Null
}

$before = Get-MdeStatus
Push-Location $script.DirectoryName
try {
  & cmd.exe /c "`"$($script.FullName)`""
  $exitCode = $LASTEXITCODE
} finally {
  Pop-Location
}

Start-Sleep -Seconds 15
$after = Get-MdeStatus

[pscustomobject]@{
  Ok = ($exitCode -eq 0 -and $after.SenseStatus -eq "Running")
  ExitCode = $exitCode
  Package = $resolvedPackage.ProviderPath
  Script = $script.FullName
  Before = $before
  After = $after
  NextCheck = "Confirm the device appears in Microsoft Defender portal > Assets > Devices."
} | ConvertTo-Json -Depth 5
