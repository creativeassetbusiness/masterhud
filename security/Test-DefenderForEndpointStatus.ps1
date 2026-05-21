$ErrorActionPreference = "SilentlyContinue"

$sense = Get-Service -Name Sense -ErrorAction SilentlyContinue
$windefend = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
$statusKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ErrorAction SilentlyContinue
$policyKey = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -ErrorAction SilentlyContinue
$recentSenseEvents = Get-WinEvent -FilterHashtable @{
  LogName = "Microsoft-Windows-SENSE/Operational"
  StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 20 -ErrorAction SilentlyContinue

[pscustomobject]@{
  DefenderAntivirus = if ($windefend) {
    [pscustomobject]@{ Installed = $true; Status = [string]$windefend.Status; StartType = [string]$windefend.StartType }
  } else {
    [pscustomobject]@{ Installed = $false; Status = "missing"; StartType = "missing" }
  }
  DefenderForEndpoint = if ($sense) {
    [pscustomobject]@{ Installed = $true; Status = [string]$sense.Status; StartType = [string]$sense.StartType }
  } else {
    [pscustomobject]@{ Installed = $false; Status = "missing"; StartType = "missing" }
  }
  OnboardingState = $statusKey.OnboardingState
  OrgId = $statusKey.OrgId
  LastConnected = $statusKey.LastConnected
  AllowSampleCollection = $policyKey.AllowSampleCollection
  RecentSenseEvents = @($recentSenseEvents | Select-Object TimeCreated, Id, ProviderName, Message)
  Onboarded = ($sense -and [string]$sense.Status -eq "Running" -and $statusKey.OnboardingState -eq 1)
} | ConvertTo-Json -Depth 5
