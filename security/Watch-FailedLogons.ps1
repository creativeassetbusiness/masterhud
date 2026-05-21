param(
  [int]$WindowMinutes = 30,
  [int]$Threshold = 10,
  [int]$BlockHours = 1,
  [string]$StatePath = "",
  [string]$AllowListPath = ""
)

$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $PSScriptRoot
if (-not $StatePath) { $StatePath = Join-Path $root "data\blocked-logon-ips.json" }
if (-not $AllowListPath) { $AllowListPath = Join-Path $PSScriptRoot "allowlist.txt" }

function Test-PublicIp {
  param([string]$Ip)
  if (-not $Ip) { return $false }
  if ($Ip -in @("127.0.0.1", "::1", "-", "")) { return $false }
  if ($Ip -match "^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.)") { return $false }
  if ($Ip -match "^(fc|fd|fe80)") { return $false }
  return $Ip -match "^[0-9a-fA-F:\.]+$"
}

function Get-SourceIpFromMessage {
  param([string]$Message)
  $match = [regex]::Match($Message, "Source Network Address:\s+([^\r\n\s]+)")
  if ($match.Success) { return $match.Groups[1].Value.Trim() }
  return $null
}

New-Item -ItemType Directory -Force -Path (Split-Path $StatePath) | Out-Null

$allow = @()
if (Test-Path $AllowListPath) {
  $allow = Get-Content $AllowListPath | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
}

$state = @{}
if (Test-Path $StatePath) {
  try {
    $raw = Get-Content $StatePath -Raw | ConvertFrom-Json
    foreach ($entry in @($raw.blocked)) { $state[$entry.ip] = $entry }
  } catch {}
}

$cutoff = (Get-Date).AddMinutes(-1 * $WindowMinutes)
$events = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625; StartTime=$cutoff} -MaxEvents 500
$counts = @{}
foreach ($event in $events) {
  $ip = Get-SourceIpFromMessage $event.Message
  if ((Test-PublicIp $ip) -and ($allow -notcontains $ip)) {
    if (-not $counts.ContainsKey($ip)) { $counts[$ip] = 0 }
    $counts[$ip] += 1
  }
}

$now = Get-Date
foreach ($ip in @($state.Keys)) {
  $expires = [datetime]$state[$ip].expiresAt
  if ($expires -le $now) {
    Get-NetFirewallRule -DisplayName "MasterHUD AutoBlock $ip" | Remove-NetFirewallRule
    Get-NetFirewallRule -DisplayName "MasterHUD ManualBlock $ip" | Remove-NetFirewallRule
    $state.Remove($ip)
  }
}

foreach ($ip in $counts.Keys) {
  if ($counts[$ip] -lt $Threshold) { continue }
  $expiresAt = (Get-Date).AddHours($BlockHours)
  $ruleName = "MasterHUD AutoBlock $ip"
  if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
  }
  $state[$ip] = [pscustomobject]@{
    ip = $ip
    count = $counts[$ip]
    blockedAt = (Get-Date).ToUniversalTime().ToString("o")
    expiresAt = $expiresAt.ToUniversalTime().ToString("o")
  }
}

[pscustomobject]@{ blocked = @($state.Values) } | ConvertTo-Json -Depth 4 | Set-Content -Path $StatePath -Encoding UTF8
