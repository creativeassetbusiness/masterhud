param(
  [string]$Ip,
  [switch]$CurrentPublicIp,
  [int[]]$Ports = @(22, 3389)
)

$ErrorActionPreference = "Stop"

if ($CurrentPublicIp) {
  $Ip = (Invoke-RestMethod "https://api.ipify.org").Trim()
}

if (-not $Ip) {
  throw "Provide -Ip x.x.x.x or -CurrentPublicIp."
}

Get-NetFirewallRule -DisplayName "MasterHUD Allow Management *" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

foreach ($port in $Ports) {
  New-NetFirewallRule `
    -DisplayName "MasterHUD Allow Management $port from $Ip" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort $port `
    -RemoteAddress $Ip `
    -Profile Any | Out-Null
}

Write-Host "Created management allow rules for $Ip on ports $($Ports -join ', ')."
Write-Host "Important: disable or narrow any older broad RDP/SSH allow rules if you want this to be exclusive."
