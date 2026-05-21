param(
  [Parameter(Mandatory=$true)]
  [string]$Ip
)

$ruleName = "MasterHUD ManualBlock $Ip"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $Ip -Profile Any | Out-Null
}
Write-Host "Blocked $Ip"
