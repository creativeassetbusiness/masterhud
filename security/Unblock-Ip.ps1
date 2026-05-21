param(
  [Parameter(Mandatory=$true)]
  [string]$Ip
)

Get-NetFirewallRule -DisplayName "MasterHUD AutoBlock $Ip" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName "MasterHUD ManualBlock $Ip" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Unblocked $Ip"
