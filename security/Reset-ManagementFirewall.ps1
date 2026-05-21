Get-NetFirewallRule -DisplayName "MasterHUD Allow Management *" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Removed MasterHUD management allow rules. Existing non-MasterHUD firewall rules were not changed."
