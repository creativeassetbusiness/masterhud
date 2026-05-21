param(
  [string[]]$ServiceNames = @(),
  [string]$MasterHudRoot = ""
)

$ErrorActionPreference = "Stop"
if (-not $MasterHudRoot) {
  $MasterHudRoot = Split-Path -Parent $PSScriptRoot
}

function Ensure-ServiceAutoStart {
  param([string]$Name)

  $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
  if (-not $service) {
    Write-Warning "Service not found: $Name"
    return
  }

  Set-Service -Name $Name -StartupType Automatic
  sc.exe failure $Name reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
  sc.exe failureflag $Name 1 | Out-Null

  $fresh = Get-CimInstance Win32_Service -Filter "Name='$Name'"
  [pscustomobject]@{
    Type = "Service"
    Name = $fresh.Name
    DisplayName = $fresh.DisplayName
    State = $fresh.State
    StartMode = $fresh.StartMode
  }
}

function Ensure-MasterHudTask {
  param([string]$Root)

  $node = (Get-Command node.exe).Source
  $action = New-ScheduledTaskAction -Execute $node -Argument "server.js" -WorkingDirectory $Root
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1)

  Register-ScheduledTask -TaskName "MasterHUD" -Description "Starts the local MasterHUD monitoring dashboard on boot." -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Get-ScheduledTask -TaskName "MasterHUD" | Select-Object @{Name="Type";Expression={"Task"}}, TaskName, State
}

function Ensure-FailedLogonBlockerTask {
  param([string]$Root)

  $script = Join-Path $Root "security\Watch-FailedLogons.ps1"
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -WindowMinutes 30 -Threshold 10 -BlockHours 1"
  $startupTrigger = New-ScheduledTaskTrigger -AtStartup
  $repeatTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3)

  Register-ScheduledTask -TaskName "MasterHUD-FailedLogonBlocker" -Description "Blocks remote IPs that repeatedly fail Windows logon attempts." -Action $action -Trigger @($startupTrigger, $repeatTrigger) -Principal $principal -Settings $settings -Force | Out-Null
  Get-ScheduledTask -TaskName "MasterHUD-FailedLogonBlocker" | Select-Object @{Name="Type";Expression={"Task"}}, TaskName, State
}

$results = @()
foreach ($serviceName in $ServiceNames) {
  $results += Ensure-ServiceAutoStart -Name $serviceName
}
$results += Ensure-MasterHudTask -Root $MasterHudRoot
$results += Ensure-FailedLogonBlockerTask -Root $MasterHudRoot

$results
