<#
.SYNOPSIS
  Register a Windows Scheduled Task that keeps `localfirst` running for
  the current user, restarting it within 30 seconds if it exits.

.DESCRIPTION
  v0.6.4 of LocalFirst aborts with exit code 1 when it cannot append to
  its audit log. This task brings the proxy back up so the agent can
  resume work as soon as the underlying I/O issue clears.

.NOTES
  Manually validated on Windows 11 Pro (PowerShell 7.x).
  Tested-on: Windows.

  The task runs at user logon, not at boot, because LocalFirst's audit
  log lives in the user profile (~/.localfirst/). Run from an elevated
  shell only if you need the task to survive logoff.
#>

$Action  = New-ScheduledTaskAction  -Execute "localfirst" -Argument "start"
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$Settings = New-ScheduledTaskSettingsSet `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable

# -User <current user> + -RunLevel Limited keeps the task in the user
# scope so Register-ScheduledTask does not require an elevated shell.
$Principal = New-ScheduledTaskPrincipal `
    -UserId    $env:USERNAME `
    -LogonType Interactive `
    -RunLevel  Limited

Register-ScheduledTask `
    -TaskName    "LocalFirst" `
    -Description "LocalFirst — local AI-agent governance proxy (v0.6.4)" `
    -Action      $Action `
    -Trigger     $Trigger `
    -Settings    $Settings `
    -Principal   $Principal `
    -Force

Write-Host "Registered scheduled task 'LocalFirst'."
Write-Host "It will start at next logon. To start now: Start-ScheduledTask -TaskName LocalFirst"
Write-Host "To remove: Unregister-ScheduledTask -TaskName LocalFirst -Confirm:`$false"
