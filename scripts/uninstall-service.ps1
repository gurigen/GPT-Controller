param([string]$TaskName = 'GPT Controller Runtime')
$ErrorActionPreference = 'Stop'
# Retire the watchdog first so it cannot race uninstall and restart the host.
foreach ($name in @("$TaskName Watchdog", $TaskName)) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
}
Write-Host "Removed task and watchdog: $TaskName. User data and evidence were preserved."
