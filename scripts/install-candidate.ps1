# Staged, opt-in installation. Requires a reviewed SOURCE_MANIFEST.json.
# No queue Action is executed as a health probe. Existing venv/source/config stay intact.
param(
    [string]$CandidateSource = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallRoot = 'C:\GPT-Controller',
    [string]$Python = '',
    [string]$RuntimeTask = 'GPT Controller Runtime',
    [string]$InteractiveTask = 'GPT Controller Interactive Host',
    [switch]$Activate,
    [switch]$AcknowledgeDesktopValidationPending
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Activation is supported on Windows only.' }
$CandidateSource = (Resolve-Path -LiteralPath $CandidateSource).Path
$configPath = Join-Path $InstallRoot 'agent.config.json'
if (-not (Test-Path -LiteralPath $configPath)) {
    throw 'An enrolled installation is required. This script will not invent a control repository or erase existing data.'
}
$configBytes = [IO.File]::ReadAllBytes($configPath)
$config = [Text.Encoding]::UTF8.GetString($configBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
$manifestPath = Join-Path $CandidateSource 'SOURCE_MANIFEST.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.base_commit -ne '90a6f329ea99ade3f08bc377936f3daf43a02774') { throw 'Unexpected candidate provenance.' }
if (@($manifest.files.PSObject.Properties).Count -lt 61) { throw 'Incomplete source manifest.' }
$releaseId = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant().Substring(0,20)
$releaseRoot = Join-Path (Join-Path $InstallRoot 'releases') $releaseId
$releaseSource = Join-Path $releaseRoot 'source'
$receiptPath = Join-Path $releaseRoot 'stage-receipt.json'
$maintenance = Join-Path $InstallRoot 'state\maintenance.lock'
$current = [Security.Principal.WindowsIdentity]::GetCurrent()

function Test-SameWindowsIdentity {
    param([string]$Principal, [Security.Principal.WindowsIdentity]$Identity)
    if ($null -eq $Identity -or $null -eq $Identity.User -or [string]::IsNullOrWhiteSpace($Principal)) { return $false }
    try {
        if ($Principal -match '^S-[0-9]-') {
            $sid = New-Object Security.Principal.SecurityIdentifier($Principal)
        } else {
            $account = New-Object Security.Principal.NTAccount($Principal)
            $sid = $account.Translate([Security.Principal.SecurityIdentifier])
        }
        return ($sid.Value -eq $Identity.User.Value)
    } catch { return $false }
}

function Invoke-Checked {
    param([string]$Program, [string[]]$Argv)
    & $Program @Argv
    if ($LASTEXITCODE -ne 0) { throw "Native command failed with exit code $LASTEXITCODE. Candidate was not activated." }
}
function Check-Tree {
    param([string]$Root)
    foreach ($entry in $manifest.files.PSObject.Properties) {
        $relative = [string]$entry.Name
        if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative -match ':') { throw 'Unsafe manifest path.' }
        $path = Join-Path $Root $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing candidate file: $relative" }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne [string]$entry.Value) { throw "Candidate content hash mismatch: $relative" }
    }
}
Check-Tree $CandidateSource
$existing = Get-ScheduledTask -TaskName $RuntimeTask -ErrorAction SilentlyContinue
if (-not $existing) { throw 'Runtime task is not enrolled. No new identity or credentials will be assumed.' }
$principal = [string]$existing.Principal.UserId
if (-not (Test-SameWindowsIdentity -Principal $principal -Identity $current)) {
    throw 'Runtime identity differs from this account. SYSTEM/another-user migration requires separate enrollment and is not automatic.'
}
if ($Activate) {
    $admin = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this reviewed activation command in an elevated PowerShell. No automatic UAC bypass is attempted.'
    }
    if ($config.interaction_policy.allow_physical_input -and -not $AcknowledgeDesktopValidationPending) {
        throw 'This candidate has no author-verified Windows desktop acceptance. Test on a dedicated environment; explicit acknowledgement is required before enabling this existing intrusive configuration.'
    }
}
if ([string]::IsNullOrWhiteSpace($Python)) { $Python = Join-Path $InstallRoot 'venv\Scripts\python.exe' }
Invoke-Checked $Python @('-c','import sys; assert sys.version_info >= (3,11), sys.version')
if (-not (Test-Path -LiteralPath $receiptPath)) {
    if (Test-Path -LiteralPath $releaseRoot) { throw "Incomplete staging directory is preserved at $releaseRoot; inspect it rather than overwriting it." }
    New-Item -ItemType Directory -Path $releaseSource -Force | Out-Null
    foreach ($entry in $manifest.files.PSObject.Properties) {
        $target = Join-Path $releaseSource $entry.Name
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath (Join-Path $CandidateSource $entry.Name) -Destination $target
    }
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $releaseSource 'SOURCE_MANIFEST.json')
    Check-Tree $releaseSource
    Invoke-Checked $Python @('-m','venv',(Join-Path $releaseRoot 'venv'))
    $candidatePython = Join-Path $releaseRoot 'venv\Scripts\python.exe'
    Invoke-Checked $candidatePython @('-m','pip','install',"${releaseSource}[all]")
    Invoke-Checked $candidatePython @('-m','playwright','install','chromium')
    $oldPlugins = $env:PYTEST_DISABLE_PLUGIN_AUTOLOAD
    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
        $env:PYTHONPATH = Join-Path $releaseSource 'src'
        Push-Location $releaseSource
        try {
            $verificationRoot = Join-Path $releaseRoot 'verification'
            Invoke-Checked $candidatePython @((Join-Path $releaseSource 'scripts\run-verification.py'),'--root',$releaseSource,'--output',$verificationRoot)
            $verificationStatus = Get-Content -LiteralPath (Join-Path $verificationRoot 'status.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($verificationStatus.status -ne 'passed' -or $verificationStatus.coverage_complete -ne $true -or $verificationStatus.source_unchanged -ne $true) {
                throw 'Candidate verification is incomplete or does not match the tested source.'
            }
            if ($verificationStatus.skipped -gt 0) { throw 'Candidate staging requires every Windows test, including real Chromium; inspect skipped tests.' }
        }
        finally { Pop-Location }
    } finally {
        $env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = $oldPlugins
        $env:PYTHONPATH = $oldPythonPath
    }
    # Git and config only. Do not probe an old, unsigned Interactive Host with new IPC.
    Invoke-Checked $candidatePython @('-m','agent_runtime.hardening.cli','--config',$configPath,'doctor','--no-ui','--require-git')
    & $candidatePython -m pip freeze | Set-Content -LiteralPath (Join-Path $releaseRoot 'requirements-frozen.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'Cannot record candidate dependency versions.' }
    @{ release_id=$releaseId; staged_at=[DateTimeOffset]::UtcNow.ToString('o'); tests='passed'; verification_run_id=$verificationStatus.run_id; verification_status_sha256=(Get-FileHash -LiteralPath (Join-Path $verificationRoot 'status.json') -Algorithm SHA256).Hash.ToLowerInvariant(); activated=$false } |
        ConvertTo-Json | Set-Content -LiteralPath $receiptPath -Encoding UTF8
}
Check-Tree $releaseSource
$candidatePython = Join-Path $releaseRoot 'venv\Scripts\python.exe'
$pythonw = Join-Path $releaseRoot 'venv\Scripts\pythonw.exe'
if (-not $Activate) {
    Write-Host "Staged only: $releaseRoot"
    Write-Host 'Existing tasks, configuration, source, venv and PC permissions were not changed.'
    exit 0
}

$backup = Join-Path (Join-Path $InstallRoot 'backups') (Get-Date -Format 'yyyyMMdd-HHmmss-ffff')
New-Item -ItemType Directory -Force -Path $backup | Out-Null
[IO.File]::WriteAllBytes((Join-Path $backup 'agent.config.json'),$configBytes)
$taskNames = @($RuntimeTask,$InteractiveTask,"$RuntimeTask Watchdog","$InteractiveTask Watchdog")
$taskBackups = @()
foreach ($name in $taskNames) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) {
        $xml = Export-ScheduledTask -TaskName $name
        $xml | Set-Content -LiteralPath (Join-Path $backup "$name.xml") -Encoding UTF8
        $taskBackups += @{ Name=$name; Xml=$xml; WasRunning=($task.State -eq 'Running') }
    }
}
$control = [Environment]::ExpandEnvironmentVariables([string]$config.control_repo)
if (@(Get-ChildItem -LiteralPath (Join-Path $control 'queue\running') -Filter '*.json' -ErrorAction SilentlyContinue).Count -gt 0) {
    throw 'A claimed Action exists. Finish/inspect it before updating; this installer will not discard or replay it.'
}
if (@(Get-ChildItem -LiteralPath (Join-Path $control 'queue\pending') -Filter '*.json' -ErrorAction SilentlyContinue).Count -gt 0) {
    throw 'Pending Actions exist. Drain the queue and stop external producers before activation.'
}
$spool = [Environment]::ExpandEnvironmentVariables([string]$config.interactive_host.spool)
foreach ($folder in @('requests','processing')) {
    if (@(Get-ChildItem -LiteralPath (Join-Path $spool $folder) -Filter '*.json' -ErrorAction SilentlyContinue).Count -gt 0) {
        throw 'An Interactive Host request is pending or processing. Resolve it before activation.'
    }
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $maintenance) | Out-Null
"candidate=$releaseId" | Set-Content -LiteralPath $maintenance -Encoding UTF8
$activationStarted = [DateTimeOffset]::UtcNow
$changed = $false
try {
    $changed = $true # Restorable state begins before stopping/disabling any task.
    foreach ($name in @("$RuntimeTask Watchdog","$InteractiveTask Watchdog")) {
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Disable-ScheduledTask -TaskName $name | Out-Null
            Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        }
    }
    foreach ($name in @($InteractiveTask,$RuntimeTask)) { Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    # Match live process identity/command, not an arbitrary PID read from old heartbeat.
    Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and $_.CommandLine -match 'agent_runtime' -and $_.CommandLine.Contains($configPath)
    } | ForEach-Object { & taskkill.exe /PID $_.ProcessId /T /F *> $null }
    $remaining = @(Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and $_.CommandLine -match 'agent_runtime' -and $_.CommandLine.Contains($configPath)
    })
    if ($remaining.Count -gt 0) { throw 'Old process termination was not confirmed.' }
    if (@(Get-ChildItem -LiteralPath (Join-Path $control 'queue\running') -Filter '*.json' -ErrorAction SilentlyContinue).Count -gt 0) {
        throw 'A claim appeared during activation. Stop and inspect it; do not replay it.'
    }
    $action = New-ScheduledTaskAction -Execute $pythonw -Argument "-m agent_runtime --config `"$configPath`"" -WorkingDirectory $InstallRoot
    $limited = New-ScheduledTaskPrincipal -UserId $current.Name -LogonType Interactive -RunLevel Limited
    Set-ScheduledTask -TaskName $RuntimeTask -Action $action -Principal $limited | Out-Null
    $hasHost = [bool](Get-ScheduledTask -TaskName $InteractiveTask -ErrorAction SilentlyContinue)
    if ($hasHost) {
        $hostAction = New-ScheduledTaskAction -Execute $pythonw -Argument "-m agent_runtime.interactive_host --config `"$configPath`"" -WorkingDirectory $InstallRoot
        # Retain the explicit locally chosen host level; never enable input permissions here.
        Set-ScheduledTask -TaskName $InteractiveTask -Action $hostAction | Out-Null
    }
    $systemPwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $runtimeHeartbeat = Join-Path (Join-Path (Split-Path -Parent $control) 'state') "$($config.agent_id)-runtime-heartbeat.json"
    foreach ($pair in @(@($RuntimeTask,$runtimeHeartbeat),@($InteractiveTask,(Join-Path $spool 'host-heartbeat.json')))) {
        $name = [string]$pair[0]
        $watchdog = "$name Watchdog"
        if (Get-ScheduledTask -TaskName $watchdog -ErrorAction SilentlyContinue) {
            $arguments = "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Join-Path $releaseSource 'scripts\watchdog-task.ps1')`" -TaskName `"$name`" -InstallRoot `"$InstallRoot`" -HeartbeatPath `"$($pair[1])`" -MaintenancePath `"$maintenance`""
            Set-ScheduledTask -TaskName $watchdog -Action (New-ScheduledTaskAction -Execute $systemPwsh -Argument $arguments -WorkingDirectory $InstallRoot) | Out-Null
        }
    }
    if ($hasHost) { Start-ScheduledTask -TaskName $InteractiveTask }
    Start-ScheduledTask -TaskName $RuntimeTask
    $healthy = $false
    $deadline = (Get-Date).AddSeconds(60)
    do {
        if (Test-Path -LiteralPath $runtimeHeartbeat) {
            try {
                $heartbeat = Get-Content -LiteralPath $runtimeHeartbeat -Raw -Encoding UTF8 | ConvertFrom-Json
                $stamp = if ($heartbeat.updated_at -is [DateTime]) { ([DateTimeOffset]$heartbeat.updated_at).ToUniversalTime() } else { [DateTimeOffset]::Parse([string]$heartbeat.updated_at).ToUniversalTime() }
                if ($stamp -ge $activationStarted -and $heartbeat.runtime_extension -eq '4.1.0rc2' -and
                    $heartbeat.source_path -like "$releaseRoot\*" -and
                    (Get-Process -Id ([int]$heartbeat.pid) -ErrorAction SilentlyContinue)) { $healthy=$true; break }
            } catch {}
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    if (-not $healthy) { throw 'Candidate did not report its own live version heartbeat.' }
    $healthArguments = @('-m','agent_runtime.hardening.cli','--config',$configPath,'doctor','--require-git')
    if ($hasHost) { $healthArguments += '--require-ui' } else { $healthArguments += '--no-ui' }
    Invoke-Checked $candidatePython $healthArguments
    # The checked source is immutable. Selector is an audit record, not an arbitrary executable path.
    @{ release_id=$releaseId; source=$releaseSource; activated_at=[DateTimeOffset]::UtcNow.ToString('o'); previous_backup=$backup } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $InstallRoot 'active-release.json') -Encoding UTF8
    Write-Host "Activated candidate $releaseId. Previous environment retained at its original path; task/config backup: $backup"
} catch {
    if ($changed) {
        foreach ($name in @($InteractiveTask,$RuntimeTask)) { Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue }
        # Prevent the old host from interpreting new signed requests as fresh old-format work.
        foreach ($folder in @('requests','processing','responses')) {
            $from = Join-Path $spool $folder
            $to = Join-Path (Join-Path $backup 'ipc-evidence') $folder
            New-Item -ItemType Directory -Force -Path $to | Out-Null
            Get-ChildItem -LiteralPath $from -Filter '*.json' -ErrorAction SilentlyContinue |
                ForEach-Object { Move-Item -LiteralPath $_.FullName -Destination (Join-Path $to $_.Name) }
        }
        [IO.File]::WriteAllBytes($configPath,$configBytes)
        foreach ($saved in $taskBackups) { Register-ScheduledTask -TaskName $saved.Name -Xml $saved.Xml -Force | Out-Null }
        foreach ($saved in $taskBackups) { if ($saved.WasRunning) { Start-ScheduledTask -TaskName $saved.Name } }
    }
    throw
} finally {
    Remove-Item -LiteralPath $maintenance -Force -ErrorAction SilentlyContinue
    foreach ($saved in $taskBackups) {
        # XML backup preserves original enablement; only re-enable originally enabled watchdogs.
        if ($saved.Name.EndsWith(' Watchdog') -and ([xml]$saved.Xml).Task.Settings.Enabled -eq 'true') {
            Enable-ScheduledTask -TaskName $saved.Name -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
