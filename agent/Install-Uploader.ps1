# Streamlined Vault pilot installer. Inspect before running on a pilot machine.
# Requires elevation and a machine-accessible Python 3.10+ installation.
# Does not purchase, download or silently install third-party software.
#Requires -RunAsAdministrator
#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$Portal,
    [Parameter(Mandatory=$true)][string[]]$Source,
    [string]$PythonPath = (Get-Command python.exe -ErrorAction Stop).Source
)
$ErrorActionPreference='Stop'
if ($Portal -notmatch '^https://[^/]+/?$') { throw 'Use the HTTPS portal origin.' }
foreach ($folder in $Source) {
    if ($folder.StartsWith('\\') -or -not [IO.Path]::IsPathRooted($folder) -or -not (Test-Path -LiteralPath $folder -PathType Container)) { throw 'Choose existing local absolute folders; network shares are not supported by this pilot installer.' }
}
$PythonPath=(Resolve-Path -LiteralPath $PythonPath).Path
$programPrefix=[IO.Path]::GetFullPath([Environment]::GetFolderPath('ProgramFiles')).TrimEnd('\')+'\'
if (-not $PythonPath.StartsWith($programPrefix,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($PythonPath) -ne 'python.exe') { throw 'Use a machine-wide Python installation in Program Files. Running a user-writable Python executable as SYSTEM is not permitted.' }
& $PythonPath -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10 or newer is required.' }
$installRoot=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Streamlined Vault Uploader'
$stateRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'StreamlinedVault'
foreach ($target in @($installRoot,$stateRoot)) {
    if (Get-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue) { throw 'An installation directory already exists. Review it before installing or re-enrolling; existing directories are never reused.' }
}
New-Item -ItemType Directory -Path $installRoot,$stateRoot | Out-Null
# Protect both executable files and local metadata before writing credentials.
foreach ($folder in @($installRoot,$stateRoot)) {
    & (Join-Path ([Environment]::GetFolderPath('System')) 'icacls.exe') $folder /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to protect uploader folder permissions.' }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'vault_agent.py'),(Join-Path $PSScriptRoot 'schedule.py') -Destination $installRoot -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../tools/vault-uploader.py') -Destination (Join-Path $installRoot 'vault_transfer.py') -Force
$agentPath=Join-Path $installRoot 'vault_agent.py'
$configPath=Join-Path $stateRoot 'config.json'
$enrollment=Read-Host 'Paste the one-time Streamlined Vault enrollment credential' -AsSecureString
# Credential travels through stdin, not shell interpolation or command-line arguments.
$enrollArgs=@($agentPath,'enroll','--portal',$Portal,'--config',$configPath)
foreach($folder in $Source){$enrollArgs+=@('--source',$folder)}
try {
    $plain=[Net.NetworkCredential]::new('',$enrollment).Password
    $plain | & $PythonPath @enrollArgs
    $enrollExit=$LASTEXITCODE
} finally { $plain=$null;$enrollment=$null }
if ($enrollExit -ne 0) { throw 'Enrollment failed; no scheduled task was installed.' }
$action=New-ScheduledTaskAction -Execute $PythonPath -Argument ('"{0}" run --config "{1}"' -f $agentPath,$configPath) -WorkingDirectory $installRoot
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'Streamlined Vault Uploader' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Uploads enrolled local folders to Streamlined Vault on the configured schedule.' | Out-Null
Start-ScheduledTask -TaskName 'Streamlined Vault Uploader'
Write-Output 'Streamlined Vault Uploader enrolled and scheduled. Confirm device contact in the portal.'
