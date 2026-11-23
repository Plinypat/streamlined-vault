param([string]$OutputDirectory='C:/Users/patri/Documents/Codex/2026-10-20/a/outputs')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$build=Join-Path $root 'data/installer-build-env'
if(-not(Test-Path -LiteralPath (Join-Path $build 'Scripts/python.exe'))){python -m venv $build;if($LASTEXITCODE -ne 0){throw 'Build environment creation failed'}}
$python=Join-Path $build 'Scripts/python.exe'
& $python -m pip install 'pyinstaller==6.22.3'
if($LASTEXITCODE -ne 0){throw 'Installer build dependency installation failed'}
$stage=Join-Path $root ('data/pilot-payload-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
$runtime=Join-Path $root 'data/python-3.14.10-embed-amd64.zip'
if(-not(Test-Path -LiteralPath $runtime)){Invoke-WebRequest 'https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip' -OutFile $runtime}
$expected='90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'
if((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw 'Official Python runtime hash mismatch'}
Copy-Item -LiteralPath $runtime -Destination (Join-Path $stage 'python-runtime.zip')
Copy-Item -LiteralPath (Join-Path $root 'agent/vault_agent.py'),(Join-Path $root 'agent/schedule.py') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'tools/vault-uploader.py') -Destination (Join-Path $stage 'vault_transfer.py')
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
& $python -m PyInstaller --noconfirm --onedir --windowed --uac-admin --name Streamlined-Vault-Pilot-Setup --distpath $OutputDirectory --workpath (Join-Path $root 'data/installer-work') --specpath (Join-Path $root 'data') --add-data ($stage+';payload') (Join-Path $root 'agent/pilot_installer.py')
if($LASTEXITCODE -ne 0){throw 'Pilot executable build failed'}
$package=Join-Path $OutputDirectory 'Streamlined-Vault-Pilot-Setup'
$exe=Join-Path $package 'Streamlined-Vault-Pilot-Setup.exe'
(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()+'  Streamlined-Vault-Pilot-Setup.exe' | Set-Content -LiteralPath ($exe+'.sha256')
Copy-Item -LiteralPath (Join-Path $root 'docs/SORSKI-PILOT.md') -Destination (Join-Path $package 'READ-ME-FIRST.txt')
$zip=Join-Path $OutputDirectory 'Streamlined-Vault-Pilot-Installer.zip'
Compress-Archive -LiteralPath $package -DestinationPath $zip -Force
(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()+'  Streamlined-Vault-Pilot-Installer.zip' | Set-Content -LiteralPath ($zip+'.sha256')
Write-Output $zip
