$ErrorActionPreference = "Stop"

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This script must run on Windows. PyInstaller cannot cross-build a Windows executable from Linux or macOS."
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$VersionLine = Select-String -Path (Join-Path $ProjectRoot "pyproject.toml") -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $VersionLine) {
    throw "Could not read the project version from pyproject.toml."
}
$AppVersion = $VersionLine.Matches[0].Groups[1].Value

$PythonLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($PythonLauncher) {
    & py -3.12 --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Python 3.12 is required. Install Python 3.12 and run this script again."
    }
    $PythonCommand = "py"
    $PythonPrefix = @("-3.12")
} else {
    $PythonCommand = "python"
    $PythonPrefix = @()
    & python --version
    if ($LASTEXITCODE -ne 0) {
        throw "Python 3.12 is required. Install it and run this script again."
    }
}

# Migrate pre-installer development data before packaging. Never overwrite
# files that already exist in the per-user application data directory.
$LegacyDataDirectory = Join-Path $ProjectRoot "data"
$UserDataDirectory = Join-Path $env:LOCALAPPDATA "WatchfulEye\data"
if (Test-Path $LegacyDataDirectory) {
    New-Item -ItemType Directory -Force $UserDataDirectory | Out-Null
    foreach ($FileName in @("devices.json", "scans.json", "observations.json", "events.json")) {
        $OldFile = Join-Path $LegacyDataDirectory $FileName
        $NewFile = Join-Path $UserDataDirectory $FileName
        if ((Test-Path $OldFile -PathType Leaf) -and -not (Test-Path $NewFile)) {
            Copy-Item $OldFile $NewFile
            Write-Host "Migrated $FileName to $UserDataDirectory"
        }
    }
}

$BuildVenv = Join-Path $ProjectRoot ".venv-build"
if (-not (Test-Path $BuildVenv)) {
    & $PythonCommand @PythonPrefix -m venv $BuildVenv
    if ($LASTEXITCODE -ne 0) { throw "Could not create the build virtual environment." }
}

$BuildPython = Join-Path $BuildVenv "Scripts\python.exe"
& $BuildPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Could not upgrade pip in the build environment." }
& $BuildPython -m pip install -e ".[build]"
if ($LASTEXITCODE -ne 0) { throw "Could not install Watchful Eye build dependencies." }

# Start from a clean PyInstaller output so stale files cannot leak into the installer.
$BuildDirectory = Join-Path $ProjectRoot "build\pyinstaller"
$DistDirectory = Join-Path $ProjectRoot "dist\WatchfulEye"
if (Test-Path $BuildDirectory) { Remove-Item $BuildDirectory -Recurse -Force }
if (Test-Path $DistDirectory) { Remove-Item $DistDirectory -Recurse -Force }

& $BuildPython -m PyInstaller --noconfirm --clean --workpath $BuildDirectory --distpath (Join-Path $ProjectRoot "dist") (Join-Path $ProjectRoot "packaging\WatchfulEye.spec")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

$Executable = Join-Path $DistDirectory "WatchfulEye.exe"
if (-not (Test-Path $Executable)) {
    throw "PyInstaller finished without producing $Executable"
}

$InnoCandidates = @()
$Command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($Command) { $InnoCandidates += $Command.Source }
if (${env:ProgramFiles(x86)}) { $InnoCandidates += (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe") }
if ($env:ProgramFiles) { $InnoCandidates += (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe") }
$ISCC = $InnoCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ISCC) {
    throw "The application bundle was built at $DistDirectory, but Inno Setup 6 was not found. Install Inno Setup 6, then rerun this script to create the installer."
}

& $ISCC "/DAppVersion=$AppVersion" (Join-Path $ProjectRoot "packaging\WatchfulEye.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }

$Installer = Join-Path $ProjectRoot "dist\installer\WatchfulEye-Setup-$AppVersion.exe"
if (-not (Test-Path $Installer)) { throw "Installer output was not created: $Installer" }

Write-Host ""
Write-Host "Build completed successfully." -ForegroundColor Green
Write-Host "Application: $DistDirectory"
Write-Host "Installer:   $Installer" -ForegroundColor Green
Write-Host "User data will be stored under %LOCALAPPDATA%\WatchfulEye and is not removed by the uninstaller."
