# Windows installer build

The supported Windows distribution is a PyInstaller **onedir** bundle wrapped
in an Inno Setup installer. The installer places application binaries under
Program Files. Mutable inventory, scan history, observations, and logs are
stored separately under `%LOCALAPPDATA%\WatchfulEye`.

## Prerequisites

- Windows 10/11 x64.
- Python 3.12 (64-bit).
- Inno Setup 6.
- Npcap installed separately for Windows packet operations. Npcap is not
  bundled by this project; the installer warns when its compatibility DLLs are
  not found.

## Build

From the project root in PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\build_windows_installer.ps1
```

The script copies any legacy project-local JSON stores into `%LOCALAPPDATA%`
when matching destination files do not already exist, creates a dedicated
`.venv-build`, installs the project's `build` extra, packages the GUI and its
runtime dependencies, then invokes Inno Setup.
Outputs:

- `dist\WatchfulEye\WatchfulEye.exe` and its onedir runtime files.
- `dist\installer\WatchfulEye-Setup-0.2.0.exe` (version follows `pyproject.toml`).

The first build requires internet access to install Python packages. If the
application bundle is created but Inno Setup is not found, install Inno Setup 6
and rerun the script; the PyInstaller step will be repeated cleanly.

## Data migration

The installer does not bundle or overwrite a developer's `data` directory.
A development upgrade copies existing `devices.json`, `scans.json`,
`observations.json`, and `events.json` files into the new user data directory
on first launch when the destination files do not already exist. For a new
installed copy, the application reads and writes its user data under
`%LOCALAPPDATA%\WatchfulEye\data`. Existing development data can be copied
there manually after closing the application:

```powershell
$Source = Join-Path (Get-Location) "data"
$Destination = Join-Path $env:LOCALAPPDATA "WatchfulEye\data"
New-Item -ItemType Directory -Force $Destination | Out-Null
Copy-Item "$Source\*.json" $Destination -Force
```

The uninstaller removes installed application files but deliberately leaves
this user data directory untouched.
