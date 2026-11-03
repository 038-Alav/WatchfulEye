# PyInstaller onedir build for the Watchful Eye desktop application.
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_submodules

# PyInstaller exposes SPECPATH as the directory containing the spec file.
# Handle both directory and file forms to avoid accidentally resolving the
# project root one directory above the checkout.
_SPEC_LOCATION = Path(SPECPATH).resolve()
_SPEC_DIRECTORY = (
    _SPEC_LOCATION.parent if _SPEC_LOCATION.is_file() else _SPEC_LOCATION
)
PROJECT_ROOT = _SPEC_DIRECTORY.parent

if not (PROJECT_ROOT / "pyproject.toml").is_file():
    raise RuntimeError(
        "Could not locate Watchful Eye project root from SPECPATH: "
        f"{_SPEC_LOCATION}. Expected pyproject.toml at {PROJECT_ROOT}."
    )

PACKAGE_ENTRY = PROJECT_ROOT / "src" / "watchfuleye" / "__main__.py"
OUI_DATABASE = PROJECT_ROOT / "src" / "watchfuleye" / "data" / "oui.txt"

if not PACKAGE_ENTRY.is_file():
    raise FileNotFoundError(f"Application entry point not found: {PACKAGE_ENTRY}")
if not OUI_DATABASE.is_file():
    raise FileNotFoundError(f"Bundled OUI database not found: {OUI_DATABASE}")

sys.path.insert(0, str(PROJECT_ROOT / "src"))

hiddenimports = [
    "watchfuleye.main",
    "scapy.all",
    "scapy.layers.l2",
    "scapy.layers.inet",
    "scapy.layers.dhcp",
    "scapy.arch.windows",
    "scapy.arch.libpcap",
    "psutil._psutil_windows",
    "ifaddr",
]
hiddenimports += collect_submodules("zeroconf")

a = Analysis(
    [str(PACKAGE_ENTRY)],
    pathex=[str(PROJECT_ROOT / "src")],
    binaries=[],
    datas=[
        (
            str(OUI_DATABASE),
            "watchfuleye/data",
        ),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest"],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WatchfulEye",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="WatchfulEye",
)
