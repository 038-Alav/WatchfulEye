from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def get_user_data_directory() -> Path:
    """Return a per-user writable directory for inventory and application logs.

    On Windows this uses LOCALAPPDATA so an installed application never
    attempts to write mutable JSON files into Program Files.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "WatchfulEye"
        return Path.home() / "AppData" / "Local" / "WatchfulEye"

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "WatchfulEye"

    base = os.environ.get("XDG_DATA_HOME")
    if base:
        return Path(base) / "watchful-eye"
    return Path.home() / ".local" / "share" / "watchful-eye"


def migrate_legacy_data(source_directory: str | Path, target_directory: str | Path) -> list[str]:
    """Copy known JSON stores from the old project-local data folder once.

    Existing per-user files always win. This preserves developer inventories
    when upgrading from releases that wrote data beside the source tree.
    """
    source = Path(source_directory)
    target = Path(target_directory)
    if not source.is_dir():
        return []

    target.mkdir(parents=True, exist_ok=True)
    migrated: list[str] = []
    for filename in ("devices.json", "scans.json", "observations.json", "events.json"):
        old_file = source / filename
        new_file = target / filename
        if old_file.is_file() and not new_file.exists():
            shutil.copy2(old_file, new_file)
            migrated.append(filename)
    return migrated
