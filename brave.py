from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterable
from pathlib import Path

# Release channels: stable, beta, dev, nightly
_CHANNELS = ("", " Beta", " Dev", " Nightly")


def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _first_existing(paths: Iterable[Path], *, executable: bool = False) -> Path | None:
    for path in paths:
        if (_is_executable(path) if executable else path.exists()):
            return path
    return None


def _find_windows() -> Path | None:
    import winreg

    # 1. Registry "App Paths" entry: covers custom install locations.
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe"
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "")
        except OSError:
            continue
        if value and Path(value).is_file():
            return Path(value)

    # 2. Default install directories. Skip env vars that aren't set
    #    (expandvars would leave a literal "%VAR%" in the path).
    candidates = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
        root = os.environ.get(var)
        if not root:
            continue
        for channel in _CHANNELS:
            folder = "Brave-Browser" + channel.replace(" ", "-")
            candidates.append(
                Path(root) / "BraveSoftware" / folder / "Application" / "brave.exe"
            )
    return _first_existing(candidates, executable=True)


def _find_macos() -> Path | None:
    roots = (Path("/Applications"), Path.home() / "Applications")
    candidates = [
        root / f"Brave Browser{channel}.app" for root in roots for channel in _CHANNELS
    ]
    # .app bundles are directories, so don't use the file/executable check.
    return _first_existing(candidates)


def _find_linux() -> Path | None:
    names = ["brave-browser", "brave", "brave-browser-stable"]
    names += [f"brave-browser{c.lower().replace(' ', '-')}" for c in _CHANNELS if c]
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)

    # Locations that are often missing from PATH (snap, flatpak, /opt).
    candidates = [
        Path("/opt/brave.com/brave/brave-browser"),
        Path("/opt/brave.com/brave/brave"),
        Path("/snap/bin/brave"),
        Path("/var/lib/flatpak/exports/bin/com.brave.Browser"),
        Path.home() / ".local/share/flatpak/exports/bin/com.brave.Browser",
    ]
    return _first_existing(candidates, executable=True)


def find_brave() -> Path | None:
    """Return the path to a Brave install, or None if not found."""
    if sys.platform == "win32":
        return _find_windows()
    if sys.platform == "darwin":
        return _find_macos()
    if sys.platform.startswith("linux"):
        return _find_linux()
    return None


def check() -> bool:
    """Return True if Brave appears to be installed."""
    return find_brave() is not None


if __name__ == "__main__":
    path = find_brave()
    print(f"Brave found at: {path}" if path else "Brave not found")