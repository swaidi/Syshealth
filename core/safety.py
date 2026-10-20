"""Protection for application data.

Programs keep their settings, sign-ins, passwords, extensions and databases in application-data folders
(AppData on Windows; hidden folders such as ~/.config, ~/.local and ~/.mozilla on Linux). Their files often
look like duplicates, junk or oddly named paths, but deleting or renaming them signs you out of browsers,
breaks extensions such as VPNs, or corrupts apps.

Every SysHealth feature that deletes, moves, renames or shreds user-chosen files checks paths here first.
The Cleanup page's junk categories are the only exception: they target known cache folders only.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Iterable, Optional

from .platform_utils import IS_WINDOWS, norm

# Folder names that always belong to a browser, password store or other sensitive app, wherever they are
# (portable browsers, Tor Browser inside Downloads, and so on).
SENSITIVE_DIR_NAMES = {"torbrowser", "user data", "keyrings", "password-store", "protonvpn", "proton vpn"}
# Files that mark a browser profile folder
PROFILE_MARKERS = ("Local State", "prefs.js", "places.sqlite", "cookies.sqlite", "key4.db", "logins.json",
                   "Login Data")
# Files or folders that mark a browser installed outside the usual places (Tor Browser in Downloads or on the
# Desktop, portable Firefox or Chromium)
INSTALL_MARKERS = ("TorBrowser", os.path.join("Browser", "TorBrowser"), "start-tor-browser.desktop",
                   "Start Tor Browser.lnk", "FirefoxPortable.exe", "ChromiumPortable.exe")
BROWSER_PROCESSES = {"chrome", "brave", "msedge", "firefox", "chromium", "opera", "vivaldi", "librewolf",
                     "tor", "torbrowser", "waterfox", "zen"}
APP_DATA_REASON = "it is application data (settings, sign-ins, passwords or extensions)"


@lru_cache(maxsize=1)
def _windows_roots() -> tuple[str, ...]:
    roots = [os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", ""),
             os.path.join(os.path.expanduser("~"), "AppData")]
    return tuple(norm(r) for r in roots if r)


@lru_cache(maxsize=1)
def _home() -> str:
    return norm(os.path.expanduser("~"))


@lru_cache(maxsize=20000)
def _dir_reason(folder: str) -> Optional[str]:
    """Reason why a folder (already normalized) holds protected app data, or None."""
    if IS_WINDOWS:
        if any(folder == r or folder.startswith(r + os.sep) for r in _windows_roots()):
            return APP_DATA_REASON
    else:
        home = _home()
        if folder.startswith(home + os.sep):
            rel = folder[len(home) + 1:].split(os.sep)
            # any hidden folder in the home tree (~/.config, ~/.local, ~/.mozilla, ~/.ssh, project/.git ...)
            if any(part.startswith(".") for part in rel) or rel[0] == "snap":
                return APP_DATA_REASON
    parts = folder.split(os.sep)
    if any(p.lower() in SENSITIVE_DIR_NAMES for p in parts):
        return "it belongs to a browser, password store or VPN"
    try:
        if any(os.path.exists(os.path.join(folder, m)) for m in PROFILE_MARKERS):
            return "it is a browser profile"
        if any(os.path.exists(os.path.join(folder, m)) for m in INSTALL_MARKERS):
            return "it is an installed or portable browser"
    except OSError:
        pass
    return None


def protected_reason(path: str) -> Optional[str]:
    """Why a file or folder must not be deleted, moved or renamed by SysHealth, or None if it may be."""
    p = norm(path)
    folder = p if os.path.isdir(p) else os.path.dirname(p)
    probe = folder
    for _ in range(40):  # the folder itself and every parent folder
        reason = _dir_reason(probe)
        if reason:
            return reason
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    return None


def is_protected_dir(path: str) -> bool:
    """Fast check used while scanning: skip this folder and everything inside it."""
    return _dir_reason(norm(path)) is not None


def split_allowed(paths: Iterable[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """(paths that may be changed, [(path, reason) that must be left alone])."""
    allowed, blocked = [], []
    for p in paths:
        reason = protected_reason(p)
        if reason:
            blocked.append((p, reason))
        else:
            allowed.append(p)
    return allowed, blocked


def running_browsers() -> list[str]:
    """Names of browsers that are open. Their caches must not be cleared while they run."""
    try:
        import psutil
    except ImportError:
        return []
    found = set()
    for proc in psutil.process_iter(["name"]):
        name = (proc.info.get("name") or "").lower()
        base = name[:-4] if name.endswith(".exe") else name
        if base in BROWSER_PROCESSES:
            found.add(base)
    return sorted(found)


def clear_cache() -> None:
    _dir_reason.cache_clear()
