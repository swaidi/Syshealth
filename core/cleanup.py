"""Cleanup: temporary files, caches, Recycle Bin, old downloads and empty folders."""
from __future__ import annotations

import glob
import os
import shutil
import stat
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .safety import is_protected_dir, running_browsers
from .platform_utils import (IS_WINDOWS, Cancelled, NeedsAdmin, human_size, is_admin, is_protected,
                             powershell, run_cmd, run_stream, wrap_privileged)

LogFn = Optional[Callable[[str], None]]
JUNK_NAMES = {"desktop.ini", "thumbs.db", ".ds_store"}


@dataclass
class Category:
    id: str
    title: str
    description: str
    patterns: list[str] = field(default_factory=list)  # folders (contents removed) or glob patterns of files
    older_than_hours: float = 0
    admin: bool = False
    clean_cmd: Optional[list[list[str]]] = None       # command-based clean (e.g. apt-get clean)
    size_fn: Optional[Callable[[], tuple[int, int]]] = None
    clean_fn: Optional[Callable[[LogFn, Optional[threading.Event]], tuple[int, int]]] = None


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _expand(patterns: list[str]) -> list[str]:
    out = []
    for p in patterns:
        out.extend(glob.glob(p) if any(ch in p for ch in "*?[") else ([p] if os.path.exists(p) else []))
    return out


def _iter_files(targets: list[str], older_than_hours: float, cancel=None):
    cutoff = time.time() - older_than_hours * 3600
    for t in targets:
        if os.path.isfile(t):
            try:
                st = os.lstat(t)
                if st.st_mtime <= cutoff or older_than_hours == 0:
                    yield t, st.st_size
            except OSError:
                pass
            continue
        for dp, dirs, files in os.walk(t, onerror=lambda e: None):
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            for f in files:
                p = os.path.join(dp, f)
                try:
                    st = os.lstat(p)
                    if not stat.S_ISREG(st.st_mode):  # never touch sockets, pipes or links
                        continue
                    if older_than_hours == 0 or st.st_mtime <= cutoff:
                        yield p, st.st_size
                except OSError:
                    continue


def _browser_cache_patterns() -> list[str]:
    if IS_WINDOWS:
        local = _env("LOCALAPPDATA")
        pats = []
        for vendor in (r"Google\Chrome", r"Microsoft\Edge", r"BraveSoftware\Brave-Browser"):
            base = os.path.join(local, vendor, "User Data", "*")
            pats += [os.path.join(base, "Cache"), os.path.join(base, "Code Cache"), os.path.join(base, "GPUCache")]
        pats.append(os.path.join(local, r"Mozilla\Firefox\Profiles\*\cache2"))
        return pats
    home = os.path.expanduser("~")
    return [os.path.join(home, ".cache", "google-chrome"), os.path.join(home, ".cache", "chromium"),
            os.path.join(home, ".cache", "mozilla", "firefox", "*", "cache2"),
            os.path.join(home, ".cache", "BraveSoftware")]


def _recycle_size() -> tuple[int, int]:
    total, count = 0, 0
    if IS_WINDOWS:
        import psutil
        for part in psutil.disk_partitions(all=False):
            for _, size in _iter_files(glob.glob(os.path.join(part.mountpoint, "$Recycle.Bin", "*")), 0):
                total += size
                count += 1
    else:
        for _, size in _iter_files([os.path.expanduser("~/.local/share/Trash")], 0):
            total += size
            count += 1
    return total, count


def _recycle_clean(log: LogFn, cancel) -> tuple[int, int]:
    size, count = _recycle_size()
    if IS_WINDOWS:
        powershell("Clear-RecycleBin -Force -ErrorAction SilentlyContinue")
    else:
        for sub in ("files", "info"):
            d = os.path.expanduser(f"~/.local/share/Trash/{sub}")
            if os.path.isdir(d):
                for name in os.listdir(d):
                    p = os.path.join(d, name)
                    shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) and not os.path.islink(p) else \
                        _safe_remove(p)
    if log:
        log(f"Emptied the Recycle Bin ({human_size(size)}).")
    return size, count


def _safe_remove(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except OSError:
        return False


def categories() -> list[Category]:
    cats: list[Category] = []
    if IS_WINDOWS:
        local, root = _env("LOCALAPPDATA"), _env("SystemRoot", r"C:\Windows")
        pdata = _env("ProgramData", r"C:\ProgramData")
        cats += [
            Category("user_temp", "Temporary files (user)", "Files left behind by programs. Older than 24 hours.",
                     [tempfile.gettempdir()], 24),
            Category("win_temp", "Temporary files (Windows)", "System temporary folder. Older than 24 hours.",
                     [os.path.join(root, "Temp")], 24, admin=True),
            Category("wu_cache", "Windows Update downloads", "Installer files of updates already applied.",
                     [os.path.join(root, "SoftwareDistribution", "Download")], 24, admin=True),
            Category("thumbs", "Thumbnail cache", "Preview images; Windows rebuilds them when needed.",
                     [os.path.join(local, r"Microsoft\Windows\Explorer\thumbcache_*.db")], 0),
            Category("crash", "Crash dumps and error reports", "Diagnostic files from application crashes.",
                     [os.path.join(local, "CrashDumps"), os.path.join(local, r"Microsoft\Windows\WER\ReportArchive"),
                      os.path.join(local, r"Microsoft\Windows\WER\ReportQueue")], 0),
            Category("crash_sys", "System crash dumps and reports", "Blue-screen dumps and system error reports.",
                     [os.path.join(root, "Minidump"), os.path.join(pdata, r"Microsoft\Windows\WER\ReportArchive"),
                      os.path.join(pdata, r"Microsoft\Windows\WER\ReportQueue")], 0, admin=True),
            Category("browser", "Browser caches", "Chrome, Edge, Brave and Firefox caches. Skipped while a browser is open.",
                     _browser_cache_patterns(), 0),
        ]
    else:
        home = os.path.expanduser("~")
        cats += [
            Category("user_temp", "Temporary files", "Your files in /tmp and /var/tmp older than 24 hours.",
                     ["/tmp", "/var/tmp"], 24),
            Category("thumbs", "Thumbnail cache", "Preview images; rebuilt when needed.",
                     [os.path.join(home, ".cache", "thumbnails")], 0),
            Category("browser", "Browser caches", "Chrome, Chromium, Brave and Firefox caches. Skipped while a browser is open.",
                     _browser_cache_patterns(), 0),
            Category("app_cache", "Application caches", "Other files in ~/.cache older than 7 days.",
                     [p for p in glob.glob(os.path.join(home, ".cache", "*")) if os.path.basename(p) not in
                      ("thumbnails", "google-chrome", "chromium", "mozilla", "BraveSoftware")], 24 * 7),
        ]
        if shutil.which("apt-get"):
            cats.append(Category("apt", "Package download cache", "Downloaded .deb installers (apt-get clean).",
                                 ["/var/cache/apt/archives/*.deb"], 0, admin=True,
                                 clean_cmd=[["apt-get", "clean"]]))
        if shutil.which("journalctl"):
            cats.append(Category("journal", "Old system logs", "System journal entries older than 14 days.",
                                 [], 0, admin=True, clean_cmd=[["journalctl", "--vacuum-time=14d"]],
                                 size_fn=_journal_size))
    cats.append(Category("recycle", "Recycle Bin" if IS_WINDOWS else "Trash",
                         "Files you deleted earlier. This permanently removes them.",
                         size_fn=_recycle_size, clean_fn=_recycle_clean))
    return cats


def _journal_size() -> tuple[int, int]:
    rc, out = run_cmd(["journalctl", "--disk-usage"])
    import re
    m = re.search(r"([\d.]+)\s*([KMGT])", out)
    if not m:
        return 0, 0
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2)]
    return int(float(m.group(1)) * mult), 0


def analyze(cat: Category, cancel=None) -> tuple[int, int]:
    if cat.size_fn:
        return cat.size_fn()
    total, count = 0, 0
    for _, size in _iter_files(_expand(cat.patterns), cat.older_than_hours, cancel):
        total += size
        count += 1
    return total, count


def clean(cat: Category, log: LogFn, cancel=None) -> tuple[int, int]:
    """Returns (bytes freed, files removed). Files in use are skipped."""
    if cat.clean_fn:
        return cat.clean_fn(log, cancel)
    if cat.clean_cmd:
        size, count = analyze(cat)
        cmd = cat.clean_cmd[0] if is_admin() else wrap_privileged(cat.clean_cmd)
        rc, _ = run_stream(cmd, log, cancel)
        return (size, count) if rc == 0 else (0, 0)
    if cat.admin and IS_WINDOWS and not is_admin():
        raise NeedsAdmin(cat.title)
    if cat.id == "browser":
        open_now = running_browsers()
        if open_now:  # clearing a running browser's cache can break pages and extensions
            if log:
                log(f"Browser caches skipped: close {', '.join(open_now)} first, then run the cleanup again.")
            return 0, 0
    freed, removed = 0, 0
    targets = _expand(cat.patterns)
    for path, size in list(_iter_files(targets, cat.older_than_hours, cancel)):
        if _safe_remove(path):
            freed += size
            removed += 1
    for t in targets:  # remove folders left empty inside the cleaned locations (never the location itself)
        if os.path.isdir(t):
            for dp, dirs, files in os.walk(t, topdown=False, onerror=lambda e: None):
                if dp != t:
                    try:
                        os.rmdir(dp)
                    except OSError:
                        pass
    if log:
        log(f"{cat.title}: removed {removed:,} files, freed {human_size(freed)}.")
    return freed, removed


# --------------------------------------------------------------------------- old downloads
def downloads_folder() -> str:
    home = os.path.expanduser("~")
    if IS_WINDOWS:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
                val = winreg.QueryValueEx(k, "{374DE290-123F-4565-9164-39C4925E467B}")[0]
                return os.path.expandvars(val)
        except OSError:
            pass
    return os.path.join(home, "Downloads")


def old_files(folder: str, days: int, cancel=None) -> list[tuple[str, int, float]]:
    cutoff = time.time() - days * 86400
    out = []
    from .duplicates import is_program_dir
    for dp, dirs, files in os.walk(folder, onerror=lambda e: None):
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        # never offer files of installed or portable programs (for example Tor Browser in Downloads)
        dirs[:] = [d for d in dirs if not is_protected_dir(os.path.join(dp, d))
                   and not is_program_dir(os.path.join(dp, d), d)]
        if is_protected_dir(dp):
            continue
        for f in files:
            p = os.path.join(dp, f)
            try:
                st = os.stat(p)
            except OSError:
                continue
            last_used = max(st.st_mtime, st.st_atime) if not IS_WINDOWS else st.st_mtime
            if last_used < cutoff:
                out.append((p, st.st_size, st.st_mtime))
    return sorted(out, key=lambda t: t[1], reverse=True)


# --------------------------------------------------------------------------- empty folders
def _inside_app_data(path: str) -> bool:
    from .safety import protected_reason
    return protected_reason(path) is not None


def _is_junk_only(names: list[str]) -> bool:
    return all(n.lower() in JUNK_NAMES for n in names)


def empty_folders(roots: list[str], cancel=None) -> list[str]:
    """Folders containing nothing (or only desktop.ini / Thumbs.db / .DS_Store), deepest first."""
    empty: set[str] = set()
    result: list[str] = []
    for root in roots:
        for dp, dirs, files in os.walk(root, topdown=False, onerror=lambda e: None):
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            if dp == root or is_protected(dp) or os.path.islink(dp) or _inside_app_data(dp):
                continue
            if _is_junk_only(files) and all(os.path.join(dp, d) in empty for d in dirs):
                empty.add(dp)
                result.append(dp)
    return result


def remove_empty_folders(folders: list[str], log: LogFn) -> tuple[int, list[str]]:
    removed, errors = 0, []
    for d in sorted(folders, key=lambda p: p.count(os.sep), reverse=True):
        if _inside_app_data(d):
            errors.append(f"{d}: left unchanged because it is application data")
            continue
        try:
            for name in os.listdir(d):
                p = os.path.join(d, name)
                if os.path.isfile(p) and name.lower() in JUNK_NAMES:
                    os.remove(p)
            os.rmdir(d)
            removed += 1
        except OSError as exc:
            errors.append(f"{d}: {exc}")
    if log:
        log(f"Removed {removed} empty folder(s).")
    return removed, errors
