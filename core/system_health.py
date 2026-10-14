"""Operating-system health checks and repair actions."""
from __future__ import annotations

import os
import shutil
import tempfile
import time

import psutil

from .checks import FAIL, INFO, OK, WARN, Check, Fix
from .platform_utils import (IS_WINDOWS, Cancelled, human_size, is_admin, list_drives,
                             open_url_or_file, ps_json, run_cmd, win_system_exe)


def _temp_dirs() -> list[str]:
    dirs = [tempfile.gettempdir()]
    if IS_WINDOWS and is_admin():
        dirs.append(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"))
    if not IS_WINDOWS:
        dirs.append(os.path.expanduser("~/.cache/thumbnails"))
    return [d for d in dirs if os.path.isdir(d)]


def _dir_size(path: str, budget_s: float = 8) -> int:
    total, start = 0, time.time()
    for dp, _, files in os.walk(path, onerror=lambda e: None):
        for f in files:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
        if time.time() - start > budget_s:
            break
    return total


def _pending_reboot() -> bool:
    if IS_WINDOWS:
        import winreg
        keys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"]
        for k in keys:
            try:
                winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k))
                return True
            except OSError:
                continue
        return False
    return os.path.exists("/var/run/reboot-required")


# --------------------------------------------------------------------------- checks
def run_checks(log=None) -> list[Check]:
    checks: list[Check] = []

    cpu = psutil.cpu_percent(interval=1)
    checks.append(Check("CPU load", OK if cpu < 85 else WARN, f"{cpu:.0f}% in use."))

    mem = psutil.virtual_memory()
    checks.append(Check("Memory", OK if mem.percent < 85 else WARN,
                        f"{mem.percent:.0f}% used of {human_size(mem.total)}."))

    for drive in list_drives():
        try:
            u = psutil.disk_usage(drive)
        except OSError:
            continue
        free_pct = 100 - u.percent
        status = OK if free_pct >= 10 else (WARN if free_pct >= 5 else FAIL)
        checks.append(Check(f"Free space {drive}", status,
                            f"{human_size(u.free)} free of {human_size(u.total)} ({free_pct:.0f}%).",
                            None if status == OK else "clean_temp"))

    uptime_days = (time.time() - psutil.boot_time()) / 86400
    checks.append(Check("Uptime", OK if uptime_days < 14 else WARN,
                        f"{uptime_days:.1f} days since last restart" +
                        ("" if uptime_days < 14 else " - a restart is recommended.")))

    if _pending_reboot():
        checks.append(Check("Pending restart", WARN, "Updates are waiting for a restart."))
    else:
        checks.append(Check("Pending restart", OK, "No restart pending."))

    temp_total = sum(_dir_size(d) for d in _temp_dirs())
    checks.append(Check("Temporary files", WARN if temp_total > 1024 ** 3 else INFO,
                        f"{human_size(temp_total)} in temporary folders.",
                        "clean_temp" if temp_total > 200 * 1024 ** 2 else None))

    if IS_WINDOWS:
        rows = ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, "
                       "AntivirusSignatureAge")
        if rows:
            r = rows[0]
            if not r.get("RealTimeProtectionEnabled"):
                checks.append(Check("Antivirus protection", WARN,
                                    "Defender real-time protection is off (fine if another antivirus is active)."))
            else:
                age = r.get("AntivirusSignatureAge", 0) or 0
                checks.append(Check("Antivirus protection", OK if age <= 3 else WARN,
                                    f"Defender active; signatures {age} day(s) old."))
        rows = ps_json("Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | "
                       "Select-Object -First 1 HotFixID, @{n='Date';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}")
        if rows:
            date = rows[0].get("Date", "")
            try:
                days = (time.time() - time.mktime(time.strptime(date, "%Y-%m-%d"))) / 86400
            except ValueError:
                days = 0
            checks.append(Check("Windows Update", OK if days <= 45 else WARN,
                                f"Last update installed on {date}.", None if days <= 45 else "windows_update"))
        rows = ps_json("Get-CimInstance Win32_StartupCommand | Select-Object Name")
        checks.append(Check("Startup programs", INFO if len(rows) <= 15 else WARN,
                            f"{len(rows)} programs start with Windows."))
        checks.append(Check("System files", INFO, "Run 'Repair system files' to verify Windows component "
                            "integrity (takes 10-30 minutes).", "repair_system"))
    else:
        if shutil.which("systemctl"):
            rc, out = run_cmd(["systemctl", "--failed", "--no-legend", "--plain"])
            failed = [l.split()[0] for l in out.splitlines() if l.strip()] if rc == 0 else []
            if rc == 0:
                checks.append(Check("System services", OK if not failed else WARN,
                                    "All services running." if not failed else f"Failed: {', '.join(failed[:5])}",
                                    None if not failed else "reset_failed"))
        if shutil.which("journalctl"):
            rc, out = run_cmd(["journalctl", "-p", "3", "-b", "--no-pager", "-q"], timeout=60)
            n = len([l for l in out.splitlines() if l.strip()])
            checks.append(Check("Errors since boot", OK if n < 20 else WARN, f"{n} error entries in the system log."))
        if shutil.which("dpkg"):
            rc, out = run_cmd(["dpkg", "--audit"])
            checks.append(Check("Package integrity", OK if not out.strip() else FAIL,
                                "No broken packages." if not out.strip() else "Broken or half-installed packages.",
                                None if not out.strip() else "fix_packages"))
    return checks


# --------------------------------------------------------------------------- fixes
def _clean_temp(log, cancel):
    cutoff = time.time() - 24 * 3600
    freed, removed = 0, 0
    for root in _temp_dirs():
        if log:
            log(f"Cleaning {root}")
        for dp, dirs, files in os.walk(root, topdown=False, onerror=lambda e: None):
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            for f in files:
                p = os.path.join(dp, f)
                try:
                    st = os.lstat(p)
                    if st.st_mtime < cutoff:
                        os.remove(p)
                        freed += st.st_size
                        removed += 1
                except OSError:
                    continue  # in use or not owned
            if dp != root:
                try:
                    os.rmdir(dp)
                except OSError:
                    pass
    if log:
        log(f"Removed {removed:,} temporary files, freed {human_size(freed)}.")


def _windows_update(log, cancel):
    open_url_or_file("ms-settings:windowsupdate")
    if log:
        log("Opened Windows Update settings.")


def _disk_cleanup(log, cancel):
    import subprocess
    subprocess.Popen([win_system_exe("cleanmgr.exe")])
    if log:
        log("Opened Windows Disk Cleanup.")


def get_fixes() -> dict[str, Fix]:
    fixes = [Fix("clean_temp", "Clean temporary files",
                 "Deletes temporary files older than 24 hours. Files in use are skipped.", python_fn=_clean_temp)]
    if IS_WINDOWS:
        dism, sfc = win_system_exe("dism.exe"), win_system_exe("sfc.exe")
        fixes += [
            Fix("repair_system", "Repair system files (DISM + SFC)",
                "Repairs the Windows component store, then verifies and repairs system files. 15-45 minutes.",
                [[dism, "/Online", "/Cleanup-Image", "/RestoreHealth"], [sfc, "/scannow"]], admin=True),
            Fix("sfc", "System File Checker (SFC)", "Verifies and repairs protected Windows files.",
                [[sfc, "/scannow"]], admin=True),
            Fix("dism_check", "DISM quick health check", "Reports whether the component store is corrupted.",
                [[dism, "/Online", "/Cleanup-Image", "/CheckHealth"]], admin=True),
            Fix("dism_scan", "DISM full scan", "Scans the component store for corruption (no changes).",
                [[dism, "/Online", "/Cleanup-Image", "/ScanHealth"]], admin=True),
            Fix("windows_update", "Open Windows Update", "Opens Windows Update settings.", python_fn=_windows_update),
            Fix("disk_cleanup", "Open Disk Cleanup", "Launches the built-in Windows Disk Cleanup tool.",
                python_fn=_disk_cleanup),
        ]
    else:
        fixes += [
            Fix("reset_failed", "Reset failed services", "Clears the failed state so services can restart.",
                [["systemctl", "reset-failed"]], admin=True),
            Fix("vacuum_journal", "Shrink system logs", "Removes system log entries older than 14 days.",
                [["journalctl", "--vacuum-time=14d"]], admin=True),
        ]
        if shutil.which("apt-get"):
            fixes += [Fix("fix_packages", "Repair broken packages", "Completes interrupted installations.",
                          [["dpkg", "--configure", "-a"], ["apt-get", "-f", "install", "-y"]], admin=True)]
    return {f.id: f for f in fixes}
