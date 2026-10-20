"""Recent changes timeline: apps installed/updated/removed, system updates, new services and drivers,
startup changes, restarts, and actions taken by SysHealth."""
from __future__ import annotations

import datetime as dt
import glob
import gzip
import json
import os
import re
import shutil
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import persistence, state
from .platform_utils import IS_WINDOWS, app_data_dir, ps_json, run_cmd

LogFn = Optional[Callable[[str], None]]


@dataclass
class Change:
    when: str      # "YYYY-MM-DD HH:MM" or "YYYY-MM-DD"
    category: str  # Apps | System updates | Services | Drivers | Startup | Restarts | SysHealth
    title: str
    detail: str = ""
    items: list = field(default_factory=list)   # files or settings affected (SysHealth actions)
    item_count: int = 0


def _since(days: int) -> str:
    return (dt.datetime.now() - dt.timedelta(days=days)).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- installed apps snapshot
def installed_apps() -> dict[str, str]:
    apps: dict[str, str] = {}
    if IS_WINDOWS:
        rows = ps_json("$k='HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                       "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                       "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; "
                       "Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and "
                       "-not $_.SystemComponent } | Select-Object DisplayName, DisplayVersion, InstallDate")
        for r in rows:
            apps[r.get("DisplayName", "")] = f"{r.get('DisplayVersion') or ''}|{r.get('InstallDate') or ''}"
    elif shutil.which("dpkg-query"):
        rc, out = run_cmd(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=60)
        for line in out.splitlines():
            if "\t" in line:
                name, ver = line.split("\t", 1)
                apps[name] = ver
    elif shutil.which("rpm"):
        rc, out = run_cmd(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=60)
        for line in out.splitlines():
            if "\t" in line:
                name, ver = line.split("\t", 1)
                apps[name] = ver
    return apps


def _apps_diff() -> list[Change]:
    path = os.path.join(app_data_dir(), "apps_snapshot.json")
    current = installed_apps()
    try:
        with open(path, encoding="utf-8") as fh:
            prev = json.load(fh)
    except (OSError, json.JSONDecodeError):
        prev = {}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"time": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "apps": current}, fh, ensure_ascii=False)
    if not prev:
        return []
    when = f"since {prev.get('time', '?')}"
    old = prev.get("apps", {})
    out = []
    ver = lambda v: (v or "").split("|")[0]
    for name in sorted(set(current) - set(old)):
        out.append(Change(when, "Apps", f"Installed: {name}", ver(current[name])))
    for name in sorted(set(old) - set(current)):
        out.append(Change(when, "Apps", f"Removed: {name}", ver(old[name])))
    for name in sorted(set(old) & set(current)):
        if ver(old[name]) != ver(current[name]):
            out.append(Change(when, "Apps", f"Updated: {name}", f"{ver(old[name])} → {ver(current[name])}"))
    return out


# --------------------------------------------------------------------------- Windows sources
def _win_install_dates(days: int) -> list[Change]:
    since = _since(days).replace("-", "")
    out = []
    for name, value in installed_apps().items():
        version, date = (value.split("|") + [""])[:2]
        if re.fullmatch(r"\d{8}", date or "") and date >= since:
            out.append(Change(f"{date[:4]}-{date[4:6]}-{date[6:]}", "Apps", f"Installed or updated: {name}", version))
    return out


def _win_updates(days: int) -> list[Change]:
    script = ("$s=New-Object -ComObject Microsoft.Update.Session; $h=$s.CreateUpdateSearcher(); "
              "$n=$h.GetTotalHistoryCount(); if ($n -gt 0) { $h.QueryHistory(0,[math]::Min($n,300)) | "
              f"Where-Object {{ $_.Date -ge (Get-Date).AddDays(-{int(days)}) }} | ForEach-Object {{ "
              "[pscustomobject]@{T=$_.Date.ToLocalTime().ToString('yyyy-MM-dd HH:mm'); Title=$_.Title; R=$_.ResultCode} } }")
    result = {2: "Installed", 3: "Installed with errors", 4: "Failed", 5: "Cancelled"}
    return [Change(r.get("T", ""), "System updates", r.get("Title", ""), result.get(r.get("R"), "In progress"))
            for r in ps_json(script, timeout=180)]


def _win_events(days: int) -> list[Change]:
    d = int(days)
    script = (
        f"$s=(Get-Date).AddDays(-{d}); "
        "$a=@(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$s} -ErrorAction SilentlyContinue | "
        "ForEach-Object { [pscustomobject]@{K='svc'; T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); "
        "A=\"$($_.Properties[0].Value)\"; B=\"$($_.Properties[1].Value)\"} }); "
        "$b=@(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-UserPnp'; Id=20001; "
        "StartTime=$s} -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{K='drv'; "
        "T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); A=\"$($_.Properties[2].Value)\"; B=\"$($_.Properties[1].Value)\"} }); "
        "$c=@(Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'; Id=@(11707,11724); "
        "StartTime=$s} -MaxEvents 300 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{K=\"msi$($_.Id)\"; "
        "T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); A=(($_.Message -split \"`n\")[0]).Trim(); B=''} }); "
        "$e=@(Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(6005,6006,6008,1074); StartTime=$s} -MaxEvents 200 "
        "-ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{K=\"boot$($_.Id)\"; "
        "T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); A=(($_.Message -split \"`n\")[0]).Trim(); B=''} }); "
        "$a + $b + $c + $e")
    out = []
    labels = {"boot6005": "System started", "boot6006": "System shut down", "boot6008": "Unexpected shutdown",
              "boot1074": "Restart or shutdown requested"}
    for r in ps_json(script, timeout=240):
        k, t, a, b = r.get("K"), r.get("T", ""), r.get("A", ""), r.get("B", "")
        if k == "svc":
            out.append(Change(t, "Services", f"New service installed: {a}", b))
        elif k == "drv":
            out.append(Change(t, "Drivers", "Driver installed", f"{a} {b}".strip()))
        elif k == "msi11707":
            out.append(Change(t, "Apps", a or "Product installed"))
        elif k == "msi11724":
            out.append(Change(t, "Apps", a or "Product removed"))
        elif k in labels:
            out.append(Change(t, "Restarts", labels[k], a if k == "boot1074" else ""))
    return out


# --------------------------------------------------------------------------- Linux sources
def _read_logs(pattern: str) -> list[str]:
    lines = []
    for f in sorted(glob.glob(pattern)):
        try:
            opener = gzip.open if f.endswith(".gz") else open
            with opener(f, "rt", encoding="utf-8", errors="replace") as fh:
                lines += fh.readlines()
        except OSError:
            continue
    return lines


def _linux_packages(days: int) -> list[Change]:
    since = _since(days)
    out = []
    for line in _read_logs("/var/log/dpkg.log*"):
        m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}):\d{2} (install|upgrade|remove) (\S+) (\S+) (\S+)", line)
        if m and m.group(1)[:10] >= since:
            verb = {"install": "Installed", "upgrade": "Updated", "remove": "Removed"}[m.group(2)]
            pkg = m.group(3).split(":")[0]
            detail = m.group(5) if m.group(2) == "install" else (
                f"{m.group(4)} → {m.group(5)}" if m.group(2) == "upgrade" else m.group(4))
            out.append(Change(m.group(1), "Apps", f"{verb}: {pkg}", detail))
    for line in _read_logs("/var/log/pacman.log*"):
        m = re.match(r"^\[(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})\S*\] \[ALPM\] (installed|upgraded|removed) (\S+) \((.+)\)", line)
        if m and m.group(1) >= since:
            out.append(Change(f"{m.group(1)} {m.group(2)}", "Apps", f"{m.group(3).capitalize()}: {m.group(4)}",
                              m.group(5)))
    for line in _read_logs("/var/log/dnf.rpm.log*"):
        m = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})\S* \S+ (Installed|Upgraded|Erase|Upgrade): (\S+)", line)
        if m and m.group(1) >= since:
            out.append(Change(f"{m.group(1)} {m.group(2)}", "Apps", f"{m.group(3)}: {m.group(4)}"))
    if shutil.which("snap"):
        rc, text = run_cmd(["snap", "changes"])
        for line in text.splitlines()[1:]:
            m = re.match(r"^\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$", line)
            if m and m.group(1) == "Done":
                out.append(Change(m.group(2)[:10], "Apps", m.group(4).strip()[:120], "snap"))
    return out


def _linux_restarts(days: int) -> list[Change]:
    if not shutil.which("last"):
        return []
    rc, text = run_cmd(["last", "-x", "-F", "reboot", "shutdown"])
    since = dt.datetime.now() - dt.timedelta(days=days)
    out = []
    for line in text.splitlines():
        m = re.match(r"^(reboot|shutdown)\s+.*?(\w{3} \w{3}\s+\d+ \d{2}:\d{2}:\d{2} \d{4})", line)
        if not m:
            continue
        try:
            t = dt.datetime.strptime(re.sub(r"\s+", " ", m.group(2)), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            continue
        if t >= since:
            out.append(Change(t.strftime("%Y-%m-%d %H:%M"), "Restarts",
                              "System started" if m.group(1) == "reboot" else "System shut down"))
    return out


# --------------------------------------------------------------------------- public API
def collect(days: int = 7, log: LogFn = None, cancel: Optional[threading.Event] = None) -> list[Change]:
    changes: list[Change] = []

    def step(label: str, fn):
        if cancel is not None and cancel.is_set():
            from .platform_utils import Cancelled
            raise Cancelled()
        if log:
            log(f"Reading {label}…")
        try:
            changes.extend(fn())
        except Exception as exc:  # one failing source should not hide the others
            if log:
                log(f"Could not read {label}: {exc}")

    diff = []
    step("installed applications", lambda: diff.extend(_apps_diff()) or [])
    changes.extend(diff)
    if IS_WINDOWS:
        if not diff:
            step("install dates", lambda: _win_install_dates(days))
        step("Windows Update history", lambda: _win_updates(days))
        step("services, drivers and restarts", lambda: _win_events(days))
    else:
        step("package history", lambda: _linux_packages(days))
        step("restarts", lambda: _linux_restarts(days))

    def startup_changes():
        entries = persistence.collect(signatures=False)
        added, removed, prev = persistence.diff_with_snapshot(entries)
        when = f"since {prev}" if prev else ""
        return ([Change(when, "Startup", f"New autostart: {a['name']}", f"{a['category']} · {a['command'][:150]}")
                 for a in added] +
                [Change(when, "Startup", f"Autostart removed: {r['name']}", r["category"]) for r in removed])
    step("startup entries", startup_changes)
    step("SysHealth history", lambda: [Change(h["time"][:16], "SysHealth", h["action"], h.get("detail", ""),
                                              h.get("items", []), h.get("item_count", len(h.get("items", []))))
                                       for h in state.read_history(days)])

    def sort_key(c: Change):
        w = c.when.replace("since ", "")
        return w
    return sorted(changes, key=sort_key, reverse=True)
